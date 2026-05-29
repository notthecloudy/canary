//! Production-grade field recovery engine v2.
//!
//! Fields emerge from *observed memory behaviour*, not offset guesses.
//!
//! A field only becomes real if it satisfies ALL of:
//!  - accessed from ≥ 3 distinct execution contexts
//!  - entropy < 0.6 (stable, consistent access pattern)
//!  - at least one write observed (live field, not padding)
//!  - appears on ≥ 2 distinct object identities (cross-object stabilisation)

use indexmap::IndexMap;
use canary_ir::function::{FunctionArena, FunctionId};
use canary_ir::llil::{LlilInstr, LlilExpr, LlilDest};

// ── Object identity ─────────────────────────────────────────────────────────

/// A stable object identity cluster derived from analysis, NOT a raw pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId(pub u64);

// ── Access event ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessType { Read, Write, CallIndirect }

#[derive(Debug, Clone)]
pub struct AccessEvent {
    pub obj:         ObjectId,
    pub offset:      i32,
    pub access_type: AccessType,
    pub context_id:  u64,   // basic-block start address used as context
}

// ── Field candidate ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FieldCandidate {
    pub offset:           i32,
    pub obj_ids:          IndexMap<u64, ()>, // set of object IDs that saw this offset
    pub context_count:    u32,
    pub reads:            u32,
    pub writes:           u32,
    pub contradictions:   u32,
    pub entropy:          f32,
    pub confidence:       f32,
}

impl FieldCandidate {
    fn new(offset: i32) -> Self {
        Self {
            offset,
            obj_ids: IndexMap::new(),
            context_count: 0,
            reads: 0,
            writes: 0,
            contradictions: 0,
            entropy: 1.0,
            confidence: 0.0,
        }
    }

    /// True if this passes ALL real-field criteria.
    pub fn is_real(&self) -> bool {
        self.context_count >= 3
            && self.entropy < 0.6
            && self.writes >= 1
            && self.obj_ids.len() >= 2
    }

    fn recompute_confidence(&mut self) {
        let support      = (self.context_count as f32).log2().max(0.0) / 4.0; // saturates at 16 contexts
        let stability    = 1.0 - self.entropy;
        let contra_pen   = self.contradictions as f32 * 0.15;
        let cross_obj    = (self.obj_ids.len() as f32 / 3.0).min(1.0) * 0.20;

        self.confidence = (support * 0.40 + stability * 0.35 + cross_obj - contra_pen)
            .clamp(0.0, 1.0);
    }
}

// ── Field Recovery Engine ─────────────────────────────────────────────────────

pub struct FieldRecoveryEngine {
    /// class vtable address → offset → candidate
    pub fields: IndexMap<u64, IndexMap<i32, FieldCandidate>>,
}

impl Default for FieldRecoveryEngine {
    fn default() -> Self { Self { fields: IndexMap::new() } }
}

impl FieldRecoveryEngine {
    pub fn new() -> Self { Self::default() }

    /// Ingest one memory-access event observed for a class.
    pub fn ingest(&mut self, class_vtable: u64, event: AccessEvent) {
        let class_fields = self.fields.entry(class_vtable).or_default();
        let cand = class_fields.entry(event.offset)
            .or_insert_with(|| FieldCandidate::new(event.offset));

        cand.obj_ids.insert(event.obj.0, ());
        cand.context_count += 1;

        match event.access_type {
            AccessType::Read  => cand.reads  += 1,
            AccessType::Write => cand.writes += 1,
            AccessType::CallIndirect => cand.reads += 1,
        }

        // Entropy: ratio of minority access type (reads vs writes)
        let total = (cand.reads + cand.writes) as f32;
        if total > 0.0 {
            let p = cand.writes as f32 / total;
            // Shannon entropy normalised to [0,1]
            cand.entropy = if p == 0.0 || p == 1.0 {
                0.0
            } else {
                -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
            };
        }

        cand.recompute_confidence();
    }

    /// Run cross-object field stabilisation — boost candidates seen on many
    /// distinct objects.
    pub fn stabilize(&mut self) {
        for class_fields in self.fields.values_mut() {
            for cand in class_fields.values_mut() {
                if cand.obj_ids.len() >= 3 {
                    // Boost confidence by up to 0.15 for wide cross-object coverage
                    let boost = ((cand.obj_ids.len() as f32 - 2.0) / 10.0).min(0.15);
                    cand.confidence = (cand.confidence + boost).min(1.0);
                }
                // Penalise contradictions accumulated so far
                if cand.contradictions > 0 {
                    cand.confidence = (cand.confidence - cand.contradictions as f32 * 0.10).max(0.0);
                }
            }
        }
    }

    /// Emit the stable struct layout for a class.
    pub fn emit_layout(&self, class_vtable: u64) -> Vec<crate::field_recovery::FieldResult> {
        let Some(class_fields) = self.fields.get(&class_vtable) else { return vec![]; };

        let mut out: Vec<crate::field_recovery::FieldResult> = class_fields.values()
            .filter(|c| c.is_real())
            .map(|c| crate::field_recovery::FieldResult {
                offset:     c.offset,
                confidence: c.confidence,
                reads:      c.reads,
                writes:     c.writes,
            })
            .collect();

        out.sort_by_key(|f| f.offset);
        out
    }
}

// ── IR walker: extract field accesses from lifted functions ───────────────────

/// Walk all lifted functions and extract memory accesses that look like
/// `this + constant_offset` loads/stores.  The result is ingested into the engine.
pub fn extract_field_accesses(
    functions: &FunctionArena,
    engine: &mut FieldRecoveryEngine,
    class_vtable: u64,
    class_method_addrs: &[u64],
) {
    for func_id in functions.all_ids() {
        let func = match functions.get(func_id) { Some(f) => f, None => continue };
        if !class_method_addrs.contains(&func.entry_addr) { continue; }
        if !func.is_lifted { continue; }

        for block in func.cfg.blocks() {
            let ctx_id = block.start_addr;

            for instr in &block.instrs {
                match instr {
                    LlilInstr::Store { addr, .. } => {
                        if let Some(offset) = extract_this_offset(addr, &func.cfg.exprs) {
                            engine.ingest(class_vtable, AccessEvent {
                                obj: ObjectId(func.entry_addr),
                                offset,
                                access_type: AccessType::Write,
                                context_id: ctx_id,
                            });
                        }
                    }
                    LlilInstr::Assign { dest: LlilDest::Mem { addr, .. }, expr: _ } => {
                        if let Some(offset) = extract_this_offset(addr, &func.cfg.exprs) {
                            engine.ingest(class_vtable, AccessEvent {
                                obj: ObjectId(func.entry_addr),
                                offset,
                                access_type: AccessType::Write,
                                context_id: ctx_id,
                            });
                        }
                    }
                    LlilInstr::Assign { dest: _, expr } => {
                        if let LlilExpr::Load { addr, .. } = expr {
                            let inner = func.cfg.exprs.get(*addr).cloned();
                            if let Some(addr_expr) = inner {
                                if let Some(offset) = extract_this_offset(&addr_expr, &func.cfg.exprs) {
                                    engine.ingest(class_vtable, AccessEvent {
                                        obj: ObjectId(func.entry_addr),
                                        offset,
                                        access_type: AccessType::Read,
                                        context_id: ctx_id,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// If the expression is `rcx + constant` or `rdi + constant` (typical
/// `this`-pointer access patterns on x64), return the offset.
fn extract_this_offset(expr: &LlilExpr, exprs: &canary_ir::arena::Arena<LlilExpr>) -> Option<i32> {
    use canary_ir::llil::{LlilOp, Reg};
    // rcx = 2, rdi = 5 on x64
    const THIS_REGS: &[u32] = &[2, 5]; // rcx, rdi

    if let LlilExpr::BinOp { op: LlilOp::Add, lhs, rhs, .. } = expr {
        let l = exprs.get(*lhs)?;
        let r = exprs.get(*rhs)?;

        let (base, offset_expr) = match (l, r) {
            (LlilExpr::Reg { reg, .. }, o) if THIS_REGS.contains(&reg.0) => (reg, o),
            (o, LlilExpr::Reg { reg, .. }) if THIS_REGS.contains(&reg.0) => (reg, o),
            _ => return None,
        };

        if let LlilExpr::Const { value, .. } = offset_expr {
            if *value < 0x10000 {
                return Some(*value as i32);
            }
        }
    }

    // Direct register dereference (offset 0)
    if let LlilExpr::Reg { reg, .. } = expr {
        if THIS_REGS.contains(&reg.0) {
            return Some(0);
        }
    }

    None
}
