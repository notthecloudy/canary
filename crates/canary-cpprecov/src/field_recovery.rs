use canary_ir::function::{Function, FunctionArena};
use canary_ir::llil::{LlilExpr, LlilInstr, LlilOp, Reg};
use canary_sdb::types::{AccessKind, ClassHypothesis, FieldAccessEvent, FieldModel};
use indexmap::IndexMap;

pub fn run(
    class_hypotheses: &[ClassHypothesis],
    functions: &FunctionArena,
    out: &mut Vec<FieldModel>,
) {
    let mut map: IndexMap<(u64, i64), FieldModel> = IndexMap::new();

    for class in class_hypotheses {
        let vtable = class.vtable_addr;

        for &method_addr in &class.methods {
            if let Some(func) = functions
                .iter()
                .find(|(_, f)| f.entry_addr == method_addr)
                .map(|(_, f)| f)
            {
                for access in extract_field_accesses(func, vtable) {
                    let key = (vtable, access.offset);

                    let entry = map.entry(key).or_insert(FieldModel {
                        class_vtable: vtable,
                        offset: access.offset,
                        reads: 0,
                        writes: 0,
                        methods_touching: 0,
                        read_entropy: 0.0,
                        write_entropy: 0.0,
                        confidence: 0.0,
                    });

                    match access.kind {
                        AccessKind::Read => entry.reads += 1,
                        AccessKind::Write => entry.writes += 1,
                    }

                    // For now, we increment methods_touching blindly; we can fix it later
                    entry.methods_touching += 1;
                }
            }
        }
    }

    out.extend(map.into_values());
}

fn extract_field_accesses(func: &Function, class_vtable: u64) -> Vec<FieldAccessEvent> {
    let mut out = Vec::new();
    let cfg = &func.cfg;

    for block in cfg.blocks() {
        for inst in &block.instrs {
            match inst {
                LlilInstr::Assign { expr, .. } => {
                    // expr is a LlilExpr directly
                    if let LlilExpr::Load { addr, .. } = expr {
                        if let Some(offset) = match_this_offset(cfg, *addr) {
                            out.push(FieldAccessEvent {
                                class_vtable,
                                function_addr: func.entry_addr,
                                offset,
                                kind: AccessKind::Read,
                            });
                        }
                    }
                }
                LlilInstr::Store { addr, .. } => {
                    // Here, addr is a LlilExpr directly! wait, let's verify.
                    // Assuming addr is a LlilExpr in Store based on LlilInstr definition
                    // Wait, I need a version of match_this_offset that takes a LlilExpr directly, or I can just check if addr is a NodeId or LlilExpr.
                    // In LlilInstr::Store, addr is LlilExpr directly.
                    if let Some(offset) = match_this_offset_expr(cfg, addr) {
                        out.push(FieldAccessEvent {
                            class_vtable,
                            function_addr: func.entry_addr,
                            offset,
                            kind: AccessKind::Write,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn match_this_offset(
    cfg: &canary_ir::cfg::ControlFlowGraph,
    expr_id: canary_ir::arena::NodeId<LlilExpr>,
) -> Option<i64> {
    let expr = cfg.exprs.get(expr_id).unwrap();
    match_this_offset_expr(cfg, expr)
}

fn match_this_offset_expr(cfg: &canary_ir::cfg::ControlFlowGraph, expr: &LlilExpr) -> Option<i64> {
    match expr {
        // Direct load [rcx]
        LlilExpr::Reg { reg, .. } => {
            if is_this_register(*reg) {
                return Some(0);
            }
        }
        // Load [rcx + offset]
        LlilExpr::BinOp {
            op: LlilOp::Add,
            lhs,
            rhs,
            ..
        } => {
            let lhs_expr = cfg.exprs.get(*lhs).unwrap();
            let rhs_expr = cfg.exprs.get(*rhs).unwrap();

            let mut reg_val = None;
            let mut const_val = None;

            if let LlilExpr::Reg { reg, .. } = lhs_expr {
                reg_val = Some(*reg);
            }
            if let LlilExpr::Const { value, .. } = lhs_expr {
                const_val = Some(*value as i64);
            }

            if let LlilExpr::Reg { reg, .. } = rhs_expr {
                reg_val = Some(*reg);
            }
            if let LlilExpr::Const { value, .. } = rhs_expr {
                const_val = Some(*value as i64);
            }

            if let (Some(r), Some(c)) = (reg_val, const_val) {
                if is_this_register(r) {
                    return Some(c);
                }
            }
        }
        _ => {}
    }
    None
}

fn is_this_register(reg: Reg) -> bool {
    // rcx = 2 in canary-arch-x86/src/registers.rs
    reg.0 == 2
}

pub fn score_all(fields: &mut [FieldModel]) {
    for f in fields.iter_mut() {
        let access_strength = (f.reads + f.writes) as f32;
        let balance = (f.writes as f32 / (f.reads + 1) as f32).clamp(0.0, 1.0);
        let stability = (f.methods_touching as f32).log2().max(0.0);

        let mut conf =
            (0.5 * access_strength.log2().max(0.0)) + (0.3 * balance) + (0.2 * stability);

        conf = conf.clamp(0.0, 1.0);
        f.confidence = conf;
    }
}
