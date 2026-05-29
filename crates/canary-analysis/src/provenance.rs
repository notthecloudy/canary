//! Pointer Provenance & Alias Lattice
//!
//! Tracks the flow, constraints, and origins of pointers across SSA form.

use canary_ir::llil::{LlilOp, Reg};
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName};
use indexmap::{IndexMap, IndexSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AliasId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PointerConstraint {
    InHeap,
    InRdata,
    Aligned(u8),
    VtableLike,
    StackFrameOffset(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasState {
    Top, // Unknown
    Unique(AliasId),
    Constrained(IndexSet<PointerConstraint>),
    MayAlias(IndexSet<AliasId>),
    Bottom, // Logical conflict
}

impl AliasState {
    pub fn merge(self, other: AliasState) -> AliasState {
        use AliasState::*;
        match (self, other) {
            (Top, t) | (t, Top) => t,
            (Bottom, _) | (_, Bottom) => Bottom,
            (a, b) if a == b => a,
            (Unique(a), Unique(b)) => {
                let mut set = IndexSet::new();
                set.insert(a);
                set.insert(b);
                MayAlias(set)
            }
            (Unique(u), MayAlias(mut m)) | (MayAlias(mut m), Unique(u)) => {
                m.insert(u);
                MayAlias(m)
            }
            (MayAlias(mut a), MayAlias(b)) => {
                a.extend(b);
                MayAlias(a)
            }
            (Constrained(a), Constrained(b)) => {
                // Intersection of constraints (properties that MUST hold for both)
                let mut intersected = IndexSet::new();
                for c in a {
                    if b.contains(&c) {
                        intersected.insert(c);
                    }
                }
                if intersected.is_empty() {
                    Top
                } else {
                    Constrained(intersected)
                }
            }
            _ => Top,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProvBase {
    Parameter(usize),
    StackFrame(i64),
    Global(u64),
    ReturnValue(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedPtr {
    pub base: ProvBase,
    pub offset: i64,
    pub alias: AliasState,
}

/// Computes the pointer provenance for a given function.
pub fn compute_provenance(func: &SsaFunction) -> IndexMap<SsaName, TrackedPtr> {
    let mut tracked: IndexMap<SsaName, TrackedPtr> = IndexMap::new();
    let mut memory: IndexMap<(ProvBase, i64), TrackedPtr> = IndexMap::new();
    let mut next_alias = 0u32;

    for block in func.blocks.values() {
        for phi in &block.phis {
            let mut merged: Option<TrackedPtr> = None;
            for operand in &phi.operands {
                if let Some(ptr) = tracked.get(&operand.name) {
                    merged = Some(match merged {
                        Some(current)
                            if current.base == ptr.base && current.offset == ptr.offset =>
                        {
                            TrackedPtr {
                                base: current.base,
                                offset: current.offset,
                                alias: current.alias.merge(ptr.alias.clone()),
                            }
                        }
                        Some(current) => TrackedPtr {
                            base: current.base,
                            offset: current.offset,
                            alias: current.alias.merge(ptr.alias.clone()),
                        },
                        None => ptr.clone(),
                    });
                }
            }
            if let Some(ptr) = merged {
                tracked.insert(phi.result, ptr);
            }
        }

        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => match dest {
                    SsaDest::Reg(reg) => {
                        if let Some(ptr) = eval_expr(expr, &mut tracked, &memory, &mut next_alias) {
                            tracked.insert(*reg, ptr);
                        }
                    }
                    SsaDest::Mem { addr, .. } => {
                        if let (Some(addr_ptr), Some(value_ptr)) = (
                            eval_expr(addr, &mut tracked, &memory, &mut next_alias),
                            eval_expr(expr, &mut tracked, &memory, &mut next_alias),
                        ) {
                            memory.insert((addr_ptr.base, addr_ptr.offset), value_ptr);
                        }
                    }
                },
                SsaInstr::Store { addr, value, .. } => {
                    if let Some(addr_ptr) = eval_expr(addr, &mut tracked, &memory, &mut next_alias)
                    {
                        if let Some(value_ptr) =
                            eval_expr(value, &mut tracked, &memory, &mut next_alias)
                        {
                            memory.insert((addr_ptr.base, addr_ptr.offset), value_ptr);
                        } else {
                            memory.shift_remove(&(addr_ptr.base, addr_ptr.offset));
                        }
                    }
                }
                SsaInstr::Call {
                    target,
                    ret: Some(ret),
                    ..
                } => {
                    let call_target = match target {
                        SsaExpr::Const { value, .. } => *value,
                        _ => 0,
                    };
                    tracked.insert(
                        *ret,
                        TrackedPtr {
                            base: ProvBase::ReturnValue(call_target),
                            offset: 0,
                            alias: fresh_alias(&mut next_alias),
                        },
                    );
                }
                _ => {}
            }
        }
    }

    tracked
}

fn eval_expr(
    expr: &SsaExpr,
    tracked: &mut IndexMap<SsaName, TrackedPtr>,
    memory: &IndexMap<(ProvBase, i64), TrackedPtr>,
    next_alias: &mut u32,
) -> Option<TrackedPtr> {
    match expr {
        SsaExpr::Reg { reg, .. } => {
            if reg.version == 0 {
                Some(seed_version_zero(*reg, next_alias))
            } else {
                tracked.get(reg).cloned()
            }
        }
        SsaExpr::Const { value, .. } if *value != 0 => Some(TrackedPtr {
            base: ProvBase::Global(*value),
            offset: 0,
            alias: constrained_alias(PointerConstraint::InRdata),
        }),
        SsaExpr::Load { addr, .. } => {
            let addr_ptr = eval_expr(addr, tracked, memory, next_alias)?;
            memory
                .get(&(addr_ptr.base.clone(), addr_ptr.offset))
                .cloned()
        }
        SsaExpr::BinOp { op, lhs, rhs, .. } => match op {
            LlilOp::Add | LlilOp::Sub => {
                let lhs_ptr = eval_expr(lhs, tracked, memory, next_alias);
                let rhs_ptr = eval_expr(rhs, tracked, memory, next_alias);
                let lhs_const = const_value(lhs);
                let rhs_const = const_value(rhs);

                if let (Some(mut ptr), Some(delta)) = (lhs_ptr, rhs_const) {
                    if matches!(op, LlilOp::Sub) {
                        ptr.offset = ptr.offset.saturating_sub(delta as i64);
                    } else {
                        ptr.offset = ptr.offset.saturating_add(delta as i64);
                    }
                    return Some(ptr);
                }

                if matches!(op, LlilOp::Add) {
                    if let (Some(mut ptr), Some(delta)) = (rhs_ptr, lhs_const) {
                        ptr.offset = ptr.offset.saturating_add(delta as i64);
                        return Some(ptr);
                    }
                }

                None
            }
            _ => None,
        },
        SsaExpr::Sx { expr, .. } | SsaExpr::Zx { expr, .. } => {
            eval_expr(expr, tracked, memory, next_alias)
        }
        _ => None,
    }
}

fn seed_version_zero(name: SsaName, _next_alias: &mut u32) -> TrackedPtr {
    let (base, constraints) = if is_frame_register(name.reg) {
        let mut constraints = IndexSet::new();
        constraints.insert(PointerConstraint::StackFrameOffset(0));
        (ProvBase::StackFrame(0), constraints)
    } else {
        let mut constraints = IndexSet::new();
        constraints.insert(PointerConstraint::Aligned(8));
        (ProvBase::Parameter(name.reg.0 as usize), constraints)
    };

    TrackedPtr {
        base,
        offset: 0,
        alias: AliasState::Constrained(constraints),
    }
}

fn is_frame_register(reg: Reg) -> bool {
    matches!(reg.0, 4 | 5)
}

fn fresh_alias(next_alias: &mut u32) -> AliasState {
    let id = AliasId(*next_alias);
    *next_alias += 1;
    AliasState::Unique(id)
}

fn constrained_alias(constraint: PointerConstraint) -> AliasState {
    let mut constraints = IndexSet::new();
    constraints.insert(constraint);
    AliasState::Constrained(constraints)
}

fn const_value(expr: &SsaExpr) -> Option<u64> {
    match expr {
        SsaExpr::Const { value, .. } => Some(*value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::OperandSize;
    use canary_ir::ssa::{SsaBlock, SsaFunction};

    #[test]
    fn propagates_parameter_pointer_arithmetic() {
        let src = SsaName {
            reg: Reg(1),
            version: 0,
        };
        let dst = SsaName {
            reg: Reg(2),
            version: 1,
        };
        let mut blocks = IndexMap::new();
        blocks.insert(
            BlockId(0),
            SsaBlock {
                id: BlockId(0),
                phis: Vec::new(),
                instrs: vec![SsaInstr::Assign {
                    dest: SsaDest::Reg(dst),
                    expr: SsaExpr::BinOp {
                        op: LlilOp::Add,
                        lhs: Box::new(SsaExpr::Reg {
                            reg: src,
                            size: OperandSize::Bits64,
                        }),
                        rhs: Box::new(SsaExpr::Const {
                            value: 0x20,
                            size: OperandSize::Bits64,
                        }),
                        size: OperandSize::Bits64,
                    },
                    confidence: Default::default(),
                }],
            },
        );
        let func = SsaFunction {
            entry_addr: 0x1000,
            name: String::new(),
            blocks,
        };

        let provenance = compute_provenance(&func);
        let ptr = provenance.get(&dst).unwrap();

        assert_eq!(ptr.base, ProvBase::Parameter(1));
        assert_eq!(ptr.offset, 0x20);
    }

    #[test]
    fn load_reads_stored_pointer_provenance() {
        let addr = SsaName {
            reg: Reg(5),
            version: 0,
        };
        let value = SsaName {
            reg: Reg(1),
            version: 0,
        };
        let dst = SsaName {
            reg: Reg(2),
            version: 1,
        };
        let mut blocks = IndexMap::new();
        blocks.insert(
            BlockId(0),
            SsaBlock {
                id: BlockId(0),
                phis: Vec::new(),
                instrs: vec![
                    SsaInstr::Store {
                        addr: SsaExpr::Reg {
                            reg: addr,
                            size: OperandSize::Bits64,
                        },
                        value: SsaExpr::Reg {
                            reg: value,
                            size: OperandSize::Bits64,
                        },
                        size: OperandSize::Bits64,
                        confidence: Default::default(),
                    },
                    SsaInstr::Assign {
                        dest: SsaDest::Reg(dst),
                        expr: SsaExpr::Load {
                            addr: Box::new(SsaExpr::Reg {
                                reg: addr,
                                size: OperandSize::Bits64,
                            }),
                            size: OperandSize::Bits64,
                        },
                        confidence: Default::default(),
                    },
                ],
            },
        );
        let func = SsaFunction {
            entry_addr: 0x1000,
            name: String::new(),
            blocks,
        };

        let provenance = compute_provenance(&func);
        let ptr = provenance.get(&dst).unwrap();

        assert_eq!(ptr.base, ProvBase::Parameter(1));
    }
}
