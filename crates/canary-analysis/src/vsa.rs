//! Value Set Analysis (VSA).
//!
//! VSA tracks integer value ranges and pointer offsets through SSA form.

use canary_ir::cfg::{BlockId, ControlFlowGraph};
use canary_ir::llil::{LlilOp, OperandSize, Reg};
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName};
use indexmap::IndexMap;
use smallvec::SmallVec;
use std::cmp;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtrBase {
    StackFrame,
    ImageBase(u64),
    Heap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSet {
    Const(i64),
    Top,
    Range { lo: i64, hi: i64 },
    Set(SmallVec<[i64; 4]>),
    PtrOffset { base: PtrBase, offset: i64 },
    Bottom,
}

impl Default for ValueSet {
    fn default() -> Self {
        Self::Bottom
    }
}

pub struct VsaResult {
    pub values: IndexMap<SsaName, ValueSet>,
}

impl ValueSet {
    pub fn join(self, other: ValueSet) -> ValueSet {
        if self == other {
            return self;
        }
        match (self, other) {
            (ValueSet::Bottom, x) | (x, ValueSet::Bottom) => x,
            (ValueSet::Top, _) | (_, ValueSet::Top) => ValueSet::Top,
            (ValueSet::Const(a), ValueSet::Const(b)) => {
                if a == b {
                    ValueSet::Const(a)
                } else {
                    let mut set = SmallVec::new();
                    set.push(cmp::min(a, b));
                    set.push(cmp::max(a, b));
                    ValueSet::Set(set)
                }
            }
            (ValueSet::Const(a), ValueSet::Range { lo, hi })
            | (ValueSet::Range { lo, hi }, ValueSet::Const(a)) => ValueSet::Range {
                lo: cmp::min(a, lo),
                hi: cmp::max(a, hi),
            },
            (ValueSet::Range { lo: lo1, hi: hi1 }, ValueSet::Range { lo: lo2, hi: hi2 }) => {
                ValueSet::Range {
                    lo: cmp::min(lo1, lo2),
                    hi: cmp::max(hi1, hi2),
                }
            }
            (ValueSet::Set(mut s), ValueSet::Const(a))
            | (ValueSet::Const(a), ValueSet::Set(mut s)) => {
                if !s.contains(&a) {
                    s.push(a);
                    s.sort_unstable();
                }
                if s.len() > 4 {
                    ValueSet::Range {
                        lo: *s.first().unwrap(),
                        hi: *s.last().unwrap(),
                    }
                } else {
                    ValueSet::Set(s)
                }
            }
            (ValueSet::Set(s1), ValueSet::Set(s2)) => {
                let mut combined = s1;
                for v in s2 {
                    if !combined.contains(&v) {
                        combined.push(v);
                    }
                }
                combined.sort_unstable();
                if combined.len() > 4 {
                    ValueSet::Range {
                        lo: *combined.first().unwrap(),
                        hi: *combined.last().unwrap(),
                    }
                } else {
                    ValueSet::Set(combined)
                }
            }
            (
                ValueSet::PtrOffset {
                    base: b1,
                    offset: o1,
                },
                ValueSet::PtrOffset {
                    base: b2,
                    offset: o2,
                },
            ) if b1 == b2 && o1 == o2 => ValueSet::PtrOffset {
                base: b1,
                offset: o1,
            },
            _ => ValueSet::Top,
        }
    }

    pub fn widen(self, other: ValueSet) -> ValueSet {
        let joined = self.clone().join(other);
        if joined != self {
            ValueSet::Top
        } else {
            self
        }
    }
}

fn eval_expr(expr: &SsaExpr, values: &IndexMap<SsaName, ValueSet>) -> ValueSet {
    match expr {
        SsaExpr::Const { value, size } => {
            let mut val = *value as i64;
            match size {
                OperandSize::Bits8 => val = (*value as i8) as i64,
                OperandSize::Bits16 => val = (*value as i16) as i64,
                OperandSize::Bits32 => val = (*value as i32) as i64,
                OperandSize::Bits64 => {}
                _ => {}
            }
            ValueSet::Const(val)
        }
        SsaExpr::Reg { reg, .. } => values.get(reg).cloned().unwrap_or(ValueSet::Bottom),
        SsaExpr::BinOp { op, lhs, rhs, .. } => {
            let left = eval_expr(lhs, values);
            let right = eval_expr(rhs, values);

            match (op, left, right) {
                (LlilOp::Add, ValueSet::Const(a), ValueSet::Const(b)) => {
                    ValueSet::Const(a.wrapping_add(b))
                }
                (LlilOp::Add, ValueSet::PtrOffset { base, offset }, ValueSet::Const(c))
                | (LlilOp::Add, ValueSet::Const(c), ValueSet::PtrOffset { base, offset }) => {
                    ValueSet::PtrOffset {
                        base,
                        offset: offset.wrapping_add(c),
                    }
                }
                (LlilOp::Sub, ValueSet::PtrOffset { base, offset }, ValueSet::Const(c)) => {
                    ValueSet::PtrOffset {
                        base,
                        offset: offset.wrapping_sub(c),
                    }
                }
                (
                    LlilOp::Add,
                    ValueSet::Range { lo: lo1, hi: hi1 },
                    ValueSet::Range { lo: lo2, hi: hi2 },
                ) => ValueSet::Range {
                    lo: lo1.saturating_add(lo2),
                    hi: hi1.saturating_add(hi2),
                },
                (LlilOp::Add, ValueSet::Const(a), ValueSet::Range { lo, hi })
                | (LlilOp::Add, ValueSet::Range { lo, hi }, ValueSet::Const(a)) => {
                    ValueSet::Range {
                        lo: lo.saturating_add(a),
                        hi: hi.saturating_add(a),
                    }
                }
                _ => ValueSet::Top,
            }
        }
        _ => ValueSet::Top,
    }
}

pub fn analyze_vsa(func: &SsaFunction, cfg: &ControlFlowGraph) -> VsaResult {
    let mut values: IndexMap<SsaName, ValueSet> = IndexMap::new();

    // RBP (6) and RSP (7) start as stack frame pointers at version 0
    values.insert(
        SsaName {
            reg: Reg(6),
            version: 0,
        },
        ValueSet::PtrOffset {
            base: PtrBase::StackFrame,
            offset: 0,
        },
    );
    values.insert(
        SsaName {
            reg: Reg(7),
            version: 0,
        },
        ValueSet::PtrOffset {
            base: PtrBase::StackFrame,
            offset: 0,
        },
    );

    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut in_worklist: indexmap::IndexSet<BlockId> = indexmap::IndexSet::new();

    if let Some(&first_block) = func.blocks.keys().next() {
        worklist.push_back(first_block);
        in_worklist.insert(first_block);
    }

    let mut block_visits: IndexMap<BlockId, u32> = IndexMap::new();

    while let Some(block_id) = worklist.pop_front() {
        in_worklist.remove(&block_id);

        let block = &func.blocks[&block_id];
        let visits = *block_visits.entry(block_id).or_insert(0);
        block_visits.insert(block_id, visits + 1);
        let widen = visits > 3;

        let mut changed = false;

        for phi in &block.phis {
            let mut joined = ValueSet::Bottom;
            for op in &phi.operands {
                if let Some(val) = values.get(&op.name) {
                    joined = joined.join(val.clone());
                }
            }
            if widen {
                if let Some(old) = values.get(&phi.result) {
                    joined = old.clone().widen(joined);
                }
            }

            if let Some(old) = values.get(&phi.result) {
                if old != &joined {
                    values.insert(phi.result, joined);
                    changed = true;
                }
            } else {
                values.insert(phi.result, joined);
                changed = true;
            }
        }

        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign {
                    dest: SsaDest::Reg(reg),
                    expr,
                    ..
                } => {
                    let val = eval_expr(expr, &values);
                    if let Some(old) = values.get(reg) {
                        if old != &val {
                            values.insert(*reg, val);
                            changed = true;
                        }
                    } else {
                        values.insert(*reg, val);
                        changed = true;
                    }
                }
                SsaInstr::Call { ret: Some(reg), .. } => {
                    let val = ValueSet::Top;
                    if let Some(old) = values.get(reg) {
                        if old != &val {
                            values.insert(*reg, val);
                            changed = true;
                        }
                    } else {
                        values.insert(*reg, val);
                        changed = true;
                    }
                }
                SsaInstr::Intrinsic { outputs, .. } => {
                    for reg in outputs {
                        let val = ValueSet::Top;
                        if let Some(old) = values.get(reg) {
                            if old != &val {
                                values.insert(*reg, val);
                                changed = true;
                            }
                        } else {
                            values.insert(*reg, val);
                            changed = true;
                        }
                    }
                }
                _ => {}
            }
        }

        if changed {
            if let Some(cfg_block) = cfg.block(block_id) {
                for edge in &cfg_block.successors {
                    if !in_worklist.contains(&edge.target) {
                        worklist.push_back(edge.target);
                        in_worklist.insert(edge.target);
                    }
                }
            }
        }
    }

    VsaResult { values }
}

pub struct InferredCallTarget {
    pub call_site: u64,
    pub targets: Vec<u64>,
}

pub fn resolve_indirect_calls(
    func: &SsaFunction,
    cfg: &ControlFlowGraph,
    vsa: &VsaResult,
) -> Vec<InferredCallTarget> {
    let mut results = Vec::new();

    for (block_id, block) in &func.blocks {
        let block_start = cfg.block(*block_id).map(|b| b.start_addr).unwrap_or(0);
        for (i, instr) in block.instrs.iter().enumerate() {
            let instr_addr = cfg
                .block(*block_id)
                .and_then(|b| b.instr_addrs.get(i).copied())
                .unwrap_or(block_start);

            if let SsaInstr::Call { target, .. } = instr {
                // If it's a register or computed target
                if !matches!(target, canary_ir::ssa::SsaExpr::Const { .. }) {
                    let val = eval_expr(target, &vsa.values);
                    match val {
                        ValueSet::Const(c) => {
                            results.push(InferredCallTarget {
                                call_site: instr_addr,
                                targets: vec![c as u64],
                            });
                        }
                        ValueSet::Set(addrs) => {
                            results.push(InferredCallTarget {
                                call_site: instr_addr,
                                targets: addrs.into_iter().map(|a| a as u64).collect(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsa_constant_propagation() {
        let mut values = IndexMap::new();
        let r0 = SsaName {
            reg: Reg(0),
            version: 1,
        };
        values.insert(r0, ValueSet::Const(1));

        let expr = SsaExpr::BinOp {
            op: LlilOp::Add,
            lhs: Box::new(SsaExpr::Reg {
                reg: r0,
                size: OperandSize::Bits64,
            }),
            rhs: Box::new(SsaExpr::Const {
                value: 2,
                size: OperandSize::Bits64,
            }),
            size: OperandSize::Bits64,
        };

        let result = eval_expr(&expr, &values);
        assert_eq!(result, ValueSet::Const(3));
    }

    #[test]
    fn vsa_phi_join() {
        let a = ValueSet::Const(1);
        let b = ValueSet::Const(2);
        assert_eq!(a.join(b), ValueSet::Set(SmallVec::from_vec(vec![1, 2])));
    }

    #[test]
    fn vsa_loop_widening() {
        let a = ValueSet::Const(0);
        let b = ValueSet::Const(1);
        let c = a.join(b);
        assert_eq!(c.widen(ValueSet::Const(2)), ValueSet::Top);
    }

    #[test]
    fn vsa_stack_pointer() {
        let mut values = IndexMap::new();
        let rbp = SsaName {
            reg: Reg(6),
            version: 0,
        };
        values.insert(
            rbp,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: 0,
            },
        );

        let expr = SsaExpr::BinOp {
            op: LlilOp::Sub,
            lhs: Box::new(SsaExpr::Reg {
                reg: rbp,
                size: OperandSize::Bits64,
            }),
            rhs: Box::new(SsaExpr::Const {
                value: 8,
                size: OperandSize::Bits64,
            }),
            size: OperandSize::Bits64,
        };

        let result = eval_expr(&expr, &values);
        assert_eq!(
            result,
            ValueSet::PtrOffset {
                base: PtrBase::StackFrame,
                offset: -8
            }
        );
    }

    #[test]
    fn vsa_range_add() {
        let mut values = IndexMap::new();
        let r1 = SsaName {
            reg: Reg(1),
            version: 1,
        };
        let r2 = SsaName {
            reg: Reg(2),
            version: 1,
        };
        values.insert(r1, ValueSet::Range { lo: 1, hi: 5 });
        values.insert(r2, ValueSet::Range { lo: 2, hi: 4 });

        let expr = SsaExpr::BinOp {
            op: LlilOp::Add,
            lhs: Box::new(SsaExpr::Reg {
                reg: r1,
                size: OperandSize::Bits64,
            }),
            rhs: Box::new(SsaExpr::Reg {
                reg: r2,
                size: OperandSize::Bits64,
            }),
            size: OperandSize::Bits64,
        };

        let result = eval_expr(&expr, &values);
        assert_eq!(result, ValueSet::Range { lo: 3, hi: 9 });
    }

    #[test]
    fn vsa_const_branch_elim() {
        // Just tests join of identical constants
        let a = ValueSet::Const(1);
        let b = ValueSet::Const(1);
        assert_eq!(a.join(b), ValueSet::Const(1));
    }
}
