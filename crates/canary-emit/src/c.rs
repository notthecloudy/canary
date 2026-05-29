//! C language emitter.
//!
//! Converts LLIL/MLIL to C pseudocode. This is the Phase 1 emitter and
//! produces syntactically valid (though not always idiomatic) C.

use crate::{EmitContext, EmitError, EmitOutput, Emitter};
use canary_ir::llil::{LlilExpr, LlilInstr, LlilOp, LlilUnOp};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write;

/// Emitter that produces C pseudocode.
pub struct CEmitter;

impl Emitter for CEmitter {
    fn language(&self) -> &'static str {
        "c"
    }

    fn emit_function(&self, ctx: &EmitContext<'_>) -> Result<EmitOutput, EmitError> {
        let func = ctx.function;
        let mut out = String::new();

        // Function signature (Phase 1: all functions are void* with no typed params)
        writeln!(out, "// Function: {}", func.name).unwrap();
        writeln!(out, "// Entry: {:#x}", func.entry_addr).unwrap();
        writeln!(out, "void* {}(void) {{", func.name).unwrap();

        if !func.is_lifted {
            writeln!(out, "    // [not yet lifted]").unwrap();
        } else {
            // Emit blocks in BFS CFG order
            let cfg = &func.cfg;
            if let Some(entry_id) = cfg.entry() {
                let mut visited = HashSet::new();
                let mut queue = VecDeque::new();
                queue.push_back(entry_id);
                visited.insert(entry_id);

                while let Some(block_id) = queue.pop_front() {
                    self.emit_block(&mut out, cfg, block_id)?;

                    if let Some(block) = cfg.block(block_id) {
                        for edge in &block.successors {
                            if visited.insert(edge.target) {
                                queue.push_back(edge.target);
                            }
                        }
                    }
                }
            }
            writeln!(out, "    return 0;").unwrap();
        }

        writeln!(out, "}}").unwrap();
        Ok(out)
    }
}

impl CEmitter {
    fn emit_block(
        &self,
        out: &mut String,
        cfg: &canary_ir::cfg::ControlFlowGraph,
        block_id: canary_ir::cfg::BlockId,
    ) -> Result<(), EmitError> {
        let block = match cfg.block(block_id) {
            Some(b) => b,
            None => return Ok(()),
        };

        writeln!(out, "label_{:#x}:", block.start_addr).unwrap();
        writeln!(out, "  // Block {block_id} @ {:#x}", block.start_addr).unwrap();

        for instr in &block.instrs {
            let line = self.emit_instr(instr, &cfg.exprs)?;
            if !line.is_empty() {
                writeln!(out, "    {line};").unwrap();
            }
        }

        Ok(())
    }

    fn emit_instr(
        &self,
        instr: &LlilInstr,
        exprs: &canary_ir::arena::Arena<LlilExpr>,
    ) -> Result<String, EmitError> {
        Ok(match instr {
            LlilInstr::Assign { dest, expr, .. } => {
                let rhs = self.emit_expr(expr, exprs)?;
                match dest {
                    canary_ir::llil::LlilDest::Reg(r) => format!("{} = {}", r, rhs),
                    canary_ir::llil::LlilDest::Mem { addr, size } => {
                        format!(
                            "*(uint{}_t*)({}) = {}",
                            size.bits(),
                            self.emit_expr(addr, exprs)?,
                            rhs
                        )
                    }
                }
            }

            LlilInstr::Store {
                addr, value, size, ..
            } => {
                format!(
                    "*(uint{}_t*)({}) = {}",
                    size.bits(),
                    self.emit_expr(addr, exprs)?,
                    self.emit_expr(value, exprs)?
                )
            }

            LlilInstr::Goto { target, .. } => {
                format!("goto label_{target:#x}")
            }

            LlilInstr::If {
                cond,
                true_target,
                false_target,
                ..
            } => {
                format!(
                    "if ({}) {{ goto label_{true_target:#x}; }} else {{ goto label_{false_target:#x}; }}",
                    self.emit_expr(cond, exprs)?
                )
            }

            LlilInstr::Call {
                target, args, ret, ..
            } => {
                let target_str = self.emit_expr(target, exprs)?;
                let args_str: Vec<String> = args
                    .iter()
                    .map(|a| self.emit_expr(a, exprs))
                    .collect::<Result<_, _>>()?;
                let call = format!("{}({})", target_str, args_str.join(", "));
                if let Some(r) = ret {
                    format!("{r} = {call}")
                } else {
                    call
                }
            }

            LlilInstr::Return { value: Some(v), .. } => {
                format!("return {}", self.emit_expr(v, exprs)?)
            }

            LlilInstr::Return { value: None, .. } => "return 0".to_string(),

            LlilInstr::Undef { bytes, .. } => {
                format!("/* undef: {} bytes */", bytes.len())
            }

            LlilInstr::Intrinsic {
                name,
                inputs,
                outputs,
                ..
            } => {
                let args: Vec<String> = inputs
                    .iter()
                    .map(|a| self.emit_expr(a, exprs))
                    .collect::<Result<_, _>>()?;
                let call = format!("__intrinsic_{}({})", name, args.join(", "));
                if !outputs.is_empty() {
                    let outs: Vec<String> = outputs.iter().map(|r| r.to_string()).collect();
                    format!("{} = {call}", outs.join(", "))
                } else {
                    call
                }
            }

            LlilInstr::SetFlags { op, lhs, rhs, .. } => {
                format!(
                    "setflags({:?}, {}, {})",
                    op,
                    self.emit_expr(lhs, exprs)?,
                    self.emit_expr(rhs, exprs)?
                )
            }
            LlilInstr::Trap { .. } => "/* __debugbreak(); */".to_string(),
        })
    }

    fn emit_expr(
        &self,
        expr: &LlilExpr,
        exprs: &canary_ir::arena::Arena<LlilExpr>,
    ) -> Result<String, EmitError> {
        Ok(match expr {
            LlilExpr::Const { value, .. } => format!("{value:#x}"),
            LlilExpr::Reg { reg, .. } => reg.to_string(),
            LlilExpr::Load { addr, size } => {
                format!(
                    "*(uint{}_t*)({})",
                    size.bits(),
                    self.emit_expr(exprs.get(*addr).unwrap(), exprs)?
                )
            }
            LlilExpr::BinOp { op, lhs, rhs, size } => {
                let l = self.emit_expr(exprs.get(*lhs).unwrap(), exprs)?;
                let r = self.emit_expr(exprs.get(*rhs).unwrap(), exprs)?;
                match op {
                    LlilOp::Add => format!("({l} + {r})"),
                    LlilOp::Sub => format!("({l} - {r})"),
                    LlilOp::Mul => format!("({l} * {r})"),
                    LlilOp::And => format!("({l} & {r})"),
                    LlilOp::Or => format!("({l} | {r})"),
                    LlilOp::Xor => format!("({l} ^ {r})"),
                    LlilOp::Lsl => format!("({l} << {r})"),
                    LlilOp::Lsr => format!("({l} >> {r})"),
                    LlilOp::Asr => format!("((int{0}_t){l} >> {r})", size.bits()),
                    LlilOp::Rol => format!("_rotl{}({l}, {r})", size.bits()),
                    LlilOp::Ror => format!("_rotr{}({l}, {r})", size.bits()),
                    LlilOp::CmpE => format!("({l} == {r})"),
                    LlilOp::CmpNe => format!("({l} != {r})"),
                    LlilOp::CmpSlt => format!("((int{0}_t){l} < (int{0}_t){r})", size.bits()),
                    LlilOp::CmpUlt => format!("((uint{0}_t){l} < (uint{0}_t){r})", size.bits()),
                    LlilOp::CmpSle => format!("((int{0}_t){l} <= (int{0}_t){r})", size.bits()),
                    LlilOp::CmpUle => format!("((uint{0}_t){l} <= (uint{0}_t){r})", size.bits()),
                    LlilOp::CmpSgt => format!("((int{0}_t){l} > (int{0}_t){r})", size.bits()),
                    LlilOp::CmpUgt => format!("((uint{0}_t){l} > (uint{0}_t){r})", size.bits()),
                    LlilOp::CmpSge => format!("((int{0}_t){l} >= (int{0}_t){r})", size.bits()),
                    LlilOp::CmpUge => format!("((uint{0}_t){l} >= (uint{0}_t){r})", size.bits()),
                    _ => format!("unimplemented_op({l}, {r})"),
                }
            }
            LlilExpr::UnOp { op, operand, size } => {
                let o = self.emit_expr(exprs.get(*operand).unwrap(), exprs)?;
                match op {
                    LlilUnOp::Neg => format!("(-{o})"),
                    LlilUnOp::Not => format!("(~{o})"),
                    LlilUnOp::Popcount => format!("__popcount{}({o})", size.bits()),
                    LlilUnOp::Bswap => format!("__bswap{}({o})", size.bits()),
                    LlilUnOp::Clz => format!("__clz{}({o})", size.bits()),
                }
            }
            LlilExpr::Sx {
                from_size,
                to_size,
                expr,
            } => {
                let e = self.emit_expr(exprs.get(*expr).unwrap(), exprs)?;
                format!(
                    "((int{}_t)((int{}_t)({e})))",
                    to_size.bits(),
                    from_size.bits()
                )
            }
            LlilExpr::Zx {
                from_size,
                to_size,
                expr,
            } => {
                let e = self.emit_expr(exprs.get(*expr).unwrap(), exprs)?;
                format!(
                    "((uint{}_t)((uint{}_t)({e})))",
                    to_size.bits(),
                    from_size.bits()
                )
            }
            LlilExpr::LabelAddr { target } => format!("{target:#x}"),
            LlilExpr::Flag { flag } => format!("{flag:?}"),
            LlilExpr::FlagCond { cond } => format!("{cond:?}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EmitContext;
    use canary_ir::cfg::{ControlFlowGraph, EdgeKind};
    use canary_ir::function::Function;
    use canary_ir::llil::{FlagCondition, LlilDest, LlilExpr, LlilInstr, LlilOp, OperandSize, Reg};

    #[test]
    fn test_c_emitter_flow() {
        let mut func = Function::new(0x1000);
        func.name = "test_func".to_string();
        func.is_lifted = true;

        let mut cfg = ControlFlowGraph::new();
        let b1 = cfg.alloc_block(0x1000);
        let b2 = cfg.alloc_block(0x1010);
        cfg.set_entry(b1);

        // Block 1:
        // r0 = 42
        // r1 = Sx(r0)
        // setflags(CmpSlt, r0, 100)
        // if cond_Less goto b2 else goto b2
        let r0 = Reg(0);
        let r1 = Reg(1);
        cfg.block_mut(b1).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r0),
                expr: LlilExpr::Const {
                    value: 42,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r1),
                expr: LlilExpr::Sx {
                    from_size: OperandSize::Bits32,
                    to_size: OperandSize::Bits64,
                    expr: cfg.exprs.alloc(LlilExpr::Reg {
                        reg: r0,
                        size: OperandSize::Bits32,
                    }),
                },
            },
            LlilInstr::SetFlags {
                confidence: Default::default(),
                op: LlilOp::CmpSlt,
                lhs: LlilExpr::Reg {
                    reg: r0,
                    size: OperandSize::Bits64,
                },
                rhs: LlilExpr::Const {
                    value: 100,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::If {
                confidence: Default::default(),
                cond: LlilExpr::FlagCond {
                    cond: FlagCondition::Less,
                },
                true_target: 0x1010,
                false_target: 0x1010,
            },
        ];

        // Block 2:
        // call 0x4000(r0)
        // return r1
        cfg.block_mut(b2).unwrap().instrs = vec![
            LlilInstr::Call {
                confidence: Default::default(),
                target: LlilExpr::Const {
                    value: 0x4000,
                    size: OperandSize::Bits64,
                },
                args: vec![LlilExpr::Reg {
                    reg: r0,
                    size: OperandSize::Bits64,
                }],
                ret: None,
            },
            LlilInstr::Return {
                confidence: Default::default(),
                value: Some(LlilExpr::Reg {
                    reg: r1,
                    size: OperandSize::Bits64,
                }),
            },
        ];

        // Wire CFG edges
        cfg.add_edge(b1, b2, EdgeKind::True);
        cfg.add_edge(b1, b2, EdgeKind::False);

        func.cfg = cfg;

        let ctx = EmitContext {
            function: &func,
            mlil: None,
            hl_cf: None,
            symbol_resolver: None,
            sdb_func: None,
            mode: crate::EmitMode::Raw,
        };
        let emitter = CEmitter;
        let output = emitter.emit_function(&ctx).unwrap();

        println!("Emitted code:\n{}", output);

        // Check key emitted constructs
        assert!(output.contains("void* test_func(void) {"));
        assert!(output.contains("label_0x1000:"));
        assert!(output.contains("r0 = 0x2a;"));
        assert!(output.contains("r1 = ((int64_t)((int32_t)(r0)));"));
        assert!(output.contains("setflags(CmpSlt, r0, 0x64);"));
        assert!(output.contains("if (Less) { goto label_0x1010; } else { goto label_0x1010; }"));
        assert!(output.contains("label_0x1010:"));
        assert!(output.contains("0x4000(r0);"));
        assert!(output.contains("return r1;"));
    }
}
