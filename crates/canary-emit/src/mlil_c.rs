//! MLIL C Emitter.
//!
//! Emits structured C code from MLIL and HighLevelControlFlow.

use crate::{EmitContext, EmitError, EmitOutput, Emitter};
use canary_analysis::structuring::HighLevelControlFlow;
use canary_ir::llil::{LlilOp, LlilUnOp};
use canary_ir::mlil::{MlilDest, MlilExpr, MlilInstr};
use canary_ir::types::IrType;
use std::fmt::Write;

pub struct MlilCEmitter;

impl Emitter for MlilCEmitter {
    fn language(&self) -> &'static str {
        "c"
    }

    fn emit_function(&self, ctx: &EmitContext<'_>) -> Result<EmitOutput, EmitError> {
        let func = ctx.function;
        let mut out = String::new();

        writeln!(out, "// Function: {}", func.name).unwrap();
        writeln!(out, "// Entry: {:#x}", func.entry_addr).unwrap();

        let mut ret_ty = "void*".to_string();
        let mut params_str = "void".to_string();

        if let Some(sdb_func) = ctx.sdb_func {
            if let Some(sig_entry) = &sdb_func.call_signature {
                let sig = &sig_entry.value;
                ret_ty = sig.return_ty.clone();
                if !sig.params.is_empty() {
                    params_str = sig
                        .params
                        .iter()
                        .enumerate()
                        .map(|(i, p)| format!("{} arg_{}", p.ty, i))
                        .collect::<Vec<_>>()
                        .join(", ");
                }
            }
        }

        writeln!(out, "{} {}({}) {{", ret_ty, func.name, params_str).unwrap();

        if let (Some(mlil), Some(hl_cf)) = (ctx.mlil, ctx.hl_cf) {
            for var in mlil.vars.values() {
                if matches!(var.source, canary_ir::mlil::VarSource::Parameter(_)) {
                    continue;
                }
                writeln!(out, "    {} {};", type_to_c(&var.ty), var.name).unwrap();
            }
            if !mlil.vars.is_empty() {
                writeln!(out).unwrap();
            }

            self.emit_ast(&mut out, ctx, hl_cf, 1)?;
        } else {
            writeln!(out, "    // [MLIL not available]").unwrap();
        }

        if ret_ty != "void" {
            writeln!(out, "    return 0;").unwrap();
        }

        writeln!(out, "}}").unwrap();
        Ok(out)
    }
}

impl MlilCEmitter {
    fn get_ret_ty(&self, ctx: &EmitContext<'_>) -> String {
        if let Some(sdb_func) = ctx.sdb_func {
            if let Some(sig_entry) = &sdb_func.call_signature {
                return sig_entry.value.return_ty.clone();
            }
        }
        "void*".to_string()
    }
    fn emit_ast(
        &self,
        out: &mut String,
        ctx: &EmitContext<'_>,
        ast: &HighLevelControlFlow,
        indent: usize,
    ) -> Result<(), EmitError> {
        let mlil = ctx.mlil.unwrap();
        let ind = "    ".repeat(indent);
        match ast {
            HighLevelControlFlow::Seq(items) => {
                for item in items {
                    self.emit_ast(out, ctx, item, indent)?;
                }
            }
            HighLevelControlFlow::Block(id) => {
                if let Some(block) = mlil.blocks.get(id) {
                    for (idx, instr) in block.instrs.iter().enumerate() {
                        if matches!(instr, MlilInstr::If { .. }) {
                            continue;
                        }
                        if let Some(provenance) = mlil.instr_provenance.get(&(*id, idx)) {
                            if !provenance.is_empty() {
                                let summary = provenance
                                    .iter()
                                    .map(|p| format!("{}+{:#x}", p.base, p.offset))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                writeln!(out, "{}/* provenance: {} */", ind, summary).unwrap();
                            }
                        }
                        write!(out, "{}", ind).unwrap();
                        self.emit_instr(out, ctx, instr)?;
                        writeln!(out, ";").unwrap();
                    }
                }
            }
            HighLevelControlFlow::If { cond, then_branch } => {
                let cond_str = self.extract_cond(ctx, *cond)?;
                writeln!(out, "{}if ({}) {{", ind, cond_str).unwrap();
                self.emit_ast(out, ctx, then_branch, indent + 1)?;
                writeln!(out, "{}}}", ind).unwrap();
            }
            HighLevelControlFlow::IfElse {
                cond,
                then_branch,
                else_branch,
            } => {
                let cond_str = self.extract_cond(ctx, *cond)?;
                writeln!(out, "{}if ({}) {{", ind, cond_str).unwrap();
                self.emit_ast(out, ctx, then_branch, indent + 1)?;
                writeln!(out, "{}}} else {{", ind).unwrap();
                self.emit_ast(out, ctx, else_branch, indent + 1)?;
                writeln!(out, "{}}}", ind).unwrap();
            }
            HighLevelControlFlow::While { cond, body } => {
                let cond_str = self.extract_cond(ctx, *cond)?;
                writeln!(out, "{}while ({}) {{", ind, cond_str).unwrap();
                self.emit_ast(out, ctx, body, indent + 1)?;
                writeln!(out, "{}}}", ind).unwrap();
            }
            HighLevelControlFlow::DoWhile { body, cond } => {
                let cond_str = self.extract_cond(ctx, *cond)?;
                writeln!(out, "{}do {{", ind).unwrap();
                self.emit_ast(out, ctx, body, indent + 1)?;
                writeln!(out, "{}}} while ({});", ind, cond_str).unwrap();
            }
            HighLevelControlFlow::Return => {
                let ret_ty = self.get_ret_ty(ctx);
                if ret_ty == "void" {
                    writeln!(out, "{}return;", ind).unwrap();
                } else {
                    writeln!(out, "{}return 0;", ind).unwrap();
                }
            }
            HighLevelControlFlow::Break => {
                writeln!(out, "{}break;", ind).unwrap();
            }
            HighLevelControlFlow::Continue => {
                writeln!(out, "{}continue;", ind).unwrap();
            }
            HighLevelControlFlow::Goto(target) => {
                writeln!(out, "{}goto bb{};", ind, target.0).unwrap();
            }
        }
        Ok(())
    }

    fn extract_cond(
        &self,
        ctx: &EmitContext<'_>,
        block_id: canary_ir::cfg::BlockId,
    ) -> Result<String, EmitError> {
        let mlil = ctx.mlil.unwrap();
        let block = mlil.blocks.get(&block_id).unwrap();
        if let Some(MlilInstr::If { cond, .. }) = block.instrs.last() {
            let mut out = String::new();
            self.emit_expr(&mut out, ctx, cond)?;
            Ok(out)
        } else {
            Ok("true".to_string())
        }
    }

    fn emit_instr(
        &self,
        out: &mut String,
        ctx: &EmitContext<'_>,
        instr: &MlilInstr,
    ) -> Result<(), EmitError> {
        let mlil = ctx.mlil.unwrap();
        match instr {
            MlilInstr::Assign { dest, expr, .. } => {
                if let MlilDest::Var(id) = dest {
                    let name = &mlil.vars[id].name;
                    if name == "r7" || name == "r6" || name == "r4" || name == "r5" || name == "r16"
                    {
                        return Ok(());
                    }
                }
                self.emit_dest(out, ctx, dest)?;
                write!(out, " = ").unwrap();
                self.emit_expr(out, ctx, expr)?;
            }
            MlilInstr::Store {
                addr, value, size, ..
            } => {
                write!(out, "*(uint{}_t*)(", size.bytes() * 8).unwrap();
                self.emit_expr(out, ctx, addr)?;
                write!(out, ") = ").unwrap();
                self.emit_expr(out, ctx, value)?;
            }
            MlilInstr::Call { target, args, .. } => {
                if let MlilExpr::Const { value, .. } = target {
                    if let Some(resolver) = ctx.symbol_resolver {
                        if let Some(name) = resolver(*value) {
                            write!(out, "{}", name).unwrap();
                        } else {
                            self.emit_expr(out, ctx, target)?;
                        }
                    } else {
                        self.emit_expr(out, ctx, target)?;
                    }
                } else {
                    self.emit_expr(out, ctx, target)?;
                }
                write!(out, "(").unwrap();
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(out, ", ").unwrap();
                    }
                    self.emit_expr(out, ctx, arg)?;
                }
                write!(out, ")").unwrap();
            }
            MlilInstr::Return { value, .. } => {
                if let Some(v) = value {
                    write!(out, "return ").unwrap();
                    self.emit_expr(out, ctx, v)?;
                } else {
                    let ret_ty = self.get_ret_ty(ctx);
                    if ret_ty == "void" {
                        write!(out, "return").unwrap();
                    } else {
                        write!(out, "return 0").unwrap();
                    }
                }
            }
            MlilInstr::If { .. } => {}
            MlilInstr::Goto { target, .. } => {
                write!(out, "goto label_{target:#x}").unwrap();
            }
            MlilInstr::Intrinsic {
                name,
                inputs,
                outputs,
                ..
            } => {
                let args: Vec<String> = inputs
                    .iter()
                    .map(|e| {
                        let mut s = String::new();
                        let _ = self.emit_expr(&mut s, ctx, e);
                        s
                    })
                    .collect();
                let call = format!("__intrinsic_{}({})", name, args.join(", "));
                if !outputs.is_empty() {
                    let outs: Vec<String> = outputs
                        .iter()
                        .map(|id| mlil.vars[id].name.clone())
                        .collect();
                    write!(out, "{} = {}", outs.join(", "), call).unwrap();
                } else {
                    write!(out, "{}", call).unwrap();
                }
            }
        }
        Ok(())
    }

    fn emit_dest(
        &self,
        out: &mut String,
        ctx: &EmitContext<'_>,
        dest: &MlilDest,
    ) -> Result<(), EmitError> {
        let mlil = ctx.mlil.unwrap();
        match dest {
            MlilDest::Var(id) => {
                write!(out, "{}", mlil.vars[id].name).unwrap();
            }
            MlilDest::Mem { addr, size } => {
                write!(out, "*(uint{}_t*)(", size.bytes() * 8).unwrap();
                self.emit_expr(out, ctx, addr)?;
                write!(out, ")").unwrap();
            }
        }
        Ok(())
    }

    fn emit_expr(
        &self,
        out: &mut String,
        ctx: &EmitContext<'_>,
        expr: &MlilExpr,
    ) -> Result<(), EmitError> {
        let mlil = ctx.mlil.unwrap();
        match expr {
            MlilExpr::Var(var_id) => {
                write!(out, "{}", mlil.vars[var_id].name).unwrap();
            }
            MlilExpr::Const { value, .. } => {
                if let Some(resolver) = ctx.symbol_resolver {
                    if let Some(name) = resolver(*value) {
                        write!(out, "{}", name).unwrap();
                        return Ok(());
                    }
                }
                write!(out, "{:#x}", value).unwrap();
            }
            MlilExpr::Load { addr, size } => {
                write!(out, "*(uint{}_t*)(", size.bytes() * 8).unwrap();
                self.emit_expr(out, ctx, addr)?;
                write!(out, ")").unwrap();
            }
            MlilExpr::BinOp { op, lhs, rhs, .. } => {
                let op_str = match op {
                    LlilOp::Add => "+",
                    LlilOp::Sub => "-",
                    LlilOp::Mul | LlilOp::MulsDp | LlilOp::MuluDp => "*",
                    LlilOp::Divu | LlilOp::Divs => "/",
                    LlilOp::Modu | LlilOp::Mods => "%",
                    LlilOp::And => "&",
                    LlilOp::Or => "|",
                    LlilOp::Xor => "^",
                    LlilOp::Lsl | LlilOp::Rol => "<<",
                    LlilOp::Lsr | LlilOp::Asr | LlilOp::Ror => ">>",
                    LlilOp::CmpE => "==",
                    LlilOp::CmpNe => "!=",
                    LlilOp::CmpSlt | LlilOp::CmpUlt => "<",
                    LlilOp::CmpSle | LlilOp::CmpUle => "<=",
                    LlilOp::CmpSgt | LlilOp::CmpUgt => ">",
                    LlilOp::CmpSge | LlilOp::CmpUge => ">=",
                };
                write!(out, "(").unwrap();
                self.emit_expr(out, ctx, lhs)?;
                write!(out, " {} ", op_str).unwrap();
                self.emit_expr(out, ctx, rhs)?;
                write!(out, ")").unwrap();
            }
            MlilExpr::UnOp { op, operand, size } => {
                let op_str = match op {
                    LlilUnOp::Not => "~",
                    LlilUnOp::Neg => "-",
                    LlilUnOp::Popcount => {
                        write!(out, "__popcount{}(", size.bits()).unwrap();
                        self.emit_expr(out, ctx, operand)?;
                        write!(out, ")").unwrap();
                        return Ok(());
                    }
                    LlilUnOp::Bswap => {
                        write!(out, "__bswap{}(", size.bits()).unwrap();
                        self.emit_expr(out, ctx, operand)?;
                        write!(out, ")").unwrap();
                        return Ok(());
                    }
                    LlilUnOp::Clz => {
                        write!(out, "__clz{}(", size.bits()).unwrap();
                        self.emit_expr(out, ctx, operand)?;
                        write!(out, ")").unwrap();
                        return Ok(());
                    }
                };
                write!(out, "({}", op_str).unwrap();
                self.emit_expr(out, ctx, operand)?;
                write!(out, ")").unwrap();
            }
            MlilExpr::Sx { expr, .. } | MlilExpr::Zx { expr, .. } => {
                self.emit_expr(out, ctx, expr)?;
            }
            MlilExpr::FlagCond { cond } => {
                write!(out, "cond_{cond:?}").unwrap();
            }
            MlilExpr::AddressOf(var_id) => {
                write!(out, "&{}", mlil.vars[var_id].name).unwrap();
            }
        }
        Ok(())
    }
}

fn type_to_c(ty: &IrType) -> String {
    match ty {
        IrType::Int { bit_width, .. } => format!("uint{}_t", bit_width),
        IrType::Pointer { .. } => "void*".to_string(),
        IrType::Struct { name, .. } => name.clone().unwrap_or_else(|| "struct".to_string()),
        IrType::Array { .. } => "void*".to_string(),
        IrType::Void => "void".to_string(),
        _ => "void*".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::function::Function;
    use canary_ir::llil::OperandSize;
    use canary_ir::mlil::{MlilBlock, MlilFunction, MlilVar, VarId, VarSource};

    #[test]
    fn test_mlil_c_emitter_basic() {
        let mut mlil = MlilFunction {
            blocks: indexmap::IndexMap::new(),
            vars: indexmap::IndexMap::new(),
            instr_provenance: indexmap::IndexMap::new(),
            semantic: None,
            scheduled_order: Vec::new(),
        };

        let var = MlilVar {
            id: VarId(0),
            name: "local_1".into(),
            ty: IrType::Int {
                bit_width: 32,
                signed: false,
            },
            source: VarSource::Temporary,
        };
        mlil.vars.insert(var.id, var.clone());

        let block = MlilBlock {
            id: BlockId(0),
            instrs: vec![MlilInstr::Assign {
                confidence: Default::default(),
                dest: MlilDest::Var(var.id),
                expr: MlilExpr::Const {
                    value: 42,
                    size: OperandSize::Bits32,
                },
            }],
        };
        mlil.blocks.insert(BlockId(0), block);

        let hl_cf = HighLevelControlFlow::Block(BlockId(0));

        let func = Function::new(0x4000);
        let ctx = EmitContext {
            function: &func,
            mlil: Some(&mlil),
            hl_cf: Some(&hl_cf),
            symbol_resolver: None,
            sdb_func: None,
            mode: crate::EmitMode::Recovered,
        };

        let emitter = MlilCEmitter;
        let out = emitter.emit_function(&ctx).unwrap();
        assert!(out.contains("uint32_t local_1;"));
        assert!(out.contains("local_1 = 0x2a;"));
    }

    #[test]
    fn test_mlil_c_emitter_if() {
        let mut mlil = MlilFunction {
            blocks: indexmap::IndexMap::new(),
            vars: indexmap::IndexMap::new(),
            instr_provenance: indexmap::IndexMap::new(),
            semantic: None,
            scheduled_order: Vec::new(),
        };

        let block = MlilBlock {
            id: BlockId(0),
            instrs: vec![MlilInstr::If {
                confidence: Default::default(),
                cond: MlilExpr::Const {
                    value: 1,
                    size: OperandSize::Bits8,
                },
                true_target: 1,
                false_target: 2,
            }],
        };
        mlil.blocks.insert(BlockId(0), block);
        mlil.blocks.insert(
            BlockId(1),
            MlilBlock {
                id: BlockId(1),
                instrs: vec![],
            },
        );
        mlil.blocks.insert(
            BlockId(2),
            MlilBlock {
                id: BlockId(2),
                instrs: vec![],
            },
        );

        let hl_cf = HighLevelControlFlow::IfElse {
            cond: BlockId(0),
            then_branch: Box::new(HighLevelControlFlow::Block(BlockId(1))),
            else_branch: Box::new(HighLevelControlFlow::Block(BlockId(2))),
        };

        let func = Function::new(0x4000);
        let ctx = EmitContext {
            function: &func,
            mlil: Some(&mlil),
            hl_cf: Some(&hl_cf),
            symbol_resolver: None,
            sdb_func: None,
            mode: crate::EmitMode::Recovered,
        };

        let emitter = MlilCEmitter;
        let out = emitter.emit_function(&ctx).unwrap();
        assert!(out.contains("if (0x1) {"));
        assert!(out.contains("} else {"));
    }
}
