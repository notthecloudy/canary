use rustc_hash::FxHashMap;
use indexmap::IndexMap;
use canary_ir::ssa::{SsaFunction, SsaInstr, SsaDest, SsaExpr, SsaName};
use canary_ir::cfg::ControlFlowGraph;
use canary_ir::mlil::{MlilFunction, MlilBlock, MlilInstr, MlilDest, MlilExpr, MlilProvenance, VarSource as MlilVarSource, MlilVar};
use canary_ir::types::{IrType, ConfidenceTag};
use canary_ir::VarId;
use crate::stack_vars::StackVar;
use crate::calling_conv::CallSignature;
use crate::provenance::{TrackedPtr, ProvBase, AliasState};
use canary_ir::BlockId;
use canary_ir::semantic::SemanticFunction;

struct LoweringCtx<'a> {
    mlil: &'a mut MlilFunction,
    next_var_id: usize,
    ssa_to_var: FxHashMap<SsaName, VarId>,
    param_vars: Vec<(crate::calling_conv::ParamLocation, VarId)>,
    stack_map: FxHashMap<i64, VarId>,
}

impl<'a> LoweringCtx<'a> {
    fn alloc_var(&mut self, name: String, ty: IrType, source: MlilVarSource) -> VarId {
        let id = VarId(self.next_var_id);
        self.next_var_id += 1;
        self.mlil.vars.insert(id, MlilVar { id, name, ty, source });
        id
    }

    fn get_or_create_var(&mut self, name: SsaName) -> VarId {
        if let Some(&id) = self.ssa_to_var.get(&name) {
            return id;
        }

        let var_name = format!("v{}_{}", name.reg.0, name.version);
        let ty = IrType::Int { bit_width: 64, signed: false }; 
        let id = self.alloc_var(var_name, ty, MlilVarSource::Register(name.reg));
        self.ssa_to_var.insert(name, id);
        id
    }

    fn translate_expr(&mut self, expr: &SsaExpr) -> MlilExpr {
        match expr {
            SsaExpr::Reg { reg, size: _ } => MlilExpr::Var(self.get_or_create_var(*reg)),
            SsaExpr::Const { value, size } => MlilExpr::Const { value: *value, size: *size },
            SsaExpr::BinOp { op, lhs, rhs, size } => {
                let l = self.translate_expr(lhs);
                let r = self.translate_expr(rhs);
                MlilExpr::BinOp { op: *op, lhs: Box::new(l), rhs: Box::new(r), size: *size }
            }
            SsaExpr::UnOp { op, operand, size } => {
                let m = self.translate_expr(operand);
                MlilExpr::UnOp { op: *op, operand: Box::new(m), size: *size }
            }
            SsaExpr::Load { addr, size } => {
                let m_addr = self.translate_expr(addr);
                MlilExpr::Load { addr: Box::new(m_addr), size: *size }
            }
            SsaExpr::Sx { expr, from_size, to_size } => {
                let m_expr = self.translate_expr(expr);
                MlilExpr::Sx { expr: Box::new(m_expr), from_size: *from_size, to_size: *to_size }
            }
            SsaExpr::Zx { expr, from_size, to_size } => {
                let m_expr = self.translate_expr(expr);
                MlilExpr::Zx { expr: Box::new(m_expr), from_size: *from_size, to_size: *to_size }
            }
            _ => MlilExpr::Const { value: 0, size: canary_ir::llil::OperandSize::Bits64 },
        }
    }
}

fn mlil_provenance(ptr: &TrackedPtr) -> MlilProvenance {
    let base = match ptr.base {
        ProvBase::StackFrame(_) => "StackFrame".to_string(),
        ProvBase::Parameter(idx) => format!("Param({})", idx),
        ProvBase::Global(addr) => format!("Global({:#x})", addr),
        ProvBase::ReturnValue(v) => format!("RetVal({:#x})", v),
    };
    let alias = match &ptr.alias {
        AliasState::Top => "Top".to_string(),
        AliasState::Bottom => "Bottom".to_string(),
        AliasState::Unique(id) => format!("Unique({})", id.0),
        AliasState::Constrained(_) => "Constrained(...)".to_string(),
        AliasState::MayAlias(_) => "MayAlias(...)".to_string(),
    };
    MlilProvenance {
        base,
        offset: ptr.offset,
        alias,
    }
}

fn get_provenance(reg: &SsaName, provenance: &IndexMap<SsaName, TrackedPtr>) -> Option<TrackedPtr> {
    if let Some(ptr) = provenance.get(reg) {
        return Some(ptr.clone());
    }

    if reg.version == 0 {
        if reg.reg.0 >= 4 && reg.reg.0 <= 7 {
            return Some(TrackedPtr {
                base: ProvBase::StackFrame(0),
                offset: 0,
                alias: AliasState::Top,
            });
        } else {
            return Some(TrackedPtr {
                base: ProvBase::Parameter(reg.reg.0 as usize),
                offset: 0,
                alias: AliasState::Top,
            });
        }
    }
    None
}

fn collect_expr_provenance(
    expr: &SsaExpr,
    provenance: &IndexMap<SsaName, TrackedPtr>,
    out: &mut Vec<MlilProvenance>,
) {
    match expr {
        SsaExpr::Reg { reg, .. } => {
            if let Some(ptr) = get_provenance(reg, provenance) {
                out.push(mlil_provenance(&ptr));
            }
        }
        SsaExpr::Load { addr, .. } => collect_expr_provenance(addr, provenance, out),
        SsaExpr::BinOp { lhs, rhs, .. } => {
            collect_expr_provenance(lhs, provenance, out);
            collect_expr_provenance(rhs, provenance, out);
        }
        SsaExpr::UnOp { operand, .. } => collect_expr_provenance(operand, provenance, out),
        SsaExpr::Sx { expr, .. } | SsaExpr::Zx { expr, .. } => {
            collect_expr_provenance(expr, provenance, out);
        }
        _ => {}
    }
}

fn collect_instr_provenance(
    instr: &SsaInstr,
    provenance: &IndexMap<SsaName, TrackedPtr>,
) -> Vec<MlilProvenance> {
    let mut out = Vec::new();
    match instr {
        SsaInstr::Assign { dest, expr, .. } => {
            if let SsaDest::Reg(reg) = dest {
                if let Some(ptr) = get_provenance(reg, provenance) {
                    out.push(mlil_provenance(&ptr));
                }
            } else if let SsaDest::Mem { addr, .. } = dest {
                collect_expr_provenance(addr, provenance, &mut out);
            }
            collect_expr_provenance(expr, provenance, &mut out);
        }
        SsaInstr::Store { addr, value, .. } => {
            collect_expr_provenance(addr, provenance, &mut out);
            collect_expr_provenance(value, provenance, &mut out);
        }
        SsaInstr::Call { target, args, ret, .. } => {
            collect_expr_provenance(target, provenance, &mut out);
            for arg in args {
                collect_expr_provenance(arg, provenance, &mut out);
            }
            if let Some(ret) = ret {
                if let Some(ptr) = get_provenance(ret, provenance) {
                    out.push(mlil_provenance(&ptr));
                }
            }
        }
        SsaInstr::Return { value, .. } => {
            if let Some(value) = value {
                collect_expr_provenance(value, provenance, &mut out);
            }
        }
        SsaInstr::If { cond, .. } => collect_expr_provenance(cond, provenance, &mut out),
        SsaInstr::SetFlags { lhs, rhs, .. } => {
            collect_expr_provenance(lhs, provenance, &mut out);
            collect_expr_provenance(rhs, provenance, &mut out);
        }
        SsaInstr::Intrinsic { inputs, outputs, .. } => {
            for input in inputs {
                collect_expr_provenance(input, provenance, &mut out);
            }
            for output in outputs {
                if let Some(ptr) = get_provenance(output, provenance) {
                    out.push(mlil_provenance(&ptr));
                }
            }
        }
        _ => {}
    }
    out
}

fn push_with_provenance(
    block_id: BlockId,
    instrs: &mut Vec<MlilInstr>,
    instr: MlilInstr,
    provenance: Vec<MlilProvenance>,
    instr_provenance: &mut IndexMap<(BlockId, usize), Vec<MlilProvenance>>,
) {
    let idx = instrs.len();
    instr_provenance.insert((block_id, idx), provenance);
    instrs.push(instr);
}

fn propagated_confidence(confidence: &ConfidenceTag) -> ConfidenceTag {
    confidence.clone()
}

pub fn lower_to_mlil(
    ssa_func: &SsaFunction,
    _cfg: &ControlFlowGraph,
    sig: &CallSignature,
    stack_vars: &[StackVar],
    provenance: &IndexMap<SsaName, TrackedPtr>,
    semantic: &SemanticFunction,
    scheduled_order: &[&str],
) -> MlilFunction {
    let mut mlil = MlilFunction {
        blocks: IndexMap::new(),
        vars: IndexMap::new(),
        scheduled_order: scheduled_order.iter().map(|&s| s.to_string()).collect(),
        instr_provenance: IndexMap::new(),
        semantic: Some(semantic.clone()),
    };

    let mut ctx = LoweringCtx {
        mlil: &mut mlil,
        next_var_id: 0,
        ssa_to_var: FxHashMap::default(),
        param_vars: Vec::new(),
        stack_map: FxHashMap::default(),
    };

    let mut instr_provenance = IndexMap::new();

    for (i, param) in sig.params.iter().enumerate() {
        let name = format!("arg_{}", i);
        let id = ctx.alloc_var(name, param.ty.clone(), MlilVarSource::Parameter(i));
        ctx.param_vars.push((param.location.clone(), id));
    }

    for sv in stack_vars.iter() {
        let name = format!("local_{:x}", sv.offset.abs());
        let ty = IrType::Int { bit_width: sv.size as u8 * 8, signed: false };
        let id = ctx.alloc_var(name, ty, MlilVarSource::StackOffset(sv.offset));
        ctx.stack_map.insert(sv.offset, id);
    }

    for (id, _block) in &ssa_func.blocks {
        ctx.mlil.blocks.insert(*id, MlilBlock {
            id: *id,
            instrs: Vec::new(),
        });
    }

    for (block_id, ssa_block) in &ssa_func.blocks {
        let mut instrs = Vec::new();
        let mut last_set_flags = None;
        let mut last_set_flags_provenance = Vec::new();

        for instr in &ssa_block.instrs {
            match instr {
                SsaInstr::SetFlags { op, lhs, rhs, confidence: _ } => {
                    let l = ctx.translate_expr(lhs);
                    let r = ctx.translate_expr(rhs);
                    last_set_flags = Some((*op, l, r));
                    last_set_flags_provenance = collect_instr_provenance(instr, provenance);
                }
                SsaInstr::Assign { dest, expr, confidence } => {
                    let source_provenance = collect_instr_provenance(instr, provenance);
                    let m_dest = match dest {
                        SsaDest::Reg(reg) => MlilDest::Var(ctx.get_or_create_var(*reg)),
                        SsaDest::Mem { addr, size } => {
                            let mut offset = None;
                            if let SsaExpr::BinOp { op: canary_ir::llil::LlilOp::Sub, lhs, rhs, .. } = addr {
                                if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value, .. }) = (&**lhs, &**rhs) {
                                    if reg.reg.0 == 6 || reg.reg.0 == 7 {
                                        offset = Some(-(*value as i64));
                                    }
                                }
                            }
                            if let Some(off) = offset {
                                if let Some(&var_id) = ctx.stack_map.get(&off) {
                                    push_with_provenance(
                                        *block_id,
                                        &mut instrs,
                                        MlilInstr::Assign {
                                            dest: MlilDest::Var(var_id),
                                            expr: ctx.translate_expr(expr),
                                            confidence: propagated_confidence(confidence),
                                        },
                                        source_provenance,
                                        &mut instr_provenance,
                                    );
                                    continue;
                                }
                            }
                            
                            let m_addr = ctx.translate_expr(addr);
                            MlilDest::Mem { addr: Box::new(m_addr), size: *size }
                        }
                    };
                    let expr_trans = ctx.translate_expr(expr);
                    push_with_provenance(
                        *block_id,
                        &mut instrs,
                        MlilInstr::Assign {
                            dest: m_dest,
                            expr: expr_trans,
                            confidence: propagated_confidence(confidence),
                        },
                        source_provenance,
                        &mut instr_provenance,
                    );
                }
                SsaInstr::Store { addr, value, size, confidence } => {
                    let source_provenance = collect_instr_provenance(instr, provenance);
                    let mut offset = None;
                    if let SsaExpr::BinOp { op: canary_ir::llil::LlilOp::Sub, lhs, rhs, .. } = addr {
                        if let (SsaExpr::Reg { reg, .. }, SsaExpr::Const { value, .. }) = (&**lhs, &**rhs) {
                            if reg.reg.0 == 6 || reg.reg.0 == 7 {
                                offset = Some(-(*value as i64));
                            }
                        }
                    }
                    if let Some(off) = offset {
                        if let Some(&var_id) = ctx.stack_map.get(&off) {
                            let expr_trans = ctx.translate_expr(value);
                            push_with_provenance(
                                *block_id,
                                &mut instrs,
                                MlilInstr::Assign {
                                    dest: MlilDest::Var(var_id),
                                    expr: expr_trans,
                                    confidence: propagated_confidence(confidence),
                                },
                                source_provenance,
                                &mut instr_provenance,
                            );
                            continue;
                        }
                    }

                    let addr_trans = ctx.translate_expr(addr);
                    let val_trans = ctx.translate_expr(value);
                    push_with_provenance(
                        *block_id,
                        &mut instrs,
                        MlilInstr::Store {
                            addr: addr_trans,
                            value: val_trans,
                            size: *size,
                            confidence: propagated_confidence(confidence),
                        },
                        source_provenance,
                        &mut instr_provenance,
                    );
                }
                SsaInstr::Call { target, args, ret, confidence } => {
                    let source_provenance = collect_instr_provenance(instr, provenance);
                    let m_args = args.iter().map(|a| ctx.translate_expr(a)).collect();
                    let m_ret = ret.map(|r| ctx.get_or_create_var(r));
                    let targ_trans = ctx.translate_expr(target);
                    push_with_provenance(
                        *block_id,
                        &mut instrs,
                        MlilInstr::Call {
                            target: targ_trans,
                            args: m_args,
                            ret: m_ret,
                            confidence: propagated_confidence(confidence),
                        },
                        source_provenance,
                        &mut instr_provenance,
                    );
                }
                SsaInstr::Return { value, confidence } => {
                    let source_provenance = collect_instr_provenance(instr, provenance);
                    let val_trans = value.as_ref().map(|v| ctx.translate_expr(v));
                    push_with_provenance(
                        *block_id,
                        &mut instrs,
                        MlilInstr::Return {
                            value: val_trans,
                            confidence: propagated_confidence(confidence),
                        },
                        source_provenance,
                        &mut instr_provenance,
                    );
                }
                SsaInstr::If { cond, true_target, false_target, confidence } => {
                    let mut source_provenance = collect_instr_provenance(instr, provenance);
                    let cond_trans = if let SsaExpr::FlagCond { cond: flag_cond } = cond {
                        if let Some((op, lhs, rhs)) = last_set_flags.take() {
                            source_provenance.extend(last_set_flags_provenance.drain(..));
                            let cmp_op = match flag_cond {
                                canary_ir::llil::FlagCondition::Equal => canary_ir::llil::LlilOp::CmpE,
                                canary_ir::llil::FlagCondition::NotEqual => canary_ir::llil::LlilOp::CmpNe,
                                canary_ir::llil::FlagCondition::Less => canary_ir::llil::LlilOp::CmpSlt,
                                canary_ir::llil::FlagCondition::LessEq => canary_ir::llil::LlilOp::CmpSle,
                                canary_ir::llil::FlagCondition::Greater => canary_ir::llil::LlilOp::CmpSgt,
                                canary_ir::llil::FlagCondition::GreaterEq => canary_ir::llil::LlilOp::CmpSge,
                                canary_ir::llil::FlagCondition::Below => canary_ir::llil::LlilOp::CmpUlt,
                                canary_ir::llil::FlagCondition::BelowEq => canary_ir::llil::LlilOp::CmpUle,
                                canary_ir::llil::FlagCondition::Above => canary_ir::llil::LlilOp::CmpUgt,
                                canary_ir::llil::FlagCondition::AboveEq => canary_ir::llil::LlilOp::CmpUge,
                                _ => op,
                            };
                            MlilExpr::BinOp { op: cmp_op, lhs: Box::new(lhs), rhs: Box::new(rhs), size: canary_ir::llil::OperandSize::Bits8 }
                        } else {
                            ctx.translate_expr(cond)
                        }
                    } else {
                        ctx.translate_expr(cond)
                    };
                    
                    push_with_provenance(
                        *block_id,
                        &mut instrs,
                        MlilInstr::If {
                            cond: cond_trans,
                            true_target: *true_target,
                            false_target: *false_target,
                            confidence: propagated_confidence(confidence),
                        },
                        source_provenance,
                        &mut instr_provenance,
                    );
                }
                SsaInstr::Goto { target, confidence } => {
                    push_with_provenance(
                        *block_id,
                        &mut instrs,
                        MlilInstr::Goto { 
                            target: *target,
                            confidence: propagated_confidence(confidence),
                        },
                        collect_instr_provenance(instr, provenance),
                        &mut instr_provenance,
                    );
                }
                SsaInstr::Intrinsic { name: _, inputs: _, outputs: _, confidence: _ } => {
                    let _source_provenance = collect_instr_provenance(instr, provenance);
                    // Minimal port to preserve the logic, if Intrinsic needs to be pushed it might not be in MLIL?
                    // It was mostly `_ => {}` in original but the compiler forced me to add `confidence`. Let's ignore it in MLIL since MlilInstr doesn't have Intrinsic.
                }
                _ => {}
            }
        }
        
        ctx.mlil.blocks.get_mut(block_id).unwrap().instrs.extend(instrs);
    }

    let mut phi_copies: FxHashMap<BlockId, Vec<MlilInstr>> = FxHashMap::default();
    
    for (block_id, ssa_block) in &ssa_func.blocks {
        for phi in &ssa_block.phis {
            let dest_var = ctx.get_or_create_var(phi.result);
            for op in &phi.operands {
                let src_var = ctx.get_or_create_var(op.name);
                if dest_var != src_var {
                    let copy_instr = MlilInstr::Assign {
                        dest: MlilDest::Var(dest_var),
                        expr: MlilExpr::Var(src_var),
                        confidence: canary_ir::types::ConfidenceTag {
                            score: canary_sdb::ConfidenceVector::base(1.0),
                            origin: "phi_resolver".to_string(),
                            evidence_ids: vec![],
                        },
                    };
                    phi_copies.entry(op.block).or_default().push(copy_instr);
                }
            }
        }
    }

    for (pred_id, mut copies) in phi_copies.into_iter() {
        if let Some(m_block) = ctx.mlil.blocks.get_mut(&pred_id) {
            let len = m_block.instrs.len();
            if len > 0 {
                if matches!(m_block.instrs[len - 1], MlilInstr::If {..} | MlilInstr::Goto {..} | MlilInstr::Return {..}) {
                    let terminator = m_block.instrs.pop().unwrap();
                    let copies_len = copies.len();
                    if let Some(term_prov) = instr_provenance.shift_remove(&(pred_id, len - 1)) {
                        instr_provenance.insert((pred_id, len - 1 + copies_len), term_prov);
                    }
                    m_block.instrs.extend(copies);
                    m_block.instrs.push(terminator);
                } else {
                    m_block.instrs.extend(copies);
                }
            } else {
                m_block.instrs.extend(copies);
            }
        }
    }

    ctx.mlil.instr_provenance = instr_provenance;

    mlil
}
// FORCE REBUILD 
