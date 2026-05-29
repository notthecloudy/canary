//! Calling Convention Recovery
//!
//! Recovers function signatures by analyzing uninitialized register usage.

use crate::vsa::VsaResult;
use canary_ir::llil::Reg;
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr};
use canary_ir::types::{CallingConvention, IrType};
use indexmap::IndexSet;

#[derive(Debug, Clone)]
pub struct CallSignature {
    pub convention: CallingConvention,
    pub params: Vec<CallParam>,
    pub return_type: IrType,
    pub is_variadic: bool,
}

#[derive(Debug, Clone)]
pub struct CallParam {
    pub name: String,
    pub ty: IrType,
    pub location: ParamLocation,
}

#[derive(Debug, Clone, Copy)]
pub enum ParamLocation {
    Register(Reg),
    Stack { offset: i64 },
}

pub fn recover_call_signature<H: std::hash::BuildHasher>(
    func: &SsaFunction,
    _vsa: &VsaResult,
    convention: CallingConvention,
    prim_types: Option<&indexmap::IndexMap<canary_ir::ssa::SsaName, IrType, H>>,
) -> CallSignature {
    let mut used_v0_regs = IndexSet::new();

    fn walk_expr(expr: &SsaExpr, used: &mut IndexSet<Reg>) {
        match expr {
            SsaExpr::Reg { reg, .. } => {
                if reg.version == 0 {
                    used.insert(reg.reg);
                }
            }
            SsaExpr::Load { addr, .. } => walk_expr(addr, used),
            SsaExpr::BinOp { lhs, rhs, .. } => {
                walk_expr(lhs, used);
                walk_expr(rhs, used);
            }
            SsaExpr::UnOp { operand, .. } => walk_expr(operand, used),
            SsaExpr::Sx { expr, .. } | SsaExpr::Zx { expr, .. } => walk_expr(expr, used),
            _ => {}
        }
    }

    let mut rax_written = false;
    let mut returned_types = Vec::new();

    for block in func.blocks.values() {
        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    walk_expr(expr, &mut used_v0_regs);
                    if let SsaDest::Mem { addr, .. } = dest {
                        walk_expr(addr, &mut used_v0_regs);
                    }
                    if let SsaDest::Reg(r) = dest {
                        if r.reg == Reg(0) {
                            rax_written = true;
                        }
                    }
                }
                SsaInstr::Store { addr, value, .. } => {
                    walk_expr(addr, &mut used_v0_regs);
                    walk_expr(value, &mut used_v0_regs);
                }
                SsaInstr::If { cond, .. } => walk_expr(cond, &mut used_v0_regs),
                SsaInstr::Call { target, args, .. } => {
                    walk_expr(target, &mut used_v0_regs);
                    for arg in args {
                        walk_expr(arg, &mut used_v0_regs);
                    }
                }
                SsaInstr::Return { value, .. } => {
                    if let Some(val) = value {
                        walk_expr(val, &mut used_v0_regs);
                        if let Some(ptypes) = prim_types {
                            if let SsaExpr::Reg { reg, .. } = val {
                                if let Some(ty) = ptypes.get(reg) {
                                    if !returned_types.contains(ty) {
                                        returned_types.push(ty.clone());
                                    }
                                }
                            } else if let SsaExpr::Const { size, .. } = val {
                                let cty = IrType::Int {
                                    bit_width: size.bits(),
                                    signed: false,
                                };
                                if !returned_types.contains(&cty) {
                                    returned_types.push(cty);
                                }
                            }
                        }
                    }
                }
                SsaInstr::Intrinsic { inputs, .. } => {
                    for input in inputs {
                        walk_expr(input, &mut used_v0_regs);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    walk_expr(lhs, &mut used_v0_regs);
                    walk_expr(rhs, &mut used_v0_regs);
                }
                _ => {}
            }
        }
    }

    let mut actual_conv = convention;
    if actual_conv == CallingConvention::Unknown {
        let mut scores = indexmap::IndexMap::new();

        // Reg indices: 1=rcx, 2=rdx, 4=rsi, 5=rdi
        let has_rcx = used_v0_regs.contains(&Reg(1));
        let has_rdx = used_v0_regs.contains(&Reg(2));
        let has_rdi = used_v0_regs.contains(&Reg(5));
        let has_rsi = used_v0_regs.contains(&Reg(4));

        let fastcall_score: f32 = if has_rcx && has_rdx {
            0.8
        } else if has_rcx {
            0.4
        } else {
            0.1
        };
        let thiscall_score: f32 = if has_rcx && !has_rdx {
            0.7
        } else if has_rcx {
            0.5
        } else {
            0.1
        };
        let sysv_score: f32 = if has_rdi && has_rsi {
            0.9
        } else if has_rdi {
            0.6
        } else {
            0.1
        };
        let cdecl_score: f32 = if !has_rcx && !has_rdx && !has_rdi && !has_rsi {
            0.8
        } else {
            0.2
        };

        scores.insert(CallingConvention::Fastcall, fastcall_score);
        scores.insert(CallingConvention::Thiscall, thiscall_score);
        scores.insert(CallingConvention::SysV64, sysv_score);
        scores.insert(CallingConvention::Cdecl, cdecl_score);

        actual_conv = scores
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap()
            .0;
    }

    let abi_regs = match actual_conv {
        CallingConvention::SysV64 => vec![Reg(5), Reg(4), Reg(3), Reg(2), Reg(8), Reg(9)], // rdi, rsi, rdx, rcx, r8, r9
        CallingConvention::Win64Fastcall => vec![Reg(2), Reg(3), Reg(8), Reg(9)], // rcx, rdx, r8, r9
        CallingConvention::Fastcall => vec![Reg(1), Reg(2)],                      // ecx, edx
        CallingConvention::Thiscall => vec![Reg(1)],                              // ecx
        _ => vec![],
    };

    let mut params = Vec::new();
    if !abi_regs.is_empty() {
        let mut last_used_idx = None;
        for (i, &reg) in abi_regs.iter().enumerate() {
            if used_v0_regs.contains(&reg) {
                last_used_idx = Some(i);
            }
        }

        if let Some(idx) = last_used_idx {
            for (i, &reg) in abi_regs.iter().enumerate().take(idx + 1) {
                params.push(CallParam {
                    name: format!("arg{}", i + 1),
                    ty: IrType::Int {
                        bit_width: 64,
                        signed: false,
                    },
                    location: ParamLocation::Register(reg),
                });
            }
        }
    }

    let mut is_variadic = false;
    let name_lower = func.name.to_lowercase();
    if name_lower.contains("printf") || name_lower.contains("scanf") {
        is_variadic = true;
    } else if actual_conv == CallingConvention::SysV64 && used_v0_regs.contains(&Reg(0)) {
        is_variadic = true;
    }

    let return_type = if !returned_types.is_empty() {
        // Use the widest type if conflicting
        let mut widest = &returned_types[0];
        for ty in &returned_types[1..] {
            match (widest, ty) {
                (IrType::Int { bit_width: w1, .. }, IrType::Int { bit_width: w2, .. })
                    if w2 > w1 =>
                {
                    widest = ty;
                }
                _ => {}
            }
        }
        widest.clone()
    } else if rax_written {
        IrType::Int {
            bit_width: 64,
            signed: false,
        }
    } else {
        IrType::Void
    };

    CallSignature {
        convention: actual_conv,
        params,
        return_type,
        is_variadic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::cfg::BlockId;
    use canary_ir::llil::OperandSize;
    use canary_ir::ssa::{SsaBlock, SsaName};

    fn make_test_vsa() -> VsaResult {
        VsaResult {
            values: indexmap::IndexMap::new(),
        }
    }

    #[test]
    fn sysv64_two_int_params() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        // read rdi_v0, rsi_v0
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Assign {
                    confidence: Default::default(),
                    dest: SsaDest::Reg(SsaName {
                        reg: Reg(10),
                        version: 1,
                    }),
                    expr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(5),
                            version: 0,
                        },
                        size: OperandSize::Bits64,
                    },
                },
                SsaInstr::Assign {
                    confidence: Default::default(),
                    dest: SsaDest::Reg(SsaName {
                        reg: Reg(11),
                        version: 1,
                    }),
                    expr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(4),
                            version: 0,
                        },
                        size: OperandSize::Bits64,
                    },
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::SysV64,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert_eq!(sig.params.len(), 2);
        assert!(matches!(
            sig.params[0].location,
            ParamLocation::Register(Reg(5))
        ));
        assert!(matches!(
            sig.params[1].location,
            ParamLocation::Register(Reg(4))
        ));
    }

    #[test]
    fn sysv64_no_params() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![],
        };
        func.blocks.insert(BlockId(0), block);

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::SysV64,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert_eq!(sig.params.len(), 0);
        assert_eq!(sig.return_type, IrType::Void);
    }

    #[test]
    fn sysv64_return_int() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![SsaInstr::Assign {
                confidence: Default::default(),
                dest: SsaDest::Reg(SsaName {
                    reg: Reg(0),
                    version: 1,
                }),
                expr: SsaExpr::Const {
                    value: 42,
                    size: OperandSize::Bits64,
                },
            }],
        };
        func.blocks.insert(BlockId(0), block);

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::SysV64,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert_eq!(
            sig.return_type,
            IrType::Int {
                bit_width: 64,
                signed: false
            }
        );
    }

    #[test]
    fn win64_param_detection() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![
                SsaInstr::Assign {
                    confidence: Default::default(),
                    dest: SsaDest::Reg(SsaName {
                        reg: Reg(10),
                        version: 1,
                    }),
                    expr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(2),
                            version: 0,
                        },
                        size: OperandSize::Bits64,
                    }, // rcx
                },
                SsaInstr::Assign {
                    confidence: Default::default(),
                    dest: SsaDest::Reg(SsaName {
                        reg: Reg(11),
                        version: 1,
                    }),
                    expr: SsaExpr::Reg {
                        reg: SsaName {
                            reg: Reg(3),
                            version: 0,
                        },
                        size: OperandSize::Bits64,
                    }, // rdx
                },
            ],
        };
        func.blocks.insert(BlockId(0), block);

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::Win64Fastcall,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert_eq!(sig.params.len(), 2);
    }

    #[test]
    fn variadic_detection() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![SsaInstr::Assign {
                confidence: Default::default(),
                dest: SsaDest::Reg(SsaName {
                    reg: Reg(10),
                    version: 1,
                }),
                expr: SsaExpr::Reg {
                    reg: SsaName {
                        reg: Reg(0),
                        version: 0,
                    },
                    size: OperandSize::Bits8,
                }, // al
            }],
        };
        func.blocks.insert(BlockId(0), block);

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::SysV64,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert!(sig.is_variadic);
    }

    #[test]
    fn variadic_detection_by_name() {
        let vsa = make_test_vsa();
        let func = SsaFunction {
            entry_addr: 0,
            name: "printf".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::SysV64,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert!(sig.is_variadic);
    }

    #[test]
    fn thiscall_detection() {
        let vsa = make_test_vsa();
        let mut func = SsaFunction {
            entry_addr: 0,
            name: "".into(),
            blocks: indexmap::IndexMap::new(),
        };

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            instrs: vec![SsaInstr::Assign {
                confidence: Default::default(),
                dest: SsaDest::Reg(SsaName {
                    reg: Reg(10),
                    version: 1,
                }),
                expr: SsaExpr::Reg {
                    reg: SsaName {
                        reg: Reg(1),
                        version: 0,
                    },
                    size: OperandSize::Bits32,
                }, // ecx
            }],
        };
        func.blocks.insert(BlockId(0), block);

        let sig = recover_call_signature(
            &func,
            &vsa,
            CallingConvention::Unknown,
            None::<&indexmap::IndexMap<SsaName, IrType>>,
        );
        assert_eq!(sig.convention, CallingConvention::Thiscall);
        assert_eq!(sig.params.len(), 1);
        assert!(matches!(
            sig.params[0].location,
            ParamLocation::Register(Reg(1))
        ));
    }
}
