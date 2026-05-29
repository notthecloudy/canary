//! `canary-arch-x86` — x86/x64 instruction lifter.
//!
//! Uses Capstone for disassembly and maps x86_64 instructions to LLIL.

pub mod operand;
pub mod registers;

use canary_arch::{ArchLifter, LiftError, NativeInstr};
use canary_ir::cfg::{BlockId, ControlFlowGraph, EdgeKind};
use canary_ir::llil::{LlilDest, LlilExpr, LlilInstr, LlilOp, OperandSize};
use capstone::prelude::*;
use indexmap::IndexMap;
use std::collections::VecDeque;
use tracing::{debug, trace, warn};

pub fn lifter_confidence() -> canary_ir::types::ConfidenceTag {
    let mut c = canary_ir::types::ConfidenceTag::default();
    c.origin = "x86_lifter".to_string();
    c
}

/// x86_64 architecture lifter backed by Capstone.
pub struct X86_64Lifter {
    cs: Capstone,
}

impl X86_64Lifter {
    /// Creates a new x86_64 lifter.
    pub fn new() -> Result<Self, LiftError> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| LiftError::Disassembly {
                addr: 0,
                reason: e.to_string(),
            })?;
        Ok(Self { cs })
    }
}

impl Default for X86_64Lifter {
    fn default() -> Self {
        Self::new().expect("Capstone initialization failed")
    }
}

impl ArchLifter for X86_64Lifter {
    fn name(&self) -> &'static str {
        "x86_64"
    }

    fn supports(&self, arch_name: &str) -> bool {
        matches!(arch_name, "x86_64" | "x64" | "amd64")
    }

    fn disassemble(&self, bytes: &[u8], start_addr: u64) -> Result<Vec<NativeInstr>, LiftError> {
        let insns =
            self.cs
                .disasm_count(bytes, start_addr, 100)
                .map_err(|e| LiftError::Disassembly {
                    addr: start_addr,
                    reason: e.to_string(),
                })?;

        Ok(insns
            .iter()
            .map(|i| NativeInstr {
                addr: i.address(),
                bytes: i.bytes().to_vec(),
                mnemonic: i.mnemonic().unwrap_or("?").to_string(),
                op_str: i.op_str().unwrap_or("").to_string(),
            })
            .collect())
    }

    fn lift_instr(
        &self,
        instr: &NativeInstr,
        exprs: &mut canary_ir::arena::Arena<canary_ir::llil::LlilExpr>,
    ) -> Result<Vec<LlilInstr>, LiftError> {
        lift_x86_instr(self, instr, exprs)
    }

    fn build_cfg(
        &self,
        bytes: &[u8],
        start_addr: u64,
        entry_addr: u64,
    ) -> Result<ControlFlowGraph, LiftError> {
        build_cfg_x86(self, bytes, start_addr, entry_addr)
    }
}

/// Maps a byte size to an [`OperandSize`].
fn op_size(bytes: u8) -> OperandSize {
    match bytes {
        1 => OperandSize::Bits8,
        2 => OperandSize::Bits16,
        4 => OperandSize::Bits32,
        _ => OperandSize::Bits64,
    }
}

/// Lifter for x86_64 instructions.
///
/// Covers common instructions. Unrecognised instructions produce `LlilInstr::Undef`
/// so that CFG construction can continue past unknown encodings.
fn lift_x86_instr(
    lifter: &X86_64Lifter,
    instr: &NativeInstr,
    exprs: &mut canary_ir::arena::Arena<canary_ir::llil::LlilExpr>,
) -> Result<Vec<LlilInstr>, LiftError> {
    let mnem = instr.mnemonic.to_lowercase();
    let _size = op_size(instr.bytes.len() as u8);

    trace!("Lifting: {} {} @ {:#x}", mnem, instr.op_str, instr.addr);

    let cs_insns = lifter
        .cs
        .disasm_all(&instr.bytes, instr.addr)
        .map_err(|e| LiftError::Disassembly {
            addr: instr.addr,
            reason: e.to_string(),
        })?;
    let cs_insn = cs_insns.first().ok_or_else(|| LiftError::Disassembly {
        addr: instr.addr,
        reason: "No instructions disassembled".to_string(),
    })?;
    let detail = lifter
        .cs
        .insn_detail(cs_insn)
        .map_err(|e| LiftError::Disassembly {
            addr: instr.addr,
            reason: e.to_string(),
        })?;
    let arch_detail = detail.arch_detail();
    let x86_detail = arch_detail.x86().unwrap();
    let operands: Vec<_> = x86_detail.operands().collect();

    use crate::operand::{op_to_dest, op_to_expr};
    use canary_ir::llil::FlagCondition;

    match mnem.as_str() {
        // --- Moves ---
        "mov" | "movl" | "movq" | "movzx" | "movsx" | "movaps" | "movups" | "movdqa" | "movdqu"
        | "movss" | "movsd" => {
            if operands.len() >= 2 {
                let dest = op_to_dest(&operands[0], exprs)?;
                let expr = op_to_expr(&operands[1], exprs)?;
                Ok(vec![LlilInstr::Assign {
                    dest,
                    expr,
                    confidence: crate::lifter_confidence(),
                }])
            } else {
                Ok(vec![])
            }
        }

        "lea" | "leaq" => {
            if operands.len() >= 2 {
                let dest = op_to_dest(&operands[0], exprs)?;
                // LEA calculates the address of the memory operand
                if let capstone::arch::x86::X86OperandType::Mem(mem) = operands[1].op_type {
                    let addr_expr = crate::operand::mem_addr_expr(&mem, exprs);
                    Ok(vec![LlilInstr::Assign {
                        dest,
                        expr: addr_expr,
                        confidence: crate::lifter_confidence(),
                    }])
                } else {
                    Ok(vec![])
                }
            } else {
                Ok(vec![])
            }
        }

        // --- Arithmetic ---
        "add" | "addl" | "addq" => {
            if operands.len() >= 2 {
                let dest = op_to_dest(&operands[0], exprs)?;
                let lhs = op_to_expr(&operands[0], exprs)?;
                let rhs = op_to_expr(&operands[1], exprs)?;
                let sz = operand::op_size_from_bytes(operands[0].size);
                Ok(vec![
                    LlilInstr::Assign {
                        dest,
                        expr: LlilExpr::BinOp {
                            op: LlilOp::Add,
                            lhs: exprs.alloc(lhs.clone()),
                            rhs: exprs.alloc(rhs.clone()),
                            size: sz,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                    LlilInstr::SetFlags {
                        op: LlilOp::Add,
                        lhs,
                        rhs,
                        confidence: crate::lifter_confidence(),
                    },
                ])
            } else {
                Ok(vec![])
            }
        }

        "sub" | "subl" | "subq" => {
            if operands.len() >= 2 {
                let dest = op_to_dest(&operands[0], exprs)?;
                let lhs = op_to_expr(&operands[0], exprs)?;
                let rhs = op_to_expr(&operands[1], exprs)?;
                let sz = operand::op_size_from_bytes(operands[0].size);
                Ok(vec![
                    LlilInstr::Assign {
                        dest,
                        expr: LlilExpr::BinOp {
                            op: LlilOp::Sub,
                            lhs: exprs.alloc(lhs.clone()),
                            rhs: exprs.alloc(rhs.clone()),
                            size: sz,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                    LlilInstr::SetFlags {
                        op: LlilOp::Sub,
                        lhs,
                        rhs,
                        confidence: crate::lifter_confidence(),
                    },
                ])
            } else {
                Ok(vec![])
            }
        }

        // --- Bitwise & Shifts ---
        "and" | "andl" | "andq" | "or" | "orl" | "orq" | "xor" | "xorl" | "xorq" => {
            if operands.len() >= 2 {
                let dest = op_to_dest(&operands[0], exprs)?;
                let lhs = op_to_expr(&operands[0], exprs)?;
                let rhs = op_to_expr(&operands[1], exprs)?;
                let sz = operand::op_size_from_bytes(operands[0].size);
                let op = match mnem.as_str() {
                    "and" | "andl" | "andq" => LlilOp::And,
                    "or" | "orl" | "orq" => LlilOp::Or,
                    "xor" | "xorl" | "xorq" => LlilOp::Xor,
                    _ => LlilOp::And,
                };
                Ok(vec![
                    LlilInstr::Assign {
                        dest,
                        expr: LlilExpr::BinOp {
                            op,
                            lhs: exprs.alloc(lhs.clone()),
                            rhs: exprs.alloc(rhs.clone()),
                            size: sz,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                    LlilInstr::SetFlags {
                        op,
                        lhs,
                        rhs,
                        confidence: crate::lifter_confidence(),
                    },
                ])
            } else {
                Ok(vec![])
            }
        }

        "shl" | "shll" | "shlq" | "sal" | "sall" | "salq" | "shr" | "shrl" | "shrq" | "sar"
        | "sarl" | "sarq" => {
            if operands.len() >= 2 {
                let dest = op_to_dest(&operands[0], exprs)?;
                let lhs = op_to_expr(&operands[0], exprs)?;
                let rhs = op_to_expr(&operands[1], exprs)?;
                let sz = operand::op_size_from_bytes(operands[0].size);
                let op = match mnem.as_str() {
                    "shl" | "shll" | "shlq" | "sal" | "sall" | "salq" => LlilOp::Lsl,
                    "shr" | "shrl" | "shrq" => LlilOp::Lsr,
                    "sar" | "sarl" | "sarq" => LlilOp::Asr,
                    _ => LlilOp::Lsl,
                };
                Ok(vec![
                    LlilInstr::Assign {
                        dest,
                        expr: LlilExpr::BinOp {
                            op,
                            lhs: exprs.alloc(lhs.clone()),
                            rhs: exprs.alloc(rhs.clone()),
                            size: sz,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                    LlilInstr::SetFlags {
                        op,
                        lhs,
                        rhs,
                        confidence: crate::lifter_confidence(),
                    },
                ])
            } else {
                Ok(vec![])
            }
        }

        // --- Stack Operations ---
        "push" | "pushq" => {
            if operands.len() >= 1 {
                let expr = op_to_expr(&operands[0], exprs)?;
                let sz = operand::op_size_from_bytes(operands[0].size);
                use crate::registers::RSP;
                let rsp = LlilExpr::Reg {
                    reg: RSP,
                    size: OperandSize::Bits64,
                };
                let eight = LlilExpr::Const {
                    value: 8,
                    size: OperandSize::Bits64,
                };
                Ok(vec![
                    LlilInstr::Assign {
                        dest: LlilDest::Reg(RSP),
                        expr: LlilExpr::BinOp {
                            op: LlilOp::Sub,
                            lhs: exprs.alloc(rsp.clone()),
                            rhs: exprs.alloc(eight),
                            size: OperandSize::Bits64,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                    LlilInstr::Store {
                        addr: LlilExpr::BinOp {
                            op: LlilOp::Sub,
                            lhs: exprs.alloc(rsp),
                            rhs: exprs.alloc(LlilExpr::Const {
                                value: 8,
                                size: OperandSize::Bits64,
                            }),
                            size: OperandSize::Bits64,
                        },
                        value: expr,
                        size: sz,
                        confidence: crate::lifter_confidence(),
                    },
                ])
            } else {
                Ok(vec![])
            }
        }

        "pop" | "popq" => {
            if operands.len() >= 1 {
                let dest = op_to_dest(&operands[0], exprs)?;
                let sz = operand::op_size_from_bytes(operands[0].size);
                use crate::registers::RSP;
                let rsp = LlilExpr::Reg {
                    reg: RSP,
                    size: OperandSize::Bits64,
                };
                let eight = LlilExpr::Const {
                    value: 8,
                    size: OperandSize::Bits64,
                };
                Ok(vec![
                    LlilInstr::Assign {
                        dest,
                        expr: LlilExpr::Load {
                            addr: exprs.alloc(rsp.clone()),
                            size: sz,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                    LlilInstr::Assign {
                        dest: LlilDest::Reg(RSP),
                        expr: LlilExpr::BinOp {
                            op: LlilOp::Add,
                            lhs: exprs.alloc(rsp),
                            rhs: exprs.alloc(eight),
                            size: OperandSize::Bits64,
                        },
                        confidence: crate::lifter_confidence(),
                    },
                ])
            } else {
                Ok(vec![])
            }
        }

        "cmp" | "cmpl" | "cmpq" => {
            if operands.len() >= 2 {
                let lhs = op_to_expr(&operands[0], exprs)?;
                let rhs = op_to_expr(&operands[1], exprs)?;
                // CMP sets all flags based on lhs - rhs (signed/unsigned comparisons all valid)
                Ok(vec![LlilInstr::SetFlags {
                    op: LlilOp::Sub,
                    lhs,
                    rhs,
                    confidence: crate::lifter_confidence(),
                }])
            } else {
                Ok(vec![])
            }
        }

        "test" | "testl" | "testq" => {
            if operands.len() >= 2 {
                let lhs = op_to_expr(&operands[0], exprs)?;
                let rhs = op_to_expr(&operands[1], exprs)?;
                // TEST sets ZF/SF/PF based on lhs & rhs; no carry/overflow
                Ok(vec![LlilInstr::SetFlags {
                    op: LlilOp::And,
                    lhs,
                    rhs,
                    confidence: crate::lifter_confidence(),
                }])
            } else {
                Ok(vec![])
            }
        }

        // --- Control flow ---
        "jmp" | "jmpq" => {
            if let Some(op) = operands.first() {
                if let capstone::arch::x86::X86OperandType::Imm(imm) = op.op_type {
                    Ok(vec![LlilInstr::Goto {
                        target: imm as u64,
                        confidence: crate::lifter_confidence(),
                    }])
                } else {
                    // Indirect jump: emit an If with the register/memory target as a
                    // computed address so CFG edges can be approximated.
                    let target_expr = op_to_expr(op, exprs)?;
                    // Represent as a call to an indirect target with no return
                    // (best-effort: we cannot statically enumerate all targets here)
                    Ok(vec![LlilInstr::Call {
                        target: target_expr,
                        args: vec![],
                        ret: None,
                        confidence: crate::lifter_confidence(),
                    }])
                }
            } else {
                Ok(vec![])
            }
        }

        "je" | "jz" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::Equal,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        "jne" | "jnz" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::NotEqual,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        // jb / jc = unsigned below (CF=1), NOT signed less-than
        "jl" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::Less,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        "jb" | "jc" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::Below,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        "jle" | "jbe" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::LessEq,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        "jg" | "ja" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::Greater,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        "jge" | "jae" => Ok(vec![LlilInstr::If {
            cond: LlilExpr::FlagCond {
                cond: FlagCondition::GreaterEq,
            },
            true_target: parse_hex_target(&instr.op_str).unwrap_or(0),
            false_target: instr.addr + instr.bytes.len() as u64,
            confidence: crate::lifter_confidence(),
        }]),

        "ret" | "retq" => Ok(vec![LlilInstr::Return {
            value: None,
            confidence: crate::lifter_confidence(),
        }]),

        "call" | "callq" => {
            if let Some(op) = operands.first() {
                // Collect SysV AMD64 integer argument registers: rdi(5), rsi(4), rdx(3), rcx(2), r8(8), r9(9)
                // We record them as input expressions so the call site captures the live regs.
                use canary_ir::llil::Reg;
                let arg_regs = [5u32, 4, 3, 2, 8, 9]; // rdi, rsi, rdx, rcx, r8, r9
                let args: Vec<LlilExpr> = arg_regs
                    .iter()
                    .map(|&r| LlilExpr::Reg {
                        reg: Reg(r),
                        size: OperandSize::Bits64,
                    })
                    .collect();
                // Return value goes into rax (reg 0)
                let ret = Some(Reg(0));

                if let capstone::arch::x86::X86OperandType::Imm(imm) = op.op_type {
                    Ok(vec![LlilInstr::Call {
                        target: LlilExpr::Const {
                            value: imm as u64,
                            size: OperandSize::Bits64,
                        },
                        args,
                        ret,
                        confidence: crate::lifter_confidence(),
                    }])
                } else {
                    let target = op_to_expr(op, exprs)?;
                    Ok(vec![LlilInstr::Call {
                        target,
                        args,
                        ret,
                        confidence: crate::lifter_confidence(),
                    }])
                }
            } else {
                Ok(vec![])
            }
        }

        "nop" => Ok(vec![]),
        "int3" | "ud2" => Ok(vec![LlilInstr::Trap {
            confidence: crate::lifter_confidence(),
        }]),

        _ => {
            trace!("Unlifted instruction: {} {}", instr.mnemonic, instr.op_str);
            Ok(vec![LlilInstr::Undef {
                bytes: instr.bytes.clone(),
                confidence: crate::lifter_confidence(),
            }])
        }
    }
}

/// Parses a hex literal like `0x401000` or `401000` from an operand string.
fn parse_hex_target(op: &str) -> Option<u64> {
    let trimmed = op.trim().trim_start_matches("0x");
    u64::from_str_radix(trimmed, 16).ok()
}

/// Builds a CFG for a function starting at `entry_addr` using recursive descent.
fn build_cfg_x86(
    lifter: &X86_64Lifter,
    bytes: &[u8],
    start_addr: u64,
    entry_addr: u64,
) -> Result<ControlFlowGraph, LiftError> {
    let mut cfg = ControlFlowGraph::new();

    // Map from instruction address to the BlockId of the block containing it
    let mut instr_to_block: IndexMap<u64, BlockId> = indexmap::IndexMap::new();
    // Work queue of entry addresses to process
    let mut queue: VecDeque<u64> = VecDeque::new();

    queue.push_back(entry_addr);

    while let Some(block_entry) = queue.pop_front() {
        // If this address is already disassembled, check if it's a block start
        if let Some(&existing_block_id) = instr_to_block.get(&block_entry) {
            let start_addr = cfg.block(existing_block_id).unwrap().start_addr;
            if start_addr == block_entry {
                // Already a block start, nothing to do
                continue;
            } else {
                // Strictly inside existing_block_id, so split it!
                let new_block_id =
                    cfg.split_block(existing_block_id, block_entry)
                        .map_err(|e| LiftError::Disassembly {
                            addr: block_entry,
                            reason: e,
                        })?;
                // Update instr_to_block mapping for the moved instructions
                let moved_addrs = cfg.block(new_block_id).unwrap().instr_addrs.clone();
                for addr in moved_addrs {
                    instr_to_block.insert(addr, new_block_id);
                }
                continue;
            }
        }

        // Check address is within our bytes range
        if block_entry < start_addr {
            debug!("Skipping out-of-range address {block_entry:#x}");
            continue;
        }
        let offset = (block_entry - start_addr) as usize;
        if offset >= bytes.len() {
            debug!("Skipping OOB address {block_entry:#x}");
            continue;
        }

        // Allocate a new block
        let block_id = cfg.alloc_block(block_entry);
        if cfg.entry().is_none() && block_entry == entry_addr {
            cfg.set_entry(block_id);
        }

        // Disassemble from block_entry
        let chunk = &bytes[offset..];
        let insns = lifter.disassemble(chunk, block_entry)?;

        if insns.is_empty() {
            debug!("Failed to disassemble at {block_entry:#x}");
            let block = cfg.block_mut(block_id).unwrap();
            block.instrs.push(LlilInstr::Trap {
                confidence: crate::lifter_confidence(),
            });
            block.end_addr = block_entry + 1; // Advance by 1 byte to prevent infinite loop
            instr_to_block.insert(block_entry, block_id);
            continue;
        }

        let mut successors: Vec<(u64, EdgeKind)> = Vec::new();
        let mut stopped = false;

        for native in &insns {
            // Check if this instruction address is already in instr_to_block (overlap/merge)
            if let Some(&overlap_block_id) = instr_to_block.get(&native.addr) {
                // We reached an already disassembled instruction!
                // We must terminate the current block here, fall through to the overlap block, and stop.
                let start_addr = cfg.block(overlap_block_id).unwrap().start_addr;
                if start_addr != native.addr {
                    // Split the overlap block at native.addr
                    let new_id = cfg
                        .split_block(overlap_block_id, native.addr)
                        .map_err(|e| LiftError::Disassembly {
                            addr: native.addr,
                            reason: e,
                        })?;
                    let moved_addrs = cfg.block(new_id).unwrap().instr_addrs.clone();
                    for addr in moved_addrs {
                        instr_to_block.insert(addr, new_id);
                    }
                }

                stopped = true;
                break;
            }

            // Lift the instruction
            let lifted = lift_x86_instr(lifter, native, &mut cfg.exprs)?;
            let is_term = lifted.iter().any(|i| i.is_terminator());

            // Add instructions to the block
            let block = cfg.block_mut(block_id).unwrap();
            let lifted_len = lifted.len();
            block.instrs.extend(lifted);
            block
                .instr_addrs
                .resize(block.instr_addrs.len() + lifted_len, native.addr);
            block.end_addr = native.addr + native.bytes.len() as u64;

            // Register this instruction in our map
            instr_to_block.insert(native.addr, block_id);

            if is_term {
                // Determine successors from the terminator
                let block = cfg.block(block_id).unwrap();
                for instr in block.instrs.iter().rev() {
                    match instr {
                        LlilInstr::Goto { target, .. } => {
                            successors.push((*target, EdgeKind::Unconditional));
                            queue.push_back(*target);
                        }
                        LlilInstr::If {
                            true_target,
                            false_target,
                            ..
                        } => {
                            successors.push((*true_target, EdgeKind::True));
                            successors.push((*false_target, EdgeKind::False));
                            queue.push_back(*true_target);
                            queue.push_back(*false_target);
                        }
                        LlilInstr::Return { .. } | LlilInstr::Trap { .. } => {}
                        _ => continue,
                    }
                    break;
                }
                stopped = true;
                break;
            }
        }

        if !stopped {
            // If we ran out of instructions without hitting a terminator (e.g. end of function bytes),
            // it falls through to the next address.
            let block = cfg.block(block_id).unwrap();
            let fallthrough_addr = block.end_addr;
            queue.push_back(fallthrough_addr);
        }
    }

    // Pass 2: Wire edges
    // Collect all block IDs first to avoid borrowing issues while mutating the CFG
    let block_ids: Vec<BlockId> = cfg.blocks().map(|b| b.id).collect();

    for block_id in block_ids {
        let (terminator, end_addr) = {
            let block = cfg.block(block_id).unwrap();
            (block.terminator().cloned(), block.end_addr)
        };

        if let Some(term) = terminator {
            match term {
                LlilInstr::Goto { target, .. } => {
                    if let Some(&target_block_id) = instr_to_block.get(&target) {
                        let target_start = cfg.block(target_block_id).unwrap().start_addr;
                        let final_id = if target_start == target {
                            target_block_id
                        } else {
                            let new_id = cfg.split_block(target_block_id, target).map_err(|e| {
                                LiftError::Disassembly {
                                    addr: target,
                                    reason: e,
                                }
                            })?;
                            let moved_addrs = cfg.block(new_id).unwrap().instr_addrs.clone();
                            for addr in moved_addrs {
                                instr_to_block.insert(addr, new_id);
                            }
                            new_id
                        };
                        cfg.add_edge(block_id, final_id, EdgeKind::Unconditional);
                    }
                }
                LlilInstr::If {
                    true_target,
                    false_target,
                    ..
                } => {
                    // True branch
                    if let Some(&target_block_id) = instr_to_block.get(&true_target) {
                        let target_start = cfg.block(target_block_id).unwrap().start_addr;
                        let final_id = if target_start == true_target {
                            target_block_id
                        } else {
                            let new_id =
                                cfg.split_block(target_block_id, true_target).map_err(|e| {
                                    LiftError::Disassembly {
                                        addr: true_target,
                                        reason: e,
                                    }
                                })?;
                            let moved_addrs = cfg.block(new_id).unwrap().instr_addrs.clone();
                            for addr in moved_addrs {
                                instr_to_block.insert(addr, new_id);
                            }
                            new_id
                        };
                        cfg.add_edge(block_id, final_id, EdgeKind::True);
                    }
                    // False branch
                    if let Some(&target_block_id) = instr_to_block.get(&false_target) {
                        let target_start = cfg.block(target_block_id).unwrap().start_addr;
                        let final_id = if target_start == false_target {
                            target_block_id
                        } else {
                            let new_id =
                                cfg.split_block(target_block_id, false_target)
                                    .map_err(|e| LiftError::Disassembly {
                                        addr: false_target,
                                        reason: e,
                                    })?;
                            let moved_addrs = cfg.block(new_id).unwrap().instr_addrs.clone();
                            for addr in moved_addrs {
                                instr_to_block.insert(addr, new_id);
                            }
                            new_id
                        };
                        cfg.add_edge(block_id, final_id, EdgeKind::False);
                    }
                }
                _ => {}
            }
        } else {
            // Fall-through to end_addr
            if let Some(&target_block_id) = instr_to_block.get(&end_addr) {
                let target_start = cfg.block(target_block_id).unwrap().start_addr;
                let final_id = if target_start == end_addr {
                    target_block_id
                } else {
                    let new_id = cfg.split_block(target_block_id, end_addr).map_err(|e| {
                        LiftError::Disassembly {
                            addr: end_addr,
                            reason: e,
                        }
                    })?;
                    let moved_addrs = cfg.block(new_id).unwrap().instr_addrs.clone();
                    for addr in moved_addrs {
                        instr_to_block.insert(addr, new_id);
                    }
                    new_id
                };
                cfg.add_edge(block_id, final_id, EdgeKind::Unconditional);
            }
        }
    }

    debug!("Built CFG with {} blocks", cfg.block_count());
    Ok(cfg)
}

/// Factory for creating `X86_64Lifter` instances.
pub struct X86_64LifterFactory;

impl canary_arch::ArchLifterFactory for X86_64LifterFactory {
    fn create(&self) -> Box<dyn canary_arch::ArchLifter> {
        Box::new(X86_64Lifter::new().expect("Failed to initialize X86_64Lifter"))
    }

    fn supports(&self, arch_name: &str) -> bool {
        matches!(arch_name, "x86_64" | "x64" | "amd64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::arena::Arena;
    use canary_ir::llil::*;

    fn lift_bytes(bytes: &[u8]) -> (Vec<LlilInstr>, Arena<LlilExpr>) {
        let lifter = X86_64Lifter::new().unwrap();
        let insns = lifter.disassemble(bytes, 0x1000).unwrap();
        let mut exprs = Arena::new();
        let instrs = lifter.lift_instr(&insns[0], &mut exprs).unwrap();
        (instrs, exprs)
    }

    #[test]
    fn test_lift_mov_reg_imm() {
        // mov eax, 42 -> b8 2a 00 00 00
        let (llil, _exprs) = lift_bytes(&[0xb8, 0x2a, 0x00, 0x00, 0x00]);
        assert_eq!(llil.len(), 1);
        if let LlilInstr::Assign {
            dest,
            expr,
            confidence: _,
        } = &llil[0]
        {
            assert_eq!(dest, &LlilDest::Reg(crate::registers::RAX));
            assert_eq!(
                expr,
                &LlilExpr::Const {
                    value: 42,
                    size: OperandSize::Bits32
                }
            );
        } else {
            panic!("Expected Assign");
        }
    }

    #[test]
    fn test_lift_add_reg_reg() {
        // add eax, ebx -> 01 d8
        // Should emit: [Assign(eax = eax + ebx), SetFlags(Add, eax, ebx)]
        let (llil, exprs) = lift_bytes(&[0x01, 0xd8]);
        assert_eq!(llil.len(), 2, "add must emit Assign + SetFlags");
        // First instruction: the assignment
        if let LlilInstr::Assign {
            dest,
            expr,
            confidence: _,
        } = &llil[0]
        {
            assert_eq!(dest, &LlilDest::Reg(crate::registers::RAX));
            if let LlilExpr::BinOp { op, lhs, rhs, size } = expr {
                assert_eq!(op, &LlilOp::Add);
                assert_eq!(
                    exprs.get(*lhs).unwrap(),
                    &LlilExpr::Reg {
                        reg: crate::registers::RAX,
                        size: OperandSize::Bits32
                    }
                );
                assert_eq!(
                    exprs.get(*rhs).unwrap(),
                    &LlilExpr::Reg {
                        reg: crate::registers::RBX,
                        size: OperandSize::Bits32
                    }
                );
                assert_eq!(size, &OperandSize::Bits32);
            } else {
                panic!("Expected BinOp Add");
            }
        } else {
            panic!("Expected Assign");
        }
        // Second instruction: flag update
        assert!(
            matches!(
                &llil[1],
                LlilInstr::SetFlags {
                    op: LlilOp::Add,
                    ..
                }
            ),
            "Expected SetFlags(Add, ..) for add instruction"
        );
    }

    #[test]
    fn test_lift_sub_reg_imm() {
        // sub rsp, 0x20 -> 48 83 ec 20
        // Should emit: [Assign(rsp = rsp - 0x20), SetFlags(Sub, rsp, 0x20)]
        let (llil, exprs) = lift_bytes(&[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(llil.len(), 2, "sub must emit Assign + SetFlags");
        // First instruction: the assignment
        if let LlilInstr::Assign {
            dest,
            expr,
            confidence: _,
        } = &llil[0]
        {
            assert_eq!(dest, &LlilDest::Reg(crate::registers::RSP));
            if let LlilExpr::BinOp { op, lhs, rhs, size } = expr {
                assert_eq!(op, &LlilOp::Sub);
                assert_eq!(
                    exprs.get(*lhs).unwrap(),
                    &LlilExpr::Reg {
                        reg: crate::registers::RSP,
                        size: OperandSize::Bits64
                    }
                );
                assert_eq!(
                    exprs.get(*rhs).unwrap(),
                    &LlilExpr::Const {
                        value: 0x20,
                        size: OperandSize::Bits64
                    }
                );
                assert_eq!(size, &OperandSize::Bits64);
            } else {
                panic!("Expected BinOp Sub");
            }
        } else {
            panic!("Expected Assign");
        }
        // Second instruction: flag update
        assert!(
            matches!(
                &llil[1],
                LlilInstr::SetFlags {
                    op: LlilOp::Sub,
                    ..
                }
            ),
            "Expected SetFlags(Sub, ..) for sub instruction"
        );
    }

    #[test]
    fn test_lift_jmp() {
        // jmp 0x1020 -> eb 1e
        let (llil, _exprs) = lift_bytes(&[0xeb, 0x1e]);
        assert_eq!(llil.len(), 1);
        if let LlilInstr::Goto {
            target,
            confidence: _,
        } = &llil[0]
        {
            assert_eq!(*target, 0x1020);
        } else {
            panic!("Expected Goto");
        }
    }

    #[test]
    fn test_cfg_construction_and_splitting() {
        let lifter = X86_64Lifter::new().unwrap();
        // b8 01 00 00 00: mov eax, 1  (5 bytes, start 0x1000)
        // 3d 02 00 00 00: cmp eax, 2  (5 bytes, start 0x1005)
        // 75 f9:          jne 0x1005  (2 bytes, start 0x100a)
        // c3:             ret         (1 byte,  start 0x100c)
        let bytes = vec![
            0xb8, 0x01, 0x00, 0x00, 0x00, 0x3d, 0x02, 0x00, 0x00, 0x00, 0x75, 0xf9, 0xc3,
        ];

        let mut cfg = lifter
            .build_cfg(&bytes, 0x1000, 0x1000)
            .expect("should build CFG");

        assert_eq!(cfg.block_count(), 3, "Expected 3 blocks after splitting");

        // Find block starting at 0x1000
        let b1 = cfg
            .blocks()
            .find(|b| b.start_addr == 0x1000)
            .expect("b1 not found");
        assert_eq!(b1.end_addr, 0x1005);

        // Find block starting at 0x1005
        let b2 = cfg
            .blocks()
            .find(|b| b.start_addr == 0x1005)
            .expect("b2 not found");
        assert_eq!(b2.end_addr, 0x100c);

        // Find block starting at 0x100c
        let b3 = cfg
            .blocks()
            .find(|b| b.start_addr == 0x100c)
            .expect("b3 not found");
        assert_eq!(b3.end_addr, 0x100d);

        // Check validation
        let val_errors = canary_ir::cfg::cfg_validate(&cfg);
        assert!(
            val_errors.is_empty(),
            "CFG should be valid: {:?}",
            val_errors
        );

        // Check edge wiring
        // b1 should have an unconditional edge to b2
        assert_eq!(b1.successors.len(), 1);
        assert_eq!(b1.successors[0].target, b2.id);
        assert_eq!(b1.successors[0].kind, EdgeKind::Unconditional);

        // b2 should have true edge to b2 (loop) and false edge to b3 (fallthrough)
        assert_eq!(b2.successors.len(), 2);
        let true_edge = b2
            .successors
            .iter()
            .find(|e| e.kind == EdgeKind::True)
            .expect("no True edge");
        let false_edge = b2
            .successors
            .iter()
            .find(|e| e.kind == EdgeKind::False)
            .expect("no False edge");
        assert_eq!(true_edge.target, b2.id);
        assert_eq!(false_edge.target, b3.id);

        // b3 should be ret, so 0 successors
        assert_eq!(b3.successors.len(), 0);

        // Extract b2.id before calling mark_back_edges
        let b2_id = b2.id;

        // Test back-edge detection
        let dom_info =
            canary_analysis::dominators::compute_dominators(&cfg).expect("dominators compute");

        canary_analysis::dominators::mark_back_edges(&mut cfg, &dom_info);

        let b2_mut = cfg.block(b2_id).unwrap();
        let loop_edge = b2_mut
            .successors
            .iter()
            .find(|e| e.target == b2_id)
            .unwrap();
        assert_eq!(
            loop_edge.kind,
            EdgeKind::Back,
            "Loop edge should be marked as Back edge"
        );
    }
}
