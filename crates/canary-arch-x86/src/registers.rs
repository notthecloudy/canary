use canary_ir::llil::{OperandSize, Reg};
use capstone::arch::x86::X86Reg;

pub const RAX: Reg = Reg(0);
pub const RBX: Reg = Reg(1);
pub const RCX: Reg = Reg(2);
pub const RDX: Reg = Reg(3);
pub const RSI: Reg = Reg(4);
pub const RDI: Reg = Reg(5);
pub const RBP: Reg = Reg(6);
pub const RSP: Reg = Reg(7);
pub const R8: Reg = Reg(8);
pub const R9: Reg = Reg(9);
pub const R10: Reg = Reg(10);
pub const R11: Reg = Reg(11);
pub const R12: Reg = Reg(12);
pub const R13: Reg = Reg(13);
pub const R14: Reg = Reg(14);
pub const R15: Reg = Reg(15);
pub const RIP: Reg = Reg(16);
pub const XMM0: Reg = Reg(17);
pub const XMM1: Reg = Reg(18);
pub const XMM2: Reg = Reg(19);
pub const XMM3: Reg = Reg(20);
pub const XMM4: Reg = Reg(21);
pub const XMM5: Reg = Reg(22);
pub const XMM6: Reg = Reg(23);
pub const XMM7: Reg = Reg(24);
pub const EFLAGS: Reg = Reg(25);
/// Returns the virtual register ID and its size in bits.
pub fn capstone_reg_to_id_and_size(reg: capstone::RegId) -> Option<(Reg, OperandSize)> {
    let x86_reg: u16 = reg.0;

    // We match on the u16 value of the enum variants
    if x86_reg == X86Reg::X86_REG_AL as u16 {
        return Some((RAX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_AH as u16 {
        return Some((RAX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_AX as u16 {
        return Some((RAX, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_EAX as u16 {
        return Some((RAX, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RAX as u16 {
        return Some((RAX, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_BL as u16 {
        return Some((RBX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_BH as u16 {
        return Some((RBX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_BX as u16 {
        return Some((RBX, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_EBX as u16 {
        return Some((RBX, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RBX as u16 {
        return Some((RBX, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_CL as u16 {
        return Some((RCX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_CH as u16 {
        return Some((RCX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_CX as u16 {
        return Some((RCX, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_ECX as u16 {
        return Some((RCX, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RCX as u16 {
        return Some((RCX, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_DL as u16 {
        return Some((RDX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_DH as u16 {
        return Some((RDX, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_DX as u16 {
        return Some((RDX, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_EDX as u16 {
        return Some((RDX, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RDX as u16 {
        return Some((RDX, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_SIL as u16 {
        return Some((RSI, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_SI as u16 {
        return Some((RSI, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_ESI as u16 {
        return Some((RSI, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RSI as u16 {
        return Some((RSI, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_DIL as u16 {
        return Some((RDI, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_DI as u16 {
        return Some((RDI, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_EDI as u16 {
        return Some((RDI, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RDI as u16 {
        return Some((RDI, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_BPL as u16 {
        return Some((RBP, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_BP as u16 {
        return Some((RBP, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_EBP as u16 {
        return Some((RBP, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RBP as u16 {
        return Some((RBP, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_SPL as u16 {
        return Some((RSP, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_SP as u16 {
        return Some((RSP, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_ESP as u16 {
        return Some((RSP, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_RSP as u16 {
        return Some((RSP, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R8B as u16 {
        return Some((R8, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R8W as u16 {
        return Some((R8, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R8D as u16 {
        return Some((R8, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R8 as u16 {
        return Some((R8, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R9B as u16 {
        return Some((R9, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R9W as u16 {
        return Some((R9, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R9D as u16 {
        return Some((R9, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R9 as u16 {
        return Some((R9, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R10B as u16 {
        return Some((R10, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R10W as u16 {
        return Some((R10, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R10D as u16 {
        return Some((R10, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R10 as u16 {
        return Some((R10, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R11B as u16 {
        return Some((R11, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R11W as u16 {
        return Some((R11, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R11D as u16 {
        return Some((R11, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R11 as u16 {
        return Some((R11, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R12B as u16 {
        return Some((R12, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R12W as u16 {
        return Some((R12, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R12D as u16 {
        return Some((R12, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R12 as u16 {
        return Some((R12, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R13B as u16 {
        return Some((R13, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R13W as u16 {
        return Some((R13, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R13D as u16 {
        return Some((R13, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R13 as u16 {
        return Some((R13, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R14B as u16 {
        return Some((R14, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R14W as u16 {
        return Some((R14, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R14D as u16 {
        return Some((R14, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R14 as u16 {
        return Some((R14, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_R15B as u16 {
        return Some((R15, OperandSize::Bits8));
    }
    if x86_reg == X86Reg::X86_REG_R15W as u16 {
        return Some((R15, OperandSize::Bits16));
    }
    if x86_reg == X86Reg::X86_REG_R15D as u16 {
        return Some((R15, OperandSize::Bits32));
    }
    if x86_reg == X86Reg::X86_REG_R15 as u16 {
        return Some((R15, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_RIP as u16 {
        return Some((RIP, OperandSize::Bits64));
    }

    if x86_reg == X86Reg::X86_REG_XMM0 as u16 {
        return Some((XMM0, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM1 as u16 {
        return Some((XMM1, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM2 as u16 {
        return Some((XMM2, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM3 as u16 {
        return Some((XMM3, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM4 as u16 {
        return Some((XMM4, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM5 as u16 {
        return Some((XMM5, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM6 as u16 {
        return Some((XMM6, OperandSize::Bits128));
    }
    if x86_reg == X86Reg::X86_REG_XMM7 as u16 {
        return Some((XMM7, OperandSize::Bits128));
    }

    if x86_reg == X86Reg::X86_REG_EFLAGS as u16 {
        return Some((EFLAGS, OperandSize::Bits32));
    }

    None
}
