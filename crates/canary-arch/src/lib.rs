//! `canary-arch` — Architecture-agnostic lifting traits.
//!
//! This crate defines the interface that all architecture implementations must fulfill.
//! Concrete implementations (e.g., `canary-arch-x86`) depend on this crate.

use canary_ir::cfg::ControlFlowGraph;
use canary_ir::llil::LlilInstr;
use thiserror::Error;

/// Errors from the lifting process.
#[derive(Debug, Error)]
pub enum LiftError {
    #[error("Disassembly failed at address {addr:#x}: {reason}")]
    Disassembly { addr: u64, reason: String },

    #[error("Instruction not supported: {mnemonic}")]
    Unsupported { mnemonic: String },

    #[error("Bytes too short at address {addr:#x}")]
    TooShort { addr: u64 },
}

/// A single disassembled native instruction before lifting.
#[derive(Debug, Clone)]
pub struct NativeInstr {
    /// Virtual address of this instruction.
    pub addr: u64,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic string (for display and error reporting).
    pub mnemonic: String,
    /// Operand string (for display).
    pub op_str: String,
}

/// The result of lifting a single native instruction.
#[derive(Debug)]
pub struct LiftedInstr {
    pub source: NativeInstr,
    /// LLIL instructions produced by lifting `source`.
    /// Most instructions produce 1–3 LLIL operations.
    pub llil: Vec<LlilInstr>,
}

/// Trait implemented by each architecture's lifter.
///
/// A lifter takes raw bytes at a given address and produces LLIL.
/// It also drives basic block discovery for CFG construction.
///
/// # Threading
///
/// Lifters are **not** required to be `Send + Sync`. For parallel function
/// analysis, each worker thread should construct its own lifter instance.
/// Lifters are cheap to construct (primarily wrapping a disassembler engine).
pub trait ArchLifter {
    /// The canonical name of this architecture (e.g., `"x86_64"`, `"aarch64"`).
    fn name(&self) -> &'static str;

    /// Returns `true` if this lifter can handle binaries with the given arch name.
    fn supports(&self, arch_name: &str) -> bool;

    /// Disassembles `bytes` starting at `start_addr`.
    ///
    /// Returns a list of [`NativeInstr`] in order.
    fn disassemble(&self, bytes: &[u8], start_addr: u64) -> Result<Vec<NativeInstr>, LiftError>;

    /// Lifts a single [`NativeInstr`] to a sequence of LLIL instructions.
    fn lift_instr(
        &self,
        instr: &NativeInstr,
        exprs: &mut canary_ir::arena::Arena<canary_ir::llil::LlilExpr>,
    ) -> Result<Vec<LlilInstr>, LiftError>;

    /// Builds a complete [`ControlFlowGraph`] from `bytes` starting at `entry_addr`.
    ///
    /// The default implementation uses recursive descent from `entry_addr`.
    /// Architecture-specific implementations may override for better accuracy.
    fn build_cfg(
        &self,
        bytes: &[u8],
        start_addr: u64,
        entry_addr: u64,
    ) -> Result<ControlFlowGraph, LiftError> {
        let _ = (bytes, start_addr, entry_addr); // suppress warnings in default stub
        unimplemented!("build_cfg must be implemented by the architecture lifter")
    }
}

/// Factory trait for creating architecture lifters.
pub trait ArchLifterFactory: Send + Sync {
    /// Creates a new instance of the architecture lifter.
    fn create(&self) -> Box<dyn ArchLifter>;

    /// Returns `true` if this factory supports the given architecture name.
    fn supports(&self, arch_name: &str) -> bool;
}
