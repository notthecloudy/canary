//! `canary-emit` — Language emitter trait and built-in emitters.
//!
//! Emitters are **visitors over the Intent Graph**. They consume the highest
//! available dialect in the IR and produce source code in a target language.
//!
//! # Emitter Design
//!
//! Each emitter implements the [`Emitter`] trait. Emitters must handle all
//! IR nodes — falling back to lower-dialect representations if a high-level
//! construct is not representable in the target language.

pub mod c;
pub mod error;
pub mod mlil_c;
pub mod xaml;

pub use c::CEmitter;
pub use error::EmitError;
pub use mlil_c::MlilCEmitter;
pub use xaml::{XamlElement, XamlSynthesizer};

use canary_ir::function::Function;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitMode {
    Raw,
    Annotated,
    Recovered,
}

/// Context passed to an emitter during source generation.
pub struct EmitContext<'a> {
    pub function: &'a Function,
    pub mlil: Option<&'a canary_ir::mlil::MlilFunction>,
    pub hl_cf: Option<&'a canary_analysis::structuring::HighLevelControlFlow>,
    pub symbol_resolver: Option<&'a dyn Fn(u64) -> Option<String>>,
    pub sdb_func: Option<&'a canary_sdb::SdbFunction>,
    pub mode: EmitMode,
}

/// The output of an emitter: a string of source code.
pub type EmitOutput = String;

/// Trait implemented by all language emitters.
pub trait Emitter {
    /// The name of the target language (e.g., `"c"`, `"rust"`, `"go"`).
    fn language(&self) -> &'static str;

    /// Emits source code for a single function.
    ///
    /// Returns a string containing the complete source representation of
    /// `ctx.function` in the target language.
    fn emit_function(&self, ctx: &EmitContext<'_>) -> Result<EmitOutput, EmitError>;
}
