//! Function representation.
//!
//! A [`Function`] owns its [`ControlFlowGraph`] and associated metadata.
//! Functions are stored in a workspace-level arena indexed by [`FunctionId`].

use crate::arena::{Arena, NodeId};
use crate::cfg::ControlFlowGraph;

/// A stable identifier for a [`Function`] in the workspace.
pub type FunctionId = NodeId<Function>;

/// A function recovered from the binary.
#[derive(Debug)]
pub struct Function {
    /// Address of the function entry point.
    pub entry_addr: u64,
    /// Inferred or user-provided name. Initially synthetic (e.g., `sub_401000`).
    pub name: String,
    /// The control flow graph for this function.
    pub cfg: ControlFlowGraph,
    /// The Static Single Assignment form of the function.
    pub ssa: Option<crate::ssa::SsaFunction>,
    /// Semantic IR retained after semantic lowering.
    pub semantic: Option<crate::semantic::SemanticFunction>,
    /// Mid-level IR retained after MLIL lowering.
    pub mlil: Option<crate::mlil::MlilFunction>,
    /// Whether this function has been fully lifted to LLIL.
    pub is_lifted: bool,
}

impl Function {
    /// Creates a new function with a synthetic name.
    pub fn new(entry_addr: u64) -> Self {
        Self {
            entry_addr,
            name: format!("sub_{entry_addr:x}"),
            cfg: ControlFlowGraph::new(),
            ssa: None,
            semantic: None,
            mlil: None,
            is_lifted: false,
        }
    }
}

/// An arena for storing all [`Function`] nodes in the workspace.
pub type FunctionArena = Arena<Function>;
