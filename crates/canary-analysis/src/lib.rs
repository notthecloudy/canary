//! `canary-analysis` — Analysis passes for CFG construction and dominators.
//!
//! This crate houses all analysis passes that operate over the IR.
//!
//! # Architecture
//!
//! Each pass is a **pure function** over a snapshot of the IR:
//!
//! ```text
//! fn analyze_dominators(cfg: &ControlFlowGraph) -> DominatorTree { ... }
//! ```
//!
//! Passes never mutate the IR directly. Results are collected and
//! committed through the core engine's validation layer.

pub mod calling_conv;
pub mod dominators;
pub mod mlil_lower;
pub mod provenance;
pub mod semantic_lower;
pub mod simplify;
pub mod ssa;
pub mod stack_vars;
pub mod struct_inference;
pub mod structuring;
pub mod ui_binding;
pub mod vsa;
pub mod worklist;

pub use calling_conv::{recover_call_signature, CallParam, CallSignature, ParamLocation};
pub use dominators::{mark_back_edges, DominanceInfo, DominatorTree};
pub use mlil_lower::lower_to_mlil;
pub use provenance::{compute_provenance, AliasState, PointerConstraint, ProvBase, TrackedPtr};
pub use simplify::simplify_ssa;
pub use ssa::SsaBuilder;
pub use stack_vars::{recover_stack_vars, StackFrame, StackVar};
pub use struct_inference::{collect_struct_accesses, infer_struct_layouts, StructAccess};
pub use structuring::{structural_analysis, HighLevelControlFlow};
pub use ui_binding::{
    BindingEdge, BindingEvidence, BindingInferenceEngine, UiBehaviorGraph, UiEdge, UiNode,
    UiNodeType, UiRelation, UiValue,
};
pub use vsa::{analyze_vsa, PtrBase, ValueSet, VsaResult};

pub mod api_tracking;
pub mod lifetime;
pub mod subsystem;
