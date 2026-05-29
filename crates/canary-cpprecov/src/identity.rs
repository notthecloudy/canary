//! Semantic identity classifier — the core "class explosion fix".
//!
//! Every recovered candidate must pass through here before it can become
//! an SdbClass.  Three tiers:
//!
//!   ≥ 0.75 → Class   (real polymorphic object)
//!   0.45–0.75 → Module  (procedural system: queues, hash tables, …)
//!   < 0.45  → Function (isolated computation)

use canary_sdb::types::{ClassHypothesis, SemanticUnit, SemanticDecision};

/// Confidence thresholds.
const CLASS_THRESHOLD: f32 = 0.75;
const MODULE_THRESHOLD: f32 = 0.45;

/// Compute a weighted confidence score for a `ClassHypothesis`.
///
/// Inputs come from the `EvidenceBundle` already stored on the hypothesis
/// plus the field cluster count from `FieldModel` evidence (passed separately).
pub fn score_hypothesis(hyp: &ClassHypothesis, field_cluster_count: usize) -> f32 {
    let vtable_score   = hyp.evidence.vtable_score;
    let this_entropy   = 1.0 - hyp.evidence.this_usage_score; // inverse: high usage → low entropy
    let callgraph      = hyp.evidence.callgraph_score;
    let rtti           = hyp.evidence.rtti_score;
    let clusters       = (field_cluster_count as f32 / 5.0).min(1.0);
    let neg_evidence   = if hyp.confidence < 0.3 { 0.4 } else { 0.0 };

    let base = vtable_score   * 0.40
             + (1.0 - this_entropy) * 0.15
             + callgraph       * 0.15
             + rtti            * 0.15
             + clusters        * 0.15
             - neg_evidence    * 0.30;

    base.clamp(0.0, 1.0)
}

/// Decide what semantic tier a hypothesis belongs to.
pub fn classify(hyp: &ClassHypothesis, field_cluster_count: usize) -> SemanticDecision {
    let confidence = score_hypothesis(hyp, field_cluster_count);

    // Hard extra requirement for Class: must have vtable evidence
    let unit = if confidence >= CLASS_THRESHOLD && hyp.evidence.vtable_score > 0.5 {
        SemanticUnit::Class
    } else if confidence >= MODULE_THRESHOLD || field_cluster_count >= 2 {
        SemanticUnit::Module
    } else {
        SemanticUnit::Function
    };

    SemanticDecision { unit, confidence, evidence: hyp.evidence.vtable_score }
}

/// Intrinsic / stub name heuristics to classify raw function names
/// before any IR exists.
pub fn classify_function_name(name: &str) -> canary_sdb::types::FunctionKind {
    use canary_sdb::types::FunctionKind;

    // Compiler intrinsics & runtime atomics
    if name.starts_with("globalAtomic")
        || name.starts_with("__atomic")
        || name.starts_with("atomic")
        || name.contains("__security_check")
        || name.contains("__chkstk")
        || name.contains("__readgsqword")
        || name.contains("llvm.")
        || name.contains("NvOptimusEnablement")
        || name.contains("AmdPowerXpress")
        || name.starts_with("default_mspace")
    {
        return FunctionKind::Intrinsic;
    }

    // Import thunks and linker stubs
    if name.starts_with("sub_")
        || name.starts_with("thunk_")
        || name.contains("_thunk")
        || name.contains("_stub")
        || name.starts_with("j_")
    {
        return FunctionKind::ExternalStub;
    }

    FunctionKind::UserCode
}
