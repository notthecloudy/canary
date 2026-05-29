use crate::SdbEntry;
use indexmap::IndexMap;

/// Edge kind in a CFG
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeKind {
    Unconditional,
    True,
    False,
    Switch,
    Call,
    Return,
    Exception,
    Fallthrough,
    Back,
}

#[derive(Debug, Clone)]
pub struct SdbBasicBlock {
    pub address: u64,
    pub size: usize,
    pub successors: Vec<(u64, EdgeKind)>,
}

#[derive(Debug, Clone)]
pub struct SdbSsaInfo {
    pub block_count: usize,
    pub phi_count: usize,
    pub def_count: usize,
}

#[derive(Debug, Clone)]
pub struct SdbVsaInfo {
    pub pointer_count: usize,
    pub unresolved_count: usize,
}

#[derive(Debug, Clone)]
pub struct SdbPointerProvenanceInfo {
    pub tracked_pointer_count: usize,
    pub parameter_pointer_count: usize,
    pub stack_pointer_count: usize,
    pub global_pointer_count: usize,
}

#[derive(Debug, Clone)]
pub struct SdbSemanticInfo {
    pub block_count: usize,
    pub transition_count: usize,
}

#[derive(Debug, Clone)]
pub struct StackVarHint {
    pub offset: i64,
    pub size: usize,
    pub name: Option<String>,
    pub ty_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SdbStackFrame {
    pub vars: Vec<StackVarHint>,
}

#[derive(Debug, Clone)]
pub struct SdbParam {
    pub name: Option<String>,
    pub ty: String,
    pub location: String, // e.g. "rcx", "stack:0x8"
}

#[derive(Debug, Clone)]
pub struct SdbCallSignature {
    pub return_ty: String,
    pub params: Vec<SdbParam>,
    pub calling_conv: String,
    pub is_variadic: bool,
    pub noreturn: bool,
}

#[derive(Debug, Clone)]
pub struct SdbHlCf {
    pub is_structured: bool,
    pub goto_count: usize,
    pub loop_count: usize,
}

#[derive(Debug, Clone)]
pub enum XrefKind {
    Call,
    Read,
    Write,
    Jump,
}

#[derive(Debug, Clone)]
pub struct SdbXref {
    pub from_addr: u64,
    pub to_addr: u64,
    pub xref_kind: XrefKind,
}

#[derive(Debug, Clone)]
pub struct InferredCallTarget {
    pub call_site: u64,
    pub targets: Vec<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SdbFunction {
    pub entry_addr: u64,
    pub name: Option<String>,
    pub size: Option<usize>,
    pub cfg_blocks: Vec<SdbBasicBlock>,
    pub ssa: Option<SdbEntry<SdbSsaInfo>>,
    pub vsa: Option<SdbEntry<SdbVsaInfo>>,
    pub pointer_provenance: Option<SdbEntry<SdbPointerProvenanceInfo>>,
    pub semantic: Option<SdbEntry<SdbSemanticInfo>>,
    pub stack_frame: Option<SdbEntry<SdbStackFrame>>,
    pub call_signature: Option<SdbEntry<SdbCallSignature>>,
    pub high_level_cfg: Option<SdbEntry<SdbHlCf>>,
    pub xrefs_out: Vec<SdbXref>,
    pub inferred_call_targets: Vec<SdbEntry<InferredCallTarget>>,
    pub mlil_complete: bool,
}

#[derive(Default)]
pub struct FunctionsNamespace {
    pub functions: IndexMap<u64, SdbEntry<SdbFunction>>,
}
