use crate::SdbEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalXrefKind {
    CodeToCode,
    CodeToData,
    CodeToAsset,
    Call,
    Goto,
    TailCall,
}

#[derive(Debug, Clone)]
pub struct SdbGlobalXref {
    pub from_address: u64,
    pub to_address: u64,
    pub kind: GlobalXrefKind,
}

#[derive(Default)]
pub struct XrefsNamespace {
    pub xrefs: Vec<SdbEntry<SdbGlobalXref>>,
    pub callgraph: crate::graphs::CallGraph,
}
