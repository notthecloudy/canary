use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StableId(pub u64);

impl Default for StableId {
    fn default() -> Self {
        Self::new()
    }
}

impl StableId {
    pub fn new() -> Self {
        Self(NEXT_ID.fetch_add(1, Ordering::SeqCst))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfidenceVector {
    pub structural: f32,
    pub semantic: f32,
    pub provenance: f32,
    pub naming: f32,
    pub temporal: f32,
}

impl ConfidenceVector {
    pub fn base(confidence: f32) -> Self {
        Self {
            structural: confidence,
            semantic: confidence,
            provenance: confidence,
            naming: confidence,
            temporal: confidence,
        }
    }

    pub fn composite(&self) -> f32 {
        (self.structural * 0.4)
            + (self.semantic * 0.3)
            + (self.provenance * 0.15)
            + (self.naming * 0.1)
            + (self.temporal * 0.05)
    }
}

/// Indicates where a specific piece of semantic information came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RecoveryOrigin {
    Debug,
    Exact,
    #[default]
    Heuristic,
    Pattern,
    Inference,
    UserAnnotated,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    StringContext(u64),
    MemoryAccess(u64),
    ImportSignature(String),
    SectionPlacement { section: String, offset: u64 },
    ExportEntry { name: String, ordinal: Option<u16> },
    RelocationTarget { from: u64, rel_type: u32 },
    DebugSymbol { name: String, source: String },
    ResourceReference { res_type: String, name: String },
    VtableEntry { vtable_addr: u64, slot: usize },
    RttiMatch { type_name: String, confidence: f32 },
    CallingPattern { convention: String, arity: usize },
}

#[derive(Debug, Clone, Default)]
pub struct Hypothesis {
    pub id: StableId,
    pub description: String,
    pub confidence: ConfidenceVector,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Default)]
pub struct ProvenanceTrail {
    pub origin: RecoveryOrigin,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Default)]
pub struct ChangeRecord {
    pub timestamp: u64,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct SdbEntry<T> {
    pub value: T,
    pub confidence: ConfidenceVector,
    pub provenance: ProvenanceTrail,
    pub hypotheses: Vec<Hypothesis>,
    pub change_history: Vec<ChangeRecord>,
}

impl<T> SdbEntry<T> {
    pub fn new(value: T, confidence: ConfidenceVector, origin: RecoveryOrigin) -> Self {
        Self {
            value,
            confidence,
            provenance: ProvenanceTrail {
                origin,
                evidence: Vec::new(),
            },
            hypotheses: Vec::new(),
            change_history: Vec::new(),
        }
    }
}

// Semantic Database (SDB)
//
// The central repository for all recovered facts, IRs, and analysis results.

/// Indicates where a specific piece of semantic information came from.
pub mod functions;
pub use functions::*;

pub mod types;
pub use types::*;

pub mod modules;
pub use modules::*;

pub mod symbols;
pub use symbols::*;

pub mod assets;
pub use assets::*;

pub mod xrefs;
pub use xrefs::*;

pub mod project;
pub use project::*;

pub mod feedback;
pub use feedback::*;

pub struct FactPlane {
    pub binary: BinaryNamespace,
    pub symbols: SymbolsNamespace,
    pub assets: AssetsNamespace,
    pub xrefs: XrefsNamespace,
}

impl Default for FactPlane {
    fn default() -> Self {
        Self {
            binary: BinaryNamespace::default(),
            symbols: SymbolsNamespace::default(),
            assets: AssetsNamespace::default(),
            xrefs: XrefsNamespace::default(),
        }
    }
}

pub struct InterpretationPlane {
    pub functions: FunctionsNamespace,
    pub types: TypesNamespace,
    pub modules: ModulesNamespace,
    pub class_hypotheses: Vec<crate::types::ClassHypothesis>,
    pub field_models: Vec<crate::types::FieldModel>,
    pub type_models: Vec<crate::types::TypeModel>,
    pub object_lifetimes: indexmap::IndexMap<String, crate::semantics::ObjectLifetime>,
    pub subsystems: Vec<crate::semantics::Subsystem>,
    pub api_hooks: Vec<crate::semantics::ApiHook>,
    pub handles: indexmap::IndexMap<String, crate::semantics::HandleLifecycle>,
}

impl Default for InterpretationPlane {
    fn default() -> Self {
        Self {
            functions: FunctionsNamespace::default(),
            types: TypesNamespace::default(),
            modules: ModulesNamespace::default(),
            class_hypotheses: Vec::new(),
            field_models: Vec::new(),
            type_models: Vec::new(),
            object_lifetimes: indexmap::IndexMap::new(),
            subsystems: Vec::new(),
            api_hooks: Vec::new(),
            handles: indexmap::IndexMap::new(),
        }
    }
}

/// The top-level semantic database containing all recovered namespaces.
pub struct SemanticDatabase {
    pub facts: FactPlane,
    pub interpretations: InterpretationPlane,
    pub project: ProjectNamespace,
    pub feedback: FeedbackNamespace,
    pub graphs: crate::graphs::GraphsNamespace,
}

impl SemanticDatabase {
    pub fn new() -> Self {
        Self {
            facts: FactPlane::default(),
            interpretations: InterpretationPlane::default(),
            project: ProjectNamespace::default(),
            feedback: FeedbackNamespace::default(),
            graphs: crate::graphs::GraphsNamespace::default(),
        }
    }
}

/// Information recovered directly from the binary container format.
#[derive(Default)]
pub struct BinaryNamespace {
    pub format: String,
    pub arch: String,
    pub image_base: u64,
    pub entry_point: u64,
    /// Mapped segments (address -> size, perms)
    pub segments: Vec<SdbEntry<MappedSegment>>,
    /// Named sections
    pub sections: Vec<SdbEntry<MappedSection>>,
    /// Imports
    pub imports: Vec<SdbEntry<Import>>,
    /// Exports
    pub exports: Vec<SdbEntry<Export>>,
    /// Relocations
    pub relocations: Vec<SdbEntry<Relocation>>,
    /// Named entry points (functions)
    pub named_functions: Vec<SdbEntry<NamedFunction>>,
    /// Debug information
    pub debug_info: Vec<SdbEntry<DebugInfo>>,
    /// Toolchain fingerprinting
    pub toolchain: Vec<SdbEntry<ToolchainInfo>>,
    /// Resource Tree entries
    pub resources: Vec<SdbEntry<ResourceBlob>>,
    /// Detected packers or overlays
    pub packers: Vec<SdbEntry<PackerInfo>>,
    /// COM descriptors (e.g. .NET runtime metadata)
    pub com_descriptors: Vec<SdbEntry<ComDescriptor>>,
    /// Rich Header data (MSVC linker info)
    pub rich_header_data: Vec<SdbEntry<RichHeaderData>>,
    /// Exception tables (unwind data blocks)
    pub exception_tables: Vec<SdbEntry<ExceptionTable>>,
}

#[derive(Debug, Clone)]
pub struct ToolchainInfo {
    pub compiler: Option<String>,
    pub runtime: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResourceBlob {
    pub res_type: String,
    pub name: Option<String>,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct PackerInfo {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct DebugInfo {
    pub info_type: String,
    pub path: Option<String>,
    pub guid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub address: u64,
    pub target: u64,
    pub rel_type: u32,
}

#[derive(Debug, Clone)]
pub struct NamedFunction {
    pub address: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct MappedSegment {
    pub address: u64,
    pub size: usize,
    pub is_read: bool,
    pub is_write: bool,
    pub is_exec: bool,
}

#[derive(Debug, Clone)]
pub struct MappedSection {
    pub name: String,
    pub address: u64,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub lib_name: String,
    pub symbol_name: String,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub symbol_name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

pub mod graphs;
pub mod semantics;

#[derive(Debug, Clone)]
pub struct EhFrame {
    pub address: u64,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct TlsCallback {
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct DelayImport {
    pub lib_name: String,
    pub symbol_name: String,
    pub address: u64,
}

pub mod bridge;
pub mod class;
pub mod database;
pub mod engine;
pub mod event;
pub mod index;
pub mod ledger;

#[derive(Debug, Clone)]
pub struct ComDescriptor {
    pub address: u64,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct RichHeaderData {
    pub comp_id: u32,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct ExceptionTable {
    pub address: u64,
    pub size: usize,
}
