//! Workspace — the top-level container for a binary analysis session.

use canary_analysis::CallSignature;
use canary_ir::function::{Function, FunctionArena, FunctionId};
use canary_ir::types::TypeArena;
use indexmap::IndexMap;

/// A workspace holds all IR state for a single binary analysis session.
///
/// The workspace is the unit of persistence — it is serialized to disk
/// between sessions and supports incremental invalidation.
pub struct Workspace {
    /// All functions discovered in the binary.
    pub functions: FunctionArena,
    /// Map from entry address → function ID.
    pub addr_to_func: IndexMap<u64, FunctionId>,
    /// Global type arena shared across all functions.
    pub types: TypeArena,
    /// Original binary bytes.
    pub binary_bytes: Vec<u8>,
    /// Path of the analyzed binary.
    pub binary_path: std::path::PathBuf,
    /// Calling conventions and signatures inferred for functions.
    pub calling_sigs: IndexMap<FunctionId, CallSignature>,
    /// The Semantic Database containing all facts and namespaces.
    pub sdb: canary_sdb::SemanticDatabase,
    /// The event-driven semantic engine bridge.
    pub bridge: canary_sdb::bridge::SdbBridge,
    /// The constraint and belief revision engine.
    /// The constraint and belief revision engine.
    pub constraints: canary_constraints::ConstraintEngine,
    /// The workspace configuration and recovery modes.
    pub config: crate::config::WorkspaceConfig,
}

impl Workspace {
    /// Creates a new workspace for the given binary.
    pub fn new(binary_path: impl Into<std::path::PathBuf>, bytes: Vec<u8>) -> Self {
        let sdb = canary_sdb::SemanticDatabase::new();

        Self {
            functions: FunctionArena::new(),
            addr_to_func: IndexMap::new(),
            types: TypeArena::new(),
            binary_bytes: bytes,
            binary_path: binary_path.into(),
            calling_sigs: IndexMap::new(),
            sdb,
            bridge: canary_sdb::bridge::SdbBridge::default(),
            constraints: canary_constraints::ConstraintEngine::default(),
            config: crate::config::WorkspaceConfig::default(),
        }
    }

    /// Registers a new function at `entry_addr`.
    /// Returns the existing function ID if one is already registered at that address.
    pub fn add_function(&mut self, entry_addr: u64) -> FunctionId {
        if let Some(&existing_id) = self.addr_to_func.get(&entry_addr) {
            return existing_id;
        }
        let func = Function::new(entry_addr);
        let id = self.functions.alloc(func);
        self.addr_to_func.insert(entry_addr, id);
        id
    }

    /// Looks up a function by entry address.
    pub fn function_at(&self, addr: u64) -> Option<FunctionId> {
        self.addr_to_func.get(&addr).copied()
    }

    /// Returns the number of functions in the workspace.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}
