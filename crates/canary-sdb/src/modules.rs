use crate::SdbEntry;
use indexmap::IndexMap;

/// Represents a logical module grouping related functions and types.
#[derive(Debug, Clone)]
pub struct SdbModule {
    pub id: u64,
    pub name: String,
    pub subsystem_tag: Option<String>,
    pub functions: Vec<u64>,
}

#[derive(Default)]
pub struct ModulesNamespace {
    /// Maps module ID to the module structure
    pub modules: IndexMap<u64, SdbEntry<SdbModule>>,

    /// Maps function addresses to their parent module ID
    pub function_to_module: IndexMap<u64, u64>,
}
