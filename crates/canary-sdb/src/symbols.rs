use crate::{RecoveryOrigin, SdbEntry};
use indexmap::IndexMap;

/// Represents a recovered name or symbol.
#[derive(Debug, Clone)]
pub struct SdbSymbol {
    pub address: u64,
    pub name: String,
    pub provenance: RecoveryOrigin,
}

#[derive(Default)]
pub struct SymbolsNamespace {
    /// Maps symbol address to its SdbSymbol
    pub symbols: IndexMap<u64, SdbEntry<SdbSymbol>>,
}
