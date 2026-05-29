//! Object Lifetime Graph construction and analysis.

use canary_sdb::functions::XrefKind;
use canary_sdb::semantics::{EventType, LifetimeEvent, ObjectLifetime};
use canary_sdb::SemanticDatabase;
use indexmap::IndexMap;

pub fn analyze_lifetimes(sdb: &SemanticDatabase) -> IndexMap<String, ObjectLifetime> {
    let mut lifetimes = IndexMap::new();
    let funcs = &sdb.interpretations.functions.functions;

    for (addr, sdb_func) in funcs {
        let func = &sdb_func.value;
        let mut events = Vec::new();

        for xref in &func.xrefs_out {
            if let XrefKind::Call = xref.xref_kind {
                if let Some(name) = resolve_call_name(sdb, xref.to_addr) {
                    if let Some(event_type) = classify_lifetime_api(&name) {
                        events.push(LifetimeEvent {
                            address: xref.from_addr,
                            event_type,
                        });
                    }
                }
            }
        }

        if !events.is_empty() {
            let object_id = format!("obj_{:x}", addr);
            lifetimes.insert(object_id.clone(), ObjectLifetime { object_id, events });
        }
    }

    lifetimes
}

fn resolve_call_name(sdb: &SemanticDatabase, addr: u64) -> Option<String> {
    if let Some(import) = sdb
        .facts
        .binary
        .imports
        .iter()
        .find(|imp| imp.value.address == addr)
    {
        return Some(import.value.symbol_name.clone());
    }

    sdb.interpretations
        .functions
        .functions
        .get(&addr)
        .and_then(|entry| entry.value.name.clone())
}

fn classify_lifetime_api(name: &str) -> Option<EventType> {
    match name.trim_start_matches('_').to_ascii_lowercase().as_str() {
        "malloc" | "calloc" | "realloc" | "operator new" | "operator new[]" => {
            Some(EventType::Allocation)
        }
        "free" | "operator delete" | "operator delete[]" => Some(EventType::Deallocation),
        "initializecriticalsection" | "initonceinitialize" => Some(EventType::Initialization),
        _ => None,
    }
}
