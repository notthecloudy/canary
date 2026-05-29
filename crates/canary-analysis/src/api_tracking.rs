//! System Interaction & API Hooking Semantics.

use canary_sdb::functions::XrefKind;
use canary_sdb::semantics::{ApiHook, HandleLifecycle};
use canary_sdb::SemanticDatabase;
use indexmap::IndexMap;

pub fn analyze_api_semantics(
    sdb: &SemanticDatabase,
) -> (Vec<ApiHook>, IndexMap<String, HandleLifecycle>) {
    let api_hooks = Vec::new();
    let mut handles = IndexMap::new();
    let funcs = &sdb.interpretations.functions.functions;

    for (_, sdb_func) in funcs {
        let func = &sdb_func.value;

        for xref in &func.xrefs_out {
            if let XrefKind::Call = xref.xref_kind {
                if let Some(name) = resolve_call_name(sdb, xref.to_addr) {
                    match classify_handle_api(&name) {
                        HandleApiKind::Acquire => {
                            let handle_id = format!("handle_{:x}", xref.from_addr);
                            handles.insert(
                                handle_id.clone(),
                                HandleLifecycle {
                                    handle_id,
                                    acquired_at: xref.from_addr,
                                    released_at: None,
                                    usage_sites: Vec::new(),
                                },
                            );
                        }
                        HandleApiKind::Release | HandleApiKind::Other => {}
                    }
                }
            }
        }
    }

    (api_hooks, handles)
}

enum HandleApiKind {
    Acquire,
    Release,
    Other,
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

fn classify_handle_api(name: &str) -> HandleApiKind {
    match name.trim_start_matches('_').to_ascii_lowercase().as_str() {
        "createfilea" | "createfilew" | "openprocess" | "openthread" | "socket" | "accept" => {
            HandleApiKind::Acquire
        }
        "closehandle" | "closesocket" => HandleApiKind::Release,
        _ => HandleApiKind::Other,
    }
}
