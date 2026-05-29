//! Semantic modeling structures (Phase 2).

use indexmap::IndexSet;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct LifetimeEvent {
    pub address: u64,
    pub event_type: EventType,
}

#[derive(Debug, Clone)]
pub enum EventType {
    Allocation,
    Initialization,
    Usage,
    Deallocation,
}

#[derive(Debug, Clone, Default)]
pub struct ObjectLifetime {
    pub object_id: String,
    pub events: Vec<LifetimeEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct Subsystem {
    pub name: String,
    pub functions: IndexSet<u64>,
    pub data_structures: IndexSet<String>,
}

#[derive(Debug, Clone)]
pub struct ApiHook {
    pub hook_address: u64,
    pub original_api: String,
    pub intercept_function: u64,
}

#[derive(Debug, Clone)]
pub struct HandleLifecycle {
    pub handle_id: String,
    pub acquired_at: u64,
    pub released_at: Option<u64>,
    pub usage_sites: Vec<u64>,
}
