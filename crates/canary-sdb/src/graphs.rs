//! Unified graph structures for program analysis.

use crate::{ConfidenceVector, Evidence, StableId};
use indexmap::{IndexMap, IndexSet};
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: StableId,
    pub address: Option<u64>,
    pub confidence: ConfidenceVector,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub id: StableId,
    pub from_node: u64,
    pub to_node: u64,
    pub confidence: ConfidenceVector,
    pub evidence: Vec<Evidence>,
}

/// Bidirectional call graph over function entry addresses.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// function addr -> list of GraphEdges (direct calls out)
    pub callees: IndexMap<u64, Vec<GraphEdge>>,
    /// function addr -> list of GraphEdges (who calls this)
    pub callers: IndexMap<u64, Vec<GraphEdge>>,
    pub nodes: IndexMap<u64, GraphNode>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a directed call edge from caller to callee.
    pub fn add_call(&mut self, caller: u64, callee: u64) {
        let callees = self.callees.entry(caller).or_default();
        if !callees.iter().any(|e| e.to_node == callee) {
            callees.push(GraphEdge {
                id: StableId::new(),
                from_node: caller,
                to_node: callee,
                confidence: ConfidenceVector::base(1.0),
                evidence: Vec::new(),
            });
        }
        let callers = self.callers.entry(callee).or_default();
        if !callers.iter().any(|e| e.from_node == caller) {
            callers.push(GraphEdge {
                id: StableId::new(),
                from_node: caller,
                to_node: callee,
                confidence: ConfidenceVector::base(1.0),
                evidence: Vec::new(),
            });
        }

        self.nodes.entry(caller).or_insert_with(|| GraphNode {
            id: StableId::new(),
            address: Some(caller),
            confidence: ConfidenceVector::base(1.0),
            evidence: Vec::new(),
        });
        self.nodes.entry(callee).or_insert_with(|| GraphNode {
            id: StableId::new(),
            address: Some(callee),
            confidence: ConfidenceVector::base(1.0),
            evidence: Vec::new(),
        });
    }

    /// All functions called by ddr.
    pub fn callees_of(&self, addr: u64) -> Vec<u64> {
        self.callees
            .get(&addr)
            .map(|v| v.iter().map(|e| e.to_node).collect())
            .unwrap_or_default()
    }

    /// All functions that call ddr.
    pub fn callers_of(&self, addr: u64) -> Vec<u64> {
        self.callers
            .get(&addr)
            .map(|v| v.iter().map(|e| e.from_node).collect())
            .unwrap_or_default()
    }

    /// Returns all known function addresses in this call graph.
    pub fn all_functions(&self) -> impl Iterator<Item = u64> + '_ {
        self.nodes.keys().copied()
    }

    /// Returns functions in approximate topological order (callees before callers).
    /// Uses Kahn's algorithm on the reversed graph.
    pub fn topological_order(&self) -> Vec<u64> {
        let mut in_degree: IndexMap<u64, usize> = IndexMap::new();
        let mut all_nodes = IndexSet::new();

        for (&caller, callees) in &self.callees {
            all_nodes.insert(caller);
            for callee_edge in callees {
                all_nodes.insert(callee_edge.to_node);
                *in_degree.entry(callee_edge.to_node).or_insert(0) += 1;
            }
        }

        for &node in &all_nodes {
            in_degree.entry(node).or_insert(0);
        }

        let mut queue: VecDeque<u64> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&n, _)| n)
            .collect();

        let mut result = Vec::with_capacity(all_nodes.len());
        while let Some(node) = queue.pop_front() {
            result.push(node);
            for callee in self.callees_of(node) {
                if let Some(deg) = in_degree.get_mut(&callee) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(callee);
                    }
                }
            }
        }

        for node in &all_nodes {
            if !result.contains(node) {
                result.push(*node);
            }
        }

        result
    }

    /// Total number of unique call edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.callees.values().map(|v| v.len()).sum()
    }

    /// Total number of unique function nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// === Skeletons for additional graph types ===

#[derive(Debug, Clone, Default)]
pub struct DataFlowGraph {}

#[derive(Debug, Clone, Default)]
pub struct TypeRelationGraph {}

#[derive(Debug, Clone, Default)]
pub struct ObjectLifetimeGraph {}

#[derive(Debug, Clone, Default)]
pub struct ResourceDependencyGraph {}

#[derive(Debug, Clone, Default)]
pub struct ModuleDependencyGraph {}

#[derive(Debug, Clone, Default)]
pub struct GraphsNamespace {
    pub call_graph: CallGraph,
}
