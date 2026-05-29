//! Subsystem and Component abstraction analysis.

use canary_sdb::semantics::Subsystem;
use canary_sdb::SemanticDatabase;
use indexmap::{IndexMap, IndexSet};
use std::collections::VecDeque;

pub fn identify_subsystems(sdb: &SemanticDatabase) -> Vec<Subsystem> {
    let mut subsystems = Vec::new();
    let call_graph = &sdb.graphs.call_graph;

    let mut visited = IndexSet::new();
    let mut subsystem_counter = 0;

    for (node_addr, _node) in &call_graph.nodes {
        if visited.contains(node_addr) {
            continue;
        }

        // BFS to find connected component
        let mut component = IndexSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(*node_addr);
        visited.insert(*node_addr);

        while let Some(current) = queue.pop_front() {
            component.insert(current);

            // Outgoing edges
            if let Some(edges) = call_graph.callees.get(&current) {
                for edge in edges {
                    if !visited.contains(&edge.to_node) {
                        visited.insert(edge.to_node);
                        queue.push_back(edge.to_node);
                    }
                }
            }

            // Incoming edges
            if let Some(edges) = call_graph.callers.get(&current) {
                for edge in edges {
                    if !visited.contains(&edge.from_node) {
                        visited.insert(edge.from_node);
                        queue.push_back(edge.from_node);
                    }
                }
            }
        }

        if component.len() > 1 {
            subsystems.push(Subsystem {
                name: format!("Subsystem_{}", subsystem_counter),
                functions: component,
                data_structures: IndexSet::new(),
            });
            subsystem_counter += 1;
        }
    }

    subsystems
}
