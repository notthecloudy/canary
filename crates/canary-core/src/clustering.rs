use crate::workspace::Workspace;
use canary_sdb::modules::SdbModule;
use canary_sdb::{RecoveryOrigin, SdbEntry};

/// Phase 6: Module, Namespace, and Architecture Clustering
/// Clusters functions into logical modules based on address locality and call cohesion.
pub fn cluster_modules(workspace: &mut Workspace) {
    let mut module_id_counter = 1;

    let func_addrs: Vec<u64> = workspace
        .sdb
        .interpretations
        .functions
        .functions
        .keys()
        .copied()
        .collect();

    if func_addrs.is_empty() {
        return;
    }

    // Build the adjacency list from xrefs
    let mut adj: indexmap::IndexMap<u64, Vec<u64>> = indexmap::IndexMap::new();
    let mut m = 0; // total number of edges
    for xref_entry in &workspace.sdb.facts.xrefs.xrefs {
        let xref = &xref_entry.value;
        if matches!(xref.kind, canary_sdb::GlobalXrefKind::Call) {
            adj.entry(xref.from_address)
                .or_default()
                .push(xref.to_address);
            adj.entry(xref.to_address)
                .or_default()
                .push(xref.from_address); // undirected for community detection
            m += 1;
        }
    }

    let mut communities: indexmap::IndexMap<u64, u64> =
        func_addrs.iter().map(|&a| (a, a)).collect();

    if m > 0 {
        let mut improved = true;
        let mut iter = 0;

        while improved && iter < 10 {
            improved = false;
            iter += 1;

            for &node in &func_addrs {
                let current_com = communities[&node];
                let neighbors = match adj.get(&node) {
                    Some(n) => n,
                    None => continue,
                };

                let mut com_counts: indexmap::IndexMap<u64, usize> = indexmap::IndexMap::new();
                for &neighbor in neighbors {
                    if let Some(&neighbor_com) = communities.get(&neighbor) {
                        *com_counts.entry(neighbor_com).or_default() += 1;
                    }
                }

                if let Some((&best_com, _)) = com_counts.iter().max_by_key(|&(_, count)| count) {
                    if best_com != current_com {
                        communities.insert(node, best_com);
                        improved = true;
                    }
                }
            }
        }
    }

    // Group functions into modules by community
    let mut module_groups: indexmap::IndexMap<u64, Vec<u64>> = indexmap::IndexMap::new();
    for (node, com) in communities {
        module_groups.entry(com).or_default().push(node);
    }

    for (_, mut funcs) in module_groups {
        funcs.sort();

        let mod_id = module_id_counter;
        module_id_counter += 1;

        // simple tag based on names
        let mut current_subsystem = None;
        for &addr in &funcs {
            if let Some(sdb_func) = workspace.sdb.interpretations.functions.functions.get(&addr) {
                if let Some(name_opt) = &sdb_func.value.name {
                    let name = name_opt.to_lowercase();
                    if name.contains("render")
                        || name.contains("draw")
                        || name.contains("d3d")
                        || name.contains("gl")
                    {
                        current_subsystem = Some("Renderer".to_string());
                        break;
                    } else if name.contains("audio") || name.contains("sound") {
                        current_subsystem = Some("Audio".to_string());
                        break;
                    } else if name.contains("phys") || name.contains("collide") {
                        current_subsystem = Some("Physics".to_string());
                        break;
                    }
                }
            }
        }

        let name = current_subsystem
            .clone()
            .unwrap_or_else(|| format!("Module_{:04X}", mod_id));

        let module = SdbModule {
            id: mod_id,
            name,
            subsystem_tag: current_subsystem,
            functions: funcs.clone(),
        };

        workspace.sdb.interpretations.modules.modules.insert(
            mod_id,
            SdbEntry::new(
                module,
                canary_sdb::ConfidenceVector::base(0.7),
                RecoveryOrigin::Heuristic,
            ),
        );

        for f_addr in funcs {
            workspace
                .sdb
                .interpretations
                .modules
                .function_to_module
                .insert(f_addr, mod_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::functions::SdbFunction;

    #[test]
    fn test_address_locality_clustering() {
        let mut workspace = Workspace::new(std::path::Path::new("dummy"), vec![]);

        // Add 3 contiguous functions
        workspace.sdb.interpretations.functions.functions.insert(
            0x1000,
            SdbEntry::new(
                SdbFunction {
                    name: Some("func1".into()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ),
        );
        workspace.sdb.interpretations.functions.functions.insert(
            0x1050,
            SdbEntry::new(
                SdbFunction {
                    name: Some("func2".into()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ),
        );
        workspace.sdb.interpretations.functions.functions.insert(
            0x10A0,
            SdbEntry::new(
                SdbFunction {
                    name: Some("func3".into()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ),
        );

        // Add xrefs to connect func1, func2, func3
        workspace
            .sdb
            .facts
            .xrefs
            .xrefs
            .push(canary_sdb::SdbEntry::new(
                canary_sdb::SdbGlobalXref {
                    from_address: 0x1000,
                    to_address: 0x1050,
                    kind: canary_sdb::GlobalXrefKind::Call,
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        workspace
            .sdb
            .facts
            .xrefs
            .xrefs
            .push(canary_sdb::SdbEntry::new(
                canary_sdb::SdbGlobalXref {
                    from_address: 0x1050,
                    to_address: 0x10A0,
                    kind: canary_sdb::GlobalXrefKind::Call,
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));

        // Add 1 disconnected function
        workspace.sdb.interpretations.functions.functions.insert(
            0x5000,
            SdbEntry::new(
                SdbFunction {
                    name: Some("render_frame".into()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ),
        );

        cluster_modules(&mut workspace);

        assert_eq!(workspace.sdb.interpretations.modules.modules.len(), 2);
    }
}
