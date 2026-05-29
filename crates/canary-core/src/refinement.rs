use crate::engine::{Engine, EngineError};
use canary_sdb::{RecoveryOrigin, RefinementAction, SdbEntry};
use std::path::Path;

pub fn run_refinement_loop(
    engine: &mut Engine,
    output_dir: &Path,
    max_iterations: usize,
) -> Result<(), EngineError> {
    for _iteration in 0..max_iterations {
        // Lift any functions that are not currently lifted.
        // engine.decompile_function() uses the lazy binary cache internally,
        // so we only need to trigger lifts via the engine rather than managing Binary::load() ourselves.
        {
            let func_ids: Vec<_> = engine
                .workspace
                .functions
                .iter()
                .map(|(id, _)| id)
                .collect();
            // Pre-load the binary into cache once for this iteration, if not already loaded
            if engine.cached_loaded.is_none() {
                let _ = engine.loaded_binary();
            }
            let loaded = engine.cached_loaded.clone();
            for id in func_ids {
                let is_lifted = engine
                    .workspace
                    .functions
                    .get(id)
                    .map(|f| f.is_lifted)
                    .unwrap_or(false);
                if !is_lifted {
                    if let Some(loaded) = loaded.as_ref() {
                        let _ = engine.lift_function(id, loaded);
                    }
                }
            }
        }

        // 1. Recover project layout
        crate::project_layout::recover_project_layout(&mut engine.workspace);

        // 2. Validate project
        let feedback = crate::validator::validate_project(&engine.workspace);
        if feedback.is_empty() {
            break;
        }

        // Apply feedback entries back to SDB
        let mut progress = false;
        for fb in feedback {
            engine
                .workspace
                .sdb
                .feedback
                .feedback_queue
                .push(SdbEntry::new(
                    fb.clone(),
                    canary_sdb::ConfidenceVector::base(1.0),
                    RecoveryOrigin::Heuristic,
                ));

            match fb.action {
                RefinementAction::RenameSymbol {
                    address,
                    old_name: _,
                    new_name,
                } => {
                    if address != 0 {
                        let mut updated = false;
                        if let Some(sym_entry) =
                            engine.workspace.sdb.facts.symbols.symbols.get_mut(&address)
                        {
                            sym_entry.value.name = new_name.clone();
                            updated = true;
                        }
                        if let Some(func_entry) = engine
                            .workspace
                            .sdb
                            .interpretations
                            .functions
                            .functions
                            .get_mut(&address)
                        {
                            func_entry.value.name = Some(new_name);
                            updated = true;
                        }
                        if updated {
                            progress = true;
                        }
                    }
                }
                RefinementAction::UpdateSignature {
                    address,
                    param_count,
                    param_types,
                } => {
                    if let Some(func_entry) = engine
                        .workspace
                        .sdb
                        .interpretations
                        .functions
                        .functions
                        .get_mut(&address)
                    {
                        let mut sig = func_entry
                            .value
                            .call_signature
                            .as_ref()
                            .map(|s| s.value.clone())
                            .unwrap_or_else(|| canary_sdb::SdbCallSignature {
                                return_ty: "void".to_string(),
                                params: Vec::new(),
                                calling_conv: "SysV64".to_string(),
                                is_variadic: false,
                                noreturn: false,
                            });

                        sig.params.truncate(param_count);
                        while sig.params.len() < param_count {
                            sig.params.push(canary_sdb::SdbParam {
                                name: Some(format!("arg_{}", sig.params.len())),
                                ty: "unknown".to_string(),
                                location: "unknown".to_string(),
                            });
                        }
                        for (i, ty) in param_types.iter().enumerate() {
                            if ty != "unknown" {
                                sig.params[i].ty = ty.clone();
                            }
                        }
                        func_entry.value.call_signature = Some(SdbEntry::new(
                            sig,
                            canary_sdb::ConfidenceVector::base(0.9),
                            RecoveryOrigin::Heuristic,
                        ));

                        // Invalidate decompilation cache
                        if let Some(&func_id) = engine.workspace.addr_to_func.get(&address) {
                            if let Some(func) = engine.workspace.functions.get_mut(func_id) {
                                func.is_lifted = false;
                            }
                        }
                        progress = true;
                    }
                }
                RefinementAction::UpdateVariableType { .. } => {
                    progress = true;
                }
            }
        }

        if !progress {
            break;
        }
    }

    // Finally generate project files
    crate::codegen::generate_project_files(engine, output_dir)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::functions::SdbFunction;
    use canary_sdb::symbols::SdbSymbol;

    #[test]
    fn test_refinement_resolves_naming_collision() {
        let mut workspace = crate::workspace::Workspace::new("dummy", vec![]);
        workspace.sdb.facts.symbols.symbols.insert(
            0x1000,
            SdbEntry::new(
                SdbSymbol {
                    address: 0x1000,
                    name: "dup".to_string(),
                    provenance: RecoveryOrigin::Heuristic,
                },
                canary_sdb::ConfidenceVector::base(0.8),
                RecoveryOrigin::Heuristic,
            ),
        );
        workspace.sdb.facts.symbols.symbols.insert(
            0x2000,
            SdbEntry::new(
                SdbSymbol {
                    address: 0x2000,
                    name: "dup".to_string(),
                    provenance: RecoveryOrigin::Heuristic,
                },
                canary_sdb::ConfidenceVector::base(0.5),
                RecoveryOrigin::Heuristic,
            ),
        );

        workspace.sdb.interpretations.functions.functions.insert(
            0x1000,
            SdbEntry::new(
                SdbFunction {
                    entry_addr: 0x1000,
                    name: Some("dup".to_string()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(0.8),
                RecoveryOrigin::Heuristic,
            ),
        );
        workspace.sdb.interpretations.functions.functions.insert(
            0x2000,
            SdbEntry::new(
                SdbFunction {
                    entry_addr: 0x2000,
                    name: Some("dup".to_string()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(0.5),
                RecoveryOrigin::Heuristic,
            ),
        );

        let mut engine = Engine::new(workspace);
        let temp_dir = std::env::temp_dir().join("canary_refinement_test");
        let res = run_refinement_loop(&mut engine, &temp_dir, 3);
        assert!(res.is_ok());

        let name_2000 = engine
            .workspace
            .sdb
            .facts
            .symbols
            .symbols
            .get(&0x2000)
            .unwrap()
            .value
            .name
            .clone();
        assert_eq!(name_2000, "dup_collision_2000");

        let func_name_2000 = engine
            .workspace
            .sdb
            .interpretations
            .functions
            .functions
            .get(&0x2000)
            .unwrap()
            .value
            .name
            .clone()
            .unwrap();
        assert_eq!(func_name_2000, "dup_collision_2000");

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
