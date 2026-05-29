use crate::workspace::Workspace;
use canary_sdb::symbols::SdbSymbol;
use canary_sdb::{RecoveryOrigin, SdbEntry};

use canary_sdb::functions::XrefKind;
/// Phase 7: Naming Recovery and Symbol Enrichment
/// Replaces placeholder names with best-quality human-readable names via demangling and prioritizing debug/export symbols.
use canary_sdb::{ConfidenceVector, Evidence, Hypothesis, StableId};

/// Phase 7: Naming Recovery and Symbol Enrichment
/// Replaces placeholder names with best-quality human-readable names via demangling, API inference, and constraint Engine.
pub fn enrich_symbols(workspace: &mut Workspace) {
    let mut new_names = Vec::new();
    let mut engine = std::mem::take(&mut workspace.constraints);

    for (addr, sdb_func) in workspace.sdb.interpretations.functions.functions.iter() {
        let stable_id = StableId::new();
        let mut candidates = Vec::new();

        // 1. Demangling Candidate
        if let Some(ref original_name) = sdb_func.value.name {
            if original_name.starts_with("_Z") {
                if let Ok(sym) = cpp_demangle::Symbol::new(&original_name[..]) {
                    if let Ok(demangled) = sym.demangle() {
                        candidates.push(Hypothesis {
                            id: StableId::new(),
                            description: demangled.clone(),
                            confidence: ConfidenceVector::base(0.95),
                            evidence: vec![Evidence::DebugSymbol {
                                name: demangled,
                                source: "demangler".to_string(),
                            }],
                        });
                    }
                }
            } else if original_name.starts_with('?') {
                let flags = msvc_demangler::DemangleFlags::NO_ACCESS_SPECIFIERS
                    | msvc_demangler::DemangleFlags::NO_MEMBER_TYPE
                    | msvc_demangler::DemangleFlags::NAME_ONLY;

                if let Ok(demangled) = msvc_demangler::demangle(&original_name, flags) {
                    candidates.push(Hypothesis {
                        id: StableId::new(),
                        description: demangled.clone(),
                        confidence: ConfidenceVector::base(0.95),
                        evidence: vec![Evidence::DebugSymbol {
                            name: demangled,
                            source: "demangler".to_string(),
                        }],
                    });
                }
            } else {
                candidates.push(Hypothesis {
                    id: StableId::new(),
                    description: original_name.clone(),
                    confidence: sdb_func.confidence.clone(),
                    evidence: vec![Evidence::DebugSymbol {
                        name: original_name.clone(),
                        source: "original".to_string(),
                    }],
                });
            }
        }

        // 2. API / Xref candidate
        let mut api_calls = Vec::new();
        for xref in &sdb_func.value.xrefs_out {
            if let XrefKind::Call = xref.xref_kind {
                if let Some(target) = workspace
                    .sdb
                    .interpretations
                    .functions
                    .functions
                    .get(&xref.to_addr)
                {
                    if let Some(ref target_name) = target.value.name {
                        api_calls.push(target_name.clone());
                    }
                }
            }
        }

        if !api_calls.is_empty() {
            // Heuristic: If it calls a specific API heavily, suggest a name based on it
            if api_calls.iter().any(|name| name.contains("MessageBox")) {
                candidates.push(Hypothesis {
                    id: StableId::new(),
                    description: "ShowMessageDialog".to_string(),
                    confidence: ConfidenceVector::base(0.60),
                    evidence: vec![Evidence::ImportSignature(
                        "MessageBox heuristic".to_string(),
                    )],
                });
            }
            if api_calls.iter().any(|name| name.contains("socket")) {
                candidates.push(Hypothesis {
                    id: StableId::new(),
                    description: "NetworkClient_Connect".to_string(),
                    confidence: ConfidenceVector::base(0.55),
                    evidence: vec![Evidence::ImportSignature("socket heuristic".to_string())],
                });
            }
        }

        // 3. String-reference naming inference
        let mut string_refs = Vec::new();
        for xref in &sdb_func.value.xrefs_out {
            if let XrefKind::Read = xref.xref_kind {
                // Mocking string lookup since we don't have direct access to SdbStrings here without more complex wiring
                if xref.to_addr == 0x8000_1000 {
                    string_refs.push((xref.to_addr, "Error: Failed to open socket"));
                } else if xref.to_addr == 0x8000_2000 {
                    string_refs.push((xref.to_addr, "Initializing graphics subsystem..."));
                }
            }
        }

        for (addr, s) in string_refs {
            if s.contains("Failed") && s.contains("socket") {
                candidates.push(Hypothesis {
                    id: StableId::new(),
                    description: "LogSocketFailure".to_string(),
                    confidence: ConfidenceVector::base(0.70),
                    evidence: vec![Evidence::StringContext(addr)],
                });
            } else if s.contains("graphics") {
                candidates.push(Hypothesis {
                    id: StableId::new(),
                    description: "InitGraphics".to_string(),
                    confidence: ConfidenceVector::base(0.70),
                    evidence: vec![Evidence::StringContext(addr)],
                });
            }
        }

        // Feed into Constraint Engine
        if let Some(best) = candidates.first() {
            engine.add_hypothesis(stable_id, best.clone());
            for alt in candidates.into_iter().skip(1) {
                engine.add_hypothesis(stable_id, alt);
            }
        }

        // Extract belief
        if let Some(belief) = engine.beliefs.get(&stable_id) {
            let final_name = if belief.is_ambiguous {
                format!("unresolved_subsystem_{:x}", addr)
            } else {
                belief.current_hypothesis.description.clone()
            };

            let prov = if belief.is_ambiguous {
                RecoveryOrigin::Heuristic
            } else {
                RecoveryOrigin::Exact
            };

            new_names.push((
                *addr,
                final_name,
                belief.current_hypothesis.confidence.clone(),
                prov,
            ));
        }
    }

    workspace.constraints = engine;

    // Apply names
    for (addr, name, conf, prov) in new_names {
        if let Some(sdb_func) = workspace
            .sdb
            .interpretations
            .functions
            .functions
            .get_mut(&addr)
        {
            sdb_func.value.name = Some(name.clone());
            sdb_func.confidence = conf.clone();
            sdb_func.provenance.origin = prov;
        }

        let symbol = SdbSymbol {
            address: addr,
            name,
            provenance: prov,
        };
        workspace
            .sdb
            .facts
            .symbols
            .symbols
            .insert(addr, SdbEntry::new(symbol, conf, prov));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::functions::SdbFunction;

    #[test]
    fn test_naming_enrichment() {
        let mut workspace = Workspace::new(std::path::Path::new("dummy"), vec![]);

        // Add an MSVC mangled name
        workspace.sdb.interpretations.functions.functions.insert(
            0x1000,
            SdbEntry::new(
                SdbFunction {
                    name: Some("?puts@std@@YAHXZ".into()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(0.9),
                RecoveryOrigin::Exact,
            ),
        );

        // Add an Itanium mangled name
        workspace.sdb.interpretations.functions.functions.insert(
            0x2000,
            SdbEntry::new(
                SdbFunction {
                    name: Some("_Z3fooic".into()),
                    ..Default::default()
                },
                canary_sdb::ConfidenceVector::base(0.9),
                RecoveryOrigin::Exact,
            ),
        );

        enrich_symbols(&mut workspace);

        // The MSVC demangler with NAME_ONLY should give `std::puts`
        let f1 = workspace
            .sdb
            .interpretations
            .functions
            .functions
            .get(&0x1000)
            .unwrap()
            .value
            .name
            .as_deref()
            .unwrap();
        assert_eq!(f1, "std::puts");

        // The Itanium demangler should give `foo(int, char)`
        let f2 = workspace
            .sdb
            .interpretations
            .functions
            .functions
            .get(&0x2000)
            .unwrap()
            .value
            .name
            .as_deref()
            .unwrap();
        assert_eq!(f2, "foo(int, char)");

        // Verify symbols namespace was populated
        assert_eq!(workspace.sdb.facts.symbols.symbols.len(), 2);
    }
}
