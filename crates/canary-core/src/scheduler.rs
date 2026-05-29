//! Pass scheduler — determines execution order for analysis passes.
//!
//! Passes declare their inputs and outputs as facts. The scheduler builds
//! a DAG of passes and executes them in topological order, running
//! embarrassingly-parallel passes concurrently via Rayon.

/// A tag identifying a fact produced or consumed by a pass.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FactTag(pub &'static str);

/// Metadata about an analysis pass for scheduling purposes.
#[derive(Debug, Clone)]
pub struct PassDescriptor {
    pub name: &'static str,
    pub requires: Vec<FactTag>,
    pub provides: Vec<FactTag>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    #[error("pass {pass} requires missing fact {fact}")]
    MissingFact {
        pass: &'static str,
        fact: &'static str,
    },
    #[error("pass dependency cycle or unsatisfied requirements")]
    Cycle,
}

pub fn schedule(
    passes: &[PassDescriptor],
    initial_facts: &[FactTag],
) -> Result<Vec<&'static str>, ScheduleError> {
    let mut available: std::collections::HashSet<FactTag> = initial_facts.iter().cloned().collect();
    let mut remaining: Vec<_> = passes.iter().collect();
    let mut ordered = Vec::with_capacity(passes.len());

    while !remaining.is_empty() {
        let mut made_progress = false;
        let mut idx = 0;

        while idx < remaining.len() {
            let pass = remaining[idx];
            if pass.requires.iter().all(|fact| available.contains(fact)) {
                let pass = remaining.remove(idx);
                for fact in &pass.provides {
                    available.insert(fact.clone());
                }
                ordered.push(pass.name);
                made_progress = true;
            } else {
                idx += 1;
            }
        }

        if !made_progress {
            let provided_later: std::collections::HashSet<FactTag> = remaining
                .iter()
                .flat_map(|pass| pass.provides.iter().cloned())
                .collect();
            for pass in &remaining {
                if let Some(missing) = pass
                    .requires
                    .iter()
                    .find(|fact| !available.contains(*fact) && !provided_later.contains(*fact))
                {
                    return Err(ScheduleError::MissingFact {
                        pass: pass.name,
                        fact: missing.0,
                    });
                }
            }
            return Err(ScheduleError::Cycle);
        }
    }

    Ok(ordered)
}

pub fn phase2_passes() -> Vec<PassDescriptor> {
    use facts::*;
    vec![
        PassDescriptor {
            name: "dominators",
            requires: vec![CFG],
            provides: vec![DOMINATORS],
        },
        PassDescriptor {
            name: "ssa",
            requires: vec![CFG, DOMINATORS],
            provides: vec![SSA_FORM],
        },
        PassDescriptor {
            name: "vsa",
            requires: vec![SSA_FORM],
            provides: vec![VALUE_SETS],
        },
        PassDescriptor {
            name: "pointer_provenance",
            requires: vec![SSA_FORM],
            provides: vec![POINTER_PROVENANCE],
        },
        PassDescriptor {
            name: "stack_vars",
            requires: vec![SSA_FORM, VALUE_SETS],
            provides: vec![STACK_FRAME],
        },
        PassDescriptor {
            name: "primitive_types",
            requires: vec![SSA_FORM],
            provides: vec![PRIMITIVE_TYPES],
        },
        PassDescriptor {
            name: "calling_conventions",
            requires: vec![SSA_FORM, VALUE_SETS, PRIMITIVE_TYPES],
            provides: vec![CALLING_CONVENTIONS],
        },
        PassDescriptor {
            name: "semantic_lowering",
            requires: vec![SSA_FORM, POINTER_PROVENANCE],
            provides: vec![SEMANTIC_IR],
        },
        PassDescriptor {
            name: "structuring",
            requires: vec![CFG, DOMINATORS],
            provides: vec![HIGH_LEVEL_CFG],
        },
        PassDescriptor {
            name: "mlil_lowering",
            requires: vec![
                SSA_FORM,
                CALLING_CONVENTIONS,
                SEMANTIC_IR,
                POINTER_PROVENANCE,
            ],
            provides: vec![MLIL],
        },
    ]
}

// Well-known fact tags
pub mod facts {
    use super::FactTag;
    pub const CFG: FactTag = FactTag("cfg");
    pub const DOMINATORS: FactTag = FactTag("dominators");
    pub const SSA_FORM: FactTag = FactTag("ssa_form");
    pub const VALUE_SETS: FactTag = FactTag("value_sets");
    pub const POINTER_PROVENANCE: FactTag = FactTag("pointer_provenance");
    pub const STACK_FRAME: FactTag = FactTag("stack_frame");
    pub const PRIMITIVE_TYPES: FactTag = FactTag("primitive_types");
    pub const SEMANTIC_IR: FactTag = FactTag("semantic_ir");
    pub const HIGH_LEVEL_CFG: FactTag = FactTag("high_level_cfg");
    pub const MLIL: FactTag = FactTag("mlil");
    pub const TYPE_GUESSES: FactTag = FactTag("type_guesses");
    pub const VTABLE_LAYOUTS: FactTag = FactTag("vtable_layouts");
    pub const CALLING_CONVENTIONS: FactTag = FactTag("calling_conventions");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase2_schedule_is_deterministic() {
        let first = schedule(&phase2_passes(), &[facts::CFG]).unwrap();
        let second = schedule(&phase2_passes(), &[facts::CFG]).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                "dominators",
                "ssa",
                "vsa",
                "pointer_provenance",
                "stack_vars",
                "primitive_types",
                "calling_conventions",
                "semantic_lowering",
                "structuring",
                "mlil_lowering"
            ]
        );
    }

    #[test]
    fn schedule_rejects_missing_facts() {
        let passes = vec![PassDescriptor {
            name: "needs_ssa",
            requires: vec![facts::SSA_FORM],
            provides: vec![facts::MLIL],
        }];

        let err = schedule(&passes, &[facts::CFG]).unwrap_err();
        assert_eq!(
            err,
            ScheduleError::MissingFact {
                pass: "needs_ssa",
                fact: "ssa_form"
            }
        );
    }
}
