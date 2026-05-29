//! Diff and Comparison Tools
//!
//! Provides the ability to semantically diff two SemanticDatabase instances,
//! highlighting added, removed, and modified functions, types, and resources.

use canary_sdb::SemanticDatabase;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub added_functions: Vec<u64>,
    pub removed_functions: Vec<u64>,
    pub modified_functions: Vec<u64>,

    pub added_types: Vec<String>,
    pub removed_types: Vec<String>,

    pub added_modules: Vec<String>,
    pub removed_modules: Vec<String>,

    pub added_resources: Vec<String>,
    pub removed_resources: Vec<String>,
}

pub struct SemanticDiff;

impl SemanticDiff {
    pub fn compare(old: &SemanticDatabase, new: &SemanticDatabase) -> DiffReport {
        // Functions
        let old_funcs: HashSet<u64> = old
            .interpretations
            .functions
            .functions
            .keys()
            .copied()
            .collect();
        let new_funcs: HashSet<u64> = new
            .interpretations
            .functions
            .functions
            .keys()
            .copied()
            .collect();

        let added_functions: Vec<u64> = new_funcs.difference(&old_funcs).copied().collect();
        let removed_functions: Vec<u64> = old_funcs.difference(&new_funcs).copied().collect();

        let mut modified_functions = Vec::new();
        for func in old_funcs.intersection(&new_funcs) {
            let old_func = old.interpretations.functions.functions.get(func).unwrap();
            let new_func = new.interpretations.functions.functions.get(func).unwrap();

            if old_func.value.cfg_blocks.len() != new_func.value.cfg_blocks.len()
                || old_func.value.xrefs_out.len() != new_func.value.xrefs_out.len()
            {
                modified_functions.push(*func);
            }
        }

        // Types
        let old_types: HashSet<String> = old
            .interpretations
            .types
            .structs
            .iter()
            .map(|s| s.value.name.clone())
            .collect();
        let new_types: HashSet<String> = new
            .interpretations
            .types
            .structs
            .iter()
            .map(|s| s.value.name.clone())
            .collect();

        let added_types: Vec<String> = new_types.difference(&old_types).cloned().collect();
        let removed_types: Vec<String> = old_types.difference(&new_types).cloned().collect();

        // Modules (Sections)
        let old_modules: HashSet<String> = old
            .facts
            .binary
            .sections
            .iter()
            .map(|s| s.value.name.clone())
            .collect();
        let new_modules: HashSet<String> = new
            .facts
            .binary
            .sections
            .iter()
            .map(|s| s.value.name.clone())
            .collect();

        let added_modules: Vec<String> = new_modules.difference(&old_modules).cloned().collect();
        let removed_modules: Vec<String> = old_modules.difference(&new_modules).cloned().collect();

        // Resources (Strings)
        let old_resources: HashSet<String> = old
            .interpretations
            .types
            .strings
            .iter()
            .map(|s| s.value.value.clone())
            .collect();
        let new_resources: HashSet<String> = new
            .interpretations
            .types
            .strings
            .iter()
            .map(|s| s.value.value.clone())
            .collect();

        let added_resources: Vec<String> =
            new_resources.difference(&old_resources).cloned().collect();
        let removed_resources: Vec<String> =
            old_resources.difference(&new_resources).cloned().collect();

        DiffReport {
            added_functions,
            removed_functions,
            modified_functions,
            added_types,
            removed_types,
            added_modules,
            removed_modules,
            added_resources,
            removed_resources,
        }
    }

    pub fn to_markdown(report: &DiffReport) -> String {
        let mut md = String::new();
        md.push_str("# Semantic Diff Report\n\n");
        md.push_str("## Functions\n");
        md.push_str(&format!("- **Added**: {}\n", report.added_functions.len()));
        md.push_str(&format!(
            "- **Removed**: {}\n",
            report.removed_functions.len()
        ));
        md.push_str(&format!(
            "- **Modified**: {}\n\n",
            report.modified_functions.len()
        ));

        md.push_str("## Types\n");
        md.push_str(&format!("- **Added**: {}\n", report.added_types.len()));
        md.push_str(&format!(
            "- **Removed**: {}\n\n",
            report.removed_types.len()
        ));

        md.push_str("## Modules\n");
        md.push_str(&format!("- **Added**: {}\n", report.added_modules.len()));
        md.push_str(&format!(
            "- **Removed**: {}\n\n",
            report.removed_modules.len()
        ));

        md.push_str("## Resources\n");
        md.push_str(&format!("- **Added**: {}\n", report.added_resources.len()));
        md.push_str(&format!(
            "- **Removed**: {}\n\n",
            report.removed_resources.len()
        ));
        md
    }

    pub fn to_json(report: &DiffReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }
}
