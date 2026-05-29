use canary_sdb::types::SdbStruct;
use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};

/// Inspects `sdb.facts.binary.sections` for a `.debug_info` section (DWARF presence).
/// If found, records a marker `SdbStruct` with confidence 0.3 indicating that DWARF data
/// is present but a full gimli pass has not yet been run.
/// If no DWARF section is present, does nothing.
pub fn import_dwarf_types(sdb: &mut SemanticDatabase) {
    let has_dwarf = sdb
        .facts
        .binary
        .sections
        .iter()
        .any(|entry| entry.value.name == ".debug_info" || entry.value.name == ".debug_abbrev");

    if has_dwarf {
        sdb.interpretations.types.structs.push(SdbEntry::new(
            SdbStruct {
                name: "_dwarf_present_".to_string(),
                total_size: 0,
                fields: vec![],
            },
            canary_sdb::ConfidenceVector::base(0.3),
            RecoveryOrigin::Debug,
        ));
    }
}

/// Inspects `sdb.binary.debug_info` for a CodeView entry (PDB path in PE binaries).
/// If found and the path is non-empty, records a marker `SdbStruct` named after the PDB file
/// with confidence 0.3, indicating PDB data is present but not yet parsed.
/// If no CodeView entry is present, does nothing.
pub fn import_pdb_types(sdb: &mut SemanticDatabase) {
    let pdb_path = sdb
        .facts
        .binary
        .debug_info
        .iter()
        .find(|entry| entry.value.info_type == "CodeView")
        .and_then(|entry| entry.value.path.clone());

    if let Some(path) = pdb_path {
        if !path.is_empty() {
            // Extract just the filename for the marker name
            let pdb_name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path)
                .to_string();

            sdb.interpretations.types.structs.push(SdbEntry::new(
                SdbStruct {
                    name: format!("_pdb_present_{}_", pdb_name),
                    total_size: 0,
                    fields: vec![],
                },
                canary_sdb::ConfidenceVector::base(0.3),
                RecoveryOrigin::Debug,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::{DebugInfo, MappedSection};

    #[test]
    fn test_import_dwarf_types_no_debug_section() {
        let mut sdb = SemanticDatabase::new();
        import_dwarf_types(&mut sdb);
        // No .debug_info section → nothing written
        assert_eq!(sdb.interpretations.types.structs.len(), 0);
    }

    #[test]
    fn test_import_dwarf_types_with_debug_section() {
        let mut sdb = SemanticDatabase::new();
        sdb.facts.binary.sections.push(SdbEntry::new(
            MappedSection {
                name: ".debug_info".to_string(),
                address: 0x1000,
                size: 256,
            },
            canary_sdb::ConfidenceVector::base(1.0),
            RecoveryOrigin::Exact,
        ));
        import_dwarf_types(&mut sdb);
        assert_eq!(sdb.interpretations.types.structs.len(), 1);
        let s = &sdb.interpretations.types.structs[0];
        assert_eq!(s.provenance.origin, RecoveryOrigin::Debug);
        assert_eq!(s.value.name, "_dwarf_present_");
        assert!((s.confidence.composite() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_import_pdb_types_no_codeview() {
        let mut sdb = SemanticDatabase::new();
        import_pdb_types(&mut sdb);
        // No CodeView entry → nothing written
        assert_eq!(sdb.interpretations.types.structs.len(), 0);
    }

    #[test]
    fn test_import_pdb_types_with_codeview() {
        let mut sdb = SemanticDatabase::new();
        sdb.facts.binary.debug_info.push(SdbEntry::new(
            DebugInfo {
                info_type: "CodeView".to_string(),
                path: Some("C:\\build\\foo.pdb".to_string()),
                guid: None,
            },
            canary_sdb::ConfidenceVector::base(1.0),
            RecoveryOrigin::Exact,
        ));
        import_pdb_types(&mut sdb);
        assert_eq!(sdb.interpretations.types.structs.len(), 1);
        let s = &sdb.interpretations.types.structs[0];
        assert_eq!(s.provenance.origin, RecoveryOrigin::Debug);
        assert!(
            s.value.name.contains("foo.pdb"),
            "name was: {}",
            s.value.name
        );
        assert!((s.confidence.composite() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_import_pdb_types_empty_path() {
        let mut sdb = SemanticDatabase::new();
        sdb.facts.binary.debug_info.push(SdbEntry::new(
            DebugInfo {
                info_type: "CodeView".to_string(),
                path: Some(String::new()),
                guid: None,
            },
            canary_sdb::ConfidenceVector::base(1.0),
            RecoveryOrigin::Exact,
        ));
        import_pdb_types(&mut sdb);
        // Empty path → nothing written
        assert_eq!(sdb.interpretations.types.structs.len(), 0);
    }
}
