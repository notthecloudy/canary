use canary_sdb::types::SdbInheritance;
use canary_sdb::SemanticDatabase;

pub fn detect_inheritance(sdb: &mut SemanticDatabase) {
    let mut inheritances = Vec::new();

    // Build a map of vtable entries array -> vtable address
    // To handle collisions, we could use a Vec<u64>, but for exact prefix matching,
    // finding any matching base vtable is sufficient.
    let mut entries_to_vtable = indexmap::IndexMap::new();
    for vtable in &sdb.interpretations.types.vtables {
        let vt = &vtable.value;
        if !vt.entries.is_empty() {
            entries_to_vtable.insert(vt.entries.clone(), vt.addr);
        }
    }

    for vtable_b_entry in &sdb.interpretations.types.vtables {
        let vtable_b = &vtable_b_entry.value;
        let entries_b = &vtable_b.entries;

        if entries_b.len() > 1 {
            // Check all valid prefixes (lengths 1 to B.len() - 1)
            for prefix_len in (1..entries_b.len()).rev() {
                let prefix = &entries_b[0..prefix_len];
                if let Some(&base_addr) = entries_to_vtable.get(prefix) {
                    inheritances.push(SdbInheritance {
                        derived_vtable: vtable_b.addr,
                        base_vtables: vec![base_addr],
                    });
                    break; // Only match the longest prefix (immediate base)
                }
            }
        }
    }

    // Process base_vtable pointers in vtable structs as well
    for inh in &inheritances {
        if let Some(vtable_b) = sdb
            .interpretations
            .types
            .vtables
            .iter_mut()
            .find(|v| v.value.addr == inh.derived_vtable)
        {
            vtable_b.value.base_vtable = Some(inh.base_vtables[0]);
        }
    }

    for inh in inheritances {
        sdb.interpretations
            .types
            .inheritance
            .push(canary_sdb::SdbEntry::new(
                inh,
                crate::cpp_confidence().score,
                canary_sdb::RecoveryOrigin::Pattern,
            ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::types::SdbVtable;
    use canary_sdb::SdbEntry;

    #[test]
    fn test_detect_inheritance() {
        let mut sdb = SemanticDatabase::new();

        let vtable_a = SdbVtable {
            addr: 0x1000,
            entries: vec![0x100, 0x110],
            class_name: None,
            base_vtable: None,
        };

        let vtable_b = SdbVtable {
            addr: 0x2000,
            entries: vec![0x100, 0x110, 0x120], // extends A
            class_name: None,
            base_vtable: None,
        };

        sdb.interpretations.types.vtables.push(SdbEntry::new(
            vtable_a,
            canary_sdb::ConfidenceVector::base(1.0),
            canary_sdb::RecoveryOrigin::Pattern,
        ));
        sdb.interpretations.types.vtables.push(SdbEntry::new(
            vtable_b,
            canary_sdb::ConfidenceVector::base(1.0),
            canary_sdb::RecoveryOrigin::Pattern,
        ));

        detect_inheritance(&mut sdb);

        assert_eq!(sdb.interpretations.types.inheritance.len(), 1);
        let inh = &sdb.interpretations.types.inheritance[0].value;
        assert_eq!(inh.derived_vtable, 0x2000);
        assert_eq!(inh.base_vtables, vec![0x1000]);

        // Also checks if base_vtable is set
        let vtable_b_updated = &sdb.interpretations.types.vtables[1].value;
        assert_eq!(vtable_b_updated.base_vtable, Some(0x1000));
    }
}
