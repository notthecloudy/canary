use canary_sdb::types::SdbClass;
use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};
use indexmap::IndexMap;

pub fn reconstruct_classes(sdb: &mut SemanticDatabase) {
    let mut classes_to_add = Vec::new();
    let mut class_id = 0;

    // Group vtables by class name
    let mut vtables_by_class: IndexMap<String, Vec<u64>> = IndexMap::new();

    for vt_entry in &sdb.interpretations.types.vtables {
        let name = vt_entry.value.class_name.clone().unwrap_or_else(|| {
            class_id += 1;
            format!("Class_{:04X}", class_id)
        });

        vtables_by_class
            .entry(name)
            .or_default()
            .push(vt_entry.value.addr);
    }

    // Build quick lookup maps
    let mut methods_by_vtable: IndexMap<u64, Vec<canary_sdb::types::SdbMethod>> = IndexMap::new();
    for method_entry in &sdb.interpretations.types.methods {
        methods_by_vtable
            .entry(method_entry.value.class_vtable)
            .or_default()
            .push(method_entry.value.clone());
    }

    let mut inh_by_vtable: IndexMap<u64, Vec<canary_sdb::types::SdbInheritance>> = IndexMap::new();
    for inh_entry in &sdb.interpretations.types.inheritance {
        inh_by_vtable
            .entry(inh_entry.value.derived_vtable)
            .or_default()
            .push(inh_entry.value.clone());
    }

    let mut vtable_by_addr = IndexMap::new();
    for vt_entry in &sdb.interpretations.types.vtables {
        vtable_by_addr.insert(vt_entry.value.addr, vt_entry.value.clone());
    }

    for (name, vtables) in vtables_by_class {
        let mut methods: Vec<canary_sdb::SdbMethod> = Vec::new();
        let mut bases: Vec<String> = Vec::new();

        for &vt_addr in &vtables {
            if let Some(vtable_methods) = methods_by_vtable.get(&vt_addr) {
                methods.extend(vtable_methods.iter().cloned());
            }

            if let Some(inhs) = inh_by_vtable.get(&vt_addr) {
                for inh in inhs {
                    for &base_vt in &inh.base_vtables {
                        if let Some(base_vtable) = vtable_by_addr.get(&base_vt) {
                            if let Some(base_name) = &base_vtable.class_name {
                                if !bases.contains(base_name) {
                                    bases.push(base_name.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        let class = SdbClass {
            name,
            vtables,
            methods,
            bases,
        };

        classes_to_add.push(SdbEntry::new(
            class,
            canary_sdb::ConfidenceVector::base(0.8),
            RecoveryOrigin::Heuristic,
        ));
    }

    sdb.interpretations.types.classes = classes_to_add;
}
