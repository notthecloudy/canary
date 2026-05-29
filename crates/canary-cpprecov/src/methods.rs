use canary_ir::function::FunctionArena;
use canary_ir::llil::LlilInstr;
use canary_sdb::SemanticDatabase;

pub fn recover_methods(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    let mut methods_to_add = Vec::new();

    // Precompute a map of entry_addr to function reference to avoid O(N^2) lookups
    let mut func_map = indexmap::IndexMap::new();
    for (id, func) in functions.iter() {
        func_map.insert(func.entry_addr, (id, func));
    }

    // For each vtable, recover virtual methods
    for vtable_entry in &sdb.interpretations.types.vtables {
        let vt = &vtable_entry.value;

        for (slot_idx, &fn_addr) in vt.entries.iter().enumerate() {
            let mut is_dtor = false;

            // Check if it's a destructor by inspecting if it calls free/delete
            if let Some((_id, func)) = func_map.get(&fn_addr) {
                // Look for calls
                for block in func.cfg.blocks() {
                    for instr in &block.instrs {
                        if let LlilInstr::Call { target, .. } = instr {
                            if let canary_ir::llil::LlilExpr::Const {
                                value: call_target, ..
                            } = target
                            {
                                // Is this call_target an import for free/delete?
                                // We check sdb.facts.binary.imports
                                if sdb.facts.binary.imports.iter().any(|imp| {
                                    imp.value.address == *call_target
                                        && (imp.value.symbol_name.contains("free")
                                            || imp.value.symbol_name.contains("delete"))
                                }) {
                                    is_dtor = true;
                                }
                            }
                        }
                    }
                }
            }

            methods_to_add.push(canary_sdb::SdbEntry::new(
                canary_sdb::types::SdbMethod {
                    fn_addr,
                    class_vtable: vt.addr,
                    is_virtual: true,
                    slot: Some(slot_idx),
                    is_ctor: false,
                    is_dtor,
                },
                crate::cpp_confidence().score,
                canary_sdb::RecoveryOrigin::Pattern,
            ));
        }
    }

    sdb.interpretations.types.methods.extend(methods_to_add);
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_ir::function::Function;
    use canary_ir::llil::{LlilExpr, OperandSize};
    use canary_sdb::types::SdbVtable;

    #[test]
    fn test_recover_methods() {
        let mut sdb = SemanticDatabase::new();
        let vt_addr = 0x4000;
        let fn1 = 0x1000;
        let fn2 = 0x1100;

        sdb.interpretations
            .types
            .vtables
            .push(canary_sdb::SdbEntry::new(
                SdbVtable {
                    addr: vt_addr,
                    entries: vec![fn1, fn2],
                    class_name: None,
                    base_vtable: None,
                },
                canary_sdb::ConfidenceVector::base(1.0),
                canary_sdb::RecoveryOrigin::Pattern,
            ));

        let free_addr = 0x9000;
        sdb.facts.binary.imports.push(canary_sdb::SdbEntry::new(
            canary_sdb::Import {
                lib_name: "libc.so".to_string(),
                symbol_name: "free".to_string(),
                address: free_addr,
            },
            canary_sdb::ConfidenceVector::base(1.0),
            canary_sdb::RecoveryOrigin::Exact,
        ));

        let mut functions = FunctionArena::new();

        let mut func2 = Function::new(fn2);
        let block_id = func2.cfg.alloc_block(fn2);
        func2.cfg.set_entry(block_id);

        let block = func2.cfg.block_mut(block_id).unwrap();
        block.instrs.push(LlilInstr::Call {
            confidence: Default::default(),
            target: LlilExpr::Const {
                value: free_addr,
                size: OperandSize::Bits64,
            },
            args: vec![],
            ret: None,
        });

        functions.alloc(func2);

        recover_methods(&mut sdb, &functions);

        assert_eq!(sdb.interpretations.types.methods.len(), 2);

        let m1 = &sdb.interpretations.types.methods[0].value;
        assert_eq!(m1.fn_addr, fn1);
        assert_eq!(m1.slot, Some(0));
        assert!(!m1.is_dtor);
        assert!(m1.is_virtual);

        let m2 = &sdb.interpretations.types.methods[1].value;
        assert_eq!(m2.fn_addr, fn2);
        assert_eq!(m2.slot, Some(1));
        assert!(m2.is_dtor); // Should be detected due to 'free' call
        assert!(m2.is_virtual);
    }
}
