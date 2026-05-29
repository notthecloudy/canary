use canary_ir::function::FunctionArena;
use canary_ir::llil::{LlilExpr, LlilInstr, LlilOp};
use canary_loader::binary::LoadedBinary;
use canary_sdb::types::SdbVtable;
use canary_sdb::SemanticDatabase;

pub fn detect_vtables(sdb: &mut SemanticDatabase, loaded: &LoadedBinary) {
    let mut new_vtables = Vec::new();

    // Scan .rodata sections for consecutive code pointers.
    // We assume 64-bit pointers for x86_64 and aarch64, and 32-bit for x86.
    let ptr_size = if loaded.arch_name == "x86" { 4 } else { 8 };

    let mut code_ranges = Vec::new();
    let mut data_ranges = Vec::new();
    for s in &loaded.sections {
        if s.flags.executable || s.name == ".text" || s.name == ".code" {
            code_ranges.push(s.virtual_range.clone());
        } else {
            data_ranges.push(s.virtual_range.clone());
        }
    }

    let is_code_ptr = |ptr: u64| -> bool { code_ranges.iter().any(|r| r.contains(&ptr)) };

    let is_data_ptr = |ptr: u64| -> bool { data_ranges.iter().any(|r| r.contains(&ptr)) };

    for section in &loaded.sections {
        if section.flags.executable || section.flags.writable {
            continue; // We only want rodata
        }

        let data = &section.data;
        let base_addr = section.virtual_range.start;

        let mut i = 0;
        let mut current_vtable = Vec::new();
        let mut current_start = 0;

        while i + ptr_size <= data.len() {
            let ptr = if ptr_size == 4 {
                u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as u64
            } else {
                u64::from_le_bytes(data[i..i + 8].try_into().unwrap())
            };

            let is_first = current_vtable.is_empty();
            let is_rtti_slot = is_first && is_data_ptr(ptr);

            if is_code_ptr(ptr) || is_rtti_slot {
                if current_vtable.is_empty() {
                    current_start = base_addr + i as u64;
                }
                current_vtable.push(ptr);
            } else {
                if current_vtable.len() >= 2 {
                    new_vtables.push(SdbVtable {
                        addr: current_start,
                        entries: current_vtable.clone(),
                        class_name: None,
                        base_vtable: None,
                    });
                }
                current_vtable.clear();
            }
            i += ptr_size;
        }

        if current_vtable.len() >= 2 {
            new_vtables.push(SdbVtable {
                addr: current_start,
                entries: current_vtable,
                class_name: None,
                base_vtable: None,
            });
        }
    }

    for vt in new_vtables {
        let mut confidence: f32 = 0.3; // Base probability

        // Signal: all entries are valid executable pointers (trivially true here, but good for scoring)
        if vt.entries.iter().all(|&p| is_code_ptr(p)) {
            confidence += 0.2;
        }

        // Signal: length
        if vt.entries.len() >= 4 {
            confidence += 0.2;
        } else if vt.entries.len() == 2 {
            confidence -= 0.1;
        }

        confidence = confidence.clamp(0.1, 0.9);

        sdb.interpretations
            .types
            .vtables
            .push(canary_sdb::SdbEntry::new(
                vt,
                canary_sdb::ConfidenceVector::base(confidence),
                canary_sdb::RecoveryOrigin::Heuristic,
            ));
    }
}

pub fn assign_vtables(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    let mut methods_to_add = Vec::new();

    // To avoid O(N^2) linear searching, build a map from vtable address to its index in the SDB.
    let mut vtable_map = indexmap::IndexMap::new();
    for (idx, entry) in sdb.interpretations.types.vtables.iter().enumerate() {
        vtable_map.insert(entry.value.addr, idx);
    }

    for (_id, func) in functions.iter() {
        if let Some(entry_id) = func.cfg.entry() {
            if let Some(block) = func.cfg.block(entry_id) {
                for instr in &block.instrs {
                    if let LlilInstr::Store {
                        addr,
                        value,
                        size: _,
                        ..
                    } = instr
                    {
                        let is_this = match addr {
                            LlilExpr::Reg { .. } => true,
                            LlilExpr::BinOp {
                                op: LlilOp::Add,
                                lhs,
                                ..
                            } => {
                                matches!(func.cfg.exprs.get(*lhs).unwrap(), LlilExpr::Reg { .. })
                            }
                            _ => false,
                        };

                        if is_this {
                            if let LlilExpr::Const {
                                value: const_val, ..
                            } = value
                            {
                                let vtable_addr = *const_val;

                                if let Some(&idx) = vtable_map.get(&vtable_addr) {
                                    let vtable_entry = &mut sdb.interpretations.types.vtables[idx];
                                    let class_name = format!("class_{:x}", func.entry_addr);
                                    vtable_entry.value.class_name = Some(class_name);

                                    methods_to_add.push(canary_sdb::SdbEntry::new(
                                        canary_sdb::types::SdbMethod {
                                            fn_addr: func.entry_addr,
                                            class_vtable: vtable_addr,
                                            is_virtual: false,
                                            slot: None,
                                            is_ctor: true,
                                            is_dtor: false,
                                        },
                                        crate::cpp_confidence().score,
                                        canary_sdb::RecoveryOrigin::Pattern,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    sdb.interpretations.types.methods.extend(methods_to_add);

    // Negative Evidence Filter:
    // If a vtable is NEVER instantiated (i.e. no constructor assigns it to `this`),
    // then it's just a random array of pointers (like a jump table), not a class!
    sdb.interpretations
        .types
        .vtables
        .retain(|vt| vt.value.class_name.is_some());
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_loader::section::{Section, SectionFlags, SectionKind};

    #[test]
    fn test_vtable_detection() {
        let mut sdb = SemanticDatabase::new();

        let code_section = Section {
            name: ".text".to_string(),
            virtual_range: 0x1000..0x2000,
            data: vec![0; 0x1000],
            flags: SectionFlags {
                readable: true,
                writable: false,
                executable: true,
            },
            kind: SectionKind::Code,
        };

        let mut rodata_bytes = vec![0u8; 8 * 6];
        // fn1: 0x1100, fn2: 0x1110, fn3: 0x1120, fn4: 0x1130
        let ptrs: [u64; 6] = [0x500, 0x1100, 0x1110, 0x1120, 0x1130, 0x3000];
        for (i, p) in ptrs.iter().enumerate() {
            rodata_bytes[i * 8..(i + 1) * 8].copy_from_slice(&p.to_le_bytes());
        }

        let rodata_section = Section {
            name: ".rodata".to_string(),
            virtual_range: 0x4000..0x4000 + 48,
            data: rodata_bytes,
            flags: SectionFlags {
                readable: true,
                writable: false,
                executable: false,
            },
            kind: SectionKind::ReadOnlyData,
        };

        let loaded = LoadedBinary {
            format: canary_loader::binary::BinaryFormat::Elf,
            arch_name: "x86_64".to_string(),
            image_base: 0,
            entry_point: 0x1000,
            sections: vec![code_section, rodata_section],
            named_functions: vec![],
            imports: vec![],
            exports: vec![],
            relocations: vec![],
            debug_info: vec![],
            toolchain: Vec::new(),
            resources: Vec::new(),
            packers: Vec::new(),
            eh_frames: Vec::new(),
            tls_callbacks: Vec::new(),
            delay_imports: Vec::new(),
            strings: Vec::new(),
            com_descriptors: Vec::new(),
            rich_header_data: Vec::new(),
            exception_tables: Vec::new(),
        };

        detect_vtables(&mut sdb, &loaded);

        assert_eq!(sdb.interpretations.types.vtables.len(), 1);
        let vt = &sdb.interpretations.types.vtables[0].value;
        assert_eq!(vt.addr, 0x4008);
        assert_eq!(vt.entries.len(), 4);
        assert_eq!(vt.entries, vec![0x1100, 0x1110, 0x1120, 0x1130]);
    }

    #[test]
    fn test_assign_vtables() {
        use canary_ir::function::Function;
        use canary_ir::llil::{OperandSize, Reg};

        let mut sdb = SemanticDatabase::new();
        sdb.interpretations
            .types
            .vtables
            .push(canary_sdb::SdbEntry::new(
                SdbVtable {
                    addr: 0x4008,
                    entries: vec![0x1100, 0x1110],
                    class_name: None,
                    base_vtable: None,
                },
                canary_sdb::ConfidenceVector::base(0.6),
                canary_sdb::RecoveryOrigin::Pattern,
            ));

        let mut functions = FunctionArena::new();
        let mut func = Function::new(0x2000);
        let block_id = func.cfg.alloc_block(0x2000);
        func.cfg.set_entry(block_id);

        let block = func.cfg.block_mut(block_id).unwrap();
        block.instrs.push(LlilInstr::Store {
            confidence: Default::default(),
            addr: LlilExpr::Reg {
                reg: Reg(1),
                size: OperandSize::Bits64,
            }, // this
            value: LlilExpr::Const {
                value: 0x4008,
                size: OperandSize::Bits64,
            },
            size: OperandSize::Bits64,
        });

        functions.alloc(func);

        assign_vtables(&mut sdb, &functions);

        assert_eq!(sdb.interpretations.types.methods.len(), 1);
        let method = &sdb.interpretations.types.methods[0].value;
        assert_eq!(method.fn_addr, 0x2000);
        assert_eq!(method.class_vtable, 0x4008);
        assert!(method.is_ctor);

        let vtable = &sdb.interpretations.types.vtables[0].value;
        assert_eq!(vtable.class_name, Some("class_2000".to_string()));
    }
}
