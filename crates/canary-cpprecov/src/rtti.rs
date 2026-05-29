use canary_loader::binary::LoadedBinary;
use canary_sdb::SemanticDatabase;

pub fn recover_rtti(sdb: &mut SemanticDatabase, loaded: &LoadedBinary) {
    let is_x86 = loaded.arch_name == "x86";
    let ptr_size = if is_x86 { 4 } else { 8 };

    for vtable in &mut sdb.interpretations.types.vtables {
        let vt_addr = vtable.value.addr;
        let col_ptr_addr = if let Some(&first_ptr) = vtable.value.entries.first() {
            if loaded
                .sections
                .iter()
                .any(|s| !s.flags.executable && s.contains(first_ptr))
            {
                vt_addr // The RTTI pointer is exactly at vt_addr
            } else {
                vt_addr.saturating_sub(ptr_size as u64) // Legacy check before it
            }
        } else {
            vt_addr.saturating_sub(ptr_size as u64)
        };

        if let Some(col_ptr_bytes) = loaded.bytes_at(col_ptr_addr, ptr_size) {
            let col_addr = if is_x86 {
                if let Ok(b) = col_ptr_bytes.try_into() {
                    u32::from_le_bytes(b) as u64
                } else {
                    continue;
                }
            } else {
                if let Ok(b) = col_ptr_bytes.try_into() {
                    u64::from_le_bytes(b)
                } else {
                    continue;
                }
            };

            if let Some(sig_bytes) = loaded.bytes_at(col_addr, 4) {
                if let Ok(sig_arr) = sig_bytes.try_into() {
                    let signature = u32::from_le_bytes(sig_arr);
                    let is_valid_sig = (is_x86 && signature == 0) || (!is_x86 && signature == 1);

                    if is_valid_sig {
                        if let Some(type_desc_rva_bytes) = loaded.bytes_at(col_addr + 12, 4) {
                            if let Ok(type_desc_arr) = type_desc_rva_bytes.try_into() {
                                let type_desc_val = u32::from_le_bytes(type_desc_arr);

                                let type_desc_addr = if is_x86 {
                                    type_desc_val as u64
                                } else {
                                    loaded.image_base + type_desc_val as u64
                                };

                                let name_addr = type_desc_addr + (2 * ptr_size as u64);
                                let mut name = String::new();
                                let mut curr_addr = name_addr;

                                while let Some(&[b]) = loaded.bytes_at(curr_addr, 1) {
                                    if b == 0 {
                                        break;
                                    }
                                    name.push(b as char);
                                    curr_addr += 1;
                                    if name.len() > 255 {
                                        break;
                                    }
                                }

                                if !name.is_empty() && name.starts_with(".?A") {
                                    let demangled = name
                                        .trim_start_matches(".?AV")
                                        .trim_start_matches(".?AU")
                                        .trim_end_matches("@@");

                                    vtable.value.class_name = Some(demangled.to_string());
                                    vtable.confidence = canary_sdb::ConfidenceVector::base(0.95);
                                    // RTTI is highly confident
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_loader::section::{Section, SectionFlags, SectionKind};
    use canary_sdb::types::SdbVtable;
    use canary_sdb::SdbEntry;

    #[test]
    fn test_recover_rtti() {
        let mut sdb = SemanticDatabase::new();
        sdb.interpretations.types.vtables.push(SdbEntry::new(
            SdbVtable {
                addr: 0x2008,
                entries: vec![0x1000],
                class_name: None,
                base_vtable: None,
            },
            canary_sdb::ConfidenceVector::base(0.6),
            canary_sdb::RecoveryOrigin::Pattern,
        ));

        let mut rdata_bytes = vec![0u8; 0x100];
        // vtable is at 0x2008, ptr is at 0x2000 (size 8). It points to COL at 0x2020.
        rdata_bytes[0..8].copy_from_slice(&0x2020u64.to_le_bytes()); // COL ptr

        // COL at 0x2020 (offset 0x20 in rdata)
        // sig=1 (offset 0x20)
        rdata_bytes[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        // pTypeDesc at offset +12 = 0x2C
        // It points to TypeDesc RVA: 0x2040. So we put 0x2040 here.
        rdata_bytes[0x2C..0x30].copy_from_slice(&0x2040u32.to_le_bytes());

        // TypeDesc at 0x2040 (offset 0x40 in rdata)
        // 2 ptrs = 16 bytes. Name at offset 0x40 + 16 = 0x50.
        // name = ".?AVTestClass@@\0"
        let name = b".?AVTestClass@@\0";
        rdata_bytes[0x50..0x50 + name.len()].copy_from_slice(name);

        let section = Section {
            name: ".rdata".to_string(),
            virtual_range: 0x2000..0x2100,
            data: rdata_bytes,
            flags: SectionFlags {
                readable: true,
                writable: false,
                executable: false,
            },
            kind: SectionKind::ReadOnlyData,
        };

        let loaded = LoadedBinary {
            format: canary_loader::binary::BinaryFormat::Pe,
            arch_name: "x86_64".to_string(),
            image_base: 0,
            entry_point: 0x1000,
            sections: vec![section],
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

        recover_rtti(&mut sdb, &loaded);

        let vtable = &sdb.interpretations.types.vtables[0].value;
        assert_eq!(vtable.class_name, Some("TestClass".to_string()));
    }
}
