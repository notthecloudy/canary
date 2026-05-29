use canary_ir::function::FunctionArena;
use canary_ir::types::{IrType, TypeArena};
use canary_sdb::types::{SdbStruct, StructField};
use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};

pub fn recover_structs(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    let mut type_arena = TypeArena::new();

    for (_, func) in functions.iter() {
        if let Some(ssa) = &func.ssa {
            // Recompute VSA because it's not stored in the function
            let vsa = canary_analysis::vsa::analyze_vsa(ssa, &func.cfg);

            let accesses = canary_analysis::struct_inference::collect_struct_accesses(ssa, &vsa);
            let layouts =
                canary_analysis::struct_inference::infer_struct_layouts(&accesses, &mut type_arena);

            for (ssa_name, ty_id) in layouts {
                if let Some(IrType::Struct { name, fields }) = type_arena.get(ty_id) {
                    let mut sdb_fields = Vec::new();
                    for field in fields {
                        let size = match type_arena.get(field.ty) {
                            Some(IrType::Int { bit_width, .. }) => (bit_width / 8) as usize,
                            Some(IrType::Array { element, count }) => {
                                if let Some(IrType::Int { bit_width, .. }) =
                                    type_arena.get(*element)
                                {
                                    ((bit_width / 8) as u64 * count) as usize
                                } else {
                                    1
                                }
                            }
                            _ => 1,
                        };
                        sdb_fields.push(StructField {
                            offset: field.offset as i64,
                            name: Some(field.name.clone()),
                            size,
                            ty_hint: None,
                            bit_mask: None,
                            bit_shift: None,
                            bit_width: None,
                        });
                    }

                    let total_size = sdb_fields.iter().map(|f| f.size).sum();

                    let struct_name = name
                        .clone()
                        .unwrap_or_else(|| format!("Struct_{}_{}", ssa_name.reg, ssa_name.version));

                    sdb.interpretations.types.structs.push(SdbEntry::new(
                        SdbStruct {
                            name: struct_name,
                            fields: sdb_fields,
                            total_size,
                        },
                        canary_sdb::ConfidenceVector::base(0.6),
                        RecoveryOrigin::Inference,
                    ));
                }
            }
        }
    }
}
