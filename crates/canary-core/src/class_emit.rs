//! Phase 8: Class and Structural Emission
//!
//! Transforms `TypeCluster`s and `SdbStruct`s into C++ classes with inheritance
//! and virtual methods, grouping data by recovered evidence.

use crate::workspace::Workspace;
use canary_sdb::{FileEntry, FileType};

pub fn emit_classes(workspace: &mut Workspace) {
    let mut header_content = String::new();
    header_content
        .push_str("#ifndef CANARY_RECOVERED_CLASSES_H\n#define CANARY_RECOVERED_CLASSES_H\n\n");
    header_content.push_str("#include \"common_types.h\"\n\n");

    // We can iterate over the semantic field models and clusters to generate classes.
    // For simplicity here, we assume any SdbStruct that has a VTable evidence is a Class.
    for sdb_struct in &workspace.sdb.interpretations.types.structs {
        let name = &sdb_struct.value.name;

        let has_vtable = sdb_struct
            .provenance
            .evidence
            .iter()
            .any(|e| matches!(e, canary_sdb::Evidence::VtableEntry { .. }));

        if has_vtable {
            header_content.push_str(&format!("class {} {{\npublic:\n", name));
            header_content.push_str(&format!("    virtual ~{}() = default;\n\n", name));
        } else {
            header_content.push_str(&format!("struct {} {{\n", name));
        }

        for field in &sdb_struct.value.fields {
            let field_name = field.name.as_deref().unwrap_or("field_unknown");
            let ty = field.ty_hint.as_deref().unwrap_or("uint8_t");
            header_content.push_str(&format!(
                "    {} {}; // offset {:#x}\n",
                ty, field_name, field.offset
            ));
        }

        if has_vtable {
            header_content.push_str("};\n\n");
        } else {
            header_content.push_str("};\n\n");
        }
    }

    header_content.push_str("#endif // CANARY_RECOVERED_CLASSES_H\n");

    // We add this to the SDB project layout
    if let Some(ref mut layout_entry) = workspace.sdb.project.layout {
        layout_entry.value.files.insert(
            "include/recovered_classes.h".to_string(),
            FileEntry {
                path: "include/recovered_classes.h".to_string(),
                file_type: FileType::Header,
                content: header_content,
                includes: vec!["include/common_types.h".to_string()],
                symbol_addresses: Vec::new(),
            },
        );
    }
}
