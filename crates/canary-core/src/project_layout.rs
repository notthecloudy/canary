use crate::workspace::Workspace;
use canary_sdb::{FileEntry, FileType, ProjectLayout, RecoveryOrigin, SdbEntry};
use indexmap::IndexMap;

pub fn recover_project_layout(workspace: &mut Workspace) {
    let mut files = IndexMap::new();

    // 1. Gather all functions from SDB/workspace
    let function_addrs: Vec<u64> = workspace
        .functions
        .iter()
        .map(|(_, f)| f.entry_addr)
        .collect();

    // 2. Identify modules or group by default using Subsystems
    let mut module_to_funcs: IndexMap<String, Vec<u64>> = IndexMap::new();

    // Check subsystems in SDB
    if !workspace.sdb.interpretations.subsystems.is_empty() {
        for subsystem in &workspace.sdb.interpretations.subsystems {
            let mod_name = subsystem.name.clone();
            module_to_funcs.insert(mod_name, subsystem.functions.iter().copied().collect());
        }
    } else if !workspace.sdb.interpretations.modules.modules.is_empty() {
        for sdb_mod in workspace.sdb.interpretations.modules.modules.values() {
            let mod_name = sdb_mod.value.name.clone();
            module_to_funcs.insert(mod_name, sdb_mod.value.functions.clone());
        }
    } else {
        // Default cluster
        module_to_funcs.insert("main_module".to_string(), function_addrs.clone());
    }

    // 3. Collect types and classify where they should go
    let mut common_types_content = String::new();
    common_types_content
        .push_str("#ifndef CANARY_COMMON_TYPES_H\n#define CANARY_COMMON_TYPES_H\n\n");
    common_types_content.push_str("#include <stdint.h>\n#include <stdbool.h>\n\n");
    common_types_content.push_str("typedef uint64_t u64;\ntypedef uint32_t u32;\ntypedef uint16_t u16;\ntypedef uint8_t u8;\n");
    common_types_content.push_str(
        "typedef int64_t i64;\ntypedef int32_t i32;\ntypedef int16_t i16;\ntypedef int8_t i8;\n",
    );
    common_types_content.push_str("typedef void* unknown;\ntypedef void* unknown_type;\n");
    common_types_content.push_str("#include <emmintrin.h>\n");
    common_types_content.push_str("typedef __m128i uint128_t;\n\n");

    // Print structs in common_types.h
    for sdb_struct in &workspace.sdb.interpretations.types.structs {
        let name = &sdb_struct.value.name;
        common_types_content.push_str(&format!("struct {} {{\n", name));
        for field in &sdb_struct.value.fields {
            let field_name = field.name.as_deref().unwrap_or("field_unknown");
            let ty = field.ty_hint.as_deref().unwrap_or("uint8_t");
            common_types_content.push_str(&format!(
                "    {} {}; // offset {:#x}, size: {}\n",
                ty, field_name, field.offset, field.size
            ));
        }
        common_types_content.push_str("};\n\n");
    }

    // Print enums in common_types.h
    for sdb_enum in &workspace.sdb.interpretations.types.enums {
        let name = &sdb_enum.value.name;
        common_types_content.push_str(&format!("enum {} {{\n", name));
        for variant in &sdb_enum.value.variants {
            common_types_content.push_str(&format!(
                "    {} = {},\n",
                variant.name, variant.discriminant
            ));
        }
        common_types_content.push_str("};\n\n");
    }

    common_types_content.push_str("#endif // CANARY_COMMON_TYPES_H\n");

    // Add `common_types.h` to the project in include/
    files.insert(
        "include/common_types.h".to_string(),
        FileEntry {
            path: "include/common_types.h".to_string(),
            file_type: FileType::Header,
            content: common_types_content,
            includes: Vec::new(),
            symbol_addresses: Vec::new(),
        },
    );

    // 4. Create files for each module
    let mut cmake_sources = Vec::new();

    for (mod_name, funcs) in &module_to_funcs {
        let header_path = format!("include/{}.h", mod_name);
        let source_path = format!("src/{}.cpp", mod_name);
        cmake_sources.push(source_path.clone());

        // Header content
        let mut header_content = String::new();
        let guard = format!("CANARY_{}_H", mod_name.to_uppercase());
        header_content.push_str(&format!("#ifndef {}\n#define {}\n\n", guard, guard));
        header_content.push_str("#include \"common_types.h\"\n\n");

        // Forward declare functions
        for &addr in funcs {
            let name = workspace
                .sdb
                .facts
                .symbols
                .symbols
                .get(&addr)
                .map(|sym| sym.value.name.clone())
                .unwrap_or_else(|| format!("sub_{:x}", addr));

            // Check calling signature
            let (ret_ty, params_str) = if let Some(func_entry) =
                workspace.sdb.interpretations.functions.functions.get(&addr)
            {
                if let Some(sig_entry) = &func_entry.value.call_signature {
                    let sig = &sig_entry.value;
                    let p_str = sig
                        .params
                        .iter()
                        .enumerate()
                        .map(|(i, p)| format!("{} arg_{}", p.ty, i))
                        .collect::<Vec<_>>()
                        .join(", ");
                    (sig.return_ty.clone(), p_str)
                } else {
                    ("void".to_string(), "void".to_string())
                }
            } else {
                ("void".to_string(), "void".to_string())
            };

            header_content.push_str(&format!("{} {}({});\n", ret_ty, name, params_str));
        }
        header_content.push_str(&format!("\n#endif // {}\n", guard));

        files.insert(
            header_path.clone(),
            FileEntry {
                path: header_path,
                file_type: FileType::Header,
                content: header_content,
                includes: vec!["include/common_types.h".to_string()],
                symbol_addresses: funcs.clone(),
            },
        );

        // Source content (this content will be filled in Phase 12, but we initialize with include header)
        let mut source_content = String::new();
        source_content.push_str(&format!("#include \"{}.h\"\n\n", mod_name));

        files.insert(
            source_path.clone(),
            FileEntry {
                path: source_path,
                file_type: FileType::Source,
                content: source_content,
                includes: vec![format!("include/{}.h", mod_name)],
                symbol_addresses: funcs.clone(),
            },
        );
    }

    // 5. Create CMakeLists.txt build file
    let mut cmake_content = String::new();
    cmake_content.push_str("cmake_minimum_required(VERSION 3.10)\n");
    cmake_content.push_str("project(canary_reconstructed CXX)\n\n");
    cmake_content.push_str("set(CMAKE_CXX_STANDARD 17)\n\n");
    cmake_content.push_str("add_executable(reconstructed_app\n");
    for src in &cmake_sources {
        cmake_content.push_str(&format!("    {}\n", src));
    }
    cmake_content.push_str(")\n\n");
    cmake_content.push_str("target_include_directories(reconstructed_app PRIVATE include)\n");

    files.insert(
        "CMakeLists.txt".to_string(),
        FileEntry {
            path: "CMakeLists.txt".to_string(),
            file_type: FileType::Build,
            content: cmake_content,
            includes: Vec::new(),
            symbol_addresses: Vec::new(),
        },
    );

    // Save into SDB
    let layout = ProjectLayout { files };
    workspace.sdb.project.layout = Some(SdbEntry::new(
        layout,
        canary_sdb::ConfidenceVector::base(0.95),
        RecoveryOrigin::Heuristic,
    ));
}
