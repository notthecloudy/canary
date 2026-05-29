//! Whole-program emission — produces a recompilable CMake project from analyzed IR.
//!
//! After `Engine::analyze_whole_program()` completes, this module emits a structured
//! directory with:
//!
//! ```text
//! <out_dir>/
//!   CMakeLists.txt        ← top-level CMake build
//!   program.h             ← all function signatures
//!   imports.h             ← IAT shim declarations
//!   RECONSTRUCTION.md     ← analysis summary and confidence stats
//!   <module_name>.cpp       ← one .cpp file per module cluster
//! ```
//!
//! The output is designed to be compilable with CMake + a C compiler, producing a binary
//! that approximates the original.

use crate::engine::{AnalysisSummary, Engine, EngineError};
use std::collections::BTreeMap;
use std::path::Path;

/// Emits the whole program as a CMake project to `out_dir`.
pub fn emit_whole_program(
    engine: &mut Engine,
    out_dir: &Path,
    summary: &AnalysisSummary,
) -> Result<(), EngineError> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| EngineError::Loader(format!("Failed to create output dir: {e}")))?;

    // Ensure the binary is in the cache. Clone the parsed metadata so the parallel
    // emission closure does not borrow through `engine.cached_loaded`.
    if engine.cached_loaded.is_none() {
        let loaded = canary_loader::binary::Binary::load(&engine.workspace.binary_bytes)
            .map_err(|e| EngineError::Loader(e.to_string()))?;
        engine.cached_loaded = Some(loaded);
    }
    let loaded = engine.cached_loaded.as_ref().unwrap().clone();

    // Collect all function code, grouped by module cluster
    let mut modules: BTreeMap<String, Vec<(String, u64, String)>> = BTreeMap::new(); // module → [(name, addr, code)]
    let mut all_signatures: Vec<String> = Vec::new();

    // Determine module for each function — deduplicate by entry address
    // (the arena may contain orphaned duplicate entries from re-registration)
    let mut seen_addrs = std::collections::HashSet::new();
    let func_ids: Vec<_> = engine
        .workspace
        .functions
        .iter()
        .filter(|(_, f)| seen_addrs.insert(f.entry_addr))
        .map(|(id, _)| id)
        .collect();

    use rayon::prelude::*;
    let mut results: Vec<_> = func_ids
        .into_par_iter()
        .filter_map(|func_id| {
            let (func_name, entry_addr, module_name, prov_comment, skip) = {
                let func = engine.workspace.functions.get(func_id).unwrap();
                let addr = func.entry_addr;
                let name = &func.name;

                let mut module_name = None;
                for section in &loaded.sections {
                    if section.contains(addr) {
                        module_name = Some(section.name.replace(".", "_"));
                        break;
                    }
                }
                if module_name.is_none() {
                    module_name = Some(
                        engine
                            .workspace
                            .sdb
                            .interpretations
                            .modules
                            .modules
                            .iter()
                            .find(|(_, m)| m.value.functions.contains(&addr))
                            .map(|(_, m)| m.value.name.clone())
                            .unwrap_or_else(|| "core".to_string()),
                    );
                }

                let prov_comment = if let Some(sdb_func) = engine
                    .workspace
                    .sdb
                    .interpretations
                    .functions
                    .functions
                    .get(&addr)
                {
                    format!(
                        "/* Provenance: {:?} | Confidence: {:.2} */\n",
                        sdb_func.provenance.origin,
                        sdb_func.confidence.composite()
                    )
                } else {
                    "/* Provenance: Unknown */\n".to_string()
                };

                let skip = if engine.workspace.config.recovery_mode
                    == crate::config::RecoveryMode::Conservative
                {
                    if let Some(sdb_func) = engine
                        .workspace
                        .sdb
                        .interpretations
                        .functions
                        .functions
                        .get(&addr)
                    {
                        sdb_func.confidence.composite() < 0.5
                    } else {
                        true
                    }
                } else {
                    false
                };

                (
                    name.to_string(),
                    addr,
                    module_name.unwrap(),
                    prov_comment,
                    skip,
                )
            };

            if skip {
                return None;
            }

            let mut code = match engine.decompile_function_stateless(func_id, "c") {
                Ok((c, _)) => c,
                Err(e) => {
                    format!(
                        "/* Failed to decompile {} ({:#x}): {} */\n",
                        &func_name, entry_addr, e
                    )
                }
            };
            code.insert_str(0, &prov_comment);

            let sig = extract_signature(&code, &func_name, entry_addr);
            Some((module_name, func_name, entry_addr, code, sig))
        })
        .collect();

    results.sort_by_key(|r| r.2);

    for (module_name, func_name, entry_addr, code, sig) in results {
        all_signatures.push(sig);
        modules
            .entry(module_name)
            .or_default()
            .push((func_name, entry_addr, code));
    }

    // 1. Write per-module .cpp files
    let src_dir = out_dir.join("src");
    let _ = std::fs::create_dir_all(&src_dir);
    let mut all_cpp_files: Vec<String> = Vec::new();
    for (module_name, funcs) in &modules {
        let safe_name = sanitize_name(module_name);
        let filename = format!("{}.cpp", safe_name);
        let filepath = src_dir.join(&filename);
        all_cpp_files.push(format!("src/{}", filename));

        let mut content = String::new();
        content.push_str(&format!(
            "/* Module: {} — reconstructed by Canary */\n",
            module_name
        ));
        content.push_str("#include \"program.h\"\n");
        content.push_str("#include \"imports.h\"\n\n");

        for (func_name, addr, code) in funcs {
            content.push_str(&format!("/* Function: {} @ {:#x} */\n", func_name, addr));
            content.push_str(code);
            content.push_str("\n\n");
        }

        std::fs::write(&filepath, &content).map_err(|e| {
            EngineError::Loader(format!("Failed to write {}: {e}", filepath.display()))
        })?;
    }

    // 2. Write program.h — all function signatures
    let include_dir = out_dir.join("include");
    let _ = std::fs::create_dir_all(&include_dir);
    let program_h_path = include_dir.join("program.h");
    let mut program_h = String::new();
    program_h.push_str("/* program.h — all recovered function signatures */\n");
    program_h.push_str("/* Generated by Canary — do not edit manually */\n\n");
    program_h.push_str("#pragma once\n");
    program_h.push_str("#include <stdint.h>\n");
    program_h.push_str("#include <stdbool.h>\n\n");
    program_h.push_str("#ifdef _MSC_VER\n");
    program_h.push_str("#include <emmintrin.h>\n");
    program_h.push_str("typedef __m128i uint128_t;\n");
    program_h.push_str("#else\n");
    program_h.push_str("typedef unsigned __int128 uint128_t;\n");
    program_h.push_str("#endif\n\n");
    program_h.push_str("/* --- Function Declarations --- */\n\n");
    for sig in &all_signatures {
        program_h.push_str(sig);
        program_h.push_str(";\n");
    }
    std::fs::write(&program_h_path, &program_h)
        .map_err(|e| EngineError::Loader(format!("Failed to write program.h: {e}")))?;

    // 3. Write imports.h — IAT shim declarations
    let imports_h_path = include_dir.join("imports.h");
    let mut imports_h = String::new();
    imports_h.push_str("/* imports.h — imported function declarations */\n");
    imports_h.push_str("/* Generated by Canary — do not edit manually */\n\n");
    imports_h.push_str("#pragma once\n");
    imports_h.push_str("#include <stdint.h>\n\n");
    imports_h.push_str("/* IAT imports — these are resolved at link time */\n\n");

    let mut seen_imports = std::collections::HashSet::new();
    let mut libs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for import in &engine.workspace.sdb.facts.binary.imports {
        if seen_imports.insert(import.value.symbol_name.clone()) {
            let decl = format!(
                "extern void* {}; /* {} */",
                import.value.symbol_name, import.value.lib_name
            );
            libs.entry(import.value.lib_name.clone())
                .or_default()
                .push(decl);
        }
    }
    for (lib, decls) in &libs {
        imports_h.push_str(&format!("/* From: {} */\n", lib));
        for decl in decls {
            imports_h.push_str(decl);
            imports_h.push_str("\n");
        }
        imports_h.push('\n');
    }
    std::fs::write(&imports_h_path, &imports_h)
        .map_err(|e| EngineError::Loader(format!("Failed to write imports.h: {e}")))?;

    // 4. Write CMakeLists.txt
    let cmake_path = out_dir.join("CMakeLists.txt");
    let cmake = generate_cmake(
        &engine.workspace.sdb.facts.binary.format,
        &engine.workspace.binary_path,
        &all_cpp_files,
        &libs.keys().cloned().collect::<Vec<_>>(),
    );
    std::fs::write(&cmake_path, &cmake)
        .map_err(|e| EngineError::Loader(format!("Failed to write CMakeLists.txt: {e}")))?;

    // 5. Write RECONSTRUCTION.md
    let md_path = out_dir.join("RECONSTRUCTION.md");
    let md = generate_reconstruction_md(engine, summary, &modules);
    std::fs::write(&md_path, &md)
        .map_err(|e| EngineError::Loader(format!("Failed to write RECONSTRUCTION.md: {e}")))?;

    // 6. UWP UI layout and resource decompile integration
    // Resolve resources.pri relative to the binary being analyzed, not CWD
    let binary_dir = engine
        .workspace
        .binary_path
        .parent()
        .unwrap_or(Path::new("."));
    let pri_path = binary_dir.join("resources.pri");
    // Also check CWD as fallback
    let pri_path = if pri_path.exists() {
        pri_path
    } else if Path::new("resources.pri").exists() {
        Path::new("resources.pri").to_path_buf()
    } else {
        tracing::warn!("resources.pri not found in binary directory ({}) or CWD — skipping XAML/resource recovery", binary_dir.display());
        Path::new("").to_path_buf()
    };
    if pri_path.exists() {
        tracing::info!(
            "Found resources.pri at {}, decompiling XAML visual layouts...",
            pri_path.display()
        );
        let temp_xml = out_dir.join("temp_resources.xml");
        match canary_loader::pri::PriParser::dump_pri(&pri_path, &temp_xml) {
            Ok(()) => {
                match canary_loader::pri::PriParser::parse_xml(&temp_xml) {
                    Ok(resources) => {
                        tracing::info!(
                            "PRI parsed: {} strings, {} assets, {} XBF layouts",
                            resources.strings.len(),
                            resources.assets.len(),
                            resources.xbfs.len()
                        );

                        // 6.1 Localized resource tables (.resw) synthesis
                        let resw_dir = out_dir.join("assets").join("strings");
                        let _ = std::fs::create_dir_all(&resw_dir);
                        match canary_loader::pri::PriParser::write_resw_files(&resources, &resw_dir)
                        {
                            Ok(files) => {
                                tracing::info!("Wrote {} .resw resource files", files.len())
                            }
                            Err(e) => tracing::warn!("Failed to write .resw files: {}", e),
                        }

                        // 6.2 Decompile XBF files to visual XAML markup templates
                        let xaml_dir = out_dir.join("ui");
                        if let Err(e) = std::fs::create_dir_all(&xaml_dir) {
                            tracing::warn!("Failed to create ui dir: {}", e);
                        }

                        // Decode all XBF files ONCE and cache the results.
                        // This avoids decoding the same binary XAML data twice:
                        // once for build_ui_behavior_graph and once for XAML synthesis.
                        let decoded_xbfs: Vec<(
                            String,
                            Result<Vec<canary_loader::xbf::XbfNode>, _>,
                        )> = resources
                            .xbfs
                            .iter()
                            .map(|xbf| {
                                let result = decode_base64(&xbf.base64_data)
                                    .map(|bytes| canary_loader::xbf::XbfDecoder::decode(&bytes))
                                    .unwrap_or_else(|| {
                                        Err(canary_loader::error::LoaderError::Parse(format!(
                                            "XBF '{}': base64 decode failed",
                                            xbf.name
                                        )))
                                    });
                                (xbf.name.clone(), result)
                            })
                            .collect();

                        // Validate Semantic Stabilization Gate threshold checks
                        let pass_gate =
                            canary_emit::xaml::XamlSynthesizer::check_stabilization_gate(
                                &engine.workspace.sdb,
                            );
                        tracing::info!(
                            "Semantic Stabilization Gate: {}",
                            if pass_gate {
                                "PASSED"
                            } else {
                                "FAILED (bindings will be empty)"
                            }
                        );

                        // Reconstruct MVVM dynamic data-bindings if semantic gates pass successfully
                        // Reuse the already-decoded XBF node lists
                        let inferred_bindings = if pass_gate {
                            let ubg = build_ui_behavior_graph_from_nodes(&decoded_xbfs);
                            let binding_engine =
                                canary_analysis::ui_binding::BindingInferenceEngine;
                            binding_engine.infer_bindings(&ubg, &engine.workspace.sdb)
                        } else {
                            Vec::new()
                        };

                        let mut xaml_success = 0;
                        let mut xaml_failed = 0;
                        for (xbf_name, decode_result) in &decoded_xbfs {
                            match decode_result {
                                Ok(nodes) => {
                                    match canary_emit::xaml::XamlSynthesizer::build_tree(nodes) {
                                        Ok(root_elem) => {
                                            match canary_emit::xaml::XamlSynthesizer::synthesize(
                                                &root_elem,
                                                &inferred_bindings,
                                            ) {
                                                Ok(xaml_str) => {
                                                    let xaml_filename = xbf_name
                                                        .trim_end_matches(".xbf")
                                                        .to_string()
                                                        + ".xaml";
                                                    let xaml_path = xaml_dir.join(&xaml_filename);
                                                    if let Err(e) =
                                                        std::fs::write(&xaml_path, &xaml_str)
                                                    {
                                                        tracing::warn!(
                                                            "Failed to write XAML {}: {}",
                                                            xaml_filename,
                                                            e
                                                        );
                                                        xaml_failed += 1;
                                                    } else {
                                                        xaml_success += 1;
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "XBF '{}': XAML synthesis failed: {}",
                                                        xbf_name,
                                                        e
                                                    );
                                                    xaml_failed += 1;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "XBF '{}': tree build failed: {}",
                                                xbf_name,
                                                e
                                            );
                                            xaml_failed += 1;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("XBF '{}': decode failed: {}", xbf_name, e);
                                    xaml_failed += 1;
                                }
                            }
                        }
                        tracing::info!(
                            "XAML recovery: {} succeeded, {} failed out of {} XBF files",
                            xaml_success,
                            xaml_failed,
                            resources.xbfs.len()
                        );
                    }
                    Err(e) => tracing::warn!("Failed to parse PRI XML: {}", e),
                }
                let _ = std::fs::remove_file(&temp_xml);
            }
            Err(e) => tracing::warn!("Failed to dump PRI: {}", e),
        }
    }

    // 7. Visual Studio Project / Solution Generation (Phase 5)
    let binary_name = engine
        .workspace
        .binary_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("CalculatorApp");

    let project_uuid = generate_deterministic_uuid(binary_name);

    // 7.1 Synthesize public C++/WinRT class declarations (.h files) from unstripped metadata
    let mut h_files = vec!["program.h".to_string(), "imports.h".to_string()];
    for class_entry in &engine.workspace.sdb.interpretations.types.classes {
        let class = &class_entry.value;
        let parts: Vec<&str> = class.name.split('.').collect();
        let name = parts.last().copied().unwrap_or("Unknown").to_string();
        let namespace = parts[..parts.len() - 1].join(".");

        let mut methods_schema = Vec::new();
        for m in &class.methods {
            let mut method_name = format!("sub_{:x}", m.fn_addr);
            if let Some(f) = engine
                .workspace
                .sdb
                .interpretations
                .functions
                .functions
                .get(&m.fn_addr)
            {
                if let Some(ref name) = f.value.name {
                    method_name = name.clone();
                }
            }
            methods_schema.push(canary_typerecov::winrt_headers::WinRtMethodSchema {
                name: method_name,
                params: Vec::new(),
                return_ty: "Void".to_string(),
                is_static: false,
            });
        }

        let schema = canary_typerecov::winrt_headers::WinRtClassSchema {
            namespace,
            name: name.clone(),
            parent_class: None,
            interfaces: vec!["IInspectable".to_string()],
            methods: methods_schema,
        };

        let header_code =
            canary_typerecov::winrt_headers::WinRtHeaderSynthesizer::synthesize_header(&schema);
        let header_filename = format!("{}.h", name);
        let header_path = include_dir.join(&header_filename);
        let _ = std::fs::write(&header_path, header_code);
        h_files.push(format!("include/{}", header_filename));
    }

    // 7.2 Collect XAML and RESW files written in previous step
    let mut xaml_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(out_dir.join("ui")) {
        for entry in entries.flatten() {
            if let Some(filename) = entry.file_name().to_str() {
                if filename.ends_with(".xaml") {
                    xaml_files.push(format!("ui\\{}", filename));
                }
            }
        }
    }
    xaml_files.sort();

    let mut resw_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(out_dir.join("assets").join("strings")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let locale_dir = entry.path();
                if let Ok(resw_entries) = std::fs::read_dir(&locale_dir) {
                    for resw_entry in resw_entries.flatten() {
                        if let Some(filename) = resw_entry.file_name().to_str() {
                            if filename.ends_with(".resw") {
                                let locale_name = locale_dir.file_name().unwrap().to_str().unwrap();
                                resw_files.push(format!(
                                    "assets\\strings\\{}\\{}",
                                    locale_name, filename
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    resw_files.sort();

    // 7.3 Generate .sln, .vcxproj, and .vcxproj.filters files
    let sln_content = generate_sln(binary_name, &project_uuid);
    let vcxproj_content = generate_vcxproj(
        &project_uuid,
        binary_name,
        &all_cpp_files,
        &h_files,
        &xaml_files,
        &resw_files,
    );
    let filters_content = generate_filters(&all_cpp_files, &h_files, &xaml_files, &resw_files);

    let sln_path = out_dir.join(format!("{}.sln", binary_name));
    let vcxproj_path = out_dir.join(format!("{}.vcxproj", binary_name));
    let filters_path = out_dir.join(format!("{}.vcxproj.filters", binary_name));

    let _ = std::fs::write(&sln_path, sln_content);
    let _ = std::fs::write(&vcxproj_path, vcxproj_content);
    let _ = std::fs::write(&filters_path, filters_content);

    tracing::info!(
        "Emitted whole-program project: {} modules, {} functions, {} .cpp files",
        modules.len(),
        summary.functions_analyzed,
        all_cpp_files.len()
    );

    Ok(())
}

/// Generates the top-level CMakeLists.txt content.
fn generate_cmake(
    format: &str,
    binary_path: &Path,
    cpp_files: &[String],
    libs: &[String],
) -> String {
    let binary_name = binary_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("program");

    let target_type = if format == "PE" {
        "add_executable"
    } else {
        "add_library"
    };

    let mut cmake = String::new();
    cmake.push_str("cmake_minimum_required(VERSION 3.20)\n");
    cmake.push_str(&format!("project({} C)\n\n", binary_name));
    cmake.push_str("set(CMAKE_C_STANDARD 99)\n");
    cmake.push_str("set(CMAKE_C_STANDARD_REQUIRED ON)\n\n");

    // Source files
    cmake.push_str("set(SOURCES\n");
    for f in cpp_files {
        cmake.push_str(&format!("    {}\n", f));
    }
    cmake.push_str(")\n\n");

    cmake.push_str(&format!(
        "{}({} ${{SOURCES}})\n\n",
        target_type, binary_name
    ));

    cmake.push_str(&format!(
        "target_include_directories({} PRIVATE ${{CMAKE_CURRENT_SOURCE_DIR}})\n\n",
        binary_name
    ));

    // Library links (from IAT)
    if !libs.is_empty() {
        cmake.push_str(&format!("target_link_libraries({} PRIVATE\n", binary_name));
        for lib in libs {
            cmake.push_str(&format!("    # {} (link manually if needed)\n", lib));
        }
        cmake.push_str(")\n\n");
    }

    cmake.push_str("# Reconstruction Notes:\n");
    cmake.push_str("# This CMake project was generated by Canary from a binary.\n");
    cmake.push_str("# The code may require manual cleanup before it compiles cleanly.\n");
    cmake.push_str("# See RECONSTRUCTION.md for analysis details.\n");

    cmake
}

/// Generates RECONSTRUCTION.md with analysis summary.
fn generate_reconstruction_md(
    engine: &Engine,
    summary: &AnalysisSummary,
    modules: &BTreeMap<String, Vec<(String, u64, String)>>,
) -> String {
    let mut md = String::new();
    md.push_str("# Canary Reconstruction Report\n\n");
    md.push_str(&format!(
        "**Binary**: `{}`\n\n",
        engine.workspace.binary_path.display()
    ));

    md.push_str("## Analysis Summary\n\n");
    md.push_str(&format!("| Metric | Value |\n|--------|-------|\n"));
    md.push_str(&format!(
        "| Functions Discovered | {} |\n",
        summary.functions_discovered
    ));
    md.push_str(&format!(
        "| Functions Analyzed | {} |\n",
        summary.functions_analyzed
    ));
    md.push_str(&format!(
        "| Functions Failed | {} |\n",
        summary.functions_failed
    ));
    md.push_str(&format!(
        "| Imports Resolved | {} |\n",
        summary.imports_resolved
    ));
    md.push_str(&format!(
        "| XRefs Recorded | {} |\n",
        summary.xrefs_recorded
    ));
    md.push_str(&format!(
        "| Call Graph Edges | {} |\n",
        engine.workspace.sdb.facts.xrefs.callgraph.edge_count()
    ));
    md.push_str(&format!("| Modules Identified | {} |\n", modules.len()));
    md.push_str(&format!(
        "| Structs Recovered | {} |\n",
        engine.workspace.sdb.interpretations.types.structs.len()
    ));
    md.push_str(&format!(
        "| Enums Recovered | {} |\n\n",
        engine.workspace.sdb.interpretations.types.enums.len()
    ));

    md.push_str("## Recovered Types\n\n");
    md.push_str("| Type Name | Fields | Confidence | Origin |\n");
    md.push_str("|-----------|--------|------------|--------|\n");
    for sdb_struct in &engine.workspace.sdb.interpretations.types.structs {
        let name = &sdb_struct.value.name;
        let field_count = sdb_struct.value.fields.len();
        let conf = sdb_struct.confidence.composite();
        let origin = format!("{:?}", sdb_struct.provenance.origin);
        md.push_str(&format!(
            "| `{}` | {} | {:.2} | `{}` |\n",
            name, field_count, conf, origin
        ));
    }
    for sdb_enum in &engine.workspace.sdb.interpretations.types.enums {
        let name = &sdb_enum.value.name;
        let field_count = sdb_enum.value.variants.len();
        let conf = sdb_enum.confidence.composite();
        let origin = format!("{:?}", sdb_enum.provenance.origin);
        md.push_str(&format!(
            "| `{}` (enum) | {} | {:.2} | `{}` |\n",
            name, field_count, conf, origin
        ));
    }
    md.push_str("\n## Modules\n\n");
    for (module, funcs) in modules {
        md.push_str(&format!("### `{}` ({} functions)\n\n", module, funcs.len()));
        for (name, addr, _) in funcs {
            md.push_str(&format!("- `{}` @ `{:#x}`\n", name, addr));
        }
        md.push('\n');
    }

    md.push_str("## Imports\n\n");
    let mut lib_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for imp in &engine.workspace.sdb.facts.binary.imports {
        lib_groups
            .entry(imp.value.lib_name.clone())
            .or_default()
            .push(imp.value.symbol_name.clone());
    }
    for (lib, symbols) in &lib_groups {
        md.push_str(&format!("### `{}`\n\n", lib));
        for sym in symbols {
            md.push_str(&format!("- `{}`\n", sym));
        }
        md.push('\n');
    }

    md.push_str("---\n");
    md.push_str("*Generated by [Canary](https://github.com/canary-project) — progressive semantic reconstruction.*\n");
    md
}

/// Extracts the function signature line from emitted C code.
fn extract_signature(code: &str, func_name: &str, addr: u64) -> String {
    for line in code.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Look for a line that looks like a function definition
        if trimmed.contains('(') && !trimmed.starts_with('#') {
            // Strip the opening brace if present
            let sig = trimmed.trim_end_matches('{').trim();
            return sig.to_string();
        }
    }
    // Fallback
    format!("void* {func_name}(void) /* {:#x} */", addr)
}

/// Sanitizes a module name for use as a filename.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let input = input.replace(|c: char| c.is_whitespace(), "");
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.chars() {
        let val = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            '=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}

/// Builds a UI behavior graph from pre-decoded XBF node lists (avoids re-decoding).
fn build_ui_behavior_graph_from_nodes(
    decoded_xbfs: &[(
        String,
        Result<Vec<canary_loader::xbf::XbfNode>, canary_loader::error::LoaderError>,
    )],
) -> canary_analysis::ui_binding::UiBehaviorGraph {
    let mut ubg = canary_analysis::ui_binding::UiBehaviorGraph::new();
    let mut node_id = 1;

    for (_name, decode_result) in decoded_xbfs {
        if let Ok(nodes) = decode_result {
            for node in nodes {
                if let canary_loader::xbf::XbfNode::ElementStart { type_name, .. } = node {
                    let node_type = match type_name.as_str() {
                        "TextBox" => canary_analysis::ui_binding::UiNodeType::TextBox,
                        "Button" => canary_analysis::ui_binding::UiNodeType::Button,
                        "TextBlock" | "Label" => canary_analysis::ui_binding::UiNodeType::Label,
                        "ListView" => canary_analysis::ui_binding::UiNodeType::ListView,
                        "CheckBox" => canary_analysis::ui_binding::UiNodeType::CheckBox,
                        other => canary_analysis::ui_binding::UiNodeType::Custom(other.to_string()),
                    };

                    ubg.add_node(canary_analysis::ui_binding::UiNode {
                        id: node_id,
                        node_type,
                        name: format!("{}_{}", type_name, node_id),
                        properties: indexmap::IndexMap::new(),
                    });
                    node_id += 1;
                }
            }
        }
    }
    ubg
}

fn generate_deterministic_uuid(seed: &str) -> String {
    let mut hash = 0u64;
    for c in seed.chars() {
        hash = hash.wrapping_mul(31).wrapping_add(c as u64);
    }
    let p1 = (hash & 0xFFFFFFFF) as u32;
    let p2 = ((hash >> 32) & 0xFFFF) as u16;
    let p3 = 0x4000 | (((hash >> 48) & 0x0FFF) as u16);
    let p4 = 0x8000 | (((hash >> 60) & 0x3FFF) as u16);
    let p5 = (hash ^ 0x5555555555555555) & 0xFFFFFFFFFFFF;
    format!("{:08X}-{:04X}-{:04X}-{:04X}-{:012X}", p1, p2, p3, p4, p5)
}

fn generate_sln(project_name: &str, project_uuid: &str) -> String {
    let mut sln = String::new();
    sln.push_str("Microsoft Visual Studio Solution File, Format Version 12.00\n");
    sln.push_str("# Visual Studio Version 17\n");
    sln.push_str("VisualStudioVersion = 17.0.31903.59\n");
    sln.push_str("MinimumVisualStudioVersion = 10.0.40219.1\n");
    sln.push_str(&format!(
        "Project(\"{{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}}\") = \"{}\", \"{}.vcxproj\", \"{{{}}}\"\n",
        project_name, project_name, project_uuid
    ));
    sln.push_str("EndProject\n");
    sln.push_str("Global\n");
    sln.push_str("\tGlobalSection(SolutionConfigurationPlatforms) = preSolution\n");
    sln.push_str("\t\tDebug|x64 = Debug|x64\n");
    sln.push_str("\t\tRelease|x64 = Release|x64\n");
    sln.push_str("\tEndGlobalSection\n");
    sln.push_str("\tGlobalSection(ProjectConfigurationPlatforms) = postSolution\n");
    sln.push_str(&format!(
        "\t\t{{{}}}.Debug|x64.ActiveCfg = Debug|x64\n",
        project_uuid
    ));
    sln.push_str(&format!(
        "\t\t{{{}}}.Debug|x64.Build.0 = Debug|x64\n",
        project_uuid
    ));
    sln.push_str(&format!(
        "\t\t{{{}}}.Release|x64.ActiveCfg = Release|x64\n",
        project_uuid
    ));
    sln.push_str(&format!(
        "\t\t{{{}}}.Release|x64.Build.0 = Release|x64\n",
        project_uuid
    ));
    sln.push_str("\tEndGlobalSection\n");
    sln.push_str("EndGlobal\n");
    sln
}

fn generate_vcxproj(
    project_uuid: &str,
    target_name: &str,
    cpp_files: &[String],
    h_files: &[String],
    xaml_files: &[String],
    resw_files: &[String],
) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<Project DefaultTargets=\"Build\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n");
    xml.push_str("  <ItemGroup Label=\"ProjectConfigurations\">\n");
    xml.push_str("    <ProjectConfiguration Include=\"Debug|x64\">\n");
    xml.push_str("      <Configuration>Debug</Configuration>\n");
    xml.push_str("      <Platform>x64</Platform>\n");
    xml.push_str("    </ProjectConfiguration>\n");
    xml.push_str("    <ProjectConfiguration Include=\"Release|x64\">\n");
    xml.push_str("      <Configuration>Release</Configuration>\n");
    xml.push_str("      <Platform>x64</Platform>\n");
    xml.push_str("    </ProjectConfiguration>\n");
    xml.push_str("  </ItemGroup>\n");

    // Globals
    xml.push_str("  <PropertyGroup Label=\"Globals\">\n");
    xml.push_str(&format!(
        "    <ProjectGuid>{{{}}}</ProjectGuid>\n",
        project_uuid
    ));
    xml.push_str("    <Keyword>Win32Proj</Keyword>\n");
    xml.push_str(&format!(
        "    <RootNamespace>{}</RootNamespace>\n",
        target_name
    ));
    xml.push_str("    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>\n");
    xml.push_str(
        "    <WindowsTargetPlatformMinVersion>10.0.17763.0</WindowsTargetPlatformMinVersion>\n",
    );
    xml.push_str("  </PropertyGroup>\n");

    // Standard imports
    xml.push_str("  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />\n");
    xml.push_str("  <PropertyGroup Label=\"Configuration\">\n");
    xml.push_str("    <ConfigurationType>Application</ConfigurationType>\n");
    xml.push_str("    <PlatformToolset>v143</PlatformToolset>\n");
    xml.push_str("    <CharacterSet>Unicode</CharacterSet>\n");
    xml.push_str("  </PropertyGroup>\n");

    xml.push_str("  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />\n");
    xml.push_str("  <ImportGroup Label=\"ExtensionSettings\" />\n");
    xml.push_str("  <ImportGroup Label=\"Shared\" />\n");
    xml.push_str("  <ImportGroup Label=\"PropertySheets\">\n");
    xml.push_str("    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\" Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\" Label=\"LocalAppDataPlatform\" />\n");
    xml.push_str("  </ImportGroup>\n");

    xml.push_str("  <PropertyGroup Label=\"UserMacros\" />\n");

    // Item definitions
    xml.push_str("  <ItemDefinitionGroup>\n");
    xml.push_str("    <ClCompile>\n");
    xml.push_str("      <WarningLevel>Level3</WarningLevel>\n");
    xml.push_str("      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\n");
    xml.push_str("      <ConformanceMode>true</ConformanceMode>\n");
    xml.push_str("      <LanguageStandard>stdcpp20</LanguageStandard>\n");
    xml.push_str("    </ClCompile>\n");
    xml.push_str("  </ItemDefinitionGroup>\n");

    // Include Source Files (.cpp)
    if !cpp_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in cpp_files {
            xml.push_str(&format!("    <ClCompile Include=\"{}\" />\n", f));
        }
        xml.push_str("  </ItemGroup>\n");
    }

    // Include Header Files (.h)
    if !h_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in h_files {
            xml.push_str(&format!("    <ClInclude Include=\"{}\" />\n", f));
        }
        xml.push_str("  </ItemGroup>\n");
    }

    // Include XAML visual pages (.xaml)
    if !xaml_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in xaml_files {
            xml.push_str(&format!("    <Page Include=\"{}\">\n", f));
            xml.push_str("      <SubType>Designer</SubType>\n");
            xml.push_str("    </Page>\n");
        }
        xml.push_str("  </ItemGroup>\n");
    }

    // Include Resource Tables (.resw)
    if !resw_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in resw_files {
            xml.push_str(&format!("    <PRIResource Include=\"{}\" />\n", f));
        }
        xml.push_str("  </ItemGroup>\n");
    }

    xml.push_str("  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />\n");
    xml.push_str("</Project>\n");
    xml
}

fn generate_filters(
    cpp_files: &[String],
    h_files: &[String],
    xaml_files: &[String],
    resw_files: &[String],
) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n");

    // Filters definitions
    xml.push_str("  <ItemGroup>\n");
    xml.push_str("    <Filter Include=\"Source Files\">\n");
    xml.push_str(
        "      <UniqueIdentifier>{4FC737F1-C7A5-4376-A066-2A32D752A2FF}</UniqueIdentifier>\n",
    );
    xml.push_str("      <Extensions>cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx</Extensions>\n");
    xml.push_str("    </Filter>\n");
    xml.push_str("    <Filter Include=\"Header Files\">\n");
    xml.push_str(
        "      <UniqueIdentifier>{93995380-89BD-4b04-88EB-625FBE52EBFB}</UniqueIdentifier>\n",
    );
    xml.push_str("      <Extensions>h;hh;hpp;hxx;hm;inl;inc;ipp;xsd</Extensions>\n");
    xml.push_str("    </Filter>\n");
    xml.push_str("    <Filter Include=\"Layouts\">\n");
    xml.push_str(
        "      <UniqueIdentifier>{54A6BE5C-34CD-49EB-87A3-20DE3FF07D87}</UniqueIdentifier>\n",
    );
    xml.push_str("      <Extensions>xaml</Extensions>\n");
    xml.push_str("    </Filter>\n");
    xml.push_str("    <Filter Include=\"Resources\">\n");
    xml.push_str(
        "      <UniqueIdentifier>{67DA6AB6-F800-4c08-8B7A-83BB121AAD01}</UniqueIdentifier>\n",
    );
    xml.push_str(
        "      <Extensions>resw;resx;tiff;tif;png;png;jpg;jpeg;jpe;sdk;pri</Extensions>\n",
    );
    xml.push_str("    </Filter>\n");
    xml.push_str("  </ItemGroup>\n");

    // Include Source Files with Filters
    if !cpp_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in cpp_files {
            xml.push_str(&format!("    <ClCompile Include=\"{}\">\n", f));
            xml.push_str("      <Filter>Source Files</Filter>\n");
            xml.push_str("    </ClCompile>\n");
        }
        xml.push_str("  </ItemGroup>\n");
    }

    // Include Header Files with Filters
    if !h_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in h_files {
            xml.push_str(&format!("    <ClInclude Include=\"{}\">\n", f));
            xml.push_str("      <Filter>Header Files</Filter>\n");
            xml.push_str("    </ClInclude>\n");
        }
        xml.push_str("  </ItemGroup>\n");
    }

    // Include XAML visual pages with Filters
    if !xaml_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in xaml_files {
            xml.push_str(&format!("    <Page Include=\"{}\">\n", f));
            xml.push_str("      <Filter>Layouts</Filter>\n");
            xml.push_str("    </Page>\n");
        }
        xml.push_str("  </ItemGroup>\n");
    }

    // Include Resource Tables with Filters
    if !resw_files.is_empty() {
        xml.push_str("  <ItemGroup>\n");
        for f in resw_files {
            xml.push_str(&format!("    <PRIResource Include=\"{}\">\n", f));
            xml.push_str("      <Filter>Resources</Filter>\n");
            xml.push_str("    </PRIResource>\n");
        }
        xml.push_str("  </ItemGroup>\n");
    }

    xml.push_str("</Project>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visual_studio_project_generation() {
        let name = "CalculatorApp";
        let uuid = generate_deterministic_uuid(name);

        // 1. Verify deterministic UUID format and consistency
        assert_eq!(uuid, generate_deterministic_uuid(name));
        assert_eq!(uuid.len(), 36);
        assert!(uuid.contains('-'));

        // 2. Verify Solution File (.sln) generation
        let sln = generate_sln(name, &uuid);
        assert!(sln.contains("Microsoft Visual Studio Solution File"));
        assert!(sln.contains("Project(\"{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}\")"));
        assert!(sln.contains(&format!("\"{}\", \"{}.vcxproj\"", name, name)));

        // 3. Verify MSBuild Project File (.vcxproj) generation
        let cpp_files = vec!["core.cpp".to_string(), "main.cpp".to_string()];
        let h_files = vec!["program.h".to_string(), "imports.h".to_string()];
        let xaml_files = vec!["xaml\\MainPage.xaml".to_string()];
        let resw_files = vec!["strings\\en-US\\Resources.resw".to_string()];

        let vcxproj = generate_vcxproj(&uuid, name, &cpp_files, &h_files, &xaml_files, &resw_files);
        assert!(vcxproj.contains("<Project DefaultTargets=\"Build\""));
        assert!(vcxproj.contains(&format!("<ProjectGuid>{{{}}}</ProjectGuid>", uuid)));
        assert!(vcxproj.contains("<ClCompile Include=\"core.cpp\" />"));
        assert!(vcxproj.contains("<ClInclude Include=\"program.h\" />"));
        assert!(vcxproj.contains("<Page Include=\"xaml\\MainPage.xaml\">"));
        assert!(vcxproj.contains("<PRIResource Include=\"strings\\en-US\\Resources.resw\" />"));

        // 4. Verify Project Filters (.vcxproj.filters) generation
        let filters = generate_filters(&cpp_files, &h_files, &xaml_files, &resw_files);
        assert!(filters.contains("<Project ToolsVersion=\"4.0\""));
        assert!(filters.contains("<Filter Include=\"Source Files\">"));
        assert!(filters.contains("<Filter Include=\"Header Files\">"));
        assert!(filters.contains("<Filter Include=\"Layouts\">"));
        assert!(filters.contains("<Filter Include=\"Resources\">"));
        assert!(filters.contains("<ClCompile Include=\"core.cpp\">"));
        assert!(filters.contains("<Filter>Source Files</Filter>"));
        assert!(filters.contains("<ClInclude Include=\"program.h\">"));
        assert!(filters.contains("<Filter>Header Files</Filter>"));
    }
}
