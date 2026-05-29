use crate::engine::{Engine, EngineError};
use canary_sdb::FileType;
use std::fs;
use std::path::Path;

pub fn generate_project_files(engine: &mut Engine, output_dir: &Path) -> Result<(), EngineError> {
    // 1. Create directories
    fs::create_dir_all(output_dir)
        .map_err(|e| EngineError::Loader(format!("Failed to create output dir: {e}")))?;
    fs::create_dir_all(output_dir.join("src"))
        .map_err(|e| EngineError::Loader(format!("Failed to create src dir: {e}")))?;
    fs::create_dir_all(output_dir.join("assets"))
        .map_err(|e| EngineError::Loader(format!("Failed to create assets dir: {e}")))?;

    // 2. Write out all extracted assets
    let assets = engine.workspace.sdb.facts.assets.assets.clone();
    for sdb_asset in &assets {
        let asset = &sdb_asset.value;
        let asset_path = output_dir.join(&asset.path);
        if let Some(parent) = asset_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                EngineError::Loader(format!("Failed to create parent for asset: {e}"))
            })?;
        }
        fs::write(&asset_path, &asset.bytes).map_err(|e| {
            EngineError::Loader(format!("Failed to write asset {}: {}", asset.path, e))
        })?;
    }

    // 3. Decompile functions and populate source contents
    let layout = engine
        .workspace
        .sdb
        .project
        .layout
        .as_ref()
        .map(|entry| entry.value.clone())
        .unwrap_or_default();

    // Note: binary loading for lift_function is handled by the engine's lazy cache.
    // We do not load the binary here directly.

    for (file_path, file_entry) in &layout.files {
        let full_path = output_dir.join(file_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                EngineError::Loader(format!("Failed to create parent for file: {e}"))
            })?;
        }

        if file_entry.file_type == FileType::Source {
            // Re-build source content with decompiled functions
            let mut source_content = String::new();
            for inc in &file_entry.includes {
                // If the include starts with "src/", we include the relative header name (without src/)
                let inc_name = inc.strip_prefix("src/").unwrap_or(inc);
                source_content.push_str(&format!("#include \"{}\"\n", inc_name));
            }
            source_content.push_str("\n");

            for &addr in &file_entry.symbol_addresses {
                if let Some(func_id) = engine.workspace.function_at(addr) {
                    let mut code = match engine.decompile_function(func_id, "c") {
                        Ok(c) => c,
                        Err(e) => {
                            format!("/* Error decompiling function at {:#x}: {} */\n", addr, e)
                        }
                    };

                    // Perform asset relinking: replace hex addresses in code with asset references
                    for sdb_asset in &assets {
                        let asset = &sdb_asset.value;
                        let from_hex = format!("{:#x}", asset.address);
                        let to_str = format!("&asset_{:x} /* {} */", asset.address, asset.path);
                        code = code.replace(&from_hex, &to_str);
                    }

                    source_content.push_str(&code);
                    source_content.push_str("\n\n");
                }
            }

            fs::write(&full_path, source_content).map_err(|e| {
                EngineError::Loader(format!("Failed to write source file {}: {}", file_path, e))
            })?;
        } else {
            // For headers, build files, write the content as-is
            fs::write(&full_path, &file_entry.content).map_err(|e| {
                EngineError::Loader(format!("Failed to write file {}: {}", file_path, e))
            })?;
        }
    }

    // 4. Generate RECONSTRUCTION_NOTES.md at the root
    let notes_path = output_dir.join("RECONSTRUCTION_NOTES.md");
    let mut notes = String::new();
    notes.push_str("# Semantic Reconstruction Notes\n\n");

    let funcs = &engine.workspace.sdb.interpretations.functions.functions;
    notes.push_str("## Functions Summary\n");
    notes.push_str(&format!("- Total Recovered Functions: {}\n", funcs.len()));

    let avg_conf: f64 = if !funcs.is_empty() {
        (funcs
            .values()
            .map(|f| f.confidence.composite())
            .sum::<f32>() as f64)
            / (funcs.len() as f64)
    } else {
        0.0
    };
    notes.push_str(&format!("- Average Recovery Confidence: {:.2}\n", avg_conf));

    notes.push_str("\n### Low-Confidence Items (< 0.5)\n");
    let mut has_low = false;
    for (addr, f) in funcs.iter() {
        if f.confidence.composite() < 0.5 {
            let name = f.value.name.as_deref().unwrap_or("unknown");
            notes.push_str(&format!(
                "- Function {} at {:#x} (conf: {:.2})\n",
                name,
                addr,
                f.confidence.composite()
            ));
            has_low = true;
        }
    }
    if !has_low {
        notes.push_str("- *None*\n");
    }

    notes.push_str("\n## Types Recovery Summary\n");
    let sdb = &engine.workspace.sdb;
    notes.push_str(&format!(
        "- Structs: {}\n",
        sdb.interpretations.types.structs.len()
    ));
    notes.push_str(&format!(
        "- Enums: {}\n",
        sdb.interpretations.types.enums.len()
    ));
    notes.push_str(&format!(
        "- Function Signatures: {}\n",
        sdb.interpretations.types.function_types.len()
    ));

    let debug_structs = sdb
        .interpretations
        .types
        .structs
        .iter()
        .filter(|s| format!("{:?}", s.provenance.origin) == "Debug")
        .count();
    notes.push_str(&format!("- Debug imported types: {}\n", debug_structs));

    notes.push_str("\n## Extracted Assets\n");
    notes.push_str(&format!("- Total Assets: {}\n", assets.len()));
    for sdb_asset in &assets {
        let asset = &sdb_asset.value;
        notes.push_str(&format!(
            "- {} (size: {} bytes) at address {:#x} -> {}\n",
            format!("{:?}", asset.detected_type),
            asset.size,
            asset.address,
            asset.path
        ));
    }

    fs::write(&notes_path, notes).map_err(|e| {
        EngineError::Loader(format!("Failed to write RECONSTRUCTION_NOTES.md: {}", e))
    })?;

    Ok(())
}
