//! Canary CLI — command-line interface for binary analysis and decompilation.
//!
//! ```
//! canary list-functions <binary>
//! canary decompile <binary> --function <name|addr>
//! canary info <binary>
//! canary cfg-dump <binary> --function <name|addr>
//! ```

use anyhow::{Context, Result};
use canary_arch_x86::X86_64LifterFactory;
use canary_core::engine::Engine;
use canary_core::workspace::Workspace;
use canary_loader::binary::Binary;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "canary",
    version = env!("CARGO_PKG_VERSION"),
    author = "Canary Contributors",
    about = "Progressive Semantic Raising — we don't un-compile, we recover intent.",
    long_about = None,
)]
struct Cli {
    /// Enable verbose logging (set RUST_LOG for fine control)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display information about a binary (format, arch, sections)
    Info {
        /// Path to the binary file
        binary: std::path::PathBuf,
        /// Show detailed recovered types
        #[arg(short, long)]
        show_types: bool,
    },

    /// List all discovered functions in a binary
    ListFunctions {
        /// Path to the binary file
        binary: std::path::PathBuf,
        /// Also run prologue heuristic discovery (slower)
        #[arg(short = 'H', long)]
        heuristics: bool,
    },

    /// Decompile a function to C pseudocode
    Decompile {
        /// Path to the binary file
        binary: std::path::PathBuf,
        /// Function name or hex address (e.g., `main` or `0x401000`)
        #[arg(short, long)]
        function: Option<String>,
        /// Output language (default: c)
        #[arg(short, long, default_value = "c")]
        lang: String,
        /// Write output to this file instead of stdout
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Decompile all discovered functions
        #[arg(short = 'a', long)]
        all_functions: bool,
        /// Decompilation mode (raw, rich, json, or graph)
        #[arg(short, long, default_value = "rich")]
        mode: String,
        /// Disable styled headers and colored output
        #[arg(long)]
        no_color: bool,
    },

    /// Dump the Control Flow Graph (CFG) for a function
    CfgDump {
        /// Path to the binary file
        binary: std::path::PathBuf,
        /// Function name or hex address (e.g., `main` or `0x401000`)
        #[arg(short, long)]
        function: Option<String>,
    },
    /// Dump C++ headers for recovered classes
    DumpHeaders {
        /// Path to the binary file
        binary: std::path::PathBuf,
        /// Directory to output headers
        #[arg(short, long)]
        out: std::path::PathBuf,
    },
    /// Export the SDB state to JSON, DOT, or Provenance trails
    Export {
        /// Path to the binary file
        binary: std::path::PathBuf,
        /// Export format (json, dot, provenance)
        #[arg(short, long)]
        format: String,
        /// Function name or hex address for provenance (if format is 'provenance')
        #[arg(short = 'f', long)]
        function: Option<String>,
        /// Output path
        #[arg(short, long)]
        out: std::path::PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        "canary=debug,info"
    } else {
        "canary=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .compact()
        .init();

    // Warn when running in debug mode — performance will be significantly worse than release.
    #[cfg(debug_assertions)]
    tracing::warn!(
        "Running in DEBUG mode — computation-heavy passes (CFG, SSA, type recovery) will be 5–20× slower. \
        Use `cargo run --release` for production performance."
    );

    match cli.command {
        Commands::Info { binary, show_types } => cmd_info(&binary, show_types),
        Commands::ListFunctions { binary, heuristics } => cmd_list_functions(&binary, heuristics),
        Commands::Decompile {
            binary,
            function,
            lang,
            output,
            all_functions,
            mode,
            no_color,
        } => cmd_decompile(
            &binary,
            function.as_deref(),
            &lang,
            output.as_deref(),
            all_functions,
            &mode,
            no_color,
        ),
        Commands::CfgDump { binary, function } => cmd_cfg_dump(&binary, function.as_deref()),
        Commands::DumpHeaders { binary, out } => cmd_dump_headers(&binary, &out),
        Commands::Export {
            binary,
            format,
            function,
            out,
        } => cmd_export(&binary, &format, function.as_deref(), &out),
    }
}

fn cmd_info(path: &std::path::Path, show_types: bool) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let loaded = Binary::load(&bytes).with_context(|| "Failed to parse binary")?;

    let mut workspace = Workspace::new(path, bytes.clone());
    workspace.sdb.facts.binary = loaded.to_sdb();
    for s in &loaded.strings {
        workspace
            .sdb
            .interpretations
            .types
            .strings
            .push(canary_sdb::SdbEntry::new(
                s.clone(),
                canary_sdb::ConfidenceVector::base(0.8),
                canary_sdb::RecoveryOrigin::Heuristic,
            ));
    }
    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    let mut engine = Engine::new(workspace).with_cached_binary(loaded);
    engine.register_lifter(Box::new(X86_64LifterFactory));

    // Quick heuristic to populate some data for types if needed
    // In a real flow, we'd run decompile on functions to get MLIL, but for info we can just run type recovery on what we have (e.g. debug types, type libs)
    let _ = engine.recover_types();

    println!("═══════════════════════════════════════");
    println!("  🐦 Canary Binary Info");
    println!("═══════════════════════════════════════");
    println!("  File:         {}", path.display());
    println!(
        "  Format:       {:?}",
        engine.loaded_binary().unwrap().format
    );
    println!(
        "  Architecture: {}",
        engine.loaded_binary().unwrap().arch_name
    );
    println!(
        "  Image Base:   {:#x}",
        engine.loaded_binary().unwrap().image_base
    );
    println!(
        "  Entry Point:  {:#x}",
        engine.loaded_binary().unwrap().entry_point
    );
    println!(
        "  Sections:     {}",
        engine.loaded_binary().unwrap().sections.len()
    );
    println!();
    println!("  Sections:");
    for section in &engine.loaded_binary().unwrap().sections {
        println!(
            "    {:12}  {:#010x} – {:#010x}  {:6} B  {:?}",
            section.name,
            section.virtual_range.start,
            section.virtual_range.end,
            section.size(),
            section.kind,
        );
    }
    println!();

    let sdb = &engine.workspace.sdb;
    println!(
        "  Functions:         {} total",
        engine.workspace.functions.len()
    );
    println!(
        "  Recovered Types:   {} Structs, {} Classes, {} Enums, {} Signatures\n",
        sdb.interpretations.types.structs.len(),
        sdb.interpretations.types.classes.len(),
        sdb.interpretations.types.enums.len(),
        sdb.interpretations.types.function_types.len()
    );

    if show_types {
        println!("\n═══════════════════════════════════════");
        println!("  Recovered Types Detail");
        println!("═══════════════════════════════════════");
        for s in &sdb.interpretations.types.structs {
            println!(
                "  Struct {} (size: {}, conf: {:.2})",
                s.value.name,
                s.value.total_size,
                s.confidence.composite()
            );
            for f in &s.value.fields {
                println!(
                    "    +{} : {} bytes ({:?})",
                    f.offset,
                    f.size,
                    f.name.as_deref().unwrap_or("")
                );
            }
        }
        for e in &sdb.interpretations.types.enums {
            println!(
                "  Enum {} (conf: {:.2})",
                e.value.name,
                e.confidence.composite()
            );
            for v in &e.value.variants {
                println!("    {} = {}", v.name, v.discriminant);
            }
        }
        for f in &sdb.interpretations.types.function_types {
            println!(
                "  FuncType {} (conf: {:.2})",
                f.value.name,
                f.confidence.composite()
            );
        }

        let mut class_count = 0;
        for c in &sdb.interpretations.types.classes {
            if class_count >= 50 {
                println!(
                    "  ... and {} more classes",
                    sdb.interpretations.types.classes.len() - 50
                );
                break;
            }
            println!(
                "  Class {} ({} methods, {} vtables)",
                c.value.name,
                c.value.methods.len(),
                c.value.vtables.len()
            );
            for base in &c.value.bases {
                println!("    : public {}", base);
            }
            for method in &c.value.methods {
                let dtor_str = if method.is_dtor { " [dtor]" } else { "" };
                println!(
                    "    {}virtual fn_{:x}(){}",
                    if method.is_virtual { "" } else { "non-" },
                    method.fn_addr,
                    dtor_str
                );
            }
            class_count += 1;
        }
    }

    Ok(())
}

fn cmd_list_functions(path: &std::path::Path, heuristics: bool) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let loaded = Binary::load(&bytes).with_context(|| "Failed to parse binary")?;

    let mut workspace = Workspace::new(path, bytes);
    workspace.sdb.facts.binary = loaded.to_sdb();
    for s in &loaded.strings {
        workspace
            .sdb
            .interpretations
            .types
            .strings
            .push(canary_sdb::SdbEntry::new(
                s.clone(),
                canary_sdb::ConfidenceVector::base(0.8),
                canary_sdb::RecoveryOrigin::Heuristic,
            ));
    }

    // Register named entry points as seeds
    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    // Optional legacy prologue heuristics (now superseded by BFS discovery)
    if heuristics {
        info!("Running prologue heuristics...");
        let candidates = canary_loader::function_discovery::discover_by_prologue(&loaded);
        for addr in candidates {
            if workspace.function_at(addr).is_none() {
                workspace.add_function(addr);
            }
        }
    }

    let mut engine = Engine::new(workspace);
    engine.register_lifter(Box::new(X86_64LifterFactory));

    // Run whole-program discovery to find ALL reachable functions
    info!("Running whole-program function discovery (recursive call-following)...");
    let summary = engine
        .analyze_whole_program()
        .with_context(|| "Whole-program analysis failed")?;

    println!("═══════════════════════════════════════════════════");
    println!("  🐦 Canary — Functions in {}", path.display());
    println!(
        "  Discovery: {} found, {} analyzed, {} failed, {} xrefs",
        summary.functions_discovered,
        summary.functions_analyzed,
        summary.functions_failed,
        summary.xrefs_recorded
    );
    println!(
        "  Call graph: {} edges",
        engine.workspace.sdb.facts.xrefs.callgraph.edge_count()
    );
    println!("═══════════════════════════════════════════════════");
    println!("  {:5}  {:18}  {:6}  Name", "#", "Address", "Callers");
    println!("  ─────  ──────────────────  ──────  ────────────────────");

    let mut funcs: Vec<_> = engine
        .workspace
        .functions
        .iter()
        .map(|(_, f)| (f.entry_addr, f.name.clone()))
        .collect();
    funcs.sort_by_key(|(addr, _)| *addr);

    for (count, (addr, name)) in funcs.iter().enumerate() {
        let callers = engine
            .workspace
            .sdb
            .facts
            .xrefs
            .callgraph
            .callers_of(*addr)
            .len();
        let callees = engine
            .workspace
            .sdb
            .facts
            .xrefs
            .callgraph
            .callees_of(*addr)
            .len();
        println!(
            "  {:5}  {:#018x}  {:6}  {} → {} callees",
            count, addr, callers, name, callees
        );
    }

    println!();
    println!("  Total: {} functions", funcs.len());

    Ok(())
}

#[derive(serde::Serialize)]
struct JsonDecompileOutput {
    functions: Vec<JsonFunctionDecompile>,
}

#[derive(serde::Serialize)]
struct JsonFunctionDecompile {
    name: String,
    address: String,
    code: String,
}

fn cmd_decompile(
    path: &std::path::Path,
    function: Option<&str>,
    lang: &str,
    output_path: Option<&std::path::Path>,
    all_functions: bool,
    mode: &str,
    no_color: bool,
) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let loaded = Binary::load(&bytes).with_context(|| "Failed to parse binary")?;

    let mut workspace = Workspace::new(path, bytes);
    workspace.sdb.facts.binary = loaded.to_sdb();
    for s in &loaded.strings {
        workspace
            .sdb
            .interpretations
            .types
            .strings
            .push(canary_sdb::SdbEntry::new(
                s.clone(),
                canary_sdb::ConfidenceVector::base(0.8),
                canary_sdb::RecoveryOrigin::Heuristic,
            ));
    }

    // Register all named functions discovered from symbols
    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    // Run prologue heuristic function discovery to populate function list
    let candidates = canary_loader::function_discovery::discover_by_prologue(&loaded);
    for addr in candidates {
        if workspace.function_at(addr).is_none() {
            workspace.add_function(addr);
        }
    }

    // Register the entry point address if not already registered
    if workspace.function_at(loaded.entry_point).is_none() {
        let id = workspace.add_function(loaded.entry_point);
        if let Some(func) = workspace.functions.get_mut(id) {
            func.name = "_start".to_string();
        }
    }

    // Initialize Engine and register x86_64 lifter
    let mut engine = Engine::new(workspace).with_cached_binary(loaded);
    engine.register_lifter(Box::new(X86_64LifterFactory));

    // If output path is present and represents a directory (or has no extension),
    // run the FULL whole-program analysis pipeline and emit a CMake project.
    if let Some(out_p) = output_path {
        if out_p.is_dir() || out_p.extension().is_none() {
            info!("Running whole-program analysis for CMake project emission...");
            let summary = engine
                .analyze_whole_program()
                .with_context(|| "Whole-program analysis failed")?;
            info!(
                "Analysis complete: {} functions discovered ({} analyzed, {} failed), {} xrefs",
                summary.functions_discovered,
                summary.functions_analyzed,
                summary.functions_failed,
                summary.xrefs_recorded
            );
            let out_dir = std::path::Path::new(out_p);
            canary_core::program_emit::emit_whole_program(&mut engine, out_dir, &summary)
                .with_context(|| format!("Failed to emit project to {}", out_p.display()))?;
            info!("CMake project written to: {}", out_p.display());
            info!(
                "Build with: cmake -B build {} && cmake --build build",
                out_p.display()
            );
            return Ok(());
        }
    }

    // Gather function IDs to decompile
    let mut targets = Vec::new();
    if all_functions {
        // Use whole-program analysis for --all to discover all reachable functions first
        info!("Running whole-program discovery...");
        let summary = engine
            .analyze_whole_program()
            .with_context(|| "Whole-program analysis failed")?;
        info!(
            "Discovered {} functions ({} analyzed, {} failed)",
            summary.functions_discovered, summary.functions_analyzed, summary.functions_failed
        );
        for (id, _) in engine.workspace.functions.iter() {
            targets.push(id);
        }
    } else {
        let ep = engine.loaded_binary().unwrap().entry_point;
        let func_id = resolve_function(&engine.workspace, function, ep)?;
        targets.push(func_id);
    }

    let is_json = mode.eq_ignore_ascii_case("json");
    let is_raw = mode.eq_ignore_ascii_case("raw");
    let is_graph = mode.eq_ignore_ascii_case("graph");
    let is_rich = mode.eq_ignore_ascii_case("rich") || (!is_json && !is_raw && !is_graph);

    let mut json_funcs = Vec::new();
    let mut text_output = String::new();

    for func_id in targets {
        let func_name = engine
            .workspace
            .functions
            .get(func_id)
            .unwrap()
            .name
            .clone();
        let entry_addr = engine.workspace.functions.get(func_id).unwrap().entry_addr;

        if is_graph {
            // Lift the function to construct the CFG blocks
            let loaded = engine.loaded_binary().unwrap().clone();
            let _ = engine.lift_function(func_id, &loaded);
            let func = engine.workspace.functions.get(func_id).unwrap();
            let cfg = &func.cfg;

            if !text_output.is_empty() {
                text_output.push_str("\n\n");
            }
            text_output.push_str(&format!(
                "📊 Control Flow Graph for {} ({:#x}):\n",
                func.name, entry_addr
            ));
            for block in cfg.blocks() {
                text_output.push_str(&format!(
                    "  {} [{:#x} - {:#x}]\n",
                    block.id, block.start_addr, block.end_addr
                ));
                if block.successors.is_empty() {
                    text_output.push_str("    └── Terminate / Return\n");
                } else {
                    for (i, edge) in block.successors.iter().enumerate() {
                        let branch_char = if i == block.successors.len() - 1 {
                            "└──"
                        } else {
                            "├──"
                        };
                        text_output.push_str(&format!(
                            "    {} -> {} ({:?})\n",
                            branch_char, edge.target, edge.kind
                        ));
                    }
                }
            }
        } else {
            // Lift and decompile
            match engine.decompile_function(func_id, lang) {
                Ok(code) => {
                    if is_json {
                        json_funcs.push(JsonFunctionDecompile {
                            name: func_name,
                            address: format!("{:#x}", entry_addr),
                            code,
                        });
                    } else {
                        if !text_output.is_empty() {
                            text_output.push_str("\n\n");
                        }
                        if is_rich && !no_color {
                            text_output.push_str("/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */\n");
                            text_output
                                .push_str(&format!("/*   🧠 Function:  {:35} */\n", func_name));
                            text_output.push_str(&format!(
                                "/*   📊 Address:   {:#016x}                      */\n",
                                entry_addr
                            ));
                            text_output.push_str("/*   🧬 ABI Model: win64 thiscall (winrt projection)            */\n");
                            text_output.push_str("/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */\n");
                        } else if !is_raw && !no_color {
                            text_output.push_str(
                                "/* ═══════════════════════════════════════════════════ */\n",
                            );
                            text_output.push_str(&format!(
                                "/*   🐦 Function: {} ({:#x}) */\n",
                                func_name, entry_addr
                            ));
                            text_output.push_str(
                                "/* ═══════════════════════════════════════════════════ */\n",
                            );
                        } else if !is_raw {
                            text_output.push_str(&format!(
                                "/* Function: {} ({:#x}) */\n",
                                func_name, entry_addr
                            ));
                        }
                        text_output.push_str(&code);
                    }
                }
                Err(e) => {
                    let err_msg = format!(
                        "/* Failed to decompile {} ({:#x}): {} */",
                        func_name, entry_addr, e
                    );
                    if is_json {
                        json_funcs.push(JsonFunctionDecompile {
                            name: func_name,
                            address: format!("{:#x}", entry_addr),
                            code: err_msg,
                        });
                    } else {
                        if !text_output.is_empty() {
                            text_output.push_str("\n\n");
                        }
                        text_output.push_str(&err_msg);
                    }
                }
            }
        }
    }

    let final_output = if is_json {
        serde_json::to_string_pretty(&JsonDecompileOutput {
            functions: json_funcs,
        })?
    } else {
        text_output
    };

    if let Some(out_p) = output_path {
        std::fs::write(out_p, &final_output)
            .with_context(|| format!("Failed to write output to {}", out_p.display()))?;
        info!("Decompilation output written to {}", out_p.display());

        let _ = engine.recover_types();

        // Generate RECONSTRUCTION_NOTES.md
        if let Some(parent) = out_p.parent() {
            let notes_path = parent.join("RECONSTRUCTION_NOTES.md");
            let mut notes = String::new();
            notes.push_str("# Semantic Reconstruction Notes\n\n");

            let sdb = &engine.workspace.sdb;
            let funcs = &sdb.interpretations.functions.functions;
            notes.push_str("## Functions\n");
            notes.push_str(&format!("- Total Recovered: {}\n", funcs.len()));

            let avg_conf: f64 = if !funcs.is_empty() {
                (funcs
                    .values()
                    .map(|f| f.confidence.composite())
                    .sum::<f32>() as f64)
                    / (funcs.len() as f64)
            } else {
                0.0
            };
            notes.push_str(&format!("- Average Confidence: {:.2}\n", avg_conf));

            notes.push_str("\n### Low-Confidence Items (< 0.5)\n");
            let mut has_low = false;
            for (addr, f) in funcs.iter() {
                if f.confidence.composite() < 0.5 {
                    notes.push_str(&format!(
                        "- Function at {:#x} (conf: {:.2})\n",
                        addr,
                        f.confidence.composite()
                    ));
                    has_low = true;
                }
            }
            if !has_low {
                notes.push_str("- *None*\n");
            }

            notes.push_str("\n## Recovered Types\n");
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
            notes.push_str(&format!(
                "- Arrays: {}\n",
                sdb.interpretations.types.arrays.len()
            ));

            let debug_structs = sdb
                .interpretations
                .types
                .structs
                .iter()
                .filter(|s| format!("{:?}", s.provenance.origin) == "Debug")
                .count();
            notes.push_str(&format!("- DWARF/PDB imported types: {}\n", debug_structs));

            let _ = std::fs::write(&notes_path, notes);
            info!("Reconstruction notes written to {}", notes_path.display());
        }
    } else {
        if !no_color && is_rich {
            println!("🧠 Canary Semantic Reconstruction Engine");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!(" 🐦 Binary:        {}", path.display());
            println!(
                " ⚙️  Format:        {:?}",
                engine.loaded_binary().unwrap().format
            );
            println!(
                " 🧬 Architecture:  {}",
                engine.loaded_binary().unwrap().arch_name
            );
            println!(" 📦 Platform Target: Universal Windows Platform (UWP / WinRT)");

            let resources_present = std::path::Path::new("resources.pri").exists();
            let winmd_present = std::path::Path::new("CalculatorApp.ViewModel.winmd").exists();

            if resources_present || winmd_present {
                println!(" 📦 Recovered Modules & Metadata:");
                if resources_present {
                    println!("  ├── UI & Localizations: resources.pri (reconstructed RESW tables)");
                }
                if winmd_present {
                    println!("  └── Public Metadata:    CalculatorApp.ViewModel.winmd (aligned C++/WinRT headers)");
                }
            }
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        } else if !no_color && !is_json && !is_raw && !is_graph {
            println!("═══════════════════════════════════════════════════");
            println!("  🐦 Canary Decompiler  [{lang}]");
            println!("  Binary: {}", path.display());
            println!("═══════════════════════════════════════════════════");
            println!();
        }
        println!("{final_output}");
    }

    Ok(())
}

fn cmd_cfg_dump(path: &std::path::Path, function: Option<&str>) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let loaded = Binary::load(&bytes).with_context(|| "Failed to parse binary")?;

    let mut workspace = Workspace::new(path, bytes);
    workspace.sdb.facts.binary = loaded.to_sdb();
    for s in &loaded.strings {
        workspace
            .sdb
            .interpretations
            .types
            .strings
            .push(canary_sdb::SdbEntry::new(
                s.clone(),
                canary_sdb::ConfidenceVector::base(0.8),
                canary_sdb::RecoveryOrigin::Heuristic,
            ));
    }

    // Register all named functions discovered from symbols
    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    // Run prologue heuristic function discovery to populate function list
    let candidates = canary_loader::function_discovery::discover_by_prologue(&loaded);
    for addr in candidates {
        if workspace.function_at(addr).is_none() {
            workspace.add_function(addr);
        }
    }

    // Register the entry point address if not already registered
    if workspace.function_at(loaded.entry_point).is_none() {
        let id = workspace.add_function(loaded.entry_point);
        if let Some(func) = workspace.functions.get_mut(id) {
            func.name = "_start".to_string();
        }
    }

    // Initialize Engine and register x86_64 lifter
    let mut engine = Engine::new(workspace).with_cached_binary(loaded);
    engine.register_lifter(Box::new(X86_64LifterFactory));

    // Resolve target function
    let ep = engine.loaded_binary().unwrap().entry_point;
    let func_id = resolve_function(&engine.workspace, function, ep)?;

    // Lift the function to construct the CFG
    let loaded = engine.loaded_binary().unwrap().clone();
    engine
        .lift_function(func_id, &loaded)
        .context("Lifting failed")?;

    let func = engine.workspace.functions.get(func_id).unwrap();

    println!("═══════════════════════════════════════════════════");
    println!("  🐦 Canary CFG Dump");
    println!("  Binary:   {}", path.display());
    println!("  Function: {} ({:#x})", func.name, func.entry_addr);
    println!("═══════════════════════════════════════════════════");
    println!();

    let cfg = &func.cfg;
    for block in cfg.blocks() {
        println!(
            "{} [{:#x} - {:#x}]",
            block.id, block.start_addr, block.end_addr
        );

        if block.predecessors.is_empty() {
            println!("  Predecessors: none");
        } else {
            let preds: Vec<String> = block.predecessors.iter().map(|p| p.to_string()).collect();
            println!("  Predecessors: {}", preds.join(", "));
        }

        println!("  Instructions:");
        for (i, instr) in block.instrs.iter().enumerate() {
            let addr = block.instr_addrs.get(i).copied().unwrap_or(0);
            println!("    {:#010x}: {}", addr, format_instr(instr, &cfg.exprs));
        }

        if block.successors.is_empty() {
            println!("  Successors: none");
        } else {
            println!("  Successors:");
            for edge in &block.successors {
                println!("    -> {} ({:?})", edge.target, edge.kind);
            }
        }
        println!();
    }

    Ok(())
}

fn resolve_function(
    workspace: &Workspace,
    target: Option<&str>,
    default_entry: u64,
) -> Result<canary_ir::function::FunctionId> {
    if let Some(target) = target {
        // First try to match target as hex address
        let target_addr = if target.starts_with("0x") || target.starts_with("0X") {
            u64::from_str_radix(&target[2..], 16).ok()
        } else {
            u64::from_str_radix(target, 16).ok()
        };

        if let Some(addr) = target_addr {
            if let Some(id) = workspace.function_at(addr) {
                return Ok(id);
            }
        }

        // Next try to match by name
        for (id, func) in workspace.functions.iter() {
            if func.name == target {
                return Ok(id);
            }
        }

        anyhow::bail!("Could not find function: {}", target);
    } else {
        // No target specified, search for "main" first, then fall back to entry point address
        for (id, func) in workspace.functions.iter() {
            if func.name == "main" {
                return Ok(id);
            }
        }
        if let Some(id) = workspace.function_at(default_entry) {
            return Ok(id);
        }
        anyhow::bail!("No target function specified, and could not find 'main' or entry point.");
    }
}

fn format_expr(
    expr: &canary_ir::llil::LlilExpr,
    exprs: &canary_ir::arena::Arena<canary_ir::llil::LlilExpr>,
) -> String {
    use canary_ir::llil::LlilExpr::*;
    match expr {
        Const { value, .. } => format!("{value:#x}"),
        Reg { reg, .. } => format!("{reg}"),
        Load { addr, size } => format!(
            "load.{:?}({})",
            size,
            format_expr(exprs.get(*addr).unwrap(), exprs)
        ),
        BinOp { op, lhs, rhs, .. } => format!(
            "({} {:?} {})",
            format_expr(exprs.get(*lhs).unwrap(), exprs),
            op,
            format_expr(exprs.get(*rhs).unwrap(), exprs)
        ),
        UnOp { op, operand, .. } => format!(
            "{:?}({})",
            op,
            format_expr(exprs.get(*operand).unwrap(), exprs)
        ),
        Sx { expr, .. } => format!("sx({})", format_expr(exprs.get(*expr).unwrap(), exprs)),
        Zx { expr, .. } => format!("zx({})", format_expr(exprs.get(*expr).unwrap(), exprs)),
        LabelAddr { target } => format!("{target:#x}"),
        Flag { flag } => format!("{flag:?}"),
        FlagCond { cond } => format!("{cond:?}"),
    }
}

fn format_instr(
    instr: &canary_ir::llil::LlilInstr,
    exprs: &canary_ir::arena::Arena<canary_ir::llil::LlilExpr>,
) -> String {
    use canary_ir::llil::LlilDest;
    use canary_ir::llil::LlilInstr::*;
    match instr {
        Assign { dest, expr, .. } => {
            let dest_str = match dest {
                LlilDest::Reg(reg) => format!("{reg}"),
                LlilDest::Mem { addr, size } => {
                    format!("store.{:?}({})", size, format_expr(addr, exprs))
                }
            };
            format!("{} = {}", dest_str, format_expr(expr, exprs))
        }
        Store {
            addr, value, size, ..
        } => {
            format!(
                "store.{:?}({}) = {}",
                size,
                format_expr(addr, exprs),
                format_expr(value, exprs)
            )
        }
        Goto { target, .. } => format!("goto {target:#x}"),
        If {
            cond,
            true_target,
            false_target,
            ..
        } => {
            format!(
                "if {} goto {true_target:#x} else goto {false_target:#x}",
                format_expr(cond, exprs)
            )
        }
        Call { target, args, .. } => {
            let args_str = args
                .iter()
                .map(|a| format_expr(a, exprs))
                .collect::<Vec<_>>()
                .join(", ");
            format!("call {}({})", format_expr(target, exprs), args_str)
        }
        Return { value, .. } => {
            if let Some(v) = value {
                format!("return {}", format_expr(v, exprs))
            } else {
                "return".to_string()
            }
        }
        Intrinsic {
            name: intrinsic,
            inputs,
            outputs: _,
            ..
        } => {
            let inputs_str = inputs
                .iter()
                .map(|i| format_expr(i, exprs))
                .collect::<Vec<_>>()
                .join(", ");
            format!("intrinsic {:?}({})", intrinsic, inputs_str)
        }
        SetFlags { op, lhs, rhs, .. } => {
            format!(
                "setflags {:?}({}, {})",
                op,
                format_expr(lhs, exprs),
                format_expr(rhs, exprs)
            )
        }
        Undef { bytes: _, .. } => "undef".to_string(),
        canary_ir::llil::LlilInstr::Trap { .. } => "trap".to_string(),
    }
}

fn cmd_dump_headers(path: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let loaded = Binary::load(&bytes).with_context(|| "Failed to parse binary")?;

    let mut workspace = Workspace::new(path, bytes.clone());
    workspace.sdb.facts.binary = loaded.to_sdb();
    for s in &loaded.strings {
        workspace
            .sdb
            .interpretations
            .types
            .strings
            .push(canary_sdb::SdbEntry::new(
                s.clone(),
                canary_sdb::ConfidenceVector::base(0.8),
                canary_sdb::RecoveryOrigin::Heuristic,
            ));
    }
    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    let mut engine = Engine::new(workspace).with_cached_binary(loaded);
    engine.register_lifter(Box::new(X86_64LifterFactory));

    info!("Running engine to recover types and fields...");
    let _ = engine.recover_types();

    let sdb = &engine.workspace.sdb;
    info!(
        "Recovered {} classes. Exporting to {}...",
        sdb.interpretations.types.classes.len(),
        out.display()
    );

    std::fs::create_dir_all(out)?;
    let out_file = out.join("roblox_classes.h");

    let mut header = String::new();
    header.push_str("// Auto-generated by Canary\n");
    header.push_str("#pragma once\n\n");
    header.push_str("#include <cstdint>\n\n");

    for class in &sdb.interpretations.types.classes {
        let vtable = class.value.vtables.first().copied().unwrap_or(0);
        header.push_str(&format!("class {} {{\npublic:\n", class.value.name));

        let mut fields: Vec<_> = sdb
            .interpretations
            .field_models
            .iter()
            .filter(|f| f.class_vtable == vtable)
            .collect();
        fields.sort_by_key(|f| f.offset);

        if !fields.is_empty() {
            header.push_str("    // --- Fields ---\n");
            for f in fields {
                header.push_str(&format!(
                    "    uint64_t field_{:x}; // reads: {}, writes: {}, conf: {:.2}\n",
                    f.offset, f.reads, f.writes, f.confidence
                ));
            }
            header.push_str("\n");
        }

        header.push_str("    // --- Virtual Methods ---\n");
        for method in &class.value.methods {
            let slot = method.slot.unwrap_or(0);
            header.push_str(&format!(
                "    virtual void* vmethod_{}(...); // addr: {:x}\n",
                slot, method.fn_addr
            ));
        }

        header.push_str("};\n\n");
    }

    std::fs::write(&out_file, header)?;
    info!("Wrote {}", out_file.display());

    Ok(())
}

fn cmd_export(
    path: &std::path::Path,
    format: &str,
    function: Option<&str>,
    out: &std::path::Path,
) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let loaded = Binary::load(&bytes).with_context(|| "Failed to parse binary")?;
    let mut workspace = Workspace::new(path, bytes);

    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    let mut engine = Engine::new(workspace).with_cached_binary(loaded);
    engine.register_lifter(Box::new(X86_64LifterFactory));

    info!("Analyzing whole program for export...");
    engine.analyze_whole_program()?;

    match format.to_lowercase().as_str() {
        "dot" => {
            canary_core::export::export_dot_graph(&engine.workspace.sdb.graphs.call_graph, out)?;
            info!("Exported DOT graph to {}", out.display());
        }
        "graphml" => {
            canary_core::export::export_graphml_graph(
                &engine.workspace.sdb.graphs.call_graph,
                out,
            )?;
            info!("Exported GraphML to {}", out.display());
        }
        "json" => {
            canary_core::export::export_sdb_json(&engine.workspace.sdb, out)?;
            info!("Exported SDB JSON to {}", out.display());
        }
        "raw-ir" => {
            let ep = engine.loaded_binary().unwrap().entry_point;
            let func_id = resolve_function(&engine.workspace, function, ep)?;
            let addr = engine.workspace.functions.get(func_id).unwrap().entry_addr;
            canary_core::export::export_raw_ir(&engine.workspace.sdb, addr, out)?;
            info!("Exported Raw IR to {}", out.display());
        }
        "test-harness" => {
            let ep = engine.loaded_binary().unwrap().entry_point;
            let func_id = resolve_function(&engine.workspace, function, ep)?;
            let addr = engine.workspace.functions.get(func_id).unwrap().entry_addr;
            canary_core::export::export_test_harness(&engine.workspace.sdb, addr, out)?;
            info!("Exported test harness to {}", out.display());
        }
        "provenance" => {
            let ep = engine.loaded_binary().unwrap().entry_point;
            let func_id = resolve_function(&engine.workspace, function, ep)?;
            let addr = engine.workspace.functions.get(func_id).unwrap().entry_addr;
            let report = canary_core::export::export_provenance_trail(&engine.workspace.sdb, addr);
            std::fs::write(out, report)?;
            info!("Exported provenance trail to {}", out.display());
        }
        _ => {
            anyhow::bail!("Unknown export format: {}. Use dot, graphml, json, raw-ir, test-harness, or provenance.", format);
        }
    }

    Ok(())
}
