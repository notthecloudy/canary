//! Export Modes
//!
//! Provides the ability to export the internal IR and SDB states
//! to various formats, including GraphML/DOT, raw JSON, and provenance traces.

use canary_sdb::graphs::CallGraph;
use canary_sdb::{SemanticDatabase, StableId};
use std::fs;
use std::path::Path;

/// Export the CallGraph to a DOT file for Graphviz rendering.
pub fn export_dot_graph(graph: &CallGraph, path: &Path) -> Result<(), std::io::Error> {
    let mut dot = String::new();
    dot.push_str("digraph CallGraph {\n");

    // Nodes
    for addr in graph.all_functions() {
        dot.push_str(&format!("  node_{} [label=\"{:#x}\"];\n", addr, addr));
    }

    // Edges
    for (caller, edges) in &graph.callees {
        for edge in edges {
            dot.push_str(&format!("  node_{} -> node_{};\n", caller, edge.to_node));
        }
    }

    dot.push_str("}\n");
    fs::write(path, dot)
}

/// Export the CallGraph to a GraphML file.
pub fn export_graphml_graph(graph: &CallGraph, path: &Path) -> Result<(), std::io::Error> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    xml.push_str("  <graph id=\"CallGraph\" edgedefault=\"directed\">\n");

    for addr in graph.all_functions() {
        xml.push_str(&format!("    <node id=\"n_{}\"/>\n", addr));
    }

    for (caller, edges) in &graph.callees {
        for edge in edges {
            xml.push_str(&format!(
                "    <edge source=\"n_{}\" target=\"n_{}\"/>\n",
                caller, edge.to_node
            ));
        }
    }

    xml.push_str("  </graph>\n</graphml>\n");
    fs::write(path, xml)
}

#[derive(serde::Serialize)]
struct SdbExportDto {
    pub functions: std::collections::HashMap<u64, FunctionDto>,
    pub structs: usize,
    pub enums: usize,
}

#[derive(serde::Serialize)]
struct FunctionDto {
    pub name: Option<String>,
    pub blocks: usize,
    pub composite_confidence: f32,
}

/// Export the entire Semantic Database state as JSON using a DTO to bypass serde macro requirements.
pub fn export_sdb_json(sdb: &SemanticDatabase, path: &Path) -> Result<(), std::io::Error> {
    let mut dto = SdbExportDto {
        functions: std::collections::HashMap::new(),
        structs: sdb.interpretations.types.structs.len(),
        enums: sdb.interpretations.types.enums.len(),
    };

    for (addr, func) in &sdb.interpretations.functions.functions {
        dto.functions.insert(
            *addr,
            FunctionDto {
                name: func.value.name.clone(),
                blocks: func.value.cfg_blocks.len(),
                composite_confidence: func.confidence.composite(),
            },
        );
    }

    let json = serde_json::to_string_pretty(&dto)?;
    fs::write(path, json)
}

/// Export the exact reasoning behind a recovered decision.
pub fn export_provenance_trail(sdb: &SemanticDatabase, function_addr: u64) -> String {
    let mut trail = String::new();
    trail.push_str(&format!(
        "Provenance Report for Function {:#x}\n",
        function_addr
    ));
    trail.push_str("==========================================\n");

    if let Some(func) = sdb.interpretations.functions.functions.get(&function_addr) {
        trail.push_str(&format!(
            "Composite Confidence: {:.2}\n",
            func.confidence.composite()
        ));

        trail.push_str("\nEvidence Trail:\n");
        for ev in &func.provenance.evidence {
            trail.push_str(&format!(" - {:?}\n", ev));
        }

        trail.push_str("\nCompeting Hypotheses:\n");
        for hyp in &func.hypotheses {
            trail.push_str(&format!(
                " - {:?} (Score: {})\n",
                hyp.evidence,
                hyp.confidence.composite()
            ));
        }
    } else {
        trail.push_str("Function not found in SDB.");
    }

    trail
}

/// Export the raw basic blocks / CFG IR to a text file for inspection.
pub fn export_raw_ir(
    sdb: &SemanticDatabase,
    function_addr: u64,
    path: &Path,
) -> Result<(), std::io::Error> {
    let mut out = String::new();
    if let Some(func) = sdb.interpretations.functions.functions.get(&function_addr) {
        out.push_str(&format!(
            "Raw IR for {:#x} ({:?})\n\n",
            function_addr, func.value.name
        ));
        for block in &func.value.cfg_blocks {
            out.push_str(&format!(
                "Block [{:#x} - {:#x}]\n",
                block.address,
                block.address + block.size as u64
            ));
            out.push_str(&format!("  Successors: {:?}\n", block.successors));
            out.push_str("\n");
        }
    } else {
        out.push_str("Function not found in SDB.");
    }
    fs::write(path, out)
}

/// Export a standalone C test harness template for the function.
pub fn export_test_harness(
    sdb: &SemanticDatabase,
    function_addr: u64,
    path: &Path,
) -> Result<(), std::io::Error> {
    let mut out = String::new();
    if let Some(func) = sdb.interpretations.functions.functions.get(&function_addr) {
        let name = func
            .value
            .name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", function_addr));

        out.push_str(&format!("// Test Harness for {}\n", name));
        out.push_str("#include <stdio.h>\n");
        out.push_str("#include <assert.h>\n\n");

        // Mock declaration
        out.push_str(&format!("extern void* {}(void* arg1);\n\n", name));

        out.push_str("int main() {\n");
        out.push_str("    printf(\"Running tests for %s...\\n\", __func__);\n");
        out.push_str(&format!("    // void* result = {}(NULL);\n", name));
        out.push_str("    // assert(result != NULL);\n");
        out.push_str("    printf(\"All tests passed!\\n\");\n");
        out.push_str("    return 0;\n");
        out.push_str("}\n");
    } else {
        out.push_str("// Function not found in SDB.\n");
    }
    fs::write(path, out)
}
