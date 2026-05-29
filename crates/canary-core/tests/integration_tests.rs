use canary_arch_x86::X86_64LifterFactory;
use canary_core::engine::Engine;
use canary_core::workspace::Workspace;
use canary_ir::function::FunctionId;
use canary_loader::{binary::LoadedBinary, Binary};

const ELF_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/x86_64/test_fixture_linux.so");
const PE_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/x86_64/test_fixture_windows.dll");

fn engine_for_fixture(path: &str, bytes: &[u8]) -> (Engine, LoadedBinary) {
    let loaded = Binary::load(bytes).expect("failed to load fixture");
    let mut workspace = Workspace::new(std::path::Path::new(path), bytes.to_vec());
    workspace.sdb.facts.binary = loaded.to_sdb();

    for ep in &loaded.named_functions {
        let id = workspace.add_function(ep.addr);
        if let Some(name) = &ep.name {
            if let Some(func) = workspace.functions.get_mut(id) {
                func.name = name.clone();
            }
        }
    }

    let mut engine = Engine::new(workspace).with_cached_binary(loaded.clone());
    engine.register_lifter(Box::new(X86_64LifterFactory));
    (engine, loaded)
}

fn find_function(engine: &Engine, needle: &str) -> FunctionId {
    engine
        .workspace
        .functions
        .iter()
        .find(|(_, f)| f.name.contains(needle))
        .map(|(id, _)| id)
        .unwrap_or_else(|| panic!("failed to find {needle}"))
}

#[test]
fn test_integration_elf_load() {
    let loaded = Binary::load(ELF_FIXTURE).expect("Failed to load ELF fixture");
    assert_eq!(loaded.arch_name, "x86_64");

    let fn_names: Vec<String> = loaded
        .named_functions
        .iter()
        .filter_map(|ep| ep.name.clone())
        .collect();

    println!("ELF Functions: {:?}", fn_names);
    assert!(
        fn_names.iter().any(|n| n.contains("add_numbers")),
        "Missing add_numbers in ELF"
    );
    assert!(
        fn_names.iter().any(|n| n.contains("simple_if")),
        "Missing simple_if in ELF"
    );
    assert!(
        fn_names.iter().any(|n| n.contains("simple_loop")),
        "Missing simple_loop in ELF"
    );
}

#[test]
fn test_integration_pe_load() {
    let loaded = Binary::load(PE_FIXTURE).expect("Failed to load PE fixture");
    assert_eq!(loaded.arch_name, "x86_64");

    let fn_names: Vec<String> = loaded
        .named_functions
        .iter()
        .filter_map(|ep| ep.name.clone())
        .collect();

    println!("PE Functions: {:?}", fn_names);
    assert!(
        fn_names.iter().any(|n| n.contains("add_numbers")),
        "Missing add_numbers in PE"
    );
    assert!(
        fn_names.iter().any(|n| n.contains("simple_if")),
        "Missing simple_if in PE"
    );
    assert!(
        fn_names.iter().any(|n| n.contains("simple_loop")),
        "Missing simple_loop in PE"
    );
}

#[test]
fn test_integration_elf_decompile_all() {
    let (mut engine, _) = engine_for_fixture("test_fixture_linux.so", ELF_FIXTURE);

    // Decompile add_numbers
    let add_fn_id = find_function(&engine, "add_numbers");
    let c_add = engine.decompile_function(add_fn_id, "c").unwrap();
    assert!(c_add.contains("add_numbers"));

    // Check SDB contents for add_numbers
    let add_func = engine.workspace.functions.get(add_fn_id).unwrap();
    assert!(
        add_func.semantic.is_some(),
        "Semantic IR should survive in function state"
    );
    let mlil = add_func
        .mlil
        .as_ref()
        .expect("MLIL should survive in function state");
    assert!(
        mlil.semantic.is_some(),
        "Semantic IR should be passed into MLIL state"
    );
    assert_eq!(
        mlil.scheduled_order,
        vec![
            "dominators",
            "ssa",
            "vsa",
            "pointer_provenance",
            "stack_vars",
            "primitive_types",
            "calling_conventions",
            "semantic_lowering",
            "structuring",
            "mlil_lowering"
        ]
    );
    println!("DEBUG: mlil.instr_provenance: {:#?}", mlil.instr_provenance);
    println!("DEBUG: ssa block: {:#?}", add_func.ssa.as_ref().unwrap().blocks);
    assert!(
        !mlil.instr_provenance.is_empty(),
        "MLIL should carry instruction provenance"
    );
    let sdb_func = engine
        .workspace
        .sdb
        .interpretations
        .functions
        .functions
        .get(&add_func.entry_addr)
        .expect("SDB function entry missing");
    assert!(
        !sdb_func.value.cfg_blocks.is_empty(),
        "SDB CFG blocks should be populated"
    );
    assert!(sdb_func.value.ssa.is_some(), "SDB SSA info missing");
    let ssa_entry = sdb_func.value.ssa.as_ref().unwrap();
    let ssa_confidence = ssa_entry.confidence.composite();
    assert!((0.0..=1.0).contains(&ssa_confidence));
    assert!(sdb_func.value.vsa.is_some(), "SDB VSA info missing");
    assert!(
        sdb_func.value.pointer_provenance.is_some(),
        "SDB pointer provenance info missing"
    );
    assert!(
        sdb_func.value.semantic.is_some(),
        "SDB semantic IR summary missing"
    );
    assert!(
        sdb_func.value.stack_frame.is_some(),
        "SDB StackFrame info missing"
    );
    assert!(
        sdb_func.value.call_signature.is_some(),
        "SDB CallSignature info missing"
    );
    assert!(
        sdb_func.value.high_level_cfg.is_some(),
        "SDB HL-CF info missing"
    );
    assert!(
        sdb_func.value.mlil_complete,
        "SDB mlil_complete should be true"
    );

    // Decompile simple_if
    let if_fn_id = find_function(&engine, "simple_if");
    let c_if = engine.decompile_function(if_fn_id, "c").unwrap();
    assert!(c_if.contains("simple_if"));

    // Decompile simple_loop
    let loop_fn_id = find_function(&engine, "simple_loop");
    let c_loop = engine.decompile_function(loop_fn_id, "c").unwrap();
    assert!(c_loop.contains("simple_loop"));
}

#[test]
fn test_integration_pe_decompile_all() {
    let (mut engine, _) = engine_for_fixture("test_fixture_windows.dll", PE_FIXTURE);

    // Decompile add_numbers
    let add_fn_id = find_function(&engine, "add_numbers");
    let c_add = engine.decompile_function(add_fn_id, "c").unwrap();
    assert!(c_add.contains("add_numbers"));

    // Decompile simple_if
    let if_fn_id = find_function(&engine, "simple_if");
    let c_if = engine.decompile_function(if_fn_id, "c").unwrap();
    assert!(c_if.contains("simple_if"));

    // Decompile simple_loop
    let loop_fn_id = find_function(&engine, "simple_loop");
    let c_loop = engine.decompile_function(loop_fn_id, "c").unwrap();
    assert!(c_loop.contains("simple_loop"));
}

#[test]
fn decompile_function_and_stateless_share_phase2_output_for_identical_inputs() {
    let (mut stateful_engine, _) = engine_for_fixture("test_fixture_linux.so", ELF_FIXTURE);
    let stateful_fn = find_function(&stateful_engine, "add_numbers");
    let stateful_code = stateful_engine
        .decompile_function(stateful_fn, "c")
        .unwrap();

    let (mut stateless_engine, loaded) = engine_for_fixture("test_fixture_linux.so", ELF_FIXTURE);
    let stateless_fn = find_function(&stateless_engine, "add_numbers");
    stateless_engine
        .lift_function(stateless_fn, &loaded)
        .expect("stateless fixture lift failed");
    let (stateless_code, stateless_sdb) = stateless_engine
        .decompile_function_stateless(stateless_fn, "c")
        .unwrap();

    assert_eq!(stateful_code, stateless_code);

    let stateful_func = stateful_engine
        .workspace
        .functions
        .get(stateful_fn)
        .unwrap();
    let stateful_sdb = &stateful_engine
        .workspace
        .sdb
        .interpretations
        .functions
        .functions
        .get(&stateful_func.entry_addr)
        .unwrap()
        .value;
    assert_eq!(
        stateful_sdb
            .call_signature
            .as_ref()
            .map(|sig| sig.value.calling_conv.clone()),
        stateless_sdb
            .call_signature
            .as_ref()
            .map(|sig| sig.value.calling_conv.clone())
    );
    assert_eq!(stateful_sdb.mlil_complete, stateless_sdb.mlil_complete);
}
