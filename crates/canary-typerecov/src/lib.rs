pub mod arrays;
pub mod bitfields;
pub mod debug_import;
pub mod enums;
pub mod primitives;
pub mod structs;
pub mod type_libs;
pub mod winrt_headers;

use canary_ir::function::FunctionArena;
use canary_sdb::SemanticDatabase;

pub fn run_all(sdb: &mut SemanticDatabase, functions: &FunctionArena) {
    sdb.interpretations.types.structs.clear();
    sdb.interpretations.types.enums.clear();
    sdb.interpretations.types.arrays.clear();

    structs::recover_structs(sdb, functions);
    type_libs::match_type_libs(sdb);
    enums::recover_enums(sdb, functions);
    arrays::recover_arrays(sdb, functions);
    bitfields::recover_bitfields(sdb, functions);
    debug_import::import_dwarf_types(sdb);
    debug_import::import_pdb_types(sdb);

    // Synthesize WinRT headers dynamically for all recovered classes
    let classes: Vec<_> = sdb
        .interpretations
        .types
        .classes
        .iter()
        .map(|c| c.value.clone())
        .collect();
    winrt_headers::WinRtHeaderSynthesizer::synthesize_all(sdb, &classes);
}

pub mod cluster;
