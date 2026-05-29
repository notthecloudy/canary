//! Core engine — orchestrates analysis passes over the workspace.

use crate::workspace::Workspace;
use canary_arch::ArchLifterFactory;
use canary_ir::function::FunctionId;
use canary_loader::binary::Binary;

/// Errors from the engine execution.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Function not found: {0:?}")]
    FunctionNotFound(FunctionId),

    #[error("Loader error: {0}")]
    Loader(String),

    #[error("No lifter factory registered for architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Lifting error: {0}")]
    Lift(#[from] canary_arch::LiftError),

    #[error("CFG validation failed: {0:?}")]
    CfgValidation(Vec<canary_ir::cfg::CfgError>),

    #[error("SSA validation failed: {0:?}")]
    SsaValidation(Vec<canary_analysis::ssa::SsaError>),

    #[error("Emit error: {0}")]
    Emit(#[from] canary_emit::EmitError),

    #[error("Output language {0} not supported")]
    UnsupportedLanguage(String),
}

/// The main analysis engine.
///
/// The engine drives the analysis pipeline:
/// 1. Load binary → populate workspace
/// 2. Discover functions
/// 3. Lift each function to LLIL (via architecture lifter)
/// 4. Construct CFG and SSA
/// 5. Run type inference passes
/// 6. Run semantic raising passes
/// 7. Emit source code
pub struct Engine {
    pub workspace: Workspace,
    lifter_factories: Vec<Box<dyn ArchLifterFactory>>,
    /// Lazily-parsed binary — avoids re-parsing the binary on every analysis pass.
    /// `pub(crate)` so refinement.rs (same crate) can access it.
    pub(crate) cached_loaded: Option<canary_loader::binary::LoadedBinary>,
}

struct Phase2Output {
    code: String,
    sdb_func: canary_sdb::SdbFunction,
    semantic: canary_ir::semantic::SemanticFunction,
    mlil: canary_ir::mlil::MlilFunction,
}

impl Engine {
    /// Creates a new analysis engine.
    pub fn new(workspace: Workspace) -> Self {
        Self {
            workspace,
            lifter_factories: Vec::new(),
            cached_loaded: None,
        }
    }

    /// Initializes the engine with an already-parsed binary, preventing redundant parsing.
    pub fn with_cached_binary(mut self, loaded: canary_loader::binary::LoadedBinary) -> Self {
        self.cached_loaded = Some(loaded);
        self
    }

    /// Returns a reference to the parsed binary, loading it lazily on first call.
    /// This avoids re-parsing the binary (which may be several MB) on every analysis pass.
    pub fn loaded_binary(&mut self) -> Result<&canary_loader::binary::LoadedBinary, EngineError> {
        if self.cached_loaded.is_none() {
            let loaded = Binary::load(&self.workspace.binary_bytes)
                .map_err(|e| EngineError::Loader(e.to_string()))?;
            self.cached_loaded = Some(loaded);
        }
        Ok(self.cached_loaded.as_ref().unwrap())
    }

    /// Registers an architecture lifter factory.
    pub fn register_lifter(&mut self, factory: Box<dyn ArchLifterFactory>) {
        self.lifter_factories.push(factory);
    }

    /// Lifts a function to LLIL, constructs its CFG, dominant tree, and builds SSA form.
    pub fn lift_function(
        &mut self,
        func_id: FunctionId,
        loaded: &canary_loader::binary::LoadedBinary,
    ) -> Result<(), EngineError> {
        // 1. Select lifter
        let factory = self
            .lifter_factories
            .iter()
            .find(|f| f.supports(&loaded.arch_name))
            .ok_or_else(|| EngineError::UnsupportedArchitecture(loaded.arch_name.clone()))?;
        let lifter = factory.create();

        // 2. Get function entry address
        let entry_addr = {
            let func = self
                .workspace
                .functions
                .get(func_id)
                .ok_or(EngineError::FunctionNotFound(func_id))?;
            func.entry_addr
        };

        // 3. Find section for entry address
        let section = loaded.section_at(entry_addr).ok_or_else(|| {
            EngineError::Loader(format!("Address {entry_addr:#x} not inside any section"))
        })?;

        // 4. Build CFG
        let mut cfg = lifter.build_cfg(&section.data, section.virtual_range.start, entry_addr)?;

        // 5. CFG Validation
        let cfg_errors = canary_ir::cfg::cfg_validate(&cfg);
        if !cfg_errors.is_empty() {
            return Err(EngineError::CfgValidation(cfg_errors));
        }

        // 6. Compute Dominators
        let dom_info = canary_analysis::dominators::compute_dominators(&cfg).ok_or_else(|| {
            EngineError::Loader("Failed to compute dominators: CFG has no entry".to_string())
        })?;

        // 7. Detect and mark back-edges
        canary_analysis::dominators::mark_back_edges(&mut cfg, &dom_info);

        // 8. Build SSA
        let ssa_builder = canary_analysis::ssa::SsaBuilder::new(&cfg, &dom_info);
        let ssa_func = ssa_builder.build_ssa();

        // 9. SSA Validation
        let ssa_errors = canary_analysis::ssa::validate_ssa(&ssa_func, &cfg, &dom_info);
        if !ssa_errors.is_empty() {
            return Err(EngineError::SsaValidation(ssa_errors));
        }

        // 10. Store result back
        let func = self
            .workspace
            .functions
            .get_mut(func_id)
            .ok_or(EngineError::FunctionNotFound(func_id))?;
        func.cfg = cfg;
        func.ssa = Some(ssa_func);
        func.is_lifted = true;

        let mut sdb_func = self
            .workspace
            .sdb
            .interpretations
            .functions
            .functions
            .shift_remove(&entry_addr)
            .map(|e| e.value)
            .unwrap_or_else(|| canary_sdb::SdbFunction {
                entry_addr,
                ..Default::default()
            });

        // We temporarily borrow from func instead of moving cfg
        let mut cfg_blocks = Vec::new();
        for bb in func.cfg.blocks() {
            let mut successors = Vec::new();
            for edge in &bb.successors {
                if let Some(succ_bb) = func.cfg.block(edge.target) {
                    let mapped_kind = match edge.kind {
                        canary_ir::cfg::EdgeKind::Unconditional => {
                            canary_sdb::EdgeKind::Unconditional
                        }
                        canary_ir::cfg::EdgeKind::True => canary_sdb::EdgeKind::True,
                        canary_ir::cfg::EdgeKind::False => canary_sdb::EdgeKind::False,
                        canary_ir::cfg::EdgeKind::Call => canary_sdb::EdgeKind::Call,
                        canary_ir::cfg::EdgeKind::Return => canary_sdb::EdgeKind::Return,
                        canary_ir::cfg::EdgeKind::Back => canary_sdb::EdgeKind::Back,
                    };
                    successors.push((succ_bb.start_addr, mapped_kind));
                }
            }
            cfg_blocks.push(canary_sdb::SdbBasicBlock {
                address: bb.start_addr,
                size: (bb.end_addr - bb.start_addr) as usize,
                successors,
            });
        }
        sdb_func.cfg_blocks = cfg_blocks;

        self.workspace
            .sdb
            .interpretations
            .functions
            .functions
            .insert(
                entry_addr,
                canary_sdb::SdbEntry::new(
                    sdb_func,
                    canary_sdb::ConfidenceVector::base(1.0),
                    canary_sdb::RecoveryOrigin::Exact,
                ),
            );

        Ok(())
    }

    pub fn recover_types(&mut self) -> Result<(), EngineError> {
        let mut iteration = 0;
        let mut previous_hash = 0;

        loop {
            tracing::info!("Running type recovery passes (Iteration {})...", iteration);
            canary_typerecov::run_all(&mut self.workspace.sdb, &self.workspace.functions);

            // Use the cached LoadedBinary to avoid re-parsing on every iteration
            if self.cached_loaded.is_none() {
                if let Ok(loaded) = Binary::load(&self.workspace.binary_bytes) {
                    self.cached_loaded = Some(loaded);
                }
            }

            // Run C++ discovery — borrows cached_loaded immutably, then drops it
            if self.cached_loaded.is_some() {
                let loaded = self.cached_loaded.as_ref().unwrap();
                canary_cpprecov::run_discovery(
                    &mut self.workspace.sdb,
                    &self.workspace.functions,
                    loaded,
                );
            }

            // Collect method addresses first (drops the borrow before we lift)
            let methods_to_lift: Vec<u64> = if self.cached_loaded.is_some() {
                self.workspace
                    .sdb
                    .interpretations
                    .types
                    .methods
                    .iter()
                    .take(5000)
                    .map(|m| m.value.fn_addr)
                    .collect()
            } else {
                Vec::new()
            };

            // Lift each method — requires &mut self, so we re-borrow cached_loaded per call
            for addr in methods_to_lift {
                let func_id = self.workspace.add_function(addr);
                if let Some(loaded) = self.cached_loaded.clone() {
                    let _ = self.lift_function(func_id, &loaded);
                }
            }

            canary_cpprecov::run_recovery(&mut self.workspace.sdb, &self.workspace.functions);
            crate::clustering::cluster_modules(&mut self.workspace);
            crate::naming::enrich_symbols(&mut self.workspace);

            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();

            self.workspace
                .sdb
                .interpretations
                .types
                .structs
                .len()
                .hash(&mut hasher);
            self.workspace
                .sdb
                .interpretations
                .types
                .classes
                .len()
                .hash(&mut hasher);
            self.workspace
                .sdb
                .interpretations
                .functions
                .functions
                .len()
                .hash(&mut hasher);
            self.workspace
                .sdb
                .interpretations
                .modules
                .modules
                .len()
                .hash(&mut hasher);

            let current_hash = hasher.finish();

            if current_hash == previous_hash {
                tracing::info!("Type recovery converged after {} iterations", iteration + 1);
                break;
            }

            previous_hash = current_hash;
            iteration += 1;

            const MAX_TYPE_RECOVERY_ITERATIONS: usize = 8;
            if iteration >= MAX_TYPE_RECOVERY_ITERATIONS {
                tracing::warn!(
                    "Type recovery stopped after max iterations ({})",
                    MAX_TYPE_RECOVERY_ITERATIONS
                );
                break;
            }
        }

        Ok(())
    }

    fn default_calling_convention(&self) -> canary_ir::types::CallingConvention {
        use canary_ir::types::CallingConvention;

        let format = self.workspace.sdb.facts.binary.format.to_ascii_lowercase();
        let arch = self.workspace.sdb.facts.binary.arch.to_ascii_lowercase();

        match (format.as_str(), arch.as_str()) {
            ("pe", "x86_64") => CallingConvention::Win64Fastcall,
            ("pe", "x86") => CallingConvention::Stdcall,
            ("elf", "x86_64") | ("mach-o", "x86_64") => CallingConvention::SysV64,
            _ => CallingConvention::Unknown,
        }
    }

    fn sdb_type_name(ty: &canary_ir::types::IrType) -> String {
        match ty {
            canary_ir::types::IrType::Void => "void".to_string(),
            canary_ir::types::IrType::Int {
                bit_width,
                signed: true,
            } => format!("int{}_t", bit_width),
            canary_ir::types::IrType::Int {
                bit_width,
                signed: false,
            } => format!("uint{}_t", bit_width),
            canary_ir::types::IrType::Pointer { .. } => "void*".to_string(),
            canary_ir::types::IrType::Float { bit_width } if *bit_width == 32 => {
                "float".to_string()
            }
            canary_ir::types::IrType::Float { .. } => "double".to_string(),
            _ => "uint64_t".to_string(),
        }
    }

    fn count_hlcf(
        node: &canary_analysis::structuring::HighLevelControlFlow,
        gotos: &mut usize,
        loops: &mut usize,
    ) {
        use canary_analysis::structuring::HighLevelControlFlow as H;
        match node {
            H::Goto(_) => *gotos += 1,
            H::While { body, .. } | H::DoWhile { body, .. } => {
                *loops += 1;
                Self::count_hlcf(body, gotos, loops);
            }
            H::If { then_branch, .. } => Self::count_hlcf(then_branch, gotos, loops),
            H::IfElse {
                then_branch,
                else_branch,
                ..
            } => {
                Self::count_hlcf(then_branch, gotos, loops);
                Self::count_hlcf(else_branch, gotos, loops);
            }
            H::Seq(items) => {
                for item in items {
                    Self::count_hlcf(item, gotos, loops);
                }
            }
            _ => {}
        }
    }

    fn run_phase2_pipeline(
        &self,
        func: &canary_ir::function::Function,
        mut cfg: canary_ir::cfg::ControlFlowGraph,
        mut sdb_func: canary_sdb::SdbFunction,
    ) -> Result<Option<Phase2Output>, EngineError> {
        let scheduled_order = crate::scheduler::schedule(
            &crate::scheduler::phase2_passes(),
            &[crate::scheduler::facts::CFG],
        )
        .map_err(|e| EngineError::Loader(format!("Phase 2 schedule invalid: {e}")))?;
        let mut executed_order = Vec::with_capacity(scheduled_order.len());

        let mut dom_info = None;
        let mut ssa = None;
        let mut vsa = None;
        let mut provenance = None;
        let mut stack_frame = None;
        let mut prim_types = None;
        let mut sig = None;
        let mut semantic = None;
        let mut hl_cf = None;
        let mut mlil = None;

        for pass in &scheduled_order {
            match *pass {
                "dominators" => {
                    let Some(computed) = canary_analysis::dominators::compute_dominators(&cfg)
                    else {
                        return Ok(None);
                    };
                    canary_analysis::dominators::mark_back_edges(&mut cfg, &computed);
                    dom_info = Some(computed);
                }
                "ssa" => {
                    let dom = dom_info.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed SSA before dominators".into(),
                        )
                    })?;
                    let ssa_builder = canary_analysis::SsaBuilder::new(&cfg, dom);
                    let mut built_ssa = ssa_builder.build_ssa();
                    canary_analysis::simplify_ssa(&mut built_ssa, &mut cfg);

                    let phi_count: usize = built_ssa.blocks.values().map(|b| b.phis.len()).sum();
                    let def_count: usize = built_ssa
                        .blocks
                        .values()
                        .map(|b| {
                            b.instrs
                                .iter()
                                .filter(|i| matches!(i, canary_ir::ssa::SsaInstr::Assign { .. }))
                                .count()
                        })
                        .sum();
                    sdb_func.ssa = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbSsaInfo {
                            block_count: built_ssa.blocks.len(),
                            phi_count,
                            def_count,
                        },
                        canary_sdb::ConfidenceVector::base(1.0),
                        canary_sdb::RecoveryOrigin::Exact,
                    ));
                    ssa = Some(built_ssa);
                }
                "vsa" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader("Phase 2 scheduler executed VSA before SSA".into())
                    })?;
                    let analyzed_vsa = canary_analysis::vsa::analyze_vsa(ssa_ref, &cfg);
                    let pointer_count = analyzed_vsa
                        .values
                        .values()
                        .filter(|v| matches!(v, canary_analysis::vsa::ValueSet::PtrOffset { .. }))
                        .count();
                    let unresolved_count = analyzed_vsa
                        .values
                        .values()
                        .filter(|v| matches!(v, canary_analysis::vsa::ValueSet::Top))
                        .count();
                    sdb_func.vsa = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbVsaInfo {
                            pointer_count,
                            unresolved_count,
                        },
                        canary_sdb::ConfidenceVector::base(0.7),
                        canary_sdb::RecoveryOrigin::Inference,
                    ));

                    for target in
                        canary_analysis::vsa::resolve_indirect_calls(ssa_ref, &cfg, &analyzed_vsa)
                    {
                        sdb_func
                            .inferred_call_targets
                            .push(canary_sdb::SdbEntry::new(
                                canary_sdb::InferredCallTarget {
                                    call_site: target.call_site,
                                    targets: target.targets,
                                },
                                canary_sdb::ConfidenceVector::base(0.8),
                                canary_sdb::RecoveryOrigin::Inference,
                            ));
                    }
                    vsa = Some(analyzed_vsa);
                }
                "pointer_provenance" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed provenance before SSA".into(),
                        )
                    })?;
                    let computed_provenance =
                        canary_analysis::provenance::compute_provenance(ssa_ref);
                    let parameter_pointer_count = computed_provenance
                        .values()
                        .filter(|ptr| {
                            matches!(
                                ptr.base,
                                canary_analysis::provenance::ProvBase::Parameter(_)
                            )
                        })
                        .count();
                    let stack_pointer_count = computed_provenance
                        .values()
                        .filter(|ptr| {
                            matches!(
                                ptr.base,
                                canary_analysis::provenance::ProvBase::StackFrame(_)
                            )
                        })
                        .count();
                    let global_pointer_count = computed_provenance
                        .values()
                        .filter(|ptr| {
                            matches!(ptr.base, canary_analysis::provenance::ProvBase::Global(_))
                        })
                        .count();
                    sdb_func.pointer_provenance = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbPointerProvenanceInfo {
                            tracked_pointer_count: computed_provenance.len(),
                            parameter_pointer_count,
                            stack_pointer_count,
                            global_pointer_count,
                        },
                        canary_sdb::ConfidenceVector::base(0.75),
                        canary_sdb::RecoveryOrigin::Inference,
                    ));
                    provenance = Some(computed_provenance);
                }
                "stack_vars" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed stack vars before SSA".into(),
                        )
                    })?;
                    let vsa_ref = vsa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed stack vars before VSA".into(),
                        )
                    })?;
                    let recovered_stack =
                        canary_analysis::stack_vars::recover_stack_vars(ssa_ref, vsa_ref);
                    let vars = recovered_stack
                        .vars
                        .iter()
                        .map(|var| canary_sdb::StackVarHint {
                            offset: var.offset,
                            size: var.size as usize,
                            name: Some(var.name.clone()),
                            ty_hint: None,
                        })
                        .collect();
                    sdb_func.stack_frame = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbStackFrame { vars },
                        canary_sdb::ConfidenceVector::base(0.85),
                        canary_sdb::RecoveryOrigin::Inference,
                    ));
                    stack_frame = Some(recovered_stack);
                }
                "primitive_types" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed primitive types before SSA".into(),
                        )
                    })?;
                    prim_types = Some(canary_typerecov::primitives::propagate_primitives(ssa_ref));
                }
                "calling_conventions" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed calling convention before SSA".into(),
                        )
                    })?;
                    let vsa_ref = vsa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed calling convention before VSA".into(),
                        )
                    })?;
                    let prim_types_ref = prim_types.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed calling convention before primitive types"
                                .into(),
                        )
                    })?;
                    let recovered_sig = canary_analysis::calling_conv::recover_call_signature(
                        ssa_ref,
                        vsa_ref,
                        self.default_calling_convention(),
                        Some(prim_types_ref),
                    );

                    let params = recovered_sig
                        .params
                        .iter()
                        .map(|param| {
                            let ty = match &param.location {
                                canary_analysis::calling_conv::ParamLocation::Register(r) => {
                                    let name = canary_ir::ssa::SsaName {
                                        reg: *r,
                                        version: 0,
                                    };
                                    prim_types_ref
                                        .get(&name)
                                        .map(Self::sdb_type_name)
                                        .unwrap_or_else(|| Self::sdb_type_name(&param.ty))
                                }
                                canary_analysis::calling_conv::ParamLocation::Stack { .. } => {
                                    Self::sdb_type_name(&param.ty)
                                }
                            };
                            canary_sdb::SdbParam {
                                name: Some(param.name.clone()),
                                ty,
                                location: format!("{:?}", param.location),
                            }
                        })
                        .collect();

                    let mut is_noreturn = false;
                    for block in func.cfg.blocks() {
                        for instr in &block.instrs {
                            if let canary_ir::llil::LlilInstr::Call { target, .. } = instr {
                                if let canary_ir::llil::LlilExpr::Const {
                                    value: call_addr, ..
                                } = target
                                {
                                    if self.workspace.sdb.facts.binary.imports.iter().any(|imp| {
                                        imp.value.address == *call_addr
                                            && matches!(
                                                imp.value.symbol_name.as_str(),
                                                "exit"
                                                    | "abort"
                                                    | "_exit"
                                                    | "ExitProcess"
                                                    | "terminate"
                                            )
                                    }) {
                                        is_noreturn = true;
                                    }
                                }
                            }
                        }
                    }

                    sdb_func.call_signature = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbCallSignature {
                            return_ty: Self::sdb_type_name(&recovered_sig.return_type),
                            params,
                            calling_conv: format!("{:?}", recovered_sig.convention),
                            is_variadic: recovered_sig.is_variadic,
                            noreturn: is_noreturn,
                        },
                        canary_sdb::ConfidenceVector::base(0.8),
                        canary_sdb::RecoveryOrigin::Inference,
                    ));
                    sig = Some(recovered_sig);
                }
                "semantic_lowering" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed semantic lowering before SSA".into(),
                        )
                    })?;
                    let semantic_ir = canary_analysis::semantic_lower::lower_to_semantic_with_sdb(
                        ssa_ref,
                        &self.workspace.sdb,
                    );
                    let semantic_transition_count: usize = semantic_ir
                        .blocks
                        .values()
                        .map(|block| block.instrs.len())
                        .sum();
                    sdb_func.semantic = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbSemanticInfo {
                            block_count: semantic_ir.blocks.len(),
                            transition_count: semantic_transition_count,
                        },
                        canary_sdb::ConfidenceVector::base(if semantic_transition_count == 0 {
                            1.0
                        } else {
                            0.7
                        }),
                        canary_sdb::RecoveryOrigin::Inference,
                    ));
                    semantic = Some(semantic_ir);
                }
                "structuring" => {
                    let dom = dom_info.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed structuring before dominators".into(),
                        )
                    })?;
                    let structured =
                        canary_analysis::structuring::structural_analysis(&cfg, &dom.tree, dom);
                    let mut goto_count = 0usize;
                    let mut loop_count = 0usize;
                    Self::count_hlcf(&structured, &mut goto_count, &mut loop_count);
                    let is_structured = goto_count == 0;
                    sdb_func.high_level_cfg = Some(canary_sdb::SdbEntry::new(
                        canary_sdb::SdbHlCf {
                            is_structured,
                            goto_count,
                            loop_count,
                        },
                        canary_sdb::ConfidenceVector::base(0.9),
                        canary_sdb::RecoveryOrigin::Pattern,
                    ));
                    hl_cf = Some(structured);
                }
                "mlil_lowering" => {
                    let ssa_ref = ssa.as_ref().ok_or_else(|| {
                        EngineError::Loader("Phase 2 scheduler executed MLIL before SSA".into())
                    })?;
                    let sig_ref = sig.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed MLIL before calling convention".into(),
                        )
                    })?;
                    let stack_frame_ref = stack_frame.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed MLIL before stack vars".into(),
                        )
                    })?;
                    let provenance_ref = provenance.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed MLIL before provenance".into(),
                        )
                    })?;
                    let semantic_ref = semantic.as_ref().ok_or_else(|| {
                        EngineError::Loader(
                            "Phase 2 scheduler executed MLIL before semantic IR".into(),
                        )
                    })?;
                    let lowered_mlil = canary_analysis::mlil_lower::lower_to_mlil(
                        ssa_ref,
                        &cfg,
                        sig_ref,
                        &stack_frame_ref.vars,
                        provenance_ref,
                        semantic_ref,
                        &scheduled_order,
                    );
                    sdb_func.mlil_complete = true;
                    mlil = Some(lowered_mlil);
                }
                other => {
                    return Err(EngineError::Loader(format!(
                        "Unknown Phase 2 scheduled pass: {other}"
                    )));
                }
            }
            executed_order.push(*pass);
        }

        assert_eq!(
            executed_order, scheduled_order,
            "executed Phase 2 pass order must exactly match scheduler output"
        );

        let hl_cf = hl_cf.ok_or_else(|| {
            EngineError::Loader("Phase 2 scheduler completed without high-level CFG".into())
        })?;
        let mlil = mlil.ok_or_else(|| {
            EngineError::Loader("Phase 2 scheduler completed without MLIL".into())
        })?;
        let semantic = semantic.ok_or_else(|| {
            EngineError::Loader("Phase 2 scheduler completed without semantic IR".into())
        })?;

        let sdb = &self.workspace.sdb;
        let symbol_resolver = |addr: u64| -> Option<String> {
            if let Some(imp) = sdb
                .facts
                .binary
                .imports
                .iter()
                .find(|i| i.value.address == addr)
            {
                return Some(imp.value.symbol_name.clone());
            }
            if let Some(f) = sdb.interpretations.functions.functions.get(&addr) {
                if let Some(name) = &f.value.name {
                    return Some(name.clone());
                }
                return Some(format!("sub_{:x}", addr));
            }
            None
        };
        let resolver_ref: &dyn Fn(u64) -> Option<String> = &symbol_resolver;

        let ctx = canary_emit::EmitContext {
            sdb_func: Some(&sdb_func),
            function: func,
            hl_cf: Some(&hl_cf),
            mlil: Some(&mlil),
            symbol_resolver: Some(resolver_ref),
            mode: canary_emit::EmitMode::Recovered,
        };

        use canary_emit::Emitter;
        let emitter = canary_emit::MlilCEmitter;
        let code = emitter.emit_function(&ctx)?;

        Ok(Some(Phase2Output {
            code,
            sdb_func,
            semantic,
            mlil,
        }))
    }

    /// Decompiles a function to pseudocode in the target language.

    pub fn decompile_function_stateless(
        &self,
        func_id: FunctionId,
        lang: &str,
    ) -> Result<(String, canary_sdb::SdbFunction), EngineError> {
        if !lang.eq_ignore_ascii_case("c") {
            return Err(EngineError::UnsupportedLanguage(lang.to_string()));
        }

        let func = self
            .workspace
            .functions
            .get(func_id)
            .ok_or(EngineError::FunctionNotFound(func_id))?;
        if !func.is_lifted {
            return Err(EngineError::Loader(
                "Function not lifted before stateless decompile!".to_string(),
            ));
        }

        let entry_addr = func.entry_addr;
        let sdb_func = self
            .workspace
            .sdb
            .interpretations
            .functions
            .functions
            .get(&entry_addr)
            .map(|e| e.value.clone())
            .unwrap_or_else(|| canary_sdb::SdbFunction {
                entry_addr,
                ..Default::default()
            });

        if let Some(result) = self.run_phase2_pipeline(func, func.cfg.clone(), sdb_func.clone())? {
            return Ok((result.code, result.sdb_func));
        }

        let ctx = canary_emit::EmitContext {
            sdb_func: None,
            function: func,
            hl_cf: None,
            mlil: None,
            symbol_resolver: None,
            mode: canary_emit::EmitMode::Raw,
        };
        let emitter = canary_emit::CEmitter;
        let code = canary_emit::Emitter::emit_function(&emitter, &ctx)?;
        Ok((code, sdb_func))
    }

    pub fn decompile_function(
        &mut self,
        func_id: FunctionId,
        lang: &str,
    ) -> Result<String, EngineError> {
        if !lang.eq_ignore_ascii_case("c") {
            return Err(EngineError::UnsupportedLanguage(lang.to_string()));
        }

        let is_lifted = {
            let func = self
                .workspace
                .functions
                .get(func_id)
                .ok_or(EngineError::FunctionNotFound(func_id))?;
            func.is_lifted
        };

        if !is_lifted {
            if self.cached_loaded.is_none() {
                let loaded = Binary::load(&self.workspace.binary_bytes)
                    .map_err(|e| EngineError::Loader(e.to_string()))?;
                self.cached_loaded = Some(loaded);
            }
            let loaded = self.cached_loaded.as_ref().unwrap().clone();
            self.lift_function(func_id, &loaded)?;
        }

        let entry_addr = self
            .workspace
            .functions
            .get(func_id)
            .ok_or(EngineError::FunctionNotFound(func_id))?
            .entry_addr;
        let sdb_func = self
            .workspace
            .sdb
            .interpretations
            .functions
            .functions
            .shift_remove(&entry_addr)
            .map(|e| e.value)
            .unwrap_or_else(|| canary_sdb::SdbFunction {
                entry_addr,
                ..Default::default()
            });

        let func = self
            .workspace
            .functions
            .get(func_id)
            .ok_or(EngineError::FunctionNotFound(func_id))?;

        if let Some(result) = self.run_phase2_pipeline(func, func.cfg.clone(), sdb_func.clone())? {
            let Phase2Output {
                code,
                sdb_func,
                semantic,
                mlil,
            } = result;
            if let Some(func) = self.workspace.functions.get_mut(func_id) {
                func.semantic = Some(semantic);
                func.mlil = Some(mlil);
            }
            self.workspace
                .sdb
                .interpretations
                .functions
                .functions
                .insert(
                    entry_addr,
                    canary_sdb::SdbEntry::new(
                        sdb_func,
                        canary_sdb::ConfidenceVector::base(1.0),
                        canary_sdb::RecoveryOrigin::Exact,
                    ),
                );
            return Ok(code);
        }

        let ctx = canary_emit::EmitContext {
            sdb_func: None,
            function: func,
            hl_cf: None,
            mlil: None,
            symbol_resolver: None,
            mode: canary_emit::EmitMode::Raw,
        };
        let emitter = canary_emit::CEmitter;
        let code = canary_emit::Emitter::emit_function(&emitter, &ctx)?;
        self.workspace
            .sdb
            .interpretations
            .functions
            .functions
            .insert(
                entry_addr,
                canary_sdb::SdbEntry::new(
                    sdb_func,
                    canary_sdb::ConfidenceVector::base(1.0),
                    canary_sdb::RecoveryOrigin::Exact,
                ),
            );
        Ok(code)
    }

    /// Whole-program analysis: recursively discovers all reachable functions,
    /// builds the global call graph, records cross-references, then runs
    /// type recovery across the entire program.
    ///
    /// This is the foundation of the "discover everything → analyze relationships
    /// → emit coherently" pipeline.
    pub fn analyze_whole_program(&mut self) -> Result<AnalysisSummary, EngineError> {
        use crate::discovery::{extract_callees, function_end_address};
        use crate::program_db::ProgramDatabase;
        use rayon::prelude::*;

        tracing::info!("Starting whole-program analysis...");

        // Use the lazy-cached binary to avoid re-parsing for every analysis pass
        if self.cached_loaded.is_none() {
            let loaded = Binary::load(&self.workspace.binary_bytes)
                .map_err(|e| EngineError::Loader(e.to_string()))?;
            self.cached_loaded = Some(loaded);
        }
        let loaded = self.cached_loaded.as_ref().unwrap();

        // Build import map: VA → symbol name
        // Note: PE imports have address = thunk VA (offset into IAT)
        let mut pdb = ProgramDatabase::new();
        for imp in &self.workspace.sdb.facts.binary.imports {
            if imp.value.address != 0 {
                pdb.import_map
                    .insert(imp.value.address, imp.value.symbol_name.clone());
            }
        }
        for exp in &self.workspace.sdb.facts.binary.exports {
            pdb.export_map
                .insert(exp.value.address, exp.value.symbol_name.clone());
        }

        // Build code section ranges for boundary checks (bypass executable flag for Byfron)
        let code_ranges: Vec<(u64, u64)> = loaded
            .sections
            .iter()
            .filter(|s| {
                !s.data.is_empty() && !s.name.starts_with(".rsrc") && !s.name.starts_with(".pdata")
            })
            .map(|s| (s.virtual_range.start, s.virtual_range.end))
            .collect();

        // Seed the discovery queue from all known entry points
        let seed_addresses: Vec<u64> = {
            let mut seeds = Vec::new();
            // 1. Binary entry point
            seeds.push(loaded.entry_point);
            // 2. Named functions from symbol table
            for nf in &self.workspace.sdb.facts.binary.named_functions {
                seeds.push(nf.value.address);
            }
            // 3. Exports
            for exp in &self.workspace.sdb.facts.binary.exports {
                seeds.push(exp.value.address);
            }
            // 4. Existing workspace functions (from prologue heuristics run before)
            for (_, func) in self.workspace.functions.iter() {
                seeds.push(func.entry_addr);
            }
            // 5. Linear Sweep for CFG Obfuscation bypass
            let swept = crate::linear_sweep::scan_for_prologues(&loaded);
            for addr in swept {
                seeds.push(addr);
            }
            seeds
        };

        for addr in seed_addresses {
            if addr != 0 && !pdb.is_import(addr) {
                pdb.enqueue(addr);
            }
        }

        let mut functions_failed = 0usize;
        let mut xrefs_recorded = 0usize;

        // BFS discovery loop using Bulk Synchronous Parallelism (BSP)
        while !pdb.pending.is_empty() {
            // Drain the current batch of pending addresses
            let batch: Vec<u64> = pdb
                .pending
                .drain(..std::cmp::min(1000, pdb.pending.len()))
                .collect();

            // Filter out addresses that shouldn't be lifted
            let targets: Vec<u64> = batch
                .into_iter()
                .filter(|&addr| {
                    !pdb.is_import(addr) && code_ranges.iter().any(|&(s, e)| addr >= s && addr < e)
                })
                .collect();

            // Parallel Lifting Phase
            let factory = self
                .lifter_factories
                .first()
                .ok_or_else(|| EngineError::UnsupportedArchitecture(loaded.arch_name.clone()))?;
            let factory_ref: &dyn ArchLifterFactory = factory.as_ref();
            let results: Vec<(
                u64,
                Result<
                    (
                        canary_ir::cfg::ControlFlowGraph,
                        Option<canary_ir::ssa::SsaFunction>,
                        canary_sdb::SdbFunction,
                    ),
                    EngineError,
                >,
            )> = targets
                .into_par_iter()
                .map_init(
                    || factory_ref.create(),
                    |lifter, addr| {
                        let section = match loaded.section_at(addr) {
                            Some(s) => s,
                            None => {
                                return (
                                    addr,
                                    Err(EngineError::Loader(format!(
                                        "Address {addr:#x} not inside any section"
                                    ))),
                                )
                            }
                        };

                        let mut cfg = match lifter.build_cfg(
                            &section.data,
                            section.virtual_range.start,
                            addr,
                        ) {
                            Ok(c) => c,
                            Err(e) => return (addr, Err(EngineError::Lift(e))),
                        };

                        let cfg_errors = canary_ir::cfg::cfg_validate(&cfg);
                        if !cfg_errors.is_empty() {
                            return (addr, Err(EngineError::CfgValidation(cfg_errors)));
                        }

                        let ssa_func = if let Some(dom_info) =
                            canary_analysis::dominators::compute_dominators(&cfg)
                        {
                            canary_analysis::dominators::mark_back_edges(&mut cfg, &dom_info);
                            let ssa_builder =
                                canary_analysis::ssa::SsaBuilder::new(&cfg, &dom_info);
                            let ssa = ssa_builder.build_ssa();
                            let ssa_errors =
                                canary_analysis::ssa::validate_ssa(&ssa, &cfg, &dom_info);
                            if ssa_errors.is_empty() {
                                Some(ssa)
                            } else {
                                None // Could return error, but let's just proceed without SSA
                            }
                        } else {
                            None
                        };

                        let mut sdb_func = canary_sdb::SdbFunction {
                            entry_addr: addr,
                            ..Default::default()
                        };

                        let mut cfg_blocks = Vec::new();
                        for bb in cfg.blocks() {
                            let mut successors = Vec::new();
                            for edge in &bb.successors {
                                if let Some(succ_bb) = cfg.block(edge.target) {
                                    let mapped_kind = match edge.kind {
                                        canary_ir::cfg::EdgeKind::Unconditional => {
                                            canary_sdb::EdgeKind::Unconditional
                                        }
                                        canary_ir::cfg::EdgeKind::True => {
                                            canary_sdb::EdgeKind::True
                                        }
                                        canary_ir::cfg::EdgeKind::False => {
                                            canary_sdb::EdgeKind::False
                                        }
                                        canary_ir::cfg::EdgeKind::Call => {
                                            canary_sdb::EdgeKind::Call
                                        }
                                        canary_ir::cfg::EdgeKind::Return => {
                                            canary_sdb::EdgeKind::Return
                                        }
                                        canary_ir::cfg::EdgeKind::Back => {
                                            canary_sdb::EdgeKind::Back
                                        }
                                    };
                                    successors.push((succ_bb.start_addr, mapped_kind));
                                }
                            }
                            cfg_blocks.push(canary_sdb::SdbBasicBlock {
                                address: bb.start_addr,
                                size: (bb.end_addr - bb.start_addr) as usize,
                                successors,
                            });
                        }
                        sdb_func.cfg_blocks = cfg_blocks;

                        (addr, Ok((cfg, ssa_func, sdb_func)))
                    },
                )
                .collect();

            // Sequential Integration Phase
            for (addr, result) in results {
                // Ensure function exists in workspace
                let func_id = if let Some(id) = self.workspace.function_at(addr) {
                    id
                } else {
                    let id = self.workspace.add_function(addr);
                    if let Some(name) = pdb.export_map.get(&addr) {
                        if let Some(func) = self.workspace.functions.get_mut(id) {
                            func.name = name.clone();
                        }
                    } else if let Some(nf) = self
                        .workspace
                        .sdb
                        .facts
                        .binary
                        .named_functions
                        .iter()
                        .find(|nf| nf.value.address == addr)
                    {
                        if let Some(func) = self.workspace.functions.get_mut(id) {
                            func.name = nf.value.name.clone();
                        }
                    }
                    id
                };

                match result {
                    Ok((cfg, ssa, sdb_func)) => {
                        pdb.mark_analyzed(addr);

                        let func = self.workspace.functions.get_mut(func_id).unwrap();
                        func.cfg = cfg;
                        func.ssa = ssa;
                        func.is_lifted = true;

                        self.workspace
                            .sdb
                            .interpretations
                            .functions
                            .functions
                            .insert(
                                addr,
                                canary_sdb::SdbEntry::new(
                                    sdb_func,
                                    canary_sdb::ConfidenceVector::base(1.0),
                                    canary_sdb::RecoveryOrigin::Exact,
                                ),
                            );

                        // Run discovery extractors
                        let disc = {
                            let f = self.workspace.functions.get(func_id).unwrap();
                            let start = f.entry_addr;
                            let end = function_end_address(&f.cfg);
                            extract_callees(
                                &f.cfg,
                                start,
                                end,
                                &pdb.import_map,
                                &pdb.analyzed,
                                &code_ranges,
                            )
                        };

                        for &(_, to) in &disc.call_xrefs {
                            self.workspace.sdb.facts.xrefs.callgraph.add_call(addr, to);
                        }
                        for &(_, to) in &disc.tail_call_xrefs {
                            self.workspace.sdb.facts.xrefs.callgraph.add_call(addr, to);
                        }

                        let sdb_xrefs = disc.to_sdb_xrefs();
                        xrefs_recorded += sdb_xrefs.len();
                        for xref in sdb_xrefs {
                            self.workspace
                                .sdb
                                .facts
                                .xrefs
                                .xrefs
                                .push(canary_sdb::SdbEntry::new(
                                    xref,
                                    canary_sdb::ConfidenceVector::base(1.0),
                                    canary_sdb::RecoveryOrigin::Exact,
                                ));
                        }

                        let call_xrefs_copy: Vec<_> =
                            disc.call_xrefs.iter().map(|&(f, t)| (f, t)).collect();
                        if let Some(sdb_func_entry) = self
                            .workspace
                            .sdb
                            .interpretations
                            .functions
                            .functions
                            .get_mut(&addr)
                        {
                            for (from, to) in &call_xrefs_copy {
                                sdb_func_entry.value.xrefs_out.push(canary_sdb::SdbXref {
                                    from_addr: *from,
                                    to_addr: *to,
                                    xref_kind: canary_sdb::XrefKind::Call,
                                });
                            }
                        }

                        for new_addr in disc.new_functions {
                            pdb.enqueue(new_addr);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to lift function at {:#x}: {}", addr, e);
                        pdb.mark_failed(addr);
                        functions_failed += 1;
                    }
                }
            }
        }

        let stats = pdb.stats();
        tracing::info!(
            "Discovery complete: {} discovered, {} analyzed, {} failed, {} xrefs",
            stats.discovered,
            stats.analyzed,
            stats.failed,
            xrefs_recorded
        );

        // Run global type recovery after all functions are analyzed
        tracing::info!("Running global type recovery...");
        let _ = self.recover_types();

        let imports_resolved = self
            .workspace
            .sdb
            .facts
            .binary
            .imports
            .iter()
            .filter(|i| i.value.address != 0)
            .count();

        let summary = AnalysisSummary {
            functions_discovered: stats.discovered,
            functions_analyzed: stats.analyzed,
            functions_failed,
            imports_resolved,
            xrefs_recorded,
            modules_identified: self.workspace.sdb.interpretations.modules.modules.len(),
        };

        tracing::info!(
            "Whole-program analysis complete: {} functions ({} analyzed, {} failed), {} call edges",
            summary.functions_discovered,
            summary.functions_analyzed,
            summary.functions_failed,
            self.workspace.sdb.facts.xrefs.callgraph.edge_count()
        );

        Ok(summary)
    }
}

/// Summary statistics from a whole-program analysis run.
#[derive(Debug, Clone)]
pub struct AnalysisSummary {
    pub functions_discovered: usize,
    pub functions_analyzed: usize,
    pub functions_failed: usize,
    pub imports_resolved: usize,
    pub xrefs_recorded: usize,
    pub modules_identified: usize,
}
