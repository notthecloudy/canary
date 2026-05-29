//! SSA construction pass.
//!
//! Implements the standard algorithm:
//! 1. Compute dominance frontiers from the dominator tree
//! 2. Insert φ-nodes at dominance frontier join points
//! 3. Rename variables using a dominator-tree walk

use canary_ir::cfg::{BlockId, ControlFlowGraph};
use canary_ir::llil::{LlilDest, LlilExpr, LlilInstr, Reg};
use canary_ir::ssa::{
    PhiNode, PhiOperand, SsaBlock, SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName,
};
use indexmap::IndexMap;
use smallvec::SmallVec;

use crate::dominators::DominanceInfo;

/// Builder for SSA form over a CFG.
pub struct SsaBuilder<'a> {
    cfg: &'a ControlFlowGraph,
    dom: &'a DominanceInfo,
}

impl<'a> SsaBuilder<'a> {
    pub fn new(cfg: &'a ControlFlowGraph, dom: &'a DominanceInfo) -> Self {
        Self { cfg, dom }
    }

    /// Computes the dominance frontiers for all blocks.
    pub fn dominance_frontiers(&self) -> IndexMap<BlockId, SmallVec<[BlockId; 4]>> {
        let mut df: IndexMap<BlockId, SmallVec<[BlockId; 4]>> = IndexMap::new();

        for block in self.cfg.blocks() {
            let preds = &block.predecessors;
            if preds.len() < 2 {
                continue;
            }
            for &pred in preds {
                let mut runner = pred;
                let block_idom = self.dom.tree.idom.get(&block.id).copied();
                while Some(runner) != block_idom {
                    df.entry(runner).or_default().push(block.id);
                    match self.dom.tree.idom.get(&runner).copied() {
                        Some(i) => runner = i,
                        None => break,
                    }
                }
            }
        }

        df
    }

    /// Places φ-nodes for `reg` at all dominance frontier blocks where `reg` is live.
    pub fn place_phi_nodes(
        &self,
        reg: Reg,
        def_blocks: &[BlockId],
        df: &IndexMap<BlockId, SmallVec<[BlockId; 4]>>,
    ) -> IndexMap<BlockId, PhiNode> {
        let mut placed: IndexMap<BlockId, PhiNode> = IndexMap::new();
        let mut work: Vec<BlockId> = def_blocks.to_vec();
        let mut in_worklist: indexmap::IndexSet<BlockId> = work.iter().copied().collect();

        while let Some(b) = work.pop() {
            if let Some(frontier) = df.get(&b) {
                for &y in frontier {
                    if placed.contains_key(&y) {
                        continue;
                    }
                    // Determine predecessor count for this join point
                    let pred_count = self.cfg.block(y).map(|b| b.predecessors.len()).unwrap_or(0);

                    let phi = PhiNode {
                        result: SsaName { reg, version: 0 }, // renamed in pass 2
                        operands: Vec::with_capacity(pred_count),
                    };
                    placed.insert(y, phi);

                    if !in_worklist.contains(&y) {
                        work.push(y);
                        in_worklist.insert(y);
                    }
                }
            }
        }

        placed
    }

    /// Finds all blocks where each register is defined.
    fn find_defs(&self) -> IndexMap<Reg, Vec<BlockId>> {
        let mut defs: IndexMap<Reg, Vec<BlockId>> = IndexMap::new();
        for block in self.cfg.blocks() {
            for instr in &block.instrs {
                match instr {
                    LlilInstr::Assign {
                        dest: LlilDest::Reg(reg),
                        ..
                    } => {
                        let list = defs.entry(*reg).or_default();
                        if list.last() != Some(&block.id) {
                            list.push(block.id);
                        }
                    }
                    LlilInstr::Call { ret: Some(reg), .. } => {
                        let list = defs.entry(*reg).or_default();
                        if list.last() != Some(&block.id) {
                            list.push(block.id);
                        }
                    }
                    LlilInstr::Intrinsic { outputs, .. } => {
                        for reg in outputs {
                            let list = defs.entry(*reg).or_default();
                            if list.last() != Some(&block.id) {
                                list.push(block.id);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        defs
    }

    /// Performs dominator-tree walk renaming.
    fn rename_walk(
        &self,
        block_id: BlockId,
        state: &mut RenameState,
        block_phis: &mut IndexMap<BlockId, Vec<PhiNode>>,
        ssa_instrs: &mut IndexMap<BlockId, Vec<SsaInstr>>,
    ) {
        let mut pushed = Vec::new();

        // 1. Rename phi-node definitions at block entry
        if let Some(phis) = block_phis.get_mut(&block_id) {
            for phi in phis.iter_mut() {
                phi.result = state.next_name(phi.result.reg);
                pushed.push(phi.result.reg);
            }
        }

        // 2. Rename instructions in the block
        let mut instrs = Vec::new();
        if let Some(block) = self.cfg.block(block_id) {
            for instr in &block.instrs {
                instrs.push(rename_instr(instr, state, &mut pushed, &self.cfg.exprs));
            }
        }
        ssa_instrs.insert(block_id, instrs);

        // 3. Fill in phi-node operands for successors
        if let Some(block) = self.cfg.block(block_id) {
            for edge in &block.successors {
                let succ_id = edge.target;
                if let Some(succ_phis) = block_phis.get_mut(&succ_id) {
                    for phi in succ_phis.iter_mut() {
                        let active = state.current_name(phi.result.reg);
                        phi.operands.push(PhiOperand {
                            block: block_id,
                            name: active,
                        });
                    }
                }
            }
        }

        // 4. Recurse on children in the dominator tree
        if let Some(children) = self.dom.tree.children.get(&block_id) {
            for &child in children {
                self.rename_walk(child, state, block_phis, ssa_instrs);
            }
        }

        // 5. Pop renamed definitions from active stacks
        for reg in pushed.iter().rev() {
            if let Some(stack) = state.stacks.get_mut(reg) {
                stack.pop();
            }
        }
    }

    /// Runs the complete SSA transformation on the CFG.
    pub fn build_ssa(&self) -> SsaFunction {
        let df = self.dominance_frontiers();
        let defs = self.find_defs();

        // Place phi nodes
        let mut block_phis: IndexMap<BlockId, Vec<PhiNode>> = IndexMap::new();
        for (&reg, def_blocks) in &defs {
            let placed = self.place_phi_nodes(reg, def_blocks, &df);
            for (block_id, phi) in placed {
                block_phis.entry(block_id).or_default().push(phi);
            }
        }

        // Sort phis inside each block by register ID for deterministic ordering
        for phis in block_phis.values_mut() {
            phis.sort_by_key(|phi| phi.result.reg.0);
        }

        let mut state = RenameState::default();
        let mut ssa_instrs: IndexMap<BlockId, Vec<SsaInstr>> = IndexMap::new();

        if let Some(entry_id) = self.cfg.entry() {
            self.rename_walk(entry_id, &mut state, &mut block_phis, &mut ssa_instrs);
        }

        let mut blocks = IndexMap::new();
        for block in self.cfg.blocks() {
            let id = block.id;
            let phis = block_phis.remove(&id).unwrap_or_default();
            let instrs = ssa_instrs.remove(&id).unwrap_or_default();
            blocks.insert(id, SsaBlock { id, phis, instrs });
        }

        SsaFunction {
            entry_addr: self
                .cfg
                .entry()
                .and_then(|id| self.cfg.block(id))
                .map(|b| b.start_addr)
                .unwrap_or(0),
            name: String::new(),
            blocks,
        }
    }
}

#[derive(Default)]
struct RenameState {
    counters: IndexMap<Reg, u32>,
    stacks: IndexMap<Reg, Vec<u32>>,
}

impl RenameState {
    fn current_name(&self, reg: Reg) -> SsaName {
        let version = self
            .stacks
            .get(&reg)
            .and_then(|s| s.last())
            .copied()
            .unwrap_or(0);
        SsaName { reg, version }
    }

    fn next_name(&mut self, reg: Reg) -> SsaName {
        let entry = self.counters.entry(reg).or_insert(0);
        *entry += 1;
        let version = *entry;
        self.stacks.entry(reg).or_default().push(version);
        SsaName { reg, version }
    }
}

fn rename_expr(
    expr: &LlilExpr,
    state: &RenameState,
    llil_exprs: &canary_ir::arena::Arena<LlilExpr>,
) -> SsaExpr {
    match expr {
        LlilExpr::Const { value, size } => SsaExpr::Const {
            value: *value,
            size: *size,
        },
        LlilExpr::Reg { reg, size } => SsaExpr::Reg {
            reg: state.current_name(*reg),
            size: *size,
        },
        LlilExpr::Load { addr, size } => SsaExpr::Load {
            addr: Box::new(rename_expr(
                llil_exprs.get(*addr).unwrap(),
                state,
                llil_exprs,
            )),
            size: *size,
        },
        LlilExpr::BinOp { op, lhs, rhs, size } => SsaExpr::BinOp {
            op: *op,
            lhs: Box::new(rename_expr(
                llil_exprs.get(*lhs).unwrap(),
                state,
                llil_exprs,
            )),
            rhs: Box::new(rename_expr(
                llil_exprs.get(*rhs).unwrap(),
                state,
                llil_exprs,
            )),
            size: *size,
        },
        LlilExpr::UnOp { op, operand, size } => SsaExpr::UnOp {
            op: *op,
            operand: Box::new(rename_expr(
                llil_exprs.get(*operand).unwrap(),
                state,
                llil_exprs,
            )),
            size: *size,
        },
        LlilExpr::Sx {
            from_size,
            to_size,
            expr,
        } => SsaExpr::Sx {
            from_size: *from_size,
            to_size: *to_size,
            expr: Box::new(rename_expr(
                llil_exprs.get(*expr).unwrap(),
                state,
                llil_exprs,
            )),
        },
        LlilExpr::Zx {
            from_size,
            to_size,
            expr,
        } => SsaExpr::Zx {
            from_size: *from_size,
            to_size: *to_size,
            expr: Box::new(rename_expr(
                llil_exprs.get(*expr).unwrap(),
                state,
                llil_exprs,
            )),
        },
        LlilExpr::LabelAddr { target } => SsaExpr::LabelAddr { target: *target },
        LlilExpr::Flag { flag } => SsaExpr::Flag { flag: *flag },
        LlilExpr::FlagCond { cond } => SsaExpr::FlagCond { cond: *cond },
    }
}

fn rename_instr(
    instr: &LlilInstr,
    state: &mut RenameState,
    pushed: &mut Vec<Reg>,
    llil_exprs: &canary_ir::arena::Arena<LlilExpr>,
) -> SsaInstr {
    match instr {
        LlilInstr::Assign {
            dest,
            expr,
            confidence,
        } => {
            let ssa_expr = rename_expr(expr, state, llil_exprs);
            let ssa_dest = match dest {
                LlilDest::Reg(reg) => {
                    let ssa_name = state.next_name(*reg);
                    pushed.push(*reg);
                    SsaDest::Reg(ssa_name)
                }
                LlilDest::Mem { addr, size } => SsaDest::Mem {
                    addr: rename_expr(addr, state, llil_exprs),
                    size: *size,
                },
            };
            SsaInstr::Assign {
                dest: ssa_dest,
                expr: ssa_expr,
                confidence: confidence.clone(),
            }
        }
        LlilInstr::Store {
            addr,
            value,
            size,
            confidence,
        } => SsaInstr::Store {
            addr: rename_expr(addr, state, llil_exprs),
            value: rename_expr(value, state, llil_exprs),
            size: *size,
            confidence: confidence.clone(),
        },
        LlilInstr::Goto { target, confidence } => SsaInstr::Goto {
            target: *target,
            confidence: confidence.clone(),
        },
        LlilInstr::If {
            cond,
            true_target,
            false_target,
            confidence,
        } => SsaInstr::If {
            cond: rename_expr(cond, state, llil_exprs),
            true_target: *true_target,
            false_target: *false_target,
            confidence: confidence.clone(),
        },
        LlilInstr::Call {
            target,
            args,
            ret,
            confidence,
        } => {
            let ssa_target = rename_expr(target, state, llil_exprs);
            let ssa_args = args
                .iter()
                .map(|arg| rename_expr(arg, state, llil_exprs))
                .collect();
            let ssa_ret = ret.map(|reg| {
                let ssa_name = state.next_name(reg);
                pushed.push(reg);
                ssa_name
            });
            SsaInstr::Call {
                target: ssa_target,
                args: ssa_args,
                ret: ssa_ret,
                confidence: confidence.clone(),
            }
        }
        LlilInstr::Return { value, confidence } => SsaInstr::Return {
            value: value
                .as_ref()
                .map(|val| rename_expr(val, state, llil_exprs)),
            confidence: confidence.clone(),
        },
        LlilInstr::Undef { bytes, confidence } => SsaInstr::Undef {
            bytes: bytes.clone(),
            confidence: confidence.clone(),
        },
        LlilInstr::Intrinsic {
            name,
            inputs,
            outputs,
            confidence,
        } => {
            let ssa_inputs = inputs
                .iter()
                .map(|i| rename_expr(i, state, llil_exprs))
                .collect();
            let ssa_outputs = outputs
                .iter()
                .map(|&reg| {
                    let ssa_name = state.next_name(reg);
                    pushed.push(reg);
                    ssa_name
                })
                .collect();
            SsaInstr::Intrinsic {
                name: name.clone(),
                inputs: ssa_inputs,
                outputs: ssa_outputs,
                confidence: confidence.clone(),
            }
        }
        LlilInstr::SetFlags {
            op,
            lhs,
            rhs,
            confidence,
        } => SsaInstr::SetFlags {
            op: *op,
            lhs: rename_expr(lhs, state, llil_exprs),
            rhs: rename_expr(rhs, state, llil_exprs),
            confidence: confidence.clone(),
        },
        LlilInstr::Trap { confidence } => SsaInstr::Trap {
            confidence: confidence.clone(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsaError {
    #[error("Variable {0} has multiple definitions")]
    MultipleDefs(SsaName),
    #[error("Variable {0} is used but not defined")]
    UndefinedUse(SsaName),
    #[error("Definition of {0} in block {1} does not dominate use in block {2}")]
    DefDoesNotDominateUse(SsaName, BlockId, BlockId),
    #[error("Phi node in block {0} has {1} operands, but block has {2} predecessors")]
    PhiOperandCountMismatch(BlockId, usize, usize),
}

pub fn validate_ssa(
    func: &SsaFunction,
    cfg: &ControlFlowGraph,
    dom: &DominanceInfo,
) -> Vec<SsaError> {
    let mut errors = Vec::new();
    let mut defs: IndexMap<SsaName, BlockId> = IndexMap::new();

    // 1. Collect all definitions and check uniqueness
    for block in func.blocks.values() {
        for phi in &block.phis {
            if defs.insert(phi.result, block.id).is_some() {
                errors.push(SsaError::MultipleDefs(phi.result));
            }
        }
        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign {
                    dest: SsaDest::Reg(reg),
                    ..
                } => {
                    if defs.insert(*reg, block.id).is_some() {
                        errors.push(SsaError::MultipleDefs(*reg));
                    }
                }
                SsaInstr::Call { ret: Some(reg), .. } => {
                    if defs.insert(*reg, block.id).is_some() {
                        errors.push(SsaError::MultipleDefs(*reg));
                    }
                }
                SsaInstr::Intrinsic { outputs, .. } => {
                    for reg in outputs {
                        if defs.insert(*reg, block.id).is_some() {
                            errors.push(SsaError::MultipleDefs(*reg));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 2. Validate predecessor operand count for each phi-node
    for block in func.blocks.values() {
        let pred_count = cfg
            .block(block.id)
            .map(|b| b.predecessors.len())
            .unwrap_or(0);
        for phi in &block.phis {
            if phi.operands.len() != pred_count {
                errors.push(SsaError::PhiOperandCountMismatch(
                    block.id,
                    phi.operands.len(),
                    pred_count,
                ));
            }
        }
    }

    // Helper closure to validate a use of SsaName
    let mut validate_use = |name: SsaName, use_block: BlockId, is_phi: Option<BlockId>| {
        if name.version == 0 {
            return;
        }

        match defs.get(&name) {
            Some(&def_block) => {
                let target_block = is_phi.unwrap_or(use_block);
                if !dom.dominates(def_block, target_block) {
                    errors.push(SsaError::DefDoesNotDominateUse(
                        name,
                        def_block,
                        target_block,
                    ));
                }
            }
            None => {
                errors.push(SsaError::UndefinedUse(name));
            }
        }
    };

    // Helper closure to validate all uses in an expression
    fn validate_expr_uses<F>(expr: &SsaExpr, use_block: BlockId, validate: &mut F)
    where
        F: FnMut(SsaName, BlockId, Option<BlockId>),
    {
        match expr {
            SsaExpr::Const { .. }
            | SsaExpr::LabelAddr { .. }
            | SsaExpr::Flag { .. }
            | SsaExpr::FlagCond { .. } => {}
            SsaExpr::Reg { reg, .. } => validate(*reg, use_block, None),
            SsaExpr::Load { addr, .. } => validate_expr_uses(addr, use_block, validate),
            SsaExpr::BinOp { lhs, rhs, .. } => {
                validate_expr_uses(lhs, use_block, validate);
                validate_expr_uses(rhs, use_block, validate);
            }
            SsaExpr::UnOp { operand, .. } => validate_expr_uses(operand, use_block, validate),
            SsaExpr::Sx { expr, .. } | SsaExpr::Zx { expr, .. } => {
                validate_expr_uses(expr, use_block, validate)
            }
        }
    }

    // 3. Validate uses in phi-nodes and instructions
    for block in func.blocks.values() {
        for phi in &block.phis {
            for op in &phi.operands {
                validate_use(op.name, block.id, Some(op.block));
            }
        }

        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    validate_expr_uses(expr, block.id, &mut validate_use);
                    if let SsaDest::Mem { addr, .. } = dest {
                        validate_expr_uses(addr, block.id, &mut validate_use);
                    }
                }
                SsaInstr::Store { addr, value, .. } => {
                    validate_expr_uses(addr, block.id, &mut validate_use);
                    validate_expr_uses(value, block.id, &mut validate_use);
                }
                SsaInstr::If { cond, .. } => {
                    validate_expr_uses(cond, block.id, &mut validate_use);
                }
                SsaInstr::Call { target, args, .. } => {
                    validate_expr_uses(target, block.id, &mut validate_use);
                    for arg in args {
                        validate_expr_uses(arg, block.id, &mut validate_use);
                    }
                }
                SsaInstr::Return { value, .. } => {
                    if let Some(v) = value {
                        validate_expr_uses(v, block.id, &mut validate_use);
                    }
                }
                SsaInstr::Intrinsic { inputs, .. } => {
                    for input in inputs {
                        validate_expr_uses(input, block.id, &mut validate_use);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    validate_expr_uses(lhs, block.id, &mut validate_use);
                    validate_expr_uses(rhs, block.id, &mut validate_use);
                }
                SsaInstr::Goto { .. } | SsaInstr::Undef { .. } | SsaInstr::Trap { .. } => {}
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dominators::compute_dominators;
    use canary_ir::cfg::{ControlFlowGraph, EdgeKind};
    use canary_ir::llil::{LlilDest, LlilExpr, LlilInstr, LlilOp, OperandSize, Reg};

    #[test]
    fn test_linear_rename() {
        let mut cfg = ControlFlowGraph::new();
        let b1 = cfg.alloc_block(0x1000);
        cfg.set_entry(b1);

        // r0 = 10
        // r1 = r0 + 5
        let r0 = Reg(0);
        let r1 = Reg(1);
        cfg.block_mut(b1).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r0),
                expr: LlilExpr::Const {
                    value: 10,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r1),
                expr: LlilExpr::BinOp {
                    op: LlilOp::Add,
                    lhs: cfg.exprs.alloc(LlilExpr::Reg {
                        reg: r0,
                        size: OperandSize::Bits64,
                    }),
                    rhs: cfg.exprs.alloc(LlilExpr::Const {
                        value: 5,
                        size: OperandSize::Bits64,
                    }),
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Return {
                confidence: Default::default(),
                value: None,
            },
        ];

        let dom = compute_dominators(&cfg).unwrap();
        let builder = SsaBuilder::new(&cfg, &dom);
        let ssa_func = builder.build_ssa();

        let ssa_errors = validate_ssa(&ssa_func, &cfg, &dom);
        assert!(
            ssa_errors.is_empty(),
            "SSA should be valid: {:?}",
            ssa_errors
        );

        let ssa_b1 = ssa_func.blocks.get(&b1).unwrap();
        assert_eq!(ssa_b1.phis.len(), 0);
        assert_eq!(ssa_b1.instrs.len(), 3);

        // First instr: r0_v1 = 10
        if let SsaInstr::Assign {
            dest: SsaDest::Reg(dest_name),
            expr: SsaExpr::Const { value: 10, .. },
            confidence: _,
        } = &ssa_b1.instrs[0]
        {
            assert_eq!(dest_name.reg, r0);
            assert_eq!(dest_name.version, 1);
        } else {
            panic!("Expected r0_v1 = 10, got: {}", ssa_b1.instrs[0]);
        }

        // Second instr: r1_v1 = r0_v1 + 5
        if let SsaInstr::Assign {
            dest: SsaDest::Reg(dest_name),
            expr: SsaExpr::BinOp { lhs, rhs: _, .. },
            confidence: _,
        } = &ssa_b1.instrs[1]
        {
            assert_eq!(dest_name.reg, r1);
            assert_eq!(dest_name.version, 1);
            if let SsaExpr::Reg { reg: use_name, .. } = &**lhs {
                assert_eq!(use_name.reg, r0);
                assert_eq!(use_name.version, 1);
            } else {
                panic!("Expected r0_v1 as lhs");
            }
        } else {
            panic!("Expected r1_v1 = r0_v1 + 5");
        }
    }

    #[test]
    fn test_diamond_rename() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.alloc_block(0x1000);
        let left = cfg.alloc_block(0x1010);
        let right = cfg.alloc_block(0x1020);
        let merge = cfg.alloc_block(0x1030);
        cfg.set_entry(entry);

        cfg.add_edge(entry, left, EdgeKind::True);
        cfg.add_edge(entry, right, EdgeKind::False);
        cfg.add_edge(left, merge, EdgeKind::Unconditional);
        cfg.add_edge(right, merge, EdgeKind::Unconditional);

        let r0 = Reg(0);

        // entry: if (cond) goto left else goto right
        cfg.block_mut(entry).unwrap().instrs = vec![LlilInstr::If {
            confidence: Default::default(),
            cond: LlilExpr::Const {
                value: 1,
                size: OperandSize::Bits8,
            },
            true_target: 0x1010,
            false_target: 0x1020,
        }];

        // left: r0 = 42; goto merge
        cfg.block_mut(left).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r0),
                expr: LlilExpr::Const {
                    value: 42,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Goto {
                confidence: Default::default(),
                target: 0x1030,
            },
        ];

        // right: r0 = 99; goto merge
        cfg.block_mut(right).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r0),
                expr: LlilExpr::Const {
                    value: 99,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Goto {
                confidence: Default::default(),
                target: 0x1030,
            },
        ];

        // merge: r1 = r0; ret
        let r1 = Reg(1);
        cfg.block_mut(merge).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r1),
                expr: LlilExpr::Reg {
                    reg: r0,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Return {
                confidence: Default::default(),
                value: None,
            },
        ];

        let dom = compute_dominators(&cfg).unwrap();
        let builder = SsaBuilder::new(&cfg, &dom);
        let ssa_func = builder.build_ssa();

        let ssa_errors = validate_ssa(&ssa_func, &cfg, &dom);
        assert!(
            ssa_errors.is_empty(),
            "SSA should be valid: {:?}",
            ssa_errors
        );

        // Check merge block phis: should have a phi for r0
        let ssa_merge = ssa_func.blocks.get(&merge).unwrap();
        assert_eq!(
            ssa_merge.phis.len(),
            1,
            "Expected 1 phi node in merge block"
        );
        let phi = &ssa_merge.phis[0];
        assert_eq!(phi.result.reg, r0);
        assert_eq!(phi.result.version, 1); // merge (v1) -> left (v2) -> right (v3)

        // operands should map left -> r0_v2, right -> r0_v3
        assert_eq!(phi.operands.len(), 2);
        let op_left = phi.operands.iter().find(|o| o.block == left).unwrap();
        let op_right = phi.operands.iter().find(|o| o.block == right).unwrap();
        assert_eq!(op_left.name.version, 2);
        assert_eq!(op_right.name.version, 3);

        // merge instruction: r1_v1 = r0_v1
        if let SsaInstr::Assign {
            dest: SsaDest::Reg(dest),
            expr: SsaExpr::Reg { reg: src, .. },
            confidence: _,
        } = &ssa_merge.instrs[0]
        {
            assert_eq!(dest.reg, r1);
            assert_eq!(dest.version, 1);
            assert_eq!(src.reg, r0);
            assert_eq!(src.version, 1);
        } else {
            panic!("Expected r1_v1 = r0_v1");
        }
    }

    #[test]
    fn test_loop_rename() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.alloc_block(0x1000);
        let header = cfg.alloc_block(0x1010);
        let body = cfg.alloc_block(0x1020);
        let exit = cfg.alloc_block(0x1030);
        cfg.set_entry(entry);

        cfg.add_edge(entry, header, EdgeKind::Unconditional);
        cfg.add_edge(header, body, EdgeKind::True);
        cfg.add_edge(header, exit, EdgeKind::False);
        cfg.add_edge(body, header, EdgeKind::Back);

        let r0 = Reg(0);

        // entry: r0 = 0; goto header
        cfg.block_mut(entry).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r0),
                expr: LlilExpr::Const {
                    value: 0,
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Goto {
                confidence: Default::default(),
                target: 0x1010,
            },
        ];

        // header: if (r0 < 10) goto body else goto exit
        cfg.block_mut(header).unwrap().instrs = vec![LlilInstr::If {
            confidence: Default::default(),
            cond: LlilExpr::BinOp {
                op: LlilOp::CmpSlt,
                lhs: cfg.exprs.alloc(LlilExpr::Reg {
                    reg: r0,
                    size: OperandSize::Bits64,
                }),
                rhs: cfg.exprs.alloc(LlilExpr::Const {
                    value: 10,
                    size: OperandSize::Bits64,
                }),
                size: OperandSize::Bits64,
            },
            true_target: 0x1020,
            false_target: 0x1030,
        }];

        // body: r0 = r0 + 1; goto header
        cfg.block_mut(body).unwrap().instrs = vec![
            LlilInstr::Assign {
                confidence: Default::default(),
                dest: LlilDest::Reg(r0),
                expr: LlilExpr::BinOp {
                    op: LlilOp::Add,
                    lhs: cfg.exprs.alloc(LlilExpr::Reg {
                        reg: r0,
                        size: OperandSize::Bits64,
                    }),
                    rhs: cfg.exprs.alloc(LlilExpr::Const {
                        value: 1,
                        size: OperandSize::Bits64,
                    }),
                    size: OperandSize::Bits64,
                },
            },
            LlilInstr::Goto {
                confidence: Default::default(),
                target: 0x1010,
            },
        ];

        // exit: ret
        cfg.block_mut(exit).unwrap().instrs = vec![LlilInstr::Return {
            confidence: Default::default(),
            value: None,
        }];

        let dom = compute_dominators(&cfg).unwrap();
        let builder = SsaBuilder::new(&cfg, &dom);
        let ssa_func = builder.build_ssa();

        let ssa_errors = validate_ssa(&ssa_func, &cfg, &dom);
        assert!(
            ssa_errors.is_empty(),
            "SSA should be valid: {:?}",
            ssa_errors
        );

        // header should have a phi node for r0
        let ssa_header = ssa_func.blocks.get(&header).unwrap();
        assert_eq!(ssa_header.phis.len(), 1);
        let phi = &ssa_header.phis[0];
        assert_eq!(phi.result.reg, r0);
        assert_eq!(phi.result.version, 2); // entry (v1) -> header phi (v2) -> body (v3)

        // operands should map entry -> r0_v1, body -> r0_v3
        assert_eq!(phi.operands.len(), 2);
        let op_entry = phi.operands.iter().find(|o| o.block == entry).unwrap();
        let op_body = phi.operands.iter().find(|o| o.block == body).unwrap();
        assert_eq!(op_entry.name.version, 1);
        assert_eq!(op_body.name.version, 3);
    }
}
