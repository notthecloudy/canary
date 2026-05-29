use canary_ir::cfg::{BlockId, ControlFlowGraph};
use canary_ir::llil::{LlilOp, LlilUnOp};
use canary_ir::ssa::{SsaDest, SsaExpr, SsaFunction, SsaInstr, SsaName};
use indexmap::{IndexMap, IndexSet};
use std::collections::VecDeque;

/// Runs simplification passes iteratively until a fixed point is reached.
pub fn simplify_ssa(ssa: &mut SsaFunction, cfg: &mut ControlFlowGraph) {
    let mut changed = true;
    while changed {
        changed = false;
        if fold_constants(ssa) {
            changed = true;
        }
        if propagate_copies_and_constants(ssa) {
            changed = true;
        }
        if eliminate_dead_code(ssa) {
            changed = true;
        }
        if simplify_branches(ssa, cfg) {
            changed = true;
        }
        if remove_unreachable_blocks(ssa, cfg) {
            changed = true;
        }
    }
}

/// Constant Folding: Evaluates deterministic unary/binary operations on constants.
fn fold_constants(ssa: &mut SsaFunction) -> bool {
    let mut changed = false;

    fn fold_expr(expr: &mut SsaExpr, changed: &mut bool) {
        // recursively fold subexpressions first
        match expr {
            SsaExpr::Load { addr, .. } => fold_expr(addr, changed),
            SsaExpr::BinOp { lhs, rhs, .. } => {
                fold_expr(lhs, changed);
                fold_expr(rhs, changed);
            }
            SsaExpr::UnOp { operand, .. } => fold_expr(operand, changed),
            SsaExpr::Sx { expr: e, .. } | SsaExpr::Zx { expr: e, .. } => fold_expr(e, changed),
            _ => {}
        }

        // now try to fold this expression
        let new_expr = match expr {
            SsaExpr::BinOp { op, lhs, rhs, size } => {
                if let (SsaExpr::Const { value: l_val, .. }, SsaExpr::Const { value: r_val, .. }) =
                    (&**lhs, &**rhs)
                {
                    let mask = if size.bits() == 64 {
                        u64::MAX
                    } else {
                        (1u64 << size.bits()) - 1
                    };
                    let l = l_val & mask;
                    let r = r_val & mask;
                    let result = match op {
                        LlilOp::Add => Some(l.wrapping_add(r)),
                        LlilOp::Sub => Some(l.wrapping_sub(r)),
                        LlilOp::Mul => Some(l.wrapping_mul(r)),
                        LlilOp::And => Some(l & r),
                        LlilOp::Or => Some(l | r),
                        LlilOp::Xor => Some(l ^ r),
                        LlilOp::Lsl => Some(l.wrapping_shl(r as u32)),
                        LlilOp::Lsr => Some(l.wrapping_shr(r as u32)),
                        LlilOp::CmpE => Some(if l == r { 1 } else { 0 }),
                        LlilOp::CmpNe => Some(if l != r { 1 } else { 0 }),
                        LlilOp::CmpUlt => Some(if l < r { 1 } else { 0 }),
                        LlilOp::CmpUle => Some(if l <= r { 1 } else { 0 }),
                        LlilOp::CmpUgt => Some(if l > r { 1 } else { 0 }),
                        LlilOp::CmpUge => Some(if l >= r { 1 } else { 0 }),
                        _ => None,
                    };
                    if let Some(res) = result {
                        Some(SsaExpr::Const {
                            value: res & mask,
                            size: *size,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            SsaExpr::UnOp { op, operand, size } => {
                if let SsaExpr::Const { value, .. } = &**operand {
                    let mask = if size.bits() == 64 {
                        u64::MAX
                    } else {
                        (1u64 << size.bits()) - 1
                    };
                    let v = value & mask;
                    let result = match op {
                        LlilUnOp::Not => Some(!v),
                        LlilUnOp::Neg => Some(0u64.wrapping_sub(v)),
                        _ => None,
                    };
                    if let Some(res) = result {
                        Some(SsaExpr::Const {
                            value: res & mask,
                            size: *size,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            SsaExpr::Zx {
                to_size, expr: e, ..
            } => {
                if let SsaExpr::Const { value, .. } = &**e {
                    let mask = if to_size.bits() == 64 {
                        u64::MAX
                    } else {
                        (1u64 << to_size.bits()) - 1
                    };
                    Some(SsaExpr::Const {
                        value: value & mask,
                        size: *to_size,
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(e) = new_expr {
            *expr = e;
            *changed = true;
        }
    }

    for block in ssa.blocks.values_mut() {
        for instr in &mut block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    if let SsaDest::Mem { addr, .. } = dest {
                        fold_expr(addr, &mut changed);
                    }
                    fold_expr(expr, &mut changed);
                }
                SsaInstr::Store { addr, value, .. } => {
                    fold_expr(addr, &mut changed);
                    fold_expr(value, &mut changed);
                }
                SsaInstr::If { cond, .. } => {
                    fold_expr(cond, &mut changed);
                }
                SsaInstr::Call { target, args, .. } => {
                    fold_expr(target, &mut changed);
                    for arg in args.iter_mut() {
                        fold_expr(arg, &mut changed);
                    }
                }
                SsaInstr::Return { value: Some(v), .. } => {
                    fold_expr(v, &mut changed);
                }
                SsaInstr::Intrinsic { inputs, .. } => {
                    for inp in inputs.iter_mut() {
                        fold_expr(inp, &mut changed);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    fold_expr(lhs, &mut changed);
                    fold_expr(rhs, &mut changed);
                }
                _ => {}
            }
        }
    }

    changed
}

/// Copy and Constant Propagation
fn propagate_copies_and_constants(ssa: &mut SsaFunction) -> bool {
    let mut replacements: IndexMap<SsaName, SsaExpr> = IndexMap::new();

    // 1. Find all `r0_v1 = Const(c)` or `r0_v1 = r1_v2`
    for block in ssa.blocks.values() {
        for instr in &block.instrs {
            if let SsaInstr::Assign {
                dest: SsaDest::Reg(reg),
                expr,
                ..
            } = instr
            {
                match expr {
                    SsaExpr::Const { .. } | SsaExpr::Reg { .. } => {
                        replacements.insert(*reg, expr.clone());
                    }
                    _ => {}
                }
            }
        }
    }

    if replacements.is_empty() {
        return false;
    }

    // Resolve transitive copies (e.g. A = B, B = C -> A = C)
    let mut transitive_replacements: IndexMap<SsaName, SsaExpr> = IndexMap::new();
    for (k, mut v) in replacements.into_iter() {
        while let SsaExpr::Reg { reg: next_reg, .. } = &v {
            if let Some(next_v) = transitive_replacements.get(next_reg) {
                v = next_v.clone();
            } else {
                break;
            }
        }
        transitive_replacements.insert(k, v);
    }

    let mut changed = false;

    fn replace_in_expr(expr: &mut SsaExpr, repls: &IndexMap<SsaName, SsaExpr>, changed: &mut bool) {
        match expr {
            SsaExpr::Reg { reg, size } => {
                if let Some(new_expr) = repls.get(reg) {
                    *expr = match new_expr {
                        SsaExpr::Const { value, .. } => SsaExpr::Const {
                            value: *value,
                            size: *size,
                        },
                        SsaExpr::Reg { reg: new_reg, .. } => SsaExpr::Reg {
                            reg: *new_reg,
                            size: *size,
                        },
                        _ => new_expr.clone(),
                    };
                    *changed = true;
                }
            }
            SsaExpr::Load { addr, .. } => replace_in_expr(addr, repls, changed),
            SsaExpr::BinOp { lhs, rhs, .. } => {
                replace_in_expr(lhs, repls, changed);
                replace_in_expr(rhs, repls, changed);
            }
            SsaExpr::UnOp { operand, .. } => replace_in_expr(operand, repls, changed),
            SsaExpr::Sx { expr: e, .. } | SsaExpr::Zx { expr: e, .. } => {
                replace_in_expr(e, repls, changed)
            }
            _ => {}
        }
    }

    for block in ssa.blocks.values_mut() {
        for phi in &mut block.phis {
            for op in &mut phi.operands {
                if let Some(new_expr) = transitive_replacements.get(&op.name) {
                    if let SsaExpr::Reg { reg, .. } = new_expr {
                        op.name = reg.clone();
                        changed = true;
                    }
                }
            }
        }

        for instr in &mut block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    if let SsaDest::Mem { addr, .. } = dest {
                        replace_in_expr(addr, &transitive_replacements, &mut changed);
                    }
                    replace_in_expr(expr, &transitive_replacements, &mut changed);
                }
                SsaInstr::Store { addr, value, .. } => {
                    replace_in_expr(addr, &transitive_replacements, &mut changed);
                    replace_in_expr(value, &transitive_replacements, &mut changed);
                }
                SsaInstr::If { cond, .. } => {
                    replace_in_expr(cond, &transitive_replacements, &mut changed);
                }
                SsaInstr::Call { target, args, .. } => {
                    replace_in_expr(target, &transitive_replacements, &mut changed);
                    for arg in args.iter_mut() {
                        replace_in_expr(arg, &transitive_replacements, &mut changed);
                    }
                }
                SsaInstr::Return { value: Some(v), .. } => {
                    replace_in_expr(v, &transitive_replacements, &mut changed);
                }
                SsaInstr::Intrinsic { inputs, .. } => {
                    for inp in inputs.iter_mut() {
                        replace_in_expr(inp, &transitive_replacements, &mut changed);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    replace_in_expr(lhs, &transitive_replacements, &mut changed);
                    replace_in_expr(rhs, &transitive_replacements, &mut changed);
                }
                _ => {}
            }
        }
    }

    changed
}

/// Dead Code Elimination
fn eliminate_dead_code(ssa: &mut SsaFunction) -> bool {
    let mut uses: IndexMap<SsaName, usize> = IndexMap::new();

    fn count_uses(expr: &SsaExpr, uses: &mut IndexMap<SsaName, usize>) {
        match expr {
            SsaExpr::Reg { reg, .. } => {
                *uses.entry(*reg).or_insert(0) += 1;
            }
            SsaExpr::Load { addr, .. } => count_uses(addr, uses),
            SsaExpr::BinOp { lhs, rhs, .. } => {
                count_uses(lhs, uses);
                count_uses(rhs, uses);
            }
            SsaExpr::UnOp { operand, .. } => count_uses(operand, uses),
            SsaExpr::Sx { expr: e, .. } | SsaExpr::Zx { expr: e, .. } => count_uses(e, uses),
            _ => {}
        }
    }

    for block in ssa.blocks.values() {
        for phi in &block.phis {
            for op in &phi.operands {
                *uses.entry(op.name).or_insert(0) += 1;
            }
        }
        for instr in &block.instrs {
            match instr {
                SsaInstr::Assign { dest, expr, .. } => {
                    if let SsaDest::Mem { addr, .. } = dest {
                        count_uses(addr, &mut uses);
                    }
                    count_uses(expr, &mut uses);
                }
                SsaInstr::Store { addr, value, .. } => {
                    count_uses(addr, &mut uses);
                    count_uses(value, &mut uses);
                }
                SsaInstr::If { cond, .. } => count_uses(cond, &mut uses),
                SsaInstr::Call { target, args, .. } => {
                    count_uses(target, &mut uses);
                    for arg in args {
                        count_uses(arg, &mut uses);
                    }
                }
                SsaInstr::Return { value: Some(v), .. } => count_uses(v, &mut uses),
                SsaInstr::Intrinsic { inputs, .. } => {
                    for inp in inputs {
                        count_uses(inp, &mut uses);
                    }
                }
                SsaInstr::SetFlags { lhs, rhs, .. } => {
                    count_uses(lhs, &mut uses);
                    count_uses(rhs, &mut uses);
                }
                _ => {}
            }
        }
    }

    let mut changed = false;

    for block in ssa.blocks.values_mut() {
        let mut new_instrs = Vec::with_capacity(block.instrs.len());
        for instr in block.instrs.drain(..) {
            if let SsaInstr::Assign {
                dest: SsaDest::Reg(reg),
                expr: _,
                ..
            } = &instr
            {
                if uses.get(reg).copied().unwrap_or(0) == 0 {
                    changed = true;
                    continue;
                }
            }
            new_instrs.push(instr);
        }
        block.instrs = new_instrs;

        let mut new_phis = Vec::with_capacity(block.phis.len());
        for phi in block.phis.drain(..) {
            if uses.get(&phi.result).copied().unwrap_or(0) > 0 {
                new_phis.push(phi);
            } else {
                changed = true;
            }
        }
        block.phis = new_phis;
    }

    changed
}

/// Simplify Branches
fn simplify_branches(ssa: &mut SsaFunction, cfg: &mut ControlFlowGraph) -> bool {
    let mut changed = false;

    for block in ssa.blocks.values_mut() {
        if let Some(SsaInstr::If {
            cond,
            true_target,
            false_target,
            confidence,
        }) = block.instrs.last().cloned()
        {
            if let SsaExpr::Const { value, .. } = cond {
                block.instrs.pop();
                let target = if value != 0 {
                    true_target
                } else {
                    false_target
                };
                block.instrs.push(SsaInstr::Goto { target, confidence });
                changed = true;

                // Update CFG edges
                let b_id = block.id;
                let to_remove_addr = if value != 0 {
                    false_target
                } else {
                    true_target
                };
                let to_remove_block = cfg
                    .blocks()
                    .find(|candidate| candidate.start_addr == to_remove_addr)
                    .map(|candidate| candidate.id);
                {
                    let cfg_block = cfg.block_mut(b_id).unwrap();
                    if let Some(to_remove_block) = to_remove_block {
                        cfg_block
                            .successors
                            .retain(|edge| edge.target != to_remove_block);
                    }
                    for succ in &mut cfg_block.successors {
                        succ.kind = canary_ir::cfg::EdgeKind::Unconditional;
                    }
                }
                if let Some(to_remove_block) = to_remove_block {
                    if let Some(removed_block) = cfg.block_mut(to_remove_block) {
                        removed_block.predecessors.retain(|pred| *pred != b_id);
                    }
                }
            }
        }
    }

    changed
}

/// Remove Unreachable Blocks
fn remove_unreachable_blocks(ssa: &mut SsaFunction, cfg: &mut ControlFlowGraph) -> bool {
    let entry = cfg.entry().unwrap();
    let mut reachable = IndexSet::new();
    let mut queue = VecDeque::new();

    reachable.insert(entry);
    queue.push_back(entry);

    while let Some(node) = queue.pop_front() {
        if let Some(block) = cfg.block(node) {
            for succ in &block.successors {
                if reachable.insert(succ.target) {
                    queue.push_back(succ.target);
                }
            }
        }
    }

    let all_blocks: Vec<BlockId> = ssa.blocks.keys().copied().collect();
    let mut removed = false;

    for &block_id in &all_blocks {
        if !reachable.contains(&block_id) {
            ssa.blocks.shift_remove(&block_id);
            // CFG removal logic could be here, but we will just fix up the phis of successors
            removed = true;
        }
    }

    if removed {
        // Fix phi nodes in reachable blocks to not refer to removed blocks
        for block in ssa.blocks.values_mut() {
            for phi in &mut block.phis {
                phi.operands.retain(|op| reachable.contains(&op.block));
            }
        }
    }

    removed
}
