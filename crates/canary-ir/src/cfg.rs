//! CFG
use crate::llil::LlilExpr;
use crate::llil::LlilInstr;
use indexmap::IndexMap;
use smallvec::SmallVec;

/// A stable identifier for a [`BasicBlock`] within a [`ControlFlowGraph`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub u32);

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Classifies the semantic meaning of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Unconditional jump or fall-through.
    Unconditional,
    /// Taken branch of a conditional.
    True,
    /// Not-taken branch of a conditional.
    False,
    /// Edge from a call instruction (to call target).
    Call,
    /// Edge from a call return.
    Return,
    /// Back edge forming a loop.
    Back,
}

/// A directed edge in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub source: BlockId,
    pub target: BlockId,
    pub kind: EdgeKind,
}

/// A basic block — a maximal straight-line sequence of LLIL instructions
/// with exactly one entry point and one or two exits.
///
/// Invariant: the last instruction is always a terminator ([`LlilInstr::is_terminator`]).
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Start address of the first instruction.
    pub start_addr: u64,
    /// End address (exclusive) — address after the last instruction.
    pub end_addr: u64,
    /// The LLIL instructions in this block, in order.
    pub instrs: Vec<LlilInstr>,
    /// Native instruction address for each LLIL instruction.
    pub instr_addrs: Vec<u64>,
    /// Successors (at most 2 for conditional branches).
    pub successors: SmallVec<[Edge; 2]>,
    /// Predecessors.
    pub predecessors: SmallVec<[BlockId; 4]>,
}

impl BasicBlock {
    /// Creates a new, empty basic block.
    pub fn new(id: BlockId, start_addr: u64) -> Self {
        Self {
            id,
            start_addr,
            end_addr: start_addr,
            instrs: Vec::new(),
            instr_addrs: Vec::new(),
            successors: SmallVec::new(),
            predecessors: SmallVec::new(),
        }
    }

    /// Returns the terminating instruction of this block, or `None`
    /// if the block has no instructions (invalid state).
    pub fn terminator(&self) -> Option<&LlilInstr> {
        self.instrs
            .last()
            .filter(|i: &&crate::llil::LlilInstr| i.is_terminator())
    }
}

/// A directed Control Flow Graph for a single function.
///
/// Use [`ControlFlowGraph::entry`] to get the entry block.
/// Iterate over all blocks with [`ControlFlowGraph::blocks`].
#[derive(Debug, Default, Clone)]
pub struct ControlFlowGraph {
    pub exprs: crate::arena::Arena<LlilExpr>,
    blocks: IndexMap<BlockId, BasicBlock>,
    entry: Option<BlockId>,
    next_id: u32,
}

impl ControlFlowGraph {
    /// Creates a new, empty CFG.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a new basic block at `start_addr` and returns its ID.
    pub fn alloc_block(&mut self, start_addr: u64) -> BlockId {
        let id = BlockId(self.next_id);
        self.next_id += 1;
        self.blocks.insert(id, BasicBlock::new(id, start_addr));
        id
    }

    /// Sets the entry block. Panics if `id` does not exist.
    pub fn set_entry(&mut self, id: BlockId) {
        assert!(self.blocks.contains_key(&id), "entry block id not found");
        self.entry = Some(id);
    }

    /// Returns the entry [`BlockId`], or `None` if not yet set.
    pub fn entry(&self) -> Option<BlockId> {
        self.entry
    }

    /// Returns a reference to a block by ID.
    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// Returns a mutable reference to a block by ID.
    pub fn block_mut(&mut self, id: BlockId) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&id)
    }

    /// Adds a directed edge between two blocks. Registers both successor and predecessor links.
    ///
    /// # Panics
    ///
    /// Panics if either block ID is not present in the CFG.
    pub fn add_edge(&mut self, source: BlockId, target: BlockId, kind: EdgeKind) {
        let source_block = self
            .blocks
            .get_mut(&source)
            .expect("source block not found");
        if source_block
            .successors
            .iter()
            .any(|e| e.target == target && e.kind == kind)
        {
            return;
        }
        let edge = Edge {
            source,
            target,
            kind,
        };
        source_block.successors.push(edge);

        let target_block = self
            .blocks
            .get_mut(&target)
            .expect("target block not found");
        if !target_block.predecessors.contains(&source) {
            target_block.predecessors.push(source);
        }
    }

    /// Iterates over all blocks in insertion order.
    pub fn blocks(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// Iterates mutably over all blocks in insertion order.
    pub fn blocks_mut(&mut self) -> impl Iterator<Item = &mut BasicBlock> {
        self.blocks.values_mut()
    }

    /// Returns the number of basic blocks in the CFG.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the total number of LLIL instructions across all blocks.
    pub fn instr_count(&self) -> usize {
        self.blocks.values().map(|b| b.instrs.len()).sum()
    }

    /// Splits a basic block at `split_addr` and returns the ID of the new block.
    ///
    /// # Panics
    ///
    /// Panics if `block_id` is not present, or if `split_addr` does not lie strictly
    /// inside the block's range, or if `split_addr` is not aligned to any instruction start.
    pub fn split_block(&mut self, block_id: BlockId, split_addr: u64) -> Result<BlockId, String> {
        // 1. Get split index and check bounds
        let (split_idx, old_end_addr) = {
            let block = self.blocks.get(&block_id).ok_or("block not found")?;
            if !(block.start_addr < split_addr && split_addr < block.end_addr) {
                return Err(format!("split_addr {split_addr:#x} must be strictly inside block {block_id} range [{:#x}, {:#x})", block.start_addr, block.end_addr));
            }

            let split_idx = block
                .instr_addrs
                .iter()
                .position(|&addr| addr == split_addr)
                .ok_or("split_addr must align with an instruction start address")?;

            (split_idx, block.end_addr)
        };

        // 2. Allocate the new block
        let new_id = self.alloc_block(split_addr);

        // 3. Move instructions and update block bounds
        let (instrs_to_move, addrs_to_move) = {
            let block = self.blocks.get_mut(&block_id).unwrap();
            block.end_addr = split_addr;
            let instrs = block.instrs.drain(split_idx..).collect::<Vec<_>>();
            let addrs = block.instr_addrs.drain(split_idx..).collect::<Vec<_>>();
            (instrs, addrs)
        };

        {
            let new_block = self.blocks.get_mut(&new_id).unwrap();
            new_block.end_addr = old_end_addr;
            new_block.instrs = instrs_to_move;
            new_block.instr_addrs = addrs_to_move;
        }

        // 4. Move successors and update their predecessor references
        let mut old_successors = {
            let block = self.blocks.get_mut(&block_id).unwrap();
            std::mem::take(&mut block.successors)
        };

        let mut targets_to_update = Vec::new();
        for edge in &mut old_successors {
            edge.source = new_id;
            targets_to_update.push(edge.target);
        }

        {
            let new_block = self.blocks.get_mut(&new_id).unwrap();
            new_block.successors = old_successors;
        }

        for target in targets_to_update {
            if let Some(target_block) = self.blocks.get_mut(&target) {
                for pred in &mut target_block.predecessors {
                    if *pred == block_id {
                        *pred = new_id;
                    }
                }
            }
        }

        // 5. Add fall-through edge from old block to new block
        self.add_edge(block_id, new_id, EdgeKind::Unconditional);

        Ok(new_id)
    }
}

/// Errors that can occur during CFG validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CfgError {
    #[error("CFG has no entry block")]
    NoEntry,
    #[error("Block {0} has no successors but is not a Return block")]
    NoSuccessors(BlockId),
    #[error("Block {0} has no predecessors and is not the entry block")]
    NoPredecessors(BlockId),
    #[error("Duplicate block start address {0:#x}")]
    DuplicateBlockAddress(u64),
}

/// Validates the structure of the given control flow graph.
pub fn cfg_validate(cfg: &ControlFlowGraph) -> Vec<CfgError> {
    let mut errors = Vec::new();

    let entry_id = match cfg.entry() {
        Some(id) => id,
        None => {
            errors.push(CfgError::NoEntry);
            return errors;
        }
    };

    let mut seen_addresses = indexmap::IndexSet::new();

    for block in cfg.blocks() {
        // Check for duplicate addresses
        if !seen_addresses.insert(block.start_addr) {
            errors.push(CfgError::DuplicateBlockAddress(block.start_addr));
        }

        // Check if block has predecessors, unless it's the entry block
        if block.id != entry_id && block.predecessors.is_empty() {
            errors.push(CfgError::NoPredecessors(block.id));
        }

        // Check if block has successors, unless its terminator is a Return
        let is_return = block
            .terminator()
            .is_some_and(|t| matches!(t, LlilInstr::Return { .. }));
        if !is_return && block.successors.is_empty() {
            errors.push(CfgError::NoSuccessors(block.id));
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_link() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.alloc_block(0x1000);
        let then = cfg.alloc_block(0x1010);
        let else_ = cfg.alloc_block(0x1020);

        cfg.set_entry(entry);
        cfg.add_edge(entry, then, EdgeKind::True);
        cfg.add_edge(entry, else_, EdgeKind::False);

        assert_eq!(cfg.block_count(), 3);
        assert_eq!(cfg.block(entry).unwrap().successors.len(), 2);
        assert_eq!(cfg.block(then).unwrap().predecessors.len(), 1);
    }
}
