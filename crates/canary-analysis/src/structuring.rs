//! Control Flow Structuring
//!
//! Recovers high-level control flow constructs from a CFG using structural analysis.

use crate::dominators::{DominanceInfo, DominatorTree};
use canary_ir::cfg::{BlockId, ControlFlowGraph};
use indexmap::IndexSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HighLevelControlFlow {
    /// A sequence of statements or block
    Seq(Vec<HighLevelControlFlow>),
    /// A basic block execution
    Block(BlockId),
    /// If-Then
    If {
        cond: BlockId,
        then_branch: Box<HighLevelControlFlow>,
    },
    /// If-Then-Else
    IfElse {
        cond: BlockId,
        then_branch: Box<HighLevelControlFlow>,
        else_branch: Box<HighLevelControlFlow>,
    },
    /// While loop
    While {
        cond: BlockId,
        body: Box<HighLevelControlFlow>,
    },
    /// Do-While loop
    DoWhile {
        body: Box<HighLevelControlFlow>,
        cond: BlockId,
    },
    Return,
    Break,
    Continue,
    Goto(BlockId),
}

pub fn structural_analysis(
    cfg: &ControlFlowGraph,
    dom: &DominatorTree,
    dom_info: &DominanceInfo,
) -> HighLevelControlFlow {
    let mut visited = IndexSet::new();

    fn visit(
        block_id: BlockId,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        dom_info: &DominanceInfo,
        visited: &mut IndexSet<BlockId>,
    ) -> HighLevelControlFlow {
        if visited.contains(&block_id) {
            return HighLevelControlFlow::Goto(block_id);
        }
        visited.insert(block_id);

        let block = cfg.block(block_id).unwrap();
        let children = dom
            .children
            .get(&block_id)
            .map(|c| c.as_slice())
            .unwrap_or(&[]);

        let out_edges: Vec<_> = block.successors.iter().collect();

        match out_edges.len() {
            0 => HighLevelControlFlow::Block(block_id),
            1 => {
                let next = out_edges[0].target;
                if out_edges[0].kind == canary_ir::cfg::EdgeKind::Back {
                    HighLevelControlFlow::Seq(vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::Goto(next),
                    ])
                } else if children.contains(&next) {
                    HighLevelControlFlow::Seq(vec![
                        HighLevelControlFlow::Block(block_id),
                        visit(next, cfg, dom, dom_info, visited),
                    ])
                } else {
                    HighLevelControlFlow::Seq(vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::Goto(next),
                    ])
                }
            }
            2 => {
                let true_br_opt = out_edges
                    .iter()
                    .find(|e| matches!(e.kind, canary_ir::cfg::EdgeKind::True))
                    .map(|e| e.target);
                let false_br_opt = out_edges
                    .iter()
                    .find(|e| matches!(e.kind, canary_ir::cfg::EdgeKind::False))
                    .map(|e| e.target);

                // If it's not a standard conditional, fallback
                if true_br_opt.is_none() || false_br_opt.is_none() {
                    return HighLevelControlFlow::Seq(vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::Goto(out_edges[0].target),
                        HighLevelControlFlow::Goto(out_edges[1].target),
                    ]);
                }
                let true_br = true_br_opt.unwrap();
                let false_br = false_br_opt.unwrap();

                let mut is_while = false;
                let mut loop_body = true_br;
                let mut loop_exit = false_br;

                // Find any block that has a back-edge to `block_id`
                let mut back_edge_sources = Vec::new();
                for b in cfg.blocks() {
                    for e in &b.successors {
                        if e.kind == canary_ir::cfg::EdgeKind::Back && e.target == block_id {
                            back_edge_sources.push(b.id);
                        }
                    }
                }

                for src in back_edge_sources {
                    if dom_info.dominates(true_br, src) {
                        is_while = true;
                    } else if dom_info.dominates(false_br, src) {
                        is_while = true;
                        loop_body = false_br;
                        loop_exit = true_br;
                    }
                }

                if is_while {
                    let body_ast = visit(loop_body, cfg, dom, dom_info, visited);
                    let mut seq = vec![HighLevelControlFlow::While {
                        cond: block_id,
                        body: Box::new(body_ast),
                    }];
                    if !visited.contains(&loop_exit) {
                        seq.push(visit(loop_exit, cfg, dom, dom_info, visited));
                    }
                    return HighLevelControlFlow::Seq(seq);
                }

                let t_dom = children.contains(&true_br);
                let f_dom = children.contains(&false_br);

                if t_dom && f_dom {
                    let t_ast = visit(true_br, cfg, dom, dom_info, visited);
                    let f_ast = visit(false_br, cfg, dom, dom_info, visited);
                    HighLevelControlFlow::Seq(vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::IfElse {
                            cond: block_id,
                            then_branch: Box::new(t_ast),
                            else_branch: Box::new(f_ast),
                        },
                    ])
                } else if t_dom {
                    let t_ast = visit(true_br, cfg, dom, dom_info, visited);
                    let mut seq = vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::If {
                            cond: block_id,
                            then_branch: Box::new(t_ast),
                        },
                    ];
                    if !visited.contains(&false_br) {
                        seq.push(visit(false_br, cfg, dom, dom_info, visited));
                    }
                    HighLevelControlFlow::Seq(seq)
                } else if f_dom {
                    let f_ast = visit(false_br, cfg, dom, dom_info, visited);
                    let mut seq = vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::If {
                            cond: block_id,
                            then_branch: Box::new(f_ast),
                        },
                    ];
                    if !visited.contains(&true_br) {
                        seq.push(visit(true_br, cfg, dom, dom_info, visited));
                    }
                    HighLevelControlFlow::Seq(seq)
                } else {
                    HighLevelControlFlow::Seq(vec![
                        HighLevelControlFlow::Block(block_id),
                        HighLevelControlFlow::IfElse {
                            cond: block_id,
                            then_branch: Box::new(HighLevelControlFlow::Goto(true_br)),
                            else_branch: Box::new(HighLevelControlFlow::Goto(false_br)),
                        },
                    ])
                }
            }
            _ => HighLevelControlFlow::Block(block_id),
        }
    }

    if let Some(entry) = cfg.entry() {
        visit(entry, cfg, dom, dom_info, &mut visited)
    } else {
        HighLevelControlFlow::Seq(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dominators::{compute_dominators, mark_back_edges};
    use canary_ir::cfg::{ControlFlowGraph, EdgeKind};

    fn make_diamond_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let b0 = cfg.alloc_block(0);
        let b1 = cfg.alloc_block(0);
        let b2 = cfg.alloc_block(0);
        let b3 = cfg.alloc_block(0);

        cfg.set_entry(b0);
        cfg.add_edge(b0, b1, EdgeKind::True);
        cfg.add_edge(b0, b2, EdgeKind::False);
        cfg.add_edge(b1, b3, EdgeKind::Unconditional);
        cfg.add_edge(b2, b3, EdgeKind::Unconditional);
        cfg
    }

    #[test]
    fn test_if_then_else() {
        let mut cfg = make_diamond_cfg();
        let dom_info = compute_dominators(&cfg).unwrap();
        mark_back_edges(&mut cfg, &dom_info);

        let ast = structural_analysis(&cfg, &dom_info.tree, &dom_info);

        if let HighLevelControlFlow::Seq(items) = ast {
            assert_eq!(items.len(), 2);
            assert!(matches!(items[0], HighLevelControlFlow::Block(BlockId(0))));

            if let HighLevelControlFlow::IfElse { cond, .. } = &items[1] {
                assert_eq!(*cond, BlockId(0));
            } else {
                panic!("Expected IfElse");
            }
        } else {
            panic!("Expected Seq");
        }
    }

    #[test]
    fn test_while_loop() {
        let mut cfg = ControlFlowGraph::new();
        let b0 = cfg.alloc_block(0); // entry
        let b1 = cfg.alloc_block(0); // loop header (cond)
        let b2 = cfg.alloc_block(0); // loop body
        let b3 = cfg.alloc_block(0); // exit

        cfg.set_entry(b0);
        cfg.add_edge(b0, b1, EdgeKind::Unconditional);
        cfg.add_edge(b1, b2, EdgeKind::True);
        cfg.add_edge(b1, b3, EdgeKind::False);
        cfg.add_edge(b2, b1, EdgeKind::Unconditional); // back edge

        let dom_info = compute_dominators(&cfg).unwrap();
        mark_back_edges(&mut cfg, &dom_info);

        let ast = structural_analysis(&cfg, &dom_info.tree, &dom_info);

        if let HighLevelControlFlow::Seq(items) = ast {
            assert!(matches!(items[0], HighLevelControlFlow::Block(BlockId(0))));
            if let HighLevelControlFlow::Seq(inner) = &items[1] {
                if let HighLevelControlFlow::While { cond, .. } = &inner[0] {
                    assert_eq!(*cond, BlockId(1));
                    return;
                }
            }
            panic!("Expected While loop");
        } else {
            panic!("Expected Seq");
        }
    }
}
