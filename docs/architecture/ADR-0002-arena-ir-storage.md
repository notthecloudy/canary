# ADR-0002: Arena-Based IR Storage

**Status:** Accepted
**Date:** 2026-05-21
**Author:** Canary Core Team

---

## Context

IR nodes are the most performance-critical data in the system. The design of their allocation and access patterns determines:
- Memory layout and cache performance during analysis
- Safety of concurrent reads
- Ease of incremental invalidation
- Absence of reference cycles

## Decision

**IR nodes are allocated in typed arenas and referenced by stable `NodeId<T>` values.**

The pattern explicitly forbidden is:
```rust
// ❌ FORBIDDEN — reference cycles, runtime borrow checking, cache-hostile
let node = Rc<RefCell<IrNode>>;
```

The mandated pattern is:
```rust
// ✅ REQUIRED — arena allocation, stable IDs
let id: NodeId<IrNode> = arena.alloc(IrNode { ... });
let node_ref: &IrNode = arena.get(id).unwrap();
```

## Rationale

### Cache Performance

An arena allocates nodes in a contiguous `Vec`. Traversing all nodes of a given type (e.g., iterating basic blocks during a dominator computation) is a sequential memory access — cache-friendly.

Pointer-chasing through individually heap-allocated `Box<Node>` nodes causes cache misses on every dereference.

### Safe Parallelism

An arena holding a completed set of IR nodes can be shared across threads as `&Arena<T>` — all threads get `&IrNode` references with the same lifetime. No `Arc<Mutex<>>` required for read-heavy phases.

Writes are serialized through the engine's commit/validate cycle.

### Stable Invalidation

`NodeId<T>` values are stable across graph rewrites. When an analysis pass is invalidated, the engine marks the relevant IDs as stale. Passes holding old `NodeId` values correctly get `None` from `arena.get(stale_id)` (generation counter mismatch in debug builds).

### No Reference Cycles

`Rc<RefCell<>>` graphs inevitably create cycles (a node's successor points back to a predecessor). With arenas, nodes store IDs, not pointers — cycles in the graph topology do not create memory cycles.

## Consequences

- IR traversal is less convenient (must pass `&arena` everywhere, cannot follow raw pointers)
- Nodes must not store `NodeId` values that outlive their arena
- Mutation requires mutable arena access — enforced by borrow checker

## Alternatives Considered

### `Rc<RefCell<IrNode>>`
- **Pro:** Convenient: `node.borrow().successor` reads naturally
- **Con:** Reference cycles cause memory leaks; runtime borrow panics in concurrent contexts; cache-hostile; no stable invalidation semantics

### Indices into a `Vec<Node>`
- **Pro:** Simple, fast
- **Con:** No generation checking (stale index silently accesses wrong node); no typed ID (can confuse block IDs with instruction IDs)

### ECS (Entity Component System)
- **Pro:** Highly cache-efficient for attribute-heavy workloads
- **Con:** Significant conceptual overhead; not a natural fit for graph-structured IR
- **Future:** ECS patterns may be adopted for specific hot paths in Phase 2+
