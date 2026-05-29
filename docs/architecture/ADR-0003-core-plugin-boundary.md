# ADR-0003: Core/Plugin Boundary

**Status:** Accepted
**Date:** 2026-05-21

---

## Decision

**Core owns truth. Plugins own hypotheses.**

## Boundary Definition

### Locked in Core (No External Access)

- SSA construction and destruction
- Alias analysis / points-to analysis
- Memory versioning (heap vs. stack modeling)
- CFG validity and dominator invariants
- Interprocedural invalidation and dependency tracking
- Type fact propagation into global state
- Any pass that can change **semantic truth**

### Plugin Capabilities (Validated by Core)

| Capability | Description |
|-----------|-------------|
| `ReadIR` | Read-only snapshot access |
| `SuggestTypes` | Type hypotheses for variables |
| `SuggestNames` | Name candidates for symbols |
| `ProposeLocalRewrite` | Bounded subgraph rewrite proposals |
| `RegisterPatternMatcher` | Register an idiom recognizer |

## Rationale

If a plugin can make the engine **incorrect** by being wrong, it must not have direct write access.

A buggy plugin that corrupts the CFG dominator tree would silently produce invalid decompilation output. This would be undetectable without re-running the entire analysis. By requiring all writes to go through a validated commit path, the engine can maintain invariants regardless of plugin quality.

## Plugin Types

### 1. Read-Only Analysis Plugins
Consume IR snapshots, return facts. Examples: type guesses, naming suggestions, pattern matches.

### 2. Proposal Plugins
Return a rewrite candidate + justification. The core validates and commits if sound.

### 3. Restricted Transformer Plugins
May rewrite within a bounded region through a guarded API. Kept rare and require explicit capability grant.

## Validation Rules (Phase 1)

A proposal is rejected if it:
1. Alters CFG edges or dominator invariants
2. Removes or reorders instructions
3. Introduces conflicting type facts
4. Falls outside declared capabilities
5. Contains empty or malformed data
