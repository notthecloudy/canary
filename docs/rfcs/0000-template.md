# RFC Template

Copy this file to `docs/rfcs/NNNN-your-feature.md` when proposing a new RFC.
Replace `NNNN` with the next sequential number from the RFC index.

---

# RFC NNNN: [Title]

**Status:** Draft
**Date:** YYYY-MM-DD
**Author(s):** [Name(s)]
**Tracking Issue:** (link to GitHub issue)

---

## Summary

One paragraph describing the proposed change and what it accomplishes.

## Motivation

Why is this change necessary? What problem does it solve? What use case does it enable?

Describe the current state of the world and what is missing.

## Detailed Design

A thorough technical description. This section must be specific enough that a contributor
could implement the feature from this RFC alone.

Include:
- API changes (with Rust signatures where applicable)
- IR schema changes
- Plugin API impact
- Effect on the core/plugin boundary (see ADR-0003)
- Dialect changes (if applicable)
- Performance implications

## Core / Plugin Boundary Impact

Does this change what the core owns vs. what plugins can access?

If yes, explain:
- What new capabilities are exposed to plugins (if any)
- What invariants must the core maintain
- How the validation layer enforces correctness

## Migration Path

If this is a breaking change:
- How are existing users/plugins migrated?
- What is the deprecation window?
- Are there automated migration tools?

## Drawbacks

What are the downsides of this approach?
- Increased complexity?
- Performance cost?
- API surface expansion?

## Alternatives

What other designs were considered and why were they rejected?

## Prior Art

References to similar designs in:
- Binary Ninja (MLIL/HLIL system)
- Ghidra (P-Code, decompiler passes)
- MLIR (dialect infrastructure)
- LLVM (pass manager, IR system)
- Academic papers

## Unresolved Questions

What open questions must be resolved before this RFC can be accepted?

List them explicitly — the RFC review process will address each one.

## Implementation Plan

After the RFC is accepted, outline:
- Which crates are modified
- Approximate order of implementation
- Whether a new crate is needed
- Test strategy
