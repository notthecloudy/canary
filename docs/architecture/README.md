# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Canary project.

ADRs document significant architectural decisions: what was decided, why it was decided, and what alternatives were rejected.

## Format

Each ADR is a markdown file named `ADR-NNNN-short-title.md`.

ADRs are **immutable** once accepted. If a decision is reversed, a new ADR is written to supersede the old one.

## Status Values

- **Draft** — under discussion
- **Accepted** — approved and in effect
- **Superseded by ADR-NNNN** — replaced by a newer decision
- **Rejected** — considered and explicitly rejected

## Index

| # | Title | Status |
|---|-------|--------|
| [001](./ADR-0001-rust-core-language.md) | Rust as Core Language | Accepted |
| [002](./ADR-0002-arena-ir-storage.md) | Arena-Based IR Storage | Accepted |
| [003](./ADR-0003-core-plugin-boundary.md) | Core/Plugin Boundary | Accepted |
| [004](./ADR-0004-ai-advisory-pattern.md) | AI as Advisory Board | Accepted |
| [005](./ADR-0005-wasm-plugin-sandbox.md) | Wasm Plugin Sandbox | Accepted |
