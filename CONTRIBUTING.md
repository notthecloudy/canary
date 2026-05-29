# Contributing to Canary

Thank you for your interest in contributing to Canary. This is a long-horizon research engineering project — correctness, reproducibility, and architectural integrity are valued above speed.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Branch Strategy](#branch-strategy)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [RFC Process](#rfc-process)
- [Adding an Architecture](#adding-an-architecture)
- [Adding a Language Emitter](#adding-a-language-emitter)
- [Writing a Plugin](#writing-a-plugin)
- [Testing Standards](#testing-standards)
- [Performance](#performance)

---

## Code of Conduct

This project adheres to the [Canary Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold it. Report unacceptable behavior to `conduct@canary-project.dev`.

---

## Getting Started

### Prerequisites

```bash
# Rust (stable, 1.78+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Required tools
cargo install cargo-audit
cargo install cargo-nextest
```

### Build

```bash
git clone https://github.com/notthecloudy/canary.git
cd canary

# Build the entire workspace
cargo build --workspace

# Run all tests (uses nextest for parallel execution)
cargo nextest run --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Security audit
cargo audit
```

---

## Development Workflow

1. **Find or create an issue.** All non-trivial work starts with a GitHub issue. This aligns expectations before code is written.
2. **For significant changes, write an RFC first.** See [RFC Process](#rfc-process).
3. **Fork and branch** from `develop`, not `main`. Name your branch `feature/<short-description>`, `fix/<issue-number>`, or `docs/<topic>`.
4. **Write tests before or alongside code.** Canary's correctness guarantees depend on test coverage.
5. **Open a Draft PR early** to get feedback before a large amount of code is written.
6. **Request review** when ready. PRs require at least one approving review from a maintainer.

---

## Branch Strategy

| Branch | Purpose | Who Can Push |
|--------|---------|-------------|
| `main` | Stable, always green. Tagged releases. | Maintainers via PR only |
| `develop` | Integration. All features merge here first. | Maintainers via PR |
| `feature/*` | New features | Contributors via PR to `develop` |
| `fix/*` | Bug fixes | Contributors via PR to `develop` |
| `docs/*` | Documentation only | Contributors via PR to `develop` |
| `release/*` | Release preparation | Maintainers |
| `research/*` | Experimental — no stability guarantees | Open |

**Never commit directly to `main` or `develop`.**

---

## Pull Request Process

### Before Submitting

- [ ] All tests pass: `cargo nextest run --workspace`
- [ ] No clippy warnings: `cargo clippy --workspace -- -D warnings`
- [ ] Code is formatted: `cargo fmt --all`
- [ ] New public APIs have doc comments
- [ ] Changes to the IR, analysis, or plugin API include an updated ADR or RFC
- [ ] Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) format

### Commit Message Format

```
<type>(<scope>): <short description>

[optional body]

[optional footer: fixes #issue]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `ci`

Examples:
```
feat(canary-ir): add phi-node insertion for SSA construction
fix(canary-loader): handle PE files with 0-size sections
docs(architecture): add ADR-005 for arena-based IR storage
```

### Review Standards

Reviewers will check:

1. **Correctness** — Does the change preserve semantic invariants?
2. **Architecture fit** — Does it follow the Core/Plugin boundary?
3. **No `Rc<RefCell<>>` in IR paths** — Use arena IDs and passes
4. **No unsafe without justification** — Any `unsafe` block needs a `// SAFETY:` comment
5. **Test coverage** — New analysis passes need both unit and integration tests

---

## Code Style

Canary follows standard Rust idioms with these project-specific conventions:

### IR Nodes

Do **not** use:
```rust
// ❌ Wrong — introduces hidden shared mutation and reference cycles
let node = Rc::new(RefCell::new(IrNode { ... }));
```

Do use:
```rust
// ✅ Correct — arena-based, stable IDs
let id: NodeId = arena.alloc(IrNode { ... });
```

### Analysis Passes

Passes are **pure functions** over a read-only snapshot. They do not mutate core state directly:

```rust
// ✅ Correct pattern
pub fn analyze_dominators(cfg: &CfgSnapshot) -> DominatorTree { ... }

// Then the core commits the result:
core.commit(ProposedFact::Dominators(tree));
```

### Unsafe Code

Every `unsafe` block must have a `// SAFETY:` comment explaining the invariant being upheld:

```rust
// SAFETY: We verified bounds above; index is guaranteed < len.
unsafe { slice.get_unchecked(index) }
```

### Documentation

All public types and functions must have doc comments. Include `# Examples` sections for non-trivial APIs.

---

## RFC Process

Any change that affects:
- The IR schema or dialect system
- The Plugin API or capability model
- The core/plugin boundary
- Cross-crate public APIs
- The analysis pass scheduling model

...requires an RFC before implementation begins.

### RFC Workflow

1. Copy `docs/rfcs/0000-template.md` to `docs/rfcs/0000-your-feature.md`
2. Fill in the template
3. Open a PR to `develop` with just the RFC document
4. RFC is discussed in the PR and on the associated issue
5. A maintainer merges the RFC (accepted) or closes it (rejected/deferred)
6. Implementation PRs reference the RFC number

---

## Adding an Architecture

Architectures are implemented as crates implementing the `canary_arch::ArchLifter` trait.

```
canary-arch-x86/   ← example to follow
canary-arch-arm64/ ← your new crate
```

Required:
1. Create `crates/canary-arch-<name>/`
2. Implement `ArchLifter` from `canary-arch`
3. Map all instructions to LLIL operations
4. Add fixture binaries to `tests/fixtures/<arch>/`
5. Add integration test in `tests/integration/`
6. Document instruction coverage in the crate's README

---

## Adding a Language Emitter

Emitters are visitors over the Intent Graph, implementing `canary_emit::Emitter`.

```
canary-emit/
  src/
    c.rs     ← example
    cpp.rs
    rust.rs  ← your new emitter
```

Required:
1. Implement `Emitter` for your language
2. Handle all Intent Graph node types (unknown nodes → lower-dialect fallback)
3. Include idiomatic output tests with known-good expected output
4. Document dialect coverage: which dialects does your emitter consume?

---

## Writing a Plugin

See [`docs/guides/writing-a-plugin.md`](./docs/guides/writing-a-plugin.md) for the full guide.

Quick summary:
- Plugins are compiled to WebAssembly (`wasm32-wasi` target)
- Use the `canary-plugin-api` crate for the interface
- Declare capabilities in `plugin.toml`
- Return typed proposals — never mutate IR directly
- Test with `canary plugin test <path-to-plugin.wasm>`

---

## Testing Standards

### Unit Tests

Every analysis pass and IR transformation should have unit tests. Use small, hand-crafted IR fragments — not full binary fixtures.

### Integration Tests

Integration tests live in `tests/integration/` and run against compiled fixture binaries in `tests/fixtures/`. These verify the full pipeline from binary to emitted source.

### Correctness Tests

For decompilation correctness: compile known C/C++ source with a fixed compiler version and flags, decompile with Canary, and verify that the CFG structure and data-flow properties match expected properties (not necessarily identical syntax).

### Fuzzing

Fuzzing targets live in `fuzz/`. Run with:

```bash
cargo fuzz run fuzz_loader
cargo fuzz run fuzz_lifter
```

---

## Performance

Canary targets analysis throughput competitive with Binary Ninja on large binaries (1M+ instruction functions). If you introduce a new analysis pass:

1. Run it through `cargo flamegraph` on a large fixture
2. Include benchmark results in the PR description if the pass is on a hot path
3. Avoid allocating in tight loops — reuse analysis scratch space
4. Prefer iteration over IR IDs to iteration over node references

---

## Questions?

- Open a [GitHub Discussion](https://github.com/notthecloudy/canary/discussions)
- Join the [Discord server](https://discord.gg/canary)
- Read the [Architecture Decision Records](./docs/architecture/)

Thank you for helping build the future of binary analysis.
