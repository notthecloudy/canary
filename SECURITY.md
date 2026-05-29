# Security Policy

## Supported Versions

Canary is currently in pre-1.0 development. Security patches are applied to the latest commit on the `main` branch only.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ Yes |
| Prior releases | ❌ No |

---

## Security Scope

Canary processes **untrusted binary inputs** (PE, ELF, Mach-O files, plugin Wasm modules). The following security properties are design goals:

### Input Handling
- The loader must not panic, corrupt memory, or allocate unbounded resources when parsing malformed or adversarially crafted binary files.
- All inputs are treated as untrusted. Canary must handle truncated, overlapping, or invalid sections gracefully.

### Plugin Sandbox
- Wasm plugins run inside a Wasmtime sandbox with explicit capability grants.
- Plugins cannot access host memory outside of shared capability buffers.
- Plugins cannot execute arbitrary system calls.
- A buggy or malicious plugin cannot corrupt the core IR database.

### AI Integration
- AI advisory outputs are treated as untrusted annotations.
- The core validation layer rejects any AI suggestion that would alter control flow or semantic truth.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report vulnerabilities via email to: `security@canary-project.dev`

Include:
1. A description of the vulnerability and its impact
2. Steps to reproduce (a minimal test case or PoC binary if possible)
3. The version/commit hash you tested against
4. Your assessment of severity (CVSS score if possible)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Resolution timeline:** Depends on severity. Critical issues targeting <14 days. High <30 days.
- **Credit:** We will credit reporters in the release notes unless anonymity is requested.

### Scope

In scope:
- Memory unsafety in the core Rust codebase
- Plugin sandbox escapes
- Malformed binary → panic / OOM / arbitrary code execution in the host process
- Incorrect validation allowing a plugin to corrupt core IR state

Out of scope:
- Incorrect decompilation output (semantic bugs) — these are tracked as regular issues
- Denial of service via very large binaries (performance, not security)
- Issues requiring an attacker to already have arbitrary code execution on the host

---

## Dependency Management

Canary runs `cargo audit` in CI against the [RustSec Advisory Database](https://rustsec.org/). Any advisory that affects a Canary dependency triggers a mandatory patch.

To audit locally:
```bash
cargo audit
```

---

## Security Architecture Notes

### Why Wasm for Plugins

WebAssembly provides memory isolation between the host engine and plugins by construction. A plugin operating on a capability-scoped buffer cannot read or write outside that buffer. This is enforced by the Wasm linear memory model, not just by API convention.

### Why Rust for the Core

Rust's ownership model eliminates entire classes of memory safety bugs at compile time:
- No use-after-free in the IR graph
- No data races during parallel analysis passes
- No iterator invalidation during graph rewrite

The use of `unsafe` in Canary is audited and minimized. All `unsafe` blocks carry `// SAFETY:` justifications.
