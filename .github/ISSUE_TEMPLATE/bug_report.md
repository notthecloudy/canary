---
name: Bug Report
about: Report incorrect analysis output, panics, or crashes
title: "[BUG] "
labels: ["bug", "triage"]
assignees: []
---

## Describe the Bug

A clear and concise description of what the bug is.

## Input

<!-- If possible, provide a minimal binary or hex dump that reproduces the issue. -->
<!-- Mark as "Sensitive" if the binary cannot be publicly shared. -->

- Binary format: (PE / ELF / Mach-O)
- Architecture: (x86_64 / ARM64 / etc.)
- Canary version/commit:

## Steps to Reproduce

```bash
canary decompile path/to/binary --function <name>
```

## Expected Output

What you expected to see.

## Actual Output

What you actually saw (paste the CLI output or error).

## Backtrace

```
# paste panic output or stack trace here
```

## Additional Context

Any relevant information: compiler version of the input binary, optimization level, etc.
