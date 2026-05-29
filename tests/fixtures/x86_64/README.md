# x86_64 Test Fixtures

These pre-compiled binaries are used for end-to-end integration testing of the Canary binary analysis pipeline.

## Fixture Sources
The source code is located in [`src/test_fixture_src.rs`](src/test_fixture_src.rs) and defines:
- `add_numbers`: basic linear control flow and arithmetic
- `simple_if`: diamond control flow with conditional jump
- `simple_loop`: back-edge loop control flow with accumulator variable

## Compilation Instructions
To ensure reproducibility, they are compiled using standard `rustc` with `panic=abort` and `no_std` setup.

### Linux ELF Shared Library (`test_fixture_linux.so`)
Compiled on Windows using rustup's target `x86_64-unknown-linux-gnu` with the built-in `rust-lld` linker:
```bash
rustc --target=x86_64-unknown-linux-gnu -C linker-flavor=ld.lld -C linker=rust-lld -C panic=abort --crate-type=cdylib -O -o test_fixture_linux.so src/test_fixture_src.rs
```

### Windows PE DLL (`test_fixture_windows.dll`)
Compiled using target `x86_64-pc-windows-msvc` and MSVC linker:
```bash
rustc --target=x86_64-pc-windows-msvc -C panic=abort --crate-type=cdylib -O -o test_fixture_windows.dll src/test_fixture_src.rs
```
