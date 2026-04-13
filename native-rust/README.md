# HOLMES Native Rust Skeleton

This directory contains the first migration seam for moving the HOT path of HOLMES
from Python into Rust without breaking the current pipeline.

Current status:
- `holmes_native_rs.NativeBatchEngine` exists as a PyO3 extension skeleton.
- The Python engine can try to load it through `HOLMES_NATIVE_BACKEND=rust`.
- The Rust side currently returns `False` from `process_batch(...)`, which means
  Python remains the source of truth and behavior is unchanged.

Intended migration order:
1. Keep Python semantics authoritative.
2. Move batch ingestion and event normalization into Rust.
3. Move graph append / online index propagation into Rust.
4. Move graph-path candidate pruning and score refresh into Rust.

Build locally:

```bash
rustup toolchain install stable
pip install maturin
cd native-rust
maturin develop --release
```

Then run HOLMES with:

```bash
export HOLMES_NATIVE_BACKEND=rust
```

Current implemented native state:
- string interning from Python event payloads into compact `u32` ids
- batched event ingestion into a flat native graph state
- adjacency storage for data-flow edges
- online-index style mapper state with depth/fan-out bounded propagation scaffolding

Current non-goals:
- native graph queries are not authoritative yet
- Python still executes the actual HOLMES semantics after the native batch returns
