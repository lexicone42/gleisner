# Gleisner Forge

Incremental Nickel package evaluator for [minimal.dev](https://minimal.dev) build specs. Evaluates the full package dependency graph in topological order, producing content-addressed results that feed into gleisner's sandbox and attestation pipeline.

**Related documents:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- overall gleisner architecture
- [SECURITY.md](SECURITY.md) -- attestation and verification design

---

## Table of Contents

1. [Why Nickel Packages](#why-nickel-packages)
2. [How It Works](#how-it-works)
3. [The minimal.dev Integration](#the-minimaldev-integration)
4. [Content-Addressed Evaluation](#content-addressed-evaluation)
5. [Performance](#performance)
6. [Crate Structure](#crate-structure)
7. [Usage](#usage)

---

## Why Nickel Packages

minimal.dev uses [Nickel](https://nickel-lang.org) as its package definition language. Each package is a `build.ncl` file that declares sources, dependencies, build commands, required capabilities, and typed outputs -- all within Nickel's contract system.

The key insight driving this integration: **minimal.dev's Nickel specs are already a declarative security policy.** They just weren't designed as one.

Every `Source.sha256` is a supply chain integrity anchor. Every `needs = { dns }` is a network capability grant. Every typed `OutputData` with `allow_executable | optional` defaulting to false is a file permission constraint. The gap between "what this build requires" and "what this build is allowed to do" is the enforcement layer -- and that's what gleisner provides.

## How It Works

### Evaluation Pipeline

```
EvalContext (created once)
+-- base CacheHub (Nickel stdlib loaded once, ~200 MB)
+-- stdlib stubs (minimal.ncl -> lightweight contracts, config.ncl -> target)
+-- package stubs (all 226 packages -> trivial records)

Per-package (in topological order):
1. clone_for_eval() -- shallow clone of base CacheHub
2. add_file(build.ncl) -- load the real package file from disk
3. Re-inject self-stub (breaks circular self-imports)
4. Inject flattened dep results via add_string() (virtual imports)
5. VmContext::prepare_eval_only -> VirtualMachine::eval_full_for_export
6. Serialize to JSON, store in content-addressed store
```

The Nickel stdlib is loaded once and cloned for each package. Without this sharing, each package would cost ~4 GB to evaluate independently.

### Virtual Import Injection

When a package does `import "../gcc/build.ncl"`, Nickel's import resolver looks up the normalized path in its `SourceCache`. We pre-register virtual entries (via `add_string()`) keyed by the same normalized paths. The resolver finds our pre-computed JSON-as-Nickel instead of loading the real file from disk.

This is standard Nickel API -- `CacheHub.sources.add_string(SourcePath::Path(...), content)` -- not a fork or hack. It's the same mechanism Nickel uses for its own stdlib.

### Transitive Dependency Flattening

Package results recursively embed their full dependency trees in `build_deps` and `runtime_deps`. Without flattening, a single gcc result is 136 MB of nested JSON because it includes all transitive dependencies. This compounds -- downstream packages that depend on gcc would embed the 136 MB, and their dependents would embed that, leading to OOM at ~17 GB.

`flatten_for_injection()` strips transitive deps before injection: each dependency entry that contains `build_deps` (indicating it's a package, not a Source or Local) is replaced with a `{ name, ty, _stub = true }` stub. With flattening, gcc is 1.7 MB and peak RSS stays under 510 MB for the full 226-package run.

## The minimal.dev Integration

### What Packages Declare

| Declaration | Example | What gleisner sees |
|---|---|---|
| `Source = { url, sha256, ... }` | Download spec with digest | SLSA material with integrity anchor |
| `import "../gcc/build.ncl"` | Dependency reference | Supply chain edge (attestable) |
| `cmd` / `cmds` | Build instructions | Auditable build steps |
| `needs = { dns, internet }` | Capability requirements | Network sandbox policy |
| `attrs.env_dir_mappings` | Filesystem mounts | Bind-mount and Landlock rules |
| `OutputLib`, `OutputBin`, `OutputData` | Typed output declarations | Artifact classification |
| `subsetOf(pkg, outputs)` | Partial dependency | Fine-grained dep tracking |

### Capability-Based Security

The `needs` abstraction is the most security-relevant part of the spec. Packages declare abstract capabilities rather than specific network rules:

```nickel
# This package needs DNS resolution but no other network access
needs = { dns }
```

This maps directly to sandbox enforcement:
- `needs = {}` -- full network deny via namespace isolation
- `needs = { dns }` -- nftables allowing UDP/TCP port 53 only
- `needs = { internet }` -- nftables allowing outbound connections

Most build systems treat network access as all-or-nothing. minimal.dev made it a typed, per-package declaration.

### Typed Outputs

```nickel
OutputLib = { ty = 'OutputLib, glob, allow_data | optional, .. }
OutputBin = { ty = 'OutputBin, glob, .. }
OutputData = { ty = 'OutputData, glob, allow_executable | optional, .. }
```

Outputs are classified, not just listed. `OutputData` defaults `allow_executable` to false -- data files cannot be executable unless explicitly opted in. This is a supply chain integrity constraint expressed as a type.

### Environment Composition

The `ComposedEnvironment` merges all packages' filesystem and capability requirements into a single sandbox configuration:

```rust
let mut env = ComposedEnvironment::new();
for (name, json) in &results {
    env.merge_package(name, json);
}
// env.dir_mappings -> sandbox bind mounts + Landlock rules
// env.needs.dns -> nftables DNS allow
// env.needs.internet -> nftables outbound policy
```

Conflicts (same path, different read_only flags) are resolved conservatively with warnings.

### Layers, Harnesses, and Automatic Environment Provisioning

minimal.dev's type system includes forward-looking constructs:

- **Harnesses** have `project_matchers` with `file_regexes` -- pattern-matching project structure to determine which build tools and test frameworks apply
- **Layers** compose packages + profiles + harnesses into complete environments
- **Profiles** inherit from other profiles and accept patches

This points toward automatic developer environment provisioning: given a project directory, determine the minimal set of tools, capabilities, and sandbox rules needed -- without anyone writing a policy file.

## Content-Addressed Evaluation

Every package evaluation result is stored by the SHA-256 of its canonical JSON (keys sorted deterministically). This provides:

- **Determinism**: same inputs, same hash, always
- **Change detection**: if a hash changes between runs, something in the supply chain moved
- **Attestation subjects**: the hash is the natural SLSA subject for provenance statements
- **Deduplication**: identical results (common for simple packages) share storage

This operates at the evaluation layer -- earlier in the supply chain than Nix's content-addressed store paths, which address build artifacts. You can detect supply chain changes before running any builds.

```
Source specs (sha256)     <-- verifiable claims
    |
Nickel evaluation         <-- content-addressed HERE (gleisner-forge)
    |
Build execution           <-- build system runs commands
    |
Build artifacts           <-- content-addressed in Nix store
```

## Performance

Upstream nickel-lang-core 0.17 (no fork dependency):

| Metric | Value |
|---|---|
| Packages | 226 (225 succeed, 1 known failure) |
| Wall time | ~38 seconds |
| Peak RSS | 510 MB |
| Store entries | 225 content-addressed JSON files |
| Stdlib load | Once (~200 MB), cloned per-package |

The single failure is cmake, whose `source_provenance.releases = 'TagBased {}` uses a Nickel enum variant with a payload argument that cannot be serialized to JSON (nickel-lang/nickel#1993).

## Crate Structure

```
crates/gleisner-forge/
+-- src/
|   +-- lib.rs          -- crate root, module declarations
|   +-- eval.rs         -- EvalContext, eval_package, flatten_for_injection
|   +-- dag.rs          -- PackageGraph, topological sort from import analysis
|   +-- store.rs        -- Content-addressed JSON store (SHA-256)
|   +-- compose.rs      -- ComposedEnvironment from merged package results
|   +-- error.rs        -- ForgeError type
+-- examples/
|   +-- eval_minimal.rs -- Full 226-package benchmark runner
+-- Cargo.toml
```

## Usage

### Full Package Evaluation

```bash
cargo run -p gleisner-forge --example eval_minimal --release -- \
    /path/to/minimal-pkgs \
    /path/to/minimal-std
```

### Single Package (via environment variable)

```bash
FORGE_PKG=gcc cargo run -p gleisner-forge --example eval_minimal --release -- \
    /path/to/minimal-pkgs \
    /path/to/minimal-std
```

### Programmatic

```rust
use gleisner_forge::eval::{EvalContext, eval_package};
use gleisner_forge::dag::PackageGraph;
use gleisner_forge::store::Store;

let graph = PackageGraph::from_directory(&pkgs_dir)?;
let order = graph.topological_order()?;
let store = Store::new(&store_dir)?;
let mut ctx = EvalContext::new(&[stdlib_dir.as_path()])?;
ctx.register_packages_dir(&pkgs_dir)?;

for node in &order {
    let dep_results = /* collect pre-evaluated deps */;
    let result = eval_package(&node.build_file, &dep_results, &store, &ctx)?;
    // result.json -- the fully evaluated package
    // result.store_ref.hash -- content-addressed key
}
```
