# Gleisner Forge

Incremental Nickel package evaluator for [minimal.dev](https://minimal.dev) build specs. Evaluates the full package dependency graph in topological order, producing content-addressed results that feed into gleisner's sandbox and attestation pipeline.

**Related documents:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- overall gleisner architecture
- [SECURITY.md](SECURITY.md) -- attestation and verification design
- [LEAN-INTEGRATION-RESEARCH.md](LEAN-INTEGRATION-RESEARCH.md) -- proof-carrying SBOMs: Lean proofs and Z3 policy compliance in CycloneDX 1.6

---

## Table of Contents

1. [Why Nickel Packages](#why-nickel-packages)
2. [How It Works](#how-it-works)
3. [The minimal.dev Integration](#the-minimaldev-integration)
4. [Content-Addressed Evaluation](#content-addressed-evaluation)
5. [Proof Verification](#proof-verification)
6. [Performance](#performance)
7. [Crate Structure](#crate-structure)
8. [Usage](#usage)

---

## Why Nickel Packages

minimal.dev uses [Nickel](https://nickel-lang.org) as its package definition language. Each package is a `build.ncl` file that declares sources, dependencies, build commands, required capabilities, and typed outputs -- all within Nickel's contract system.

The key insight driving this integration: **minimal.dev's Nickel specs are already a declarative security policy.**

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

### Store-Ref Projection

Package results recursively embed their full dependency trees in `build_deps` and `runtime_deps`. Without intervention, a single gcc result is 136 MB of nested JSON because it includes all transitive dependencies. This compounds -- downstream packages that depend on gcc would embed the 136 MB, and their dependents would embed that, leading to OOM at ~17 GB.

`project_for_injection()` solves this by projecting each result down to only the fields downstream Nickel code actually accesses: `name`, `ty`, `outputs`, `target`, and `prebuilt`, plus a `_store_ref` back-pointer to the full result in the content-addressed store. A gcc result that was 136 MB full is ~200 bytes projected. Peak RSS stays under 510 MB for the full 226-package run.

The full result (with `cmd`, `build_deps`, `attrs`, etc.) remains available in the store for compose, SBOM generation, and attestation. `flatten_for_injection()` is still available as a utility for inspection use cases.

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

In addition, the bridge extracts domains from `build_deps` source URLs (e.g., `github.com` from a tarball download) and adds them to the sandbox's domain allowlist. This means a package's actual network surface is the union of its declared `needs` and its source download domains -- no more, no less. A `needs = { dns }` package that downloads from `storage.googleapis.com` gets DNS + that one domain, not the whole internet.

Most build systems treat network access as all-or-nothing. minimal.dev made it a typed, per-package declaration; gleisner derives the minimal domain set from the source of truth.

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
// env.dir_mappings      -> sandbox bind mounts + Landlock rules
// env.needs.dns         -> nftables DNS allow
// env.needs.internet    -> nftables outbound policy
// env.source_domains    -> per-domain nftables allowlist
// env.state_wirings     -> persistent cache directories
```

Conflicts (same path, different read_only flags) are resolved conservatively with warnings. Source domains are deduplicated across packages (first occurrence tracked for provenance).

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

## Proof Verification

Packages can declare `verified_properties` in their `attrs`, linking to formal proofs checked by an external proof kernel:

```nickel
attrs = {
  verified_properties = [
    {
      property = "zlib_roundtrip",
      description = "decompress(compress(data)) = data for all compression levels (RFC 1950)",
      proof_system = "lean4",
      kernel_version = "leanprover/lean4:v4.29.0-rc2",
      specification_hash = "sha256:d5d9988f...",
      proof_hash = "sha256:41d114c4...",
      proof_uri = "https://github.com/kim-em/lean-zip/blob/master/Zip/Spec/ZlibCorrect.lean",
    },
  ],
} | Attrs,
```

When `gleisner forge --verify` is passed, the forge:

1. Identifies packages with `verified_properties` in their evaluated output
2. Clones proof repositories from `proof_uri` fields
3. Runs `lake build` to type-check all proofs via the Lean 4 kernel
4. Hashes the compiled `.olean` artifact per property (SHA-256)
5. Records per-property results in the attestation output

### zlib: First Verified Package

[lean-zip](https://github.com/kim-em/lean-zip) provides the first real-world
test case -- three roundtrip properties verified end-to-end:

| Property | Lean Theorem | RFC |
|----------|-------------|-----|
| `zlib_roundtrip` | `zlib_decompressSingle_compress` | 1950 |
| `deflate_roundtrip` | `inflate_deflateRaw` | 1951 |
| `gzip_roundtrip` | `gzip_decompressSingle_compress` | 1952 |

The full 226-package pipeline reports: `zlib — 3/3 verified, 0 failed`.
Packages without proofs are reported as `unchecked` rather than failed.

### Verification Results

Results flow into the attestation as `VerifiedProperty` structs with:

| Field | Description |
|---|---|
| `property` | Property name (e.g., `zlib_roundtrip`) |
| `proof_system` | Proof system used (e.g., `lean4`) |
| `kernel_version` | Declared kernel version from the package |
| `specification_hash` | SHA-256 of the specification |
| `proof_hash` | Forge-computed SHA-256 of the compiled `.olean` artifact |
| `declared_proof_hash` | Original hash declared by the package author |
| `forge_kernel_version` | Actual Lean version used (read from `lean-toolchain`) |
| `verified_by_forge` | `true` (verified), `false` (failed), or `null` (unchecked) |

The `proof_hash` / `declared_proof_hash` separation lets the forge independently
verify what the package author claimed. A `VerificationSummary` reports aggregate
counts: total, verified, failed, and unchecked.

### Graceful Degradation

If the Lean binary is not available, verification is skipped with a warning. If `--strict-verify` is passed, any failure is a hard error. The schema supports arbitrary proof systems -- Lean 4 is the first.

## CycloneDX 1.6 SBOM

`gleisner forge --sbom` generates a proof-carrying SBOM using CycloneDX 1.6 **Declarations**. Two kinds of formal evidence are embedded:

### Lean Proof Claims

Each `VerifiedProperty` becomes an attestation claim with:
- Proof artifact hashes and URIs as evidence data
- Conformance score: 1.0 (forge-verified), 0.0 (unchecked/failed)
- Assessors: gleisner-forge (local) + proof kernel (third-party)

### Z3 Policy Compliance Claims

When policy compliance data is provided (from the `gleisner-lacerta` lattice module), each baseline check becomes a claim or counter-claim:
- **UNSAT** (compliant): claim with conformance 1.0 — Z3 proved subsumption
- **SAT** (non-compliant): counter-claim with conformance 0.0 + concrete witness as evidence

Standard baselines: SLSA Build L1 (materials), L2 (+ sandbox + audit), L3 (+ chain + zero denials), Gleisner Strict (all rules, tight limits).

The Z3 SMT Solver appears as a third-party assessor alongside proof kernels. Both are mechanically certain — conformance 1.0 means mathematical proof, not heuristic confidence.

See [LEAN-INTEGRATION-RESEARCH.md](LEAN-INTEGRATION-RESEARCH.md) for the full proposal on proof-carrying SBOMs.

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
|   +-- eval.rs         -- EvalContext, eval_package, project_for_injection
|   +-- dag.rs          -- PackageGraph, topological sort from import analysis
|   +-- store.rs        -- Content-addressed JSON store (SHA-256)
|   +-- compose.rs      -- ComposedEnvironment from merged package results
|   +-- orchestrate.rs  -- ForgeConfig, evaluate_packages (top-level entry point)
|   +-- bridge.rs       -- BridgeReport, compose_to_policy (forge→sandbox translation)
|   +-- attest.rs       -- ForgeAttestation, package metadata extraction, verification summary, PolicyComplianceProof
|   +-- sbom.rs         -- CycloneDX 1.6 SBOM generation with Declarations (proof claims + policy compliance)
|   +-- verify.rs       -- Lean 4 proof verification (via lake build)
|   +-- negotiate.rs    -- Capability negotiation between package needs and profile rules
|   +-- deploy.rs       -- Deployment helpers (store layout, output paths)
|   +-- error.rs        -- ForgeError type
+-- tests/
|   +-- integration.rs  -- Integration tests for orchestration pipeline
+-- Cargo.toml
```

## Usage

### CLI (`gleisner forge`)

The primary interface for forge evaluation:

```bash
# Evaluate all packages, write composed environment
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/

# Evaluate with proof verification (via lake build)
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/ --verify

# Dry run (JSON to stdout, no files written)
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/ --verify --dry-run

# Evaluate and run Claude Code in a composed sandbox
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/ --run

# Evaluate specific packages only
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/ --packages gcc,zlib

# Generate proof-carrying CycloneDX 1.6 SBOM with Declarations
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/ --verify --sbom
```

### Programmatic

```rust
use gleisner_forge::orchestrate::{ForgeConfig, evaluate_packages};
use gleisner_forge::bridge::compose_to_policy;

let config = ForgeConfig {
    pkgs_dir: "packages/".into(),
    stdlib_dir: "stdlib/".into(),
    store_dir: ".gleisner/forge-store".into(),
    filter: vec![],
};

let output = evaluate_packages(&config)?;
let report = compose_to_policy(&output.environment);
// report.filesystem -- sandbox bind-mount rules
// report.network -- DNS/internet policy
// report.credential_paths -- paths excluded from mounts
```

### Container Integration

With the `forge` feature on `gleisner-container`, sandboxes auto-configure from forge output:

```rust
use gleisner_container::ForgeComposition;

let composition = ForgeComposition::new(report, project_dir);
let sandbox = composition.sandbox()?;  // fully configured from package metadata

// Harness detection adds build tools + env vars automatically
let harness = detect_harness(&harness_specs, project_dir);
composition.apply_harness(&mut sandbox, &resolved_harness);

let output = sandbox.command("claude").run()?;
```

The task API also integrates with forge for agent-driven workflows:

```rust
use gleisner_container::task::TaskSandbox;

let sb = TaskSandbox::new(project_dir)
    .needs_tools(["cargo", "git"])
    .needs_network(["crates.io"])
    .build()?;

// After the run, narrow the config based on what was actually used
let report = task.narrow(&observed_capabilities);
eprintln!("{}", report.summary);  // "Unused capabilities: tools [git]"
```
