# gleisner-forge: Verified Package Attestation for minimal.dev

## What it does

gleisner-forge evaluates minimal.dev's Nickel package tree, produces
content-addressed attestation output, and optionally verifies formal
proofs declared in packages.

```
  build.ncl (226 packages)
        |
        v
 ┌──────────────┐    content-addressed
 │  forge eval   │──► evaluation store
 └──────┬───────┘    (377 entries, SHA-256 keyed)
        |
        v
 ┌──────────────┐    clone proof repo,
 │ forge verify  │──► run `lake build`,
 └──────┬───────┘    hash .olean artifacts
        |
        v
 ┌──────────────┐
 │ forge compose │──► resolved dependency graph
 └──────┬───────┘
        |
        v
 ┌──────────────┐    attestation JSON
 │ forge attest  │──► (packages, provenance,
 └──────────────┘    verification summary)
```

## Pipeline in numbers

| Metric | Value |
|--------|-------|
| Packages evaluated | 226 |
| Store entries | 377 (content-addressed) |
| Verified properties (zlib) | 3/3 |
| Proof system | Lean 4 (v4.29.0-rc2) |
| Attestation output | 162 KB JSON |

## What verified properties look like

A package declares `verified_properties` in its `attrs`:

```nickel
attrs = {
  verified_properties = [
    {
      property = "zlib_roundtrip",
      description = "decompress(compress(data)) = data (RFC 1950)",
      proof_system = "lean4",
      kernel_version = "leanprover/lean4:v4.29.0-rc2",
      proof_uri = "https://github.com/kim-em/lean-zip/...",
    },
  ],
}
```

The forge clones the proof repo, runs `lake build` (Lean's kernel
checks every proof obligation), hashes the resulting `.olean` artifact,
and records the result in the attestation:

```json
{
  "property": "zlib_roundtrip",
  "verified_by_forge": true,
  "proof_hash": "sha256:dbdae4b2...",
  "declared_proof_hash": "sha256:41d114c4...",
  "forge_kernel_version": "leanprover/lean4:v4.29.0-rc2"
}
```

- `proof_hash` — forge-computed SHA-256 of the compiled `.olean`
- `declared_proof_hash` — what the package author originally declared
- `forge_kernel_version` — actual Lean version used (from `lean-toolchain`)

## Diffing attestation runs

```
$ gleisner forge-diff before.json after.json

=== Forge Attestation Diff ===

Packages added (1):
  + lean4

Source changes (1):
  ~ zlib: abc123... → def456...

Verification changes (1):
  ~ zlib/zlib_roundtrip: unverified → verified
```

## How it fits together

```
 ┌─────────────┐
 │ minimal.dev  │  Nickel package declarations
 │ packages     │  (source of truth)
 └──────┬──────┘
        │ evaluated by
        v
 ┌─────────────┐
 │ gleisner-    │  Incremental eval, verify, compose, attest
 │ forge        │  (this tool)
 └──────┬──────┘
        │ produces
        v
 ┌─────────────┐
 │ attestation  │  JSON with provenance, hashes, proof status
 │ bundle       │  (machine-readable, diffable)
 └──────┬──────┘
        │ consumed by
        v
 ┌─────────────┐
 │ gleisner     │  SBOM generation, policy verification,
 │ CLI          │  diff, inspect
 └─────────────┘
```

## Key properties

- **Incremental**: content-addressed store skips unchanged packages
- **Proof-system agnostic**: schema supports any prover (Lean 4 is first)
- **Diffable**: `forge-diff` shows exactly what changed between runs
- **Trust separation**: package authors declare properties, forge independently verifies them
- **Graceful degradation**: packages without proofs are `unchecked`, not failed

## Built with

- [nickel-lang-core](https://github.com/nickel-lang/nickel) 0.17 — Nickel evaluation
- [lean4](https://github.com/leanprover/lean4) — proof verification kernel
- [kim-em/lean-zip](https://github.com/kim-em/lean-zip) — zlib roundtrip proofs
