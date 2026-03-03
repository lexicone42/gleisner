# Lean Formal Verification Integration Research

*Research notes from 2026-03-03, prompted by Leo de Moura's blog post:
"When AI Writes the World's Software, Who Verifies It?"
(https://leodemoura.github.io/blog/2026/02/28/when-ai-writes-the-worlds-software.html)*

## Context

De Moura (creator of Lean, AWS Senior Principal Applied Scientist) argues that as
AI generates the majority of code, mathematical proofs — not just tests or reviews —
become the trust mechanism. Lean's tiny proof kernel (thousands of lines) can
mechanically verify correctness guarantees that no amount of testing can provide.

Key developments cited:
- Kim Morrison's team converted zlib to Lean with AI assistance, proving the
  roundtrip property: `decompress(compress(data)) = data`
- AlphaProof, SEED Prover, Aristotle — all build on Lean
- AWS verified Cedar authorization engine in Lean
- Microsoft verifies SymCrypt cryptographic library in Lean
- Mathlib: 200,000+ formalized theorems, 750 contributors

## How Gleisner Fits

### Structural Parallel

Blog's architecture:
```
Specification  →  Implementation  →  Proof  →  Verified artifact
```

Gleisner's current pipeline:
```
Package declaration  →  Evaluation  →  Composition  →  Attestation  →  Enforcement
```

The missing link is proof — mathematical certificates bridging "this package
declares X" to "this package provably satisfies X."

### Three Levels of Specification in Gleisner

1. **Package specs** — what a package needs (filesystem, network, dns) and provides
   (binaries, data, env vars). Nickel `build.ncl` declarations.

2. **Profile specs** — what a sandbox allows/denies. TOML profiles (konishi,
   developer, etc.) with filesystem deny lists, network defaults, rlimits.

3. **Session specs** — what actually happened. Session manifests with exit codes,
   timing, forge output digests.

All three are declarative but not formally verified today.

### Complementary Trust Layers

Proofs and attestation serve different functions:
- A **proof** says "this component is correct"
- An **attestation** says "this specific binary, with this hash, was built from
  this source, evaluated in this sandbox, with this exit code"

Without attestation, someone could substitute an unproved binary for a proved one.
Without proofs, attestation can only say "this is what ran" not "this is correct."
Together they form a complete trust chain.

| Layer | Trust mechanism | Gleisner today | With Lean |
|-------|----------------|----------------|-----------|
| Source | Where did this come from? | PURLs, provenance | + specification hashes |
| Build | How was it built? | Package eval, store hashes | + proof of build correctness |
| Composition | Does the whole work? | Forge compose, profile validation | + composition preserves invariants |
| Runtime | Is it behaving correctly? | Landlock audit, sandbox enforcement | + enforcement of proved properties |
| Audit | What happened? | Session manifest, attestation bundle | + proof certificates in attestation |

## Integration Plan

### Near Term: Schema Ready -- IMPLEMENTED

**Status:** Shipped in `gleisner-forge`. See [VERIFIED-PROPERTIES-SUMMARY.md](VERIFIED-PROPERTIES-SUMMARY.md).

`verified_properties` is now part of the attestation `package_metadata`. The
`VerifiedProperty` struct includes `property`, `description`, `proof_system`,
`kernel_version`, `specification_hash`, `proof_hash`, `proof_uri`, and
`verified_by_forge` fields. The `verified_properties` attr class has been added
to minimal.dev's `attr_classes.ncl`, and zlib is the first package declaring it
with three roundtrip properties (zlib/deflate/gzip per RFC 1950/1951/1952).

### Medium Term: Forge Verify Step -- IMPLEMENTED

**Status:** Shipped in `gleisner-forge`. Invoked via `gleisner forge --verify`.

The pipeline is:

```
forge evaluate → forge verify → forge compose → forge attest
```

- `lake build` runs the Lean 4 kernel for packages with `verified_properties`
- Verification results embedded in attestation as `VerifiedProperty` structs with `verified_by_forge` field
- `--strict-verify` makes any failure a hard stop
- Graceful degradation: missing Lean binary skips verification with a warning

### Long Term: Self-Verifying Infrastructure

- Lean specifications for gleisner profiles (prove konishi satisfies security properties)
- Prove Landlock policy generator preserves security properties
- Prove Nickel-to-policy bridge correctness
- The sandbox carries proofs of its own correctness
- Lean specs for the forge compose step's invariants

## SBOM Integration (CycloneDX 1.6)

CycloneDX 1.6 already supports:
- `evidence` field — verification results for a component
- `formulation` — how a component was built
- `externalReferences` — links to proof artifacts

Example component with proof artifacts:

```json
{
  "type": "library",
  "name": "zlib",
  "version": "1.3.1",
  "purl": "pkg:lean4/verified-zlib@1.3.1",
  "evidence": {
    "identity": {
      "field": "verified",
      "methods": [{
        "technique": "formal-verification",
        "value": "lean4-kernel-check"
      }]
    }
  },
  "properties": [
    { "name": "proof:roundtrip", "value": "decompress(compress(data)) = data" },
    { "name": "proof:kernel", "value": "lean4/4.16.0" },
    { "name": "proof:hash", "value": "sha256:..." }
  ]
}
```

## Management Claude Upgrade

Currently: pattern-match on JSON policy to decide if a session is safe.

With proof artifacts:
- Check that cryptographic components carry constant-time proofs
- Verify that parser components have memory-safety proofs
- Require proof coverage thresholds before approving deployment
- Trust chain goes from "I checked the policy" to "I verified the proofs"

The management Claude doesn't need to understand Lean — just invoke the kernel
(a binary) and check the exit code. The kernel is the oracle.

## Key Quotes from the Blog

> "A proof cannot be gamed. It covers all inputs by construction."

> "Specification becomes the core engineering discipline."

> "Each verified component becomes public infrastructure. Unlike proprietary
> software, verified open-source libraries cannot be degraded or have guarantees
> revoked."

> "The real comparison is not Lean versus C, but verified versus unverified code."

## Open Questions

1. **Proof artifact format**: ~~What's the canonical way to distribute `.olean` files
   or Lean proof objects?~~ **Partially answered:** The forge clones proof repos from
   `proof_uri` (GitHub URLs) and builds locally. Distribution via package registries
   or IPFS remains an open design question for scale.

2. **Specification ownership**: Who writes the specs? The package maintainer? A
   separate verification team? The management Claude?

3. **Partial verification**: ~~How do we represent "these 3 properties are proved,
   these 12 are tested only"?~~ **Answered:** The `VerificationSummary` reports per-property
   status: `verified`, `failed`, or `unchecked`. Packages without proofs are `unchecked`,
   not failed.

4. **Proof freshness**: A proof is valid for a specific version. How do we handle
   the gap between "latest source" and "latest proved version"?

5. **Composition proofs**: Individual component proofs don't automatically compose.
   The forge compose step needs its own correctness argument.

6. **Lean as a minimal.dev package**: ~~Can we package the Lean kernel itself via
   minimal.dev?~~ **Partially answered:** The forge auto-detects Lean from `elan` or
   `PATH`. Packaging Lean via minimal.dev is feasible but not yet done.
