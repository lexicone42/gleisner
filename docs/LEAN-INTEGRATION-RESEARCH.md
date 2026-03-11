# Proof-Carrying SBOMs: Embedding Formal Verification in CycloneDX 1.6

*A concrete proposal for the mundane infrastructure that connects proof kernels to supply chain metadata.*

---

## The Problem

Leo de Moura's ["When AI Writes the World's Software, Who Verifies It?"](https://leodemoura.github.io/blog/2026/02/28/when-ai-writes-the-worlds-software.html) makes a compelling case: as AI generates more code, mathematical proofs become the trust mechanism. Lean's kernel (thousands of lines of code) can mechanically verify correctness guarantees that no amount of testing provides.

The exciting work is happening — lean-zip proves `decompress(compress(data)) = data` for zlib, AWS verified Cedar in Lean, Microsoft verifies SymCrypt. But there's a gap: **once a proof exists, how does it travel with the software?** How does a downstream consumer know that the zlib binary in their container was built from the source that was actually proved correct?

This is the supply chain plumbing problem. Proofs are only useful if they can be discovered, attributed to specific artifacts, and verified independently. Today, proof status lives in READMEs and CI badges. It should live in machine-readable metadata bound to specific package versions.

## What We Built

[Gleisner](https://github.com/lexicone42/gleisner) is a supply chain security tool for AI coding agents. As part of its forge pipeline (which evaluates [minimal.dev](https://minimal.dev) Nickel packages), we've implemented two kinds of formal evidence in [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/) SBOMs using the **Declarations** model:

### 1. Lean Proof Claims

Packages declare `verified_properties` linking to proof artifacts:

```nickel
attrs = {
  verified_properties = [{
    property = "zlib_roundtrip",
    description = "decompress(compress(data)) = data (RFC 1950)",
    proof_system = "lean4",
    kernel_version = "leanprover/lean4:v4.29.0-rc2",
    specification_hash = "sha256:d5d9988f...",
    proof_hash = "sha256:41d114c4...",
    proof_uri = "https://github.com/kim-em/lean-zip/...",
  }],
}
```

The forge clones the proof repo, runs `lake build`, hashes the `.olean` output, and records whether the forge's kernel check matched the declared hash. This becomes a CycloneDX **Attestation Claim** with:

- **Requirement**: `formal-verification/zlib/roundtrip`
- **Evidence**: proof system, kernel version, specification hash, proof artifact hash + URI
- **Conformance**: 1.0 (forge-verified), 0.0 (unchecked or failed)
- **Assessors**: the forge tool + the Lean 4 proof kernel (as a third-party assessor)

### 2. Z3 Policy Compliance Claims

We encode session security policies as Z3 QF_LIA constraints and check subsumption against named baselines (SLSA Build L1/L2/L3). This answers: "does this build's security posture meet a given standard?"

When the Z3 solver returns UNSAT, the session provably meets the baseline — every input the session policy accepts is also accepted by the baseline. When SAT, the solver produces a concrete **counterexample witness**: an input that would pass the session but fail the baseline. This becomes a CycloneDX **Counter-Claim** with the witness as evidence.

- **Requirement**: `policy-compliance/slsa-build-l2`
- **Evidence**: Z3 SMT proof method (QF_LIA), baseline definition
- **Counter-evidence** (when non-compliant): concrete witness input as JSON
- **Conformance**: 1.0 (UNSAT = proved compliant) or 0.0 (SAT = counterexample found)

### Combined SBOM Output

A single CycloneDX 1.6 SBOM carries both:

```
Declarations
├── Assessors
│   ├── gleisner-forge (local)
│   ├── Lean 4 proof kernel (third-party)
│   └── Z3 SMT Solver (third-party)
├── Attestation: "Formal verification of 3 properties across 1 package"
│   ├── formal-verification/zlib/roundtrip         → conformance 1.0
│   ├── formal-verification/zlib/deflate_roundtrip  → conformance 1.0
│   └── formal-verification/zlib/gzip_roundtrip     → conformance 1.0
└── Attestation: "Policy compliance: 2/4 baselines met"
    ├── policy-compliance/slsa-build-l1  → claim, conformance 1.0
    ├── policy-compliance/slsa-build-l2  → claim, conformance 1.0
    ├── policy-compliance/slsa-build-l3  → counter-claim + witness, conformance 0.0
    └── policy-compliance/gleisner-strict → counter-claim + witness, conformance 0.0
```

## Why CycloneDX 1.6 Declarations

CycloneDX 1.6 added a Declarations model with **claims**, **counter-claims**, **evidence**, and **conformance scores**. It was designed for compliance attestations, but it maps naturally to formal verification:

| CycloneDX concept | Lean proof mapping | Z3 policy mapping |
|---|---|---|
| Claim | "zlib satisfies roundtrip property" | "session meets SLSA L2" |
| Counter-claim | (proof failed or unchecked) | "session does NOT meet SLSA L3" |
| Evidence | proof artifact hash, kernel version, spec hash | Z3 UNSAT/SAT result, witness |
| Assessor | Lean 4 kernel (third-party, mechanically certain) | Z3 solver (third-party, mechanically certain) |
| Conformance score | 1.0 = kernel-verified, 0.0 = unchecked | 1.0 = UNSAT (proved), 0.0 = SAT (disproved) |

The key insight: both proof kernel verification and SMT solving are **mechanically certain**. When conformance is 1.0, it's not an opinion or a heuristic — it's a mathematical result. The confidence field is always 1.0 for both.

## The Question

We haven't found anyone else embedding formal verification proofs in standard SBOM formats. Is anyone working on this from the proof side? Specifically:

1. **Proof artifact distribution** — Is there a standard way to reference and retrieve `.olean` files (or proof objects from other systems) in package metadata? We're using URIs + SHA-256 hashes, but a content-addressed scheme (IPFS, OCI artifacts) might be better.

2. **Specification identity** — How should specifications be identified across versions? We hash the spec file, but specifications evolve. A specification registry with versioned identifiers would be more robust.

3. **Cross-prover interop** — The schema supports arbitrary proof systems (Lean, Coq/Rocq, Isabelle). Should there be a common metadata format for "this component has been formally verified" that's prover-agnostic?

4. **Composition** — Individual component proofs don't compose automatically. We have Z3 checking policy *subsumption* at the session level, but proving that "composition of verified components preserves verified properties" is a harder problem. Is anyone working on compositional verification frameworks that could produce SBOM-embeddable evidence?

## Implementation

- **Code**: [github.com/lexicone42/gleisner](https://github.com/lexicone42/gleisner), crates `gleisner-forge` (SBOM generation) and `gleisner-lacerta` (Z3 policy lattice)
- **Lean proofs used**: [kim-em/lean-zip](https://github.com/kim-em/lean-zip) — zlib/deflate/gzip roundtrip properties
- **Z3 encoding**: 8 policy rules → 10 Z3 variables → QF_LIA, solves in microseconds
- **Test coverage**: Cross-validation pattern — Z3 produces a witness, runtime policy evaluator confirms it actually passes/fails as Z3 predicted

The forge pipeline: `eval → verify (lake build) → compose → attest → SBOM (CycloneDX 1.6 with Declarations)`
