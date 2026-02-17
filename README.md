# Gleisner

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blueviolet)](https://docs.anthropic.com/en/docs/claude-code)

Supply chain security for Claude Code. Sandbox sessions, attest every action, verify provenance.

Named after the Gleisner robots in Greg Egan's *Diaspora* -- software intelligence housed in constrained physical bodies. Like their namesakes, Gleisner wraps an autonomous intelligence in a body with hard physical limits: filesystem boundaries it cannot cross, network rules it cannot override, and a cryptographic record of everything it does.

## Requirements

- **Linux** (x86_64) -- Gleisner relies on Linux-specific kernel features (namespaces, Landlock LSM, cgroups v2, seccomp BPF)
- **[bubblewrap](https://github.com/containers/bubblewrap)** (`bwrap`) -- unprivileged sandbox creation. Install via your package manager (e.g., `apt install bubblewrap`, `pacman -S bubblewrap`)
- **Rust 1.85+** (edition 2024) -- install via [rustup](https://rustup.rs/)
- **Claude Code** -- Anthropic's CLI coding assistant (`npm install -g @anthropic-ai/claude-code`)

Optional:
- **nftables** or **iptables** -- for network domain allowlisting (slirp4netns + firewall rules)
- **Sigstore** tools -- for keyless signing via Fulcio and transparency logging via Rekor

## Architecture

```
                           +──────────────+
                           │ gleisner-cli │  CLI entry point
                           +──────┬───────+
                                  │
          ┌──────────┬────────────┼────────────┐
          ▼          ▼            ▼             ▼
    +-----------+ +----------+ +-----------+ +----------+
    │   polis   │ │ introdus │ │  lacerta  │ │ bridger  │
    │ (sandbox) │ │ (attest) │ │ (verify)  │ │  (SBOM)  │
    +-----------+ +----------+ +-----------+ +----------+

    polis ─────► Landlock/cgroup sandbox, inotify monitoring
    introdus ──► in-toto attestation bundles, ECDSA signing
    lacerta ───► signature/digest verification, policy engine
    bridger ───► Cargo.lock → CycloneDX 1.5 SBOM generation
```

## Quick Start

```bash
# Build
cargo build --release

# Wrap a Claude Code session in a sandbox (no attestation)
gleisner wrap -- claude

# Record a sandboxed session with full attestation
gleisner record -- claude

# Record without linking to a previous attestation (start a new chain)
gleisner record --no-chain -- claude

# Inspect an attestation bundle
gleisner inspect bundle.json
gleisner inspect --detailed bundle.json
gleisner inspect --json bundle.json

# Verify signatures, digests, and policies
gleisner verify bundle.json
gleisner verify bundle.json --policy policy.json
gleisner verify bundle.json --check-files --base-dir ./project
gleisner verify --json bundle.json

# Verify the full attestation chain from a bundle
gleisner verify --chain bundle.json

# Generate a Software Bill of Materials
gleisner sbom
gleisner sbom --json
gleisner sbom --json --output sbom.json
gleisner sbom --project-dir /path/to/project
```

## Chain Verification

Gleisner links attestation bundles into a verifiable chain. Each `record` session automatically discovers the most recent attestation in the project's `.gleisner/` directory and embeds a reference to it -- the SHA-256 digest of the parent's payload -- in the new attestation's provenance predicate under `gleisner:chain`.

This creates a tamper-evident history: if any attestation in the chain is modified or deleted, the digest link breaks and verification fails.

**How it works:**

1. When `gleisner record` runs, it scans `.gleisner/` for existing `attestation-*.json` files and selects the one with the latest `buildFinishedOn` timestamp.
2. It computes the SHA-256 digest of that parent bundle's `payload` field and stores it as `gleisner:chain.parentDigest` in the new attestation.
3. When verifying with `--chain`, Gleisner walks the chain backwards from the given bundle, resolving each `parentDigest` to a file in the same directory, until it reaches a root (an attestation with no parent link) or a broken link.

**Example chain walk:**

```
attestation-003.json  (latest)
  └─ parentDigest: sha256(attestation-002.json.payload)
       └─ parentDigest: sha256(attestation-001.json.payload)
            └─ (root -- no parent)
```

Use `--no-chain` with `gleisner record` to start a new chain (e.g., after a major refactor or repository migration).

## Crates

| Crate | Description |
|-------|-------------|
| `gleisner-cli` | CLI binary with `wrap`, `record`, `verify`, `inspect`, `sbom` commands |
| `gleisner-polis` | Sandbox enforcement: Landlock LSM, cgroup resource limits, inotify file monitoring with snapshot reconciliation |
| `gleisner-introdus` | Attestation bundle creation: in-toto statements, ECDSA P-256 signing |
| `gleisner-lacerta` | Verification: signature checking (local key + Sigstore), digest verification, policy engine (JSON + WASM) |
| `gleisner-bridger` | SBOM generation: Cargo.lock parsing, CycloneDX 1.5 JSON output |
| `gleisner-scapes` | Event bus and monitoring infrastructure |

## Configuration

### Sandbox Profiles

Profiles live in `~/.config/gleisner/profiles/` or `profiles/` in the project root. A profile defines Landlock filesystem rules and cgroup resource limits.

### Verification Policies

Policies can be JSON (built-in rules) or WASM (custom OPA/Rego):

```json
{
  "require_sandbox": true,
  "allowed_profiles": ["default", "strict"],
  "max_session_duration_secs": 3600,
  "require_audit_log": true
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flows, crate responsibilities, and design decisions |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model, key management, policy engine, sandbox layers, and hardening checklist |
| [docs/RUST_PATTERNS.md](docs/RUST_PATTERNS.md) | Rust patterns and idioms used in the codebase (learning guide) |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model covering attack surfaces, trust boundaries, and mitigations |

## Contributing

Contributions are welcome. Before submitting a PR:

1. Run the full lint and test suite:
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
2. Format your code: `cargo fmt --all`
3. Ensure `cargo deny check` passes (licenses and advisories)
4. Keep `unsafe_code = "forbid"` -- no `unsafe` in Gleisner's own code

The project uses strict Clippy lints (`clippy::all = deny`, `clippy::pedantic = warn`, `clippy::nursery = warn`) and workspace-level dependency inheritance. All dependency versions live in the root `Cargo.toml`; never duplicate a version in a member crate.

## License

Licensed under [Apache License, Version 2.0](LICENSE-APACHE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you shall be licensed under the Apache-2.0 license, without any additional terms or conditions.
