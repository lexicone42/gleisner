# Gleisner

Supply chain security for Claude Code. Sandbox sessions, attest every action, verify provenance.

Named after the Gleisner robots in Greg Egan's *Diaspora* -- software intelligence housed in constrained physical bodies.

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

    polis ─────► Landlock/cgroup sandbox, fanotify monitoring
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

# Inspect an attestation bundle
gleisner inspect bundle.json
gleisner inspect --detailed bundle.json
gleisner inspect --json bundle.json

# Verify signatures, digests, and policies
gleisner verify bundle.json
gleisner verify bundle.json --policy policy.json
gleisner verify bundle.json --check-files --base-dir ./project
gleisner verify --json bundle.json

# Generate a Software Bill of Materials
gleisner sbom
gleisner sbom --json
gleisner sbom --json --output sbom.json
gleisner sbom --project-dir /path/to/project
```

## Crates

| Crate | Description |
|-------|-------------|
| `gleisner-cli` | CLI binary with `wrap`, `record`, `verify`, `inspect`, `sbom` commands |
| `gleisner-polis` | Sandbox enforcement: Landlock LSM, cgroup resource limits, fanotify file monitoring |
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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
