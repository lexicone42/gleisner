# Gleisner

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blueviolet)](https://docs.anthropic.com/en/docs/claude-code)

Supply chain security for Claude Code. Sandbox sessions, attest every action, verify provenance.

Named after the Gleisner robots in Greg Egan's *Diaspora* -- software intelligence housed in constrained physical bodies. Like their namesakes, Gleisner wraps an autonomous intelligence in a body with hard physical limits: filesystem boundaries it cannot cross, network rules it cannot override, and a cryptographic record of everything it does.

## Requirements

- **Linux** (x86_64) -- Gleisner relies on Linux-specific kernel features (user namespaces, Landlock LSM, cgroups v2)
- **[bubblewrap](https://github.com/containers/bubblewrap)** (`bwrap`) -- unprivileged sandbox creation. Install via your package manager (e.g., `apt install bubblewrap`, `pacman -S bubblewrap`)
- **Rust 1.85+** (edition 2024) -- install via [rustup](https://rustup.rs/)
- **Claude Code** -- Anthropic's CLI coding assistant (`npm install -g @anthropic-ai/claude-code`)

Optional:
- **[pasta](https://passt.top/)** (from passt) -- TAP networking for domain-filtered network access inside the sandbox. Required if your profile uses `allow_domains` with a deny-default network policy.
- **nftables** or **iptables** -- firewall rules for domain allowlisting (nftables preferred; iptables as fallback)
- **Sigstore** tools -- for keyless signing via Fulcio and transparency logging via Rekor (`cargo build --features keyless`)

## Architecture

```
                 +──────────────+     +──────────────+
                 │ gleisner-cli │     │ gleisner-tui │
                 +──────┬───────+     +──────┬───────+
                        │                    │
          ┌──────────┬──┴────────────────────┴──┬──────────┐
          ▼          ▼            ▼              ▼          ▼
    +-----------+ +----------+ +-----------+ +----------+ +--------+
    │   polis   │ │ introdus │ │  lacerta  │ │ bridger  │ │ scapes │
    │ (sandbox) │ │ (attest) │ │ (verify)  │ │  (SBOM)  │ │(events)│
    +-----------+ +----------+ +-----------+ +----------+ +--------+
          │
    +---------------+
    │ sandbox-init  │  Landlock trampoline (inside bwrap)
    +---------------+

    polis ─────► bwrap + Landlock V7 sandbox, pasta networking, cgroup/rlimit resource limits
    introdus ──► in-toto v1 attestation bundles, ECDSA P-256 + Sigstore signing, chain linking
    lacerta ───► signature/digest verification, policy engine (JSON + WASM/OPA)
    bridger ───► Cargo.lock → CycloneDX 1.5 SBOM generation
    scapes ────► event bus (tokio broadcast), JSONL audit writer, session recorder
```

### Sandbox Layers

Gleisner applies five independent isolation layers, each enforced by a different Linux kernel mechanism:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| 1 | User namespaces | Unprivileged isolation -- sandboxed process has no real host privileges |
| 2 | Bubblewrap (bwrap) | Mount namespace -- bind-mounts, tmpfs deny, PID namespace, `--die-with-parent` |
| 3 | Landlock LSM (V7) | Fine-grained filesystem and network access control, IPC scope isolation, kernel audit logging |
| 4 | Cgroups v2 + rlimits | Memory, CPU, PID, FD, and disk write limits |
| 5 | Network filtering | pasta + nftables/iptables for domain-level allowlisting |

Compromising one layer does not automatically compromise the others. For example, even if the mount namespace is bypassed, Landlock independently restricts filesystem access at the kernel level.

## Quick Start

```bash
# Build
cargo build --release

# ── Interactive TUI (recommended) ──────────────────────────────────

# TUI without sandbox (unsandboxed Claude Code with security dashboard)
gleisner-tui --project-dir /path/to/project

# TUI with sandbox and automatic attestation recording
gleisner-tui --sandbox --profile developer --project-dir /path/to/project

# ── CLI commands ───────────────────────────────────────────────────

# Wrap a Claude Code session in a sandbox (no attestation)
gleisner wrap -- claude

# Record a sandboxed session with full attestation
gleisner record -- claude

# Record without linking to a previous attestation (start a new chain)
gleisner record --no-chain -- claude

# Inspect an attestation bundle
gleisner inspect .gleisner/attestation-*.json
gleisner inspect --detailed .gleisner/attestation-*.json

# Verify signatures, digests, and policies
gleisner verify .gleisner/attestation-*.json
gleisner verify .gleisner/attestation-*.json --policy policy.json
gleisner verify --chain .gleisner/attestation-*.json

# Compare two attestation bundles
gleisner diff .gleisner/attestation-old.json .gleisner/attestation-new.json

# Generate a sandbox profile from kernel audit observations
gleisner learn --kernel-audit-log /var/log/gleisner/landlock-audit.log

# Generate a Software Bill of Materials
gleisner sbom --json --output sbom.json
```

## TUI

The TUI wraps Claude Code in an interactive terminal interface with a live security dashboard, attestation recording, and inline security tooling.

```bash
# Interactive TUI (no sandbox)
gleisner-tui --profile konishi --project-dir /path/to/project

# Sandboxed TUI with full attestation pipeline
gleisner-tui --sandbox --profile developer --project-dir /path/to/project

# With additional allowed domains and paths
gleisner-tui --sandbox --profile konishi \
  --allow-network registry.npmjs.org \
  --allow-path /tmp/build-cache \
  --project-dir /path/to/project
```

### Slash Commands

| Command | Description |
|---------|-------------|
| `/sbom` | Generate and display SBOM summary |
| `/verify <path>` | Verify an attestation bundle |
| `/inspect <path>` | Display attestation details |
| `/cosign [token]` | Sign the session attestation with Sigstore keyless OIDC (requires `--features keyless`) |
| `/help` | Show available commands |

### Security Dashboard

When running, the TUI displays a telemetry sidebar showing:
- **Sandbox status**: whether bwrap isolation is active
- **Attestation recording**: live event count with a **REC** indicator
- **Cosign status**: whether the session has been Sigstore-signed
- **Tool call counters**: file reads, writes, and total tool invocations
- **Session metrics**: agent turns, cumulative cost, and context window usage (color-coded bar)

### Attestation Pipeline

When `--sandbox` is passed, the TUI automatically:
1. Creates a bubblewrap + Landlock sandbox for the Claude session
2. Monitors filesystem changes (inotify) and child processes (`/proc`)
3. Records all events to a JSONL audit log
4. On session end, reconciles pre/post filesystem snapshots
5. Assembles a signed in-toto v1 attestation bundle with chain linking
6. Writes `.gleisner/attestation-{timestamp}.json` and `.gleisner/audit-{timestamp}.jsonl`

The `/cosign` command can then apply Sigstore keyless signing to the bundle without leaving the TUI.

### Keystrokes

Vim-inspired modal input: `i` enters insert mode, `Esc` returns to normal mode. In normal mode, `j`/`k` scroll the conversation, `g`/`G` jump to top/bottom, `q` quits. `Enter` submits prompts in insert mode. `Ctrl+C` interrupts streaming.

## Demo Walkthrough

A complete pipeline demonstration, from sandbox to verified chain.

### 1. Record a sandboxed session

```bash
gleisner record --profile developer -- claude -p "What is 2+2?"
```

This wraps the Claude session in a bubblewrap sandbox with Landlock V7 filesystem rules, cgroup resource limits, and network filtering. When the session ends, Gleisner:
- Captures a pre/post filesystem snapshot for reconciliation
- Monitors child processes via `/proc`
- Collects Landlock denial events (if kernel audit is configured)
- Signs the attestation with a local ECDSA P-256 key
- Links to the previous attestation in `.gleisner/` (chain)

Output files appear in `.gleisner/`:
```
.gleisner/
  attestation-2026-02-20T14-30-00Z.json   # Signed in-toto v1 statement
  audit-2026-02-20T14-30-00Z.jsonl         # Raw event log
```

### 2. Inspect the attestation

```bash
gleisner inspect .gleisner/attestation-2026-02-20T14-30-00Z.json
```

Shows the statement type (in-toto v1.0.0), predicate type, builder ID, session timing, subject/material counts, and sandbox profile used.

Use `--detailed` for full subject and material listings, or `--json` for machine-readable output.

### 3. Verify the attestation

```bash
gleisner verify .gleisner/attestation-2026-02-20T14-30-00Z.json
```

Checks:
- **Signature**: ECDSA P-256 verification against the embedded public key
- **Digests**: Audit log digest matches the referenced JSONL file
- **Policy**: (optional) Enforce rules like `require_sandbox`, `max_session_duration_secs`, `allowed_profiles`

Add `--chain` to walk the full attestation chain:

```bash
gleisner verify --chain .gleisner/attestation-2026-02-20T14-30-00Z.json
```

This resolves each `parentDigest` link backwards until it reaches the chain root, verifying digest integrity at every step.

### 4. Run a second session and diff

```bash
gleisner record --profile developer -- claude -p "Add a docstring to main.rs"
gleisner diff .gleisner/attestation-*-14-30-*.json .gleisner/attestation-*-14-45-*.json
```

The diff shows:
- **Subjects**: Files added, removed, or changed (with digest comparison)
- **Materials**: Input file differences
- **Environment**: Model, profile, or sandbox config changes
- **Timing**: Session duration comparison

### 5. Generate an SBOM

```bash
gleisner sbom --json --output sbom.json
```

Parses `Cargo.lock` and produces a CycloneDX 1.5 JSON document listing every dependency with name, version, package URL (purl), and SHA-256 hash.

## Chain Verification

Gleisner links attestation bundles into a verifiable chain. Each `record` session (and each `gleisner-tui --sandbox` session) automatically discovers the most recent attestation in the project's `.gleisner/` directory and embeds a reference to it -- the SHA-256 digest of the parent's payload -- in the new attestation's provenance predicate under `gleisner:chain`.

This creates a tamper-evident history: if any attestation in the chain is modified or deleted, the digest link breaks and verification fails.

**How it works:**

1. When a session ends, Gleisner scans `.gleisner/` for existing `attestation-*.json` files and selects the one with the latest `buildFinishedOn` timestamp.
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
| `gleisner-cli` | CLI binary: `wrap`, `record`, `verify`, `inspect`, `sbom`, `diff`, `learn` |
| `gleisner-tui` | Interactive TUI: security dashboard, slash commands (`/sbom`, `/verify`, `/inspect`, `/cosign`), automatic attestation recording |
| `gleisner-polis` | Sandbox enforcement: bubblewrap, Landlock LSM V7 (filesystem + network + scope + audit), cgroup/rlimit resource limits, inotify monitoring, pasta networking, profile learning |
| `gleisner-introdus` | Attestation bundles: in-toto v1 statements, ECDSA P-256 signing, Sigstore keyless signing, chain linking |
| `gleisner-lacerta` | Verification: signature checking (local key + Sigstore), digest verification, policy engine (JSON + WASM/OPA) |
| `gleisner-bridger` | SBOM generation: Cargo.lock parsing, CycloneDX 1.5 JSON output |
| `gleisner-scapes` | Event bus (tokio broadcast), JSONL audit writer, session recorder |
| `gleisner-sandbox-init` | Trampoline binary: applies Landlock rules inside bubblewrap before exec |

## Configuration

### Sandbox Profiles

Profiles are TOML files that define filesystem rules, network policy, process isolation, and resource limits. They live in `~/.config/gleisner/profiles/` or `profiles/` in the project root.

Four profiles are bundled (named after polises in *Diaspora*):

| Profile | Description |
|---------|-------------|
| **konishi** | Default balanced. Anthropic API only, credentials hidden, PID isolated, 4GB memory, 256 PIDs. |
| **carter-zimmerman** | Exploratory. Broader network (npm, PyPI, GitHub, crates.io), 8GB memory, 512 PIDs. |
| **ashton-laval** | Strict. Anthropic API only, DNS disabled, 2GB memory, 128 PIDs, 50% CPU cap. |
| **developer** | Development-focused. Full Rust toolchain (cargo, rustup, crates.io, GitHub), 16GB memory. Designed for gleisner-in-gleisner self-hosting. |

A profile defines five dimensions of isolation:

```toml
name = "konishi"
description = "Default balanced profile"

[filesystem]
readonly_bind = ["/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin"]
readwrite_bind = []
deny = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gcloud"]
tmpfs = ["/tmp"]

[network]
default = "deny"
allow_domains = ["api.anthropic.com", "sentry.io"]
allow_ports = [443]
allow_dns = true

[process]
pid_namespace = true
no_new_privileges = true
command_allowlist = []

[resources]
max_memory_mb = 4096
max_cpu_percent = 100
max_pids = 256
max_file_descriptors = 1024
max_disk_write_mb = 10240
```

### Verification Policies

Policies can be JSON (built-in rules) or WASM (custom OPA/Rego):

```json
{
  "require_sandbox": true,
  "allowed_profiles": ["konishi", "ashton-laval"],
  "max_session_duration_secs": 3600,
  "require_audit_log": true
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flows, crate responsibilities, TUI architecture, and design decisions |
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
