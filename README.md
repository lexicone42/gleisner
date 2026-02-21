# Gleisner

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blueviolet)](https://docs.anthropic.com/en/docs/claude-code)

Supply chain security for Claude Code. Sandbox sessions, attest every action, verify provenance.

Named after the Gleisner robots in Greg Egan's *Diaspora* -- software intelligence housed in constrained physical bodies. Gleisner wraps an autonomous coding agent in hard limits: filesystem boundaries it cannot cross, network rules it cannot override, and a cryptographic record of everything it does.

## What Gleisner Does

**Sandbox** -- Run Claude Code inside a multi-layer Linux sandbox (bubblewrap + Landlock V7 + cgroups + nftables). Credentials are hidden, network egress is restricted to an explicit domain allowlist, and filesystem writes are confined to the project directory.

**Attest** -- Every sandboxed session produces a signed [in-toto v1](https://in-toto.io/) attestation bundle with [SLSA](https://slsa.dev/)-compatible provenance. Materials (files read), subjects (files written), timestamps, sandbox configuration, and git state are all cryptographically bound. Attestations chain together via parent payload digests.

**Verify** -- Check signatures (ECDSA P-256 or Sigstore keyless), validate digest integrity, walk the attestation chain, and evaluate configurable policies (JSON rules or WASM/OPA).

## Getting Started

### Requirements

- **Linux** (x86_64) -- user namespaces, Landlock LSM, cgroups v2
- **[bubblewrap](https://github.com/containers/bubblewrap)** -- `apt install bubblewrap` / `pacman -S bubblewrap`
- **Rust 1.85+** -- [rustup.rs](https://rustup.rs/)
- **Claude Code** -- `npm install -g @anthropic-ai/claude-code`
- **[pasta](https://passt.top/)** (from passt) -- required for domain-filtered networking. `apt install passt` / `pacman -S passt`

Optional:
- **nftables** or **iptables** -- firewall backend for domain allowlisting (nftables preferred)
- **Sigstore** -- keyless signing via Fulcio/Rekor (`cargo build --features keyless`)

### Build

```bash
cargo build --release
```

Binaries are placed in `target/release/`: `gleisner` (CLI) and `gleisner-tui`.

## TUI (Recommended)

The TUI is the primary way to use Gleisner. It wraps Claude Code in an interactive terminal with a live security dashboard, automatic attestation recording, and inline security tooling.

```bash
# Sandboxed session with attestation (the standard workflow)
gleisner-tui --sandbox --profile developer --project-dir /path/to/project

# Without sandbox (security dashboard only, no isolation)
gleisner-tui --project-dir /path/to/project

# With additional allowed domains and paths
gleisner-tui --sandbox --profile konishi \
  --allow-network registry.npmjs.org \
  --allow-path /tmp/build-cache \
  --project-dir /path/to/project
```

### Security Dashboard

The TUI displays a telemetry sidebar with live status:

```
+- Telemetry ---------------+
| State                      |
|  Profile  developer        |
|  Sandbox  . bwrap          |
|  Attest   . REC 42         |
|  Cosign   . /cosign        |
|                            |
| Sensors                    |
|  Reads    12               |
|  Writes   3                |
|  Tools    47               |
|                            |
| Link                       |
|  Turns    5                |
|  Cost     $0.1234          |
|  Ctx      ####.. 62%       |
+----------------------------+
```

- **Sandbox**: green when bwrap isolation is active
- **Attest**: red REC indicator with live event count during recording
- **Cosign**: amber when ready for Sigstore signing, green after signed
- **Ctx**: context window usage bar, color-coded (green/amber/red)

### Slash Commands

| Command | Description |
|---------|-------------|
| `/sbom` | Generate and display CycloneDX SBOM |
| `/verify <path>` | Verify an attestation bundle |
| `/inspect <path>` | Display attestation details |
| `/cosign [token]` | Sign the session with Sigstore keyless OIDC (requires `--features keyless`) |
| `/help` | Show available commands |

### Keystrokes

Vim-inspired modal input. `i` enters insert mode, `Esc` returns to normal mode. In normal mode: `j`/`k` scroll, `g`/`G` jump to top/bottom, `q` quits. In insert mode: `Enter` submits, `Ctrl+C` interrupts streaming.

### Attestation Pipeline

When `--sandbox` is passed, the TUI automatically:

1. Creates a bubblewrap + Landlock sandbox for the Claude session
2. Monitors filesystem changes (inotify) and child processes (`/proc`)
3. Records all events to a JSONL audit log
4. Reconciles pre/post filesystem snapshots on session end
5. Assembles a signed in-toto v1 attestation bundle with chain linking
6. Writes `.gleisner/attestation-{timestamp}.json` and `.gleisner/audit-{timestamp}.jsonl`

The `/cosign` command can then apply Sigstore keyless signing without leaving the TUI.

## CLI Commands

The CLI provides the same capabilities as the TUI for scripting, CI, and non-interactive use.

```bash
# Sandbox a session (no attestation)
gleisner wrap -- claude

# Record a sandboxed session with full attestation
gleisner record -- claude

# Inspect an attestation bundle
gleisner inspect .gleisner/attestation-*.json
gleisner inspect --detailed .gleisner/attestation-*.json

# Verify signatures, digests, and policies
gleisner verify .gleisner/attestation-*.json
gleisner verify .gleisner/attestation-*.json --policy policy.json

# Verify the full attestation chain
gleisner verify --chain .gleisner/attestation-*.json

# Compare two attestation bundles
gleisner diff .gleisner/attestation-old.json .gleisner/attestation-new.json

# Generate a sandbox profile from kernel audit observations
gleisner learn --kernel-audit-log /var/log/gleisner/landlock-audit.log

# Generate a Software Bill of Materials
gleisner sbom --json --output sbom.json
```

## Sandbox Layers

Five independent isolation layers, each enforced by a different Linux kernel mechanism:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| 1 | User namespaces | Unprivileged isolation -- no real host privileges |
| 2 | Bubblewrap (bwrap) | Mount namespace -- bind-mounts, tmpfs deny, PID namespace, `--die-with-parent` |
| 3 | Landlock LSM (V7) | Filesystem and network access control, IPC scope isolation, kernel audit logging |
| 4 | Cgroups v2 + rlimits | Memory, CPU, PID, FD, and disk write limits |
| 5 | Network filtering | pasta + nftables/iptables for domain-level allowlisting |

Compromising one layer does not compromise the others. Even if the mount namespace is bypassed, Landlock independently restricts filesystem access at the kernel level.

## Sandbox Profiles

Profiles are TOML files defining filesystem rules, network policy, process isolation, resource limits, and Claude Code plugin restrictions. They live in `~/.config/gleisner/profiles/` or `profiles/` in the project root.

Four profiles are bundled (named after polises in *Diaspora*):

| Profile | Network | Resources | Use Case |
|---------|---------|-----------|----------|
| **konishi** | Anthropic API only | 4 GB, 256 PIDs | Default balanced usage |
| **carter-zimmerman** | + npm, PyPI, GitHub, crates.io | 8 GB, 512 PIDs | Projects needing external registries |
| **ashton-laval** | Anthropic API only, DNS disabled | 2 GB, 128 PIDs, 50% CPU | High-security, minimal permissions |
| **developer** | + crates.io, GitHub, Sigstore | 16 GB, 1024 PIDs | Rust development, gleisner-in-gleisner |

All profiles hide credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`) and enforce PID namespace isolation.

### Profile Structure

```toml
name = "konishi"
description = "Default balanced profile"

[filesystem]
readonly_bind = ["/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin", "/opt"]
readwrite_bind = []
deny = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gcloud", "~/.azure", "~/.kube", "~/.docker"]
tmpfs = ["/tmp"]

[network]
default = "deny"
allow_domains = ["api.anthropic.com", "sentry.io", "statsig.anthropic.com"]
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

[plugins]
skip_permissions = true
add_dirs = ["~/.claude/exo-self"]
disallowed_tools = []
mcp_network_domains = []
```

The `[plugins]` section controls Claude Code's MCP tool access inside the sandbox. `disallowed_tools` blocks specific MCP tools (e.g., Playwright browser automation, shell-escape tools). `mcp_network_domains` allows additional domains required by MCP servers.

## Attestation Chain

Each session automatically discovers the most recent attestation in `.gleisner/` and links to it via a SHA-256 payload digest, creating a tamper-evident history:

```
attestation-003.json  (latest)
  +- parentDigest: sha256(attestation-002.json.payload)
       +- parentDigest: sha256(attestation-001.json.payload)
            +- (root -- no parent)
```

If any attestation in the chain is modified or deleted, the digest link breaks and `gleisner verify --chain` fails. Use `--no-chain` with `gleisner record` to start a new chain.

The chain links on the **payload** digest (not the bundle digest), so re-signing an attestation (key rotation, switching to Sigstore) does not break the chain.

## Verification Policies

Policies enforce rules against attestation bundles. JSON for built-in rules, WASM for custom OPA/Rego logic.

```json
{
  "require_sandbox": true,
  "allowed_profiles": ["konishi", "ashton-laval"],
  "max_session_duration_secs": 3600,
  "require_audit_log": true,
  "require_parent_attestation": true
}
```

```bash
gleisner verify --policy policy.json .gleisner/attestation-*.json
```

All rules are opt-in. Absent fields are skipped, not failed.

## Architecture

```
                 +--────────────+     +──────────────+
                 | gleisner-cli |     | gleisner-tui |
                 +──────┬───────+     +──────┬───────+
                        |                    |
          +----------+--+--------------------+--+----------+
          v          v            v              v          v
    +-----------+ +----------+ +-----------+ +----------+ +--------+
    |   polis   | | introdus | |  lacerta  | | bridger  | | scapes |
    | (sandbox) | | (attest) | | (verify)  | |  (SBOM)  | |(events)|
    +-----------+ +----------+ +-----------+ +----------+ +--------+
          |
    +---------------+
    | sandbox-init  |  Landlock trampoline (inside bwrap)
    +---------------+
```

| Crate | Role |
|-------|------|
| `gleisner-cli` | CLI: `wrap`, `record`, `verify`, `inspect`, `diff`, `sbom`, `learn` |
| `gleisner-tui` | Interactive TUI with security dashboard, slash commands, attestation recording |
| `gleisner-polis` | Sandbox: bubblewrap, Landlock V7, cgroups/rlimits, inotify, pasta networking, profile learning |
| `gleisner-introdus` | Attestation: in-toto v1 statements, ECDSA P-256 + Sigstore signing, chain linking |
| `gleisner-lacerta` | Verification: signature checking, digest verification, policy engine (JSON + WASM/OPA) |
| `gleisner-bridger` | SBOM: Cargo.lock parsing, CycloneDX 1.5 JSON |
| `gleisner-scapes` | Events: tokio broadcast bus, JSONL audit writer, session recorder |
| `gleisner-sandbox-init` | Trampoline: applies Landlock rules inside bubblewrap before exec |

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flows, crate responsibilities, design decisions |
| [docs/SECURITY.md](docs/SECURITY.md) | Cryptographic design, key management, policy engine, hardening checklist |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat actors, attack surfaces, LACERTA scenarios, mitigations matrix |
| [docs/RUST_PATTERNS.md](docs/RUST_PATTERNS.md) | Rust patterns and idioms in the codebase (learning guide) |

## Contributing

Before submitting a PR:

1. Run the full lint and test suite:
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
2. Format: `cargo fmt --all`
3. Audit: `cargo deny check`
4. No `unsafe` -- the workspace enforces `unsafe_code = "forbid"`

All dependency versions live in the root `Cargo.toml` via workspace inheritance. Never duplicate a version in a member crate.

## License

Licensed under [Apache License, Version 2.0](LICENSE-APACHE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you shall be licensed under the Apache-2.0 license, without any additional terms or conditions.
