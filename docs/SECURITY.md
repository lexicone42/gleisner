# Gleisner -- Security Guide

**Document version:** 0.2.0
**Date:** 2026-02-21
**Status:** Living document
**Companion:** This document covers practical security guidance. For threat
scenarios, attack surface analysis, and residual risk assessment, see
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## 1. Security Properties

Gleisner provides three categories of security guarantee when Claude Code
sessions are run via `gleisner wrap`, `gleisner record`, or
`gleisner-tui --sandbox`:

### 1.1 Attestation Integrity

Every session produces a cryptographically signed in-toto v1 attestation
bundle (`AttestationBundle`) containing:

- **Payload** -- canonical JSON of the `InTotoStatement` (subjects, provenance
  predicate, materials, timestamps, sandbox profile summary).
- **Signature** -- ECDSA P-256 over the payload bytes.
- **Verification material** -- either the public key (local signing) or a
  Fulcio certificate chain plus Rekor log ID (Sigstore keyless).

The attestation cannot be modified after signing without invalidating the
signature. Tampering with any field -- subjects, materials, timestamps, audit
log digest -- is detected at verification time.

### 1.2 Sandbox Isolation

The sandbox (`gleisner-polis`) enforces process-level isolation using Linux
kernel primitives. Claude Code runs inside a restricted environment where:

- Credential directories (`~/.ssh/`, `~/.aws/`, etc.) are replaced with empty
  tmpfs mounts and are invisible to the sandboxed process.
- Filesystem writes are confined to the project directory and designated temp
  paths.
- Network egress is restricted to an explicit domain allowlist.
- Process visibility is limited to the sandbox's own PID namespace.
- Resource consumption is bounded by cgroups v2 and rlimits (FSIZE, AS, NPROC, NOFILE).

These constraints are applied externally at the kernel level. Claude Code
cannot disable them from within the sandbox.

### 1.3 Audit Completeness

`gleisner-scapes` records a timestamped, sequenced JSONL event stream of every
observable action inside the sandbox. The SHA-256 digest of this log is embedded
in the attestation's `gleisner:auditLogDigest` field, cryptographically binding
the audit trail to the signed statement. Post-hoc verification confirms that the
log has not been truncated or modified.

---

## 2. Cryptographic Design

### 2.1 Signing Algorithm

Gleisner uses **ECDSA with the NIST P-256 curve and SHA-256** for all
attestation signatures. The implementation is provided by `aws-lc-rs`, a Rust
binding to AWS-LC -- a formally verified C cryptographic library maintained by
AWS.

| Property | Value |
|---|---|
| Algorithm | ECDSA P-256 (secp256r1) |
| Hash | SHA-256 |
| ASN.1 encoding | `ECDSA_P256_SHA256_ASN1` |
| Key format (private) | PKCS#8 DER wrapped in PEM |
| Key format (public) | SubjectPublicKeyInfo (SPKI) DER wrapped in PEM |
| Signature encoding | ASN.1 DER, then base64 |
| Crypto provider | `aws-lc-rs` 1.x |

### 2.2 Digest Algorithm

All content digests (subject artifacts, audit log, sandbox profile, CLAUDE.md)
use **SHA-256** via the `sha2` crate, producing 64-character lowercase hex
strings.

### 2.3 Payload Canonicalization

The attestation payload is the `serde_json::to_string()` serialization of the
`InTotoStatement`. This produces deterministic JSON (keys in struct field order,
no trailing whitespace). The signature is computed over the raw bytes of this
string. Verification re-parses the payload from the bundle and checks the
signature against those same bytes.

Consequence: re-serializing the payload with a different JSON library that
reorders keys will invalidate the signature. Always verify against the
`payload` field as stored in the bundle.

### 2.4 Sigstore Keyless Flow

When Sigstore is available, Gleisner uses the keyless signing flow:

1. The developer authenticates via OIDC (typically a GitHub or Google identity).
2. **Fulcio** issues a short-lived X.509 certificate (10-minute validity)
   binding the OIDC identity to an ephemeral signing key.
3. Gleisner signs the attestation payload with the ephemeral key.
4. The signature and certificate are recorded in **Rekor**, Sigstore's
   transparency log, producing an immutable log entry.
5. The `AttestationBundle` stores the certificate chain and Rekor log ID as
   `VerificationMaterial::Sigstore`.

At verification time, `gleisner-lacerta` extracts the public key from the leaf
certificate, verifies the ECDSA signature using the `sigstore` crate's
`CosignVerificationKey`, and logs the Rekor entry ID. Online Rekor verification
is recorded but not required (to support air-gapped verification).

---

## 3. Sandbox Layers

> For full implementation details, architecture diagrams, and design
> rationale, see
> [ARCHITECTURE.md § Sandbox Architecture](ARCHITECTURE.md#sandbox-architecture).

Gleisner implements defense in depth through five independent isolation layers,
each enforced by a different Linux kernel subsystem:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| 1 | User namespaces | Unprivileged isolation -- sandboxed process has no real host privileges |
| 2 | Bubblewrap (bwrap) | Mount namespace -- bind-mounts, tmpfs deny, PID namespace, `--die-with-parent` |
| 3 | Landlock LSM (V7) | Filesystem and network access control, IPC scope isolation, `PR_SET_NO_NEW_PRIVS`, kernel audit logging |
| 4 | Cgroups v2 + rlimits | Memory, CPU, PID, FD, and disk write limits (cgroups with rlimit fallback) |
| 5 | Network filtering | pasta + nftables/iptables for domain-level allowlisting |

Compromising one layer does not automatically compromise the others. For
example, even if bubblewrap's mount namespace is bypassed, Landlock
independently restricts filesystem access.

---

## 4. Key Management

### 4.1 Local Key Storage

When using local signing (the default for air-gapped or offline environments),
Gleisner auto-generates an ECDSA P-256 key pair on first use:

```
~/.config/gleisner/keys/local.pem    # PKCS#8 PEM private key
```

The path is determined by `directories::ProjectDirs` (XDG-compliant on Linux).
Fallback: `$HOME/.config/gleisner/keys/local.pem`.

File permissions are set to `0o600` (owner read/write only) on creation. The
key is loaded on subsequent runs without regeneration.

The corresponding public key is derived at signing time from the private key
and embedded in the `AttestationBundle` as `VerificationMaterial::LocalKey`.

### 4.2 Sigstore Keyless (Recommended)

Sigstore keyless signing eliminates persistent key material entirely:

- No private key is stored on disk.
- Identity is established via OIDC (GitHub, Google, or custom provider).
- Fulcio issues a 10-minute certificate, ensuring key compromise windows are
  minimal.
- Every signing event is recorded in the Rekor transparency log.

Use Sigstore keyless mode in any environment with internet access and OIDC
identity. It provides stronger guarantees against insider threats (LACERTA-007
in the threat model) because there is no long-lived key to steal.

### 4.3 Key Rotation Guidance

**Local keys:**

1. Delete `~/.config/gleisner/keys/local.pem`.
2. Run any `gleisner wrap` command -- a new key pair is generated automatically.
3. Update any verification pipelines or CI jobs that reference the old public
   key.
4. Previous attestation bundles remain verifiable using the public key embedded
   in their `verification_material` field.

**Sigstore keyless:** No rotation needed. Each session uses a fresh ephemeral
key. Rotate your OIDC identity (e.g., GitHub PAT) according to your
organization's credential rotation policy.

**When to rotate local keys:**

- If the key file may have been exposed (copied to an insecure location,
  included in a backup, visible in a container image layer).
- Periodically (e.g., quarterly) as a hygiene measure.
- When transitioning between environments or machines.

### 4.4 Extracting the Public Key

To extract the public key for use in verification pipelines:

```bash
# The public key is embedded in every attestation bundle.
# Extract it from any bundle signed with the key:
jq -r '.verification_material.public_key' attestation.json > pubkey.pem

# Or derive it from the private key using OpenSSL:
openssl ec -in ~/.config/gleisner/keys/local.pem -pubout -out pubkey.pem
```

---

## 5. Policy Engine

Gleisner's verification layer (`gleisner-lacerta`) evaluates attestations
against configurable policy rules. Two backends are supported:

### 5.1 Built-in JSON Policies

Create a JSON file with the rules you want to enforce. All fields are optional
-- absent rules are skipped, not failed.

```json
{
  "require_sandbox": true,
  "allowed_profiles": ["konishi", "ashton-laval"],
  "max_session_duration_secs": 3600,
  "require_audit_log": true,
  "allowed_builders": ["gleisner-cli/0.1.0"],
  "require_materials": true,
  "require_parent_attestation": false
}
```

| Rule | Type | Effect |
|---|---|---|
| `require_sandbox` | `bool` | Fail if the session was not sandboxed |
| `allowed_profiles` | `[string]` | Fail if the sandbox profile name is not in the list |
| `max_session_duration_secs` | `float` | Fail if the session exceeded this duration |
| `require_audit_log` | `bool` | Fail if no audit log digest is present |
| `allowed_builders` | `[string]` | Fail if the builder ID is not in the list |
| `require_materials` | `bool` | Fail if no materials (dependencies) are recorded |
| `require_parent_attestation` | `bool` | Fail if the attestation is not part of a chain |

Apply the policy during verification:

```bash
gleisner verify --policy policy.json attestation.json
```

### 5.2 WASM/OPA Policies

For complex policy logic, compile OPA/Rego policies to WASM and pass the
`.wasm` file to the verifier. Gleisner uses **Wasmtime 27** as the WASM
runtime, providing sandboxed policy execution. Module loading is implemented;
the full OPA ABI evaluation layer is in progress. The built-in JSON engine
covers immediate policy needs.

```bash
# Compile a Rego policy to WASM (requires OPA CLI):
opa build -t wasm -e 'data.gleisner.allow' policy.rego

# Extract the wasm file:
tar -xzf bundle.tar.gz /policy.wasm

# Use it with gleisner:
gleisner verify --policy policy.wasm attestation.json
```

Policy auto-detection: `gleisner-lacerta` inspects the file extension --
`.json` files load as `BuiltinPolicy`, `.wasm` files load as `WasmPolicy`.

### 5.3 Writing Custom Policies

The policy engine receives a `PolicyInput` struct extracted from the
attestation payload:

```rust
pub struct PolicyInput {
    pub sandboxed: Option<bool>,
    pub sandbox_profile: Option<String>,
    pub session_duration_secs: Option<f64>,
    pub has_audit_log: bool,
    pub builder_id: Option<String>,
    pub has_materials: bool,
    pub has_parent_attestation: bool,
    pub chain_length: Option<u64>,
}
```

For WASM policies, this struct is passed as JSON input. Your Rego policy should
evaluate `data.gleisner.allow` to `true` or `false` based on these fields.

---

## 6. Attestation Chain

> For the full chain algorithm (walk_chain pseudocode, digest indexing, cycle
> detection, mermaid diagrams), see
> [ARCHITECTURE.md § Chain Verification](ARCHITECTURE.md#chain-verification).

Each attestation records the SHA-256 digest of its parent's payload in the
`gleisner:chain.parentDigest` field, creating a verifiable history of Claude
Code sessions.

**Key security properties:**

- **Digest integrity** -- each link's `parentDigest` must match the actual
  `sha256(payload)` of the parent bundle.
- **Unsigned link detection** -- chain verification flags bundles with
  `VerificationMaterial::None` as failures.
- **Cycle detection** -- visited digest tracking prevents infinite loops
  on malformed chains.

**What "broken chain" means:** A gap in the attestation history -- an
intermediate bundle was deleted, a session was run without Gleisner, or the
chain directory is incomplete. Policies can enforce chain completeness via
`require_parent_attestation`.

**Payload digest vs. bundle digest:** The chain links on
`sha256(bundle.payload)`, not `sha256(entire file)`. This means re-signing
(key rotation) does not break the chain.

---

## 7. Supply Chain Hardening

Gleisner's own dependency tree is hardened through multiple mechanisms:

### 7.1 cargo-deny Configuration

The `deny.toml` at the repository root enforces:

| Check | Setting | Effect |
|---|---|---|
| Vulnerabilities | `vulnerability = "deny"` | CI fails on any crate with a known RUSTSEC advisory |
| Unmaintained | `unmaintained = "warn"` | Warning on crates flagged as unmaintained |
| Unknown registries | `unknown-registry = "deny"` | Blocks crates from non-crates.io registries |
| Unknown git sources | `unknown-git = "deny"` | Blocks git dependencies from unknown sources |
| Wildcards | `wildcards = "deny"` | Prevents `*` version specifications |
| Licenses | Allowlist | Only `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0` |

### 7.2 Lockfile Pinning

`Cargo.lock` is committed to the repository, pinning every transitive
dependency to an exact version. This ensures reproducible builds and prevents
supply chain attacks that exploit version ranges.

### 7.3 Workspace Dependency Inheritance

All dependency versions are centralized in the workspace `Cargo.toml` under
`[workspace.dependencies]`. Individual crate `Cargo.toml` files use
`dep.workspace = true` only. This prevents version drift across the five
internal crates and ensures a single point of audit for version updates.

### 7.4 `unsafe_code = "forbid"`

The workspace lint configuration sets `unsafe_code = "forbid"`, meaning no
`unsafe` block can appear in any Gleisner crate. This eliminates memory
corruption vulnerabilities in Gleisner's own code.

Note: this lint applies only to Gleisner's source. Dependencies such as
`aws-lc-rs`, `nix`, `wasmtime`, and `landlock` use `unsafe` internally
for FFI and kernel interfaces. These crates are widely audited but represent
a trust boundary.

### 7.5 Clippy Strictness

The workspace enables `clippy::all = "deny"`, `clippy::pedantic = "warn"`, and
`clippy::nursery = "warn"`, catching common correctness and performance issues
at compile time.

### 7.6 Dependency Audit Workflow

When updating dependencies:

```bash
# Check for known vulnerabilities and license violations:
cargo deny check

# Review what changed:
cargo update --dry-run

# After updating, verify the lockfile diff:
git diff Cargo.lock
```

---

## 8. Reporting Vulnerabilities

If you discover a security vulnerability in Gleisner, please report it
responsibly.

**Email:** security@gleisner.dev *(placeholder -- update with actual contact)*

**What to include:**

- Description of the vulnerability.
- Steps to reproduce.
- Affected version(s).
- Potential impact assessment.

**What to expect:**

- Acknowledgment within 48 hours.
- Assessment and severity classification within 7 days.
- Fix or mitigation timeline communicated after assessment.

**Scope:** This policy covers the Gleisner codebase and its documented security
properties. Issues in upstream dependencies (e.g., `aws-lc-rs`, `wasmtime`,
`sigstore`) should be reported to the respective projects, though we appreciate
a heads-up if the issue affects Gleisner's security guarantees.

Please do **not** file security vulnerabilities as public GitHub issues.

---

## 9. Security Checklist

Practical steps for users setting up Gleisner in a new environment.

### Initial Setup

- [ ] **Install bubblewrap.** Gleisner requires `bwrap` on PATH.
      (`apt install bubblewrap` / `pacman -S bubblewrap` / etc.)
- [ ] **Install passt** (for network filtering via pasta).
      (`apt install passt` / `pacman -S passt` / `emerge net-misc/passt`)
- [ ] **Verify kernel version.** Landlock requires Linux 5.13+.
      Run `uname -r` to check.
- [ ] **Verify cgroups v2.** Check that `/sys/fs/cgroup` is the unified
      hierarchy. Run `mount | grep cgroup2`.
- [ ] **Use `gleisner wrap` or `gleisner-tui --sandbox`, never bare `claude`.**
      Gleisner's protections are opt-in. Running `claude` directly bypasses all
      sandboxing and attestation.

### Key Management

- [ ] **Prefer Sigstore keyless** in connected environments. It eliminates
      persistent key material and provides transparency logging.
- [ ] **Verify key file permissions** if using local signing. The file at
      `~/.config/gleisner/keys/local.pem` must be `0600`.
      Run `stat -c '%a' ~/.config/gleisner/keys/local.pem`.
- [ ] **Never commit signing keys** to version control. Add
      `*.pem` to `.gitignore` if keys are anywhere near the repository.
- [ ] **Back up local keys securely** if attestation continuity matters (e.g.,
      for CI verification). Use encrypted storage or a secrets manager.

### Sandbox Profiles

- [ ] **Start with the `ashton-laval` profile** and relax only as needed.
- [ ] **Review the `allow_domains` list.** Every allowed domain is a potential
      exfiltration channel. Minimize to what is actually required (typically
      `api.anthropic.com` plus package registries).
- [ ] **Set `allow_dns: false`** in high-security environments to prevent DNS
      tunneling. Pre-resolve required domains or use a local DNS proxy.
- [ ] **Review `readwrite_bind` paths.** Only the project directory and temp
      paths should be writable.
- [ ] **Set resource limits** (`max_memory_mb`, `max_pids`, `max_cpu_percent`)
      to prevent resource exhaustion.

### Verification

- [ ] **Verify attestations before trusting session output.**
      Run `gleisner verify attestation.json`.
- [ ] **Enable chain verification** (`--check-chain`) to detect gaps in the
      attestation history.
- [ ] **Use policy files** to codify your organization's requirements (require
      sandbox, require audit log, allowed profiles, etc.).
- [ ] **Check audit log integrity.** Pass `--audit-log <path>` to verify the
      log digest matches the attestation.
- [ ] **Check subject digests.** Pass `--base-dir <path>` to verify that output
      file hashes match what the attestation claims.

### CI/CD Integration

- [ ] **Store the public key** (or use Sigstore) in your CI environment for
      automated verification.
- [ ] **Fail the pipeline** if `gleisner verify` reports any `Fail` outcomes.
- [ ] **Archive attestation bundles** alongside build artifacts for audit trails.
- [ ] **Run `cargo deny check`** in CI to catch dependency issues before they
      reach production.

### Ongoing

- [ ] **Keep Gleisner updated.** Dependency updates may include security fixes.
- [ ] **Review SBOM diffs** (`gleisner-bridger` output) after Claude Code
      sessions to audit newly introduced dependencies.
- [ ] **Monitor the audit log** (`gleisner-scapes` JSONL) for unexpected
      commands, especially `curl`, `wget`, `nc`, or any command targeting
      credential paths.
- [ ] **Rotate local signing keys** periodically (see Section 4.3).
- [ ] **Re-read the [threat model](THREAT_MODEL.md)** when Gleisner is
      updated -- new features may introduce new attack surface.
