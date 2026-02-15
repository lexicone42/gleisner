# Gleisner -- Security Guide

**Document version:** 0.1.0
**Date:** 2026-02-14
**Status:** Living document
**Companion:** This document covers practical security guidance. For threat
scenarios, attack surface analysis, and residual risk assessment, see
[THREAT_MODEL.md](../THREAT_MODEL.md).

---

## 1. Security Properties

Gleisner provides three categories of security guarantee when Claude Code
sessions are run via `gleisner wrap`:

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
- Syscall surface is reduced via seccomp BPF profiles.
- Resource consumption is bounded by cgroups v2 limits.

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

Gleisner implements defense in depth through six independent isolation layers.
Each layer is enforced by a different Linux kernel subsystem, so compromising
one does not automatically compromise the others.

### Layer 1: User Namespaces

`gleisner-polis` creates unprivileged user namespaces via `clone(2)` with
`CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET`. The sandboxed
process sees itself as UID 0 inside the namespace but has no real privileges on
the host. PID namespace isolation means the process cannot see or signal host
processes.

### Layer 2: Bubblewrap (bwrap)

[Bubblewrap](https://github.com/containers/bubblewrap) constructs the mount
namespace. It bind-mounts only the paths declared in the sandbox profile:

- `readonly_bind` -- project-relevant paths visible read-only.
- `readwrite_bind` -- project directory and designated temp paths, writable.
- `deny` -- sensitive paths replaced with empty tmpfs (e.g., `~/.ssh/`,
  `~/.aws/`, `~/.config/gcloud/`).
- `tmpfs` -- ephemeral scratch space that does not persist.

Bubblewrap also sets `--die-with-parent` (sandbox dies if the parent exits)
and `--new-session` (prevents terminal signal injection).

### Layer 3: Landlock LSM

[Landlock](https://landlock.io/) provides fine-grained filesystem access
control at the kernel level. Even if bubblewrap's mount namespace is somehow
bypassed, Landlock rules independently restrict which paths the process can
read, write, or execute. Requires Linux 5.13+.

### Layer 4: Seccomp BPF

Optional seccomp BPF profiles filter the system calls available to the
sandboxed process. The `ProcessPolicy` in the sandbox profile can reference
a custom seccomp JSON profile. Additionally, `prctl(PR_SET_NO_NEW_PRIVS, 1)`
is set before `exec`, preventing SUID/SGID escalation.

### Layer 5: Cgroups v2

`gleisner-polis` creates a dedicated cgroup under
`/sys/fs/cgroup/gleisner-{uuid}/` and enforces:

| Control file | Profile field | Effect |
|---|---|---|
| `memory.max` | `max_memory_mb` | Hard memory limit |
| `cpu.max` | `max_cpu_percent` | CPU bandwidth cap |
| `pids.max` | `max_pids` | Fork bomb prevention |

The cgroup is automatically cleaned up on drop (processes moved to parent,
directory removed).

### Layer 6: Network Filtering

When the profile sets `network.default = "deny"` with `allow_domains`:

1. A user + network namespace pair is created via `unshare`.
2. **slirp4netns** provides a TAP device (`tap0`) inside the network namespace,
   giving the sandbox a private network stack (guest IP `10.0.2.100/24`,
   gateway `10.0.2.2`).
3. **nftables** (preferred) or **iptables** (fallback) rules are applied inside
   the namespace:
   - Default OUTPUT policy: DROP (blocks both IPv4 and IPv6 with nft).
   - Loopback traffic: ACCEPT.
   - DNS (UDP 53): ACCEPT only if `allow_dns: true`.
   - Allowed domains: resolved to IPs and explicitly permitted on ports 443/80.
4. Bubblewrap enters this pre-configured namespace via `nsenter` instead of
   creating its own with `--unshare-net`.

This architecture ensures that even if Claude Code spawns arbitrary subprocesses,
they inherit the filtered network namespace.

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
  "allowed_profiles": ["strict", "default"],
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
runtime, providing sandboxed policy execution.

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

### 6.1 How Chains Work

When multiple Gleisner sessions build on each other's output, each attestation
records the SHA-256 digest of its parent attestation's payload in the
`gleisner:chain.parentDigest` field. This creates a linked chain of attestations
where each session's provenance is connected to the session that produced its
inputs.

```
Session 3          Session 2          Session 1 (root)
+-----------+      +-----------+      +-----------+
| payload   |      | payload   |      | payload   |
| signature |      | signature |      | signature |
| chain:    |      | chain:    |      | chain:    |
|  parent = |----->|  parent = |----->|  (none)   |
|  sha256(2)|      |  sha256(1)|      |           |
+-----------+      +-----------+      +-----------+
```

### 6.2 Chain Verification

`gleisner-lacerta` walks the chain backwards from the newest attestation:

1. Load the bundle at the starting path.
2. Extract `gleisner:chain.parentDigest`.
3. Scan the chain directory for a bundle whose payload digest matches.
4. Repeat until no parent is found (chain root) or the parent is missing.

Verification checks:

- **Digest integrity:** Each link's `parentDigest` must match the actual
  `sha256(payload)` of the parent bundle. A mismatch produces:
  `"chain link N: parent digest mismatch"`.
- **Chain completeness:** If a `parentDigest` references a bundle that cannot
  be found in the chain directory, the verifier reports:
  `"chain link N: parent attestation not found (broken chain)"`.
- **Cycle detection:** The chain walker tracks visited payload digests in a
  `HashSet`. If a digest is encountered twice, the walk terminates with a
  warning, preventing infinite loops on cyclic chains.
- **Unsigned link detection:** Each chain entry tracks whether its bundle has
  `VerificationMaterial` other than `None`. If any link in the chain is
  unsigned, the verifier emits a failure:
  `"chain contains N unsigned link(s) (VerificationMaterial::None)"`.
- **Duplicate digest handling:** When building the digest index,
  `build_digest_index()` keeps the first file for each payload digest and
  logs a warning about duplicates, ensuring deterministic chain walking.

### 6.3 What "Broken Chain" Means

A broken chain means there is a gap in the attestation history. Possible causes:

- An intermediate attestation bundle was deleted or moved.
- A session was run without Gleisner (`claude` instead of `gleisner wrap`),
  producing no attestation for that step.
- The chain directory does not contain all relevant bundles.

A broken chain does not necessarily indicate an attack, but it means the
provenance of the current artifacts cannot be fully verified back to the root.
Policies can enforce chain completeness via `require_parent_attestation`.

### 6.4 Payload Digest vs. Bundle Digest

- **Payload digest** (`sha256(bundle.payload)`) -- the canonical identifier for
  an attestation in the chain. This is what `parentDigest` references. It covers
  the statement, subjects, materials, timestamps, and all provenance metadata.
- **Bundle digest** (`sha256(entire JSON file)`) -- covers payload + signature +
  verification material. Not used for chaining because the same logical
  attestation could be re-signed with a different key without changing its
  content.

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
- [ ] **Install slirp4netns** (for network filtering).
      (`apt install slirp4netns` / `pacman -S slirp4netns`)
- [ ] **Verify kernel version.** Landlock requires Linux 5.13+.
      Run `uname -r` to check.
- [ ] **Verify cgroups v2.** Check that `/sys/fs/cgroup` is the unified
      hierarchy. Run `mount | grep cgroup2`.
- [ ] **Use `gleisner wrap`, never bare `claude`.** Gleisner's protections are
      opt-in. Running `claude` directly bypasses all sandboxing and attestation.

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

- [ ] **Start with the `strict` profile** and relax only as needed.
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
- [ ] **Re-read the [threat model](../THREAT_MODEL.md)** when Gleisner is
      updated -- new features may introduce new attack surface.
