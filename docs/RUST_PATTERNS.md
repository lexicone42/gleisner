# Rust Patterns in the Gleisner Codebase

This document walks through notable Rust patterns found in Gleisner, a supply-chain
attestation tool for sandboxed Claude Code sessions. Each section shows a real pattern
from the codebase, explains why it exists, and links to relevant Rust documentation.

If you are learning Rust, these patterns represent practical, production-quality
idioms -- not textbook exercises. They solve real problems.

---

## Table of Contents

1. [Workspace Dependency Inheritance](#1-workspace-dependency-inheritance)
2. [Serde Customization](#2-serde-customization)
3. [Error Handling with thiserror](#3-error-handling-with-thiserror)
4. [The let-else Pattern](#4-the-let-else-pattern)
5. [Option Chaining for JSON Navigation](#5-option-chaining-for-json-navigation)
6. [Trait Objects for Extensibility](#6-trait-objects-for-extensibility)
7. [Async Orchestration](#7-async-orchestration)
8. [Drop Guards for Resource Cleanup](#8-drop-guards-for-resource-cleanup)
9. [Clippy Pedantic as a Teaching Tool](#9-clippy-pedantic-as-a-teaching-tool)
10. [The Builder-ish Config Pattern](#10-the-builder-ish-config-pattern)

---

## 1. Workspace Dependency Inheritance

**What it is:** Centralizing all dependency versions in the root `Cargo.toml` so
that individual crates never specify version numbers themselves.

**Why it matters:** In a multi-crate workspace, you do not want `serde = "1.0.193"`
in one crate and `serde = "1.0.197"` in another. Version drift causes confusing
build failures and bloated binaries. Workspace inheritance eliminates this class of
bug entirely.

### Root `Cargo.toml`

```toml
[workspace]
resolver = "3"
members = ["crates/*"]

# ── ALL versions go here ──
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
sha2 = "0.10"
# ... every dependency listed once, with features

# ── ALL lint config goes here ──
[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
```

### Member crate `Cargo.toml` (e.g. `gleisner-lacerta`)

```toml
[package]
name = "gleisner-lacerta"
version = "0.1.0"
edition.workspace = true        # inherits "2024"
rust-version.workspace = true   # inherits "1.85"
license.workspace = true        # inherits "Apache-2.0"

[dependencies]
serde.workspace = true          # no version here -- inherited
serde_json.workspace = true
thiserror.workspace = true

[lints]
workspace = true                # inherits ALL lint configuration
```

Notice the member crate has **zero version numbers** and **zero lint rules**. It just
says `.workspace = true` for everything. This means upgrading a dependency is a
one-line change in the root, not a six-file grep-and-replace.

**Rust docs:** [Cargo Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-dependencies-table)

---

## 2. Serde Customization

**What it is:** Fine-grained control over how Rust structs serialize to JSON (and
sometimes deserialize from JSON). Serde's derive macros accept attributes that
rename fields, skip optional values, and tag enum variants.

**Why it matters:** Gleisner generates attestation bundles that must conform to the
SLSA provenance specification and the in-toto statement format. These specs mandate
`camelCase` field names, specific tag values, and optional fields that should be
absent (not `null`) when empty.

### `rename_all` for case conventions

From `provenance.rs`:

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GleisnerProvenance {
    pub build_type: &'static str,       // serializes as "buildType"
    pub builder: Builder,
    pub invocation: Invocation,
    pub metadata: BuildMetadata,
    pub materials: Vec<Material>,
    // ...
}
```

Rust convention is `snake_case` for fields. JSON specs typically use `camelCase`.
The `rename_all` attribute bridges this gap at zero runtime cost -- the renaming
happens at compile time in the generated serialization code.

### Custom field names with `rename`

```rust
/// SHA-256 digest of the full JSONL audit log.
#[serde(rename = "gleisner:auditLogDigest")]
pub audit_log_digest: String,

/// Digest of the parent attestation's payload.
#[serde(rename = "gleisner:chain", skip_serializing_if = "Option::is_none")]
pub chain: Option<ChainMetadata>,
```

The SLSA spec uses namespaced extension fields like `gleisner:chain`. You cannot
express colons in a Rust identifier, so `rename` maps the Rust name to the wire
name. Combined with `skip_serializing_if`, the `chain` field is entirely absent
from JSON when `None` -- not `"gleisner:chain": null`.

### `&'static str` for constant-value fields

```rust
pub struct ClaudeCodeEnvironment {
    /// Always `"claude-code"`.
    pub tool: &'static str,
    // ...
}
```

This field is always the string `"claude-code"`. Using `&'static str` instead of
`String` avoids a heap allocation for what is essentially a constant. You construct
it as `tool: "claude-code"` -- the string lives in the binary's read-only data
segment.

### Tagged enum serialization

From `bundle.rs`:

```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VerificationMaterial {
    #[serde(rename = "sigstore")]
    Sigstore {
        certificate_chain: String,
        rekor_log_id: String,
    },
    #[serde(rename = "local_key")]
    LocalKey {
        public_key: String,
    },
    #[serde(rename = "none")]
    None,
}
```

Without `#[serde(tag = "type")]`, serde would use externally tagged representation:
`{"Sigstore": {"certificate_chain": "..."}}`. With the tag attribute, it produces
internally tagged JSON: `{"type": "sigstore", "certificate_chain": "..."}`. This is
what most JSON APIs expect.

### The Serialize-only vs Serialize+Deserialize gap

Notice that `GleisnerProvenance` derives only `Serialize`, while `AttestationBundle`
derives both `Serialize, Deserialize`. This is deliberate:

- **Provenance structs** are *produced* by Gleisner and written into attestation
  bundles. They are never parsed back into typed structs -- when reading them back,
  the code uses `serde_json::Value` for flexible navigation (see pattern 5).
- **Bundle structs** must round-trip: write to disk, read from disk for verification.

Only deriving what you need avoids requiring `Deserialize` implementations for types
like `&'static str` fields that cannot be deserialized from arbitrary input.

**Rust docs:** [Serde attributes](https://serde.rs/attributes.html), [Enum representations](https://serde.rs/enum-representations.html)

---

## 3. Error Handling with thiserror

**What it is:** Using the `thiserror` crate to derive `std::error::Error` on enum
types, with automatic `From` conversions that enable the `?` operator.

**Why it matters:** Rust does not have exceptions. Errors are values, and they need
explicit types. Writing `impl Display` and `impl Error` and `impl From<X>` by hand
for every error variant is tedious. `thiserror` generates all of it from attributes.

From `error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("failed to serialize attestation: {0}")]
    SerializeError(#[from] serde_json::Error),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("git state capture failed: {0}")]
    GitError(String),

    #[error("key error: {0}")]
    KeyError(String),

    #[error("attestation I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
```

Key details:

- **`#[error("...")]`** generates the `Display` implementation. The `{0}` refers to
  the first field of the variant.
- **`#[from]`** generates `impl From<serde_json::Error> for AttestationError` and
  `impl From<std::io::Error> for AttestationError`. This is what makes `?` work.
- Variants without `#[from]` (like `SigningFailed(String)`) require manual
  construction -- you call
  `AttestationError::SigningFailed("reason".to_owned())` explicitly.

### How `?` flows through the code

In `signer.rs`, the `?` operator uses these conversions implicitly:

```rust
async fn sign(
    &self,
    statement: &InTotoStatement,
) -> Result<AttestationBundle, AttestationError> {
    let payload = serde_json::to_string(statement)?;
    //            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ returns serde_json::Error
    //            ? converts it to AttestationError::SerializeError via #[from]

    let sig = self.key_pair
        .sign(&self.rng, payload.as_bytes())
        .map_err(|e| AttestationError::SigningFailed(
            format!("ECDSA sign failed: {e}")
        ))?;
    //  ^^^^^ no #[from] for aws_lc_rs errors, so map_err is used

    Ok(AttestationBundle { /* ... */ })
}
```

The pattern: use `#[from]` for errors you convert frequently, and `map_err` for
one-off conversions where a `From` impl would be misleading.

**Rust docs:** [thiserror crate](https://docs.rs/thiserror), [The `?` operator](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html#a-shortcut-for-propagating-errors-the--operator)

---

## 4. The let-else Pattern

**What it is:** `let PATTERN = EXPRESSION else { DIVERGE };` -- a way to
destructure a value and bail out (return, continue, break) if the pattern does not
match.

**Why it matters:** Before `let-else`, you would write nested `if let` or a
`match` that pushes your happy path deeper with each check. `let-else` keeps the
happy path flat. In Rust 2024, Clippy's `manual_let_else` lint (enabled in this
codebase) warns you to use it whenever applicable.

From `chain.rs`, in the `find_latest_attestation` function:

```rust
let Ok(data) = std::fs::read_to_string(&path) else {
    continue;
};
let Ok(bundle) = serde_json::from_str::<AttestationBundle>(&data) else {
    continue;
};
```

This is inside a `for` loop scanning attestation files. If a file cannot be read or
parsed, we skip it and move on. Without `let-else`, this would be:

```rust
// The old way -- nested and harder to read
let data = match std::fs::read_to_string(&path) {
    Ok(d) => d,
    Err(_) => continue,
};
let bundle = match serde_json::from_str::<AttestationBundle>(&data) {
    Ok(b) => b,
    Err(_) => continue,
};
```

Same logic, more visual noise.

Another example from `netfilter.rs`, in `find_child_pid`:

```rust
let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
    return false;
};
```

```rust
let Ok(pid) = pid_str.parse::<u32>() else {
    continue;
};
let Ok(status) = std::fs::read_to_string(&status_path) else {
    continue;
};
```

The `else` block must diverge -- it must `return`, `continue`, `break`, or call a
diverging function like `panic!()`. This is enforced by the compiler.

**Rust docs:** [let-else statements](https://doc.rust-lang.org/rust-by-example/flow_control/let_else.html)

---

## 5. Option Chaining for JSON Navigation

**What it is:** Using `.get()?.as_str()?` chains to navigate untyped
`serde_json::Value` trees, leveraging `Option`'s `?` propagation in functions
that return `Option`.

**Why it matters:** Attestation payloads are nested JSON objects with optional
fields at every level. You could deserialize into a struct, but that requires
knowing the exact schema and fails on any unexpected field. Option chaining lets
you extract specific values from deeply nested JSON without committing to a full
schema.

From `chain.rs`:

```rust
fn extract_parent_digest(bundle: &AttestationBundle) -> Option<String> {
    let payload: serde_json::Value = serde_json::from_str(&bundle.payload).ok()?;
    payload
        .get("predicate")?
        .get("gleisner:chain")?
        .get("parentDigest")?
        .as_str()
        .map(String::from)
}
```

This navigates `payload.predicate["gleisner:chain"].parentDigest` and returns
`None` at any point if a key is missing or the value is not a string. The `?`
after each `.get()` short-circuits: if the key does not exist, `get()` returns
`None`, and `?` immediately returns `None` from the function.

The `extract_finished_on` function chains even deeper:

```rust
fn extract_finished_on(bundle: &AttestationBundle) -> Option<DateTime<Utc>> {
    let payload: serde_json::Value = serde_json::from_str(&bundle.payload).ok()?;
    let ts = payload
        .get("predicate")?
        .get("metadata")?
        .get("buildFinishedOn")?
        .as_str()?;
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}
```

And from `policy.rs`, the `extract_policy_input` function shows `.and_then()`
chaining when `?` is not available (because the function returns a struct, not
`Option`):

```rust
let sandboxed = predicate
    .and_then(|p| p.get("invocation"))
    .and_then(|i| i.get("environment"))
    .and_then(|e| e.get("sandboxed"))
    .and_then(serde_json::Value::as_bool);

let has_audit_log = predicate
    .and_then(|p| p.get("gleisner:auditLogDigest"))
    .and_then(|d| d.as_str())
    .is_some_and(|s| !s.is_empty());
```

Notice `is_some_and()` at the end -- it unwraps an `Option<&str>` and tests the
inner value, returning `false` if the `Option` is `None`. This avoids a
`.map(...).unwrap_or(false)` chain.

**Rust docs:** [Option](https://doc.rust-lang.org/std/option/enum.Option.html), [serde_json::Value](https://docs.rs/serde_json/latest/serde_json/enum.Value.html)

---

## 6. Trait Objects for Extensibility

**What it is:** Using `dyn Trait` behind `Box` to accept different
implementations of a behavior at runtime, without the caller knowing which
concrete type is in use.

**Why it matters:** Gleisner supports multiple signing backends (local ECDSA,
Sigstore keyless) and multiple policy engines (builtin JSON rules, WASM/Rego
policies). Trait objects let the orchestration code work with any implementation
through a shared interface.

### The `Signer` trait

From `signer.rs`:

```rust
#[expect(async_fn_in_trait, reason = "internal trait -- all impls are Send")]
pub trait Signer: Send + Sync {
    async fn sign(
        &self,
        statement: &InTotoStatement,
    ) -> Result<AttestationBundle, AttestationError>;

    fn description(&self) -> &'static str;
}
```

Key details:

- **`Send + Sync` bounds** are required for the trait to be used across async task
  boundaries. Without them, you cannot hold a `&dyn Signer` across an `.await`.
- **`async fn` in traits** is stable in Rust 2024. The `#[expect(...)]` attribute
  suppresses the lint that warns about it (the lint exists because `async fn` in
  public traits has object-safety implications, but this trait is internal).
- The return type `&'static str` for `description()` avoids allocating a `String`
  for what is always a compile-time-known value.

### The `PolicyEngine` trait

From `policy.rs`:

```rust
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        input: &PolicyInput,
    ) -> Result<Vec<PolicyResult>, VerificationError>;
}
```

And its use in `verify.rs`:

```rust
pub struct VerifyConfig {
    pub policies: Vec<Box<dyn PolicyEngine>>,
    // ...
}
```

`Vec<Box<dyn PolicyEngine>>` means: a list of heap-allocated objects that each
implement `PolicyEngine`, but may be different concrete types. One entry might be a
`BuiltinPolicy`, another a `WasmPolicy`. The verifier iterates over them uniformly:

```rust
for engine in &self.config.policies {
    match engine.evaluate(&input) {
        Ok(results) => { /* ... */ }
        Err(e) => { /* ... */ }
    }
}
```

The `load_policy` function shows how trait objects are created:

```rust
pub fn load_policy(path: &Path) -> Result<Box<dyn PolicyEngine>, VerificationError> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "wasm" {
        let p = crate::policy_wasm::WasmPolicy::from_file(path)?;
        Ok(Box::new(p))  // WasmPolicy -> Box<dyn PolicyEngine>
    } else {
        let p = BuiltinPolicy::from_file(path)?;
        Ok(Box::new(p))  // BuiltinPolicy -> Box<dyn PolicyEngine>
    }
}
```

The caller does not care which type it gets back. It only knows it can call
`.evaluate()`.

**Rust docs:** [Trait objects](https://doc.rust-lang.org/book/ch18-02-trait-objects.html), [Object safety](https://doc.rust-lang.org/reference/items/traits.html#object-safety)

---

## 7. Async Orchestration

**What it is:** Using `tokio::spawn`, `CancellationToken`, and join handles to run
multiple concurrent tasks with structured shutdown.

**Why it matters:** The `record` command runs multiple things simultaneously: a
sandboxed Claude Code process, a filesystem monitor (inotify), a process monitor
(`/proc` scanner), an audit log writer, and a session recorder. All of these must
start concurrently, run for the session duration, and shut down cleanly when the
child process exits.

From `record.rs`:

### Spawning concurrent tasks

```rust
let cancel = CancellationToken::new();
let mut monitor_handles = Vec::new();

if !args.no_fs_monitor {
    let fs_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) =
            gleisner_polis::fs_monitor::run_fs_monitor(fs_config, fs_publisher, fs_cancel).await
        {
            tracing::warn!(error = %e, "filesystem monitor failed");
        }
    });
    monitor_handles.push(handle);
}
```

Each `tokio::spawn` returns a `JoinHandle` that is stored for later. The
`CancellationToken` is cloned for each task -- all clones share the same
cancellation state.

### Awaiting the child, then cancelling monitors

```rust
// 8. Await child exit
let status = child.wait().await
    .map_err(|e| eyre!("failed to wait on sandboxed process: {e}"))?;

// 9. Cancel monitors and await their completion
cancel.cancel();
for handle in monitor_handles {
    let _ = handle.await;
}
```

This is structured concurrency: the monitors run while the child runs, and when
the child exits, all monitors are cancelled and joined. No orphaned tasks.

### Dropping publishers to signal completion

```rust
drop(publisher);
drop(bus);
let recorder_output = recorder_handle.await
    .map_err(|e| eyre!("recorder task panicked: {e}"))?;
writer_handle.await
    .map_err(|e| eyre!("audit writer panicked: {e}"))?;
```

The event bus uses broadcast channels. Dropping the publisher (sender) causes all
subscribers (receivers) to get a "channel closed" signal, which lets them flush
and exit. The explicit `drop()` calls make the ordering visible to the reader.

**Rust docs:** [tokio::spawn](https://docs.rs/tokio/latest/tokio/fn.spawn.html), [CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)

---

## 8. Drop Guards for Resource Cleanup

**What it is:** Implementing the `Drop` trait to ensure resources are released
when a value goes out of scope, and using explicit `drop()` calls when cleanup
must happen at a specific point.

**Why it matters:** Gleisner manages external processes (namespace holder) that
must be killed when the session ends. If the program calls
`std::process::exit()`, Rust skips destructors. Without careful ordering, child
processes would leak.

### The `Drop` implementation

From `netfilter.rs`:

```rust
impl Drop for NamespaceHandle {
    fn drop(&mut self) {
        debug!(holder_pid = self.holder_pid, "destroying network namespace");
        if let Err(e) = self.holder.kill() {
            warn!(
                holder_pid = self.holder_pid,
                error = %e,
                "failed to kill namespace holder — namespace may leak"
            );
        }
        let _ = self.holder.wait();
    }
}
```

Notice the two error-handling approaches. `kill()` logs a warning on failure
because a leaked namespace holder is a real problem worth surfacing. `wait()`
uses `let _ =` to discard its result -- in a destructor you cannot propagate
errors, and `let _ =` explicitly satisfies the `#[must_use]` lint.

Note: `TapHandle` (pasta) does not need a `Drop` implementation because pasta
configures the namespace and exits -- there is no long-running child process.

### Explicit `drop()` before `exit()`

From `record.rs`:

```rust
// Drop network handles before exit() -- exit() skips destructors,
// which would leak namespace holder processes.
drop(tap);
drop(ns);
drop(cgroup_scope);

std::process::exit(exit_code);
```

`std::process::exit()` terminates immediately without running destructors. If
the code just called `exit()`, the `NamespaceHandle` would
never be dropped, leaving orphan processes. The explicit `drop()` calls before
`exit()` ensure cleanup happens. The comment explains *why* -- this is the kind
of code that looks wrong without the comment.

**Rust docs:** [Drop trait](https://doc.rust-lang.org/std/ops/trait.Drop.html), [std::process::exit](https://doc.rust-lang.org/std/process/fn.exit.html)

---

## 9. Clippy Pedantic as a Teaching Tool

**What it is:** Enabling Clippy's `pedantic` and `nursery` lint groups at the
workspace level to enforce idiomatic Rust patterns.

**Why it matters:** Clippy pedantic catches patterns that are *legal* but
*suboptimal*. For a learner, it acts as a persistent code reviewer that teaches
you Rust idioms. Gleisner enables it at `warn` level (not `deny`) so it guides
without blocking.

From the workspace `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"              # no unsafe anywhere
missing_docs = "warn"               # encourage documentation
unreachable_pub = "warn"            # don't pub what doesn't need to be pub
unused_qualifications = "warn"      # remove redundant path qualifiers
unsafe_op_in_unsafe_fn = "deny"     # require unsafe blocks inside unsafe fn

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }

# Pedantic overrides -- allow specific lints that are too noisy
module_name_repetitions = "allow"   # e.g., AttestationError in attestation module
must_use_candidate = "allow"        # too many false positives
missing_errors_doc = "allow"        # not every Result fn needs error docs

# Enforce modern patterns
manual_let_else = "warn"            # use let-else instead of match
uninlined_format_args = "warn"      # use {x} not {}, x
semicolon_if_nothing_returned = "warn"
cloned_instead_of_copied = "warn"   # use .copied() for Copy types
redundant_clone = "warn"            # remove unnecessary .clone()
needless_pass_by_value = "warn"     # pass by reference when possible
flat_map_option = "warn"            # use .flatten() instead of .filter_map(|x| x)
from_iter_instead_of_collect = "warn"
implicit_clone = "warn"             # prefer explicit .clone() or .to_owned()
inefficient_to_string = "warn"      # use write! instead of format! for Display
```

Some specific lints and what they teach:

| Lint | What it catches | What it teaches |
|------|----------------|-----------------|
| `manual_let_else` | `match x { Ok(v) => v, Err(_) => return }` | Use `let Ok(v) = x else { return };` |
| `uninlined_format_args` | `format!("{}", x)` | Use `format!("{x}")` (Rust 2021+) |
| `cloned_instead_of_copied` | `.cloned()` on `Copy` types | `.copied()` is more precise |
| `needless_pass_by_value` | `fn f(s: String)` when `&str` suffices | Pass by reference when you don't need ownership |
| `redundant_clone` | `.clone()` on a value that is not used again | Remove the clone |
| `flat_map_option` | `.filter_map(|x| x)` | Use `.flatten()` |
| `implicit_clone` | `x.to_owned()` where `.clone()` is clearer | Prefer explicit `.clone()` |
| `inefficient_to_string` | `format!("{x}")` on Display types | Use `write!` or `x.to_string()` directly |

The `#[expect(...)]` attribute (Rust 2024) is used in the codebase to acknowledge
specific lint violations with a reason:

```rust
#[expect(async_fn_in_trait, reason = "internal trait -- all impls are Send")]
pub trait Signer: Send + Sync { /* ... */ }
```

```rust
#[expect(
    clippy::cast_precision_loss,
    reason = "session durations don't approach 2^52 ms"
)]
Some(dur.num_milliseconds() as f64 / 1000.0)
```

`#[expect]` is better than `#[allow]` because it warns you when the suppressed
lint is *no longer triggered* -- meaning the code changed and the suppression is
stale.

**Rust docs:** [Clippy lints list](https://rust-lang.github.io/rust-clippy/master/), [The expect attribute](https://doc.rust-lang.org/reference/attributes/diagnostics.html#the-expect-attribute)

---

## 10. The Builder-ish Config Pattern

**What it is:** Using a struct with `Default` derive and `Option` fields as
configuration, combined with struct update syntax (`..Default::default()`).

**Why it matters:** Gleisner's `VerifyConfig` has many optional settings (public
key override, audit log path, policy engines, chain verification). A full builder
pattern with `.set_x().set_y().build()` would work but adds boilerplate. The
`Default` + struct literal approach gives the same ergonomics with less code.

From `verify.rs`:

```rust
#[derive(Default)]
pub struct VerifyConfig {
    pub public_key_override: Option<PathBuf>,
    pub audit_log_path: Option<PathBuf>,
    pub check_files_base: Option<PathBuf>,
    pub policies: Vec<Box<dyn PolicyEngine>>,
    pub check_chain: bool,
    pub chain_dir: Option<PathBuf>,
}
```

Usage in tests shows the ergonomics:

```rust
// Minimal config -- everything defaults
let verifier = Verifier::new(VerifyConfig::default());

// Override just what you need
let verifier = Verifier::new(VerifyConfig {
    policies: vec![Box::new(policy)],
    ..Default::default()  // everything else stays default
});

// Override multiple fields
let verifier = Verifier::new(VerifyConfig {
    public_key_override: Some(key_file.path().to_path_buf()),
    check_chain: true,
    ..Default::default()
});
```

The `..Default::default()` syntax fills in all unspecified fields with their
default values. For `Option` fields, that is `None`. For `Vec`, that is `vec![]`.
For `bool`, that is `false`.

Notice also the `BuiltinPolicy` struct in `policy.rs`, which uses the same pattern
for its rule configuration:

```rust
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BuiltinPolicy {
    pub require_sandbox: Option<bool>,
    pub allowed_profiles: Option<Vec<String>>,
    pub max_session_duration_secs: Option<f64>,
    pub require_audit_log: Option<bool>,
    pub allowed_builders: Option<Vec<String>>,
    pub require_materials: Option<bool>,
    pub require_parent_attestation: Option<bool>,
}
```

All `Option` fields mean "absent = don't check this rule." An empty
`BuiltinPolicy::default()` passes everything, and you opt into strictness by
setting specific fields. This is the "open by default, restrictive by
configuration" pattern.

**Rust docs:** [Default trait](https://doc.rust-lang.org/std/default/trait.Default.html), [Struct update syntax](https://doc.rust-lang.org/book/ch05-01-defining-structs.html#creating-instances-from-other-instances-with-struct-update-syntax)

---

## Further Reading

- [The Rust Book](https://doc.rust-lang.org/book/) -- start here if you are new
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/) -- learn by doing
- [The Cargo Book](https://doc.rust-lang.org/cargo/) -- workspace and dependency management
- [Serde documentation](https://serde.rs/) -- serialization framework
- [Tokio tutorial](https://tokio.rs/tokio/tutorial) -- async runtime
- [Clippy lint list](https://rust-lang.github.io/rust-clippy/master/) -- all available lints
