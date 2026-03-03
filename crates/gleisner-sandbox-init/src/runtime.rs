//! Container runtime implementation.
//!
//! Creates Linux namespaces, sets up bind mounts with `pivot_root`,
//! applies Landlock restrictions, and exec's the inner command.

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use gleisner_polis::SandboxSpec;
use gleisner_polis::profile::PolicyDefault;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root};

/// Run the sandbox: set up namespaces, mounts, landlock, then exec.
pub(crate) fn run(spec: SandboxSpec) -> Result<(), String> {
    // ── 0. Die with parent — prevent orphaned sandboxes ──────────
    // Equivalent to bwrap's --die-with-parent: if our parent exits,
    // the kernel sends us SIGKILL.
    // SAFETY: prctl(PR_SET_PDEATHSIG) is a simple kernel call with no
    // memory-safety implications — it just sets the signal to deliver
    // when this process's parent terminates.
    unsafe {
        nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL);
    }

    // ── 0b. Rootless cgroup delegation ─────────────────────────────
    // Create a cgroup scope and move ourselves into it BEFORE unshare().
    // The kernel allows a process to migrate itself within a writable
    // cgroup hierarchy without CAP_SYS_ADMIN — it only blocks cross-process
    // migration. After unshare(), the new namespaced process inherits its
    // cgroup membership, so limits apply without any privilege escalation.
    let _cgroup_guard = if let Some(ref limits) = spec.resource_limits {
        match gleisner_polis::CgroupScope::create(limits) {
            Ok(scope) => {
                let pid = std::process::id();
                match scope.add_pid(pid) {
                    Ok(()) => {
                        eprintln!(
                            "gleisner-sandbox-init: cgroup limits applied (rootless, pid={pid})"
                        );
                        Some(scope)
                    }
                    Err(e) => {
                        eprintln!("gleisner-sandbox-init: cgroup add_pid failed (continuing): {e}");
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("gleisner-sandbox-init: cgroup creation failed (continuing): {e}");
                None
            }
        }
    } else {
        None
    };

    // ── 1. Create namespaces ──────────────────────────────────────
    let mut clone_flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS;
    if spec.process.pid_namespace {
        clone_flags |= CloneFlags::CLONE_NEWPID;
    }
    if !spec.use_external_netns && matches!(spec.network.default, PolicyDefault::Deny) {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }

    unshare(clone_flags).map_err(|e| format!("unshare failed: {e}"))?;
    eprintln!("gleisner-sandbox-init: namespaces created");

    // ── 2. Map UID/GID ────────────────────────────────────────────
    write_id_map("/proc/self/uid_map", spec.uid, spec.uid)?;
    fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| format!("failed to write setgroups: {e}"))?;
    write_id_map("/proc/self/gid_map", spec.gid, spec.gid)?;
    eprintln!(
        "gleisner-sandbox-init: uid/gid mapped ({} -> {})",
        spec.uid, spec.uid
    );

    // ── 3. Set up filesystem (bind mounts + pivot_root) ──────────
    setup_filesystem(&spec)?;
    eprintln!("gleisner-sandbox-init: filesystem ready");

    // ── 4. Apply Landlock ─────────────────────────────────────────
    if spec.enable_landlock {
        match gleisner_polis::apply_landlock(
            &spec.filesystem,
            &spec.network,
            &spec.project_dir,
            &spec.extra_rw_paths,
            false,
        ) {
            Ok(status) => {
                eprintln!(
                    "gleisner-sandbox-init: landlock {:?} (network={}, scope={}, audit={})",
                    status.enforcement,
                    status.network_enforced,
                    status.scope_enforced,
                    status.audit_log_enabled
                );
                if !status.skipped_paths.is_empty() {
                    eprintln!(
                        "gleisner-sandbox-init: skipped {} nonexistent paths",
                        status.skipped_paths.len()
                    );
                }
            }
            Err(e) => {
                eprintln!("gleisner-sandbox-init: landlock failed (continuing): {e}");
            }
        }
    } else {
        eprintln!("gleisner-sandbox-init: landlock disabled");
    }

    // ── 4b. Enforce no_new_privileges if Landlock didn't already ──
    // Landlock's restrict_self() sets PR_SET_NO_NEW_PRIVS automatically.
    // When Landlock is disabled, enforce it explicitly if the profile asks.
    if !spec.enable_landlock && spec.process.no_new_privileges {
        let ret = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret == 0 {
            eprintln!("gleisner-sandbox-init: no_new_privileges set");
        } else {
            eprintln!("gleisner-sandbox-init: failed to set no_new_privileges (continuing)");
        }
    }

    // ── 5. Set working directory ──────────────────────────────────
    chdir(&spec.work_dir).map_err(|e| format!("chdir to {}: {e}", spec.work_dir.display()))?;

    // ── 6. Exec the inner command ─────────────────────────────────
    if spec.inner_command.is_empty() {
        return Err("no inner command specified".to_owned());
    }

    let program = &spec.inner_command[0];
    let err = Command::new(program).args(&spec.inner_command[1..]).exec();

    Err(format!("failed to exec {program}: {err}"))
}

/// Set up the sandbox filesystem using bind mounts and `pivot_root`.
///
/// Creates a new root filesystem from scratch:
/// 1. Create a tmpfs as the new root
/// 2. Bind-mount all paths from the spec (4-phase ordering)
/// 3. Provide /proc and /dev
/// 4. `pivot_root` to the new root
fn setup_filesystem(spec: &SandboxSpec) -> Result<(), String> {
    let new_root = PathBuf::from("/tmp/.gleisner-root");
    let old_root = new_root.join("old_root");

    // Create new root tmpfs
    fs::create_dir_all(&new_root).map_err(|e| format!("failed to create new root: {e}"))?;

    // Make sure we have a private mount namespace
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("failed to make mounts private: {e}"))?;

    // Mount tmpfs as new root
    mount(
        Some("tmpfs"),
        &new_root,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=64k,mode=0755"),
    )
    .map_err(|e| format!("failed to mount tmpfs at new root: {e}"))?;

    // Create old_root mount point for pivot_root
    fs::create_dir_all(&old_root).map_err(|e| format!("failed to create old_root: {e}"))?;

    // ── Phase 1: Read-only bind mounts ───────────────────────────
    let home_dir = std::env::var("HOME").ok().map(PathBuf::from);
    let mut deferred_symlink_targets: Vec<PathBuf> = Vec::new();

    for path in &spec.filesystem.readonly_bind {
        if !path.exists() {
            continue;
        }
        bind_mount(path, &new_root, MsFlags::MS_RDONLY)?;

        // Collect resolved symlink targets for deferred binding (Phase 3)
        let is_user_subdir = home_dir
            .as_ref()
            .is_some_and(|home| path.starts_with(home) && path != home);
        if is_user_subdir && path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_symlink() {
                        if let Ok(resolved) = fs::canonicalize(&entry_path) {
                            if resolved.exists() {
                                deferred_symlink_targets.push(resolved);
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Phase 2: Read-write bind mounts ──────────────────────────
    for path in &spec.filesystem.readwrite_bind {
        if path.exists() {
            bind_mount(path, &new_root, MsFlags::empty())?;
        }
    }
    for path in &spec.extra_rw_paths {
        if path.exists() {
            bind_mount(path, &new_root, MsFlags::empty())?;
        }
    }
    // Project directory is always read-write
    if spec.project_dir.exists() {
        bind_mount(&spec.project_dir, &new_root, MsFlags::empty())?;
    }

    // ── Phase 3: Symlink target binds ────────────────────────────
    for target in &deferred_symlink_targets {
        bind_mount(target, &new_root, MsFlags::MS_RDONLY)?;
    }

    // ── Phase 4: Deny paths + tmpfs ──────────────────────────────
    for path in &spec.filesystem.deny {
        if path.exists() {
            let target = new_root.join(path.strip_prefix("/").unwrap_or(path));
            if target.exists() {
                mount(
                    Some("tmpfs"),
                    &target,
                    Some("tmpfs"),
                    MsFlags::empty(),
                    Some("size=0,mode=0000"),
                )
                .map_err(|e| format!("tmpfs deny {}: {e}", path.display()))?;
            }
        }
    }
    for path in &spec.filesystem.tmpfs {
        let target = new_root.join(path.strip_prefix("/").unwrap_or(path));
        fs::create_dir_all(&target).ok();
        mount(
            Some("tmpfs"),
            &target,
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("tmpfs {}: {e}", path.display()))?;
    }

    // ── Provide /proc and /dev ───────────────────────────────────
    let new_proc = new_root.join("proc");
    fs::create_dir_all(&new_proc).ok();
    mount(
        Some("proc"),
        &new_proc,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| format!("mount /proc: {e}"))?;

    let new_dev = new_root.join("dev");
    fs::create_dir_all(&new_dev).ok();
    // Best effort: make /dev private before binding it
    mount(
        None::<&str>,
        "/dev",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .ok();
    bind_mount(Path::new("/dev"), &new_root, MsFlags::empty())?;

    // ── pivot_root ───────────────────────────────────────────────
    pivot_root(&new_root, &old_root).map_err(|e| format!("pivot_root failed: {e}"))?;

    chdir("/").map_err(|e| format!("chdir /: {e}"))?;

    umount2("/old_root", MntFlags::MNT_DETACH).map_err(|e| format!("unmount old_root: {e}"))?;
    fs::remove_dir("/old_root").ok();

    // ── Post-pivot hardening ─────────────────────────────────────
    // Ensure the new root has fully private mount propagation.
    // The pre-pivot MS_PRIVATE on "/" affected the old root; after
    // pivot_root, "/" is a new mount. Making it recursively private
    // prevents any mount events from leaking between sandbox and host.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("post-pivot mount propagation isolation failed: {e}"))?;

    Ok(())
}

/// Bind-mount a host path into the new root.
fn bind_mount(source: &Path, new_root: &Path, extra_flags: MsFlags) -> Result<(), String> {
    let relative = source.strip_prefix("/").unwrap_or(source);
    let target = new_root.join(relative);

    // Create mount point
    if source.is_dir() {
        fs::create_dir_all(&target).map_err(|e| format!("mkdir {}: {e}", target.display()))?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir parent of {}: {e}", target.display()))?;
        }
        fs::write(&target, b"")
            .map_err(|e| format!("create mount point {}: {e}", target.display()))?;
    }

    // Bind mount
    mount(
        Some(source),
        &target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        format!(
            "bind mount {} -> {}: {e}",
            source.display(),
            target.display()
        )
    })?;

    // Remount with extra flags (e.g., readonly)
    if !extra_flags.is_empty() {
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | extra_flags,
            None::<&str>,
        )
        .map_err(|e| format!("remount {}: {e}", target.display()))?;
    }

    Ok(())
}

/// Write a UID or GID map entry.
fn write_id_map(path: &str, inside: u32, outside: u32) -> Result<(), String> {
    fs::write(path, format!("{inside} {outside} 1\n"))
        .map_err(|e| format!("failed to write {path}: {e}"))
}
