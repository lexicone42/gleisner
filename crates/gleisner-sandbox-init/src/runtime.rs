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
use nix::sys::resource::{Resource, setrlimit};
use nix::unistd::{chdir, pivot_root, sethostname};

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
    // User, mount, IPC (shared memory/semaphores), UTS (hostname).
    // CLONE_NEWTIME is included to isolate CLOCK_MONOTONIC/CLOCK_BOOTTIME
    // — must be combined with CLONE_NEWUSER in the same unshare() call
    // because time namespace creation requires owning a user namespace.
    //
    // The nix crate doesn't expose CLONE_NEWTIME in CloneFlags yet,
    // so we combine it via raw bits.
    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS;
    if spec.process.pid_namespace {
        flags |= CloneFlags::CLONE_NEWPID;
    }
    if !spec.use_external_netns && matches!(spec.network.default, PolicyDefault::Deny) {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    // Add CLONE_NEWTIME via raw bits (not in nix::sched::CloneFlags).
    // SAFETY: unshare() is a simple kernel call. We pass the combined flags
    // including CLONE_NEWTIME (0x80) which nix doesn't expose yet.
    let raw_flags = flags.bits() | nix::libc::CLONE_NEWTIME;
    let unshare_result = unsafe { nix::libc::unshare(raw_flags) };
    let has_timens = if unshare_result == 0 {
        true
    } else {
        // Time namespace not available (kernel < 5.6) — retry without it.
        unshare(flags).map_err(|e| format!("unshare failed: {e}"))?;
        false
    };

    if !has_timens {
        eprintln!("gleisner-sandbox-init: time namespace not available (continuing)");
    }

    // Set a distinctive hostname inside the UTS namespace.
    // Visible in shell prompts and logs — makes it obvious you're sandboxed.
    sethostname("gleisner-sandbox").map_err(|e| format!("sethostname failed: {e}"))?;

    eprintln!("gleisner-sandbox-init: namespaces created (ipc+uts isolated)");

    // ── 2. Map UID/GID ────────────────────────────────────────────
    write_id_map("/proc/self/uid_map", spec.uid, spec.uid)?;
    fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| format!("failed to write setgroups: {e}"))?;
    write_id_map("/proc/self/gid_map", spec.gid, spec.gid)?;
    eprintln!(
        "gleisner-sandbox-init: uid/gid mapped ({} -> {})",
        spec.uid, spec.uid
    );

    // ── 2b. Time namespace offset ────────────────────────────────
    // Must be written after UID mapping (procfs requires valid UID),
    // but before any child process enters the time namespace.
    // Zeroes CLOCK_MONOTONIC so the sandbox starts at ~0, preventing:
    // - Timing side-channels (probing host activity via clock deltas)
    // - Non-deterministic builds (monotonic timestamps in outputs)
    // - Uptime fingerprinting (host uptime leaking into sandbox)
    if has_timens {
        if let Ok(ts) = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC) {
            let offset = format!("monotonic -{} -{}\n", ts.tv_sec(), ts.tv_nsec());
            if fs::write("/proc/self/timens_offsets", &offset).is_ok() {
                eprintln!("gleisner-sandbox-init: time namespace isolated (monotonic zeroed)");
            } else {
                eprintln!("gleisner-sandbox-init: time namespace offset write failed (continuing)");
            }
        }
    }

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

    // ── 5. Apply resource limits ────────────────────────────────────
    // Set rlimits inside the sandbox before exec. This is more reliable than
    // the orchestrator's prlimit(1) approach: no race window between spawn
    // and limit application, and works regardless of privilege level.
    if let Some(ref limits) = spec.resource_limits {
        if limits.max_file_descriptors > 0 {
            let val = limits.max_file_descriptors;
            setrlimit(Resource::RLIMIT_NOFILE, val, val)
                .map_err(|e| format!("setrlimit NOFILE: {e}"))?;
        }
        if limits.max_memory_mb > 0 {
            let bytes = limits.max_memory_mb * 1024 * 1024;
            setrlimit(Resource::RLIMIT_AS, bytes, bytes)
                .map_err(|e| format!("setrlimit AS: {e}"))?;
        }
        if limits.max_pids > 0 {
            setrlimit(
                Resource::RLIMIT_NPROC,
                u64::from(limits.max_pids),
                u64::from(limits.max_pids),
            )
            .map_err(|e| format!("setrlimit NPROC: {e}"))?;
        }
        if limits.max_disk_write_mb > 0 {
            let bytes = limits.max_disk_write_mb * 1024 * 1024;
            setrlimit(Resource::RLIMIT_FSIZE, bytes, bytes)
                .map_err(|e| format!("setrlimit FSIZE: {e}"))?;
        }
        eprintln!("gleisner-sandbox-init: rlimits applied inside sandbox");
    }

    // ── 6. Set working directory ──────────────────────────────────
    chdir(&spec.work_dir).map_err(|e| format!("chdir to {}: {e}", spec.work_dir.display()))?;

    // ── 7. Exec the inner command ─────────────────────────────────
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
        // Tmpfs mounts get noexec+nosuid+nodev: data files in /tmp should
        // never be executable, and no device nodes or SUID binaries allowed.
        mount(
            Some("tmpfs"),
            &target,
            Some("tmpfs"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("size=256m"),
        )
        .map_err(|e| format!("tmpfs {}: {e}", path.display()))?;
    }

    // ── Provide /proc and /dev ───────────────────────────────────
    // Try mounting a new procfs first (works when we own the PID namespace).
    // If that fails (EPERM — PID namespace takes effect only after fork()),
    // fall back to bind-mounting the host's /proc.
    let new_proc = new_root.join("proc");
    fs::create_dir_all(&new_proc).ok();
    let proc_mounted = mount(
        Some("proc"),
        &new_proc,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .is_ok();
    if !proc_mounted {
        // Bind-mount host /proc — still gives us /proc/self etc.
        // Use a direct bind without the hardening remount (nosuid/nodev
        // on procfs causes EPERM in user namespaces).
        let proc_source = Path::new("/proc");
        mount(
            Some(proc_source),
            &new_proc,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| format!("bind /proc: {e}"))?;
    }

    setup_minimal_dev(&new_root)?;

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

/// Create a minimal `/dev` with only essential device nodes.
///
/// Instead of bind-mounting the host's full `/dev` (which exposes block devices,
/// GPU devices, etc.), we mount a fresh tmpfs and create only the handful of
/// device nodes that userspace actually needs:
/// - `/dev/null`, `/dev/zero`, `/dev/full` — standard sinks/sources
/// - `/dev/urandom` — randomness (urandom, not random — never blocks)
/// - `/dev/tty` — controlling terminal
/// - `/dev/pts` — pseudo-terminal directory (bind-mounted from host)
///
/// This is a significant attack surface reduction over host `/dev` access.
fn setup_minimal_dev(new_root: &Path) -> Result<(), String> {
    let dev_dir = new_root.join("dev");
    fs::create_dir_all(&dev_dir).map_err(|e| format!("mkdir /dev: {e}"))?;

    // Mount a small tmpfs for /dev — nosuid+noexec (no executables in /dev)
    mount(
        Some("tmpfs"),
        &dev_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("size=64k,mode=0755"),
    )
    .map_err(|e| format!("mount tmpfs /dev: {e}"))?;

    // Create essential device nodes.
    // Inside a user namespace we can't mknod directly (EPERM), so we
    // bind-mount each device from the host.
    let devices = [
        ("null", MsFlags::empty()),
        ("zero", MsFlags::empty()),
        ("full", MsFlags::empty()),
        ("urandom", MsFlags::empty()),
        ("tty", MsFlags::empty()),
    ];

    for (name, extra) in &devices {
        let host_path = PathBuf::from(format!("/dev/{name}"));
        let target = dev_dir.join(name);

        if !host_path.exists() {
            continue;
        }

        // Create mount point file
        fs::write(&target, b"").map_err(|e| format!("create /dev/{name}: {e}"))?;

        mount(
            Some(host_path.as_path()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind /dev/{name}: {e}"))?;

        // Remount with hardening: nosuid+nodev+noexec + any extra flags
        let harden = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | *extra;
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | harden,
            None::<&str>,
        )
        .map_err(|e| format!("remount /dev/{name}: {e}"))?;
    }

    // /dev/pts — pseudo-terminal support (needed for interactive shells)
    let pts_dir = dev_dir.join("pts");
    fs::create_dir_all(&pts_dir).map_err(|e| format!("mkdir /dev/pts: {e}"))?;
    let host_pts = Path::new("/dev/pts");
    if host_pts.exists() {
        mount(
            Some(host_pts),
            &pts_dir,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| format!("bind /dev/pts: {e}"))?;
    }

    // /dev/shm — shared memory (some programs expect this)
    let shm_dir = dev_dir.join("shm");
    fs::create_dir_all(&shm_dir).map_err(|e| format!("mkdir /dev/shm: {e}"))?;
    mount(
        Some("tmpfs"),
        &shm_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        Some("size=64m"),
    )
    .map_err(|e| format!("mount /dev/shm: {e}"))?;

    // Symlinks that many programs expect
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::symlink;
        symlink("/proc/self/fd", dev_dir.join("fd")).ok();
        symlink("/proc/self/fd/0", dev_dir.join("stdin")).ok();
        symlink("/proc/self/fd/1", dev_dir.join("stdout")).ok();
        symlink("/proc/self/fd/2", dev_dir.join("stderr")).ok();
    }

    Ok(())
}

/// Bind-mount a host path into the new root.
///
/// All bind mounts are hardened with `nosuid|nodev` to prevent SUID binaries
/// and device node access inside the sandbox. Read-only mounts additionally
/// get `MS_RDONLY` via `extra_flags`.
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

    // Remount with hardening flags: always nosuid+nodev, plus any extra (e.g., rdonly).
    let harden_flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | extra_flags;
    mount(
        None::<&str>,
        &target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | harden_flags,
        None::<&str>,
    )
    .map_err(|e| format!("remount {}: {e}", target.display()))?;

    Ok(())
}

/// Write a UID or GID map entry.
fn write_id_map(path: &str, inside: u32, outside: u32) -> Result<(), String> {
    fs::write(path, format!("{inside} {outside} 1\n"))
        .map_err(|e| format!("failed to write {path}: {e}"))
}
