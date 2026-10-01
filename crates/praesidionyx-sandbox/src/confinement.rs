//! Restrictions are installed in a single-threaded, disposable worker, before MCP.
use anyhow::{ensure, Context, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use std::{
    ffi::CString,
    fs::File,
    io,
    net::TcpStream,
    os::fd::{AsRawFd, FromRawFd},
};

pub const CONNECTION_FD: i32 = 198;
pub const PROBE_FD: i32 = 199;

pub fn install(writable: bool) -> Result<serde_json::Value> {
    // No /proc mount enters the sandbox. The launcher passes a temporary proc
    // directory descriptor solely for these checks, closed before serving MCP.
    // SAFETY: the trusted launcher reserves this unique descriptor for this process.
    let proc = unsafe { File::from_raw_fd(PROBE_FD) };
    let mut namespaces = serde_json::Map::new();
    for name in ["user", "mnt", "pid", "net", "ipc", "uts", "cgroup"] {
        let path = CString::new(format!("self/ns/{name}"))?;
        let mut buffer = [0u8; 128];
        // SAFETY: proc is live, path is NUL terminated, buffer has the supplied length.
        let n = unsafe {
            libc::readlinkat(
                proc.as_raw_fd(),
                path.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        ensure!(
            n > 0 && (n as usize) < buffer.len(),
            "namespace evidence unavailable"
        );
        namespaces.insert(
            name.into(),
            String::from_utf8(buffer[..n as usize].to_vec())?.into(),
        );
    }
    drop(proc);
    let access = if writable {
        AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::MakeReg
            | AccessFs::Truncate
    } else {
        AccessFs::ReadFile | AccessFs::ReadDir
    };
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V3))?
        .create()?
        .add_rule(PathBeneath::new(PathFd::new("/work")?, access))?
        .restrict_self()?;
    ensure!(
        status.ruleset == RulesetStatus::FullyEnforced,
        "Landlock V3 must be fully enforced"
    );
    // This file is mounted by the launcher, so EACCES proves actual Landlock enforcement.
    ensure!(
        File::open("/usr/bin/true").unwrap_err().raw_os_error() == Some(libc::EACCES),
        "Landlock probe failed"
    );
    let names: Vec<String> =
        serde_json::from_str(include_str!("../../../docker/seccomp-worker.json"))?;
    let mut filter = ScmpFilterContext::new(ScmpAction::Errno(libc::EPERM))?;
    for name in names {
        filter.add_rule(
            ScmpAction::Allow,
            ScmpSyscall::from_name(&name).with_context(|| name.clone())?,
        )?;
    }
    // Tokio signal bookkeeping uses an anonymous Unix socket pair. This creates
    // no reachable listener or connection to any other process.
    filter.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("socketpair")?,
        &[ScmpArgCompare::new(
            0,
            ScmpCompareOp::Equal,
            libc::AF_UNIX as u64,
        )],
    )?;
    // Tokio's stdio uses pthreads. Permit threads, never a new process or namespace.
    let forbidden = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP;
    filter.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("clone")?,
        &[ScmpArgCompare::new(
            0,
            ScmpCompareOp::MaskedEqual((forbidden | libc::CLONE_THREAD) as u64),
            libc::CLONE_THREAD as u64,
        )],
    )?;
    // glibc retries clone when clone3 is unavailable, with filterable flags.
    filter.add_rule(
        ScmpAction::Errno(libc::ENOSYS),
        ScmpSyscall::from_name("clone3")?,
    )?;
    filter.load()?;
    // SAFETY: no pointers; failed socket creation owns no descriptor. Unexpected
    // success is closed and rejected rather than silently weakening isolation.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let denied = fd == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if fd >= 0 {
        // SAFETY: owned descriptor from socket above.
        unsafe { libc::close(fd) };
    }
    ensure!(denied, "seccomp socket denial probe failed");
    // SAFETY: unshare takes only flags. Unexpected success changes only this
    // disposable worker, and immediately fails the probe before any request.
    ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWUSER) } == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "seccomp namespace denial probe failed"
    );
    let nonexistent = CString::new("/definitely-not-an-praesidionyx-program")?;
    // SAFETY: valid path and NUL-terminated empty argv/envp arrays. The absent
    // executable cannot run even if the filter were unexpectedly ineffective.
    ensure!(
        unsafe {
            libc::execve(
                nonexistent.as_ptr(),
                [std::ptr::null()].as_ptr(),
                [std::ptr::null()].as_ptr(),
            )
        } == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "seccomp exec denial probe failed"
    );
    Ok(
        serde_json::json!({"landlock":"fully_enforced_v3","seccomp":"allowlist","network":"isolated_preconnected_only","namespaces":namespaces}),
    )
}

/// No links or parent traversal, even if another actor races path replacement.
pub fn open_workspace(path: &str, write: bool) -> Result<File> {
    super::runner::validate_path(path)?;
    let directory = File::open("/work")?;
    let name = CString::new(path)?;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if write {
                libc::O_WRONLY | libc::O_CREAT
            } else {
                libc::O_RDONLY
            }) as u64,
        mode: if write { 0o600 } else { 0 },
        resolve: 0x08 | 0x04 | 0x02, // BENEATH | NO_SYMLINKS | NO_MAGICLINKS
    };
    // SAFETY: valid NUL-terminated name and initialized open_how with the documented
    // ABI size; directory owns the live dirfd. Kernel returns a new owned fd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful openat2 returned this unique descriptor.
    let file = unsafe { File::from_raw_fd(fd as i32) };
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "only regular files with one link are supported"
    );
    if write {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Called once in the worker, only when the trusted launcher supplied its socket.
pub fn take_connection() -> Result<TcpStream> {
    // SAFETY: fcntl only queries this descriptor; ownership is taken after it exists.
    ensure!(
        unsafe { libc::fcntl(CONNECTION_FD, libc::F_GETFD) } >= 0,
        "missing broker connection"
    );
    // SAFETY: launcher reserves fd 198, transfers ownership to this process, and
    // this function is called once before any worker threads are created.
    let stream = unsafe { TcpStream::from_raw_fd(CONNECTION_FD) };
    stream
        .peer_addr()
        .context("broker descriptor is not a connected TCP socket")?;
    stream.set_nonblocking(true)?;
    Ok(stream)
}
