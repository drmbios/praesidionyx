//! The daemon creates a bounded cgroup before executing bubblewrap. No fallback.
use anyhow::{ensure, Context, Result};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::{Child, Command};

pub fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 512,
        "invalid workspace path"
    );
    ensure!(
        path.split('/').all(|p| !p.is_empty()
            && p != "."
            && p != ".."
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "path must be relative with plain components and no traversal"
    );
    Ok(())
}

pub struct Worker {
    pub child: Child,
    pub parent_namespaces: serde_json::Value,
    group: PathBuf,
}
impl Worker {
    pub async fn finish(&mut self) {
        let _ = std::fs::write(self.group.join("cgroup.kill"), "1");
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        let _ = std::fs::remove_dir(&self.group);
    }
    pub fn verify_proof(&self, proof: &serde_json::Value) -> Result<()> {
        ensure!(
            proof["landlock"] == "fully_enforced_v3" && proof["seccomp"] == "allowlist",
            "worker restrictions missing"
        );
        for name in ["user", "mnt", "pid", "net", "ipc", "uts", "cgroup"] {
            ensure!(
                proof["namespaces"][name].is_string()
                    && proof["namespaces"][name] != self.parent_namespaces[name],
                "namespace {name} was not isolated"
            );
        }
        for (name, expected) in [
            ("cpu.max", "50000 100000"),
            ("memory.max", "67108864"),
            ("memory.swap.max", "0"),
            ("pids.max", "32"),
        ] {
            ensure!(
                std::fs::read_to_string(self.group.join(name))?.trim() == expected,
                "cgroup limit {name} changed"
            );
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Runs on timeout, cancellation and transport errors as well as success.
        let _ = std::fs::write(self.group.join("cgroup.kill"), "1");
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir(&self.group);
    }
}

#[cfg(target_os = "linux")]
pub fn launch(
    workspace: &Path,
    agent: &str,
    tool: &str,
    resource: &str,
    connection: Option<std::net::TcpStream>,
) -> Result<Worker> {
    use std::{
        fs,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::CommandExt,
        },
    };
    ensure!(uuid::Uuid::parse_str(agent).is_ok(), "invalid agent id");
    ensure!(
        matches!(tool, "probe" | "fs.read" | "fs.write" | "http.get"),
        "unknown tool"
    );
    ensure!(
        (tool == "http.get") == connection.is_some(),
        "network connection requires http.get"
    );
    let binary = std::env::current_exe()?.with_file_name("praesidionyx-tool");
    ensure!(binary.is_file(), "praesidionyx-tool must be beside daemon");
    let workspace = workspace.canonicalize()?;
    let root = PathBuf::from("/sys/fs/cgroup/agents");
    let agent_group = root.join(agent);
    fs::create_dir_all(&agent_group).context("cgroup delegation unavailable")?;
    fs::write(agent_group.join("cpu.max"), "50000 100000")?;
    fs::write(agent_group.join("memory.max"), "134217728")?;
    fs::write(agent_group.join("memory.swap.max"), "0")?;
    fs::write(agent_group.join("pids.max"), "32")?;
    fs::write(
        agent_group.join("cgroup.subtree_control"),
        "+cpu +memory +pids",
    )?;
    // Reap empty cgroups left by a cancelled call; never remove a populated one.
    for entry in fs::read_dir(&agent_group)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let _ = fs::remove_dir(entry.path());
        }
    }
    let group = agent_group.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&group)?;
    let prepared = (|| -> Result<_> {
        fs::write(group.join("memory.max"), "67108864")?;
        fs::write(group.join("memory.swap.max"), "0")?;
        fs::write(group.join("cpu.max"), "50000 100000")?;
        fs::write(group.join("pids.max"), "32")?;
        let procs = fs::OpenOptions::new()
            .write(true)
            .open(group.join("cgroup.procs"))?;
        // Duplicate inherited descriptors above reserved slots before fork, avoiding
        // collisions even when the daemon has many open descriptors.
        fn inherit(fd: i32) -> Result<OwnedFd> {
            // SAFETY: fcntl duplicates a live descriptor; the result is uniquely owned.
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 200) };
            if copy < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: successful duplication returned a fresh owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(copy) })
        }
        let proc = inherit(fs::File::open("/proc")?.as_raw_fd())?;
        let connection = connection
            .as_ref()
            .map(|s| inherit(s.as_raw_fd()))
            .transpose()?;
        let mut parent_namespaces = serde_json::Map::new();
        for name in ["user", "mnt", "pid", "net", "ipc", "uts", "cgroup"] {
            parent_namespaces.insert(
                name.into(),
                fs::read_link(format!("/proc/self/ns/{name}"))?
                    .to_string_lossy()
                    .to_string()
                    .into(),
            );
        }
        let mut command = std::process::Command::new("/usr/bin/bwrap");
        command.env_clear().env("PATH", "/usr/bin:/bin").args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/bin",
            "/bin",
        ]);
        if Path::new("/lib64").exists() {
            command.args(["--symlink", "usr/lib64", "/lib64"]);
        }
        command
            .args(["--dev", "/dev", "--tmpfs", "/tmp"])
            .arg(if tool == "fs.write" {
                "--bind"
            } else {
                "--ro-bind"
            })
            .arg(&workspace)
            .arg("/work")
            .arg("--ro-bind")
            .arg(&binary)
            .arg("/worker")
            .args(["--chdir", "/work", "--", "/worker", tool, resource])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // SAFETY: after fork only async-signal-safe write/dup2 are called. Captured
        // files remain alive until exec; descriptors are CLOEXEC except reserved 198/199.
        unsafe {
            command.pre_exec(move || {
                if libc::write(procs.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(proc.as_raw_fd(), super::confinement::PROBE_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(ref socket) = connection {
                    if libc::dup2(socket.as_raw_fd(), super::confinement::CONNECTION_FD) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut command = Command::from(command);
        command.kill_on_drop(true);
        Ok((
            command
                .spawn()
                .context("cannot start mandatory bubblewrap sandbox")?,
            serde_json::Value::Object(parent_namespaces),
        ))
    })();
    match prepared {
        Ok((child, parent_namespaces)) => Ok(Worker {
            child,
            parent_namespaces,
            group,
        }),
        Err(error) => {
            let _ = fs::remove_dir(&group);
            Err(error)
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub fn launch(
    _: &Path,
    _: &str,
    _: &str,
    _: &str,
    _: Option<std::net::TcpStream>,
) -> Result<Worker> {
    anyhow::bail!("Linux confinement is required")
}
#[cfg(test)]
mod tests {
    #[test]
    fn paths_reject_traversal_and_ambiguous_forms() {
        for path in [
            "", "/a", "../a", "a/../b", "a//b", "a/./b", "a\\b", "a%2fb", "a\0b",
        ] {
            assert!(super::validate_path(path).is_err(), "{path:?}");
        }
        assert!(super::validate_path("notes/a-b.txt").is_ok());
    }
}
