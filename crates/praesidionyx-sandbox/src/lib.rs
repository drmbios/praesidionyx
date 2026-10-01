//! Linux feature probes and fail-closed tool confinement.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(target_os = "linux")]
pub mod confinement;
pub mod runner;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    pub name: String,
    pub support: String,
    pub usability: String,
    pub detail: String,
}
fn feature(name: &str, support: &str, usability: &str, detail: impl Into<String>) -> Feature {
    Feature {
        name: name.into(),
        support: support.into(),
        usability: usability.into(),
        detail: detail.into(),
    }
}
pub fn detect() -> Vec<Feature> {
    #[cfg(target_os = "linux")]
    {
        linux::detect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        [
            "landlock",
            "seccomp",
            "user_namespaces",
            "cgroup_v2",
            "ebpf",
        ]
        .iter()
        .map(|name| {
            feature(
                name,
                "unavailable",
                "unavailable",
                "Linux is required; run through Docker Compose",
            )
        })
        .collect()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{fs, io, process::Command};

    pub fn detect() -> Vec<Feature> {
        vec![landlock(), seccomp(), user_namespaces(), cgroups(), ebpf()]
    }
    fn landlock() -> Feature {
        // SAFETY: ABI query passes no ruleset, length zero, and the documented
        // LANDLOCK_CREATE_RULESET_VERSION flag (1). No pointers are dereferenced.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                1u32,
            )
        };
        if abi > 0 {
            feature(
                "landlock",
                "detected",
                "unverified",
                format!("ABI {abi}; see tool_sandbox for actual worker enforcement"),
            )
        } else {
            feature(
                "landlock",
                "unavailable",
                "unavailable",
                io::Error::last_os_error().to_string(),
            )
        }
    }
    fn seccomp() -> Feature {
        // SAFETY: PR_GET_SECCOMP reads the calling thread's mode; unused args are zero.
        let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        if mode >= 0 {
            feature("seccomp", "detected", "unverified", format!("Current mode {mode} (2 = outer container filter); see tool_sandbox for worker allowlist enforcement"))
        } else {
            feature(
                "seccomp",
                "unavailable",
                "unavailable",
                io::Error::last_os_error().to_string(),
            )
        }
    }
    fn user_namespaces() -> Feature {
        let support = if fs::metadata("/proc/self/ns/user").is_ok() {
            "detected"
        } else {
            "unknown"
        };
        match Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user", "/usr/bin/true"])
            .output()
        {
            Ok(output) if output.status.success() => feature(
                "user_namespaces",
                support,
                "available",
                "A child process created a user namespace; daemon namespace unchanged",
            ),
            Ok(output) => feature(
                "user_namespaces",
                support,
                "blocked",
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ),
            Err(error) => feature(
                "user_namespaces",
                support,
                "unverified",
                format!("Cannot run unshare probe: {error}"),
            ),
        }
    }
    fn cgroups() -> Feature {
        match fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
            Ok(controllers) => {
                let path = format!(
                    "/sys/fs/cgroup/agents/praesidionyx-probe-{}",
                    std::process::id()
                );
                match fs::create_dir(&path) {
                    Ok(()) => {
                        let cleanup = fs::remove_dir(&path);
                        feature("cgroup_v2", "detected", "unverified", format!("Writable hierarchy; controllers: {}; see tool_sandbox for real limits; probe cleanup: {cleanup:?}", controllers.trim()))
                    }
                    Err(error) => feature(
                        "cgroup_v2",
                        "detected",
                        "blocked",
                        format!(
                            "Controllers: {}; delegation unavailable: {error}",
                            controllers.trim()
                        ),
                    ),
                }
            }
            Err(error) => feature("cgroup_v2", "unavailable", "unavailable", error.to_string()),
        }
    }
    fn ebpf() -> Feature {
        // bpf_attr's BPF_MAP_CREATE prefix: map_type, key_size, value_size,
        // max_entries, map_flags. The zero-filled aligned tail is reserved.
        let mut attr = [0u64; 18];
        let prefix = [2u32, 4, 4, 1]; // BPF_MAP_TYPE_ARRAY, one 4-byte entry.
        for (i, pair) in prefix.as_chunks::<2>().0.iter().enumerate() {
            let mut bytes = [0u8; 8];
            bytes[..4].copy_from_slice(&pair[0].to_ne_bytes());
            bytes[4..].copy_from_slice(&pair[1].to_ne_bytes());
            attr[i] = u64::from_ne_bytes(bytes);
        }
        // SAFETY: attr is aligned and initialized for the entire supplied length.
        // BPF_MAP_CREATE (0) only reads it and returns an owned fd or an error.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                0u32,
                attr.as_ptr(),
                std::mem::size_of_val(&attr),
            )
        };
        if fd >= 0 {
            // SAFETY: fd is the newly owned map descriptor; it is closed exactly once.
            unsafe { libc::close(fd as libc::c_int) };
            feature(
                "ebpf",
                "detected",
                "unverified",
                "Map creation succeeded; program loading/attachment not tested",
            )
        } else {
            let error = io::Error::last_os_error();
            let support = if fs::metadata("/proc/sys/kernel/unprivileged_bpf_disabled").is_ok() {
                "detected"
            } else {
                "unknown"
            };
            feature(
                "ebpf",
                support,
                "blocked",
                format!("Map creation failed: {error}; no BPF program is loaded"),
            )
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn report_covers_all_required_controls() {
        let report = super::detect();
        let names: Vec<_> = report.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "landlock",
                "seccomp",
                "user_namespaces",
                "cgroup_v2",
                "ebpf"
            ]
        );
        assert!(report
            .iter()
            .all(|f| !f.detail.is_empty() && !f.usability.is_empty()));
    }
}
pub mod sqlite;
