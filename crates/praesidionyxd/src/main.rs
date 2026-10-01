#![forbid(unsafe_code)]
use anyhow::{bail, Context};
use fs2::FileExt;
use praesidionyxd::{
    auth,
    kernel::Kernel,
    proto::{agent_syscalls_server::AgentSyscallsServer, supervisor_server::SupervisorServer},
    transport,
};
use std::{
    env,
    fs::{self, OpenOptions},
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::net::{TcpListener, UnixListener};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

fn socket(path: &Path) -> anyhow::Result<UnixListener> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            bail!("refusing to replace non-socket {}", path.display());
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
async fn shutdown() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let state = PathBuf::from(
        env::var("PRAESIDIONYX_STATE_DIR").unwrap_or_else(|_| "/var/lib/praesidionyx".into()),
    );
    fs::create_dir_all(&state)?;
    if fs::symlink_metadata(&state)?.file_type().is_symlink() {
        bail!("state directory must not be a symlink");
    }
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join("daemon.lock"))?;
    lock.try_lock_exclusive()
        .context("another praesidionyxd already owns this state directory")?;
    let bootstrap = auth::load_or_create(&state.join("bootstrap.key"))?;
    let supervisor = auth::load_or_create(&state.join("supervisor.key"))?;
    if auth::matches(&bootstrap, &supervisor) {
        bail!("bootstrap and supervisor keys must differ");
    }
    let mut kernel = Kernel::open(bootstrap, supervisor, &state)?;
    kernel.initialize_tools().await;
    for f in &kernel.features.features {
        tracing::info!(feature = %f.name, support = %f.support, usability = %f.usability, detail = %f.detail, "kernel feature probe");
        if f.usability != "available" {
            tracing::warn!(feature = %f.name, "feature unavailable or unverified; see tool_sandbox for aggregate enforcement");
        }
    }
    tracing::info!(
        enabled = kernel.features.tool_execution_enabled,
        "tool execution gated by mandatory confinement; taint approvals and scheduler enabled"
    );
    let agent_socket = socket(&state.join("agent.sock"))?;
    let supervisor_socket = socket(&state.join("supervisor.sock"))?;
    let agent_http = TcpListener::bind(
        env::var("PRAESIDIONYX_AGENT_HTTP").unwrap_or_else(|_| "127.0.0.1:8080".into()),
    )
    .await?;
    let supervisor_http = TcpListener::bind(
        env::var("PRAESIDIONYX_SUPERVISOR_HTTP").unwrap_or_else(|_| "127.0.0.1:8081".into()),
    )
    .await?;
    let agent_service = AgentSyscallsServer::new(kernel.clone()).max_decoding_message_size(65536);
    let supervisor_service = SupervisorServer::new(kernel.clone()).max_decoding_message_size(65536);
    tracing::info!(state_dir = %state.display(), "praesidionyxd ready");
    tokio::select! {
        _ = kernel.run_scheduler() => anyhow::bail!("scheduler stopped unexpectedly"),
        result = Server::builder().add_service(agent_service).serve_with_incoming(UnixListenerStream::new(agent_socket)) => result?,
        result = Server::builder().add_service(supervisor_service).serve_with_incoming(UnixListenerStream::new(supervisor_socket)) => result?,
        result = axum::serve(agent_http, transport::agent_router(kernel.clone())) => result?,
        result = axum::serve(supervisor_http, transport::supervisor_router(kernel.clone())) => result?,
        _ = shutdown() => { tracing::info!("shutdown requested; in-memory registry discarded"); }
    }
    for path in [state.join("agent.sock"), state.join("supervisor.sock")] {
        fs::remove_file(path)?;
    }
    Ok(())
}
