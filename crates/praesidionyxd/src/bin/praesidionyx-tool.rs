#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    let mut args = std::env::args().skip(1);
    let tool = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("tool required"))?;
    let resource = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("resource required"))?;
    let connection = if tool == "http.get" {
        Some(praesidionyx_sandbox::confinement::take_connection()?)
    } else {
        None
    };
    let proof = praesidionyx_sandbox::confinement::install(tool == "fs.write")?;
    if tool == "probe" {
        println!("{proof}");
        return Ok(());
    }
    let server = praesidionyxd::worker::WorkerServer {
        tool,
        resource,
        proof,
        connection: std::sync::Mutex::new(connection),
        used: std::sync::atomic::AtomicBool::new(false),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            server
                .serve(rmcp::transport::stdio())
                .await?
                .waiting()
                .await?;
            Ok(())
        })
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux is required")
}
