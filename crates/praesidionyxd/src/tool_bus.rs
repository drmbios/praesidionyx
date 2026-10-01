//! Capability scope normalization, outbound connection broker, and private MCP client.
use anyhow::{ensure, Context, Result};
use praesidionyx_sandbox::runner;
use rmcp::{model::CallToolRequestParams, ServiceExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{net::Ipv4Addr, path::Path, time::Duration};
use tokio::io::AsyncReadExt;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_BYTES: usize = 32768;

pub fn canonical_resource(tool: &str, resource: &str) -> Result<String> {
    match tool {
        "fs.read" | "fs.write" => {
            runner::validate_path(resource)?;
            Ok(resource.into())
        }
        "http.get" => {
            ensure!(
                resource.len() <= 2048 && !resource.chars().any(char::is_control),
                "invalid URL"
            );
            let url = url::Url::parse(resource)?;
            ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "only HTTP(S) URLs without credentials/fragments are allowed"
            );
            ensure!(
                url.port_or_known_default() == Some(if url.scheme() == "https" { 443 } else { 80 }),
                "only default HTTP(S) ports are allowed"
            );
            Ok(url.to_string())
        }
        _ => anyhow::bail!("tool is disabled by policy"),
    }
}
pub fn capability_scope(tool: &str, resource: &str) -> Result<String> {
    let resource = canonical_resource(tool, resource)?;
    Ok(format!(
        "{}:{}",
        if tool == "http.get" { "url" } else { "file" },
        hex::encode(Sha256::digest(resource.as_bytes()))
    ))
}
pub fn arguments(tool: &str, raw: &str) -> Result<(String, serde_json::Map<String, Value>)> {
    ensure!(raw.len() <= 48000, "tool arguments too large");
    let value: Value = serde_json::from_str(raw)?;
    let mut args = value
        .as_object()
        .context("arguments must be an object")?
        .clone();
    let key = if tool == "http.get" { "url" } else { "path" };
    let resource = canonical_resource(
        tool,
        args.get(key)
            .and_then(Value::as_str)
            .context("missing resource")?,
    )?;
    let expected = if tool == "fs.write" { 2 } else { 1 };
    ensure!(args.len() == expected, "unknown arguments");
    if tool == "fs.write" {
        ensure!(
            args.get("content")
                .and_then(Value::as_str)
                .is_some_and(|s| s.len() <= MAX_BYTES),
            "content must be a string of at most 32 KiB"
        );
    }
    args.insert(key.into(), resource.clone().into());
    Ok((resource, args))
}
// Deliberately conservative IPv4-only broker. Never trust DNS a second time.
fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}
async fn connect(resource: &str) -> Result<std::net::TcpStream> {
    // Two immutable, reserved .invalid mock fixtures. They cannot select another
    // host/path or forward traffic. They exercise real HTTP in an offline demo.
    let fixture = match resource {
        "http://fixtures.praesidionyx.invalid/injection" => {
            Some(include_str!("../../../examples/fixtures/injection.html"))
        }
        "http://fixtures.praesidionyx.invalid/research" => {
            Some(include_str!("../../../examples/fixtures/research.html"))
        }
        _ => None,
    };
    if let Some(body) = fixture {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let connection = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (mut server, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = tokio::time::timeout(TIMEOUT, async {
                let mut buffer = [0;4096];
                if server.read(&mut buffer).await? == 0 { return Ok(()); }
                server.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await
            }).await;
        });
        return Ok(connection.into_std()?);
    }

    let url = url::Url::parse(resource)?;
    let host = url.host_str().context("missing host")?;
    let addresses: Vec<_> = tokio::net::lookup_host((host, url.port_or_known_default().unwrap()))
        .await?
        .filter(|a| a.is_ipv4())
        .collect();
    ensure!(
        !addresses.is_empty()
            && addresses.iter().all(|a| match a.ip() {
                std::net::IpAddr::V4(ip) => public_ipv4(ip),
                _ => false,
            }),
        "destination is not permitted public IPv4"
    );
    let stream = tokio::net::TcpStream::connect(addresses[0]).await?;
    Ok(stream.into_std()?)
}

pub async fn probe(workspace: &Path, agent: &str) -> Result<Value> {
    let mut worker = runner::launch(workspace, agent, "probe", "", None)?;
    let result = tokio::time::timeout(TIMEOUT, async {
        let mut output = String::new();
        worker
            .child
            .stdout
            .take()
            .context("missing stdout")?
            .take(16384)
            .read_to_string(&mut output)
            .await?;
        ensure!(worker.child.wait().await?.success(), "sandbox probe failed");
        let proof: Value = serde_json::from_str(&output)?;
        worker.verify_proof(&proof)?;
        Ok::<_, anyhow::Error>(proof)
    })
    .await
    .context("sandbox probe timed out")?;
    worker.finish().await;
    result
}
pub async fn invoke(
    workspace: &Path,
    agent: &str,
    tool: &str,
    resource: &str,
    args: serde_json::Map<String, Value>,
) -> Result<Value> {
    tokio::time::timeout(TIMEOUT, async {
        let connection = if tool == "http.get" {
            Some(connect(resource).await?)
        } else {
            None
        };
        invoke_connected(workspace, agent, tool, resource, args, connection).await
    })
    .await
    .context("tool invocation exceeded 10 seconds")?
}
async fn invoke_connected(
    workspace: &Path,
    agent: &str,
    tool: &str,
    resource: &str,
    args: serde_json::Map<String, Value>,
    connection: Option<std::net::TcpStream>,
) -> Result<Value> {
    let mut worker = runner::launch(workspace, agent, tool, resource, connection)?;
    let output = worker.child.stdout.take().context("missing stdout")?;
    let input = worker.child.stdin.take().context("missing stdin")?;
    let result = async {
        let mut service = ().serve((output, input)).await?;
        let reply = service.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args)).await?;
        let structured = reply.structured_content.context("worker returned no structured content")?;
        worker.verify_proof(&structured["sandbox"])?;
        // Explicitly tear down transport; cgroup cleanup also covers cancellation.
        service.close().await?;
        Ok::<_, anyhow::Error>(json!({"output":structured["output"], "sandbox":structured["sandbox"], "limits":{"cpu_max":"50000 100000","memory_bytes":67108864,"swap_bytes":0,"pids":32,"timeout_ms":10000}, "is_error":reply.is_error.unwrap_or(false)}))
    }.await;
    worker.finish().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_and_egress_validation() {
        assert_eq!(
            capability_scope("http.get", "https://example.com").unwrap(),
            capability_scope("http.get", "https://example.com/").unwrap()
        );
        assert_ne!(
            capability_scope("fs.read", "a").unwrap(),
            capability_scope("fs.read", "b").unwrap()
        );
        for url in [
            "file:///etc/passwd",
            "https://user:secret@example.com/",
            "https://example.com/#x",
            "http://example.com:3000/",
        ] {
            assert!(canonical_resource("http.get", url).is_err());
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "192.0.2.1",
        ] {
            assert!(!public_ipv4(ip.parse().unwrap()));
        }
        assert!(public_ipv4("93.184.215.14".parse().unwrap()));
        assert!(arguments("fs.read", r#"{"path":"../secret"}"#).is_err());
        assert!(arguments("fs.read", r#"{"path":"a","extra":1}"#).is_err());
    }
    /// Executed explicitly by scripts/check-sandbox.sh with delegated cgroups.
    #[tokio::test]
    #[ignore = "requires Linux namespace/cgroup delegation; scripts/check-sandbox.sh runs offline"]
    async fn real_sandbox_offline() -> Result<()> {
        use tokio::{io::AsyncWriteExt, net::TcpListener};
        let workspace = tempfile::tempdir()?;
        let id = uuid::Uuid::new_v4().to_string();
        probe(workspace.path(), &id).await?;
        let call = |tool: &'static str, args: Value| {
            let (resource, args) = arguments(tool, &args.to_string()).unwrap();
            let path = workspace.path();
            let id = &id;
            async move { invoke(path, id, tool, &resource, args).await }
        };
        let write = call(
            "fs.write",
            json!({"path":"note.txt","content":"sandbox works"}),
        )
        .await?;
        ensure!(write["is_error"] == false, "{write}");
        let read = call("fs.read", json!({"path":"note.txt"})).await?;
        ensure!(read["output"]["content"] == "sandbox works", "{read}");
        std::os::unix::fs::symlink("/usr/bin/true", workspace.path().join("escape"))?;
        ensure!(
            call("fs.read", json!({"path":"escape"})).await?["is_error"] == true,
            "symlink escaped"
        );
        let neighbor = tempfile::tempdir()?;
        std::fs::write(neighbor.path().join("secret"), "neighbor secret")?;
        std::fs::hard_link(
            neighbor.path().join("secret"),
            workspace.path().join("hardlink"),
        )?;
        ensure!(
            call("fs.write", json!({"path":"hardlink","content":"tampered"})).await?["is_error"]
                == true,
            "hard link write allowed"
        );
        ensure!(
            std::fs::read_to_string(neighbor.path().join("secret"))? == "neighbor secret",
            "hard link target changed"
        );
        std::fs::write(
            workspace.path().join("too-large"),
            vec![b'x'; MAX_BYTES + 1],
        )?;
        ensure!(
            call("fs.read", json!({"path":"too-large"})).await?["is_error"] == true,
            "oversized file accepted"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let socket = tokio::net::TcpStream::connect(listener.local_addr()?)
            .await?
            .into_std()?;
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let n = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..n]).starts_with("GET /fixture HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\noffline fixture").await.unwrap();
        });
        // Only this private test bypasses the public-address broker; no runtime knob.
        let result = tokio::time::timeout(
            TIMEOUT,
            invoke_connected(
                workspace.path(),
                &id,
                "http.get",
                "http://example.com/fixture",
                json!({"url":"http://example.com/fixture"})
                    .as_object()
                    .unwrap()
                    .clone(),
                Some(socket),
            ),
        )
        .await??;
        ensure!(result["output"]["body"] == "offline fixture", "{result}");
        fixture.await?;
        // A stalled server must not leave a worker or an open connection behind.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let socket = tokio::net::TcpStream::connect(listener.local_addr()?)
            .await?
            .into_std()?;
        let (mut stalled, _) = listener.accept().await?;
        let result = tokio::time::timeout(
            Duration::from_millis(250),
            invoke_connected(
                workspace.path(),
                &id,
                "http.get",
                "http://example.com/stall",
                json!({"url":"http://example.com/stall"})
                    .as_object()
                    .unwrap()
                    .clone(),
                Some(socket),
            ),
        )
        .await;
        ensure!(result.is_err(), "stalled request did not time out");
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stalled.read_to_end(&mut received)).await??;
        ensure!(
            received.starts_with(b"GET /stall HTTP/1.1"),
            "fixture was not reached"
        );
        let group = std::path::Path::new("/sys/fs/cgroup/agents").join(&id);
        for _ in 0..100 {
            if std::fs::read_to_string(group.join("cgroup.events"))?.contains("populated 0") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        ensure!(
            std::fs::read_to_string(group.join("cgroup.events"))?.contains("populated 0"),
            "cancelled worker survived"
        );
        ensure!(
            connect("http://127.0.0.1/").await.is_err(),
            "private broker destination allowed"
        );
        Ok(())
    }
}
