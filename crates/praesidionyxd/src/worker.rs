//! Trusted single-purpose MCP adapter inside the disposable Linux sandbox.
use crate::tool_bus::{arguments, MAX_BYTES};
use anyhow::{ensure, Context, Result};
use rmcp::{model::*, service::RequestContext, ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

pub struct WorkerServer {
    pub tool: String,
    pub resource: String,
    pub proof: Value,
    pub connection: Mutex<Option<std::net::TcpStream>>,
    pub used: AtomicBool,
}
impl ServerHandler for WorkerServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = json!({"type":"object","properties":{"path":{"type":"string"},"url":{"type":"string"},"content":{"type":"string"}}});
        Ok(ListToolsResult {
            tools: vec![Tool::new(
                self.tool.clone(),
                "Capability-bound isolated tool",
                schema.as_object().unwrap().clone(),
            )],
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let result = async {
            ensure!(
                !self.used.swap(true, Ordering::SeqCst),
                "worker is single-use"
            );
            ensure!(
                request.name == self.tool,
                "tool does not match launch grant"
            );
            let (resource, args) =
                arguments(&self.tool, &serde_json::to_string(&request.arguments)?)?;
            ensure!(
                resource == self.resource,
                "resource does not match launch grant"
            );
            match self.tool.as_str() {
                "fs.read" => {
                    let mut content = String::new();
                    praesidionyx_sandbox::confinement::open_workspace(&resource, false)?
                        .take((MAX_BYTES + 1) as u64)
                        .read_to_string(&mut content)?;
                    ensure!(content.len() <= MAX_BYTES, "file exceeds 32 KiB");
                    Ok(json!({"content":content}))
                }
                "fs.write" => {
                    let content = args["content"].as_str().unwrap();
                    let mut file =
                        praesidionyx_sandbox::confinement::open_workspace(&resource, true)?;
                    file.write_all(content.as_bytes())?;
                    file.sync_all()?;
                    Ok(json!({"bytes_written":content.len()}))
                }
                "http.get" => {
                    let socket = self
                        .connection
                        .lock()
                        .map_err(|_| anyhow::anyhow!("connection lock poisoned"))?
                        .take()
                        .context("missing broker connection")?;
                    http_get(&resource, socket).await
                }
                _ => anyhow::bail!("unknown tool"),
            }
        }
        .await;
        let output = match &result {
            Ok(value) => value.clone(),
            Err(error) => json!({"error":error.to_string()}),
        };
        let body = json!({"output":output,"sandbox":self.proof});
        Ok(if result.is_ok() {
            CallToolResult::structured(body)
        } else {
            CallToolResult::structured_error(body)
        }
        .into())
    }
}
async fn http_get(resource: &str, connection: std::net::TcpStream) -> Result<Value> {
    let url = url::Url::parse(resource)?;
    let socket = tokio::net::TcpStream::from_std(connection)?;
    if url.scheme() == "https" {
        use tokio_rustls::{
            rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
            TlsConnector,
        };
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server = ServerName::try_from(url.host_str().context("missing host")?.to_owned())?;
        let stream = TlsConnector::from(std::sync::Arc::new(config))
            .connect(server, socket)
            .await?;
        fetch(&url, stream).await
    } else {
        fetch(&url, socket).await
    }
}
async fn fetch<T>(url: &url::Url, stream: T) -> Result<Value>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use http_body_util::{BodyExt, Empty};
    use hyper::{client::conn::http1, Request};
    let (mut sender, connection) = http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let driver = tokio::spawn(connection);
    let uri = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", url.host_str().unwrap())
        .header("Connection", "close")
        .body(Empty::<bytes::Bytes>::new())?;
    let result = async {
        let response = sender.send_request(request).await?;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                ensure!(
                    bytes.len() + data.len() <= MAX_BYTES,
                    "response exceeds 32 KiB"
                );
                bytes.extend_from_slice(&data);
            }
        }
        Ok::<_, anyhow::Error>(
            json!({"status":status,"body":String::from_utf8(bytes)?,"redirects_followed":false}),
        )
    }
    .await;
    driver.abort();
    result
}
