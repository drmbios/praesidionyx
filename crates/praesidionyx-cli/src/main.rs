#![forbid(unsafe_code)]
use anyhow::Context;
use clap::{Args as ClapArgs, Parser, Subcommand};
use hyper_util::rt::TokioIo;
use praesidionyxd::proto::{
    self, agent_syscalls_client::AgentSyscallsClient, supervisor_client::SupervisorClient,
};
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tonic::{
    transport::{Channel, Endpoint},
    Request,
};
use tower::service_fn;

#[derive(Parser)]
#[command(
    name = "praesidionyx",
    about = "Praesidionyx supervisor: capabilities, lifecycle, and signed audit"
)]
struct Args {
    #[arg(
        long,
        env = "PRAESIDIONYX_STATE_DIR",
        default_value = "/var/lib/praesidionyx"
    )]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(ClapArgs)]
struct Limits {
    #[arg(long, default_value_t = 4096)]
    tokens: u64,
    #[arg(long, default_value_t = 60000)]
    wall_time_ms: u64,
    #[arg(long, default_value_t = 16)]
    tool_calls: u64,
    #[arg(long, default_value_t = 0)]
    cost_microusd: u64,
}
impl Limits {
    fn budget(&self) -> proto::Budget {
        proto::Budget {
            tokens: self.tokens,
            wall_time_ms: self.wall_time_ms,
            tool_calls: self.tool_calls,
            cost_microusd: self.cost_microusd,
        }
    }
    fn cap_budget(&self) -> praesidionyx_caps::Budget {
        praesidionyx_caps::Budget {
            tokens: self.tokens,
            wall_time_ms: self.wall_time_ms,
            tool_calls: self.tool_calls,
            cost_microusd: self.cost_microusd,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    ListAgents,
    Approvals,
    Kill {
        agent_id: String,
    },
    Pause {
        agent_id: String,
    },
    Resume {
        agent_id: String,
    },
    Memory {
        #[arg(long)]
        credentials_file: PathBuf,
        operation: String,
        #[arg(long, default_value = "")]
        content: String,
        #[arg(long, default_value = "user")]
        label: String,
        #[arg(long, default_value_t = 1024)]
        max_tokens: u64,
        #[arg(long, default_value = "")]
        snapshot_id: String,
    },
    Approve {
        request_id: String,
    },
    Deny {
        request_id: String,
    },
    /// Invoke one capability-authorized tool over the agent socket.
    Invoke {
        #[arg(long)]
        credentials_file: PathBuf,
        #[arg(long)]
        capability_file: PathBuf,
        tool: String,
        #[arg(long, default_value = "")]
        approval_id: String,
        /// JSON object: path/content for files or url for HTTP.
        #[arg(long)]
        args: String,
    },
    Features,
    /// Human provisioning client: issues a one-use spawn capability unless supplied.
    Spawn {
        #[arg(long, default_value = "demo")]
        name: String,
        #[arg(long, default_value = "Hello, Praesidionyx")]
        prompt: String,
        #[arg(long, env = "PRAESIDIONYX_MODEL", default_value = "mock-v1")]
        model: String,
        #[arg(long, env = "PRAESIDIONYX_PROVIDER", default_value = "mock")]
        provider: String,
        #[command(flatten)]
        limits: Limits,
        #[arg(long)]
        capability_file: Option<PathBuf>,
    },
    /// Reads the JSON spawn response containing session_token and exit_capability.
    Exit {
        agent_id: String,
        #[arg(long)]
        credentials_file: PathBuf,
        #[arg(long, default_value_t = 0)]
        status: i32,
    },
    Caps {
        #[command(subcommand)]
        command: Caps,
    },
    Audit {
        #[command(subcommand)]
        command: Audit,
    },
}
#[derive(Subcommand)]
enum Caps {
    /// Supervisor-only grant for one agent, tool, and exact path or URL.
    IssueTool {
        agent_id: String,
        tool: String,
        resource: String,
        #[arg(long, default_value_t = 1)]
        max_calls: u64,
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
    },
    /// Supervisor-only issuance of bootstrap spawn authority.
    Issue {
        #[arg(long, default_value_t = 1)]
        max_calls: u64,
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
        #[command(flatten)]
        limits: Limits,
    },
    /// Append restrictions without the signing key (output is a raw Biscuit token).
    Attenuate {
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        public_key_file: Option<PathBuf>,
        #[arg(long, default_value = "bootstrap")]
        subject: String,
        #[arg(long, default_value = "agent.spawn")]
        operation: String,
        #[arg(long, default_value = "agents")]
        resource: String,
        #[arg(long, default_value_t = 1)]
        max_calls: u64,
        #[arg(long, default_value_t = 60)]
        ttl_seconds: u64,
        #[command(flatten)]
        limits: Limits,
    },
}
#[derive(Subcommand)]
enum Audit {
    /// Verify via supervisor socket, or verify an exported file with a pinned key.
    Verify {
        #[arg(long, requires = "public_key_file")]
        file: Option<PathBuf>,
        #[arg(long, requires = "file")]
        public_key_file: Option<PathBuf>,
        #[arg(long, requires = "file")]
        checkpoint: Option<PathBuf>,
    },
    Tail {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}
async fn connect(path: PathBuf) -> anyhow::Result<Channel> {
    Ok(Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await?)
}
fn request<T>(body: T, key: &str) -> anyhow::Result<Request<T>> {
    let mut request = Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {}", key.trim()).parse()?);
    Ok(request)
}
fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}
fn read_cap(path: &Path) -> anyhow::Result<String> {
    let data = read(path)?;
    if data.trim_start().starts_with('{') {
        Ok(serde_json::from_str::<proto::CapabilityResponse>(&data)?.capability)
    } else {
        Ok(data.trim().into())
    }
}
async fn supervisor(state: &Path) -> anyhow::Result<SupervisorClient<Channel>> {
    Ok(SupervisorClient::new(
        connect(state.join("supervisor.sock")).await?,
    ))
}
async fn issue(
    state: &Path,
    max_calls: u64,
    ttl_seconds: u64,
    budget: proto::Budget,
) -> anyhow::Result<proto::CapabilityResponse> {
    Ok(supervisor(state)
        .await?
        .issue_capability(request(
            proto::IssueCapabilityRequest {
                max_calls,
                ttl_seconds,
                budget: Some(budget),
            },
            &read(&state.join("supervisor.key"))?,
        )?)
        .await?
        .into_inner())
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let state = args.state_dir;
    let output = match args.command {
        Command::Memory {
            credentials_file,
            operation,
            content,
            label,
            max_tokens,
            snapshot_id,
        } => {
            let creds: proto::SpawnResponse = serde_json::from_str(&read(&credentials_file)?)?;
            let response = AgentSyscallsClient::new(connect(state.join("agent.sock")).await?)
                .memory(request(
                    proto::MemoryRequest {
                        agent_id: creds.agent.context("missing agent")?.agent_id,
                        capability: creds.local_capability,
                        operation,
                        content,
                        label,
                        max_tokens,
                        snapshot_id,
                    },
                    &creds.session_token,
                )?)
                .await?
                .into_inner();
            serde_json::from_str(&response.result_json)?
        }
        command @ (Command::Kill { .. } | Command::Pause { .. } | Command::Resume { .. }) => {
            let (agent_id, action) = match command {
                Command::Kill { agent_id } => (agent_id, "kill"),
                Command::Pause { agent_id } => (agent_id, "pause"),
                Command::Resume { agent_id } => (agent_id, "resume"),
                _ => unreachable!(),
            };
            serde_json::to_value(
                supervisor(&state)
                    .await?
                    .control(request(
                        proto::ControlRequest {
                            agent_id,
                            action: action.into(),
                        },
                        &read(&state.join("supervisor.key"))?,
                    )?)
                    .await?
                    .into_inner(),
            )?
        }
        Command::Approvals => serde_json::to_value(
            supervisor(&state)
                .await?
                .list_approvals(request(
                    proto::Empty {},
                    &read(&state.join("supervisor.key"))?,
                )?)
                .await?
                .into_inner(),
        )?,
        command @ (Command::Approve { .. } | Command::Deny { .. }) => {
            let (request_id, approve) = match command {
                Command::Approve { request_id } => (request_id, true),
                Command::Deny { request_id } => (request_id, false),
                _ => unreachable!(),
            };
            serde_json::to_value(
                supervisor(&state)
                    .await?
                    .decide_approval(request(
                        proto::ApprovalDecision {
                            request_id,
                            approve,
                        },
                        &read(&state.join("supervisor.key"))?,
                    )?)
                    .await?
                    .into_inner(),
            )?
        }
        Command::Invoke {
            credentials_file,
            capability_file,
            tool,
            args,
            approval_id,
        } => {
            let credentials: proto::SpawnResponse =
                serde_json::from_str(&read(&credentials_file)?)?;
            let message = proto::InvokeRequest {
                agent_id: credentials.agent.context("missing agent")?.agent_id,
                tool,
                args_json: args,
                approval_id,
                capability: read_cap(&capability_file)?,
            };
            serde_json::to_value(
                AgentSyscallsClient::new(connect(state.join("agent.sock")).await?)
                    .invoke(request(message, &credentials.session_token)?)
                    .await?
                    .into_inner(),
            )?
        }
        Command::Caps {
            command:
                Caps::IssueTool {
                    agent_id,
                    tool,
                    resource,
                    max_calls,
                    ttl_seconds,
                },
        } => serde_json::to_value(
            supervisor(&state)
                .await?
                .issue_tool_capability(request(
                    proto::IssueToolCapabilityRequest {
                        agent_id,
                        tool,
                        resource,
                        max_calls,
                        ttl_seconds,
                    },
                    &read(&state.join("supervisor.key"))?,
                )?)
                .await?
                .into_inner(),
        )?,
        Command::ListAgents => serde_json::to_value(
            supervisor(&state)
                .await?
                .list_agents(request(
                    proto::Empty {},
                    &read(&state.join("supervisor.key"))?,
                )?)
                .await?
                .into_inner(),
        )?,
        Command::Features => serde_json::to_value(
            supervisor(&state)
                .await?
                .features(request(
                    proto::Empty {},
                    &read(&state.join("supervisor.key"))?,
                )?)
                .await?
                .into_inner(),
        )?,
        Command::Spawn {
            name,
            prompt,
            model,
            provider,
            limits,
            capability_file,
        } => {
            let budget = limits.budget();
            let capability = match capability_file {
                Some(path) => read_cap(&path)?,
                None => issue(&state, 1, 300, budget).await?.capability,
            };
            let message = proto::SpawnRequest {
                spec: Some(proto::AgentSpec {
                    name,
                    prompt,
                    model,
                    provider,
                    context_window: 4096,
                }),
                budget: Some(budget),
                capability,
            };
            serde_json::to_value(
                AgentSyscallsClient::new(connect(state.join("agent.sock")).await?)
                    .spawn(request(message, &read(&state.join("bootstrap.key"))?)?)
                    .await?
                    .into_inner(),
            )?
        }
        Command::Exit {
            agent_id,
            credentials_file,
            status,
        } => {
            let credentials: proto::SpawnResponse =
                serde_json::from_str(&read(&credentials_file)?)?;
            anyhow::ensure!(
                credentials.agent.as_ref().map(|a| a.agent_id.as_str()) == Some(agent_id.as_str()),
                "credentials belong to another agent"
            );
            let message = proto::ExitRequest {
                agent_id,
                status,
                capability: credentials.exit_capability,
            };
            serde_json::to_value(
                AgentSyscallsClient::new(connect(state.join("agent.sock")).await?)
                    .exit(request(message, &credentials.session_token)?)
                    .await?
                    .into_inner(),
            )?
        }
        Command::Caps {
            command:
                Caps::Issue {
                    max_calls,
                    ttl_seconds,
                    limits,
                },
        } => serde_json::to_value(issue(&state, max_calls, ttl_seconds, limits.budget()).await?)?,
        Command::Caps {
            command:
                Caps::Attenuate {
                    token_file,
                    public_key_file,
                    subject,
                    operation,
                    resource,
                    max_calls,
                    ttl_seconds,
                    limits,
                },
        } => {
            let expires_at = praesidionyx_caps::now()?
                .checked_add(ttl_seconds)
                .context("TTL overflow")?;
            let restriction = praesidionyx_caps::Grant {
                subject,
                operation,
                resource,
                expires_at,
                max_calls,
                budget: limits.cap_budget(),
            };
            println!(
                "{}",
                praesidionyx_caps::attenuate(
                    &read_cap(&token_file)?,
                    &read(&public_key_file.unwrap_or_else(|| state.join("capability.pub")))?,
                    &restriction
                )?
            );
            return Ok(());
        }
        Command::Audit {
            command:
                Audit::Verify {
                    file: Some(file),
                    public_key_file: Some(public),
                    checkpoint,
                },
        } => {
            let key = praesidionyx_audit::public_key(&read(&public)?)?;
            let result = praesidionyx_audit::verify(&file, &key, checkpoint.as_deref())?;
            serde_json::json!({"valid":true,"records":result.head.records,"head_hash":result.head.hash,"checkpoint_checked":checkpoint.is_some()})
        }
        Command::Audit {
            command: Audit::Verify { .. },
        } => serde_json::to_value(
            supervisor(&state)
                .await?
                .audit_verify(request(
                    proto::Empty {},
                    &read(&state.join("supervisor.key"))?,
                )?)
                .await?
                .into_inner(),
        )?,
        Command::Audit {
            command: Audit::Tail { limit },
        } => {
            let response = supervisor(&state)
                .await?
                .audit_tail(request(
                    proto::AuditTailRequest { limit },
                    &read(&state.join("supervisor.key"))?,
                )?)
                .await?
                .into_inner();
            serde_json::Value::Array(
                response
                    .records_json
                    .iter()
                    .map(|s| serde_json::from_str(s))
                    .collect::<Result<_, _>>()?,
            )
        }
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
