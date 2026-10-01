mod runtime;
use crate::{
    auth,
    proto::*,
    provider::{self, LlmProvider},
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use runtime::{Delegation, Runtime};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
use tonic::Status;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub enum AgentState {
    Created,
    Running,
    Paused,
    Killed,
    Finished,
}
impl AgentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Killed => "killed",
            Self::Finished => "finished",
        }
    }
}
struct AgentProcess {
    view: Agent,
    // SigningKey zeroizes its private material on drop. It never leaves the kernel.
    _identity: SigningKey,
    session_token: String,
    state: AgentState,
    tools: Arc<Mutex<()>>,
    runtime: Runtime,
    label: praesidionyx_policy::Label,
    approvals: BTreeMap<String, PendingApproval>,
}
struct PendingApproval {
    view: Approval,
    capability_hash: String,
}
#[derive(Clone)]
pub struct Kernel {
    agents: Arc<Mutex<BTreeMap<String, AgentProcess>>>,
    bootstrap_key: Arc<String>,
    supervisor_key: Arc<String>,
    pub features: FeatureReport,
    security: Arc<std::sync::Mutex<Security>>,
    provider: Arc<dyn LlmProvider>,
    state_dir: std::path::PathBuf,
    memory: Arc<std::sync::Mutex<praesidionyx_memory::Store>>,
}
struct Security {
    authority: praesidionyx_caps::Authority,
    audit: praesidionyx_audit::AuditLog,
    calls: BTreeMap<String, u64>,
    audit_public: String,
    delegations: BTreeMap<(String, String), Delegation>,
}
fn cap_budget(b: &Budget) -> praesidionyx_caps::Budget {
    praesidionyx_caps::Budget {
        tokens: b.tokens,
        wall_time_ms: b.wall_time_ms,
        tool_calls: b.tool_calls,
        cost_microusd: b.cost_microusd,
    }
}
fn security_error(error: impl std::fmt::Display) -> Status {
    tracing::error!(error = %error, "security storage failure; operation refused");
    Status::unavailable("security storage unavailable; operation refused")
}
fn persist_public(path: &std::path::Path, value: &str) -> anyhow::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if path.try_exists()? {
        anyhow::ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_file(),
            "public key path must be a regular file"
        );
        anyhow::ensure!(
            std::fs::read_to_string(path)? == value,
            "pinned public key mismatch"
        );
    } else {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
    }
    Ok(())
}
impl Kernel {
    pub fn open(
        bootstrap_key: String,
        supervisor_key: String,
        state: &std::path::Path,
    ) -> anyhow::Result<Self> {
        use std::fs;
        // Never silently generate replacement keys for an existing audit history.
        if state.join("audit.jsonl").try_exists()? {
            for name in ["audit.key", "audit.pub", "capability.key", "capability.pub"] {
                anyhow::ensure!(
                    state.join(name).try_exists()?,
                    "missing security key for existing history: {name}"
                );
            }
        }
        let audit_seed: [u8; 32] = hex::decode(auth::load_or_create(&state.join("audit.key"))?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad audit key"))?;
        let caps_seed: [u8; 32] =
            hex::decode(auth::load_or_create(&state.join("capability.key"))?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad capability key"))?;
        let signing = SigningKey::from_bytes(&audit_seed);
        let audit_public = hex::encode(signing.verifying_key().as_bytes());
        let authority = praesidionyx_caps::Authority::from_seed(&caps_seed)?;
        persist_public(&state.join("audit.pub"), &audit_public)?;
        persist_public(&state.join("capability.pub"), &authority.public_hex())?;
        fs::File::open(state)?.sync_all()?;
        let mut audit = praesidionyx_audit::AuditLog::open(
            &state.join("audit.jsonl"),
            &state.join("audit.head"),
            signing,
        )?;
        let mut calls = BTreeMap::new();
        for record in audit.verify()?.records {
            if record.event.outcome == "authorized" {
                if let Some(id) = record.event.capability_id {
                    *calls.entry(id).or_insert(0u64) += 1;
                }
            }
        }
        audit.append("kernel", "kernel.start", "started", None, None)?;
        Ok(Self {
            agents: Arc::new(Mutex::new(BTreeMap::new())),
            bootstrap_key: Arc::new(bootstrap_key),
            supervisor_key: Arc::new(supervisor_key),
            features: FeatureReport {
                platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
                features: praesidionyx_sandbox::detect()
                    .into_iter()
                    .map(|f| Feature {
                        name: f.name,
                        support: f.support,
                        usability: f.usability,
                        detail: f.detail,
                    })
                    .collect(),
                tool_execution_enabled: false,
            },
            provider: provider::configured()?,
            state_dir: state.to_owned(),
            memory: Arc::new(std::sync::Mutex::new(praesidionyx_memory::Store::open(
                &state.join("memory.sqlite"),
            )?)),
            security: Arc::new(std::sync::Mutex::new(Security {
                authority,
                audit,
                calls,
                audit_public,
                delegations: BTreeMap::new(),
            })),
        })
    }
    /// Only the real sandbox probe can enable tools. Lifecycle remains available on failure.
    pub async fn initialize_tools(&mut self) {
        let id = Uuid::new_v4().to_string();
        let path = self.state_dir.join("workspaces").join(&id);
        let result = async {
            std::fs::create_dir_all(&path)?;
            crate::tool_bus::probe(&path, &id).await
        }
        .await;
        let (usability, detail) = match result {
            Ok(_) => {
                self.features.tool_execution_enabled = true;
                ("available", "Real worker probe passed: namespaces, Landlock V3, seccomp, and CPU/memory/pids cgroups".to_string())
            }
            Err(error) => ("blocked", format!("Tools disabled: {error:#}")),
        };
        let _ = std::fs::remove_dir(&path);
        let _ = std::fs::remove_dir(std::path::Path::new("/sys/fs/cgroup/agents").join(id));
        self.features.features.push(Feature {
            name: "tool_sandbox".into(),
            support: "required".into(),
            usability: usability.into(),
            detail,
        });
    }
    pub async fn issue_tool_capability(
        &self,
        token: &str,
        request: IssueToolCapabilityRequest,
    ) -> Result<CapabilityResponse, Status> {
        self.authorize_supervisor(token, "supervisor.issue_tool")?;
        if !(1..=1024).contains(&request.max_calls) || !(1..=86400).contains(&request.ttl_seconds) {
            return Err(Status::invalid_argument(
                "calls must be 1..1024 and TTL 1..86400",
            ));
        }
        let scope = crate::tool_bus::capability_scope(&request.tool, &request.resource)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let agents = self.agents.lock().await;
        let agent = agents
            .get(&request.agent_id)
            .ok_or_else(|| Status::not_found("unknown agent"))?;
        if !agent.view.parent_id.is_empty() {
            return Err(Status::permission_denied(
                "child tool rights must be delegated through its parent",
            ));
        }
        if !matches!(agent.state, AgentState::Running) {
            return Err(Status::failed_precondition("agent is not running"));
        }
        let expires_at = praesidionyx_caps::now().map_err(security_error)? + request.ttl_seconds;
        let mut security = self.security()?;
        let (grant_id, capability) = security
            .authority
            .issue(&praesidionyx_caps::Grant {
                subject: request.agent_id.clone(),
                operation: request.tool,
                resource: scope,
                expires_at,
                max_calls: request.max_calls,
                budget: praesidionyx_caps::Budget {
                    tokens: 0,
                    wall_time_ms: 10000,
                    tool_calls: 1,
                    cost_microusd: 0,
                },
            })
            .map_err(security_error)?;
        security
            .audit
            .append(
                "supervisor",
                "capability.issue_tool",
                "issued",
                Some(&grant_id),
                Some(&request.agent_id),
            )
            .map_err(security_error)?;
        Ok(CapabilityResponse {
            capability,
            grant_id,
            expires_at,
            root_public_key: security.authority.public_hex(),
        })
    }
    async fn tool_gate(
        &self,
        id: &str,
        token: &str,
        operation: &str,
    ) -> Result<Arc<Mutex<()>>, Status> {
        let agents = self.agents.lock().await;
        let Some(process) = agents.get(id) else {
            self.record("unauthenticated", operation, "denied.unknown_agent")?;
            return Err(Status::not_found("unknown agent"));
        };
        if !auth::matches(&process.session_token, token) {
            self.record("unauthenticated", operation, "denied.authentication")?;
            return Err(Status::unauthenticated(
                "agent session authentication required",
            ));
        }
        Ok(process.tools.clone())
    }
    pub async fn invoke(
        &self,
        token: &str,
        request: InvokeRequest,
    ) -> Result<InvokeResponse, Status> {
        let gate = self
            .tool_gate(&request.agent_id, token, "agent.invoke")
            .await?;
        let _guard = gate.lock().await;
        {
            let agents = self.agents.lock().await;
            if !matches!(agents[&request.agent_id].state, AgentState::Running) {
                self.record(&request.agent_id, "agent.invoke", "denied.state")?;
                return Err(Status::failed_precondition("agent is not running"));
            }
        }
        let (resource, args) = match crate::tool_bus::arguments(&request.tool, &request.args_json) {
            Ok(value) => value,
            Err(error) => {
                self.record(&request.agent_id, "agent.invoke", "denied.validation")?;
                return Err(Status::invalid_argument(error.to_string()));
            }
        };
        let scope = crate::tool_bus::capability_scope(&request.tool, &resource)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        self.check_capability(
            &request.agent_id,
            &request.tool,
            &scope,
            &request.capability,
            &Budget {
                tokens: 0,
                wall_time_ms: 10000,
                tool_calls: 1,
                cost_microusd: 0,
            },
        )?;
        if let Some(response) = self.approval_gate(&request, &args).await? {
            return Ok(response);
        }
        self.authorize_capability(
            &request.agent_id,
            &request.tool,
            &scope,
            &request.capability,
            &Budget {
                tokens: 0,
                wall_time_ms: 10000,
                tool_calls: 1,
                cost_microusd: 0,
            },
            &scope,
        )?;
        if !self.features.tool_execution_enabled {
            self.record(&request.agent_id, &request.tool, "denied.sandbox")?;
            return Err(Status::unavailable(
                "mandatory sandbox controls unavailable",
            ));
        }
        let (cancel, _flight) = self.begin_tool(&request.agent_id).await?;
        self.memory()?
            .taint(&request.agent_id)
            .map_err(security_error)?;
        // Conservatively taint before external I/O, so cancellation cannot launder provenance.
        {
            let mut agents = self.agents.lock().await;
            let process = agents.get_mut(&request.agent_id).unwrap();
            process.label = process.label.join(praesidionyx_policy::Label::Untrusted);
            process.view.context_label = process.label.as_str().into();
            process.view.context_revision += 1;
        }
        let workspace = self.state_dir.join("workspaces").join(&request.agent_id);
        std::fs::create_dir_all(&workspace).map_err(security_error)?;
        let result = tokio::select! {
            result=crate::tool_bus::invoke(&workspace,&request.agent_id,&request.tool,&resource,args) => result,
            _=cancel.cancelled() => Err(anyhow::anyhow!("agent preempted or budget exhausted")),
        };
        match result {
            Ok(value) => {
                self.append_context(
                    &request.agent_id,
                    &value["output"].to_string(),
                    praesidionyx_policy::Label::Untrusted,
                )?;
                self.record(
                    &request.agent_id,
                    &request.tool,
                    if value["is_error"] == true {
                        "tool.error"
                    } else {
                        "tool.completed"
                    },
                )?;
                Ok(InvokeResponse {
                    result_json: value.to_string(),
                    label: "untrusted".into(),
                    outcome: "completed".into(),
                    request_id: String::new(),
                })
            }
            Err(error) => {
                tracing::warn!(agent_id=%request.agent_id, tool=%request.tool, error=%error, "tool invocation failed");
                self.record(&request.agent_id, &request.tool, "tool.failed")?;
                Err(Status::unavailable(
                    "tool failed or mandatory confinement unavailable; call consumed",
                ))
            }
        }
    }
    fn check_capability(
        &self,
        actor: &str,
        op: &str,
        scope: &str,
        token: &str,
        budget: &Budget,
    ) -> Result<(), Status> {
        let security = self.security()?;
        let checked = (|| -> anyhow::Result<()> {
            let id = security.authority.root_id(token)?;
            let delegation = security.delegations.get(&(actor.to_owned(), id.clone()));
            let context = praesidionyx_caps::Context {
                subject: delegation.map(|d| d.subject.as_str()).unwrap_or(actor),
                operation: op,
                resource: scope,
                now: praesidionyx_caps::now()?,
                calls_used: *security.calls.get(&id).unwrap_or(&0),
                budget: &cap_budget(budget),
            };
            if let Some(delegation) = delegation {
                praesidionyx_policy::authorize(&security.authority, &delegation.floor, &context)?;
            }
            praesidionyx_policy::authorize(&security.authority, token, &context)
        })();
        drop(security);
        if checked.is_err() {
            self.record(actor, op, "denied.capability")?;
            return Err(Status::permission_denied("invalid or exhausted capability"));
        }
        Ok(())
    }
    pub async fn list_approvals(&self, token: &str) -> Result<ApprovalList, Status> {
        self.authorize_supervisor(token, "supervisor.approvals")?;
        Ok(ApprovalList {
            requests: self
                .agents
                .lock()
                .await
                .values()
                .flat_map(|p| p.approvals.values().map(|a| a.view.clone()))
                .collect(),
        })
    }
    pub async fn decide_approval(
        &self,
        token: &str,
        request: ApprovalDecision,
    ) -> Result<Approval, Status> {
        self.authorize_supervisor(token, "supervisor.decide")?;
        let mut agents = self.agents.lock().await;
        for process in agents.values_mut() {
            if let Some(pending) = process.approvals.get_mut(&request.request_id) {
                if pending.view.status != "pending"
                    || pending.view.expires_at
                        <= praesidionyx_caps::now().map_err(security_error)?
                    || pending.view.context_revision != process.view.context_revision
                    || !matches!(process.state, AgentState::Running)
                {
                    return Err(Status::failed_precondition(
                        "request is decided, stale, expired, or agent stopped",
                    ));
                }
                let decision = if request.approve {
                    "approved"
                } else {
                    "denied"
                };
                self.security()?
                    .audit
                    .append(
                        "supervisor",
                        "approval.decide",
                        decision,
                        None,
                        Some(&request.request_id),
                    )
                    .map_err(security_error)?;
                pending.view.status = decision.into();
                return Ok(pending.view.clone());
            }
        }
        Err(Status::not_found("unknown approval request"))
    }
    async fn approval_gate(
        &self,
        request: &InvokeRequest,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<InvokeResponse>, Status> {
        use sha2::{Digest, Sha256};
        let mut agents = self.agents.lock().await;
        let process = agents.get_mut(&request.agent_id).unwrap();
        if !matches!(process.state, AgentState::Running) {
            return Err(Status::failed_precondition("agent stopped or paused"));
        }
        if !praesidionyx_policy::needs_approval(process.label, &request.tool) {
            return Ok(None);
        }
        let canonical = serde_json::to_string(args).map_err(security_error)?;
        let capability_hash = hex::encode(Sha256::digest(request.capability.as_bytes()));
        let now = praesidionyx_caps::now().map_err(security_error)?;
        if !request.approval_id.is_empty() {
            let pending = process
                .approvals
                .get_mut(&request.approval_id)
                .ok_or_else(|| Status::permission_denied("unknown approval"))?;
            if pending.view.tool != request.tool
                || pending.view.args_json != canonical
                || pending.capability_hash != capability_hash
                || pending.view.context_revision != process.view.context_revision
                || pending.view.expires_at <= now
            {
                return Err(Status::permission_denied(
                    "approval scope changed or expired",
                ));
            }
            if pending.view.status == "approved" {
                self.security()?
                    .audit
                    .append(
                        &request.agent_id,
                        "approval.consume",
                        "consumed",
                        None,
                        Some(&request.approval_id),
                    )
                    .map_err(security_error)?;
                pending.view.status = "consumed".into();
                return Ok(None);
            }
            if pending.view.status != "pending" {
                return Err(Status::permission_denied("approval denied or consumed"));
            }
            return Ok(Some(InvokeResponse {
                outcome: "needs_approval".into(),
                request_id: pending.view.request_id.clone(),
                label: "untrusted".into(),
                result_json: "{}".into(),
            }));
        }
        process.approvals.retain(|_, p| p.view.expires_at > now);
        if process.approvals.len() >= 32 {
            return Err(Status::resource_exhausted("approval queue full"));
        }
        let id = Uuid::new_v4().to_string();
        self.security()?
            .audit
            .append(
                &request.agent_id,
                "approval.request",
                "needs_approval",
                None,
                Some(&id),
            )
            .map_err(security_error)?;
        process.approvals.insert(
            id.clone(),
            PendingApproval {
                view: Approval {
                    request_id: id.clone(),
                    agent_id: request.agent_id.clone(),
                    tool: request.tool.clone(),
                    args_json: canonical,
                    status: "pending".into(),
                    expires_at: now + 300,
                    context_revision: process.view.context_revision,
                },
                capability_hash,
            },
        );
        Ok(Some(InvokeResponse {
            outcome: "needs_approval".into(),
            request_id: id,
            label: "untrusted".into(),
            result_json: "{}".into(),
        }))
    }
    fn memory(&self) -> Result<std::sync::MutexGuard<'_, praesidionyx_memory::Store>, Status> {
        self.memory.lock().map_err(security_error)
    }
    fn append_context(
        &self,
        agent: &str,
        text: &str,
        label: praesidionyx_policy::Label,
    ) -> Result<(), Status> {
        let mut store = self.memory()?;
        // Persist provenance even for empty output or a later failed page write.
        if label == praesidionyx_policy::Label::Untrusted {
            store.taint(agent).map_err(security_error)?;
        }
        let chars: Vec<char> = text.chars().collect();
        for chunk in chars.chunks(8192) {
            store
                .remember(agent, &chunk.iter().collect::<String>(), label)
                .map_err(security_error)?;
        }
        Ok(())
    }
    pub async fn memory_call(
        &self,
        token: &str,
        request: MemoryRequest,
    ) -> Result<MemoryResponse, Status> {
        let gate = self
            .tool_gate(&request.agent_id, token, "agent.memory")
            .await?;
        let _guard = gate.lock().await;
        let mut agents = self.agents.lock().await;
        let process = agents.get_mut(&request.agent_id).unwrap();
        if !matches!(process.state, AgentState::Running) {
            return Err(Status::failed_precondition("agent is not running"));
        }
        if !matches!(
            request.operation.as_str(),
            "remember" | "recall" | "context" | "checkpoint" | "rollback"
        ) {
            return Err(Status::invalid_argument("unknown memory operation"));
        }
        self.authorize_capability(
            &request.agent_id,
            "agent.local",
            &request.agent_id,
            &request.capability,
            &Budget::default(),
            &request.operation,
        )?;
        if request.operation == "remember" && request.label == "untrusted" {
            process.label = praesidionyx_policy::Label::Untrusted;
            process.view.context_label = "untrusted".into();
            process.view.context_revision += 1;
        }
        let mut store = self.memory()?;
        if process.label == praesidionyx_policy::Label::Untrusted {
            store.taint(&request.agent_id).map_err(security_error)?;
        }
        let result = (|| -> anyhow::Result<serde_json::Value> {
            Ok(match request.operation.as_str() {
                "remember" => {
                    let requested = match request.label.as_str() {
                        "trusted" => praesidionyx_policy::Label::Trusted,
                        "user" => praesidionyx_policy::Label::User,
                        "untrusted" => praesidionyx_policy::Label::Untrusted,
                        _ => anyhow::bail!("invalid provenance label"),
                    };
                    // Agent-supplied data cannot promote its current provenance.
                    serde_json::to_value(
                        store.remember(
                            &request.agent_id,
                            &request.content,
                            requested
                                .join(process.label)
                                .join(praesidionyx_policy::Label::User),
                        )?,
                    )?
                }
                "recall" => serde_json::to_value(store.recall(
                    &request.agent_id,
                    &request.content,
                    request.max_tokens,
                )?)?,
                "context" => serde_json::to_value(store.context(&request.agent_id)?)?,
                "checkpoint" => {
                    serde_json::json!({"snapshot_id":store.checkpoint(&request.agent_id)?})
                }
                "rollback" => {
                    serde_json::to_value(store.rollback(&request.agent_id, &request.snapshot_id)?)?
                }
                _ => unreachable!(),
            })
        })()
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let label = store
            .context(&request.agent_id)
            .map_err(security_error)?
            .label;
        process.label = process.label.join(label);
        process.view.context_label = process.label.as_str().into();
        if request.operation != "context" && request.operation != "checkpoint" {
            process.view.context_revision += 1;
        }
        self.record(
            &request.agent_id,
            &format!("memory.{}", request.operation),
            "completed",
        )?;
        Ok(MemoryResponse {
            result_json: result.to_string(),
        })
    }
    fn security(&self) -> Result<std::sync::MutexGuard<'_, Security>, Status> {
        self.security.lock().map_err(security_error)
    }
    fn record(&self, actor: &str, op: &str, outcome: &str) -> Result<(), Status> {
        self.security()?
            .audit
            .append(actor, op, outcome, None, None)
            .map_err(security_error)?;
        Ok(())
    }
    fn authorize_supervisor(&self, token: &str, op: &str) -> Result<(), Status> {
        if !auth::matches(&self.supervisor_key, token) {
            self.record("unauthenticated", op, "denied.authentication")?;
            return Err(Status::unauthenticated(
                "supervisor authentication required",
            ));
        }
        if !praesidionyx_policy::supervisor_operation(op) {
            self.record("supervisor", op, "denied.policy")?;
            return Err(Status::permission_denied("operation denied by policy"));
        }
        self.record("supervisor", op, "allowed")
    }
    fn authorize_capability(
        &self,
        actor: &str,
        op: &str,
        resource: &str,
        capability: &str,
        budget: &Budget,
        target: &str,
    ) -> Result<(), Status> {
        let mut security = self.security()?;
        let result = (|| -> anyhow::Result<String> {
            let id = security.authority.root_id(capability)?;
            let delegation = security.delegations.get(&(actor.to_owned(), id.clone()));
            let context = praesidionyx_caps::Context {
                subject: delegation.map(|d| d.subject.as_str()).unwrap_or(actor),
                operation: op,
                resource,
                now: praesidionyx_caps::now()?,
                calls_used: *security.calls.get(&id).unwrap_or(&0),
                budget: &cap_budget(budget),
            };
            if let Some(delegation) = delegation {
                praesidionyx_policy::authorize(&security.authority, &delegation.floor, &context)?;
            }
            praesidionyx_policy::authorize(&security.authority, capability, &context)?;
            Ok(id)
        })();
        match result {
            Ok(id) => {
                security
                    .audit
                    .append(actor, op, "authorized", Some(&id), Some(target))
                    .map_err(security_error)?;
                *security.calls.entry(id).or_default() += 1;
                Ok(())
            }
            Err(_) => {
                security
                    .audit
                    .append(actor, op, "denied.capability", None, None)
                    .map_err(security_error)?;
                Err(Status::permission_denied(
                    "capability missing, invalid, expired, exhausted, or outside scope",
                ))
            }
        }
    }
    pub fn issue_capability(
        &self,
        token: &str,
        request: IssueCapabilityRequest,
    ) -> Result<CapabilityResponse, Status> {
        self.authorize_supervisor(token, "supervisor.issue")?;
        if !(1..=1024).contains(&request.max_calls)
            || !(1..=86400).contains(&request.ttl_seconds)
            || request.budget.is_none()
        {
            self.record("supervisor", "supervisor.issue", "denied.validation")?;
            return Err(Status::invalid_argument(
                "calls must be 1..1024, TTL 1..86400 seconds, and budget required",
            ));
        }
        let expires_at = praesidionyx_caps::now().map_err(security_error)? + request.ttl_seconds;
        let grant = praesidionyx_caps::Grant {
            subject: "bootstrap".into(),
            operation: "agent.spawn".into(),
            resource: "agents".into(),
            expires_at,
            max_calls: request.max_calls,
            budget: cap_budget(&request.budget.unwrap()),
        };
        let mut security = self.security()?;
        let (grant_id, capability) = security
            .authority
            .issue(&grant)
            .map_err(|_| Status::invalid_argument("invalid capability budget"))?;
        security
            .audit
            .append(
                "supervisor",
                "capability.issue",
                "issued",
                Some(&grant_id),
                None,
            )
            .map_err(security_error)?;
        Ok(CapabilityResponse {
            capability,
            grant_id,
            expires_at,
            root_public_key: security.authority.public_hex(),
        })
    }
    pub async fn spawn(&self, token: &str, request: SpawnRequest) -> Result<SpawnResponse, Status> {
        self.spawn_inner(token, request, None).await
    }
    async fn spawn_inner(
        &self,
        token: &str,
        request: SpawnRequest,
        parent_id: Option<&str>,
    ) -> Result<SpawnResponse, Status> {
        if !auth::matches(&self.bootstrap_key, token) {
            self.record("unauthenticated", "agent.spawn", "denied.authentication")?;
            return Err(Status::unauthenticated("bootstrap authentication required"));
        }
        let validated = (|| -> Result<(AgentSpec, Budget), Status> {
            let spec = request
                .spec
                .ok_or_else(|| Status::invalid_argument("spec is required"))?;
            let budget = request
                .budget
                .ok_or_else(|| Status::invalid_argument("budget is required"))?;
            if spec.provider != self.provider.name() {
                return Err(Status::failed_precondition(
                    "requested provider is not the configured provider",
                ));
            }
            if spec.name.is_empty()
                || spec.name.len() > 128
                || spec.model.is_empty()
                || spec.model.len() > 128
                || spec.prompt.len() > 16384
                || !(1..=131072).contains(&spec.context_window)
                || spec.prompt.len() as u32 > spec.context_window
                || budget.tokens == 0
                || !(1..=86400000).contains(&budget.wall_time_ms)
                || budget.tokens > 1000000
                || budget.tool_calls > 100000
                || budget.cost_microusd > 1000000000
            {
                return Err(Status::invalid_argument("invalid spec or budget"));
            }
            Ok((spec, budget))
        })();
        let (spec, budget) = match validated {
            Ok(value) => value,
            Err(error) => {
                self.record("bootstrap", "agent.spawn", "denied.validation")?;
                return Err(error);
            }
        };
        let mut agents = self.agents.lock().await;
        if agents.len() >= 1024 {
            self.record("bootstrap", "agent.spawn", "denied.capacity")?;
            return Err(Status::resource_exhausted("registry full"));
        }
        let mut runtime = Runtime::new(budget.wall_time_ms);
        let mut label = praesidionyx_policy::Label::User;
        if let Some(parent_id) = parent_id {
            let parent = agents
                .get(parent_id)
                .ok_or_else(|| Status::not_found("unknown parent"))?;
            if !matches!(parent.state, AgentState::Running) {
                return Err(Status::failed_precondition(
                    "parent stopped before child creation",
                ));
            }
            runtime.deadline = runtime.deadline.min(parent.runtime.deadline);
            label = label.join(parent.label);
        }
        let identity = SigningKey::generate(&mut OsRng);
        let id = Uuid::new_v4().to_string();
        let session_token = auth::new_secret();
        let expires_at = praesidionyx_caps::now().map_err(security_error)? + 86400;
        let exit_capability = self
            .security()?
            .authority
            .issue(&praesidionyx_caps::Grant {
                subject: id.clone(),
                operation: "agent.exit".into(),
                resource: id.clone(),
                expires_at,
                max_calls: 1,
                budget: praesidionyx_caps::Budget::default(),
            })
            .map_err(security_error)?
            .1;
        self.authorize_capability(
            "bootstrap",
            "agent.spawn",
            "agents",
            &request.capability,
            &budget,
            &id,
        )?;
        self.memory()?
            .create(&id, spec.context_window as u64)
            .map_err(security_error)?;
        if label == praesidionyx_policy::Label::Untrusted {
            self.memory()?.taint(&id).map_err(security_error)?;
        }
        self.append_context(&id, &spec.prompt, label)?;
        let local_capability = self
            .security()?
            .authority
            .issue(&praesidionyx_caps::Grant {
                subject: id.clone(),
                operation: "agent.local".into(),
                resource: id.clone(),
                expires_at,
                max_calls: 100000,
                budget: praesidionyx_caps::Budget::default(),
            })
            .map_err(security_error)?
            .1;
        let agent = Agent {
            agent_id: id.clone(),
            identity_public_key: hex::encode(identity.verifying_key().as_bytes()),
            spec: Some(spec.clone()),
            budget: Some(budget),
            state: AgentState::Created.as_str().into(),
            mock_response: String::new(),
            exit_status: None,
            context_label: label.as_str().into(),
            context_revision: 0,
            used: Some(Budget {
                tokens: budget.tokens,
                cost_microusd: budget.cost_microusd,
                ..Budget::default()
            }),
            parent_id: parent_id.unwrap_or_default().into(),
        };
        agents.insert(
            id.clone(),
            AgentProcess {
                view: agent.clone(),
                _identity: identity,
                session_token: session_token.clone(),
                state: AgentState::Created,
                tools: Arc::new(Mutex::new(())),
                runtime,
                label,
                approvals: BTreeMap::new(),
            },
        );
        let cancel = agents[&id].runtime.cancel.clone();
        let deadline = agents[&id].runtime.deadline;
        drop(agents);
        // Inference never holds the registry lock: other agents and scheduler run.
        // Unknown usage after cancellation retains the conservative full reservation.
        let completion = tokio::select! {
            value=self.provider.complete(&spec.model,&spec.prompt,&budget)=>value,
            _=cancel.cancelled()=>Err(anyhow::anyhow!("agent preempted during inference")),
            _=tokio::time::sleep_until(deadline)=>Err(anyhow::anyhow!("inference deadline exceeded")),
        };
        let mut agents = self.agents.lock().await;
        let process = agents.get_mut(&id).unwrap();
        let completion = match completion {
            Ok(value) if matches!(process.state, AgentState::Created) => value,
            _ => {
                self.stop(process, "provider.failed_or_preempted")?;
                return Err(Status::unavailable(
                    "provider failed or was preempted; budget reservation retained",
                ));
            }
        };
        process.view.used = Some(Budget {
            tokens: completion.tokens,
            cost_microusd: completion.cost_microusd,
            ..Default::default()
        });
        if completion.tokens > budget.tokens || completion.cost_microusd > budget.cost_microusd {
            self.stop(process, "budget.provider_usage")?;
            return Err(Status::resource_exhausted("provider exceeded budget"));
        }
        if let Err(error) = self.append_context(&id, &completion.text, process.label) {
            let _ = self.stop(process, "provider.context_storage_failed");
            return Err(error);
        }
        process.view.mock_response = completion.text;
        process.state = AgentState::Running;
        process.view.state = "running".into();
        if let Err(error) = self.record(&id, "provider.complete", "completed") {
            let _ = self.stop(process, "provider.completion_audit_failed");
            return Err(error);
        }
        let agent = process.view.clone();
        Ok(SpawnResponse {
            agent: Some(agent),
            session_token,
            exit_capability,
            local_capability,
        })
    }
    pub async fn exit(&self, token: &str, request: ExitRequest) -> Result<Agent, Status> {
        let gate = self
            .tool_gate(&request.agent_id, token, "agent.exit")
            .await?;
        let _guard = gate.lock().await;
        let mut agents = self.agents.lock().await;
        let Some(process) = agents.get_mut(&request.agent_id) else {
            self.record("unauthenticated", "agent.exit", "denied.unknown_agent")?;
            return Err(Status::not_found("unknown agent"));
        };
        if !auth::matches(&process.session_token, token) {
            self.record("unauthenticated", "agent.exit", "denied.authentication")?;
            return Err(Status::unauthenticated(
                "agent session authentication required",
            ));
        }
        if !matches!(process.state, AgentState::Running) {
            self.record(&request.agent_id, "agent.exit", "denied.state")?;
            return Err(Status::failed_precondition("agent is not running"));
        }
        self.authorize_capability(
            &request.agent_id,
            "agent.exit",
            &request.agent_id,
            &request.capability,
            &Budget::default(),
            &request.agent_id,
        )?;
        process.runtime.cancel.cancel();
        process.state = AgentState::Finished;
        process.view.state = process.state.as_str().into();
        process.view.exit_status = Some(request.status);
        let view = process.view.clone();
        self.stop_descendants(&mut agents, request.agent_id, "parent.finished")?;
        Ok(view)
    }
    pub async fn list(&self, token: &str) -> Result<AgentList, Status> {
        self.authorize_supervisor(token, "supervisor.list")?;
        Ok(AgentList {
            agents: self
                .agents
                .lock()
                .await
                .values()
                .map(|a| a.view.clone())
                .collect(),
        })
    }
    pub fn feature_report(&self, token: &str) -> Result<FeatureReport, Status> {
        self.authorize_supervisor(token, "supervisor.features")?;
        Ok(self.features.clone())
    }
    pub fn audit_verify(&self, token: &str) -> Result<AuditVerification, Status> {
        self.authorize_supervisor(token, "supervisor.audit_verify")?;
        let security = self.security()?;
        let head = security.audit.verify().map_err(security_error)?.head;
        Ok(AuditVerification {
            records: head.records,
            head_hash: head.hash,
            public_key: security.audit_public.clone(),
        })
    }
    pub fn audit_tail(
        &self,
        token: &str,
        request: AuditTailRequest,
    ) -> Result<AuditTailResponse, Status> {
        self.authorize_supervisor(token, "supervisor.audit_tail")?;
        if !(1..=100).contains(&request.limit) {
            return Err(Status::invalid_argument("limit must be 1..100"));
        }
        let verified = self.security()?.audit.verify().map_err(security_error)?;
        let skip = verified
            .records
            .len()
            .saturating_sub(request.limit as usize);
        Ok(AuditTailResponse {
            records_json: verified
                .records
                .iter()
                .skip(skip)
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()
                .map_err(security_error)?,
        })
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    #[tokio::test]
    async fn approvals_bind_arguments_revision_and_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let k = Kernel::open("b".into(), "s".into(), dir.path()).unwrap();
        let budget = Budget {
            tokens: 1000,
            wall_time_ms: 60000,
            tool_calls: 10,
            cost_microusd: 0,
        };
        let cap = k
            .issue_capability(
                "s",
                IssueCapabilityRequest {
                    max_calls: 1,
                    ttl_seconds: 300,
                    budget: Some(budget),
                },
            )
            .unwrap();
        let a = k
            .spawn(
                "b",
                SpawnRequest {
                    spec: Some(AgentSpec {
                        name: "test".into(),
                        provider: "mock".into(),
                        model: "mock-v1".into(),
                        prompt: "hello".into(),
                        context_window: 1000,
                    }),
                    budget: Some(budget),
                    capability: cap.capability,
                },
            )
            .await
            .unwrap();
        let id = a.agent.unwrap().agent_id;
        k.agents.lock().await.get_mut(&id).unwrap().label = praesidionyx_policy::Label::Untrusted;
        let grant = k
            .issue_tool_capability(
                "s",
                IssueToolCapabilityRequest {
                    agent_id: id.clone(),
                    tool: "fs.write".into(),
                    resource: "x".into(),
                    max_calls: 2,
                    ttl_seconds: 300,
                },
            )
            .await
            .unwrap();
        let mut request = InvokeRequest {
            agent_id: id,
            tool: "fs.write".into(),
            args_json: r#"{"path":"x","content":"original"}"#.into(),
            capability: grant.capability,
            approval_id: String::new(),
        };
        let pending = k.invoke(&a.session_token, request.clone()).await.unwrap();
        assert_eq!(pending.outcome, "needs_approval");
        assert!(!dir.path().join("workspaces").exists());
        assert!(k
            .decide_approval(
                &a.session_token,
                ApprovalDecision {
                    request_id: pending.request_id.clone(),
                    approve: true
                }
            )
            .await
            .is_err());
        k.decide_approval(
            "s",
            ApprovalDecision {
                request_id: pending.request_id.clone(),
                approve: true,
            },
        )
        .await
        .unwrap();
        request.approval_id = pending.request_id;
        let mut changed = request.clone();
        changed.args_json = r#"{"path":"x","content":"changed"}"#.into();
        assert_eq!(
            k.invoke(&a.session_token, changed)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        // Correct approval reaches confinement checks; it cannot bypass them.
        assert_eq!(
            k.invoke(&a.session_token, request.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            k.invoke(&a.session_token, request.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        request.approval_id.clear();
        let stale = k.invoke(&a.session_token, request.clone()).await.unwrap();
        k.memory_call(
            &a.session_token,
            MemoryRequest {
                agent_id: request.agent_id.clone(),
                capability: a.local_capability,
                operation: "remember".into(),
                content: "changed context".into(),
                label: "user".into(),
                max_tokens: 0,
                snapshot_id: String::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            k.decide_approval(
                "s",
                ApprovalDecision {
                    request_id: stale.request_id.clone(),
                    approve: true,
                }
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::FailedPrecondition
        );
        request.approval_id = stale.request_id;
        assert_eq!(
            k.invoke(&a.session_token, request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
}
