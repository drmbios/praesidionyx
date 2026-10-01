use super::*;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub const TICK: Duration = Duration::from_millis(50);
pub(super) struct Runtime {
    pub(super) started: Instant,
    pub(super) deadline: Instant,
    pub(super) cancel: CancellationToken,
    pub(super) busy: Arc<AtomicBool>,
    pub(super) inbox: VecDeque<serde_json::Value>,
}
impl Runtime {
    pub(super) fn new(ms: u64) -> Self {
        let started = Instant::now();
        Self {
            started,
            deadline: started + Duration::from_millis(ms),
            cancel: CancellationToken::new(),
            busy: Arc::new(AtomicBool::new(false)),
            inbox: VecDeque::new(),
        }
    }
}
pub(super) struct Flight(Arc<AtomicBool>);
impl Drop for Flight {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
pub(super) struct Delegation {
    pub(super) subject: String,
    pub(super) floor: String,
}
impl Kernel {
    fn exhausted(process: &AgentProcess) -> Option<&'static str> {
        let used = process.view.used.as_ref().unwrap();
        let budget = process.view.budget.as_ref().unwrap();
        if Instant::now() >= process.runtime.deadline {
            Some("wall_time")
        } else if matches!(process.state, AgentState::Created) {
            None
        } else if used.tokens >= budget.tokens {
            Some("tokens")
        } else if budget.cost_microusd > 0 && used.cost_microusd >= budget.cost_microusd {
            Some("cost")
        } else if budget.tool_calls > 0
            && used.tool_calls >= budget.tool_calls
            && !process.runtime.busy.load(Ordering::SeqCst)
        {
            Some("tool_calls")
        } else {
            None
        }
    }
    pub(super) fn stop(&self, process: &mut AgentProcess, reason: &str) -> Result<(), Status> {
        if matches!(process.state, AgentState::Killed | AgentState::Finished) {
            return Ok(());
        }
        process.runtime.cancel.cancel();
        process.state = AgentState::Killed;
        process.view.state = "killed".into();
        process.view.exit_status = Some(-1);
        self.record(&process.view.agent_id, "agent.kill", reason)
    }
    pub(super) fn stop_descendants(
        &self,
        agents: &mut BTreeMap<String, AgentProcess>,
        id: String,
        reason: &str,
    ) -> Result<(), Status> {
        let mut stopped = vec![id];
        let mut failure = None;
        while let Some(id) = stopped.pop() {
            for process in agents.values_mut() {
                if process.view.parent_id == id
                    && matches!(
                        process.state,
                        AgentState::Created | AgentState::Running | AgentState::Paused
                    )
                {
                    if let Err(error) = self.stop(process, reason) {
                        failure.get_or_insert(error);
                    }
                    stopped.push(process.view.agent_id.clone());
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
    fn stop_tree(
        &self,
        agents: &mut BTreeMap<String, AgentProcess>,
        id: &str,
        reason: &str,
    ) -> Result<(), Status> {
        let process = agents
            .get_mut(id)
            .ok_or_else(|| Status::not_found("unknown agent"))?;
        let root = self.stop(process, reason);
        // Cancellation must reach every descendant even if recording the root fails.
        let descendants = self.stop_descendants(agents, id.to_owned(), "parent.killed");
        root.and(descendants)
    }
    pub async fn tick(&self) -> Result<(), Status> {
        let mut agents = self.agents.lock().await;
        let mut exhausted = Vec::new();
        for process in agents.values_mut() {
            if matches!(
                process.state,
                AgentState::Created | AgentState::Running | AgentState::Paused
            ) {
                process.view.used.as_mut().unwrap().wall_time_ms = process
                    .runtime
                    .started
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX))
                    as u64;
                if let Some(reason) = Self::exhausted(process) {
                    exhausted.push((process.view.agent_id.clone(), format!("budget.{reason}")));
                }
            }
        }
        let mut failure = None;
        for (id, reason) in exhausted {
            if let Err(error) = self.stop_tree(&mut agents, &id, &reason) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
    pub async fn run_scheduler(&self) {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = self.tick().await {
                tracing::error!(%error,"scheduler audit failure; affected agent stopped");
            }
        }
    }
    pub(super) async fn begin_tool(&self, id: &str) -> Result<(CancellationToken, Flight), Status> {
        let mut agents = self.agents.lock().await;
        let p = agents.get_mut(id).unwrap();
        if !matches!(p.state, AgentState::Running) {
            return Err(Status::failed_precondition("agent stopped or paused"));
        }
        if let Some(reason) = Self::exhausted(p) {
            self.stop_tree(&mut agents, id, &format!("budget.{reason}"))?;
            return Err(Status::resource_exhausted("agent budget exhausted"));
        }
        if p.view.used.as_ref().unwrap().tool_calls >= p.view.budget.as_ref().unwrap().tool_calls {
            self.stop_tree(&mut agents, id, "budget.tool_calls")?;
            return Err(Status::resource_exhausted("tool budget exhausted"));
        }
        p.view.used.as_mut().unwrap().tool_calls += 1;
        p.runtime.busy.store(true, Ordering::SeqCst);
        Ok((p.runtime.cancel.clone(), Flight(p.runtime.busy.clone())))
    }
    pub async fn control(&self, token: &str, request: ControlRequest) -> Result<Agent, Status> {
        // An authenticated emergency kill remains effective when the audit disk is
        // unavailable. Report the storage error after cancelling the whole tree.
        if request.action == "kill"
            && auth::matches(&self.supervisor_key, token)
            && praesidionyx_policy::supervisor_operation("supervisor.kill")
        {
            let authorization = self.authorize_supervisor(token, "supervisor.kill");
            let mut agents = self.agents.lock().await;
            let p = agents
                .get(&request.agent_id)
                .ok_or_else(|| Status::not_found("unknown agent"))?;
            if !matches!(
                p.state,
                AgentState::Created | AgentState::Running | AgentState::Paused
            ) {
                return Err(Status::failed_precondition("agent already stopped"));
            }
            let stopped = self.stop_tree(&mut agents, &request.agent_id, "supervisor");
            let view = agents[&request.agent_id].view.clone();
            authorization.and(stopped)?;
            return Ok(view);
        }
        self.authorize_supervisor(token, "supervisor.kill")?;
        let mut agents = self.agents.lock().await;
        let p = agents
            .get_mut(&request.agent_id)
            .ok_or_else(|| Status::not_found("unknown agent"))?;
        match request.action.as_str() {
            "pause" if matches!(p.state, AgentState::Running) => {
                self.record(&request.agent_id, "agent.pause", "paused")?;
                p.runtime.cancel.cancel();
                p.state = AgentState::Paused;
                p.view.state = "paused".into();
            }
            "resume" if matches!(p.state, AgentState::Paused) => {
                self.record(&request.agent_id, "agent.resume", "running")?;
                p.runtime.cancel = CancellationToken::new();
                p.state = AgentState::Running;
                p.view.state = "running".into();
            }
            _ => return Err(Status::failed_precondition("invalid control or state")),
        }
        Ok(p.view.clone())
    }
    pub async fn message(
        &self,
        token: &str,
        request: MessageRequest,
    ) -> Result<MemoryResponse, Status> {
        let gate = self
            .tool_gate(&request.agent_id, token, "agent.message")
            .await?;
        let mut gates = vec![(request.agent_id.clone(), gate)];
        if request.operation == "send" && request.target_id != request.agent_id {
            let agents = self.agents.lock().await;
            let receiver = agents
                .get(&request.target_id)
                .ok_or_else(|| Status::not_found("unknown recipient"))?;
            gates.push((request.target_id.clone(), receiver.tools.clone()));
        }
        // Ordered acquisition prevents cross-send deadlocks and serializes incoming
        // provenance with a recipient's approval check and external effect.
        gates.sort_by(|a, b| a.0.cmp(&b.0));
        let mut guards = Vec::new();
        for (_, gate) in gates {
            guards.push(gate.lock_owned().await);
        }
        let mut agents = self.agents.lock().await;
        let sender = agents.get(&request.agent_id).unwrap();
        if !matches!(sender.state, AgentState::Running) {
            return Err(Status::failed_precondition("agent not running"));
        }
        let label = sender.label;
        self.authorize_capability(
            &request.agent_id,
            "agent.local",
            &request.agent_id,
            &request.capability,
            &Budget::default(),
            &request.operation,
        )?;
        let value = match request.operation.as_str() {
            "send" => {
                if !matches!(request.kind.as_str(), "text" | "task" | "result")
                    || request.content.len() > 16384
                {
                    return Err(Status::invalid_argument("invalid message kind or payload"));
                }
                let receiver = agents
                    .get_mut(&request.target_id)
                    .ok_or_else(|| Status::not_found("unknown recipient"))?;
                if !matches!(
                    receiver.state,
                    AgentState::Created | AgentState::Running | AgentState::Paused
                ) || receiver.runtime.inbox.len() >= 64
                {
                    return Err(Status::resource_exhausted(
                        "recipient stopped or inbox full",
                    ));
                }
                self.record(&request.agent_id, "message.send", "sent")?;
                let id = Uuid::new_v4().to_string();
                receiver.label = receiver.label.join(label);
                receiver.view.context_label = receiver.label.as_str().into();
                receiver.view.context_revision += 1;
                self.append_context(&request.target_id, &request.content, label)?;
                receiver.runtime.inbox.push_back(serde_json::json!({"id":id,"sender":request.agent_id,"kind":request.kind,"content":request.content,"label":label.as_str()}));
                serde_json::json!({"message_id":id})
            }
            "receive" => {
                serde_json::json!({"message":agents.get_mut(&request.agent_id).unwrap().runtime.inbox.pop_front()})
            }
            "yield" => serde_json::json!({"yielded":true}),
            _ => return Err(Status::invalid_argument("unknown message operation")),
        };
        drop(agents);
        tokio::task::yield_now().await;
        Ok(MemoryResponse {
            result_json: value.to_string(),
        })
    }
}

impl Kernel {
    pub async fn spawn_child(
        &self,
        token: &str,
        request: SpawnChildRequest,
    ) -> Result<SpawnChildResponse, Status> {
        let gate = self
            .tool_gate(&request.agent_id, token, "agent.spawn_child")
            .await?;
        let _guard = gate.lock().await;
        let spec = request
            .spec
            .clone()
            .ok_or_else(|| Status::invalid_argument("child spec required"))?;
        let budget = request
            .budget
            .ok_or_else(|| Status::invalid_argument("child budget required"))?;
        if budget.tokens == 0 || budget.wall_time_ms == 0 || budget.tool_calls == 0 {
            return Err(Status::invalid_argument(
                "child requires positive token/time/tool budgets",
            ));
        }
        let scope = crate::tool_bus::capability_scope(&request.tool, &request.resource)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        self.check_capability(
            &request.agent_id,
            "agent.local",
            &request.agent_id,
            &request.capability,
            &Budget::default(),
        )?;
        self.check_capability(
            &request.agent_id,
            &request.tool,
            &scope,
            &request.delegated_capability,
            &Budget {
                tokens: 0,
                wall_time_ms: 10000,
                tool_calls: 1,
                cost_microusd: 0,
            },
        )?;
        {
            let security = self.security()?;
            let root = security
                .authority
                .root_id(&request.delegated_capability)
                .map_err(security_error)?;
            if let Some(inherited) = security.delegations.get(&(request.agent_id.clone(), root)) {
                // Re-delegation must start at the exact inherited floor. Accepting
                // an ancestor here would discard a previous attenuation block.
                if inherited.floor != request.delegated_capability {
                    return Err(Status::permission_denied(
                        "re-delegate the exact inherited capability",
                    ));
                }
            }
        }
        let args=serde_json::json!({"spec":spec,"budget":budget,"tool":request.tool,"resource":request.resource,"delegated_capability":request.delegated_capability}).as_object().unwrap().clone();
        let approval = InvokeRequest {
            agent_id: request.agent_id.clone(),
            tool: "agent.spawn_child".into(),
            args_json: serde_json::to_string(&args).map_err(security_error)?,
            capability: request.capability.clone(),
            approval_id: request.approval_id,
        };
        if let Some(pending) = self.approval_gate(&approval, &args).await? {
            return Ok(SpawnChildResponse {
                child: None,
                delegated_capability: String::new(),
                outcome: pending.outcome,
                request_id: pending.request_id,
            });
        }
        let (label, deadline) = {
            let mut agents = self.agents.lock().await;
            let parent = agents.get_mut(&request.agent_id).unwrap();
            if !matches!(parent.state, AgentState::Running) {
                return Err(Status::failed_precondition("parent is not running"));
            }
            let used = parent.view.used.as_mut().unwrap();
            let ceiling = parent.view.budget.as_ref().unwrap();
            let remaining_ms = parent
                .runtime
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            if budget.tokens > ceiling.tokens.saturating_sub(used.tokens)
                || budget.tool_calls > ceiling.tool_calls.saturating_sub(used.tool_calls)
                || budget.cost_microusd > ceiling.cost_microusd.saturating_sub(used.cost_microusd)
                || u128::from(budget.wall_time_ms) > remaining_ms
            {
                return Err(Status::permission_denied(
                    "child budget exceeds parent's remaining budget",
                ));
            }
            self.authorize_capability(
                &request.agent_id,
                "agent.local",
                &request.agent_id,
                &request.capability,
                &Budget::default(),
                "spawn_child",
            )?;
            // Reserve child allocations up front; failure/cancellation never refunds authority.
            used.tokens += budget.tokens;
            used.tool_calls += budget.tool_calls;
            used.cost_microusd += budget.cost_microusd;
            parent.view.context_revision += 1;
            (parent.label, parent.runtime.deadline)
        };
        let (grant_id, subject, delegated_capability, bootstrap_cap) = {
            let security = self.security()?;
            let grant_id = security
                .authority
                .root_id(&request.delegated_capability)
                .map_err(security_error)?;
            let subject = security
                .delegations
                .get(&(request.agent_id.clone(), grant_id.clone()))
                .map(|d| d.subject.clone())
                .unwrap_or_else(|| request.agent_id.clone());
            let calls = *security.calls.get(&grant_id).unwrap_or(&0);
            let narrowed = praesidionyx_caps::attenuate(
                &request.delegated_capability,
                &security.authority.public_hex(),
                &praesidionyx_caps::Grant {
                    subject: subject.clone(),
                    operation: request.tool,
                    resource: scope,
                    expires_at: praesidionyx_caps::now().map_err(security_error)? + 300,
                    max_calls: calls.saturating_add(budget.tool_calls),
                    budget: praesidionyx_caps::Budget {
                        tokens: 0,
                        wall_time_ms: 10000,
                        tool_calls: 1,
                        cost_microusd: 0,
                    },
                },
            )
            .map_err(security_error)?;
            let (_, bootstrap) = security
                .authority
                .issue(&praesidionyx_caps::Grant {
                    subject: "bootstrap".into(),
                    operation: "agent.spawn".into(),
                    resource: "agents".into(),
                    expires_at: praesidionyx_caps::now().map_err(security_error)? + 60,
                    max_calls: 1,
                    budget: cap_budget(&budget),
                })
                .map_err(security_error)?;
            (grant_id, subject, narrowed, bootstrap)
        };
        let mut spawned = self
            .spawn_inner(
                &self.bootstrap_key,
                SpawnRequest {
                    spec: Some(spec),
                    budget: Some(budget),
                    capability: bootstrap_cap,
                },
                Some(&request.agent_id),
            )
            .await?;
        let child_id = spawned.agent.as_ref().unwrap().agent_id.clone();
        let mut agents = self.agents.lock().await;
        let parent_running = agents
            .get(&request.agent_id)
            .is_some_and(|p| matches!(p.state, AgentState::Running));
        let child = agents.get_mut(&child_id).unwrap();
        child.view.parent_id = request.agent_id.clone();
        child.runtime.deadline = child.runtime.deadline.min(deadline);
        child.label = child.label.join(label);
        child.view.context_label = child.label.as_str().into();
        if child.label == praesidionyx_policy::Label::Untrusted {
            self.memory()?.taint(&child_id).map_err(security_error)?;
        }
        if !parent_running {
            self.stop(child, "parent.stopped_during_spawn")?;
            return Err(Status::aborted("parent stopped during child creation"));
        }
        let mut security = self.security()?;
        let recorded = security
            .audit
            .append(
                &request.agent_id,
                "agent.spawn_child",
                "delegated",
                Some(&grant_id),
                Some(&child_id),
            )
            .map_err(security_error);
        if let Err(error) = recorded {
            drop(security);
            let _ = self.stop(child, "delegation.audit_failed");
            return Err(error);
        }
        security.delegations.insert(
            (child_id, grant_id),
            Delegation {
                subject,
                floor: delegated_capability.clone(),
            },
        );
        spawned.agent = Some(child.view.clone());
        Ok(SpawnChildResponse {
            child: Some(spawned),
            delegated_capability,
            outcome: "completed".into(),
            request_id: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn fixture() -> (tempfile::TempDir, Kernel, SpawnResponse) {
        let dir = tempfile::tempdir().unwrap();
        let k = Kernel::open("b".into(), "s".into(), dir.path()).unwrap();
        let budget = Budget {
            tokens: 4096,
            wall_time_ms: 60000,
            tool_calls: 16,
            cost_microusd: 0,
        };
        let capability = k
            .issue_capability(
                "s",
                IssueCapabilityRequest {
                    max_calls: 1,
                    ttl_seconds: 300,
                    budget: Some(budget),
                },
            )
            .unwrap()
            .capability;
        let a = k
            .spawn(
                "b",
                SpawnRequest {
                    spec: Some(AgentSpec {
                        name: "parent".into(),
                        provider: "mock".into(),
                        model: "mock-v1".into(),
                        prompt: "hello".into(),
                        context_window: 256,
                    }),
                    budget: Some(budget),
                    capability,
                },
            )
            .await
            .unwrap();
        (dir, k, a)
    }
    #[tokio::test]
    async fn failed_remember_and_empty_message_preserve_reported_taint() {
        let (_dir, k, a) = fixture().await;
        let id = a.agent.as_ref().unwrap().agent_id.clone();
        let memory = MemoryRequest {
            agent_id: id.clone(),
            capability: a.local_capability.clone(),
            operation: "remember".into(),
            content: String::new(),
            label: "untrusted".into(),
            ..Default::default()
        };
        assert_eq!(
            k.memory_call(&a.session_token, memory)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            k.memory().unwrap().context(&id).unwrap().label,
            praesidionyx_policy::Label::Untrusted
        );
        let budget = a.agent.as_ref().unwrap().budget.unwrap();
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
        let b = k
            .spawn(
                "b",
                SpawnRequest {
                    spec: a.agent.as_ref().unwrap().spec.clone(),
                    budget: Some(budget),
                    capability: cap.capability,
                },
            )
            .await
            .unwrap();
        let bid = b.agent.as_ref().unwrap().agent_id.clone();
        k.message(
            &a.session_token,
            MessageRequest {
                agent_id: id,
                capability: a.local_capability,
                operation: "send".into(),
                target_id: bid.clone(),
                kind: "text".into(),
                content: String::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            k.agents.lock().await[&bid].label,
            praesidionyx_policy::Label::Untrusted
        );
        assert_eq!(
            k.memory().unwrap().context(&bid).unwrap().label,
            praesidionyx_policy::Label::Untrusted
        );
    }
    #[tokio::test]
    async fn audit_failure_never_interrupts_emergency_tree_cancellation() {
        for emergency in [false, true] {
            let (dir, k, a) = fixture().await;
            let id = a.agent.as_ref().unwrap().agent_id.clone();
            let budget = a.agent.as_ref().unwrap().budget.unwrap();
            let mut cancellations = Vec::new();
            for _ in 0..2 {
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
                let b = k
                    .spawn(
                        "b",
                        SpawnRequest {
                            spec: a.agent.as_ref().unwrap().spec.clone(),
                            budget: Some(budget),
                            capability: cap.capability,
                        },
                    )
                    .await
                    .unwrap();
                let bid = b.agent.unwrap().agent_id;
                let mut agents = k.agents.lock().await;
                let child = agents.get_mut(&bid).unwrap();
                child.view.parent_id = id.clone();
                cancellations.push(child.runtime.cancel.clone());
            }
            // Corrupt only a temporary fixture's log, never the real state volume.
            std::fs::write(dir.path().join("audit.jsonl"), "tampered\n").unwrap();
            if emergency {
                assert!(k
                    .control(
                        "s",
                        ControlRequest {
                            agent_id: id.clone(),
                            action: "kill".into()
                        }
                    )
                    .await
                    .is_err());
            } else {
                k.agents.lock().await.get_mut(&id).unwrap().runtime.deadline = Instant::now();
                assert!(k.tick().await.is_err());
            }
            assert!(cancellations.iter().all(CancellationToken::is_cancelled));
            assert!(k
                .agents
                .lock()
                .await
                .values()
                .all(|p| matches!(p.state, AgentState::Killed)));
        }
    }
    #[tokio::test]
    async fn one_tick_budget_stop_and_supervisor_preemption() {
        let (_dir, k, a) = fixture().await;
        let id = a.agent.unwrap().agent_id;
        let (cancel, flight) = k.begin_tool(&id).await.unwrap();
        assert!(!cancel.is_cancelled());
        assert!(k
            .control(
                &a.session_token,
                ControlRequest {
                    agent_id: id.clone(),
                    action: "kill".into()
                }
            )
            .await
            .is_err());
        k.control(
            "s",
            ControlRequest {
                agent_id: id.clone(),
                action: "pause".into(),
            },
        )
        .await
        .unwrap();
        assert!(cancel.is_cancelled());
        drop(flight);
        k.control(
            "s",
            ControlRequest {
                agent_id: id.clone(),
                action: "resume".into(),
            },
        )
        .await
        .unwrap();
        let (cancel, flight) = k.begin_tool(&id).await.unwrap();
        k.agents.lock().await.get_mut(&id).unwrap().runtime.deadline = Instant::now();
        k.tick().await.unwrap();
        assert!(cancel.is_cancelled());
        drop(flight);
        assert_eq!(k.list("s").await.unwrap().agents[0].state, "killed");
        assert!(k
            .audit_tail("s", AuditTailRequest { limit: 100 })
            .unwrap()
            .records_json
            .join("")
            .contains("budget.wall_time"));
    }
    #[tokio::test]
    async fn every_budget_is_stopped_on_one_tick() {
        for reason in ["tokens", "cost", "tool_calls"] {
            let (_dir, k, a) = fixture().await;
            let id = a.agent.unwrap().agent_id;
            {
                let mut agents = k.agents.lock().await;
                let p = agents.get_mut(&id).unwrap();
                let budget = p.view.budget.as_mut().unwrap();
                let used = p.view.used.as_mut().unwrap();
                match reason {
                    "tokens" => used.tokens = budget.tokens,
                    "cost" => {
                        budget.cost_microusd = 1;
                        used.cost_microusd = 1;
                    }
                    "tool_calls" => used.tool_calls = budget.tool_calls,
                    _ => unreachable!(),
                }
            }
            k.tick().await.unwrap();
            assert_eq!(k.agents.lock().await[&id].view.state, "killed");
            assert!(k
                .audit_tail("s", AuditTailRequest { limit: 100 })
                .unwrap()
                .records_json
                .join("")
                .contains(&format!("budget.{reason}")));
        }
    }
    #[tokio::test]
    async fn parent_kill_cancels_child_during_provider_dispatch() {
        struct SlowProvider;
        #[async_trait::async_trait]
        impl crate::provider::LlmProvider for SlowProvider {
            fn name(&self) -> &'static str {
                "mock"
            }
            async fn complete(
                &self,
                _: &str,
                _: &str,
                _: &Budget,
            ) -> anyhow::Result<crate::provider::Completion> {
                std::future::pending().await
            }
        }
        let (_dir, mut k, a) = fixture().await;
        k.provider = Arc::new(SlowProvider);
        let id = a.agent.as_ref().unwrap().agent_id.clone();
        let cap = k
            .issue_tool_capability(
                "s",
                IssueToolCapabilityRequest {
                    agent_id: id.clone(),
                    tool: "fs.read".into(),
                    resource: "notes".into(),
                    max_calls: 3,
                    ttl_seconds: 300,
                },
            )
            .await
            .unwrap();
        let task_kernel = k.clone();
        let parent_id = id.clone();
        let task = tokio::spawn(async move {
            task_kernel
                .spawn_child(
                    &a.session_token,
                    SpawnChildRequest {
                        agent_id: parent_id,
                        capability: a.local_capability,
                        spec: Some(AgentSpec {
                            name: "slow-child".into(),
                            provider: "mock".into(),
                            model: "mock-v1".into(),
                            prompt: "hello".into(),
                            context_window: 256,
                        }),
                        budget: Some(Budget {
                            tokens: 512,
                            wall_time_ms: 10000,
                            tool_calls: 1,
                            cost_microusd: 0,
                        }),
                        tool: "fs.read".into(),
                        resource: "notes".into(),
                        delegated_capability: cap.capability,
                        approval_id: String::new(),
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if k.list("s")
                    .await
                    .unwrap()
                    .agents
                    .iter()
                    .any(|p| p.parent_id == id && p.state == "created")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        k.control(
            "s",
            ControlRequest {
                agent_id: id,
                action: "kill".into(),
            },
        )
        .await
        .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(k
            .list("s")
            .await
            .unwrap()
            .agents
            .iter()
            .all(|p| p.state == "killed"));
    }
    #[tokio::test]
    async fn delegated_floor_survives_ancestor_token_and_message_taint_flows() {
        let (_dir, k, a) = fixture().await;
        let id = a.agent.as_ref().unwrap().agent_id.clone();
        let cap = k
            .issue_tool_capability(
                "s",
                IssueToolCapabilityRequest {
                    agent_id: id.clone(),
                    tool: "fs.read".into(),
                    resource: "notes".into(),
                    max_calls: 3,
                    ttl_seconds: 300,
                },
            )
            .await
            .unwrap();
        let child = k
            .spawn_child(
                &a.session_token,
                SpawnChildRequest {
                    agent_id: id.clone(),
                    capability: a.local_capability.clone(),
                    spec: Some(AgentSpec {
                        name: "child".into(),
                        provider: "mock".into(),
                        model: "mock-v1".into(),
                        prompt: "read notes".into(),
                        context_window: 256,
                    }),
                    budget: Some(Budget {
                        tokens: 512,
                        wall_time_ms: 10000,
                        tool_calls: 1,
                        cost_microusd: 0,
                    }),
                    tool: "fs.read".into(),
                    resource: "notes".into(),
                    delegated_capability: cap.capability.clone(),
                    approval_id: String::new(),
                },
            )
            .await
            .unwrap();
        let b = child.child.unwrap();
        let bid = b.agent.unwrap().agent_id;
        // A nested child may not rebuild its delegation from an ancestor token.
        assert_eq!(
            k.spawn_child(
                &b.session_token,
                SpawnChildRequest {
                    agent_id: bid.clone(),
                    capability: b.local_capability.clone(),
                    spec: Some(AgentSpec {
                        name: "grandchild".into(),
                        provider: "mock".into(),
                        model: "mock-v1".into(),
                        prompt: "hello".into(),
                        context_window: 256
                    }),
                    budget: Some(Budget {
                        tokens: 128,
                        wall_time_ms: 1000,
                        tool_calls: 1,
                        cost_microusd: 0
                    }),
                    tool: "fs.read".into(),
                    resource: "notes".into(),
                    delegated_capability: cap.capability.clone(),
                    approval_id: String::new(),
                }
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        let mut call = InvokeRequest {
            agent_id: bid.clone(),
            tool: "fs.read".into(),
            args_json: r#"{"path":"other"}"#.into(),
            capability: child.delegated_capability,
            approval_id: String::new(),
        };
        assert_eq!(
            k.invoke(&b.session_token, call.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        call.args_json = r#"{"path":"notes"}"#.into();
        assert_eq!(
            k.invoke(&b.session_token, call.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        // Even possession of the original parent token cannot lift the child's floor.
        call.capability = cap.capability;
        assert_eq!(
            k.invoke(&b.session_token, call).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        k.memory_call(
            &a.session_token,
            MemoryRequest {
                agent_id: id.clone(),
                capability: a.local_capability.clone(),
                operation: "remember".into(),
                content: "web instruction".into(),
                label: "untrusted".into(),
                max_tokens: 0,
                snapshot_id: String::new(),
            },
        )
        .await
        .unwrap();
        k.message(
            &a.session_token,
            MessageRequest {
                agent_id: id.clone(),
                capability: a.local_capability,
                operation: "send".into(),
                target_id: bid.clone(),
                kind: "task".into(),
                content: "derived instruction".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            k.agents.lock().await[&bid].label,
            praesidionyx_policy::Label::Untrusted
        );
        let received = k
            .message(
                &b.session_token,
                MessageRequest {
                    agent_id: bid.clone(),
                    capability: b.local_capability,
                    operation: "receive".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(received.result_json.contains("untrusted"));
        k.control(
            "s",
            ControlRequest {
                agent_id: id,
                action: "kill".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(k.agents.lock().await[&bid].view.state, "killed");
    }
}
