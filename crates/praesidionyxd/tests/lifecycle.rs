#![forbid(unsafe_code)]
use axum::{body::Body, http::Request as HttpRequest};
use hyper_util::rt::TokioIo;
use praesidionyxd::{kernel::Kernel, proto::*, transport};
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{
    transport::{Endpoint, Server},
    Code, Request,
};
use tower::{service_fn, ServiceExt};

fn fixture() -> (tempfile::TempDir, Kernel) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Kernel::open("bootstrap".into(), "supervisor".into(), dir.path()).unwrap();
    (dir, kernel)
}
fn spec(kernel: &Kernel) -> SpawnRequest {
    SpawnRequest {
        spec: Some(AgentSpec {
            name: "test".into(),
            provider: "mock".into(),
            model: "mock-v1".into(),
            prompt: "hello".into(),
            context_window: 128,
        }),
        budget: Some(Budget {
            tokens: 100,
            wall_time_ms: 1000,
            tool_calls: 0,
            cost_microusd: 0,
        }),
        capability: kernel
            .issue_capability(
                "supervisor",
                IssueCapabilityRequest {
                    max_calls: 1,
                    ttl_seconds: 300,
                    budget: Some(Budget {
                        tokens: 100,
                        wall_time_ms: 1000,
                        tool_calls: 0,
                        cost_microusd: 0,
                    }),
                },
            )
            .unwrap()
            .capability,
    }
}
fn rpc<T>(body: T, token: &str) -> Request<T> {
    let mut request = Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}
#[tokio::test]
async fn lifecycle_identity_and_authority_are_isolated() {
    let (_state, kernel) = fixture();
    assert_eq!(
        kernel.spawn("", spec(&kernel)).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    assert_eq!(
        kernel
            .spawn("supervisor", spec(&kernel))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(
        kernel.list("bootstrap").await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let a = kernel.spawn("bootstrap", spec(&kernel)).await.unwrap();
    let b = kernel.spawn("bootstrap", spec(&kernel)).await.unwrap();
    let view = a.agent.unwrap();
    let other = b.agent.unwrap();
    assert_eq!(view.state, "running");
    assert_eq!(view.identity_public_key.len(), 64);
    assert_ne!(view.agent_id, other.agent_id);
    assert_ne!(view.identity_public_key, other.identity_public_key);
    assert_ne!(a.session_token, b.session_token);
    assert_eq!(view.mock_response, other.mock_response);
    let exit = ExitRequest {
        agent_id: view.agent_id.clone(),
        status: 7,
        capability: a.exit_capability.clone(),
    };
    assert_eq!(
        kernel
            .exit(&b.session_token, exit.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(
        kernel
            .exit("supervisor", exit.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let finished = kernel.exit(&a.session_token, exit.clone()).await.unwrap();
    assert_eq!(finished.state, "finished");
    assert_eq!(finished.exit_status, Some(7));
    assert_eq!(
        kernel
            .exit(&a.session_token, exit)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let listing = kernel.list("supervisor").await.unwrap();
    assert_eq!(listing.agents.len(), 2);
    let json = serde_json::to_string(&listing).unwrap();
    assert!(!json.contains(&a.session_token));
    assert!(!json.contains(&b.session_token));
}
#[tokio::test]
async fn validates_requests_and_fails_closed_for_unimplemented_features() {
    let (_state, kernel) = fixture();
    let mut request = spec(&kernel);
    request.spec.as_mut().unwrap().provider = "anthropic".into();
    assert_eq!(
        kernel.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    let mut request = spec(&kernel);
    request.capability = "not-a-real-token".into();
    assert_eq!(
        kernel.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let mut request = spec(&kernel);
    request.budget = None;
    assert_eq!(
        kernel.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut request = spec(&kernel);
    request.spec.as_mut().unwrap().context_window = 1;
    assert_eq!(
        kernel.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert!(kernel.list("supervisor").await.unwrap().agents.is_empty());
    assert!(!kernel.features.tool_execution_enabled);
    assert_eq!(
        kernel
            .exit(
                "x",
                ExitRequest {
                    agent_id: "absent".into(),
                    status: 0,
                    capability: String::new(),
                }
            )
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}
#[tokio::test]
async fn concurrent_spawns_do_not_lose_agents() {
    let (_state, kernel) = fixture();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let k = kernel.clone();
        tasks.spawn(async move { k.spawn("bootstrap", spec(&k)).await.unwrap() });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    assert_eq!(kernel.list("supervisor").await.unwrap().agents.len(), 16);
}
#[tokio::test]
async fn http_gateway_authentication_and_route_separation() {
    let (_state, kernel) = fixture();
    let agent = transport::agent_router(kernel.clone());
    let supervisor = transport::supervisor_router(kernel.clone());
    let response = agent
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri("/v1/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
    let response = supervisor
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri("/v1/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let response = supervisor
        .oneshot(
            HttpRequest::builder()
                .uri("/v1/agents")
                .header("authorization", "Bearer bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let response = agent
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/v1/capabilities/tools")
                .header("authorization", "Bearer bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let response = agent
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/v1/agents")
                .header("content-type", "application/json")
                .header("authorization", "Bearer bootstrap")
                .body(Body::from(serde_json::to_vec(&spec(&kernel)).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let spawned: SpawnResponse = serde_json::from_slice(&body).unwrap();
    let response = agent
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/v1/agents/{}/exit",
                    spawned.agent.unwrap().agent_id
                ))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", spawned.session_token))
                .body(Body::from(
                    serde_json::json!({"status":0,"capability":spawned.exit_capability})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}
#[tokio::test]
async fn grpc_unix_socket_lifecycle_and_service_separation() {
    let dir = tempfile::tempdir().unwrap();
    let agent_path = dir.path().join("agent.sock");
    let supervisor_path = dir.path().join("supervisor.sock");
    let agent_listener = UnixListener::bind(&agent_path).unwrap();
    let supervisor_listener = UnixListener::bind(&supervisor_path).unwrap();
    let (_state, kernel) = fixture();
    let k = kernel.clone();
    let agent_server = tokio::spawn(async move {
        Server::builder()
            .add_service(agent_syscalls_server::AgentSyscallsServer::new(k))
            .serve_with_incoming(UnixListenerStream::new(agent_listener))
            .await
            .unwrap()
    });
    let supervisor_kernel = kernel.clone();
    let supervisor_server = tokio::spawn(async move {
        Server::builder()
            .add_service(supervisor_server::SupervisorServer::new(supervisor_kernel))
            .serve_with_incoming(UnixListenerStream::new(supervisor_listener))
            .await
            .unwrap()
    });
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_| {
            let path = agent_path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let sup_channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_| {
            let path = supervisor_path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let mut misplaced = supervisor_client::SupervisorClient::new(channel.clone());
    assert_eq!(
        misplaced
            .list_agents(rpc(Empty {}, "supervisor"))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    let mut client = agent_syscalls_client::AgentSyscallsClient::new(channel);
    assert_eq!(
        client.spawn(spec(&kernel)).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let spawned = client
        .spawn(rpc(spec(&kernel), "bootstrap"))
        .await
        .unwrap()
        .into_inner();
    let id = spawned.agent.unwrap().agent_id;
    let mut supervisor = supervisor_client::SupervisorClient::new(sup_channel);
    assert_eq!(
        supervisor
            .list_agents(rpc(Empty {}, "bootstrap"))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(
        supervisor
            .list_agents(rpc(Empty {}, "supervisor"))
            .await
            .unwrap()
            .into_inner()
            .agents
            .len(),
        1
    );
    let finished = client
        .exit(rpc(
            ExitRequest {
                agent_id: id,
                status: 0,
                capability: spawned.exit_capability,
            },
            &spawned.session_token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(finished.state, "finished");
    agent_server.abort();
    supervisor_server.abort();
}

#[tokio::test]
async fn capabilities_are_required_in_addition_to_sessions() {
    let (_dir, k) = fixture();
    let mut request = spec(&k);
    request.capability.clear();
    assert_eq!(
        k.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let a = k.spawn("bootstrap", spec(&k)).await.unwrap();
    let b = k.spawn("bootstrap", spec(&k)).await.unwrap();
    for capability in [String::new(), b.exit_capability] {
        assert_eq!(
            k.exit(
                &a.session_token,
                ExitRequest {
                    agent_id: a.agent.as_ref().unwrap().agent_id.clone(),
                    status: 0,
                    capability
                }
            )
            .await
            .unwrap_err()
            .code(),
            Code::PermissionDenied
        );
    }
    assert!(k
        .issue_capability(
            "bootstrap",
            IssueCapabilityRequest {
                max_calls: 1,
                ttl_seconds: 300,
                budget: Some(Budget::default())
            }
        )
        .is_err());
    assert!(k.audit_verify(&a.session_token).is_err());
    assert!(k
        .audit_tail(&a.session_token, AuditTailRequest { limit: 1 })
        .is_err());
    let records = k
        .audit_tail("supervisor", AuditTailRequest { limit: 100 })
        .unwrap()
        .records_json
        .join("\n");
    assert!(records.contains("denied.capability"));
    assert!(!records.contains(&a.session_token));
    assert!(!records.contains(&a.exit_capability));
}
#[tokio::test]
async fn call_quota_is_atomic_and_survives_restart() {
    let (dir, k) = fixture();
    let request = spec(&k);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let k = k.clone();
        let request = request.clone();
        tasks.spawn(async move { k.spawn("bootstrap", request).await });
    }
    let mut successes = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(_) => successes += 1,
            Err(error) => assert_eq!(error.code(), Code::PermissionDenied),
        }
    }
    assert_eq!(successes, 1);
    drop(k);
    let restarted = Kernel::open("bootstrap".into(), "supervisor".into(), dir.path()).unwrap();
    assert_eq!(
        restarted
            .spawn("bootstrap", request)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}
#[tokio::test]
async fn audit_tampering_stops_mutations_and_restart() {
    let (dir, k) = fixture();
    let request = spec(&k);
    let path = dir.path().join("audit.jsonl");
    let mut bytes = std::fs::read(&path).unwrap();
    let i = bytes
        .windows(12)
        .position(|b| b == b"kernel.start")
        .unwrap();
    bytes[i] = b'K';
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        k.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    drop(k);
    assert!(Kernel::open("bootstrap".into(), "supervisor".into(), dir.path()).is_err());
}
#[tokio::test]
async fn attenuated_budget_is_enforced_and_tokens_share_usage() {
    let (_dir, k) = fixture();
    let issued = k
        .issue_capability(
            "supervisor",
            IssueCapabilityRequest {
                max_calls: 2,
                ttl_seconds: 300,
                budget: Some(Budget {
                    tokens: 100,
                    wall_time_ms: 1000,
                    ..Budget::default()
                }),
            },
        )
        .unwrap();
    let restriction = praesidionyx_caps::Grant {
        subject: "bootstrap".into(),
        operation: "agent.spawn".into(),
        resource: "agents".into(),
        expires_at: issued.expires_at,
        max_calls: 1,
        budget: praesidionyx_caps::Budget {
            tokens: 50,
            wall_time_ms: 1000,
            ..praesidionyx_caps::Budget::default()
        },
    };
    let child =
        praesidionyx_caps::attenuate(&issued.capability, &issued.root_public_key, &restriction)
            .unwrap();
    let mut request = spec(&k);
    request.capability = child.clone();
    assert_eq!(
        k.spawn("bootstrap", request.clone())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    request.budget.as_mut().unwrap().tokens = 50;
    k.spawn("bootstrap", request.clone()).await.unwrap();
    assert_eq!(
        k.spawn("bootstrap", request.clone())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    request.capability = issued.capability;
    k.spawn("bootstrap", request.clone()).await.unwrap();
    assert_eq!(
        k.spawn("bootstrap", request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}

#[tokio::test]
async fn tool_capabilities_are_exact_and_missing_controls_fail_closed() {
    let (state, k) = fixture();
    let a = k.spawn("bootstrap", spec(&k)).await.unwrap();
    let b = k.spawn("bootstrap", spec(&k)).await.unwrap();
    let id = a.agent.unwrap().agent_id;
    let grant = IssueToolCapabilityRequest {
        agent_id: id.clone(),
        tool: "fs.write".into(),
        resource: "note.txt".into(),
        max_calls: 1,
        ttl_seconds: 300,
    };
    assert_eq!(
        k.issue_tool_capability(&a.session_token, grant.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let issued = k.issue_tool_capability("supervisor", grant).await.unwrap();
    let req = InvokeRequest {
        approval_id: String::new(),
        agent_id: id.clone(),
        tool: "fs.write".into(),
        args_json: r#"{"path":"note.txt","content":"test"}"#.into(),
        capability: issued.capability.clone(),
    };
    assert_eq!(
        k.invoke(&b.session_token, req.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let mut changed = req.clone();
    changed.capability.clear();
    assert_eq!(
        k.invoke(&a.session_token, changed)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut changed = req.clone();
    changed.args_json = r#"{"path":"other.txt","content":"test"}"#.into();
    assert_eq!(
        k.invoke(&a.session_token, changed)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut changed = req.clone();
    changed.tool = "http.get".into();
    changed.args_json = r#"{"url":"http://127.0.0.1/"}"#.into();
    assert_eq!(
        k.invoke(&a.session_token, changed)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut changed = req.clone();
    changed.agent_id = b.agent.unwrap().agent_id;
    assert_eq!(
        k.invoke(&b.session_token, changed)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        k.invoke(&a.session_token, req.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert!(
        !state.path().join("workspaces").exists(),
        "unconfined execution must not touch workspace"
    );
    assert_eq!(
        k.invoke(&a.session_token, req).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    k.audit_verify("supervisor").unwrap();
}
