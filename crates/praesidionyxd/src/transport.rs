use crate::{
    kernel::Kernel,
    proto::{self, agent_syscalls_server::AgentSyscalls, supervisor_server::Supervisor},
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tonic::{Request, Status};

fn rpc_token<T>(request: &Request<T>) -> &str {
    request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}
fn http_token(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}
#[tonic::async_trait]
impl AgentSyscalls for Kernel {
    async fn message(
        &self,
        request: Request<proto::MessageRequest>,
    ) -> Result<tonic::Response<proto::MemoryResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.message(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }
    async fn spawn_child(
        &self,
        request: Request<proto::SpawnChildRequest>,
    ) -> Result<tonic::Response<proto::SpawnChildResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.spawn_child(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }

    async fn memory(
        &self,
        request: Request<proto::MemoryRequest>,
    ) -> Result<tonic::Response<proto::MemoryResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.memory_call(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }

    async fn invoke(
        &self,
        request: Request<proto::InvokeRequest>,
    ) -> Result<tonic::Response<proto::InvokeResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.invoke(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }

    async fn spawn(
        &self,
        request: Request<proto::SpawnRequest>,
    ) -> Result<tonic::Response<proto::SpawnResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.spawn(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }
    async fn exit(
        &self,
        request: Request<proto::ExitRequest>,
    ) -> Result<tonic::Response<proto::Agent>, Status> {
        let token = rpc_token(&request).to_owned();
        self.exit(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }
}
#[tonic::async_trait]
impl Supervisor for Kernel {
    async fn control(
        &self,
        request: Request<proto::ControlRequest>,
    ) -> Result<tonic::Response<proto::Agent>, Status> {
        let token = rpc_token(&request).to_owned();
        self.control(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }

    async fn list_approvals(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<tonic::Response<proto::ApprovalList>, Status> {
        self.list_approvals(rpc_token(&request))
            .await
            .map(tonic::Response::new)
    }
    async fn decide_approval(
        &self,
        request: Request<proto::ApprovalDecision>,
    ) -> Result<tonic::Response<proto::Approval>, Status> {
        let token = rpc_token(&request).to_owned();
        self.decide_approval(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }

    async fn issue_tool_capability(
        &self,
        request: Request<proto::IssueToolCapabilityRequest>,
    ) -> Result<tonic::Response<proto::CapabilityResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.issue_tool_capability(&token, request.into_inner())
            .await
            .map(tonic::Response::new)
    }

    async fn list_agents(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<tonic::Response<proto::AgentList>, Status> {
        self.list(rpc_token(&request))
            .await
            .map(tonic::Response::new)
    }
    async fn features(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<tonic::Response<proto::FeatureReport>, Status> {
        self.feature_report(rpc_token(&request))
            .map(tonic::Response::new)
    }
    async fn issue_capability(
        &self,
        request: Request<proto::IssueCapabilityRequest>,
    ) -> Result<tonic::Response<proto::CapabilityResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.issue_capability(&token, request.into_inner())
            .map(tonic::Response::new)
    }
    async fn audit_verify(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<tonic::Response<proto::AuditVerification>, Status> {
        self.audit_verify(rpc_token(&request))
            .map(tonic::Response::new)
    }
    async fn audit_tail(
        &self,
        request: Request<proto::AuditTailRequest>,
    ) -> Result<tonic::Response<proto::AuditTailResponse>, Status> {
        let token = rpc_token(&request).to_owned();
        self.audit_tail(&token, request.into_inner())
            .map(tonic::Response::new)
    }
}
struct HttpError(Status);
impl From<Status> for HttpError {
    fn from(s: Status) -> Self {
        Self(s)
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let code = match self.0.code() {
            tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
            tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
            tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            tonic::Code::NotFound => StatusCode::NOT_FOUND,
            tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
            tonic::Code::FailedPrecondition => StatusCode::CONFLICT,
            tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, Json(serde_json::json!({"error":self.0.message()}))).into_response()
    }
}
pub fn agent_router(kernel: Kernel) -> Router {
    Router::new().route("/healthz", get(|State(kernel): State<Kernel>| async move { Json(serde_json::json!({"status":"ok", "milestone":7, "tool_execution_enabled":kernel.features.tool_execution_enabled})) }))
        .route("/v1/agents", post(spawn))
        .route("/v1/invoke", post(invoke))
        .route("/v1/memory", post(memory))
        .route("/v1/message", post(message))
        .route("/v1/children", post(spawn_child))
        .route("/v1/agents/{agent_id}/exit", post(exit))
        .layer(DefaultBodyLimit::max(65536)).with_state(kernel)
}
pub fn supervisor_router(kernel: Kernel) -> Router {
    Router::new()
        .route("/v1/agents", get(list))
        .route("/v1/features", get(features))
        .route("/v1/approvals", get(approvals))
        .route("/v1/control", post(control))
        .route("/v1/approvals/decide", post(decide))
        .route("/v1/capabilities", post(issue))
        .route("/v1/capabilities/tools", post(issue_tool))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/v1/audit/tail", get(audit_tail))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(kernel)
}
async fn spawn(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::SpawnRequest>,
) -> Result<Json<proto::SpawnResponse>, HttpError> {
    Ok(Json(kernel.spawn(http_token(&headers), request).await?))
}
#[derive(serde::Deserialize)]
struct ExitBody {
    status: i32,
    #[serde(default)]
    capability: String,
}
async fn exit(
    State(kernel): State<Kernel>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ExitBody>,
) -> Result<Json<proto::Agent>, HttpError> {
    Ok(Json(
        kernel
            .exit(
                http_token(&headers),
                proto::ExitRequest {
                    agent_id,
                    status: body.status,
                    capability: body.capability,
                },
            )
            .await?,
    ))
}
async fn list(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
) -> Result<Json<proto::AgentList>, HttpError> {
    Ok(Json(kernel.list(http_token(&headers)).await?))
}
async fn features(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
) -> Result<Json<proto::FeatureReport>, HttpError> {
    Ok(Json(kernel.feature_report(http_token(&headers))?))
}

async fn issue(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::IssueCapabilityRequest>,
) -> Result<Json<proto::CapabilityResponse>, HttpError> {
    Ok(Json(
        kernel.issue_capability(http_token(&headers), request)?,
    ))
}
async fn audit_verify(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
) -> Result<Json<proto::AuditVerification>, HttpError> {
    Ok(Json(kernel.audit_verify(http_token(&headers))?))
}
async fn audit_tail(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
) -> Result<Json<proto::AuditTailResponse>, HttpError> {
    Ok(Json(kernel.audit_tail(
        http_token(&headers),
        proto::AuditTailRequest { limit: 20 },
    )?))
}

async fn invoke(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::InvokeRequest>,
) -> Result<Json<proto::InvokeResponse>, HttpError> {
    Ok(Json(kernel.invoke(http_token(&headers), request).await?))
}
async fn issue_tool(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::IssueToolCapabilityRequest>,
) -> Result<Json<proto::CapabilityResponse>, HttpError> {
    Ok(Json(
        kernel
            .issue_tool_capability(http_token(&headers), request)
            .await?,
    ))
}

async fn approvals(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
) -> Result<Json<proto::ApprovalList>, HttpError> {
    Ok(Json(kernel.list_approvals(http_token(&headers)).await?))
}
async fn decide(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::ApprovalDecision>,
) -> Result<Json<proto::Approval>, HttpError> {
    Ok(Json(
        kernel
            .decide_approval(http_token(&headers), request)
            .await?,
    ))
}

async fn memory(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::MemoryRequest>,
) -> Result<Json<proto::MemoryResponse>, HttpError> {
    Ok(Json(
        kernel.memory_call(http_token(&headers), request).await?,
    ))
}

async fn message(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::MessageRequest>,
) -> Result<Json<proto::MemoryResponse>, HttpError> {
    Ok(Json(kernel.message(http_token(&headers), request).await?))
}
async fn spawn_child(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::SpawnChildRequest>,
) -> Result<Json<proto::SpawnChildResponse>, HttpError> {
    Ok(Json(
        kernel.spawn_child(http_token(&headers), request).await?,
    ))
}
async fn control(
    State(kernel): State<Kernel>,
    headers: HeaderMap,
    Json(request): Json<proto::ControlRequest>,
) -> Result<Json<proto::Agent>, HttpError> {
    Ok(Json(kernel.control(http_token(&headers), request).await?))
}
