#![forbid(unsafe_code)]
//! Deny by default. A valid token alone never enables a future syscall.
use anyhow::{ensure, Result};
use praesidionyx_caps::{Authority, Context};

pub fn authorize(authority: &Authority, token: &str, context: &Context<'_>) -> Result<()> {
    ensure!(
        matches!(
            context.operation,
            "agent.spawn" | "agent.exit" | "agent.local" | "fs.read" | "fs.write" | "http.get"
        ),
        "operation disabled by policy"
    );
    match context.operation {
        "agent.spawn" => ensure!(
            context.subject == "bootstrap" && context.resource == "agents",
            "bootstrap scope required"
        ),
        "agent.exit" | "agent.local" => ensure!(
            context.subject == context.resource && context.subject != "bootstrap",
            "own-agent scope required"
        ),
        "fs.read" | "fs.write" | "http.get" => ensure!(
            context.subject != "bootstrap"
                && context
                    .resource
                    .starts_with(if context.operation == "http.get" {
                        "url:"
                    } else {
                        "file:"
                    }),
            "tool scope required"
        ),
        _ => unreachable!(),
    }
    authority.authorize(token, context)
}
pub fn supervisor_operation(operation: &str) -> bool {
    matches!(
        operation,
        "supervisor.list"
            | "supervisor.features"
            | "supervisor.issue"
            | "supervisor.issue_tool"
            | "supervisor.audit_verify"
            | "supervisor.audit_tail"
            | "supervisor.approvals"
            | "supervisor.decide"
            | "supervisor.kill"
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use praesidionyx_caps::{Budget, Grant};
    #[test]
    fn unscoped_file_and_network_rights_do_not_enable_tools() {
        let a = Authority::from_seed(&[1; 32]).unwrap();
        for operation in ["fs.read", "fs.write", "http.get", "unknown"] {
            let grant = Grant {
                subject: "alice".into(),
                operation: operation.into(),
                resource: "/work/file".into(),
                expires_at: 100,
                max_calls: 1,
                budget: Budget::default(),
            };
            let (_, token) = a.issue(&grant).unwrap();
            let ctx = Context {
                subject: "alice",
                operation,
                resource: "/work/file",
                now: 1,
                calls_used: 0,
                budget: &Budget::default(),
            };
            assert!(authorize(&a, &token, &ctx).is_err());
            assert!(authorize(&a, "", &ctx).is_err());
        }
    }
}

/// Provenance only ever moves toward less trusted data; agents cannot declassify it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Trusted,
    User,
    Untrusted,
}
impl Label {
    pub fn join(self, other: Self) -> Self {
        self.max(other)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::User => "user",
            Self::Untrusted => "untrusted",
        }
    }
}
pub fn needs_approval(label: Label, operation: &str) -> bool {
    label == Label::Untrusted && matches!(operation, "fs.write" | "http.get" | "agent.spawn_child")
}
