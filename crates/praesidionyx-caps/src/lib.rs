#![forbid(unsafe_code)]
//! Biscuit authority, bounded verification, and holder-side attenuation.
use anyhow::{bail, ensure, Result};
use biscuit_auth::{
    builder::{fact, int, string, AuthorizerBuilder, BlockBuilder},
    Algorithm, Biscuit, KeyPair, PrivateKey, PublicKey,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Budget {
    pub tokens: u64,
    pub wall_time_ms: u64,
    pub tool_calls: u64,
    pub cost_microusd: u64,
}
#[derive(Debug, Clone)]
pub struct Grant {
    pub subject: String,
    pub operation: String,
    pub resource: String,
    pub expires_at: u64,
    pub max_calls: u64,
    pub budget: Budget,
}
pub struct Context<'a> {
    pub subject: &'a str,
    pub operation: &'a str,
    pub resource: &'a str,
    pub now: u64,
    pub calls_used: u64,
    pub budget: &'a Budget,
}
pub struct Authority {
    key: KeyPair,
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn number(value: u64) -> Result<i64> {
    Ok(value.try_into()?)
}
fn bounded_token(encoded: &str, public: PublicKey) -> Result<Biscuit> {
    ensure!(
        !encoded.is_empty() && encoded.len() <= 16384,
        "invalid capability size"
    );
    let token = Biscuit::from_base64(encoded, public)?;
    ensure!(token.block_count() <= 8, "too many attenuation blocks");
    Ok(token)
}
fn builder() -> AuthorizerBuilder {
    AuthorizerBuilder::new().set_limits(biscuit_auth::AuthorizerLimits {
        max_facts: 256,
        max_iterations: 16,
        max_time: Duration::from_millis(50),
    })
}
// Authority scope also trusts authorizer facts in Biscuit. Only the server supplies
// contextual facts; the issuer puts only grant/right facts in the authority block. Attenuation blocks
// cannot forge actor/time/usage/budget facts to bypass an earlier restriction.
fn restrictions(grant: &Grant) -> Result<String> {
    ensure!(grant.max_calls > 0, "max_calls must be positive");
    Ok(format!(
        "check if actor({}) trusting authority;\ncheck if operation({}) trusting authority;\ncheck if resource({}) trusting authority;\ncheck if now($n), $n < {} trusting authority;\ncheck if calls_used($n), $n < {} trusting authority;\ncheck if tokens($n), $n <= {} trusting authority;\ncheck if wall_time_ms($n), $n <= {} trusting authority;\ncheck if tool_calls($n), $n <= {} trusting authority;\ncheck if cost_microusd($n), $n <= {} trusting authority;",
        quote(&grant.subject)?, quote(&grant.operation)?, quote(&grant.resource)?,
        number(grant.expires_at)?, number(grant.max_calls)?, number(grant.budget.tokens)?,
        number(grant.budget.wall_time_ms)?, number(grant.budget.tool_calls)?, number(grant.budget.cost_microusd)?,
    ))
}
fn quote(value: &str) -> Result<String> {
    // Narrow identifier alphabet avoids differences between JSON and Datalog escaping.
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:/-".contains(&c)),
        "invalid scope identifier"
    );
    Ok(format!("\"{value}\""))
}
impl Authority {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            key: KeyPair::from(&PrivateKey::from_bytes(seed, Algorithm::Ed25519)?),
        })
    }
    pub fn public_hex(&self) -> String {
        self.key.public().to_bytes_hex()
    }
    pub fn issue(&self, grant: &Grant) -> Result<(String, String)> {
        let id = Uuid::new_v4().to_string();
        let token = Biscuit::builder()
            .fact(fact("grant", &[string(&id), string(&grant.subject)]))?
            .fact(fact(
                "right",
                &[string(&grant.operation), string(&grant.resource)],
            ))?
            .code(restrictions(grant)?)?
            .build(&self.key)?;
        Ok((id, token.to_base64()?))
    }
    pub fn root_id(&self, encoded: &str) -> Result<String> {
        let token = bounded_token(encoded, self.key.public())?;
        let mut authorizer = builder().build(&token)?;
        let ids: Vec<(String,)> =
            authorizer.query("data($id) <- grant($id, $subject) trusting authority")?;
        if ids.len() != 1 {
            bail!("capability must have exactly one authority grant id");
        }
        Ok(ids[0].0.clone())
    }
    pub fn authorize(&self, encoded: &str, ctx: &Context<'_>) -> Result<()> {
        let token = bounded_token(encoded, self.key.public())?;
        let mut b = builder()
            .fact(fact("actor", &[string(ctx.subject)]))?
            .fact(fact("operation", &[string(ctx.operation)]))?
            .fact(fact("resource", &[string(ctx.resource)]))?;
        for (name, value) in [
            ("now", ctx.now),
            ("calls_used", ctx.calls_used),
            ("tokens", ctx.budget.tokens),
            ("wall_time_ms", ctx.budget.wall_time_ms),
            ("tool_calls", ctx.budget.tool_calls),
            ("cost_microusd", ctx.budget.cost_microusd),
        ] {
            b = b.fact(fact(name, &[int(number(value)?)]))?;
        }
        b.code("allow if right($op, $res), operation($op), resource($res) trusting authority;")?
            .build(&token)?
            .authorize()?;
        Ok(())
    }
}
/// Appends checks using only the parent token and pinned public key. The caller
/// retains the original token; all branches share the authority's usage counter.
pub fn attenuate(encoded: &str, public_hex: &str, restriction: &Grant) -> Result<String> {
    let public = PublicKey::from_bytes_hex(public_hex.trim(), Algorithm::Ed25519)?;
    let token = bounded_token(encoded, public)?;
    ensure!(token.block_count() < 8, "attenuation block limit reached");
    Ok(token
        .append(BlockBuilder::new().code(restrictions(restriction)?)?)?
        .to_base64()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant() -> Grant {
        Grant {
            subject: "alice".into(),
            operation: "fs.read".into(),
            resource: "/work/file".into(),
            expires_at: 100,
            max_calls: 4,
            budget: Budget {
                tokens: 100,
                ..Budget::default()
            },
        }
    }
    fn check(a: &Authority, t: &str, op: &str, at: u64, calls: u64, tokens: u64) -> bool {
        a.authorize(
            t,
            &Context {
                subject: "alice",
                operation: op,
                resource: "/work/file",
                now: at,
                calls_used: calls,
                budget: &Budget {
                    tokens,
                    ..Budget::default()
                },
            },
        )
        .is_ok()
    }
    #[test]
    fn signatures_scope_expiry_and_limits_are_enforced() {
        let a = Authority::from_seed(&[1; 32]).unwrap();
        let (_, t) = a.issue(&grant()).unwrap();
        assert!(check(&a, &t, "fs.read", 99, 3, 100));
        for (op, at, calls, tokens) in [
            ("fs.write", 1, 0, 0),
            ("fs.read", 100, 0, 0),
            ("fs.read", 1, 4, 0),
            ("fs.read", 1, 0, 101),
        ] {
            assert!(!check(&a, &t, op, at, calls, tokens));
        }
        assert!(!check(
            &Authority::from_seed(&[2; 32]).unwrap(),
            &t,
            "fs.read",
            1,
            0,
            0
        ));
        assert!(!check(&a, "forged", "fs.read", 1, 0, 0));
        assert!(a
            .authorize(
                &t,
                &Context {
                    subject: "bob",
                    operation: "fs.read",
                    resource: "/work/file",
                    now: 1,
                    calls_used: 0,
                    budget: &Budget::default()
                }
            )
            .is_err());
    }
    #[test]
    fn attenuation_cannot_widen_parent_or_reset_usage() {
        let a = Authority::from_seed(&[1; 32]).unwrap();
        let (id, t) = a.issue(&grant()).unwrap();
        let mut narrower = grant();
        narrower.max_calls = 2;
        narrower.expires_at = 50;
        narrower.budget.tokens = 10;
        let child = attenuate(&t, &a.public_hex(), &narrower).unwrap();
        assert_eq!(a.root_id(&child).unwrap(), id);
        assert!(check(&a, &child, "fs.read", 49, 1, 10));
        assert!(!check(&a, &child, "fs.read", 50, 0, 0));
        assert!(!check(&a, &child, "fs.read", 1, 2, 0));
        assert!(!check(&a, &child, "fs.read", 1, 0, 11));
        let mut wider = grant();
        wider.operation = "fs.write".into();
        wider.expires_at = 1000;
        wider.max_calls = 100;
        let bad = attenuate(&child, &a.public_hex(), &wider).unwrap();
        assert!(!check(&a, &bad, "fs.write", 1, 0, 0));
        assert!(!check(&a, &bad, "fs.read", 1, 0, 0));
    }
    #[test]
    fn appended_facts_cannot_forge_rights_time_or_usage() {
        let a = Authority::from_seed(&[1; 32]).unwrap();
        let (_, t) = a.issue(&grant()).unwrap();
        let b = bounded_token(&t, a.key.public())
            .unwrap()
            .append(
                BlockBuilder::new()
                    .code("right(\"fs.write\", \"/work/file\"); grant(\"reset-quota\", \"alice\"); now(1); calls_used(0); tokens(0);")
                    .unwrap(),
            )
            .unwrap()
            .to_base64()
            .unwrap();
        assert_eq!(a.root_id(&b).unwrap(), a.root_id(&t).unwrap());
        assert!(!check(&a, &b, "fs.write", 1, 0, 0));
        assert!(!check(&a, &b, "fs.read", 100, 0, 0));
        assert!(!check(&a, &b, "fs.read", 1, 4, 0));
        assert!(!check(&a, &b, "fs.read", 1, 0, 101));
    }
}
