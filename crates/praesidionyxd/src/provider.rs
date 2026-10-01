//! Pluggable model transport. Only the selected provider is reachable by agents.
use crate::proto::Budget;
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug)]
pub struct Completion {
    pub text: String,
    pub tokens: u64,
    pub cost_microusd: u64,
}
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn complete(&self, model: &str, prompt: &str, budget: &Budget) -> Result<Completion>;
}
pub struct MockProvider;
#[async_trait]
impl LlmProvider for MockProvider {
    fn name(&self) -> &'static str {
        "mock"
    }
    async fn complete(&self, model: &str, prompt: &str, budget: &Budget) -> Result<Completion> {
        ensure!(
            prompt.len() as u64 <= budget.tokens,
            "prompt exceeds token budget"
        );
        let digest = Sha256::digest(format!("{model}\0{prompt}").as_bytes());
        let mut text = format!("mock:{}", hex::encode(digest));
        text.truncate((budget.tokens - prompt.len() as u64).min(text.len() as u64) as usize);
        Ok(Completion {
            tokens: prompt.len() as u64 + text.len() as u64,
            text,
            cost_microusd: 0,
        })
    }
}
struct HttpProvider {
    kind: &'static str,
    client: reqwest::Client,
    endpoint: String,
    model: Option<String>,
    key: Option<String>,
    input_rate: u64,
    output_rate: u64,
}
pub fn configured() -> Result<Arc<dyn LlmProvider>> {
    let kind = std::env::var("PRAESIDIONYX_PROVIDER").unwrap_or_else(|_| "mock".into());
    if kind == "mock" {
        return Ok(Arc::new(MockProvider));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    match kind.as_str() {
        "ollama" => {
            let base = std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:11434".into());
            let url = url::Url::parse(&base)?;
            ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none(),
                "invalid configured Ollama URL"
            );
            Ok(Arc::new(HttpProvider {
                kind: "ollama",
                client,
                endpoint: format!("{}/api/generate", base.trim_end_matches('/')),
                model: None,
                key: None,
                input_rate: 0,
                output_rate: 0,
            }))
        }
        "anthropic" => {
            let key = std::env::var("ANTHROPIC_API_KEY").context("ANTHROPIC_API_KEY required")?;
            ensure!(!key.is_empty(), "empty API key");
            let model = std::env::var("PRAESIDIONYX_MODEL")
                .context("pin PRAESIDIONYX_MODEL for the configured prices")?;
            ensure!(!model.is_empty(), "model required");
            let input_rate = std::env::var("PRAESIDIONYX_INPUT_MICROUSD_PER_TOKEN")
                .context("configure conservative input pricing")?
                .parse::<u64>()?;
            let output_rate = std::env::var("PRAESIDIONYX_OUTPUT_MICROUSD_PER_TOKEN")
                .context("configure conservative output pricing")?
                .parse::<u64>()?;
            ensure!(
                (1..=1000000).contains(&input_rate) && (1..=1000000).contains(&output_rate),
                "invalid token rates"
            );
            Ok(Arc::new(HttpProvider {
                kind: "anthropic",
                client,
                endpoint: "https://api.anthropic.com/v1/messages".into(),
                model: Some(model),
                key: Some(key),
                input_rate,
                output_rate,
            }))
        }
        _ => anyhow::bail!("unknown provider; choose mock, ollama, or anthropic"),
    }
}
impl HttpProvider {
    fn payload(&self, model: &str, prompt: &str, budget: &Budget) -> Result<Value> {
        if let Some(pinned) = &self.model {
            ensure!(
                model == pinned,
                "model differs from configured priced model"
            );
        }
        // Bytes plus a conservative framing allowance reserve input. Response usage
        // is authoritative for accounting; remote cancellation is best effort.
        let input = prompt.len() as u64 + 256;
        let mut output = budget.tokens.saturating_sub(input).min(4096);
        if let Some(affordable) = budget
            .cost_microusd
            .saturating_sub(input * self.input_rate)
            .checked_div(self.output_rate)
        {
            output = output.min(affordable);
        }
        ensure!(
            output > 0,
            "insufficient token/cost budget before provider dispatch"
        );
        Ok(if self.kind == "ollama" {
            json!({"model":model,"prompt":prompt,"stream":false,"options":{"num_predict":output}})
        } else {
            json!({"model":model,"max_tokens":output,"messages":[{"role":"user","content":prompt}]})
        })
    }
    fn decode(&self, value: Value) -> Result<Completion> {
        let (text, input, output) = if self.kind == "ollama" {
            ensure!(value["done"] == true, "incomplete Ollama response");
            (
                value["response"]
                    .as_str()
                    .context("missing provider text")?
                    .to_owned(),
                value["prompt_eval_count"]
                    .as_u64()
                    .context("missing input usage")?,
                value["eval_count"]
                    .as_u64()
                    .context("missing output usage")?,
            )
        } else {
            let text = value["content"]
                .as_array()
                .context("missing content")?
                .iter()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let usage = &value["usage"];
            let input = usage["input_tokens"]
                .as_u64()
                .context("missing input usage")?
                .checked_add(usage["cache_creation_input_tokens"].as_u64().unwrap_or(0))
                .and_then(|v| v.checked_add(usage["cache_read_input_tokens"].as_u64().unwrap_or(0)))
                .context("usage overflow")?;
            (
                text,
                input,
                usage["output_tokens"]
                    .as_u64()
                    .context("missing output usage")?,
            )
        };
        ensure!(text.len() <= 32768, "model output exceeds 32 KiB");
        let tokens = input.checked_add(output).context("usage overflow")?;
        let cost_microusd = input
            .checked_mul(self.input_rate)
            .and_then(|v| {
                output
                    .checked_mul(self.output_rate)
                    .and_then(|o| v.checked_add(o))
            })
            .context("cost overflow")?;
        Ok(Completion {
            text,
            tokens,
            cost_microusd,
        })
    }
}
#[async_trait]
impl LlmProvider for HttpProvider {
    fn name(&self) -> &'static str {
        self.kind
    }
    async fn complete(&self, model: &str, prompt: &str, budget: &Budget) -> Result<Completion> {
        let payload = self.payload(model, prompt, budget)?;
        let mut request = self.client.post(&self.endpoint).json(&payload);
        if let Some(key) = &self.key {
            request = request
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01");
        }
        let mut response = request.send().await?;
        ensure!(
            response.status().is_success(),
            "provider returned HTTP {}",
            response.status().as_u16()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 1024 * 1024,
                "provider response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        self.decode(serde_json::from_slice(&bytes)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn mock_is_deterministic_and_budgeted() {
        let budget = Budget {
            tokens: 100,
            ..Default::default()
        };
        let a = MockProvider
            .complete("mock-v1", "hello", &budget)
            .await
            .unwrap();
        assert_eq!(
            a.text,
            MockProvider
                .complete("mock-v1", "hello", &budget)
                .await
                .unwrap()
                .text
        );
        assert_ne!(
            a.text,
            MockProvider
                .complete("mock-v1", "different", &budget)
                .await
                .unwrap()
                .text
        );
        let tiny = MockProvider
            .complete(
                "mock-v1",
                "hello",
                &Budget {
                    tokens: 10,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(tiny.tokens, 10);
    }
    #[tokio::test]
    async fn provider_http_contract_offline() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for kind in ["ollama", "anthropic"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let endpoint = format!("http://{}/fixture", listener.local_addr()?);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(index) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        if serde_json::from_slice::<Value>(&bytes[index + 4..]).is_ok() {
                            break;
                        }
                    }
                }
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.contains("POST /fixture"));
                assert!(text.contains("model-test"));
                let body=if kind=="ollama" {json!({"response":"hello","done":true,"prompt_eval_count":4,"eval_count":2})} else {assert!(text.contains("anthropic-version"));json!({"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":4,"output_tokens":2}})}.to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            });
            let provider = HttpProvider {
                kind,
                client: reqwest::Client::builder().no_proxy().build()?,
                endpoint,
                model: Some("model-test".into()),
                key: if kind == "anthropic" {
                    Some("offline-test-placeholder".into())
                } else {
                    None
                },
                input_rate: 2,
                output_rate: 3,
            };
            let result = provider
                .complete(
                    "model-test",
                    "hello",
                    &Budget {
                        tokens: 1000,
                        cost_microusd: 10000,
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(result.text, "hello");
            assert_eq!(result.tokens, 6);
            assert_eq!(result.cost_microusd, 14);
            server.await?;
            assert!(provider
                .payload("different", "x", &Budget::default())
                .is_err());
        }
        Ok(())
    }
}
