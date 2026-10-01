#![forbid(unsafe_code)]
//! Agent-owned context paging and deterministic vector retrieval; no remote embeddings.
use anyhow::{ensure, Context, Result};
use praesidionyx_policy::Label;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub content: String,
    pub label: Label,
    pub tokens: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextView {
    pub items: Vec<Item>,
    pub tokens: u64,
    pub limit: u64,
    pub label: Label,
}
pub struct Store {
    db: Connection,
}
// Byte counts conservatively bound model token counts for this MVP. No hidden
// whitespace-based undercount; UTF-8 slicing is never used to split an item.
pub fn tokens(text: &str) -> u64 {
    text.len() as u64
}
fn embedding(text: &str) -> Vec<u8> {
    let mut vector = [0f32; 64];
    for word in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        let digest = Sha256::digest(word.to_lowercase().as_bytes());
        vector[digest[0] as usize % 64] += if digest[1] & 1 == 0 { 1.0 } else { -1.0 };
    }
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut vector {
            *value /= norm;
        }
    }
    vector.into_iter().flat_map(f32::to_le_bytes).collect()
}
fn parse_label(raw: String) -> rusqlite::Result<Label> {
    match raw.as_str() {
        "trusted" => Ok(Label::Trusted),
        "user" => Ok(Label::User),
        "untrusted" => Ok(Label::Untrusted),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn item(row: &rusqlite::Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item {
        id: row.get(0)?,
        content: row.get(1)?,
        label: parse_label(row.get(2)?)?,
        tokens: u64::from(row.get::<_, u32>(3)?),
    })
}
impl Store {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        praesidionyx_sandbox::sqlite::register_vector_extension()?;
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;
          CREATE TABLE IF NOT EXISTS owners(id TEXT PRIMARY KEY, window INTEGER NOT NULL, tainted INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS pages(seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, agent TEXT NOT NULL REFERENCES owners(id), content TEXT NOT NULL, label TEXT NOT NULL, tokens INTEGER NOT NULL, embedding BLOB NOT NULL, active INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS pages_owner ON pages(agent,active,seq);
          CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES owners(id), pages TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS episodes(seq INTEGER PRIMARY KEY, agent TEXT NOT NULL, kind TEXT NOT NULL, item TEXT NOT NULL, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);")?;
        let version: String = db.query_row("SELECT vec_version()", [], |r| r.get(0))?;
        ensure!(!version.is_empty(), "sqlite-vec unavailable");
        Ok(Self { db })
    }
    pub fn create(&mut self, agent: &str, window: u64) -> Result<()> {
        ensure!((1..=131072).contains(&window), "invalid context window");
        self.db.execute(
            "INSERT INTO owners(id,window) VALUES(?1,?2)",
            params![agent, window as u32],
        )?;
        Ok(())
    }
    pub fn taint(&mut self, agent: &str) -> Result<()> {
        ensure!(
            self.db
                .execute("UPDATE owners SET tainted=1 WHERE id=?1", [agent])?
                == 1,
            "unknown owner"
        );
        Ok(())
    }
    fn page_out(db: &Connection, agent: &str, limit: u64) -> Result<()> {
        let mut total: u64 = db.query_row(
            "SELECT COALESCE(SUM(tokens),0) FROM pages WHERE agent=?1 AND active=1",
            [agent],
            |r| r.get::<_, u32>(0).map(u64::from),
        )?;
        while total > limit {
            let (id, cost): (String, u64) = db.query_row(
                "SELECT id,tokens FROM pages WHERE agent=?1 AND active=1 ORDER BY seq LIMIT 1",
                [agent],
                |r| Ok((r.get(0)?, u64::from(r.get::<_, u32>(1)?))),
            )?;
            db.execute(
                "UPDATE pages SET active=0 WHERE agent=?1 AND id=?2",
                params![agent, id],
            )?;
            db.execute(
                "INSERT INTO episodes(agent,kind,item) VALUES(?1,'page_out',?2)",
                params![agent, id],
            )?;
            total -= cost;
        }
        Ok(())
    }
    pub fn remember(&mut self, agent: &str, content: &str, label: Label) -> Result<Item> {
        ensure!(
            !content.is_empty() && content.len() <= 32768,
            "memory item must be 1..32768 bytes"
        );
        let count: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM pages WHERE agent=?1", [agent], |r| {
                    r.get::<_, u32>(0).map(u64::from)
                })?;
        ensure!(count < 4096, "memory item quota reached");
        let limit: u64 =
            self.db
                .query_row("SELECT window FROM owners WHERE id=?1", [agent], |r| {
                    r.get::<_, u32>(0).map(u64::from)
                })?;
        let entry = Item {
            id: Uuid::new_v4().to_string(),
            content: content.into(),
            label,
            tokens: tokens(content),
        };
        let tx = self.db.transaction()?;
        tx.execute("INSERT INTO pages(id,agent,content,label,tokens,embedding,active) VALUES(?1,?2,?3,?4,?5,?6,1)",params![entry.id,agent,content,label.as_str(),entry.tokens as u32,embedding(content)])?;
        if label == Label::Untrusted {
            tx.execute("UPDATE owners SET tainted=1 WHERE id=?1", [agent])?;
        }
        tx.execute(
            "INSERT INTO episodes(agent,kind,item) VALUES(?1,'remember',?2)",
            params![agent, entry.id],
        )?;
        Self::page_out(&tx, agent, limit)?;
        tx.commit()?;
        Ok(entry)
    }
    pub fn context(&self, agent: &str) -> Result<ContextView> {
        let (limit, tainted): (u64, bool) = self.db.query_row(
            "SELECT window,tainted FROM owners WHERE id=?1",
            [agent],
            |r| Ok((u64::from(r.get::<_, u32>(0)?), r.get(1)?)),
        )?;
        let items=self.db.prepare("SELECT id,content,label,tokens FROM pages WHERE agent=?1 AND active=1 ORDER BY seq")?.query_map([agent],item)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ContextView {
            tokens: items.iter().map(|i| i.tokens).sum(),
            items,
            limit,
            label: if tainted {
                Label::Untrusted
            } else {
                Label::User
            },
        })
    }
    pub fn recall(&mut self, agent: &str, query: &str, max_tokens: u64) -> Result<Vec<Item>> {
        ensure!(
            !query.is_empty() && query.len() <= 4096 && max_tokens > 0,
            "invalid recall query/limit"
        );
        let limit: u64 =
            self.db
                .query_row("SELECT window FROM owners WHERE id=?1", [agent], |r| {
                    r.get::<_, u32>(0).map(u64::from)
                })?;
        let mut remaining = max_tokens.min(limit);
        let ranked=self.db.prepare("SELECT id,content,label,tokens FROM pages WHERE agent=?1 ORDER BY vec_distance_L2(embedding,?2),seq DESC LIMIT 4096")?.query_map(params![agent,embedding(query)],item)?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut selected = Vec::new();
        for entry in ranked {
            if entry.tokens <= remaining {
                remaining -= entry.tokens;
                selected.push(entry);
            }
        }
        // Page selected entries in without immediately evicting them: evict other
        // active pages first, then retain every selected item within the hard limit.
        let tx = self.db.transaction()?;
        tx.execute("UPDATE pages SET active=0 WHERE agent=?1", [agent])?;
        for entry in &selected {
            tx.execute(
                "UPDATE pages SET active=1 WHERE agent=?1 AND id=?2",
                params![agent, entry.id],
            )?;
        }
        tx.execute(
            "INSERT INTO episodes(agent,kind,item) VALUES(?1,'recall',?2)",
            params![agent, selected.len().to_string()],
        )?;
        tx.commit()?;
        Ok(selected)
    }
    pub fn checkpoint(&mut self, agent: &str) -> Result<String> {
        let count: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM snapshots WHERE agent=?1",
            [agent],
            |r| r.get::<_, u32>(0).map(u64::from),
        )?;
        ensure!(count < 128, "snapshot quota reached");
        let ids: Vec<_> = self
            .context(agent)?
            .items
            .into_iter()
            .map(|i| i.id)
            .collect();
        let id = Uuid::new_v4().to_string();
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO snapshots VALUES(?1,?2,?3)",
            params![id, agent, serde_json::to_string(&ids)?],
        )?;
        tx.execute(
            "INSERT INTO episodes(agent,kind,item) VALUES(?1,'checkpoint',?2)",
            params![agent, id],
        )?;
        tx.commit()?;
        Ok(id)
    }
    pub fn rollback(&mut self, agent: &str, snapshot: &str) -> Result<ContextView> {
        let raw: String = self
            .db
            .query_row(
                "SELECT pages FROM snapshots WHERE agent=?1 AND id=?2",
                params![agent, snapshot],
                |r| r.get(0),
            )
            .context("unknown snapshot for this agent")?;
        let ids: Vec<String> = serde_json::from_str(&raw)?;
        let tx = self.db.transaction()?;
        tx.execute("UPDATE pages SET active=0 WHERE agent=?1", [agent])?;
        for id in ids {
            ensure!(
                tx.execute(
                    "UPDATE pages SET active=1 WHERE agent=?1 AND id=?2",
                    params![agent, id]
                )? == 1,
                "snapshot page missing"
            );
        }
        tx.execute(
            "INSERT INTO episodes(agent,kind,item) VALUES(?1,'rollback',?2)",
            params![agent, snapshot],
        )?;
        tx.commit()?;
        self.context(agent)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paging_vectors_isolation_and_monotonic_rollback() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("memory.db");
        let mut store = Store::open(&path)?;
        store.create("a", 30)?;
        store.create("b", 30)?;
        let apple = store.remember("a", "apple red fruit", Label::User)?;
        store.remember("a", "cpu kernel namespaces", Label::User)?;
        assert!(store.context("a")?.tokens <= 30);
        assert!(!store.context("a")?.items.iter().any(|i| i.id == apple.id));
        let recalled = store.recall("a", "apple", 16)?;
        assert_eq!(recalled[0].id, apple.id);
        let snapshot = store.checkpoint("a")?;
        store.remember("a", "untrusted injection", Label::Untrusted)?;
        let context = store.rollback("a", &snapshot)?;
        assert_eq!(context.label, Label::Untrusted);
        assert_eq!(context.items[0].id, apple.id);
        assert!(store.rollback("b", &snapshot).is_err());
        assert!(store.recall("b", "apple", 30)?.is_empty());
        drop(store);
        let store = Store::open(&path)?;
        assert_eq!(store.context("a")?.label, Label::Untrusted);
        Ok(())
    }
}
