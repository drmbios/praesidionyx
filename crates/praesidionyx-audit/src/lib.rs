#![forbid(unsafe_code)]
//! Canonical JSONL records, domain-separated hashes, Ed25519 signatures, and a
//! signed local checkpoint. A checkpoint mismatch is never repaired implicitly.
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

// Legacy signing domains are protocol identifiers, retained only for reading
// pre-rename records. New records and checkpoints always use the new domains.
const LEGACY_EVENT_DOMAIN: &[u8] = b"agentos-audit-event-v1\0";
const LEGACY_HEAD_DOMAIN: &[u8] = b"agentos-audit-head-v1\0";
const EVENT_DOMAIN: &[u8] = b"praesidionyx-audit-event-v1\0";
const HEAD_DOMAIN: &[u8] = b"praesidionyx-audit-head-v1\0";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u64,
    pub previous_hash: String,
    pub unix_ms: u64,
    pub actor: String,
    pub operation: String,
    pub outcome: String,
    pub capability_id: Option<String>,
    pub target: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub event: Event,
    pub hash: String,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub records: u64,
    pub hash: String,
}
impl Default for Head {
    fn default() -> Self {
        Self {
            records: 0,
            hash: ZERO.into(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    head: Head,
    signature: String,
}
pub struct Verified {
    pub head: Head,
    pub records: Vec<Record>,
}
pub struct AuditLog {
    path: PathBuf,
    checkpoint: PathBuf,
    file: File,
    key: SigningKey,
    head: Head,
    poisoned: bool,
}
fn digest(event: &Event) -> Result<Vec<u8>> {
    digest_with_domain(event, EVENT_DOMAIN)
}
fn digest_with_domain(event: &Event, domain: &[u8]) -> Result<Vec<u8>> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(event)?);
    Ok(hash.finalize().to_vec())
}
fn checkpoint_bytes(head: &Head) -> Result<Vec<u8>> {
    checkpoint_with_domain(head, HEAD_DOMAIN)
}
fn checkpoint_with_domain(head: &Head, domain: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(head)?);
    Ok(bytes)
}
pub fn public_key(encoded: &str) -> Result<VerifyingKey> {
    Ok(VerifyingKey::from_bytes(
        &hex::decode(encoded.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte public key"))?,
    )?)
}
fn check_signature(key: &VerifyingKey, bytes: &[u8], signature: &str) -> Result<()> {
    let decoded = hex::decode(signature)?;
    ensure!(
        hex::encode(&decoded) == signature,
        "noncanonical signature encoding"
    );
    key.verify_strict(bytes, &Signature::from_slice(&decoded)?)
        .context("invalid audit signature")
}
fn regular(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "audit path must be a regular file: {}",
        path.display()
    );
    Ok(())
}
/// Supply an independently pinned public key. The log never chooses its own signer.
/// Without a checkpoint this detects edits/reordering, but not valid suffix deletion.
pub fn verify(path: &Path, key: &VerifyingKey, checkpoint: Option<&Path>) -> Result<Verified> {
    regular(path)?;
    ensure!(
        fs::metadata(path)?.len() <= MAX_LOG_BYTES,
        "audit size limit reached; archive under supervision"
    );
    let mut reader = BufReader::new(File::open(path)?);
    let mut head = Head::default();
    let mut records = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        ensure!(
            line.len() <= 16384 && line.last() == Some(&b'\n'),
            "partial or oversized audit record"
        );
        line.pop();
        let record: Record = serde_json::from_slice(&line).context("invalid audit JSON")?;
        ensure!(
            serde_json::to_vec(&record)? == line,
            "noncanonical audit record"
        );
        ensure!(
            record.event.sequence == head.records + 1 && record.event.previous_hash == head.hash,
            "audit chain discontinuity"
        );
        let mut hash = digest(&record.event)?;
        if record.hash != hex::encode(&hash) {
            hash = digest_with_domain(&record.event, LEGACY_EVENT_DOMAIN)?;
        }
        ensure!(record.hash == hex::encode(&hash), "audit hash mismatch");
        check_signature(key, &hash, &record.signature)?;
        head = Head {
            records: record.event.sequence,
            hash: record.hash.clone(),
        };
        records.push(record);
    }
    if let Some(path) = checkpoint {
        regular(path)?;
        ensure!(fs::metadata(path)?.len() <= 4096, "oversized checkpoint");
        let data = fs::read(path)?;
        let checkpoint: Checkpoint = serde_json::from_slice(&data)?;
        ensure!(
            serde_json::to_vec(&checkpoint)? == data,
            "noncanonical checkpoint"
        );
        check_signature(
            key,
            &checkpoint_bytes(&checkpoint.head)?,
            &checkpoint.signature,
        )
        .or_else(|_| {
            check_signature(
                key,
                &checkpoint_with_domain(&checkpoint.head, LEGACY_HEAD_DOMAIN)?,
                &checkpoint.signature,
            )
        })?;
        ensure!(
            checkpoint.head == head,
            "audit checkpoint mismatch (truncation, rollback, or interrupted append)"
        );
    }
    Ok(Verified { head, records })
}
impl AuditLog {
    pub fn open(path: &Path, checkpoint: &Path, key: SigningKey) -> Result<Self> {
        let fresh = !path.try_exists()?;
        if fresh {
            ensure!(
                !checkpoint.try_exists()?,
                "audit log missing but checkpoint exists"
            );
        } else {
            regular(path)?;
            ensure!(
                fs::metadata(path)?.permissions().mode() & 0o777 == 0o600,
                "audit file must be mode 0600"
            );
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(fresh)
            .mode(0o600)
            .open(path)?;
        file.try_lock_exclusive()
            .context("audit log already has a writer")?;
        let mut log = Self {
            path: path.into(),
            checkpoint: checkpoint.into(),
            file,
            key,
            head: Head::default(),
            poisoned: false,
        };
        if fresh {
            log.file.sync_all()?;
            log.save_checkpoint()?;
        }
        log.head = log.verify()?.head;
        Ok(log)
    }
    pub fn verify(&self) -> Result<Verified> {
        let disk = fs::symlink_metadata(&self.path)?;
        let open = self.file.metadata()?;
        ensure!(
            disk.dev() == open.dev() && disk.ino() == open.ino(),
            "audit file replaced while open"
        );
        verify(
            &self.path,
            &self.key.verifying_key(),
            Some(&self.checkpoint),
        )
    }
    fn save_checkpoint(&self) -> Result<()> {
        let checkpoint = Checkpoint {
            head: self.head.clone(),
            signature: hex::encode(self.key.sign(&checkpoint_bytes(&self.head)?).to_bytes()),
        };
        let temp = self.checkpoint.with_extension("pending");
        // A leftover pending file requires explicit operator recovery after a crash.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(&checkpoint)?)?;
        file.sync_all()?;
        fs::rename(&temp, &self.checkpoint)?;
        File::open(self.checkpoint.parent().context("checkpoint parent")?)?.sync_all()?;
        Ok(())
    }
    pub fn append(
        &mut self,
        actor: &str,
        operation: &str,
        outcome: &str,
        capability_id: Option<&str>,
        target: Option<&str>,
    ) -> Result<Head> {
        ensure!(
            !self.poisoned,
            "audit writer is poisoned; operator recovery required"
        );
        self.poisoned = true;
        // Revalidate disk before every append. This intentionally favors integrity
        // over throughput in the bounded local MVP; it detects live file edits too.
        ensure!(
            self.verify()?.head == self.head,
            "audit head changed externally"
        );
        let event = Event {
            sequence: self.head.records + 1,
            previous_hash: self.head.hash.clone(),
            unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
            actor: actor.into(),
            operation: operation.into(),
            outcome: outcome.into(),
            capability_id: capability_id.map(str::to_owned),
            target: target.map(str::to_owned),
        };
        let hash = digest(&event)?;
        let record = Record {
            event,
            hash: hex::encode(&hash),
            signature: hex::encode(self.key.sign(&hash).to_bytes()),
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        ensure!(
            line.len() <= 16384 && self.file.metadata()?.len() + line.len() as u64 <= MAX_LOG_BYTES,
            "audit capacity exceeded"
        );
        self.file.write_all(&line)?;
        self.file.sync_all()?;
        self.head = Head {
            records: record.event.sequence,
            hash: record.hash,
        };
        self.save_checkpoint()?;
        self.poisoned = false;
        Ok(self.head.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn populated() -> (tempfile::TempDir, SigningKey) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut log = AuditLog::open(
            &dir.path().join("audit.jsonl"),
            &dir.path().join("audit.head"),
            key.clone(),
        )
        .unwrap();
        log.append(
            "bootstrap",
            "agent.spawn",
            "authorized",
            Some("grant"),
            Some("agent"),
        )
        .unwrap();
        log.append(
            "agent",
            "agent.exit",
            "authorized",
            Some("exit"),
            Some("agent"),
        )
        .unwrap();
        (dir, key)
    }
    #[test]
    fn legacy_log_can_continue_with_new_domains_without_rewriting_history() {
        let (dir, key) = populated();
        let path = dir.path().join("audit.jsonl");
        let checkpoint = dir.path().join("audit.head");
        let mut records: Vec<Record> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut previous = ZERO.to_owned();
        let mut legacy_bytes = Vec::new();
        for record in &mut records {
            record.event.previous_hash = previous;
            let hash = digest_with_domain(&record.event, LEGACY_EVENT_DOMAIN).unwrap();
            record.hash = hex::encode(&hash);
            record.signature = hex::encode(key.sign(&hash).to_bytes());
            previous = record.hash.clone();
            legacy_bytes.extend(serde_json::to_vec(record).unwrap());
            legacy_bytes.push(b'\n');
        }
        fs::write(&path, &legacy_bytes).unwrap();
        let head = Head {
            records: 2,
            hash: previous,
        };
        let signed = Checkpoint {
            signature: hex::encode(
                key.sign(&checkpoint_with_domain(&head, LEGACY_HEAD_DOMAIN).unwrap())
                    .to_bytes(),
            ),
            head,
        };
        fs::write(&checkpoint, serde_json::to_vec(&signed).unwrap()).unwrap();
        let mut log = AuditLog::open(&path, &checkpoint, key.clone()).unwrap();
        log.append("supervisor", "list", "allowed", None, None)
            .unwrap();
        let verified = log.verify().unwrap();
        assert_eq!(verified.head.records, 3);
        assert!(fs::read(&path).unwrap().starts_with(&legacy_bytes));
        let newest = &verified.records[2];
        assert_eq!(newest.hash, hex::encode(digest(&newest.event).unwrap()));
        let signed: Checkpoint = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
        check_signature(
            &key.verifying_key(),
            &checkpoint_bytes(&signed.head).unwrap(),
            &signed.signature,
        )
        .unwrap();
        let mut tampered = fs::read(&path).unwrap();
        let index = tampered
            .windows(9)
            .position(|bytes| bytes == b"bootstrap")
            .unwrap();
        tampered[index] = b'B';
        fs::write(&path, tampered).unwrap();
        assert!(log.verify().is_err());
        assert!(log.append("x", "x", "x", None, None).is_err());
    }
    #[test]
    fn verifies_and_continues_across_restart() {
        let (dir, key) = populated();
        let p = dir.path().join("audit.jsonl");
        let h = dir.path().join("audit.head");
        assert_eq!(
            verify(&p, &key.verifying_key(), Some(&h))
                .unwrap()
                .head
                .records,
            2
        );
        let mut log = AuditLog::open(&p, &h, key).unwrap();
        log.append("supervisor", "list", "allowed", None, None)
            .unwrap();
        assert_eq!(log.verify().unwrap().head.records, 3);
    }
    #[test]
    fn one_byte_tamper_fails_and_writer_refuses_to_append() {
        let (dir, key) = populated();
        let p = dir.path().join("audit.jsonl");
        let h = dir.path().join("audit.head");
        let mut log = AuditLog::open(&p, &h, key.clone()).unwrap();
        let mut bytes = fs::read(&p).unwrap();
        let i = bytes.windows(9).position(|s| s == b"bootstrap").unwrap();
        bytes[i] = b'B';
        fs::write(&p, &bytes).unwrap();
        assert!(verify(&p, &key.verifying_key(), Some(&h)).is_err());
        assert!(log.append("x", "x", "x", None, None).is_err());
        assert_eq!(fs::read(&p).unwrap(), bytes);
    }
    #[test]
    fn truncation_reordering_wrong_key_and_partial_record_fail() {
        let (dir, key) = populated();
        let p = dir.path().join("audit.jsonl");
        let h = dir.path().join("audit.head");
        let original = fs::read(&p).unwrap();
        assert!(verify(
            &p,
            &SigningKey::from_bytes(&[8; 32]).verifying_key(),
            Some(&h)
        )
        .is_err());
        let first = original.iter().position(|c| *c == b'\n').unwrap() + 1;
        fs::write(&p, &original[..first]).unwrap();
        assert!(verify(&p, &key.verifying_key(), Some(&h)).is_err());
        fs::write(&p, []).unwrap();
        assert!(verify(&p, &key.verifying_key(), Some(&h)).is_err());
        let reversed = [&original[first..], &original[..first]].concat();
        fs::write(&p, reversed).unwrap();
        assert!(verify(&p, &key.verifying_key(), Some(&h)).is_err());
        fs::write(&p, &original[..original.len() - 1]).unwrap();
        assert!(verify(&p, &key.verifying_key(), Some(&h)).is_err());
    }
    #[test]
    fn whitespace_changes_and_missing_checkpoint_fail() {
        let (dir, key) = populated();
        let p = dir.path().join("audit.jsonl");
        let h = dir.path().join("audit.head");
        let original = fs::read(&p).unwrap();
        let changed = [b" ".as_slice(), original.as_slice()].concat();
        fs::write(&p, changed).unwrap();
        assert!(verify(&p, &key.verifying_key(), Some(&h)).is_err());
        fs::write(&p, original).unwrap();
        fs::remove_file(&h).unwrap();
        assert!(AuditLog::open(&p, &h, key).is_err());
    }

    #[test]
    fn changing_only_signature_hex_case_fails() {
        let (dir, key) = populated();
        let path = dir.path().join("audit.jsonl");
        let checkpoint = dir.path().join("audit.head");
        let original = fs::read(&path).unwrap();
        let marker = b"\"signature\":\"";
        let start = original
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap()
            + marker.len();
        let offset = original[start..start + 128]
            .iter()
            .position(|b| b.is_ascii_lowercase())
            .unwrap();
        let mut changed = original.clone();
        changed[start + offset] = changed[start + offset].to_ascii_uppercase();
        assert_eq!(
            original
                .iter()
                .zip(&changed)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        fs::write(&path, changed).unwrap();
        assert!(verify(&path, &key.verifying_key(), Some(&checkpoint)).is_err());
    }
}
