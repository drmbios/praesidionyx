use anyhow::{bail, Context};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use subtle::ConstantTimeEq;

pub fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn matches(expected: &str, provided: &str) -> bool {
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}
pub fn load_or_create(path: &Path) -> anyhow::Result<String> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            let key = new_secret();
            file.write_all(key.as_bytes())?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
                bail!("{} must be a regular file with mode 0600", path.display());
            }
            let value = fs::read_to_string(path).context("reading authentication key")?;
            if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
                bail!("invalid authentication key in {}", path.display());
            }
            Ok(value)
        }
        Err(error) => Err(error.into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_keys_persist_without_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let first = load_or_create(&path).unwrap();
        assert_eq!(first, load_or_create(&path).unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!matches(&first, &new_secret()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create(&path).is_err());
    }
}
