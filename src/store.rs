use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

/// Top-level structure of envault.toml (committed to repo, no secret values).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EnvaultToml {
    pub meta: Meta,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Meta {
    pub version: u32,
    pub kdf: String,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Profile {
    pub keys: Vec<String>,
}

/// Top-level structure of secrets.enc (gitignored, holds encrypted values).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SecretsEnc {
    pub meta: EncMeta,
    #[serde(flatten)]
    pub profiles: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EncMeta {
    pub version: u32,
    pub kdf: String,
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String, // base64
    pub cipher: String,
}

pub const ENVAULT_TOML: &str = "envault.toml";
pub const SECRETS_ENC: &str = ".envault/secrets.enc";

/// Read and parse a TOML file of type T.
pub fn read_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("parsing {} as TOML", path.display()))
}

/// Write a TOML file atomically: write to `<path>.tmp` then rename over target.
pub fn write_toml_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let toml_str = toml::to_string_pretty(value)?;
    let tmp_path = format!("{}.tmp", path.display());
    let tmp = Path::new(&tmp_path);
    fs::write(&tmp, toml_str)
        .with_context(|| format!("writing temp {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Load envault.toml from the current directory.
pub fn load_envault_toml() -> Result<EnvaultToml> {
    read_toml(Path::new(ENVAULT_TOML)).context("failed to load envault.toml")
}

/// Load secrets.enc.
pub fn load_secrets_enc() -> Result<SecretsEnc> {
    read_toml(Path::new(SECRETS_ENC)).context("failed to load .envault/secrets.enc")
}

/// Persist secrets.enc atomically.
pub fn save_secrets_enc(secrets: &SecretsEnc) -> Result<()> {
    let path = Path::new(SECRETS_ENC);
    write_toml_atomic(path, secrets)
}

/// Ensure `.envault/secrets.enc` is listed in `.gitignore`.
pub fn ensure_gitignore_entry() -> Result<()> {
    let gitignore = Path::new(".gitignore");
    let entry = ".envault/secrets.enc\n";
    if gitignore.exists() {
        let content = fs::read_to_string(gitignore)?;
        if content.lines().any(|l| l.trim() == ".envault/secrets.enc") {
            return Ok(());
        }
        let mut appended = content;
        if !appended.ends_with('\n') {
            appended.push('\n');
        }
        appended.push_str(entry);
        fs::write(gitignore, appended)?;
    } else {
        fs::write(gitignore, entry)?;
    }
    Ok(())
}

/// Build the AAD (associated data) for a profile/key pair: `profile\0key`.
pub fn aad_for(profile: &str, key: &str) -> Vec<u8> {
    let mut aad = profile.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(key.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aad_includes_null_separator() {
        let a = aad_for("dev", "DATABASE_URL");
        assert_eq!(a, b"dev\0DATABASE_URL");
    }
}
