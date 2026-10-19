use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, bail, Context};
use rpassword::prompt_password;
use secrecy::ExposeSecret;
use zeroize::Zeroize;
use crate::crypto::{derive_key, encrypt_value, encode_enc_value, wipe_secret, KdfParams};
use crate::store::{
    aad_for, load_envault_toml, load_secrets_enc, save_secrets_enc, write_toml_atomic,
    ENVAULT_TOML,
};

/// Parse a simple .env file: lines of `KEY=VALUE`, skipping blanks and `#`
/// comments. Inline `#` comments inside values are NOT stripped (values may
/// contain them).
fn parse_dotenv(content: &str) -> Result<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                bail!("empty key at line {}", lineno + 1);
            }
            entries.push((key.to_string(), value.to_string()));
        } else {
            bail!("malformed line {} (expected KEY=VALUE)", lineno + 1);
        }
    }
    Ok(entries)
}

pub fn execute(path: String, profile: String) -> Result<()> {
    let dotenv_path = Path::new(&path);
    if !dotenv_path.exists() {
        bail!("dotenv file not found: {}", path);
    }

    // Validate / ensure profile exists in envault.toml (structure file).
    // We also add imported keys here so that `run --profile <name>` delivers
    // them to the child process.
    let mut toml = load_envault_toml()?;
    let profile_keys = toml
        .profiles
        .entry(profile.clone())
        .or_insert_with(|| crate::store::Profile { keys: Vec::new() });

    // Prompt for master password (hidden input).
    let mut password = prompt_password("Enter master password: ")?;
    if password.is_empty() {
        bail!("master password must not be empty");
    }

    // Read and parse the .env file.
    let content = fs::read_to_string(dotenv_path)
        .with_context(|| format!("reading {}", path))?;
    let entries = parse_dotenv(&content)?;
    if entries.is_empty() {
        bail!("no entries found in {}", path);
    }

    // Load store and derive master key.
    let mut secrets = load_secrets_enc()?;
    let params = KdfParams {
        mem_kib: secrets.meta.mem_kib,
        iterations: secrets.meta.iterations,
        parallelism: secrets.meta.parallelism,
    };
    let mut master_key = derive_key(&password, &secrets.meta.salt, &params)?;
    let key_bytes = master_key.expose_secret();
    // Wipe the master password now that the key is derived.
    password.zeroize();

    // Encrypt each entry and add to store.
    let store_profile = secrets
        .profiles
        .entry(profile.clone())
        .or_insert_with(BTreeMap::new);

    let count = entries.len();
    for (key, value) in &entries {
        let aad = aad_for(&profile, key);
        let (nonce, ct) = encrypt_value(key_bytes, &aad, value.as_bytes())?;
        store_profile.insert(key.clone(), encode_enc_value(&nonce, &ct));
        // Declare the key in envault.toml so `run` delivers it.
        if !profile_keys.keys.contains(key) {
            profile_keys.keys.push(key.clone());
        }
    }

    // Wipe the master key from memory now that everything is encrypted.
    wipe_secret(&mut master_key);

    // Atomic write of the encrypted store.
    save_secrets_enc(&secrets)?;

    // Persist the updated structure (profile keys) atomically too.
    write_toml_atomic(Path::new(ENVAULT_TOML), &toml)?;

    // Delete the source .env after successful encryption.
    match fs::remove_file(dotenv_path) {
        Ok(()) => println!(
            "Imported {} entries into '{}'; deleted {}.",
            count, profile, path
        ),
        Err(e) => {
            eprintln!(
                "WARNING: encryption succeeded but failed to delete {}. \
                 Please delete it manually: {}",
                path, e
            );
        }
    }

    println!("Import complete for profile '{}'.", profile);
    Ok(())
}
