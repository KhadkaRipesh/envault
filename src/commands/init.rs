use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result, bail};
use rpassword::prompt_password;
use crate::crypto::{derive_key, KdfParams};
use crate::store::{self, EnvaultToml, Meta, SecretsEnc, EncMeta};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use zeroize::Zeroize;

const DEFAULT_PARAMS: KdfParams = KdfParams {
    mem_kib: 65536,
    iterations: 3,
    parallelism: 4,
};

pub fn execute(shared: bool) -> Result<()> {
    if Path::new(store::ENVAULT_TOML).exists() {
        bail!("envault.toml already exists; refusing to overwrite");
    }
    if Path::new(store::SECRETS_ENC).exists() {
        bail!(".envault/secrets.enc already exists; refusing to overwrite");
    }

    // Prompt for master password (hidden input) and confirm.
    let mut password = prompt_password("Enter master password: ")?;
    let mut confirm = prompt_password("Confirm master password: ")?;
    if password != confirm {
        bail!("passwords do not match");
    }
    if password.is_empty() {
        bail!("master password must not be empty");
    }
    // Wipe the confirmation copy as soon as it's been compared.
    confirm.zeroize();

    // Generate a random 16-byte salt for the master key derivation.
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt_b64 = general_purpose::STANDARD.encode(&salt_bytes);

    // Validate that the password can derive a key (catches bad params early).
    let _key = derive_key(&password, &salt_b64, &DEFAULT_PARAMS)?;
    // Wipe the master password from memory now that the key is derived.
    password.zeroize();

    // --- envault.toml (committed: structure only, no secrets) ---
    let envault_toml = EnvaultToml {
        meta: Meta {
            version: 1,
            kdf: "argon2id".to_string(),
            cipher: "xchacha20poly1305".to_string(),
        },
        profiles: BTreeMap::new(),
    };
    let toml_str = toml::to_string_pretty(&envault_toml).context("serializing envault.toml")?;
    fs::write(store::ENVAULT_TOML, &toml_str).context("writing envault.toml")?;

    // --- .envault/secrets.enc (gitignored: encrypted values) ---
    fs::create_dir_all(
        Path::new(store::SECRETS_ENC)
            .parent()
            .unwrap_or(Path::new(".")),
    )?;
    let secrets_enc = SecretsEnc {
        meta: EncMeta {
            version: 1,
            kdf: "argon2id".to_string(),
            mem_kib: DEFAULT_PARAMS.mem_kib,
            iterations: DEFAULT_PARAMS.iterations,
            parallelism: DEFAULT_PARAMS.parallelism,
            salt: salt_b64,
            cipher: "xchacha20poly1305".to_string(),
        },
        profiles: BTreeMap::new(),
    };
    store::write_toml_atomic(Path::new(store::SECRETS_ENC), &secrets_enc)?;

    // Add .envault/secrets.enc to .gitignore, unless --shared (commit it).
    if !shared {
        store::ensure_gitignore_entry()?;
    }

    // Wipe password from memory as soon as we're done deriving.
    drop(_key);

    println!("Initialized envault:");
    println!("  {} (safe to commit)", store::ENVAULT_TOML);
    if shared {
        println!("  {} (NOT gitignored — safe to commit with --shared)", store::SECRETS_ENC);
    } else {
        println!("  {} (gitignored, holds encrypted values)", store::SECRETS_ENC);
        println!("  .gitignore updated (if present)");
    }
    Ok(())
}
