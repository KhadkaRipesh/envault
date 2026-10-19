use std::process::Command;
use anyhow::{Result, bail, Context, anyhow};
use rpassword::prompt_password;
use secrecy::ExposeSecret;
use zeroize::Zeroize;
use crate::crypto::{derive_key, decrypt_value, wipe_secret, KdfParams, parse_enc_value};
use crate::store::{aad_for, load_envault_toml, load_secrets_enc};

pub fn execute(profile: String, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        bail!("no command provided");
    }

    // 1. Read envault.toml to find which keys belong to the chosen profile.
    let toml = load_envault_toml()?;
    let profile_keys = toml
        .profiles
        .get(&profile)
        .ok_or_else(|| anyhow!("profile '{}' not found in envault.toml", profile))?
        .keys
        .clone();

    // 2. Prompt for master password (hidden input).
    let mut password = prompt_password("Enter master password: ")?;
    if password.is_empty() {
        bail!("master password must not be empty");
    }

    // 3. Load secrets.enc and derive the master key.
    let secrets = load_secrets_enc()?;
    let params = KdfParams {
        mem_kib: secrets.meta.mem_kib,
        iterations: secrets.meta.iterations,
        parallelism: secrets.meta.parallelism,
    };
    let master_key = derive_key(&password, &secrets.meta.salt, &params)?;
    let key_bytes = master_key.expose_secret();
    // Wipe the master password now that the key is derived.
    password.zeroize();

    // 4. Decrypt the relevant values into memory only (SecretVec, no disk).
    let mut env_secrets: Vec<(String, secrecy::SecretVec<u8>)> = Vec::new();
    let store_profile = secrets
        .profiles
        .get(&profile)
        .ok_or_else(|| anyhow!("profile '{}' not found in secrets.enc", profile))?;

    for key in &profile_keys {
        let encoded = store_profile
            .get(key)
            .ok_or_else(|| {
                anyhow!("secret '{}' not found in store for profile '{}'", key, profile)
            })?;
        let (nonce, ct) = parse_enc_value(encoded)?;
        let aad = aad_for(&profile, key);
        let plaintext = decrypt_value(key_bytes, &aad, &nonce, &ct)?;
        env_secrets.push((key.clone(), plaintext));
    }

    // Drop the master key now that all values are decrypted.
    drop(master_key);

    // 5. Build child environment = current process env + decrypted profile keys.
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    // Command inherits the current environment by default; overlay the secrets.
    for (key, secret) in &env_secrets {
        cmd.env(key, String::from_utf8(secret.expose_secret().clone())?);
    }

    // 6. Fork/exec the command.
    let mut child = cmd
        .spawn()
        .context("failed to spawn command")?;

    // 7. Zero the decrypted secret buffers in memory now that the child has
    //    its own copy of the environment (fork/exec copies env). Never write
    //    decrypted values to disk.
    for (_key, secret) in &mut env_secrets {
        wipe_secret(secret);
    }

    let status = child.wait().context("failed to wait for command")?;

    if !status.success() {
        bail!("command exited with status {:?}", status.code());
    }
    Ok(())
}
