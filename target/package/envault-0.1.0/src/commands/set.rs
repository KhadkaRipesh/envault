use std::collections::BTreeMap;
use anyhow::{Result, bail, anyhow};
use rpassword::prompt_password;
use secrecy::ExposeSecret;
use zeroize::Zeroize;
use crate::crypto::{derive_key, encrypt_value, encode_enc_value, wipe_secret, KdfParams};
use crate::store::{aad_for, load_envault_toml, load_secrets_enc, save_secrets_enc};

pub fn execute(profile: String, key: String) -> Result<()> {
    // 1. Validate the profile/key is declared in envault.toml (structure only).
    let toml = load_envault_toml()?;
    toml.profiles
        .get(&profile)
        .and_then(|p| p.keys.contains(&key).then_some(()))
        .ok_or_else(|| anyhow!(
            "key '{}' not declared in profile '{}' in envault.toml",
            key, profile
        ))?;

    // 2. Prompt for master password (hidden input).
    let mut password = prompt_password("Enter master password: ")?;
    if password.is_empty() {
        bail!("master password must not be empty");
    }

    // 3. Load the encrypted store and derive the master key into a SecretVec.
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

    // 4. Prompt for the secret value (hidden input, never echoed).
    let value = prompt_password(format!("Enter value for {}: ", key).as_str())?;
    if value.is_empty() {
        bail!("secret value must not be empty");
    }

    // 5. Encrypt with AAD binding to profile\0key.
    let aad = aad_for(&profile, &key);
    let (nonce, ct) = encrypt_value(key_bytes, &aad, value.as_bytes())?;

    // 6. Wipe plaintext and master key from memory immediately after encryption.
    drop(value);
    wipe_secret(&mut master_key);

    // 7. Store encoded value: enc:v1:<nonce_b64>:<ct_b64>.
    secrets
        .profiles
        .entry(profile.clone())
        .or_insert_with(BTreeMap::new)
        .insert(key.clone(), encode_enc_value(&nonce, &ct));

    // 8. Atomic write: secrets.enc.tmp then rename over original.
    save_secrets_enc(&secrets)?;

    println!("Set {}/{}", profile, key);
    Ok(())
}
