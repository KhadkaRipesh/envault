use anyhow::{Result, anyhow};
use crate::store::{load_envault_toml, load_secrets_enc};

pub fn execute(profile: String) -> Result<()> {
    let _toml = load_envault_toml()?;
    let secrets = load_secrets_enc()?;

    let keys = secrets
        .profiles
        .get(&profile)
        .ok_or_else(|| anyhow!("profile '{}' not found in secrets.enc", profile))?;

    if keys.is_empty() {
        println!("Profile '{}' has no stored secrets.", profile);
        return Ok(());
    }

    println!("Profile '{}' ({} keys):", profile, keys.len());
    for key in keys.keys() {
        // Only key names are printed — values are never revealed here.
        println!("  {} = <encrypted>", key);
    }
    Ok(())
}
