use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, Payload};
use hybrid_array::ArrayN;
use rand::RngCore;
use secrecy::SecretVec;
use anyhow::{Result, bail};

/// Prefix for every encrypted value stored in secrets.enc.
const ENC_PREFIX: &str = "enc:v1:";

/// XChaCha20-Poly1305 uses a 24-byte (192-bit) nonce.
const NONCE_LEN: usize = 24;

/// Argon2id parameters stored in `[meta]` of secrets.enc.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Derive a 32-byte master key from a user password + b64-encoded salt using
/// Argon2id. The key is returned inside a `SecretVec` whose memory is
/// zeroized on drop.
pub fn derive_key(password: &str, salt_b64: &str, params: &KdfParams) -> Result<SecretVec<u8>> {
    let salt_bytes = general_purpose::STANDARD.decode(salt_b64)?;

    let params = Params::new(params.mem_kib, params.iterations, params.parallelism, None)
        .map_err(|e| anyhow::anyhow!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive a raw 32-byte key directly (no base64 PHC string involved).
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_bytes)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {}", e))?;
    Ok(SecretVec::from(key_bytes.to_vec()))
}

/// Encrypt a plaintext with a fresh random nonce. The AAD binds the
/// ciphertext to `profile\0key` so a value cannot be moved to another
/// profile/key and still decrypt.
///
/// Returns `(nonce, ciphertext+tag)`.
pub fn encrypt_value(
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("invalid key length: {}", e))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = ArrayN::<u8, 24>::from(nonce_bytes);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("encrypt failed: {}", e))?;
    Ok((nonce_bytes.to_vec(), ct))
}

/// Decrypt a single value. Returns the plaintext inside a `SecretVec`.
pub fn decrypt_value(
    key: &[u8],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<SecretVec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("invalid key length: {}", e))?;
    let nonce_arr: [u8; NONCE_LEN] = nonce.try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be {} bytes", NONCE_LEN))?;
    let nonce = ArrayN::<u8, 24>::from(nonce_arr);
    let pt = cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow::anyhow!("decrypt failed: {}", e))?;
    Ok(SecretVec::from(pt))
}

/// Encode an encrypted value to the `enc:v1:<nonce_b64>:<ct_b64>` store format.
pub fn encode_enc_value(nonce: &[u8], ciphertext: &[u8]) -> String {
    // ENC_PREFIX already ends with ":", so no extra separator here.
    format!(
        "{}{}:{}",
        ENC_PREFIX,
        general_purpose::STANDARD.encode(nonce),
        general_purpose::STANDARD.encode(ciphertext)
    )
}

/// Parse `enc:v1:<nonce_b64>:<ct_b64>` back into `(nonce, ciphertext)`.
pub fn parse_enc_value(encoded: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let stripped = encoded
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("missing enc:v1: prefix"))?;
    let parts: Vec<&str> = stripped.splitn(2, ':').collect();
    if parts.len() != 2 {
        bail!("malformed enc:v1 value");
    }
    let nonce = general_purpose::STANDARD.decode(parts[0])?;
    let ct = general_purpose::STANDARD.decode(parts[1])?;
    Ok((nonce, ct))
}

/// Zeroize a `SecretVec` in place. Replaces the buffer with an empty one so
/// the old buffer is dropped; `SecretVec`'s `Drop` implementation zeroizes
/// the memory before releasing it.
pub fn wipe_secret(secret: &mut SecretVec<u8>) {
    let empty = SecretVec::new(vec![]);
    let _replaced = std::mem::replace(secret, empty);
    // `_replaced` is dropped here, zeroizing the old buffer.
}
