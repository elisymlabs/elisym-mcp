//! AES-256-GCM + Argon2id encryption for agent secret keys.
//!
//! Compatible with elisym-client's `cli/crypto.rs` — same format,
//! same key derivation, same serialization (bs58).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result};
use argon2::Argon2;
use serde::Deserialize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Encrypted secrets stored in config.toml `[encryption]` section.
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionSection {
    pub ciphertext: String, // bs58
    pub salt: String,       // bs58
    pub nonce: String,      // bs58
}

/// Decrypted secrets bundle — matches elisym-client's `SecretsBundle`.
#[derive(Deserialize)]
pub struct SecretsBundle {
    pub nostr_secret_key: String,
    pub solana_secret_key: String,
    // llm_api_key and customer_llm_api_key are ignored — MCP doesn't use them
}

/// Derive a 256-bit key from password + salt using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Decrypt a secrets bundle with a password.
pub fn decrypt_secrets(section: &EncryptionSection, password: &str) -> Result<SecretsBundle> {
    let ciphertext = bs58::decode(&section.ciphertext)
        .into_vec()
        .context("invalid ciphertext encoding")?;
    let salt = bs58::decode(&section.salt)
        .into_vec()
        .context("invalid salt encoding")?;
    let nonce_bytes: [u8; NONCE_LEN] = bs58::decode(&section.nonce)
        .into_vec()
        .context("invalid nonce encoding")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("nonce must be {NONCE_LEN} bytes, got {}", v.len()))?;

    anyhow::ensure!(salt.len() == SALT_LEN, "salt must be {SALT_LEN} bytes");

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("wrong password or corrupted data"))?;

    let bundle: SecretsBundle = serde_json::from_slice(&plaintext)
        .context("failed to parse decrypted secrets")?;

    Ok(bundle)
}
