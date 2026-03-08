//! AES-256-GCM + Argon2id encryption for agent secret keys.
//!
//! Compatible with elisym-client's `cli/crypto.rs` — same format,
//! same key derivation, same serialization (bs58).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result};
use argon2::{Argon2, Params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Pinned Argon2id parameters for key derivation.
/// These MUST NOT change between versions, or existing encrypted configs will
/// become undecryptable. If stronger params are needed, add a version field
/// to EncryptionSection and handle migration.
const ARGON2_M_COST_KIB: u32 = 19_456; // ~19 MiB memory
const ARGON2_T_COST: u32 = 2;          // 2 iterations
const ARGON2_P_COST: u32 = 1;          // 1 thread

/// Encrypted secrets stored in config.toml `[encryption]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionSection {
    pub ciphertext: String, // bs58
    pub salt: String,       // bs58
    pub nonce: String,      // bs58
}

/// Decrypted secrets bundle — matches elisym-client's `SecretsBundle`.
#[derive(Serialize, Deserialize)]
pub struct SecretsBundle {
    pub nostr_secret_key: String,
    pub solana_secret_key: String,
    #[serde(default)]
    pub llm_api_key: String,
    #[serde(default)]
    pub customer_llm_api_key: Option<String>,
}

/// Derive a 256-bit key from password + salt using Argon2id with pinned parameters.
/// Returns the key wrapped in `Zeroizing` so it is zeroed when dropped.
fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
    buf
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
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("wrong password or corrupted data"))?,
    );

    let bundle: SecretsBundle = serde_json::from_slice(&plaintext)
        .context("failed to parse decrypted secrets")?;

    Ok(bundle)
}

/// Encrypt a secrets bundle with a password.
pub fn encrypt_secrets(bundle: &SecretsBundle, password: &str) -> Result<EncryptionSection> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(bundle).context("failed to serialize secrets")?,
    );

    let salt = random_bytes::<SALT_LEN>();
    let nonce_bytes = random_bytes::<NONCE_LEN>();

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    Ok(EncryptionSection {
        ciphertext: bs58::encode(&ciphertext).into_string(),
        salt: bs58::encode(salt).into_string(),
        nonce: bs58::encode(nonce_bytes).into_string(),
    })
}
