#[allow(deprecated)]
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

#[allow(deprecated)]
pub fn decrypt_device_kv(
    private_key_b64: &str,
    ephemeral_pub_b64: &str,
    dek_nonce_b64: &str,
    encrypted_dek_b64: &str,
    body_nonce_b64: &str,
    ciphertext_b64: &str,
    aad_b64: &str,
) -> Result<Vec<u8>> {
    let priv_bytes: [u8; 32] = B64
        .decode(private_key_b64.trim())
        .context("invalid private key encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("device key must be 32 bytes"))?;
    let secret = StaticSecret::from(priv_bytes);

    let eph_bytes: [u8; 32] = B64
        .decode(ephemeral_pub_b64)
        .context("invalid ephemeral_pub encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ephemeral_pub must be 32 bytes"))?;
    let eph_pub = PublicKey::from(eph_bytes);

    let shared = secret.diffie_hellman(&eph_pub);

    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(b"kv-device-wrap", &mut wrap_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let dek_nonce = B64.decode(dek_nonce_b64).context("invalid dek_nonce encoding")?;
    let enc_dek = B64.decode(encrypted_dek_b64).context("invalid encrypted_dek encoding")?;
    let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let dek = wrap_cipher
        .decrypt(Nonce::from_slice(&dek_nonce), enc_dek.as_ref())
        .map_err(|_| anyhow::anyhow!("DEK decryption failed — wrong device key?"))?;

    let body_nonce = B64.decode(body_nonce_b64).context("invalid nonce encoding")?;
    let ciphertext = B64.decode(ciphertext_b64).context("invalid ciphertext encoding")?;
    let aad = B64.decode(aad_b64).context("invalid aad encoding")?;
    let body_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let plaintext = body_cipher
        .decrypt(
            Nonce::from_slice(&body_nonce),
            Payload { msg: &ciphertext, aad: &aad },
        )
        .map_err(|_| anyhow::anyhow!("body decryption failed"))?;

    Ok(plaintext)
}
