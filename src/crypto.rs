#[allow(deprecated)]
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Decryption ────────────────────────────────────────────────────────────────

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

    let dek = unwrap_dek(shared.as_bytes(), &B64.decode(dek_nonce_b64)?, &B64.decode(encrypted_dek_b64)?)?;

    let body_nonce = B64.decode(body_nonce_b64).context("invalid nonce encoding")?;
    let ciphertext = B64.decode(ciphertext_b64).context("invalid ciphertext encoding")?;
    let aad = B64.decode(aad_b64).context("invalid aad encoding")?;
    decrypt_body(&dek, &body_nonce, &ciphertext, &aad)
}

// ── Encryption ────────────────────────────────────────────────────────────────

pub struct DeviceWrap {
    pub device_id: String,
    pub key_type: String,
    pub ephemeral_pub: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,
}

pub struct EncryptedPayload {
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub recipients: Vec<DeviceWrap>,
}

#[allow(deprecated)]
pub fn encrypt_for_devices(
    kv_key: &str,
    plaintext: &[u8],
    devices: &[(String, String, String)], // (device_id, key_type, public_key_b64)
) -> Result<EncryptedPayload> {
    if devices.is_empty() {
        anyhow::bail!("no registered devices to encrypt for");
    }

    let mut rng = OsRng;

    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);

    let mut body_nonce = [0u8; 12];
    rng.fill_bytes(&mut body_nonce);

    let aad_str = format!("device-kv:{kv_key}");
    let aad_bytes = aad_str.as_bytes();

    let body_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let ciphertext = body_cipher
        .encrypt(
            Nonce::from_slice(&body_nonce),
            Payload { msg: plaintext, aad: aad_bytes },
        )
        .map_err(|_| anyhow::anyhow!("body encryption failed"))?;

    let mut recipients = Vec::new();
    for (device_id, key_type, public_key_b64) in devices {
        let pub_bytes = B64.decode(public_key_b64).context("invalid device public key")?;
        let (eph_pub_bytes, shared_bytes) = match key_type.as_str() {
            "x25519" => wrap_x25519(&pub_bytes)?,
            "p256" => wrap_p256(&pub_bytes)?,
            other => anyhow::bail!("unsupported key type: {other}"),
        };

        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared_bytes);
        let mut wrap_key = [0u8; 32];
        hk.expand(b"kv-device-wrap", &mut wrap_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

        let mut dek_nonce = [0u8; 12];
        rng.fill_bytes(&mut dek_nonce);

        let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
        let encrypted_dek = wrap_cipher
            .encrypt(Nonce::from_slice(&dek_nonce), dek.as_ref())
            .map_err(|_| anyhow::anyhow!("DEK encryption failed"))?;

        recipients.push(DeviceWrap {
            device_id: device_id.clone(),
            key_type: key_type.clone(),
            ephemeral_pub: B64.encode(&eph_pub_bytes),
            dek_nonce: B64.encode(dek_nonce),
            encrypted_dek: B64.encode(&encrypted_dek),
        });
    }

    Ok(EncryptedPayload {
        nonce: B64.encode(body_nonce),
        ciphertext: B64.encode(&ciphertext),
        aad: B64.encode(aad_bytes),
        recipients,
    })
}

// ── Internals ─────────────────────────────────────────────────────────────────

fn wrap_x25519(pub_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("X25519 public key must be 32 bytes"))?;
    let device_pub = PublicKey::from(arr);
    let ephemeral = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&device_pub);
    Ok((eph_pub.as_bytes().to_vec(), shared.as_bytes().to_vec()))
}

fn wrap_p256(pub_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePublicKey;
    let device_pub = p256::PublicKey::from_public_key_der(pub_bytes)
        .map_err(|e| anyhow::anyhow!("invalid P-256 public key: {e}"))?;
    let ephemeral = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let eph_pub = ephemeral.public_key();
    let shared = ephemeral.diffie_hellman(&device_pub);
    let eph_pub_bytes = eph_pub.to_encoded_point(false).as_bytes().to_vec();
    Ok((eph_pub_bytes, shared.raw_secret_bytes().to_vec()))
}

#[allow(deprecated)]
fn unwrap_dek(shared: &[u8], dek_nonce: &[u8], encrypted_dek: &[u8]) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared);
    let mut wrap_key = [0u8; 32];
    hk.expand(b"kv-device-wrap", &mut wrap_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    cipher
        .decrypt(Nonce::from_slice(dek_nonce), encrypted_dek)
        .map_err(|_| anyhow::anyhow!("DEK decryption failed — wrong device key?"))
}

#[allow(deprecated)]
fn decrypt_body(dek: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload { msg: ciphertext, aad },
        )
        .map_err(|_| anyhow::anyhow!("body decryption failed"))
}
