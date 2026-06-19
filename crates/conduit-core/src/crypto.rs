use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;

use crate::{Error, Result};

#[derive(Clone)]
pub struct MasterKey(Key);

impl MasterKey {
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).map_err(|e| Error::Crypto(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(Error::Crypto("master key must be 32 bytes (64 hex chars)".into()));
        }
        Ok(Self(*Key::from_slice(&bytes)))
    }

    pub fn from_env(var: &str) -> Result<Self> {
        let raw = std::env::var(var).map_err(|_| Error::Crypto(format!("env {var} not set")))?;
        Self::from_hex(&raw)
    }

    pub fn generate_hex() -> String {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        hex::encode(buf)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.0);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < 12 {
            return Err(Error::Crypto("blob too short".into()));
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(&self.0);
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}
