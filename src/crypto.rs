use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt::Write;

type HmacSha256 = Hmac<Sha256>;

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub struct SessionKeys {
    pub room_id: String,
    pub cipher: ChaCha20Poly1305,
    auth_key: [u8; 32],
}

impl SessionKeys {
    pub fn from_code(code: &str) -> Result<Self, String> {
        let trimmed = code.trim();
        if trimmed.is_empty() {
            return Err("Transfer code cannot be empty".into());
        }
        let code_bytes = trimmed.as_bytes();

        // 1. Derive room ID for libp2p protocol negotiation (truncated hex of SHA-256)
        let mut room_hasher = Sha256::new();
        room_hasher.update(b"voidhop-room:");
        room_hasher.update(code_bytes);
        let room_hash = hex_encode(&room_hasher.finalize()[..10]);

        // 2. Derive cryptographic keys via HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(b"voidhop-protocol-v1-salt"), code_bytes);

        let mut cipher_key_bytes = [0u8; 32];
        hk.expand(b"voidhop-cipher-key", &mut cipher_key_bytes)
            .expect("32 bytes for cipher key is within HKDF limits");

        let mut auth_key = [0u8; 32];
        hk.expand(b"voidhop-auth-key", &mut auth_key)
            .expect("32 bytes for auth key is within HKDF limits");

        let cipher_key = Key::from(cipher_key_bytes);
        let cipher = ChaCha20Poly1305::new(&cipher_key);

        Ok(Self {
            room_id: room_hash,
            cipher,
            auth_key,
        })
    }

    /// Derives a 32-byte hex token for Internet relay pairing
    pub fn transit_token(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"voidhop-transit-relay-token:");
        hasher.update(&self.auth_key);
        hex_encode(&hasher.finalize())
    }

    /// Generates an HMAC-SHA256 response for a challenge
    pub fn compute_auth_response(&self, challenge: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.auth_key)
            .expect("HMAC can take key of any size");
        mac.update(challenge);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verifies an HMAC-SHA256 response for a challenge in constant time
    pub fn verify_auth_response(&self, challenge: &[u8; 32], response: &[u8; 32]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.auth_key)
            .expect("HMAC can take key of any size");
        mac.update(challenge);
        mac.verify_slice(response).is_ok()
    }

    /// Builds a 12-byte nonce from a 64-bit chunk index and direction (0=sender->receiver, 1=receiver->sender)
    fn make_nonce(chunk_index: u64, direction: u8) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[0] = direction;
        bytes[4..12].copy_from_slice(&chunk_index.to_be_bytes());
        Nonce::from(bytes)
    }

    /// Encrypts a chunk with ChaCha20-Poly1305
    pub fn encrypt_chunk(&self, chunk_index: u64, direction: u8, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = Self::make_nonce(chunk_index, direction);
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encryption error: {:?}", e))
    }

    /// Decrypts a chunk with ChaCha20-Poly1305
    pub fn decrypt_chunk(&self, chunk_index: u64, direction: u8, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = Self::make_nonce(chunk_index, direction);
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Decryption error (data corrupted or incorrect code): {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_code_rejected() {
        assert!(SessionKeys::from_code("").is_err());
        assert!(SessionKeys::from_code("   ").is_err());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let k1 = SessionKeys::from_code("1234-cosmic-falcon").unwrap();
        let k2 = SessionKeys::from_code(" 1234-cosmic-falcon ").unwrap();
        assert_eq!(k1.room_id, k2.room_id);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = SessionKeys::from_code("test-code").unwrap();
        let data = b"Hello, VoidHop encrypted world!";
        let ciphertext = keys.encrypt_chunk(0, 0, data).unwrap();
        assert_ne!(&ciphertext[..], data);

        let decrypted = keys.decrypt_chunk(0, 0, &ciphertext).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_with_wrong_code_fails() {
        let k1 = SessionKeys::from_code("code-a").unwrap();
        let k2 = SessionKeys::from_code("code-b").unwrap();
        let data = b"Sensitive payload";
        let ciphertext = k1.encrypt_chunk(0, 0, data).unwrap();
        assert!(k2.decrypt_chunk(0, 0, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_direction_or_chunk_fails() {
        let keys = SessionKeys::from_code("code-a").unwrap();
        let data = b"Sensitive payload";
        let ciphertext = keys.encrypt_chunk(0, 0, data).unwrap();
        // Wrong direction
        assert!(keys.decrypt_chunk(0, 1, &ciphertext).is_err());
        // Wrong chunk index
        assert!(keys.decrypt_chunk(1, 0, &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let keys = SessionKeys::from_code("code-a").unwrap();
        let data = b"Integrity check";
        let mut ciphertext = keys.encrypt_chunk(0, 0, data).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01; // flip 1 bit
        assert!(keys.decrypt_chunk(0, 0, &ciphertext).is_err());
    }

    #[test]
    fn test_auth_hmac_challenge_response() {
        let k1 = SessionKeys::from_code("secret-code").unwrap();
        let k2 = SessionKeys::from_code("secret-code").unwrap();
        let wrong_k = SessionKeys::from_code("wrong-code").unwrap();

        let mut challenge = [0u8; 32];
        challenge[0] = 42;
        let response = k1.compute_auth_response(&challenge);

        assert!(k2.verify_auth_response(&challenge, &response));
        assert!(!wrong_k.verify_auth_response(&challenge, &response));

        let mut wrong_response = response;
        wrong_response[0] ^= 0xFF;
        assert!(!k2.verify_auth_response(&challenge, &wrong_response));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0x10, 0xff]), "000f10ff");
    }

    #[test]
    fn test_transit_token_deterministic() {
        let k1 = SessionKeys::from_code("1234-cosmic-falcon").unwrap();
        let k2 = SessionKeys::from_code("1234-cosmic-falcon").unwrap();
        assert_eq!(k1.transit_token(), k2.transit_token());
        assert_eq!(k1.transit_token().len(), 64);
    }
}
