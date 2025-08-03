//! AEAD (Authenticated Encryption with Associated Data) 加密接口
//!
//! 提供统一的AEAD加密接口，支持多种加密算法

use super::Method;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use chacha20poly1305::ChaCha20Poly1305;

/// AEAD加密器特征
pub trait AeadCipher: Send + Sync {
    /// 加密数据
    ///
    /// # 参数
    /// * `nonce` - 随机数
    /// * `plaintext` - 明文数据
    /// * `associated_data` - 关联数据（用于认证但不加密）
    ///
    /// # 返回
    /// 加密后的数据（包含认证标签）
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;

    /// 解密数据
    ///
    /// # 参数
    /// * `nonce` - 随机数
    /// * `ciphertext` - 密文数据（包含认证标签）
    /// * `associated_data` - 关联数据
    ///
    /// # 返回
    /// 解密后的明文数据
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;

    /// 获取密钥长度
    fn key_size(&self) -> usize;

    /// 获取随机数长度
    fn nonce_size(&self) -> usize;

    /// 获取认证标签长度
    fn tag_size(&self) -> usize;
}

impl std::fmt::Debug for dyn AeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadCipher")
            .field("key_size", &self.key_size())
            .field("nonce_size", &self.nonce_size())
            .field("tag_size", &self.tag_size())
            .finish()
    }
}

/// AES-128-GCM加密器
pub struct Aes128GcmCipher {
    cipher: Aes128Gcm,
}

impl Aes128GcmCipher {
    /// 创建新的AES-128-GCM加密器
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(anyhow::anyhow!("AES-128-GCM requires 16-byte key"));
        }

        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Failed to create AES-128-GCM cipher: {}", e))?;

        Ok(Self { cipher })
    }
}

impl AeadCipher for Aes128GcmCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("AES-128-GCM requires 12-byte nonce"));
        }

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = plaintext.to_vec();

        self.cipher
            .encrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(buffer)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("AES-128-GCM requires 12-byte nonce"));
        }

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = ciphertext.to_vec();

        self.cipher
            .decrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(buffer)
    }

    fn key_size(&self) -> usize {
        16
    }
    fn nonce_size(&self) -> usize {
        12
    }
    fn tag_size(&self) -> usize {
        16
    }
}

/// AES-256-GCM加密器
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// 创建新的AES-256-GCM加密器
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("AES-256-GCM requires 32-byte key"));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Failed to create AES-256-GCM cipher: {}", e))?;

        Ok(Self { cipher })
    }
}

impl AeadCipher for Aes256GcmCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("AES-256-GCM requires 12-byte nonce"));
        }

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = plaintext.to_vec();

        self.cipher
            .encrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(buffer)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("AES-256-GCM requires 12-byte nonce"));
        }

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = ciphertext.to_vec();

        self.cipher
            .decrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(buffer)
    }

    fn key_size(&self) -> usize {
        32
    }
    fn nonce_size(&self) -> usize {
        12
    }
    fn tag_size(&self) -> usize {
        16
    }
}

/// ChaCha20-Poly1305加密器
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// 创建新的ChaCha20-Poly1305加密器
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("ChaCha20-Poly1305 requires 32-byte key"));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Failed to create ChaCha20-Poly1305 cipher: {}", e))?;

        Ok(Self { cipher })
    }
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("ChaCha20-Poly1305 requires 12-byte nonce"));
        }

        use chacha20poly1305::Nonce;
        let nonce = Nonce::from_slice(nonce);
        let mut buffer = plaintext.to_vec();

        self.cipher
            .encrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(buffer)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("ChaCha20-Poly1305 requires 12-byte nonce"));
        }

        use chacha20poly1305::Nonce;
        let nonce = Nonce::from_slice(nonce);
        let mut buffer = ciphertext.to_vec();

        self.cipher
            .decrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(buffer)
    }

    fn key_size(&self) -> usize {
        32
    }
    fn nonce_size(&self) -> usize {
        12
    }
    fn tag_size(&self) -> usize {
        16
    }
}

/// 创建AEAD加密器
pub fn create_cipher(method: Method, key: &[u8]) -> Result<Box<dyn AeadCipher>> {
    match method {
        Method::Aes128Gcm => {
            let cipher = Aes128GcmCipher::new(key)?;
            Ok(Box::new(cipher))
        }
        Method::Aes256Gcm => {
            let cipher = Aes256GcmCipher::new(key)?;
            Ok(Box::new(cipher))
        }
        Method::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305Cipher::new(key)?;
            Ok(Box::new(cipher))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    #[test]
    fn test_aes128_gcm_cipher() {
        let key = random_bytes(16);
        let cipher = Aes128GcmCipher::new(&key).unwrap();

        let nonce = random_bytes(12);
        let plaintext = b"Hello, World!";
        let associated_data = b"test";

        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data).unwrap();
        let decrypted = cipher
            .decrypt(&nonce, &ciphertext, associated_data)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes256_gcm_cipher() {
        let key = random_bytes(32);
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce = random_bytes(12);
        let plaintext = b"Hello, World!";
        let associated_data = b"test";

        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data).unwrap();
        let decrypted = cipher
            .decrypt(&nonce, &ciphertext, associated_data)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_cipher() {
        let key = random_bytes(32);
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let nonce = random_bytes(12);
        let plaintext = b"Hello, World!";
        let associated_data = b"test";

        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data).unwrap();
        let decrypted = cipher
            .decrypt(&nonce, &ciphertext, associated_data)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_create_cipher() {
        let key = random_bytes(32);

        let cipher = create_cipher(Method::Aes256Gcm, &key).unwrap();
        assert_eq!(cipher.key_size(), 32);
        assert_eq!(cipher.nonce_size(), 12);
        assert_eq!(cipher.tag_size(), 16);
    }

    #[test]
    fn test_invalid_key_size() {
        let key = random_bytes(10); // 错误的密钥长度
        assert!(Aes128GcmCipher::new(&key).is_err());
    }

    #[test]
    fn test_invalid_nonce_size() {
        let key = random_bytes(16);
        let cipher = Aes128GcmCipher::new(&key).unwrap();

        let nonce = random_bytes(10); // 错误的随机数长度
        let plaintext = b"test";
        let associated_data = b"";

        assert!(cipher.encrypt(&nonce, plaintext, associated_data).is_err());
    }
}
