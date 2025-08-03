//! 加密上下文模块
//!
//! 提供高级的加密和解密接口，管理密钥和随机数

use super::{AeadCipher, Method, aead::create_cipher, derive_key, increment_nonce, random_bytes};
use anyhow::{Result, anyhow};
use std::sync::Arc;

/// 加密上下文
///
/// 管理加密算法、密钥和随机数状态
#[derive(Debug)]
pub struct CryptoContext {
    cipher: Arc<dyn AeadCipher>,
    method: Method,
    key: Vec<u8>,
    nonce_counter: std::sync::Mutex<Vec<u8>>,
}

impl CryptoContext {
    /// 创建新的加密上下文
    ///
    /// # 参数
    /// * `method` - 加密方法字符串
    /// * `password` - 密码
    ///
    /// # 返回
    /// 加密上下文实例
    pub fn new(method: &str, password: &str) -> Result<Self> {
        let method = Method::from_str(method)?;
        let key = derive_key(password, method.key_size());
        let cipher = create_cipher(method, &key)?;

        // 初始化随机数计数器
        let nonce_counter = random_bytes(method.nonce_size());

        Ok(Self {
            cipher: Arc::from(cipher),
            method,
            key,
            nonce_counter: std::sync::Mutex::new(nonce_counter),
        })
    }

    /// 从现有密钥创建加密上下文
    ///
    /// # 参数
    /// * `method` - 加密方法
    /// * `key` - 密钥
    ///
    /// # 返回
    /// 加密上下文实例
    pub fn from_key(method: Method, key: Vec<u8>) -> Result<Self> {
        if key.len() != method.key_size() {
            return Err(anyhow!("Invalid key size for method {}", method.as_str()));
        }

        let cipher = create_cipher(method, &key)?;
        let nonce_counter = random_bytes(method.nonce_size());

        Ok(Self {
            cipher: Arc::from(cipher),
            method,
            key,
            nonce_counter: std::sync::Mutex::new(nonce_counter),
        })
    }

    /// 加密载荷数据
    ///
    /// # 参数
    /// * `payload` - 要加密的数据
    ///
    /// # 返回
    /// 加密后的数据（包含随机数和密文）
    pub fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.generate_nonce()?;
        let ciphertext = self.cipher.encrypt(&nonce, payload, &[])?;

        // 格式: [nonce][ciphertext]
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// 解密载荷数据
    ///
    /// # 参数
    /// * `payload` - 要解密的数据（包含随机数和密文）
    ///
    /// # 返回
    /// 解密后的明文数据
    pub fn decrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let nonce_size = self.method.nonce_size();

        if payload.len() < nonce_size {
            return Err(anyhow!("Payload too short, missing nonce"));
        }

        let (nonce, ciphertext) = payload.split_at(nonce_size);
        let plaintext = self.cipher.decrypt(nonce, ciphertext, &[])?;

        Ok(plaintext)
    }

    /// 使用指定随机数加密数据
    ///
    /// # 参数
    /// * `nonce` - 随机数
    /// * `plaintext` - 明文数据
    /// * `associated_data` - 关联数据
    ///
    /// # 返回
    /// 加密后的密文
    pub fn encrypt_with_nonce(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher.encrypt(nonce, plaintext, associated_data)
    }

    /// 使用指定随机数解密数据
    ///
    /// # 参数
    /// * `nonce` - 随机数
    /// * `ciphertext` - 密文数据
    /// * `associated_data` - 关联数据
    ///
    /// # 返回
    /// 解密后的明文
    pub fn decrypt_with_nonce(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher.decrypt(nonce, ciphertext, associated_data)
    }

    /// 生成新的随机数
    ///
    /// 使用内部计数器生成唯一的随机数
    fn generate_nonce(&self) -> Result<Vec<u8>> {
        let mut counter = self
            .nonce_counter
            .lock()
            .map_err(|e| anyhow!("Failed to lock nonce counter: {}", e))?;

        let nonce = counter.clone();
        increment_nonce(&mut counter);

        Ok(nonce)
    }

    /// 获取加密方法
    pub fn method(&self) -> Method {
        self.method
    }

    /// 获取密钥长度
    pub fn key_size(&self) -> usize {
        self.method.key_size()
    }

    /// 获取随机数长度
    pub fn nonce_size(&self) -> usize {
        self.method.nonce_size()
    }

    /// 获取标签长度
    pub fn tag_size(&self) -> usize {
        self.method.tag_size()
    }

    /// 获取密钥
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// 重置随机数计数器
    pub fn reset_nonce(&self) {
        if let Ok(mut nonce) = self.nonce_counter.lock() {
            *nonce = random_bytes(self.method.nonce_size());
        }
    }

    /// 获取标签长度
    pub fn tag_len(&self) -> usize {
        self.cipher.tag_size()
    }

    /// 获取随机数长度
    pub fn nonce_len(&self) -> usize {
        self.cipher.nonce_size()
    }
}

// 实现Clone，但需要重新生成随机数计数器
impl Clone for CryptoContext {
    fn clone(&self) -> Self {
        let nonce_counter = random_bytes(self.method.nonce_size());

        Self {
            cipher: self.cipher.clone(),
            method: self.method,
            key: self.key.clone(),
            nonce_counter: std::sync::Mutex::new(nonce_counter),
        }
    }
}

/// 加密流上下文
///
/// 用于流式加密，维护连续的随机数状态
pub struct StreamCipher {
    context: CryptoContext,
    encrypt_nonce: Vec<u8>,
    decrypt_nonce: Vec<u8>,
}

impl StreamCipher {
    /// 创建新的流加密器
    pub fn new(method: &str, password: &str) -> Result<Self> {
        let context = CryptoContext::new(method, password)?;
        let encrypt_nonce = random_bytes(context.nonce_size());
        let decrypt_nonce = random_bytes(context.nonce_size());

        Ok(Self {
            context,
            encrypt_nonce,
            decrypt_nonce,
        })
    }

    /// 加密数据块
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = self
            .context
            .encrypt_with_nonce(&self.encrypt_nonce, chunk, &[])?;
        increment_nonce(&mut self.encrypt_nonce);
        Ok(ciphertext)
    }

    /// 解密数据块
    pub fn decrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self
            .context
            .decrypt_with_nonce(&self.decrypt_nonce, chunk, &[])?;
        increment_nonce(&mut self.decrypt_nonce);
        Ok(plaintext)
    }

    /// 重置加密随机数
    pub fn reset_encrypt_nonce(&mut self, nonce: Vec<u8>) {
        self.encrypt_nonce = nonce;
    }

    /// 重置解密随机数
    pub fn reset_decrypt_nonce(&mut self, nonce: Vec<u8>) {
        self.decrypt_nonce = nonce;
    }

    /// 获取当前加密随机数
    pub fn encrypt_nonce(&self) -> &[u8] {
        &self.encrypt_nonce
    }

    /// 获取当前解密随机数
    pub fn decrypt_nonce(&self) -> &[u8] {
        &self.decrypt_nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_context_new() {
        let context = CryptoContext::new("aes-256-gcm", "test_password").unwrap();
        assert_eq!(context.method(), Method::Aes256Gcm);
        assert_eq!(context.key_size(), 32);
        assert_eq!(context.nonce_size(), 12);
        assert_eq!(context.tag_size(), 16);
    }

    #[test]
    fn test_encrypt_decrypt_payload() {
        let context = CryptoContext::new("aes-256-gcm", "test_password").unwrap();
        let plaintext = b"Hello, Shadowsocks!";

        let encrypted = context.encrypt_payload(plaintext).unwrap();
        let decrypted = context.decrypt_payload(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_with_nonce() {
        let context = CryptoContext::new("aes-256-gcm", "test_password").unwrap();
        let nonce = random_bytes(12);
        let plaintext = b"Hello, World!";
        let associated_data = b"test";

        let ciphertext = context
            .encrypt_with_nonce(&nonce, plaintext, associated_data)
            .unwrap();
        let decrypted = context
            .decrypt_with_nonce(&nonce, &ciphertext, associated_data)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_stream_cipher() {
        let mut cipher = StreamCipher::new("aes-256-gcm", "test_password").unwrap();

        let chunk1 = b"First chunk";
        let chunk2 = b"Second chunk";

        let encrypted1 = cipher.encrypt_chunk(chunk1).unwrap();
        let encrypted2 = cipher.encrypt_chunk(chunk2).unwrap();

        // 重置解密随机数到初始状态
        let initial_nonce = cipher.encrypt_nonce().to_vec();
        cipher.reset_decrypt_nonce(initial_nonce);

        let decrypted1 = cipher.decrypt_chunk(&encrypted1).unwrap();
        let decrypted2 = cipher.decrypt_chunk(&encrypted2).unwrap();

        assert_eq!(chunk1, decrypted1.as_slice());
        assert_eq!(chunk2, decrypted2.as_slice());
    }

    #[test]
    fn test_invalid_method() {
        assert!(CryptoContext::new("invalid-method", "password").is_err());
    }

    #[test]
    fn test_payload_too_short() {
        let context = CryptoContext::new("aes-256-gcm", "test_password").unwrap();
        let short_payload = vec![1, 2, 3]; // 太短，缺少随机数

        assert!(context.decrypt_payload(&short_payload).is_err());
    }

    #[test]
    fn test_context_clone() {
        let context1 = CryptoContext::new("aes-256-gcm", "test_password").unwrap();
        let context2 = context1.clone();

        let plaintext = b"test data";

        let encrypted1 = context1.encrypt_payload(plaintext).unwrap();
        let encrypted2 = context2.encrypt_payload(plaintext).unwrap();

        // 两个上下文应该能够解密对方的数据
        let decrypted1 = context2.decrypt_payload(&encrypted1).unwrap();
        let decrypted2 = context1.decrypt_payload(&encrypted2).unwrap();

        assert_eq!(plaintext, decrypted1.as_slice());
        assert_eq!(plaintext, decrypted2.as_slice());
    }
}
