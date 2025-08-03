//! 加密模块
//!
//! 提供Shadowsocks协议所需的加密和解密功能

pub mod aead;
pub mod cipher;

pub use aead::AeadCipher;
pub use cipher::CryptoContext;

use anyhow::{Result, anyhow};
use ring::digest;
use std::num::Wrapping;

/// 支持的加密方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    /// 从字符串解析加密方法
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(Method::Aes128Gcm),
            "aes-256-gcm" => Ok(Method::Aes256Gcm),
            "chacha20-poly1305" => Ok(Method::ChaCha20Poly1305),
            _ => Err(anyhow!("Unsupported encryption method: {}", s)),
        }
    }

    /// 获取密钥长度
    pub fn key_size(&self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            Method::Aes256Gcm => 32,
            Method::ChaCha20Poly1305 => 32,
        }
    }

    /// 获取密钥长度（别名）
    pub fn key_len(&self) -> usize {
        self.key_size()
    }

    /// 获取随机数长度
    pub fn nonce_size(&self) -> usize {
        match self {
            Method::Aes128Gcm | Method::Aes256Gcm => 12,
            Method::ChaCha20Poly1305 => 12,
        }
    }

    /// 获取标签长度
    pub fn tag_size(&self) -> usize {
        16
    }

    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Aes128Gcm => "aes-128-gcm",
            Method::Aes256Gcm => "aes-256-gcm",
            Method::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// 从密码派生密钥
///
/// 使用HKDF-SHA1算法从密码派生指定长度的密钥
pub fn derive_key(password: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let password_bytes = password.as_bytes();

    let mut d = Vec::new();
    let mut i = 0u32;

    while key.len() < key_len {
        let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(&d);
        ctx.update(password_bytes);
        d = ctx.finish().as_ref().to_vec();

        key.extend_from_slice(&d);
        i += 1;

        // 防止无限循环
        if i > 100 {
            break;
        }
    }

    key.truncate(key_len);
    key
}

/// 增加随机数计数器
///
/// 用于生成唯一的随机数
pub fn increment_nonce(nonce: &mut [u8]) {
    let mut carry = 1u16;
    for byte in nonce.iter_mut().rev() {
        let sum = Wrapping(*byte as u16) + Wrapping(carry);
        *byte = sum.0 as u8;
        carry = sum.0 >> 8;
        if carry == 0 {
            break;
        }
    }
}

/// 生成随机字节
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_from_str() {
        assert_eq!(Method::from_str("aes-128-gcm").unwrap(), Method::Aes128Gcm);
        assert_eq!(Method::from_str("aes-256-gcm").unwrap(), Method::Aes256Gcm);
        assert_eq!(
            Method::from_str("chacha20-poly1305").unwrap(),
            Method::ChaCha20Poly1305
        );
        assert!(Method::from_str("invalid").is_err());
    }

    #[test]
    fn test_method_key_size() {
        assert_eq!(Method::Aes128Gcm.key_size(), 16);
        assert_eq!(Method::Aes256Gcm.key_size(), 32);
        assert_eq!(Method::ChaCha20Poly1305.key_size(), 32);
    }

    #[test]
    fn test_method_nonce_size() {
        assert_eq!(Method::Aes128Gcm.nonce_size(), 12);
        assert_eq!(Method::Aes256Gcm.nonce_size(), 12);
        assert_eq!(Method::ChaCha20Poly1305.nonce_size(), 12);
    }

    #[test]
    fn test_derive_key() {
        let key = derive_key("test_password", 32);
        assert_eq!(key.len(), 32);

        // 相同密码应该生成相同密钥
        let key2 = derive_key("test_password", 32);
        assert_eq!(key, key2);

        // 不同密码应该生成不同密钥
        let key3 = derive_key("different_password", 32);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_increment_nonce() {
        let mut nonce = vec![0u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[11], 1);

        // 测试进位
        let mut nonce = vec![255u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, vec![0u8; 12]);
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(16);
        let bytes2 = random_bytes(16);

        assert_eq!(bytes1.len(), 16);
        assert_eq!(bytes2.len(), 16);
        // 随机字节应该不同（虽然理论上可能相同，但概率极低）
        assert_ne!(bytes1, bytes2);
    }
}
