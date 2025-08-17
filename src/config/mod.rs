//! 配置模块
//!
//! 提供服务端和客户端的配置结构和解析功能

pub mod client;
pub mod multi;
pub mod server;

pub use client::ClientConfig;
pub use multi::MultiProtocolConfig;
pub use server::ServerConfig;

use anyhow::Result;
use std::fs;

/// 从文件加载配置
pub fn load_config_from_file<T>(path: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    Ok(config)
}

/// 验证加密方法是否支持
pub fn validate_method(method: &str) -> bool {
    matches!(method, "aes-128-gcm" | "aes-256-gcm" | "chacha20-poly1305")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_method() {
        assert!(validate_method("aes-128-gcm"));
        assert!(validate_method("aes-256-gcm"));
        assert!(validate_method("chacha20-poly1305"));
        assert!(!validate_method("invalid-method"));
    }
}
