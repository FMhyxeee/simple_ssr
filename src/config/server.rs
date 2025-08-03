//! 服务端配置模块
//!
//! 定义服务端运行所需的配置参数

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 服务端配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 服务器监听地址
    pub server: String,
    /// 服务器监听端口
    pub server_port: u16,
    /// 加密密码
    pub password: String,
    /// 加密方法
    pub method: String,
    /// 连接超时时间（秒）
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// 是否启用UDP代理
    #[serde(default = "default_enable_udp")]
    pub enable_udp: bool,
    /// 最大并发连接数
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl ServerConfig {
    /// 创建新的服务端配置
    pub fn new(server: String, server_port: u16, password: String, method: String) -> Self {
        Self {
            server,
            server_port,
            password,
            method,
            timeout: default_timeout(),
            enable_udp: default_enable_udp(),
            max_connections: default_max_connections(),
        }
    }

    /// 获取服务器监听地址
    pub fn server_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.server, self.server_port);
        addr.parse()
            .map_err(|e| anyhow!("Invalid server address: {}", e))
    }

    /// 验证配置有效性
    pub fn validate(&self) -> Result<()> {
        if self.password.is_empty() {
            return Err(anyhow!("Password cannot be empty"));
        }

        if !super::validate_method(&self.method) {
            return Err(anyhow!("Unsupported encryption method: {}", self.method));
        }

        if self.server_port == 0 {
            return Err(anyhow!("Invalid server port: {}", self.server_port));
        }

        if self.timeout == 0 {
            return Err(anyhow!("Timeout must be greater than 0"));
        }

        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: "0.0.0.0".to_string(),
            server_port: 8388,
            password: String::new(),
            method: "aes-256-gcm".to_string(),
            timeout: default_timeout(),
            enable_udp: default_enable_udp(),
            max_connections: default_max_connections(),
        }
    }
}

/// 默认超时时间（秒）
fn default_timeout() -> u64 {
    300
}

/// 默认是否启用UDP
fn default_enable_udp() -> bool {
    true
}

/// 默认最大连接数
fn default_max_connections() -> usize {
    1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_new() {
        let config = ServerConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert_eq!(config.server, "127.0.0.1");
        assert_eq!(config.server_port, 8388);
        assert_eq!(config.password, "test_password");
        assert_eq!(config.method, "aes-256-gcm");
    }

    #[test]
    fn test_server_addr() {
        let config = ServerConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        let addr = config.server_addr().unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:8388");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = ServerConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_password() {
        let config = ServerConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_method() {
        let config = ServerConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "test_password".to_string(),
            "invalid-method".to_string(),
        );

        assert!(config.validate().is_err());
    }
}
