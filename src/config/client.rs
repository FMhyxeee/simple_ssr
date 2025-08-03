//! 客户端配置模块
//!
//! 定义客户端运行所需的配置参数

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 客户端配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 服务器地址
    pub server: String,
    /// 服务器端口
    pub server_port: u16,
    /// 本地监听地址
    pub local_address: String,
    /// 本地监听端口
    pub local_port: u16,
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
    /// UDP本地监听端口
    #[serde(default = "default_udp_port")]
    pub local_udp_port: Option<u16>,
    /// 最大并发连接数
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl ClientConfig {
    /// 创建新的客户端配置
    pub fn new(
        server: String,
        server_port: u16,
        local_address: String,
        local_port: u16,
        password: String,
        method: String,
    ) -> Self {
        Self {
            server,
            server_port,
            local_address,
            local_port,
            password,
            method,
            timeout: default_timeout(),
            enable_udp: default_enable_udp(),
            local_udp_port: default_udp_port(),
            max_connections: default_max_connections(),
        }
    }

    /// 获取服务器地址
    pub fn server_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.server, self.server_port);
        addr.parse()
            .map_err(|e| anyhow!("Invalid server address: {}", e))
    }

    /// 获取服务器端口
    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    /// 获取本地端口
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// 获取本地监听地址
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.local_address, self.local_port);
        addr.parse()
            .map_err(|e| anyhow!("Invalid local address: {}", e))
    }

    /// 获取UDP本地监听地址
    pub fn local_udp_addr(&self) -> Result<Option<SocketAddr>> {
        if let Some(port) = self.local_udp_port {
            let addr = format!("{}:{}", self.local_address, port);
            Ok(Some(addr.parse().map_err(|e| {
                anyhow!("Invalid local UDP address: {}", e)
            })?))
        } else {
            Ok(None)
        }
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

        if self.local_port == 0 {
            return Err(anyhow!("Invalid local port: {}", self.local_port));
        }

        if self.timeout == 0 {
            return Err(anyhow!("Timeout must be greater than 0"));
        }

        // 验证地址格式
        self.server_addr()?;
        self.local_addr()?;
        self.local_udp_addr()?;

        Ok(())
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            local_address: "127.0.0.1".to_string(),
            local_port: 1080,
            password: String::new(),
            method: "aes-256-gcm".to_string(),
            timeout: default_timeout(),
            enable_udp: default_enable_udp(),
            local_udp_port: default_udp_port(),
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

/// 默认UDP端口
fn default_udp_port() -> Option<u16> {
    Some(1081)
}

/// 默认最大连接数
fn default_max_connections() -> usize {
    1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_new() {
        let config = ClientConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "127.0.0.1".to_string(),
            1080,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert_eq!(config.server, "127.0.0.1");
        assert_eq!(config.server_port, 8388);
        assert_eq!(config.local_address, "127.0.0.1");
        assert_eq!(config.local_port, 1080);
        assert_eq!(config.password, "test_password");
        assert_eq!(config.method, "aes-256-gcm");
    }

    #[test]
    fn test_server_addr() {
        let config = ClientConfig::new(
            "192.168.1.100".to_string(),
            8388,
            "127.0.0.1".to_string(),
            1080,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        let addr = config.server_addr().unwrap();
        assert_eq!(addr.to_string(), "192.168.1.100:8388");
    }

    #[test]
    fn test_local_addr() {
        let config = ClientConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "127.0.0.1".to_string(),
            1080,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        let addr = config.local_addr().unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = ClientConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "127.0.0.1".to_string(),
            1080,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_password() {
        let config = ClientConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "127.0.0.1".to_string(),
            1080,
            "".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_local_udp_addr() {
        let mut config = ClientConfig::default();
        config.local_udp_port = Some(1081);

        let addr = config.local_udp_addr().unwrap().unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:1081");
    }
}
