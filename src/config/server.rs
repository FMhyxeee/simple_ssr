//! 服务端配置模块
//!
//! 定义服务端运行所需的配置参数

use crate::unified::config::UnifiedConfig;
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
    /// 是否启用统一端口模式
    #[serde(default = "default_enable_unified_port")]
    pub enable_unified_port: bool,
    /// 统一端口配置
    #[serde(default)]
    pub unified_port_config: Option<UnifiedConfig>,
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
            enable_unified_port: default_enable_unified_port(),
            unified_port_config: None,
        }
    }

    /// 获取服务器监听地址
    pub fn server_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.server, self.server_port);
        addr.parse()
            .map_err(|e| anyhow!("Invalid server address: {}", e))
    }

    /// 获取统一端口配置
    pub fn unified_config(&self) -> Option<&UnifiedConfig> {
        self.unified_port_config.as_ref()
    }

    /// 设置统一端口配置
    pub fn set_unified_config(&mut self, config: UnifiedConfig) {
        self.unified_port_config = Some(config);
        self.enable_unified_port = true;
    }

    /// 获取统一端口监听地址
    pub fn unified_addr(&self) -> Result<Option<SocketAddr>> {
        if self.enable_unified_port {
            if let Some(config) = &self.unified_port_config {
                Ok(Some(config.unified_addr))
            } else {
                // 如果启用了统一端口但没有配置，使用默认地址
                let addr = format!("{}:{}", self.server, self.server_port);
                Ok(Some(
                    addr.parse()
                        .map_err(|e| anyhow!("Invalid unified address: {}", e))?,
                ))
            }
        } else {
            Ok(None)
        }
    }

    /// 是否应该使用统一端口模式
    pub fn should_use_unified_port(&self) -> bool {
        self.enable_unified_port
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

        // 验证统一端口配置
        if self.enable_unified_port {
            if let Some(config) = &self.unified_port_config {
                config
                    .validate()
                    .map_err(|e| anyhow!("Invalid unified port config: {}", e))?;
            }
            self.unified_addr()?;
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
            enable_unified_port: default_enable_unified_port(),
            unified_port_config: None,
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

/// 默认是否启用统一端口
fn default_enable_unified_port() -> bool {
    false
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

    #[test]
    fn test_unified_port_disabled_by_default() {
        let config = ServerConfig::default();
        assert!(!config.should_use_unified_port());
        assert!(config.unified_config().is_none());
        assert!(config.unified_addr().unwrap().is_none());
    }

    #[test]
    fn test_unified_port_with_config() {
        use crate::unified::config::UnifiedConfig;

        let mut config = ServerConfig::default();
        config.password = "test_password".to_string();

        let unified_config = UnifiedConfig::new("0.0.0.0:8388".parse().unwrap());

        config.set_unified_config(unified_config);

        assert!(config.should_use_unified_port());
        assert!(config.unified_config().is_some());

        let addr = config.unified_addr().unwrap().unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:8388");
    }

    #[test]
    fn test_unified_port_without_config() {
        let mut config = ServerConfig::default();
        config.password = "test_password".to_string();
        config.enable_unified_port = true;

        assert!(config.should_use_unified_port());
        assert!(config.unified_config().is_none());

        // 应该使用默认的服务器地址和端口
        let addr = config.unified_addr().unwrap().unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:8388");
    }
}
