//! 统一端口配置模块
//!
//! 定义统一端口功能的配置选项和相关结构

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// 统一端口配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedConfig {
    /// 是否启用统一端口模式
    pub enabled: bool,

    /// 统一端口地址
    pub unified_addr: SocketAddr,

    /// 协议检测超时时间（毫秒）
    pub detection_timeout_ms: u64,

    /// 缓冲区大小
    pub buffer_size: usize,

    /// TCP连接超时时间（毫秒）
    pub tcp_timeout_ms: u64,

    /// UDP会话超时时间（毫秒）
    pub udp_timeout_ms: u64,

    /// 最大并发连接数
    pub max_connections: usize,

    /// 是否启用详细日志
    pub verbose_logging: bool,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            unified_addr: "127.0.0.1:8388".parse().unwrap(),
            detection_timeout_ms: 5000,
            buffer_size: 8192,
            tcp_timeout_ms: 30000,
            udp_timeout_ms: 60000,
            max_connections: 1000,
            verbose_logging: false,
        }
    }
}

impl UnifiedConfig {
    /// 创建新的统一端口配置
    pub fn new(unified_addr: SocketAddr) -> Self {
        Self {
            enabled: true,
            unified_addr,
            ..Default::default()
        }
    }

    /// 设置协议检测超时时间
    pub fn with_detection_timeout(mut self, timeout_ms: u64) -> Self {
        self.detection_timeout_ms = timeout_ms;
        self
    }

    /// 设置缓冲区大小
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// 设置TCP超时时间
    pub fn with_tcp_timeout(mut self, timeout_ms: u64) -> Self {
        self.tcp_timeout_ms = timeout_ms;
        self
    }

    /// 设置UDP超时时间
    pub fn with_udp_timeout(mut self, timeout_ms: u64) -> Self {
        self.udp_timeout_ms = timeout_ms;
        self
    }

    /// 设置最大并发连接数
    pub fn with_max_connections(mut self, max_conn: usize) -> Self {
        self.max_connections = max_conn;
        self
    }

    /// 启用详细日志
    pub fn with_verbose_logging(mut self, enabled: bool) -> Self {
        self.verbose_logging = enabled;
        self
    }

    /// 获取协议检测超时时间
    pub fn detection_timeout(&self) -> Duration {
        Duration::from_millis(self.detection_timeout_ms)
    }

    /// 获取TCP超时时间
    pub fn tcp_timeout(&self) -> Duration {
        Duration::from_millis(self.tcp_timeout_ms)
    }

    /// 获取UDP超时时间
    pub fn udp_timeout(&self) -> Duration {
        Duration::from_millis(self.udp_timeout_ms)
    }

    /// 验证配置是否有效
    pub fn validate(&self) -> Result<(), String> {
        if self.detection_timeout_ms == 0 {
            return Err("检测超时时间不能为0".to_string());
        }

        if self.buffer_size == 0 {
            return Err("缓冲区大小不能为0".to_string());
        }

        if self.max_connections == 0 {
            return Err("最大连接数不能为0".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UnifiedConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.unified_addr.port(), 8388);
        assert_eq!(config.detection_timeout_ms, 5000);
        assert_eq!(config.buffer_size, 8192);
    }

    #[test]
    fn test_new_config() {
        let addr = "127.0.0.1:9999".parse().unwrap();
        let config = UnifiedConfig::new(addr);
        assert!(config.enabled);
        assert_eq!(config.unified_addr, addr);
    }

    #[test]
    fn test_config_builder() {
        let addr = "127.0.0.1:9999".parse().unwrap();
        let config = UnifiedConfig::new(addr)
            .with_detection_timeout(3000)
            .with_buffer_size(4096)
            .with_max_connections(500)
            .with_verbose_logging(true);

        assert_eq!(config.detection_timeout_ms, 3000);
        assert_eq!(config.buffer_size, 4096);
        assert_eq!(config.max_connections, 500);
        assert!(config.verbose_logging);
    }

    #[test]
    fn test_config_validation() {
        let mut config = UnifiedConfig::default();
        assert!(config.validate().is_ok());

        config.detection_timeout_ms = 0;
        assert!(config.validate().is_err());

        config.detection_timeout_ms = 1000;
        config.buffer_size = 0;
        assert!(config.validate().is_err());

        config.buffer_size = 1024;
        config.max_connections = 0;
        assert!(config.validate().is_err());
    }
}
