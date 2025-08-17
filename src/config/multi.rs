//! 多协议配置管理
//!
//! 支持多种代理协议的统一配置管理

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

use crate::protocol::traits::ProtocolType;

/// 多协议配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiProtocolConfig {
    /// 全局配置
    pub global: GlobalConfig,
    
    /// 协议实例配置
    pub instances: HashMap<String, ProtocolInstanceConfig>,
    
    /// 路由规则
    pub routes: Vec<RouteConfig>,
    
    /// 日志配置
    pub logging: LoggingConfig,
}

/// 全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// 工作模式 (server/client)
    pub mode: String,
    
    /// 全局超时设置（秒）
    pub timeout: u64,
    
    /// 最大连接数
    pub max_connections: usize,
    
    /// 缓冲区大小
    pub buffer_size: usize,
    
    /// 启用UDP
    pub enable_udp: bool,
    
    /// 启用统一端口模式
    pub enable_unified_port: bool,
    
    /// 统一端口配置
    pub unified_port: Option<UnifiedPortConfig>,
}

/// 统一端口配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedPortConfig {
    /// 监听地址
    pub listen_addr: String,
    
    /// 协议检测超时（毫秒）
    pub detection_timeout: u64,
    
    /// 启用自动协议检测
    pub auto_detect: bool,
    
    /// 支持的协议列表
    pub supported_protocols: Vec<String>,
}

/// 协议实例配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol")]
pub enum ProtocolInstanceConfig {
    /// Shadowsocks配置
    #[serde(rename = "shadowsocks")]
    Shadowsocks(ShadowsocksInstanceConfig),
    
    /// VMess配置
    #[serde(rename = "vmess")]
    VMess(VmessInstanceConfig),
    
    /// SOCKS5配置
    #[serde(rename = "socks5")]
    Socks5(Socks5InstanceConfig),
    
    /// HTTP代理配置
    #[serde(rename = "http")]
    Http(HttpInstanceConfig),
    
    /// HTTPS代理配置
    #[serde(rename = "https")]
    Https(HttpsInstanceConfig),
}

/// Shadowsocks实例配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksInstanceConfig {
    /// 实例名称
    pub name: String,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// 服务器地址（客户端模式）
    pub server_addr: Option<String>,
    
    /// 密码
    pub password: String,
    
    /// 加密方法
    pub method: String,
    
    /// 启用状态
    pub enabled: bool,
    
    /// 超时设置
    pub timeout: Option<u64>,
}

/// VMess实例配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessInstanceConfig {
    /// 实例名称
    pub name: String,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// 用户ID
    pub user_id: String,
    
    /// 额外ID
    pub alter_id: u16,
    
    /// 安全类型
    pub security: String,
    
    /// 服务器地址（客户端模式）
    pub server_addr: Option<String>,
    
    /// 路径（WebSocket模式）
    pub path: Option<String>,
    
    /// 主机头（WebSocket模式）
    pub host: Option<String>,
    
    /// 启用状态
    pub enabled: bool,
}

/// SOCKS5实例配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5InstanceConfig {
    /// 实例名称
    pub name: String,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// 启用认证
    pub auth: bool,
    
    /// 用户名（如果启用认证）
    pub username: Option<String>,
    
    /// 密码（如果启用认证）
    pub password: Option<String>,
    
    /// 启用状态
    pub enabled: bool,
    
    /// 允许的IP列表
    pub allowed_ips: Option<Vec<String>>,
}

/// HTTP代理实例配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInstanceConfig {
    /// 实例名称
    pub name: String,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// 启用认证
    pub auth: bool,
    
    /// 用户名（如果启用认证）
    pub username: Option<String>,
    
    /// 密码（如果启用认证）
    pub password: Option<String>,
    
    /// 启用状态
    pub enabled: bool,
    
    /// 允许的域名列表
    pub allowed_domains: Option<Vec<String>>,
}

/// HTTPS代理实例配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsInstanceConfig {
    /// 实例名称
    pub name: String,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// TLS证书路径
    pub cert_path: String,
    
    /// TLS私钥路径
    pub key_path: String,
    
    /// 启用认证
    pub auth: bool,
    
    /// 用户名（如果启用认证）
    pub username: Option<String>,
    
    /// 密码（如果启用认证）
    pub password: Option<String>,
    
    /// 启用状态
    pub enabled: bool,
}

/// 路由配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// 规则名称
    pub name: String,
    
    /// 源地址模式
    pub source: Option<String>,
    
    /// 目标地址模式
    pub target: Option<String>,
    
    /// 协议类型
    pub protocol: Option<String>,
    
    /// 目标实例
    pub target_instance: String,
    
    /// 优先级
    pub priority: u32,
}

/// 日志配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// 日志级别
    pub level: String,
    
    /// 日志文件路径
    pub file_path: Option<String>,
    
    /// 启用控制台输出
    pub console: bool,
    
    /// 日志格式
    pub format: LogFormat,
}

/// 日志格式
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON格式
    Json,
    
    /// 文本格式
    Text,
    
    /// 简洁格式
    Compact,
}

impl Default for MultiProtocolConfig {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            instances: HashMap::new(),
            routes: Vec::new(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            mode: "server".to_string(),
            timeout: 300,
            max_connections: 1024,
            buffer_size: 8192,
            enable_udp: true,
            enable_unified_port: false,
            unified_port: None,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: None,
            console: true,
            format: LogFormat::Text,
        }
    }
}

impl ProtocolInstanceConfig {
    /// 获取协议类型
    pub fn protocol_type(&self) -> ProtocolType {
        match self {
            ProtocolInstanceConfig::Shadowsocks(_) => ProtocolType::Shadowsocks,
            ProtocolInstanceConfig::VMess(_) => ProtocolType::VMess,
            ProtocolInstanceConfig::Socks5(_) => ProtocolType::SOCKS5,
            ProtocolInstanceConfig::Http(_) => ProtocolType::HTTP,
            ProtocolInstanceConfig::Https(_) => ProtocolType::HTTPS,
        }
    }

    /// 获取实例名称
    pub fn name(&self) -> &str {
        match self {
            ProtocolInstanceConfig::Shadowsocks(config) => &config.name,
            ProtocolInstanceConfig::VMess(config) => &config.name,
            ProtocolInstanceConfig::Socks5(config) => &config.name,
            ProtocolInstanceConfig::Http(config) => &config.name,
            ProtocolInstanceConfig::Https(config) => &config.name,
        }
    }

    /// 检查是否启用
    pub fn is_enabled(&self) -> bool {
        match self {
            ProtocolInstanceConfig::Shadowsocks(config) => config.enabled,
            ProtocolInstanceConfig::VMess(config) => config.enabled,
            ProtocolInstanceConfig::Socks5(config) => config.enabled,
            ProtocolInstanceConfig::Http(config) => config.enabled,
            ProtocolInstanceConfig::Https(config) => config.enabled,
        }
    }

    /// 获取监听地址
    pub fn listen_addr(&self) -> &str {
        match self {
            ProtocolInstanceConfig::Shadowsocks(config) => &config.listen_addr,
            ProtocolInstanceConfig::VMess(config) => &config.listen_addr,
            ProtocolInstanceConfig::Socks5(config) => &config.listen_addr,
            ProtocolInstanceConfig::Http(config) => &config.listen_addr,
            ProtocolInstanceConfig::Https(config) => &config.listen_addr,
        }
    }

    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        match self {
            ProtocolInstanceConfig::Shadowsocks(config) => {
                if config.enabled {
                    if config.password.is_empty() {
                        return Err(anyhow::anyhow!("Shadowsocks password cannot be empty"));
                    }
                    if config.method.is_empty() {
                        return Err(anyhow::anyhow!("Shadowsocks method cannot be empty"));
                    }
                    // 验证监听地址
                    config.listen_addr.parse::<std::net::SocketAddr>()?;
                }
            }
            ProtocolInstanceConfig::VMess(config) => {
                if config.enabled {
                    if config.user_id.is_empty() {
                        return Err(anyhow::anyhow!("VMess user ID cannot be empty"));
                    }
                    // 验证UUID格式
                    config.user_id.parse::<uuid::Uuid>()?;
                    // 验证监听地址
                    config.listen_addr.parse::<std::net::SocketAddr>()?;
                }
            }
            ProtocolInstanceConfig::Socks5(config) => {
                if config.enabled {
                    // 验证监听地址
                    config.listen_addr.parse::<std::net::SocketAddr>()?;
                }
            }
            ProtocolInstanceConfig::Http(config) => {
                if config.enabled {
                    // 验证监听地址
                    config.listen_addr.parse::<std::net::SocketAddr>()?;
                }
            }
            ProtocolInstanceConfig::Https(config) => {
                if config.enabled {
                    // 验证监听地址
                    config.listen_addr.parse::<std::net::SocketAddr>()?;
                    // 验证证书文件存在
                    if !Path::new(&config.cert_path).exists() {
                        return Err(anyhow::anyhow!("Certificate file not found: {}", config.cert_path));
                    }
                    if !Path::new(&config.key_path).exists() {
                        return Err(anyhow::anyhow!("Private key file not found: {}", config.key_path));
                    }
                }
            }
        }
        Ok(())
    }
}

impl MultiProtocolConfig {
    /// 从文件加载配置
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).await?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// 保存配置到文件
    pub async fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content).await?;
        Ok(())
    }

    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        // 验证全局配置
        if self.global.mode != "server" && self.global.mode != "client" {
            return Err(anyhow::anyhow!("Invalid mode: must be 'server' or 'client'"));
        }

        // 验证协议实例配置
        for (name, instance) in &self.instances {
            instance.validate()?;
            if name != instance.name() {
                return Err(anyhow::anyhow!(
                    "Instance name mismatch: key '{}' != config '{}'",
                    name,
                    instance.name()
                ));
            }
        }

        // 验证路由配置
        for route in &self.routes {
            if route.target_instance.is_empty() {
                return Err(anyhow::anyhow!("Route target instance cannot be empty"));
            }
            if !self.instances.contains_key(&route.target_instance) {
                return Err(anyhow::anyhow!(
                    "Route target instance '{}' not found",
                    route.target_instance
                ));
            }
        }

        Ok(())
    }

    /// 获取启用的协议实例
    pub fn enabled_instances(&self) -> HashMap<String, &ProtocolInstanceConfig> {
        self.instances
            .iter()
            .filter(|(_, config)| config.is_enabled())
            .map(|(name, config)| (name.clone(), config))
            .collect()
    }

    /// 获取指定协议类型的实例
    pub fn instances_by_protocol(&self, protocol_type: &ProtocolType) -> Vec<&ProtocolInstanceConfig> {
        self.instances
            .values()
            .filter(|config| config.protocol_type() == *protocol_type)
            .collect()
    }

    /// 创建默认的服务端配置
    pub fn default_server() -> Self {
        let mut instances = HashMap::new();
        
        // 添加默认的Shadowsocks实例
        instances.insert(
            "ss-main".to_string(),
            ProtocolInstanceConfig::Shadowsocks(ShadowsocksInstanceConfig {
                name: "ss-main".to_string(),
                listen_addr: "0.0.0.0:8388".to_string(),
                server_addr: None,
                password: "your_password_here".to_string(),
                method: "aes-256-gcm".to_string(),
                enabled: true,
                timeout: Some(300),
            }),
        );

        // 添加默认的VMess实例
        instances.insert(
            "vmess-main".to_string(),
            ProtocolInstanceConfig::VMess(VmessInstanceConfig {
                name: "vmess-main".to_string(),
                listen_addr: "0.0.0.0:10086".to_string(),
                user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
                alter_id: 0,
                security: "aes-128-gcm".to_string(),
                server_addr: None,
                path: None,
                host: None,
                enabled: true,
            }),
        );

        Self {
            global: GlobalConfig {
                mode: "server".to_string(),
                timeout: 300,
                max_connections: 1024,
                buffer_size: 8192,
                enable_udp: true,
                enable_unified_port: false,
                unified_port: None,
            },
            instances,
            routes: Vec::new(),
            logging: LoggingConfig::default(),
        }
    }

    /// 创建默认的客户端配置
    pub fn default_client() -> Self {
        let mut instances = HashMap::new();
        
        // 添加默认的SOCKS5客户端实例
        instances.insert(
            "socks5-client".to_string(),
            ProtocolInstanceConfig::Socks5(Socks5InstanceConfig {
                name: "socks5-client".to_string(),
                listen_addr: "127.0.0.1:1080".to_string(),
                auth: false,
                username: None,
                password: None,
                enabled: true,
                allowed_ips: None,
            }),
        );

        Self {
            global: GlobalConfig {
                mode: "client".to_string(),
                timeout: 300,
                max_connections: 1024,
                buffer_size: 8192,
                enable_udp: true,
                enable_unified_port: false,
                unified_port: None,
            },
            instances,
            routes: Vec::new(),
            logging: LoggingConfig::default(),
        }
    }

    /// 生成配置模板
    pub fn generate_template() -> Self {
        let mut instances = HashMap::new();
        
        // Shadowsocks服务器配置
        instances.insert(
            "shadowsocks-server".to_string(),
            ProtocolInstanceConfig::Shadowsocks(ShadowsocksInstanceConfig {
                name: "shadowsocks-server".to_string(),
                listen_addr: "0.0.0.0:8388".to_string(),
                server_addr: None,
                password: "your_strong_password".to_string(),
                method: "aes-256-gcm".to_string(),
                enabled: true,
                timeout: Some(300),
            }),
        );

        // VMess服务器配置
        instances.insert(
            "vmess-server".to_string(),
            ProtocolInstanceConfig::VMess(VmessInstanceConfig {
                name: "vmess-server".to_string(),
                listen_addr: "0.0.0.0:10086".to_string(),
                user_id: "generate-a-new-uuid-here".to_string(),
                alter_id: 0,
                security: "aes-128-gcm".to_string(),
                server_addr: None,
                path: Some("/vmess".to_string()),
                host: Some("your-domain.com".to_string()),
                enabled: true,
            }),
        );

        // SOCKS5代理配置
        instances.insert(
            "socks5-proxy".to_string(),
            ProtocolInstanceConfig::Socks5(Socks5InstanceConfig {
                name: "socks5-proxy".to_string(),
                listen_addr: "127.0.0.1:1080".to_string(),
                auth: false,
                username: None,
                password: None,
                enabled: true,
                allowed_ips: None,
            }),
        );

        // HTTP代理配置
        instances.insert(
            "http-proxy".to_string(),
            ProtocolInstanceConfig::Http(HttpInstanceConfig {
                name: "http-proxy".to_string(),
                listen_addr: "127.0.0.1:8080".to_string(),
                auth: false,
                username: None,
                password: None,
                enabled: true,
                allowed_domains: None,
            }),
        );

        Self {
            global: GlobalConfig {
                mode: "server".to_string(),
                timeout: 300,
                max_connections: 1024,
                buffer_size: 8192,
                enable_udp: true,
                enable_unified_port: true,
                unified_port: Some(UnifiedPortConfig {
                    listen_addr: "0.0.0.0:443".to_string(),
                    detection_timeout: 1000,
                    auto_detect: true,
                    supported_protocols: vec![
                        "shadowsocks".to_string(),
                        "vmess".to_string(),
                        "socks5".to_string(),
                        "http".to_string(),
                    ],
                }),
            },
            instances,
            routes: vec![
                RouteConfig {
                    name: "local-direct".to_string(),
                    source: Some("127.0.0.1:*".to_string()),
                    target: None,
                    protocol: None,
                    target_instance: "socks5-proxy".to_string(),
                    priority: 100,
                },
            ],
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: Some("proxy.log".to_string()),
                console: true,
                format: LogFormat::Text,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MultiProtocolConfig::default();
        assert_eq!(config.global.mode, "server");
        assert!(config.instances.is_empty());
        assert!(config.routes.is_empty());
    }

    #[test]
    fn test_shadowsocks_config_validation() {
        let config = ProtocolInstanceConfig::Shadowsocks(ShadowsocksInstanceConfig {
            name: "test".to_string(),
            listen_addr: "127.0.0.1:8388".to_string(),
            server_addr: None,
            password: "test".to_string(),
            method: "aes-256-gcm".to_string(),
            enabled: true,
            timeout: Some(300),
        });

        assert!(config.validate().is_ok());

        let invalid_config = ProtocolInstanceConfig::Shadowsocks(ShadowsocksInstanceConfig {
            name: "test".to_string(),
            listen_addr: "invalid".to_string(),
            server_addr: None,
            password: "".to_string(),
            method: "aes-256-gcm".to_string(),
            enabled: true,
            timeout: Some(300),
        });

        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_vmess_config_validation() {
        let config = ProtocolInstanceConfig::VMess(VmessInstanceConfig {
            name: "test".to_string(),
            listen_addr: "127.0.0.1:10086".to_string(),
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "aes-128-gcm".to_string(),
            server_addr: None,
            path: None,
            host: None,
            enabled: true,
        });

        assert!(config.validate().is_ok());

        let invalid_config = ProtocolInstanceConfig::VMess(VmessInstanceConfig {
            name: "test".to_string(),
            listen_addr: "127.0.0.1:10086".to_string(),
            user_id: "invalid-uuid".to_string(),
            alter_id: 0,
            security: "aes-128-gcm".to_string(),
            server_addr: None,
            path: None,
            host: None,
            enabled: true,
        });

        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_multi_protocol_config_validation() {
        let mut config = MultiProtocolConfig::default();
        
        // 添加一个无效的实例
        config.instances.insert(
            "test".to_string(),
            ProtocolInstanceConfig::Shadowsocks(ShadowsocksInstanceConfig {
                name: "different-name".to_string(), // 名称不匹配
                listen_addr: "127.0.0.1:8388".to_string(),
                server_addr: None,
                password: "test".to_string(),
                method: "aes-256-gcm".to_string(),
                enabled: true,
                timeout: Some(300),
            }),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_template() {
        let template = MultiProtocolConfig::generate_template();
        assert!(template.instances.len() > 0);
        assert!(template.routes.len() > 0);
        assert_eq!(template.global.mode, "server");
    }
}