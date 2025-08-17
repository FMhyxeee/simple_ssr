//! 代理协议 trait 定义
//!
//! 定义所有代理协议必须实现的通用接口

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

/// 协议类型枚举
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum ProtocolType {
    Shadowsocks,
    VMess,
    SOCKS5,
    HTTP,
    HTTPS,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Shadowsocks => write!(f, "shadowsocks"),
            ProtocolType::VMess => write!(f, "vmess"),
            ProtocolType::SOCKS5 => write!(f, "socks5"),
            ProtocolType::HTTP => write!(f, "http"),
            ProtocolType::HTTPS => write!(f, "https"),
        }
    }
}

impl std::str::FromStr for ProtocolType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "shadowsocks" | "ss" => Ok(ProtocolType::Shadowsocks),
            "vmess" | "vm" => Ok(ProtocolType::VMess),
            "socks5" | "socks" => Ok(ProtocolType::SOCKS5),
            "http" => Ok(ProtocolType::HTTP),
            "https" => Ok(ProtocolType::HTTPS),
            _ => Err(format!("Unknown protocol type: {}", s)),
        }
    }
}

/// 协议配置 trait
pub trait ProtocolConfig: Send + Sync {
    /// 协议类型
    fn protocol_type(&self) -> ProtocolType;
    
    /// 验证配置
    fn validate(&self) -> Result<()>;
    
    /// 获取监听地址
    fn listen_address(&self) -> Result<SocketAddr>;
    
    /// 转换为Any trait对象，用于向下转型
    fn as_any(&self) -> &dyn std::any::Any;
    
    /// 转换为可变的Any trait对象，用于向下转型
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
    
    /// 克隆配置
    fn clone_config(&self) -> Box<dyn ProtocolConfig>;
}


/// 用于AsyncRead + AsyncWrite的trait alias
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// Box化的AsyncRead + AsyncWrite类型
pub type BoxAsyncRead = Box<dyn AsyncReadWrite + 'static>;

/// 协议处理器 trait
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// 创建新的协议处理器
    fn new(config: Box<dyn ProtocolConfig>) -> Result<Self>
    where
        Self: Sized;

    /// 启动服务器
    async fn start_server(&mut self, listener: TcpListener) -> Result<()>;

    /// 处理入站连接
    async fn handle_inbound(
        &self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<()>;

    /// 停止服务器
    async fn stop_server(&mut self) -> Result<()>;
}

/// 协议客户端 trait
#[async_trait]
pub trait ProtocolClient: Send + Sync {
    /// 创建新的协议客户端
    fn new(config: Box<dyn ProtocolConfig>) -> Result<Self>
    where
        Self: Sized;

    /// 连接到远程服务器
    async fn connect(
        &self,
        target_addr: SocketAddr,
    ) -> Result<BoxAsyncRead>;

    /// 处理出站连接
    async fn handle_outbound(
        &self,
        stream: BoxAsyncRead,
        target_addr: SocketAddr,
    ) -> Result<()>;
}

/// 协议工厂 trait
/// 用于动态创建协议处理器和客户端
pub trait ProtocolFactory: Send + Sync {
    /// 协议类型
    fn protocol_type(&self) -> ProtocolType;

    /// 创建协议处理器
    fn create_server(
        &self,
        config: Box<dyn ProtocolConfig>,
    ) -> Result<Box<dyn ProtocolHandler>>;

    /// 创建协议客户端
    fn create_client(
        &self,
        config: Box<dyn ProtocolConfig>,
    ) -> Result<Box<dyn ProtocolClient>>;

    /// 解析协议特定配置
    fn parse_config(&self, config: &toml::Value) -> Result<Box<dyn ProtocolConfig>>;
}

/// 协议注册表
/// 管理所有可用的协议类型
pub struct ProtocolRegistry {
    factories: std::collections::HashMap<ProtocolType, Box<dyn ProtocolFactory>>,
}

impl ProtocolRegistry {
    /// 创建新的协议注册表
    pub fn new() -> Self {
        Self {
            factories: std::collections::HashMap::new(),
        }
    }

    /// 注册协议工厂
    pub fn register(&mut self, factory: Box<dyn ProtocolFactory>) {
        let protocol_type = factory.protocol_type();
        self.factories.insert(protocol_type, factory);
    }

    /// 获取协议工厂
    pub fn get_factory(&self, protocol_type: &ProtocolType) -> Option<&dyn ProtocolFactory> {
        self.factories.get(protocol_type).map(|f| f.as_ref())
    }

    /// 获取所有注册的协议类型
    pub fn registered_protocols(&self) -> Vec<ProtocolType> {
        self.factories.keys().cloned().collect()
    }

    /// 检查协议是否支持
    pub fn is_protocol_supported(&self, protocol_type: &ProtocolType) -> bool {
        self.factories.contains_key(protocol_type)
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 通用代理配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyConfig {
    /// 协议类型
    pub protocol: ProtocolType,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// 目标地址（用于出站连接）
    pub target_addr: Option<String>,
    
    /// 启用状态
    pub enabled: bool,
    
    /// 协议特定配置
    pub protocol_config: Option<toml::Value>,
}

impl ProtocolConfig for ProxyConfig {
    fn protocol_type(&self) -> ProtocolType {
        self.protocol.clone()
    }

    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // 验证监听地址
        self.listen_address()?;

        // 如果有目标地址，也验证一下
        if let Some(target) = &self.target_addr {
            target.parse::<SocketAddr>().map_err(|e| {
                anyhow::anyhow!("Invalid target address {}: {}", target, e)
            })?;
        }

        Ok(())
    }

    fn listen_address(&self) -> Result<SocketAddr> {
        self.listen_addr.parse::<SocketAddr>().map_err(|e| {
            anyhow::anyhow!("Invalid listen address {}: {}", self.listen_addr, e)
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn clone_config(&self) -> Box<dyn ProtocolConfig> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_protocol_type_from_str() {
        assert_eq!(ProtocolType::from_str("shadowsocks").unwrap(), ProtocolType::Shadowsocks);
        assert_eq!(ProtocolType::from_str("ss").unwrap(), ProtocolType::Shadowsocks);
        assert_eq!(ProtocolType::from_str("vmess").unwrap(), ProtocolType::VMess);
        assert_eq!(ProtocolType::from_str("vm").unwrap(), ProtocolType::VMess);
        assert_eq!(ProtocolType::from_str("socks5").unwrap(), ProtocolType::SOCKS5);
        assert_eq!(ProtocolType::from_str("http").unwrap(), ProtocolType::HTTP);
        assert_eq!(ProtocolType::from_str("https").unwrap(), ProtocolType::HTTPS);
        assert!(ProtocolType::from_str("unknown").is_err());
    }

    #[test]
    fn test_protocol_type_display() {
        assert_eq!(ProtocolType::Shadowsocks.to_string(), "shadowsocks");
        assert_eq!(ProtocolType::VMess.to_string(), "vmess");
        assert_eq!(ProtocolType::SOCKS5.to_string(), "socks5");
        assert_eq!(ProtocolType::HTTP.to_string(), "http");
        assert_eq!(ProtocolType::HTTPS.to_string(), "https");
    }

    #[test]
    fn test_proxy_config_validation() {
        let config = ProxyConfig {
            protocol: ProtocolType::Shadowsocks,
            listen_addr: "127.0.0.1:8388".to_string(),
            target_addr: Some("127.0.0.1:80".to_string()),
            enabled: true,
            protocol_config: None,
        };

        assert!(config.validate().is_ok());

        let invalid_config = ProxyConfig {
            protocol: ProtocolType::Shadowsocks,
            listen_addr: "invalid_address".to_string(),
            target_addr: None,
            enabled: true,
            protocol_config: None,
        };

        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_protocol_registry() {
        let mut registry = ProtocolRegistry::new();
        assert_eq!(registry.registered_protocols().len(), 0);
        
        // 检查空注册表
        assert!(!registry.is_protocol_supported(&ProtocolType::Shadowsocks));
        assert!(registry.get_factory(&ProtocolType::Shadowsocks).is_none());
    }
}