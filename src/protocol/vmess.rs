//! VMess协议实现
//!
//! 实现VMess协议的客户端和服务端逻辑

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::protocol::traits::{ProtocolClient, ProtocolConfig, ProtocolFactory, ProtocolHandler};
use crate::protocol::traits::BoxAsyncRead;
use crate::protocol::address::Address;

// type HmacSha256 = Hmac<Sha256>;

/// VMess协议版本
pub const VMESS_VERSION: u8 = 1;

/// VMess安全配置
#[derive(Debug, Clone)]
pub struct VmessSecurity {
    /// 用户ID
    pub user_id: Uuid,
    
    /// 额外ID（用于多用户）
    pub alter_id: u16,
    
    /// 安全类型
    pub security: SecurityType,
}

/// VMess安全类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityType {
    /// AES-128-GCM
    Aes128Gcm,
    
    /// AES-256-GCM
    Aes256Gcm,
    
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    
    /// 无加密
    None,
}

impl std::str::FromStr for SecurityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(SecurityType::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(SecurityType::Aes256Gcm),
            "chacha20-poly1305" | "aead_chacha20_poly1305" => Ok(SecurityType::ChaCha20Poly1305),
            "none" | "plain" => Ok(SecurityType::None),
            _ => Err(format!("Unknown security type: {}", s)),
        }
    }
}

/// VMess配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VmessConfig {
    /// 监听地址
    pub listen_addr: String,
    
    /// 用户ID
    pub user_id: String,
    
    /// 额外ID
    #[serde(default = "default_alter_id")]
    pub alter_id: u16,
    
    /// 安全类型
    #[serde(default = "default_security")]
    pub security: String,
    
    /// 启用状态
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_alter_id() -> u16 {
    0
}

fn default_security() -> String {
    "aes-128-gcm".to_string()
}

fn default_enabled() -> bool {
    true
}

impl ProtocolConfig for VmessConfig {
    fn protocol_type(&self) -> crate::protocol::traits::ProtocolType {
        crate::protocol::traits::ProtocolType::VMess
    }

    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // 验证监听地址
        self.listen_address()?;

        // 验证用户ID
        self.user_id.parse::<Uuid>().map_err(|e| {
            anyhow::anyhow!("Invalid user ID {}: {}", self.user_id, e)
        })?;

        // 验证安全类型
        self.security.parse::<SecurityType>().map_err(|e| {
            anyhow::anyhow!("Invalid security type {}: {}", self.security, e)
        })?;

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

/// VMess请求头
#[derive(Debug, Clone)]
pub struct VmessRequest {
    /// 版本
    pub version: u8,
    
    /// 请求ID
    pub request_id: u64,
    
    /// 安全类型
    pub security: SecurityType,
    
    /// 命令类型
    pub command: CommandType,
    
    /// 目标地址
    pub address: Address,
    
    /// 时间戳
    pub timestamp: u64,
}

/// VMess命令类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandType {
    /// TCP连接
    Tcp,
    
    /// UDP连接
    Udp,
    
    /// Mux连接
    Mux,
}

/// VMess响应头
#[derive(Debug, Clone)]
pub struct VmessResponse {
    /// 版本
    pub version: u8,
    
    /// 响应ID
    pub response_id: u64,
    
    /// 选项
    pub options: u8,
}

/// VMess协议处理器
pub struct VmessHandler {
    config: VmessConfig,
    security: VmessSecurity,
    #[allow(dead_code)]
    connections: HashMap<u64, TcpStream>,
}

impl VmessHandler {
    /// 创建新的VMess处理器
    pub fn new(config: VmessConfig) -> Result<Self> {
        let user_id = config.user_id.parse::<Uuid>()?;
        let security_type = config.security.parse::<SecurityType>().map_err(|e| anyhow::anyhow!("Invalid security type: {}", e))?;
        
        let security = VmessSecurity {
            user_id,
            alter_id: config.alter_id,
            security: security_type,
        };

        Ok(Self {
            config,
            security,
            connections: HashMap::new(),
        })
    }

    /// 生成请求ID
    #[allow(dead_code)]
    fn generate_request_id(&self) -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 使用时间戳和随机数生成请求ID
        let random = rand::random::<u32>() as u64;
        (timestamp << 32) | random
    }

    /// 验证请求头
    fn validate_request(&self, request: &VmessRequest) -> Result<()> {
        // 验证版本
        if request.version != VMESS_VERSION {
            return Err(anyhow!("Unsupported VMess version: {}", request.version));
        }

        // 验证时间戳（允许5分钟的误差）
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if current_time.abs_diff(request.timestamp) > 300 {
            return Err(anyhow!("Timestamp validation failed"));
        }

        // TODO: 实现更复杂的验证逻辑
        // 包括HMAC验证、用户ID验证等

        Ok(())
    }

    /// 生成认证信息
    #[allow(dead_code)]
    fn generate_auth(&self, request_id: u64, timestamp: u64) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.security.user_id.as_bytes()).unwrap();
        mac.update(&request_id.to_be_bytes());
        mac.update(&timestamp.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// 解析VMess请求
    async fn parse_request(&self, stream: &mut TcpStream) -> Result<VmessRequest> {
        // 读取版本
        let version = stream.read_u8().await?;
        
        // 读取请求ID
        let request_id = stream.read_u64().await?;
        
        // 读取时间戳
        let timestamp = stream.read_u64().await?;
        
        // 读取安全类型
        let security_type_byte = stream.read_u8().await?;
        let security = match security_type_byte {
            0 => SecurityType::None,
            1 => SecurityType::Aes128Gcm,
            2 => SecurityType::Aes256Gcm,
            3 => SecurityType::ChaCha20Poly1305,
            _ => return Err(anyhow!("Unknown security type: {}", security_type_byte)),
        };
        
        // 读取命令类型
        let command_byte = stream.read_u8().await?;
        let command = match command_byte {
            1 => CommandType::Tcp,
            2 => CommandType::Udp,
            3 => CommandType::Mux,
            _ => return Err(anyhow!("Unknown command type: {}", command_byte)),
        };
        
        // 读取地址
        let address = self.read_address(stream).await?;
        
        let request = VmessRequest {
            version,
            request_id,
            security,
            command,
            address,
            timestamp,
        };
        
        // 验证请求
        self.validate_request(&request)?;
        
        Ok(request)
    }

    /// 读取地址
    async fn read_address(&self, stream: &mut TcpStream) -> Result<Address> {
        let addr_type = stream.read_u8().await?;
        
        match addr_type {
            1 => {
                // IPv4
                let mut addr_bytes = [0u8; 4];
                stream.read_exact(&mut addr_bytes).await?;
                let port = stream.read_u16().await?;
                Ok(Address::SocketAddr(SocketAddr::from((std::net::Ipv4Addr::from(addr_bytes), port))))
            }
            2 => {
                // 域名
                let domain_len = stream.read_u8().await? as usize;
                let mut domain_bytes = vec![0u8; domain_len];
                stream.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8(domain_bytes)?;
                let port = stream.read_u16().await?;
                Ok(Address::DomainNameAddr(domain, port))
            }
            3 => {
                // IPv6
                let mut addr_bytes = [0u8; 16];
                stream.read_exact(&mut addr_bytes).await?;
                let port = stream.read_u16().await?;
                Ok(Address::SocketAddr(SocketAddr::from((std::net::Ipv6Addr::from(addr_bytes), port))))
            }
            _ => Err(anyhow!("Unknown address type: {}", addr_type)),
        }
    }

    /// 写入地址
    #[allow(dead_code)]
    async fn write_address(&self, stream: &mut TcpStream, address: &Address) -> Result<()> {
        match address {
            Address::SocketAddr(addr) => {
                match addr.ip() {
                    IpAddr::V4(ipv4) => {
                        stream.write_u8(1).await?;
                        stream.write_all(&ipv4.octets()).await?;
                        stream.write_u16(addr.port()).await?;
                    }
                    IpAddr::V6(ipv6) => {
                        stream.write_u8(3).await?;
                        stream.write_all(&ipv6.octets()).await?;
                        stream.write_u16(addr.port()).await?;
                    }
                }
            }
            Address::DomainNameAddr(domain, port) => {
                stream.write_u8(2).await?;
                stream.write_u8(domain.len() as u8).await?;
                stream.write_all(domain.as_bytes()).await?;
                stream.write_u16(*port).await?;
            }
        }
        Ok(())
    }

    /// 处理TCP连接
    async fn handle_tcp_connection(
        &self,
        client_stream: TcpStream,
        target_address: Address,
    ) -> Result<()> {
        // 解析目标地址为SocketAddr
        let target_socket_addr = match target_address {
            Address::SocketAddr(addr) => addr,
            Address::DomainNameAddr(domain, port) => {
                // 解析域名
                let addr_str = format!("{}:{}", domain, port);
                use tokio::net::lookup_host;
                lookup_host(&addr_str).await?.next().ok_or_else(|| {
                    anyhow!("Failed to resolve domain: {}", domain)
                })?
            }
        };

        // 连接到目标服务器
        let target_stream = TcpStream::connect(target_socket_addr).await?;

        // 使用proxy_bidirectional进行双向转发
        let (mut client_reader, mut client_writer) = client_stream.into_split();
        let (mut target_reader, mut target_writer) = target_stream.into_split();

        let client_to_target = tokio::spawn(async move {
            tokio::io::copy(&mut client_reader, &mut target_writer).await
        });

        let target_to_client = tokio::spawn(async move {
            tokio::io::copy(&mut target_reader, &mut client_writer).await
        });

        // 等待任一方向完成
        tokio::select! {
            result = client_to_target => {
                if let Err(e) = result {
                    tracing::error!("Client to target copy error: {}", e);
                }
            }
            result = target_to_client => {
                if let Err(e) = result {
                    tracing::error!("Target to client copy error: {}", e);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl ProtocolHandler for VmessHandler {
    fn new(config: Box<dyn ProtocolConfig>) -> Result<Self>
    where
        Self: Sized,
    {
        // 向下转型获取VmessConfig
        let vmess_config = config.as_any()
            .downcast_ref::<VmessConfig>()
            .ok_or_else(|| anyhow!("Expected VmessConfig"))?;
        
        Self::new(vmess_config.clone())
    }

    async fn start_server(&mut self, listener: TcpListener) -> Result<()> {
        tracing::info!("VMess server started on {}", self.config.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_inbound(stream, addr).await {
                            tracing::error!("Error handling VMess connection from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_inbound(&self, mut stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        tracing::debug!("Received VMess connection from {}", client_addr);
        
        // 解析VMess请求
        let request = self.parse_request(&mut stream).await?;
        
        tracing::debug!("VMess request: {:?}", request);

        match request.command {
            CommandType::Tcp => {
                self.handle_tcp_connection(stream, request.address).await?;
            }
            CommandType::Udp => {
                tracing::warn!("UDP command not yet implemented");
            }
            CommandType::Mux => {
                tracing::warn!("Mux command not yet implemented");
            }
        }

        Ok(())
    }

    async fn stop_server(&mut self) -> Result<()> {
        tracing::info!("VMess server stopped");
        Ok(())
    }
}

/// VMess客户端
pub struct VmessClient {
    config: VmessConfig,
    security: VmessSecurity,
}

impl VmessClient {
    /// 创建新的VMess客户端
    pub fn new(config: VmessConfig) -> Result<Self> {
        let user_id = config.user_id.parse::<Uuid>()?;
        let security_type = config.security.parse::<SecurityType>().map_err(|e| anyhow::anyhow!("Invalid security type: {}", e))?;
        
        let security = VmessSecurity {
            user_id,
            alter_id: config.alter_id,
            security: security_type,
        };

        Ok(Self {
            config,
            security,
        })
    }

    /// 创建VMess请求
    fn create_request(&self, target_address: Address) -> VmessRequest {
        VmessRequest {
            version: VMESS_VERSION,
            request_id: self.generate_request_id(),
            security: self.security.security.clone(),
            command: CommandType::Tcp,
            address: target_address,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// 生成请求ID
    fn generate_request_id(&self) -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let random = rand::random::<u32>() as u64;
        (timestamp << 32) | random
    }

    /// 发送VMess请求
    async fn send_request(&self, stream: &mut TcpStream, request: &VmessRequest) -> Result<()> {
        // 写入版本
        stream.write_u8(request.version).await?;
        
        // 写入请求ID
        stream.write_u64(request.request_id).await?;
        
        // 写入时间戳
        stream.write_u64(request.timestamp).await?;
        
        // 写入安全类型
        let security_byte = match request.security {
            SecurityType::None => 0,
            SecurityType::Aes128Gcm => 1,
            SecurityType::Aes256Gcm => 2,
            SecurityType::ChaCha20Poly1305 => 3,
        };
        stream.write_u8(security_byte).await?;
        
        // 写入命令类型
        let command_byte = match request.command {
            CommandType::Tcp => 1,
            CommandType::Udp => 2,
            CommandType::Mux => 3,
        };
        stream.write_u8(command_byte).await?;
        
        // 写入地址
        self.write_address(stream, &request.address).await?;
        
        Ok(())
    }

    /// 写入地址
    #[allow(dead_code)]
    async fn write_address(&self, stream: &mut TcpStream, address: &Address) -> Result<()> {
        match address {
            Address::SocketAddr(addr) => {
                match addr.ip() {
                    IpAddr::V4(ipv4) => {
                        stream.write_u8(1).await?;
                        stream.write_all(&ipv4.octets()).await?;
                        stream.write_u16(addr.port()).await?;
                    }
                    IpAddr::V6(ipv6) => {
                        stream.write_u8(3).await?;
                        stream.write_all(&ipv6.octets()).await?;
                        stream.write_u16(addr.port()).await?;
                    }
                }
            }
            Address::DomainNameAddr(domain, port) => {
                stream.write_u8(2).await?;
                stream.write_u8(domain.len() as u8).await?;
                stream.write_all(domain.as_bytes()).await?;
                stream.write_u16(*port).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ProtocolClient for VmessClient {
    fn new(config: Box<dyn ProtocolConfig>) -> Result<Self>
    where
        Self: Sized,
    {
        // 向下转型获取VmessConfig
        let vmess_config = config.as_any()
            .downcast_ref::<VmessConfig>()
            .ok_or_else(|| anyhow!("Expected VmessConfig"))?;
        
        Self::new(vmess_config.clone())
    }

    async fn connect(
        &self,
        target_addr: SocketAddr,
    ) -> Result<BoxAsyncRead> {
        // 连接到VMess服务器
        let server_addr = self.config.listen_address()?;
        let mut stream = TcpStream::connect(server_addr).await?;

        // 创建目标地址
        let target_address = Address::from(target_addr);

        // 创建并发送VMess请求
        let request = self.create_request(target_address);
        self.send_request(&mut stream, &request).await?;

        Ok(Box::new(stream))
    }

    async fn handle_outbound(
        &self,
        stream: BoxAsyncRead,
        target_addr: SocketAddr,
    ) -> Result<()> {
        // 这里处理出站连接逻辑
        // 在实际实现中，这里应该处理与VMess服务器的通信
        tracing::debug!("Handling outbound connection to {}", target_addr);
        
        // 简化实现：直接转发数据
        // 实际VMess实现需要加密和数据封装
        let _stream = stream;
        
        // 这里应该实现完整的VMess协议通信
        // 包括握手、加密、数据传输等
        
        Ok(())
    }
}

/// VMess协议工厂
pub struct VmessFactory;

impl ProtocolFactory for VmessFactory {
    fn protocol_type(&self) -> crate::protocol::traits::ProtocolType {
        crate::protocol::traits::ProtocolType::VMess
    }

    fn create_server(
        &self,
        config: Box<dyn ProtocolConfig>,
    ) -> Result<Box<dyn ProtocolHandler>> {
        let vmess_config = config.as_any()
            .downcast_ref::<VmessConfig>()
            .ok_or_else(|| anyhow!("Invalid VMess config type"))?;
        
        let handler = VmessHandler::new(vmess_config.clone())?;
        Ok(Box::new(handler))
    }

    fn create_client(
        &self,
        config: Box<dyn ProtocolConfig>,
    ) -> Result<Box<dyn ProtocolClient>> {
        let vmess_config = config.as_any()
            .downcast_ref::<VmessConfig>()
            .ok_or_else(|| anyhow!("Invalid VMess config type"))?;
        
        let client = VmessClient::new(vmess_config.clone())?;
        Ok(Box::new(client))
    }

    fn parse_config(&self, config: &toml::Value) -> Result<Box<dyn ProtocolConfig>> {
        let vmess_config: VmessConfig = config.clone().try_into()
            .map_err(|e| anyhow!("Failed to parse VMess config: {}", e))?;
        
        Ok(Box::new(vmess_config))
    }
}

impl Clone for VmessHandler {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            security: self.security.clone(),
            connections: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_security_type_from_str() {
        assert_eq!(SecurityType::from_str("aes-128-gcm").unwrap(), SecurityType::Aes128Gcm);
        assert_eq!(SecurityType::from_str("aes-256-gcm").unwrap(), SecurityType::Aes256Gcm);
        assert_eq!(SecurityType::from_str("chacha20-poly1305").unwrap(), SecurityType::ChaCha20Poly1305);
        assert_eq!(SecurityType::from_str("none").unwrap(), SecurityType::None);
        assert!(SecurityType::from_str("unknown").is_err());
    }

    #[test]
    fn test_vmess_config_validation() {
        let config = VmessConfig {
            listen_addr: "127.0.0.1:8388".to_string(),
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "aes-128-gcm".to_string(),
            enabled: true,
        };

        assert!(config.validate().is_ok());

        let invalid_config = VmessConfig {
            listen_addr: "invalid_address".to_string(),
            user_id: "invalid-uuid".to_string(),
            alter_id: 0,
            security: "unknown-security".to_string(),
            enabled: true,
        };

        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_vmess_request_creation() {
        let config = VmessConfig {
            listen_addr: "127.0.0.1:8388".to_string(),
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "aes-128-gcm".to_string(),
            enabled: true,
        };

        let client = VmessClient::new(config).unwrap();
        let target_address = Address::DomainNameAddr("example.com".to_string(), 443);
        let request = client.create_request(target_address);

        assert_eq!(request.version, VMESS_VERSION);
        assert_eq!(request.security, SecurityType::Aes128Gcm);
        assert_eq!(request.command, CommandType::Tcp);
    }

    #[tokio::test]
    async fn test_vmess_factory() {
        let factory = VmessFactory;
        assert_eq!(factory.protocol_type(), crate::protocol::traits::ProtocolType::VMess);
    }
}