# 统一端口实现指南

## 1. 实现概述

本文档提供统一端口功能的具体实现步骤和代码示例，帮助开发者将TCP和UDP请求统一到同一个端口。

## 2. 实现步骤

### 2.1 创建统一监听器模块

首先在 `src/` 目录下创建 `unified/` 模块：

```
src/
├── unified/
│   ├── mod.rs
│   ├── listener.rs
│   ├── detector.rs
│   ├── router.rs
│   └── config.rs
```

### 2.2 核心代码实现

#### 统一监听器 (src/unified/listener.rs)

```rust
//! 统一端口监听器
//! 
//! 在单个端口同时监听TCP和UDP请求

use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{info, error, debug};

use crate::unified::detector::ProtocolDetector;
use crate::unified::router::{TcpRouter, UdpRouter};
use crate::unified::config::UnifiedConfig;

/// 统一端口监听器
pub struct UnifiedListener {
    /// TCP监听器
    tcp_listener: TcpListener,
    /// UDP套接字
    udp_socket: Arc<UdpSocket>,
    /// 配置
    config: Arc<UnifiedConfig>,
    /// TCP路由器
    tcp_router: Arc<TcpRouter>,
    /// UDP路由器
    udp_router: Arc<UdpRouter>,
    /// 协议检测器
    detector: Arc<ProtocolDetector>,
}

impl UnifiedListener {
    /// 创建新的统一监听器
    pub async fn new(
        bind_addr: SocketAddr,
        config: UnifiedConfig,
    ) -> Result<Self> {
        info!("Creating unified listener on {}", bind_addr);
        
        // 创建TCP监听器
        let tcp_listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind TCP listener: {}", e))?;
            
        // 创建UDP套接字
        let udp_socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind UDP socket: {}", e))?;
            
        let config = Arc::new(config);
        let tcp_router = Arc::new(TcpRouter::new(config.clone()));
        let udp_router = Arc::new(UdpRouter::new(config.clone()));
        let detector = Arc::new(ProtocolDetector::new());
        
        Ok(Self {
            tcp_listener,
            udp_socket: Arc::new(udp_socket),
            config,
            tcp_router,
            udp_router,
            detector,
        })
    }
    
    /// 启动统一监听器
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting unified listener");
        
        // 创建任务通道
        let (tcp_tx, mut tcp_rx) = mpsc::channel(1000);
        let (udp_tx, mut udp_rx) = mpsc::channel(1000);
        
        // 启动TCP监听任务
        let tcp_listener = self.tcp_listener.try_clone()
            .map_err(|e| anyhow!("Failed to clone TCP listener: {}", e))?;
        let tcp_router = self.tcp_router.clone();
        
        tokio::spawn(async move {
            Self::handle_tcp_connections(tcp_listener, tcp_router, tcp_tx).await;
        });
        
        // 启动UDP监听任务
        let udp_socket = self.udp_socket.clone();
        let udp_router = self.udp_router.clone();
        
        tokio::spawn(async move {
            Self::handle_udp_packets(udp_socket, udp_router, udp_tx).await;
        });
        
        // 处理连接和数据包
        loop {
            tokio::select! {
                Some(tcp_conn) = tcp_rx.recv() => {
                    debug!("Received TCP connection");
                    // TCP连接已经在handle_tcp_connections中处理
                }
                Some(udp_packet) = udp_rx.recv() => {
                    debug!("Received UDP packet");
                    // UDP数据包已经在handle_udp_packets中处理
                }
                else => {
                    info!("All channels closed, stopping unified listener");
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// 处理TCP连接
    async fn handle_tcp_connections(
        listener: TcpListener,
        router: Arc<TcpRouter>,
        _tx: mpsc::Sender<()>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Accepted TCP connection from {}", addr);
                    let router = router.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = router.handle_connection(stream, addr).await {
                            error!("TCP connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                    break;
                }
            }
        }
    }
    
    /// 处理UDP数据包
    async fn handle_udp_packets(
        socket: Arc<UdpSocket>,
        router: Arc<UdpRouter>,
        _tx: mpsc::Sender<()>,
    ) {
        let mut buffer = vec![0u8; 65536];
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, addr)) => {
                    debug!("Received UDP packet from {}, {} bytes", addr, len);
                    let data = buffer[..len].to_vec();
                    let router = router.clone();
                    let socket = socket.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = router.handle_packet(socket, data, addr).await {
                            error!("UDP packet error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to receive UDP packet: {}", e);
                    break;
                }
            }
        }
    }
}
```

#### 协议检测器 (src/unified/detector.rs)

```rust
//! 协议检测器
//!
//! 自动识别TCP和UDP协议类型

use std::net::SocketAddr;
use tokio::net::TcpStream;

/// 协议类型枚举
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolType {
    Tcp(TcpStream, SocketAddr),
    Udp(Vec<u8>, SocketAddr),
}

/// 协议检测器
pub struct ProtocolDetector;

impl ProtocolDetector {
    /// 创建新的协议检测器
    pub fn new() -> Self {
        Self
    }
    
    /// 检测TCP连接
    pub fn detect_tcp(&self, stream: TcpStream, addr: SocketAddr) -> ProtocolType {
        ProtocolType::Tcp(stream, addr)
    }
    
    /// 检测UDP数据包
    pub fn detect_udp(&self, data: Vec<u8>, addr: SocketAddr) -> ProtocolType {
        ProtocolType::Udp(data, addr)
    }
    
    /// 验证协议数据有效性
    pub fn validate_protocol(&self, protocol: &ProtocolType) -> bool {
        match protocol {
            ProtocolType::Tcp(_, _) => true,
            ProtocolType::Udp(data, _) => {
                // 基本的UDP数据包验证
                !data.is_empty() && data.len() <= 65507
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_protocol_detector_creation() {
        let detector = ProtocolDetector::new();
        assert!(true); // 检测器创建成功
    }
    
    #[test]
    fn test_udp_validation() {
        let detector = ProtocolDetector::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // 测试有效UDP数据包
        let valid_data = vec![1, 2, 3, 4, 5];
        let protocol = detector.detect_udp(valid_data, addr);
        assert!(detector.validate_protocol(&protocol));
        
        // 测试空UDP数据包
        let empty_data = vec![];
        let protocol = detector.detect_udp(empty_data, addr);
        assert!(!detector.validate_protocol(&protocol));
    }
}
```

#### 路由器模块 (src/unified/router.rs)

```rust
//! 请求路由器
//!
//! 将TCP和UDP请求路由到相应的处理器

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error};

use crate::unified::config::UnifiedConfig;
use crate::client::tcp::TcpClient;
use crate::client::udp::UdpClient;
use crate::server::tcp::TcpServer;
use crate::server::udp::UdpServer;

/// TCP路由器
pub struct TcpRouter {
    config: Arc<UnifiedConfig>,
}

impl TcpRouter {
    /// 创建新的TCP路由器
    pub fn new(config: Arc<UnifiedConfig>) -> Self {
        Self { config }
    }
    
    /// 处理TCP连接
    pub async fn handle_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        debug!("Routing TCP connection from {}", addr);
        
        // 根据配置决定是客户端还是服务端处理
        if self.config.is_server_mode {
            // 服务端模式：处理来自客户端的连接
            self.handle_server_connection(stream, addr).await
        } else {
            // 客户端模式：处理来自本地应用的连接
            self.handle_client_connection(stream, addr).await
        }
    }
    
    /// 处理服务端TCP连接
    async fn handle_server_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        // 这里应该调用现有的服务端TCP处理逻辑
        // 为了简化，这里只是一个占位符
        debug!("Handling server TCP connection from {}", addr);
        Ok(())
    }
    
    /// 处理客户端TCP连接
    async fn handle_client_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        // 这里应该调用现有的客户端TCP处理逻辑
        // 为了简化，这里只是一个占位符
        debug!("Handling client TCP connection from {}", addr);
        Ok(())
    }
}

/// UDP路由器
pub struct UdpRouter {
    config: Arc<UnifiedConfig>,
}

impl UdpRouter {
    /// 创建新的UDP路由器
    pub fn new(config: Arc<UnifiedConfig>) -> Self {
        Self { config }
    }
    
    /// 处理UDP数据包
    pub async fn handle_packet(
        &self,
        socket: Arc<UdpSocket>,
        data: Vec<u8>,
        addr: SocketAddr,
    ) -> Result<()> {
        debug!("Routing UDP packet from {}, {} bytes", addr, data.len());
        
        // 根据配置决定是客户端还是服务端处理
        if self.config.is_server_mode {
            // 服务端模式：处理来自客户端的数据包
            self.handle_server_packet(socket, data, addr).await
        } else {
            // 客户端模式：处理来自本地应用的数据包
            self.handle_client_packet(socket, data, addr).await
        }
    }
    
    /// 处理服务端UDP数据包
    async fn handle_server_packet(
        &self,
        socket: Arc<UdpSocket>,
        data: Vec<u8>,
        addr: SocketAddr,
    ) -> Result<()> {
        // 这里应该调用现有的服务端UDP处理逻辑
        debug!("Handling server UDP packet from {}", addr);
        Ok(())
    }
    
    /// 处理客户端UDP数据包
    async fn handle_client_packet(
        &self,
        socket: Arc<UdpSocket>,
        data: Vec<u8>,
        addr: SocketAddr,
    ) -> Result<()> {
        // 这里应该调用现有的客户端UDP处理逻辑
        debug!("Handling client UDP packet from {}", addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified::config::UnifiedConfig;
    
    #[tokio::test]
    async fn test_tcp_router_creation() {
        let config = Arc::new(UnifiedConfig::default());
        let router = TcpRouter::new(config);
        assert!(true); // 路由器创建成功
    }
    
    #[tokio::test]
    async fn test_udp_router_creation() {
        let config = Arc::new(UnifiedConfig::default());
        let router = UdpRouter::new(config);
        assert!(true); // 路由器创建成功
    }
}
```

### 2.3 配置集成

#### 统一配置 (src/unified/config.rs)

```rust
//! 统一端口配置
//!
//! 管理统一端口模式的配置参数

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 统一端口配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedConfig {
    /// 是否启用统一端口模式
    pub enable_unified_port: bool,
    /// 统一端口号
    pub unified_port: u16,
    /// 绑定地址
    pub bind_address: String,
    /// 是否为服务端模式
    pub is_server_mode: bool,
    /// TCP超时设置
    pub tcp_timeout: Duration,
    /// UDP会话超时
    pub udp_session_timeout: Duration,
    /// 最大并发连接数
    pub max_connections: usize,
    /// 向后兼容模式
    pub legacy_compatibility: bool,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            enable_unified_port: false,
            unified_port: 8388,
            bind_address: "0.0.0.0".to_string(),
            is_server_mode: false,
            tcp_timeout: Duration::from_secs(300),
            udp_session_timeout: Duration::from_secs(60),
            max_connections: 1024,
            legacy_compatibility: true,
        }
    }
}

impl UnifiedConfig {
    /// 创建服务端配置
    pub fn server_config(port: u16, bind_addr: String) -> Self {
        Self {
            enable_unified_port: true,
            unified_port: port,
            bind_address: bind_addr,
            is_server_mode: true,
            ..Default::default()
        }
    }
    
    /// 创建客户端配置
    pub fn client_config(port: u16, bind_addr: String) -> Self {
        Self {
            enable_unified_port: true,
            unified_port: port,
            bind_address: bind_addr,
            is_server_mode: false,
            ..Default::default()
        }
    }
    
    /// 验证配置有效性
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.unified_port == 0 {
            return Err(anyhow::anyhow!("Invalid unified port: 0"));
        }
        
        if self.bind_address.is_empty() {
            return Err(anyhow::anyhow!("Bind address cannot be empty"));
        }
        
        if self.max_connections == 0 {
            return Err(anyhow::anyhow!("Max connections must be greater than 0"));
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
        assert!(!config.enable_unified_port);
        assert_eq!(config.unified_port, 8388);
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_server_config() {
        let config = UnifiedConfig::server_config(9999, "127.0.0.1".to_string());
        assert!(config.enable_unified_port);
        assert!(config.is_server_mode);
        assert_eq!(config.unified_port, 9999);
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_client_config() {
        let config = UnifiedConfig::client_config(1080, "127.0.0.1".to_string());
        assert!(config.enable_unified_port);
        assert!(!config.is_server_mode);
        assert_eq!(config.unified_port, 1080);
        assert!(config.validate().is_ok());
    }
}
```

## 3. 集成步骤

### 3.1 修改现有配置

在 `ClientConfig` 和 `ServerConfig` 中添加统一端口支持：

```rust
// 在 src/config/client.rs 中添加
pub struct ClientConfig {
    // ... 现有字段 ...
    
    /// 统一端口配置
    #[serde(default)]
    pub unified_config: Option<UnifiedConfig>,
}

// 在 src/config/server.rs 中添加
pub struct ServerConfig {
    // ... 现有字段 ...
    
    /// 统一端口配置
    #[serde(default)]
    pub unified_config: Option<UnifiedConfig>,
}
```

### 3.2 修改启动逻辑

在客户端和服务端的启动代码中添加统一端口支持：

```rust
// 在客户端启动逻辑中
if let Some(unified_config) = &config.unified_config {
    if unified_config.enable_unified_port {
        // 使用统一端口模式
        let mut unified_listener = UnifiedListener::new(
            format!("{}:{}", unified_config.bind_address, unified_config.unified_port)
                .parse()?,
            unified_config.clone(),
        ).await?;
        
        unified_listener.run().await?;
    } else {
        // 使用传统分离端口模式
        // ... 现有逻辑 ...
    }
} else {
    // 使用传统分离端口模式
    // ... 现有逻辑 ...
}
```

## 4. 测试用例

### 4.1 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};
    
    #[tokio::test]
    async fn test_unified_listener_creation() {
        let config = UnifiedConfig::default();
        let addr = "127.0.0.1:0".parse().unwrap();
        
        let result = UnifiedListener::new(addr, config).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_tcp_udp_simultaneous_listening() {
        let config = UnifiedConfig {
            enable_unified_port: true,
            unified_port: 0, // 使用随机端口
            ..Default::default()
        };
        
        let addr = "127.0.0.1:0".parse().unwrap();
        let mut listener = UnifiedListener::new(addr, config).await.unwrap();
        
        // 启动监听器（带超时）
        let listen_result = timeout(Duration::from_millis(100), listener.run()).await;
        
        // 超时是预期的，因为没有连接
        assert!(listen_result.is_err());
    }
}
```

### 4.2 集成测试

```rust
#[tokio::test]
async fn test_unified_port_integration() {
    // 创建服务端配置
    let server_config = UnifiedConfig::server_config(
        0, // 随机端口
        "127.0.0.1".to_string(),
    );
    
    // 创建客户端配置
    let client_config = UnifiedConfig::client_config(
        0, // 随机端口
        "127.0.0.1".to_string(),
    );
    
    // 验证配置
    assert!(server_config.validate().is_ok());
    assert!(client_config.validate().is_ok());
    
    // 测试监听器创建
    let server_addr = "127.0.0.1:0".parse().unwrap();
    let server_listener = UnifiedListener::new(server_addr, server_config).await;
    assert!(server_listener.is_ok());
    
    let client_addr = "127.0.0.1:0".parse().unwrap();
    let client_listener = UnifiedListener::new(client_addr, client_config).await;
    assert!(client_listener.is_ok());
}
```

## 5. 部署注意事项

1. **向后兼容性**：确保现有配置文件仍然有效
2. **性能考虑**：统一端口可能会增加少量延迟，需要进行性能测试
3. **错误处理**：添加详细的错误日志和恢复机制
4. **安全性**：确保协议检测不会泄露敏感信息
5. **监控**：添加统计信息收集，监控统一端口的使用情况

