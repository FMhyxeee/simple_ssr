//! Shadowsocks服务端模块
//!
//! 实现Shadowsocks服务端的核心功能，包括TCP和UDP代理

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::ServerConfig;
use crate::crypto::CryptoContext;
use crate::protocol::{Address, ShadowsocksProtocol};
use crate::utils::{copy_bidirectional_with_timeout, timeout_future};

pub mod tcp;
pub mod udp;

pub use tcp::TcpServer;
pub use udp::UdpServer;

/// 连接信息
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    client_addr: SocketAddr,
    start_time: Instant,
    last_activity: Instant,
}

/// 连接管理器，用于管理服务器连接
#[derive(Debug)]
pub struct ConnectionManager {
    max_connections: usize,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    start_time: Instant,
    connections: Arc<RwLock<HashMap<u64, ConnectionInfo>>>,
    connection_timeout: Duration,
}

/// 连接统计信息
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub active_connections: usize,
    pub total_connections: u64,
    pub uptime: u64,
}

impl ConnectionManager {
    /// 创建新的连接管理器
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            start_time: Instant::now(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            connection_timeout: Duration::from_secs(300), // 5分钟超时
        }
    }

    /// 检查是否可以接受新连接
    pub fn can_accept_connection(&self) -> bool {
        self.active_connections.load(Ordering::Relaxed) < self.max_connections
    }

    /// 注册新连接
    pub async fn register_connection(&self, client_addr: SocketAddr) -> Result<u64> {
        if !self.can_accept_connection() {
            return Err(anyhow!("Connection limit reached"));
        }

        self.active_connections.fetch_add(1, Ordering::SeqCst);
        let connection_id = self.total_connections.fetch_add(1, Ordering::SeqCst);

        // 记录连接信息
        let connection_info = ConnectionInfo {
            client_addr,
            start_time: Instant::now(),
            last_activity: Instant::now(),
        };

        let mut connections = self.connections.write().await;
        connections.insert(connection_id, connection_info);

        debug!(
            "Registered connection {} from {}",
            connection_id, client_addr
        );
        Ok(connection_id)
    }

    /// 注销连接
    pub async fn unregister_connection(&self, connection_id: u64) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);

        let mut connections = self.connections.write().await;
        if let Some(conn_info) = connections.remove(&connection_id) {
            let duration = conn_info.start_time.elapsed();
            debug!(
                "Unregistered connection {} from {}, duration: {:?}",
                connection_id, conn_info.client_addr, duration
            );
        }
    }

    /// 获取连接统计信息
    pub fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            uptime: self.start_time.elapsed().as_secs(),
        }
    }

    /// 运行清理任务
    pub async fn run_cleanup_task(&self) {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(300)); // 5分钟统计一次

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired_connections().await;
                }
                _ = stats_interval.tick() => {
                    self.log_statistics().await;
                }
            }
        }
    }

    /// 清理过期连接
    async fn cleanup_expired_connections(&self) {
        let now = Instant::now();
        let mut connections = self.connections.write().await;
        let mut expired_connections = Vec::new();

        // 查找过期连接
        for (&connection_id, connection_info) in connections.iter() {
            if now.duration_since(connection_info.last_activity) > self.connection_timeout {
                expired_connections.push(connection_id);
            }
        }

        // 移除过期连接
        for connection_id in expired_connections {
            if let Some(conn_info) = connections.remove(&connection_id) {
                self.active_connections.fetch_sub(1, Ordering::SeqCst);
                warn!(
                    "Cleaned up expired connection {} from {}, duration: {:?}",
                    connection_id,
                    conn_info.client_addr,
                    conn_info.start_time.elapsed()
                );
            }
        }

        debug!(
            "Connection cleanup completed, active connections: {}",
            self.active_connections.load(Ordering::Relaxed)
        );
    }

    /// 记录统计信息
    async fn log_statistics(&self) {
        let stats = self.get_stats();
        let connections = self.connections.read().await;

        info!(
            "Connection statistics - Active: {}, Total: {}, Uptime: {}s, Tracked: {}",
            stats.active_connections,
            stats.total_connections,
            stats.uptime,
            connections.len()
        );

        // 记录连接持续时间分布
        let mut durations: Vec<Duration> = connections
            .values()
            .map(|conn| conn.start_time.elapsed())
            .collect();

        if !durations.is_empty() {
            durations.sort();
            let median_idx = durations.len() / 2;
            let median_duration = durations[median_idx];
            let max_duration = durations.last().unwrap();

            debug!(
                "Connection duration stats - Median: {:?}, Max: {:?}",
                median_duration, max_duration
            );
        }
    }

    /// 更新连接活动时间
    pub async fn update_connection_activity(&self, connection_id: u64) {
        let mut connections = self.connections.write().await;
        if let Some(connection_info) = connections.get_mut(&connection_id) {
            connection_info.last_activity = Instant::now();
        }
    }

    /// 获取连接详细信息
    pub async fn get_connection_info(&self, connection_id: u64) -> Option<ConnectionInfo> {
        let connections = self.connections.read().await;
        connections.get(&connection_id).cloned()
    }

    /// 获取所有活跃连接
    pub async fn get_active_connections(&self) -> Vec<(u64, ConnectionInfo)> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .map(|(&id, info)| (id, info.clone()))
            .collect()
    }

    /// 停止连接管理器
    pub async fn stop(&self) -> Result<()> {
        info!("Connection manager stopped");
        Ok(())
    }
}

/// Shadowsocks服务端
pub struct ShadowsocksServer {
    config: Arc<ServerConfig>,
    tcp_server: Option<TcpServer>,
    udp_server: Option<UdpServer>,
    connection_manager: Arc<ConnectionManager>,
}

impl ShadowsocksServer {
    /// 创建新的Shadowsocks服务端
    pub fn new(config: ServerConfig) -> Result<Self> {
        let config = Arc::new(config);
        let connection_manager = Arc::new(ConnectionManager::new(config.max_connections));

        let tcp_server = Some(TcpServer::new(config.clone(), connection_manager.clone())?);
        let udp_server = if config.enable_udp {
            Some(UdpServer::new(config.clone(), connection_manager.clone())?)
        } else {
            None
        };

        Ok(Self {
            config,
            tcp_server,
            udp_server,
            connection_manager,
        })
    }

    /// 启动服务端
    pub async fn run(&mut self) -> Result<()> {
        info!(
            "Starting Shadowsocks server on {}",
            self.config.server_addr()?
        );
        info!("Encryption method: {}", self.config.method);
        info!("UDP enabled: {}", self.config.enable_udp);
        info!("Max connections: {}", self.config.max_connections);

        let mut handles = Vec::new();

        // 启动TCP服务器
        if let Some(ref mut tcp_server) = self.tcp_server {
            let tcp_handle = {
                let mut server = tcp_server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        error!("TCP server error: {}", e);
                    }
                })
            };
            handles.push(tcp_handle);
        }

        // 启动UDP服务器
        if let Some(ref mut udp_server) = self.udp_server {
            let udp_handle = {
                let mut server = udp_server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.run().await {
                        error!("UDP server error: {}", e);
                    }
                })
            };
            handles.push(udp_handle);
        }

        // 启动连接管理器
        let manager_handle = {
            let manager = self.connection_manager.clone();
            tokio::spawn(async move {
                manager.run_cleanup_task().await;
            })
        };
        handles.push(manager_handle);

        // 等待所有任务完成
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Task error: {}", e);
            }
        }

        Ok(())
    }

    /// 停止服务端
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Shadowsocks server...");

        if let Some(ref mut tcp_server) = self.tcp_server {
            tcp_server.stop().await?;
        }

        if let Some(ref mut udp_server) = self.udp_server {
            udp_server.stop().await?;
        }

        self.connection_manager.stop().await?;

        info!("Shadowsocks server stopped");
        Ok(())
    }

    /// 获取服务器统计信息
    pub fn get_stats(&self) -> ServerStats {
        let tcp_stats = self
            .tcp_server
            .as_ref()
            .map(|s| s.get_stats())
            .unwrap_or_default();

        let udp_stats = self
            .udp_server
            .as_ref()
            .map(|s| s.get_stats())
            .unwrap_or_default();

        let connection_stats = self.connection_manager.get_stats();

        ServerStats {
            tcp_connections: tcp_stats.tcp_connections,
            tcp_bytes_sent: tcp_stats.tcp_bytes_sent,
            tcp_bytes_received: tcp_stats.tcp_bytes_received,
            udp_packets_sent: udp_stats.udp_packets_sent,
            udp_packets_received: udp_stats.udp_packets_received,
            udp_bytes_sent: udp_stats.udp_bytes_sent,
            udp_bytes_received: udp_stats.udp_bytes_received,
            active_connections: connection_stats.active_connections,
            total_connections: connection_stats.total_connections,
            uptime: connection_stats.uptime,
        }
    }

    /// 获取配置信息
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// 检查服务器是否正在运行
    pub fn is_running(&self) -> bool {
        let tcp_running = self
            .tcp_server
            .as_ref()
            .map(|s| s.is_running())
            .unwrap_or(false);

        let udp_running = self
            .udp_server
            .as_ref()
            .map(|s| s.is_running())
            .unwrap_or(true); // 如果UDP未启用，认为是"运行"状态

        tcp_running && udp_running
    }
}

/// 服务器统计信息
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    /// TCP连接数
    pub tcp_connections: u64,
    /// TCP发送字节数
    pub tcp_bytes_sent: u64,
    /// TCP接收字节数
    pub tcp_bytes_received: u64,
    /// UDP发送包数
    pub udp_packets_sent: u64,
    /// UDP接收包数
    pub udp_packets_received: u64,
    /// UDP发送字节数
    pub udp_bytes_sent: u64,
    /// UDP接收字节数
    pub udp_bytes_received: u64,
    /// 当前活跃连接数
    pub active_connections: usize,
    /// 总连接数
    pub total_connections: u64,
    /// 运行时间（秒）
    pub uptime: u64,
}

impl ServerStats {
    /// 格式化统计信息
    pub fn format(&self) -> String {
        format!(
            "TCP: {} connections, {}/{} bytes | UDP: {}/{} packets, {}/{} bytes | Active: {}/{} | Uptime: {}s",
            self.tcp_connections,
            self.tcp_bytes_sent,
            self.tcp_bytes_received,
            self.udp_packets_sent,
            self.udp_packets_received,
            self.udp_bytes_sent,
            self.udp_bytes_received,
            self.active_connections,
            self.total_connections,
            self.uptime
        )
    }
}

/// 处理客户端连接的通用函数
/// 返回 (发送字节数, 接收字节数)
pub async fn handle_client_connection(
    mut client_stream: TcpStream,
    config: Arc<ServerConfig>,
    connection_manager: Arc<ConnectionManager>,
) -> Result<(u64, u64)> {
    let client_addr = client_stream
        .peer_addr()
        .map_err(|e| anyhow!("Failed to get client address: {}", e))?;

    debug!("New client connection from: {}", client_addr);

    // 检查连接限制
    if !connection_manager.can_accept_connection() {
        warn!(
            "Connection limit reached, rejecting client: {}",
            client_addr
        );
        return Err(anyhow!("Connection limit reached"));
    }

    // 注册连接
    let connection_id = connection_manager.register_connection(client_addr).await?;

    // 创建加密上下文
    let crypto = create_server_crypto(&config)?;
    let mut protocol = ShadowsocksProtocol::new(crypto);

    let result = async {
        // 读取第一个请求包，获取目标地址
        let target_address = protocol
            .handle_tcp_handshake(&mut client_stream)
            .await
            .map_err(|e| anyhow!("Failed to handle handshake: {}", e))?;

        debug!("Target address: {:?}", target_address);

        // 连接到目标服务器
        let target_stream = connect_to_target(&target_address, config.timeout)
            .await
            .map_err(|e| anyhow!("Failed to connect to target: {}", e))?;

        info!("Connected to target: {:?}", target_address);

        // 开始双向数据转发
        let result = copy_bidirectional_with_timeout(
            client_stream,
            target_stream,
            Duration::from_secs(config.timeout),
        )
        .await;

        match result {
            Ok((client_to_target, target_to_client)) => {
                info!(
                    "Connection closed: {} -> {}, transferred: {} bytes up, {} bytes down",
                    client_addr, target_address, client_to_target, target_to_client
                );
                Ok((client_to_target, target_to_client))
            }
            Err(e) => {
                warn!(
                    "Connection error: {} -> {}: {}",
                    client_addr, target_address, e
                );
                Err(e)
            }
        }
    }
    .await;

    // 注销连接
    connection_manager
        .unregister_connection(connection_id)
        .await;

    result
}

/// 连接到目标服务器
async fn connect_to_target(address: &Address, timeout_secs: u64) -> Result<TcpStream> {
    let timeout_duration = Duration::from_secs(timeout_secs);

    match address {
        Address::SocketAddr(addr) => timeout_future(timeout_duration, TcpStream::connect(addr))
            .await?
            .map_err(|e| anyhow!("Failed to connect to {}: {}", addr, e)),
        Address::DomainNameAddr(domain, port) => {
            let addr_str = format!("{}:{}", domain, port);
            timeout_future(timeout_duration, TcpStream::connect(&addr_str))
                .await?
                .map_err(|e| anyhow!("Failed to connect to {}: {}", addr_str, e))
        }
    }
}

/// 验证客户端请求
pub fn validate_client_request(address: &Address) -> Result<()> {
    match address {
        Address::SocketAddr(addr) => {
            // 检查是否为本地地址
            if addr.ip().is_loopback() {
                return Err(anyhow!("Loopback address not allowed: {}", addr));
            }

            // 检查端口范围
            if addr.port() == 0 {
                return Err(anyhow!("Invalid port: 0"));
            }
        }
        Address::DomainNameAddr(domain, port) => {
            // 检查域名长度
            if domain.is_empty() || domain.len() > 255 {
                return Err(anyhow!("Invalid domain name length: {}", domain.len()));
            }

            // 检查端口范围
            if *port == 0 {
                return Err(anyhow!("Invalid port: 0"));
            }

            // 简单的域名格式检查
            if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
                return Err(anyhow!("Invalid domain name format: {}", domain));
            }
        }
    }

    Ok(())
}

/// 创建服务端加密上下文
pub fn create_server_crypto(config: &ServerConfig) -> Result<CryptoContext> {
    CryptoContext::new(config.method.as_str(), &config.password)
}

/// 服务端错误类型
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Connection limit reached")]
    ConnectionLimit,

    #[error("Timeout error")]
    Timeout,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// 服务端事件类型
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// 服务器启动
    Started {
        tcp_addr: SocketAddr,
        udp_addr: Option<SocketAddr>,
    },
    /// 服务器停止
    Stopped,
    /// 新连接
    NewConnection {
        client_addr: SocketAddr,
        connection_id: u64,
    },
    /// 连接关闭
    ConnectionClosed {
        client_addr: SocketAddr,
        connection_id: u64,
        duration: Duration,
        bytes_transferred: (u64, u64),
    },
    /// 连接错误
    ConnectionError {
        client_addr: SocketAddr,
        error: String,
    },
    /// 统计信息更新
    StatsUpdate(ServerStats),
}

/// 服务端事件监听器
pub trait ServerEventListener: Send + Sync {
    /// 处理服务端事件
    fn on_event(&self, event: ServerEvent);
}

/// 默认事件监听器（记录日志）
pub struct DefaultEventListener;

impl ServerEventListener for DefaultEventListener {
    fn on_event(&self, event: ServerEvent) {
        match event {
            ServerEvent::Started { tcp_addr, udp_addr } => {
                info!("Server started - TCP: {}, UDP: {:?}", tcp_addr, udp_addr);
            }
            ServerEvent::Stopped => {
                info!("Server stopped");
            }
            ServerEvent::NewConnection {
                client_addr,
                connection_id,
            } => {
                debug!("New connection: {} (ID: {})", client_addr, connection_id);
            }
            ServerEvent::ConnectionClosed {
                client_addr,
                connection_id,
                duration,
                bytes_transferred,
            } => {
                info!(
                    "Connection closed: {} (ID: {}, Duration: {:?}, Bytes: {}/{})",
                    client_addr, connection_id, duration, bytes_transferred.0, bytes_transferred.1
                );
            }
            ServerEvent::ConnectionError { client_addr, error } => {
                warn!("Connection error from {}: {}", client_addr, error);
            }
            ServerEvent::StatsUpdate(stats) => {
                debug!("Stats: {}", stats.format());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::crypto::Method;

    fn create_test_config() -> ServerConfig {
        ServerConfig {
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            password: "test_password".to_string(),
            method: Method::Aes128Gcm.as_str().to_string(),
            timeout: 300,
            enable_udp: true,
            max_connections: 1000,
            enable_unified_port: false,
            unified_port_config: None,
        }
    }

    #[test]
    fn test_server_creation() {
        let config = create_test_config();
        let server = ShadowsocksServer::new(config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_validate_client_request_valid() {
        // 有效的IP地址
        let addr = Address::SocketAddr("8.8.8.8:80".parse().unwrap());
        assert!(validate_client_request(&addr).is_ok());

        // 有效的域名
        let addr = Address::DomainNameAddr("example.com".to_string(), 80);
        assert!(validate_client_request(&addr).is_ok());
    }

    #[test]
    fn test_validate_client_request_invalid() {
        // 回环地址
        let addr = Address::SocketAddr("127.0.0.1:80".parse().unwrap());
        assert!(validate_client_request(&addr).is_err());

        // 端口为0
        let addr = Address::SocketAddr("8.8.8.8:0".parse().unwrap());
        assert!(validate_client_request(&addr).is_err());

        // 无效域名
        let addr = Address::DomainNameAddr("..invalid..".to_string(), 80);
        assert!(validate_client_request(&addr).is_err());

        // 空域名
        let addr = Address::DomainNameAddr("".to_string(), 80);
        assert!(validate_client_request(&addr).is_err());
    }

    #[test]
    fn test_create_server_crypto() {
        let config = create_test_config();
        let crypto = create_server_crypto(&config);
        assert!(crypto.is_ok());
    }

    #[test]
    fn test_server_stats_format() {
        let stats = ServerStats {
            tcp_connections: 100,
            tcp_bytes_sent: 1024,
            tcp_bytes_received: 2048,
            udp_packets_sent: 50,
            udp_packets_received: 75,
            udp_bytes_sent: 512,
            udp_bytes_received: 768,
            active_connections: 10,
            total_connections: 150,
            uptime: 3600,
        };

        let formatted = stats.format();
        assert!(formatted.contains("TCP: 100 connections"));
        assert!(formatted.contains("UDP: 50/75 packets"));
        assert!(formatted.contains("Active: 10/150"));
        assert!(formatted.contains("Uptime: 3600s"));
    }

    #[test]
    fn test_server_error_display() {
        let error = ServerError::Config("Invalid password".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid password");

        let error = ServerError::ConnectionLimit;
        assert_eq!(error.to_string(), "Connection limit reached");
    }

    #[test]
    fn test_default_event_listener() {
        let listener = DefaultEventListener;

        // 测试各种事件（主要确保不会panic）
        listener.on_event(ServerEvent::Started {
            tcp_addr: "127.0.0.1:8388".parse().unwrap(),
            udp_addr: Some("127.0.0.1:8388".parse().unwrap()),
        });

        listener.on_event(ServerEvent::NewConnection {
            client_addr: "192.168.1.1:12345".parse().unwrap(),
            connection_id: 1,
        });

        listener.on_event(ServerEvent::ConnectionClosed {
            client_addr: "192.168.1.1:12345".parse().unwrap(),
            connection_id: 1,
            duration: Duration::from_secs(60),
            bytes_transferred: (1024, 2048),
        });

        listener.on_event(ServerEvent::Stopped);
    }

    #[tokio::test]
    async fn test_server_lifecycle() {
        let config = create_test_config();
        let server = ShadowsocksServer::new(config).unwrap();

        // 初始状态应该是未运行
        assert!(!server.is_running());

        // 获取统计信息
        let stats = server.get_stats();
        assert_eq!(stats.tcp_connections, 0);
        assert_eq!(stats.active_connections, 0);
    }
}
