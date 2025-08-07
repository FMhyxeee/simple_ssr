//! TCP服务器模块
//!
//! 实现Shadowsocks TCP代理服务器

use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::config::ServerConfig;
use crate::server::{ConnectionManager, ServerStats, handle_client_connection};

/// TCP服务器
#[derive(Clone)]
pub struct TcpServer {
    config: Arc<ServerConfig>,
    connection_manager: Arc<ConnectionManager>,
    stats: Arc<TcpStats>,
    running: Arc<AtomicBool>,
    listener: Option<Arc<TcpListener>>,
}

/// TCP服务器统计信息
#[derive(Debug, Default)]
pub struct TcpStats {
    /// 连接数
    pub connections: AtomicU64,
    /// 发送字节数
    pub bytes_sent: AtomicU64,
    /// 接收字节数
    pub bytes_received: AtomicU64,
    /// 启动时间
    pub start_time: std::sync::Mutex<Option<Instant>>,
}

impl TcpStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            connections: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            start_time: std::sync::Mutex::new(None),
        }
    }

    /// 增加连接数
    pub fn increment_connections(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加发送字节数
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加接收字节数
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 设置启动时间
    pub fn set_start_time(&self, time: Instant) {
        *self.start_time.lock().unwrap() = Some(time);
    }

    /// 获取运行时间（秒）
    pub fn get_uptime(&self) -> u64 {
        if let Some(start_time) = *self.start_time.lock().unwrap() {
            start_time.elapsed().as_secs()
        } else {
            0
        }
    }

    /// 转换为服务器统计信息
    pub fn to_server_stats(&self) -> ServerStats {
        ServerStats {
            tcp_connections: self.connections.load(Ordering::Relaxed),
            tcp_bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            tcp_bytes_received: self.bytes_received.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

impl TcpServer {
    /// 创建新的TCP服务器
    pub fn new(
        config: Arc<ServerConfig>,
        connection_manager: Arc<ConnectionManager>,
    ) -> Result<Self> {
        Ok(Self {
            config,
            connection_manager,
            stats: Arc::new(TcpStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            listener: None,
        })
    }

    /// 启动TCP服务器
    pub async fn run(&mut self) -> Result<()> {
        let bind_addr = self.config.server_addr()?.to_string();

        info!("Starting TCP server on {}", bind_addr);

        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind TCP listener to {}: {}", bind_addr, e))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))?;

        info!("TCP server listening on {}", local_addr);

        self.listener = Some(Arc::new(listener));
        self.running.store(true, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());

        // 获取监听器的引用
        let listener = self.listener.as_ref().unwrap().clone();

        while self.running.load(Ordering::Relaxed) {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    debug!("Accepted TCP connection from {}", client_addr);

                    self.stats.increment_connections();

                    // 在新任务中处理连接
                    let config = self.config.clone();
                    let connection_manager = self.connection_manager.clone();
                    let stats = self.stats.clone();

                    tokio::spawn(async move {
                        let start_time = Instant::now();

                        match Self::handle_connection(
                            stream,
                            client_addr,
                            config,
                            connection_manager,
                            stats.clone(),
                        )
                        .await
                        {
                            Ok((bytes_sent, bytes_received)) => {
                                let duration = start_time.elapsed();
                                stats.add_bytes_sent(bytes_sent);
                                stats.add_bytes_received(bytes_received);

                                info!(
                                    "TCP connection from {} closed after {:?}, transferred: {} bytes up, {} bytes down",
                                    client_addr, duration, bytes_sent, bytes_received
                                );
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                warn!(
                                    "TCP connection from {} failed after {:?}: {}",
                                    client_addr, duration, e
                                );
                            }
                        }
                    });
                }
                Err(e) => {
                    if self.running.load(Ordering::Relaxed) {
                        error!("Failed to accept TCP connection: {}", e);
                        // 短暂延迟后重试
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        info!("TCP server stopped");
        Ok(())
    }

    /// 停止TCP服务器
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping TCP server...");
        self.running.store(false, Ordering::Relaxed);

        // 等待一小段时间让正在处理的连接完成
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    /// 检查服务器是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> ServerStats {
        self.stats.to_server_stats()
    }

    /// 获取绑定地址
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        if let Some(ref listener) = self.listener {
            listener
                .local_addr()
                .map_err(|e| anyhow!("Failed to get local address: {}", e))
        } else {
            Err(anyhow!("Server not started"))
        }
    }

    /// 处理单个连接
    async fn handle_connection(
        stream: TcpStream,
        client_addr: SocketAddr,
        config: Arc<ServerConfig>,
        connection_manager: Arc<ConnectionManager>,
        stats: Arc<TcpStats>,
    ) -> Result<(u64, u64)> {
        // 设置TCP选项
        if let Err(e) = Self::configure_tcp_stream(&stream) {
            warn!("Failed to configure TCP stream for {}: {}", client_addr, e);
        }

        // 使用通用的连接处理函数
        match handle_client_connection(stream, config, connection_manager).await {
            Ok((bytes_sent, bytes_received)) => {
                // 更新统计信息
                stats.add_bytes_sent(bytes_sent);
                stats.add_bytes_received(bytes_received);
                debug!(
                    "Connection from {} completed: {} bytes sent, {} bytes received",
                    client_addr, bytes_sent, bytes_received
                );
                Ok((bytes_sent, bytes_received))
            }
            Err(e) => {
                warn!("Connection from {} failed: {}", client_addr, e);
                Err(e)
            }
        }
    }

    /// 配置TCP流选项
    fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
        use std::mem;
        use std::os::windows::io::AsRawSocket;
        use winapi::shared::ws2def::{IPPROTO_TCP, TCP_NODELAY};

        let socket = stream.as_raw_socket();

        // 设置TCP_NODELAY
        let nodelay: i32 = 1;
        let result = unsafe {
            winapi::um::winsock2::setsockopt(
                socket as winapi::um::winsock2::SOCKET,
                IPPROTO_TCP as i32,
                TCP_NODELAY,
                &nodelay as *const i32 as *const i8,
                mem::size_of::<i32>() as i32,
            )
        };

        if result != 0 {
            return Err(anyhow!("Failed to set TCP_NODELAY"));
        }

        // 设置SO_KEEPALIVE
        let keepalive: i32 = 1;
        let result = unsafe {
            winapi::um::winsock2::setsockopt(
                socket as winapi::um::winsock2::SOCKET,
                winapi::um::winsock2::SOL_SOCKET,
                winapi::um::winsock2::SO_KEEPALIVE,
                &keepalive as *const i32 as *const i8,
                mem::size_of::<i32>() as i32,
            )
        };

        if result != 0 {
            return Err(anyhow!("Failed to set SO_KEEPALIVE"));
        }

        Ok(())
    }

    /// 获取连接统计信息
    pub fn get_connection_stats(&self) -> (u64, u64, u64) {
        (
            self.stats.connections.load(Ordering::Relaxed),
            self.stats.bytes_sent.load(Ordering::Relaxed),
            self.stats.bytes_received.load(Ordering::Relaxed),
        )
    }

    /// 重置统计信息
    pub fn reset_stats(&self) {
        self.stats.connections.store(0, Ordering::Relaxed);
        self.stats.bytes_sent.store(0, Ordering::Relaxed);
        self.stats.bytes_received.store(0, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());
    }
}

/// TCP连接处理器
pub struct TcpConnectionHandler {
    config: Arc<ServerConfig>,
    connection_manager: Arc<ConnectionManager>,
}

impl TcpConnectionHandler {
    /// 创建新的连接处理器
    pub fn new(config: Arc<ServerConfig>, connection_manager: Arc<ConnectionManager>) -> Self {
        Self {
            config,
            connection_manager,
        }
    }

    /// 处理连接
    pub async fn handle(&self, stream: TcpStream, _client_addr: SocketAddr) -> Result<()> {
        match handle_client_connection(stream, self.config.clone(), self.connection_manager.clone())
            .await
        {
            Ok((_bytes_sent, _bytes_received)) => {
                // 连接处理成功，字节统计信息已在handle_client_connection中处理
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// TCP服务器构建器
pub struct TcpServerBuilder {
    config: Option<Arc<ServerConfig>>,
    connection_manager: Option<Arc<ConnectionManager>>,
}

impl TcpServerBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            config: None,
            connection_manager: None,
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: Arc<ServerConfig>) -> Self {
        self.config = Some(config);
        self
    }

    /// 设置连接管理器
    pub fn with_connection_manager(mut self, manager: Arc<ConnectionManager>) -> Self {
        self.connection_manager = Some(manager);
        self
    }

    /// 构建TCP服务器
    pub fn build(self) -> Result<TcpServer> {
        let config = self.config.ok_or_else(|| anyhow!("Config is required"))?;
        let connection_manager = self
            .connection_manager
            .ok_or_else(|| anyhow!("Connection manager is required"))?;

        TcpServer::new(config, connection_manager)
    }
}

impl Default for TcpServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::crypto::Method;
    use crate::server::ConnectionManager;

    fn create_test_config() -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            server: "127.0.0.1".to_string(),
            server_port: 0, // 使用随机端口
            password: "test_password".to_string(),
            method: Method::Aes128Gcm.as_str().to_string(),
            timeout: 300,
            enable_udp: false,
            max_connections: 100,
            enable_unified_port: false,
            unified_port_config: None,
        })
    }

    #[test]
    fn test_tcp_stats_creation() {
        let stats = TcpStats::new();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tcp_stats_operations() {
        let stats = TcpStats::new();

        stats.increment_connections();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 1);

        stats.add_bytes_sent(1024);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 1024);

        stats.add_bytes_received(2048);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 2048);
    }

    #[test]
    fn test_tcp_stats_to_server_stats() {
        let stats = TcpStats::new();
        stats.increment_connections();
        stats.add_bytes_sent(1024);
        stats.add_bytes_received(2048);

        let server_stats = stats.to_server_stats();
        assert_eq!(server_stats.tcp_connections, 1);
        assert_eq!(server_stats.tcp_bytes_sent, 1024);
        assert_eq!(server_stats.tcp_bytes_received, 2048);
    }

    #[tokio::test]
    async fn test_tcp_server_creation() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let server = TcpServer::new(config, connection_manager);
        assert!(server.is_ok());

        let server = server.unwrap();
        assert!(!server.is_running());
    }

    #[test]
    fn test_tcp_connection_handler_creation() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let _handler = TcpConnectionHandler::new(config, connection_manager);
        // 只是确保创建成功
        assert!(true);
    }

    #[test]
    fn test_tcp_server_builder() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = TcpServerBuilder::new()
            .with_config(config)
            .with_connection_manager(connection_manager);

        let server = builder.build();
        assert!(server.is_ok());
    }

    #[test]
    fn test_tcp_server_builder_missing_config() {
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = TcpServerBuilder::new().with_connection_manager(connection_manager);

        let server = builder.build();
        assert!(server.is_err());
    }

    #[test]
    fn test_tcp_server_builder_missing_connection_manager() {
        let config = create_test_config();

        let builder = TcpServerBuilder::new().with_config(config);

        let server = builder.build();
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn test_tcp_server_lifecycle() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let server = TcpServer::new(config, connection_manager).unwrap();

        // 初始状态
        assert!(!server.is_running());

        // 获取统计信息
        let stats = server.get_stats();
        assert_eq!(stats.tcp_connections, 0);

        // 重置统计信息
        server.reset_stats();
        let stats = server.get_stats();
        assert_eq!(stats.tcp_connections, 0);
    }
}
