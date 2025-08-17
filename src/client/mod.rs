//! 客户端模块
//!
//! 实现Shadowsocks客户端功能

use anyhow::{Result, anyhow};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::client::socks5::{Socks5ConnectionHandler, Socks5Stats};
use crate::config::ClientConfig;
use crate::crypto::CryptoContext;
use crate::protocol::{Address, ShadowsocksProtocol};

pub mod socks5;
pub mod tcp;
pub mod udp;

use tcp::TcpClient;
use udp::UdpClient;

/// 客户端统计信息
#[derive(Debug, Default, Clone)]
pub struct ClientStats {
    /// TCP连接数
    pub tcp_connections: u64,
    /// TCP发送字节数
    pub tcp_bytes_sent: u64,
    /// TCP接收字节数
    pub tcp_bytes_received: u64,
    /// UDP数据包数
    pub udp_packets: u64,
    /// UDP发送字节数
    pub udp_bytes_sent: u64,
    /// UDP接收字节数
    pub udp_bytes_received: u64,
    /// 启动时间
    pub start_time: Option<Instant>,
}

impl ClientStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// 获取运行时间（秒）
    pub fn get_uptime(&self) -> u64 {
        if let Some(start_time) = self.start_time {
            start_time.elapsed().as_secs()
        } else {
            0
        }
    }

    /// 合并统计信息
    pub fn merge(&mut self, other: &ClientStats) {
        self.tcp_connections += other.tcp_connections;
        self.tcp_bytes_sent += other.tcp_bytes_sent;
        self.tcp_bytes_received += other.tcp_bytes_received;
        self.udp_packets += other.udp_packets;
        self.udp_bytes_sent += other.udp_bytes_sent;
        self.udp_bytes_received += other.udp_bytes_received;
    }
}

/// 连接管理器
pub struct ConnectionManager {
    max_connections: usize,
    active_connections: Arc<AtomicU64>,
}

impl ConnectionManager {
    /// 创建新的连接管理器
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active_connections: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 尝试获取连接
    pub fn acquire_connection(&self) -> Result<ConnectionGuard> {
        let current = self.active_connections.load(Ordering::Relaxed);
        if current >= self.max_connections as u64 {
            return Err(anyhow!(
                "Maximum connections reached: {}",
                self.max_connections
            ));
        }

        self.active_connections.fetch_add(1, Ordering::Relaxed);
        Ok(ConnectionGuard {
            manager: self.active_connections.clone(),
        })
    }

    /// 获取活跃连接数
    pub fn get_active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// 获取最大连接数
    pub fn get_max_connections(&self) -> usize {
        self.max_connections
    }
}

/// 连接守卫
pub struct ConnectionGuard {
    manager: Arc<AtomicU64>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.manager.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shadowsocks客户端
pub struct ShadowsocksClient {
    config: Arc<ClientConfig>,
    connection_manager: Arc<ConnectionManager>,
    tcp_client: Option<TcpClient>,
    udp_client: Option<UdpClient>,
    running: Arc<AtomicBool>,
    stats: Arc<std::sync::Mutex<ClientStats>>,
}

impl ShadowsocksClient {
    /// 创建新的客户端
    pub fn new(config: ClientConfig) -> Result<Self> {
        let config = Arc::new(config);
        let connection_manager = Arc::new(ConnectionManager::new(config.max_connections));

        Ok(Self {
            config,
            connection_manager,
            tcp_client: None,
            udp_client: None,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(std::sync::Mutex::new(ClientStats::new())),
        })
    }

    /// 启动客户端
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Shadowsocks client...");

        self.running.store(true, Ordering::Relaxed);

        // 启动TCP客户端
        let tcp_client = TcpClient::new(self.config.clone(), self.connection_manager.clone())?;

        self.tcp_client = Some(tcp_client.clone());

        // 启动UDP客户端（如果启用）
        if self.config.enable_udp {
            let udp_client = UdpClient::new(self.config.clone(), self.connection_manager.clone())?;

            self.udp_client = Some(udp_client.clone());
        }

        // 启动服务
        let mut handles = Vec::new();

        // TCP服务
        if let Some(ref mut tcp_client) = self.tcp_client {
            let tcp_handle = {
                let mut tcp_client = tcp_client.clone();
                tokio::spawn(async move {
                    if let Err(e) = tcp_client.run().await {
                        error!("TCP client error: {}", e);
                    }
                })
            };
            handles.push(tcp_handle);
        }

        // UDP服务
        if let Some(ref mut udp_client) = self.udp_client {
            let udp_handle = {
                let mut udp_client = udp_client.clone();
                tokio::spawn(async move {
                    if let Err(e) = udp_client.run().await {
                        error!("UDP client error: {}", e);
                    }
                })
            };
            handles.push(udp_handle);
        }

        info!("Shadowsocks client started successfully");
        info!(
            "Local SOCKS5 proxy: {}:{}",
            self.config.local_addr()?,
            self.config.local_port()
        );

        if self.config.enable_udp
            && let Some(udp_port) = self.config.local_udp_port
        {
            info!("UDP relay enabled on port: {}", udp_port);
        }

        // 等待所有服务完成
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Service task error: {}", e);
            }
        }

        info!("Shadowsocks client stopped");
        Ok(())
    }

    /// 停止客户端
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Shadowsocks client...");

        self.running.store(false, Ordering::Relaxed);

        // 停止TCP客户端
        if let Some(ref mut tcp_client) = self.tcp_client {
            tcp_client.stop().await?;
        }

        // 停止UDP客户端
        if let Some(ref mut udp_client) = self.udp_client {
            udp_client.stop().await?;
        }

        // 等待一小段时间让连接完成
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    /// 检查客户端是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> ClientStats {
        let mut stats = self.stats.lock().unwrap().clone();

        // 合并TCP统计信息
        if let Some(ref tcp_client) = self.tcp_client {
            let tcp_stats = tcp_client.get_stats();
            stats.tcp_connections = tcp_stats.tcp_connections;
            stats.tcp_bytes_sent = tcp_stats.tcp_bytes_sent;
            stats.tcp_bytes_received = tcp_stats.tcp_bytes_received;
        }

        // 合并UDP统计信息
        if let Some(ref udp_client) = self.udp_client {
            let udp_stats = udp_client.get_stats();
            stats.udp_packets = udp_stats.udp_packets;
            stats.udp_bytes_sent = udp_stats.udp_bytes_sent;
            stats.udp_bytes_received = udp_stats.udp_bytes_received;
        }

        stats
    }

    /// 获取配置
    pub fn get_config(&self) -> &ClientConfig {
        &self.config
    }

    /// 获取连接管理器
    pub fn get_connection_manager(&self) -> &ConnectionManager {
        &self.connection_manager
    }

    /// 重置统计信息
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = ClientStats::new();

        if let Some(ref tcp_client) = self.tcp_client {
            tcp_client.reset_stats();
        }

        if let Some(ref udp_client) = self.udp_client {
            udp_client.reset_stats();
        }
    }

    /// 测试连接到服务器
    pub async fn test_connection(&self) -> Result<Duration> {
        let start_time = Instant::now();

        // 连接到服务器
        let server_addr = self.config.server_addr()?.to_string();

        let duration = Duration::from_secs(self.config.timeout);
        let stream = tokio::time::timeout(duration, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Failed to connect to server: {}", e))?;

        let elapsed = start_time.elapsed();

        // 关闭连接
        drop(stream);

        info!("Connection test successful, latency: {:?}", elapsed);
        Ok(elapsed)
    }
}

/// 处理客户端连接
/// 返回 (发送字节数, 接收字节数)
pub async fn handle_client_connection(
    stream: TcpStream,
    config: Arc<ClientConfig>,
    connection_manager: Arc<ConnectionManager>,
) -> Result<(u64, u64)> {
    // 获取连接守卫
    let _guard = connection_manager
        .acquire_connection()
        .map_err(|e| anyhow!("Failed to acquire connection: {}", e))?;

    let client_addr = stream
        .peer_addr()
        .map_err(|e| anyhow!("Failed to get client address: {}", e))?;

    debug!("Handling client connection from {}", client_addr);

    let stats = Arc::new(Socks5Stats::new());

    // 创建SOCKS5处理器
    let socks5_handler =
        Socks5ConnectionHandler::new(config.clone(), connection_manager.clone(), stats.clone());

    // 处理SOCKS5连接并获取字节数统计
    let (bytes_sent, bytes_received) = socks5_handler
        .handle_connection_with_stats(stream, client_addr)
        .await
        .map_err(|e| anyhow!("SOCKS5 handling failed: {}", e))?;

    debug!(
        "Client connection from {} completed, transferred: {} sent, {} received",
        client_addr, bytes_sent, bytes_received
    );
    Ok((bytes_sent, bytes_received))
}

/// 连接到Shadowsocks服务器
pub async fn connect_to_shadowsocks_server(
    config: Arc<ClientConfig>,
    target_addr: Address,
) -> Result<TcpStream> {
    let server_addr = config.server_addr()?.to_string();

    debug!("Connecting to Shadowsocks server at {}", server_addr);

    // 连接到服务器
    let duration = Duration::from_secs(config.timeout);
    let mut stream = tokio::time::timeout(duration, TcpStream::connect(&server_addr))
        .await
        .map_err(|_| anyhow!("Connection timeout"))?
        .map_err(|e| anyhow!("Failed to connect to server: {}", e))?;

    debug!("Connected to Shadowsocks server, performing handshake");

    // 创建加密上下文
    let crypto = Arc::new(CryptoContext::new(
        config.method.as_str(),
        &config.password,
    )?);

    // 创建协议处理器
    let mut protocol = ShadowsocksProtocol::new((*crypto).clone());

    // 执行握手
    // 发送目标地址到服务器
    let request_data = protocol.encode_request(&target_addr, &[])?;
    stream
        .write_all(&request_data)
        .await
        .map_err(|e| anyhow!("Failed to send handshake: {}", e))?;

    debug!("Shadowsocks handshake completed successfully");
    Ok(stream)
}

/// 验证客户端请求
pub fn validate_client_request(target_addr: &Address) -> Result<()> {
    // 检查地址类型
    match target_addr {
        Address::SocketAddr(addr) => {
            // 检查端口范围
            if addr.port() == 0 {
                return Err(anyhow!("Invalid port: 0"));
            }

            // 检查IP地址
            if addr.ip().is_unspecified() || addr.ip().is_loopback() {
                return Err(anyhow!("Unspecified or loopback IP address"));
            }

            Ok(())
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

            // 检查域名格式
            if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
                return Err(anyhow!("Invalid domain format: {}", domain));
            }

            Ok(())
        }
    }
}
