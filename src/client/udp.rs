//! 客户端UDP模块
//!
//! 实现Shadowsocks客户端UDP代理功能

use anyhow::{Result, anyhow};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::client::{ClientStats, ConnectionManager};
use crate::config::ClientConfig;
use crate::crypto::CryptoContext;
use crate::protocol::{Address, ShadowsocksProtocol};

/// UDP客户端
#[derive(Clone)]
pub struct UdpClient {
    config: Arc<ClientConfig>,
    connection_manager: Arc<ConnectionManager>,
    stats: Arc<UdpStats>,
    running: Arc<AtomicBool>,
    socket: Option<Arc<UdpSocket>>,
    session_manager: Arc<UdpSessionManager>,
}

/// UDP客户端统计信息
#[derive(Debug, Default)]
pub struct UdpStats {
    /// 数据包数量
    pub packets: AtomicU64,
    /// 发送字节数
    pub bytes_sent: AtomicU64,
    /// 接收字节数
    pub bytes_received: AtomicU64,
    /// 活跃会话数
    pub active_sessions: AtomicU64,
    /// 启动时间
    pub start_time: std::sync::Mutex<Option<Instant>>,
}

impl UdpStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            start_time: std::sync::Mutex::new(None),
        }
    }

    /// 增加数据包数
    pub fn increment_packets(&self) {
        self.packets.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加发送字节数
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加接收字节数
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 设置活跃会话数
    pub fn set_active_sessions(&self, count: u64) {
        self.active_sessions.store(count, Ordering::Relaxed);
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

    /// 转换为客户端统计信息
    pub fn to_client_stats(&self) -> ClientStats {
        ClientStats {
            udp_packets: self.packets.load(Ordering::Relaxed),
            udp_bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            udp_bytes_received: self.bytes_received.load(Ordering::Relaxed),
            start_time: self.start_time.lock().unwrap().clone(),
            ..Default::default()
        }
    }
}

/// UDP会话信息
#[derive(Debug, Clone)]
pub struct UdpSession {
    /// 本地客户端地址
    pub local_addr: SocketAddr,
    /// 目标地址
    pub target_addr: Address,
    /// 服务器套接字
    pub server_socket: Option<Arc<UdpSocket>>,
    /// 最后活跃时间
    pub last_active: Instant,
    /// 加密上下文
    pub crypto: Arc<CryptoContext>,
    /// 发送字节数
    pub bytes_sent: u64,
    /// 接收字节数
    pub bytes_received: u64,
    /// 连接ID
    pub connection_id: Option<u64>,
}

impl UdpSession {
    /// 创建新的会话
    pub fn new(local_addr: SocketAddr, target_addr: Address, crypto: Arc<CryptoContext>) -> Self {
        Self {
            local_addr,
            target_addr,
            server_socket: None,
            last_active: Instant::now(),
            crypto,
            bytes_sent: 0,
            bytes_received: 0,
            connection_id: None,
        }
    }

    /// 更新最后活跃时间
    pub fn update_activity(&mut self) {
        self.last_active = Instant::now();
    }

    /// 检查会话是否过期
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_active.elapsed() > timeout
    }

    /// 设置服务器套接字
    pub fn set_server_socket(&mut self, socket: Arc<UdpSocket>) {
        self.server_socket = Some(socket);
    }

    /// 添加发送字节数
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
    }

    /// 添加接收字节数
    pub fn add_bytes_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
    }

    /// 设置连接ID
    pub fn set_connection_id(&mut self, connection_id: u64) {
        self.connection_id = Some(connection_id);
    }
}

/// UDP会话管理器
pub struct UdpSessionManager {
    sessions: RwLock<HashMap<SocketAddr, UdpSession>>,
    cleanup_interval: Duration,
    session_timeout: Duration,
}

impl UdpSessionManager {
    /// 创建新的会话管理器
    pub fn new(cleanup_interval: Duration, session_timeout: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            cleanup_interval,
            session_timeout,
        }
    }

    /// 获取或创建会话
    pub async fn get_or_create_session(
        &self,
        local_addr: SocketAddr,
        target_addr: Address,
        crypto: Arc<CryptoContext>,
    ) -> Result<UdpSession> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&local_addr) {
            session.update_activity();
            return Ok(session.clone());
        }

        let session = UdpSession::new(local_addr, target_addr, crypto);
        sessions.insert(local_addr, session.clone());

        Ok(session)
    }

    /// 更新会话
    pub async fn update_session(&self, local_addr: SocketAddr, session: UdpSession) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(local_addr, session);
    }

    /// 移除会话
    pub async fn remove_session(&self, local_addr: &SocketAddr) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(local_addr);
    }

    /// 清理过期会话
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, session| !session.is_expired(self.session_timeout));

        let removed_count = initial_count - sessions.len();
        if removed_count > 0 {
            debug!("Cleaned up {} expired UDP sessions", removed_count);
        }

        removed_count
    }

    /// 获取活跃会话数
    pub async fn get_active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// 启动清理任务
    pub async fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                interval.tick().await;
                self.cleanup_expired_sessions().await;
            }
        });
    }
}

impl UdpClient {
    /// 创建新的UDP客户端
    pub fn new(
        config: Arc<ClientConfig>,
        connection_manager: Arc<ConnectionManager>,
    ) -> Result<Self> {
        let session_manager = Arc::new(UdpSessionManager::new(
            Duration::from_secs(60),                    // 清理间隔
            Duration::from_secs(config.timeout as u64), // 会话超时
        ));

        Ok(Self {
            config,
            connection_manager,
            stats: Arc::new(UdpStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            socket: None,
            session_manager,
        })
    }

    /// 启动UDP客户端
    pub async fn run(&mut self) -> Result<()> {
        let udp_port = self
            .config
            .local_udp_port
            .unwrap_or(self.config.local_port + 1);
        let bind_addr = format!("{}:{}", self.config.local_address, udp_port);

        info!("Starting UDP client on {}", bind_addr);

        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind UDP socket to {}: {}", bind_addr, e))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))?;

        info!("UDP client listening on {}", local_addr);

        self.socket = Some(Arc::new(socket));
        self.running.store(true, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());

        // 启动会话清理任务
        self.session_manager.clone().start_cleanup_task().await;

        // 获取套接字的引用
        let socket = self.socket.as_ref().unwrap().clone();
        let config = self.config.clone();
        let session_manager = self.session_manager.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();

        // 启动数据包处理循环
        while running.load(Ordering::Relaxed) {
            let mut buf = vec![0u8; 65536]; // UDP最大数据包大小

            match socket.recv_from(&mut buf).await {
                Ok((len, local_client_addr)) => {
                    buf.truncate(len);
                    stats.increment_packets();
                    stats.add_bytes_received(len as u64);

                    debug!(
                        "Received UDP packet from local client {}, size: {}",
                        local_client_addr, len
                    );

                    // 在新任务中处理数据包
                    let socket = socket.clone();
                    let config = config.clone();
                    let session_manager = session_manager.clone();
                    let stats = stats.clone();
                    let connection_manager = self.connection_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_packet(
                            socket,
                            local_client_addr,
                            Bytes::from(buf),
                            config,
                            session_manager,
                            stats,
                            connection_manager,
                        )
                        .await
                        {
                            warn!(
                                "Failed to handle UDP packet from {}: {}",
                                local_client_addr, e
                            );
                        }
                    });
                }
                Err(e) => {
                    if running.load(Ordering::Relaxed) {
                        error!("Failed to receive UDP packet: {}", e);
                        // 短暂延迟后重试
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }

            // 更新活跃会话数统计
            let session_count = session_manager.get_active_session_count().await;
            stats.set_active_sessions(session_count as u64);
        }

        info!("UDP client stopped");
        Ok(())
    }

    /// 停止UDP客户端
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping UDP client...");
        self.running.store(false, Ordering::Relaxed);

        // 等待一小段时间让正在处理的数据包完成
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    /// 检查客户端是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> ClientStats {
        self.stats.to_client_stats()
    }

    /// 获取绑定地址
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        if let Some(ref socket) = self.socket {
            socket
                .local_addr()
                .map_err(|e| anyhow!("Failed to get local address: {}", e))
        } else {
            Err(anyhow!("Client not started"))
        }
    }

    /// 处理UDP数据包
    async fn handle_packet(
        local_socket: Arc<UdpSocket>,
        local_client_addr: SocketAddr,
        data: Bytes,
        config: Arc<ClientConfig>,
        session_manager: Arc<UdpSessionManager>,
        stats: Arc<UdpStats>,
        connection_manager: Arc<ConnectionManager>,
    ) -> Result<()> {
        // 解析SOCKS5 UDP请求
        let (target_addr, payload) = Self::parse_socks5_udp_request(&data)
            .map_err(|e| anyhow!("Failed to parse SOCKS5 UDP request: {}", e))?;

        debug!(
            "UDP request to {}, payload size: {}",
            target_addr,
            payload.len()
        );

        // 创建加密上下文
        let crypto = Arc::new(CryptoContext::new(
            config.method.as_str(),
            &config.password,
        )?);

        // 获取或创建会话
        let mut session = session_manager
            .get_or_create_session(local_client_addr, target_addr.clone(), crypto.clone())
            .await?;

        // 如果会话没有服务器套接字，创建一个并获取连接
        if session.server_socket.is_none() {
            // 获取连接
            let _connection_guard = connection_manager.acquire_connection()?;
            
            let server_socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| anyhow!("Failed to create server socket: {}", e))?;

            session.set_server_socket(Arc::new(server_socket));
            // 注意：这里我们不存储connection_guard，因为UDP是无状态的
            // 连接会在函数结束时自动释放
            session_manager
                .update_session(local_client_addr, session.clone())
                .await;
        }

        let server_socket = session.server_socket.as_ref().unwrap().clone();

        // 创建Shadowsocks协议处理器
        let mut protocol = ShadowsocksProtocol::new((*crypto).clone());

        // 创建Shadowsocks UDP请求
        let ss_request = protocol
            .create_udp_packet(&target_addr, &payload)
            .map_err(|e| anyhow!("Failed to create Shadowsocks UDP request: {}", e))?;

        // 发送到Shadowsocks服务器
        let server_addr = format!("{}:{}", config.server, config.server_port);
        let server_sockaddr: SocketAddr = server_addr
            .parse()
            .map_err(|e| anyhow!("Invalid server address: {}", e))?;

        match server_socket.send_to(&ss_request, server_sockaddr).await {
            Ok(sent_bytes) => {
                debug!(
                    "Sent {} bytes to Shadowsocks server {}",
                    sent_bytes, server_sockaddr
                );
                stats.add_bytes_sent(sent_bytes as u64);

                // 启动响应监听任务
                let local_socket = local_socket.clone();
                let server_socket = server_socket.clone();
                let local_client_addr = local_client_addr;
                let protocol = protocol.clone();
                let stats = stats.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_response(
                        local_socket,
                        server_socket,
                        local_client_addr,
                        protocol,
                        stats,
                    )
                    .await
                    {
                        warn!(
                            "Failed to handle UDP response for {}: {}",
                            local_client_addr, e
                        );
                    }
                });
            }
            Err(e) => {
                error!(
                    "Failed to send UDP packet to server {}: {}",
                    server_sockaddr, e
                );
                return Err(anyhow!("Failed to send UDP packet: {}", e));
            }
        }

        Ok(())
    }

    /// 处理UDP响应
    async fn handle_response(
        local_socket: Arc<UdpSocket>,
        server_socket: Arc<UdpSocket>,
        local_client_addr: SocketAddr,
        mut protocol: ShadowsocksProtocol,
        stats: Arc<UdpStats>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        // 设置接收超时
        let timeout_duration = Duration::from_secs(30);

        match tokio::time::timeout(timeout_duration, server_socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                buf.truncate(len);
                debug!("Received {} bytes from Shadowsocks server", len);

                // 解析Shadowsocks UDP响应
                let (target_addr, payload) = protocol
                    .parse_udp_packet(&buf)
                    .map_err(|e| anyhow!("Failed to parse Shadowsocks UDP response: {}", e))?;

                // 创建SOCKS5 UDP响应
                let socks5_response = Self::create_socks5_udp_response(target_addr, payload.into())
                    .map_err(|e| anyhow!("Failed to create SOCKS5 UDP response: {}", e))?;

                // 发送响应给本地客户端
                match local_socket
                    .send_to(&socks5_response, local_client_addr)
                    .await
                {
                    Ok(sent_bytes) => {
                        debug!(
                            "Sent {} bytes response to local client {}",
                            sent_bytes, local_client_addr
                        );
                        stats.add_bytes_sent(sent_bytes as u64);
                    }
                    Err(e) => {
                        error!(
                            "Failed to send UDP response to {}: {}",
                            local_client_addr, e
                        );
                        return Err(anyhow!("Failed to send UDP response: {}", e));
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Failed to receive from Shadowsocks server: {}", e);
                return Err(anyhow!("Failed to receive from server: {}", e));
            }
            Err(_) => {
                debug!(
                    "UDP response timeout for local client {}",
                    local_client_addr
                );
                // 超时不算错误，只是记录日志
            }
        }

        Ok(())
    }

    /// 解析SOCKS5 UDP请求
    fn parse_socks5_udp_request(data: &[u8]) -> Result<(Address, Bytes)> {
        if data.len() < 10 {
            return Err(anyhow!("UDP request too short"));
        }

        // SOCKS5 UDP请求格式:
        // +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   | Variable |    2     | Variable |
        // +----+------+------+----------+----------+----------+

        let mut offset = 0;

        // 跳过RSV (2字节)
        offset += 2;

        // 跳过FRAG (1字节)
        offset += 1;

        // 解析地址
        let (address, addr_len) = Address::parse_from_bytes(&data[offset..])
            .map_err(|e| anyhow!("Failed to parse address: {}", e))?;

        offset += addr_len;

        // 获取数据部分
        let payload = Bytes::copy_from_slice(&data[offset..]);

        Ok((address, payload))
    }

    /// 创建SOCKS5 UDP响应
    fn create_socks5_udp_response(target_addr: Address, payload: Bytes) -> Result<Vec<u8>> {
        let mut response = Vec::new();

        // RSV (2字节)
        response.extend_from_slice(&[0x00, 0x00]);

        // FRAG (1字节)
        response.push(0x00);

        // 地址
        let addr_bytes = target_addr
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize address: {}", e))?;
        response.extend_from_slice(&addr_bytes);

        // 数据
        response.extend_from_slice(&payload);

        Ok(response)
    }

    /// 获取会话统计信息
    pub async fn get_session_stats(&self) -> (usize, u64, u64, u64) {
        let session_count = self.session_manager.get_active_session_count().await;
        (
            session_count,
            self.stats.packets.load(Ordering::Relaxed),
            self.stats.bytes_sent.load(Ordering::Relaxed),
            self.stats.bytes_received.load(Ordering::Relaxed),
        )
    }

    /// 重置统计信息
    pub fn reset_stats(&self) {
        self.stats.packets.store(0, Ordering::Relaxed);
        self.stats.bytes_sent.store(0, Ordering::Relaxed);
        self.stats.bytes_received.store(0, Ordering::Relaxed);
        self.stats.active_sessions.store(0, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());
    }
}

/// UDP客户端构建器
pub struct UdpClientBuilder {
    config: Option<Arc<ClientConfig>>,
    connection_manager: Option<Arc<ConnectionManager>>,
}

impl UdpClientBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            config: None,
            connection_manager: None,
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.config = Some(config);
        self
    }

    /// 设置连接管理器
    pub fn with_connection_manager(mut self, manager: Arc<ConnectionManager>) -> Self {
        self.connection_manager = Some(manager);
        self
    }

    /// 构建UDP客户端
    pub fn build(self) -> Result<UdpClient> {
        let config = self.config.ok_or_else(|| anyhow!("Config is required"))?;
        let connection_manager = self
            .connection_manager
            .ok_or_else(|| anyhow!("Connection manager is required"))?;

        UdpClient::new(config, connection_manager)
    }
}

impl Default for UdpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectionManager;
    use crate::config::ClientConfig;
    use crate::crypto::Method;
    use crate::protocol::Address;

    fn create_test_config() -> Arc<ClientConfig> {
        Arc::new(ClientConfig {
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            local_address: "127.0.0.1".to_string(),
            local_port: 1080,
            password: "test_password".to_string(),
            method: Method::Aes128Gcm.as_str().to_string(),
            timeout: 300,
            enable_udp: true,
            local_udp_port: Some(0), // 使用随机端口
            max_connections: 100,
        })
    }

    #[test]
    fn test_udp_stats_creation() {
        let stats = UdpStats::new();
        assert_eq!(stats.packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_sessions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_udp_stats_operations() {
        let stats = UdpStats::new();

        stats.increment_packets();
        assert_eq!(stats.packets.load(Ordering::Relaxed), 1);

        stats.add_bytes_sent(1024);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 1024);

        stats.add_bytes_received(2048);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 2048);

        stats.set_active_sessions(5);
        assert_eq!(stats.active_sessions.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_udp_session_creation() {
        let local_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = Address::from_str("example.com:80").unwrap();
        let crypto = Arc::new(CryptoContext::new(Method::Aes128Gcm.as_str(), "password").unwrap());

        let session = UdpSession::new(local_addr, target_addr, crypto);
        assert_eq!(session.local_addr, local_addr);
        assert_eq!(session.bytes_sent, 0);
        assert_eq!(session.bytes_received, 0);
        assert!(session.server_socket.is_none());
    }

    #[test]
    fn test_udp_session_operations() {
        let local_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = Address::from_str("example.com:80").unwrap();
        let crypto = Arc::new(CryptoContext::new(Method::Aes128Gcm.as_str(), "password").unwrap());

        let mut session = UdpSession::new(local_addr, target_addr, crypto);

        let initial_time = session.last_active;
        std::thread::sleep(Duration::from_millis(10));
        session.update_activity();
        assert!(session.last_active > initial_time);

        session.add_bytes_sent(1024);
        assert_eq!(session.bytes_sent, 1024);

        session.add_bytes_received(2048);
        assert_eq!(session.bytes_received, 2048);

        // 测试过期检查
        assert!(!session.is_expired(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn test_udp_session_manager() {
        let manager = UdpSessionManager::new(Duration::from_secs(60), Duration::from_secs(300));

        let local_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = Address::from_str("example.com:80").unwrap();
        let crypto = Arc::new(CryptoContext::new(Method::Aes128Gcm.as_str(), "password").unwrap());

        // 创建会话
        let session = manager
            .get_or_create_session(local_addr, target_addr.clone(), crypto.clone())
            .await
            .unwrap();

        assert_eq!(session.local_addr, local_addr);
        assert_eq!(manager.get_active_session_count().await, 1);

        // 获取相同会话
        let session2 = manager
            .get_or_create_session(local_addr, target_addr, crypto)
            .await
            .unwrap();

        assert_eq!(session2.local_addr, local_addr);
        assert_eq!(manager.get_active_session_count().await, 1);

        // 移除会话
        manager.remove_session(&local_addr).await;
        assert_eq!(manager.get_active_session_count().await, 0);
    }

    #[tokio::test]
    async fn test_udp_client_creation() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let client = UdpClient::new(config, connection_manager);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert!(!client.is_running());
    }

    #[test]
    fn test_udp_client_builder() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = UdpClientBuilder::new()
            .with_config(config)
            .with_connection_manager(connection_manager);

        let client = builder.build();
        assert!(client.is_ok());
    }

    #[test]
    fn test_socks5_udp_request_parsing() {
        // 创建测试数据
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00]); // RSV
        data.push(0x00); // FRAG
        data.push(0x01); // ATYP (IPv4)
        data.extend_from_slice(&[127, 0, 0, 1]); // IP
        data.extend_from_slice(&[0x00, 0x50]); // Port (80)
        data.extend_from_slice(b"test data"); // Data

        let result = UdpClient::parse_socks5_udp_request(&data);
        assert!(result.is_ok());

        let (_address, payload) = result.unwrap();
        assert_eq!(payload, Bytes::from_static(b"test data"));
    }

    #[test]
    fn test_socks5_udp_response_creation() {
        let target_addr = Address::from_str("127.0.0.1:80").unwrap();
        let payload = Bytes::from_static(b"response data");

        let result = UdpClient::create_socks5_udp_response(target_addr, payload);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.len() > 10); // 至少包含头部
        assert_eq!(&response[0..3], &[0x00, 0x00, 0x00]); // RSV + FRAG
    }

    #[tokio::test]
    async fn test_udp_client_lifecycle() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let client = UdpClient::new(config, connection_manager).unwrap();

        // 初始状态
        assert!(!client.is_running());

        // 获取统计信息
        let stats = client.get_stats();
        assert_eq!(stats.udp_packets, 0);

        // 重置统计信息
        client.reset_stats();
        let stats = client.get_stats();
        assert_eq!(stats.udp_packets, 0);
    }

}
