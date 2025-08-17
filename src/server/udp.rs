//! UDP服务器模块
//!
//! 实现Shadowsocks UDP代理服务器

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

use crate::config::ServerConfig;
use crate::crypto::CryptoContext;
use crate::protocol::{Address, ShadowsocksProtocol};
use crate::server::{ConnectionManager, ServerStats};
use crate::utils::timeout_future;

/// UDP服务器
#[derive(Clone)]
pub struct UdpServer {
    config: Arc<ServerConfig>,
    connection_manager: Arc<ConnectionManager>,
    stats: Arc<UdpStats>,
    running: Arc<AtomicBool>,
    socket: Option<Arc<UdpSocket>>,
    session_manager: Arc<UdpSessionManager>,
}

/// UDP服务器统计信息
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

    /// 转换为服务器统计信息
    pub fn to_server_stats(&self) -> ServerStats {
        ServerStats {
            udp_packets_sent: self.packets.load(Ordering::Relaxed),
            udp_packets_received: self.packets.load(Ordering::Relaxed),
            udp_bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            udp_bytes_received: self.bytes_received.load(Ordering::Relaxed),
            active_connections: self.active_sessions.load(Ordering::Relaxed) as usize,
            total_connections: self.active_sessions.load(Ordering::Relaxed),
            uptime: self.get_uptime(),
            ..Default::default()
        }
    }
}

/// UDP会话信息
#[derive(Debug, Clone)]
pub struct UdpSession {
    /// 客户端地址
    pub client_addr: SocketAddr,
    /// 目标地址
    pub target_addr: Address,
    /// 目标套接字
    pub target_socket: Option<Arc<UdpSocket>>,
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
    pub fn new(client_addr: SocketAddr, target_addr: Address, crypto: Arc<CryptoContext>) -> Self {
        Self {
            client_addr,
            target_addr,
            target_socket: None,
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

    /// 设置目标套接字
    pub fn set_target_socket(&mut self, socket: Arc<UdpSocket>) {
        self.target_socket = Some(socket);
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
        client_addr: SocketAddr,
        target_addr: Address,
        crypto: Arc<CryptoContext>,
    ) -> Result<UdpSession> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&client_addr) {
            session.update_activity();
            return Ok(session.clone());
        }

        let session = UdpSession::new(client_addr, target_addr, crypto);
        sessions.insert(client_addr, session.clone());

        Ok(session)
    }

    /// 更新会话
    pub async fn update_session(&self, client_addr: SocketAddr, session: UdpSession) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(client_addr, session);
    }

    /// 移除会话
    pub async fn remove_session(&self, client_addr: &SocketAddr) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(client_addr);
    }

    /// 清理过期会话
    pub async fn cleanup_expired_sessions(
        &self,
        connection_manager: Option<Arc<ConnectionManager>>,
    ) -> usize {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();
        let mut expired_sessions = Vec::new();

        // 收集过期会话
        sessions.retain(|_, session| {
            if session.is_expired(self.session_timeout) {
                expired_sessions.push(session.clone());
                false
            } else {
                true
            }
        });

        // 注销过期会话的连接
        if let Some(conn_mgr) = connection_manager {
            for session in expired_sessions {
                if let Some(connection_id) = session.connection_id {
                    conn_mgr.unregister_connection(connection_id).await;
                }
            }
        }

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
    pub fn start_cleanup_task(self: Arc<Self>, connection_manager: Option<Arc<ConnectionManager>>) {
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                interval.tick().await;
                self.cleanup_expired_sessions(connection_manager.clone())
                    .await;
            }
        });
    }
}

impl UdpServer {
    /// 创建新的UDP服务器
    pub fn new(
        config: Arc<ServerConfig>,
        connection_manager: Arc<ConnectionManager>,
    ) -> Result<Self> {
        let session_manager = Arc::new(UdpSessionManager::new(
            Duration::from_secs(60),             // 清理间隔
            Duration::from_secs(config.timeout), // 会话超时
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

    /// 启动UDP服务器
    pub async fn run(&mut self) -> Result<()> {
        let bind_addr = self.config.server_addr()?.to_string();

        info!("Starting UDP server on {}", bind_addr);

        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind UDP socket to {}: {}", bind_addr, e))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))?;

        info!("UDP server listening on {}", local_addr);

        self.socket = Some(Arc::new(socket));
        self.running.store(true, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());

        // 启动会话清理任务
        self.session_manager
            .clone()
            .start_cleanup_task(Some(self.connection_manager.clone()));

        // 获取套接字的引用
        let socket = self.socket.as_ref().unwrap().clone();
        let config = self.config.clone();
        let session_manager = self.session_manager.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();
        let connection_manager = self.connection_manager.clone();

        // 启动数据包处理循环
        while running.load(Ordering::Relaxed) {
            let mut buf = vec![0u8; 65536]; // UDP最大数据包大小

            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    buf.truncate(len);
                    stats.increment_packets();
                    stats.add_bytes_received(len as u64);

                    debug!("Received UDP packet from {}, size: {}", client_addr, len);

                    // 在新任务中处理数据包
                    let socket = socket.clone();
                    let config = config.clone();
                    let session_manager = session_manager.clone();
                    let stats = stats.clone();

                    let connection_manager_clone = connection_manager.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_packet(
                            socket,
                            client_addr,
                            Bytes::from(buf),
                            config,
                            session_manager,
                            stats,
                            connection_manager_clone,
                        )
                        .await
                        {
                            warn!("Failed to handle UDP packet from {}: {}", client_addr, e);
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

        info!("UDP server stopped");
        Ok(())
    }

    /// 停止UDP服务器
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping UDP server...");
        self.running.store(false, Ordering::Relaxed);

        // 等待一小段时间让正在处理的数据包完成
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
        if let Some(ref socket) = self.socket {
            socket
                .local_addr()
                .map_err(|e| anyhow!("Failed to get local address: {}", e))
        } else {
            Err(anyhow!("Server not started"))
        }
    }

    /// 处理UDP数据包
    async fn handle_packet(
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        data: Bytes,
        config: Arc<ServerConfig>,
        session_manager: Arc<UdpSessionManager>,
        stats: Arc<UdpStats>,
        connection_manager: Arc<ConnectionManager>,
    ) -> Result<()> {
        // 检查连接限制
        if !connection_manager.can_accept_connection() {
            warn!("UDP connection limit reached for client {}", client_addr);
            return Err(anyhow!("Connection limit reached"));
        }

        // 创建加密上下文
        let crypto = Arc::new(CryptoContext::new(
            config.method.as_str(),
            &config.password,
        )?);

        // 创建Shadowsocks协议处理器
        let mut protocol = ShadowsocksProtocol::new((*crypto).clone());

        // 解析UDP数据包
        let (target_addr, payload) = protocol
            .parse_udp_packet(&data)
            .map_err(|e| anyhow!("Failed to parse UDP request: {}", e))?;

        debug!(
            "UDP request to {}, payload size: {}",
            target_addr,
            payload.len()
        );

        // 获取或创建会话
        let mut session = session_manager
            .get_or_create_session(client_addr, target_addr.clone(), crypto.clone())
            .await?;

        // 如果会话没有目标套接字，创建一个并注册连接
        if session.target_socket.is_none() {
            // 注册新连接
            let connection_id = connection_manager.register_connection(client_addr).await?;

            let target_socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| anyhow!("Failed to create target socket: {}", e))?;

            session.set_target_socket(Arc::new(target_socket));
            session.set_connection_id(connection_id);
            session_manager
                .update_session(client_addr, session.clone())
                .await;
        }

        let target_socket = session.target_socket.as_ref().unwrap().clone();

        // 解析目标地址
        let target_sockaddr = crate::utils::address::resolve_address(&target_addr)
            .await
            .map_err(|e| anyhow!("Failed to resolve target address: {}", e))?;

        // 发送数据到目标服务器
        match target_socket.send_to(&payload, target_sockaddr).await {
            Ok(sent_bytes) => {
                debug!("Sent {} bytes to target {}", sent_bytes, target_sockaddr);
                stats.add_bytes_sent(sent_bytes as u64);

                // 启动响应监听任务
                let socket = socket.clone();
                let target_socket = target_socket.clone();
                let protocol = protocol.clone();
                let stats = stats.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_response(socket, target_socket, client_addr, protocol, stats)
                            .await
                    {
                        warn!("Failed to handle UDP response for {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to send UDP packet to {}: {}", target_sockaddr, e);
                return Err(anyhow!("Failed to send UDP packet: {}", e));
            }
        }

        Ok(())
    }

    /// 处理UDP响应
    async fn handle_response(
        client_socket: Arc<UdpSocket>,
        target_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        mut protocol: ShadowsocksProtocol,
        stats: Arc<UdpStats>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        // 设置接收超时
        let timeout_duration = Duration::from_secs(30);

        match timeout_future(timeout_duration, target_socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                buf.truncate(len);
                debug!("Received {} bytes from target", len);

                // 创建UDP响应数据包
                let target_addr = Address::SocketAddr(
                    target_socket
                        .local_addr()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                );
                let response_data = protocol
                    .create_udp_packet(&target_addr, &buf[..len])
                    .map_err(|e| anyhow!("Failed to create UDP response: {}", e))?;

                // 发送响应给客户端
                match client_socket.send_to(&response_data, client_addr).await {
                    Ok(sent_bytes) => {
                        debug!(
                            "Sent {} bytes response to client {}",
                            sent_bytes, client_addr
                        );
                        stats.add_bytes_sent(sent_bytes as u64);
                    }
                    Err(e) => {
                        error!("Failed to send UDP response to {}: {}", client_addr, e);
                        return Err(anyhow!("Failed to send UDP response: {}", e));
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Failed to receive from target: {}", e);
                return Err(anyhow!("Failed to receive from target: {}", e));
            }
            Err(_) => {
                debug!("UDP response timeout for client {}", client_addr);
                // 超时不算错误，只是记录日志
            }
        }

        Ok(())
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

/// UDP服务器构建器
pub struct UdpServerBuilder {
    config: Option<Arc<ServerConfig>>,
    connection_manager: Option<Arc<ConnectionManager>>,
}

impl UdpServerBuilder {
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

    /// 构建UDP服务器
    pub fn build(self) -> Result<UdpServer> {
        let config = self.config.ok_or_else(|| anyhow!("Config is required"))?;
        let connection_manager = self
            .connection_manager
            .ok_or_else(|| anyhow!("Connection manager is required"))?;

        UdpServer::new(config, connection_manager)
    }
}

impl Default for UdpServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::crypto::Method;
    use crate::protocol::Address;
    use crate::server::ConnectionManager;

    fn create_test_config() -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            server: "127.0.0.1".to_string(),
            server_port: 0, // 使用随机端口
            password: "test_password".to_string(),
            method: Method::Aes128Gcm.as_str().to_string(),
            timeout: 300,
            enable_udp: true,
            max_connections: 100,
            enable_unified_port: false,
            unified_port_config: None,
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
        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = Address::from_str("example.com:80").unwrap();
        let crypto = Arc::new(CryptoContext::new(Method::Aes128Gcm.as_str(), "password").unwrap());

        let session = UdpSession::new(client_addr, target_addr, crypto);
        assert_eq!(session.client_addr, client_addr);
        assert_eq!(session.bytes_sent, 0);
        assert_eq!(session.bytes_received, 0);
        assert!(session.target_socket.is_none());
    }

    #[test]
    fn test_udp_session_operations() {
        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = Address::from_str("example.com:80").unwrap();
        let crypto = Arc::new(CryptoContext::new(Method::Aes128Gcm.as_str(), "password").unwrap());

        let mut session = UdpSession::new(client_addr, target_addr, crypto);

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

        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = Address::from_str("example.com:80").unwrap();
        let crypto = Arc::new(CryptoContext::new(Method::Aes128Gcm.as_str(), "password").unwrap());

        // 创建会话
        let session = manager
            .get_or_create_session(client_addr, target_addr.clone(), crypto.clone())
            .await
            .unwrap();

        assert_eq!(session.client_addr, client_addr);
        assert_eq!(manager.get_active_session_count().await, 1);

        // 获取相同会话
        let session2 = manager
            .get_or_create_session(client_addr, target_addr, crypto)
            .await
            .unwrap();

        assert_eq!(session2.client_addr, client_addr);
        assert_eq!(manager.get_active_session_count().await, 1);

        // 移除会话
        manager.remove_session(&client_addr).await;
        assert_eq!(manager.get_active_session_count().await, 0);
    }

    #[tokio::test]
    async fn test_udp_server_creation() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let server = UdpServer::new(config, connection_manager);
        assert!(server.is_ok());

        let server = server.unwrap();
        assert!(!server.is_running());
    }

    #[test]
    fn test_udp_server_builder() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = UdpServerBuilder::new()
            .with_config(config)
            .with_connection_manager(connection_manager);

        let server = builder.build();
        assert!(server.is_ok());
    }

    #[test]
    fn test_udp_server_builder_missing_config() {
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = UdpServerBuilder::new().with_connection_manager(connection_manager);

        let server = builder.build();
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn test_udp_server_lifecycle() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let server = UdpServer::new(config, connection_manager).unwrap();

        // 初始状态
        assert!(!server.is_running());

        // 获取统计信息
        let stats = server.get_stats();
        assert_eq!(stats.udp_packets_received + stats.udp_bytes_received, 0);

        // 重置统计信息
        server.reset_stats();
        let stats = server.get_stats();
        assert_eq!(stats.udp_packets_received + stats.udp_bytes_received, 0);
    }
}
