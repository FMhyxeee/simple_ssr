//! 客户端SOCKS5模块
//!
//! 实现SOCKS5代理客户端功能

use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::client::{ClientStats, ConnectionManager};
use crate::config::ClientConfig;
use crate::protocol::Address;
use crate::protocol::socks5::{AddressType, AuthMethod, Command, ResponseCode};
use crate::utils::copy_bidirectional_with_stats;

/// SOCKS5客户端
#[derive(Clone)]
pub struct Socks5Client {
    config: Arc<ClientConfig>,
    connection_manager: Arc<ConnectionManager>,
    stats: Arc<Socks5Stats>,
    running: Arc<AtomicBool>,
    listener: Option<Arc<TcpListener>>,
}

/// SOCKS5客户端统计信息
#[derive(Debug, Default)]
pub struct Socks5Stats {
    /// 连接数
    pub connections: AtomicU64,
    /// 活跃连接数
    pub active_connections: AtomicU64,
    /// TCP发送字节数
    pub tcp_bytes_sent: AtomicU64,
    /// TCP接收字节数
    pub tcp_bytes_received: AtomicU64,
    /// 成功连接数
    pub successful_connections: AtomicU64,
    /// 失败连接数
    pub failed_connections: AtomicU64,
    /// UDP发送字节数
    pub udp_bytes_sent: AtomicU64,
    /// UDP接受字节数
    pub udp_bytes_received: AtomicU64,
    /// UDP包数
    pub udp_packets: AtomicU64,
    /// 启动时间
    pub start_time: std::sync::Mutex<Option<Instant>>,
}

impl Socks5Stats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            tcp_bytes_sent: AtomicU64::new(0),
            tcp_bytes_received: AtomicU64::new(0),
            successful_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            start_time: std::sync::Mutex::new(None),
            udp_bytes_sent: AtomicU64::new(0),
            udp_bytes_received: AtomicU64::new(0),
            udp_packets: AtomicU64::new(0),
        }
    }

    /// 增加连接数
    pub fn increment_connections(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 减少活跃连接数
    pub fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// 增加TCP发送字节数
    pub fn add_tcp_bytes_sent(&self, bytes: u64) {
        self.tcp_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加TCP接收字节数
    pub fn add_tcp_bytes_received(&self, bytes: u64) {
        self.tcp_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加成功连接数
    pub fn increment_successful_connections(&self) {
        self.successful_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加失败连接数
    pub fn increment_failed_connections(&self) {
        self.failed_connections.fetch_add(1, Ordering::Relaxed);
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

    /// 增加UDP发送字节数
    pub fn add_udp_bytes_sent(&self, bytes: u64) {
        self.udp_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加UDP接收字节数
    pub fn add_udp_bytes_received(&self, bytes: u64) {
        self.udp_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加发送字节数（TCP）
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.tcp_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加接收字节数（TCP）
    pub fn add_bytes_received(&self, bytes: u64) {
        self.tcp_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 转换为客户端统计信息
    pub fn to_client_stats(&self) -> ClientStats {
        ClientStats {
            tcp_connections: self.connections.load(Ordering::Relaxed),
            tcp_bytes_sent: self.tcp_bytes_sent.load(Ordering::Relaxed),
            tcp_bytes_received: self.tcp_bytes_received.load(Ordering::Relaxed),
            udp_bytes_sent: self.udp_bytes_sent.load(Ordering::Relaxed),
            udp_bytes_received: self.udp_bytes_received.load(Ordering::Relaxed),
            start_time: *self.start_time.lock().unwrap(),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
        }
    }
}

/// SOCKS5连接处理器
pub struct Socks5ConnectionHandler {
    config: Arc<ClientConfig>,
    connection_manager: Arc<ConnectionManager>,
    stats: Arc<Socks5Stats>,
}

impl Socks5ConnectionHandler {
    /// 创建新的连接处理器
    pub fn new(
        config: Arc<ClientConfig>,
        connection_manager: Arc<ConnectionManager>,
        stats: Arc<Socks5Stats>,
    ) -> Self {
        Self {
            config,
            connection_manager,
            stats,
        }
    }

    /// 处理SOCKS5连接
    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<TcpStream> {
        debug!("Handling SOCKS5 connection from {}", client_addr);

        // 获取连接守卫
        let _guard = self
            .connection_manager
            .acquire_connection()
            .map_err(|e| anyhow!("Failed to acquire connection: {}", e))?;

        self.stats.increment_connections();

        let result = self.handle_socks5_connection(&mut stream).await;

        // 更新统计信息
        self.stats.decrement_active_connections();

        match result {
            Ok(_) => {
                self.stats.increment_successful_connections();
                debug!(
                    "SOCKS5 connection from {} completed successfully",
                    client_addr
                );
            }
            Err(ref e) => {
                self.stats.increment_failed_connections();
                warn!("SOCKS5 connection from {} failed: {}", client_addr, e);
            }
        }

        Ok(stream)
    }

    /// 处理SOCKS5连接并返回传输字节数统计
    /// 返回 (发送字节数, 接收字节数)
    pub async fn handle_connection_with_stats(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(u64, u64)> {
        debug!("Handling SOCKS5 connection from {} with stats", client_addr);

        // 获取连接守卫
        let _guard = self
            .connection_manager
            .acquire_connection()
            .map_err(|e| anyhow!("Failed to acquire connection: {}", e))?;

        self.stats.increment_connections();

        // 记录处理前的字节数
        let bytes_sent_before = self.stats.tcp_bytes_sent.load(Ordering::Relaxed);
        let bytes_received_before = self.stats.tcp_bytes_received.load(Ordering::Relaxed);

        let result = self.handle_socks5_connection(&mut stream).await;

        // 计算传输的字节数
        let bytes_sent = self.stats.tcp_bytes_sent.load(Ordering::Relaxed) - bytes_sent_before;
        let bytes_received =
            self.stats.tcp_bytes_received.load(Ordering::Relaxed) - bytes_received_before;

        // 更新统计信息
        self.stats.decrement_active_connections();

        match result {
            Ok(_) => {
                self.stats.increment_successful_connections();
                debug!(
                    "SOCKS5 connection from {} completed successfully, transferred: {} sent, {} received",
                    client_addr, bytes_sent, bytes_received
                );
                Ok((bytes_sent, bytes_received))
            }
            Err(e) => {
                self.stats.increment_failed_connections();
                warn!("SOCKS5 connection from {} failed: {}", client_addr, e);
                Err(e)
            }
        }
    }

    /// 处理SOCKS5握手（仅协议协商部分）
    /// 返回目标地址，不包含数据转发
    async fn handle_socks5_handshake(&self, stream: &mut TcpStream) -> Result<Address> {
        // 1. 处理认证协商
        self.handle_auth_negotiation(stream)
            .await
            .map_err(|e| anyhow!("Authentication negotiation failed: {}", e))?;

        // 2. 处理连接请求
        let target_addr = self
            .handle_connect_request(stream)
            .await
            .map_err(|e| anyhow!("Connect request failed: {}", e))?;

        Ok(target_addr)
    }

    /// 处理完整的SOCKS5连接（握手 + 数据转发）
    async fn handle_socks5_connection(&self, stream: &mut TcpStream) -> Result<()> {
        // 1. 执行SOCKS5握手
        let target_addr = self
            .handle_socks5_handshake(stream)
            .await
            .map_err(|e| anyhow!("SOCKS5 handshake failed: {}", e))?;

        // 2. 连接到Shadowsocks服务器
        let mut ss_stream = self
            .connect_to_shadowsocks_server(&target_addr)
            .await
            .map_err(|e| anyhow!("Failed to connect to Shadowsocks server: {}", e))?;

        // 3. 发送成功响应
        self.send_connect_response(stream, ResponseCode::Success)
            .await
            .map_err(|e| anyhow!("Failed to send connect response: {}", e))?;

        // 4. 开始数据转发
        self.relay_data(stream, &mut ss_stream)
            .await
            .map_err(|e| anyhow!("Data relay failed: {}", e))?;

        Ok(())
    }

    /// 处理认证协商
    async fn handle_auth_negotiation(&self, stream: &mut TcpStream) -> Result<()> {
        // 读取客户端认证方法
        let mut buf = [0u8; 2];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| anyhow!("Failed to read auth header: {}", e))?;

        let version = buf[0];
        let nmethods = buf[1];

        if version != 0x05 {
            return Err(anyhow!("Unsupported SOCKS version: {}", version));
        }

        if nmethods == 0 {
            return Err(anyhow!("No authentication methods provided"));
        }

        // 读取认证方法列表
        let mut methods = vec![0u8; nmethods as usize];
        stream
            .read_exact(&mut methods)
            .await
            .map_err(|e| anyhow!("Failed to read auth methods: {}", e))?;

        // 检查是否支持无认证方法
        let selected_method = if methods.contains(&(AuthMethod::NoAuth as u8)) {
            AuthMethod::NoAuth
        } else {
            AuthMethod::NoAcceptable
        };

        // 发送认证方法选择响应
        let response = [0x05, selected_method as u8];
        stream
            .write_all(&response)
            .await
            .map_err(|e| anyhow!("Failed to send auth response: {}", e))?;

        if selected_method == AuthMethod::NoAcceptable {
            return Err(anyhow!("No acceptable authentication methods"));
        }

        debug!("SOCKS5 authentication negotiation completed");
        Ok(())
    }

    /// 处理连接请求
    async fn handle_connect_request(&self, stream: &mut TcpStream) -> Result<Address> {
        // 读取请求头
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| anyhow!("Failed to read connect request header: {}", e))?;

        let version = buf[0];
        let command = buf[1];
        let _reserved = buf[2];
        let address_type = buf[3];

        if version != 0x05 {
            return Err(anyhow!("Unsupported SOCKS version: {}", version));
        }

        if command != (Command::Connect as u8) {
            return Err(anyhow!("Unsupported SOCKS command: {}", command));
        }

        // 解析目标地址
        let target_addr = match AddressType::from(address_type) {
            AddressType::Ipv4 => {
                let mut addr_buf = [0u8; 6]; // 4字节IP + 2字节端口
                stream
                    .read_exact(&mut addr_buf)
                    .await
                    .map_err(|e| anyhow!("Failed to read IPv4 address: {}", e))?;

                let ip =
                    std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);

                Address::SocketAddr(SocketAddr::from((ip, port)))
            }
            AddressType::Ipv6 => {
                let mut addr_buf = [0u8; 18]; // 16字节IP + 2字节端口
                stream
                    .read_exact(&mut addr_buf)
                    .await
                    .map_err(|e| anyhow!("Failed to read IPv6 address: {}", e))?;

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&addr_buf[0..16]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);

                Address::SocketAddr(SocketAddr::from((ip, port)))
            }
            AddressType::Domain => {
                // 读取域名长度
                let mut len_buf = [0u8; 1];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| anyhow!("Failed to read domain length: {}", e))?;

                let domain_len = len_buf[0] as usize;
                if domain_len == 0 {
                    return Err(anyhow!("Invalid domain length: 0"));
                }

                // 读取域名和端口
                let mut domain_buf = vec![0u8; domain_len + 2]; // 域名 + 2字节端口
                stream
                    .read_exact(&mut domain_buf)
                    .await
                    .map_err(|e| anyhow!("Failed to read domain and port: {}", e))?;

                let domain = String::from_utf8(domain_buf[0..domain_len].to_vec())
                    .map_err(|e| anyhow!("Invalid domain name: {}", e))?;
                let port = u16::from_be_bytes([domain_buf[domain_len], domain_buf[domain_len + 1]]);

                Address::DomainNameAddr(domain, port)
            }
        };

        debug!("SOCKS5 connect request to {}", target_addr);
        Ok(target_addr)
    }

    /// 连接到Shadowsocks服务器
    async fn connect_to_shadowsocks_server(&self, target_addr: &Address) -> Result<TcpStream> {
        let server_addr = self.config.server_addr()?.to_string();

        debug!(
            "Connecting to Shadowsocks server {} for target {}",
            server_addr, target_addr
        );

        // 连接到Shadowsocks服务器
        let timeout_duration = Duration::from_secs(self.config.timeout);
        let stream = tokio::time::timeout(timeout_duration, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Failed to connect to server: {}", e))?;

        debug!("Connected to Shadowsocks server successfully");
        Ok(stream)
    }

    /// 发送连接响应
    async fn send_connect_response(
        &self,
        stream: &mut TcpStream,
        status: ResponseCode,
    ) -> Result<()> {
        let mut response = BytesMut::new();

        // SOCKS5响应格式:
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+

        response.put_u8(0x05); // VER
        response.put_u8(status as u8); // REP
        response.put_u8(0x00); // RSV
        response.put_u8(AddressType::Ipv4 as u8); // ATYP

        // BND.ADDR (绑定地址，使用0.0.0.0)
        response.put_slice(&[0, 0, 0, 0]);

        // BND.PORT (绑定端口，使用0)
        response.put_u16(0);

        stream
            .write_all(&response)
            .await
            .map_err(|e| anyhow!("Failed to send connect response: {}", e))?;

        debug!("Sent SOCKS5 connect response with status: {:?}", status);
        Ok(())
    }

    /// 数据转发
    async fn relay_data(
        &self,
        client_stream: &mut TcpStream,
        server_stream: &mut TcpStream,
    ) -> Result<()> {
        debug!("Starting data relay");

        let (bytes_sent, bytes_received) =
            copy_bidirectional_with_stats(client_stream, server_stream)
                .await
                .map_err(|e| anyhow!("Data relay failed: {}", e))?;

        // 更新统计信息
        self.stats.add_bytes_sent(bytes_sent);
        self.stats.add_bytes_received(bytes_received);

        debug!(
            "Data relay completed: sent {} bytes, received {} bytes",
            bytes_sent, bytes_received
        );
        Ok(())
    }
}

impl Socks5Client {
    /// 创建新的SOCKS5客户端
    pub fn new(
        config: Arc<ClientConfig>,
        connection_manager: Arc<ConnectionManager>,
    ) -> Result<Self> {
        Ok(Self {
            config,
            connection_manager,
            stats: Arc::new(Socks5Stats::new()),
            running: Arc::new(AtomicBool::new(false)),
            listener: None,
        })
    }

    /// 启动SOCKS5客户端
    pub async fn run(&mut self) -> Result<()> {
        let bind_addr = self.config.local_addr()?.to_string();

        info!("Starting SOCKS5 client on {}", bind_addr);

        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind to {}: {}", bind_addr, e))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))?;

        info!("SOCKS5 client listening on {}", local_addr);

        self.listener = Some(Arc::new(listener));
        self.running.store(true, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());

        // 获取监听器的引用
        let listener = self.listener.as_ref().unwrap().clone();
        let config = self.config.clone();
        let connection_manager = self.connection_manager.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();

        // 接受连接循环
        while running.load(Ordering::Relaxed) {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    debug!("Accepted SOCKS5 connection from {}", client_addr);

                    // 在新任务中处理连接
                    let handler = Socks5ConnectionHandler::new(
                        config.clone(),
                        connection_manager.clone(),
                        stats.clone(),
                    );

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_connection(stream, client_addr).await {
                            warn!(
                                "Failed to handle SOCKS5 connection from {}: {}",
                                client_addr, e
                            );
                        }
                    });
                }
                Err(e) => {
                    if running.load(Ordering::Relaxed) {
                        error!("Failed to accept SOCKS5 connection: {}", e);
                        // 短暂延迟后重试
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        info!("SOCKS5 client stopped");
        Ok(())
    }

    /// 停止SOCKS5客户端
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping SOCKS5 client...");
        self.running.store(false, Ordering::Relaxed);

        // 等待一小段时间让正在处理的连接完成
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
        if let Some(ref listener) = self.listener {
            listener
                .local_addr()
                .map_err(|e| anyhow!("Failed to get local address: {}", e))
        } else {
            Err(anyhow!("Client not started"))
        }
    }

    /// 获取连接统计信息
    pub fn get_connection_stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.stats.connections.load(Ordering::Relaxed),
            self.stats.active_connections.load(Ordering::Relaxed),
            self.stats.tcp_bytes_sent.load(Ordering::Relaxed),
            self.stats.tcp_bytes_received.load(Ordering::Relaxed),
            self.stats.successful_connections.load(Ordering::Relaxed),
            self.stats.failed_connections.load(Ordering::Relaxed),
        )
    }

    /// 重置统计信息
    pub fn reset_stats(&self) {
        self.stats.connections.store(0, Ordering::Relaxed);
        self.stats.active_connections.store(0, Ordering::Relaxed);
        self.stats.tcp_bytes_sent.store(0, Ordering::Relaxed);
        self.stats.tcp_bytes_received.store(0, Ordering::Relaxed);
        self.stats
            .successful_connections
            .store(0, Ordering::Relaxed);
        self.stats.failed_connections.store(0, Ordering::Relaxed);
        self.stats.set_start_time(Instant::now());
    }
}

/// SOCKS5客户端构建器
pub struct Socks5ClientBuilder {
    config: Option<Arc<ClientConfig>>,
    connection_manager: Option<Arc<ConnectionManager>>,
}

impl Socks5ClientBuilder {
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

    /// 构建SOCKS5客户端
    pub fn build(self) -> Result<Socks5Client> {
        let config = self.config.ok_or_else(|| anyhow!("Config is required"))?;
        let connection_manager = self
            .connection_manager
            .ok_or_else(|| anyhow!("Connection manager is required"))?;

        Socks5Client::new(config, connection_manager)
    }
}

impl Default for Socks5ClientBuilder {
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
    use crate::protocol::{Socks5AuthMethod, Socks5CommandType};

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
            local_udp_port: Some(0),
            max_connections: 100,
            enable_unified_port: false,
            unified_port_config: None,
        })
    }

    #[test]
    fn test_socks5_stats_creation() {
        let stats = Socks5Stats::new();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tcp_bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tcp_bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.successful_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_socks5_stats_operations() {
        let stats = Socks5Stats::new();

        stats.increment_connections();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 1);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        stats.decrement_active_connections();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);

        stats.add_bytes_sent(1024);
        assert_eq!(stats.tcp_bytes_sent.load(Ordering::Relaxed), 1024);

        stats.add_bytes_received(2048);
        assert_eq!(stats.tcp_bytes_received.load(Ordering::Relaxed), 2048);

        stats.increment_successful_connections();
        assert_eq!(stats.successful_connections.load(Ordering::Relaxed), 1);

        stats.increment_failed_connections();
        assert_eq!(stats.failed_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_socks5_stats_to_client_stats() {
        let stats = Socks5Stats::new();

        stats.increment_connections();
        stats.add_bytes_sent(1024);
        stats.add_bytes_received(2048);
        stats.increment_successful_connections();

        let client_stats = stats.to_client_stats();
        assert_eq!(client_stats.tcp_connections, 1);
        assert_eq!(client_stats.tcp_bytes_sent, 1024);
        assert_eq!(client_stats.tcp_bytes_received, 2048);
    }

    #[tokio::test]
    async fn test_socks5_client_creation() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = Socks5ClientBuilder::new()
            .with_config(config)
            .with_connection_manager(connection_manager);

        let client = builder.build();

        assert!(client.is_ok());

        let client = client.unwrap();
        assert!(!client.is_running());
    }

    #[test]
    fn test_socks5_client_builder() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));

        let builder = Socks5ClientBuilder::new()
            .with_config(config)
            .with_connection_manager(connection_manager);

        let client = builder.build();
        assert!(client.is_ok());
    }

    #[test]
    fn test_socks5_connection_handler_creation() {
        let config = create_test_config();
        let connection_manager = Arc::new(ConnectionManager::new(100));
        let stats = Arc::new(Socks5Stats::new());

        let _handler = Socks5ConnectionHandler::new(config, connection_manager, stats);

        // 验证处理器创建成功
    }

    // #[tokio::test]
    // async fn test_socks5_client_lifecycle() {
    //     let config = create_test_config();
    //     let connection_manager = Arc::new(ConnectionManager::new(100));

    //     let client = Socks5Client::new();

    //     // 初始状态
    //     assert!(!client.is_running());

    //     // 获取统计信息
    //     let stats = client.get_stats();
    //     assert_eq!(stats.tcp_connections, 0);

    //     // 获取连接统计信息
    //     let (connections, active, sent, received, successful, failed) = client.get_connection_stats();
    //     assert_eq!(connections, 0);
    //     assert_eq!(active, 0);
    //     assert_eq!(sent, 0);
    //     assert_eq!(received, 0);
    //     assert_eq!(successful, 0);
    //     assert_eq!(failed, 0);

    // }

    #[test]
    fn test_socks5_address_type_conversion() {
        assert_eq!(AddressType::from(0x01), AddressType::Ipv4);
        assert_eq!(AddressType::from(0x03), AddressType::Domain);
        assert_eq!(AddressType::from(0x04), AddressType::Ipv6);
    }

    #[test]
    fn test_socks5_auth_method_values() {
        assert_eq!(Socks5AuthMethod::NoAuth as u8, 0x00);
        assert_eq!(Socks5AuthMethod::UserPass as u8, 0x02);
        assert_eq!(Socks5AuthMethod::NoAcceptable as u8, 0xFF);
    }

    #[test]
    fn test_socks5_command_values() {
        assert_eq!(Socks5CommandType::Connect as u8, 0x01);
        assert_eq!(Socks5CommandType::Bind as u8, 0x02);
        assert_eq!(Socks5CommandType::UdpAssociate as u8, 0x03);
    }

    #[test]
    fn test_socks5_response_status_values() {
        assert_eq!(ResponseCode::Success as u8, 0x00);
        assert_eq!(ResponseCode::GeneralFailure as u8, 0x01);
        assert_eq!(ResponseCode::ConnectionNotAllowed as u8, 0x02);
        assert_eq!(ResponseCode::NetworkUnreachable as u8, 0x03);
        assert_eq!(ResponseCode::HostUnreachable as u8, 0x04);
        assert_eq!(ResponseCode::ConnectionRefused as u8, 0x05);
        assert_eq!(ResponseCode::TtlExpired as u8, 0x06);
        assert_eq!(ResponseCode::CommandNotSupported as u8, 0x07);
        assert_eq!(ResponseCode::AddressTypeNotSupported as u8, 0x08);
    }
}
