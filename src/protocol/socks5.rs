//! SOCKS5协议实现
//!
//! 实现SOCKS5代理协议的服务端和客户端逻辑

use crate::protocol::Address;
use anyhow::{Result, anyhow};
use bytes::Buf;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// SOCKS5版本号
pub const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5认证方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// 无需认证
    NoAuth = 0x00,
    /// GSSAPI认证
    Gssapi = 0x01,
    /// 用户名/密码认证
    UserPass = 0x02,
    /// 无可接受的方法
    NoAcceptable = 0xFF,
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => AuthMethod::NoAuth,
            0x01 => AuthMethod::Gssapi,
            0x02 => AuthMethod::UserPass,
            _ => AuthMethod::NoAcceptable,
        }
    }
}

/// SOCKS5命令类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// TCP连接
    Connect = 0x01,
    /// TCP绑定
    Bind = 0x02,
    /// UDP关联
    UdpAssociate = 0x03,
}

impl From<u8> for Command {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => Command::Connect, // 默认为连接
        }
    }
}

/// SOCKS5响应状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    /// 成功
    Success = 0x00,
    /// 一般SOCKS服务器失败
    GeneralFailure = 0x01,
    /// 连接不被规则允许
    ConnectionNotAllowed = 0x02,
    /// 网络不可达
    NetworkUnreachable = 0x03,
    /// 主机不可达
    HostUnreachable = 0x04,
    /// 连接被拒绝
    ConnectionRefused = 0x05,
    /// TTL过期
    TtlExpired = 0x06,
    /// 命令不支持
    CommandNotSupported = 0x07,
    /// 地址类型不支持
    AddressTypeNotSupported = 0x08,
}

impl From<u8> for ResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ResponseCode::Success,
            0x01 => ResponseCode::GeneralFailure,
            0x02 => ResponseCode::ConnectionNotAllowed,
            0x03 => ResponseCode::NetworkUnreachable,
            0x04 => ResponseCode::HostUnreachable,
            0x05 => ResponseCode::ConnectionRefused,
            0x06 => ResponseCode::TtlExpired,
            0x07 => ResponseCode::CommandNotSupported,
            0x08 => ResponseCode::AddressTypeNotSupported,
            _ => ResponseCode::GeneralFailure,
        }
    }
}

/// SOCKS5地址类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// IPv4地址
    Ipv4 = 0x01,
    /// 域名
    Domain = 0x03,
    /// IPv6地址
    Ipv6 = 0x04,
}

impl From<u8> for AddressType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => AddressType::Ipv4,
            0x03 => AddressType::Domain,
            0x04 => AddressType::Ipv6,
            _ => AddressType::Domain, // 默认为域名
        }
    }
}

/// SOCKS5请求
#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub command: Command,
    pub address: Address,
}

/// SOCKS5响应
#[derive(Debug, Clone)]
pub struct Socks5Response {
    pub code: ResponseCode,
    pub address: Address,
}

/// SOCKS5服务器
pub struct Socks5Server {
    auth_methods: Vec<AuthMethod>,
    username: Option<String>,
    password: Option<String>,
}

impl Default for Socks5Server {
    fn default() -> Self {
        Self {
            auth_methods: vec![AuthMethod::NoAuth],
            username: None,
            password: None,
        }
    }
}

impl Socks5Server {
    /// 创建新的SOCKS5服务器
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置认证方法
    pub fn with_auth_methods(mut self, methods: Vec<AuthMethod>) -> Self {
        self.auth_methods = methods;
        self
    }

    /// 设置用户名密码认证
    pub fn with_user_pass(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        if !self.auth_methods.contains(&AuthMethod::UserPass) {
            self.auth_methods.push(AuthMethod::UserPass);
        }
        self
    }

    /// 处理SOCKS5握手
    /// 使用tokio的AsyncReadExt和AsyncWriteExt trait提供的方法进行异步字节读写
    pub async fn handle_handshake<S>(&self, stream: &mut S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 使用tokio的read_u8方法读取客户端认证方法请求
        let version = stream
            .read_u8()
            .await
            .map_err(|e| anyhow!("Failed to read SOCKS version: {}", e))?;
        if version != SOCKS5_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {}", version));
        }

        let method_count = stream
            .read_u8()
            .await
            .map_err(|e| anyhow!("Failed to read method count: {}", e))?;
        let mut client_methods = Vec::with_capacity(method_count as usize);

        // 使用tokio的read_exact方法批量读取认证方法
        let mut methods_buf = vec![0u8; method_count as usize];
        stream
            .read_exact(&mut methods_buf)
            .await
            .map_err(|e| anyhow!("Failed to read authentication methods: {}", e))?;

        for method_byte in methods_buf {
            client_methods.push(AuthMethod::from(method_byte));
        }

        // 选择认证方法
        let selected_method = self.select_auth_method(&client_methods);

        // 使用tokio的write_u8方法发送认证方法选择响应
        stream
            .write_u8(SOCKS5_VERSION)
            .await
            .map_err(|e| anyhow!("Failed to write SOCKS version: {}", e))?;
        stream
            .write_u8(selected_method as u8)
            .await
            .map_err(|e| anyhow!("Failed to write selected method: {}", e))?;

        // 处理认证
        match selected_method {
            AuthMethod::NoAuth => {
                // 无需认证
            }
            AuthMethod::UserPass => {
                self.handle_user_pass_auth(stream).await?;
            }
            AuthMethod::NoAcceptable => {
                return Err(anyhow!("No acceptable authentication method"));
            }
            _ => {
                return Err(anyhow!(
                    "Unsupported authentication method: {:?}",
                    selected_method
                ));
            }
        }

        Ok(())
    }

    /// 处理SOCKS5请求
    /// 使用tokio的AsyncReadExt trait提供的方法进行高效的异步字节读取
    pub async fn handle_request<S>(&self, stream: &mut S) -> Result<Socks5Request>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 使用tokio的read_u8方法读取请求头
        let version = stream
            .read_u8()
            .await
            .map_err(|e| anyhow!("Failed to read SOCKS version: {}", e))?;
        if version != SOCKS5_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {}", version));
        }

        let command = Command::from(
            stream
                .read_u8()
                .await
                .map_err(|e| anyhow!("Failed to read command: {}", e))?,
        );
        let _reserved = stream
            .read_u8()
            .await
            .map_err(|e| anyhow!("Failed to read reserved field: {}", e))?; // 保留字段
        let address_type = AddressType::from(
            stream
                .read_u8()
                .await
                .map_err(|e| anyhow!("Failed to read address type: {}", e))?,
        );

        // 读取地址
        let address = match address_type {
            AddressType::Ipv4 => {
                let mut ip_bytes = [0u8; 4];
                stream
                    .read_exact(&mut ip_bytes)
                    .await
                    .map_err(|e| anyhow!("Failed to read IPv4 address: {}", e))?;
                let port = stream
                    .read_u16()
                    .await
                    .map_err(|e| anyhow!("Failed to read port: {}", e))?;
                let ip = Ipv4Addr::from(ip_bytes);
                Address::SocketAddr(SocketAddr::new(IpAddr::V4(ip), port))
            }
            AddressType::Ipv6 => {
                let mut ip_bytes = [0u8; 16];
                stream
                    .read_exact(&mut ip_bytes)
                    .await
                    .map_err(|e| anyhow!("Failed to read IPv6 address: {}", e))?;
                let port = stream
                    .read_u16()
                    .await
                    .map_err(|e| anyhow!("Failed to read port: {}", e))?;
                let ip = Ipv6Addr::from(ip_bytes);
                Address::SocketAddr(SocketAddr::new(IpAddr::V6(ip), port))
            }
            AddressType::Domain => {
                let domain_len = stream
                    .read_u8()
                    .await
                    .map_err(|e| anyhow!("Failed to read domain length: {}", e))?
                    as usize;
                let mut domain_bytes = vec![0u8; domain_len];
                stream
                    .read_exact(&mut domain_bytes)
                    .await
                    .map_err(|e| anyhow!("Failed to read domain name: {}", e))?;
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|e| anyhow!("Invalid domain name: {}", e))?;
                let port = stream
                    .read_u16()
                    .await
                    .map_err(|e| anyhow!("Failed to read port: {}", e))?;
                Address::DomainNameAddr(domain, port)
            }
        };

        Ok(Socks5Request { command, address })
    }

    /// 发送SOCKS5响应
    /// 使用tokio的AsyncWriteExt trait提供的方法进行高效的异步字节写入
    pub async fn send_response<S>(&self, stream: &mut S, response: &Socks5Response) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        // 使用tokio的write_u8方法写入响应头
        stream
            .write_u8(SOCKS5_VERSION)
            .await
            .map_err(|e| anyhow!("Failed to write SOCKS version: {}", e))?;
        stream
            .write_u8(response.code as u8)
            .await
            .map_err(|e| anyhow!("Failed to write response code: {}", e))?;
        stream
            .write_u8(0x00)
            .await
            .map_err(|e| anyhow!("Failed to write reserved field: {}", e))?; // 保留字段

        // 写入地址
        match &response.address {
            Address::SocketAddr(addr) => {
                match addr.ip() {
                    IpAddr::V4(ipv4) => {
                        stream
                            .write_u8(AddressType::Ipv4 as u8)
                            .await
                            .map_err(|e| anyhow!("Failed to write IPv4 address type: {}", e))?;
                        stream
                            .write_all(&ipv4.octets())
                            .await
                            .map_err(|e| anyhow!("Failed to write IPv4 address: {}", e))?;
                    }
                    IpAddr::V6(ipv6) => {
                        stream
                            .write_u8(AddressType::Ipv6 as u8)
                            .await
                            .map_err(|e| anyhow!("Failed to write IPv6 address type: {}", e))?;
                        stream
                            .write_all(&ipv6.octets())
                            .await
                            .map_err(|e| anyhow!("Failed to write IPv6 address: {}", e))?;
                    }
                }
                stream
                    .write_u16(addr.port())
                    .await
                    .map_err(|e| anyhow!("Failed to write port: {}", e))?;
            }
            Address::DomainNameAddr(domain, port) => {
                stream
                    .write_u8(AddressType::Domain as u8)
                    .await
                    .map_err(|e| anyhow!("Failed to write domain address type: {}", e))?;
                stream
                    .write_u8(domain.len() as u8)
                    .await
                    .map_err(|e| anyhow!("Failed to write domain length: {}", e))?;
                stream
                    .write_all(domain.as_bytes())
                    .await
                    .map_err(|e| anyhow!("Failed to write domain name: {}", e))?;
                stream
                    .write_u16(*port)
                    .await
                    .map_err(|e| anyhow!("Failed to write port: {}", e))?;
            }
        }

        stream
            .flush()
            .await
            .map_err(|e| anyhow!("Failed to flush stream: {}", e))?;
        Ok(())
    }

    /// 选择认证方法
    fn select_auth_method(&self, client_methods: &[AuthMethod]) -> AuthMethod {
        for method in &self.auth_methods {
            if client_methods.contains(method) {
                return *method;
            }
        }
        AuthMethod::NoAcceptable
    }

    /// 处理用户名密码认证
    async fn handle_user_pass_auth<S>(&self, stream: &mut S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let version = stream.read_u8().await?;

        if version != 0x01 {
            return Err(anyhow!("Unsupported user/pass auth version: {}", version));
        }

        let username_len = stream.read_u8().await? as usize;
        let mut username_bytes = vec![0u8; username_len];
        stream.read_exact(&mut username_bytes).await?;
        let username =
            String::from_utf8(username_bytes).map_err(|e| anyhow!("Invalid username: {}", e))?;

        let password_len = stream.read_u8().await? as usize;
        let mut password_bytes = vec![0u8; password_len];
        stream.read_exact(&mut password_bytes).await?;
        let password =
            String::from_utf8(password_bytes).map_err(|e| anyhow!("Invalid password: {}", e))?;

        // 验证用户名密码
        let auth_success = if let (Some(expected_user), Some(expected_pass)) =
            (self.username.as_ref(), self.password.as_ref())
        {
            username == *expected_user && password == *expected_pass
        } else {
            false
        };

        // 发送认证响应
        stream.write_u8(0x01).await?; // 版本
        stream
            .write_u8(if auth_success { 0x00 } else { 0x01 })
            .await?; // 状态

        if !auth_success {
            return Err(anyhow!("Authentication failed"));
        }

        Ok(())
    }
}

/// SOCKS5客户端
#[derive(Default)]
pub struct Socks5Client {
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Client {
    /// 创建新的SOCKS5客户端
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置用户名密码认证
    pub fn with_user_pass(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    /// 连接到SOCKS5代理
    pub async fn connect(
        &self,
        proxy_addr: SocketAddr,
        target_addr: &Address,
    ) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .map_err(|e| anyhow!("Failed to connect to proxy: {}", e))?;

        // 执行握手
        self.handshake(&mut stream).await?;

        // 发送连接请求
        self.send_connect_request(&mut stream, target_addr).await?;

        // 读取响应
        let response = self.read_response(&mut stream).await?;
        if response.code != ResponseCode::Success {
            return Err(anyhow!("SOCKS5 connect failed: {:?}", response.code));
        }

        Ok(stream)
    }

    /// 执行SOCKS5握手
    async fn handshake<S>(&self, stream: &mut S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 发送认证方法请求
        let mut methods = vec![AuthMethod::NoAuth as u8];
        if self.username.is_some() && self.password.is_some() {
            methods.push(AuthMethod::UserPass as u8);
        }

        stream.write_u8(SOCKS5_VERSION).await?;
        stream.write_u8(methods.len() as u8).await?;

        for method in methods {
            stream.write_u8(method).await?;
        }

        // 读取服务器选择的认证方法
        let version = stream.read_u8().await?;
        if version != SOCKS5_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {}", version));
        }

        let selected_method = AuthMethod::from(stream.read_u8().await?);

        // 处理认证
        match selected_method {
            AuthMethod::NoAuth => {
                // 无需认证
            }
            AuthMethod::UserPass => {
                self.handle_user_pass_auth(stream).await?;
            }
            AuthMethod::NoAcceptable => {
                return Err(anyhow!("No acceptable authentication method"));
            }
            _ => {
                return Err(anyhow!(
                    "Unsupported authentication method: {:?}",
                    selected_method
                ));
            }
        }

        Ok(())
    }

    /// 发送连接请求
    async fn send_connect_request<S>(&self, stream: &mut S, target_addr: &Address) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        // 写入请求头
        stream.write_u8(SOCKS5_VERSION).await?;
        stream.write_u8(Command::Connect as u8).await?;
        stream.write_u8(0x00).await?; // 保留字段

        // 写入地址
        match target_addr {
            Address::SocketAddr(addr) => {
                match addr.ip() {
                    IpAddr::V4(ipv4) => {
                        stream.write_u8(AddressType::Ipv4 as u8).await?;
                        stream.write_all(&ipv4.octets()).await?;
                    }
                    IpAddr::V6(ipv6) => {
                        stream.write_u8(AddressType::Ipv6 as u8).await?;
                        stream.write_all(&ipv6.octets()).await?;
                    }
                }
                stream.write_u16(addr.port()).await?;
            }
            Address::DomainNameAddr(domain, port) => {
                stream.write_u8(AddressType::Domain as u8).await?;
                stream.write_u8(domain.len() as u8).await?;
                stream.write_all(domain.as_bytes()).await?;
                stream.write_u16(*port).await?;
            }
        }

        stream.flush().await?;
        Ok(())
    }

    /// 读取响应
    async fn read_response<S>(&self, stream: &mut S) -> Result<Socks5Response>
    where
        S: AsyncRead + Unpin,
    {
        // 读取响应头
        let version = stream.read_u8().await?;
        if version != SOCKS5_VERSION {
            return Err(anyhow!("Unsupported SOCKS version: {}", version));
        }

        let code = ResponseCode::from(stream.read_u8().await?);
        let _reserved = stream.read_u8().await?; // 保留字段
        let address_type = AddressType::from(stream.read_u8().await?);

        // 读取地址
        let address = match address_type {
            AddressType::Ipv4 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                let port = stream.read_u16().await?;
                let ip = Ipv4Addr::from(ip_bytes);
                Address::SocketAddr(SocketAddr::new(IpAddr::V4(ip), port))
            }
            AddressType::Ipv6 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await?;
                let port = stream.read_u16().await?;
                let ip = Ipv6Addr::from(ip_bytes);
                Address::SocketAddr(SocketAddr::new(IpAddr::V6(ip), port))
            }
            AddressType::Domain => {
                let domain_len = stream.read_u8().await? as usize;
                let mut domain_bytes = vec![0u8; domain_len];
                stream.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|e| anyhow!("Invalid domain name: {}", e))?;
                let port = stream.read_u16().await?;
                Address::DomainNameAddr(domain, port)
            }
        };

        Ok(Socks5Response { code, address })
    }

    /// 处理用户名密码认证
    async fn handle_user_pass_auth<S>(&self, stream: &mut S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let username = self
            .username
            .as_ref()
            .ok_or_else(|| anyhow!("Username required for user/pass auth"))?;
        let password = self
            .password
            .as_ref()
            .ok_or_else(|| anyhow!("Password required for user/pass auth"))?;

        // 发送认证请求
        stream.write_u8(0x01).await?; // 版本
        stream.write_u8(username.len() as u8).await?;
        stream.write_all(username.as_bytes()).await?;
        stream.write_u8(password.len() as u8).await?;
        stream.write_all(password.as_bytes()).await?;

        // 读取认证响应
        let version = stream.read_u8().await?;
        if version != 0x01 {
            return Err(anyhow!("Unsupported user/pass auth version: {}", version));
        }

        let status = stream.read_u8().await?;
        if status != 0x00 {
            return Err(anyhow!("Authentication failed"));
        }

        Ok(())
    }
}

/// UDP关联处理
pub struct UdpAssociation {
    socket: UdpSocket,
    client_addr: SocketAddr,
}

impl UdpAssociation {
    /// 创建UDP关联
    pub async fn new(bind_addr: SocketAddr, client_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| anyhow!("Failed to bind UDP socket: {}", e))?;

        Ok(Self {
            socket,
            client_addr,
        })
    }

    /// 获取绑定地址
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))
    }

    /// 处理UDP数据包
    pub async fn handle_packet(&self) -> Result<()> {
        let mut buffer = vec![0u8; 65536];

        loop {
            let (len, src_addr) = self
                .socket
                .recv_from(&mut buffer)
                .await
                .map_err(|e| anyhow!("Failed to receive UDP packet: {}", e))?;

            // 只处理来自客户端的数据包
            if src_addr != self.client_addr {
                continue;
            }

            // 解析SOCKS5 UDP数据包
            let packet = &buffer[..len];
            if let Ok((target_addr, data)) = self.parse_udp_packet(packet) {
                // 转发数据包到目标地址
                if let Err(e) = self.forward_packet(&target_addr, &data).await {
                    tracing::warn!("Failed to forward UDP packet: {}", e);
                }
            }
        }
    }

    /// 解析SOCKS5 UDP数据包
    fn parse_udp_packet(&self, packet: &[u8]) -> Result<(Address, Vec<u8>)> {
        if packet.len() < 4 {
            return Err(anyhow!("UDP packet too short"));
        }

        let mut cursor = io::Cursor::new(packet);

        // 跳过保留字段和分片字段
        cursor.advance(3);

        let address_type = AddressType::from(cursor.get_u8());

        // 解析地址
        let address = match address_type {
            AddressType::Ipv4 => {
                if cursor.remaining() < 6 {
                    return Err(anyhow!("Invalid IPv4 address in UDP packet"));
                }
                let mut ip_bytes = [0u8; 4];
                cursor.copy_to_slice(&mut ip_bytes);
                let port = cursor.get_u16();
                let ip = Ipv4Addr::from(ip_bytes);
                Address::SocketAddr(SocketAddr::new(IpAddr::V4(ip), port))
            }
            AddressType::Ipv6 => {
                if cursor.remaining() < 18 {
                    return Err(anyhow!("Invalid IPv6 address in UDP packet"));
                }
                let mut ip_bytes = [0u8; 16];
                cursor.copy_to_slice(&mut ip_bytes);
                let port = cursor.get_u16();
                let ip = Ipv6Addr::from(ip_bytes);
                Address::SocketAddr(SocketAddr::new(IpAddr::V6(ip), port))
            }
            AddressType::Domain => {
                if cursor.remaining() < 1 {
                    return Err(anyhow!("Invalid domain address in UDP packet"));
                }
                let domain_len = cursor.get_u8() as usize;
                if cursor.remaining() < domain_len + 2 {
                    return Err(anyhow!("Invalid domain address in UDP packet"));
                }
                let mut domain_bytes = vec![0u8; domain_len];
                cursor.copy_to_slice(&mut domain_bytes);
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|e| anyhow!("Invalid domain name: {}", e))?;
                let port = cursor.get_u16();
                Address::DomainNameAddr(domain, port)
            }
        };

        // 剩余数据
        let pos = cursor.position() as usize;
        let data = cursor.into_inner()[pos..].to_vec();

        Ok((address, data))
    }

    /// 转发数据包
    async fn forward_packet(&self, target_addr: &Address, data: &[u8]) -> Result<()> {
        // 这里应该实现实际的转发逻辑
        // 为了简化，这里只是记录日志
        tracing::info!(
            "Forwarding UDP packet to {:?}, {} bytes",
            target_addr,
            data.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_auth_method_conversion() {
        assert_eq!(AuthMethod::from(0x00), AuthMethod::NoAuth);
        assert_eq!(AuthMethod::from(0x01), AuthMethod::Gssapi);
        assert_eq!(AuthMethod::from(0x02), AuthMethod::UserPass);
        assert_eq!(AuthMethod::from(0xFF), AuthMethod::NoAcceptable);
        assert_eq!(AuthMethod::from(0x99), AuthMethod::NoAcceptable);
    }

    #[test]
    fn test_command_conversion() {
        assert_eq!(Command::from(0x01), Command::Connect);
        assert_eq!(Command::from(0x02), Command::Bind);
        assert_eq!(Command::from(0x03), Command::UdpAssociate);
        assert_eq!(Command::from(0x99), Command::Connect);
    }

    #[test]
    fn test_response_code_conversion() {
        assert_eq!(ResponseCode::from(0x00), ResponseCode::Success);
        assert_eq!(ResponseCode::from(0x01), ResponseCode::GeneralFailure);
        assert_eq!(ResponseCode::from(0x05), ResponseCode::ConnectionRefused);
        assert_eq!(ResponseCode::from(0x99), ResponseCode::GeneralFailure);
    }

    #[test]
    fn test_address_type_conversion() {
        assert_eq!(AddressType::from(0x01), AddressType::Ipv4);
        assert_eq!(AddressType::from(0x03), AddressType::Domain);
        assert_eq!(AddressType::from(0x04), AddressType::Ipv6);
        assert_eq!(AddressType::from(0x99), AddressType::Domain);
    }

    #[test]
    fn test_socks5_server_creation() {
        let server = Socks5Server::new();
        assert_eq!(server.auth_methods, vec![AuthMethod::NoAuth]);
        assert!(server.username.is_none());
        assert!(server.password.is_none());
    }

    #[test]
    fn test_socks5_server_with_auth() {
        let server = Socks5Server::new().with_user_pass("user".to_string(), "pass".to_string());

        assert!(server.auth_methods.contains(&AuthMethod::UserPass));
        assert_eq!(server.username, Some("user".to_string()));
        assert_eq!(server.password, Some("pass".to_string()));
    }

    #[test]
    fn test_socks5_client_creation() {
        let client = Socks5Client::new();
        assert!(client.username.is_none());
        assert!(client.password.is_none());
    }

    #[test]
    fn test_socks5_client_with_auth() {
        let client = Socks5Client::new().with_user_pass("user".to_string(), "pass".to_string());

        assert_eq!(client.username, Some("user".to_string()));
        assert_eq!(client.password, Some("pass".to_string()));
    }

    #[test]
    fn test_socks5_request_creation() {
        let address = Address::from_str("example.com:80").unwrap();
        let request = Socks5Request {
            command: Command::Connect,
            address: address.clone(),
        };

        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.address, address);
    }

    #[test]
    fn test_socks5_response_creation() {
        let address = Address::from_str("192.168.1.1:8080").unwrap();
        let response = Socks5Response {
            code: ResponseCode::Success,
            address: address.clone(),
        };

        assert_eq!(response.code, ResponseCode::Success);
        assert_eq!(response.address, address);
    }

    #[tokio::test]
    async fn test_udp_packet_parsing() {
        let association = UdpAssociation {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            client_addr: "127.0.0.1:12345".parse().unwrap(),
        };

        // 构造一个简单的UDP数据包
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // 保留字段和分片字段
        packet.push(0x01); // IPv4地址类型
        packet.extend_from_slice(&[192, 168, 1, 1]); // IP地址
        packet.extend_from_slice(&80u16.to_be_bytes()); // 端口
        packet.extend_from_slice(b"Hello, World!"); // 数据

        let (address, data) = association.parse_udp_packet(&packet).unwrap();

        assert_eq!(address, Address::from_str("192.168.1.1:80").unwrap());
        assert_eq!(data, b"Hello, World!");
    }

    #[test]
    fn test_select_auth_method() {
        let server =
            Socks5Server::new().with_auth_methods(vec![AuthMethod::NoAuth, AuthMethod::UserPass]);

        // 客户端支持NoAuth
        let client_methods = vec![AuthMethod::NoAuth, AuthMethod::Gssapi];
        assert_eq!(
            server.select_auth_method(&client_methods),
            AuthMethod::NoAuth
        );

        // 客户端只支持UserPass
        let client_methods = vec![AuthMethod::UserPass, AuthMethod::Gssapi];
        assert_eq!(
            server.select_auth_method(&client_methods),
            AuthMethod::UserPass
        );

        // 客户端不支持任何服务器方法
        let client_methods = vec![AuthMethod::Gssapi];
        assert_eq!(
            server.select_auth_method(&client_methods),
            AuthMethod::NoAcceptable
        );
    }

    #[tokio::test]
    async fn test_tokio_optimized_handshake() {
        let server = Socks5Server::new().with_auth_methods(vec![AuthMethod::NoAuth]);

        // 模拟客户端握手请求数据
        let handshake_data = vec![
            SOCKS5_VERSION,           // 版本
            1,                        // 方法数量
            AuthMethod::NoAuth as u8, // NoAuth方法
        ];

        let mut cursor = Cursor::new(handshake_data);
        let result = server.handle_handshake(&mut cursor).await;

        assert!(result.is_ok(), "使用tokio优化的握手处理应该成功");
    }

    #[tokio::test]
    async fn test_tokio_optimized_request_parsing() {
        let server = Socks5Server::new();

        // 模拟SOCKS5连接请求数据
        let mut request_data = vec![
            SOCKS5_VERSION,          // 版本
            Command::Connect as u8,  // 连接命令
            0x00,                    // 保留字段
            AddressType::Ipv4 as u8, // IPv4地址类型
        ];
        request_data.extend_from_slice(&[192, 168, 1, 1]); // IP地址
        request_data.extend_from_slice(&8080u16.to_be_bytes()); // 端口

        let mut cursor = Cursor::new(request_data);
        let result = server.handle_request(&mut cursor).await;

        assert!(result.is_ok(), "使用tokio优化的请求解析应该成功");
        let request = result.unwrap();
        assert_eq!(request.command, Command::Connect);
        assert_eq!(
            request.address,
            Address::from_str("192.168.1.1:8080").unwrap()
        );
    }

    #[tokio::test]
    async fn test_tokio_optimized_response_sending() {
        let server = Socks5Server::new();
        let response = Socks5Response {
            code: ResponseCode::Success,
            address: Address::from_str("127.0.0.1:8080").unwrap(),
        };

        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        let result = server.send_response(&mut cursor, &response).await;

        assert!(result.is_ok(), "使用tokio优化的响应发送应该成功");

        // 验证响应数据格式
        assert_eq!(buffer[0], SOCKS5_VERSION); // 版本
        assert_eq!(buffer[1], ResponseCode::Success as u8); // 响应码
        assert_eq!(buffer[2], 0x00); // 保留字段
        assert_eq!(buffer[3], AddressType::Ipv4 as u8); // 地址类型
    }

    #[tokio::test]
    async fn test_udp_association_creation() {
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let client_addr = "127.0.0.1:12345".parse().unwrap();

        let association = UdpAssociation::new(bind_addr, client_addr).await.unwrap();

        assert!(association.local_addr().is_ok());
        assert_eq!(association.client_addr, client_addr);
    }
}
