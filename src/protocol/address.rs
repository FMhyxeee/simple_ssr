//! 地址解析模块
//!
//! 处理Shadowsocks协议中的地址格式解析和序列化

use super::{
    read_exact, read_string, read_u8, read_u16_be, write_all, write_string, write_u8, write_u16_be,
};
use anyhow::{Result, anyhow};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 地址类型
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

/// 地址结构
///
/// 支持IPv4、IPv6和域名三种地址格式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Socket地址（IPv4或IPv6）
    SocketAddr(SocketAddr),
    /// 域名地址
    DomainNameAddr(String, u16),
}

impl Address {
    /// 从字节数组解析地址
    ///
    /// 返回(Address, 解析的字节数)
    pub fn parse_from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(data);
        let address = Self::read_from(&mut cursor)?;
        let bytes_read = cursor.position() as usize;
        Ok((address, bytes_read))
    }

    /// 从流中读取地址
    ///
    /// 地址格式：
    /// - IPv4: 0x01 + 4字节IP + 2字节端口
    /// - 域名: 0x03 + 1字节长度 + 域名 + 2字节端口
    /// - IPv6: 0x04 + 16字节IP + 2字节端口
    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let addr_type = AddressType::from(read_u8(reader)?);

        match addr_type {
            AddressType::Ipv4 => {
                let mut ip_bytes = [0u8; 4];
                read_exact(reader, &mut ip_bytes)?;
                let ip = Ipv4Addr::from(ip_bytes);
                let port = read_u16_be(reader)?;
                Ok(Address::SocketAddr(SocketAddr::new(IpAddr::V4(ip), port)))
            }
            AddressType::Domain => {
                let domain = read_string(reader)?;
                let port = read_u16_be(reader)?;
                Ok(Address::DomainNameAddr(domain, port))
            }
            AddressType::Ipv6 => {
                let mut ip_bytes = [0u8; 16];
                read_exact(reader, &mut ip_bytes)?;
                let ip = Ipv6Addr::from(ip_bytes);
                let port = read_u16_be(reader)?;
                Ok(Address::SocketAddr(SocketAddr::new(IpAddr::V6(ip), port)))
            }
        }
    }

    /// 将地址转换为字节数组
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write_to(&mut buf)?;
        Ok(buf)
    }

    /// 将地址写入流
    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        match self {
            Address::SocketAddr(addr) => match addr.ip() {
                IpAddr::V4(ip) => {
                    write_u8(writer, AddressType::Ipv4 as u8)?;
                    write_all(writer, &ip.octets())?;
                    write_u16_be(writer, addr.port())?;
                }
                IpAddr::V6(ip) => {
                    write_u8(writer, AddressType::Ipv6 as u8)?;
                    write_all(writer, &ip.octets())?;
                    write_u16_be(writer, addr.port())?;
                }
            },
            Address::DomainNameAddr(domain, port) => {
                write_u8(writer, AddressType::Domain as u8)?;
                write_string(writer, domain)?;
                write_u16_be(writer, *port)?;
            }
        }
        Ok(())
    }

    /// 获取序列化后的长度
    pub fn serialized_len(&self) -> usize {
        match self {
            Address::SocketAddr(addr) => {
                match addr.ip() {
                    IpAddr::V4(_) => 1 + 4 + 2,  // 类型 + IPv4 + 端口
                    IpAddr::V6(_) => 1 + 16 + 2, // 类型 + IPv6 + 端口
                }
            }
            Address::DomainNameAddr(domain, _) => {
                1 + 1 + domain.len() + 2 // 类型 + 长度 + 域名 + 端口
            }
        }
    }

    /// 获取端口号
    pub fn port(&self) -> u16 {
        match self {
            Address::SocketAddr(addr) => addr.port(),
            Address::DomainNameAddr(_, port) => *port,
        }
    }

    /// 获取主机部分的字符串表示
    pub fn host(&self) -> String {
        match self {
            Address::SocketAddr(addr) => addr.ip().to_string(),
            Address::DomainNameAddr(domain, _) => domain.clone(),
        }
    }

    /// 转换为字符串表示
    pub fn to_string(&self) -> String {
        match self {
            Address::SocketAddr(addr) => addr.to_string(),
            Address::DomainNameAddr(domain, port) => format!("{}:{}", domain, port),
        }
    }

    /// 从字符串解析地址
    ///
    /// 支持的格式：
    /// - "192.168.1.1:8080" (IPv4)
    /// - "[::1]:8080" (IPv6)
    /// - "example.com:8080" (域名)
    pub fn from_str(s: &str) -> Result<Self> {
        // 尝试解析为SocketAddr
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Address::SocketAddr(addr));
        }

        // 尝试解析为域名:端口格式
        if let Some(colon_pos) = s.rfind(':') {
            let host = &s[..colon_pos];
            let port_str = &s[colon_pos + 1..];

            if let Ok(port) = port_str.parse::<u16>() {
                // 检查是否为IPv6地址（包含方括号）
                if host.starts_with('[') && host.ends_with(']') {
                    let ipv6_str = &host[1..host.len() - 1];
                    if let Ok(ip) = ipv6_str.parse::<Ipv6Addr>() {
                        return Ok(Address::SocketAddr(SocketAddr::new(IpAddr::V6(ip), port)));
                    }
                }

                // 检查是否为IPv4地址
                if let Ok(ip) = host.parse::<Ipv4Addr>() {
                    return Ok(Address::SocketAddr(SocketAddr::new(IpAddr::V4(ip), port)));
                }

                // 作为域名处理
                return Ok(Address::DomainNameAddr(host.to_string(), port));
            }
        }

        Err(anyhow!("Invalid address format: {}", s))
    }

    /// 检查是否为IP地址
    pub fn is_ip(&self) -> bool {
        matches!(self, Address::SocketAddr(_))
    }

    /// 检查是否为域名
    pub fn is_domain(&self) -> bool {
        matches!(self, Address::DomainNameAddr(_, _))
    }

    /// 获取地址类型
    pub fn address_type(&self) -> AddressType {
        match self {
            Address::SocketAddr(addr) => match addr.ip() {
                IpAddr::V4(_) => AddressType::Ipv4,
                IpAddr::V6(_) => AddressType::Ipv6,
            },
            Address::DomainNameAddr(_, _) => AddressType::Domain,
        }
    }

    /// 异步解析为SocketAddr
    ///
    /// 对于域名地址，会进行DNS解析
    pub async fn to_socket_addr(&self) -> Result<SocketAddr> {
        match self {
            Address::SocketAddr(addr) => Ok(*addr),
            Address::DomainNameAddr(domain, port) => {
                use tokio::net::lookup_host;
                let addr_str = format!("{}:{}", domain, port);
                let mut addrs = lookup_host(&addr_str).await
                    .map_err(|e| anyhow!("DNS解析失败: {}", e))?;
                addrs.next()
                    .ok_or_else(|| anyhow!("DNS解析未返回任何地址"))
            }
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// 从SocketAddr创建Address
impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::SocketAddr(addr)
    }
}

/// 尝试转换为SocketAddr
impl TryFrom<Address> for SocketAddr {
    type Error = anyhow::Error;

    fn try_from(addr: Address) -> Result<Self> {
        match addr {
            Address::SocketAddr(socket_addr) => Ok(socket_addr),
            Address::DomainNameAddr(_, _) => {
                Err(anyhow!("Cannot convert domain name address to SocketAddr"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ipv4_address_serialization() {
        let addr = Address::SocketAddr("192.168.1.1:8080".parse().unwrap());

        let mut buf = Vec::new();
        addr.write_to(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed_addr = Address::read_from(&mut cursor).unwrap();

        assert_eq!(addr, parsed_addr);
    }

    #[test]
    fn test_ipv6_address_serialization() {
        let addr = Address::SocketAddr("[::1]:8080".parse().unwrap());

        let mut buf = Vec::new();
        addr.write_to(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed_addr = Address::read_from(&mut cursor).unwrap();

        assert_eq!(addr, parsed_addr);
    }

    #[test]
    fn test_domain_address_serialization() {
        let addr = Address::DomainNameAddr("example.com".to_string(), 8080);

        let mut buf = Vec::new();
        addr.write_to(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed_addr = Address::read_from(&mut cursor).unwrap();

        assert_eq!(addr, parsed_addr);
    }

    #[test]
    fn test_address_from_str() {
        // IPv4
        let addr = Address::from_str("192.168.1.1:8080").unwrap();
        assert!(addr.is_ip());
        assert_eq!(addr.port(), 8080);

        // IPv6
        let addr = Address::from_str("[::1]:8080").unwrap();
        assert!(addr.is_ip());
        assert_eq!(addr.port(), 8080);

        // 域名
        let addr = Address::from_str("example.com:8080").unwrap();
        assert!(addr.is_domain());
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "example.com");
    }

    #[test]
    fn test_address_serialized_len() {
        let ipv4_addr = Address::SocketAddr("192.168.1.1:8080".parse().unwrap());
        assert_eq!(ipv4_addr.serialized_len(), 7); // 1 + 4 + 2

        let ipv6_addr = Address::SocketAddr("[::1]:8080".parse().unwrap());
        assert_eq!(ipv6_addr.serialized_len(), 19); // 1 + 16 + 2

        let domain_addr = Address::DomainNameAddr("example.com".to_string(), 8080);
        assert_eq!(domain_addr.serialized_len(), 15); // 1 + 1 + 11 + 2
    }

    #[test]
    fn test_address_type() {
        let ipv4_addr = Address::SocketAddr("192.168.1.1:8080".parse().unwrap());
        assert_eq!(ipv4_addr.address_type(), AddressType::Ipv4);

        let ipv6_addr = Address::SocketAddr("[::1]:8080".parse().unwrap());
        assert_eq!(ipv6_addr.address_type(), AddressType::Ipv6);

        let domain_addr = Address::DomainNameAddr("example.com".to_string(), 8080);
        assert_eq!(domain_addr.address_type(), AddressType::Domain);
    }

    #[test]
    fn test_invalid_address_format() {
        assert!(Address::from_str("invalid").is_err());
        assert!(Address::from_str("192.168.1.1").is_err()); // 缺少端口
        assert!(Address::from_str("192.168.1.1:abc").is_err()); // 无效端口
    }

    #[test]
    fn test_address_display() {
        let ipv4_addr = Address::SocketAddr("192.168.1.1:8080".parse().unwrap());
        assert_eq!(format!("{}", ipv4_addr), "192.168.1.1:8080");

        let domain_addr = Address::DomainNameAddr("example.com".to_string(), 8080);
        assert_eq!(format!("{}", domain_addr), "example.com:8080");
    }
}
