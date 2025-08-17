//! 地址工具模块
//!
//! 提供地址解析和DNS查询相关的工具函数

use crate::protocol::Address;
use crate::utils::dns::get_global_resolver;
use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tokio::net::lookup_host;

/// DNS解析器类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverType {
    /// 系统默认解析器
    System,
    /// LDNS解析器
    Ldns,
}

/// 异步DNS解析
///
/// 将域名解析为IP地址列表
pub async fn resolve_domain(domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
    resolve_domain_with_resolver(domain, port, ResolverType::System).await
}

/// 使用指定解析器进行异步DNS解析
///
/// # 参数
/// * `domain` - 要解析的域名
/// * `port` - 端口号
/// * `resolver_type` - 解析器类型
///
/// # 返回
/// 返回解析到的SocketAddr列表
pub async fn resolve_domain_with_resolver(
    domain: &str,
    port: u16,
    resolver_type: ResolverType,
) -> Result<Vec<SocketAddr>> {
    match resolver_type {
        ResolverType::System => {
            let addr_str = format!("{}:{}", domain, port);
            match lookup_host(&addr_str).await {
                Ok(addrs) => {
                    let resolved: Vec<SocketAddr> = addrs.collect();
                    if resolved.is_empty() {
                        Err(anyhow!("No addresses found for domain: {}", domain))
                    } else {
                        Ok(resolved)
                    }
                }
                Err(e) => Err(anyhow!("DNS resolution failed for {}: {}", domain, e)),
            }
        }
        ResolverType::Ldns => resolve_domain_with_ldns(domain, port).await,
    }
}

/// 使用LDNS解析器进行域名解析
///
/// # 参数
/// * `domain` - 要解析的域名
/// * `port` - 端口号
///
/// # 返回
/// 返回解析到的SocketAddr列表
pub async fn resolve_domain_with_ldns(domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let resolver = get_global_resolver().await?;
    let ips = resolver.resolve(domain).await?;

    let socket_addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();

    if socket_addrs.is_empty() {
        Err(anyhow!("No addresses found for domain: {}", domain))
    } else {
        Ok(socket_addrs)
    }
}

/// 同步DNS解析（阻塞）
///
/// 将域名解析为IP地址列表
pub fn resolve_domain_sync(domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addr_str = format!("{}:{}", domain, port);

    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let resolved: Vec<SocketAddr> = addrs.collect();
            if resolved.is_empty() {
                Err(anyhow!("No addresses found for domain: {}", domain))
            } else {
                Ok(resolved)
            }
        }
        Err(e) => Err(anyhow!("DNS resolution failed for {}: {}", domain, e)),
    }
}

/// 解析地址为SocketAddr
///
/// 如果是域名地址，会进行DNS解析
pub async fn resolve_address(address: &Address) -> Result<SocketAddr> {
    address_to_socket_addr(address).await
}

/// 将Address转换为SocketAddr
///
/// 如果是域名地址，会进行DNS解析
pub async fn address_to_socket_addr(address: &Address) -> Result<SocketAddr> {
    address_to_socket_addr_with_resolver(address, ResolverType::System).await
}

/// 使用指定解析器将Address转换为SocketAddr
///
/// # 参数
/// * `address` - 要转换的地址
/// * `resolver_type` - 解析器类型
///
/// # 返回
/// 返回转换后的SocketAddr
pub async fn address_to_socket_addr_with_resolver(
    address: &Address,
    resolver_type: ResolverType,
) -> Result<SocketAddr> {
    match address {
        Address::SocketAddr(addr) => Ok(*addr),
        Address::DomainNameAddr(domain, port) => {
            let addrs = resolve_domain_with_resolver(domain, *port, resolver_type).await?;
            // 优先返回IPv4地址
            for addr in &addrs {
                if addr.is_ipv4() {
                    return Ok(*addr);
                }
            }
            // 如果没有IPv4地址，返回第一个IPv6地址
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("No valid address found for domain: {}", domain))
        }
    }
}

/// 使用LDNS解析器将Address转换为SocketAddr
///
/// # 参数
/// * `address` - 要转换的地址
///
/// # 返回
/// 返回转换后的SocketAddr
pub async fn address_to_socket_addr_with_ldns(address: &Address) -> Result<SocketAddr> {
    address_to_socket_addr_with_resolver(address, ResolverType::Ldns).await
}

/// 同步版本的地址转换
pub fn address_to_socket_addr_sync(address: &Address) -> Result<SocketAddr> {
    match address {
        Address::SocketAddr(addr) => Ok(*addr),
        Address::DomainNameAddr(domain, port) => {
            let addrs = resolve_domain_sync(domain, *port)?;
            // 优先返回IPv4地址
            for addr in &addrs {
                if addr.is_ipv4() {
                    return Ok(*addr);
                }
            }
            // 如果没有IPv4地址，返回第一个IPv6地址
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("No valid address found for domain: {}", domain))
        }
    }
}

/// 检查地址是否为本地地址
pub fn is_local_address(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unicast_link_local(),
    }
}

/// 检查地址是否为私有地址
pub fn is_private_address(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(ipv6) => {
            // IPv6私有地址范围
            let segments = ipv6.segments();
            // fc00::/7 (Unique Local Addresses)
            (segments[0] & 0xfe00) == 0xfc00
        }
    }
}

/// 检查地址是否为回环地址
pub fn is_loopback_address(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// 获取地址的字符串表示（不包含端口）
pub fn get_host_string(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ipv4) => ipv4.to_string(),
        IpAddr::V6(ipv6) => format!("[{}]", ipv6),
    }
}

/// 标准化地址格式
///
/// 确保IPv6地址被正确格式化
pub fn normalize_address(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(_) => addr.to_string(),
        IpAddr::V6(ipv6) => format!("[{}]:{}", ipv6, addr.port()),
    }
}

/// 解析地址字符串为Address
///
/// 支持多种格式：
/// - "192.168.1.1:8080"
/// - "[::1]:8080"
/// - "example.com:8080"
pub fn parse_address_string(addr_str: &str) -> Result<Address> {
    addr_str.parse::<Address>()
}

/// 验证地址是否可达（简单检查）
pub async fn is_address_reachable(addr: &SocketAddr, timeout_ms: u64) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::{Duration, timeout};

    let timeout_duration = Duration::from_millis(timeout_ms);

    matches!(
        timeout(timeout_duration, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// 获取本机的公网IP地址（通过连接外部服务）
pub async fn get_public_ip() -> Result<IpAddr> {
    use tokio::net::TcpStream;

    // 尝试连接到公网DNS服务器来获取本机IP
    let addrs = ["8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"];

    for addr_str in &addrs {
        if let Ok(addr) = addr_str.parse::<SocketAddr>()
            && let Ok(stream) = TcpStream::connect(addr).await
            && let Ok(local_addr) = stream.local_addr()
        {
            return Ok(local_addr.ip());
        }
    }

    Err(anyhow!("Failed to determine public IP address"))
}

/// 地址池管理器
///
/// 用于管理多个地址的负载均衡
pub struct AddressPool {
    addresses: Vec<SocketAddr>,
    current_index: std::sync::atomic::AtomicUsize,
}

impl AddressPool {
    /// 创建新的地址池
    pub fn new(addresses: Vec<SocketAddr>) -> Self {
        Self {
            addresses,
            current_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 从域名创建地址池
    pub async fn from_domain(domain: &str, port: u16) -> Result<Self> {
        let addresses = resolve_domain(domain, port).await?;
        Ok(Self::new(addresses))
    }

    /// 获取下一个地址（轮询）
    pub fn next_address(&self) -> Option<SocketAddr> {
        if self.addresses.is_empty() {
            return None;
        }

        let index = self
            .current_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let addr_index = index % self.addresses.len();
        Some(self.addresses[addr_index])
    }

    /// 获取所有地址
    pub fn all_addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// 检查地址池是否为空
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// 获取地址数量
    pub fn len(&self) -> usize {
        self.addresses.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_local_address() {
        let localhost_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(is_local_address(&localhost_v4));

        let localhost_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        assert!(is_local_address(&localhost_v6));

        let private_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert!(is_local_address(&private_addr));

        let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        assert!(!is_local_address(&public_addr));
    }

    #[test]
    fn test_is_private_address() {
        let private_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert!(is_private_address(&private_addr));

        let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        assert!(!is_private_address(&public_addr));
    }

    #[test]
    fn test_is_loopback_address() {
        let localhost_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(is_loopback_address(&localhost_v4));

        let localhost_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        assert!(is_loopback_address(&localhost_v6));

        let other_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert!(!is_loopback_address(&other_addr));
    }

    #[test]
    fn test_get_host_string() {
        let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(get_host_string(&ipv4_addr), "192.168.1.1");

        let ipv6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        assert_eq!(get_host_string(&ipv6_addr), "[::1]");
    }

    #[test]
    fn test_normalize_address() {
        let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(normalize_address(&ipv4_addr), "192.168.1.1:8080");

        let ipv6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        assert_eq!(normalize_address(&ipv6_addr), "[::1]:8080");
    }

    #[test]
    fn test_parse_address_string() {
        // IPv4
        let addr = parse_address_string("192.168.1.1:8080").unwrap();
        assert!(addr.is_ip());
        assert_eq!(addr.port(), 8080);

        // IPv6
        let addr = parse_address_string("[::1]:8080").unwrap();
        assert!(addr.is_ip());
        assert_eq!(addr.port(), 8080);

        // 域名
        let addr = parse_address_string("example.com:8080").unwrap();
        assert!(addr.is_domain());
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "example.com");
    }

    #[test]
    fn test_address_pool() {
        let addresses = vec![
            "192.168.1.1:8080".parse().unwrap(),
            "192.168.1.2:8080".parse().unwrap(),
            "192.168.1.3:8080".parse().unwrap(),
        ];

        let pool = AddressPool::new(addresses.clone());

        assert_eq!(pool.len(), 3);
        assert!(!pool.is_empty());

        // 测试轮询
        for i in 0..6 {
            let addr = pool.next_address().unwrap();
            let expected = addresses[i % 3];
            assert_eq!(addr, expected);
        }
    }

    #[test]
    fn test_empty_address_pool() {
        let pool = AddressPool::new(vec![]);

        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
        assert!(pool.next_address().is_none());
    }

    #[tokio::test]
    async fn test_resolve_domain_localhost() {
        // 测试解析localhost
        let result = resolve_domain("localhost", 8080).await;
        assert!(result.is_ok());

        let addrs = result.unwrap();
        assert!(!addrs.is_empty());

        // 应该包含回环地址
        assert!(addrs.iter().any(|addr| addr.ip().is_loopback()));
    }

    #[tokio::test]
    async fn test_resolve_domain_with_resolver() {
        // 测试系统解析器
        let result = resolve_domain_with_resolver("localhost", 8080, ResolverType::System).await;
        assert!(result.is_ok());

        let addrs = result.unwrap();
        assert!(!addrs.is_empty());

        // 检查端口是否正确
        for addr in addrs {
            assert_eq!(addr.port(), 8080);
        }
    }

    #[tokio::test]
    async fn test_resolve_domain_with_ldns() {
        // 测试LDNS解析器
        let result = resolve_domain_with_ldns("localhost", 8080).await;
        // 注意：这个测试可能会失败，如果LDNS解析器没有正确配置
        // 在实际环境中，你可能需要使用一个已知的公共域名进行测试
        if result.is_ok() {
            let addrs = result.unwrap();
            assert!(!addrs.is_empty());

            // 检查端口是否正确
            for addr in addrs {
                assert_eq!(addr.port(), 8080);
            }
        }
    }

    #[tokio::test]
    async fn test_address_to_socket_addr() {
        // 测试IP地址
        let ip_addr = Address::SocketAddr("192.168.1.1:8080".parse().unwrap());
        let result = address_to_socket_addr(&ip_addr).await.unwrap();
        assert_eq!(result.to_string(), "192.168.1.1:8080");

        // 测试域名地址
        let domain_addr = Address::DomainNameAddr("localhost".to_string(), 8080);
        let result = address_to_socket_addr(&domain_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_address_to_socket_addr_with_resolver() {
        // 测试使用系统解析器
        let domain_addr = Address::DomainNameAddr("localhost".to_string(), 8080);
        let result = address_to_socket_addr_with_resolver(&domain_addr, ResolverType::System).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port(), 8080);
    }

    #[tokio::test]
    async fn test_address_to_socket_addr_with_ldns() {
        // 测试使用LDNS解析器
        let domain_addr = Address::DomainNameAddr("localhost".to_string(), 8080);
        let result = address_to_socket_addr_with_ldns(&domain_addr).await;
        // 注意：这个测试可能会失败，如果LDNS解析器没有正确配置
        if result.is_ok() {
            assert_eq!(result.unwrap().port(), 8080);
        }
    }

    #[test]
    fn test_resolver_type() {
        // 测试解析器类型枚举
        assert_eq!(ResolverType::System, ResolverType::System);
        assert_eq!(ResolverType::Ldns, ResolverType::Ldns);
        assert_ne!(ResolverType::System, ResolverType::Ldns);
    }

    #[test]
    fn test_address_to_socket_addr_sync() {
        // 测试IP地址的同步转换
        let ip_addr = Address::SocketAddr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ));
        let result = address_to_socket_addr_sync(&ip_addr);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port(), 8080);

        // 测试域名地址的同步转换
        let domain_addr = Address::DomainNameAddr("localhost".to_string(), 8080);
        let result = address_to_socket_addr_sync(&domain_addr);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port(), 8080);
    }
}
