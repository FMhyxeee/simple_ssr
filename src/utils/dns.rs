//! DNS解析模块
//!
//! 提供基于trust-dns-resolver的DNS解析功能，并使用LRU缓存来提高性能

use anyhow::{Result, anyhow};
use lru::LruCache;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

/// DNS缓存条目
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// 解析结果
    ips: Vec<IpAddr>,
    /// 缓存时间
    cached_at: Instant,
    /// TTL（生存时间）
    ttl: Duration,
}

impl DnsCacheEntry {
    /// 创建新的缓存条目
    fn new(ips: Vec<IpAddr>, ttl: Duration) -> Self {
        Self {
            ips,
            cached_at: Instant::now(),
            ttl,
        }
    }

    /// 检查缓存是否过期
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// LDNS解析器配置
#[derive(Debug, Clone)]
pub struct LdnsConfig {
    /// 缓存大小
    pub cache_size: usize,
    /// 默认TTL
    pub default_ttl: Duration,
    /// 超时时间
    pub timeout: Duration,
    /// 重试次数
    pub retry_attempts: usize,
    /// 自定义DNS服务器
    pub custom_servers: Vec<SocketAddr>,
}

impl Default for LdnsConfig {
    fn default() -> Self {
        Self {
            cache_size: 1000,
            default_ttl: Duration::from_secs(300), // 5分钟
            timeout: Duration::from_secs(5),
            retry_attempts: 3,
            custom_servers: vec![],
        }
    }
}

/// LDNS解析器
///
/// 提供DNS解析功能，支持LRU缓存
pub struct LdnsResolver {
    /// 异步DNS解析器
    resolver: TokioAsyncResolver,
    /// LRU缓存
    cache: Arc<RwLock<LruCache<String, DnsCacheEntry>>>,
    /// 配置
    config: LdnsConfig,
    /// 统计信息
    stats: Arc<Mutex<ResolverStats>>,
}

/// 解析器统计信息
#[derive(Debug, Default)]
pub struct ResolverStats {
    /// 总查询次数
    pub total_queries: u64,
    /// 缓存命中次数
    pub cache_hits: u64,
    /// 缓存未命中次数
    pub cache_misses: u64,
    /// 解析失败次数
    pub resolution_failures: u64,
}

impl ResolverStats {
    /// 获取缓存命中率
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_queries as f64
        }
    }
}

impl LdnsResolver {
    /// 创建新的LDNS解析器
    ///
    /// # 参数
    /// * `config` - 解析器配置
    ///
    /// # 返回
    /// 返回配置好的解析器实例
    pub async fn new(config: LdnsConfig) -> Result<Self> {
        let resolver = if config.custom_servers.is_empty() {
            // 使用系统默认DNS配置
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        } else {
            // 使用自定义DNS服务器
            let mut resolver_config = ResolverConfig::new();
            for server in &config.custom_servers {
                resolver_config.add_name_server(NameServerConfig {
                    socket_addr: *server,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                });
            }

            let mut opts = ResolverOpts::default();
            opts.timeout = config.timeout;
            opts.attempts = config.retry_attempts;

            TokioAsyncResolver::tokio(resolver_config, opts)
        };

        let cache = Arc::new(RwLock::new(LruCache::new(
            std::num::NonZeroUsize::new(config.cache_size)
                .ok_or_else(|| anyhow!("Cache size must be greater than 0"))?,
        )));

        Ok(Self {
            resolver,
            cache,
            config,
            stats: Arc::new(Mutex::new(ResolverStats::default())),
        })
    }

    /// 使用默认配置创建解析器
    pub async fn with_default_config() -> Result<Self> {
        Self::new(LdnsConfig::default()).await
    }

    /// 解析域名为IP地址列表
    ///
    /// # 参数
    /// * `domain` - 要解析的域名
    ///
    /// # 返回
    /// 返回解析到的IP地址列表
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // 更新统计信息
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_queries += 1;
        }

        // 检查缓存
        if let Some(cached_result) = self.get_from_cache(domain).await {
            let mut stats = self.stats.lock().unwrap();
            stats.cache_hits += 1;
            return Ok(cached_result);
        }

        // 缓存未命中，进行DNS查询
        {
            let mut stats = self.stats.lock().unwrap();
            stats.cache_misses += 1;
        }

        match self.resolver.lookup_ip(domain).await {
            Ok(lookup_result) => {
                let ips: Vec<IpAddr> = lookup_result.iter().collect();

                // 使用默认TTL
                let ttl = self.config.default_ttl;

                // 存入缓存
                self.put_to_cache(domain, &ips, ttl).await;

                Ok(ips)
            }
            Err(e) => {
                let mut stats = self.stats.lock().unwrap();
                stats.resolution_failures += 1;
                Err(anyhow!("DNS resolution failed for {}: {}", domain, e))
            }
        }
    }

    /// 解析域名为SocketAddr
    ///
    /// # 参数
    /// * `domain` - 要解析的域名
    /// * `port` - 端口号
    ///
    /// # 返回
    /// 返回第一个解析到的SocketAddr（优先IPv4）
    pub async fn resolve_to_socket_addr(&self, domain: &str, port: u16) -> Result<SocketAddr> {
        let ips = self.resolve(domain).await?;

        // 优先返回IPv4地址
        for ip in &ips {
            if ip.is_ipv4() {
                return Ok(SocketAddr::new(*ip, port));
            }
        }

        // 如果没有IPv4地址，返回第一个IPv6地址
        ips.into_iter()
            .next()
            .map(|ip| SocketAddr::new(ip, port))
            .ok_or_else(|| anyhow!("No valid IP address found for domain: {}", domain))
    }

    /// 从缓存中获取结果
    async fn get_from_cache(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.write().await;

        if let Some(entry) = cache.get(domain) {
            if !entry.is_expired() {
                return Some(entry.ips.clone());
            } else {
                // 缓存过期，移除
                cache.pop(domain);
            }
        }

        None
    }

    /// 将结果存入缓存
    async fn put_to_cache(&self, domain: &str, ips: &[IpAddr], ttl: Duration) {
        let mut cache = self.cache.write().await;
        let entry = DnsCacheEntry::new(ips.to_vec(), ttl);
        cache.put(domain.to_string(), entry);
    }

    /// 清空缓存
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// 获取缓存大小
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> ResolverStats {
        let stats = self.stats.lock().unwrap();
        ResolverStats {
            total_queries: stats.total_queries,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            resolution_failures: stats.resolution_failures,
        }
    }

    /// 重置统计信息
    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock().unwrap();
        *stats = ResolverStats::default();
    }

    /// 预热缓存
    ///
    /// # 参数
    /// * `domains` - 要预热的域名列表
    pub async fn warmup_cache(&self, domains: &[String]) -> Result<()> {
        for domain in domains {
            if let Err(e) = self.resolve(domain).await {
                log::warn!("Failed to warmup cache for domain {}: {}", domain, e);
            }
        }
        Ok(())
    }
}

/// 全局DNS解析器实例
static GLOBAL_RESOLVER: tokio::sync::OnceCell<LdnsResolver> = tokio::sync::OnceCell::const_new();

/// 获取全局DNS解析器实例
///
/// # 返回
/// 返回全局解析器实例的引用
pub async fn get_global_resolver() -> Result<&'static LdnsResolver> {
    GLOBAL_RESOLVER
        .get_or_try_init(|| async { LdnsResolver::with_default_config().await })
        .await
}

/// 初始化全局DNS解析器
///
/// # 参数
/// * `config` - 解析器配置
pub async fn init_global_resolver(config: LdnsConfig) -> Result<()> {
    let resolver = LdnsResolver::new(config).await?;
    GLOBAL_RESOLVER
        .set(resolver)
        .map_err(|_| anyhow!("Global resolver already initialized"))?;
    Ok(())
}

/// 便捷函数：使用LDNS解析域名
///
/// # 参数
/// * `domain` - 要解析的域名
///
/// # 返回
/// 返回解析到的IP地址列表
pub async fn ldns_resolve_domain(domain: &str) -> Result<Vec<IpAddr>> {
    let resolver = get_global_resolver().await?;
    resolver.resolve(domain).await
}

/// 便捷函数：使用LDNS解析域名为SocketAddr
///
/// # 参数
/// * `domain` - 要解析的域名
/// * `port` - 端口号
///
/// # 返回
/// 返回解析到的SocketAddr
pub async fn ldns_resolve_domain_to_socket_addr(domain: &str, port: u16) -> Result<SocketAddr> {
    let resolver = get_global_resolver().await?;
    resolver.resolve_to_socket_addr(domain, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ldns_resolver_creation() {
        let config = LdnsConfig::default();
        let resolver = LdnsResolver::new(config).await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let resolver = LdnsResolver::with_default_config().await.unwrap();
        let result = resolver.resolve("localhost").await;
        assert!(result.is_ok());

        let ips = result.unwrap();
        assert!(!ips.is_empty());
        assert!(ips.iter().any(|ip| ip.is_loopback()));
    }

    #[tokio::test]
    async fn test_resolve_to_socket_addr() {
        let resolver = LdnsResolver::with_default_config().await.unwrap();
        let result = resolver.resolve_to_socket_addr("localhost", 8080).await;
        assert!(result.is_ok());

        let addr = result.unwrap();
        assert_eq!(addr.port(), 8080);
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let resolver = LdnsResolver::with_default_config().await.unwrap();

        // 第一次解析
        let result1 = resolver.resolve("localhost").await.unwrap();
        let stats1 = resolver.get_stats();
        assert_eq!(stats1.cache_misses, 1);
        assert_eq!(stats1.cache_hits, 0);

        // 第二次解析（应该命中缓存）
        let result2 = resolver.resolve("localhost").await.unwrap();
        let stats2 = resolver.get_stats();
        assert_eq!(stats2.cache_hits, 1);

        // 结果应该相同
        assert_eq!(result1, result2);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = LdnsConfig {
            default_ttl: Duration::from_millis(100), // 很短的TTL
            ..Default::default()
        };

        let resolver = LdnsResolver::new(config).await.unwrap();

        // 第一次解析
        resolver.resolve("localhost").await.unwrap();

        // 等待缓存过期
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 再次解析（缓存应该已过期）
        resolver.resolve("localhost").await.unwrap();
        let stats = resolver.get_stats();
        assert_eq!(stats.cache_misses, 2); // 两次都是缓存未命中
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let resolver = LdnsResolver::with_default_config().await.unwrap();

        // 添加一些缓存条目
        resolver.resolve("localhost").await.unwrap();
        assert_eq!(resolver.cache_size().await, 1);

        // 清空缓存
        resolver.clear_cache().await;
        assert_eq!(resolver.cache_size().await, 0);
    }

    #[tokio::test]
    async fn test_stats_functionality() {
        let resolver = LdnsResolver::with_default_config().await.unwrap();

        // 进行一些解析
        resolver.resolve("localhost").await.unwrap();
        resolver.resolve("localhost").await.unwrap(); // 缓存命中

        let stats = resolver.get_stats();
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hit_rate(), 0.5);

        // 重置统计
        resolver.reset_stats();
        let stats_after_reset = resolver.get_stats();
        assert_eq!(stats_after_reset.total_queries, 0);
    }

    #[tokio::test]
    async fn test_custom_dns_servers() {
        let config = LdnsConfig {
            custom_servers: vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()],
            ..Default::default()
        };

        let resolver = LdnsResolver::new(config).await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_global_resolver() {
        // 测试全局解析器
        let result = ldns_resolve_domain("localhost").await;
        assert!(result.is_ok());

        let result = ldns_resolve_domain_to_socket_addr("localhost", 8080).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_warmup_cache() {
        let resolver = LdnsResolver::with_default_config().await.unwrap();

        let domains = vec!["localhost".to_string()];
        let result = resolver.warmup_cache(&domains).await;
        assert!(result.is_ok());

        // 验证缓存中有条目
        assert!(resolver.cache_size().await > 0);
    }

    #[test]
    fn test_dns_cache_entry() {
        let ips = vec!["127.0.0.1".parse().unwrap()];
        let ttl = Duration::from_secs(300);
        let entry = DnsCacheEntry::new(ips.clone(), ttl);

        assert_eq!(entry.ips, ips);
        assert_eq!(entry.ttl, ttl);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_ldns_config_default() {
        let config = LdnsConfig::default();
        assert_eq!(config.cache_size, 1000);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.retry_attempts, 3);
        assert!(config.custom_servers.is_empty());
    }

    #[test]
    fn test_resolver_stats() {
        let mut stats = ResolverStats::default();
        assert_eq!(stats.cache_hit_rate(), 0.0);

        stats.total_queries = 10;
        stats.cache_hits = 7;
        assert_eq!(stats.cache_hit_rate(), 0.7);
    }
}
