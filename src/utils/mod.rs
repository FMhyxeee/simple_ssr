//! 工具模块
//!
//! 提供各种实用工具函数

pub mod address;
pub mod dns;

pub use address::*;
pub use dns::*;

use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{io::AsyncWriteExt, time::timeout};

/// 获取当前时间戳（毫秒）
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 获取当前时间戳（秒）
pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 带超时的异步操作
pub async fn with_timeout<F, T>(duration: Duration, future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", duration)),
    }
}

/// 带超时的Future包装器
pub async fn timeout_future<F, T>(duration: Duration, future: F) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    match timeout(duration, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", duration)),
    }
}

/// 格式化字节大小
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// 计算传输速率
pub fn format_speed(bytes: u64, duration: Duration) -> String {
    if duration.is_zero() {
        return "0 B/s".to_string();
    }

    let bytes_per_sec = bytes as f64 / duration.as_secs_f64();
    format!("{}/s", format_bytes(bytes_per_sec as u64))
}

/// 验证端口号是否有效
pub fn is_valid_port(port: u16) -> bool {
    port > 0
}

/// 验证IP地址字符串
pub fn is_valid_ip(ip: &str) -> bool {
    use std::net::IpAddr;
    ip.parse::<IpAddr>().is_ok()
}

/// 验证域名格式
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // 检查是否包含无效字符
    if domain.contains("//") || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    // 检查每个标签
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // 标签不能以连字符开始或结束
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        // 检查字符是否有效（字母、数字、连字符）
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// 生成随机字符串
pub fn random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 安全地关闭TCP流
pub async fn safe_shutdown(stream: &mut tokio::net::TcpStream) {
    let _ = stream.shutdown().await;
}

/// 复制数据流（双向）
pub async fn copy_bidirectional(
    mut left: tokio::net::TcpStream,
    mut right: tokio::net::TcpStream,
) -> Result<(u64, u64)> {
    tokio::io::copy_bidirectional(&mut left, &mut right)
        .await
        .map_err(|e| anyhow::anyhow!("Bidirectional copy failed: {}", e))
}

/// 复制数据流（双向）并返回统计信息
/// 这是copy_bidirectional的别名，用于兼容性
pub async fn copy_bidirectional_with_stats(
    left: &mut tokio::net::TcpStream,
    right: &mut tokio::net::TcpStream,
) -> Result<(u64, u64)> {
    tokio::io::copy_bidirectional(left, right)
        .await
        .map_err(|e| anyhow::anyhow!("Bidirectional copy with stats failed: {}", e))
}

/// 带超时的双向复制数据流
pub async fn copy_bidirectional_with_timeout(
    mut left: tokio::net::TcpStream,
    mut right: tokio::net::TcpStream,
    timeout_duration: Duration,
) -> Result<(u64, u64)> {
    let copy_future = async { tokio::io::copy_bidirectional(&mut left, &mut right).await };

    timeout_future(timeout_duration, copy_future)
        .await?
        .map_err(|e| anyhow::anyhow!("Copy bidirectional with timeout failed: {}", e))
}

/// 限制缓冲区大小的复制操作
pub async fn copy_with_buffer_limit(
    reader: &mut (dyn tokio::io::AsyncRead + Unpin),
    writer: &mut (dyn tokio::io::AsyncWrite + Unpin),
    buffer_size: usize,
) -> Result<u64> {
    let mut buffer = vec![0u8; buffer_size];
    let mut total_copied = 0u64;

    loop {
        let bytes_read = tokio::io::AsyncReadExt::read(reader, &mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        tokio::io::AsyncWriteExt::write_all(writer, &buffer[..bytes_read]).await?;
        total_copied += bytes_read as u64;
    }

    Ok(total_copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_current_timestamp() {
        let ts_ms = current_timestamp_ms();
        let ts_secs = current_timestamp_secs();

        assert!(ts_ms > 0);
        assert!(ts_secs > 0);
        assert!(ts_ms / 1000 >= ts_secs - 1); // 允许1秒误差
    }

    #[tokio::test]
    async fn test_with_timeout_success() {
        let result = with_timeout(Duration::from_millis(100), async {
            Ok::<i32, anyhow::Error>(42)
        })
        .await;

        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_with_timeout_failure() {
        let result = with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<i32, anyhow::Error>(42)
        })
        .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_format_speed() {
        let duration = Duration::from_secs(1);
        assert_eq!(format_speed(1024, duration), "1.00 KB/s");

        let duration = Duration::from_secs(2);
        assert_eq!(format_speed(2048, duration), "1.00 KB/s");

        assert_eq!(format_speed(1024, Duration::ZERO), "0 B/s");
    }

    #[test]
    fn test_is_valid_port() {
        assert!(!is_valid_port(0));
        assert!(is_valid_port(1));
        assert!(is_valid_port(8080));
        assert!(is_valid_port(65535));
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("invalid"));
        assert!(!is_valid_ip("256.256.256.256"));
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("test-domain.co.uk"));

        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example.com."));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
        assert!(!is_valid_domain("example.com//path"));
    }

    #[test]
    fn test_random_string() {
        let s1 = random_string(10);
        let s2 = random_string(10);

        assert_eq!(s1.len(), 10);
        assert_eq!(s2.len(), 10);
        assert_ne!(s1, s2); // 极小概率相同

        // 检查字符是否都是有效的
        assert!(s1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_random_string_empty() {
        let s = random_string(0);
        assert_eq!(s.len(), 0);
        assert_eq!(s, "");
    }
}
