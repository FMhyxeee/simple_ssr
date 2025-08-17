//! 协议检测器模块
//!
//! 实现TCP和UDP协议的自动检测功能

use crate::unified::{ProtocolType, UnifiedResult};
use log::{debug, warn};
use std::net::SocketAddr;
use tokio::time::{Duration, timeout};

/// 协议检测器
#[derive(Debug, Clone)]
pub struct ProtocolDetector {
    /// 检测超时时间
    timeout_duration: Duration,
    /// 是否启用详细日志
    verbose_logging: bool,
}

/// 检测结果
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// 检测到的协议类型
    pub protocol: ProtocolType,
    /// 客户端地址
    pub client_addr: SocketAddr,
    /// 初始数据（如果有）
    pub initial_data: Vec<u8>,
    /// 置信度 (0.0 - 1.0)
    pub confidence: f32,
}

impl ProtocolDetector {
    /// 创建新的协议检测器
    pub fn new(timeout_duration: Duration, verbose_logging: bool) -> Self {
        Self {
            timeout_duration,
            verbose_logging,
        }
    }

    /// 从原始套接字数据检测协议类型
    pub async fn detect_from_socket(
        &self,
        socket: &tokio::net::UdpSocket,
    ) -> UnifiedResult<DetectionResult> {
        let mut buffer = vec![0u8; 8192];

        match timeout(self.timeout_duration, socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, client_addr))) => {
                buffer.truncate(size);
                let protocol = self.detect_protocol_from_data(&buffer, client_addr);

                if self.verbose_logging {
                    debug!(
                        "检测到来自 {} 的 {} 协议数据，大小: {} 字节",
                        client_addr, protocol, size
                    );
                }

                let confidence = self.calculate_confidence(&buffer, protocol);
                UnifiedResult::Success(DetectionResult {
                    protocol,
                    client_addr,
                    initial_data: buffer,
                    confidence,
                })
            }
            Ok(Err(e)) => {
                warn!("套接字接收错误: {}", e);
                UnifiedResult::Error(format!("套接字接收错误: {}", e))
            }
            Err(_) => {
                if self.verbose_logging {
                    debug!("协议检测超时");
                }
                UnifiedResult::Error("协议检测超时".to_string())
            }
        }
    }

    /// 从数据包检测协议类型
    pub fn detect_protocol_from_data(&self, data: &[u8], client_addr: SocketAddr) -> ProtocolType {
        if data.is_empty() {
            return ProtocolType::Unknown;
        }

        // 检测HTTP协议
        if self.is_http_request(data) {
            if self.verbose_logging {
                debug!("检测到来自 {} 的HTTP请求", client_addr);
            }
            return ProtocolType::Http;
        }

        // 检测HTTPS协议（TLS握手）
        if self.is_https_request(data) {
            if self.verbose_logging {
                debug!("检测到来自 {} 的HTTPS/TLS握手", client_addr);
            }
            return ProtocolType::Https;
        }

        // 检测SOCKS5协议（通常用于TCP）
        if self.is_socks5_handshake(data) {
            if self.verbose_logging {
                debug!("检测到来自 {} 的SOCKS5握手，判定为TCP", client_addr);
            }
            return ProtocolType::Tcp;
        }

        // 检测Shadowsocks协议特征
        if self.is_shadowsocks_tcp(data) {
            if self.verbose_logging {
                debug!("检测到来自 {} 的Shadowsocks TCP数据", client_addr);
            }
            return ProtocolType::Tcp;
        }

        if self.is_shadowsocks_udp(data) {
            if self.verbose_logging {
                debug!("检测到来自 {} 的Shadowsocks UDP数据", client_addr);
            }
            return ProtocolType::Udp;
        }

        // 基于数据包大小和模式的启发式检测
        if self.is_likely_udp_packet(data) {
            if self.verbose_logging {
                debug!("基于启发式规则，判定来自 {} 的数据为UDP", client_addr);
            }
            return ProtocolType::Udp;
        }

        // 默认判定为TCP
        if self.verbose_logging {
            debug!("无法明确识别协议，默认判定来自 {} 的数据为TCP", client_addr);
        }
        ProtocolType::Tcp
    }

    /// 检测是否为HTTP请求
    /// 识别常见的HTTP方法：GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE
    fn is_http_request(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // 将数据转换为字符串进行检查
        let data_str = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 检查是否以HTTP方法开头
        let http_methods = [
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ",
        ];

        for method in &http_methods {
            if data_str.starts_with(method) {
                // 进一步验证是否包含HTTP版本信息
                if data_str.contains("HTTP/1.") || data_str.contains("HTTP/2") {
                    return true;
                }
                // 即使没有完整的HTTP版本信息，如果有HTTP方法也认为是HTTP请求
                return true;
            }
        }

        false
    }

    /// 检测是否为HTTPS请求（TLS握手包）
    /// 识别TLS ClientHello消息
    fn is_https_request(&self, data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }

        // TLS记录格式：
        // - 内容类型 (1字节): 0x16 表示握手
        // - 版本 (2字节): 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3)
        // - 长度 (2字节)
        // - 握手类型 (1字节): 0x01 表示ClientHello

        // 检查是否为TLS握手记录
        if data[0] != 0x16 {
            return false;
        }

        // 检查TLS版本
        let version = u16::from_be_bytes([data[1], data[2]]);
        if !(0x0301..=0x0304).contains(&version) {
            return false;
        }

        // 检查记录长度是否合理
        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_length == 0 || record_length > 16384 {
            return false;
        }

        // 检查是否为ClientHello消息
        if data.len() > 5 && data[5] == 0x01 {
            return true;
        }

        false
    }

    /// 检测是否为SOCKS5握手
    fn is_socks5_handshake(&self, data: &[u8]) -> bool {
        // SOCKS5握手：版本号(0x05) + 方法数量 + 方法列表
        data.len() >= 3 && data[0] == 0x05 && data[1] > 0 && data.len() >= (2 + data[1] as usize)
    }

    /// 检测是否为Shadowsocks TCP数据
    fn is_shadowsocks_tcp(&self, data: &[u8]) -> bool {
        // Shadowsocks TCP通常以地址类型开始
        if data.is_empty() {
            return false;
        }

        // 检查地址类型字段（解密后的第一个字节）
        // 0x01: IPv4, 0x03: 域名, 0x04: IPv6
        let addr_type = data[0];
        matches!(addr_type, 0x01 | 0x03 | 0x04)
    }

    /// 检测是否为Shadowsocks UDP数据
    fn is_shadowsocks_udp(&self, data: &[u8]) -> bool {
        // Shadowsocks UDP包通常较小且有特定的结构
        if data.len() < 10 || data.len() > 1500 {
            return false;
        }

        // UDP包通常以RSV(2字节) + FRAG(1字节) + ATYP(1字节)开始
        // RSV通常为0x0000
        data.len() >= 4 && data[0] == 0x00 && data[1] == 0x00
    }

    /// 基于启发式规则判断是否可能是UDP包
    fn is_likely_udp_packet(&self, data: &[u8]) -> bool {
        // UDP包通常较小
        if data.len() > 1400 {
            return false;
        }

        // 检查是否包含常见的UDP协议标识
        // 例如DNS查询、DHCP等
        if data.len() >= 12 {
            // DNS查询通常以特定模式开始
            let flags = u16::from_be_bytes([data[2], data[3]]);
            if (flags & 0x8000) == 0 && (flags & 0x7800) == 0 {
                return true;
            }
        }

        // 其他启发式规则可以在这里添加
        false
    }

    /// 检测TCP协议
    pub fn detect_tcp(&self, data: &[u8]) -> (ProtocolType, f32) {
        let protocol = if self.is_socks5_handshake(data) || self.is_shadowsocks_tcp(data) {
            ProtocolType::Tcp
        } else {
            ProtocolType::Unknown
        };
        let confidence = self.calculate_confidence(data, protocol);
        (protocol, confidence)
    }

    /// 检测UDP协议
    pub fn detect_udp(&self, data: &[u8]) -> (ProtocolType, f32) {
        let protocol = if self.is_shadowsocks_udp(data) || self.is_likely_udp_packet(data) {
            ProtocolType::Udp
        } else {
            ProtocolType::Unknown
        };
        let confidence = self.calculate_confidence(data, protocol);
        (protocol, confidence)
    }

    /// 计算检测置信度
    fn calculate_confidence(&self, data: &[u8], protocol: ProtocolType) -> f32 {
        match protocol {
            ProtocolType::Http => {
                if self.is_http_request(data) {
                    // 检查是否包含完整的HTTP版本信息
                    if let Ok(data_str) = std::str::from_utf8(data) {
                        if data_str.contains("HTTP/1.") || data_str.contains("HTTP/2") {
                            0.95 // 包含HTTP版本信息，非常确定
                        } else {
                            0.85 // 只有HTTP方法，较确定
                        }
                    } else {
                        0.70 // 基本确定
                    }
                } else {
                    0.50 // 不确定
                }
            }
            ProtocolType::Https => {
                if self.is_https_request(data) {
                    0.90 // TLS握手特征明确
                } else {
                    0.50 // 不确定
                }
            }
            ProtocolType::Tcp => {
                if self.is_socks5_handshake(data) {
                    0.95 // SOCKS5握手非常明确
                } else if self.is_shadowsocks_tcp(data) {
                    0.80 // Shadowsocks TCP特征较明确
                } else {
                    0.60 // 默认TCP判断
                }
            }
            ProtocolType::Udp => {
                if self.is_shadowsocks_udp(data) {
                    0.85 // Shadowsocks UDP特征较明确
                } else if self.is_likely_udp_packet(data) {
                    0.70 // 启发式UDP判断
                } else {
                    0.50 // 不确定
                }
            }
            ProtocolType::Unknown => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_socks5_detection() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        // SOCKS5握手包
        let socks5_data = vec![0x05, 0x01, 0x00];
        let addr = "127.0.0.1:1080".parse().unwrap();

        assert_eq!(
            detector.detect_protocol_from_data(&socks5_data, addr),
            ProtocolType::Tcp
        );
    }

    #[test]
    fn test_shadowsocks_tcp_detection() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        // Shadowsocks TCP数据（IPv4地址类型）
        let ss_tcp_data = vec![0x01, 0x7f, 0x00, 0x00, 0x01, 0x1f, 0x90];
        let addr = "127.0.0.1:8388".parse().unwrap();

        assert_eq!(
            detector.detect_protocol_from_data(&ss_tcp_data, addr),
            ProtocolType::Tcp
        );
    }

    #[test]
    fn test_shadowsocks_udp_detection() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        // Shadowsocks UDP数据
        let ss_udp_data = vec![0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x35];
        let addr = "127.0.0.1:8388".parse().unwrap();

        assert_eq!(
            detector.detect_protocol_from_data(&ss_udp_data, addr),
            ProtocolType::Udp
        );
    }

    #[test]
    fn test_http_detection() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);
        let addr = "127.0.0.1:8080".parse().unwrap();

        // 测试GET请求
        let get_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            detector.detect_protocol_from_data(get_request, addr),
            ProtocolType::Http
        );

        // 测试POST请求
        let post_request = b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
        assert_eq!(
            detector.detect_protocol_from_data(post_request, addr),
            ProtocolType::Http
        );

        // 测试不完整的HTTP请求（只有方法）
        let partial_request = b"GET /path";
        assert_eq!(
            detector.detect_protocol_from_data(partial_request, addr),
            ProtocolType::Http
        );
    }

    #[test]
    fn test_https_detection() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);
        let addr = "127.0.0.1:8443".parse().unwrap();

        // 模拟TLS 1.2 ClientHello握手包
        let tls12_handshake = vec![
            0x16, // 内容类型：握手
            0x03, 0x03, // TLS 1.2版本
            0x00, 0x20, // 记录长度
            0x01, // 握手类型：ClientHello
            // 后续数据...
            0x00, 0x00, 0x1c, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            detector.detect_protocol_from_data(&tls12_handshake, addr),
            ProtocolType::Https
        );

        // 模拟TLS 1.3 ClientHello握手包
        let tls13_handshake = vec![
            0x16, // 内容类型：握手
            0x03, 0x04, // TLS 1.3版本
            0x00, 0x18, // 记录长度
            0x01, // 握手类型：ClientHello
            // 后续数据...
            0x00, 0x00, 0x14, 0x03, 0x04,
        ];
        assert_eq!(
            detector.detect_protocol_from_data(&tls13_handshake, addr),
            ProtocolType::Https
        );
    }

    #[test]
    fn test_http_methods() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        let methods = [
            "GET /",
            "POST /api",
            "PUT /resource",
            "DELETE /item",
            "HEAD /info",
            "OPTIONS /",
            "PATCH /update",
            "TRACE /debug",
        ];

        for method in &methods {
            let request = method.as_bytes();
            assert!(
                detector.is_http_request(request),
                "Failed to detect HTTP method: {}",
                method
            );
        }
    }

    #[test]
    fn test_tls_versions() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        // 测试不同TLS版本
        let versions = [
            (0x03, 0x01), // TLS 1.0
            (0x03, 0x02), // TLS 1.1
            (0x03, 0x03), // TLS 1.2
            (0x03, 0x04), // TLS 1.3
        ];

        for (major, minor) in &versions {
            let tls_handshake = vec![
                0x16, // 内容类型：握手
                *major, *minor, // TLS版本
                0x00, 0x10, // 记录长度
                0x01, // 握手类型：ClientHello
                0x00, 0x00, 0x0c, // 后续数据
            ];
            assert!(
                detector.is_https_request(&tls_handshake),
                "Failed to detect TLS {}.{}",
                major,
                minor
            );
        }
    }

    #[test]
    fn test_confidence_calculation() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        // 测试HTTP置信度
        let http_with_version = b"GET / HTTP/1.1\r\n";
        let confidence = detector.calculate_confidence(http_with_version, ProtocolType::Http);
        assert!(confidence >= 0.95);

        let http_without_version = b"GET /path";
        let confidence = detector.calculate_confidence(http_without_version, ProtocolType::Http);
        assert!((0.85..0.95).contains(&confidence));

        // 测试HTTPS置信度
        let tls_handshake = vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x01];
        let confidence = detector.calculate_confidence(&tls_handshake, ProtocolType::Https);
        assert!(confidence >= 0.90);

        // 测试其他协议
        let socks5_data = vec![0x05, 0x01, 0x00];
        let confidence = detector.calculate_confidence(&socks5_data, ProtocolType::Tcp);
        assert!(confidence > 0.9);

        let unknown_data = vec![0xff, 0xff, 0xff];
        let confidence = detector.calculate_confidence(&unknown_data, ProtocolType::Unknown);
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn test_http_https_confidence() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        // HTTP请求置信度测试
        let http_data = b"GET /test HTTP/1.1\r\n";
        let confidence = detector.calculate_confidence(http_data, ProtocolType::Http);
        assert!(confidence >= 0.9);

        // HTTPS握手置信度测试
        let https_data = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x01];
        let confidence = detector.calculate_confidence(&https_data, ProtocolType::Https);
        assert!(confidence >= 0.90);
    }
}
