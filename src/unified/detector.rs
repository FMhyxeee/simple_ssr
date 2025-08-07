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
    fn test_confidence_calculation() {
        let detector = ProtocolDetector::new(Duration::from_secs(5), false);

        let socks5_data = vec![0x05, 0x01, 0x00];
        let confidence = detector.calculate_confidence(&socks5_data, ProtocolType::Tcp);
        assert!(confidence > 0.9);

        let unknown_data = vec![0xff, 0xff, 0xff];
        let confidence = detector.calculate_confidence(&unknown_data, ProtocolType::Unknown);
        assert_eq!(confidence, 0.0);
    }
}
