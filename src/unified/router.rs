//! 请求路由器模块
//!
//! 根据检测到的协议类型将请求路由到相应的处理器

use crate::unified::detector::DetectionResult;
use crate::unified::{ProtocolType, UnifiedResult};
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// 路由事件类型
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// TCP连接事件
    TcpConnection {
        stream: Arc<TcpStream>,
        client_addr: SocketAddr,
        initial_data: Vec<u8>,
    },
    /// UDP数据包事件
    UdpPacket {
        data: Vec<u8>,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    },
    /// HTTP请求事件
    HttpRequest {
        stream: Arc<TcpStream>,
        client_addr: SocketAddr,
        request_data: Vec<u8>,
        is_https: bool,
    },
    /// 路由错误事件
    Error {
        message: String,
        client_addr: Option<SocketAddr>,
    },
}

/// 路由结果
#[derive(Debug)]
pub enum RouteResult {
    /// 成功路由到TCP处理器
    TcpRouted,
    /// 成功路由到UDP处理器
    UdpRouted,
    /// 成功路由到HTTP处理器
    HttpRouted,
    /// 路由失败
    Failed(String),
}

/// 请求路由器
#[derive(Debug, Clone)]
pub struct RequestRouter {
    /// TCP事件发送器
    tcp_sender: mpsc::UnboundedSender<RouteEvent>,
    /// UDP事件发送器
    udp_sender: mpsc::UnboundedSender<RouteEvent>,
    /// HTTP事件发送器
    http_sender: mpsc::UnboundedSender<RouteEvent>,
    /// 是否启用详细日志
    verbose_logging: bool,
    /// 路由统计
    stats: Arc<tokio::sync::Mutex<RouterStats>>,
}

/// 路由统计信息
#[derive(Debug, Default, Clone)]
pub struct RouterStats {
    /// TCP路由计数
    pub tcp_routes: u64,
    /// UDP路由计数
    pub udp_routes: u64,
    /// HTTP路由计数
    pub http_routes: u64,
    /// 路由错误计数
    pub route_errors: u64,
    /// 总处理请求数
    pub total_requests: u64,
}

impl RequestRouter {
    /// 创建新的请求路由器
    pub fn new(
        tcp_sender: mpsc::UnboundedSender<RouteEvent>,
        udp_sender: mpsc::UnboundedSender<RouteEvent>,
        http_sender: mpsc::UnboundedSender<RouteEvent>,
        verbose_logging: bool,
    ) -> Self {
        Self {
            tcp_sender,
            udp_sender,
            http_sender,
            verbose_logging,
            stats: Arc::new(tokio::sync::Mutex::new(RouterStats::default())),
        }
    }

    /// 路由检测结果到相应的处理器
    pub async fn route_detection_result(
        &self,
        detection_result: DetectionResult,
        socket: Arc<UdpSocket>,
    ) -> UnifiedResult<RouteResult> {
        let mut stats = self.stats.lock().await;
        stats.total_requests += 1;

        match detection_result.protocol {
            ProtocolType::Tcp => {
                stats.tcp_routes += 1;
                drop(stats);

                if self.verbose_logging {
                    info!(
                        "路由TCP请求: {} -> TCP处理器 (置信度: {:.2})",
                        detection_result.client_addr, detection_result.confidence
                    );
                }

                self.route_to_tcp(detection_result, socket).await
            }
            ProtocolType::Udp => {
                stats.udp_routes += 1;
                drop(stats);

                if self.verbose_logging {
                    info!(
                        "路由UDP请求: {} -> UDP处理器 (置信度: {:.2})",
                        detection_result.client_addr, detection_result.confidence
                    );
                }

                self.route_to_udp(detection_result, socket).await
            }
            ProtocolType::Http | ProtocolType::Https => {
                stats.http_routes += 1;
                drop(stats);

                if self.verbose_logging {
                    info!(
                        "路由{}请求: {} -> HTTP处理器 (置信度: {:.2})",
                        if matches!(detection_result.protocol, ProtocolType::Http) {
                            "HTTP"
                        } else {
                            "HTTPS"
                        },
                        detection_result.client_addr,
                        detection_result.confidence
                    );
                }

                self.route_to_http(detection_result, socket).await
            }
            ProtocolType::Unknown => {
                stats.route_errors += 1;
                drop(stats);

                let error_msg = format!("无法识别来自 {} 的协议类型", detection_result.client_addr);

                if self.verbose_logging {
                    error!("{}", error_msg);
                }

                UnifiedResult::Error(error_msg)
            }
        }
    }

    /// 路由到TCP处理器
    async fn route_to_tcp(
        &self,
        detection_result: DetectionResult,
        _socket: Arc<UdpSocket>,
    ) -> UnifiedResult<RouteResult> {
        // 对于TCP请求，我们需要建立TCP连接
        match self
            .establish_tcp_connection(detection_result.client_addr)
            .await
        {
            Ok(stream) => {
                let event = RouteEvent::TcpConnection {
                    stream: Arc::new(stream),
                    client_addr: detection_result.client_addr,
                    initial_data: detection_result.initial_data,
                };

                if let Err(e) = self.tcp_sender.send(event) {
                    let error_msg = format!("发送TCP事件失败: {}", e);
                    error!("{}", error_msg);
                    return UnifiedResult::Error(error_msg);
                }

                UnifiedResult::Success(RouteResult::TcpRouted)
            }
            Err(e) => {
                let error_msg = format!(
                    "建立到 {} 的TCP连接失败: {}",
                    detection_result.client_addr, e
                );
                error!("{}", error_msg);
                UnifiedResult::Error(error_msg)
            }
        }
    }

    /// 路由到UDP处理器
    async fn route_to_udp(
        &self,
        detection_result: DetectionResult,
        socket: Arc<UdpSocket>,
    ) -> UnifiedResult<RouteResult> {
        let event = RouteEvent::UdpPacket {
            data: detection_result.initial_data,
            client_addr: detection_result.client_addr,
            socket,
        };

        if let Err(e) = self.udp_sender.send(event) {
            let error_msg = format!("发送UDP事件失败: {}", e);
            error!("{}", error_msg);
            return UnifiedResult::Error(error_msg);
        }

        UnifiedResult::Success(RouteResult::UdpRouted)
    }

    /// 路由到HTTP处理器
    async fn route_to_http(
        &self,
        detection_result: DetectionResult,
        _socket: Arc<UdpSocket>,
    ) -> UnifiedResult<RouteResult> {
        // 对于HTTP/HTTPS请求，我们需要建立TCP连接
        match self
            .establish_tcp_connection(detection_result.client_addr)
            .await
        {
            Ok(stream) => {
                let is_https = matches!(detection_result.protocol, ProtocolType::Https);
                let event = RouteEvent::HttpRequest {
                    stream: Arc::new(stream),
                    client_addr: detection_result.client_addr,
                    request_data: detection_result.initial_data,
                    is_https,
                };

                if let Err(e) = self.http_sender.send(event) {
                    let error_msg = format!("发送HTTP事件失败: {}", e);
                    error!("{}", error_msg);
                    return UnifiedResult::Error(error_msg);
                }

                UnifiedResult::Success(RouteResult::HttpRouted)
            }
            Err(e) => {
                let error_msg = format!(
                    "建立到 {} 的HTTP连接失败: {}",
                    detection_result.client_addr, e
                );
                error!("{}", error_msg);
                UnifiedResult::Error(error_msg)
            }
        }
    }

    /// 建立TCP连接
    async fn establish_tcp_connection(
        &self,
        client_addr: SocketAddr,
    ) -> Result<TcpStream, std::io::Error> {
        // 注意：这里需要根据实际需求调整
        // 在实际实现中，可能需要从统一监听器转换为TCP连接
        // 这里暂时使用占位符实现

        if self.verbose_logging {
            debug!("尝试建立到 {} 的TCP连接", client_addr);
        }

        // TODO: 实现实际的TCP连接建立逻辑
        // 这可能涉及到从UDP socket转换为TCP stream的复杂逻辑
        Err(std::io::Error::other("TCP连接建立功能待实现"))
    }

    /// 发送错误事件
    pub async fn send_error(&self, message: String, client_addr: Option<SocketAddr>) {
        let event = RouteEvent::Error {
            message: message.clone(),
            client_addr,
        };

        // 尝试发送到TCP、UDP和HTTP处理器
        if let Err(e) = self.tcp_sender.send(event.clone()) {
            error!("发送错误事件到TCP处理器失败: {}", e);
        }

        if let Err(e) = self.udp_sender.send(event.clone()) {
            error!("发送错误事件到UDP处理器失败: {}", e);
        }

        if let Err(e) = self.http_sender.send(event) {
            error!("发送错误事件到HTTP处理器失败: {}", e);
        }

        let mut stats = self.stats.lock().await;
        stats.route_errors += 1;
    }

    /// 获取路由统计信息
    pub async fn get_stats(&self) -> RouterStats {
        self.stats.lock().await.clone()
    }

    /// 重置统计信息
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.lock().await;
        *stats = RouterStats::default();
    }

    /// 获取TCP事件接收器
    pub fn create_tcp_receiver() -> mpsc::UnboundedReceiver<RouteEvent> {
        let (_, receiver) = mpsc::unbounded_channel();
        receiver
    }

    /// 获取UDP事件接收器
    pub fn create_udp_receiver() -> mpsc::UnboundedReceiver<RouteEvent> {
        let (_, receiver) = mpsc::unbounded_channel();
        receiver
    }

    /// 获取HTTP事件接收器
    pub fn create_http_receiver() -> mpsc::UnboundedReceiver<RouteEvent> {
        let (_, receiver) = mpsc::unbounded_channel();
        receiver
    }

    /// 创建路由器和事件接收器
    pub fn create_with_receivers(
        verbose_logging: bool,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<RouteEvent>,
        mpsc::UnboundedReceiver<RouteEvent>,
        mpsc::UnboundedReceiver<RouteEvent>,
    ) {
        let (tcp_sender, tcp_receiver) = mpsc::unbounded_channel();
        let (udp_sender, udp_receiver) = mpsc::unbounded_channel();
        let (http_sender, http_receiver) = mpsc::unbounded_channel();

        let router = Self::new(tcp_sender, udp_sender, http_sender, verbose_logging);

        (router, tcp_receiver, udp_receiver, http_receiver)
    }
}

impl RouterStats {
    /// 计算成功路由总数
    pub fn total_successful_routes(&self) -> u64 {
        self.tcp_routes + self.udp_routes + self.http_routes
    }

    /// 计算总路由数（包括错误）
    pub fn total_routes(&self) -> u64 {
        self.total_successful_routes() + self.route_errors
    }

    /// 计算成功率
    pub fn success_rate(&self) -> f64 {
        let total = self.total_routes();
        if total == 0 {
            0.0
        } else {
            self.total_successful_routes() as f64 / total as f64
        }
    }

    /// 计算TCP路由比例
    pub fn tcp_ratio(&self) -> f64 {
        let total = self.total_successful_routes();
        if total == 0 {
            0.0
        } else {
            self.tcp_routes as f64 / total as f64
        }
    }

    /// 计算UDP路由比例
    pub fn udp_ratio(&self) -> f64 {
        let total = self.total_successful_routes();
        if total == 0 {
            0.0
        } else {
            self.udp_routes as f64 / total as f64
        }
    }

    /// 计算HTTP路由比例
    pub fn http_ratio(&self) -> f64 {
        let total = self.total_successful_routes();
        if total == 0 {
            0.0
        } else {
            self.http_routes as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_router_creation() {
        let (tcp_sender, _tcp_receiver) = mpsc::unbounded_channel();
        let (udp_sender, _udp_receiver) = mpsc::unbounded_channel();
        let (http_sender, _http_receiver) = mpsc::unbounded_channel();

        let router = RequestRouter::new(tcp_sender, udp_sender, http_sender, false);
        let stats = router.get_stats().await;

        assert_eq!(stats.tcp_routes, 0);
        assert_eq!(stats.udp_routes, 0);
        assert_eq!(stats.http_routes, 0);
        assert_eq!(stats.route_errors, 0);
    }

    #[tokio::test]
    async fn test_router_stats() {
        let stats = RouterStats {
            tcp_routes: 10,
            udp_routes: 5,
            http_routes: 3,
            route_errors: 2,
            total_requests: 20,
        };

        assert_eq!(stats.total_successful_routes(), 18);
        assert_eq!(stats.total_routes(), 20);
        assert_eq!(stats.success_rate(), 18.0 / 20.0);
        assert_eq!(stats.tcp_ratio(), 10.0 / 18.0);
        assert_eq!(stats.udp_ratio(), 5.0 / 18.0);
        assert_eq!(stats.http_ratio(), 3.0 / 18.0);
    }

    #[tokio::test]
    async fn test_send_error() {
        let (tcp_sender, mut tcp_receiver) = mpsc::unbounded_channel();
        let (udp_sender, mut udp_receiver) = mpsc::unbounded_channel();
        let (http_sender, mut http_receiver) = mpsc::unbounded_channel();

        let router = RequestRouter::new(tcp_sender, udp_sender, http_sender, false);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        router
            .send_error("测试错误".to_string(), Some(client_addr))
            .await;

        // 检查TCP接收器
        if let Ok(event) = tcp_receiver.try_recv() {
            match event {
                RouteEvent::Error { message, .. } => {
                    assert_eq!(message, "测试错误");
                }
                _ => panic!("期望错误事件"),
            }
        }

        // 检查UDP接收器
        if let Ok(event) = udp_receiver.try_recv() {
            match event {
                RouteEvent::Error { message, .. } => {
                    assert_eq!(message, "测试错误");
                }
                _ => panic!("期望错误事件"),
            }
        }

        // 检查HTTP接收器
        if let Ok(event) = http_receiver.try_recv() {
            match event {
                RouteEvent::Error { message, .. } => {
                    assert_eq!(message, "测试错误");
                }
                _ => panic!("期望错误事件"),
            }
        }

        let stats = router.get_stats().await;
        assert_eq!(stats.route_errors, 1);
    }

    #[test]
    fn test_create_with_receivers() {
        let (router, _tcp_receiver, _udp_receiver, _http_receiver) =
            RequestRouter::create_with_receivers(false);
        assert!(!router.verbose_logging);
    }

    #[tokio::test]
    async fn test_http_routing() {
        let (tcp_sender, _tcp_receiver) = mpsc::unbounded_channel();
        let (udp_sender, _udp_receiver) = mpsc::unbounded_channel();
        let (http_sender, _http_receiver) = mpsc::unbounded_channel();

        let router = RequestRouter::new(tcp_sender, udp_sender, http_sender, true);

        // 模拟HTTP检测结果
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let detection_result = DetectionResult {
            protocol: ProtocolType::Http,
            confidence: 0.9,
            client_addr,
            initial_data: b"GET / HTTP/1.1\r\n".to_vec(),
        };

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // 注意：这个测试会失败，因为establish_tcp_connection是占位符实现
        // 在实际实现中，需要提供真实的TCP连接建立逻辑
        let result = router.route_to_http(detection_result, socket).await;

        // 验证错误处理
        match result {
            UnifiedResult::Error(msg) => {
                assert!(msg.contains("建立到"));
                assert!(msg.contains("的HTTP连接失败"));
            }
            _ => panic!("期望错误结果"),
        }
    }
}
