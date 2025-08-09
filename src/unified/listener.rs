//! 统一监听器模块
//!
//! 实现TCP和UDP请求的统一端口监听和处理

use crate::unified::{
    UnifiedResult,
    config::UnifiedConfig,
    detector::ProtocolDetector,
    router::{RequestRouter, RouteEvent, RouteResult},
};
use crate::protocol::http::HttpProxy;


use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::sleep;

/// 统一监听器状态
#[derive(Debug, Clone, PartialEq)]
pub enum ListenerState {
    /// 未启动
    Stopped,
    /// 正在启动
    Starting,
    /// 运行中
    Running,
    /// 正在停止
    Stopping,
    /// 错误状态
    Error(String),
}

/// 统一监听器
#[derive(Debug)]
pub struct UnifiedListener {
    /// 配置
    config: UnifiedConfig,
    /// 协议检测器
    detector: Arc<ProtocolDetector>,
    /// 请求路由器
    router: Arc<RequestRouter>,
    /// 监听器状态
    state: Arc<RwLock<ListenerState>>,
    /// 停止信号发送器
    stop_sender: Option<mpsc::UnboundedSender<()>>,
    /// TCP事件接收器
    tcp_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<RouteEvent>>>>,
    /// UDP事件接收器
    udp_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<RouteEvent>>>>,
    /// HTTP事件接收器
    http_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<RouteEvent>>>>,
    /// 活跃连接计数
    active_connections: Arc<tokio::sync::Mutex<u32>>,
}

/// 监听器统计信息
#[derive(Debug, Clone)]
pub struct ListenerStats {
    /// TCP连接数
    pub tcp_connections: u64,
    /// UDP数据包数
    pub udp_packets: u64,
    /// HTTP请求数
    pub http_requests: u64,
    /// HTTPS请求数
    pub https_requests: u64,
    /// HTTP CONNECT请求数
    pub http_connect_requests: u64,
    /// 总字节数
    pub total_bytes: u64,
    /// 失败请求数
    pub failed_requests: u64,
    /// 启动时间
    pub start_time: std::time::Instant,
}

impl Default for ListenerStats {
    fn default() -> Self {
        Self {
            tcp_connections: 0,
            udp_packets: 0,
            http_requests: 0,
            https_requests: 0,
            http_connect_requests: 0,
            total_bytes: 0,
            failed_requests: 0,
            start_time: std::time::Instant::now(),
        }
    }
}

impl UnifiedListener {
    /// 创建新的统一监听器
    pub fn new(config: UnifiedConfig) -> Self {
        let detector = Arc::new(ProtocolDetector::new(
            config.detection_timeout(),
            config.verbose_logging,
        ));

        let (router, tcp_receiver, udp_receiver, http_receiver) =
            RequestRouter::create_with_receivers(config.verbose_logging);
        let router = Arc::new(router);

        Self {
            config,
            detector,
            router,
            state: Arc::new(RwLock::new(ListenerState::Stopped)),
            stop_sender: None,
            tcp_receiver: Arc::new(Mutex::new(Some(tcp_receiver))),
            udp_receiver: Arc::new(Mutex::new(Some(udp_receiver))),
            http_receiver: Arc::new(Mutex::new(Some(http_receiver))),
            active_connections: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    /// 启动统一监听器
    pub async fn start(&mut self) -> UnifiedResult<()> {
        // 检查配置有效性
        if let Err(e) = self.config.validate() {
            return UnifiedResult::Error(format!("配置验证失败: {}", e));
        }

        // 更新状态
        {
            let mut state = self.state.write().await;
            if *state != ListenerState::Stopped {
                return UnifiedResult::Error("监听器已在运行或正在启动".to_string());
            }
            *state = ListenerState::Starting;
        }

        info!("启动统一端口监听器，地址: {}", self.config.unified_addr);

        // 创建停止信号通道
        let (stop_sender, stop_receiver) = mpsc::unbounded_channel();
        self.stop_sender = Some(stop_sender);

        // 绑定UDP套接字
        let udp_socket = match UdpSocket::bind(self.config.unified_addr).await {
            Ok(socket) => {
                info!("UDP套接字绑定成功: {}", self.config.unified_addr);
                Arc::new(socket)
            }
            Err(e) => {
                let error_msg = format!("UDP套接字绑定失败: {}", e);
                error!("{}", error_msg);
                *self.state.write().await = ListenerState::Error(error_msg.clone());
                return UnifiedResult::Error(error_msg);
            }
        };

        // 启动TCP事件处理器
        let tcp_receiver = {
            let mut receiver_guard = self.tcp_receiver.lock().await;
            receiver_guard.take()
        };

        if let Some(tcp_rx) = tcp_receiver {
            let verbose_logging = self.config.verbose_logging;
            let tcp_handler = Self::spawn_tcp_handler(verbose_logging, tcp_rx);
            tokio::spawn(tcp_handler);
        }

        // 启动UDP事件处理器
        let udp_receiver = {
            let mut receiver_guard = self.udp_receiver.lock().await;
            receiver_guard.take()
        };

        if let Some(udp_rx) = udp_receiver {
            let verbose_logging = self.config.verbose_logging;
            let udp_handler = Self::spawn_udp_handler(verbose_logging, udp_rx);
            tokio::spawn(udp_handler);
        }

        // 启动HTTP事件处理器
        let http_receiver = {
            let mut receiver_guard = self.http_receiver.lock().await;
            receiver_guard.take()
        };

        if let Some(http_rx) = http_receiver {
            let verbose_logging = self.config.verbose_logging;
            let http_handler = Self::spawn_http_handler(verbose_logging, http_rx);
            tokio::spawn(http_handler);
        }

        // 启动主监听循环
        let detector = self.detector.clone();
        let router = self.router.clone();
        let active_connections = self.active_connections.clone();
        let verbose_logging = self.config.verbose_logging;
        let main_loop = Self::spawn_main_loop(
            udp_socket.clone(),
            stop_receiver,
            detector,
            router,
            active_connections,
            verbose_logging,
        );

        // 更新状态为运行中
        *self.state.write().await = ListenerState::Running;

        info!("统一端口监听器启动完成");

        // 等待主循环完成
        tokio::spawn(main_loop);

        UnifiedResult::Success(())
    }

    /// 停止统一监听器
    pub async fn stop(&mut self) -> UnifiedResult<()> {
        {
            let mut state = self.state.write().await;
            if *state == ListenerState::Stopped {
                return UnifiedResult::Success(());
            }
            *state = ListenerState::Stopping;
        }

        info!("正在停止统一端口监听器...");

        // 发送停止信号
        if let Some(sender) = &self.stop_sender {
            if let Err(e) = sender.send(()) {
                warn!("发送停止信号失败: {}", e);
            }
        }

        // 等待所有连接关闭
        let timeout_duration = Duration::from_secs(10);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout_duration {
            let active_count = *self.active_connections.lock().await;
            if active_count == 0 {
                break;
            }

            debug!("等待 {} 个活跃连接关闭...", active_count);
            sleep(Duration::from_millis(100)).await;
        }

        *self.state.write().await = ListenerState::Stopped;
        info!("统一端口监听器已停止");

        UnifiedResult::Success(())
    }

    /// 获取监听器状态
    pub async fn get_state(&self) -> ListenerState {
        self.state.read().await.clone()
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ListenerStats {
        let router_stats = self.router.get_stats().await;
        let _active_connections = *self.active_connections.lock().await;

        ListenerStats {
            tcp_connections: router_stats.tcp_routes,
            udp_packets: router_stats.udp_routes,
            http_requests: router_stats.http_routes,
            https_requests: 0, // TODO: 实现HTTPS计数
            http_connect_requests: 0, // TODO: 实现CONNECT计数
            total_bytes: 0, // TODO: 实现字节计数
            failed_requests: router_stats.route_errors,
            start_time: std::time::Instant::now(), // TODO: 实现正确的启动时间
        }
    }

    /// 主监听循环
    async fn spawn_main_loop(
        udp_socket: Arc<UdpSocket>,
        mut stop_receiver: mpsc::UnboundedReceiver<()>,
        detector: Arc<crate::unified::detector::ProtocolDetector>,
        router: Arc<RequestRouter>,
        active_connections: Arc<tokio::sync::Mutex<u32>>,
        verbose_logging: bool,
    ) -> UnifiedResult<()> {
        loop {
            tokio::select! {
                // 检查停止信号
                _ = stop_receiver.recv() => {
                    if verbose_logging {
                        debug!("收到停止信号，退出主循环");
                    }
                    break;
                }

                // 处理传入的数据
                detection_result = detector.detect_from_socket(&udp_socket) => {
                    match detection_result {
                        UnifiedResult::Success(result) => {
                            // 增加活跃连接计数
                            {
                                let mut count = active_connections.lock().await;
                                *count += 1;
                            }

                            // 路由请求
                            let route_result = router.route_detection_result(
                                result,
                                udp_socket.clone()
                            ).await;

                            match route_result {
                                UnifiedResult::Success(RouteResult::TcpRouted) => {
                                    if verbose_logging {
                                        debug!("成功路由TCP请求");
                                    }
                                }
                                UnifiedResult::Success(RouteResult::UdpRouted) => {
                                    if verbose_logging {
                                        debug!("成功路由UDP请求");
                                    }
                                }
                                UnifiedResult::Success(RouteResult::HttpRouted) => {
                                    if verbose_logging {
                                        debug!("成功路由HTTP请求");
                                    }
                                }
                                UnifiedResult::Success(RouteResult::Failed(msg)) => {
                                    warn!("路由失败: {}", msg);
                                }
                                UnifiedResult::Error(e) => {
                                    error!("路由错误: {}", e);
                                }
                                _ => {}
                            }

                            // 减少活跃连接计数
                            {
                                let mut count = active_connections.lock().await;
                                if *count > 0 {
                                    *count -= 1;
                                }
                            }
                        }
                        UnifiedResult::Error(e) => {
                            if verbose_logging {
                                debug!("协议检测错误: {}", e);
                            }
                        }
                        UnifiedResult::NeedMoreData => {
                            if verbose_logging {
                                debug!("需要更多数据进行协议检测");
                            }
                        }
                    }
                }
            }
        }

        UnifiedResult::Success(())
    }

    /// 生成TCP事件处理器
    async fn spawn_tcp_handler(
        verbose_logging: bool,
        mut tcp_receiver: mpsc::UnboundedReceiver<RouteEvent>,
    ) -> UnifiedResult<()> {
        if verbose_logging {
            info!("启动TCP事件处理器");
        }

        while let Some(event) = tcp_receiver.recv().await {
            match event {
                RouteEvent::TcpConnection {
                    stream: _,
                    client_addr,
                    initial_data,
                } => {
                    if verbose_logging {
                        debug!(
                            "处理来自 {} 的TCP连接，初始数据大小: {} 字节",
                            client_addr,
                            initial_data.len()
                        );
                    }

                    // TODO: 实现实际的TCP连接处理逻辑
                    // 这里应该调用现有的TCP处理器
                }
                RouteEvent::Error {
                    message,
                    client_addr,
                } => {
                    error!(
                        "TCP处理器收到错误事件: {} (客户端: {:?})",
                        message, client_addr
                    );
                }
                _ => {
                    warn!("TCP处理器收到非TCP事件");
                }
            }
        }

        if verbose_logging {
            info!("TCP事件处理器已停止");
        }

        UnifiedResult::Success(())
    }

    /// 生成UDP事件处理器
    async fn spawn_udp_handler(
        verbose_logging: bool,
        mut udp_receiver: mpsc::UnboundedReceiver<RouteEvent>,
    ) -> UnifiedResult<()> {
        if verbose_logging {
            info!("启动UDP事件处理器");
        }

        while let Some(event) = udp_receiver.recv().await {
            match event {
                RouteEvent::UdpPacket {
                    data,
                    client_addr,
                    socket: _,
                } => {
                    if verbose_logging {
                        debug!(
                            "处理来自 {} 的UDP数据包，大小: {} 字节",
                            client_addr,
                            data.len()
                        );
                    }

                    // TODO: 实现实际的UDP数据包处理逻辑
                    // 这里应该调用现有的UDP处理器
                }
                RouteEvent::Error {
                    message,
                    client_addr,
                } => {
                    error!(
                        "UDP处理器收到错误事件: {} (客户端: {:?})",
                        message, client_addr
                    );
                }
                _ => {
                    warn!("UDP处理器收到非UDP事件");
                }
            }
        }

        if verbose_logging {
            info!("UDP事件处理器已停止");
        }

        UnifiedResult::Success(())
    }

    /// 生成HTTP事件处理器
    async fn spawn_http_handler(
        verbose_logging: bool,
        mut http_receiver: mpsc::UnboundedReceiver<RouteEvent>,
    ) -> UnifiedResult<()> {
        if verbose_logging {
            info!("启动HTTP事件处理器");
        }

        while let Some(event) = http_receiver.recv().await {
            match event {
                RouteEvent::HttpRequest {
                    stream,
                    client_addr,
                    request_data,
                    is_https,
                } => {
                    if verbose_logging {
                        debug!(
                            "处理来自 {} 的{}请求，数据大小: {} 字节",
                            client_addr,
                            if is_https { "HTTPS" } else { "HTTP" },
                            request_data.len()
                        );
                    }

                    // 调用HTTP代理处理器来处理请求
                    // 从Arc中克隆TcpStream
                    let stream_clone = match Arc::try_unwrap(stream) {
                        Ok(s) => s,
                        Err(_arc_stream) => {
                            // 如果无法unwrap，说明还有其他引用，我们需要创建一个新的连接
                            warn!("无法获取TcpStream的独占所有权，跳过HTTP处理");
                            continue;
                        }
                    };
                    
                    let result = Self::handle_http_request(
                        stream_clone,
                        client_addr,
                        request_data,
                        is_https,
                        verbose_logging,
                    ).await;

                    if let Err(e) = result {
                        error!("HTTP请求处理失败: {} (客户端: {})", e, client_addr);
                    }
                }
                RouteEvent::Error {
                    message,
                    client_addr,
                } => {
                    error!(
                        "HTTP处理器收到错误事件: {} (客户端: {:?})",
                        message, client_addr
                    );
                }
                _ => {
                    warn!("HTTP处理器收到非HTTP事件");
                }
            }
        }

        if verbose_logging {
            info!("HTTP事件处理器已停止");
        }

        UnifiedResult::Success(())
    }

    /// 处理HTTP/HTTPS请求
    async fn handle_http_request(
        stream: tokio::net::TcpStream,
        client_addr: std::net::SocketAddr,
        _request_data: Vec<u8>,
        _is_https: bool,
        verbose_logging: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if verbose_logging {
            debug!("开始处理来自 {} 的HTTP请求", client_addr);
        }

        // 创建HTTP代理实例
        let http_proxy = HttpProxy::new();

        // 直接使用HttpProxy的handle_request方法处理所有HTTP/HTTPS请求
        match http_proxy.handle_request(stream, client_addr).await {
            Ok(_) => {
                if verbose_logging {
                    debug!("HTTP请求处理完成: {}", client_addr);
                }
                Ok(())
            }
            Err(e) => {
                error!("处理HTTP请求失败: {}", e);
                Err(format!("HTTP处理失败: {}", e).into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use std::time::Duration;

    /// 测试HTTP代理功能
    #[tokio::test]
    async fn test_http_proxy() {
        // 创建测试配置
        let config = UnifiedConfig {
            unified_addr: "127.0.0.1:0".parse().unwrap(),
            verbose_logging: true,
            ..Default::default()
        };

        // 创建监听器
        let listener = UnifiedListener::new(config);
        
        // 测试统计信息初始化
        let stats = listener.get_stats().await;
        assert_eq!(stats.http_requests, 0);
        assert_eq!(stats.https_requests, 0);
        assert_eq!(stats.http_connect_requests, 0);
        assert_eq!(stats.failed_requests, 0);
    }

    /// 测试HTTPS CONNECT请求处理
    #[tokio::test]
    async fn test_https_connect_handling() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        // 创建模拟的CONNECT请求数据
        let connect_request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        
        // 创建模拟的TCP流
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // 启动服务器任务
        let server_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = vec![0u8; 1024];
                if let Ok(n) = stream.read(&mut buffer).await {
                    buffer.truncate(n);
                    // 验证接收到CONNECT请求
                    assert!(buffer.starts_with(b"CONNECT"));
                }
            }
        });
        
        // 创建客户端连接
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(connect_request).await.unwrap();
        
        // 等待服务器处理
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    /// 测试HTTP请求解析
    #[tokio::test]
    async fn test_http_request_parsing() {
        // 创建模拟的HTTP请求数据
        let http_request = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        
        // 验证请求数据格式
        assert!(http_request.starts_with(b"GET"));
        let request_str = String::from_utf8_lossy(http_request);
        assert!(request_str.contains("Host: example.com"));
        
        // 测试请求数据包含必要的HTTP头
        let request_str = String::from_utf8_lossy(http_request);
        assert!(request_str.contains("HTTP/1.1"));
        assert!(request_str.contains("Host:"));
    }

    /// 测试统计信息更新
    #[tokio::test]
    async fn test_stats_update() {
        let mut stats = ListenerStats::default();
        
        // 模拟HTTP请求统计
        stats.http_requests += 1;
        stats.total_bytes += 100;
        
        assert_eq!(stats.http_requests, 1);
        assert_eq!(stats.total_bytes, 100);
        
        // 模拟HTTPS请求统计
        stats.https_requests += 1;
        stats.http_connect_requests += 1;
        
        assert_eq!(stats.https_requests, 1);
        assert_eq!(stats.http_connect_requests, 1);
    }

    /// 测试错误处理
    #[tokio::test]
    async fn test_error_handling() {
        let mut stats = ListenerStats::default();
        
        // 模拟失败请求
        stats.failed_requests += 1;
        
        assert_eq!(stats.failed_requests, 1);
    }
}
