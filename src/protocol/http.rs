//! HTTP/HTTPS代理协议实现
//!
//! 提供HTTP代理和HTTPS隧道功能

use anyhow::{Result, anyhow};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    BufReader as AsyncBufReader,
};
use tokio::net::TcpStream;
use url::Url;

/// HTTP方法枚举
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
}

impl std::str::FromStr for HttpMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            "CONNECT" => Ok(HttpMethod::Connect),
            "TRACE" => Ok(HttpMethod::Trace),
            _ => Err(anyhow!("不支持的HTTP方法: {}", s)),
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let method_str = match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Trace => "TRACE",
        };
        write!(f, "{}", method_str)
    }
}

/// HTTP请求结构
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP方法
    pub method: HttpMethod,
    /// 请求URI
    pub uri: String,
    /// HTTP版本
    pub version: String,
    /// 请求头
    pub headers: HashMap<String, String>,
    /// 请求体
    pub body: Vec<u8>,
}

/// HTTP响应结构
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP版本
    pub version: String,
    /// 状态码
    pub status_code: u16,
    /// 状态消息
    pub status_message: String,
    /// 响应头
    pub headers: HashMap<String, String>,
    /// 响应体
    pub body: Vec<u8>,
}

/// HTTP代理处理器
#[derive(Debug, Clone)]
pub struct HttpProxy {
    /// 是否启用详细日志
    verbose_logging: bool,
    /// 用户代理字符串
    user_agent: String,
    /// 连接超时时间（秒）
    connect_timeout: u64,
}

impl Default for HttpProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProxy {
    /// 创建新的HTTP代理实例
    pub fn new() -> Self {
        Self {
            verbose_logging: false,
            user_agent: "SimpleSSR-HttpProxy/1.0".to_string(),
            connect_timeout: 30,
        }
    }

    /// 设置详细日志
    pub fn with_verbose_logging(mut self, enabled: bool) -> Self {
        self.verbose_logging = enabled;
        self
    }

    /// 设置用户代理
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// 设置连接超时
    pub fn with_connect_timeout(mut self, timeout_seconds: u64) -> Self {
        self.connect_timeout = timeout_seconds;
        self
    }

    /// 处理HTTP代理请求
    pub async fn handle_request<S>(&self, mut stream: S, client_addr: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 解析HTTP请求
        let request = self.parse_http_request(&mut stream).await?;

        if self.verbose_logging {
            info!(
                "收到来自 {} 的 {} 请求: {}",
                client_addr, request.method, request.uri
            );
        }

        match request.method {
            HttpMethod::Connect => {
                // 处理HTTPS隧道
                self.handle_connect_method(stream, &request, client_addr)
                    .await
            }
            _ => {
                // 处理普通HTTP请求
                self.handle_http_method(stream, &request, client_addr).await
            }
        }
    }

    /// 解析HTTP请求
    async fn parse_http_request<S>(&self, stream: &mut S) -> Result<HttpRequest>
    where
        S: AsyncRead + Unpin,
    {
        let mut reader = AsyncBufReader::new(stream);
        let mut line = String::new();

        // 读取请求行
        reader.read_line(&mut line).await?;
        let request_line = line.trim();

        if request_line.is_empty() {
            return Err(anyhow!("空的HTTP请求行"));
        }

        // 解析请求行: METHOD URI VERSION
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(anyhow!("无效的HTTP请求行格式: {}", request_line));
        }

        let method: HttpMethod = parts[0].parse()?;
        let uri = parts[1].to_string();
        let version = parts[2].to_string();

        // 解析请求头
        let mut headers = HashMap::new();
        loop {
            line.clear();
            reader.read_line(&mut line).await?;
            let header_line = line.trim();

            if header_line.is_empty() {
                break; // 空行表示头部结束
            }

            if let Some(colon_pos) = header_line.find(':') {
                let name = header_line[..colon_pos].trim().to_lowercase();
                let value = header_line[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            }
        }

        // 读取请求体（如果有Content-Length）
        let mut body = Vec::new();
        if let Some(content_length_str) = headers.get("content-length")
            && let Ok(content_length) = content_length_str.parse::<usize>()
            && content_length > 0
        {
            body.resize(content_length, 0);
            reader.read_exact(&mut body).await?;
        }

        Ok(HttpRequest {
            method,
            uri,
            version,
            headers,
            body,
        })
    }

    /// 处理HTTP CONNECT方法（HTTPS隧道）
    async fn handle_connect_method<S>(
        &self,
        mut client_stream: S,
        request: &HttpRequest,
        client_addr: SocketAddr,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 解析目标地址
        let target_addr = self.parse_connect_target(&request.uri)?;

        if self.verbose_logging {
            debug!(
                "为客户端 {} 建立到 {} 的HTTPS隧道",
                client_addr, target_addr
            );
        }

        // 连接到目标服务器
        let target_stream = match tokio::time::timeout(
            tokio::time::Duration::from_secs(self.connect_timeout),
            TcpStream::connect(&target_addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!("连接到目标服务器 {} 失败: {}", target_addr, e);
                self.send_connect_error(&mut client_stream, 502, "Bad Gateway")
                    .await?;
                return Err(anyhow!("连接目标服务器失败: {}", e));
            }
            Err(_) => {
                error!("连接到目标服务器 {} 超时", target_addr);
                self.send_connect_error(&mut client_stream, 504, "Gateway Timeout")
                    .await?;
                return Err(anyhow!("连接目标服务器超时"));
            }
        };

        // 发送200 Connection Established响应
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        client_stream.write_all(response.as_bytes()).await?;
        client_stream.flush().await?;

        if self.verbose_logging {
            info!("HTTPS隧道建立成功: {} <-> {}", client_addr, target_addr);
        }

        // 开始双向数据转发
        self.tunnel_data(client_stream, target_stream).await?;

        Ok(())
    }

    /// 处理普通HTTP方法
    async fn handle_http_method<S>(
        &self,
        mut client_stream: S,
        request: &HttpRequest,
        client_addr: SocketAddr,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 解析目标URL
        let url = self.parse_http_url(&request.uri)?;
        let target_addr = self.resolve_http_target(&url).await?;

        if self.verbose_logging {
            debug!("为客户端 {} 转发HTTP请求到 {}", client_addr, target_addr);
        }

        // 连接到目标服务器
        let mut target_stream = match tokio::time::timeout(
            tokio::time::Duration::from_secs(self.connect_timeout),
            TcpStream::connect(&target_addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!("连接到目标服务器 {} 失败: {}", target_addr, e);
                self.send_http_error(&mut client_stream, 502, "Bad Gateway")
                    .await?;
                return Err(anyhow!("连接目标服务器失败: {}", e));
            }
            Err(_) => {
                error!("连接到目标服务器 {} 超时", target_addr);
                self.send_http_error(&mut client_stream, 504, "Gateway Timeout")
                    .await?;
                return Err(anyhow!("连接目标服务器超时"));
            }
        };

        // 构建并发送请求到目标服务器
        let forwarded_request = self.build_forwarded_request(request, &url)?;
        target_stream
            .write_all(forwarded_request.as_bytes())
            .await?;
        target_stream.flush().await?;

        // 读取目标服务器响应并转发给客户端
        let mut buffer = vec![0u8; 8192];
        loop {
            match target_stream.read(&mut buffer).await {
                Ok(0) => break, // 连接关闭
                Ok(n) => {
                    client_stream.write_all(&buffer[..n]).await?;
                    client_stream.flush().await?;
                }
                Err(e) => {
                    warn!("从目标服务器读取数据时出错: {}", e);
                    break;
                }
            }
        }

        if self.verbose_logging {
            info!("HTTP请求转发完成: {} -> {}", client_addr, target_addr);
        }

        Ok(())
    }

    /// 解析CONNECT方法的目标地址
    fn parse_connect_target(&self, uri: &str) -> Result<String> {
        // CONNECT方法的URI格式: host:port
        if uri.contains(':') {
            Ok(uri.to_string())
        } else {
            // 如果没有端口，默认使用443（HTTPS）
            Ok(format!("{}:443", uri))
        }
    }

    /// 解析HTTP URL
    fn parse_http_url(&self, uri: &str) -> Result<Url> {
        if uri.starts_with("http://") || uri.starts_with("https://") {
            Url::parse(uri).map_err(|e| anyhow!("解析URL失败: {}", e))
        } else {
            // 相对URL，假设为HTTP
            Url::parse(&format!("http://{}", uri)).map_err(|e| anyhow!("解析相对URL失败: {}", e))
        }
    }

    /// 解析HTTP目标地址
    async fn resolve_http_target(&self, url: &Url) -> Result<String> {
        let host = url.host_str().ok_or_else(|| anyhow!("URL中缺少主机名"))?;
        let port = url.port().unwrap_or_else(|| match url.scheme() {
            "https" => 443,
            _ => 80,
        });
        Ok(format!("{}:{}", host, port))
    }

    /// 构建转发的HTTP请求
    fn build_forwarded_request(&self, request: &HttpRequest, url: &Url) -> Result<String> {
        let mut request_lines = Vec::new();

        // 构建请求行
        let path_and_query = if let Some(query) = url.query() {
            format!("{}?{}", url.path(), query)
        } else {
            url.path().to_string()
        };

        request_lines.push(format!(
            "{} {} {}",
            request.method, path_and_query, request.version
        ));

        // 添加Host头（如果原请求中没有）
        let mut has_host = false;
        for (name, value) in &request.headers {
            if name.to_lowercase() == "host" {
                has_host = true;
            }
            request_lines.push(format!("{}: {}", name, value));
        }

        if !has_host && let Some(host) = url.host_str() {
            let host_header = if let Some(port) = url.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            request_lines.push(format!("Host: {}", host_header));
        }

        // 添加空行
        request_lines.push(String::new());

        let mut result = request_lines.join("\r\n");

        // 添加请求体
        if !request.body.is_empty() {
            result.push_str(&String::from_utf8_lossy(&request.body));
        }

        Ok(result)
    }

    /// 发送CONNECT错误响应
    async fn send_connect_error<S>(
        &self,
        stream: &mut S,
        status_code: u16,
        status_message: &str,
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let response = format!("HTTP/1.1 {} {}\r\n\r\n", status_code, status_message);
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }

    /// 发送HTTP错误响应
    async fn send_http_error<S>(
        &self,
        stream: &mut S,
        status_code: u16,
        status_message: &str,
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let body = format!(
            "<html><body><h1>{} {}</h1></body></html>",
            status_code, status_message
        );
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            status_code,
            status_message,
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }

    /// 双向数据隧道转发
    async fn tunnel_data<C, T>(&self, client_stream: C, target_stream: T) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (target_read, target_write) = tokio::io::split(target_stream);

        let mut client_read_buf = tokio::io::BufReader::new(client_read);
        let mut target_write_buf = tokio::io::BufWriter::new(target_write);
        let mut target_read_buf = tokio::io::BufReader::new(target_read);
        let mut client_write_buf = tokio::io::BufWriter::new(client_write);

        let client_to_target = tokio::io::copy(&mut client_read_buf, &mut target_write_buf);
        let target_to_client = tokio::io::copy(&mut target_read_buf, &mut client_write_buf);

        // 等待任一方向的传输完成
        tokio::select! {
            result = client_to_target => {
                if let Err(e) = result {
                    debug!("客户端到目标服务器的数据传输结束: {}", e);
                }
            }
            result = target_to_client => {
                if let Err(e) = result {
                    debug!("目标服务器到客户端的数据传输结束: {}", e);
                }
            }
        }

        Ok(())
    }

    /// 检测数据是否为HTTP请求
    pub fn is_http_request(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let data_str = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 检查是否以HTTP方法开头
        let methods = [
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
        ];
        methods.iter().any(|method| data_str.starts_with(method))
    }

    /// 检测数据是否为HTTPS请求（TLS握手）
    pub fn is_https_request(data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }

        // TLS握手包特征:
        // 第一个字节: 0x16 (Handshake)
        // 第二、三字节: TLS版本 (0x03, 0x01-0x04)
        data[0] == 0x16 && data[1] == 0x03 && (data[2] >= 0x01 && data[2] <= 0x04)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_http_method_parsing() {
        assert_eq!("GET".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("POST".parse::<HttpMethod>().unwrap(), HttpMethod::Post);
        assert_eq!(
            "CONNECT".parse::<HttpMethod>().unwrap(),
            HttpMethod::Connect
        );
        assert!("INVALID".parse::<HttpMethod>().is_err());
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Connect.to_string(), "CONNECT");
    }

    #[test]
    fn test_is_http_request() {
        assert!(HttpProxy::is_http_request(b"GET / HTTP/1.1\r\n"));
        assert!(HttpProxy::is_http_request(b"POST /api HTTP/1.1\r\n"));
        assert!(HttpProxy::is_http_request(
            b"CONNECT example.com:443 HTTP/1.1\r\n"
        ));
        assert!(!HttpProxy::is_http_request(b"\x16\x03\x01\x00\x01"));
        assert!(!HttpProxy::is_http_request(b"INVALID"));
    }

    #[test]
    fn test_is_https_request() {
        assert!(HttpProxy::is_https_request(&[
            0x16, 0x03, 0x01, 0x00, 0x01, 0x00
        ]));
        assert!(HttpProxy::is_https_request(&[
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00
        ]));
        assert!(!HttpProxy::is_https_request(&[
            0x15, 0x03, 0x01, 0x00, 0x01, 0x00
        ]));
        assert!(!HttpProxy::is_https_request(b"GET / HTTP/1.1"));
        assert!(!HttpProxy::is_https_request(&[0x16, 0x02]));
    }

    #[tokio::test]
    async fn test_parse_http_request() {
        let proxy = HttpProxy::new();
        let request_data = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let mut cursor = Cursor::new(request_data);

        let request = proxy.parse_http_request(&mut cursor).await.unwrap();
        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.uri, "/test");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(
            request.headers.get("host"),
            Some(&"example.com".to_string())
        );
        assert_eq!(request.headers.get("user-agent"), Some(&"test".to_string()));
    }

    #[test]
    fn test_parse_connect_target() {
        let proxy = HttpProxy::new();
        assert_eq!(
            proxy.parse_connect_target("example.com:443").unwrap(),
            "example.com:443"
        );
        assert_eq!(
            proxy.parse_connect_target("example.com").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn test_parse_http_url() {
        let proxy = HttpProxy::new();
        let url = proxy.parse_http_url("http://example.com/path").unwrap();
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");

        let url = proxy.parse_http_url("example.com/path").unwrap();
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");
    }

    #[tokio::test]
    async fn test_resolve_http_target() {
        let proxy = HttpProxy::new();
        let url = Url::parse("http://example.com/path").unwrap();
        let target = proxy.resolve_http_target(&url).await.unwrap();
        assert_eq!(target, "example.com:80");

        let url = Url::parse("https://example.com/path").unwrap();
        let target = proxy.resolve_http_target(&url).await.unwrap();
        assert_eq!(target, "example.com:443");
    }

    #[test]
    fn test_build_forwarded_request() {
        let proxy = HttpProxy::new();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "test".to_string());

        let request = HttpRequest {
            method: HttpMethod::Get,
            uri: "/test".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
            body: Vec::new(),
        };

        let url = Url::parse("http://example.com/test").unwrap();
        let forwarded = proxy.build_forwarded_request(&request, &url).unwrap();

        assert!(forwarded.contains("GET /test HTTP/1.1"));
        assert!(forwarded.contains("Host: example.com"));
        assert!(forwarded.contains("user-agent: test"));
    }

    #[test]
    fn test_http_proxy_creation() {
        let proxy = HttpProxy::new();
        assert!(!proxy.verbose_logging);
        assert_eq!(proxy.user_agent, "SimpleSSR-HttpProxy/1.0");
        assert_eq!(proxy.connect_timeout, 30);

        let proxy = HttpProxy::new()
            .with_verbose_logging(true)
            .with_user_agent("Custom/1.0".to_string())
            .with_connect_timeout(60);

        assert!(proxy.verbose_logging);
        assert_eq!(proxy.user_agent, "Custom/1.0");
        assert_eq!(proxy.connect_timeout, 60);
    }
}
