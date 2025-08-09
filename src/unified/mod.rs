//! 统一端口模块
//!
//! 该模块实现了TCP和UDP请求的统一端口处理功能，包括：
//! - 协议自动检测
//! - 请求路由
//! - 统一监听器
//! - 配置管理

pub mod config;
pub mod detector;
pub mod listener;
pub mod router;

pub use config::UnifiedConfig;
pub use detector::ProtocolDetector;
pub use listener::UnifiedListener;
pub use router::RequestRouter;

/// 统一端口处理结果
#[derive(Debug, Clone)]
pub enum UnifiedResult<T> {
    /// 成功处理
    Success(T),
    /// 处理失败
    Error(String),
    /// 需要更多数据
    NeedMoreData,
}

/// 协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    /// TCP协议
    Tcp,
    /// UDP协议
    Udp,
    /// HTTP代理协议
    Http,
    /// HTTPS代理协议
    Https,
    /// 未知协议
    Unknown,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Tcp => write!(f, "TCP"),
            ProtocolType::Udp => write!(f, "UDP"),
            ProtocolType::Http => write!(f, "HTTP"),
            ProtocolType::Https => write!(f, "HTTPS"),
            ProtocolType::Unknown => write!(f, "Unknown"),
        }
    }
}
