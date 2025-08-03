//! Simple SSR - Shadowsocks 实现
//!
//! 一个用Rust实现的Shadowsocks代理系统，支持TCP和UDP协议

pub mod client;
pub mod config;
pub mod crypto;
pub mod protocol;
pub mod server;
pub mod utils;

// 重新导出主要类型
pub use config::{ClientConfig, ServerConfig};
pub use crypto::{CryptoContext, Method};
pub use protocol::{Address, ShadowsocksProtocol, Socks5Server};

use anyhow::Result;
use tracing::info;

/// 运行服务端
pub async fn run_server(config: ServerConfig) -> Result<()> {
    info!("Starting Shadowsocks server on {}", config.server_addr()?);

    // 验证配置
    config.validate()?;

    // TODO: 实现服务端逻辑
    info!("Server started successfully");

    // 保持运行
    tokio::signal::ctrl_c().await?;
    info!("Server shutting down...");

    Ok(())
}

/// 运行客户端
pub async fn run_client(config: ClientConfig) -> Result<()> {
    info!(
        "Starting Shadowsocks client, local proxy on {}",
        config.local_addr()?
    );

    // 验证配置
    config.validate()?;

    // TODO: 实现客户端逻辑
    info!("Client started successfully");

    // 保持运行
    tokio::signal::ctrl_c().await?;
    info!("Client shutting down...");

    Ok(())
}

/// 初始化日志系统
pub fn init_logger() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_creation() {
        let config = ServerConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_client_config_creation() {
        let config = ClientConfig::new(
            "127.0.0.1".to_string(),
            8388,
            "127.0.0.1".to_string(),
            1080,
            "test_password".to_string(),
            "aes-256-gcm".to_string(),
        );

        assert!(config.validate().is_ok());
    }
}
