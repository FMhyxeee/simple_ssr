//! Shadowsocks 主程序入口
//!
//! 提供命令行界面来启动服务端或客户端

use anyhow::Result;
use clap::{Parser, Subcommand};
use simple_ssr::config::load_config_from_file;
use simple_ssr::{ClientConfig, ServerConfig, init_logger, run_client, run_server};
use tracing::{error, info};

/// Shadowsocks 命令行工具
#[derive(Parser)]
#[command(name = "simple-ssr")]
#[command(about = "A Shadowsocks implementation in Rust")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// 可用的命令
#[derive(Subcommand)]
enum Commands {
    /// 启动服务端
    Server {
        /// 配置文件路径
        #[arg(short, long, default_value = "server.toml")]
        config: String,

        /// 服务器地址
        #[arg(short, long)]
        server: Option<String>,

        /// 服务器端口
        #[arg(short, long)]
        port: Option<u16>,

        /// 密码
        #[arg(short = 'k', long)]
        password: Option<String>,

        /// 加密方法
        #[arg(short, long)]
        method: Option<String>,
    },
    /// 启动客户端
    Client {
        /// 配置文件路径
        #[arg(short, long, default_value = "client.toml")]
        config: String,

        /// 服务器地址
        #[arg(short, long)]
        server: Option<String>,

        /// 服务器端口
        #[arg(short = 'p', long)]
        server_port: Option<u16>,

        /// 本地地址
        #[arg(short = 'b', long)]
        local: Option<String>,

        /// 本地端口
        #[arg(short = 'l', long)]
        local_port: Option<u16>,

        /// 密码
        #[arg(short = 'k', long)]
        password: Option<String>,

        /// 加密方法
        #[arg(short = 'm', long)]
        method: Option<String>,
    },
    /// 生成配置文件模板
    GenConfig {
        /// 配置类型 (server/client)
        #[arg(value_enum)]
        config_type: ConfigType,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<String>,
    },
}

/// 配置类型
#[derive(clap::ValueEnum, Clone)]
enum ConfigType {
    Server,
    Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    init_logger();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            config,
            server,
            port,
            password,
            method,
        } => {
            info!("Starting in server mode");

            // 尝试从配置文件加载
            let mut server_config = if std::path::Path::new(&config).exists() {
                info!("Loading server config from: {}", config);
                load_config_from_file::<ServerConfig>(&config)?
            } else {
                info!("Config file not found, using default config");
                ServerConfig::default()
            };

            // 命令行参数覆盖配置文件
            if let Some(s) = server {
                server_config.server = s;
            }
            if let Some(p) = port {
                server_config.server_port = p;
            }
            if let Some(pwd) = password {
                server_config.password = pwd;
            }
            if let Some(m) = method {
                server_config.method = m;
            }

            // 验证配置
            if server_config.password.is_empty() {
                error!(
                    "Password is required. Please set it in config file or use --password option."
                );
                std::process::exit(1);
            }

            run_server(server_config).await?
        }
        Commands::Client {
            config,
            server,
            server_port,
            local,
            local_port,
            password,
            method,
        } => {
            info!("Starting in client mode");

            // 尝试从配置文件加载
            let mut client_config = if std::path::Path::new(&config).exists() {
                info!("Loading client config from: {}", config);
                load_config_from_file::<ClientConfig>(&config)?
            } else {
                info!("Config file not found, using default config");
                ClientConfig::default()
            };

            // 命令行参数覆盖配置文件
            if let Some(s) = server {
                client_config.server = s;
            }
            if let Some(p) = server_port {
                client_config.server_port = p;
            }
            if let Some(l) = local {
                client_config.local_address = l;
            }
            if let Some(lp) = local_port {
                client_config.local_port = lp;
            }
            if let Some(pwd) = password {
                client_config.password = pwd;
            }
            if let Some(m) = method {
                client_config.method = m;
            }

            // 验证配置
            if client_config.password.is_empty() {
                error!(
                    "Password is required. Please set it in config file or use --password option."
                );
                std::process::exit(1);
            }

            run_client(client_config).await?
        }
        Commands::GenConfig {
            config_type,
            output,
        } => match config_type {
            ConfigType::Server => {
                let config = ServerConfig {
                    server: "0.0.0.0".to_string(),
                    server_port: 8388,
                    password: "your_password_here".to_string(),
                    method: "aes-256-gcm".to_string(),
                    timeout: 300,
                    enable_udp: true,
                    max_connections: 1024,
                    enable_unified_port: false,
                    unified_port_config: None,
                };

                let toml_content = toml::to_string_pretty(&config)?;
                let output_file = output.unwrap_or_else(|| "server.toml".to_string());

                std::fs::write(&output_file, toml_content)?;
                info!("Server config template generated: {}", output_file);
            }
            ConfigType::Client => {
                let config = ClientConfig {
                    server: "your_server_ip".to_string(),
                    server_port: 8388,
                    local_address: "127.0.0.1".to_string(),
                    local_port: 1080,
                    password: "your_password_here".to_string(),
                    method: "aes-256-gcm".to_string(),
                    timeout: 300,
                    enable_udp: true,
                    local_udp_port: Some(1081),
                    max_connections: 1024,
                    enable_unified_port: false,
                    unified_port_config: None,
                };

                let toml_content = toml::to_string_pretty(&config)?;
                let output_file = output.unwrap_or_else(|| "client.toml".to_string());

                std::fs::write(&output_file, toml_content)?;
                info!("Client config template generated: {}", output_file);
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_verify() {
        // 验证CLI定义是否正确
        Cli::command().debug_assert();
    }

    #[test]
    fn test_server_command_parsing() {
        let args = vec![
            "simple-ssr",
            "server",
            "--config",
            "test.toml",
            "--server",
            "0.0.0.0",
            "--port",
            "8388",
            "--password",
            "test123",
            "--method",
            "aes-256-gcm",
        ];

        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::Server {
                config,
                server,
                port,
                password,
                method,
            } => {
                assert_eq!(config, "test.toml");
                assert_eq!(server, Some("0.0.0.0".to_string()));
                assert_eq!(port, Some(8388));
                assert_eq!(password, Some("test123".to_string()));
                assert_eq!(method, Some("aes-256-gcm".to_string()));
            }
            _ => panic!("Expected server command"),
        }
    }

    #[test]
    fn test_client_command_parsing() {
        let args = vec![
            "simple-ssr",
            "client",
            "--config",
            "client.toml",
            "--server",
            "192.168.1.100",
            "--server-port",
            "8388",
            "--local",
            "127.0.0.1",
            "--local-port",
            "1080",
            "--password",
            "test123",
            "--method",
            "aes-256-gcm",
        ];

        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::Client {
                config,
                server,
                server_port,
                local,
                local_port,
                password,
                method,
            } => {
                assert_eq!(config, "client.toml");
                assert_eq!(server, Some("192.168.1.100".to_string()));
                assert_eq!(server_port, Some(8388));
                assert_eq!(local, Some("127.0.0.1".to_string()));
                assert_eq!(local_port, Some(1080));
                assert_eq!(password, Some("test123".to_string()));
                assert_eq!(method, Some("aes-256-gcm".to_string()));
            }
            _ => panic!("Expected client command"),
        }
    }
}
