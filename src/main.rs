//! Shadowsocks 主程序入口
//!
//! 提供命令行界面来启动服务端或客户端

use anyhow::Result;
use clap::{Parser, Subcommand};
use simple_ssr::config::load_config_from_file;
use simple_ssr::utils::address::{
    ResolverType, resolve_domain_with_ldns, resolve_domain_with_resolver,
};
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
    /// 测试DNS解析功能
    TestDns {
        /// 要解析的域名
        #[arg(short, long)]
        domain: String,

        /// 端口号
        #[arg(short, long, default_value = "80")]
        port: u16,

        /// 使用LDNS解析器
        #[arg(short, long)]
        ldns: bool,

        /// 显示详细信息
        #[arg(short, long)]
        verbose: bool,
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
        Commands::TestDns {
            domain,
            port,
            ldns,
            verbose,
        } => {
            info!("Testing DNS resolution for: {}:{}", domain, port);

            if ldns {
                info!("Using LDNS resolver with LRU cache");
                match resolve_domain_with_ldns(&domain, port).await {
                    Ok(addrs) => {
                        info!(
                            "LDNS resolution successful! Found {} addresses:",
                            addrs.len()
                        );
                        for (i, addr) in addrs.iter().enumerate() {
                            info!("  [{}] {}", i + 1, addr);
                        }

                        if verbose {
                            // 显示缓存统计信息
                            if let Ok(resolver) =
                                simple_ssr::utils::dns::get_global_resolver().await
                            {
                                let stats = resolver.get_stats();
                                info!("Cache statistics:");
                                info!("  Total queries: {}", stats.total_queries);
                                info!("  Cache hits: {}", stats.cache_hits);
                                info!("  Cache misses: {}", stats.cache_misses);
                                info!("  Hit rate: {:.2}%", stats.cache_hit_rate() * 100.0);
                                info!("  Cache size: {}", resolver.cache_size().await);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LDNS resolution failed: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                info!("Using system resolver");
                match resolve_domain_with_resolver(&domain, port, ResolverType::System).await {
                    Ok(addrs) => {
                        info!(
                            "System resolution successful! Found {} addresses:",
                            addrs.len()
                        );
                        for (i, addr) in addrs.iter().enumerate() {
                            info!("  [{}] {}", i + 1, addr);
                        }
                    }
                    Err(e) => {
                        error!("System resolution failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            // 比较两种解析器的性能
            if verbose {
                info!("\nPerformance comparison:");

                let start = std::time::Instant::now();
                let _ = resolve_domain_with_resolver(&domain, port, ResolverType::System).await;
                let system_time = start.elapsed();

                let start = std::time::Instant::now();
                let _ = resolve_domain_with_ldns(&domain, port).await;
                let ldns_time = start.elapsed();

                info!("  System resolver: {:?}", system_time);
                info!("  LDNS resolver: {:?}", ldns_time);

                if ldns_time < system_time {
                    info!("  LDNS is faster by {:?}", system_time - ldns_time);
                } else {
                    info!("  System is faster by {:?}", ldns_time - system_time);
                }
            }
        }
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

    #[test]
    fn test_test_dns_command_parsing() {
        let args = vec![
            "simple-ssr",
            "test-dns",
            "--domain",
            "example.com",
            "--port",
            "443",
            "--ldns",
            "--verbose",
        ];

        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::TestDns {
                domain,
                port,
                ldns,
                verbose,
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
                assert!(ldns);
                assert!(verbose);
            }
            _ => panic!("Expected test-dns command"),
        }
    }

    #[test]
    fn test_test_dns_command_defaults() {
        let args = vec!["simple-ssr", "test-dns", "--domain", "localhost"];

        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::TestDns {
                domain,
                port,
                ldns,
                verbose,
            } => {
                assert_eq!(domain, "localhost");
                assert_eq!(port, 80); // 默认端口
                assert!(!ldns); // 默认不使用LDNS
                assert!(!verbose); // 默认不显示详细信息
            }
            _ => panic!("Expected test-dns command"),
        }
    }

    #[test]
    fn test_gen_config_command_parsing() {
        let args = vec![
            "simple-ssr",
            "gen-config",
            "server",
            "--output",
            "my_server.toml",
        ];

        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::GenConfig {
                config_type,
                output,
            } => {
                assert!(matches!(config_type, ConfigType::Server));
                assert_eq!(output, Some("my_server.toml".to_string()));
            }
            _ => panic!("Expected gen-config command"),
        }
    }
}
