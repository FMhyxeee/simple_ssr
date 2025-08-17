//! 多协议代理应用程序
//!
//! 支持多种代理协议的统一应用程序入口点

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing::{error, info};

use crate::config::MultiProtocolConfig;
use crate::protocol::manager::ProtocolManager;
use crate::protocol::traits::ProtocolRegistry;
use crate::protocol::vmess::VmessFactory;

/// 多协议代理命令行工具
#[derive(Parser)]
#[command(name = "simple-proxy")]
#[command(about = "A multi-protocol proxy implementation in Rust")]
#[command(version = "0.2.0")]
struct MultiProtocolCli {
    #[command(subcommand)]
    command: Commands,
}

/// 可用的命令
#[derive(Subcommand)]
enum Commands {
    /// 启动多协议代理服务器
    Start {
        /// 配置文件路径
        #[arg(short, long, default_value = "config.toml")]
        config: String,

        /// 验证配置但不启动
        #[arg(long)]
        validate: bool,

        /// 日志级别
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// 生成配置模板
    GenerateConfig {
        /// 配置类型 (server/client/template)
        #[arg(value_enum)]
        config_type: ConfigType,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<String>,

        /// 包含示例配置
        #[arg(long)]
        with_examples: bool,
    },

    /// 验证配置文件
    Validate {
        /// 配置文件路径
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },

    /// 显示协议状态
    Status {
        /// 配置文件路径
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },

    /// 管理协议实例
    Manage {
        #[command(subcommand)]
        action: ManageAction,
    },
}

/// 管理操作
#[derive(Subcommand)]
enum ManageAction {
    /// 列出所有协议实例
    List {
        /// 配置文件路径
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },

    /// 启动指定实例
    Start {
        /// 配置文件路径
        #[arg(short, long, default_value = "config.toml")]
        config: String,

        /// 实例名称
        instance: String,
    },

    /// 停止指定实例
    Stop {
        /// 配置文件路径
        #[arg(short, long, default_value = "config.toml")]
        config: String,

        /// 实例名称
        instance: String,
    },
}

/// 配置类型
#[derive(clap::ValueEnum, Clone)]
enum ConfigType {
    Server,
    Client,
    Template,
}

/// 多协议代理应用程序
pub struct MultiProtocolApp {
    /// 协议注册表
    registry: Arc<ProtocolRegistry>,
    
    /// 协议管理器
    manager: Arc<ProtocolManager>,
    
    /// 配置
    config: Option<MultiProtocolConfig>,
}

impl MultiProtocolApp {
    /// 创建新的多协议代理应用程序
    pub fn new() -> Self {
        let registry = Arc::new(ProtocolRegistry::new());
        let manager = Arc::new(ProtocolManager::new(registry.clone()));
        
        Self {
            registry,
            manager,
            config: None,
        }
    }

    /// 初始化协议注册表
    async fn init_protocols(&self) -> Result<()> {
        // 注册VMess协议
        self.manager.register_protocol(Box::new(VmessFactory)).await;
        
        // TODO: 注册其他协议
        // self.manager.register_protocol(Box::new(ShadowsocksFactory)).await;
        // self.manager.register_protocol(Box::new(Socks5Factory)).await;
        
        info!("Registered {} protocols", self.registry.registered_protocols().len());
        
        for protocol_type in self.registry.registered_protocols() {
            info!("  - {}", protocol_type);
        }
        
        Ok(())
    }

    /// 加载配置
    async fn load_config(&mut self, config_path: &str) -> Result<()> {
        info!("Loading configuration from: {}", config_path);
        
        let config = MultiProtocolConfig::from_file(config_path).await?;
        config.validate()?;
        
        self.config = Some(config);
        
        info!("Configuration loaded successfully");
        Ok(())
    }

    /// 启动所有启用的协议实例
    async fn start_instances(&self) -> Result<()> {
        if let Some(ref config) = self.config {
            let enabled_instances = config.enabled_instances();
            
            info!("Starting {} protocol instances...", enabled_instances.len());
            
            for (instance_name, instance_config) in enabled_instances {
                info!("Starting instance: {} ({})", instance_name, instance_config.protocol_type());
                
                // 创建协议实例
                let instance = crate::protocol::manager::ProtocolInstance {
                    id: instance_name.clone(),
                    protocol_type: instance_config.protocol_type(),
                    config: self.create_protocol_config(instance_config)?,
                    listen_addr: instance_config.listen_addr().to_string(),
                    is_running: false,
                    enabled: instance_config.is_enabled(),
                };
                
                // 添加到管理器
                self.manager.add_instance(instance).await?;
                
                // 启动实例
                if let Err(e) = self.manager.start_instance(&instance_name).await {
                    error!("Failed to start instance {}: {}", instance_name, e);
                }
            }
            
            // 显示统计信息
            self.show_stats().await;
        }
        
        Ok(())
    }

    /// 创建协议配置
    fn create_protocol_config(
        &self,
        instance_config: &crate::config::multi::ProtocolInstanceConfig,
    ) -> Result<Box<dyn crate::protocol::traits::ProtocolConfig>> {
        use crate::config::multi::ProtocolInstanceConfig;
        
        match instance_config {
            ProtocolInstanceConfig::VMess(vmess_config) => {
                let vmess_config = crate::protocol::vmess::VmessConfig {
                    listen_addr: vmess_config.listen_addr.clone(),
                    user_id: vmess_config.user_id.clone(),
                    alter_id: vmess_config.alter_id,
                    security: vmess_config.security.clone(),
                    enabled: vmess_config.enabled,
                };
                Ok(Box::new(vmess_config))
            }
            // TODO: 实现其他协议的配置转换
            _ => Err(anyhow::anyhow!(
                "Protocol config conversion not implemented for: {:?}",
                instance_config.protocol_type()
            )),
        }
    }

    /// 显示统计信息
    async fn show_stats(&self) {
        let stats = self.manager.get_stats().await;
        
        info!("=== Protocol Manager Statistics ===");
        info!("Total instances: {}", stats.total_instances);
        info!("Running instances: {}", stats.running_instances);
        info!("Active handlers: {}", stats.active_handlers);
        info!("Active clients: {}", stats.active_clients);
        info!("Supported protocols: {}", stats.supported_protocols.len());
        
        for protocol in stats.supported_protocols {
            info!("  - {}", protocol);
        }
    }

    /// 运行应用程序
    pub async fn run(&mut self) -> Result<()> {
        let cli = MultiProtocolCli::parse();
        
        match cli.command {
            Commands::Start {
                config,
                validate,
                log_level,
            } => {
                self.start_command(config, validate, log_level).await?;
            }
            Commands::GenerateConfig {
                config_type,
                output,
                with_examples,
            } => {
                self.generate_config_command(config_type, output, with_examples).await?;
            }
            Commands::Validate { config } => {
                self.validate_config_command(config).await?;
            }
            Commands::Status { config } => {
                self.status_command(config).await?;
            }
            Commands::Manage { action } => {
                self.manage_command(action).await?;
            }
        }
        
        Ok(())
    }

    /// 启动命令
    async fn start_command(
        &mut self,
        config_path: String,
        validate_only: bool,
        log_level: String,
    ) -> Result<()> {
        // 设置日志级别
        self.set_log_level(&log_level);
        
        // 初始化协议
        self.init_protocols().await?;
        
        // 加载配置
        self.load_config(&config_path).await?;
        
        if validate_only {
            info!("Configuration validation passed");
            return Ok(());
        }
        
        // 启动实例
        self.start_instances().await?;
        
        // 等待中断信号
        info!("Server started successfully. Press Ctrl+C to stop.");
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
        
        // 停止所有实例
        if let Err(e) = self.manager.stop_all_instances().await {
            error!("Error stopping instances: {}", e);
        }
        
        Ok(())
    }

    /// 生成配置命令
    async fn generate_config_command(
        &self,
        config_type: ConfigType,
        output: Option<String>,
        with_examples: bool,
    ) -> Result<()> {
        let config = match config_type {
            ConfigType::Server => MultiProtocolConfig::default_server(),
            ConfigType::Client => MultiProtocolConfig::default_client(),
            ConfigType::Template => {
                if with_examples {
                    MultiProtocolConfig::generate_template()
                } else {
                    MultiProtocolConfig::default()
                }
            }
        };
        
        let output_file = output.unwrap_or_else(|| match config_type {
            ConfigType::Server => "server.toml".to_string(),
            ConfigType::Client => "client.toml".to_string(),
            ConfigType::Template => "config.toml".to_string(),
        });
        
        config.to_file(&output_file).await?;
        info!("Configuration generated: {}", output_file);
        
        Ok(())
    }

    /// 验证配置命令
    async fn validate_config_command(&mut self, config_path: String) -> Result<()> {
        self.load_config(&config_path).await?;
        info!("Configuration validation passed");
        Ok(())
    }

    /// 状态命令
    async fn status_command(&mut self, config_path: String) -> Result<()> {
        self.load_config(&config_path).await?;
        
        if let Some(ref config) = self.config {
            info!("=== Configuration Status ===");
            info!("Mode: {}", config.global.mode);
            info!("Timeout: {}s", config.global.timeout);
            info!("Max connections: {}", config.global.max_connections);
            info!("UDP enabled: {}", config.global.enable_udp);
            info!("Unified port: {}", config.global.enable_unified_port);
            
            info!("\n=== Protocol Instances ===");
            for (name, instance) in &config.instances {
                let status = if instance.is_enabled() { "Enabled" } else { "Disabled" };
                info!("{}: {} ({})", name, instance.protocol_type(), status);
            }
            
            info!("\n=== Routes ===");
            for route in &config.routes {
                info!("{} -> {} (priority: {})", route.name, route.target_instance, route.priority);
            }
        }
        
        Ok(())
    }

    /// 管理命令
    async fn manage_command(&self, action: ManageAction) -> Result<()> {
        match action {
            ManageAction::List { config } => {
                self.list_instances_command(config).await?;
            }
            ManageAction::Start { config, instance } => {
                self.start_instance_command(config, instance).await?;
            }
            ManageAction::Stop { config, instance } => {
                self.stop_instance_command(config, instance).await?;
            }
        }
        Ok(())
    }

    /// 列出实例命令
    async fn list_instances_command(&self, config_path: String) -> Result<()> {
        // TODO: 实现实例列表功能
        info!("Listing instances from: {}", config_path);
        Ok(())
    }

    /// 启动实例命令
    async fn start_instance_command(&self, config_path: String, instance: String) -> Result<()> {
        // TODO: 实现启动单个实例功能
        info!("Starting instance {} from: {}", instance, config_path);
        Ok(())
    }

    /// 停止实例命令
    async fn stop_instance_command(&self, config_path: String, instance: String) -> Result<()> {
        // TODO: 实现停止单个实例功能
        info!("Stopping instance {} from: {}", instance, config_path);
        Ok(())
    }

    /// 设置日志级别
    fn set_log_level(&self, level: &str) {
        use tracing_subscriber::EnvFilter;
        
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(level));
        
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .init();
    }
}

impl Default for MultiProtocolApp {
    fn default() -> Self {
        Self::new()
    }
}

/// 启动多协议代理应用程序
pub async fn run_multi_protocol_app() -> Result<()> {
    let mut app = MultiProtocolApp::new();
    app.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_creation() {
        let app = MultiProtocolApp::new();
        assert_eq!(app.registry.registered_protocols().len(), 0);
    }

    #[tokio::test]
    async fn test_config_generation() {
        let app = MultiProtocolApp::new();
        
        // 测试生成服务器配置
        let config = MultiProtocolConfig::default_server();
        assert_eq!(config.global.mode, "server");
        
        // 测试生成客户端配置
        let config = MultiProtocolConfig::default_client();
        assert_eq!(config.global.mode, "client");
    }
}