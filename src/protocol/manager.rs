//! 多协议管理器
//!
//! 管理多个代理协议实例，提供统一的接口

use anyhow::Result;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use crate::protocol::traits::{
    ProtocolClient, ProtocolConfig, ProtocolFactory, ProtocolHandler, ProtocolRegistry,
    ProtocolType,
};

/// 协议实例信息
pub struct ProtocolInstance {
    /// 实例ID
    pub id: String,
    
    /// 协议类型
    pub protocol_type: ProtocolType,
    
    /// 配置
    pub config: Box<dyn ProtocolConfig>,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// 运行状态
    pub is_running: bool,
    
    /// 启用状态
    pub enabled: bool,
}

impl Clone for ProtocolInstance {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            protocol_type: self.protocol_type.clone(),
            config: self.config.clone_config(),
            listen_addr: self.listen_addr.clone(),
            is_running: self.is_running,
            enabled: self.enabled,
        }
    }
}

impl std::fmt::Debug for ProtocolInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolInstance")
            .field("id", &self.id)
            .field("protocol_type", &self.protocol_type)
            .field("listen_addr", &self.listen_addr)
            .field("is_running", &self.is_running)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// 协议管理器
/// 管理多个协议实例的生命周期
pub struct ProtocolManager {
    /// 协议注册表
    registry: Arc<ProtocolRegistry>,
    
    /// 协议实例
    instances: Arc<RwLock<HashMap<String, ProtocolInstance>>>,
    
    /// 协议处理器
    handlers: Arc<Mutex<HashMap<String, Box<dyn ProtocolHandler>>>>,
    
    /// 协议客户端
    clients: Arc<RwLock<HashMap<String, Box<dyn ProtocolClient>>>>,
}

impl ProtocolManager {
    /// 创建新的协议管理器
    pub fn new(registry: Arc<ProtocolRegistry>) -> Self {
        Self {
            registry,
            instances: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 注册协议工厂
    pub async fn register_protocol(&self, factory: Box<dyn ProtocolFactory>) {
        let protocol_type = factory.protocol_type();
        // 由于Arc是只读的，我们需要使用其他方法
        // 暂时先记录日志，不实际注册
        info!("Protocol type received for registration: {}", protocol_type);
    }

    /// 添加协议实例
    pub async fn add_instance(&self, instance: ProtocolInstance) -> Result<String> {
        let instance_id = instance.id.clone();
        
        // 验证配置
        instance.config.validate()?;
        
        // 检查协议是否支持
        if !self.registry.is_protocol_supported(&instance.protocol_type) {
            return Err(anyhow::anyhow!(
                "Protocol {} is not supported",
                instance.protocol_type
            ));
        }
        
        // 存储实例信息
        let mut instances = self.instances.write().await;
        instances.insert(instance_id.clone(), instance.clone());
        
        info!("Added protocol instance: {} ({})", instance_id, instance.protocol_type);
        Ok(instance_id)
    }

    /// 启动协议实例
    pub async fn start_instance(&self, instance_id: &str) -> Result<()> {
        let instances = self.instances.read().await;
        let instance = instances.get(instance_id).ok_or_else(|| {
            anyhow::anyhow!("Protocol instance {} not found", instance_id)
        })?;

        if instance.is_running {
            warn!("Protocol instance {} is already running", instance_id);
            return Ok(());
        }

        // 获取协议工厂
        let factory = self.registry.get_factory(&instance.protocol_type).ok_or_else(|| {
            anyhow::anyhow!("No factory found for protocol {}", instance.protocol_type)
        })?;

        // 创建协议处理器
        let config = instance.config.clone_config();
        let handler = factory.create_server(config)?;
        
        // 创建TCP监听器
        let listen_addr = instance.config.listen_address()?;
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        
        // 启动协议处理器
        let handler_id = instance_id.to_string();
        
        // 在单独的task中启动服务器
        let mut handler_for_task = factory.create_server(instance.config.clone_config())?;
        let _listener_handle = tokio::spawn(async move {
            if let Err(e) = handler_for_task.start_server(listener).await {
                error!("Protocol server {} error: {}", handler_id, e);
            }
        });

        // 存储处理器
        let mut handlers = self.handlers.lock().await;
        handlers.insert(instance_id.to_string(), handler);

        // 更新实例状态
        drop(instances);
        let mut instances = self.instances.write().await;
        if let Some(instance) = instances.get_mut(instance_id) {
            instance.is_running = true;
        }

        info!("Started protocol instance: {}", instance_id);
        Ok(())
    }

    /// 停止协议实例
    pub async fn stop_instance(&self, instance_id: &str) -> Result<()> {
        let mut instances = self.instances.write().await;
        let instance = instances.get_mut(instance_id).ok_or_else(|| {
            anyhow::anyhow!("Protocol instance {} not found", instance_id)
        })?;

        if !instance.is_running {
            warn!("Protocol instance {} is not running", instance_id);
            return Ok(());
        }

        // 停止协议处理器
        let mut handlers = self.handlers.lock().await;
        if let Some(mut handler) = handlers.remove(instance_id) {
            if let Err(e) = handler.stop_server().await {
                error!("Error stopping protocol handler {}: {}", instance_id, e);
            }
        }

        // 更新实例状态
        instance.is_running = false;

        info!("Stopped protocol instance: {}", instance_id);
        Ok(())
    }

    /// 移除协议实例
    pub async fn remove_instance(&self, instance_id: &str) -> Result<()> {
        // 先停止实例
        if self.is_instance_running(instance_id).await {
            self.stop_instance(instance_id).await?;
        }

        // 移除实例
        let mut instances = self.instances.write().await;
        instances.remove(instance_id);

        // 移除处理器
        let mut handlers = self.handlers.lock().await;
        handlers.remove(instance_id);

        // 移除客户端
        let mut clients = self.clients.write().await;
        clients.remove(instance_id);

        info!("Removed protocol instance: {}", instance_id);
        Ok(())
    }

    /// 获取协议实例
    pub async fn get_instance(&self, instance_id: &str) -> Option<ProtocolInstance> {
        let instances = self.instances.read().await;
        instances.get(instance_id).cloned()
    }

    /// 获取所有协议实例
    pub async fn get_all_instances(&self) -> Vec<ProtocolInstance> {
        let instances = self.instances.read().await;
        instances.values().cloned().collect()
    }

    /// 获取指定协议类型的实例
    pub async fn get_instances_by_protocol(&self, protocol_type: &ProtocolType) -> Vec<ProtocolInstance> {
        let instances = self.instances.read().await;
        instances
            .values()
            .filter(|instance| instance.protocol_type == *protocol_type)
            .cloned()
            .collect()
    }

    /// 检查实例是否在运行
    pub async fn is_instance_running(&self, instance_id: &str) -> bool {
        let instances = self.instances.read().await;
        instances
            .get(instance_id)
            .map(|instance| instance.is_running)
            .unwrap_or(false)
    }

    /// 创建协议客户端
    pub async fn create_client(&self, instance_id: &str) -> Result<Box<dyn ProtocolClient>> {
        let instances = self.instances.read().await;
        let instance = instances.get(instance_id).ok_or_else(|| {
            anyhow::anyhow!("Protocol instance {} not found", instance_id)
        })?;

        // 获取协议工厂
        let factory = self.registry.get_factory(&instance.protocol_type).ok_or_else(|| {
            anyhow::anyhow!("No factory found for protocol {}", instance.protocol_type)
        })?;

        // 创建协议客户端
        let client = factory.create_client(instance.config.clone_config())?;

        // 存储客户端的克隆
        let client_clone = factory.create_client(instance.config.clone_config())?;
        let mut clients = self.clients.write().await;
        clients.insert(instance_id.to_string(), client_clone);

        Ok(client)
    }

    /// 获取协议客户端
    pub async fn get_client(&self, instance_id: &str) -> Option<Box<dyn ProtocolClient>> {
        let clients = self.clients.read().await;
        clients.get(instance_id).map(|_client| {
            // 注意：这里需要实现客户端的克隆机制
            // 目前返回一个占位符
            unimplemented!("Client cloning not yet implemented")
        })
    }

    /// 获取支持的协议列表
    pub fn supported_protocols(&self) -> Vec<ProtocolType> {
        self.registry.registered_protocols()
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ProtocolManagerStats {
        let instances = self.instances.read().await;
        let handlers = self.handlers.lock().await;
        let clients = self.clients.read().await;

        ProtocolManagerStats {
            total_instances: instances.len(),
            running_instances: instances.values().filter(|instance| instance.is_running).count(),
            active_handlers: handlers.len(),
            active_clients: clients.len(),
            supported_protocols: self.supported_protocols(),
        }
    }

    /// 启动所有启用的实例
    pub async fn start_all_instances(&self) -> Result<()> {
        let instances = self.instances.read().await;
        let mut failed_instances = Vec::new();

        for (instance_id, instance) in instances.iter() {
            if instance.config.protocol_type() != ProtocolType::HTTP && instance.enabled {
                if let Err(e) = self.start_instance(instance_id).await {
                    error!("Failed to start instance {}: {}", instance_id, e);
                    failed_instances.push(instance_id.clone());
                }
            }
        }

        if !failed_instances.is_empty() {
            warn!("Failed to start {} instances: {:?}", failed_instances.len(), failed_instances);
        }

        Ok(())
    }

    /// 停止所有运行的实例
    pub async fn stop_all_instances(&self) -> Result<()> {
        let instances = self.instances.read().await;
        let mut failed_instances = Vec::new();

        for (instance_id, instance) in instances.iter() {
            if instance.is_running {
                if let Err(e) = self.stop_instance(instance_id).await {
                    error!("Failed to stop instance {}: {}", instance_id, e);
                    failed_instances.push(instance_id.clone());
                }
            }
        }

        if !failed_instances.is_empty() {
            warn!("Failed to stop {} instances: {:?}", failed_instances.len(), failed_instances);
        }

        Ok(())
    }
}

/// 协议管理器统计信息
#[derive(Debug, Clone)]
pub struct ProtocolManagerStats {
    /// 总实例数
    pub total_instances: usize,
    
    /// 运行中的实例数
    pub running_instances: usize,
    
    /// 活跃的处理器数
    pub active_handlers: usize,
    
    /// 活跃的客户端数
    pub active_clients: usize,
    
    /// 支持的协议列表
    pub supported_protocols: Vec<ProtocolType>,
}

/// 协议路由器
/// 根据配置将流量路由到不同的协议实例
pub struct ProtocolRouter {
    /// 协议管理器
    manager: Arc<ProtocolManager>,
    
    /// 路由规则
    routes: Arc<RwLock<Vec<RouteRule>>>,
}

impl ProtocolRouter {
    /// 创建新的协议路由器
    pub fn new(manager: Arc<ProtocolManager>) -> Self {
        Self {
            manager,
            routes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 添加路由规则
    pub async fn add_route(&self, rule: RouteRule) -> Result<()> {
        let mut routes = self.routes.write().await;
        routes.push(rule);
        Ok(())
    }

    /// 路由连接到合适的协议实例
    pub async fn route_connection(
        &self,
        client_addr: std::net::SocketAddr,
        target_addr: std::net::SocketAddr,
    ) -> Result<String> {
        let routes = self.routes.read().await;
        
        // 查找匹配的路由规则
        for rule in routes.iter() {
            if rule.matches(client_addr, target_addr) {
                return Ok(rule.target_instance.clone());
            }
        }

        // 如果没有匹配的规则，返回默认实例
        Err(anyhow::anyhow!("No matching route found for connection from {} to {}", client_addr, target_addr))
    }

    /// 获取所有路由规则
    pub async fn get_routes(&self) -> Vec<RouteRule> {
        let routes = self.routes.read().await;
        routes.clone()
    }

    /// 清除所有路由规则
    pub async fn clear_routes(&self) -> Result<()> {
        let mut routes = self.routes.write().await;
        routes.clear();
        Ok(())
    }
}

/// 路由规则
#[derive(Debug, Clone)]
pub struct RouteRule {
    /// 规则名称
    pub name: String,
    
    /// 源地址模式
    pub source_pattern: Option<String>,
    
    /// 目标地址模式
    pub target_pattern: Option<String>,
    
    /// 协议类型过滤
    pub protocol_filter: Option<ProtocolType>,
    
    /// 目标实例ID
    pub target_instance: String,
    
    /// 优先级
    pub priority: u32,
}

impl RouteRule {
    /// 检查规则是否匹配给定的连接
    pub fn matches(&self, client_addr: std::net::SocketAddr, target_addr: std::net::SocketAddr) -> bool {
        // 检查源地址模式
        if let Some(ref source_pattern) = self.source_pattern {
            if !self.addr_matches_pattern(client_addr, source_pattern) {
                return false;
            }
        }

        // 检查目标地址模式
        if let Some(ref target_pattern) = self.target_pattern {
            if !self.addr_matches_pattern(target_addr, target_pattern) {
                return false;
            }
        }

        true
    }

    /// 检查地址是否匹配模式
    fn addr_matches_pattern(&self, addr: std::net::SocketAddr, pattern: &str) -> bool {
        // 简单的模式匹配
        // 可以扩展为支持更复杂的模式，如CIDR、通配符等
        if pattern.contains('*') {
            // 通配符匹配
            let addr_str = addr.to_string();
            let pattern_regex = pattern.replace('.', r"\.").replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&format!("^{}$", pattern_regex)) {
                return regex.is_match(&addr_str);
            }
        } else if pattern.contains('/') {
            // CIDR匹配
            if let Ok(cidr) = ipnetwork::IpNetwork::from_str(pattern) {
                return cidr.contains(addr.ip());
            }
        } else {
            // 精确匹配
            return addr.to_string() == pattern || addr.ip().to_string() == pattern;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vmess::VmessConfig;

    #[tokio::test]
    async fn test_protocol_manager() {
        let mut registry = ProtocolRegistry::new();
        // 注册VMess协议工厂
        registry.register(Box::new(crate::protocol::vmess::VmessFactory));
        let registry = Arc::new(registry);
        let manager = Arc::new(ProtocolManager::new(registry));

        // 创建测试实例
        let config = VmessConfig {
            listen_addr: "127.0.0.1:8388".to_string(),
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "aes-128-gcm".to_string(),
            enabled: true,
        };

        let instance = ProtocolInstance {
            id: "test-vmess".to_string(),
            protocol_type: ProtocolType::VMess,
            config: Box::new(config),
            listen_addr: "127.0.0.1:8388".to_string(),
            is_running: false,
            enabled: true,
        };

        // 添加实例
        let instance_id = manager.add_instance(instance).await.unwrap();
        assert_eq!(instance_id, "test-vmess");

        // 获取实例
        let retrieved_instance = manager.get_instance("test-vmess").await.unwrap();
        assert_eq!(retrieved_instance.id, "test-vmess");

        // 获取所有实例
        let all_instances = manager.get_all_instances().await;
        assert_eq!(all_instances.len(), 1);
    }

    #[test]
    fn test_route_rule_matching() {
        let rule = RouteRule {
            name: "test-rule".to_string(),
            source_pattern: Some("127.0.0.1:*".to_string()),
            target_pattern: None,
            protocol_filter: None,
            target_instance: "test-instance".to_string(),
            priority: 1,
        };

        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let target_addr = "192.168.1.1:80".parse().unwrap();

        assert!(rule.matches(client_addr, target_addr));

        let client_addr2 = "192.168.1.100:54321".parse().unwrap();
        assert!(!rule.matches(client_addr2, target_addr));
    }
}