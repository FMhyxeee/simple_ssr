# Simple Proxy - 多协议代理实现

一个高性能、安全的多协议代理实现，使用 Rust 语言开发，支持 Shadowsocks、VMess、SOCKS5、HTTP/HTTPS 代理。

## 特性

- 🚀 **高性能**: 基于 Tokio 异步运行时，支持高并发
- 🔒 **安全加密**: 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305
- 🌐 **全协议支持**: Shadowsocks、VMess、SOCKS5、HTTP/HTTPS 代理
- 🔄 **统一端口**: 智能协议检测，单端口支持多协议
- 🧬 **智能DNS解析**: 内置LDNS解析器，支持LRU缓存和高性能域名解析
- 📊 **实时监控**: 连接统计、流量监控、性能指标
- 🛠️ **易于配置**: TOML 配置文件，命令行参数
- 🔧 **模块化设计**: 清晰的代码结构，易于扩展
- 🏗️ **多协议架构**: 抽象协议接口，支持动态协议注册
- 📈 **可扩展性**: 基于Trait的协议工厂模式，易于添加新协议

## 快速开始

### 安装

```bash
# 克隆项目
git clone https://github.com/FMhyxeee/simple_proxy.git
cd simple_proxy

# 编译
cargo build --release
```

### 配置

#### 生成配置文件

```bash
# 生成服务端配置
./target/release/simple_proxy generate-config server --output server.toml

# 生成客户端配置
./target/release/simple_proxy generate-config client --output client.toml

# 生成完整配置模板
./target/release/simple_proxy generate-config template --with-examples --output config.toml
```

#### 服务端配置示例

```toml
[global]
mode = "server"
timeout = 300
max_connections = 1024
buffer_size = 8192
enable_udp = true
enable_unified_port = true

[global.unified_port]
listen_addr = "0.0.0.0:443"
detection_timeout = 1000
auto_detect = true
supported_protocols = ["shadowsocks", "vmess", "socks5", "http"]

[instances.shadowsocks-server]
protocol = "shadowsocks"
name = "shadowsocks-server"
listen_addr = "0.0.0.0:8388"
password = "your_secure_password"
method = "aes-256-gcm"
enabled = true
timeout = 300

[instances.vmess-server]
protocol = "vmess"
name = "vmess-server"
listen_addr = "0.0.0.0:10086"
user_id = "b831381d-6324-4d53-ad4f-8cda48b30811"
alter_id = 0
security = "aes-128-gcm"
enabled = true

[[routes]]
name = "local-direct"
source = "127.0.0.1:*"
target_instance = "socks5-proxy"
priority = 100

[logging]
level = "info"
console = true
format = "text"
```

#### 客户端配置示例

```toml
[global]
mode = "client"
timeout = 300
max_connections = 1024
buffer_size = 8192
enable_udp = true

[instances.socks5-client]
protocol = "socks5"
name = "socks5-client"
listen_addr = "127.0.0.1:1080"
auth = false
enabled = true

[instances.vmess-client]
protocol = "vmess"
name = "vmess-client"
listen_addr = "127.0.0.1:1081"
user_id = "b831381d-6324-4d53-ad4f-8cda48b30811"
alter_id = 0
security = "aes-128-gcm"
server_addr = "your_server_ip:10086"
enabled = true
```

### 运行

#### 启动服务端

```bash
./target/release/simple_proxy start --config server.toml
```

#### 启动客户端

```bash
./target/release/simple_proxy start --config client.toml
```

#### 验证配置

```bash
./target/release/simple_proxy validate --config config.toml
```

#### 查看状态

```bash
./target/release/simple_proxy status --config config.toml
```

### 使用代理

客户端启动后，可以通过以下方式使用代理：

- **SOCKS5 代理**: `127.0.0.1:1080`
- **VMess 代理**: `127.0.0.1:1081`
- **HTTP 代理**: `127.0.0.1:8080`
- **统一端口**: `127.0.0.1:443` (自动检测协议类型)

#### HTTP/HTTPS 代理使用

```bash
# 设置 HTTP 代理
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# 或在浏览器中配置
# HTTP 代理: 127.0.0.1:8080
# HTTPS 代理: 127.0.0.1:8080
```

## 支持的协议

### 代理协议

| 协议 | 类型 | 特性 | 用途 |
|------|------|------|------|
| Shadowsocks | 加密代理 | 高安全性，抗检测 | 突破网络限制 |
| VMess | 加密代理 | UUID认证，多种加密 | 现代代理协议 |
| SOCKS5 | 通用代理 | 标准协议，兼容性好 | 应用程序代理 |
| HTTP | 明文代理 | 简单易用，广泛支持 | Web 浏览代理 |
| HTTPS | 加密代理 | CONNECT 隧道 | 安全 Web 代理 |

### 加密方法

| 方法 | 密钥长度 | 安全性 | 性能 |
|------|----------|--------|------|
| aes-128-gcm | 128 位 | 高 | 很高 |
| aes-256-gcm | 256 位 | 很高 | 高 |
| chacha20-poly1305 | 256 位 | 很高 | 高 |

## DNS解析功能

内置高性能LDNS解析器，支持LRU缓存机制，提供比系统默认解析器更快的域名解析性能。

### 核心特性

- **高性能异步解析**: 基于trust-dns-resolver的异步DNS解析
- **LRU缓存机制**: 智能缓存DNS查询结果，减少重复解析
- **灵活配置**: 支持自定义缓存大小、TTL、超时时间等参数
- **统计监控**: 提供查询次数、缓存命中率等统计信息
- **多解析器支持**: 可选择使用系统解析器或LDNS解析器
- **IPv4/IPv6支持**: 同时支持A记录和AAAA记录解析

### 配置选项

```rust
// LDNS解析器配置
LdnsConfig {
    cache_size: 1000,           // LRU缓存大小
    default_ttl: 300,           // 默认TTL (秒)
    timeout: Duration::from_secs(5),  // 查询超时
    retries: 3,                 // 重试次数
    dns_servers: vec![          // 自定义DNS服务器
        "8.8.8.8:53".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
    ],
}
```

### 使用示例

```bash
# 使用系统解析器测试域名解析
./simple_proxy test-dns -d google.com -p 443

# 使用LDNS解析器测试域名解析
./simple_proxy test-dns -d google.com -p 443 --ldns

# 显示详细统计信息和性能对比
./simple_proxy test-dns -d google.com -p 443 --ldns -v
```

### 性能优势

- **缓存命中**: 重复查询同一域名时，直接从缓存返回结果
- **并发解析**: 支持多个域名同时解析，提高整体性能
- **智能TTL**: 根据DNS记录的TTL自动管理缓存过期
- **统计监控**: 实时监控解析性能和缓存效率

## 多协议架构

本项目采用现代化的多协议架构设计，基于抽象接口和工厂模式，支持动态协议注册和管理。

### 核心架构组件

#### 协议抽象接口
- **ProtocolHandler**: 协议处理器接口，处理入站连接
- **ProtocolClient**: 协议客户端接口，处理出站连接  
- **ProtocolFactory**: 协议工厂接口，动态创建处理器和客户端
- **ProtocolConfig**: 协议配置接口，统一配置管理

#### 协议管理器
- **ProtocolManager**: 统一管理多个协议实例的生命周期
- **ProtocolRegistry**: 协议注册表，支持动态协议注册
- **ProtocolRouter**: 协议路由器，根据规则分发流量

#### 配置系统
- **MultiProtocolConfig**: 统一的多协议配置管理
- **协议实例配置**: 支持不同协议的特定配置
- **路由规则**: 灵活的流量路由和分发策略

### VMess 协议实现

完整的 VMess 协议支持，包括：

#### 认证机制
- **UUID认证**: 基于 UUID 的用户身份验证
- **时间戳验证**: 防止重放攻击
- **HMAC签名**: 请求完整性验证

#### 加密支持
- **AES-128-GCM**: 高性能加密
- **AES-256-GCM**: 高安全性加密
- **ChaCha20-Poly1305**: 移动设备优化加密

#### 连接管理
- **TCP代理**: 完整的 TCP 连接代理
- **地址处理**: 支持 IPv4、IPv6、域名地址
- **错误处理**: 完善的错误处理和日志记录

### 协议扩展性

#### 添加新协议
1. 实现 `ProtocolHandler`、`ProtocolClient`、`ProtocolFactory` trait
2. 创建协议特定的配置结构
3. 在协议注册表中注册新协议
4. 更新配置系统支持新协议类型

#### 动态管理
- **运行时注册**: 支持运行时动态注册新协议
- **实例管理**: 独立的协议实例生命周期管理
- **状态监控**: 实时监控协议实例状态和性能

## 统一端口功能

统一端口功能允许在单个端口上同时支持多种协议，通过智能检测自动识别客户端使用的协议类型。

### 协议检测机制

- **HTTP 检测**: 识别 GET、POST、PUT、DELETE 等 HTTP 方法
- **HTTPS 检测**: 识别 TLS 握手包和 CONNECT 方法
- **SOCKS5 检测**: 识别 SOCKS5 握手包（版本号 0x05）
- **Shadowsocks 检测**: 基于数据包特征和地址类型检测
- **VMess 检测**: 识别 VMess 协议头和版本信息

### 配置示例

```toml
[global.unified_port]
listen_addr = "0.0.0.0:443"
detection_timeout = 1000
auto_detect = true
supported_protocols = ["shadowsocks", "vmess", "socks5", "http"]
```

### VMess 配置示例

#### 服务端配置
```toml
[instances.vmess-server]
protocol = "vmess"
name = "vmess-server"
listen_addr = "0.0.0.0:10086"
user_id = "b831381d-6324-4d53-ad4f-8cda48b30811"
alter_id = 0
security = "aes-128-gcm"
enabled = true
```

#### 客户端配置
```toml
[instances.vmess-client]
protocol = "vmess"
name = "vmess-client"
listen_addr = "127.0.0.1:1081"
user_id = "b831381d-6324-4d53-ad4f-8cda48b30811"
alter_id = 0
security = "aes-128-gcm"
server_addr = "your_server_ip:10086"
enabled = true
```

#### VMess URL分享格式
```
vmess://YWJjZDEyMzQtYWJjZC0xMjM0LWFiY2QtMTIzNDU2Nzg5MABAY3liZXItZXhhbXBsZS5jb206NDQzP2FsdGVySWQ9MCZzZWN1cml0eT1hZXMtMTI4LWdjbSZ0eXBlPXRjcCZob3N0PWN5YmVyLWV4YW1wbGUuY29tJnBhdGg9L3ZtZXNz
```

解码后包含：
- 用户ID (UUID)
- 服务器地址和端口
- 额外ID (alterId)
- 安全类型
- 网络类型 (tcp)
- 主机头和路径 (WebSocket模式)

## 命令行选项

```bash
# 查看帮助
./simple-proxy --help

# 启动多协议代理
./simple-proxy start [OPTIONS]
  -c, --config <FILE>         配置文件路径 (默认: config.toml)
  --validate                  验证配置但不启动
  --log-level <LEVEL>        日志级别 (默认: info)

# 生成配置文件
./simple-proxy generate-config [OPTIONS]
  <config_type>              配置类型 (server|client|template)
  -o, --output <FILE>        输出文件路径
  --with-examples            包含示例配置

# 验证配置文件
./simple-proxy validate [OPTIONS]
  -c, --config <FILE>        配置文件路径 (默认: config.toml)

# 查看协议状态
./simple-proxy status [OPTIONS]
  -c, --config <FILE>        配置文件路径 (默认: config.toml)

# 管理协议实例
./simple-proxy manage [OPTIONS]
  list [-c <FILE>]           列出所有协议实例
  start [-c <FILE>] <instance> 启动指定实例
  stop [-c <FILE>] <instance>  停止指定实例

# DNS解析测试
./simple-proxy test-dns [OPTIONS]
  -d, --domain <DOMAIN>      要解析的域名
  -p, --port <PORT>          目标端口 (默认: 80)
  --ldns                     使用LDNS解析器 (默认: 系统解析器)
  -v, --verbose              显示详细信息和性能统计
```

## 性能优化

### 系统优化

```bash
# Linux 系统优化
# 增加文件描述符限制
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# 优化网络参数
echo "net.core.rmem_max = 134217728" >> /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 87380 134217728" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 134217728" >> /etc/sysctl.conf
sysctl -p
```

### 配置优化

- 根据网络环境调整 `timeout` 值
- 根据服务器性能设置 `max_connections`
- 选择合适的加密方法平衡安全性和性能

## 监控和日志

### 启用详细日志

```bash
# 设置日志级别
RUST_LOG=info ./simple_ssr server -c config.json
RUST_LOG=debug ./simple_ssr client -c config.json
```

### 日志级别

- `error`: 错误信息
- `warn`: 警告信息
- `info`: 一般信息
- `debug`: 调试信息
- `trace`: 详细追踪信息

## 开发

### 构建要求

- Rust 1.70+
- Cargo

### 主要依赖

- `tokio` - 异步运行时
- `serde` / `toml` - 序列化/反序列化
- `trust-dns-resolver` - DNS解析器
- `lru` - LRU缓存实现
- `aes-gcm` / `chacha20poly1305` - 加密算法
- `uuid` - UUID生成和解析
- `async-trait` - 异步trait支持
- `clap` - 命令行参数解析
- `anyhow` / `thiserror` - 错误处理
- `tracing` / `log` - 日志记录
- `hmac` / `sha2` - 哈希消息认证码
- `regex` - 正则表达式支持
- `ipnetwork` - IP网络操作

### 开发构建

```bash
# 开发构建
cargo build

# 运行测试
cargo test

# 代码格式化
cargo fmt

# 静态检查
cargo clippy
```

### 项目结构

```
src/
├── lib.rs              # 库入口
├── main.rs             # 主程序
├── multi_app.rs        # 多协议应用程序
├── config/             # 配置管理
│   ├── mod.rs          # 配置模块导出
│   └── multi.rs        # 多协议配置管理
├── crypto/             # 加密模块
├── protocol/           # 协议实现
│   ├── mod.rs          # 协议模块导出
│   ├── traits.rs       # 协议抽象接口
│   ├── manager.rs      # 协议管理器
│   ├── vmess.rs        # VMess 协议
│   ├── shadowsocks.rs  # Shadowsocks 协议
│   ├── socks5.rs       # SOCKS5 协议
│   ├── http.rs         # HTTP/HTTPS 协议
│   └── address.rs      # 地址处理
├── server/             # 服务端
├── client/             # 客户端
├── unified/            # 统一端口模块
│   ├── detector.rs     # 协议检测器
│   ├── router.rs       # 请求路由器
│   ├── listener.rs     # 统一监听器
│   └── config.rs       # 统一配置
└── utils/              # 工具函数
    ├── address.rs      # 地址解析和处理
    ├── dns.rs          # LDNS解析器和LRU缓存
    └── mod.rs          # 工具模块导出
```

## 故障排除

### 常见问题

#### 连接失败

1. 检查服务器地址和端口是否正确
2. 确认密码和加密方法匹配
3. 检查防火墙设置
4. 验证网络连通性
5. 确认协议类型是否支持

#### HTTP/HTTPS 代理问题

1. **浏览器无法连接**
   - 检查代理设置是否正确
   - 确认 HTTP 代理端口是否开启
   - 验证防火墙是否阻止连接

2. **HTTPS 网站无法访问**
   - 确认支持 CONNECT 方法
   - 检查 TLS 握手是否正常
   - 验证证书链是否完整

3. **协议检测失败**
   - 增加检测超时时间
   - 启用详细日志查看检测过程
   - 检查数据包是否完整

#### 性能问题

1. 检查系统资源使用情况
2. 调整最大连接数设置
3. 优化网络参数
4. 选择合适的加密方法
5. 调整协议检测超时时间

#### 内存使用过高

1. 检查连接数是否过多
2. 调整超时设置
3. 监控会话清理情况
4. 检查协议检测缓存
5. 调整DNS缓存大小设置

#### DNS解析问题

1. **域名解析失败**
   - 检查网络连接是否正常
   - 验证DNS服务器是否可达
   - 尝试使用不同的DNS服务器
   - 检查域名是否存在

2. **解析速度慢**
   - 启用LDNS解析器提高性能
   - 调整DNS查询超时时间
   - 增加DNS缓存大小
   - 检查网络延迟情况

3. **缓存问题**
   - 检查缓存命中率统计
   - 调整缓存TTL设置
   - 清空DNS缓存重新测试
   - 监控缓存内存使用情况

### 调试技巧

```bash
# 网络连接测试
telnet server_ip server_port

# 端口监听检查
netstat -tlnp | grep :8388
netstat -tlnp | grep :8389  # 统一端口
netstat -tlnp | grep :8080  # HTTP 代理端口

# 进程监控
top -p $(pgrep simple_proxy)

# 网络流量监控
iftop -i eth0

# HTTP 代理测试
curl -x http://127.0.0.1:8080 http://httpbin.org/ip
curl -x http://127.0.0.1:8080 https://httpbin.org/ip

# 协议检测测试
echo "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc 127.0.0.1 8389

# DNS解析测试
./simple_proxy test-dns -d google.com --ldns -v
./simple_proxy test-dns -d github.com -p 443 --ldns
nslookup google.com
dig google.com @8.8.8.8
```

## 使用示例

### 浏览器配置

#### Chrome/Chromium
```bash
# 启动时指定代理
chrome --proxy-server="http://127.0.0.1:8080"

# 或使用 SOCKS5 代理
chrome --proxy-server="socks5://127.0.0.1:1080"
```

#### Firefox
1. 打开设置 → 网络设置
2. 选择"手动代理配置"
3. HTTP 代理: `127.0.0.1:8080`
4. HTTPS 代理: `127.0.0.1:8080`

### 命令行工具

```bash
# curl 使用 HTTP 代理
curl -x http://127.0.0.1:8080 https://www.google.com

# wget 使用 HTTP 代理
wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 https://www.google.com

# git 使用代理
git config --global http.proxy http://127.0.0.1:8080
git config --global https.proxy http://127.0.0.1:8080
```

## 安全建议

### 通用安全

1. **使用强密码**: 建议使用 32 字符以上的随机密码
2. **定期更换密码**: 建议每月更换一次密码
3. **选择安全的加密方法**: 推荐使用 `aes-256-gcm` 或 `chacha20-poly1305`
4. **限制连接数**: 根据实际需求设置合理的最大连接数
5. **监控异常**: 定期检查日志，发现异常及时处理
6. **网络隔离**: 在可能的情况下使用网络隔离

### HTTP/HTTPS 代理安全

1. **访问控制**: 限制 HTTP 代理的访问来源，避免开放给公网
2. **日志监控**: 记录 HTTP 请求日志，监控异常访问模式
3. **请求过滤**: 对恶意请求进行过滤和阻断
4. **带宽限制**: 设置合理的带宽限制，防止滥用
5. **协议限制**: 根据需要禁用不必要的 HTTP 方法
6. **证书验证**: 对 HTTPS 连接进行适当的证书验证

### 统一端口安全

1. **协议白名单**: 只启用必要的协议类型
2. **检测超时**: 设置合理的协议检测超时时间
3. **连接限制**: 对单个 IP 的连接数进行限制
4. **异常检测**: 监控协议检测失败的情况

## 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 本项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

