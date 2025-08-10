# Simple SSR - 多协议代理实现

一个高性能、安全的多协议代理实现，使用 Rust 语言开发，支持 Shadowsocks、SOCKS5、HTTP/HTTPS 代理。

## 特性

- 🚀 **高性能**: 基于 Tokio 异步运行时，支持高并发
- 🔒 **安全加密**: 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305
- 🌐 **全协议支持**: TCP、UDP、SOCKS5、HTTP/HTTPS 代理
- 🔄 **统一端口**: 智能协议检测，单端口支持多协议
- 📊 **实时监控**: 连接统计、流量监控、性能指标
- 🛠️ **易于配置**: JSON/YAML 配置文件，命令行参数
- 🔧 **模块化设计**: 清晰的代码结构，易于扩展

## 快速开始

### 安装

```bash
# 克隆项目
git clone https://github.com/your-username/simple_ssr.git
cd simple_ssr

# 编译
cargo build --release
```

### 配置

#### 生成配置文件

```bash
# 生成服务端配置
./target/release/simple_ssr generate-config --type server > server.json

# 生成客户端配置
./target/release/simple_ssr generate-config --type client > client.json
```

#### 服务端配置示例

```json
{
  "server_addr": "0.0.0.0",
  "server_port": 8388,
  "password": "your_secure_password",
  "method": "aes-256-gcm",
  "timeout": 300,
  "udp_enabled": true,
  "max_connections": 1000,
  "unified_port": {
    "enabled": true,
    "port": 8389,
    "protocols": ["shadowsocks", "socks5", "http", "https"]
  }
}
```

#### 客户端配置示例

```json
{
  "server_addr": "your_server_ip",
  "server_port": 8388,
  "local_addr": "127.0.0.1",
  "local_port": 1080,
  "password": "your_secure_password",
  "method": "aes-256-gcm",
  "timeout": 300,
  "udp_enabled": true,
  "udp_local_port": 1081,
  "max_connections": 100,
  "http_proxy": {
    "enabled": true,
    "port": 8080
  }
}
```

### 运行

#### 启动服务端

```bash
./target/release/simple_ssr server -c server.json
```

#### 启动客户端

```bash
./target/release/simple_ssr client -c client.json
```

### 使用代理

客户端启动后，可以通过以下方式使用代理：

- **SOCKS5 代理**: `127.0.0.1:1080`
- **UDP 代理**: `127.0.0.1:1081`
- **HTTP 代理**: `127.0.0.1:8080`
- **统一端口**: `127.0.0.1:8389` (自动检测协议类型)

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
| SOCKS5 | 通用代理 | 标准协议，兼容性好 | 应用程序代理 |
| HTTP | 明文代理 | 简单易用，广泛支持 | Web 浏览代理 |
| HTTPS | 加密代理 | CONNECT 隧道 | 安全 Web 代理 |

### 加密方法

| 方法 | 密钥长度 | 安全性 | 性能 |
|------|----------|--------|------|
| aes-128-gcm | 128 位 | 高 | 很高 |
| aes-256-gcm | 256 位 | 很高 | 高 |
| chacha20-poly1305 | 256 位 | 很高 | 高 |

## 统一端口功能

统一端口功能允许在单个端口上同时支持多种协议，通过智能检测自动识别客户端使用的协议类型。

### 协议检测机制

- **HTTP 检测**: 识别 GET、POST、PUT、DELETE 等 HTTP 方法
- **HTTPS 检测**: 识别 TLS 握手包和 CONNECT 方法
- **SOCKS5 检测**: 识别 SOCKS5 握手包（版本号 0x05）
- **Shadowsocks 检测**: 基于数据包特征和地址类型检测

### 配置示例

```json
{
  "unified_port": {
    "enabled": true,
    "port": 8389,
    "protocols": ["shadowsocks", "socks5", "http", "https"],
    "detection_timeout": 5000,
    "verbose_logging": false
  }
}
```

## 命令行选项

```bash
# 查看帮助
./simple_ssr --help

# 启动服务端
./simple_ssr server [OPTIONS]
  -c, --config <FILE>    配置文件路径
  -p, --port <PORT>      覆盖配置文件中的端口
  --password <PASSWORD>  覆盖配置文件中的密码
  --method <METHOD>      覆盖配置文件中的加密方法

# 启动客户端
./simple_ssr client [OPTIONS]
  -c, --config <FILE>    配置文件路径
  -s, --server <ADDR>    服务器地址
  -p, --port <PORT>      服务器端口
  -l, --local-port <PORT> 本地端口
  --password <PASSWORD>  密码
  --method <METHOD>      加密方法

# 生成配置模板
./simple_ssr generate-config --type <TYPE>
  --type <TYPE>          配置类型 (server|client)
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
├── config/             # 配置管理
├── crypto/             # 加密模块
├── protocol/           # 协议实现
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

### 调试技巧

```bash
# 网络连接测试
telnet server_ip server_port

# 端口监听检查
netstat -tlnp | grep :8388
netstat -tlnp | grep :8389  # 统一端口
netstat -tlnp | grep :8080  # HTTP 代理端口

# 进程监控
top -p $(pgrep simple_ssr)

# 网络流量监控
iftop -i eth0

# HTTP 代理测试
curl -x http://127.0.0.1:8080 http://httpbin.org/ip
curl -x http://127.0.0.1:8080 https://httpbin.org/ip

# 协议检测测试
echo "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc 127.0.0.1 8389
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

