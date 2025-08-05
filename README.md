# Simple SSR - Shadowsocks Implementation in Rust

一个高性能、安全的 Shadowsocks 实现，使用 Rust 语言开发，支持 TCP 和 UDP 代理。

## 特性

- 🚀 **高性能**: 基于 Tokio 异步运行时，支持高并发
- 🔒 **安全加密**: 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305
- 🌐 **全协议支持**: TCP、UDP、SOCKS5 代理
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
  "max_connections": 1000
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
  "max_connections": 100
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

## 支持的加密方法

| 方法 | 密钥长度 | 安全性 | 性能 |
|------|----------|--------|------|
| aes-128-gcm | 128 位 | 高 | 很高 |
| aes-256-gcm | 256 位 | 很高 | 高 |
| chacha20-poly1305 | 256 位 | 很高 | 高 |

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
├── server/             # 服务端
├── client/             # 客户端
└── utils/              # 工具函数
```

## 故障排除

### 常见问题

#### 连接失败

1. 检查服务器地址和端口是否正确
2. 确认密码和加密方法匹配
3. 检查防火墙设置
4. 验证网络连通性

#### 性能问题

1. 检查系统资源使用情况
2. 调整最大连接数设置
3. 优化网络参数
4. 选择合适的加密方法

#### 内存使用过高

1. 检查连接数是否过多
2. 调整超时设置
3. 监控会话清理情况

### 调试技巧

```bash
# 网络连接测试
telnet server_ip server_port

# 端口监听检查
netstat -tlnp | grep :8388

# 进程监控
top -p $(pgrep simple_ssr)

# 网络流量监控
iftop -i eth0
```

## 安全建议

1. **使用强密码**: 建议使用 32 字符以上的随机密码
2. **定期更换密码**: 建议每月更换一次密码
3. **选择安全的加密方法**: 推荐使用 `aes-256-gcm` 或 `chacha20-poly1305`
4. **限制连接数**: 根据实际需求设置合理的最大连接数
5. **监控异常**: 定期检查日志，发现异常及时处理
6. **网络隔离**: 在可能的情况下使用网络隔离

## 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 本项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

