# 文件传输工具 | File Transfer Tool

[中文](README.md) | [English](README_EN.md)

## 项目简介

这是一个基于C++17开发的高性能文件传输工具，支持文件的安全上传和下载。项目使用CMake构建系统，采用OpenSSL进行加密传输，保证数据传输的安全性。

### 主要特性

- 支持大文件分块传输
- 传输过程加密，使用AES-256-CBC算法
- 实现Diffie-Hellman密钥交换协议确保密钥安全
- 断点续传功能
- 支持并发连接
- 实时传输进度显示
- **兼容OpenSSL 3.0+** - 使用现代EVP API，避免废弃函数警告

## 环境要求

- C++17兼容的编译器 (GCC 9+ 或 Clang 10+)
- CMake 3.15+
- **OpenSSL 3.0+** (推荐) 或 OpenSSL 1.1.1+
- ZLIB
- JSONCPP
- POSIX兼容系统 (Linux, macOS)

## 构建与安装

### 安装依赖

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev zlib1g-dev libjsoncpp-dev
```

#### CentOS/RHEL

```bash
sudo yum install -y gcc-c++ cmake openssl-devel zlib-devel jsoncpp-devel
```

#### macOS

```bash
brew install cmake openssl zlib jsoncpp
```

### 构建项目

```bash
# 克隆仓库
git clone https://github.com/259han/file_transfer_tool.git
cd file-transfer-tool

# 创建并进入构建目录
mkdir -p build
cd build

# 配置
cmake ..

# 编译
make -j$(nproc)
```

或者使用提供的构建脚本:

```bash
./build.sh
```

## 使用方法

### 服务器模式

```bash
./build/bin/file_transfer_server [选项]
```

选项:
- `-p, --port <端口>` - 指定监听端口 (默认: 12345)
- `-d, --dir <目录>` - 指定存储目录 (默认: ./storage)
- `-c, --config <文件>` - 指定配置文件
- `-v, --verbose` - 启用详细日志
- `--log-level <级别>` - 设置日志级别 (debug, info, warning, error)

### 客户端模式

客户端支持三种基本命令：upload（上传）、download（下载）和test（测试连接）。

#### 上传文件

```bash
./build/bin/file_transfer_client upload <服务器> <端口> <本地文件> [远程文件名]
```

#### 下载文件

```bash
./build/bin/file_transfer_client download <服务器> <端口> <远程文件名> [本地文件]
```

#### 测试连接

```bash
./build/bin/file_transfer_client test <服务器> <端口>
```

#### 客户端选项

所有客户端命令都支持以下选项：
- `--log-level <级别>` - 设置日志级别 (debug, info, warning, error)
- `--no-encrypt` - 禁用加密传输（默认启用加密）

## 配置选项

### 服务器配置

| 配置文件选项 | 命令行选项 | 描述 | 默认值 |
|-------------|-----------------|---------------|------------|
| bind_address | - | 绑定地址 | 0.0.0.0 |
| port | -p, --port | 服务器端口 | 12345 |
| storage_path | -d, --dir | 服务器存储目录 | ./storage |
| max_connections | - | 最大连接数 | 服务器自动决定 |
| thread_pool_size | - | 线程池大小 | 服务器自动决定 |

### 客户端配置

客户端通过命令行参数直接配置，不使用配置文件。

## 开发

项目遵循模块化设计，各模块职责分明：

- **客户端模块 (src/client/)**: 负责文件上传和下载的客户端实现，包含密钥交换的发起
- **服务器模块 (src/server/)**: 处理客户端请求，管理文件存储，响应密钥交换并保障数据安全
- **公共模块 (src/common/)**: 包含网络协议、加密和工具类，提供加密算法和密钥交换协议的实现

### 项目目录结构

```
src/
├── client/                     # 客户端模块
│   ├── core/                   # 客户端核心逻辑
│   │   └── client_core.*       # 客户端主要功能实现，连接管理、加密协商
│   ├── handlers/               # 客户端处理器
│   │   ├── upload_handler.*    # 文件上传处理逻辑
│   │   └── download_handler.*  # 文件下载处理逻辑
│   ├── utils/                  # 客户端工具类
│   │   └── progress_tracker.*  # 传输进度跟踪器
│   └── client.cpp              # 客户端命令行入口程序
│
├── server/                     # 服务器模块
│   ├── core/                   # 服务器核心逻辑
│   │   ├── server_core.*       # 服务器主要功能实现，连接监听管理
│   │   └── client_session.*    # 客户端会话管理，加密状态维护
│   ├── handlers/               # 服务器处理器
│   │   ├── upload_handler.*    # 服务器端文件上传处理
│   │   ├── download_handler.*  # 服务器端文件下载处理
│   │   ├── key_exchange_handler.* # DH密钥交换处理器
│   │   ├── protocol_handler.*  # 协议消息分发处理
│   │   ├── file_lock_manager.* # 文件锁管理器，防止并发冲突
│   │   └── file_version.*      # 文件版本管理
│   ├── session/                # 会话管理
│   │   └── session_manager.*   # 客户端会话生命周期管理
│   └── server.cpp              # 服务器命令行入口程序
│
└── common/                     # 公共模块
    ├── network/                # 网络通信模块
    │   ├── socket/             # 套接字封装
    │   │   └── tcp_socket.*    # TCP套接字实现，支持超时和错误处理
    │   ├── connection/         # 连接管理
    │   │   └── connection_pool.* # 连接池管理
    │   └── async/              # 异步处理
    │       └── event_loop.*    # 事件循环实现
    │
    ├── protocol/               # 通信协议模块
    │   ├── core/               # 协议核心
    │   │   └── protocol_header.* # 协议头定义和处理
    │   ├── messages/           # 协议消息
    │   │   ├── upload_message.*    # 上传消息格式
    │   │   ├── download_message.*  # 下载消息格式
    │   │   └── key_exchange_message.* # 密钥交换消息格式
    │   └── protocol.*          # 协议基础定义和消息处理
    │
    └── utils/                  # 工具类模块
        ├── crypto/             # 加密工具
        │   └── encryption.*    # OpenSSL 3.0 EVP API封装，DH密钥交换和AES加密
        ├── logging/            # 日志系统
        │   └── logger.*        # 日志记录器实现
        └── config/             # 配置管理
            └── config_parser.* # 配置文件解析器
```

#### 设计理念

**分层架构**: 项目采用三层架构设计，客户端、服务器和公共模块相互独立，便于维护和扩展。

**模块化设计**: 每个功能模块都有明确的职责边界，core模块负责核心逻辑，handlers模块处理具体业务，utils模块提供工具支持。

**代码复用**: 公共模块包含网络通信、协议处理、加密算法等通用功能，避免代码重复，确保一致性。

**安全优先**: 加密模块使用最新的OpenSSL 3.0 API，支持现代密码学标准，确保数据传输安全。

### 加密实现

项目使用现代OpenSSL 3.0 API实现安全的文件传输：

- **Diffie-Hellman密钥交换**: 使用RFC 7919标准的ffdhe2048命名组，确保密钥交换的安全性
- **AES-256-CBC加密**: 基于共享密钥派生的AES-256-CBC加密密钥和IV
- **HKDF密钥派生**: 使用HKDF-SHA256从DH共享密钥派生加密密钥和初始化向量
- **EVP API**: 全面使用OpenSSL 3.0的EVP API，避免使用已废弃的低级API
- **自动加密检测**: 通过消息标志位识别加密状态，自动处理加密和解密

#### OpenSSL兼容性

- **OpenSSL 3.0+**: 完全兼容，无警告信息
- **OpenSSL 1.1.1**: 兼容，但可能显示废弃函数警告
- **性能优化**: DH参数生成时间从数秒优化到毫秒级别

### 最近更新

- **2025-5-24**: **OpenSSL 3.0 API迁移**
  - 将所有DH相关函数从废弃的`DH_*`API迁移到现代EVP API
  - 使用RFC 7919标准的ffdhe2048命名组替代自定义DH参数
  - 消除了所有OpenSSL废弃函数警告
  - 显著提升了DH密钥生成性能（从秒级优化到毫秒级）
  - 增强了密钥交换的安全性和标准化程度

- **2025-5-19**: 修复了字节序问题，确保在不同平台之间正确传输文件大小信息
  - 解决了大文件传输中的数据大小不匹配问题
  - 实现了上传和下载消息中64位整数的网络字节序转换
  - 优化了加密传输中的数据处理流程


## 贡献

欢迎贡献代码、报告问题或提出新功能建议。请遵循以下步骤：

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

此项目基于 MIT 许可证发布 - 详细信息请查看 [LICENSE](LICENSE) 文件。