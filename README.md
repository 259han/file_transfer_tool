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

## 环境要求

- C++17兼容的编译器 (GCC 9+ 或 Clang 10+)
- CMake 3.15+
- OpenSSL 1.1.1+
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

### 加密实现

- 使用Diffie-Hellman密钥交换协议安全地在客户端和服务器之间生成共享密钥
- 基于共享密钥派生AES-256-CBC加密密钥和IV
- 在传输过程中对文件数据进行加密和解密
- 通过消息标志位识别加密状态，自动处理加密和解密

### 最近更新

- **2023-11-15**: 修复了字节序问题，确保在不同平台之间正确传输文件大小信息
  - 解决了大文件传输中的数据大小不匹配问题
  - 实现了上传和下载消息中64位整数的网络字节序转换
  - 优化了加密传输中的数据处理流程

详细的开发文档请参考 `docs/` 目录和 `development_guide.md` 文件。

## 贡献

欢迎贡献代码、报告问题或提出新功能建议。请遵循以下步骤：

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

此项目基于 MIT 许可证发布 - 详细信息请查看 [LICENSE](LICENSE) 文件。