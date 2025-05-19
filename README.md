# 文件传输工具 | File Transfer Tool

<div align="center">
  <p>
    <a href="#" id="zh-cn-btn" onclick="switchLanguage('zh-cn')">中文</a> | 
    <a href="#" id="en-btn" onclick="switchLanguage('en')">English</a>
  </p>
</div>

<div id="zh-cn">
## 错误处理

记得使用log

不可恢复错误（Fatal Errors）
定义：系统运行时无法处理的严重错误，例如系统故障、程序员编写的严重错误（如越界访问、野指针等）。
处理方式：
快速失败（Fail Fast）：直接终止程序运行，避免程序在未知状态下继续执行。
记录错误信息：将错误信息（如堆栈信息、错误描述等）输出到日志或控制台，便于后续排查问题。
避免掩盖错误：不要试图忽略这些错误，因为它们可能导致程序在其他位置崩溃，增加问题排查的难度。
可恢复错误（Recoverable Errors）
定义：在运行时可以被程序捕获并处理的错误，例如文件打开失败、网络连接超时、数据格式错误等。
处理方式：
尝试恢复：根据错误类型采取相应的恢复措施，例如重试操作、跳过当前任务、等待条件满足等。
继续执行：在处理完错误后，程序应继续执行后续任务，而不是直接退出。
特殊情况：内存不足（OOM）
定义：内存分配失败（如std::bad_alloc）。
处理方式：
区分场景：
不可恢复：如果内存不足导致关键业务逻辑无法继续（如核心对象无法分配），则视为不可恢复错误，直接终止程序。
可恢复：如果可以通过调整内存分配策略（如减少分配量、释放其他资源）来解决，则视为可恢复错误。
异常处理的使用
不可恢复错误：C++的异常处理机制（如try-catch）更适合用于处理不可恢复错误，因为这些错误通常需要快速终止程序。
可恢复错误：对于可恢复错误，可以考虑使用返回错误码等机制，而不是依赖异常处理，以避免对程序性能造成不必要的冲击。
避免滥用异常：并非所有错误都需要通过异常处理来解决，异常处理应主要用于处理那些无法通过正常逻辑处理的异常情况。
错误处理的哲学
明确错误类型：区分错误是不可恢复还是可恢复，避免将不可恢复错误当作可恢复错误处理，反之亦然。
优雅性与性能平衡：在选择错误处理机制时，应权衡代码的优雅性和程序的性能，避免过度依赖异常处理而影响关键计算任务的性能。


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
- POSIX兼容系统 (Linux, macOS)

## 构建与安装

### 安装依赖

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev zlib1g-dev
```

#### CentOS/RHEL

```bash
sudo yum install -y gcc-c++ cmake openssl-devel zlib-devel
```

#### macOS

```bash
brew install cmake openssl zlib
```

### 构建项目

```bash
# 克隆仓库
git clone https://github.com/yourusername/file-transfer-tool.git
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
./bin/file_transfer_tool --server --port 8080 --storage ./storage
```

### 客户端模式

#### 上传文件

```bash
./bin/file_transfer_tool --upload --file path/to/file --server 192.168.1.100 --port 8080
```

#### 下载文件

```bash
./bin/file_transfer_tool --download --file filename --output path/to/save --server 192.168.1.100 --port 8080
```

## 配置选项

| 选项 | 描述 | 默认值 |
|-------------|-----------------|---------------|
| --server    | 以服务器模式运行 | - |
| --port      | 服务器端口 | 8080 |
| --storage   | 服务器存储目录 | ./storage |
| --upload    | 上传模式 | - |
| --download  | 下载模式 | - |
| --file      | 文件路径/名称 | - |
| --output    | 下载输出目录 | ./ |
| --server    | 服务器地址 | 127.0.0.1 |
| --encrypt   | 启用加密 | false |

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

</div>

<div id="en" style="display: none;">

## Project Description

This is a high-performance file transfer tool developed in C++17, supporting secure file upload and download. The project uses the CMake build system and OpenSSL for encrypted transmission to ensure data transfer security.

### Main Features

- Support for large file chunked transfer
- Encrypted transmission using AES-256-CBC algorithm
- Diffie-Hellman key exchange protocol for secure key establishment
- Resume transfer from breakpoints
- Support for concurrent connections
- Real-time transfer progress display

## Requirements

- C++17 compatible compiler (GCC 9+ or Clang 10+)
- CMake 3.15+
- OpenSSL 1.1.1+
- ZLIB
- POSIX compatible system (Linux, macOS)

## Build and Installation

### Install Dependencies

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev zlib1g-dev
```

#### CentOS/RHEL

```bash
sudo yum install -y gcc-c++ cmake openssl-devel zlib-devel
```

#### macOS

```bash
brew install cmake openssl zlib
```

### Build the Project

```bash
# Clone the repository
git clone https://github.com/yourusername/file-transfer-tool.git
cd file-transfer-tool

# Create and enter build directory
mkdir -p build
cd build

# Configure
cmake ..

# Build
make -j$(nproc)
```

Or use the provided build script:

```bash
./build.sh
```

## Usage

### Server Mode

```bash
./bin/file_transfer_tool --server --port 8080 --storage ./storage
```

### Client Mode

#### Upload a file

```bash
./bin/file_transfer_tool --upload --file path/to/file --server 192.168.1.100 --port 8080
```

#### Download a file

```bash
./bin/file_transfer_tool --download --file filename --output path/to/save --server 192.168.1.100 --port 8080
```

## Configuration Options

| Option | Description | Default |
|-------------|-----------------|---------------|
| --server    | Run in server mode | - |
| --port      | Server port | 8080 |
| --storage   | Server storage directory | ./storage |
| --upload    | Upload mode | - |
| --download  | Download mode | - |
| --file      | File path/name | - |
| --output    | Download output directory | ./ |
| --server    | Server address | 127.0.0.1 |
| --encrypt   | Enable encryption | false |

## Development

The project follows a modular design with clear responsibilities for each module:

- **Client module (src/client/)**: Client implementation for file upload and download, including initiating key exchange
- **Server module (src/server/)**: Handling client requests, managing file storage, responding to key exchange and ensuring data security
- **Common module (src/common/)**: Contains network protocols, encryption, and utility classes, providing encryption algorithms and key exchange protocol implementations

### Encryption Implementation

- Using Diffie-Hellman key exchange protocol to securely generate shared keys between client and server
- Deriving AES-256-CBC encryption keys and IVs from the shared key
- Encrypting and decrypting file data during transmission
- Identifying encryption status through message flags, automatically handling encryption and decryption

### Recent Updates

- **2023-11-15**: Fixed endianness issues to ensure correct file size information transfer between different platforms
  - Resolved data size mismatch problems in large file transfers
  - Implemented network byte order conversion for 64-bit integers in upload and download messages
  - Optimized data processing workflow in encrypted transmissions

For detailed development documentation, please refer to the `docs/` directory and the `development_guide.md` file.

## Contributing

Contributions, bug reports, and feature requests are welcome. Please follow these steps:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

</div>

<script>
function switchLanguage(lang) {
  // 隐藏所有语言内容
  document.getElementById('zh-cn').style.display = 'none';
  document.getElementById('en').style.display = 'none';
  
  // 显示选中的语言
  document.getElementById(lang).style.display = 'block';
  
  // 更新按钮样式
  document.getElementById('zh-cn-btn').style.fontWeight = lang === 'zh-cn' ? 'bold' : 'normal';
  document.getElementById('en-btn').style.fontWeight = lang === 'en' ? 'bold' : 'normal';
}

// 初始化显示中文
document.addEventListener('DOMContentLoaded', function() {
  switchLanguage('zh-cn');
});
</script> 