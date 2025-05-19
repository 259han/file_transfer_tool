# 更新日志 | Changelog

本文档记录项目的所有重要变更。

## [未发布]

## [1.1.0] - 2023-11-15

### 修复
- 修复了文件传输系统中的字节序问题，特别是在下载功能中
  - 修复了端到端加密测试失败，错误信息为"File size mismatch: expected 14036192901539048345 bytes, got 10224 bytes"
  - 在`download_message.cpp`中添加了字节序转换，使用`host_to_net64`和`net_to_host64`函数确保64位整数在网络传输中正确处理
  - 在`upload_message.cpp`中也修复了相同问题
  - 修改了服务器端的`handle_download`方法，使用`DownloadMessage::set_response_data`来正确设置响应数据

### 改进
- 优化了服务器响应处理，确保包含正确的文件大小信息
- 改进了加密响应的处理方式，确保在加密传输时也能正确保留文件大小信息

## [1.0.0] - 2023-10-01

### 新功能
- 初始版本发布
- 支持文件上传和下载
- 实现Diffie-Hellman密钥交换协议
- 支持AES-256-CBC加密传输
- 实现断点续传功能
- 支持并发连接
- 实时传输进度显示

# Changelog (English)

This document records all notable changes to the project.

## [Unreleased]

## [1.1.0] - 2023-11-15

### Fixed
- Fixed endianness issues in the file transfer system, especially in the download functionality
  - Resolved end-to-end encryption test failure with error "File size mismatch: expected 14036192901539048345 bytes, got 10224 bytes"
  - Added byte order conversion in `download_message.cpp` using `host_to_net64` and `net_to_host64` functions to ensure correct handling of 64-bit integers in network transmission
  - Fixed the same issue in `upload_message.cpp`
  - Modified the server's `handle_download` method to use `DownloadMessage::set_response_data` for correctly setting response data

### Improved
- Optimized server response handling to ensure correct file size information is included
- Enhanced encrypted response processing to ensure file size information is correctly preserved in encrypted transmissions

## [1.0.0] - 2023-10-01

### Added
- Initial release
- Support for file upload and download
- Implementation of Diffie-Hellman key exchange protocol
- Support for AES-256-CBC encrypted transmission
- Implementation of resume transfer from breakpoints
- Support for concurrent connections
- Real-time transfer progress display 