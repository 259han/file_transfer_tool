# File Transfer Tool

[中文](README.md) | [English](README_EN.md)

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
- JSONCPP
- POSIX compatible system (Linux, macOS)

## Build and Installation

### Install Dependencies

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

### Build the Project

```bash
# Clone the repository
git clone https://github.com/259han/file_transfer_tool.git
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
./build/bin/file_transfer_server [options]
```

Options:
- `-p, --port <port>` - Specify listening port (default: 12345)
- `-d, --dir <directory>` - Specify storage directory (default: ./storage)
- `-c, --config <file>` - Specify configuration file
- `-v, --verbose` - Enable verbose logging
- `--log-level <level>` - Set log level (debug, info, warning, error)

### Client Mode

The client supports three basic commands: upload, download, and test (connection testing).

#### Upload a file

```bash
./build/bin/file_transfer_client upload <server> <port> <local_file> [remote_filename]
```

#### Download a file

```bash
./build/bin/file_transfer_client download <server> <port> <remote_filename> [local_file]
```

#### Test connection

```bash
./build/bin/file_transfer_client test <server> <port>
```

#### Client Options

All client commands support the following options:
- `--log-level <level>` - Set log level (debug, info, warning, error)
- `--no-encrypt` - Disable encrypted transfer (enabled by default)

## Configuration Options

### Server Configuration

| Config File Option | Command-line Option | Description | Default |
|-------------|-----------------|---------------|------------|
| bind_address | - | Binding address | 0.0.0.0 |
| port | -p, --port | Server port | 12345 |
| storage_path | -d, --dir | Server storage directory | ./storage |
| max_connections | - | Maximum connections | Auto-determined by server |
| thread_pool_size | - | Thread pool size | Auto-determined by server |

### Client Configuration

Client is configured directly through command-line parameters and doesn't use configuration files.

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

- **2023-11-15**: Fixed byte order issues to ensure correct transmission of file size information across different platforms
  - Resolved data size mismatch issues in large file transfers
  - Implemented network byte order conversion for 64-bit integers in upload and download messages
  - Optimized data processing flow in encrypted transmissions

For detailed development documentation, please refer to the `docs/` directory and the `development_guide.md` file.

## Contributing

Contributions are welcome! You can contribute code, report issues, or suggest new features. Please follow these steps:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 