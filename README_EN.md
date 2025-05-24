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
- **OpenSSL 3.0+ Compatible** - Uses modern EVP APIs, avoiding deprecated function warnings
- **User Management System** - Support multi-user authentication, permission control and API key management

## Requirements

- C++17 compatible compiler (GCC 9+ or Clang 10+)
- CMake 3.15+
- **OpenSSL 3.0+** (recommended) or OpenSSL 1.1.1+
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

### Project Directory Structure

```
src/
├── client/                     # Client module
│   ├── core/                   # Client core logic
│   │   └── client_core.*       # Client main functionality, connection management, encryption negotiation
│   ├── handlers/               # Client handlers
│   │   ├── upload_handler.*    # File upload processing logic
│   │   └── download_handler.*  # File download processing logic
│   ├── utils/                  # Client utilities
│   │   └── progress_tracker.*  # Transfer progress tracker
│   └── client.cpp              # Client command-line entry program
│
├── server/                     # Server module
│   ├── core/                   # Server core logic
│   │   ├── server_core.*       # Server main functionality, connection listening management
│   │   └── client_session.*    # Client session management, encryption state maintenance
│   ├── handlers/               # Server handlers
│   │   ├── upload_handler.*    # Server-side file upload processing
│   │   ├── download_handler.*  # Server-side file download processing
│   │   ├── key_exchange_handler.* # DH key exchange handler
│   │   ├── protocol_handler.*  # Protocol message dispatching
│   │   ├── file_lock_manager.* # File lock manager, prevents concurrent conflicts
│   │   └── file_version.*      # File version management
│   ├── session/                # Session management
│   │   └── session_manager.*   # Client session lifecycle management
│   └── server.cpp              # Server command-line entry program
│
└── common/                     # Common module
    ├── network/                # Network communication module
    │   ├── socket/             # Socket wrapper
    │   │   └── tcp_socket.*    # TCP socket implementation with timeout and error handling
    │   ├── connection/         # Connection management
    │   │   └── connection_pool.* # Connection pool management
    │   └── async/              # Asynchronous processing
    │       └── event_loop.*    # Event loop implementation
    │
    ├── protocol/               # Communication protocol module
    │   ├── core/               # Protocol core
    │   │   └── protocol_header.* # Protocol header definition and processing
    │   ├── messages/           # Protocol messages
    │   │   ├── upload_message.*    # Upload message format
    │   │   ├── download_message.*  # Download message format
    │   │   └── key_exchange_message.* # Key exchange message format
    │   └── protocol.*          # Protocol base definitions and message processing
    │
    └── utils/                  # Utility classes module
        ├── crypto/             # Encryption tools
        │   └── encryption.*    # OpenSSL 3.0 EVP API wrapper, DH key exchange and AES encryption
        ├── logging/            # Logging system
        │   └── logger.*        # Logger implementation
        └── config/             # Configuration management
            └── config_parser.* # Configuration file parser
```

#### Design Philosophy

**Layered Architecture**: The project adopts a three-tier architecture design where client, server, and common modules are independent of each other, facilitating maintenance and extension.

**Modular Design**: Each functional module has clear responsibility boundaries - core modules handle core logic, handlers modules process specific business logic, and utils modules provide tool support.

**Code Reusability**: The common module contains general-purpose functionalities like network communication, protocol processing, and encryption algorithms, avoiding code duplication and ensuring consistency.

**Security First**: The encryption module uses the latest OpenSSL 3.0 APIs, supporting modern cryptographic standards to ensure secure data transmission.

### Encryption Implementation

The project uses modern OpenSSL 3.0 APIs to implement secure file transfer:

- **Diffie-Hellman Key Exchange**: Uses RFC 7919 standard ffdhe2048 named groups for secure key exchange
- **AES-256-CBC Encryption**: AES-256-CBC encryption keys and IVs derived from shared keys
- **HKDF Key Derivation**: Uses HKDF-SHA256 to derive encryption keys and initialization vectors from DH shared keys
- **EVP APIs**: Comprehensive use of OpenSSL 3.0 EVP APIs, avoiding deprecated low-level APIs
- **Automatic Encryption Detection**: Identifies encryption status through message flags, automatically handling encryption and decryption

#### OpenSSL Compatibility

- **OpenSSL 3.0+**: Fully compatible with no warning messages
- **OpenSSL 1.1.1**: Compatible but may show deprecated function warnings
- **Performance Optimization**: DH parameter generation time optimized from seconds to milliseconds

### Recent Updates

- **2025-01-26**: **User Management System**
  - Added complete user authentication system with username/password authentication
  - Implemented 4-level permission control system (Read, Write, Delete, Admin)
  - Added API key support providing dual authentication mechanism
  - Included user management CLI tool supporting user CRUD operations, key generation and authentication testing
  - Password encrypted storage with SHA-256 + random salt for account security
  - User data stored in `data/auth/` directory with permission isolation

- **2025-5-24**: **OpenSSL 3.0 API Migration**
  - Migrated all DH-related functions from deprecated `DH_*` APIs to modern EVP APIs
  - Replaced custom DH parameters with RFC 7919 standard ffdhe2048 named groups
  - Eliminated all OpenSSL deprecated function warnings
  - Significantly improved DH key generation performance (from seconds to milliseconds)
  - Enhanced security and standardization of key exchange

- **2025-5-19**: Fixed byte order issues to ensure correct transmission of file size information across different platforms
  - Resolved data size mismatch issues in large file transfers
  - Implemented network byte order conversion for 64-bit integers in upload and download messages
  - Optimized data processing flow in encrypted transmissions


## Contributing

Contributions are welcome! You can contribute code, report issues, or suggest new features. Please follow these steps:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 