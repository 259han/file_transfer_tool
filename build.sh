#!/bin/bash

# 创建构建目录
mkdir -p build

# 进入构建目录
cd build

# 运行CMake
cmake ..

# 编译
make -j$(nproc)

# 返回根目录
cd ..

echo "构建完成，二进制文件位于 build/bin/ 目录下" 