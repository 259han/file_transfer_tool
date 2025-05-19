#!/bin/bash

# 设置错误时退出
set -e

# 默认构建类型
BUILD_TYPE="Release"
CLEAN_BUILD=false

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        *)
            echo "未知参数: $1"
            echo "用法: $0 [--debug] [--clean]"
            exit 1
            ;;
    esac
done

# 如果指定了清理选项，删除构建目录
if [ "$CLEAN_BUILD" = true ]; then
    echo "清理构建目录..."
    rm -rf build
fi

# 创建构建目录
mkdir -p build

# 进入构建目录
cd build

# 运行CMake
echo "配置项目..."
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE ..

# 编译
echo "开始编译..."
make -j$(nproc)

# 检查编译结果
if [ $? -eq 0 ]; then
    echo "构建成功！"
    echo "主程序位于 build/bin/ 目录下"
    echo "测试程序位于 build/bin/tests/ 目录下"
else
    echo "构建失败！"
    exit 1
fi

# 返回根目录
cd .. 