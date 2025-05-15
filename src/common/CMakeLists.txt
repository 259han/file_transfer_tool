# 添加子目录
add_subdirectory(protocol)
add_subdirectory(network)
add_subdirectory(utils)

# 创建头文件安装目标
set(COMMON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include/common)
file(MAKE_DIRECTORY ${COMMON_INCLUDE_DIR}) 