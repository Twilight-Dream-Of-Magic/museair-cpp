cmake_minimum_required(VERSION 3.10)

# 项目名称和版本
project(MuseAirHashTest VERSION 1.0)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 可执行文件名和源文件列表
add_executable(test_muse_air main.cpp)

# 添加你实现的头文件路径
target_include_directories(test_muse_air PRIVATE ${CMAKE_SOURCE_DIR})

# 根据编译模式设置编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        target_compile_options(EtherealChaosCipher PRIVATE /W4 /RTC1 /Zi /Od)  # 启用运行时检查和调试符号
    else()
        target_compile_options(EtherealChaosCipher PRIVATE -g -O0 -Wall -Wextra -Wpedantic)
    endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        target_compile_options(EtherealChaosCipher PRIVATE /O3 /W4)  # 启用优化
    else()
        target_compile_options(EtherealChaosCipher PRIVATE -O3 -Wall -Wextra -Wpedantic)
    endif()
endif()

# 默认构建类型为Release，除非用户指定其他类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()