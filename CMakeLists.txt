cmake_minimum_required(VERSION 3.10)
project(RSA_AES_Project)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)


# 将 cmake 目录添加到模块路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

# 查找必要的库
find_package(OpenSSL REQUIRED)
find_package(GMP REQUIRED)

# 添加头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 添加源文件

add_executable(main
	src/main.cpp
	src/rsa.cpp
	src/aes.cpp
)

# 链接库

target_link_libraries(main
	OpenSSL::SSL 
	OpenSSL::Crypto
    	gmp
)
