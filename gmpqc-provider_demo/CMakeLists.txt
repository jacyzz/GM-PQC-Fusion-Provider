# 设定要求的 CMake 最低版本，低于此版本的 CMake 将无法执行此脚本。
cmake_minimum_required(VERSION 3.10)

# 定义项目名称为 "gmpqc-provider"，并指定主要编程语言为 C。
project(gmpqc-provider C)

# --- 版本管理 ---
# 自动获取 Git 提交哈希，用于版本追溯。
execute_process(
    # 执行的命令：获取最近一次的 git commit hash 的缩写形式。
    COMMAND git log -1 --format=%h
    # 在项目的根目录执行此命令。
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    # 将命令的输出结果存放到名为 GIT_COMMIT_HASH 的变量中。
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    # 移除输出结果末尾的空白字符。
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
# 添加一个编译宏定义，这样 C 代码中就可以使用 GMPQC_PROVIDER_COMMIT 这个宏来获取哈希值。
# 例如：printf("Version: %s\n", GMPQC_PROVIDER_COMMIT);
add_definitions(-DGMPQC_PROVIDER_COMMIT="\"${GIT_COMMIT_HASH}\"")
# 在执行 CMake 时，在终端打印一条状态信息，显示当前编译的代码版本。
message(STATUS "Compiling GMPQC-Provider from git commit: ${GIT_COMMIT_HASH}")


# --- 寻找依赖库 ---
# 寻找 OpenSSL 库。REQUIRED 表示如果找不到，CMake 将立即报错停止。
# 成功后会创建 Imported Target "OpenSSL::Crypto"。
find_package(OpenSSL REQUIRED)

# 寻找 pkg-config 工具，它是寻找很多 Linux 库的常用工具。
find_package(PkgConfig REQUIRED)
# 使用 pkg-config 工具寻找 liboqs 库。成功后会设置 OQS_LIBRARIES 等变量。
pkg_search_module(OQS REQUIRED liboqs)

# 因为 GmSSL 是非标准安装，所以需要手动指定路径来寻找。
# find_path 用于寻找包含特定文件（openssl/sm2.h）的目录，作为头文件目录。
# HINTS 提供了寻找的优先路径。
find_path(GMSSL_INCLUDE_DIR gmssl/sm2.h HINTS /opt/gmssl/include)
# find_library 用于寻找指定的库文件（llibgmssl.a）。
find_library(GMSSL_CRYPTO_LIBRARY NAMES libgmssl.so HINTS /opt/gmssl/lib)

# 这是一个健壮性检查，确保 GmSSL 的头文件和库文件都已成功找到。
# 方案A：不在 provider 中引入 GmSSL，统一使用 OpenSSL 3 原生 SM2/SM3/SM4。


# --- 设置头文件包含路径 ---
# 将所有需要的头文件目录告知编译器。
include_directories(
    # 项目自身的 include 目录，用于存放对外接口的头文件。
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    # 项目自身的 internal 目录，用于存放内部模块的头文件。
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
    # liboqs 的头文件目录（由 pkg_search_module 设置）。
    ${OQS_INCLUDE_DIRS}
    # 注意：OpenSSL 的头文件路径无需在此添加，因为它会通过链接 OpenSSL::Crypto 自动包含。
)


# --- 定义目标库 ---
# add_library 命令用于定义一个编译目标。
# "gmpqc_provider" 是我们为目标库设定的名字。
# "MODULE" 类型指定编译为动态加载模块（在 Linux 上是 .so 文件）。
# 后面列出了所有需要参与编译的源文件。
add_library(gmpqc_provider MODULE
    src/prov.c
    src/hybrid_kem.c
    src/keymgmt.c
    src/internal/hybrid_crypto.c
)


# --- 【精简】文件名控制（仅保留Linux部分）---
# 在 Linux 上，OpenSSL Provider 文件名前不应有 "lib" 前缀（例如，应该是 oqsprovider.so 而不是 liboqsprovider.so）。
# 此命令将目标库的前缀设置为空。
set_target_properties(gmpqc_provider PROPERTIES PREFIX "")


# --- 链接依赖库 ---
# 将所有外部库链接到我们自己的目标库上。
target_link_libraries(gmpqc_provider
    PRIVATE
    # 使用现代 CMake 的 Imported Target 方式链接 OpenSSL 加密库。
    OpenSSL::Crypto
    # 链接 liboqs 库。
    ${OQS_LIBRARIES}
)

# 引入 GNUInstallDirs 模块，它提供了一系列标准的安装路径变量，如 CMAKE_INSTALL_LIBDIR。
include(GNUInstallDirs)

# 定义安装规则。当执行 "make install" 时，CMake 会执行这里的指令。
install(TARGETS gmpqc_provider
    # 指定安装类型为 LIBRARY（通常指动态库）。
    # DESTINATION 指定安装的目标路径。${CMAKE_INSTALL_LIBDIR}/ossl-modules 是 OpenSSL 存放 Provider 模块的标准目录。
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/ossl-modules
)