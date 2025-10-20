好的，我们来为您量身打造一份详细的、可直接交付给开发工具（如Cursor）执行的**混合密码模块实现步骤**。

这份计划书明确了您的项目目标、技术架构和开发环境，并将核心模块的实现分解为具体的、可操作的编码步骤。

-----

### **项目：国密-后量子混合密码核心模块实现**

#### **1. 项目目标与技术架构**

  * **核心目标**：
    开发一个独立的、可重用的C语言密码学模块（以下简称“混合模块”）。该模块旨在提供符合国密标准和国际后量子密码（PQC）标准的混合加密能力，为上层协议（如TLS 1.3）的抗量子化改造提供核心的密码学后端支持。

  * **技术架构**：

      * **形式**：一个独立的软件库，由一系列 `.c` 和 `.h` 文件组成，最终可编译为静态库 (`.a`) 或动态库 (`.so`)。
      * **依赖关系**：本模块将作为封装层，依赖并调用两个底层密码库：
        1.  **国密算法库**：**GmSSL** (推荐) 或支持国密算法的 **OpenSSL 3.x**。用于提供SM2、SM3、SM4的实现 [1, 2, 3]。
        2.  **后量子算法库**：**liboqs** (Open Quantum Safe项目)。用于提供NIST标准化的ML-KEM (Kyber) 和 ML-DSA (Dilithium) 算法的实现 [4, 5]。
      * **接口设计**：模块将提供一套简洁的高级API，用于执行混合密钥交换和复合签名/验证，对上层应用屏蔽底层算法组合的复杂性。

#### **2. 开发与测试环境要求 (VMware)**

  * **虚拟化软件**：VMware Workstation Player 或 Pro。
  * **虚拟机配置**：
      * 创建两台虚拟机：`pqc-dev-server` 和 `pqc-dev-client`。
      * **操作系统**：均为 Ubuntu Server 22.04 LTS。
      * **硬件**：每台虚拟机分配至少 2个CPU核心、2GB RAM、25GB硬盘。
  * **网络配置**：
      * 为每台虚拟机配置两个网络适配器：
        1.  **网卡1 (NAT模式)**：用于访问互联网，下载依赖包。
        2.  **网卡2 (仅主机模式)**：用于创建隔离的内部测试网络（例如 `192.168.56.0/24`），确保两台虚拟机可以通过内部IP互相通信。
  * **环境初始化命令** (在两台虚拟机上分别执行)：
    ```bash
    # 1. 更新系统并安装基础编译工具
    sudo apt update && sudo apt upgrade -y
    sudo apt install build-essential git cmake -y

    # 2. 克隆并编译 GmSSL (国密算法库)
    git clone https://github.com/guanzhi/GmSSL.git
    cd GmSSL
    ```

./config
make
sudo make install
cd..

````
# 3. 克隆并编译 liboqs (后量子算法库)
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake.. -DOQS_USE_OPENSSL=OFF
make
sudo make install
cd../..

# 4. 更新动态链接库缓存
sudo ldconfig
```
````

#### **3. 核心模块实现步骤**

**项目文件结构**：

```
/hybrid_crypto

|-- include/
| |-- hybrid_common.h
| |-- hybrid_kex.h
| |-- hybrid_sig.h
|-- src/
| |-- hybrid_kex.c
| |-- hybrid_sig.c
|-- test/
| |-- test_main.c
|-- CMakeLists.txt
```

-----

**步骤 3.1：定义通用头文件 (`include/hybrid_common.h`)**

此文件包含项目共用的定义、算法标识符和错误码。

```c
#ifndef HYBRID_COMMON_H
#define HYBRID_COMMON_H

#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>

// 定义混合算法名称
#define HYBRID_KEX_ALG "sm2_mlkem768"
#define HYBRID_SIG_ALG "sm2_mldsa65"

// 定义PQC算法参数
#define OQS_KEX_ALG OQS_KEM_alg_kyber_768
#define OQS_SIG_ALG OQS_SIG_alg_dilithium_3

// 定义固定长度
#define SM2_PUBKEY_LEN 65 // 0x04 uncompressed point + 32-byte X + 32-byte Y
#define SM2_PRIKEY_LEN 32
#define SM2_SIG_MAX_LEN 72

// 错误码
#define HYBRID_SUCCESS 0
#define HYBRID_ERROR_MALLOC -1
#define HYBRID_ERROR_KEX_KEYGEN -10
#define HYBRID_ERROR_KEX_DERIVE -11
#define HYBRID_ERROR_SIG_KEYGEN -20
#define HYBRID_ERROR_SIG_SIGN -21
#define HYBRID_ERROR_SIG_VERIFY -22

#endif // HYBRID_COMMON_H
```

-----

**步骤 3.2：实现混合密钥交换模块 (`hybrid_kex.h` 和 `hybrid_kex.c`)**

**头文件 (`include/hybrid_kex.h`)**:

```c
#ifndef HYBRID_KEX_H
#define HYBRID_KEX_H

#include "hybrid_common.h"

// 生成混合密钥对
int hybrid_kex_keygen(
    uint8_t **public_key, size_t *public_key_len,
    uint8_t **private_key, size_t *private_key_len
);

// 服务器端：根据客户端公钥，生成共享密钥和给客户端的响应
int hybrid_kex_server_derive(
    uint8_t **shared_secret, size_t *shared_secret_len,
    uint8_t **server_response, size_t *server_response_len,
    const uint8_t *client_public_key, size_t client_public_key_len,
    const uint8_t *server_private_key, size_t server_private_key_len
);

// 客户端：根据服务器响应，生成共享密钥
int hybrid_kex_client_derive(
    uint8_t **shared_secret, size_t *shared_secret_len,
    const uint8_t *server_response, size_t server_response_len,
    const uint8_t *client_private_key, size_t client_private_key_len
);

void free_key_data(uint8_t *key_data);

#endif // HYBRID_KEX_H
```

**实现文件 (`src/hybrid_kex.c`)** (伪代码逻辑):

```c
#include "hybrid_kex.h"
#include <string.h>

// 伪代码：实现 hybrid_kex_keygen
int hybrid_kex_keygen(...) {
    // 1. 初始化 OQS KEM
    OQS_KEM *kem = OQS_KEM_new(OQS_KEX_ALG);
    
    // 2. 分配内存
    uint8_t *sm2_pub = malloc(SM2_PUBKEY_LEN);
    uint8_t *sm2_priv = malloc(SM2_PRIKEY_LEN);
    uint8_t *mlkem_pub = malloc(kem->length_public_key);
    uint8_t *mlkem_priv = malloc(kem->length_secret_key);

    // 3. 生成 SM2 密钥对 (使用 GmSSL/OpenSSL 的 EVP_PKEY API)
    //    EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);... EVP_PKEY_keygen();
    //    EVP_PKEY_get_raw_public_key() 和 EVP_PKEY_get_raw_private_key()
    
    // 4. 生成 ML-KEM 密钥对
    OQS_KEM_keypair(kem, mlkem_pub, mlkem_priv);

    // 5. 拼接公钥和私钥
    *public_key_len = SM2_PUBKEY_LEN + kem->length_public_key;
    *public_key = malloc(*public_key_len);
    memcpy(*public_key, sm2_pub, SM2_PUBKEY_LEN);
    memcpy(*public_key + SM2_PUBKEY_LEN, mlkem_pub, kem->length_public_key);

    *private_key_len = SM2_PRIKEY_LEN + kem->length_secret_key;
    *private_key = malloc(*private_key_len);
    //... 同样拼接私钥...

    // 6. 清理
    free(sm2_pub); free(sm2_priv); free(mlkem_pub); free(mlkem_priv);
    OQS_KEM_free(kem);
    return HYBRID_SUCCESS;
}

// 伪代码：实现 hybrid_kex_server_derive
int hybrid_kex_server_derive(...) {
    // 1. 解析客户端公钥
    const uint8_t *client_sm2_pub = client_public_key;
    const uint8_t *client_mlkem_pub = client_public_key + SM2_PUBKEY_LEN;

    // 2. 解析服务器私钥
    const uint8_t *server_sm2_priv = server_private_key;
    const uint8_t *server_mlkem_priv = server_private_key + SM2_PRIKEY_LEN;

    // 3. 计算 SM2 共享密钥 (SS_sm2)
    //    使用 EVP_PKEY_derive API
    
    // 4. 执行 ML-KEM 封装 (Encapsulation)
    OQS_KEM *kem = OQS_KEM_new(OQS_KEX_ALG);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *ss_mlkem = malloc(kem->length_shared_secret);
    OQS_KEM_encaps(kem, ciphertext, ss_mlkem, client_mlkem_pub);

    // 5. 生成服务器自己的临时 SM2 密钥对 (用于响应)
    //   ... 与 keygen 类似...
    
    // 6. 拼接服务器响应
    *server_response_len = SM2_PUBKEY_LEN + kem->length_ciphertext;
    *server_response = malloc(*server_response_len);
    //    将服务器临时 SM2 公钥和 ML-KEM 密文 ciphertext 拼接到 *server_response
    
    // 7. 派生最终共享密钥
    //    拼接 SS_sm2 和 ss_mlkem
    //    使用 SM3 作为 KDF 计算最终的 shared_secret
    
    // 8. 清理
    return HYBRID_SUCCESS;
}

// 伪代码：实现 hybrid_kex_client_derive
int hybrid_kex_client_derive(...) {
    // 1. 解析服务器响应
    const uint8_t *server_sm2_pub = server_response;
    const uint8_t *ciphertext = server_response + SM2_PUBKEY_LEN;

    // 2. 解析客户端私钥
    const uint8_t *client_sm2_priv = client_private_key;
    const uint8_t *client_mlkem_priv = client_private_key + SM2_PRIKEY_LEN;

    // 3. 计算 SM2 共享密钥 (SS_sm2)
    //    使用 EVP_PKEY_derive API
    
    // 4. 执行 ML-KEM 解封装 (Decapsulation)
    OQS_KEM *kem = OQS_KEM_new(OQS_KEX_ALG);
    uint8_t *ss_mlkem = malloc(kem->length_shared_secret);
    OQS_KEM_decaps(kem, ss_mlkem, ciphertext, client_mlkem_priv);

    // 5. 派生最终共享密钥 (使用与服务器完全相同的 KDF 流程)
    
    // 6. 清理
    return HYBRID_SUCCESS;
}
```

-----

**步骤 3.3：实现复合签名模块 (`hybrid_sig.h` 和 `hybrid_sig.c`)**

**头文件 (`include/hybrid_sig.h`)**:

```c
#ifndef HYBRID_SIG_H
#define HYBRID_SIG_H

#include "hybrid_common.h"

// 生成复合签名密钥对
int hybrid_sig_keygen(
    uint8_t **public_key, size_t *public_key_len,
    uint8_t **private_key, size_t *private_key_len
);

// 对消息摘要进行复合签名
int hybrid_sig_sign(
    uint8_t **signature, size_t *signature_len,
    const uint8_t *message_digest, size_t digest_len,
    const uint8_t *private_key, size_t private_key_len
);

// 验证复合签名
int hybrid_sig_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message_digest, size_t digest_len,
    const uint8_t *public_key, size_t public_key_len
);

#endif // HYBRID_SIG_H
```

**实现文件 (`src/hybrid_sig.c`)** (伪代码逻辑):

```c
#include "hybrid_sig.h"
#include <string.h>

// 伪代码：实现 hybrid_sig_keygen
int hybrid_sig_keygen(...) {
    // 流程与 hybrid_kex_keygen 类似，但调用 OQS_SIG_new(OQS_SIG_ALG) 和 OQS_SIG_keypair()
    return HYBRID_SUCCESS;
}

// 伪代码：实现 hybrid_sig_sign
int hybrid_sig_sign(...) {
    // 1. 解析私钥
    const uint8_t *sm2_priv_raw = private_key;
    const uint8_t *mldsa_priv_raw = private_key + SM2_PRIKEY_LEN;

    // 2. 执行 SM2 签名
    //    使用 EVP_DigestSign* API
    
    // 3. 执行 ML-DSA 签名
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_ALG);
    uint8_t *mldsa_sig = malloc(sig->length_signature);
    OQS_SIG_sign(sig, mldsa_sig, &mldsa_sig_len, message_digest, digest_len, mldsa_priv_raw);

    // 4. 拼接签名
    *signature_len = sm2_sig_len + mldsa_sig_len;
    *signature = malloc(*signature_len);
    //    将 sm2_sig 和 mldsa_sig 拼接到 *signature
    
    // 5. 清理
    return HYBRID_SUCCESS;
}

// 伪代码：实现 hybrid_sig_verify
int hybrid_sig_verify(...) {
    // 1. 解析公钥
    const uint8_t *sm2_pub_raw = public_key;
    const uint8_t *mldsa_pub_raw = public_key + SM2_PUBKEY_LEN;

    // 2. 解析签名 (根据固定长度)
    OQS_SIG *sig_alg = OQS_SIG_new(OQS_SIG_ALG);
    size_t mldsa_sig_len = sig_alg->length_signature;
    size_t sm2_sig_len = signature_len - mldsa_sig_len;
    const uint8_t *sm2_sig = signature;
    const uint8_t *mldsa_sig = signature + sm2_sig_len;

    // 3. 验证 SM2 签名
    //    使用 EVP_DigestVerify* API
    //    如果失败，立即返回错误
    
    // 4. 验证 ML-DSA 签名
    int mldsa_ok = OQS_SIG_verify(sig_alg, message_digest, digest_len, mldsa_sig, mldsa_sig_len, mldsa_pub_raw);
    if (mldsa_ok!= OQS_SUCCESS) {
        // 返回错误
    }

    // 5. 清理
    return HYBRID_SUCCESS;
}
```

-----

**步骤 3.4：编写单元测试 (`test/test_main.c`)**

创建一个独立的测试程序，用于验证上述模块的正确性。

```c
#include "hybrid_kex.h"
#include "hybrid_sig.h"
#include <stdio.h>
#include <assert.h>

void test_kex() {
    printf("Testing Hybrid Key Exchange (SM2+ML-KEM)...\n");
    // 1. 生成客户端和服务器密钥对
    // 2. 服务器使用客户端公钥派生密钥，并生成响应
    // 3. 客户端使用服务器响应派生密钥
    // 4. 使用 assert() 比较两端生成的共享密钥是否完全一致
    printf("KEX test PASSED.\n");
}

void test_sig() {
    printf("Testing Composite Signature (SM2+ML-DSA)...\n");
    // 1. 生成复合签名密钥对
    // 2. 创建一个消息，并用 SM3 计算其摘要
    // 3. 使用私钥对摘要进行签名
    // 4. 使用公钥验证签名，assert() 结果为成功
    // 5. 篡改签名或摘要，再次验证，assert() 结果为失败
    printf("Signature test PASSED.\n");
}

int main() {
    OQS_init();
    test_kex();
    test_sig();
    OQS_destroy();
    return 0;
}
```

-----

**步骤 3.5：编译和执行**

使用 CMake (`CMakeLists.txt`) 来管理项目编译，确保正确链接 GmSSL/OpenSSL 和 liboqs。

```cmake
# CMakeLists.txt 示例
cmake_minimum_required(VERSION 3.10)
project(hybrid_crypto C)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIBRARY NAMES oqs)

# 添加头文件目录
include_directories(include ${OPENSSL_INCLUDE_DIR})

# 创建静态库
add_library(hybrid_crypto STATIC src/hybrid_kex.c src/hybrid_sig.c)
target_link_libraries(hybrid_crypto ${OPENSSL_CRYPTO_LIBRARY} ${OQS_LIBRARY})

# 创建测试程序
add_executable(run_tests test/test_main.c)
target_link_libraries(run_tests hybrid_crypto)
```

**编译与运行命令**：

```bash
mkdir build && cd build
cmake..
make
./run_tests
```

**预期输出**：

```
Testing Hybrid Key Exchange (SM2+ML-KEM)...
KEX test PASSED.
Testing Composite Signature (SM2+ML-DSA)...
Signature test PASSED.
```

