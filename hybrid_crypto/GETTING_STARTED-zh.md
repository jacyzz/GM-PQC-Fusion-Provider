## 混合密码库使用与测试指南（VM/容器）

本指南面向拿到仓库后需要“快速搭建、演示功能、进行性能验证”的使用者。完成本页步骤，你将能在两台虚拟机或两容器间完成 SM2+ML‑KEM 的混合握手，并用 SM4‑GCM 完成加密通信；同时给出可复现的性能测量方法与常见问题排查。

### 1. 仓库获取与目录
```bash
git clone https://github.com/<your-org>/GM-PQC-Fusion-Provider.git
cd GM-PQC-Fusion-Provider/hybrid_crypto
```
关键目录/文件：
- include/: 对外头文件（`hybrid_common.h`, `hybrid_kex.h`, `hybrid_sig.h`）
- src/: 实现
- apps/: 演示程序（`hybrid_server`, `hybrid_client`）
- test/: 单测入口（`run_tests`）
- CMakeLists.txt: 构建入口

### 2. 环境要求
- Linux（Ubuntu 22.04 推荐）
- 构建工具：gcc/clang、cmake>=3.16
- 依赖库：OpenSSL 3（启用SM2/SM3/SM4）、liboqs（含 ML‑KEM/ML‑DSA）
- 可选：GmSSL（作为国密实现变体）

提示：本仓库提供 `.devcontainer/Dockerfile` 可一键构建开发镜像，已包含以上依赖，推荐优先使用。

### 3. 快速开始（两种方式）

#### 3.1 容器方式（推荐）
构建镜像：
```bash
docker build -f .devcontainer/Dockerfile -t gm-pqc-dev:latest ../
# ↑ 在 hybrid_crypto 上级目录执行（项目根）
```
在容器内构建：
```bash
docker run --rm -it -v $(pwd):/work -w /work gm-pqc-dev \
  bash -lc "cd hybrid_crypto && mkdir -p build && cd build && cmake .. && make -j"
```

#### 3.2 原生方式（VM/物理机）
```bash
sudo apt update && sudo apt install -y build-essential cmake ninja-build git
# 按需安装 OpenSSL 3 与 liboqs（或直接使用本仓库镜像）
cd hybrid_crypto && mkdir -p build && cd build
cmake .. && make -j
```

### 4. 功能演示（本机、两VM、两容器）

#### 4.1 本机两终端
```bash
# 终端A
cd hybrid_crypto/build
./apps/hybrid_server 5555

# 终端B
cd hybrid_crypto/build
./apps/hybrid_client 127.0.0.1 5555
```
预期：双方打印相同共享密钥前缀，客户端收到 "pong"。

#### 4.2 两台虚拟机
- VM1（服务器）：
```bash
cd hybrid_crypto && mkdir -p build && cd build
cmake .. && make -j
./apps/hybrid_server 5555
```
- VM2（客户端）：
```bash
cd hybrid_crypto && mkdir -p build && cd build
cmake .. && make -j
./apps/hybrid_client <vm1_ip> 5555
```

（可选）通过 Nginx 四层代理对外暴露：在 VM1 `nginx.conf` 顶层添加：
```nginx
stream {
  upstream hybrid_upstream { server 127.0.0.1:5555; }
  server { listen 7443; proxy_timeout 300s; proxy_pass hybrid_upstream; }
}
```
重载后，客户端连接 `./apps/hybrid_client <vm1_ip> 7443`。

#### 4.3 两容器（同一宿主）
```bash
# 构建镜像（项目根）
docker build -f .devcontainer/Dockerfile -t gm-pqc-dev:latest .

# 终端A（服务器容器）
docker run --rm -it -p 5555:5555 -v $(pwd):/work -w /work gm-pqc-dev \
  bash -lc "cd hybrid_crypto && mkdir -p build && cd build && cmake .. && make -j && ./apps/hybrid_server 5555"

# 终端B（客户端容器，host 网络最简便）
docker run --rm -it --network host -v $(pwd):/work -w /work gm-pqc-dev \
  bash -lc "cd hybrid_crypto/build && ./apps/hybrid_client 127.0.0.1 5555"
```
如禁用 host 网络，可使用自定义 bridge，并用容器名/IP 连接服务器容器。

### 5. 单元测试与自检
```bash
cd hybrid_crypto/build
./run_tests
```
预期输出包含 KEX 与 Signature 测试通过。

自检 Provider（容器中通常已就绪）：
```bash
OPENSSL_MODULES=/usr/local/lib64/ossl-modules \
  openssl list -kem-algorithms -provider oqsprovider -provider default
```

### 6. 性能验证（可复现）
说明：当前 demo 每次连接只握手并交换一次小报文，适合评估“握手延迟/并发能力”。如需持续吞吐评估，可在此基础上扩展应用层循环或引入 gateway。

1) 单次握手延迟
```bash
cd hybrid_crypto/build
/usr/bin/time -f "elapsed=%E user=%U sys=%S" ./apps/hybrid_client <server_ip> 5555
```
多次：
```bash
for i in $(seq 50); do ./apps/hybrid_client <server_ip> 5555 >/dev/null; done
```
可选（更友好统计，若安装 hyperfine）：
```bash
hyperfine "./apps/hybrid_client <server_ip> 5555"
```

2) 并发握手能力（粗略 RPS）
```bash
cd hybrid_crypto/build
seq 200 | xargs -n1 -P 32 -I{} ./apps/hybrid_client <server_ip> 5555 >/dev/null
```
服务器侧观测：
```bash
pidof hybrid_server | xargs -I{} pidstat -p {} 1
# 或：perf stat -p <pid> -- sleep 30
```

3) 对称加密基线（SM4‑GCM 吞吐）
```bash
openssl speed -evp sm4-gcm
```

4) PQC/KEM/签名基线（可选）
- 构建 liboqs 时启用官方基准工具（speed_kem/speed_sig），获得算法级耗时/吞吐指标。

### 7. 常见问题排查
- 连接失败：确认服务器监听端口（5555/7443）、IP/端口正确、Nginx 转发与防火墙策略。
- `EVP_CIPHER_fetch("SM4-GCM")` 为空：确保 Provider 可见（`OPENSSL_MODULES=/usr/local/lib64/ossl-modules`）且默认 provider 已加载。
- CMake 找不到 liboqs：设置 `PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig` 后重新 `cmake ..`。
- 握手失败（-11）：多为 SM2 ECDH/KEM 导出失败，确保双方代码版本一致、链路稳定；必要时抓包核对首帧。

### 8. GMSSL 变体（可选）
构建时切换为 GmSSL 作为 SM2/SM3/SM4 实现：
```bash
cd hybrid_crypto && mkdir -p build && cd build
cmake .. -DHYBRID_USE_GMSSL=ON -DGMSSL_ROOT=/opt/gmssl
make -j
```
产物与 API 不变；仅需在部署环境确保 GmSSL 静态库/路径可用。

### 9. 集成到你的服务（两种方式）
方式A：子工程引入（推荐）
```cmake
add_subdirectory(hybrid_crypto)
target_link_libraries(your_app PRIVATE hybrid_crypto)
target_include_directories(your_app PRIVATE ${CMAKE_SOURCE_DIR}/hybrid_crypto/include)
```

方式B：预编译产物分发
- 分发 `hybrid_crypto/build/libhybrid_crypto.a` 与 `hybrid_crypto/include/`
- 链接：`hybrid_crypto`、`crypto`、`oqs`
- 如需：设置 `LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib` 与 `OPENSSL_MODULES=/usr/local/lib64/ossl-modules`

### 10. API 速览
```c
int hybrid_kex_keygen(uint8_t **pub, size_t *pub_len,
                      uint8_t **priv, size_t *priv_len);
int hybrid_kex_server_derive(uint8_t **shared, size_t *shared_len,
                             uint8_t **resp, size_t *resp_len,
                             const uint8_t *client_pub, size_t client_pub_len,
                             const uint8_t *server_priv, size_t server_priv_len);
int hybrid_kex_client_derive(uint8_t **shared, size_t *shared_len,
                             const uint8_t *resp, size_t resp_len,
                             const uint8_t *client_priv, size_t client_priv_len);

int hybrid_sig_keygen(uint8_t **pub, size_t *pub_len,
                      uint8_t **priv, size_t *priv_len);
int hybrid_sig_sign(uint8_t **sig, size_t *sig_len,
                    const uint8_t *msg_digest, size_t digest_len,
                    const uint8_t *priv, size_t priv_len);
int hybrid_sig_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg_digest, size_t digest_len,
                      const uint8_t *pub, size_t pub_len);
```

---



