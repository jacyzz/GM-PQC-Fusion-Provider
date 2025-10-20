## 混合密码库（SM2/SM3/SM4 + Kyber/Dilithium）

本模块提供：
- **混合密钥交换**：SM2 ECDH + Kyber/ML-KEM，使用 SM3 进行 KDF 合成共享密钥
- **复合签名**：SM2 + Dilithium/ML-DSA，对消息摘要分别签名并拼接
- **演示应用**：基于共享密钥的 SM4-GCM 加密通信的客户端/服务器示例

### 环境与依赖
- **OpenSSL 3.x**（启用 SM2/SM3/SM4）
- **liboqs**（包含 Kyber/ML-KEM、Dilithium/ML-DSA）
- 可选：**GmSSL**（如果希望用 GmSSL 的 SM2/SM3/SM4 实现）
- 构建工具：`cmake >= 3.16`、`gcc/clang`

你的 devcontainer 镜像已预装上述依赖（OpenSSL 3、liboqs、oqs-provider、GmSSL）。

### 目录结构
```
hybrid_crypto/
  include/
    hybrid_common.h
    hybrid_kex.h
    hybrid_sig.h
  src/
    hybrid_common.c
    hybrid_kex.c
    hybrid_sig.c
  apps/
    hybrid_server.c
    hybrid_client.c
  test/
    test_main.c
  CMakeLists.txt
```

### 快速构建
```bash
cd hybrid_crypto
mkdir build && cd build
cmake ..
make -j
```

如需切换为 **GmSSL** 作为 SM2/SM3/SM4 的实现：
```bash
cmake .. -DHYBRID_USE_GMSSL=ON -DGMSSL_ROOT=/opt/gmssl
make -j
```

### 自检（可选）
验证 PQC provider 可用（在容器内通常已就绪）：
```bash
OPENSSL_MODULES=/usr/local/lib64/ossl-modules \
  openssl list -kem-algorithms -provider oqsprovider -provider default
```

### 单元测试
```bash
./run_tests
```
预期输出包含 KEX 与 Signature 测试通过。

### 演示应用（本机两终端）
```bash
# 终端A
./apps/hybrid_server 5555
# 终端B
./apps/hybrid_client 127.0.0.1 5555
```
你将看到双方导出的共享密钥前缀，以及基于 SM4-GCM 的 ping/pong 加密通信。

### 在 Docker 中运行（同一主机两容器）
先基于仓库提供的 `.devcontainer/Dockerfile` 构建镜像：
```bash
docker build -f .devcontainer/Dockerfile -t gm-pqc-dev:latest .
```

分别启动服务端与客户端容器：
```bash
# 终端A：服务端
docker run --rm -it -v $(pwd):/work -w /work gm-pqc-dev \
  bash -lc "cd hybrid_crypto && mkdir -p build && cd build && cmake .. && make -j && ./apps/hybrid_server 5555"

# 终端B：客户端（Linux 可使用 --network host 简化网络）
docker run --rm -it --network host -v $(pwd):/work -w /work gm-pqc-dev \
  bash -lc "cd hybrid_crypto/build && ./apps/hybrid_client 127.0.0.1 5555"
```
如宿主禁用 `--network host`，可创建自定义 bridge 网络，使用服务器容器的 IP 连接。

### 在两台虚拟机上运行
- **方案A（推荐）**：两台 VM 都安装 Docker，使用上面构建好的镜像与同样命令运行。
- **方案B（原生安装）**：在两台 VM 原生安装 OpenSSL 3 与 liboqs，然后在 `hybrid_crypto` 内构建并运行；在 VM1 运行 `hybrid_server`，在 VM2 运行 `hybrid_client <VM1_IP>`。

### API 说明
```c
// 混合密钥交换（公钥: SM2_pub||MLKEM_pub，私钥: SM2_priv||MLKEM_sk）
int hybrid_kex_keygen(uint8_t **pub, size_t *pub_len,
                      uint8_t **priv, size_t *priv_len);

// 服务端：输入客户端公钥和本端私钥，导出共享密钥并生成响应
// 响应格式：server_sm2_pub(65字节) || mlkem_ciphertext
int hybrid_kex_server_derive(uint8_t **shared, size_t *shared_len,
                             uint8_t **resp, size_t *resp_len,
                             const uint8_t *client_pub, size_t client_pub_len,
                             const uint8_t *server_priv, size_t server_priv_len);

// 客户端：输入服务器响应与自身私钥，导出共享密钥
int hybrid_kex_client_derive(uint8_t **shared, size_t *shared_len,
                             const uint8_t *resp, size_t resp_len,
                             const uint8_t *client_priv, size_t client_priv_len);

// 复合签名（公钥: SM2_pub||MLDSA_pub，私钥: SM2_priv||MLDSA_sk）
int hybrid_sig_keygen(uint8_t **pub, size_t *pub_len,
                      uint8_t **priv, size_t *priv_len);

// 对消息摘要进行复合签名（摘要建议为 SM3 结果）
int hybrid_sig_sign(uint8_t **sig, size_t *sig_len,
                    const uint8_t *msg_digest, size_t digest_len,
                    const uint8_t *priv, size_t priv_len);

// 验证复合签名
int hybrid_sig_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg_digest, size_t digest_len,
                      const uint8_t *pub, size_t pub_len);
```

### 关键实现要点
- 共享密钥派生：将 SM2 ECDH 输出与 ML-KEM 共享密钥拼接后，经 `SM3` 进行 KDF，得到 32 字节共享密钥（示例中取前 16 字节作为 SM4-GCM 密钥）。
- 复合签名：对同一摘要分别生成 SM2（DER 编码）与 ML-DSA 签名，并按 `SM2_sig(DER)||MLDSA_sig` 拼接。

### 注意事项（生产化建议）
- 在 KDF 中加入上下文绑定（如角色标识、会话参数），并进行参数校验与错误处理细化。
- 考虑 side-channel 抵御（恒时序比较、敏感内存清零等）。
- 根据合规性要求选择 OpenSSL 3 还是 GmSSL 的国密实现。


