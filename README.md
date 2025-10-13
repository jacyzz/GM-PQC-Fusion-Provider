GM-PQC-Fusion-Provider
======================

混合国密与后量子（PQC）的开发与演示环境，基于 OpenSSL 3 Provider（SM2/SM3/SM4 + ML-KEM/ML-DSA）。

### 快速开始
```bash
make up       # 构建并启动（使用 infra/compose/docker-compose.yml）
make shell    # 进入容器（/workspaces/project）
make verify   # 环境自检（infra/scripts/verify_env.sh）
make down     # 停止容器
```

### 运行期验证
```bash
openssl version -a
pkg-config --modversion liboqs
OPENSSL_MODULES=/usr/local/lib64/ossl-modules openssl list -providers
OPENSSL_MODULES=/usr/local/lib64/ossl-modules openssl list -kem-algorithms -provider oqsprovider -provider default
```

更多细节见 `README-devcontainer.md`。

## 构建并安装自研 Provider（gmpqc_provider）

在容器中执行以下命令（默认工作目录为 `/workspaces/project`）：

```bash
# 配置与构建
cd /workspaces/project/gmpqc-provider_demo
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib64 ..
ninja

# 安装到 OpenSSL 模块目录（需要 sudo）
sudo ninja install
```

卸载/清理：

```bash
# 方式一：按安装清单删除（推荐）
cd /workspaces/project/gmpqc-provider_demo/build
sudo xargs -a install_manifest.txt -I{} rm -v "{}"

# 方式二：直接删除已安装模块（简单）
sudo rm -v /usr/local/lib64/ossl-modules/gmpqc_provider.so

# 清理本地构建产物
cd /workspaces/project/gmpqc-provider_demo && rm -rf build
```

## 验证 Provider 是否可见以及算法名称

```bash
# 查看已加载的 Provider（应看到 default 与 gmpqc_provider）
openssl list -providers -provider gmpqc_provider -provider default

# 查看 KEM 算法（应看到：SM2-ML-KEM-768 @ gmpqc_provider）
openssl list -kem-algorithms -provider gmpqc_provider -provider default

# 使用项目内自测程序进行回环测试（keygen/encap/decap）
./examples/kem_demo --provider gmpqc_provider --kem SM2-ML-KEM-768
```

注意：openssl CLI 的 `genpkey` 写私钥到文件需要 serializer/encoder，本项目的最小实现尚未提供私钥序列化。如需验证 keygen/KEM，请使用上面的 `kem_demo` 或示例 server/client。

## 运行服务端与客户端（使用自研 Provider）

- 服务端（会发送携带 KEM 名称与公钥的 Hello）：

```bash
./examples/server \
	--provider gmpqc_provider \
	--kem SM2-ML-KEM-768 \
	--aead aes-128-gcm \
	--listen 0.0.0.0:8443 \
	--payload 1024 \
	--n 200
```

- 客户端（收到服务端 Hello 后按相同的 KEM 名进行封装）：

```bash
./examples/client \
	--provider gmpqc_provider \
	--mode pqc \
	--aead aes-128-gcm \
	--connect 127.0.0.1:8443 \
	--payload 1024 \
	--n 200
```

要求：客户端与服务端都必须加载相同的 provider（`--provider gmpqc_provider`），且服务端 `--kem` 的算法名需与 provider 暴露的名字完全一致（`SM2-ML-KEM-768`）。

## 故障排查（常见）

- “Unable to query provider parameters”：升级后已实现 GETTABLE/GET PARAMS，如仍出现请确认已重新安装 `.so` 并指向正确的 `OPENSSL_MODULES`。
- “kem keygen fail”：
	- 先用 `./examples/kem_demo --provider gmpqc_provider --kem SM2-ML-KEM-768` 验证；
	- 确认 `openssl list -kem-algorithms -provider gmpqc_provider -provider default` 有 `SM2-ML-KEM-768`；
	- 两端都传 `--provider gmpqc_provider`。
- 打开 OpenSSL 运行期 trace 观察算法选择与 provider 加载：

```bash
OPENSSL_TRACE=algorithm,provider \
./examples/server --provider gmpqc_provider --kem SM2-ML-KEM-768 --aead aes-128-gcm --listen 0.0.0.0:8443 --payload 1024 --n 1
```

## 查看 Provider 与算法（速查）

如果模块目录不是默认路径，请先确认环境变量（容器里通常已指向 `/usr/local/lib64/ossl-modules`）：

```bash
# 如需自定义：
# export OPENSSL_MODULES=/usr/local/lib64/ossl-modules
```

- 查看已加载的 Provider：

```bash
openssl list -providers
```

- 同时加载并查看自定义 Provider（建议总是带上 default）：

```bash
openssl list -providers -provider gmpqc_provider -provider default
```

- 列出 KEM 算法（加载 gmpqc_provider + default）：

```bash
openssl list -kem-algorithms -provider gmpqc_provider -provider default
```

- 仅查看某个 Provider 提供的算法（属性过滤）：

```bash
openssl list -kem-algorithms -provider gmpqc_provider -provider default -propquery 'provider=gmpqc'
```

- 其他常用算法类别：

```bash
openssl list -cipher-algorithms  -provider default
openssl list -digest-algorithms  -provider default
openssl list -mac-algorithms     -provider default
openssl list -kdf-algorithms     -provider default
openssl list -public-key-algorithms -provider default
```

- 显示更详细来源信息：

```bash
openssl list -kem-algorithms -provider gmpqc_provider -provider default -verbose
```

- 获取 list 子命令帮助：

```bash
openssl list -help
```

## Provider 设计与“混合密钥”实现逻辑（SM2 + ML-KEM）

本项目的自研 Provider（模块名：`gmpqc_provider`，算法名：`SM2-ML-KEM-768`）以 OpenSSL 3 Provider 模式实现“国密 SM2 + PQC ML-KEM-768”的混合 KEM，核心由两部分组成：

- KEYMGMT（密钥管理，算法名同为 `SM2-ML-KEM-768`）
- KEM（封装/解封装接口，算法名 `SM2-ML-KEM-768`）

实现原则：
- 国密部分全部使用 OpenSSL 3 的原生 EVP SM2 能力（不在 provider 内引入 GmSSL）。
- PQC 部分使用 liboqs（本实现固定为 ML-KEM-768，对应 OQS 名称 `ML-KEM-768`）。
- 通过 KEYMGMT 将“混合密钥”的公钥序列化为“可被应用层直接携带/传输”的二进制，KEM 则消费该公钥完成混合封装。

### 数据结构与格式

- 混合公钥（KEYMGMT 导出的 `OSSL_PKEY_PARAM_PUB_KEY` 值）：
	- 格式：`[2 字节大端 SM2 SPKI DER 长度] | [SM2 SPKI DER] | [ML-KEM 公钥]`
	- 说明：
		- SM2 SPKI DER 使用 OpenSSL `i2d_PUBKEY()` 导出（标准 X.509 SubjectPublicKeyInfo）。
		- ML-KEM 公钥来自 liboqs 的 `OQS_KEM_keypair()` 生成。

- 混合密文（KEM 封装输出 out）：
	- 格式：`[2 字节大端 SM2 密文长度] | [SM2 密文] | [ML-KEM 密文]`
	- 说明：
		- SM2 密文由 EVP `EVP_PKEY_encrypt()` 对 32 字节随机片段加密得到（即 SM2 KEM 的对称种子部分）。
		- ML-KEM 密文由 liboqs `OQS_KEM_encaps()` 生成。

- 共享秘密（KEM 封装/解封装的 secret）：
	- 格式：`[SM2 共享片段(32B)] | [ML-KEM 共享秘密]`
	- 说明：
		- SM2 共享片段是封装端随机生成的 32 字节，经 SM2 公钥加密/私钥解密对齐。
		- ML-KEM 共享秘密由 liboqs 提供（ML-KEM-768 通常为 32 字节）。
		- 合并后一般为 64 字节（32 + 32）。

### KEYMGMT（生成/导入/导出）

- 生成（`GEN`）：
	1) 使用 OpenSSL EVP 生成 SM2 密钥对。
	2) 使用 liboqs 生成 ML-KEM-768 密钥对。
	3) 将二者保存在 provider 私有结构（`GMPQC_KEY`）。

- 导入公钥（`IMPORT`）：
	- 支持从上面的“混合公钥格式”导入，仅用于公共参数（服务端发给客户端，或客户端收到后封装）。

- 导出公钥（`EXPORT` / `GET_PARAMS`）：
	- 通过 `OSSL_PKEY_PARAM_PUB_KEY` 返回“混合公钥格式”二进制，便于应用层直接传输。

注意：目前未实现私钥的序列化（serializer/encoder）。这意味着 `openssl genpkey -out key.pem` 这类直接写文件的命令不适用；但不影响示例程序的生成/封装/解封装使用。

### KEM（封装/解封装）

- 封装（客户端侧）：
	1) `ENCAPSULATE_INIT` 从 `vkey`（KEYMGMT）中提取序列化混合公钥。
	2) 解析得到 SM2 SPKI DER 与 ML-KEM 公钥。
	3) 生成 32 字节随机片段，用 SM2 公钥 `EVP_PKEY_encrypt()` 加密，得到 SM2 密文。
	4) 调用 `OQS_KEM_encaps(ML-KEM-768)` 得到 ML-KEM 密文与共享秘密。
	5) 输出混合密文与共享秘密（共享秘密为 32B SM2 片段 + ML-KEM 共享秘密）。

- 解封装（服务端侧）：
	1) `DECAPSULATE_INIT` 基于 `vkey` 克隆出内部私钥材料（SM2 私钥 + ML-KEM 私钥）。
	2) 解析混合密文，分离 SM2 密文与 ML-KEM 密文。
	3) 用 SM2 私钥 `EVP_PKEY_decrypt()` 还原 32 字节片段。
	4) 调用 `OQS_KEM_decaps()` 还原 ML-KEM 共享秘密。
	5) 拼接得到共享秘密（同封装端）。

### Provider 能力与属性

- Provider 参数：已实现 `NAME`、`VERSION`、`BUILDINFO` 以便 `openssl list -providers` 无警告列出。
- 暴露的操作与算法：
	- `OSSL_OP_KEYMGMT`：`SM2-ML-KEM-768`（属性：`provider=gmpqc`）
	- `OSSL_OP_KEM`：`SM2-ML-KEM-768`（属性：`provider=gmpqc`）
- 算法选择：应用层可通过 `-provider gmpqc_provider -provider default` 加载，并在需要时用 `-propquery 'provider=gmpqc'` 做属性过滤。

### 与示例程序的对接

- 服务端：`--kem SM2-ML-KEM-768` 生成混合密钥并导出“混合公钥格式”，打包进 ServerHello 发给客户端。
- 客户端：收到“混合公钥格式”后，使用 `SM2-ML-KEM-768` 完成封装，返回“混合密文”。
- 双方用 HKDF-SHA3-256 对共享秘密派生会话密钥，再用 AEAD（默认 `aes-128-gcm`）进行数据加解密。

### 限制与可扩展项

- 暂未提供私钥 serializer/encoder；如需 `genpkey -out` 导出，请扩展相应组件。
- 可选增强：
	- 支持配置 SM2 Dist-ID（双方需要一致）。
	- 把 OQS KEM 名称参数化（例如 ML-KEM-512/1024）。
	- 增加错误信息的可观测性与统计。


