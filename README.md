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


