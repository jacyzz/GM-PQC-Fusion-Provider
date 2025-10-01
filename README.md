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
