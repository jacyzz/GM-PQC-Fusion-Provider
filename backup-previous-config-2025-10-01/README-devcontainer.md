## 可共享开发环境（Dev Container）

本环境基于 Docker 与 Dev Container，预装：
- OpenSSL 3.${OPENSSL_MINOR:-2}.x（启用 SM2/SM3/SM4）
- liboqs（共享库）
- oqs-provider（OpenSSL 3 Provider，含 ML-KEM/ML-DSA）

### 一键使用（VS Code / Cursor）
1. 安装 Docker 与 VS Code Dev Containers 扩展（Cursor 同样支持）。
2. 打开本仓库，选择“Reopen in Container”。
3. 首次启动将自动构建镜像并执行 `scripts/verify_env.sh` 自检。

### 命令行使用（无 VS Code）
```bash
docker compose up -d --build
docker exec -it pqc-dev bash
```

### 使用 Makefile（更简洁）
```bash
make up       # 构建并启动
make shell    # 进入容器
make verify   # 环境自检
make down     # 停止容器
```

### 快速验证
```bash
OPENSSL_MODULES=/usr/local/lib/ossl-modules openssl list -provider oqsprovider -kem-algorithms | grep -i ml-kem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out /tmp/sm2.key
OPENSSL_MODULES=/usr/local/lib/ossl-modules openssl genpkey -provider oqsprovider -algorithm mldsa44 -out /tmp/mldsa.key
```

### 目录与文件
- `.devcontainer/Dockerfile`：镜像构建，包含 OpenSSL/liboqs/oqs-provider。
- `.devcontainer/devcontainer.json`：Dev Container 配置，自动加载 oqs-provider。
- `scripts/verify_env.sh`：启动后自检脚本。
- `docker-compose.yml`：独立 Docker 运行方式。

### 常见问题
- 若 `oqsprovider.so` 未找到，确认 `OPENSSL_MODULES=/usr/local/lib/ossl-modules`。\
  也可在容器内执行 `ldconfig -p | grep ossl-modules` 检查路径。
- 若 `openssl` 版本非 3.x，请确认 PATH 指向 `/usr/local/bin/openssl`（镜像已默认）。


若需推送预编译镜像以便团队复用：make buildx-push IMAGE=<repo/name> TAG=<tag>。
