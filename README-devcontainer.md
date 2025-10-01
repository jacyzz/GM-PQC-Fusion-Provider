## 可共享开发环境（Dev Container）

本环境基于 Docker 与 Dev Container，预装：
- OpenSSL 3.${OPENSSL_MINOR:-2}.x（启用 SM2/SM3/SM4）
- liboqs（共享库）
- GMSSL

### 一键使用（VS Code / Cursor）
1. 安装 Docker 与 VS Code Dev Containers 扩展（Cursor 同样支持）。
2. 打开本仓库，选择“Reopen in Container”。
3. 首次启动将自动构建镜像并执行 `infra/scripts/verify_env.sh` 自检。

### 命令行使用（无 VS Code）
```bash
docker compose -f infra/compose/docker-compose.yml up -d --build
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
openssl version -a
pkg-config --modversion liboqs
ls -l /usr/local/lib64 | grep liboqs.so
# 看看 provider 是否可见
OPENSSL_MODULES=/usr/local/lib64/ossl-modules openssl list -providers
# 列出 pqc KEM 算法
OPENSSL_MODULES=/usr/local/lib64/ossl-modules openssl list -kem-algorithms -provider oqsprovider -provider default
ls -l /opt/gmssl/lib/libgmssl.a
bash infra/scripts/verify_env.sh
```

### 目录与文件
- `.devcontainer/Dockerfile`：镜像构建，包含 OpenSSL/liboqs/oqs-provider。
- `.devcontainer/devcontainer.json`：Dev Container 配置，引用 `infra/compose/docker-compose.yml` 并自动运行自检。
- `infra/scripts/verify_env.sh`：启动后自检脚本。
- `infra/compose/docker-compose.yml`：独立 Docker 运行方式。

### 常见问题
- 若 `oqsprovider.so` 未找到，确认 `OPENSSL_MODULES=/usr/local/lib64/ossl-modules`。\
  也可在容器内执行 `ls -l /usr/local/lib64/ossl-modules` 或 `ldconfig -p | grep ossl-modules` 检查路径。
- 若 `openssl` 版本非 3.x，请确认 PATH 指向 `/usr/local/bin/openssl`（镜像已默认）。


若需推送预编译镜像以便团队复用：make buildx-push IMAGE=<repo/name> TAG=<tag>。

### 当前环境布置概况（容器内 pqc-dev）：

- 基础系统
  - Ubuntu 22.04
  - 开发用户 `dev`，工作目录 `/workspaces/project`

- OpenSSL
  - 版本：OpenSSL 3.2.1（启用 SM2/SM3/SM4）
  - 安装位置：`/usr/local`（库在 `/usr/local/lib64`）
  - 运行时：已将 `/usr/local/lib64` 写入 `ld.so.conf.d` 并执行 `ldconfig`

- PQC 库（liboqs）
  - 版本：main（共享库）
  - 安装位置：`/usr/local/lib64`，头文件在 `/usr/local/include`
  - pkg-config：`liboqs.pc` 可用（`PKG_CONFIG_PATH` 包含 `/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig`）

- PQC Provider（oqs-provider）
  - 安装位置：`/usr/local/lib64/ossl-modules/oqsprovider.so`
  - 运行时：`OPENSSL_MODULES=/usr/local/lib64/ossl-modules`

- 国密库（GmSSL）
  - 形式：静态库
  - 安装位置：`/opt/gmssl`
  - 头文件：`/opt/gmssl/include`
  - 库文件：`/opt/gmssl/lib/libgmssl.a`
  - 可执行：`/opt/gmssl/bin/gmssl`（若存在会在自检中打印版本）

- Compose/DevContainer
  - Compose 文件：`infra/compose/docker-compose.yml`
  - 镜像内已设置 `OPENSSL_MODULES=/usr/local/lib64/ossl-modules`
  - 自检脚本：`infra/scripts/verify_env.sh`（包含 OpenSSL 版本、liboqs、oqs-provider、SM2 与 GmSSL 检查）



编译链接要点：
- OpenSSL：`-I/usr/local/include -L/usr/local/lib64 -lssl -lcrypto`
- liboqs：`$(pkg-config --cflags --libs liboqs)`
- GmSSL（静态）：`-I/opt/gmssl/include -L/opt/gmssl/lib -lgmssl`（必要时补 `-ldl -lpthread`）
- 运行时如需避免设置环境变量，可增加 rpath：`-Wl,-rpath,/usr/local/lib64`