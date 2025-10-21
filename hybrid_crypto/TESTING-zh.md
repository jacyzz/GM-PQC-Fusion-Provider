## TLS 混合密码方案测试指南（方案A/方案B）

本指南给出两条可操作的测试路径：
- 方案A（立即可跑）基于本仓库的应用层握手 demo（hybrid_server/hybrid_client）完成功能演示与性能测试；
- 方案B（TLS层）在提供“支持目标算法的 TLS 服务器”的前提下，使用 openssl/curl 进行 TLS 维度的功能、兼容与性能测试，并说明如何获得/构建支持你算法的服务器。

目录：
- 0. 前置环境
- 1. 方案A：应用层握手 Demo（功能+性能）
- 2. 方案B：TLS 层测试（如何获得支持你算法的服务器 + 测试项）
- 3. 故障排查

---

### 0. 前置环境
- 两台 Ubuntu 22.04（VM/容器均可），或本机两终端（127.0.0.1）。
- 构建工具：gcc/clang, cmake>=3.16。
- 依赖：OpenSSL 3（SM2/SM3/SM4），liboqs（ML‑KEM/ML‑DSA）。
- 本仓库路径：`GM-PQC-Fusion-Provider/hybrid_crypto`。

构建（通用于A/B两方案的 demo 与工具）：
```bash
cd hybrid_crypto
mkdir -p build && cd build
cmake .. && make -j
```

---

### 1. 方案A：应用层握手 Demo（功能+性能）

方案A不依赖TLS，直接用本仓库的 demo 做“混合握手 + SM4‑GCM 加密”演示与性能评估。

#### 1.1 功能演示（两终端/两VM/两容器）
- 服务器端：
```bash
cd hybrid_crypto/build
./apps/hybrid_server 5555
```
- 客户端：
```bash
cd hybrid_crypto/build
./apps/hybrid_client <server_ip> 5555
```
预期：双方打印相同共享密钥前缀；客户端收到 "pong"。

#### 1.2 性能评估（应用层握手延迟/并发）
- 单次握手延迟：
```bash
cd hybrid_crypto/build
/usr/bin/time -f "elapsed=%E user=%U sys=%S" ./apps/hybrid_client <server_ip> 5555
```
- 平均延迟（示例50次）：
```bash
for i in $(seq 50); do \
  /usr/bin/time -f "%e" -o /tmp/t.$$ ./apps/hybrid_client <server_ip> 5555 >/dev/null 2>&1; \
  cat /tmp/t.$$; \
done | awk '{s+=$1} END{printf "avg_ms=%.3f\n", (s/NR)*1000}'
```
- 并发握手能力（粗略RPS）：
```bash
seq 200 | xargs -n1 -P 32 -I{} ./apps/hybrid_client <server_ip> 5555 >/dev/null
```
- 服务器CPU观测（任选）：
```bash
pidof hybrid_server | xargs -I{} pidstat -p {} 1
# 或：perf stat -p <pid> -- sleep 30
```

#### 1.3 可视化验证（可选）
- 在实体机或服务器上抓取 5555 端口流量，用 Wireshark 观察首帧负载（应包含 SM2 公钥与 ML‑KEM 密文等大体量字段），可作为“混合材料确已在交互中的”证据。

---

### 2. 方案B：TLS 层测试

方案B基于 TLS 端口进行 s_client/curl 维度的功能、兼容性与性能测试。前提是“获得一个支持你目标算法（如 sm2_mlkem768）的 TLS 服务器”。

#### 2.1 如何获得“支持你算法”的 TLS 服务器

你有三种途径（择一）：

- B.1 已有自研/定制的 TLS 栈（推荐直接使用）
  - 如果你的团队已经在 libssl 中“注册”了混合命名组（如 sm2_mlkem768），且完成了 key_share 编解码、协商与握手逻辑，那么：
    1) 用该 libssl 重编 OpenSSL 工具与服务器（如 Nginx/OpenResty）。
    2) Nginx 配置 `ssl_curves sm2_mlkem768;`（或等价配置）并加载复合证书/私钥。
    3) 服务端对外开放 443（或自定端口）。

- B.2 先行验证“方法论”：使用 OQS OpenSSL 的（混合）PQ 组作为阶段性替代
  - 目标：先通过 PQ/混合组（如 `X25519_mlkem768`）走通“TLS端测试流程”，验证脚本与方法；随后再切换到你的自定义组。
  - 步骤：
    1) 构建 liboqs 与 oqs-openssl（Open Quantum Safe 的 OpenSSL 分支，支持 PQ/混合组）。
    2) 重编 Nginx 使其链接 oqs-openssl；配置 listen 443 与 `ssl_curves <oqs-组名>`。
    3) 客户端用该分支的 `openssl s_client -groups <oqs-组名>` 验证握手；确认方法论正确、脚本能出报告。
  - 注意：这并不是你最终的“SM2+ML‑KEM”组，只是验证路径与工具链的“过渡演示”。

- B.3 自行扩展 TLS 实现以支持“SM2+ML‑KEM”混合组（工程量大）
  - 适用：当你需要在 TLS 内“原生”支持 `sm2_mlkem768`。
  - 要点：
    - 在 libssl 中新增命名组条目（IANA 私有范围 ID）、key_share 线格式（组合 SM2 ECDH 公钥与 ML‑KEM 公钥/密文）、客户端/服务器两端的协商与派生逻辑。
    - 若采用 oqs-openssl 分支作为基线，参考其已实现的“混合组”代码路径，替换/扩展为 SM2 曲线 + ML‑KEM。
    - 重编 openssl 工具和 Nginx（`./configure --with-openssl=<你的libssl源码>`），在配置中开启你的组名。
  - 这是一个项目级改造，建议评估里程碑与合规要求后实施。

> 小结：若你已有具备该能力的 TLS 服务器，直接进入 2.2 测试步骤；若没有，可先用 B.2 的 oqs 混合组做方法验证，随后推进 B.3 的定制实现。

#### 2.2 功能与兼容性测试（TLS）

假定服务器已在 443 提供支持你目标组的 TLS：

- 混合模式连接测试（客户端 VM）：
```bash
OPENSSL=/usr/local/bin/openssl  # 指向你的自编译 openssl
echo | ${OPENSSL} s_client -connect <server_ip>:443 -tls1_3 -groups sm2_mlkem768 -brief -ign_eof
```
期望：输出中可见已协商组为 `sm2_mlkem768`（不同版本格式不同，可搜索组名）。

- 向后兼容性测试（旧客户端回退）：
```bash
curl https://<server_ip> --insecure
```
期望：连接成功；服务器日志显示协商为“纯 SM2”而非混合。

- 复合证书验证测试：
```bash
${OPENSSL} s_client -connect <server_ip>:443 -tls1_3 -groups sm2_mlkem768 -verify_quiet -verify_return_error -brief -ign_eof
```
期望：包含 `Verify return code: 0 (ok)`；无证书错误。

#### 2.3 性能测试（TLS）

使用仓库脚本自动生成报告（需 TLS 端口）：
```bash
cd hybrid_crypto
chmod +x scripts/tls_benchmark.sh
SERVER=<Server_IP> PORT=443 BASE_GROUP=SM2 HYBRID_GROUP=sm2_mlkem768 ITER=100 \
bash scripts/tls_benchmark.sh
```
输出：
- `benchmarks/report-*.md` 含表格（基线/混合平均握手时延与百分比开销、协商/兼容/验证结果）；
- `benchmarks/raw-*.log` 原始日志可溯源。

并发与 CPU 观测：
- 可在脚本外单独进行并发连接（xargs -P 并发）并用 `top/htop/pidstat` 监控服务器负载；
- 若服务器为 Nginx，可让脚本尝试采样 nginx 进程的 pidstat（需预装 `sysstat`）。

#### 2.4 流量分析（TLS）
- 在实体机 Wireshark 抓 VMnet 接口流量；
- 筛选 `tls.handshake.type == 1`（ClientHello），展开 `extensions -> key_share`；
- 验证包含 `sm2_mlkem768` 条目，且该条目数据长度约 ~1.2KB（典型 PQC 体量）。

---

### 3. 故障排查
- s_client 报不认识组名：说明 TLS 服务器/客户端使用的 libssl 未注册该组；请确认 B.1/B.2/B.3 的构建来源。
- curl 失败：检查证书与 TLS 配置，或使用 `--insecure` 进行连通性验证后再排查证书链。
- `tls_benchmark.sh` 未生成表格：检查环境变量（SERVER/PORT/OPENSSL）与 TLS 端口连通性；查看 `benchmarks/raw-*.log`。
- 应用层 demo 连接失败：检查双方是否运行相同版本、端口是否放通、防火墙与容器网络配置。

---

附：与本仓库的关系
- 方案A 完全使用本仓库现有代码即可落地（无需 TLS）。
- 方案B 需要一个“支持你目标混合组”的 TLS 终端：
  - 已有自研/定制则直接使用；
  - 或先用 oqs‑openssl 的现成（混合）组验证方法，再推进你组的定制注册；
  - 注册你组（如 sm2_mlkem768）需要在 libssl 中新增命名组与 key_share 编解码及协商逻辑，这是 TLS 实现层的改动，独立于本仓库的应用层库。


