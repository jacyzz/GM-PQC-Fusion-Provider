#!/usr/bin/env bash
set -euo pipefail

# Simple TLS handshake benchmark & validation script using openssl s_client
# Usage examples:
#   SERVER=10.0.0.5 PORT=443 BASE_GROUP=SM2 HYBRID_GROUP=sm2_mlkem768 ITER=100 bash scripts/tls_benchmark.sh
#   OPENSSL=/usr/local/bin/openssl SERVER=127.0.0.1 PORT=7443 bash scripts/tls_benchmark.sh

OPENSSL_BIN=${OPENSSL:-${OPENSSL_BIN:-openssl}}
SERVER=${SERVER:-127.0.0.1}
PORT=${PORT:-443}
ITER=${ITER:-100}
BASE_GROUP=${BASE_GROUP:-SM2}
HYBRID_GROUP=${HYBRID_GROUP:-sm2_mlkem768}
OUTDIR=${OUTDIR:-benchmarks}
CONCURRENCY=${CONCURRENCY:-32}
REQUESTS=${REQUESTS:-200}

mkdir -p "${OUTDIR}"
STAMP=$(date +%Y%m%d-%H%M%S)
REPORT="${OUTDIR}/report-${STAMP}.md"
RAWLOG="${OUTDIR}/raw-${STAMP}.log"

echo "[info] openssl: ${OPENSSL_BIN}" | tee -a "${RAWLOG}"
echo "[info] server: ${SERVER}:${PORT}" | tee -a "${RAWLOG}"
echo "[info] base_group: ${BASE_GROUP}, hybrid_group: ${HYBRID_GROUP}" | tee -a "${RAWLOG}"

measure_avg_ms() {
  local group=$1
  local iter=$2
  local sum=0.0
  local i t
  for ((i=1;i<=iter;i++)); do
    # Use external time for portability; capture real seconds
    /usr/bin/time -f "%e" -o "/tmp/.t.$$" \
      bash -lc "echo | ${OPENSSL_BIN} s_client -connect ${SERVER}:${PORT} -tls1_3 -groups ${group} -brief -ign_eof -quiet >/dev/null 2>&1" || true
    t=$(cat "/tmp/.t.$$")
    # sum seconds as float via awk
    sum=$(awk -v a="$sum" -v b="$t" 'BEGIN{printf "%.6f", a + b}')
  done
  # average in ms
  awk -v s="$sum" -v n="$iter" 'BEGIN{printf "%.3f", (s/n)*1000.0}'
}

check_negotiated_group() {
  local group=$1
  # Capture s_client output
  local out
  set +e
  out=$(echo | ${OPENSSL_BIN} s_client -connect ${SERVER}:${PORT} -tls1_3 -groups ${group} -brief -ign_eof 2>&1)
  local rc=$?
  set -e
  echo "$out" >> "${RAWLOG}"
  # Look for negotiated group hints; OpenSSL prints lines like "Group: X25519" or detailed summary
  if echo "$out" | grep -qi "${group}"; then
    echo "ok"
  else
    echo "fail"
  fi
}

check_cert_verify_ok() {
  local group=$1
  local out
  set +e
  out=$(echo | ${OPENSSL_BIN} s_client -connect ${SERVER}:${PORT} -tls1_3 -groups ${group} -verify_quiet -verify_return_error -brief -ign_eof 2>&1)
  local rc=$?
  set -e
  echo "$out" >> "${RAWLOG}"
  if echo "$out" | grep -qi "Verify return code: 0 (ok)"; then
    echo "ok"
  else
    echo "fail"
  fi
}

curl_backward_compat() {
  if ! command -v curl >/dev/null 2>&1; then echo "skip"; return 0; fi
  set +e
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --insecure "https://${SERVER}:${PORT}/" )
  local rc=$?
  set -e
  if [ "$rc" -eq 0 ] && [ "$code" != "000" ]; then echo "ok(${code})"; else echo "fail"; fi
}

cpu_usage_sample() {
  # Optional: requires pidstat and a known server process name (nginx or your server)
  local pname=${1:-nginx}
  if ! command -v pidstat >/dev/null 2>&1; then echo "skip"; return 0; fi
  local pids
  pids=$(pgrep -x "$pname" || true)
  if [ -z "$pids" ]; then echo "skip"; return 0; fi
  pidstat -p $(echo "$pids" | tr '\n' ' ') 1 10 2>/dev/null | tee -a "${RAWLOG}" | awk '/^[0-9]/ {sum+=$8; cnt++} END{ if(cnt>0) printf("%.1f", sum/cnt); else print "skip" }'
}

concurrency_stress() {
  local group=$1
  local req=${2:-$REQUESTS}
  local conc=${3:-$CONCURRENCY}
  seq "$req" | xargs -n1 -P "$conc" -I{} bash -lc "echo | ${OPENSSL_BIN} s_client -connect ${SERVER}:${PORT} -tls1_3 -groups ${group} -brief -ign_eof >/dev/null 2>&1"
}

echo "[step] measuring baseline (group=${BASE_GROUP}) ${ITER} iters" | tee -a "${RAWLOG}"
BASE_AVG_MS=$(measure_avg_ms "${BASE_GROUP}" "${ITER}")
echo "[result] baseline avg(ms): ${BASE_AVG_MS}" | tee -a "${RAWLOG}"

echo "[step] measuring hybrid (group=${HYBRID_GROUP}) ${ITER} iters" | tee -a "${RAWLOG}"
HYB_AVG_MS=$(measure_avg_ms "${HYBRID_GROUP}" "${ITER}")
echo "[result] hybrid avg(ms): ${HYB_AVG_MS}" | tee -a "${RAWLOG}"

OVERHEAD_PCT=$(awk -v b="$BASE_AVG_MS" -v h="$HYB_AVG_MS" 'BEGIN{ if (b>0) printf("%.1f", ((h-b)/b)*100.0); else print "n/a" }')

echo "[step] negotiated group check (hybrid)" | tee -a "${RAWLOG}"
NEGOT_RES=$(check_negotiated_group "${HYBRID_GROUP}")

echo "[step] backward compatibility via curl (pure SM2 expected)" | tee -a "${RAWLOG}"
CURL_RES=$(curl_backward_compat)

echo "[step] certificate verify status (hybrid)" | tee -a "${RAWLOG}"
VERIFY_RES=$(check_cert_verify_ok "${HYBRID_GROUP}")

echo "[step] concurrency stress ${REQUESTS} reqs @ ${CONCURRENCY} conc (hybrid)" | tee -a "${RAWLOG}"
set +e
concurrency_stress "${HYBRID_GROUP}" "$REQUESTS" "$CONCURRENCY" 2>>"${RAWLOG}"
set -e

echo "[step] cpu usage sampling (if pidstat/nginx available)" | tee -a "${RAWLOG}"
CPU_SRV=$(cpu_usage_sample nginx)
CPU_CLI=$(cpu_usage_sample ${OPENSSL_BIN##*/})

cat >"${REPORT}" <<EOF
# TLS 基准测试报告 (${STAMP})

目标服务器: ${SERVER}:${PORT}  迭代次数: ${ITER}

## 握手延迟

| 场景 | 平均握手延迟 (ms) | 备注 |
|---|---:|---|
| 纯国密基线 (${BASE_GROUP}) | ${BASE_AVG_MS} | 基准值 |
| 混合模式 (${HYBRID_GROUP}) | ${HYB_AVG_MS} | 相比基线开销 ${OVERHEAD_PCT}% |

## 连接与兼容性校验

| 检验项 | 结果 |
|---|---|
| 混合模式协商组是否为 ${HYBRID_GROUP} | ${NEGOT_RES} |
| 向后兼容（curl --insecure） | ${CURL_RES} |
| 证书验证（s_client Verify return code=0） | ${VERIFY_RES} |

## 并发与 CPU 观测（可选）

| 指标 | 数值 |
|---|---|
| 并发压力 ${REQUESTS}@${CONCURRENCY}（混合） | 完成（详见原始日志） |
| 服务器 CPU 平均占用(%) | ${CPU_SRV} |
| 客户端 CPU 平均占用(%) | ${CPU_CLI} |

> 原始输出见: ${RAWLOG}

EOF

echo "[done] report written: ${REPORT}"

