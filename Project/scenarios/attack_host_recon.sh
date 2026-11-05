#!/usr/bin/env bash
# 커널 버전과 CPU 정보만 읽는다. id, uname, /etc/passwd는 정상 운영과 ls에서도 열려 넣지 않는다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat /proc/version >/dev/null
  cat /proc/cpuinfo >/dev/null
'
