#!/usr/bin/env bash
# frontend에서 환경변수와 프로세스 환경 파일을 읽고 출력은 버린다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c \
  'env >/dev/null; cat /proc/self/environ >/dev/null'
