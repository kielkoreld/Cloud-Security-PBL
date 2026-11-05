#!/usr/bin/env bash
# 토큰 파일의 첫 바이트만 읽고 버린다. API 호출은 하지 않는다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c \
  'head -c 1 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null'
