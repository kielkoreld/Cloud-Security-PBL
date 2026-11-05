#!/usr/bin/env bash
# 운영 중 환경변수 확인. 출력은 버린다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c 'env >/dev/null'
