#!/usr/bin/env bash
# 컨테이너 안의 shadow 파일을 읽고 출력은 버린다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec "${POD}" -- sh -c 'cat /etc/shadow >/dev/null'
