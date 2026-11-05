#!/usr/bin/env bash
# 파일에 적은 명령을 셸 문자열로 실행한다. 파일 경로를 직접 실행하지 않는다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/pbl-inline.sh <<EOF
echo pbl-inline-no-network
EOF
  sh -c "$(cat /tmp/pbl-inline.sh)"
  rm -f /tmp/pbl-inline.sh
'
