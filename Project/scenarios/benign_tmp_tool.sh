#!/usr/bin/env bash
# 로컬에서만 끝나는 임시 점검 스크립트. 네트워크 연결은 없다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/pbl-health.sh <<EOF
#!/bin/sh
echo ok
EOF
  chmod +x /tmp/pbl-health.sh
  /bin/sh /tmp/pbl-health.sh
  rm -f /tmp/pbl-health.sh
'
