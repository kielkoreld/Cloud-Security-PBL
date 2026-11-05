#!/usr/bin/env bash
# 다른 이름의 로컬 스크립트를 만들고 실행한 뒤 지운다. 네트워크 연결은 없다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/pbl-marker.sh <<EOF
#!/bin/sh
echo pbl-marker-no-network
EOF
  chmod +x /tmp/pbl-marker.sh
  /bin/sh /tmp/pbl-marker.sh
  rm -f /tmp/pbl-marker.sh
'
