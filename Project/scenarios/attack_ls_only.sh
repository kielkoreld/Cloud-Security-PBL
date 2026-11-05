#!/usr/bin/env bash
# 자격증명 경로가 있는지만 보고, 내용은 읽지 않는다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec "${POD}" -- sh -c '
  for path in /root/.aws/credentials /root/.ssh/id_rsa /root/.kube/config /etc/shadow; do
    if [ -e "$path" ]; then
      ls -l "$path" >/dev/null
    fi
  done
'
