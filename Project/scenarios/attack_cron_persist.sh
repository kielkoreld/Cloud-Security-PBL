#!/usr/bin/env bash
# 로컬 echo만 반복하는 cron 항목을 기록한 뒤 지운다. crond는 띄우지 않고 외부로 연결하지 않는다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  mkdir -p /etc/cron.d
  printf "%s\n" "* * * * * echo pbl-cron-no-network" >/etc/cron.d/pbl-marker
  rm -f /etc/cron.d/pbl-marker
'
