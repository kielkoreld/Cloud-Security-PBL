#!/usr/bin/env bash
# 정상 운영과 같은 종류의 읽기·임시 파일 쓰기. 파일 이름만 다르다.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat /etc/hostname >/dev/null
  cat /www/index.html >/dev/null
  echo note >/tmp/pbl-benign-note
  cat /tmp/pbl-benign-note >/dev/null
  rm -f /tmp/pbl-benign-note
'

kubectl -n "${NS}" exec -c curl-client "${POD}" -- sh -c '
  curl -fsS http://127.0.0.1/ >/tmp/pbl-benign-health
  rm -f /tmp/pbl-benign-health
'
