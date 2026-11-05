# Category 1 탐지 실습

파드 안의 파일·프로세스 행위를 Falco 로그로 모아 정상과 공격을 나눕니다.
아래는 환경 준비와 실행 방법만 적습니다.

## 환경

- Ubuntu 22.04/24.04 또는 Debian 12
- x86_64 또는 ARM64
- `sudo` 사용 가능
- Python 3

Docker, kind, kubectl, Helm, Falco는 `install.sh`가 설치합니다.

## 1. 클러스터 설치

저장소 루트에서 실행합니다.

```bash
chmod +x install.sh category1/*.sh Project/scenarios/*.sh
./install.sh
```

Docker를 처음 설치한 경우 로그아웃 후 다시 로그인한 뒤 `./install.sh`를 한 번 더 실행합니다.

설치 확인:

```bash
kubectl get nodes
kubectl get pods -n pbl-security
kubectl get pods -n falco
```

노드 3개가 `Ready`이고 `pbl-security`, `falco` 네임스페이스의 Pod가 `Running`이면 준비된 상태입니다.

## 2. Falco 규칙 적용

저장소 루트에서 수정한 규칙을 적용합니다.
`category1/falco-values-original.yaml`은 건드리지 않습니다.

```bash
helm upgrade --install falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  --set tty=true \
  --set falco.json_output=true \
  --set falco.rule_matching=all \
  --values category1/falco-values.yaml \
  --wait --timeout 12m
```

## 3. 탐지 평가 실행

저장소 루트에서 실행합니다.

```bash
python3 Project/run_eval.py
```

15개 시나리오(제공 스크립트 4개 + 추가 시나리오)를 순서를 섞어 실행하고,
Falco 로그로 판단한 뒤 오탐·미탐을 집계합니다.

결과는 다음에 저장됩니다.

- `Project/results/결과.md`
- `Project/results/summary.json`

## 참고

`kubectl logs --follow`가 바로 끊기면 kind 노드에서 inotify 한도를 올린 뒤 다시 실행합니다.

```bash
for n in $(kind get nodes --name pbl-security); do
  docker exec "$n" sysctl -w fs.inotify.max_user_instances=8192
done
```
