# 실무클라우드보안 PBL Project

**한국어** | [English](README_EN.md)


| 실습         | 관찰 도구     | 정상 행위                    | 비정상 행위                |
| ---------- | --------- | ------------------------ | --------------------- |
| Category 1 | Falco     | 설정·임시 파일·health check    | shadow·token 접근, 셸 실행 |
| Category 2 | Hubble    | 서비스 경로·DNS 통신            | 직접 접근·내부 탐색·비정상 포트    |
| Category 3 | Audit Log | Pod·ConfigMap·Service 조회 | Secret·Pod exec·반복 조회 |


## 과제 관련 내용은 `Project/README.md` 참조

## 1. 준비

- Ubuntu 22.04/24.04 또는 Debian 12
- x86_64 또는 ARM64
- `sudo` 사용 권한

Docker Engine, kind, kubectl, Helm, Cilium, Hubble, Falco는 미리 설치하지 않아도 됩니다.

## 2. 설치

저장소를 clone한 뒤 프로젝트 루트에서 실행합니다.

```bash
cd pbl-project
chmod +x install.sh category1/*.sh category2/*.sh category3/*.sh
./install.sh
```

Docker를 처음 설치한 경우 스크립트가 로그아웃을 요청할 수 있습니다. 그때는 VM에서 로그아웃 후 다시 로그인하고 `./install.sh`를 한 번 더 실행합니다.

설치 결과를 확인합니다.

```bash
kubectl get nodes
kubectl get pods -A
```

노드 3개가 `Ready`이고 워크로드, Cilium, Hubble, Falco Pod가 `Running`이면 준비 완료입니다. 노드 3개는 별도 VM이 아니라 현재 VM의 Docker 컨테이너입니다.

## 3. 실습

모든 명령은 프로젝트 루트에서 실행합니다.

```bash
# Category 1: Falco
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh

# Category 2: Hubble
./category2/normal.sh
./category2/abnormal_1.sh
./category2/abnormal_2.sh
./category2/abnormal_3.sh

# Category 3: Kubernetes Audit Log
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

로그를 실시간으로 보는 방법은 각 문서를 따릅니다.

- [Category 1 - Falco](category1/README.md)
- [Category 2 - Hubble](category2/README.md)
- [Category 3 - Audit Log](category3/README.md)

각 Category의 `logs/normal.log`, `logs/abnormal_1.log`부터 `logs/abnormal_3.log`까지는 예상 로그 예시입니다. 실제 로그의 Pod 이름, IP, 시간은 실행할 때마다 달라집니다.