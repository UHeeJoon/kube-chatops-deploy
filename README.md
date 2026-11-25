# kube-chatops-deploy

kube-chatops(AIOps, MLOps) 애플리케이션의 배포 매니페스트입니다.
클러스터 플랫폼은 [`UHeeJoon/homelab`](https://github.com/UHeeJoon/homelab), 소스 코드는 [`UHeeJoon/kube-chatops`](https://github.com/UHeeJoon/kube-chatops)에 있습니다.

## 구조

```
<네임스페이스>/<앱>/    폴더 하나 = Argo CD App 하나 (kube-chatops-<네임스페이스>-<앱>)
```

| 네임스페이스 | 내용 |
|---|---|
| `aiops` | n8n, chat-gateway, agent, aiops PostgreSQL |
| `mcp` | MCP 서버 (prometheus, loki, k8s, anomaly, runbook) |
| `demo` | 장애 주입용 demo-app, load-gen, 알림 규칙 |
| `mlops` | MLflow, 학습 파이프라인, InferenceService |

Argo CD Application은 이 저장소에 두지 않습니다. homelab의 ApplicationSet `kube-chatops-apps`가 폴더마다 App을 만들고, AppProject `kube-chatops`가 소스와 배포 대상을 제한합니다.

## 규칙

- 앱 폴더에는 plain YAML 또는 kustomize만 둡니다. 외부 Helm 차트는 `scripts/render.sh`로 렌더링한 결과를 커밋합니다.
- 클러스터 범위 리소스(Namespace, CRD, ClusterRole 등), Argo CD 리소스, ResourceQuota, LimitRange는 둘 수 없습니다. 필요하면 homelab에 추가합니다.
- 자체 이미지(`ghcr.io/uheejoon/*`)는 digest로 고정해야 하고, `kube-chatops` main 워크플로가 서명한 이미지여야 합니다.
- 비밀 값은 `ExternalSecret`만 둡니다. 네임스페이스마다 있는 SecretStore `vault`를 쓰고, Vault 경로는 `secret/kube-chatops/*`입니다.

## 배포 흐름

```
kube-chatops CI가 이미지 빌드, 서명 후 main에 digest bump → 이 저장소 CI 검사 → release로 승격 → Argo CD 반영
```

Argo CD는 `release` 브랜치만 읽습니다.
