#!/usr/bin/env bash
# 외부 Helm 차트를 plain YAML 로 렌더링한다 (rendered manifests).
# 사용: scripts/render.sh <repo-url> <chart> <version> <values.yaml> <출력 폴더> [release 이름]
# 예:   scripts/render.sh https://community-charts.github.io/helm-charts n8n 1.0.0 aiops/n8n/values.yaml aiops/n8n n8n
set -euo pipefail
repo=$1 chart=$2 version=$3 values=$4 out=$5 name=${6:-$2}
ns=$(cut -d/ -f1 <<<"$out")
mkdir -p "$out"
helm template "$name" "$chart" --repo "$repo" --version "$version" -n "$ns" -f "$values" \
  --include-crds=false > "$out/rendered.yaml"
echo "# chart: $repo $chart $version" | cat - "$out/rendered.yaml" > "$out/rendered.tmp" && mv "$out/rendered.tmp" "$out/rendered.yaml"
