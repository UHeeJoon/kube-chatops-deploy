#!/usr/bin/env python3
"""n8n 워크플로 JSON(kube-chatops 저장소 n8n/workflows) → ConfigMap aiops/n8n/workflows.yaml.

사용: python3 scripts/gen-n8n-workflows.py ../kube-chatops/n8n/workflows

Argo CD 는 앱 폴더의 .json 도 매니페스트로 읽으므로 JSON 을 그대로 두지 않고 ConfigMap 으로 감싼다.
내용 해시를 Deployment 의 파드 어노테이션에 적어서, 워크플로가 바뀌면 n8n 이 재시작하며 다시 import 한다.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
root = Path(__file__).resolve().parent.parent
files = sorted(src.glob("*.json"))
if not files:
    sys.exit(f"{src} 에 워크플로 JSON 이 없습니다")

digest = hashlib.sha256()
lines = [
    "# 생성 파일: scripts/gen-n8n-workflows.py 로 다시 만든다. 직접 고치지 말 것.",
    "apiVersion: v1",
    "kind: ConfigMap",
    "metadata:",
    "  name: n8n-workflows",
    "  namespace: aiops",
    "  labels: { app.kubernetes.io/name: n8n }",
    "data:",
]
for f in files:
    text = json.dumps(json.loads(f.read_text()), ensure_ascii=False, indent=1)
    digest.update(f.name.encode() + text.encode())
    lines.append(f"  {f.name}: |")
    lines.extend("    " + ln for ln in text.splitlines())
(root / "aiops/n8n/workflows.yaml").write_text("\n".join(lines) + "\n")

sha = digest.hexdigest()[:16]
dep = root / "aiops/n8n/deployment.yaml"
text = dep.read_text()  # yq 로 고치면 파일 전체 서식이 바뀌어서 해당 줄만 바꾼다
new, n = re.subn(r"(kube-chatops/workflows-sha: )\S+", rf"\g<1>{sha}", text)
if n != 1:
    sys.exit("deployment.yaml 에 kube-chatops/workflows-sha 어노테이션이 없습니다")
dep.write_text(new)
print(f"{len(files)} workflows, sha {sha}")
