#!/usr/bin/env python3
"""장애 시나리오 평가: demo-app 에 장애를 넣고, 알림 → 에이전트 조사 → Slack 보고가 원인을 맞히는지 잰다.

  S1 메모리 누수  /chaos/leak?kb=200     → DemoMemoryNearLimit (또는 OOM 뒤 DemoPodRestarting)
  S2 지연         /chaos/latency?ms=800  → DemoHighLatency
  S3 오류         /chaos/error?rate=0.3  → DemoHighErrorRate

시나리오마다: 주입 → 알림 firing → Slack 보고(감사 기록) → 사건 기록에서 보고서를 꺼내 채점 → 해제 → 알림이 꺼질 때까지 대기.
채점은 보고서 글에 기대 낱말이 있는지로 한다 (원인 적중). 조치 제안, 런북 인용, 경과(timeline)가 있는지도 함께 적는다.

주의: 실제 알림이 Slack 에 울리고 조사 비용(건당 약 $0.1)이 든다.
사용: python3 scripts/scenario-eval.py [--only s2,s3] [--out result.json]
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime

PROM_PORT = 19394

SCENARIOS = {
    # 이름: (주입 경로, 기다릴 알림들, 알림 대기 초, 원인으로 인정할 낱말(하나라도), 기대 조치)
    "s2": ("지연", "/chaos/latency?ms=800", ["DemoHighLatency"], 420, ["지연 주입", "latency", "지연 장애 주입", "chaos"], "none"),
    "s3": ("오류", "/chaos/error?rate=0.3", ["DemoHighErrorRate"], 360, ["오류 주입", "error", "에러 주입", "장애 주입", "chaos"], "none"),
    "s1": ("메모리 누수", "/chaos/leak?kb=200", ["DemoMemoryNearLimit", "DemoPodRestarting"], 1500, ["누수", "leak", "OOM"], "restart 또는 none"),
}


def sh(cmd: str, timeout: int = 180) -> str:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return (p.stdout + p.stderr).strip()


def prom(query: str) -> list[dict]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PROM_PORT}/api/v1/query?query={urllib.parse.quote(query)}", timeout=10) as r:
            return json.load(r)["data"]["result"]
    except (OSError, ValueError, KeyError):
        return []


def firing(alerts: list[str]) -> str | None:
    rows = prom('ALERTS{alertstate="firing",alertname=~"' + "|".join(alerts) + '"}')
    return rows[0]["metric"]["alertname"] if rows else None


def wait(cond, timeout: int, every: float = 5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = cond()
        if v:
            return v, time.time() - t0
        time.sleep(every)
    return None, None


def chaos(path: str) -> None:
    """장애 주입 상태는 파드마다 따로라 demo-app 파드 전부에 넣는다 (파드 안에서 localhost 로)."""
    pods = sh("kubectl -n demo get pods -l app.kubernetes.io/name=demo-app --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'").split()
    code = f"import urllib.request as u; print(u.urlopen(u.Request('http://localhost:8080{path}', method='POST'), timeout=5).status)"
    for pod in pods:
        out = sh(f"kubectl -n demo exec {pod} -- python -c {shlex.quote(code)}")
        print(f"    {pod} {path} → {out.splitlines()[-1] if out else '?'}")


def audits(since: float) -> list[dict]:
    out = sh(f"kubectl -n aiops logs deploy/chat-gateway --since={int((time.time() - since) / 60) + 2}m")
    rows = []
    for line in out.splitlines():
        if '"audit"' not in line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("flow") == "wf-02-investigate" and r.get("source") == "alert":
            at = datetime.fromisoformat(r["at"].replace("Z", "+00:00")).timestamp()
            if at >= since:
                rows.append({**r, "_at": at})
    return rows


def incident(incident_id: int) -> dict:
    code = ("import json,os,urllib.request as u; "
            f"r=u.Request('http://localhost:8080/incidents/{incident_id}', headers={{'Authorization':'Bearer '+os.environ['API_TOKEN']}}); "
            "print(json.dumps(json.load(u.urlopen(r, timeout=20))['incident']))")
    out = sh(f"kubectl -n aiops exec deploy/agent -- python -c {shlex.quote(code)}")
    return json.loads(out.splitlines()[-1])


def run(key: str) -> dict:
    name, path, alerts, timeout, words, want_action = SCENARIOS[key]
    print(f"\n== {key.upper()} {name}: {path}")
    t0 = time.time()
    chaos(path)
    row: dict = {"scenario": key, "name": name, "inject": path, "expected_action": want_action}
    try:
        alert, secs = wait(lambda: firing(alerts), timeout)
        row["alert"], row["alert_seconds"] = alert, round(secs) if secs else None
        print(f"    알림: {alert} ({row['alert_seconds']}초)")
        if not alert:
            return row
        audit, secs = wait(lambda: next((a for a in audits(t0) if a.get("alert") in alerts), None), 300)
        if not audit:
            print("    Slack 보고가 5분 안에 오지 않음")
            return row
        row |= {"report_seconds": round(audit["_at"] - t0), "cost_usd": audit.get("cost_usd"), "tool_calls": audit.get("tool_calls"),
                "result": audit.get("result"), "incident_id": audit.get("incident_id"), "injection_suspected": audit.get("injection_suspected")}
        if audit.get("incident_id"):
            rep = (incident(audit["incident_id"])["reports"] or [{}])[-1].get("report") or {}
            text = json.dumps(rep, ensure_ascii=False)
            causes = rep.get("causes") or []
            row |= {
                "status": rep.get("status"), "headline": rep.get("headline"),
                "cause": causes[0]["title"] if causes else None, "confidence": causes[0]["confidence"] if causes else None,
                "hit": any(w.lower() in text.lower() for w in words),
                "actions": [f"{a['type']} {a['target']}" for a in rep.get("actions") or []],
                "references": rep.get("references") or [], "timeline": len(rep.get("timeline") or []), "data_gaps": rep.get("data_gaps") or [],
            }
        print(f"    보고: {row.get('report_seconds')}초 · ${row.get('cost_usd')} · 도구 {row.get('tool_calls')}회 · 적중 {row.get('hit')}")
        print(f"    {row.get('headline')}\n    원인: {row.get('cause')} ({row.get('confidence')}) · 조치: {row.get('actions')} · 참고: {row.get('references')}")
    finally:
        chaos("/chaos/reset")
        _, secs = wait(lambda: not firing(alerts), 900, 10)
        print(f"    해제 후 알림 꺼짐: {round(secs) if secs is not None else '15분 안에 안 꺼짐'}초")
    return row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="s2,s3,s1")
    ap.add_argument("--out")
    a = ap.parse_args()
    pf = subprocess.Popen(["kubectl", "-n", "monitoring", "port-forward", "svc/kube-prometheus-kube-prome-prometheus", f"{PROM_PORT}:9090"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows = []
    try:
        wait(lambda: prom("vector(1)"), 20, 1)
        for key in [k.strip() for k in a.only.split(",") if k.strip()]:
            rows.append(run(key))
            if a.out:
                json.dump(rows, open(a.out, "w"), ensure_ascii=False, indent=1)
    finally:
        pf.terminate()
    print("\n| 시나리오 | 알림 | 알림까지 | 보고까지 | 비용 | 도구 | 원인 적중 | 조치 제안 | 참고 |\n|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['scenario'].upper()} {r['name']} | {r.get('alert')} | {r.get('alert_seconds')}초 | {r.get('report_seconds')}초 | ${r.get('cost_usd')} | {r.get('tool_calls')} "
              f"| {'O' if r.get('hit') else 'X'} ({r.get('confidence')}) | {', '.join(r.get('actions') or []) or '-'} | {', '.join(r.get('references') or []) or '-'} |")


if __name__ == "__main__":
    main()
