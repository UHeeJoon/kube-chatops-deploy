"""상황판 대시보드 → ConfigMap (Grafana 사이드카가 grafana_dashboard=1 라벨을 모든 ns 에서 읽는다).

생성: python3 scripts/gen-incident-dashboard.py demo/alerts/dashboard.yaml
한 화면에서 "지금 무슨 일이 일어나고 있나" 를 본다: 울리는 알림, 서비스 상태(장애), 공격과 조치(보안), 격리된 파드.
자세한 분석은 다른 대시보드로: 이상 탐지 모델(kube-chatops-anomaly-model), 에이전트 비용.
"""
import json
import sys

PROM = {"type": "prometheus", "uid": "${datasource}"}
LOKI = {"type": "loki", "uid": "${loki}"}
panels, y = [], 0
PATH = 'path!~"/chaos/.*|/metrics|/healthz.*"'
ALERTS = 'ALERTS{alertstate="firing", kube_chatops="true"}'
WAF = 'caddy_http_request_duration_seconds_count{namespace="demo", handler="waf", code="403"}'
TETRA = 'tetragon_policy_events_total{namespace="demo", policy="webshell-block"}'


def since(metric, rng):
    """카운터의 최근 rng 동안 증가량. 처음 생긴 시계열(파드가 처음 막은 순간 생김)은 increase() 가 0 이라 현재 값을 더한다."""
    return f"sum((increase({metric}[{rng}]) unless ({metric} unless {metric} offset {rng})) or ({metric} unless {metric} offset {rng})) or vector(0)"


def panel(kind, title, targets, x, w, h, unit=None, desc=None, ds=PROM, **extra):
    p = {"type": kind, "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [{"expr": e, "legendFormat": l, "refId": chr(65 + i), "datasource": ds, **t} for i, (e, l, *rest) in enumerate(targets) for t in [rest[0] if rest else {}]],
         "fieldConfig": {"defaults": {}, "overrides": []}, "options": {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    if desc:
        p["description"] = desc
    for k, v in extra.items():
        if k == "defaults":
            p["fieldConfig"]["defaults"].update(v)
        elif k == "overrides":
            p["fieldConfig"]["overrides"] = v
        elif k == "options":
            p["options"].update(v)
        else:
            p[k] = v
    panels.append(p)


def row(title):
    global y
    panels.append({"type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []})
    y += 1


thr = lambda *steps: {"thresholds": {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]}}
bg = {"colorMode": "background", "graphMode": "none", "textMode": "value"}
INSTANT = {"instant": True, "range": False}

row("지금")
panel("stat", "울리는 알림", [(f"count({ALERTS}) or vector(0)", "")], 0, 4, 5, None,
      "kube-chatops 가 다루는 알림(Slack 으로 조사·보고가 가는 것) 중 지금 firing 인 수",
      defaults=thr((None, "green"), (1, "red")), options=bg)
panel("stat", "이상 탐지 모델", [('max(anomaly_model_is_anomaly{rule="hybrid"}) or vector(0)', "")], 4, 4, 5, None,
      "학습된 모델의 마지막 1분 판정 (요청 수, 오류율, 지연, 메모리)",
      defaults={"mappings": [{"type": "value", "options": {"0": {"text": "정상", "color": "green"}, "1": {"text": "이상", "color": "red"}}}],
                **thr((None, "green"), (1, "red"))}, options=bg)
panel("stat", "격리된 파드", [('count(kube_pod_owner{namespace="demo", owner_kind="<none>"}) or vector(0)', "")], 8, 4, 5, None,
      "선 조치로 격리된 파드 (라벨을 떼어 ReplicaSet 에서 분리됨, 모든 통신 차단). 조사 끝나면 Slack 의 [격리 파드 삭제]",
      defaults=thr((None, "green"), (1, "orange")), options=bg)
panel("stat", "웹셸 차단 (24시간)", [(since(TETRA, "24h"), "")], 12, 4, 5, None,
      "Tetragon 이 커널에서 죽인 실행 시도 (웹 서버가 셸·다운로더를 실행하려 함)",
      defaults={"decimals": 0, **thr((None, "green"), (1, "red"))}, options=bg)
panel("stat", "WAF 차단 (24시간)", [(since(WAF, "24h"), "")], 16, 4, 5, None,
      "웹 방화벽(Coraza, OWASP CRS)이 403 으로 막은 요청 (SQLi, 경로 조작, 명령 주입, 스캐너 등)",
      defaults={"decimals": 0, **thr((None, "green"), (1, "orange"), (100, "red"))}, options=bg)
panel("stat", "demo 오류율 / p95", [
    (f'sum(rate(http_requests_total{{namespace="demo", {PATH}, status=~"5.."}}[2m])) / sum(rate(http_requests_total{{namespace="demo", {PATH}}}[2m])) or vector(0)', "오류율"),
    (f'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{namespace="demo", {PATH}}}[2m])))', "p95"),
], 20, 4, 5, None, "최근 2분",
      overrides=[{"matcher": {"id": "byName", "options": "오류율"}, "properties": [{"id": "unit", "value": "percentunit"}, {"id": "thresholds", "value": thr((None, "green"), (0.01, "orange"), (0.05, "red"))["thresholds"]}]},
                 {"matcher": {"id": "byName", "options": "p95"}, "properties": [{"id": "unit", "value": "s"}, {"id": "thresholds", "value": thr((None, "green"), (0.3, "orange"), (1, "red"))["thresholds"]}]}],
      options={"colorMode": "value", "graphMode": "area", "textMode": "value_and_name"})
y += 5

row("알림")
panel("table", "지금 울리는 알림", [(ALERTS, "", {"format": "table", **INSTANT})], 0, 10, 8, None,
      "누가 처리 중인지는 Slack 알림 채널의 스레드에서 본다",
      transformations=[{"id": "organize", "options": {
          "excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True, "kube_chatops": True, "prometheus": True, "container": True, "endpoint": True, "instance": True, "job": True, "service": True},
          "indexByName": {"alertname": 0, "severity": 1, "category": 2, "namespace": 3, "pod": 4},
          "renameByName": {"alertname": "알림", "severity": "심각도", "category": "분류", "namespace": "ns", "pod": "파드", "auto_action": "선 조치"}}}],
      overrides=[{"matcher": {"id": "byName", "options": "심각도"}, "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                  {"id": "mappings", "value": [{"type": "value", "options": {"critical": {"color": "red"}, "warning": {"color": "orange"}}}]}]}])
panel("state-timeline", "알림 흐름 (언제 울렸나)", [(f"max by (alertname) ({ALERTS})", "{{alertname}}")], 10, 14, 8, None,
      "빨간 막대 = firing 이던 시간",
      defaults={"color": {"mode": "fixed", "fixedColor": "red"}, "custom": {"fillOpacity": 80, "lineWidth": 0},
                "mappings": [{"type": "value", "options": {"1": {"text": "firing", "color": "red"}}}]},
      options={"showValue": "never", "mergeValues": True, "rowHeight": 0.8, "legend": {"showLegend": False}})
y += 8

row("서비스 상태 (장애)")
panel("timeseries", "요청 수 · 5xx", [
    (f'sum(rate(http_requests_total{{namespace="demo", {PATH}}}[2m]))', "요청/s"),
    (f'sum(rate(http_requests_total{{namespace="demo", {PATH}, status=~"5.."}}[2m]))', "5xx/s"),
], 0, 8, 7, "reqps", overrides=[{"matcher": {"id": "byName", "options": "5xx/s"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]}])
panel("timeseries", "p95 지연", [(f'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{namespace="demo", {PATH}}}[2m])))', "p95")], 8, 5, 7, "s")
panel("timeseries", "메모리 (한도 대비, 파드별)", [
    ('max by (pod) (container_memory_working_set_bytes{namespace="demo", container="app"}) / max by (pod) (kube_pod_container_resource_limits{namespace="demo", container="app", resource="memory"})', "{{pod}}")],
      13, 6, 7, "percentunit", defaults={"max": 1})
panel("timeseries", "재시작 (구간별)", [('sum by (pod) (increase(kube_pod_container_status_restarts_total{namespace="demo"}[$__interval]))', "{{pod}}")],
      19, 5, 7, "short", "OOMKilled 등으로 다시 뜬 횟수", interval="5m",
      defaults={"custom": {"drawStyle": "bars", "fillOpacity": 80}})
y += 7

row("보안 (공격과 조치)")
panel("timeseries", "WAF 차단 (구간별)", [(f"sum(increase({WAF}[$__interval]))", "차단")], 0, 8, 7, "short",
      "5분에 5건을 넘으면 DemoWafAttackBlocked 알림", interval="5m",
      defaults={"custom": {"drawStyle": "bars", "fillOpacity": 80}, "color": {"mode": "fixed", "fixedColor": "orange"}})
panel("timeseries", "웹셸 차단 (파드별, 구간별)", [(f"sum by (pod) (increase({TETRA}[$__interval]))", "{{pod}}")], 8, 8, 7, "short",
      "한 번이면 DemoWebshellBlocked(차단 보고), 5분 안에 3번이면 DemoWebshellRepeated(격리 후 보고)", interval="5m",
      defaults={"custom": {"drawStyle": "bars", "fillOpacity": 80}})
panel("table", "많이 막힌 출발 IP", [
    ('topk(10, sum by (client_ip) (count_over_time({namespace="demo", container="waf"} |= "\\"transaction\\"" | json client_ip="transaction.client_ip" [$__range])))', "", {"queryType": "instant"})],
      16, 8, 7, None, "WAF 감사 로그 기준, 보는 기간 전체. 실제 IP 는 Cloudflare 의 CF-Connecting-IP (클러스터 안 요청은 사설 IP)", ds=LOKI,
      transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": {"client_ip": "출발 IP", "Value #A": "차단 수"}}},
                       {"id": "sortBy", "options": {"sort": [{"field": "차단 수", "desc": True}]}}])
y += 7
panel("logs", "최근 웹셸 차단 (Tetragon)", [
    ('{namespace="kube-system", container="export-stdout"} |= "webshell-block" |= "\\"namespace\\":\\"demo\\"" | json victim="process_kprobe.process.pod.name", parent="process_kprobe.parent.binary", target="process_kprobe.args[0].linux_binprm_arg.path", action="process_kprobe.action" | line_format "{{.victim}}  {{.parent}} → {{.target}}  ({{ trimPrefix \\"KPROBE_ACTION_\\" .action }})"', "")],
      0, 12, 7, None, "웹 서버(parent)가 실행하려던 것(target). SIGKILL = 실행 전에 죽임", ds=LOKI,
      options={"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending", "enableLogDetails": True})
panel("logs", "최근 WAF 차단", [
    ('{namespace="demo", container="waf"} |= "\\"transaction\\"" | json ip="transaction.client_ip", method="transaction.request.method", uri="transaction.request.uri" | line_format "{{.ip}}  {{.method}} {{.uri}}"', "")],
      12, 12, 7, None, "걸린 규칙은 줄을 펼치거나 Slack 에서 봇에게 물으면 (mcp-loki waf_blocks) 나온다", ds=LOKI,
      options={"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending", "enableLogDetails": True})
y += 7
panel("text", "더 보기", [], 0, 24, 3, options={"mode": "markdown", "content":
      "- **이상 탐지 모델** 대시보드: 모델 판정 vs 실제 장애, 특성별 z-score  ·  **Hubble** (흐름, 정책 차단): http://hubble.ascode.click\n"
      "- 조치: 알림이 오면 n8n 이 에이전트 조사 결과를 Slack 알림 채널에 올린다. 웹셸 반복 공격은 자동 격리 후 보고, 삭제·재시작 같은 조치는 Slack 버튼(승인)으로"})

dash = {"uid": "kube-chatops-incident", "title": "kube-chatops / 상황판", "tags": ["kube-chatops", "security", "incident"],
        "timezone": "Asia/Seoul", "refresh": "30s", "time": {"from": "now-6h", "to": "now"}, "schemaVersion": 39, "editable": True,
        "templating": {"list": [
            {"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus", "current": {}, "hide": 0},
            {"name": "loki", "label": "Loki", "type": "datasource", "query": "loki", "current": {}, "hide": 0}]},
        "links": [{"title": "이상 탐지 모델", "type": "link", "url": "/d/kube-chatops-anomaly-model", "icon": "dashboard"}],
        "panels": panels, "annotations": {"list": []}}
body = json.dumps(dash, ensure_ascii=False, indent=1)
out = """# Grafana 대시보드: 상황판 (울리는 알림, 서비스 상태, 공격과 조치, 격리된 파드).
# Grafana 사이드카가 모든 ns 에서 grafana_dashboard=1 라벨 ConfigMap 을 읽는다.
# 수정은 Grafana 에서 하지 말고 생성기에서: python3 scripts/gen-incident-dashboard.py demo/alerts/dashboard.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: incident-dashboard
  namespace: demo
  labels:
    grafana_dashboard: "1"
data:
  kube-chatops-incident.json: |
""" + "\n".join("    " + l for l in body.splitlines()) + "\n"
open(sys.argv[1], "w").write(out)
print(len(panels), "panels")
