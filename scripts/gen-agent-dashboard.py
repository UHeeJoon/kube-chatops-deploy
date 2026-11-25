"""kube-chatops LLM 비용 대시보드 → ConfigMap (Grafana 사이드카가 grafana_dashboard=1 라벨을 모든 ns 에서 읽는다)."""
import json, sys
DS = {"type": "prometheus", "uid": "${datasource}"}
panels, y = [], 0
def panel(kind, title, exprs, x, w, h, unit=None, desc=None, **extra):
    p = {"type": kind, "title": title, "datasource": DS, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [{"expr": e, "legendFormat": l, "refId": chr(65 + i), "datasource": DS} for i, (e, l) in enumerate(exprs)],
         "fieldConfig": {"defaults": {}, "overrides": []}, "options": {}}
    if unit: p["fieldConfig"]["defaults"]["unit"] = unit
    if desc: p["description"] = desc
    for k, v in extra.items():
        if k == "defaults": p["fieldConfig"]["defaults"].update(v)
        else: p["options"].update(v) if k == "options" else p.update({k: v})
    panels.append(p)
def row(title):
    global y
    panels.append({"type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}); y += 1
COST = "agent_llm_cost_usd_total"; TOK = "agent_llm_tokens_total"
thr = lambda *steps: {"thresholds": {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]}}

row("예산"); 
panel("stat", "오늘 사용액 (KST)", [("max(agent_budget_spent_today_usd)", "")], 0, 4, 5, "currencyUSD", "Postgres 장부 기준 오늘 누적. 자정(KST)에 0", defaults={"decimals": 2})
panel("stat", "일일 예산", [("max(agent_budget_daily_limit_usd)", "")], 4, 3, 5, "currencyUSD")
panel("gauge", "예산 사용률", [("100 * max(agent_budget_spent_today_usd) / max(agent_budget_daily_limit_usd)", "")], 7, 4, 5, "percent",
      "100% 가 되면 agent 가 새 요청을 429 로 거절", defaults={"min": 0, "max": 100, **thr((None, "green"), (70, "orange"), (90, "red"))})
panel("stat", "최근 24시간 비용", [(f"sum(increase({COST}[24h]))", "")], 11, 3, 5, "currencyUSD", defaults={"decimals": 2})
panel("stat", "조사 1건 평균 비용 (24h)", [(f'sum(increase({COST}{{stage=~"investigate|report"}}[24h])) / clamp_min(sum(increase(agent_requests_total{{api="investigate",status="200"}}[24h])), 1)', "")],
      14, 4, 5, "currencyUSD", "요청당 상한 MAX_REQUEST_USD 와 비교", defaults={"decimals": 3})
panel("stat", "프롬프트 캐시 적중률 (24h)", [(f'sum(increase({TOK}{{kind="cache_read"}}[24h])) / sum(increase({TOK}{{kind=~"input|cache_read|cache_write"}}[24h]))', "")],
      18, 3, 5, "percentunit", "입력 토큰 중 캐시에서 읽은 비율. 높을수록 싸다 (캐시 읽기는 입력 단가의 0.1배)", defaults={**thr((None, "red"), (0.3, "orange"), (0.6, "green"))})
panel("stat", "조사 수 (24h)", [('sum(increase(agent_requests_total{api="investigate",status="200"}[24h]))', "")], 21, 3, 5, defaults={"decimals": 0})
y += 5

row("비용과 토큰")
panel("timeseries", "시간당 비용 (단계별)", [(f"sum by (stage) (increase({COST}[1h]))", "{{stage}}")], 0, 12, 8, "currencyUSD",
      "route: 의도 분류, investigate: 도구 루프, report: 최종 보고서", defaults={"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 80}})
panel("timeseries", "토큰 (종류별, 시간당)", [(f"sum by (kind) (increase({TOK}[1h]))", "{{kind}}")], 12, 12, 8, "short",
      "input: 캐시 안 된 입력, cache_write: 캐시에 쓴 입력(1.25배), cache_read: 캐시에서 읽은 입력(0.1배), output: 출력",
      defaults={"custom": {"drawStyle": "bars", "stacking": {"mode": "normal"}, "fillOpacity": 80}})
y += 8
panel("timeseries", "모델별 비용 (시간당)", [(f"sum by (model) (increase({COST}[1h]))", "{{model}}")], 0, 12, 7, "currencyUSD", "fallback 으로 다른 모델이 응답하면 여기 따로 보인다")
panel("timeseries", "오늘 누적 사용액 vs 예산", [("max(agent_budget_spent_today_usd)", "사용액"), ("max(agent_budget_daily_limit_usd)", "예산")], 12, 12, 7, "currencyUSD")
y += 7

row("요청과 조사")
panel("timeseries", "API 요청 (시간당)", [("sum by (api, status) (increase(agent_requests_total[1h]))", "{{api}} {{status}}")], 0, 8, 7, "short", "401: 토큰 오류, 429: 예산 초과, 500: 내부 오류")
panel("bargauge", "조사 종료 이유 (24h)", [("sum by (reason) (increase(agent_investigation_stops_total[24h]))", "{{reason}}")], 8, 8, 7, "short",
      "done: 정상, llm_calls / tool_calls / time / cost: 상한 도달, refusal: 모델 거절", options={"displayMode": "basic", "orientation": "horizontal"})
panel("timeseries", "처리 시간 p95", [("histogram_quantile(0.95, sum by (le, api) (rate(agent_request_duration_seconds_bucket[$__rate_interval])))", "{{api}}")], 16, 8, 7, "s")
y += 7

row("MCP 도구")
panel("timeseries", "도구 호출 (시간당)", [("sum by (server, tool) (increase(agent_tool_calls_total[1h]))", "{{server}}/{{tool}}")], 0, 10, 8, "short", "도구 호출이 많을수록 입력 토큰이 늘어난다")
panel("timeseries", "도구 실행 p95 (MCP 서버)", [("histogram_quantile(0.95, sum by (le, job, tool) (rate(mcp_tool_duration_seconds_bucket[$__rate_interval])))", "{{job}}/{{tool}}")], 10, 8, 8, "s")
panel("stat", "도구 오류 (24h)", [('sum(increase(agent_tool_calls_total{status="error"}[24h]))', "")], 18, 3, 4, "short", defaults=thr((None, "green"), (1, "orange")))
panel("stat", "MCP 인증 실패 (24h)", [("sum(increase(mcp_auth_failures_total[24h]))", "")], 21, 3, 4, "short", "0 이 아니면 토큰 불일치 또는 무단 접근 시도", defaults=thr((None, "green"), (1, "red")))
panel("stat", "입력 오류 (24h)", [('sum(increase(mcp_tool_calls_total{status="invalid"}[24h]))', "")], 18, 6, 4, "short", "모델이 허용 범위 밖 값(다른 ns, 너무 긴 기간 등)을 넣은 횟수")
panels[-1]["gridPos"]["y"] += 4

dash = {"uid": "kube-chatops-llm-cost", "title": "kube-chatops / LLM 비용과 에이전트", "tags": ["kube-chatops", "llm", "cost"],
        "timezone": "Asia/Seoul", "refresh": "1m", "time": {"from": "now-24h", "to": "now"}, "schemaVersion": 39, "editable": True,
        "templating": {"list": [{"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus", "current": {}, "hide": 0}]},
        "panels": panels, "annotations": {"list": []}}
body = json.dumps(dash, ensure_ascii=False, indent=1)
out = """# Grafana 대시보드: LLM 비용, 예산, 조사 결과, MCP 도구.
# Grafana 사이드카가 모든 ns 에서 grafana_dashboard=1 라벨 ConfigMap 을 읽는다 (homelab 변경 불필요).
# 수정은 Grafana 에서 하지 말고 이 파일에서 (사이드카가 덮어쓴다). 생성: python3 scripts/gen-agent-dashboard.py aiops/agent/dashboard.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-cost-dashboard
  namespace: aiops
  labels:
    grafana_dashboard: "1"
data:
  kube-chatops-llm-cost.json: |
""" + "\n".join("    " + l for l in body.splitlines()) + "\n"
open(sys.argv[1], "w").write(out)
print(len(panels), "panels")
