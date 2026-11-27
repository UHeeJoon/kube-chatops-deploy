"""이상 탐지 모델 대시보드 → ConfigMap (Grafana 사이드카가 grafana_dashboard=1 라벨을 모든 ns 에서 읽는다).

생성: python3 scripts/gen-anomaly-dashboard.py mlops/anomaly-serve/dashboard.yaml
모델 판정 메트릭(anomaly_model_*)은 mcp-anomaly 의 모니터가 1분마다 마지막 1분을 모델에 넣어 내보낸다.
입력 지표 PromQL 은 kube-chatops services/mcp-anomaly/app/features.py 와 같다.
"""
import json
import sys

DS = {"type": "prometheus", "uid": "${datasource}"}
panels, y = [], 0
PATH = 'path!~"/chaos/.*|/metrics|/healthz.*"'
FEATURES = {
    "rps": f'sum(rate(http_requests_total{{namespace="demo", {PATH}}}[2m]))',
    "error_ratio": f'sum(rate(http_requests_total{{namespace="demo", {PATH}, status=~"5.."}}[2m])) / sum(rate(http_requests_total{{namespace="demo", {PATH}}}[2m]))',
    "p95_seconds": f'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{namespace="demo", {PATH}}}[2m])))',
    "mem_ratio": 'max(max by (pod) (container_memory_working_set_bytes{namespace="demo", container="app"}) / max by (pod) (kube_pod_container_resource_limits{namespace="demo", container="app", resource="memory"}))',
    "mem_growth": 'max(max by (pod) (deriv(container_memory_working_set_bytes{namespace="demo", container="app"}[5m])) * 60 / max by (pod) (kube_pod_container_resource_limits{namespace="demo", container="app", resource="memory"}) and on (pod) (time() - max by (pod) (kube_pod_container_state_started{namespace="demo", container="app"}) > 300))',
}
TRUTH = 'max by (kind) (demo_chaos_active{namespace="demo"})'  # demo-app: latency|error|leak, load-gen: traffic_drop


def panel(kind, title, exprs, x, w, h, unit=None, desc=None, **extra):
    p = {"type": kind, "title": title, "datasource": DS, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [{"expr": e, "legendFormat": l, "refId": chr(65 + i), "datasource": DS} for i, (e, l) in enumerate(exprs)],
         "fieldConfig": {"defaults": {}, "overrides": []}, "options": {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    if any("$__interval" in e for e, _ in exprs):
        # 겹치지 않는 구간 합계 막대 (이동 창을 촘촘히 찍으면 한 번의 호출이 한 시간 내내 반복돼 보인다)
        p.update({"interval": "5m", "maxDataPoints": 48})
        p["fieldConfig"]["defaults"]["custom"] = {"drawStyle": "bars", "fillOpacity": 80, "stacking": {"mode": "normal"}}
        desc = (desc + ". " if desc else "") + "막대 하나 = 한 구간의 합 (15분 보기 5분, 24시간 보기 30분)"
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
step_line = {"custom": {"drawStyle": "line", "lineInterpolation": "stepAfter", "fillOpacity": 25, "lineWidth": 1}}
color = lambda name, c: {"matcher": {"id": "byName", "options": name}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
color_re = lambda rx, c: {"matcher": {"id": "byRegexp", "options": rx}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}

row("지금")
panel("stat", "지금 판정 (마지막 1분)", [('max(anomaly_model_is_anomaly{rule="hybrid"})', "")], 0, 4, 5, None,
      "혼합 규칙: IsolationForest 점수가 경계를 넘거나, 한 특성이라도 |z| ≥ 4 이거나, 요청 수가 급감 경계(rps_low) 아래면 이상",
      defaults={"mappings": [{"type": "value", "options": {"0": {"text": "정상", "color": "green"}, "1": {"text": "이상", "color": "red"}}}],
                **thr((None, "green"), (1, "red"))}, options={"colorMode": "background"})
panel("stat", "가장 크게 벗어난 특성", [("topk(1, abs(max by (feature) (anomaly_model_feature_z)))", "{{feature}}")], 4, 5, 5, None,
      "평소(학습 기간) 대비 몇 표준편차인지. 4 이상이면 이상. 모델 v1 은 특성별 z 를 내보내지 않아 비어 있다",
      defaults={"decimals": 1, **thr((None, "green"), (3, "orange"), (4, "red"))}, options={"textMode": "value_and_name", "colorMode": "value"})
panel("stat", "서빙 중인 모델", [("max by (model_version) (anomaly_model_info)", "{{model_version}}")], 9, 6, 5, None,
      "MLflow model id. 레지스트리 버전과 지표는 MLflow 화면에서 본다", options={"textMode": "name", "colorMode": "none"})
panel("stat", "이상 판정 (24h)", [('avg_over_time(max(anomaly_model_is_anomaly{rule="hybrid"})[24h:1m]) * 1440', "")], 15, 4, 5, "m",
      "지난 24시간 중 이상으로 판정한 분 수", defaults={"decimals": 0})
panel("stat", "모니터 마지막 판정", [("time() - max(anomaly_monitor_last_success_timestamp_seconds)", "")], 19, 5, 5, "s",
      "mcp-anomaly 모니터가 마지막으로 판정에 성공한 뒤 지난 시간. 3분을 넘으면 Prometheus 나 예측 서버 연결을 확인",
      defaults={"decimals": 0, **thr((None, "green"), (180, "orange"), (600, "red"))})
y += 5

row("모델 판정과 실제 장애 주입")
panel("timeseries", "판정 vs 정답", [
    ('max(anomaly_model_is_anomaly{rule="hybrid"})', "모델 판정 (혼합)"),
    (f"{TRUTH} * 0.8", "정답: {{kind}} 주입"),
], 0, 24, 7, None,
      "모델이 이상이라 본 시간(빨강)과 실제로 장애를 주입한 시간(정답, 높이 0.8)이 겹치면 맞힌 것. 주입 직후 2~3분은 지표(2분 rate)가 늦게 따라온다",
      defaults={**step_line, "min": 0, "max": 1.05}, overrides=[color("모델 판정 (혼합)", "red"), color_re("정답: .*", "blue")])
y += 7
panel("timeseries", "특성별 z-score (왜 이상인가)", [("max by (feature) (anomaly_model_feature_z)", "{{feature}}")], 0, 14, 8, None,
      "+ 는 평소보다 큼, - 는 작음. 점선 ±4 를 넘으면 그 특성만으로 이상 판정. 모델 v2 부터 나온다",
      defaults={"custom": {"thresholdsStyle": {"mode": "line+area"}, "fillOpacity": 0},
                "thresholds": {"mode": "absolute", "steps": [{"color": "transparent", "value": None}, {"color": "red", "value": 4}]}})
panel("timeseries", "규칙별 판정", [('max by (rule) (anomaly_model_is_anomaly{rule=~"iforest|zscore|traffic_drop|pod"})', "{{rule}}")], 14, 10, 4, None,
      "iforest: 여러 지표의 조합이 평소와 다름. zscore: 한 지표가 크게 벗어남. traffic_drop: 요청 급감 (절대 하한 또는 한 시간 전 대비, v11 부터). pod: 파드별로 따로 채점했을 때 어느 파드든 이상", defaults={**step_line, "min": 0, "max": 1.05})
panel("timeseries", "IsolationForest 이상 점수", [("max(anomaly_model_score)", "점수")], 14, 10, 4, None,
      "클수록 이상. 경계는 학습 정상 구간 점수의 상위 0.1% (MLflow run 의 threshold 지표)", gridPos={"x": 14, "y": y + 4, "w": 10, "h": 4})
y += 8

row("부분 급감과 파드별 판정")
panel("timeseries", "요청 수: 한 시간 전 같은 시점 대비", [("max(anomaly_model_rps_vs_prev_cycle)", "비율")], 0, 12, 6, None,
      "부하가 1시간 주기라 최근 평균이 아니라 한 주기 전과 비교한다. 정상은 0.88 이상, 학습된 경계(약 0.63) 아래면 급감. 모델 v11 부터 (그 전 모델은 0 으로 보인다)",
      defaults={"min": 0, "custom": {"thresholdsStyle": {"mode": "line+area"}, "fillOpacity": 0},
                "thresholds": {"mode": "absolute", "steps": [{"color": "red", "value": None}, {"color": "transparent", "value": 0.625}]}})
panel("timeseries", "이상으로 판정된 파드 (z)", [("max by (pod, feature) (anomaly_model_pod_z)", "{{pod}} {{feature}}")], 12, 12, 6, None,
      "같은 모델에 파드별 값을 따로 넣었을 때 이상인 파드만 값이 있다. 서비스 합계로는 절반으로 보이는 파드 하나의 문제를 가려낸다 (DemoSinglePodAnomaly)")
y += 6

row("모델에 들어가는 값 (1분 단위)")
panel("timeseries", "요청 수", [(FEATURES["rps"], "rps")], 0, 5, 6, "reqps")
panel("timeseries", "5xx 비율", [(FEATURES["error_ratio"], "error_ratio")], 5, 5, 6, "percentunit")
panel("timeseries", "p95 지연", [(FEATURES["p95_seconds"], "p95")], 10, 4, 6, "s")
panel("timeseries", "메모리 사용률 (한도 대비, 최대 파드)", [(FEATURES["mem_ratio"], "mem_ratio")], 14, 5, 6, "percentunit", defaults={"max": 1})
panel("timeseries", "메모리 증가 속도 (분당, 한도 대비)", [(FEATURES["mem_growth"], "mem_growth")], 19, 5, 6, "percentunit",
      "누수를 메모리가 아직 낮을 때 잡는 특성 (모델 v6 부터). 재시작 직후 5분은 비어 있다")
y += 6

row("서빙과 도구")
panel("timeseries", "detect_anomalies 호출 (구간별)", [('sum by (status) (increase(mcp_tool_calls_total{job="mcp-anomaly"}[$__interval]))', "{{status}}")], 0, 8, 6, "short",
      "에이전트가 조사 중에 이상 탐지 도구를 부른 횟수")
panel("timeseries", "모니터 판정 (구간별)", [("sum by (status) (increase(anomaly_monitor_runs_total[$__interval]))", "{{status}}")], 8, 8, 6, "short")
panel("text", "더 보기", [], 16, 8, 6, options={"mode": "markdown", "content":
      "- **MLflow** (실험, 지표 비교, 모델 버전): http://mlflow.ascode.click\n"
      "- **Argo Workflows** (학습 파이프라인 실행 기록): http://workflows.ascode.click\n"
      "- Slack 에서 봇에게 \"이상 탐지 모델 상태\" 라고 물으면 버전 목록과 재학습·승격 버튼이 온다"})

dash = {"uid": "kube-chatops-anomaly-model", "title": "kube-chatops / 이상 탐지 모델", "tags": ["kube-chatops", "mlops"],
        "timezone": "Asia/Seoul", "refresh": "1m", "time": {"from": "now-6h", "to": "now"}, "schemaVersion": 39, "editable": True,
        "templating": {"list": [{"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus", "current": {}, "hide": 0}]},
        "panels": panels, "annotations": {"list": []}}
body = json.dumps(dash, ensure_ascii=False, indent=1)
out = """# Grafana 대시보드: 이상 탐지 모델 (지금 판정, 판정 vs 실제 장애, 특성별 z-score, 입력 지표).
# Grafana 사이드카가 모든 ns 에서 grafana_dashboard=1 라벨 ConfigMap 을 읽는다.
# 수정은 Grafana 에서 하지 말고 생성기에서: python3 scripts/gen-anomaly-dashboard.py mlops/anomaly-serve/dashboard.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: anomaly-model-dashboard
  namespace: mlops
  labels:
    grafana_dashboard: "1"
data:
  kube-chatops-anomaly-model.json: |
""" + "\n".join("    " + l for l in body.splitlines()) + "\n"
open(sys.argv[1], "w").write(out)
print(len(panels), "panels")
