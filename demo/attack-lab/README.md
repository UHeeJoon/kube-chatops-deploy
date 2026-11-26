# attack-lab

보안 탐지를 검증하려고 **일부러 취약하게 만든** 앱이다. 실제 서비스에 쓰지 않는다.

- php: `cmd.php?c=<명령>` 이 그대로 셸에서 실행된다 (업로드된 웹셸 흉내)
- php: `upload.php?p=<경로>[&x=1]` 이 요청 본문을 그 경로에 쓴다 (검사 없는 업로드, 웹 루트가 쓰기 가능), `run.php?b=<파일>` 이 셸 없이 직접 실행한다 (셸 차단 우회 흉내)
- java: `/run?c=<명령>` 이 그대로 셸에서 실행된다 (Log4Shell 같은 원격 실행 흉내)

안전장치
- HTTPRoute 없음, NetworkPolicy 로 들고 나는 통신 모두 차단. `kubectl exec` 로 파드 안에서만 부른다.
- demo 의 TracingPolicyNamespaced `webshell-block` 이 셸 실행을, `webroot-tamper-block`·`dropper-block`·`privesc-block` 이 웹 루트 쓰기·투하 파일 실행·권한 상승을 커널에서 막는다.

재현
```sh
kubectl -n demo exec deploy/attack-lab-php -- curl -s 'localhost/cmd.php?c=id'
kubectl -n demo exec deploy/attack-lab-java -- wget -qO- 'localhost:8080/run?c=id'
```
차단되면 응답이 비거나 오류이고, Tetragon 이벤트와 `DemoWebshellBlocked` 알림이 생긴다.

```sh
# 웹셸 파일 심기 → 쓰기 거부 (DemoFileTamperBlocked)
kubectl -n demo exec deploy/attack-lab-php -- curl -s --data-binary '<?php system($_GET[0]);' 'localhost/upload.php?p=/var/www/html/uploads/s.php'
# 실행 파일 투하 후 셸 없이 실행 → 종료 + 격리 (DemoCompromiseBlocked)
kubectl -n demo exec deploy/attack-lab-php -- sh -c "curl -s --data-binary @/usr/bin/id 'localhost/upload.php?p=/tmp/x&x=1' && curl -s 'localhost/run.php?b=/tmp/x'"
```
