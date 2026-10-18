# Нейропитомец

**Категория:** Reverse
**Флаг:** `SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}`

## Дано

Файл `neuropet.ab`, бэкап Android-приложения (`adb backup`). Внутри APK игрушки-"нейропитомца".

## Распаковка бэкапа

Формат `.ab` простой: заголовок `ANDROID BACKUP`, версия, флаг сжатия, флаг шифрования (в этом файле `none`), и после четвёртого перевода строки сразу zlib-поток, внутри которого обычный TAR с содержимым бэкапа. Разворачивается стандартной библиотекой `tarfile` поверх распакованного zlib.

```python
header = raw.split(b'\n', 4)
assert header[:4] == [b'ANDROID BACKUP', b'1', b'1', b'none']
with tarfile.open(fileobj=io.BytesIO(zlib.decompress(header[4]))) as tf:
    apk = tf.extractfile('apps/com.solarlabs.neuropet/a/base.apk').read()
```

Внутри APK — `assets/neuro/skin.dat` и `assets/neuro/brain.bin`.

## Расшифровка скрытого DEX

JADX на обычном коде приложения показывает, что `skin.dat` это не просто картинка-"скин", а зашифрованный DEX: первые два байта little-endian задают seed для классического LCG `s = s*1103515245 + 12345 (mod 2^32)`, а каждый байт полезной нагрузки XOR-ится с байтом `(s >> 16) & 0xFF` на очередном шаге генератора:

```python
def lcg_xor(data, seed):
    out = bytearray()
    for b in data:
        seed = (seed * 1103515245 + 12345) & 0xffffffff
        out.append(b ^ ((seed >> 16) & 255))
    return bytes(out)

dex = b'dex\n' + lcg_xor(skin[2:], int.from_bytes(skin[:2], 'little'))[4:]
```

Расшифрованный DEX открывает скрытую `LabActivity`, которая вызывается по условию "пять нажатий за 1.5 секунды" и запускает `run("devroom")` — то есть обращается к встроенному скриптовому движку.

## Собственный байткод-движок в нативной библиотеке

`lib/x86_64/libneurocore.so` (разобран Ghidra headless) грузит `brain.bin` — контейнер собственного формата `NRBC v1`: число скриптов, для каждого имя, тот же LCG-seed и зашифрованный код (тем же `lcg_xor`, что и для DEX). Опкод простой: сырой байт умножается на 183 по модулю 256, дальше диспатч по результату на стековую VM (push constant, pop, dup, арифметика, битовый ротейт по маске, LCG-шаг состояния, условные и безусловные переходы, и главное — `EMIT`, который забирает верхушку стека в именованный сегмент вывода).

Полный интерпретатор уместился в полсотни строк Python (см. приложение), выполняется только над данными скрипта `devroom`, саму игру запускать не нужно. На `EMIT`-инструкциях видно, как собирается флаг по четырём сегментам:

```text
EMIT 1 b'SOLARCTF{F'
EMIT 2 b'R1d0Mp_Sc4'
EMIT 3 b'n_p4G3s_i'
EMIT 4 b'n_GamEEE}'
HALT 524 steps
FLAG: SOLARCTF{FR1d0Mp_Sc4n_p4G3s_in_GamEEE}
```

## Приложение: автономный солвер

```python
import io, pathlib, struct, sys, tarfile, zipfile, zlib

def lcg_xor(data, seed):
    out = bytearray()
    for b in data:
        seed = (seed * 1103515245 + 12345) & 0xffffffff
        out.append(b ^ ((seed >> 16) & 255))
    return bytes(out)

def recover(path):
    raw = pathlib.Path(path).read_bytes()
    header = raw.split(b'\n', 4)
    with tarfile.open(fileobj=io.BytesIO(zlib.decompress(header[4]))) as tf:
        apk = tf.extractfile('apps/com.solarlabs.neuropet/a/base.apk').read()
    with zipfile.ZipFile(io.BytesIO(apk)) as z:
        brain = z.read('assets/neuro/brain.bin')
        skin = z.read('assets/neuro/skin.dat')

    pos = 8
    scripts = {}
    for _ in range(int.from_bytes(brain[6:8], 'little')):
        n = brain[pos]; pos += 1
        name = brain[pos:pos+n].decode(); pos += n
        seed, size = struct.unpack_from('<II', brain, pos); pos += 8
        scripts[name] = seed, lcg_xor(brain[pos:pos+size], seed); pos += size

    seed, code = scripts['devroom']
    stack = [0]; pc = 0; segments = {}
    while True:
        op = (code[pc] * 183) & 255; pc += 1
        if op == 0x4b:
            break
        elif op == 0x4c:
            stack.append(struct.unpack_from('<I', code, pc)[0]); pc += 4
        elif op == 0x4d: stack.pop()
        elif op == 0x4e: stack.append(stack[-1])
        elif 0x4f <= op <= 0x54 or op == 0x57:
            a, b = stack.pop(), stack.pop()
            v = {0x4f: a+b, 0x50: a-b, 0x51: a*b, 0x52: a^b,
                 0x53: a << (b & 31), 0x54: a >> (b & 31), 0x57: int(a == b)}[op]
            stack.append(v & 0xffffffff)
        elif op == 0x55:
            n = code[pc] & 7; pc += 1
            a = stack.pop() & 255
            stack.append(((a << n) | (a >> (8 - n))) & 255)
        elif op == 0x56:
            stack[-1] = (stack[-1]*1103515245+12345) & 0xffffffff
        elif op in (0x58, 0x59):
            dst = struct.unpack_from('<I', code, pc)[0]; pc += 4
            if op == 0x59 or stack.pop() == 0: pc = dst
        elif op == 0x5b:
            slot, size = struct.unpack_from('<BH', code, pc); pc += 3
            data = bytes(v & 255 for v in stack[-size:]) if size else b''
            if size: del stack[-size:]
            if slot: segments[slot] = data

    return b''.join(segments[k] for k in sorted(segments))

if __name__ == '__main__':
    print('FLAG:', recover(sys.argv[1]).decode())
```

## Вывод

Трёхслойная матрёшка: Android-бэкап прячет зашифрованный LCG-ключом DEX, тот прячет вызов собственной стековой VM внутри нативной библиотеки, а VM собирает флаг из четырёх кусков через инструкцию `EMIT`. Ничего из этого не требует живого запуска приложения: весь путь восстанавливается статически, от распаковки `.ab` до полного интерпретатора байткода на Python.
