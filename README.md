# WarpPocket

Небольшой SOCKS5-клиент Cloudflare WARP для выбранных приложений. Целевой результат — один Windows EXE с Tkinter-интерфейсом, без драйверов и прав администратора.

## Текущее состояние

Реализован **headless-этап**: приватные профили и кеш, безопасный импорт, управляемые процессы, backend wireproxy и реальные HTTPS-проверки. Обязательный сетевой gate **пройден локально 2026-10-19**. GUI, поиск стратегий и onefile-сборка ещё не реализованы — это следующие этапы. Текущее состояние и доказательства записаны в [execution contract](docs/goals/2026-10-18-warppocket-mvp.md); исходное предложение — [docs/origin.md](docs/origin.md).

Причина прежних таймаутов: Cloudflare WARP требует 3 байта `reserved` (24-битный client id) в WireGuard-сообщениях; `wgcf` их не пишет, а upstream `wireproxy` не поддерживает. Патченная сборка helper'а (`scripts/build_wireproxy.py`) добавляет `reserved` в исходящие пакеты и очищает зеркалированное сервером поле во входящих; это подтверждено контрольным экспериментом с `sing-box` на том же профиле и endpoint.

Gate прошёл: primary на `188.114.96.1:4500` (417 мс), после полной остановки другой endpoint `188.114.97.1:4500` (327 мс), повторное использование сохранённого профиля без регистрации, отдельный probe при непрерывных запросах primary (6 запросов, 0 сбоев) без изменений PID/порта/профиля, cleanup подтверждён. `engage.cloudflareclient.com:2408` в тестовых сетях стабильно таймаутит; рабочие кандидаты — `188.114.9x.1:4500`.

GitHub Actions собирает патченный helper (Go 1.26) на Linux и Windows и прогоняет полный набор тестов с платформенными skips; на Windows выполняются настоящие Job Object owner-crash/handle tests, DACL test и offline smoke helper'а. Проверенный прогон: [run 39235875257](https://github.com/0FL01/WarpPocket/actions/runs/39235875257). Это не проверка готового onefile EXE и не замена Windows 10-приёмке.

Не считать открытый SOCKS-порт доказательством подключения: проверка требует `warp=on/plus` и независимого HTTPS-ресурса. Это не системный VPN и не гарантия обхода DPI.

## Разработка

Python >=3.12, Tkinter/ttk из стандартной библиотеки. Для будущей Windows-сборки закреплён обычный CPython 3.13.16 x64 и PyInstaller 6.22.3. Актуальные security-релизы Python 3.12 не имеют официального Windows installer.

Fedora/Linux x64:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python scripts/fetch_vendor.py --platform linux-amd64      # wgcf, проверка SHA256
.venv/bin/python scripts/build_wireproxy.py --platform linux-amd64   # нужен Go 1.26+
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Windows x64 (PowerShell, для разработки нужен Python и Go):

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.txt
.venv\Scripts\python scripts/fetch_vendor.py --platform windows-amd64
.venv\Scripts\python scripts/build_wireproxy.py --platform windows-amd64
$env:PYTHONPATH = 'src'
.venv\Scripts\python -m unittest discover -s tests -v
```

Узкая проверка: `python -m unittest discover -s tests -p 'test_profiles.py' -v` с `PYTHONPATH=src`. Windows-specific Job Object/DACL tests запускаются на Windows; POSIX permissions — на Linux. Actual-helper smoke использует синтетические ключи и loopback endpoint, не интернет и не регистрацию.

`fetch_vendor.py` получает только закреплённый `wgcf 2.3.1` и проверяет SHA256 до использования. `build_wireproxy.py` собирает `wireproxy 1.1.3` из закреплённых исходников (tarball и модуль `golang.zx2c4.com/wireguard`) с патчем `reserved-support`, проверяет SHA256 архива и печатает SHA256 результата. Ненулевой результат загрузчика или ошибка сборки запрещает продолжать со старыми бинарниками. Helpers, окружения и результаты сборок не хранятся в Git.

## Реальный сетевой gate: только явно

**Регистрация передаёт данные Cloudflare и означает принятие [условий](https://www.cloudflare.com/application/terms/).** Обычный CI никогда не регистрирует устройства. Два флага согласия раздельны: второй профиль нужен для поиска без вмешательства в основной WireGuard-туннель.

```sh
.venv/bin/python scripts/e2e_network.py \
  --data-dir "$HOME/.local/share/warppocket-e2e" \
  --accept-tos --accept-probe-tos \
  --report "$HOME/.local/share/warppocket-e2e/last-report.json"
```

Последующие запуски используют существующий профиль/аккаунт. Валидный аккаунт после частичной ошибки регистрации не регистрируется заново: повторяется генерация. Невалидный частичный аккаунт не заменяется автоматически. Не удаляйте аккаунты для бесконечных повторных регистраций.

Gate последовательно проверяет:

1. Регистрация/сохранённый профиль → `127.0.0.1:25344` → TLS-verified HTTPS trace и Google/Apple.
2. Полная остановка → другой endpoint → повторный успех.
3. Повторное использование сохранённого профиля без регистрации.
4. Активный primary + последовательные проверки отдельным probe при непрерывных основных HTTPS-запросах.
5. Сохранность PID/порта/профиля primary и cleanup процессов/портов.

Можно добавить кандидатов повторением `--endpoint IP:port`. За один этап проверяется не более 30 уникальных кандидатов; после 180 секунд новые проверки не начинаются. Практический пример рабочих кандидатов: `--endpoint 188.114.96.1:4500 --endpoint 188.114.97.1:4500`. Если в профиле нет `Reserved`, e2e сам запрашивает его через Cloudflare API (`ensure_reserved`). Неудача даёт ненулевой exit code и безопасный JSON-отчёт, а не ложный статус «Подключено». При блокировке WireGuard/UDP GUI не решит проблему транспорта.

## Данные и приватность

Обычный каталог приложения:

- Windows: `%LOCALAPPDATA%\WarpPocket`;
- Linux: `$XDG_DATA_HOME/warppocket`, иначе `~/.local/share/warppocket`.

E2E использует **отдельный** каталог, заданный `--data-dir`.

```text
settings.json                  # только endpoint, роль, время, HTTPS-задержка
profiles/primary/              # account.toml и нормализованный profile.conf, секреты
profiles/probe/                # отдельная идентичность
run/                           # приватные временные конфиги
logs/                          # ограниченные собственные диагностические события
```

Windows-каталог защищён DACL текущего пользователя; на Linux каталоги `0700`, секретные файлы `0600`. Кеш записывается атомарно. Повреждение кеша не затрагивает профили; неизвестная версия кеша не перезаписывается. Сырой вывод helpers не сохраняется: он может содержать ключи и токены.

Импорт принимает только нормализованный single-peer WireGuard-профиль: ключи, адреса, DNS-IP, полный IPv4-маршрут, endpoint, MTU, необязательные keepalive/PSK и `Reserved` (три байта 0..255; нужен для WARP-совместимых профилей). Дополнительные listeners/peers, hooks, `WGConfig` и переменные окружения запрещены. Импорт выполняется только при остановленных операциях; исходный текст никогда не передаётся helper напрямую.

Разные локальные SOCKS-порты **не изолируют одинаковые WireGuard-ключи**. Не используйте импортированную идентичность одновременно в другом клиенте.

## SOCKS и DNS

Адрес основного прокси: `127.0.0.1:25344`, SOCKS5. Например, в Firefox нужен SOCKS v5 и флажок удалённого DNS через SOCKS. В requests используется `socks5h`, а не `socks5`. Системные маршруты, глобальный прокси и firewall приложение не меняет.

wireproxy поддерживает TCP CONNECT, но **не UDP ASSOCIATE**. UDP/QUIC и приложения, игнорирующие прокси, не становятся защищёнными автоматически. Разрешение hostname самого WARP endpoint до поднятия туннеля отличается от DNS браузерного трафика; DNS проксируемых доменов должен идти через явно заданный туннельный resolver, без системного fallback.

## Лицензии

Upstream notices находятся в [vendor/licenses](vendor/licenses): wireproxy (ISC), wgcf (MIT), списки ros-scripts (MIT). Оригинальные списки эндпоинтов закреплены на commit `d92d68db030e833c7f6032697e4f177dfe976230`. Условия Cloudflare применяются отдельно от лицензий компонентов.
