# WarpPocket

Небольшой SOCKS5-клиент Cloudflare WARP для выбранных приложений. Целевой результат — один Windows EXE с Tkinter-интерфейсом, без драйверов и прав администратора.

## Текущее состояние

Реализован **headless-этап**: приватные профили и кеш, безопасный импорт, управляемые процессы, конкретный backend wireproxy и реальные HTTPS-проверки. Это пока **не готовое Windows-приложение**: GUI, поиск стратегий и onefile-сборка не реализованы, поскольку обязательный сетевой gate не пройден. Текущее состояние и доказательства записаны в [execution contract](docs/goals/2026-10-18-warppocket-mvp.md); исходное предложение — [docs/origin.md](docs/origin.md).

Сетевая проверка 2026-10-18: регистрация и генерация primary успешны, но все 30 проверенных endpoint дали `health_timeout`. Отдельный TCP CONNECT к `1.1.1.1:443` через SOCKS, без DNS, тоже не установился; сгенерированный конфиг проходит проверку самого helper. Причина таймаутов не установлена — это не доказательство блокировки всего WARP. После неудачи helper остановлен, порт и временные конфиги освобождены. Второй профиль не создавался, поскольку проверка не дошла до фонового поиска. Нужна сеть/endpoint, где подтверждается передача данных через WireGuard; интерфейс не должен маскировать этот блокер.

[Headless CI](https://github.com/0FL01/WarpPocket/actions/runs/39165431267) успешно проверил 52 теста на Linux Python 3.12.15/3.13.16 и Windows Python 3.13.16 с платформенными skips. На Windows выполнены настоящие Job Object owner-crash/handle tests, DACL test и offline smoke закреплённого `wireproxy`; это не проверка готового onefile EXE или реального WARP-трафика.

Не считать открытый SOCKS-порт доказательством подключения: проверка требует `warp=on/plus` и независимого HTTPS-ресурса. Это не системный VPN и не гарантия обхода DPI.

## Разработка

Python >=3.12, Tkinter/ttk из стандартной библиотеки. Для будущей Windows-сборки закреплён обычный CPython 3.13.16 x64 и PyInstaller 6.22.3. Актуальные security-релизы Python 3.12 не имеют официального Windows installer.

Fedora/Linux x64:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python scripts/fetch_vendor.py --platform linux-amd64
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Windows x64 (PowerShell, для разработки нужен Python):

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.txt
.venv\Scripts\python scripts/fetch_vendor.py --platform windows-amd64
$env:PYTHONPATH = 'src'
.venv\Scripts\python -m unittest discover -s tests -v
```

Узкая проверка: `python -m unittest discover -s tests -p 'test_profiles.py' -v` с `PYTHONPATH=src`. Windows-specific Job Object/DACL tests запускаются на Windows; POSIX permissions — на Linux. Actual-helper smoke использует синтетические ключи и loopback endpoint, не интернет и не регистрацию.

Загрузчик получает только закреплённые wireproxy 1.1.3 и wgcf 2.3.1, проверяет SHA256 до использования и безопасно извлекает единственный ожидаемый файл. Ненулевой результат загрузчика запрещает продолжать с оставшимися старыми бинарниками. Helpers, окружения и результаты сборок не хранятся в Git.

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

Можно добавить кандидатов повторением `--endpoint IP:port`. За один этап проверяется не более 30 уникальных кандидатов; после 180 секунд новые проверки не начинаются. Неудача даёт ненулевой exit code и безопасный JSON-отчёт, а не ложный статус «Подключено». При блокировке WireGuard/UDP GUI не решит проблему транспорта.

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

Импорт принимает только нормализованный single-peer WireGuard-профиль: ключи, адреса, DNS-IP, полный IPv4-маршрут, endpoint, MTU, необязательные keepalive/PSK. Дополнительные listeners/peers, hooks, `WGConfig`, переменные окружения и `Reserved` запрещены. Импорт выполняется только при остановленных операциях; исходный текст никогда не передаётся helper напрямую.

Разные локальные SOCKS-порты **не изолируют одинаковые WireGuard-ключи**. Не используйте импортированную идентичность одновременно в другом клиенте.

## SOCKS и DNS

Адрес основного прокси: `127.0.0.1:25344`, SOCKS5. Например, в Firefox нужен SOCKS v5 и флажок удалённого DNS через SOCKS. В requests используется `socks5h`, а не `socks5`. Системные маршруты, глобальный прокси и firewall приложение не меняет.

wireproxy поддерживает TCP CONNECT, но **не UDP ASSOCIATE**. UDP/QUIC и приложения, игнорирующие прокси, не становятся защищёнными автоматически. Разрешение hostname самого WARP endpoint до поднятия туннеля отличается от DNS браузерного трафика; DNS проксируемых доменов должен идти через явно заданный туннельный resolver, без системного fallback.

## Лицензии

Upstream notices находятся в [vendor/licenses](vendor/licenses): wireproxy (ISC), wgcf (MIT), списки ros-scripts (MIT). Оригинальные списки эндпоинтов закреплены на commit `d92d68db030e833c7f6032697e4f177dfe976230`. Условия Cloudflare применяются отдельно от лицензий компонентов.
