<div align="center">

<br>

# Penguin

**VPN-клиент с раздельным тоннелированием: по приложениям, по адресам и по тому и другому сразу.**

[![Rust](https://img.shields.io/badge/Rust-1.98-000000?logo=rust&logoColor=white)](rust-toolchain.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#лицензия)
[![Windows](https://img.shields.io/badge/Windows-x64-0078D6?logo=windows&logoColor=white)](crates/platform)
[![macOS](https://img.shields.io/badge/macOS-arm64%20%7C%20x64-000000?logo=apple&logoColor=white)](crates/platform)
[![Linux](https://img.shields.io/badge/Linux-x64-FCC624?logo=linux&logoColor=black)](crates/platform)

<br>

</div>

---

<div align="center">

<br>

<img src="assets/screens/light.png" alt="Главное окно, светлая тема" width="330">
&nbsp;&nbsp;&nbsp;
<img src="assets/screens/dark.png" alt="Главное окно, тёмная тема" width="330">

<br>
<br>

<img src="assets/screens/servers-light.png" alt="Экран «Серверы», светлая тема" width="680">

<br>
<br>

<img src="assets/screens/servers-dark.png" alt="Экран «Серверы», тёмная тема" width="680">

<br>

</div>

---

<br>

## Стек

<br>

| Слой | ![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white) | ![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black) | ![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white) |
|---|---|---|---|
| **Язык** | ![Rust](https://img.shields.io/badge/Rust%201.98-000000?logo=rust&logoColor=white) | ![Rust](https://img.shields.io/badge/Rust%201.98-000000?logo=rust&logoColor=white) | ![Rust](https://img.shields.io/badge/Rust%201.98-000000?logo=rust&logoColor=white) |
| **Протокол** | ![Hysteria 2](https://img.shields.io/badge/Hysteria%202-6f42c1) ![TUIC](https://img.shields.io/badge/TUIC-6f42c1) ![Juicity](https://img.shields.io/badge/Juicity-6f42c1) ![AnyTLS](https://img.shields.io/badge/AnyTLS-6f42c1) ![VLESS](https://img.shields.io/badge/VLESS-6f42c1) ![Trojan](https://img.shields.io/badge/Trojan-6f42c1) ![Shadowsocks](https://img.shields.io/badge/Shadowsocks-6f42c1) ![ShadowsocksR](https://img.shields.io/badge/ShadowsocksR-6f42c1) ![Snell](https://img.shields.io/badge/Snell-6f42c1) ![GOST](https://img.shields.io/badge/GOST%20Relay-6f42c1) ![Brook](https://img.shields.io/badge/Brook-6f42c1) ![Mieru](https://img.shields.io/badge/Mieru-6f42c1) ![NaiveProxy](https://img.shields.io/badge/NaiveProxy-6f42c1) ![SSH](https://img.shields.io/badge/SSH-6f42c1) ![SOCKS5](https://img.shields.io/badge/SOCKS5-6f42c1) ![HTTP/HTTPS](https://img.shields.io/badge/HTTP%2FHTTPS-6f42c1) | ![Hysteria 2](https://img.shields.io/badge/Hysteria%202-6f42c1) ![TUIC](https://img.shields.io/badge/TUIC-6f42c1) ![Juicity](https://img.shields.io/badge/Juicity-6f42c1) ![AnyTLS](https://img.shields.io/badge/AnyTLS-6f42c1) ![VLESS](https://img.shields.io/badge/VLESS-6f42c1) ![Trojan](https://img.shields.io/badge/Trojan-6f42c1) ![Shadowsocks](https://img.shields.io/badge/Shadowsocks-6f42c1) ![ShadowsocksR](https://img.shields.io/badge/ShadowsocksR-6f42c1) ![Snell](https://img.shields.io/badge/Snell-6f42c1) ![GOST](https://img.shields.io/badge/GOST%20Relay-6f42c1) ![Brook](https://img.shields.io/badge/Brook-6f42c1) ![Mieru](https://img.shields.io/badge/Mieru-6f42c1) ![NaiveProxy](https://img.shields.io/badge/NaiveProxy-6f42c1) ![SSH](https://img.shields.io/badge/SSH-6f42c1) ![SOCKS5](https://img.shields.io/badge/SOCKS5-6f42c1) ![HTTP/HTTPS](https://img.shields.io/badge/HTTP%2FHTTPS-6f42c1) | ![Hysteria 2](https://img.shields.io/badge/Hysteria%202-6f42c1) ![TUIC](https://img.shields.io/badge/TUIC-6f42c1) ![Juicity](https://img.shields.io/badge/Juicity-6f42c1) ![AnyTLS](https://img.shields.io/badge/AnyTLS-6f42c1) ![VLESS](https://img.shields.io/badge/VLESS-6f42c1) ![Trojan](https://img.shields.io/badge/Trojan-6f42c1) ![Shadowsocks](https://img.shields.io/badge/Shadowsocks-6f42c1) ![ShadowsocksR](https://img.shields.io/badge/ShadowsocksR-6f42c1) ![Snell](https://img.shields.io/badge/Snell-6f42c1) ![GOST](https://img.shields.io/badge/GOST%20Relay-6f42c1) ![Brook](https://img.shields.io/badge/Brook-6f42c1) ![Mieru](https://img.shields.io/badge/Mieru-6f42c1) ![NaiveProxy](https://img.shields.io/badge/NaiveProxy-6f42c1) ![SSH](https://img.shields.io/badge/SSH-6f42c1) ![SOCKS5](https://img.shields.io/badge/SOCKS5-6f42c1) ![HTTP/HTTPS](https://img.shields.io/badge/HTTP%2FHTTPS-6f42c1) |
| **Транспорт** | ![quinn](https://img.shields.io/badge/quinn-1f6feb) ![rustls](https://img.shields.io/badge/rustls-1f6feb) ![h3](https://img.shields.io/badge/h3-1f6feb) | ![quinn](https://img.shields.io/badge/quinn-1f6feb) ![rustls](https://img.shields.io/badge/rustls-1f6feb) ![h3](https://img.shields.io/badge/h3-1f6feb) | ![quinn](https://img.shields.io/badge/quinn-1f6feb) ![rustls](https://img.shields.io/badge/rustls-1f6feb) ![h3](https://img.shields.io/badge/h3-1f6feb) |
| **Стек TCP/IP** | ![smoltcp](https://img.shields.io/badge/smoltcp-0a7c5a) | ![smoltcp](https://img.shields.io/badge/smoltcp-0a7c5a) | ![smoltcp](https://img.shields.io/badge/smoltcp-0a7c5a) |
| **Адаптер** | ![wintun](https://img.shields.io/badge/wintun-0a7c5a) | ![/dev/net/tun](https://img.shields.io/badge/%2Fdev%2Fnet%2Ftun-0a7c5a) | ![utun](https://img.shields.io/badge/utun-0a7c5a) |
| **Маршруты** | ![IP Helper](https://img.shields.io/badge/IP%20Helper-0a7c5a) | ![netlink](https://img.shields.io/badge/netlink-0a7c5a) | ![PF_ROUTE](https://img.shields.io/badge/PF__ROUTE-0a7c5a) |
| **Kill switch** | ![Windows Firewall](https://img.shields.io/badge/Windows%20Firewall-b3261e) | ![nftables](https://img.shields.io/badge/nftables-b3261e) | ![pf](https://img.shields.io/badge/pf-b3261e) |
| **Разбор DNS** | ![hickory-proto](https://img.shields.io/badge/hickory--proto-0a7c5a) | ![hickory-proto](https://img.shields.io/badge/hickory--proto-0a7c5a) | ![hickory-proto](https://img.shields.io/badge/hickory--proto-0a7c5a) |
| **Настройки DNS** | ![netsh](https://img.shields.io/badge/netsh-0a7c5a) | ![resolvectl](https://img.shields.io/badge/resolvectl-0a7c5a) ![resolv.conf](https://img.shields.io/badge/resolv.conf-0a7c5a) | ![networksetup](https://img.shields.io/badge/networksetup-0a7c5a) |
| **Владелец соединения** | ![IP Helper](https://img.shields.io/badge/IP%20Helper-0a7c5a) | ![procfs](https://img.shields.io/badge/procfs-0a7c5a) | ![libproc](https://img.shields.io/badge/libproc-0a7c5a) |
| **Служба** | ![SCM](https://img.shields.io/badge/SCM-6f42c1) | ![systemd](https://img.shields.io/badge/systemd-6f42c1) | ![launchd](https://img.shields.io/badge/launchd-6f42c1) |
| **Права** | ![UAC](https://img.shields.io/badge/UAC-6f42c1) | ![polkit](https://img.shields.io/badge/polkit-6f42c1) | ![Authorization Services](https://img.shields.io/badge/Authorization%20Services-6f42c1) |
| **Автозапуск окна** | ![HKCU Run](https://img.shields.io/badge/HKCU%20Run-6f42c1) | ![.desktop](https://img.shields.io/badge/.desktop-6f42c1) | ![LaunchAgent](https://img.shields.io/badge/LaunchAgent-6f42c1) |
| **Канал управления** | ![named pipe](https://img.shields.io/badge/named%20pipe-1f6feb) ![interprocess](https://img.shields.io/badge/interprocess-1f6feb) | ![unix socket](https://img.shields.io/badge/unix%20socket-1f6feb) ![interprocess](https://img.shields.io/badge/interprocess-1f6feb) | ![unix socket](https://img.shields.io/badge/unix%20socket-1f6feb) ![interprocess](https://img.shields.io/badge/interprocess-1f6feb) |
| **Системный слой** | ![windows-rs](https://img.shields.io/badge/windows--rs-4b8bbe) ![windows-service](https://img.shields.io/badge/windows--service-4b8bbe) | ![nix](https://img.shields.io/badge/nix-4b8bbe) ![libc](https://img.shields.io/badge/libc-4b8bbe) | ![nix](https://img.shields.io/badge/nix-4b8bbe) ![libc](https://img.shields.io/badge/libc-4b8bbe) |
| **Асинхронность** | ![tokio](https://img.shields.io/badge/tokio-c04b2f) | ![tokio](https://img.shields.io/badge/tokio-c04b2f) | ![tokio](https://img.shields.io/badge/tokio-c04b2f) |
| **Интерфейс** | ![iced](https://img.shields.io/badge/iced%200.14-4b8bbe) ![clap](https://img.shields.io/badge/clap-4b8bbe) | ![iced](https://img.shields.io/badge/iced%200.14-4b8bbe) ![clap](https://img.shields.io/badge/clap-4b8bbe) | ![iced](https://img.shields.io/badge/iced%200.14-4b8bbe) ![clap](https://img.shields.io/badge/clap-4b8bbe) |

<br>

---

<br>

## Что он делает

<br>

Забирает трафик машины через TUN-адаптер, узнаёт для каждого соединения
приложение-владельца и адрес назначения, а дальше по правилам решает:
**в тоннель**, **напрямую** или **оборвать**.

<br>

- **Правила по владельцу соединения** — путь, имя или шаблон пути к `.exe`.
  Владелец определяется по локальному порту средствами ОС: без своего драйвера,
  без WinDivert и без подписанных callout'ов WFP.

- **Правила по назначению** — домен, суффикс, подстрока, regex, CIDR, порт,
  диапазон портов, GeoIP, GeoSite, вид трафика. Условия складываются в
  `all` / `any` / `not`.

- **Ответ на вопрос «почему это приложение пошло не туда»** — `rules explain`
  показывает сработавшее правило и те, что сработали бы без него.

- **Свой DNS** — fake-IP, кеш, hosts, апстримы UDP / DoT / DoH.

- **Kill switch и доступ к локальной сети** — переключателями.

- **Локальный SOCKS5 и HTTP-прокси** — без прав администратора и без драйвера.

- **Окно, терминал и служба** — в одном исполняемом файле.

<br>

---

<br>

## Устройство

<br>

```
приложение → penguin-tun → penguin-netstack → penguin-router → Tunnel / Direct / Block
                              │                    ▲
                              ├── penguin-process ─┤  кто владелец: порт → pid → путь
                              ├── penguin-dns ─────┤  fake-IP → домен
                              └── engine::sniff ───┘  SNI из первых байт
```

<br>

| Каталог | Что там |
|---|---|
| `crates/` | инфраструктура клиента: транспорт, маршрутизация, DNS, демон, GUI, CLI |
| `protocols/` | реализации протоколов, по крейту на протокол |
| `vendor/rust-ui-kit` | UI-кит поверх `iced`, подключён submodule'ом |

<br>

Протокол не знает ни про TUN, ни про правила, ни про GUI — он умеет только
открыть соединение к адресу. Всё остальное описано контрактом в `penguin-proto`.

<br>

---

<br>

## Сборка

<br>

```bash
git clone --recurse-submodules git@github.com:Saviartache/penguin.git
```

```bash
cargo build --workspace
```

<br>

Уже склонированный без submodule'а чинится через
`git submodule update --init --recursive`. Кит в workspace не входит — он
отдельный репозиторий со своими правилами и проверяется своим
`vendor/rust-ui-kit/scripts/check.sh`.

<br>

---

<br>

## Запуск

<br>

```bash
cargo run -p penguin-app -- doctor
```

```bash
cargo run -p penguin-app -- rules explain steamcontent.com:443 --process steam.exe
```

<br>

`doctor` проверяет настройки, профили, правила и права. Все поля настроек с
пояснениями — в [`assets/config.example.toml`](assets/config.example.toml).

Окно поднимается через `cargo run -p penguin-app` — и это единственное, что
нужно запускать. Службу оно ставит и запускает само, а права спрашивает
системным окном: UAC на Windows, окно с отпечатком или паролем на macOS,
polkit на Linux. Команды `penguin service …` существуют для тех, кто
разбирается, почему что-то пошло не так; в обычной работе они не нужны.

<br>

---

<br>

## Документация

<br>

| Файл | О чём |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | путь одного соединения и граф зависимостей |
| [`docs/split-tunneling.md`](docs/split-tunneling.md) | как определяется владелец соединения |
| [`docs/protocols.md`](docs/protocols.md) | как добавить протокол |
| [`AGENTS.md`](AGENTS.md) | правила работы с репозиторием |

<br>

---

<br>

## Лицензия

MIT

<br>
