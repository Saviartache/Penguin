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

<img src="assets/screens/light.png" alt="Главное окно, светлая тема" width="330">
&nbsp;&nbsp;&nbsp;
<img src="assets/screens/dark.png" alt="Главное окно, тёмная тема" width="330">

<br>
<br>

<img src="assets/screens/servers-light.png" alt="Экран «Серверы», светлая тема" width="680">

<br>

</div>

---

## Что он делает

Забирает трафик машины через TUN-адаптер, узнаёт для каждого соединения
приложение-владельца и адрес назначения и решает: **в тоннель**, **напрямую**
или **оборвать**.

- **Правила по владельцу** — путь, имя или шаблон пути к `.exe`. Владелец
  определяется по локальному порту средствами ОС: без своего драйвера.
- **Правила по назначению** — домен, суффикс, подстрока, regex, CIDR, порт,
  диапазон, GeoIP, GeoSite, вид трафика; складываются в `all` / `any` / `not`.
- **`rules explain`** — показывает сработавшее правило и те, что сработали бы
  без него.
- **Свой DNS** — fake-IP, кеш, hosts, апстримы UDP / DoT / DoH.
- **Kill switch и доступ к локальной сети** — переключателями.
- **Локальный SOCKS5 и HTTP-прокси** — без прав администратора.
- **Окно, терминал и служба** — в одном исполняемом файле.

---

## Протоколы

Pingwin (свой, с сервером в этом же дереве), WireGuard, OpenConnect,
Hysteria 2, TUIC, Juicity, AnyTLS, VLESS, VMess, Trojan, Shadowsocks,
NaiveProxy, MASQUE, TrustTunnel, SOCKS5, HTTP/HTTPS.

Что умеет и чего не умеет каждый — в документе его крейта в
[`protocols/`](protocols).

Отдельно стоит **режим DPI** ([`protocols/dpi`](protocols/dpi)): сервера у него
нет вовсе. Соединение идёт прямо к сайту, и по плану обхода уходит только его
первая посылка — этого хватает там, где адрес сайта достижим, а разговор рвут,
прочитав в приветствии имя узла.

---

## Стек

| Слой | Windows | Linux | macOS |
|---|---|---|---|
| Транспорт | `quinn`, `rustls`, `h3` | ← | ← |
| Стек TCP/IP | `smoltcp` | ← | ← |
| Адаптер | `wintun` | `/dev/net/tun` | `utun` |
| Маршруты | IP Helper | netlink | `PF_ROUTE` |
| Kill switch | Windows Firewall | nftables | pf |
| Настройки DNS | `netsh` | `resolvectl`, `resolv.conf` | `networksetup` |
| Владелец соединения | IP Helper | procfs | libproc |
| Служба | SCM | systemd | launchd |
| Права | UAC | polkit | Authorization Services |
| Канал управления | named pipe | unix socket | unix socket |
| Системный слой | `windows-rs` | `nix`, `libc` | `nix`, `libc` |

Разбор DNS — `hickory-proto`, асинхронность — `tokio`, интерфейс — `iced` и
`clap`; везде одинаково.

---

## Устройство

```
приложение → penguin-tun → penguin-netstack → penguin-router → Tunnel / Direct / Block
                              │                    ▲
                              ├── penguin-process ─┤  кто владелец: порт → pid → путь
                              ├── penguin-dns ─────┤  fake-IP → домен
                              └── engine::sniff ───┘  SNI из первых байт
```

| Каталог | Что там |
|---|---|
| `crates/` | инфраструктура клиента: транспорт, маршрутизация, DNS, демон, GUI, CLI |
| `protocols/` | реализации протоколов, по крейту на протокол |
| `servers/` | серверы для другой машины; сейчас один — `pingwin` |
| `vendor/rust-ui-kit` | UI-кит поверх `iced`, подключён submodule'ом |

Протокол не знает ни про TUN, ни про правила, ни про GUI — он умеет только
открыть соединение к адресу. Всё остальное описано контрактом в `penguin-proto`.

---

## Сборка и запуск

```bash
git clone --recurse-submodules git@github.com:Saviartache/penguin.git
cargo build --workspace
cargo run -p penguin-app
```

Окно — единственное, что нужно запускать: службу оно ставит само, права
спрашивает системным окном. Склонированный без submodule'а чинится через
`git submodule update --init --recursive`.

На Linux окну нужны системные библиотеки значка в лотке — без них не соберётся
`penguin-gui`:

```bash
sudo apt install libgtk-3-dev libappindicator3-dev # или libayatana-appindicator3-dev
```

```bash
cargo run -p penguin-app -- doctor
cargo run -p penguin-app -- rules explain steamcontent.com:443 --process steam.exe
```

`doctor` проверяет настройки, профили, правила и права. Все поля настроек — в
[`assets/config.example.toml`](assets/config.example.toml).

---

## Документация

| Файл | О чём |
|---|---|
| [`AGENTS.md`](AGENTS.md) | правила репозитория: граф зависимостей, раскладка, ошибки |
| [`protocols/pingwin/PROTOCOL.md`](protocols/pingwin/PROTOCOL.md) | формат провода своего протокола |
| [`servers/pingwin/docker/README.md`](servers/pingwin/docker/README.md) | как поднять свой сервер одной командой |

---

## Лицензия

MIT
