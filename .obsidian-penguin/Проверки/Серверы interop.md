---
type: справка
summary: Какой чужой сервер проверяет какой протокол
code: scripts/interop/compose.yml
tags:
  - проверка
  - interop
---

# Серверы interop

| Протокол | Эталонный сервер | Настройки |
|---|---|---|
| SOCKS5 (с паролем и открытый) | `serjs/go-socks5-proxy` | `compose.yml` |
| SOCKS5 поверх TLS | `nginx:alpine` перед SOCKS5 | `nginx/` |
| Trojan, TUIC, VLESS, AnyTLS, Shadowsocks | `sing-box` | `singbox/*.json` |
| Trojan, VLESS, VMess | `xray-core` | `xray/config.json` |
| NaiveProxy | свой образ Caddy (HTTP/2 + HTTP/3 на одном порту) | `naive/` |
| Juicity | `ghcr.io/juicity/juicity` | `juicity/` |
| Hysteria 2 | `tobyxdd/hysteria` | `hysteria2/` |

Цель всех — `target` (`nginx:alpine`), см. [[Ход прогона interop]].

Чего нет в списке — [[Пробелы interop]].
