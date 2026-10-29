---
type: инструкция
summary: pingwin-server link печатает ссылку для «Добавить сервер» → «Ссылка»
code: servers/pingwin/src/main.rs
tags:
  - pingwin
  - сервер
---

# Профиль клиента Pingwin

```bash
docker compose run --rm --no-deps --entrypoint pingwin-server pingwin \
    link --config /etc/pingwin/pingwin.toml --host vpn.example.com:443
```

Результат — [[Ссылка-приглашение]]. В клиенте: «Добавить сервер» → «Ссылка».
