---
type: справка
summary: pingwin.toml — адрес, ключ, сертификат, прикрытие, пользователи; права 600 и uid 10001
code: servers/pingwin/src/config.rs
tags:
  - pingwin
  - сервер
  - настройки
---

# Настройки сервера Pingwin

```toml
listen   = "0.0.0.0:8443"                        # внутри контейнера; наружу 443/udp
key      = "<закрытый ключ>"
cert     = "/etc/pingwin/certs/fullchain.pem"
cert_key = "/etc/pingwin/certs/privkey.pem"
cover    = "/srv/cover"

[[users]]
name     = "petya"
password = "<длинный случайный пароль>"
```

| Поле | Что это |
|---|---|
| `listen` | адрес внутри контейнера |
| `key` | закрытый X25519 из `keygen` — [[Ключи]] |
| `cert`, `cert_key` | сертификат Let's Encrypt — [[Соединение]] |
| `cover` | каталог сайта — [[Прикрытие]] |
| `users` | имя и пароль; у каждого пользователя свой |

> [!warning] Права обязательны
> В файле закрытый ключ. Владелец — uid, под которым сервер работает в
> контейнере (`Dockerfile`, `--uid 10001`):
> `chown 10001:10001 pingwin.toml && chmod 600 pingwin.toml`

Файл создаётся на сервере и в репозиторий не входит.
