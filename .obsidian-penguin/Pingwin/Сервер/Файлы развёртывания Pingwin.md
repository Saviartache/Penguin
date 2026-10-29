---
type: справка
summary: Что лежит в servers/pingwin/docker и зачем
code: servers/pingwin/docker
tags:
  - pingwin
  - сервер
  - развёртывание
---

# Файлы развёртывания Pingwin

Пути — относительно `servers/pingwin/docker/`.

| Файл | Что это |
|---|---|
| `../deploy.sh` | [[Развёртывание Pingwin одной командой]] |
| `Dockerfile` | сборка сервера из исходников, образ на `debian-slim`, uid 10001 |
| `workspace.toml` | корень workspace на пять крейтов; `stage.sh` кладёт его в контекст как `Cargo.toml` |
| `stage.sh` | вырезает из репозитория контекст сборки |
| `dockerignore` | ложится как `.dockerignore`: держит `target/`, ключ и сертификат подальше от образа |
| `compose.yml` | сервер и `certbot` |
| `renew.sh` | продление сертификата и перезапуск сервера, если он сменился |
| `cover/html` | сайт прикрытия — [[Прикрытие]] |
| `pingwin.toml` | [[Настройки сервера Pingwin]]; только на сервере |
