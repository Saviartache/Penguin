---
type: инструкция
summary: Повторный deploy.sh или rsync с исключениями и --force-recreate
code: servers/pingwin/deploy.sh
tags:
  - pingwin
  - сервер
  - развёртывание
---

# Обновление сервера Pingwin

Проще всего — ещё раз [[Развёртывание Pingwin одной командой|deploy.sh]].

Вручную:

```bash
bash servers/pingwin/docker/stage.sh /tmp/pingwin-ctx
rsync -a --delete --exclude target --exclude pingwin.toml --exclude .env \
    --exclude certs --exclude letsencrypt /tmp/pingwin-ctx/ root@СЕРВЕР:/opt/pingwin/
ssh root@СЕРВЕР 'cd /opt/pingwin && docker compose up -d --build --force-recreate'
```

| Флаг | Почему обязателен |
|---|---|
| `--exclude …` | ключ, пароли и сертификат живут только на сервере |
| `--force-recreate` | Docker держит примонтированные файлы по inode: без пересоздания контейнер читал бы прежние |
