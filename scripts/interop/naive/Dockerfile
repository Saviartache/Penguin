# Сервер NaiveProxy — это Caddy с форком плагина forwardproxy, а не отдельная
# программа: своего сервера у проекта нет вовсе. Готового образа тоже нет,
# отсюда своя сборка.
#
# Команда сборки взята дословно из README эталона (`klzgrad/naiveproxy`), а не
# подобрана: селектор версии `@naive` — часть пути к форку, и без него
# соберётся обычный forwardproxy, который схемы дополнения не знает.
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive

FROM caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
