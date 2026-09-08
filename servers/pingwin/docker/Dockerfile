# Сервер Pingwin: сборка и запуск.
#
# Контекст сборки — не корень репозитория, а вырезка из него: её собирает
# `stage.sh`. Причина простая — в корне лежит workspace на два десятка крейтов
# и подмодуль с UI-китом, и Docker тащил бы всё это в контекст ради шести
# папок, из которых собирается сервер.
#
#   docker build -f Dockerfile -t pingwin-server .
#
# Собирается из исходников на месте, а не берётся готовым бинарником: сервер
# и клиент обязаны говорить на одной версии протокола, и единственный способ
# это гарантировать — собрать их из одного дерева.

FROM rust:1.98-slim-bookworm AS build

WORKDIR /build

# Только то, от чего сервер зависит по-настоящему (`AGENTS.md` §1.6):
# контракт, общие типы, общий транспорт, отпечатки TLS и сам протокол.
COPY Cargo.toml ./Cargo.toml
COPY crates ./crates
COPY protocols ./protocols
COPY servers ./servers

RUN cargo build --release -p penguin-pingwin-server \
    && strip target/release/pingwin-server

FROM debian:bookworm-slim

# Сертификаты не нужны самому серверу — он не ходит по TLS, — но нужны тому,
# к чему он ходит по просьбе клиента: без них не разрешится ни одно имя через
# системный резолвер с DoT.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Своя учётная запись: порт внутри контейнера непривилегированный (8443), и
# работать под `root` серверу, который принимает соединения из интернета,
# незачем. Наружу его публикует `compose.yml` на 443.
#
# Номер задан явно, а не выдан системой, и это не мелочь: файл с ключом лежит
# на хосте и подсовывается томом. Права на нём должны быть 600 — ключ не для
# всех, — а значит, владелец обязан совпасть с тем, под кем работает сервер.
# Выданный системой номер менялся бы от образа к образу, и после каждой
# пересборки файл переставал бы читаться.
RUN useradd --system --uid 10001 --user-group \
        --no-create-home --shell /usr/sbin/nologin pingwin

COPY --from=build /build/target/release/pingwin-server /usr/local/bin/pingwin-server

USER pingwin
EXPOSE 8443

# Проверка живости — та же команда, что и у человека: разбор настроек без
# сети. Она отвечает на вопрос «поднимется ли», а не «отвечает ли порт»:
# отвечать на пробу сервер обязан молчанием (см. `fallback`), и healthcheck,
# стучащийся в порт, ловил бы прикрытие, а не сервер.
HEALTHCHECK --interval=60s --timeout=5s --start-period=5s --retries=3 \
    CMD ["pingwin-server", "check", "--config", "/etc/pingwin/pingwin.toml"]

ENTRYPOINT ["pingwin-server"]
CMD ["run", "--config", "/etc/pingwin/pingwin.toml"]
