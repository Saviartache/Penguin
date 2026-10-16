#!/usr/bin/env bash
#
# Продлевает сертификат и отдаёт его серверу. `deploy.sh` ставит его в cron.
#
#   bash /opt/pingwin/renew.sh
#
# Файлы Let's Encrypt принадлежат `root` и читаются только им, а сервер
# работает под `10001` (Dockerfile): поэтому сертификат копируется в `certs/`
# с его владельцем. Сервер читает сертификат при запуске — перезапускается,
# только если файл сменился.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DOMAIN="$(sed -n 's/^PINGWIN_DOMAIN=//p' .env)"
[[ -n "$DOMAIN" ]] || { echo "в .env нет PINGWIN_DOMAIN" >&2; exit 1; }

docker compose run --rm --service-ports certbot renew --quiet

install -d -o 10001 -g 10001 -m 700 certs
CHANGED=0
for FILE in fullchain privkey; do
    if ! cmp -s "letsencrypt/live/$DOMAIN/$FILE.pem" "certs/$FILE.pem"; then
        install -o 10001 -g 10001 -m 600 "letsencrypt/live/$DOMAIN/$FILE.pem" "certs/$FILE.pem"
        CHANGED=1
    fi
done

if [[ "$CHANGED" == 1 ]] && docker compose ps --status running -q pingwin | grep -q .; then
    docker compose restart pingwin
fi
