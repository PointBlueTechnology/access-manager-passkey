#!/bin/sh
# Copies the jar and JSPs to one Identity Server node and restarts it.
# Usage: scripts/deploy-test.sh root@idp-host   (run `mvn package` first)
set -eu

HOST="${1:?usage: deploy-test.sh user@idp-host}"
NIDP=/opt/novell/nam/idp/webapps/nidp
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAR="$(ls "$ROOT"/target/nam-passkey-auth-*.jar | grep -v original | head -1)"

scp -q "$JAR" "$HOST:$NIDP/WEB-INF/lib/nam-passkey-auth.jar.new"
scp -q "$ROOT"/src/main/webapp/jsp/passkey_* "$HOST:$NIDP/jsp/"
ssh "$HOST" "cd $NIDP \
    && mv WEB-INF/lib/nam-passkey-auth.jar.new WEB-INF/lib/nam-passkey-auth.jar \
    && chown novlwww:novlwww WEB-INF/lib/nam-passkey-auth.jar jsp/passkey_* \
    && chmod 664 WEB-INF/lib/nam-passkey-auth.jar jsp/passkey_* \
    && /etc/init.d/novell-idp restart"
