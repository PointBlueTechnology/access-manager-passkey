#!/usr/bin/env bash
# Installs and configures the passkey class on an Identity Server cluster through the Administration
# Console, with amcli (https://github.com/PointBlueTechnology/access-manager-cli). Run it from the
# unpacked release bundle. See INSTALL.md, "Scripted: amcli".
#
#   ./amcli-deploy.sh files  [--dry-run]                 jar and JSPs through Advanced File Configurator,
#                                                        sent to the servers, then an Update (restarts them)
#   ./amcli-deploy.sh config [--dry-run] [--helpdesk] [--config FILE]
#                                                        class, methods and contracts from amcli/passkey.json,
#                                                        then an Update
#   ./amcli-deploy.sh all    [--dry-run] [--helpdesk]    both
#
# Settings come from the environment, or from the env file in AMCLI_ENV_FILE (see amcli/amcli.env.example):
# amcli's AMCLI_ settings, and the PASSKEY_ values amcli/passkey.json refers to. Set AMCLI to amcli's
# path if it isn't on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AMCLI="${AMCLI:-amcli}"
WEBAPP=/opt/novell/nids/lib/webapp
MIN_AMCLI=0.3.1

usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

step() {
    echo "==> $*" >&2
}

run_amcli() {
    "$AMCLI" "$@" --compact
}

action="${1:-}"
[ $# -gt 0 ] && shift
dry_run=""
helpdesk=""
config="$HERE/amcli/passkey.json"
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) dry_run="--dry-run" ;;
        --helpdesk) helpdesk=1 ;;
        --config) config="${2:?--config needs a file}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

case "$action" in
    files|config|all) ;;
    -h|--help|help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

if ! command -v "$AMCLI" >/dev/null 2>&1; then
    echo "amcli isn't installed. Install it from https://github.com/PointBlueTechnology/access-manager-cli/releases/latest, or set AMCLI to its path." >&2
    exit 2
fi
have="$("$AMCLI" --version)"
if [ "$(printf '%s\n%s\n' "$MIN_AMCLI" "$have" | sort -V | head -1)" != "$MIN_AMCLI" ]; then
    echo "amcli $have is too old: this script needs $MIN_AMCLI or later." >&2
    exit 2
fi
version="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"

step "Checking the connection"
run_amcli ping >/dev/null

deploy_files() {
    local jar="$HERE/lib/nam-passkey-auth.jar"
    [ -f "$jar" ] || { echo "No $jar: run this from the unpacked release bundle." >&2; exit 2; }
    local sent=()
    step "Uploading the jar to Advanced File Configurator (needs a restart)"
    run_amcli afc upload "$jar" --dir "$WEBAPP/WEB-INF/lib" --type "Passkey authentication" \
        --description "nam-passkey-auth $version" --restart $dry_run
    sent+=("$WEBAPP/WEB-INF/lib/nam-passkey-auth.jar")
    for page in "$HERE"/jsp/passkey_*; do
        step "Uploading jsp/$(basename "$page")"
        run_amcli afc upload "$page" --dir "$WEBAPP/jsp" --type "Passkey authentication" \
            --description "nam-passkey-auth $version" $dry_run
        sent+=("$WEBAPP/jsp/$(basename "$page")")
    done
    if [ -n "$dry_run" ]; then
        step "Dry run: would send ${#sent[@]} files and run an Update, which restarts the Identity Servers"
        return
    fi
    step "Sending ${#sent[@]} files to the servers, then updating them (they restart; this takes a few minutes)"
    run_amcli afc send "${sent[@]}" --yes --update --timeout 900
}

apply_config() {
    local file="$1"
    local backup
    backup="$(pwd)/$(basename "$file" .json).restore-$(date +%Y%m%d-%H%M%S).json"
    if [ -n "$dry_run" ]; then
        step "Dry run of $(basename "$file")"
        run_amcli apply -f "$file" --dry-run
        return
    fi
    step "Applying $(basename "$file")"
    run_amcli apply -f "$file" --backup "$backup"
    echo "To undo it: $AMCLI apply -f $backup --yes, then $AMCLI update --yes --wait. The file can hold the recovery pepper: keep it private." >&2
}

configure() {
    apply_config "$config"
    if [ -n "$helpdesk" ]; then
        apply_config "$HERE/amcli/passkey-helpdesk.json"
    fi
    if [ -z "$dry_run" ]; then
        step "Updating the Identity Servers"
        run_amcli update --yes --wait
    fi
}

case "$action" in
    files) deploy_files ;;
    config) configure ;;
    all) deploy_files; configure ;;
esac
step "Done"
