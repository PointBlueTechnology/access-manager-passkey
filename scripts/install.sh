#!/bin/bash
# Installs the NAM passkey authentication class on one Identity Server node.
#
# Run as root from the unpacked release bundle (nam-passkey-auth-<version>.zip):
#
#   ./install.sh --dry-run            show what would change
#   ./install.sh --restart            install or upgrade, then restart the Identity Server
#   ./install.sh --status             compare what's installed with this bundle
#   ./install.sh --uninstall          remove the jar and JSPs (backed up first)
#   ./install.sh --list-backups       show the backups this script has taken
#   ./install.sh --rollback [ID]      put back the files from a backup (default: the newest)
#
# For a cluster, or Docker/Kubernetes, use the Advanced File Configurator instead (INSTALL.md).
# Works with bash 3.2 and later, GNU or BSD tools, so it runs on SLES 12+/RHEL 7+ as shipped.
set -euo pipefail

PROG=$(basename "$0")
BUNDLE_DIR=$(cd -P "$(dirname "$0")" && pwd -P)

NIDP_DIR=/opt/novell/nam/idp/webapps/nidp
BACKUP_ROOT=/root/nam-passkey-auth-backup
OWNER=novlwww:novlwww
FILE_MODE=664
JAR_REL=WEB-INF/lib/nam-passkey-auth.jar
LOG_HINT=/opt/novell/nam/idp/logs/catalina.out

ACTION=install
DRY_RUN=0
RESTART=0
FORCE=0
ROLLBACK_ID=

usage() {
    cat <<EOF
Usage: $PROG [action] [options]

Actions (default: install):
  --install           Install or upgrade the jar and JSPs from this bundle
  --uninstall         Remove them; the class's Admin Console objects stop working
  --rollback [ID]     Put back the files saved in backup ID (default: the newest one
                      taken by an install or uninstall)
  --status            Compare the installed files with this bundle; changes nothing
  --list-backups      List backups; changes nothing

Options:
  -n, --dry-run       Show what would be done, change nothing
  -r, --restart       Restart the Identity Server afterwards (needed to load a new jar)
      --nidp-dir DIR  Identity Server webapp (default: $NIDP_DIR)
      --backup-dir DIR  Where backups go (default: $BACKUP_ROOT)
      --owner U:G     Owner of installed files (default: $OWNER)
  -f, --force         Skip the Identity Server checks (nidp.jar, novell-idp service),
                      e.g. when building a container image
  -h, --help          This help

Every run that changes files first copies whatever it replaces or removes to
<backup-dir>/<timestamp>/, so it can be undone with --rollback.
EOF
}

say()  { printf '%s\n' "$*"; }
warn() { printf '%s: warning: %s\n' "$PROG" "$*" >&2; }
die()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

# Runs a command, or prints it under --dry-run.
run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] %s\n' "$*"
    else
        printf '  + %s\n' "$*"
        "$@"
    fi
}

# Prints "user:group mode" for a file, with GNU or BSD stat.
file_meta() {
    stat -c '%U:%G %a' "$1" 2>/dev/null || stat -f '%Su:%Sg %Lp' "$1"
}

# True if $1 is one of the lines in $2.
in_lines() {
    case "
$2
" in
        *"
$1
"*) return 0 ;;
    esac
    return 1
}

# ---------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
    case "$1" in
        --install)      ACTION=install ;;
        --uninstall)    ACTION=uninstall ;;
        --status)       ACTION=status ;;
        --list-backups) ACTION=list-backups ;;
        --rollback)
            ACTION=rollback
            if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then ROLLBACK_ID=$2; shift; fi ;;
        -n|--dry-run)   DRY_RUN=1 ;;
        -r|--restart)   RESTART=1 ;;
        -f|--force)     FORCE=1 ;;
        --nidp-dir)     [ $# -gt 1 ] || die "--nidp-dir needs a directory"; NIDP_DIR=$2; shift ;;
        --backup-dir)   [ $# -gt 1 ] || die "--backup-dir needs a directory"; BACKUP_ROOT=$2; shift ;;
        --owner)        [ $# -gt 1 ] || die "--owner needs user:group"; OWNER=$2; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage >&2; die "unknown argument: $1" ;;
    esac
    shift
done

case "$OWNER" in *:*) ;; *) die "--owner must be user:group, got '$OWNER'" ;; esac
OWNER_USER=${OWNER%%:*}
OWNER_GROUP=${OWNER#*:}
INSTALLED_LIST=$BACKUP_ROOT/installed.list

# ---------------------------------------------------------------- the bundle

BUNDLE_VERSION=unknown
[ -f "$BUNDLE_DIR/VERSION" ] && BUNDLE_VERSION=$(head -n 1 "$BUNDLE_DIR/VERSION")

# Relative paths (under the nidp webapp) this bundle installs, one per line.
bundle_files() {
    printf '%s\n' "$JAR_REL"
    local f
    for f in "$BUNDLE_DIR"/jsp/passkey_*; do
        [ -f "$f" ] && printf 'jsp/%s\n' "$(basename "$f")"
    done
}

# Where a relative path comes from in the bundle.
bundle_source() {
    case "$1" in
        "$JAR_REL") printf '%s\n' "$BUNDLE_DIR/lib/nam-passkey-auth.jar" ;;
        jsp/*)      printf '%s\n' "$BUNDLE_DIR/$1" ;;
        *)          return 1 ;;
    esac
}

check_bundle() {
    [ -f "$BUNDLE_DIR/lib/nam-passkey-auth.jar" ] \
        || die "no lib/nam-passkey-auth.jar next to $PROG. Run it from the unpacked release bundle (mvn package builds target/nam-passkey-auth-<version>-bundle.zip)."
    ls "$BUNDLE_DIR"/jsp/passkey_*.jsp >/dev/null 2>&1 \
        || die "no jsp/passkey_*.jsp next to $PROG. Run it from the unpacked release bundle."
}

# ---------------------------------------------------------------- the node

# NPA_ALLOW_NONROOT=1 is only for testing the script against a scratch directory.
check_root() {
    if [ "$DRY_RUN" = 0 ] && [ "$(id -u)" != 0 ] && [ "${NPA_ALLOW_NONROOT:-}" != 1 ]; then
        die "run as root (or try --dry-run first)"
    fi
}

check_node() {
    [ -d "$NIDP_DIR/WEB-INF/lib" ] && [ -d "$NIDP_DIR/jsp" ] \
        || die "$NIDP_DIR doesn't look like the Identity Server webapp (no WEB-INF/lib or jsp). Is this an Identity Server node? Use --nidp-dir if it lives elsewhere."
    if [ "$FORCE" = 0 ]; then
        [ -f "$NIDP_DIR/WEB-INF/lib/nidp.jar" ] \
            || die "$NIDP_DIR/WEB-INF/lib/nidp.jar not found, so this isn't an Identity Server node (--force to skip this check)"
        have_service \
            || die "no novell-idp service (init script or systemd unit), so this isn't an Identity Server node (--force to skip this check)"
    fi
    id "$OWNER_USER" >/dev/null 2>&1 || die "user $OWNER_USER doesn't exist (--owner to change it)"
}

have_service() {
    [ -x /etc/init.d/novell-idp ] && return 0
    command -v systemctl >/dev/null 2>&1 && systemctl cat novell-idp.service >/dev/null 2>&1
}

restart_hint() {
    say "Restart the Identity Server to load the jar: run this again with --restart, or"
    say "/etc/init.d/novell-idp restart (systemctl restart novell-idp.service)."
}

restart_idp() {
    say ""
    say "Restarting the Identity Server (this takes about a minute):"
    if command -v systemctl >/dev/null 2>&1 && systemctl cat novell-idp.service >/dev/null 2>&1; then
        run systemctl restart novell-idp.service
    elif [ -x /etc/init.d/novell-idp ]; then
        run /etc/init.d/novell-idp restart
    else
        die "no novell-idp service to restart; restart the Identity Server yourself"
    fi
    [ "$DRY_RUN" = 1 ] || say "Check $LOG_HINT for errors, and the server's health in Administration Console."
}

# ---------------------------------------------------------------- backups

BACKUP_DIR=

# Creates the backup directory for this run (once) and records what it's for.
start_backup() {
    local op=$1
    [ -n "$BACKUP_DIR" ] && return 0
    local ts n=1
    ts=$(date +%Y%m%d-%H%M%S)
    BACKUP_DIR=$BACKUP_ROOT/$ts
    while [ -e "$BACKUP_DIR" ]; do n=$((n + 1)); BACKUP_DIR=$BACKUP_ROOT/$ts-$n; done
    say ""
    if [ "$DRY_RUN" = 1 ]; then
        say "Would back up to $BACKUP_DIR:"
    else
        say "Backing up to $BACKUP_DIR:"
        mkdir -p "$BACKUP_DIR/files"
    fi
    if [ "$DRY_RUN" = 0 ]; then
        chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR"
        {
            printf 'op=%s\n' "$op"
            printf 'date=%s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
            printf 'host=%s\n' "$(hostname 2>/dev/null || echo unknown)"
            printf 'nidp_dir=%s\n' "$NIDP_DIR"
            printf 'bundle_version=%s\n' "$BUNDLE_VERSION"
            printf 'installed_before=%s\n' "$(installed_version)"
        } > "$BACKUP_DIR/meta"
        : > "$BACKUP_DIR/absent.list"
        : > "$BACKUP_DIR/saved.list"
        [ -f "$INSTALLED_LIST" ] && cp -p "$INSTALLED_LIST" "$BACKUP_DIR/installed.list.before"
    fi
    return 0
}

# Saves the current copy of a relative path, or notes that it didn't exist.
backup_file() {
    local rel=$1 dst=$NIDP_DIR/$1
    if [ -e "$dst" ]; then
        say "  save     $rel"
        [ "$DRY_RUN" = 1 ] && return 0
        mkdir -p "$BACKUP_DIR/files/$(dirname "$rel")"
        cp -p "$dst" "$BACKUP_DIR/files/$rel"
        printf '%s\n' "$rel" >> "$BACKUP_DIR/saved.list"
    else
        say "  note     $rel didn't exist"
        [ "$DRY_RUN" = 1 ] || printf '%s\n' "$rel" >> "$BACKUP_DIR/absent.list"
    fi
}

meta_value() { sed -n "s/^$2=//p" "$1/meta" 2>/dev/null | head -n 1; }

list_backups() {
    if [ ! -d "$BACKUP_ROOT" ]; then
        say "No backups in $BACKUP_ROOT."
        return 0
    fi
    local d found=0
    printf '%-20s %-10s %-26s %-16s %s\n' ID OPERATION DATE BEFORE "BUNDLE"
    for d in "$BACKUP_ROOT"/*/; do
        [ -f "$d/meta" ] || continue
        found=1
        printf '%-20s %-10s %-26s %-16s %s\n' "$(basename "$d")" "$(meta_value "$d" op)" \
            "$(meta_value "$d" date)" "$(meta_value "$d" installed_before)" "$(meta_value "$d" bundle_version)"
    done
    [ "$found" = 1 ] || say "No backups in $BACKUP_ROOT."
}

# ---------------------------------------------------------------- what's installed

installed_version() {
    if [ -f "$INSTALLED_LIST" ]; then
        sed -n 's/^# version=//p' "$INSTALLED_LIST" | head -n 1
    elif [ -f "$NIDP_DIR/$JAR_REL" ]; then
        echo "untracked"
    else
        echo "none"
    fi
}

# Relative paths a previous install recorded, one per line.
previously_installed() {
    [ -f "$INSTALLED_LIST" ] && grep -v '^#' "$INSTALLED_LIST" | grep -v '^$' || true
}

# Other copies of the jar (versioned names from manual copies) that would also be on the classpath.
stray_jars() {
    local f
    for f in "$NIDP_DIR"/WEB-INF/lib/nam-passkey-auth*.jar; do
        [ -f "$f" ] || continue
        [ "WEB-INF/lib/$(basename "$f")" = "$JAR_REL" ] || printf 'WEB-INF/lib/%s\n' "$(basename "$f")"
    done
}

write_installed_list() {
    [ "$DRY_RUN" = 1 ] && return 0
    mkdir -p "$BACKUP_ROOT"
    chmod 700 "$BACKUP_ROOT"
    {
        printf '# version=%s\n' "$BUNDLE_VERSION"
        printf '# installed=%s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
        bundle_files
    } > "$INSTALLED_LIST"
}

# ---------------------------------------------------------------- install

# "new", "changed", "perms" (same content, wrong owner/mode) or "same".
compare_file() {
    local src=$1 dst=$2
    [ -e "$dst" ] || { echo new; return; }
    cmp -s "$src" "$dst" || { echo changed; return; }
    [ "$(file_meta "$dst")" = "$OWNER $FILE_MODE" ] || { echo perms; return; }
    echo same
}

# Copies beside the target, sets owner and mode, then renames into place,
# so a running Tomcat never sees a half-written file.
copy_into_place() {
    local src=$1 dst=$2 tmp
    tmp="$(dirname "$dst")/.$(basename "$dst").passkey-tmp.$$"
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] copy %s -> %s (%s, mode %s)\n' "$src" "$dst" "$OWNER" "$FILE_MODE"
        return 0
    fi
    printf '  + copy %s -> %s (%s, mode %s)\n' "$src" "$dst" "$OWNER" "$FILE_MODE"
    if ! { cp "$src" "$tmp" && chown "$OWNER" "$tmp" && chmod "$FILE_MODE" "$tmp" && mv -f "$tmp" "$dst"; }; then
        rm -f "$tmp"
        die "couldn't install $dst; the files changed so far can be put back with --rollback"
    fi
}

# Like copy_into_place, but keeps the owner and mode the backup recorded.
restore_into_place() {
    local src=$1 dst=$2 tmp
    tmp="$(dirname "$dst")/.$(basename "$dst").passkey-tmp.$$"
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] restore %s -> %s\n' "$src" "$dst"
        return 0
    fi
    printf '  + restore %s -> %s\n' "$src" "$dst"
    mkdir -p "$(dirname "$dst")"
    if ! { cp -p "$src" "$tmp" && mv -f "$tmp" "$dst"; }; then
        rm -f "$tmp"
        die "couldn't restore $dst"
    fi
}

selinux_relabel() {
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then
        run restorecon "$@"
    fi
}

do_install() {
    check_bundle
    check_root
    check_node

    say "Bundle:    nam-passkey-auth $BUNDLE_VERSION ($BUNDLE_DIR)"
    say "Webapp:    $NIDP_DIR"
    say "Installed: $(installed_version)"
    say ""

    local rel src dst state plan="" stale="" wanted
    wanted=$(bundle_files)
    local n_new=0 n_changed=0 n_perms=0 n_same=0 n_remove=0
    while IFS= read -r rel; do
        src=$(bundle_source "$rel")
        dst=$NIDP_DIR/$rel
        state=$(compare_file "$src" "$dst")
        case "$state" in
            new)     n_new=$((n_new + 1));         say "  add      $rel" ;;
            changed) n_changed=$((n_changed + 1)); say "  replace  $rel" ;;
            perms)   n_perms=$((n_perms + 1));     say "  fix      $rel (owner/mode is $(file_meta "$dst"))" ;;
            same)    n_same=$((n_same + 1));       say "  ok       $rel" ;;
        esac
        plan="$plan$state $rel
"
    done <<EOF
$(bundle_files)
EOF

    # Files a previous version installed that this one doesn't ship, and stray jar copies.
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        in_lines "$rel" "$wanted" && continue
        [ -e "$NIDP_DIR/$rel" ] || continue
        in_lines "$rel" "$stale" && continue
        stale="$stale$rel
"
        n_remove=$((n_remove + 1))
        say "  remove   $rel (no longer part of the bundle)"
    done <<EOF
$(previously_installed)
$(stray_jars)
EOF

    if [ $((n_new + n_changed + n_perms + n_remove)) = 0 ]; then
        say ""
        say "Nothing to change: version $BUNDLE_VERSION is already installed."
        write_installed_list
        [ "$RESTART" = 1 ] && restart_idp
        return 0
    fi

    start_backup install
    while IFS=' ' read -r state rel; do
        [ -n "$rel" ] || continue
        case "$state" in changed|new|perms) backup_file "$rel" ;; esac
    done <<EOF
$plan
EOF
    while IFS= read -r rel; do
        [ -n "$rel" ] && backup_file "$rel"
    done <<EOF
$stale
EOF

    say ""
    say "Installing:"
    local touched=""
    while IFS=' ' read -r state rel; do
        [ -n "$rel" ] || continue
        dst=$NIDP_DIR/$rel
        case "$state" in
            new|changed) copy_into_place "$(bundle_source "$rel")" "$dst"; touched="$touched $dst" ;;
            perms)       run chown "$OWNER" "$dst"; run chmod "$FILE_MODE" "$dst" ;;
        esac
    done <<EOF
$plan
EOF
    while IFS= read -r rel; do
        [ -n "$rel" ] && run rm -f "$NIDP_DIR/$rel"
    done <<EOF
$stale
EOF
    # shellcheck disable=SC2086
    [ -n "$touched" ] && selinux_relabel $touched
    write_installed_list

    say ""
    if [ "$DRY_RUN" = 1 ]; then
        say "Dry run: nothing was changed."
    else
        say "Installed nam-passkey-auth $BUNDLE_VERSION. Backup: $BACKUP_DIR"
    fi
    if [ "$RESTART" = 1 ]; then
        restart_idp
    elif [ $((n_new + n_changed + n_remove)) -gt 0 ]; then
        restart_hint
    fi
}

# ---------------------------------------------------------------- uninstall

do_uninstall() {
    check_root
    check_node

    local rel targets=""
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        [ -e "$NIDP_DIR/$rel" ] || continue
        in_lines "$rel" "$targets" && continue
        targets="$targets$rel
"
    done <<EOF
$(bundle_files 2>/dev/null || true)
$(previously_installed)
$(stray_jars)
EOF

    if [ -z "$targets" ]; then
        say "Nothing to remove: the passkey class isn't installed in $NIDP_DIR."
        return 0
    fi

    say "Removing from $NIDP_DIR:"
    printf '%s' "$targets" | sed 's/^/  /'
    start_backup uninstall
    while IFS= read -r rel; do
        [ -n "$rel" ] && backup_file "$rel"
    done <<EOF
$targets
EOF
    say ""
    while IFS= read -r rel; do
        [ -n "$rel" ] && run rm -f "$NIDP_DIR/$rel"
    done <<EOF
$targets
EOF
    run rm -f "$INSTALLED_LIST"

    say ""
    [ "$DRY_RUN" = 1 ] && say "Dry run: nothing was changed." || say "Removed. Backup: $BACKUP_DIR"
    say "Any Class, Method or Contract in Administration Console that uses"
    say "com.pointbluetech.nam.login.passkey.PasskeyAuthClass now fails to load; remove them too."
    [ "$RESTART" = 1 ] && restart_idp
    return 0
}

# ---------------------------------------------------------------- rollback

do_rollback() {
    check_root
    check_node

    local src_dir
    if [ -n "$ROLLBACK_ID" ]; then
        src_dir=$BACKUP_ROOT/$ROLLBACK_ID
        [ -f "$src_dir/meta" ] || die "no backup $ROLLBACK_ID in $BACKUP_ROOT (see --list-backups)"
    else
        local d
        src_dir=
        for d in "$BACKUP_ROOT"/*/; do
            [ -f "$d/meta" ] || continue
            [ "$(meta_value "$d" op)" = rollback ] && continue
            src_dir=${d%/}
        done
        [ -n "$src_dir" ] || die "no install or uninstall backups in $BACKUP_ROOT"
    fi
    [ "$(meta_value "$src_dir" nidp_dir)" = "$NIDP_DIR" ] \
        || warn "backup was taken from $(meta_value "$src_dir" nidp_dir), restoring into $NIDP_DIR"

    say "Rolling back to the state before $(meta_value "$src_dir" op) of $(meta_value "$src_dir" date)"
    say "(backup $(basename "$src_dir"); version then: $(meta_value "$src_dir" installed_before))"
    say ""

    local rel restore="" remove=""
    [ -f "$src_dir/saved.list" ] && [ -f "$src_dir/absent.list" ] \
        || die "backup $(basename "$src_dir") is incomplete (no saved.list or absent.list)"
    restore=$(grep -v '^$' "$src_dir/saved.list" || true)
    remove=$(grep -v '^$' "$src_dir/absent.list" || true)
    while IFS= read -r rel; do
        [ -z "$rel" ] || [ -f "$src_dir/files/$rel" ] || die "backup $(basename "$src_dir") lists $rel but doesn't hold it"
    done <<EOF
$restore
EOF
    if [ -z "$restore" ] && [ -z "$remove" ]; then
        say "That backup holds no files; nothing to do."
        return 0
    fi
    printf '%s\n' "$restore" | sed '/^$/d; s/^/  restore  /'
    printf '%s\n' "$remove" | sed '/^$/d; s/^/  remove   /'

    start_backup rollback
    while IFS= read -r rel; do
        [ -n "$rel" ] && backup_file "$rel"
    done <<EOF
$restore
$remove
EOF
    say ""
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        restore_into_place "$src_dir/files/$rel" "$NIDP_DIR/$rel"
    done <<EOF
$restore
EOF
    while IFS= read -r rel; do
        [ -n "$rel" ] && run rm -f "$NIDP_DIR/$rel"
    done <<EOF
$remove
EOF
    if [ -f "$src_dir/installed.list.before" ]; then
        run cp -p "$src_dir/installed.list.before" "$INSTALLED_LIST"
    else
        run rm -f "$INSTALLED_LIST"
    fi

    say ""
    [ "$DRY_RUN" = 1 ] && say "Dry run: nothing was changed." || say "Rolled back. Backup of what was replaced: $BACKUP_DIR"
    if [ "$RESTART" = 1 ]; then
        restart_idp
    else
        restart_hint
    fi
}

# ---------------------------------------------------------------- status

jar_version() {
    command -v unzip >/dev/null 2>&1 || { echo "?"; return; }
    unzip -p "$1" META-INF/MANIFEST.MF 2>/dev/null | tr -d '\r' \
        | sed -n 's/^Implementation-Version: //p' | head -n 1
}

do_status() {
    check_bundle
    [ -d "$NIDP_DIR" ] || die "$NIDP_DIR not found (use --nidp-dir)"
    say "Bundle:    $BUNDLE_VERSION ($BUNDLE_DIR)"
    say "Installed: $(installed_version) (from $INSTALLED_LIST)"
    [ -f "$NIDP_DIR/$JAR_REL" ] && say "Jar:       Implementation-Version $(jar_version "$NIDP_DIR/$JAR_REL")"
    say ""
    local rel src dst state diff=0
    while IFS= read -r rel; do
        src=$(bundle_source "$rel")
        dst=$NIDP_DIR/$rel
        if [ ! -e "$dst" ]; then
            state=missing; diff=1
        elif ! cmp -s "$src" "$dst"; then
            state=differs; diff=1
        elif [ "$(file_meta "$dst")" != "$OWNER $FILE_MODE" ]; then
            state="same, but $(file_meta "$dst")"; diff=1
        else
            state=same
        fi
        printf '  %-40s %s\n' "$rel" "$state"
    done <<EOF
$(bundle_files)
EOF
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        diff=1
        printf '  %-40s %s\n' "$rel" "extra copy of the jar: remove it (install does)"
    done <<EOF
$(stray_jars)
EOF
    say ""
    if [ "$diff" = 0 ]; then
        say "The installed files match this bundle."
        say "Running Tomcat loads the jar at startup: if it was replaced since, restart the Identity Server."
    else
        say "The installed files don't match this bundle; $PROG --dry-run shows what install would do."
    fi
}

# ---------------------------------------------------------------- main

case "$ACTION" in
    install)      do_install ;;
    uninstall)    do_uninstall ;;
    rollback)     do_rollback ;;
    status)       do_status ;;
    list-backups) list_backups ;;
esac
