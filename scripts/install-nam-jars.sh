#!/usr/bin/env bash
# Installs the IDP jars from reference/ into the local Maven repository so the
# build can use them as "provided" dependencies. Re-run after replacing the jars
# with ones from a different IDP version (and bump NAM_VERSION to match pom.xml).
set -euo pipefail

NAM_VERSION="${NAM_VERSION:-5.1.3}"
REF_DIR="$(cd "$(dirname "$0")/.." && pwd)/reference"

# "mail" is javax.mail as shipped with NAM (mail-1.5.0-b01.jar), installed under a stable name
for jar in nidp NAMCommon jcc nmasclient ldap nam-email-client-core nam-email-client-config-nidp nam-email-client-config-xsd mail; do
    case "$jar" in
        mail) file=mail-1.5.0-b01 ;;
        *) file="$jar" ;;
    esac
    if [[ ! -f "$REF_DIR/$file.jar" ]]; then
        echo "Missing $REF_DIR/$file.jar - copy it from /opt/novell/nam/idp/webapps/nidp/WEB-INF/lib" >&2
        exit 1
    fi
    mvn -q install:install-file \
        -Dfile="$REF_DIR/$file.jar" \
        -DgroupId=com.novell.nam \
        -DartifactId="$jar" \
        -Dversion="$NAM_VERSION" \
        -Dpackaging=jar \
        -DgeneratePom=true
    echo "Installed com.novell.nam:$jar:$NAM_VERSION"
done
