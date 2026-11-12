#!/bin/sh
# Renders every diagram in docs/diagrams/passkey-flows.flow to docs/diagrams/<id>.svg.
# Needs the FlowDiagram command-line tool, fdiag, on the PATH.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/docs/diagrams/passkey-flows.flow"

command -v fdiag >/dev/null 2>&1 || { echo "fdiag (FlowDiagram) isn't on the PATH" >&2; exit 1; }

fdiag validate "$SOURCE"
fdiag list "$SOURCE" | cut -f1 | while read -r id; do
    fdiag render "$SOURCE" --diagram "$id" -o "$ROOT/docs/diagrams/$id.svg"
    echo "docs/diagrams/$id.svg"
done
