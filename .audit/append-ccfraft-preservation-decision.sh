#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: $0 <phase> <decision> <why> <evidence> <result>" >&2
  exit 2
fi

log="$(dirname "$0")/ccfraft-preservation-refactor.tsv"

sanitize() {
  local value="$1"
  value="${value//$'\t'/ }"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  case "$value" in
    [=+@-]*) value="'$value" ;;
  esac
  printf '%s' "$value"
}

if [[ ! -f "$log" ]]; then
  printf 'ts\tphase\tdecision\twhy\tevidence\tresult\n' >"$log"
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  "$(sanitize "$1")" \
  "$(sanitize "$2")" \
  "$(sanitize "$3")" \
  "$(sanitize "$4")" \
  "$(sanitize "$5")" >>"$log"
