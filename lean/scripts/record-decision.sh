#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 PHASE DECISION WHY EVIDENCE RESULT" >&2
  exit 2
fi

root="$(git rev-parse --show-toplevel)"
log="${root}/lean/decisions.tsv"

sanitize() {
  local value="$1"
  value="${value//$'\t'/ }"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  case "${value}" in
    [=+@-]*) value="'${value}" ;;
  esac
  printf '%s' "${value}"
}

if [[ ! -e "${log}" ]]; then
  printf 'ts\tphase\tdecision\twhy\tevidence\tresult\n' > "${log}"
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  "$(sanitize "$1")" \
  "$(sanitize "$2")" \
  "$(sanitize "$3")" \
  "$(sanitize "$4")" \
  "$(sanitize "$5")" >> "${log}"
