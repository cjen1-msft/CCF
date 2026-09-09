#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

script_path="$(realpath "$0")"
cd "$(dirname "$script_path")"

if ! CVC5="${CVC5:-$(command -v cvc5)}" || [[ ! -x "$CVC5" ]]; then
  echo "cvc5 is required; set CVC5 to its executable path" >&2
  exit 1
fi
export CVC5
"$CVC5" --version
command -v lake >/dev/null
mkdir -p Artifacts/checked-traces

nice -n 10 lake build ControlActionAudit EncoderAudit encode_trace
nice -n 10 python3 -m unittest -v \
  tests.test_replication_encoding \
  tests.test_leader_writes \
  tests.test_client_request_encoding.SatisfiableCertificateTests \
  tests.test_client_request_encoding.ToolchainFailureTests \
  tests.test_template_client_requests.TemplateClientRequestTests.test_distinct_names_do_not_imply_distinct_transaction_values \
  tests.test_template_client_requests.TemplateClientRequestTests.test_log_capacity_core_keeps_the_causal_action \
  tests.test_template_client_requests.TemplateClientRequestTests.test_retirement_refresh_bound_keeps_the_causal_action

status="$(
  nice -n 10 python3 validate_checked.py \
    Traces/Replication/send.json \
    Artifacts/checked-traces/replication --cvc5 "$CVC5"
)"
if [[ "$status" != "sat" ]]; then
  echo "replication fixture: expected sat, got $status" >&2
  exit 1
fi
echo "result=passed"
