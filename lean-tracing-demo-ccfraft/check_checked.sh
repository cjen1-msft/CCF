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

nice -n 10 lake build ControlActionAudit EncoderAudit encode_trace \
  Shared.SmtConditionalFixtureMain \
  MachineGenerated.ControlTraceScalingMain \
  MachineGenerated.SymbolicAudit \
  MachineGenerated.SymbolicMessageSummaryTests \
  MachineGenerated.TraceStateObservationTests \
  MachineGenerated.SymbolicTraceObservationTests \
  MachineGenerated.BoundedSymbolicTraceTests \
  MachineGenerated.SymbolicTraceCertificateTests \
  MachineGenerated.SymbolicTraceOutputTests \
  Shared.SymbolicTraceTests Shared.SymbolicNamedTests Shared.SymbolicNamedScalingTests \
  Shared.SymbolicContainerScalingTests
nice -n 10 lake env lean --run Shared/SymbolicContainerScalingTests.lean
nice -n 10 lake env lean --run Shared/SymbolicNamedTests.lean "$CVC5"
nice -n 10 lake env lean --run Shared/SymbolicNamedScalingTests.lean
nice -n 10 lake env lean --run MachineGenerated/SymbolicTraceOutputTests.lean "$CVC5"
nice -n 10 python3 -m unittest -v \
  tests.test_replication_encoding \
  tests.test_control_encoding \
  tests.test_core_refinement \
  tests.test_explorer.ExplorerTests \
  tests.test_smt_scalar_encoding \
  tests.test_solver \
  tests.test_symbolic_encoding \
  tests.test_symbolic_causality \
  tests.test_symbolic_trace_decoding \
  tests.test_raw_normalization \
  tests.test_leader_writes \
  tests.test_client_request_encoding \
  tests.test_template_client_requests

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
