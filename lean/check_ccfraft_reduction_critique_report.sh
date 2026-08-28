#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

script_path="$(realpath "$0")"
cd "$(dirname "$0")"

output_dir=".lake/build/reduction-critique"
check_dir="$output_dir/check-work"
audit="$output_dir/corpus-audit-v1.json"
audit_second="$check_dir/corpus-audit-v1.second.json"
report="CCFRaft/reduction-critique-report.html"
report_fixed_one="$check_dir/report-fixed-one.html"
report_fixed_two="$check_dir/report-fixed-two.html"
javascript="$check_dir/report.js"
tidy_log="$check_dir/tidy.log"
audit_script="CCFRaft/audit_reduction_corpus.py"
generator="CCFRaft/generate_reduction_critique_report.py"

cleanup() {
  rm -rf "$check_dir"
}
trap cleanup EXIT

resolve_tool() {
  local executable="$1"
  local package="$2"
  local store_path
  local store_paths=()
  if command -v "$executable" >/dev/null; then
    command -v "$executable"
    return
  fi
  mapfile -t store_paths < <(
    nix build --no-link --print-out-paths "nixpkgs#$package"
  )
  for store_path in "${store_paths[@]}"; do
    if [[ -x "$store_path/bin/$executable" ]]; then
      printf '%s/bin/%s\n' "$store_path" "$executable"
      return
    fi
  done
  echo "Nix package $package does not contain $executable" >&2
  return 1
}

check_diff() {
  local path="$1"
  local output
  local status
  set +e
  output="$(git diff --no-index --check /dev/null "$path" 2>&1)"
  status="$?"
  set -e
  if [[ "$status" -gt 1 || -n "$output" ]]; then
    printf '%s\n' "$output" >&2
    echo "diff check failed for $path" >&2
    exit 1
  fi
}

mkdir -p "$check_dir"

python3 "$audit_script"
python3 "$audit_script" --output "$audit_second"
cmp "$audit" "$audit_second"

python3 "$generator"
python3 "$generator" \
  --output "$report_fixed_one" \
  --generated-at "2000-01-01T00:00:00Z"
python3 "$generator" \
  --output "$report_fixed_two" \
  --generated-at "2001-01-01T00:00:00Z"

PYTHONPYCACHEPREFIX="$check_dir/pycache" python3 -m py_compile \
  "$audit_script" \
  "$generator"

black_bin="$(resolve_tool black black)"
"$black_bin" --check --quiet "$audit_script" "$generator"

shellcheck_bin="$(resolve_tool shellcheck shellcheck)"
"$shellcheck_bin" "$script_path"

python3 - \
  "$report" \
  "$report_fixed_one" \
  "$report_fixed_two" \
  "$javascript" \
  "$audit" \
  "$audit_script" \
  "$generator" \
  "$script_path" <<'PY'
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

(
    report_name,
    fixed_one_name,
    fixed_two_name,
    javascript_name,
    audit_name,
    audit_script_name,
    generator_name,
    check_script_name,
) = sys.argv[1:]
report_path = Path(report_name).resolve()
fixed_one_path = Path(fixed_one_name).resolve()
fixed_two_path = Path(fixed_two_name).resolve()
javascript_path = Path(javascript_name).resolve()
audit_path = Path(audit_name).resolve()


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = []
        self.hrefs = []
        self.tags = []
        self.title_depth = 0
        self.title_text = []
        self.script = None
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        self.tags.append(tag)
        if "id" in values:
            self.ids.append(values["id"])
        if "href" in values:
            self.hrefs.append(values["href"])
        if tag == "title":
            self.title_depth += 1
        if tag == "script":
            self.script = {
                "type": values.get("type", "").lower(),
                "src": values.get("src"),
                "text": [],
            }

    def handle_endtag(self, tag):
        if tag == "title":
            self.title_depth -= 1
        if tag == "script" and self.script is not None:
            self.scripts.append(self.script)
            self.script = None

    def handle_data(self, value):
        if self.title_depth:
            self.title_text.append(value)
        if self.script is not None:
            self.script["text"].append(value)


def parse_report(path):
    parser = ReportParser()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


def assert_ascii(path):
    value = path.read_bytes()
    bad = [byte for byte in value if byte > 0x7F]
    if bad:
        raise SystemExit(f"non-ASCII byte in {path}")


def normalize_timestamp(value):
    return re.sub(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
        "<GENERATED_AT>",
        value,
    )


def validate_url(value):
    vscode_prefix = "vscode://vscode-remote/wsl+AzureLinux3.0"
    if value.startswith(vscode_prefix):
        target = value[len(vscode_prefix) :]
        match = re.fullmatch(r"(.+):(\d+):(\d+)", target)
        path_text = match.group(1) if match else target
        path = Path(path_text)
        if not path.exists():
            raise SystemExit(f"VS Code link target is absent: {value}")
        return
    if value.startswith("https://"):
        if not re.fullmatch(
            r"https://github\.com/cjen1-msft/CCF/blob/[0-9a-f]{40}/[^#]+#L\d+",
            value,
        ):
            raise SystemExit(f"GitHub URL is not commit-pinned: {value}")
        return
    parsed = urlparse(value)
    if parsed.scheme:
        raise SystemExit(f"unsupported URL scheme: {value}")


parser = parse_report(report_path)
required_tags = {"html", "head", "body", "main", "h1", "title"}
missing_tags = required_tags - set(parser.tags)
if missing_tags:
    raise SystemExit(f"report lacks basic tags: {sorted(missing_tags)}")
if not "".join(parser.title_text).strip():
    raise SystemExit("report title is empty")
duplicates = sorted({value for value in parser.ids if parser.ids.count(value) > 1})
if duplicates:
    raise SystemExit(f"duplicate HTML IDs: {duplicates}")
required_ids = {
    "main",
    "architectureStages",
    "architectureDetail",
    "strictnessRange",
    "mappingChoices",
    "eventList",
    "eventDetail",
    "shimChoices",
    "riskList",
    "riskTable",
    "corpusTable",
    "functionBars",
    "packetBars",
    "sourceTable",
    "artifactTable",
    "report-data",
}
missing_ids = required_ids - set(parser.ids)
if missing_ids:
    raise SystemExit(f"report lacks interactive IDs: {sorted(missing_ids)}")
for href in parser.hrefs:
    if href.startswith("#"):
        if href[1:] not in parser.ids:
            raise SystemExit(f"internal link target is absent: {href}")
    else:
        validate_url(href)

executable = []
report_data = None
for script in parser.scripts:
    if script["src"]:
        raise SystemExit("report has an external script dependency")
    text = "".join(script["text"])
    if script["type"] == "application/json":
        report_data = json.loads(text)
    elif script["type"] in {"", "text/javascript", "module"}:
        executable.append(text)
if report_data is None:
    raise SystemExit("embedded report data is absent")
if not executable:
    raise SystemExit("executable report JavaScript is absent")
javascript_path.write_text("\n;\n".join(executable), encoding="utf-8")

expected_risks = {
    "total": 28,
    "severity": {"High": 12, "Medium": 16},
    "lens": {"Correctness": 10, "Maintainability": 8, "Operational": 10},
    "disposition": {"Act now": 24, "Consider": 2, "Noted": 2},
}
if report_data["riskCounts"] != expected_risks:
    raise SystemExit(f"risk counts drifted: {report_data['riskCounts']}")
aggregate = report_data["audit"]["aggregate"]
headline = {
    "scenario_count": aggregate["scenario_count"],
    "raw": aggregate["total_raw_events"],
    "preprocessed": aggregate["total_preprocessed_events"],
    "accepted": aggregate["accepted_scenario_count"],
    "accepted_events": aggregate["accepted_event_instances"],
    "accepted_percentage": aggregate["accepted_event_percentage"],
    "functions": aggregate["function_inventory_count"],
    "packets": aggregate["packet_family_count"],
    "reducer_functions": aggregate["reducer_expected_function_count"],
}
expected_headline = {
    "scenario_count": 50,
    "raw": 10092,
    "preprocessed": 9480,
    "accepted": 1,
    "accepted_events": 53,
    "accepted_percentage": 0.56,
    "functions": 19,
    "packets": 7,
    "reducer_functions": 10,
}
if headline != expected_headline:
    raise SystemExit(f"headline facts drifted: {headline}")
if len(report_data["audit"]["scenarios"]) != 50:
    raise SystemExit("corpus table does not contain 50 scenarios")
if report_data["certificate"]["projected"] != 558:
    raise SystemExit("projected field count drifted")
if report_data["certificate"]["omitted"] != 695:
    raise SystemExit("omitted field count drifted")
if report_data["certificate"]["exceptionCount"] != 9:
    raise SystemExit("exception count drifted")
for source in report_data["sources"]:
    validate_url(source["url"])
for artifact in report_data["artifacts"]:
    validate_url(artifact["url"])
validate_url(report_data["workspace"])

fixed_one = fixed_one_path.read_text(encoding="utf-8")
fixed_two = fixed_two_path.read_text(encoding="utf-8")
if normalize_timestamp(fixed_one) != normalize_timestamp(fixed_two):
    raise SystemExit("report differs beyond its generation timestamp")

for name in (
    report_name,
    audit_name,
    audit_script_name,
    generator_name,
    check_script_name,
):
    assert_ascii(Path(name))
PY

node --check "$javascript"

tidy_bin="$(resolve_tool tidy html-tidy)"
set +e
"$tidy_bin" -quiet -errors --doctype html5 "$report" \
  >"$check_dir/tidy.out" 2>"$tidy_log"
tidy_status="$?"
set -e
if [[ "$tidy_status" -ge 2 ]]; then
  cat "$tidy_log" >&2
  echo "HTML Tidy found report errors" >&2
  exit 1
fi

check_diff "$audit_script"
check_diff "$generator"
check_diff "$report"
check_diff "$script_path"
check_diff "$audit"

printf 'corpus scenarios=50 raw=10092 preprocessed=9480 accepted=1 event_coverage=0.56%%\n'
printf 'report risks=28 high=12 medium=16 scenarios=50 projected=558 omitted=695\n'
printf 'validation=python,black,shellcheck,html,node,tidy,ascii,links,determinism,diff\n'
