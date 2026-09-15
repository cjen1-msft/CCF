# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Alignment and browser contracts. Synthetic UI fixtures are not proof evidence."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import quote

from native_explorer import aligned_rows, build_view, render_explorer
from native_origin import RawOrigin
from native_run import NativeRun
from raw_normalization import NormalizedTrace
from Shared.trace_io import loads_ndjson


def fixture() -> NativeRun:
    values = [
        {"cmd": "start_node,0"},
        {"msg": {"function": "add_configuration", "state": {"node_id": "0"}}},
        {"msg": {"function": "send_append_entries", "packet": {"idx": 2}}},
        {"cmd": "unmapped command"},
        {"msg": {"function": "later_event"}},
    ]
    records = tuple(loads_ndjson("\n".join(json.dumps(value) for value in values)))
    instructions = [
        {"kind": "changeConfiguration", "node": "0", "newConfiguration": ["0", "1"]},
        {"kind": "logLength", "node": "0", "value": 3},
        {"kind": "appendEntries", "source": "0", "destination": "1", "batchEnd": 2},
        {"kind": "logLength", "node": "0", "value": 2},
        {"kind": "commitIndex", "node": "0", "value": 0},
    ]
    sources = [[2], [2], [2, 3], [2], [5]]
    steps = [
        {
            "kind": "action" if index in (0, 2) else "observation",
            "rule": "fixture-rule",
            "provenance": [{"line": line} for line in lines],
        }
        for index, lines in enumerate(sources)
    ]
    clauses = [
        {"name": f"assertion_{index}", "expression": expression}
        for index, expression in enumerate(
            ["true", "true", "(= log_length 3)", "true", "(= log_length 2)", "true"]
        )
    ]
    groups = [
        {
            "instruction": None if index == 0 else index - 1,
            "start": index,
            "stop": index + 1,
        }
        for index in range(6)
    ]
    return NativeRun(
        document={"instructions": instructions},
        details={"groups": groups, "clauses": clauses},
        result={"status": "unsat"},
        core=frozenset({"assertion_2", "assertion_4"}),
        owners=(None, 0, 1, 2, 3, 4),
        origin=RawOrigin(records, {}, NormalizedTrace({}, (), steps, {})),
    )


class NativeExplorerViewTests(unittest.TestCase):
    def test_alignment_preserves_both_orders_and_exact_sources(self):
        run = fixture()
        view = build_view(run)
        rows = view["rows"]
        self.assertEqual([row["line"] for row in rows], [None, 1, 2, 3, 4, 5])
        items = [item for row in rows for item in row["instructions"]]
        self.assertEqual([item["index"] for item in items], [None, 0, 1, 2, 3, 4])
        self.assertEqual([item["index"] for item in rows[2]["instructions"]], [0, 1])
        self.assertEqual([item["index"] for item in rows[3]["instructions"]], [2, 3])
        self.assertEqual(rows[3]["instructions"][1]["source_lines"], [2])
        self.assertEqual(rows[4]["instructions"], [])
        self.assertEqual(
            [
                (item["index"], clause["name"])
                for item in items
                for clause in item["core"]
            ],
            [(1, "assertion_2"), (3, "assertion_4")],
        )

    def test_missing_source_is_not_silently_mapped(self):
        with self.assertRaisesRegex(ValueError, "absent raw event"):
            aligned_rows([], [{"source_lines": [1]}])

    def test_initial_domains_and_model_only_runs(self):
        run = replace(fixture(), origin=None, core=frozenset({"assertion_0"}))
        view = build_view(run)
        self.assertEqual(len(view["rows"]), 1)
        self.assertEqual(
            view["rows"][0]["instructions"][0]["core"][0]["instruction"], None
        )
        self.assertTrue(
            all(not item["source_lines"] for item in view["rows"][0]["instructions"])
        )
        self.assertIsNone(view["raw_url"])

    def test_embedding_and_source_links(self):
        run = fixture()
        malicious = "</script><script>window.injected=true</script>"
        run.document["instructions"][0]["node"] = malicious
        directory = Path("/tmp/retained run")
        document = render_explorer(run, directory)
        self.assertNotIn(malicious, document)
        self.assertIn(r"\u003c/script>", document)
        self.assertNotIn("__NATIVE_EXPLORER_DATA__", document)
        view = build_view(run, directory)
        self.assertTrue(
            view["workspace_url"].endswith(
                quote(str(Path(__file__).resolve().parents[2]))
            )
        )
        self.assertTrue(view["raw_url"].endswith("/tmp/retained%20run/raw.ndjson"))


@unittest.skipUnless(shutil.which("chromium"), "needs Chromium on PATH")
class NativeExplorerBrowserTests(unittest.TestCase):
    def browser(
        self, run: NativeRun, checks: str, *, width: int = 1440, fragment: str = ""
    ):
        with tempfile.TemporaryDirectory(
            prefix="native-explorer-browser-"
        ) as temporary:
            root = Path(temporary)
            document = render_explorer(run)
            script = """
<script>
function check(value, message) { if (!value) throw new Error(message); }
try {
  const textRange = document.createRange();
  textRange.selectNodeContents(document.querySelector("h1"));
  check(textRange.getBoundingClientRect().width > 0, "browser needs working fonts");
CHECKS
  document.title = "NATIVE_EXPLORER_PASSED";
} catch (error) { document.title = "NATIVE_EXPLORER_FAILED: " + error.message; }
</script>
""".replace("CHECKS", checks)
            page = root / "explorer.html"
            page.write_text(
                document.replace("</body>", script + "</body>"), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    "chromium",
                    "--headless",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    f"--user-data-dir={root / 'browser'}",
                    f"--window-size={width},1000",
                    "--dump-dom",
                    page.as_uri() + fragment,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            title = re.search(r"<title>(.*?)</title>", completed.stdout)
            self.assertIsNotNone(title, completed.stderr[-2000:])
            self.assertEqual(title.group(1), "NATIVE_EXPLORER_PASSED")

    def test_alignment_selection_search_and_navigation(self):
        run = fixture()
        run.document["instructions"][0][
            "node"
        ] = "</script><script>window.injected=true</script>"
        self.browser(
            run,
            """
check(!window.injected, "trace text cannot execute");
check(byId("core-only").checked, "core context is the initial view");
check(document.querySelectorAll("[data-clause]").length === 2, "only returned clauses");
check(!document.querySelector('[data-raw="4"]'), "unrelated command hidden");
check(document.querySelectorAll(".instruction-cell .card").length === 4, "expanded context retained");
function aligned(owner) {
  const middle = document.querySelector(`.instruction-cell[data-owner="${owner}"]`).getBoundingClientRect();
  const right = document.querySelector(`.core-cell[data-owner="${owner}"]`).getBoundingClientRect();
  check(Math.abs(middle.top - right.top) < 1 && Math.abs(middle.height - right.height) < 1, "shared grid alignment " + owner);
}
aligned("1"); aligned("3");
document.querySelector('[data-clause="assertion_4"]').click();
check(document.querySelector('[data-raw="2"]').classList.contains("selected"), "reordered exact source highlighted");
check(!document.querySelector('[data-raw="3"]').classList.contains("selected"), "alignment is not false provenance");
check(byId("detail").textContent.includes("(= log_length 2)"), "exact core expression");
check(byId("detail").textContent.includes("add_configuration"), "original source details");
document.querySelector('[data-raw="2"]').click();
check(document.querySelectorAll(".instruction-cell .selected").length === 4, "one-to-many and many-to-many highlighting");
byId("search").value = "assertion_4"; byId("search").dispatchEvent(new Event("input"));
check(document.querySelector('[data-raw="2"]'), "search retains earlier source");
check(document.querySelector('[data-clause="assertion_4"]'), "search retains clause");
byId("search").value = "add_configuration"; byId("search").dispatchEvent(new Event("input"));
check(document.querySelector('[data-clause="assertion_4"]'), "source search retains dependent instructions");
byId("search").value = "no-such-event"; byId("search").dispatchEvent(new Event("input"));
check(!byId("empty").hidden, "empty search explained");
byId("next").click();
check(document.querySelector(".instruction-cell .selected"), "core navigation reveals hidden target");
byId("core-only").checked = false; byId("core-only").dispatchEvent(new Event("change"));
check(document.querySelector('[data-raw="4"]'), "full trace includes unmapped commands");
document.querySelector('[data-raw="4"]').click();
check(byId("selection-note").textContent.startsWith("0 linked"), "unmapped event does not invent instruction");
const rawCard = document.querySelector('[data-raw="2"]');
rawCard.append(element("pre", "expanded raw detail\\n".repeat(80)));
aligned("1"); aligned("3");
check(byId("verdict-note").textContent.includes("not necessarily minimal"), "honest core label");
location.hash = "#assertion_4";
window.dispatchEvent(new HashChangeEvent("hashchange"));
check(byId("detail-title").textContent === "assertion_4", "history selection follows URL");
""",
        )

    def test_narrow_layout_and_deep_link(self):
        self.browser(
            fixture(),
            """
check(byId("detail-title").textContent === "assertion_4", "clause deep link");
check(byId("timeline-scroll").scrollWidth > byId("timeline-scroll").clientWidth, "narrow screen keeps shared horizontal scroll");
const left = document.querySelector('.instruction-cell[data-owner="3"]').getBoundingClientRect();
const right = document.querySelector('.core-cell[data-owner="3"]').getBoundingClientRect();
check(Math.abs(left.top - right.top) < 1, "narrow columns remain aligned");
""",
            width=600,
            fragment="#assertion_4",
        )

    def test_sat_unknown_and_initial_domains(self):
        for status in ("sat", "unknown"):
            with self.subTest(status=status):
                self.browser(
                    replace(fixture(), result={"status": status}, core=frozenset()),
                    """
check(!document.querySelector("[data-clause]"), "no stale core");
check(byId("next").disabled && byId("core-only").disabled, "unavailable core controls disabled");
check(byId("verdict-note").textContent.startsWith(data.status.toUpperCase()), "verdict remains explicit");
""",
                )
        self.browser(
            replace(fixture(), origin=None, core=frozenset({"assertion_0"})),
            """
check(document.querySelector('[data-clause="assertion_0"]'), "initial-domain core visible");
document.querySelector('[data-clause="assertion_0"]').click();
check(byId("detail").textContent.includes("initialDomains"), "initial-domain selection");
check(!document.querySelector("[data-raw]"), "Model-only run invents no raw event");
""",
        )


if __name__ == "__main__":
    unittest.main()
