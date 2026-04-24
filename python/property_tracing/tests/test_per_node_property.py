# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Per-node property evaluation via a ``Generator``.

A ``PerNodeStartupGenerator`` watches the merged log stream and, on first
sight of each ``node_id``, spawns a ``_NodeScopedStartupFSM``: a
``NodeStartupFSM`` whose ``filter`` is additionally constrained to that
node's ``node_id``.  Spawned tags are ``"<base-tag>[<node_id>]"``.
"""

from pathlib import Path

from log_serialisation import CCFTTYLogSource, LogEntry, LogSource, MergeTimeSource
from property_utils import Generator, PropertyViolation, StateMachine, evaluate
from test_startup_fsm import NodeStartupFSM


DATA_DIR = Path(__file__).resolve().parent / "data" / "startup_fsm"
_LOGS = ["node0.out", "node1.out", "node2.out"]


class _NodeScopedStartupFSM(NodeStartupFSM):
    """``NodeStartupFSM`` whose ``filter`` accepts only entries from a
    single ``node_id``.  Tag is ``"<base_tag>[<node_id>]"``."""

    def __init__(self, base_tag: str, node_id: str):
        self._node_id = node_id
        # NodeStartupFSM.__init__ calls self.init(); StateMachine.__init__
        # is what binds self.tag, so call it explicitly with the namespaced
        # tag rather than relying on NodeStartupFSM's parameterless ctor.
        StateMachine.__init__(self, f"{base_tag}[{node_id}]")
        self.init()

    def filter(self, entry: LogEntry) -> bool:
        if entry.node_id != self._node_id:
            return False
        return super().filter(entry)


class PerNodeStartupGenerator(Generator):
    """Spawns one ``_NodeScopedStartupFSM`` per distinct ``node_id`` seen."""

    def __init__(self, base_tag: str = "startup"):
        super().__init__(tag=base_tag)
        self._base_tag = base_tag
        self.init()

    def init(self) -> None:
        self._seen: set[str] = set()

    def try_spawn(self, entry: LogEntry) -> list[StateMachine]:
        nid = entry.node_id
        if nid is None or nid in self._seen:
            return []
        self._seen.add(nid)
        return [_NodeScopedStartupFSM(self._base_tag, nid)]


# --- Helpers -----------------------------------------------------------------


def _node_ids() -> dict[str, str]:
    """Return ``{log_filename: node_id}`` for the three startup_fsm fixtures."""
    return {
        name: CCFTTYLogSource(str(DATA_DIR / name)).node_id for name in _LOGS
    }


def _merged_source() -> MergeTimeSource:
    sources = {name: CCFTTYLogSource(str(DATA_DIR / name)) for name in _LOGS}
    return MergeTimeSource(sources, "path")


def _tags(sms) -> set[str]:
    return {sm.tag for sm in sms}


def _by_tag(d: dict) -> dict:
    return {sm.tag: v for sm, v in d.items()}


# --- Tests -------------------------------------------------------------------


def test_all_three_nodes_succeed():
    """All three real fixtures reach SERVICE_OPEN under the merged source."""
    source = _merged_source()
    success, repro, non_repro = evaluate(
        properties=[], source=source, generators=[PerNodeStartupGenerator()]
    )

    expected = {f"startup[{nid}]" for nid in _node_ids().values()}
    assert _tags(success) == expected, (
        f"expected {expected}, got success={_tags(success)} "
        f"repro={_by_tag(repro)} non_repro={_by_tag(non_repro)}"
    )
    assert repro == {}
    assert non_repro == {}


# --- Failure-isolation: drop node1's "Service open" and expect ONLY node1 to fail.


class _DropMessageSource(LogSource):
    """Wrap a LogSource, dropping entries from a target node whose joined
    message contains a given substring.  Used to inject a synthetic
    failure into one node's stream while leaving other nodes intact.
    """

    def __init__(self, inner: LogSource, target_node_id: str, drop_substr: str):
        self._inner = inner
        self._target = target_node_id
        self._drop = drop_substr
        self._next: LogEntry | None = None

    def init(self):
        self._inner.init()
        self._next = None

    def _advance(self):
        while True:
            entry = self._inner.pop()
            if entry is None:
                self._next = None
                return
            msg = "\n".join(entry.message)
            if entry.node_id == self._target and self._drop in msg:
                continue
            self._next = entry
            return

    def peek(self):
        if self._next is None:
            self._advance()
        return self._next

    def pop(self):
        if self._next is None:
            self._advance()
        entry = self._next
        self._next = None
        return entry


def test_one_node_fails_others_succeed():
    """node1's Service-open is dropped; only node1's per-node tag must fail."""
    ids = _node_ids()
    target = ids["node1.out"]

    inner = _merged_source()
    source = _DropMessageSource(inner, target, "Service open at seqno")

    success, repro, non_repro = evaluate(
        properties=[],
        source=source,
        generators=[PerNodeStartupGenerator()],
    )

    failing_tag = f"startup[{target}]"
    surviving = {f"startup[{nid}]" for nid in ids.values()} - {failing_tag}

    assert _tags(success) == surviving, (
        f"expected only {surviving} to succeed, got success={_tags(success)}"
    )

    repro_by_tag = _by_tag(repro)
    assert failing_tag in repro_by_tag, (
        f"expected {failing_tag} in repro, got repro={list(repro_by_tag)} "
        f"non_repro={list(_by_tag(non_repro))}"
    )
    assert non_repro == {}

    entries, exc = repro_by_tag[failing_tag]
    assert "did not reach SERVICE_OPEN" in str(exc)

    # CRITICAL: the recorded failure entries must contain ONLY node1's entries.
    other_node_ids = {nid for name, nid in ids.items() if name != "node1.out"}
    for entry in entries:
        assert entry.node_id == target, (
            f"failure trace for {failing_tag} contains entry from "
            f"node_id={entry.node_id} (expected only {target}); "
            f"other nodes in fixture: {other_node_ids}"
        )


def test_pass2_respawns_deterministically():
    """Pass 2 must respawn the same failing tag.  We verify by triggering
    a failure, then checking that the failure tag actually appears in
    repro (which only happens if pass 2 re-spawned and re-failed it).
    """
    ids = _node_ids()
    target = ids["node2.out"]

    inner = _merged_source()
    source = _DropMessageSource(inner, target, "Node has now joined")

    success, repro, non_repro = evaluate(
        properties=[],
        source=source,
        generators=[PerNodeStartupGenerator()],
    )

    failing_tag = f"startup[{target}]"
    repro_by_tag = _by_tag(repro)
    # If pass 2 failed to respawn deterministically, this tag would land
    # in non_repro (failure didn't reproduce) instead of repro.
    assert failing_tag in repro_by_tag, (
        f"pass 2 did not reproduce failure for {failing_tag}: "
        f"repro={list(repro_by_tag)} non_repro={list(_by_tag(non_repro))}"
    )
    _, exc = repro_by_tag[failing_tag]
    msg = str(exc)
    assert "Service open" in msg or "did not reach SERVICE_OPEN" in msg, (
        f"unexpected violation message: {msg}"
    )


def test_unknown_node_id_does_not_spawn():
    """Entries whose ``node_id`` is ``None`` must not spawn a child."""

    class _StripNodeIdSource(LogSource):
        def __init__(self, inner: LogSource):
            self._inner = inner

        def init(self):
            self._inner.init()

        def peek(self):
            return self._inner.peek()

        def pop(self):
            entry = self._inner.pop()
            if entry is not None:
                entry.node_id = None
            return entry

    inner = CCFTTYLogSource(str(DATA_DIR / "node0.out"))
    source = _StripNodeIdSource(inner)

    success, repro, non_repro = evaluate(
        properties=[],
        source=source,
        generators=[PerNodeStartupGenerator()],
    )

    # Nothing spawned; nothing failed.
    assert success == set(), (
        f"expected no spawned children, got success={_tags(success)}"
    )
    assert repro == {}
    assert non_repro == {}


def test_spawn_then_advance_feeds_triggering_entry_to_child():
    """The entry that causes a generator to spawn a child must also be
    visible to that child via try_advance in the same iteration.

    Realised by a one-shot StateMachine that succeeds iff it observes at
    least one entry.  Because spawn fires on the very first entry of a
    single-source stream, omitting the spawning entry would leave the
    child with zero entries and finalise() would raise.
    """

    class _RequireAnyEntry(StateMachine):
        def __init__(self, tag):
            super().__init__(tag)
            self.init()

        def init(self):
            self.saw_first = False

        def filter(self, entry):
            return True

        def try_advance(self, entry):
            self.saw_first = True

        def finalise(self):
            if not self.saw_first:
                raise PropertyViolation("never saw any entry")

    class _OneShotGenerator(Generator):
        def __init__(self, base_tag: str):
            super().__init__(tag=base_tag)
            self._base_tag = base_tag
            self.init()

        def init(self):
            self._spawned = False

        def try_spawn(self, entry):
            if self._spawned or entry.node_id is None:
                return []
            self._spawned = True
            return [_RequireAnyEntry(f"{self._base_tag}[{entry.node_id}]")]

    # Build a synthetic single-entry source so the only entry IS the
    # spawning entry; spawn-then-advance is the only way the child sees
    # anything.
    class _SingleEntrySource(LogSource):
        def __init__(self, node_id: str):
            self._node_id = node_id
            self.init()

        def init(self):
            self._entry: LogEntry | None = LogEntry(
                timestamp=1, message=["only entry"], node_id=self._node_id, metadata={}
            )

        def peek(self):
            return self._entry

        def pop(self):
            e = self._entry
            self._entry = None
            return e

    nid = "nodeX" + "0" * 59
    source = _SingleEntrySource(nid)
    success, repro, non_repro = evaluate(
        properties=[], source=source, generators=[_OneShotGenerator("first")]
    )
    assert _tags(success) == {f"first[{nid}]"}, (
        f"spawn-then-advance: expected spawning entry to be visible to child; "
        f"got success={_tags(success)} repro={_by_tag(repro)}"
    )


def test_static_and_generator_coexist():
    """A static property and a generator can run side-by-side; static
    property tags are not namespaced, generator-spawned tags are."""

    class _CountEntries(StateMachine):
        def __init__(self):
            super().__init__("count")
            self.init()

        def init(self):
            self.count = 0

        def filter(self, entry):
            return True

        def try_advance(self, entry):
            self.count += 1

        def finalise(self):
            if self.count == 0:
                raise PropertyViolation("no entries observed")

    counter = _CountEntries()
    source = _merged_source()
    success, repro, non_repro = evaluate(
        properties=[counter],
        source=source,
        generators=[PerNodeStartupGenerator()],
    )

    expected_node_tags = {f"startup[{nid}]" for nid in _node_ids().values()}
    assert _tags(success) == {"count"} | expected_node_tags
    assert counter.count > 0
    assert repro == {} and non_repro == {}
