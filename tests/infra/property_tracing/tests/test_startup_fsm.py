# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unified node-startup property test.

A single ``NodeStartupFSM`` models both the start and joiner lifecycles
described in ``doc/operations/start_network.rst``.  The FSM is driven by
log markers that map onto a subset of ``ccf::NodeStartupState`` from
``include/ccf/node_startup_state.h``, but with the role-discriminating
split made directly off the configuration dump so the path is committed
as early as possible.

State diagram (intentionally asymmetric)::

    UNINITIALISED -- '"type": "Start"' --> CREATING_SERVICE
    UNINITIALISED -- '"type": "Join"'  --> PENDING_JOIN

    CREATING_SERVICE -- 'Service open at seqno N'           --> SERVICE_OPEN
    PENDING_JOIN     -- 'Node has now joined the network'   --> PART_OF_NETWORK
    PART_OF_NETWORK  -- 'Service open at seqno N'           --> SERVICE_OPEN

The asymmetry is deliberate.  Start nodes call ``sm.advance(partOfNetwork)``
silently inside an async task scheduled by ``create_and_send_boot_request``
(``src/node/node_state.h:1536``); no ``LOG_*`` line in ``node_state.h``
strictly post-dates that advance while remaining absent from joiner logs
prior to ``Service open at seqno`` -- candidates inside ``node_state.h``
either pre-date the advance (e.g.\\ ``Created new node`` at line 993) or
fire on joiners too via the same governance hooks (e.g.\\ ``[global]
Accepting network connections`` at line 2907 races with ``Service open at
seqno`` on joiners with no ordering guarantee).  Joiners by contrast emit
``Node has now joined the network`` (line 1290) immediately after their
``sm.advance(partOfNetwork)`` (line 1281), giving an observable witness.
The FSM models what the logs actually expose and does not invent a
start-path PoN marker that the system does not emit.

Recover is detected (``"type": "Recover"`` in the config) and rejected as
out of scope: the recover lifecycle goes via ``readingPublicLedger`` /
``partOfPublicNetwork`` / ``readingPrivateLedger`` and is not modelled.
"""

import re
from enum import Enum, auto
from pathlib import Path

import pytest

from log_serialisation import CCFTTYLogSource
from property_utils import PropertyViolation, StateMachine, evaluate


DATA_DIR = Path(__file__).resolve().parent / "data" / "startup_fsm"


# Marker patterns matched against the joined message text of each log entry.
#
# The config dump emits the start-type as a top-level JSON field.  We accept
# any of the three valid values; a nested ``"type": "THIM"`` field appears
# elsewhere in the same dump but is excluded by anchoring on the value set.
_RE_CONFIG_TYPE = re.compile(r'"type":\s*"(?P<role>Start|Join|Recover)"')
_RE_JOINED = re.compile(
    r"Node has now joined the network as node n\[[0-9a-f]{64}\]"
)
_RE_SERVICE_OPEN = re.compile(r"Service open at seqno \d+")

_FILTER_REGEXES = (
    _RE_CONFIG_TYPE,
    _RE_JOINED,
    _RE_SERVICE_OPEN,
)


def _msg(entry) -> str:
    return "\n".join(entry.message)


class NodeState(Enum):
    """States observable from CCF logs along the start and join paths."""

    UNINITIALISED = auto()
    CREATING_SERVICE = auto()
    PENDING_JOIN = auto()
    PART_OF_NETWORK = auto()
    SERVICE_OPEN = auto()


class Role(Enum):
    """Detected startup role.

    ``UNKNOWN`` is the initial value before the configuration dump has been
    parsed.  It commits to ``START`` or ``JOINER`` exactly once on the first
    matching ``"type"`` field.  ``RECOVER`` is detected so we can fail
    explicitly rather than silently mis-modelling the recovery path.
    """

    UNKNOWN = auto()
    START = auto()
    JOINER = auto()
    RECOVER = auto()


class NodeStartupFSM(StateMachine):
    """Models the lifecycle of a single CCF node from launch to SERVICE_OPEN."""

    def __init__(self):
        super().__init__("startup")
        self.init()

    def init(self):
        self.state = NodeState.UNINITIALISED
        self.role = Role.UNKNOWN
        self.history: list[NodeState] = [self.state]

    def filter(self, entry):
        m = _msg(entry)
        return any(r.search(m) for r in _FILTER_REGEXES)

    def _go(self, new_state: NodeState):
        self.state = new_state
        self.history.append(new_state)

    def try_advance(self, entry):
        m = _msg(entry)

        # 1. Configuration dump: commits the role and drives the first
        #    transition out of UNINITIALISED.
        type_match = _RE_CONFIG_TYPE.search(m)
        if type_match is not None:
            role_str = type_match.group("role")
            observed = {
                "Start": Role.START,
                "Join": Role.JOINER,
                "Recover": Role.RECOVER,
            }[role_str]

            if self.role is not Role.UNKNOWN:
                if self.role is not observed:
                    raise PropertyViolation(
                        f"role conflict: have {self.role.name}, "
                        f"config 'type' implies {observed.name}"
                    )
                # Idempotent re-observation of the same role: ignore.
                return

            if self.state is not NodeState.UNINITIALISED:
                raise PropertyViolation(
                    f"config 'type' seen in state {self.state.name}"
                )

            if observed is Role.RECOVER:
                raise PropertyViolation(
                    "Recover startup path is not modelled by this FSM"
                )

            self.role = observed
            self._go(
                NodeState.CREATING_SERVICE
                if observed is Role.START
                else NodeState.PENDING_JOIN
            )
            return

        # 2. Joiner terminal-of-startup: PENDING_JOIN -> PART_OF_NETWORK.
        if _RE_JOINED.search(m):
            if self.state is not NodeState.PENDING_JOIN:
                raise PropertyViolation(
                    f"'Node has now joined the network' seen in state "
                    f"{self.state.name}"
                )
            self._go(NodeState.PART_OF_NETWORK)
            return

        # 3. Service open: terminal for both paths.  Start nodes go directly
        #    CREATING_SERVICE -> SERVICE_OPEN (no observable PoN marker on
        #    the start path; see module docstring).  Joiners go
        #    PART_OF_NETWORK -> SERVICE_OPEN.
        if _RE_SERVICE_OPEN.search(m):
            if self.state is NodeState.CREATING_SERVICE:
                self._go(NodeState.SERVICE_OPEN)
                return
            if self.state is NodeState.PART_OF_NETWORK:
                self._go(NodeState.SERVICE_OPEN)
                return
            raise PropertyViolation(
                f"'Service open at seqno' seen in state {self.state.name}"
            )

    def finalise(self):
        if self.state is not NodeState.SERVICE_OPEN:
            raise PropertyViolation(
                f"node did not reach SERVICE_OPEN "
                f"(final state {self.state.name}, role {self.role.name})"
            )


# Each fixture: log file, expected detected role, expected history.
_FIXTURES = [
    pytest.param(
        "node0.out",
        Role.START,
        [
            NodeState.UNINITIALISED,
            NodeState.CREATING_SERVICE,
            NodeState.SERVICE_OPEN,
        ],
        id="node0-start",
    ),
    pytest.param(
        "node1.out",
        Role.JOINER,
        [
            NodeState.UNINITIALISED,
            NodeState.PENDING_JOIN,
            NodeState.PART_OF_NETWORK,
            NodeState.SERVICE_OPEN,
        ],
        id="node1-join",
    ),
    pytest.param(
        "node2.out",
        Role.JOINER,
        [
            NodeState.UNINITIALISED,
            NodeState.PENDING_JOIN,
            NodeState.PART_OF_NETWORK,
            NodeState.SERVICE_OPEN,
        ],
        id="node2-join",
    ),
]


def _run(log_name: str) -> tuple[NodeStartupFSM, set, dict, dict]:
    source = CCFTTYLogSource(str(DATA_DIR / log_name))
    fsm = NodeStartupFSM()
    successes, repro_failures, non_repro_failures = evaluate([fsm], source)
    return fsm, successes, repro_failures, non_repro_failures


@pytest.mark.parametrize("log_name,expected_role,expected_history", _FIXTURES)
def test_reaches_service_open(log_name, expected_role, expected_history):
    fsm, successes, repro, non_repro = _run(log_name)
    assert successes == {fsm}, (
        f"{log_name}: expected success, got "
        f"repro={repro} non_repro={non_repro}"
    )
    assert fsm.state is NodeState.SERVICE_OPEN


@pytest.mark.parametrize("log_name,expected_role,expected_history", _FIXTURES)
def test_role_detected(log_name, expected_role, expected_history):
    fsm, *_ = _run(log_name)
    assert fsm.role is expected_role, (
        f"{log_name}: expected role {expected_role.name}, got {fsm.role.name}"
    )


@pytest.mark.parametrize("log_name,expected_role,expected_history", _FIXTURES)
def test_state_history(log_name, expected_role, expected_history):
    fsm, *_ = _run(log_name)
    assert fsm.history == expected_history, (
        f"{log_name}: expected history {[s.name for s in expected_history]}, "
        f"got {[s.name for s in fsm.history]}"
    )


# --- Synthetic-log failure-path tests ----------------------------------------

def _line(ts_us: int, msg: str) -> str:
    """Synthesise a single CCF TTY log line with monotonically advancing time."""
    secs = 42 + ts_us // 1_000_000
    micros = ts_us % 1_000_000
    ts = f"2026-04-22T13:29:{secs:02d}.{micros:06d}Z"
    return f"{ts} 0   [info ] src/node/node_state.h:1 | {msg}\n"


def _synth_log(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "synth.out"
    p.write_text("".join(lines))
    return p


def _run_synth(log_path: Path) -> tuple[NodeStartupFSM, set, dict, dict]:
    source = CCFTTYLogSource(str(log_path))
    fsm = NodeStartupFSM()
    successes, repro, non_repro = evaluate([fsm], source)
    return fsm, successes, repro, non_repro


def test_truncated_start_log_fails_finalise(tmp_path):
    """Start node identified but never reaches SERVICE_OPEN."""
    log = _synth_log(
        tmp_path,
        [
            _line(0, '"type": "Start"'),
            # Missing Accepting-network-connections and Service-open.
        ],
    )
    fsm, successes, repro, _ = _run_synth(log)
    assert successes == set()
    assert fsm in repro
    _, exc = repro[fsm]
    assert "did not reach SERVICE_OPEN" in str(exc)
    assert fsm.state is NodeState.CREATING_SERVICE


def test_truncated_join_log_fails_finalise(tmp_path):
    """Join node identified but never reaches SERVICE_OPEN."""
    log = _synth_log(
        tmp_path,
        [
            _line(0, '"type": "Join"'),
            # Missing Node-has-joined and Service-open.
        ],
    )
    fsm, successes, repro, _ = _run_synth(log)
    assert successes == set()
    assert fsm in repro
    _, exc = repro[fsm]
    assert "did not reach SERVICE_OPEN" in str(exc)
    assert fsm.state is NodeState.PENDING_JOIN


def test_contradictory_role_markers_fail(tmp_path):
    """Two config dumps with conflicting roles."""
    log = _synth_log(
        tmp_path,
        [
            _line(0, '"type": "Start"'),
            _line(1_000, '"type": "Join"'),
        ],
    )
    fsm, successes, repro, _ = _run_synth(log)
    assert successes == set()
    assert fsm in repro
    _, exc = repro[fsm]
    assert "role conflict" in str(exc)


def test_recover_role_rejected(tmp_path):
    """Recover startup path is detected and explicitly rejected."""
    log = _synth_log(
        tmp_path,
        [
            _line(0, '"type": "Recover"'),
        ],
    )
    fsm, successes, repro, _ = _run_synth(log)
    assert successes == set()
    assert fsm in repro
    _, exc = repro[fsm]
    assert "Recover" in str(exc)


def test_marker_out_of_order_fails(tmp_path):
    """Service-open arrives before any role marker."""
    log = _synth_log(
        tmp_path,
        [
            _line(0, "Service open at seqno 19"),
            _line(1_000, '"type": "Start"'),
        ],
    )
    fsm, successes, repro, _ = _run_synth(log)
    assert successes == set()
    assert fsm in repro
    _, exc = repro[fsm]
    assert "Service open" in str(exc)


def test_joined_marker_on_start_path_fails(tmp_path):
    """Start node sees the joiner-only 'Node has now joined' marker."""
    log = _synth_log(
        tmp_path,
        [
            _line(0, '"type": "Start"'),
            _line(1_000, f"Node has now joined the network as node n[{'a' * 64}]"),
        ],
    )
    fsm, successes, repro, _ = _run_synth(log)
    assert successes == set()
    assert fsm in repro
    _, exc = repro[fsm]
    assert "Node has now joined" in str(exc)
