# CCFRaft trace validator arena

## Decision

Candidate 5 was the base because whole-trace backtracking can revise an earlier
choice after a later mismatch. The final implementation is
`lean/CCFRaft/TraceValidation.lean`.

| Candidate                       | Mapping | Canonical authority | Ambiguity bounds | Evidence | Integration | Total |
| ------------------------------- | ------: | ------------------: | ---------------: | -------: | ----------: | ----: |
| 1. Pure Lean BFS                |       2 |                   5 |                3 |        4 |           4 |    18 |
| 2. Python BFS and Lean worker   |       4 |                   5 |                4 |        5 |           2 |    20 |
| 3. Planner and Lean certificate |       4 |                   3 |                4 |        5 |           3 |    19 |
| 4. Incremental event registry   |       3 |                   5 |                2 |        5 |           5 |    20 |
| 5. Whole-trace Lean search      |       3 |                   5 |                5 |        5 |           4 |    22 |

Mapping scores reflect the submitted prototypes, not the repaired final code.
Candidate 4 lacked CCF's bootstrap projection. Candidate 5 checked
`replicate` against post-action state even though the C++ record contains
pre-action state.

## Grafts

- Candidate 4 supplied the event registry split between preconditions,
  candidate actions, and postconditions.
- Candidate 5 supplied global backtracking, opaque node-ID interning, bootstrap
  index projection, explicit search bounds, and canonical witness replay.
- Candidate 3 supplied the checkpoint constraint shape. The final code keeps
  `ExactRun`, `checkpointsHold`, `CertificateValid`, and
  `exactRunReachable`.
- Candidate 2's narrow-authority lesson remains: search proposes actions, but
  only `system.applyAction` decides whether they are canonical transitions.

## Rejected pieces

- Candidate 3's generated theorem used `native_decide`. CCFRaft's axiom audit
  rejects `Lean.ofReduceBool`. Kernel reduction of the 15-action example did
  not finish in ten minutes, so the final CLI emits and canonically replays an
  exact witness instead of claiming a practical generated theorem.
- Candidate 2 serialized the full model state through a large Python/JSON
  worker protocol. Keeping parsing and bounded search in Lean removes that
  protocol and its second state representation.
- Candidate 4 committed greedily at each observation and could not reconsider
  an earlier match.
- Candidate 5 allowed arbitrary hidden client, send, and commit actions. The
  final search inserts only AppendEntries response deliveries.
- The first fan-out used `/tmp`; all five agents declined to write there. Those
  empty attempts supplied no evidence and were rerun under this repository.

## Repairs after cross-review

Independent review of the integrated implementation found and drove fixes for:

- C++ pre-action timing;
- failed or undelivered sends;
- required C++ state and packet fields;
- raw wire-packet pairing before projection;
- bootstrap index and configuration membership;
- prefix heartbeats and one-entry batch scope;
- semantic rejection versus bound exhaustion;
- the eight-transaction simulator limit and factorial ID search;
- duplicate in-flight heartbeats coalesced by the model.

## Evidence

From `lean/`:

```bash
./check_ccfraft_trace_validation.sh
./check_ccfraft_reconfiguration_model.sh
lake build CCFRaft
```

The trace-validation check covers accepted ordinary replication, the
runner-shaped internal records, prefix heartbeats, duplicate heartbeats, nine
replications, invalid commit, wrong event timing, undelivered send, malformed
state, raw packet mismatch, changed or stacked configurations, wrong bootstrap
index, search-bound exhaustion, and the 64-transaction capacity result.
