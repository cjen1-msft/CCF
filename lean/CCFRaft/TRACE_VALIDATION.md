# CCF Raft implementation-trace validation

`TraceValidation.lean` checks partial CCF `raft_trace` NDJSON against the
canonical `Action`, `Enabled`, and `next` definitions in `Model.lean`. It does
not translate through TLA or run TLC.

This first slice constrains these preprocessed events:

| CCF event             | Model constraint                                                |
| --------------------- | --------------------------------------------------------------- |
| `bootstrap`           | Match the model's initial state without taking an action.       |
| `replicate`           | Match pre-action state, then append a transaction or signature. |
| `send_append_entries` | Match pre-action state and packet, then take `appendEntries`.   |
| `recv_append_entries` | Match pre-action state and queued packet, then take `receive`.  |
| `commit`              | Match pre-action state, then take `advanceCommitIndex`.         |

These events expose state before the corresponding C++ mutation. The matcher
checks post-action fields such as the replicated sequence number, sent index,
and commit target after applying the model action.

The parser projects away `execute_append_entries_sync`,
`send_append_entries_response`, `recv_append_entries_response`, and follower
`commit` records. The canonical receive action already performs their state
updates. The validator reports how many such records it ignored. Other
unsupported functions are errors.

## Run it

Build and run the validator from `lean/`:

```bash
lake build ccf-raft-trace-validator
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  /tmp/ccf-raft-witness.trace
.lake/build/bin/ccf-raft-simulator replay /tmp/ccf-raft-witness.trace
```

The optional trailing bounds are total action depth, hidden actions between
observations, and explored states. Their defaults are `64`, `6`, and `50000`.
In ordinary validation mode, an unsuccessful search that reaches any bound
returns `INCONCLUSIVE` with exit code 4 rather than rejecting the trace.

Pass `--minimize-bounds` before the optional ceilings to find the
lexicographically minimum successful bounds:

```bash
.lake/build/bin/ccf-raft-trace-validator \
  CCFRaft/traces/implementation/accepted.ndjson \
  /tmp/ccf-raft-witness.trace \
  --minimize-bounds 64 6 50000
```

The minimizer first finds the smallest total action depth, then the smallest
hidden-action gap at that depth. For that deterministic search order, the
successful run's expansion count is the exact explored-state budget. The
supplied values are ceilings, not starting guesses. If any minimization probe
exhausts the explored-state ceiling, the result is `INCONCLUSIVE`; the tool
does not claim a minimum from an incomplete probe. Depth and gap ceilings
define the minimization domain, so proving that no witness exists within either
ceiling returns `REJECT`, even though ordinary validation would conservatively
classify the same pruning as `INCONCLUSIVE`.

Run the checked examples with:

```bash
./check_ccfraft_trace_validation.sh
```

The main accepted fixture has 12 implementation observations. The validator
emits 15 exact model actions. Four hidden actions deliver AppendEntries
responses before the observed commit. `accepted-preprocessed.ndjson` also
contains the three internal response and follower-execution records emitted
around a receive. The rejected fixtures cover an unsupported commit,
post-action state reported as pre-action state, an undelivered send, and
missing required state fields.

## Bootstrap and node projection

`tests/raft_scenarios_runner.py` replaces CCF's initial configuration,
signature, and commit sequence with `bootstrap`. The retained record has
`args.idx = 2`. The Lean model starts after that prefix with empty logs, so the
parser maps implementation index 2 to model index 0 and subtracts 2 from later
ledger indices. It preserves CCF's zero sentinel for unset commit, sent, and
match indices. Any other bootstrap index is a parse error.

Opaque CCF node IDs are interned in first-seen order. The bootstrap leader maps
to model node 0. The bootstrap configuration may contain any nonempty subset
of the 15-node world, but it must contain the observed leader. The parser
stores this configuration and leader as a `Bootstrap` value.

Search, canonical replay, and checkpoint checks all use the parsed `Bootstrap`.
The validator never interprets a witness under the canonical default after
searching under a different bootstrap.

Generated witnesses start with
`bootstrap,<leader>,<member>...`. The standalone simulator parses that header
and installs the same `Bootstrap` before replay. Headerless action traces use
`defaultBootstrap` for backward compatibility.

## Search and trust boundary

The search backtracks across the whole observation sequence. A later mismatch
can make it choose a different earlier hidden path. Search is bounded by
action depth, hidden gap, and visited state count.

Transaction contents are not visible in `raft_trace`. The matcher assigns the
next fresh simulator ID instead of exploring equivalent ID permutations. The
trace simulator has 64 IDs. More than 64 ordinary replications returns
`INCONCLUSIVE`.

The search cannot invent unobserved client requests, signatures, sends, or
commits. It may insert only delivery of AppendEntries responses. Every
observed AppendEntries send must have a later matching receive, so the slice
does not accept failed, dropped, or still-undelivered sends. This restriction
is necessary because CCF logs the send record before `send_authenticated`
reports success. Pairing compares the raw wire fields before index and
bootstrap-term projection.

The model coalesces duplicate in-flight requests. The validator records when a
second observed send leaves the model queue unchanged, then checks the matching
duplicate receive as a zero-action observation. This preserves CCF traces with
repeated heartbeats without duplicating model messages.

The parser requires the state and packet fields that the C++ trace sites always
emit. It supports heartbeats and one-entry AppendEntries only. CCF batches with
more than one entry fail with a scope error instead of being approximated.

The parser and search choose a candidate witness. Acceptance then:

1. Replays every witness action with `system.applyAction`.
2. Runs the simulator's state and edge checks after each action.
3. Rechecks every observation at its recorded pre-action checkpoint.

`CertificateValid` states the corresponding exact-run and observation
constraints for an explicit `[Bootstrap]`. `ParsedCertificateValid` selects
the bootstrap from the parsed trace. `exactRunReachable` proves that any exact
witness ends in a model-reachable state. The CLI checks a concrete witness by
execution rather than generating a theorem. Kernel reduction of the 15-action
example is impractically slow, and `native_decide` is not used because the
CCFRaft axiom audit rejects `Lean.ofReduceBool`.

## Current limit

Input must start with the synthetic `bootstrap`. Election and reconfiguration
records remain future slices. The bootstrap and every later commit must name
exactly one active configuration with the same members. AppendEntries batches,
failed or undelivered sends, and traces beyond the configured search bounds
are not accepted by this slice.

The proposed replacement for preprocessing, production-window cuts, and
symbolic reconstruction is recorded in
[Grammar-safe cuts and symbolic trace alignment](../adr/0002-grammar-safe-cuts-and-symbolic-trace-alignment.md).
