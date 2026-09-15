# Shared trace infrastructure

This directory contains reusable trace, expression, and solver infrastructure.
CCFRaft preprocessing stays in [reduction.py](../reduction.py), raw identifier
normalization in [raw_normalization.py](../raw_normalization.py), and model
transition adapters in `../MachineGenerated/`.

The [main README](../README.md) describes the migrated raw route, explicit
five-bound profiles, commands, and development blockers. Native symbolic
receive and end-to-end raw validation remain under development. Shared
infrastructure proofs and mocked Python tests do not establish those runs.

## Python orchestration

| Module | Responsibility |
| --- | --- |
| `trace_io.py` | Parse NDJSON while retaining original records and line numbers |
| `capture_traces.py` | Run the CCF `build/raft_driver` and collect tagged events without semantic preprocessing |
| `solver.py` | Discover cvc5, execute it, retain stdout and stderr, and read statuses and query payloads |
| `smt.py` | Add solver queries, parse named cores, restrict assertions, and reduce cores within a budget |

Capture requires an existing repository-root `build/raft_driver`; it does not
build one. `--check` compares captures without replacing fixtures.

`validate.py` delegates checked validation to `validate_checked.py`. Both use
`solver.py`; the raw runner's historical private solver names are aliases,
not implementations. The live callers do not use the retained
`../ccfraft_projection.py`.

`smt.py` does not lower model actions. It operates on SMT-LIB emitted by Lean.
Proof queries enable both proof production and cvc5's internal proof checking.
Core reduction keeps a deletion only when another check returns UNSAT.
An inconclusive check or exhausted budget prevents a complete minimality claim.
Core restriction selects assertions, not a replayable model trace.

## Lean expressions and trace composition

The explicit-entry encoder uses `Smt.lean`, `SmtOrder.lean`, `Equality.lean`,
and `Guarded.lean`. These define expression semantics, computable term ordering,
exact list equality, and guarded choices for alias-sensitive queue operations.
Distinct branch-local bindings must retain distinct names.

The symbolic-entry design uses:

| Module | Responsibility |
| --- | --- |
| `Symbolic.lean` | Typed expressions and evaluation under one assignment |
| `SymbolicData.lean`, `SymbolicFinite.lean`, `SymbolicInput.lean` | Data representations, finite domains, and symbolic input construction |
| `SymbolicNormalize.lean` | Expression normalization |
| `SymbolicNormalizeMemo.lean` | Proof-carrying normalization with shared-expression caches |
| `SymbolicSharing.lean`, `SymbolicEvalMemo.lean` | Exact typed DAG equality and assignment-local evaluation |
| `SymbolicSmt.lean` | Grouped SMT serialization and named definitions |
| `SymbolicNaming.lean` | Proved changed-field naming with field-local DAG caches |
| `SymbolicTrace.lean` | Generic action/observation composition with adapter correctness obligations |

`Symbolic.Trace.Semantics` requires bounds, enabledness, successor, and
observation correspondence. Its trace theorem composes these obligations
under the same assignment. It does not replace the model-specific obligations
in [BoundedSymbolicTrace.lean](../BoundedSymbolicTrace.lean).

The CCFRaft entry has symbolic control fields and bounded container shapes,
not a whole-state enumeration or a fabricated bootstrap state. Named values
retain producer groups so later constraints can identify causal actions.
Normalization, sharing, and memoization must preserve expression meaning and
those diagnostic dependencies.

## Trust boundary

Review shared infrastructure separately from each model adapter. Lean
correspondence theorems cover expression meaning; JSON decoding, SMT
serialization, the compiler, and cvc5 remain trusted. Source labels and saved
artifacts are diagnostic metadata, not additional semantic proofs.
