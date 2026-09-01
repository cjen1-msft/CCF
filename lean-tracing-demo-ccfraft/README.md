# CCFRaft trace validation demo

This directory contains a standalone demonstration of mid-trace validation
against the CCFRaft Lean model.

## Review these files

The manual review boundary contains these files:

- `Model.lean` defines `CCFRaft.Action`, `CCFRaft.Enabled`, and `CCFRaft.next`.
- `Properties.lean` defines the three consensus-safety claims.
- `Reduction.lean` defines the Lean preprocessing and reduction rules.
- `reduction.py` defines the Python preprocessing and reduction rules.
- `TraceProperties.lean` defines `ValidEntryState`,
  `MidtraceSatisfiable`, `FormulaSatisfiable`, and `lowerTrace_correct`.

The reducers separate three jobs:

1. Shared code parses and consumes the captured trace without changing its
   meaning.
2. Audited preprocessing groups or removes implementation events.
3. Audited reduction rules emit model actions and observations.

## Do not manually review generated proofs

`MachineGenerated/` contains lowering code, proof bodies, and the inductive
model proof. An agent may replace these files. Lean must compile them without
`sorry` before the demo passes.

`Shared/` contains model-independent trace and solver code. Review this code
once as infrastructure, not once per model.

## Claim made by the validator

`TraceProperties.lean` defines the intended claim. For one reduced trace,
`MidtraceSatisfiable` means that an entry state satisfying `ValidEntryState`
and a sequence of enabled `CCFRaft.next` transitions can explain every reduced
action and observation.

The result does not prove that the entry state is reachable from bootstrap.
It does not prove whole-implementation equivalence. Running many overlapping
segments provides operational evidence, not a stronger theorem.

The executable SMT backend currently checks only a projection of that claim.
`Shared/smt.py` models terms, roles, log lengths, commit indices, allocation,
and join state. It does not encode complete logs, messages, votes, or
configurations. Its `sat` and `unsat` results therefore do not yet establish
`MidtraceSatisfiable` for the complete model.

`MachineGenerated/Lowering.lean` and
`MachineGenerated/LoweringProofs.lean` prove that all ten typed action
lowerings preserve the canonical Lean transition relation. The remaining
blocker is to connect the emitted SMT formula to that typed formula.

The projected backend trusts cvc5 for `sat` and `unsat`. For `unsat`, it saves
the cvc5 proof and unsat core and asks cvc5 to check both. It reduces the core
within a fixed wall-clock budget by removing deterministic chunks and then
individual assertions. It accepts a removal only when cvc5 still returns
`unsat`. It reconstructs a formula from the reduced core and generates the
proof from that formula. `diagnosis.json` maps each remaining constraint back
to its action or observation, reducer rule, and raw trace line.
The report records wall-clock time for the initial check, core generation,
budgeted reduction, and proof invocation.

## Run the demo

Run:

```bash
./check_demo.sh
```

The command:

1. Builds `Demo.lean` and checks every `CCFRaft` theorem for forbidden axioms.
2. Runs the Python reducer tests.
3. Checks that both captured traces are `sat`.
4. Checks that all four hand-edited traces are `unsat`.
5. Uses `jq -S` and `diff` to compare regenerated Python certificates with
   the checked-in certificates.
6. Writes `Report/index.html`.

The Lean and Python reducers are separate audited implementations. The Lean
reducer compiles and covers all action constructors. It does not yet consume
the NDJSON fixtures, so reducer equivalence remains a manual source review.

To reproduce the captured implementation traces, run:

```bash
./Shared/capture_traces.py --check
```

This command invokes `build/raft_driver` directly. It does not call the old
semantic preprocessor in `tests/raft_scenarios_runner.py`.

## Source checkpoint

`bootstrap_from_checkpoint.py` copied the original CCFRaft model and proof from
commit `73292060d`. Development continues in this directory. The old
`lean/CCFRaft/` source tree is removed after migration.
