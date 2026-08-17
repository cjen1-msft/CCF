# Static certified CCF Raft safety core in Lean

This experiment applies the pure Lean transition-system approach to a
certificate-based, static signed-log core derived from
`tla/consensus/ccfraft.tla`.

It proves, for every reachable state:

- `LeaderCompleteness`: every higher-term leader contains each lower-term
  server's committed log;
- `CommittedLogsNoConflicts`: any two local committed logs are prefix-comparable
  (`abs.tla`'s `NoConflicts`);
- `CommittedLogAppendOnly`: every reachable transition preserves each local
  committed log as a prefix (`abs.tla`'s `AppendOnlyProp`);
- `GlobalCommitAppendOnly`: the ghost committed upper bound only extends.

These are selected safety consequences of `abs.tla`. There is no abstract
state mapping, step simulation, or trace-lifting theorem yet, so this project
does not prove `ccfraft.tla`'s `RefinementToAbsProp`.

## Structure

- `Model.lean`: roles, signed entries, state, seven actions, `CertifiedStep`, and
  `Reachable`.
- `Properties.lean`: inductive core and exported safety properties.
- `Proofs.lean`: action preservation, reachability induction, leader
  completeness, no-conflicts, and append-only proofs.
- `Examples.lean`: a concrete two-server
  request/sign/commit/replicate/elect execution.

## Run

```bash
cd lean
lake build CCFRaft
```

The root module prints the axioms of the exported theorems and rejects any
theorem under `CCFRaft` that transitively depends on `sorryAx`.

## Refinement boundary

This is not a complete port of `ccfraft.tla`. It omits the asynchronous
network, vote messages, quorum calculation, reconfiguration, retirement,
pre-vote, and fairness. Initialization also deliberately uses empty logs and
term `1`, rather than parameterizing `StartTerm` and reproducing CCF's bootstrap
logs.

The omitted protocol appears through explicit proof-certificate guards:

- advancing the ghost committed upper bound must show that the old bound is a
  prefix of the new committed prefix;
- advancing or learning a commit must show the new prefix is visible to every
  higher-term leader;
- becoming leader must show the candidate contains the ghost committed upper
  prefix after truncation to its last signature;
- replication must show it preserves the follower's committed prefix.

`CertifiedStep` also enforces two source-level CCF rules directly: commits end
at signatures, leader commits use a current-term signature, and election
truncates unsigned suffixes.

The proofs establish that the certificates are sufficient for the stated
safety properties. They do not establish that the concrete protocol produces
the certificates. A faithful next layer must model messages, votes, log
matching, current-term commit rules, and quorum intersection, then prove every
concrete action maps to a `CertifiedStep` or stutter.

`CommittedLogsNoConflicts` and `CommittedLogAppendOnly` are the consensus-log
safety facts sometimes informally grouped under linearizability. They are not
a full linearizability or refinement proof, and they are not client
request/response linearizability; the latter remains the subject of
`CCFConsistency`.
