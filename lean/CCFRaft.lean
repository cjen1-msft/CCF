import CCFRaft.ExecutableTransitionSystem
import CCFRaft.Model
import CCFRaft.Properties
import CCFRaft.Proofs
import CCFRaft.Simulation

/-!
# CCFRaft TLA port

The executable model and its proof are generated from the checked-out
`tla/consensus/ccfraft.tla`.

## Action correspondence

| TLA declaration | Lean declaration | Status |
| --- | --- | --- |
| `Timeout` | `Model.Action.timeout`, `Model.nextTimeout` | Executable |
| `RequestVote` | `Model.Action.requestVote`, `Model.requestVoteMessage` | Executable |
| `AppendEntries` | `Model.Action.appendEntries`, `Model.appendEntriesMessage` | Executable |
| `BecomeLeader` | `Model.Action.becomeLeader`, `Model.nextBecomeLeader` | Executable |
| `ClientRequest` | `Model.Action.clientRequest`, `Model.nextClientRequest` | Executable |
| `SignCommittableMessages` | `Model.Action.signCommittableMessages`, `Model.nextSignCommittableMessages` | Executable |
| `ChangeConfiguration` | `Model.Action.changeConfiguration`, `Model.nextChangeConfiguration` | Executable |
| `AdvanceCommitIndex` | `Model.Action.advanceCommitIndex`, `Model.nextAdvanceCommitIndex` | Executable |
| `Receive` | `Model.Action.receive`, `Model.ReceiveKind`, `Model.nextReceive` | Executable |
| `UpdateTerm` | `Model.ReceiveKind.updateTerm` | Executable receive branch |
| `HandleRequestVoteRequest` | `Model.ReceiveKind.handleRequestVoteRequest` | Executable receive branch |
| `HandleRequestVoteResponse` | `Model.ReceiveKind.handleRequestVoteResponse` | Executable receive branch |
| `HandleAppendEntriesRequest` | Six AppendEntries request values of `Model.ReceiveKind` | Executable receive branches |
| `HandleAppendEntriesResponse` | Success and failure values of `Model.ReceiveKind` | Executable receive branches |
| `DropStaleResponse` | RequestVote and AppendEntries stale values of `Model.ReceiveKind` | Executable receive branches |
| `DropResponseWhenNotInState` | RequestVote and AppendEntries out-of-state values of `Model.ReceiveKind` | Executable receive branches |
| `DropIgnoredMessage` | `Model.ReceiveKind.dropIgnored` | Executable receive branch |

`Model.Action`, `Model.Enabled`, and `Model.next` are the only transition
semantics used by reachability and replay.

## Property correspondence

| TLA declaration | Lean declaration | Status |
| --- | --- | --- |
| `LogInv` | `Model.LogInv` | Defined; initial state proved |
| `MoreThanOneLeaderInv` | `Model.MoreThanOneLeaderInv` | Defined; initial state proved |
| `LogMatchingInv` | `Model.LogMatchingInv` | Defined; preservation pending |
| `LeaderCompletenessInv` | `Model.LeaderCompletenessInv` | Defined; preservation pending |
| `SignatureInv` | `Model.SignatureInv` | Defined; initial state proved |
| `MonoTermInv` | `Model.MonoTermInv` | Defined; preservation pending |
| `MonoLogInv` | `Model.MonoLogInv` | Defined; preservation pending |
| `LogConfigurationConsistentInv` | `Model.LogConfigurationConsistentInv` | Defined; preservation pending |
| `CommittedLogAppendOnlyProp` | `Model.CommittedLogAppendOnlyProp` | Defined; proof pending |
| `CandidateTermNotInLogInv` | `Model.CandidateTermNotInLogInv` | Defined; preservation pending |
| `ElectionSafetyInv` | `Model.ElectionSafetyInv` | Defined; preservation pending |
| `QuorumLogInv` | `Model.QuorumLogInv` | Defined; preservation pending |
| `ReplicationInv` | `Model.ReplicationInv` | Defined; preservation pending |
| `MonotonicCommitIndexProp` | `Model.MonotonicCommitIndexProp` | Proved for every enabled action |
| `MonotonicTermProp` | `Model.MonotonicTermProp` | Proved for every enabled action and lifted to reachable states |
| `MonotonicMatchIndexProp` | `Model.MonotonicMatchIndexProp` | Proved for every enabled action |
| `NeverCommitEntryPrevTermsProp` | `Model.NeverCommitEntryPrevTermsProp` | Defined; proof pending |
| `MatchIndexBoundedByLogInv` | `Model.MatchIndexBoundedByLogInv` | Defined; preservation pending |
| AppendEntries response bound | `Properties.AppendEntriesResponseBoundInv` | Added after a checked inductiveness-only forged-ACK countermodel; preservation pending |

`Properties.FullInductivenessObligation` is the exact unproved preservation
statement. `Model.forgedAck_after_not_bounded` classifies the current blocker:
it is an inductiveness-only countermodel, not a reachable execution or a
protocol defect. The invariant must carry causal evidence for successful
AppendEntries responses before the remaining leader and log safety proofs can
close.

## Semantic projections

| TLA feature | Lean projection |
| --- | --- |
| `Servers` | `Fin 15` |
| Nondeterministic initial leader | Explicit `start : Node` parameter to `Model.system` |
| TLA 1-based sequences | Lean lists with `entryAt?`, `logPrefix`, and `subsequence` |
| Configuration functions keyed by log index | Increasing `List ConfigurationAt`; `overrideConfigurations` implements TLA `@@` |
| `OrderedNoDup` destination queues | Deduplicated FIFO queue for each source-destination pair, which is the subsequence observable through `MessagesTo` |
| Nondeterministic action and receive choices | Constructor arguments of `Model.Action` and `Model.ReceiveKind` |
| Client request payloads | One undifferentiated `EntryContent.entry`, as in `ccfraft.tla` |
| `AppendEntriesBatchsize` | The literal singleton `sentIndex + 1`, so a request carries zero or one entry |
| Pre-vote | Omitted; status is fixed to `PreVoteDisabled`, while `isPreVote` message fields remain |
| `TypeRetired`, `AppendRetiredCommitted`, final shutdown | Omitted; earlier retirement phases and `retirementCompleted` remain |
| `CheckQuorum` | Omitted |
| `SigTermProposeVote` and `ProposeVoteRequest` | Omitted |
| Fairness and `[Next]_vars` stuttering | Omitted from finite reachability; identity steps preserve all listed safety predicates |
| Partial TLA indexing outside `TypeInv` | Totalized with `Option`, zero, or the empty configuration; reachable well-formed states use the TLA-defined cases |
-/
