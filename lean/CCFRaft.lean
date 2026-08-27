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

## Required property correspondence

| TLA declaration | Lean declaration | Status |
| --- | --- | --- |
| `LogInv` | `Model.LogInv` | Proved for every reachable state |
| `MoreThanOneLeaderInv` | `Model.MoreThanOneLeaderInv` | Proved for every reachable state |
| `LogMatchingInv` | `Model.LogMatchingInv` | Proved for every reachable state |
| `LeaderCompletenessInv` | `Model.LeaderCompletenessInv` | Proved for every reachable state |
| `SignatureInv` | `Model.SignatureInv` | Proved for every reachable state |
| `MonoTermInv` | `Model.MonoTermInv` | Initialization and all-action preservation proved from monotonic logs and minimum log terms |
| `MonoLogInv` | `Model.MonoLogInv` | Proved for every reachable state |
| `LogConfigurationConsistentInv` | `Model.LogConfigurationConsistentInv` | Proved for every reachable state from exact configuration projection |
| `CommittedLogAppendOnlyProp` | `Model.CommittedLogAppendOnlyProp` | Proved for every enabled step from a reachable state |
| `CandidateTermNotInLogInv` | `Model.CandidateTermNotInLogInv` | Proved for every reachable state |
| `ElectionSafetyInv` | `Model.ElectionSafetyInv` | Proved for every reachable state |
| `QuorumLogInv` | `Model.QuorumLogInv` | Proved for every reachable state |
| `ReplicationInv` | `Model.ReplicationInv` | Proved for every reachable state |
| `MonotonicCommitIndexProp` | `Model.MonotonicCommitIndexProp` | Proved for every enabled action |
| `MonotonicTermProp` | `Model.MonotonicTermProp` | Proved for every enabled action and lifted to reachable states |
| `MonotonicMatchIndexProp` | `Model.MonotonicMatchIndexProp` | Proved for every enabled action |
| `NeverCommitEntryPrevTermsProp` | `Model.NeverCommitEntryPrevTermsProp` | Proved for every enabled step from a reachable state |
| `MatchIndexBoundedByLogInv` | `Model.MatchIndexBoundedByLogInv` | Proved for every reachable state |
| AppendEntries response bound | `Properties.AppendEntriesResponseBoundInv` | State-only diagnostic; causal ACK history replaces it |
| Configuration representation | `Properties.ConfigurationsWellFormedInv` | Initialization and all-action preservation proved |
| Exact configuration projection | `Properties.ConfigurationsExactInv` | Proved for every reachable state |
| Message representation | `Properties.MessagesWellFormedInv` | Initialization and all-action preservation proved |
| No leader before term 2 | `Properties.NoLeaderBeforeInitialTermInv` | Derived from the preserved active-role term invariant |
| Active role minimum term | `Properties.ActiveRoleTermInv` | Initialization and all-action preservation proved |
| Message minimum term | `Properties.MessageTermAtLeastStartInv` | Initialization and all-action preservation proved |
| AppendEntries payload minimum term | `Properties.MessageEntriesAtLeastStartInv` | Initialization and all-action preservation proved |
| Minimum log term | `Properties.LogTermsAtLeastStartInv` | Initialization and all-action preservation proved |
| Leader log boundary | `Properties.LeaderLogBoundaryInv` | Initialization and all-action preservation proved |
| AppendEntries log safety | `Properties.AppendEntriesLogSafetyInv` | Derived from request origins, historical MonoLog, and temporal log matching |
| Queue insertion history | `Properties.QueueHistoryConsistent` | Proved for every explicit protocol history |
| AppendEntries request history | `Properties.AppendEntriesRequestHistoryConsistent` | Derived from queue insertion history |
| AppendEntries response history | `Properties.AppendEntriesResponseHistoryConsistent` | Derived from queue insertion history |
| Successful ACK history | `Properties.SuccessfulAckHistoryConsistent` | Derived for every reachable state |
| Match-index history | `Properties.MatchIndexHistoryConsistent` | Proved for every reachable state |
| RequestVote message history | `Properties.RequestVoteMessageHistoryConsistent` | Derived from queue insertion history |
| Vote-owner history | `Properties.HasVoteHistory` | Initialization and all-action preservation proved |
| Leader election history | `Properties.LeaderHistoryConsistent` | Proved for every reachable state |
| Historical log core | `Properties.HistoricalLogCore` | Initialization and append-step proved |
| Full election/log core | `Properties.HistoricalFullElectionLogCore` | Proved for every explicit protocol history |
| Hereditary chosen-commit core | `Properties.HereditaryHistoricalChosenCommitCore` | Proved for every explicit protocol history |
| Complete safety core | `Properties.HistoricalCompleteSafetyCore` | Proved for every explicit protocol history |
| Counted candidate formation overlap | `Properties.QuorumCandidateFormationOverlapObligation` | Derived from the complete safety core |
| Counted-to-potential formation overlap | `Properties.CountedToPotentialCandidateFormationOverlapObligation` | Derived from the complete safety core |
| Newly-counted-to-potential overlap | `Properties.CountedCandidateFormationToPotentialOverlapObligation` | Derived from the complete safety core |
| Current match prefix history | `Properties.CurrentMatchIndexPrefixHistoryConsistent` | Proved for every explicit protocol history |

`Proofs.fullSafetyCompletionObligation` proves
`Properties.FullSafetyCompletionObligation`.
`Proofs.reachable_CCFRaftSafety` proves `Properties.StateSafety` and every
enabled-step `Properties.TransitionSafety` for each reachable state.
`Properties.StateOnlyInductivenessAttempt` is retained only as a refuted
diagnostic target because causal election, message, and log evidence is not
recoverable from an arbitrary state.
`Model.forgedAck_after_not_bounded` is a checked
inductiveness-only test fixture. The code does not prove that its state is
unreachable, so it is not evidence of a protocol defect.
`Model.vacuousElection_after_not_oneLeader` is a second checked
inductiveness-only fixture: an arbitrary candidate with an empty
configuration list can take `BecomeLeader` vacuously and create two leaders
in one term. No reachability claim is made for that state.
`Model.updateTermAppendEntries_not_stateOnlyInductive` proves
`Not Properties.StateOnlyInductivenessAttempt`: an arbitrary queued request
can become unsafe after `UpdateTerm`. This is also an inductiveness-only
countermodel, not a reachable execution or protocol defect.
`Model.reachable_matchIndex_gt_sentIndex` is a reachable 73-action execution:
a delayed old NACK lowers `sentIndex` before a newer success ACK raises
`matchIndex`. Therefore `matchIndex <= sentIndex` is not an invariant.
`Model.reachable_oldTermAckPrefix_overwritten` is a distinct reachable
70-action execution showing that an acknowledged uncommitted prefix may be
overwritten after a later-term election. ACK-prefix retention is consequently
restricted to witnesses from the current leader term.

## Semantic projections

| TLA feature | Lean projection |
| --- | --- |
| `Servers` | Materialized `Nat` identifiers in `State.nodes`; reconfiguration may add fresh identifiers |
| Initial servers and leader | `InitialConfiguration` parameter to `Model.system`; every initial node shares the trusted genesis prefix |
| TLA 1-based sequences | Lean lists with `entryAt?`, `logPrefix`, and `subsequence` |
| Configuration functions keyed by log index | Increasing `List ConfigurationAt`; `overrideConfigurations` implements TLA `@@` |
| `OrderedNoDup` destination queues | Deduplicated FIFO queue for each source-destination pair, which is the subsequence observable through `MessagesTo` |
| Nondeterministic action and receive choices | Constructor arguments of `Model.Action` and `Model.ReceiveKind` |
| Nodes outside the materialized set | Total `NodeMap` defaults; action guards reject unknown endpoints |
| Removed nodes | Remain materialized and may be referenced by retirement handling; identifiers are not reused |
| Client request payloads | One undifferentiated `EntryContent.entry`, as in `ccfraft.tla` |
| `AppendEntriesBatchsize` | The literal singleton `sentIndex + 1`, so a request carries zero or one entry |
| Pre-vote | Omitted; status is fixed to `PreVoteDisabled`, while `isPreVote` message fields remain |
| `TypeRetired`, `AppendRetiredCommitted`, final shutdown | Omitted; earlier retirement phases and `retirementCompleted` remain |
| `CheckQuorum` | Omitted |
| `SigTermProposeVote` and `ProposeVoteRequest` | Omitted |
| Fairness and `[Next]_vars` stuttering | Omitted from finite reachability; identity steps preserve all listed safety predicates |
| Partial TLA indexing outside `TypeInv` | Totalized with `Option`, zero, or the empty configuration; reachable well-formed states use the TLA-defined cases |

The required 229-action disjoint `5 -> 5 -> 5` replay starts from a singleton
genesis and is defined in `Simulation.lean`. The same file checks 1-, 3-, and
5-node genesis parameters and introduces nodes 16 and 17 by reconfiguration.
Run the compiled checks with
`lake exe ccfraft-sim`. The compiled replay reaches every expected
configuration, election, commit index, retirement phase, and final client
request.
-/
