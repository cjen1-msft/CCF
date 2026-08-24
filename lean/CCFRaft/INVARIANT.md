# CCF Raft inductive invariant

`SystemInductiveInvariant` stores the evidence needed to prove safety after
every enabled transition. It does not store `ConsensusSafety`, `LogMatching`,
or `LeaderCompleteness` as assumptions.

## Runtime-local facts

The first six `InvariantFacts` fields do not depend on proof histories.

| Field                           | Why preservation needs it                                                         |
| ------------------------------- | --------------------------------------------------------------------------------- |
| `commitIndicesBounded`          | Keeps every committed prefix inside its node log.                                 |
| `currentTermsPositive`          | Excludes term zero for participating nodes and closes bootstrap cases.            |
| `entriesDoNotExceedCurrentTerm` | Orders log entries below the node term used by election arguments.                |
| `candidatesSelfVote`            | Supplies the candidate's persistent first voter.                                  |
| `leadersHaveElectionWitness`    | Records either the bootstrap leader or one configuration that elected the leader. |
| `leaderProgressBounded`         | Connects `sentIndex` and `matchIndex` to the leader log.                          |

## Transport facts

These fields connect runtime messages and mutable vote state to immutable
proof histories.

| Field                  | Why preservation needs it                                          |
| ---------------------- | ------------------------------------------------------------------ |
| `voteHistory`          | Remembers one vote per voter and term after `votedFor` is cleared. |
| `networkHistory`       | Records the log and vote snapshots carried by queued messages.     |
| `historicalSafety`     | Selects the immutable histories and causal facts listed below.     |
| `grantedVoteSnapshots` | Retains the candidate and voter logs behind each effective vote.   |
| `processedAckHistory`  | Retains the exact prefix behind each positive `matchIndex`.        |

## Historical safety facts

`historicalSafety` existentially selects the immutable histories used by
`HistoricalSafetyFacts`. The named fields form the causal chain from a
committed signature, through later configurations and elections, to every
future leader.

| Field                    | Why preservation needs it                                                              |
| ------------------------ | -------------------------------------------------------------------------------------- |
| `termOwnership`          | Gives each elected term one owner and one canonical log history.                       |
| `electionHistory`        | Freezes the ballot and promotion log for each elected term.                            |
| `electionConfigurations` | Relates frozen ballots to the configurations active for later candidates.              |
| `grantedVoteCanonical`   | Ties granted-vote snapshots to canonical term histories.                               |
| `ackerCurrent`           | Tracks whether an ACK supporter still has the prefix or has crossed a later election.  |
| `ackerVotes`             | Transfers an acknowledged prefix through a later vote by that supporter.               |
| `activationVotes`        | Transfers an activated configuration prefix through later votes.                       |
| `ackerElections`         | Relates effective ACK support directly to frozen later elections.                      |
| `ackerActivations`       | Orders current ACK support against immutable configuration activations.                |
| `queuedElections`        | Ensures same-term queued AppendEntries histories extend the elected promotion log.     |
| `activationProgress`     | Keeps every activation supporter's current term above the activation term.             |
| `activationQuorums`      | Supplies record, candidate, committed-log, and competing-prefix bridges.               |
| `commitEvidence`         | Validates the term, signature, authority, and ACK quorum of every live commit.         |
| `prospectiveCommits`     | Carries each commit frontier through ACK members, queued sends, and future candidates. |
| `activationEvidence`     | Records commit authorities and orders evidence across configuration changes.           |
| `activationCanonical`    | Ties activation histories and supporters to canonical term histories.                  |
| `activationElections`    | Preserves each activated prefix in every later election.                               |
| `configurationCoverage`  | Assigns every positive current configuration to a causally covering activation.        |

### Activation quorum bridges

`activationQuorums` contains the shared activation history and the bridges
needed before a new commit exists.

| Field               | Why preservation needs it                                                   |
| ------------------- | --------------------------------------------------------------------------- |
| `history`           | Validates immutable activation records and orders activation prefixes.      |
| `recordBridge`      | Relates a potential commit prefix to a later frozen election.               |
| `candidateBridge`   | Relates a potential commit prefix to a live later candidate.                |
| `committedBridge`   | Compares an effective commit prefix with every committed log.               |
| `potentialBridge`   | Compares two effective current-term signature prefixes.                     |
| `queuedComparable`  | Orders an activation prefix against same-term queued AppendEntries history. |
| `committedCoverage` | Covers every signed frontier at or below a node commit index.               |
| `queuedCoverage`    | Covers every signed frontier advertised by a queued AppendEntries request.  |

### Commit authority evidence

`activationEvidence` orders live commit evidence after configuration changes.

| Field                         | Why preservation needs it                                                         |
| ----------------------------- | --------------------------------------------------------------------------------- |
| `authorityRecorded`           | Associates each non-bootstrap commit authority with an activation and term bound. |
| `authorityIndexUnique`        | Makes equal authority indices identify one configuration.                         |
| `authorityBridge`             | Orders full commit frontiers from strictly ordered authorities.                   |
| `supportedPrefixesComparable` | Orders the shorter signed prefixes currently supported by live evidence.          |
| `candidateBridge`             | Transfers a commit frontier or its authority into a later candidate.              |

## Safety derivation

The public theorems directly derive safety from these fields. The other fields
preserve the evidence consumed by these derivations.

| Result                         | Main evidence                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `CommittedLogsPrefix`          | `commitEvidence` and `activationEvidence.supportedPrefixesComparable`          |
| `CommittedFrontierIsSignature` | `commitEvidence`                                                               |
| `ElectionSafety`               | `termOwnership`                                                                |
| `LogMatching` and `MonoLog`    | `termOwnership` and canonical histories                                        |
| `LeaderCompleteness`           | `termOwnership`, `electionHistory`, `commitEvidence`, and `prospectiveCommits` |

Run the source and documentation audit with:

```bash
cd lean
python3 refactor_ccfraft_reconfiguration_invariant.py --check
lake build CCFRaft
```
