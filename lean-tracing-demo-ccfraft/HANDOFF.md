# Resume the checked CCFRaft trace encoder

## Current direction: native-array exact encoding

### Immediate continuation: core receive and membership actions

The user now prioritizes `requestVote`, receive requestVote, `appendEntries`,
receive appendEntries, and membership change. Vote sends, vote-request receive,
and append sends are public.
Finish this core before unrelated remaining actions.
Delegate mechanical proofs to `gpt-5.6-sol` with medium reasoning effort.
The main agent owns semantic lemmas. Build reusable proof components where
they remove repeated execution decomposition and assignment-extension repair.
This supersedes the earlier serial-only worker instruction.

Factory tools are unavailable in this session. `NativeDefinitions` and
`NativeDefinitionsEncoding` now provide reusable heterogeneous definition
sequences, execution shape, and specific-assignment extension. Campaign writes
use them without changing generated scripts or exported theorem statements.
The parent rebuild and campaign regressions pass in
`native-campaign-reuse-public-build.log` and `native-campaign-reuse-tests.log`.
`NativeAppendSend` now composes append guards, the sentIndex store, and FIFO
enqueue. Its packet reads the original cursor. `NativeAppendSendEncoding`
proves full-frame soundness and specific-assignment extension. The parent
build passes in `native-append-send-parent-build.log`.
Worker `b53cfbd8-539b-4835-b9bf-32d4fb1d4892` completed public `appendEntries`
decoding, dispatch, and both whole-trace proofs. The parent accepted its
three-file compiler change after inspection and an independent public build
in `native-public-append-parent-build.log`. Those files are parent-owned again.
`NativeFirstMatchEncoding` is complete and independently builds. Its 530
emitted-SMT cases include ignored tails, nested binders, and huge live bounds.
Those cases and signature regressions pass in `native-first-match-tests.log`.
`NativeRetirementEncoding` now composes concrete signature-after-retirement
and first-retired-record predicates with that generic proof. Its 1,410
Model-derived SMT cases pass in `native-retirement-scan-tests.log`, including
noncanonical cells, tag discrimination, ignored tails, and nested binders.
The refreshed proof build and fixtures pass in
`native-retirement-refreshed-build.log` and
`native-retirement-refreshed-tests.log`.
`NativeArrayAppendNetwork` now proves full-frame stepdown and consuming
append-receive correspondence, including metadata refresh after NACKs.
The parent inspected it and rebuilt it in
`native-array-append-network-parent-build.log`.
`NativeLogSpliceEncoding` now proves quantified live-range log copies from
explicit source arrays, with unconstrained output tails. Its constructive
completeness witness copies the raw cells, not merely their decoded values.
The parent build passes in `native-log-splice-parent-build.log`.
Its 1,280 emitted-SMT cases pass in `native-log-splice-tests.log`, including
nested binders, noncanonical cells, truncated prefixes, and oversized cursors.
`NativeArrayAppendReceiveGuard` now proves exact receive enablement, including
allocation and destination validity as guard conditions rather than premises.
It derives the source header from the selected FIFO.
The parent build passes in `native-array-append-receive-guard-parent-build.log`.
`NativeLogRangeEncoding` now proves the already-done, term-conflict, and
no-conflict-extension predicates over explicit arrays. It uses normalized
entries, saturated subtraction, and a reusable bounded-forall proof.
The independent proof check passes in `native-log-range-parent-check.log`.
Its 4,800 actual-Model SMT cases pass in `native-log-range-tests.log`.
They include mixed canonical and noncanonical cells, empty payloads,
same-term content differences, ignored tails, and nested binders.
`NativeAppendResponseTerm` now proves the symbolic append-response packet
constructor with explicit response endpoints. Its 756 SMT cases pass in
`native-append-response-tests.log`, including wrong tags, both directions,
self responses, large scalars, and mixed Boolean and integer binders.
The independent proof check passes in `native-append-response-parent-check.log`.
That worker is idle.
The main agent owns `NativeArrayVoteReceive` and subsequent receive semantics.
Its handler and full-frame correspondence proofs build in
`native-vote-receive-model-build.log`. Public `receiveRequestVote` is now wired.
Campaign integration is committed as `bf0c05a55`.

The main-agent semantic prerequisites now include:
- `NativeArrayVoteReceive`: log freshness, exact Model handler, receive
  enablement, selected-head bridge, and full-frame receive correspondence.
- `NativeVoteReceiveTerms`: request-kind test, snapshot reads, symbolic grant,
  and reply construction. Freshness compares against the latest signature,
  not the commit frontier. Stale requests reply negatively. Newer terms block
  receive until a separate term update.
- `NativeVoteReceiveGuardEncoding`: the guard is equivalent to actual Model
  receive enablement plus the fact that the selected packet is a vote request.
  It allows unallocated senders and self-addressed requests. Unlike `updateTerm`,
  receive requires the packet destination to match its containing queue.
- `NativeArrayAppend`: the Model's enabled send frontier yields zero or one
  entry. The send updates the source's sentIndex and appends a packet.
- `NativeEntryNormalize` and `NativeAppendPacket`: canonical symbolic entries
  and exact AppendEntries packet construction without a quantified log copy.
- `NativeAppendGuardEncoding`: exact send guards, including the
  retirement-completed exception and exact frontier, with two-witness
  assignment-extension completeness. `native-append-guard-tests.log` records
  1,216 passing actual-Model cases.
- `NativeArrayLogRanges`: arbitrary-length receive overlap comparisons.
  Already-done and conflict compare terms; extension compares complete entries.
  `NativeArrayLogWrite` proves truncation, append, splice, and the Model
  conflict-truncation branch. Both modules build with their axiom gates in
  `native-log-ranges-build.log` and `native-log-write-build.log`.
- `NativeArrayAppendReceive`: bounded signature/commit correspondence,
  already-done and extension ACK branches, exact NACK matching and response,
  rejection guards, and same-term candidate stepdown without consuming the
  request. Reuses `LogMatchSummary.StorageSummary` rather than a new scan
  definition. `native-append-receive-branches-build.log` records the clean build.
  Local branch composition and full-frame retirement refresh are proved.
  Public append receive remains unwired.
- `NativeArrayAllocation` proves exact Model allocation for membership change.
  Existing rows survive; missing members become fresh nodes. Abstract reads
  stay unchanged because missing rows already read as fresh. The eventual
  encoder must still reset hidden raw cells before exposing a new allocation.
  `native-array-allocation-build.log` records the clean proof build.
- `NativeArrayChangeConfiguration` now proves membership-change guards,
  source-row updates, and full-frame Model correspondence given the exact
  configuration and retirement witnesses. Existing allocated rows survive.
  Added-peer cursors use the old log length. The public action is not wired.
  `native-array-change-configuration-parent-build.log` records the parent build.
- `RetirementScan` proves the first exclusion after first inclusion, including
  the implicit bootstrap configuration. Once found, that retirement index
  survives later appended entries, even configurations that re-add the node.
  `native-retirement-scan-build.log` records the clean proof build.
  It also characterizes the first signature strictly after retirement, the
  first retired-committed entry naming a node, and membership in committed
  retired records. These use list searches without ordered-term assumptions.
  `native-retirement-secondary-scans-build.log` records the proof build.
- `NativeArrayFirstMatch` proves a reusable first-match summary over live
  array positions, including absent matches and shifted indices.
  `NativeArrayRetirement` uses it for exact Model signature and retired-record
  indices. It also proves bounded array membership for committed and all
  retired records. `native-array-retirement-build.log` records the proof build.
  It now also proves local retirement refresh from scan summaries and bounded
  previous-configuration membership. `RetirementScan.completed_nodes_correct`
  characterizes the global completed-retirement set without dropping the
  committed-prefix retirement condition. The combined build passes in
  `native-retirement-refresh-build.log`. Consuming append NACKs refresh this
  metadata too; only the nonconsuming candidate-stepdown branch skips refresh.
  `NativeArrayConfiguration` now proves the full current configuration from
  native index and node-set witnesses. `completed_nodes_from_scans_correct`
  combines this with bounded previous-membership and retired-record scans.
  `native-retirement-completed-scans-build.log` records the proof build.
  `log_first_removal_from_first_inclusion` now decomposes retirement into
  the first inclusion and the first later exclusion. It uses proven ordering
  of configuration indices, not ordering of entry terms.
  `native-retirement-first-inclusion-build.log` records its build.

Public append integration coverage is in
`NativeArrayAppendFixtureMain`, `Traces/native_append_fifo_conflict.json`,
and `test_native_lean_smt.py`. It includes 1,200 Model-derived traces,
successive cursor updates, duplicate heartbeats, strict input errors, and
explorer core attribution. All six targeted methods pass in 145 seconds in
`native-public-append-tests.log`. Both assurance flags remain false.
The follow-up sequence cases include 21 declared nodes and append sends
followed by a vote request and term update. They pass in
`native-public-append-sequence-tests.log`.
`frameObservations` in `NativeArrayFixtureJson` now shares complete local and
queue observations with the receive-write fixture. The 192 receive-write cases
and import-boundary check pass in `native-shared-frame-tests.log`.

`NativeArrayAppendReceiveFixtureMain` now generates 1,344 actual-Model receive
traces, with 334 expected SAT cases. They cover all four consuming handlers,
nonconsuming stepdown, multi-entry payloads, retirement refresh after
NACKs, duplicate and self queues, and wrong packet kinds.
`NativeArrayMembershipFixtureMain` generates 1,572 membership traces, with
147 expected SAT cases. Its allocation counterexamples corrupt newly
allocated rows and already allocated rows separately.
Both generators build. Their Model-only coverage checks pass in
`native-core-model-fixture-coverage.log`. Neither action is public yet:
these are prepared integration inputs, not passing encoder coverage.
Wire them through `assert_model_traces` when their public actions land.

`NativeQueuePop` and `NativeQueuePopEncoding` now prove total directed FIFO
pop, including empty queues and negative raw scalars, full-frame preservation,
and extension of a specific satisfying assignment. `native-queue-pop-tests.log`
records 112 passing push/pop fixtures, including duplicate and self queues.
`NativeVoteReceiveWrites` and its encoding proof now compose the conditional
vote store, FIFO pop, and reply. Replies read the original columns.
`native-vote-receive-write-tests.log` records 192 complete Model transition
cases and four invalid-symbol errors. Cases include stale requests,
unallocated senders, self receives, existing duplicate replies, and full
post-state observations.
`NativeVoteReceive` and `NativeVoteReceiveEncoding` now compose the
request-specific guard, signature witness, and writes. Public decoding,
dispatch, and both trace-proof directions include `receiveRequestVote`.
`NativeArrayVoteReceiveFixtureMain` builds and generates 480
Model-derived traces, including enabled generic receives of the wrong packet
kind that must be rejected by the vote-specific action.
`native-public-vote-receive-failing-first.log` records rejection before wiring.
All six targeted methods, including send/update/receive sequences, explorer
core attribution, input errors, and append regressions, pass in 197 seconds
in `native-public-vote-receive-tests.log`.
The shared Model fixture runner also passes the existing 1,200 append cases
in `native-model-runner-tests.log`.
`NativeArrayRetirementIndex` now connects the two-search retirement
decomposition to bounded first-match summaries over a bootstrap-prefixed
virtual log. The parent inspected it and rebuilt it in
`native-array-retirement-index-parent-build.log`.
`NativeFirstMatchWitness` and `NativeRetirementIndexSound` now extract
canonical witnesses from successful arbitrary SMT assignments. They derive
both sentinels, rather than assuming valid optional indices.
Parent proof checks against the compiled dependencies pass in
`native-first-match-witness-parent-check.log` and
`native-retirement-index-sound-parent-check.log`.
`NativeRetirementRefreshTerms` now proves the four retirement scalar results
from canonical scan witnesses, including zero-to-one-based index conversion.
Its 1,440 actual-Model SMT cases pass in `native-retirement-refresh-tests.log`.
They cover all five membership states, inclusive commit boundaries, and
active nodes with a present committed retired-record index.
The independent proof check passes in
`native-retirement-refresh-terms-parent-check.log`.
Worker `af5d19d5-1186-4609-9b0b-4f224d4a4330` is idle.
`NativeRetirementIndexEncoding` is complete. It composes first inclusion and
first later exclusion without materializing a shifted array. Its 1,788
Model-derived SMT cases pass in `native-retirement-index-tests.log`.
They include never-included nodes, bootstrap members, re-additions, wrong
tags, ignored tails, invalid sentinels, and nested log-row and first-index
bindings. The independent proof build passes in
`native-retirement-index-encoding-parent-build.log`.

Worker `a04f39b9-8aa6-4733-9c2c-228d7432032e` completed
the entry-observation normalization cleanup. Its completed
`NativeArrayAppendHandlerCases.handles_iff` proves exact local handler
enablement from the four native branch guards. The parent build passes in
`native-append-handler-cases-parent-build.log`.

The next structural prerequisite is mutable allocation and log columns.
Allocation, log length, commit, and log cells still use fixed symbols 0, 3,
4, and 6. Entry observations now normalize raw entries to their Model values.
Their proofs no longer carry the initial `NodeDomain` through later states.
Initial domain assertions and realization remain intact.
`NativeIntegerTerms` holds the unchanged integer helpers below normalization,
removing the previous import cycle. The eleven cleanup files are parent-owned.
The independent public proof build passes in
`native-observation-normalize-parent-build.log`.
`NativeObservationNormalizeFixtureMain` supplies 576 direct raw-cell cases.
`native-normalized-observation-failing-first.log` records the pre-change
failure for raw term -5 decoding to Model term 0.
Those cases and existing public observation, append, campaign, receive,
and explorer regressions now pass in `native-observation-normalize-tests.log`.

Worker `a04f39b9-8aa6-4733-9c2c-228d7432032e` now owns the four-column
reference migration in existing native core and proof files. It excludes
fixture modules, pure `NativeArray*` semantics, and the two new witness modules.
The new fields are `allocated`, `logLength`, `commit`, and `logEntries`.
Preserve initial IDs 0, 3, 4, and 6 and the next-symbol counter 24.
Runtime readers must take current `Columns` explicitly, with no initial-column
default. The migration includes representation, reference bounds, assignment
transport, guards, packets, observations, and trace proofs. Initial domains
still use initial references. No new action is part of this migration.
The parent owns the new `NativeRelocatedColumnsFixtureMain` and Python test.
It compares every emitted clause before and after relocating all columns,
including mixed action histories. The initial failure is the four missing
column fields, recorded in `native-relocated-columns-first-compile.log`.
This test remains pending until the migration finishes.
The range, retirement-scalar, and response-packet encoders and fixtures have
been checked against compiled dependencies. Rebuild their Lake targets after
the column migration. Both explicit-term workers are idle.

`NativeArrayVoteState` now holds frame state and the existing action semantics.
`NativeArrayVote` retains instruction traces and their correspondence proofs.
The declaration names are unchanged. Receive and append semantic modules import
the state module, so the trace module can later import them without a cycle.
`native-frame-state-split-build.log` records the targeted build.

Internal `.receiveVote` trace semantics now retain an explicit
selected-vote-request premise. Internal `.appendEntries` traces also have
actual Model correspondence, including the exact batch frontier.
The public decoder accepts append sends and vote-request receives.
`NativeArrayVote`, `NativeFrameStep`, and the public decoded-trace
proofs build in `native-vote-receive-trace-model-build.log`,
`native-vote-receive-writes-integration-build.log`, and
`native-campaign-reuse-public-build.log`. Shell `101` has completed.
`native-append-trace-model-build.log` records the append trace build.
It rebuilt only the five trace/compiler modules, not the core campaign proofs.

The import-boundary cleanup is complete. `NativeFrameInitial` contains
the unchanged initial frame assertions. Core column/action proofs no longer
import `NativeFrameEncode` or the instruction trace module. This avoids an
import cycle during public action integration and repeated rebuilds of the
725-second campaign write proof after decoder changes.
`NativeImportBoundaryTests` enforces the transitive dependency boundary.
The core targets pass in `native-core-import-boundary-build.log`.
Affected public proofs and fixture modules pass in
`native-core-import-public-build.log`. Guard regressions and the dependency
boundary pass in `native-core-import-tests.log`. Shell `123` has completed.
No solver or representation change is involved.

`native-vote-receive-tests.log` records 1,728 passing response/guard cases.
`native-append-packet-tests.log` records 2,538 passing packet/normalization cases.
Both compare with actual Model results. Each new proof module builds with the
allowed-axiom gate. Append send and vote-request receive are now public.
Keep append receive and membership change
next in priority. Do not replace generic receive with a silently restricted
vote-only action: retain the packet-kind fact in the correspondence statement.

The solver migration is committed as `29312d591`, following `137a4f3d6`,
the versioned FIFO column slice.
`NativeMembershipEncoding.lean` proves scoped active membership,
existential witnesses, and correspondence with `activeNodeUnion`.
It is imported by `Sparse.lean` and builds with the normal axiom gate.
`NativeMembershipFixtureMain.lean` and `test_model_active_membership` generate
1,140 Model-derived cases. The old cvc5 runner failed these cases.
The explicit Z3 migration is complete. All 48 native solver and explorer test
methods pass, including 156 kernel-backed formulas and 1,140 membership cases.
`NativeVotePacket.lean` now proves last-committable index/term reads and symbolic
vote-packet construction. `vote_packet_term_model_correct` uses the asserted
latest-signature condition and reaches the actual Model packet constructors.
The term read clips negative raw values and ignores zero/out-of-range indices.
The full Sparse audit passes. `native-vote-packet-fixture-build.log` and
`native-vote-packet-tests.log` record 2,560 passing solver cases in 33 seconds.
The matrix covers both packet kinds, all logs of length 0-2 over four contents,
five commit values including `10^30`, allocated/absent nodes, three identity
pairs including self, and equality/inequality against Model packets.
Forty additional cases within that total exercise raw negative terms and
negative, zero, live, and outside indices.
Packet construction is committed as `357b438dd`.
The next slice now accepts `requestVote` and `requestPreVote` publicly.
`NativeVoteGuards` proves enabled guards and extends any existing assignment
with current-configuration, membership, and signature witnesses.
`NativeVoteSendEncoding` composes actual compiler execution with FIFO writes,
proving whole-frame soundness and assignment-extension completeness.
`NativeFrameStep` and `NativeFrameTrace` include vote sends; the existing
decoded-document/script theorem now covers all three public actions.
`native-public-vote-build.log` records the full Sparse and public encoder build.
`native-public-vote-tests.log` records 24 passing methods in 152 seconds:
400 Model vote-send cases, 160 guard cases, repeated/interleaved FIFO sends
with 2 and 21 identities, strict input errors, existing quorum/framing cases,
and solver/explorer compatibility. `native-vote-core-tests.log` adds the
synthetic duplicate-vote contradiction with actual explorer core ownership.
That fixture is `Traces/native_vote_fifo_conflict.json`, not a captured trace.
Both assurance flags remain false.

Public vote sends are committed as `7d815af66`.
The term-column slice moves current-term reads from fixed column 5 to
`Columns.currentTerm`, initially 5. `ReferencesValid` now tracks that reference,
and observations and vote packets read it. Initial-state domain constraints
remain on original column 5, as with the already-mutable role fields.
The packet matrix now includes a second current-term column whose old column-5
value deliberately disagrees, giving 5,080 cases.
`native-term-column-full-build.log` records the full Sparse/public encoder build.
All eight targeted methods pass in `native-term-column-tests.log`, including
the 5,080 packet cases, 400 public vote sends, quorum, framing, and explorer cores.
The 400 pre-change public vote scripts have a SHA-256 manifest at
`files/native-vote-before-term-columns.sha256`. The rerun into
`files/native-public-vote-fixtures` passes that manifest comparison.
All 400 default-column scripts remain byte-identical.

Then implement `updateTerm`, `timeout`, and `becomePreVoteCandidate`.
`NativeArrayVote` already supplies their array-level Model correspondence.
Packet construction reads the latest term column. Log/commit columns remain
fixed for now.

The term-column slice is committed as `0876682fa`.
`NativeQueueHead` and `NativeQueueHeadEncoding` now prove normalized head reads
against any represented FIFO, including different physical offsets.
`NativeTermGuardEncoding.term_update_guards_model_correct` reaches actual
`Enabled state (.updateTerm source destination)`. It covers source allocation
only for response packets, destination allocation, nonempty queues, and strict
term increase. It deliberately does not require packet destination to equal
the containing queue destination, matching the Model.
`native-term-guard-full-build.log` and `native-term-guard-tests.log` record
the full Sparse build and 216 passing cases in 14 seconds.
The fixture consumes 168 existing actual-Model term cases but checks only
their prefix and guard, not the later state observations. Another 48 cases
cover negative/huge raw heads and lengths, invalid payloads, wrong sources,
and a higher-term trap at a negative raw offset.
The guard prerequisites are committed as `3ad294966`.
`NativeTermUpdate` now emits all five writes. `NativeTermUpdateEncoding` proves
node preservation, actual execution shape, whole-frame soundness, and
assignment-extension completeness using five `define_extension` applications.
The public decoder and both frame-trace directions now include `updateTerm`.
The queue is not consumed. `votesGranted` and all unrelated state are preserved.
The guard fixture now reuses the public decoder.
`native-public-term-full-build.log` records the complete Sparse/public build.
`native-public-term-tests.log` records nine passing methods in 194 seconds:
168 complete Model term traces, 30 frame/sequence cases, strict input errors,
216 guard cases, 400 public votes, FIFO framing, 150 Model quorum cases, local
state framing, and the explorer-core regression. The Model fixture starts with
nonempty election fields and checks them after the update.
Both assurance flags remain false.

The public term-update slice is committed as `97cb812c0`.
`NativeCampaignMember` now proves signature-bounded membership.
`NativeCampaignGuardEncoding` proves enabled guards and extension of a specific
assignment with three fresh integer witnesses. Its complete guard includes the
retirement-completed exception. `native-campaign-guard-tests.log` records
1,200 passing Model-derived cases in 31 seconds. These include the 400 existing
campaign prefixes and an 800-case matrix of allocation, role, membership,
pre-vote status, configuration exclusion, and retirement completion.
`NativeCampaignGuardFixtureMain` tests guards only, not post-state writes.
The guard slice is committed as `d083c6f37`.
`NativeCampaign` now defines runtime writes for both campaign actions.
`NativeCampaignWrites` proves node preservation, five-write execution shape,
whole-frame preservation, and assignment-extension completeness.
`native-campaign-writes-build.log` records the passing build.
Both actions use five stores for now. Pre-vote writes back the same term,
votedFor, and granted votes to keep the proof uniform.
`NativeCampaignEncoding` composes the guards and writes. Its build passes in
`native-campaign-complete-build.log`, taking 367 seconds.
The decoder and both whole-frame trace directions now include campaigns.
The full Sparse/public build passes in `native-public-campaign-build.log`.
Runtime tests pass: nine methods in
160 seconds in `native-public-campaign-tests.log`, including 400 complete Model
campaign traces, 18 state/sequence cases, strict campaign input errors, the
1,200 guard cases, and vote/term/quorum/explorer regressions.
`native-public-campaign-failing-first.log` records the test failure before
public action wiring. The guard fixture now reuses the public decoder.
The public encoder now covers eight actions. The full-model and raw-reducer
assurance flags remain false.
Then continue the remaining Model actions and partial packet observations,
followed by Python raw reduction and explorer raw/code provenance.

cvc5 1.3.4 returns incorrect UNSAT on
`membership-free-false-1-0-0`. The two-assertion reduction contains a canonical
one-entry signature log and `currentCandidate`. Setting the current index to
zero supplies a satisfying witness. cvc5 returns UNSAT without that equality,
then SAT after adding it. Its `--check-proofs --dump-proofs` invocation aborts
with an unclosed proof using the free assumption `(not true)`.
Z3 4.16.0 returns SAT on the same reduced script.
The false UNSAT occurs without MBQI too.
This is a solver trust-boundary failure, not evidence of a Model contradiction.
Later explicit pair-sort qualification removes that small cvc5 failure.
The Z3 migration remains justified by the qualified large-commit case:
cvc5 returns unknown at a 30-second budget, while Z3 returns SAT in 10 ms.
`native-qualified-large-commit-comparison.log` records that comparison.
The full qualified case matrix is `native-membership-qualified-cases.json`.
The cvc5 matrix probe stopped at that case; it did not complete all 1,140.

Session artifacts under `files/`:
- `native-membership-first-failure.log`: first failed default-runner case.
- `native_membership_probe.py`: repeatable clause and option isolation.
- `native-membership-probe/`: reduced scripts, results, and `cvc5-proof.txt`.
- `native-membership-cases.json`: all 1,140 generated scripts and expected verdicts.
- `native_membership_solvers.py`: explicit solver comparison with a five-second
  per-query measurement budget.
- `native-membership-z3.log`: all 1,140 cases match in 11.2 seconds.
- `native-membership-z3/results.jsonl`: individual outcomes and timings.
- `native-membership-weak.log`: partial alternative-cvc5 results.

`--arrays-weak-equiv` avoids the small false UNSAT, but rejects model generation
and returns unknown on many `10^30` commit cases within the measurement budget.
That experiment was stopped after the repeated failures. The original failing
batch was also stopped.
No expected verdicts or assurance flags changed.
Z3 is available at
`/nix/store/xv5zrxcpp6qj1lkbq1kxj5xfv017v39n-z3-4.16.0/bin/z3`.
`native_solver.py` now runs Z3 interactively and requests the core only after
UNSAT. `NativeEncode.compiledDetails` emits that query text. The native wrapper
now accepts `--z3`, not `--cvc5`. Version 2 encoding/run schemas retain the query
and solver identity; the explorer rejects older artifacts.
The complete Sparse proof build passes in `native-z3-protocol-build.log`.
Fifteen protocol/explorer tests pass in `native-z3-protocol-tests.log`.
The first full native run stopped after 14 methods, at
`test_proved_fixtures / queue-decode-invalid-term`. Z3 rejects an ambiguous
unqualified polymorphic `native_pair` constructor. The runner correctly rejects
the error instead of adopting the subsequent SAT line.
The renderer now qualifies pair constructors, including ground defaults, with
their explicit pair sort. Matching raw interpretation, syntax-safety, lowering,
and reference proofs pass in `native-qualified-pair-build.log`.
Z3 then returned unknown on the older `packet-match-0` fixture because of
incomplete quantifiers. `native_z3_packet_probe.py` records that diagnosis in
`native-z3-packet-probe.json`. `NativePacketMatch` now uses the already-proved
packet literal, removing the redundant field-by-field matcher. Its Model
correspondence statement is unchanged, and no expected verdict was relaxed.
All 152 proved formulas and 17 solver/explorer tests now pass in
`native-exact-packet-match-tests.log`.
The full Sparse build passed in `native-z3-final-build.log`.
The next suite stopped after 21 methods on a public append-packet observation
returning unknown. `native_z3_point_minimize.py` isolated the unrelated global
transaction-set tail quantifier as the cause. Packet observation alone was SAT,
as was its combination with each other initial clause.
`NativeNatSet` now guards membership with the finite extent and ignores raw
negative and tail cells. Its domain only requires a nonnegative limit.
The finite-set codec, initial frame, observations, frame preservation, trace,
and decoded-script proofs all build with the revised representation.
Four new kernel-backed formulas force raw tail cells to one but membership to
false. All 156 kernel-backed formulas pass. The sparse-ID script-size delta is
now 90 characters, with the index in two bounds and one lookup, not 30.
No expected solver verdict changed.
`native-finite-set-tests.log` records seven passing targeted methods, including
public packet observations, transaction membership, queue writes, and all local
fields. `native-finite-set-full-build.log` records the full Sparse/native build.
All 31 native Lean methods and 17 solver/explorer methods pass in
`native-migration-complete-tests.log`, taking 1,016 seconds.
Black and Ruff pass on all six affected Python files, retaining the pre-existing
EXE001 exclusion for the non-executable wrapper.
The full original failure remains in
`native-z3-full-tests.log`. New scripts are in
`native-lean-z3-fixtures/`, preserving the older cvc5 evidence separately.
The loopback explorer now serves the synthetic Z3/schema-v2 run from
`files/native-explorer-z3-run`, on `http://127.0.0.1:8091/api/run`.
Its shell handle is `native-explorer-api-v2`. Both run and core endpoints respond.
The old snapshot artifacts remain untouched. Both assurance flags remain false.

The user superseded the eager bounded-entry architecture described below.
Keep that implementation as a reference; do not resume its unfinished integration
as the delivery path.

The diagnostic aim and proof boundary are defined in
[Aim of trace validation](README.md#aim-of-trace-validation).
UNSAT identifies a disagreement among recorded facts, reduction, assumptions,
and the Model. It does not by itself identify an implementation bug.
The reducer's interpretation of implementation events remains a hypothesis to
test, not a proved implementation refinement.

The delivery boundary is now explicit: keep raw reduction in Python and move
the encoder, SMT construction, and observation-driven specialization into Lean.
The Python native-array emitter is a reference prototype, not the delivery
encoder. Moving string construction to Lean alone does not prove emission
correctness.

Python must emit an ordered Model-level input with source records, reduction
rule IDs, and event boundaries. Lean validates that input, asserts observations,
and only then uses those asserted facts to specialize encoding. This gives
specialization a proof premise without trusting Python's interpretation of the
raw trace. The requested stopping point includes reducer integration, not just
additional action prototypes.

The user also requested an explorer API and continued serial work through the
evening, with brief progress updates that do not end the work. The existing
`explore_checked.py` generates static HTML for the old checked backend.
The native explorer API must retain native-run inputs, instruction/constraint
provenance, and distinct solver outcomes without inheriting old proof claims.
Do not restart worker fan-out.

The first native explorer API is implemented in `explorer_api.py` and
`native_run.py`. Lean `encodeFrameDetails` emits named SMT clauses and instruction
ranges from the actual compiled assertion array. `native_lean.py` retains the
exact input, encoding metadata, solver outputs, and a hash manifest written only
after a successful solver invocation. Z3 supplies the core in response to the
Lean-emitted query; Python does not construct SMT queries.
The API is read-only, binds to loopback, and serves a fixed startup snapshot.
It exposes run status, input, paginated instructions, named constraints, and the
solver core. It rejects mixed artifacts and never adopts old checked-backend
proof claims. `Traces/native_quorum_conflict.json` is a deliberate synthetic
UNSAT example, not a captured trace. Raw-event/code provenance still depends on
reducer integration. See README's "Native explorer API" section.

The public Lean encoder uses `Sparse/NativeFrameEncode.lean`
and `Sparse/NativeEncodeMain.lean`, with `native_lean.py` as its JSON and solver
wrapper. It shares local-state compilation with `Sparse/NativeEncode.lean`.
It supports `checkQuorum`, `requestVote`, `requestPreVote`, and all sixteen local observation kinds, including
the nullable `retirementIndex`, `retirementCommittableIndex`, and
`retiredCommittedIndex` fields, nullable `votedFor`, both vote sets, and
`membershipState`, `sentIndex`, and `matchIndex`, plus global `hasJoined` and
`preVoteStatus`, `retirementCompleted`, and `submittedTxId`, plus `queueLength`
and exact `queuePoint` observations of all seven packet kinds.
The Python reference still supports six actions and the broader observation
schema. Do not confuse these coverage levels or fall back to Python SMT emission.

`Sparse/NativeSmt.lean` now builds. Its denotation must remain reducible so that
Lean can resolve the underlying integer, Boolean, and bitvector instances.
The typed AST supports native arrays, scoped quantifiers, arbitrary-width bits,
products, and sums. cvc5 rejected symbolic `as const` array values, so that
constructor was removed. The later `Term.defaultValue` constructor permits
only ground defaults. Use explicit quantified constraints for symbolic resets.
`NativeSmtFixtureMain` supplies kernel-proved formula verdicts to the solver
suite. `NativeEncodeProofs` proves the bitset/configuration selectors and
assertion-backed allocation specialization. Normal `lake build Sparse` includes
the new core and encoding axiom audits.

Fresh definitions now use `NativeEncode.define`. The `Encoding.symbolsBounded`
invariant keeps assertion symbols below `next`, and definition inputs are
checked before allocating the new index. `NativeSmt.Term.eval_congr` and
`eval_set_of_fresh` prove symbol locality. `fresh_binding_exists` and
`NativeEncode.definition_preserves_satisfiability` justify adding a fresh
equality binding to the existing typed assertions.
The locality proof uses structural recursion over terms. Automatic dependent
induction exceeded the default heartbeat budget; no budget increase was needed.

The first Lean action emitter matches 150 actual-Model `checkQuorum` cases.
It also handles 21 identities and a trillion-entry symbolic log. The wrapper
retains solver artifacts and distinguishes SAT, UNSAT, unknown, and input errors.
The internal Lean input is canonical JSON to reject duplicate-key text before
any encoding. The Python wrapper accepts ordinary JSON and canonicalizes it.

The supported trace now has a Model-to-script theorem, and the actual JSON
compiler establishes its compilation and initial-state premises.
Full Model coverage remains unfinished. Queue-point clauses use proved
observation-directed packet literals, retaining the complete observed value.
Reducer integration, remaining action coverage, and initial-state materialization
remain unfinished. The new Lean encoder is experimental, not a proved validator.
`Sparse/NativeQuorumEncoding.lean` now connects the exact `currentCandidate` and
`noLaterConfiguration` expressions used by `checkQuorum` to
`NativeArrayCheckQuorum.CurrentIndex` and actual `currentConfigurationAt`.
`ConfigurationLogRep` explicitly assumes matching live-log contents, length,
and commit index. The proof converts the SMT integer scan to natural Model
positions and derives a natural current-index witness from the asserted domain.
The refactor preserves all 150 previously emitted Model-case scripts byte for byte.

`other_configuration_exact` now characterizes the exact peer-guard expression,
including the bootstrap branch where the physical witness is unused.
`other_configuration_exists_correct` and `configuration_guards_exists_correct`
connect both existential index assignments to `CurrentIndex` and `OtherAt`.
Assigning these integer witnesses leaves the represented log state unchanged.

`Sparse/NativeNodeEncoding.lean` now defines `NodeColumnsRep` for the supported
currently observed column kinds. `node_columns_model_enabled` connects the exact
shared `leadingGuards` and `configurationGuards` expressions to actual Model
enabledness. `node_columns_model_step` connects `stepDownRole` and
`stepDownFollower` stores to the actual Model successor. The full native-array
record correspondence proves that unobserved Model fields are preserved too.
Both results assume the input representations; they do not establish them.
The refactor still preserves all 150 old emitted Model-case scripts byte for byte.

`Sparse/NativeValues.lean` now contains the shared role, node-set, and entry
codecs. It proves both value round trips under explicit natural-number domains,
plus correspondence for the emitted entry-domain and entry-literal expressions.
`Sparse/NativeInitialEncoding.lean` connects the actual `initialAssertions`
list to per-node domains and realizes those domains as `NodeColumnsRep` and
a Model state. This is the soundness direction for the initial columns.
Its proof-only witness chooses fresh values for unobserved fields; the emitted
clauses do not impose those values. The normal Sparse target audits both modules.

`model_initial_assertions` now proves the converse for arbitrary Model states.
`initialAssignment` populates the initial columns from native arrays and
retains the seed assignment's other symbols. The original Model state remains
the represented state, so its unobserved fields need not be fresh.

The JSON decoder now returns typed `NativeArrayCheckQuorum.Instruction` values
with identities in `Fin width` and actual Model entry payloads. The encoder uses
`entryTerm` and the shared `observationClauses` rather than constructing
observation expressions in the JSON parser. `NativeObservationEncoding` proves
the supported observation kinds against actual Model observations.
Entry equality uses the live-index assertion before applying the value-domain
round trip. The refactor preserves all 150 earlier Model-case scripts exactly.

`NativeCompilerEncoding` now proves exact assertion append and block sequencing
for the actual state transformer. `observation_instruction_success` connects
executed observation instructions to Model observations while retaining the
existing assertions and column references. `initial_domains_success` connects
the executed initial block to its node domains. Shared `assertAll` replaces
the four separate assertion loops. The assertion and fresh primitives expose
their state transformations directly instead of hiding them behind monadic
get/set operations.

`fresh_success`, `define_success`, and `define_satisfiability` now connect actual
allocation and definition execution to symbol freshness and satisfiability.
`quorum_success` proves the exact ordered clauses and all four new symbol IDs
produced by actual `checkQuorum` execution. `quorum_model_success` takes a
satisfying assignment for that block to an enabled Model step and represented
successor, retaining the predecessor assertions.

`compileInstructions` is now the shared typed trace driver used by the JSON
wrapper. It retains instruction groups and indexed errors while accumulating
groups without repeated concatenation. `NativeTraceEncoding` proves prefix
assertion preservation and whole-trace soundness for that actual driver.
`compiled_trace_model` combines the executed initial block with the whole
ordered trace to produce one Model execution from one satisfying typed-term
assignment. Its inputs identify the initial role/follower columns and the
matching bootstrap set. It does not establish SMT text semantics.

`NativeSmt.Assignment.AgreesBelow` now captures agreement on earlier symbols.
`NativeAssignmentEncoding` proves that fresh extensions preserve existing
assertions, node columns, and initial domains. `ReferencesValid` tracks the
static columns and current role/follower references below the fresh counter.
`quorum_complete` constructs witnesses and both array assignments for every
enabled native step without changing earlier symbols.

`NativeTraceCompleteness.compiled_trace_iff` now proves both directions for
the complete supported typed trace. Its premises are successful initial and
trace compilation, an initially empty assertion list, initial columns 1 and 2,
valid references, and the matching bootstrap set. The completeness direction
starts from an arbitrary Model state, not a bootstrap-reachable state.
`Assignment.default` supplies otherwise unused proof-witness values; it emits
no default-state constraints.

`NativeSExpr` now parses and renders the generated unquoted S-expression
grammar, with a kernel-proved safe-atom round trip and malformed-input cases.
`Ty.syntax` and `Term.syntax` are the actual trees used by the native renderer.
`NativeSyntaxProofs` proves that every emitted sort and term parses back to its
tree. It reuses the existing decimal-token safety proofs, not the old bounded
encoder. The old syntax reader has a closed atom vocabulary and cannot parse
the new native sorts or binders.

`NativeNames` now decodes recursive sort codes and full free-symbol names.
`symbolName_injective` rules out collisions across sorts and IDs.
Bound names round-trip separately and cannot equal free names.
The renderer uses shared `Variable.level` and `binderName` definitions.
`NamedLocals.Rep.cons` proves that binding at the current context length
represents the new local value without changing older scoped reads.

`NativeInterpretation` now interprets raw expression trees, including parsed
sorts and names. It rejects wrong types and arities. Quantifiers require a
Boolean body for every bound value, and matches check both branches' result
sorts even when one branch is not selected.
`NativeLowering.Term.syntax_eval` proves correspondence for every constructor.
`Term.render_eval` composes it with the parser round trip, and
`Term.closed_render_eval` starts from an empty named environment.
Both modules pass the normal Sparse axiom audit without new axioms or budgets.

`NativeScript` now owns `renderScript`, which renders explicit command trees
instead of interpolating command strings. Its kernel proof pins the exact
datatype prelude. `NativeScriptSyntax` proves that every generated command
parses back to its tree and that declarations parse to their original sort
and ID. Mismatched sorts and bound-variable names fail declaration parsing.
The refactor preserves all 150 old Model-case scripts byte for byte.

`NativeScriptText` now proves `script_text_parses` for the complete emitted
script. Safe generated expressions contain no LF characters, so each command
occupies one line. The reader requires the final LF, rejects blank command
lines, and parses every line. This is the emitted format, not a general
SMT-LIB layout parser. The proof uses the shared expression parser and
`List.splitOn_intercalate`; it does not add another token parser.

`NativeReferences` now scans raw expression atoms in the same numeral-first
order as interpretation. `Term.syntax_symbols` proves that the scan finds
exactly the typed term's free references, including references under binders.
`declared_syntax_symbols` proves that the generated declarations cover every
reference. `declaration_names_unique` rules out duplicate declaration names
after deduplication.

`NativeScriptRun` now interprets complete generated scripts. It requires the
fixed prelude, rejects duplicate or mismatched declarations, and permits
declarations only before assertions. It checks reference coverage, Boolean
assertion values, indexed named wrappers, and the single final `check-sat`.
It also rejects a malformed suffix after a false assertion.
`script_text_holds` proves equivalence with typed assertion satisfaction.
[`NativeScriptTrace`](Sparse/NativeScriptTrace.lean) proves
`NativeEncode.compiled_script_iff` by composing this with `compiled_trace_iff`.
The emitted text has a satisfying
assignment exactly when the supported Model trace has an execution, under
the same successful-compilation and initial-state premises. Both named and
unnamed scripts are covered. The SMT interpretation is explicit Lean
semantics for the generated subset; the solver itself is not verified.

`NativeEncode.decodeDocument` now produces `Decoded`, carrying a positive
width, a nonempty bootstrap set, and typed instructions. It checks nonemptiness
on the decoded set rather than retaining a separate source-array check.
`initialEncoding` and `compileDecoded` are shared by the actual JSON path.
[`NativeDecoded`](Sparse/NativeDecoded.lean) proves that successful compilation
establishes the initial columns, empty assertion list, reference bounds,
bootstrap, and trace-execution premises.
`encode_document_iff` covers plain output. `encodeDetails_document_iff` covers
the actual script field returned in details mode. Both equate script
satisfiability with `DocumentConsistent`, defined through the actual decoder.
The proof-only bootstrap witness chooses a member of the nonempty set. It
does not impose an initial leader or fresh initial Model state in SMT.
Lean's JSON parser, IO runtime, and the solver are not verified by these theorems.

Next, expand Model actions and observations before raw reducer integration.
Keep the full-model assurance flag false: current coverage is still one
action, sixteen local observation kinds, all four global observation kinds,
queue lengths, and exact queue packet points. Partial packets remain unsupported.
No change to the reducer's untrusted
interpretation boundary follows from proving the JSON encoder.

`NativeFrameEncode` wraps the local compiler in the broader
`NativeArrayVote.Instruction` family. `hasJoined` uses scalar bitvector column
16, and fresh allocation starts at 17. The local-column script hash baseline
is therefore obsolete. The field is independent of node allocation and
bootstrap membership, and accepts duplicate or reordered declared identities.
`NativeFrameColumns` proves initial representation and completeness for
arbitrary frames. It seeds global values before reusing node initialization.
`NativeFrameStep` reuses the existing quorum proofs and preserves global state.
`NativeFrameTrace.compiled_frame_trace_iff` proves whole-trace correspondence.
`NativeFrameDecoded.encodeFrame_document_iff` and
`encodeFrameDetails_document_iff` cover the public JSON-to-script path.
The normal Sparse build audits the entire proof chain. The joined-set slice
passed the 31-test combined native suite, including conflicts, 21 identities, quorum
framing, malformed inputs, and actual wrapper/explorer core ownership.
`preVoteStatus` adds Boolean-array column 17, with fresh allocation starting
at 18. Both `capable` and `enabled` are valid for every declared identity,
regardless of allocation or bootstrap membership. `NativeValues` proves its
Boolean decoding and equality. The full initial-state, frame, trace, and
JSON-to-script correspondence includes the field. `nodeArray` supplies the
completeness assignment without a new indexing helper. Generated framing
cases now distinguish allocation-guarded local fields from global fields.
`retirementCompleted` adds bitvector-array column 18, with fresh allocation
starting at 19. The full proof chain covers independent per-node sets without
source or member allocation constraints, or relationships to local retirement
state. The generated cases cover all identities, duplicate and reordered
members, absent nodes, mixed rows, and preservation across quorum steps.
Six targeted methods passed, covering both newer globals, strict input errors,
joined sets, and all 150 Model quorum cases.
`submittedTxId` now has its full correspondence proof and solver coverage.
Column 19 stores one-bit cells, column 20 is the unknown finite support limit,
and fresh allocation starts at 21. `initialFrameDomains` combines node domains
with the finite-set domain. `NativeNatSet.natSetMember` now requires both an
in-range index and bit one. The initial zero-tail constraint described in this
checkpoint was replaced by extent-guarded reads during the Z3 migration above.
The initial Boolean-cell implementation returned `unknown` on a mixed-global
SAT case after about 32 seconds. The same constraints with one-bit cells solved
in about 27 ms. No bounds or observations were dropped. Solver-option changes
did not fix the Boolean case, and no solver flags were changed.
The build `native-submitted-bit-complete-build.log` in session files passes
the full Sparse proof chain. Seven targeted methods passed in
`native-submitted-bit-tests.log`, including all global fields, strict input
errors, all 150 Model quorum cases, and actual wrapper/explorer core ownership.
The fixture method initially failed because a Lean linter warning preceded
its JSON output. The proof was rewritten to remove that warning, and all
31 kernel-backed formulas passed in `native-submitted-fixture-tests.log`.
The sparse-ID case initially grew by 30 characters when replacing zero with
`10^30`. Extent-guarded reads now grow by 90 characters, without allocating or
enumerating intervening cells.
`Assignment.set_other_index` avoids assuming distinct sorts when writing
other symbol IDs. This matters when the node universe also has width one.
Packet observations, remaining actions, and raw reducer integration are still
unsupported by the public encoder.
Continue source-local packet observations, then the already-proved native vote
and campaign actions. Do not stop at
observation coverage; reducer integration is still the requested delivery boundary.

`NativeRenaming` now supplies typed renaming and `Term.weaken` for packet logs
under nested index binders. `rename_eval` and `weaken_eval` prove capture-free
value preservation, and the corresponding symbol theorems preserve free
references. The normal Sparse target audits the module. Three new fixtures
cover nested quantifiers, sum-match branches, and free array reads.
All 34 kernel-backed formulas pass in `native-renaming-fixture-tests.log`.
No public instruction coverage changed in this supporting slice.

`NativeLogValue` now proves a canonical length/array codec for packet payloads.
`logDomain` constrains live entry values and fixes negative and tail cells to
the zero-term signature entry. `log_value_model`, `model_log_value`, and
`model_log_eq_iff` make whole-array equality exact for finite Model lists.
The domain uses the proved `Term.weaken` when adding its integer index binder.
The node-log representation remains unchanged. Packet instructions are not
yet accepted by the public encoder.
All 40 kernel-backed fixtures pass in `native-log-fixture-tests.log`.
The fixture main now sets `warningAsError` so linter warnings fail its build
instead of preceding and corrupting its JSON output.
Next build packet headers and payload sums on this codec, then queue columns.

`NativePacketHeader` now proves the shared header codec and actual domain
expression. It reuses `nodeValue?` and `optionalNodeDomain` rather than adding
another identity decoder. `modelPacketHeader` requires valid identity domains,
and the full value round trips and emitted literal equality are proved.
All 48 kernel-backed fixtures pass in `native-packet-header-fixture-tests.log`,
including first/last identities, a single-node universe, huge terms, and
invalid terms or identities. No allocation or source/destination inequality
constraint was added. Next compose the seven payload alternatives with this
header and `NativeLogValue`; packet JSON and queue columns are still pending.

`NativePacketValue` and `NativePacketDomain` now cover all seven Model message
constructors. A shared header is paired with a tagged payload sum; append
payloads contain the canonical `NativeLogValue` array. Both complete packet
round trips and exact equality are proved. The actual emitted payload/full
domains and source selector also have correspondence proofs.
No relationships among term/index fields were added beyond natural-number
domains. Distinct vote and pre-vote tags remain distinct, and packet sources
or destinations need not be allocated or differ from each other.
All 62 kernel-backed formulas pass in `native-packet-fixture-tests.log`,
including valid alternatives, invalid scalar fields, append-log domain
composition, and tag/source behavior.
`NativeQueueScalars` now supplies source-local scalar decoding, with full
public JSON-to-script correspondence. Column 21 is a destination-first,
source-second integer matrix. Fresh allocation starts at 22.
Each raw integer cell decodes with `Int.toNat`; the emitted `ite` implements
that function. `FrameColumnsRep.queueLength` relates decoded values to the
native queues. No universal queue-length domain remains.
`initialFrame` constructs source-correct queue witnesses directly, replacing
the empty-network template. Neither endpoint must be allocated.
`initial_frame_assignment_rep` preserves arbitrary original frames in the
completeness direction. Quorum steps preserve queue lengths.
The normal Sparse proof build passes. There are now 115 kernel-backed formula
fixtures, including positive and negative raw-cell decoding.
The public queue regression includes one, two, and 21 identities, large lengths,
strict input errors, independent pairs, and quorum framing.
Its first run exposed an incorrect test expectation: `checkQuorum` requires a
distinct configuration peer and is therefore disabled in a one-identity universe.
That expectation is corrected. All 47 queue cases pass in
`native-queue-length-corrected-tests.log`. Four other targeted methods passed
in `native-queue-length-tests.log`, covering strict queue input, submitted sets,
all 150 Model quorum cases, and actual wrapper/explorer outcomes.
The baseline is correct but slow: a 21-node, zero-length observation takes
50.6 seconds to solve. The session's `native_queue_domain_probe.py` compares
the same finite constraints as nested quantifiers, row-wise quantifiers,
and ground assertions. Those variants took 50.6, 13.9, and 9.7 seconds.
A total nonnegative-cell domain also took about 9.5 seconds, but returned
`unknown` for independent-pair cases. That representation was rejected.
Natural-number decoding took 9.4 seconds and solved those cases.
`queue_scalar_correct` proves the emitted read equals the cell's `Int.toNat`.
The complete initial-state, instruction, trace, and JSON-to-script proofs build
without a queue-domain premise. Completeness still represents the original
arbitrary frame, not a replacement with different queues.
Six targeted methods pass in `native-queue-decoded-tests.log`, including all
47 queue cases, strict queue input, all 73 formulas, submitted sets, all 150
Model quorum cases, and actual wrapper/explorer outcomes. Total time was
209.814 seconds. The actual encoder's 21-node zero-length case takes 9.7 seconds,
down from the baseline's 50.6 seconds.
Readback must expose the decoded natural count, not the raw integer cell.
The test helper now retains status, wall time, and script size in per-formula
`.metrics.json` files when `CCF_NATIVE_ARRAY_ARTIFACTS` is set.
Next add live packet cells and observations. Packet observations remain unsupported.

`NativeLogMatch` supplies finite literal matching for append-packet logs.
`logMatches` compares the length and each supplied entry. `log_value_eq_iff`
uses the canonical tails to connect those checks to whole-array value equality.
`log_matches_correct` connects the actual emitted expression to Model list
equality. No constant-array constructor or packet-log size bound was added.
`NativeEncodeProofs.all_eval` supplies shared conjunction correspondence.
The standalone proof passes. Six new fixtures cover empty logs, missing entries,
duplicates, proper-prefix rejection, large transaction payloads, and order.
The full build passes in `native-log-match-final-build.log`, and all 79 formulas
pass in `native-log-match-fixture-tests.log`.
Next compose packet literal matching from the header, payload tags/scalars,
and this log matcher, before wiring live queue cells.

`NativePacketMatch` now proves full literal matching for all seven constructors.
`appendPayloadMatches` combines scalar equality and `logMatches`.
`packetPayloadMatches` preserves each protocol tag, and `packetMatches`
checks the header too. The proofs connect actual emitted expressions to
`modelPacket` equality under the existing packet domain.
The normal Sparse target includes the module. All 103 formula fixtures pass
in `native-packet-match-fixture-tests.log`.
`SatCase` adds genuine SAT witnesses to the fixture suite, rather than requiring
every satisfying formula to be true for every assignment. Seven packet fixtures
use `packetValue` as the witness. Seventeen conflict fixtures cover every tag,
all header fields, append scalars, and log length, order, duplication, and values.
Both fixture collections have the allowed-axiom audit.
No public packet observation is accepted yet. Next wire queue head/live cells
with source-partition validity, then strict packet decoding and observations.

The universal live-queue packet domain was measured and rejected. A row with
head and length `10^30` returned `unknown` after 34.3 seconds. Its script and
metrics are retained as `native-universal-queue-row-baseline.*` in session files.
The uncommitted universal row/cell emitters were removed rather than weakening
the expected SAT verdict or imposing a queue-size bound.

`NativeQueueDomain.queuePacketDomain` checks one raw packet's validity and source.
`NativeQueuePacket.modelQueuePacket` gives every raw cell a source-correct Model
interpretation. Valid source-correct cells decode normally; others represent
`defaultQueuePacket source`, a zero-term self-addressed ProposeVote.
This is an internal storage codec, not permissive JSON decoding.
`model_queue_packet_value` preserves every valid Model packet from its source.
`queue_packet_term_correct` proves the corresponding datatype-valued `ite`.
That direct `ite` still caused cvc5 `unknown` in two point-observation fixtures.
`queuePacketMatches` now specializes its Boolean clauses using the expected
packet, retaining the full observation. If it is not the default, the clauses
assert both raw validity/source and the raw packet match. Otherwise they permit
either an invalid raw cell or a matching raw packet. Both branches are proved
equivalent to the total decoder.

`NativeQueuePoint.modelQueue` constructs a well-formed native FIFO from arbitrary
raw cells. `model_queue_complete` preserves every original source-correct
FIFO's decoded sequence, including duplicate packets and nonzero heads.
`queue_point_correct` proves actual emitted live-index and packet matching
against the native queue's list lookup. There is no universal live-cell premise.
All 115 formulas pass in `native-queue-observed-packet-tests.log`.
The huge-row fixture now observes its first and last packets and solves in
11.4 ms. The append-packet row solves in 32.1 ms. Solver metrics are retained.

`NativeQueueColumns` now integrates complete queue storage into the public
frame representation. Length remains column 21, head is column 22, and
packet cells are column 23. Fresh allocation starts at 24.
`NativeQueueLengths` was renamed to `NativeQueueScalars`; the same natural
decoder now serves both head and length.
`queueRow` uses the total packet decoder for initial realization.
`FrameColumnsRep.queues` equates decoded live lists. Queue-length correspondence
is derived from that equality. Unused raw cells need not match unused native cells.
`initial_frame_assignment_rep` takes `frame.Valid` for source correspondence,
already available from `of_model_valid` in trace completeness. It still
preserves arbitrary valid original Model states.
The full public proof and normal Sparse build pass. Seven runtime regression
methods pass in `native-queue-columns-tests.log`, including queue lengths,
all 115 formulas, all 150 Model quorum cases, global/local framing, and actual
wrapper/explorer outcomes. Total time was 220.271 seconds.
The following slices integrate strict packet JSON and public `queuePoint`.

The public queue-point slice exposed two solver failures when append-packet
observations were combined with quorum constraints. Their expected verdicts
remain SAT. The original two-node and 21-node scripts are preserved in session
files under `native-packet-observation-probe`, with metrics.
The rerunnable `native_packet_observation_probe.py` compares unchanged scripts,
literal tail guards, exact quantified cells, existential construction, and
ground constant-array construction. Only the ground construction solved both
cases, in 59 ms and 9.7 seconds. Nested MBQI did not fix the original formula.
No solver flags or Model bounds changed.

`Term.defaultValue sort` emits `Ty.defaultSyntax` and denotes `Ty.default`.
The constructor takes no expression, so a symbolic `as const` cannot be emitted.
The syntax, interpretation, declaration/reference, and renaming proofs cover
the constructor. Eight new kernel-backed fixtures cover all default sorts,
one-bit and 21-bit arrays, nested arrays, and a large negative read index.
The normal Sparse build passes in `native-ground-default-complete-build.log`;
all 123 formulas pass in `native-ground-default-fixture-tests.log`.
`NativeLogTerm.log_term_eval` now proves that finite stores over a ground default
array equal the complete canonical packet log, including negative and tail cells.
`NativePacketTerm` constructs all seven packet literals with full value
correspondence. `queuePacketMatches` now asserts literal equality and the
expected source partition. Only the default-packet case retains the invalid
raw-cell alternative from the total decoder. Its correspondence theorem still
has no raw packet-domain premise.

`NativePacketJson` strictly decodes every packet field and append entry.
The public `queuePoint` path now builds through `NativeFrameDecoded`.
Seven runtime methods pass in `native-public-queue-ground-tests.log`, covering
all packet kinds, scalar and log conflicts, independent pairs, duplicate
packets, huge positions, quorum framing, 123 formulas, queue lengths, and
actual wrapper/explorer core ownership. The 168 existing Model fixtures also
round-trip their packet JSON through the new decoder and independent serializer.
Malformed packet/point inputs pass separately in `native-public-packet-input-tests.log`.
The former two-node failure now solves in 57.7 ms with 11,314 bytes.
The 21-node case solves in 9.8 seconds with 60,173 bytes.
The full normal Sparse build passes in `native-ground-queue-final-build.log`.
No queue bounds, missing-packet defaults, or solver-option changes were added.
Next integrate the existing native action semantics with public Lean emission
and correspondence. Partial packet observations, raw reduction, readback, and
raw/code explorer provenance remain unfinished. Both assurance flags stay false.

`NativeSignatureEncoding` now supplies the shared scan needed by vote sends
and campaigns. `signatureAtTerm` checks the positive, live one-based index
before inspecting content. `signatureIndexTerm` accepts zero or a signature
position and excludes later signatures with an integer quantifier.
The proofs cover arbitrary scoped terms, recover natural witnesses from the
emitted guards, and connect the result to actual `maxCommittableIndex`.
They reuse `ConfigurationLogRep`; no log-length or identity bound was added.
The normal Sparse target imports and audits the module.
`NativeSignatureFixtureMain` generates all 85 logs of length zero through three
over the four entry kinds, then checks every candidate from -1 through length+1.
All 483 Model-derived cases pass in `native-signature-model-tests.log`, including
85 SAT cases. The proof build is `native-signature-final-build.log`.
This is action-encoding support, not another publicly accepted action.
Next prove active-peer membership, last-committable term construction, and
FIFO append storage, then wire requestVote/requestPreVote through the compiler.

`NativeQueuePush` now proves the row-level append used by sends.
`queuePushCells` stores at decoded head plus decoded length.
`model_queue_push` equates the full decoded queue structure with native
`Queue.push`, and `queue_push_cells_correct` gives exact list append for the
actual emitted store. The packet must have the row's source; old raw cells
need not have a packet-domain proof. Duplicate packets are not suppressed.
The normal Sparse target includes the module. All 152 kernel-backed formulas
pass in `native-queue-push-fixture-tests.log`.
The 29 new cases cover each packet kind at empty, nonzero, and `10^30`
head/length positions, two identical pushes per packet kind, and preservation
of every other raw cell. Build log: `native-queue-push-fixture-build.log`.
`NativeQueueStore` now updates the outer destination/source columns and
allocates fresh length and packet versions. Both definitions capture the old
columns, so the append position uses the old length. Packet symbols are checked
before either allocation. A reference at the original fresh counter is rejected
even though it would become allocated by the first definition.
`NativeQueueStoreEncoding` proves the actual execution shape, assertion
semantics, valid references, complete frame soundness, and completeness.
`define_extension` in `NativeAssignmentEncoding` extends a specific satisfying
assignment and preserves all earlier symbols. Queue completeness composes that
helper across the two executed definitions.
The normal Sparse target imports these proofs.
`NativeQueueStoreFixtureMain` supplies 56 actual-execution solver cases,
using `NativeArrayQueue.send` to compute expected observations after each send.
Each case interleaves six sends across directed and self queues, preserving
duplicates and earlier packets. All seven kinds run with empty, nonzero,
`10^30`, and negative raw head/length values. The latter use the proved `toNat`
interpretation. Five cases reject unallocated packet symbols before and after
a send, including the original fresh counter. A permitted old packet symbol
also runs through the allocator.
All 56 cases and the 152 kernel-backed formulas pass in
`native-queue-store-tests.log`. The proof build is
`native-queue-store-final-build.log`.
This completes internal send storage, not public action integration.
Next prove active-peer membership and last-committable packet construction,
then wire requestVote/requestPreVote through the compiler and trace theorem.
Reducer integration, readback, and raw/code explorer provenance remain pending.

`NativeOptional` is the next value-codec unit for local-state coverage.
It uses the existing sum datatype for optional natural indices and identities.
Decoding distinguishes a valid absent value, `some none`, from invalid payloads,
`none`. It rejects negative indices and identities outside the declared width.
The proofs cover round trips, exact literal equality, and actual domain terms.
`NativeSmtFixtureMain` now has 115 kernel-backed solver cases, including nine
optional-value cases. The codecs are now wired for all three retirement-index
fields and `votedFor`.

`Encoding` now inherits `Columns`, the record of column references.
`SameReferences`, `fresh_success`, and `define_success` preserve the complete
column record. `QuorumResult.columns` specifies the record update, with
derived role and follower equalities for callers. All prior scripts remain
byte-for-byte unchanged.
`NodeColumnsRep`, `observationClauses`, and their callers now take this record
instead of separate role and follower indices. Quorum representation updates
retain the predecessor record's unchanged fields. Trace and script proofs
now assume the default initial column record rather than separate role and
follower premises; the actual JSON compiler discharges this premise.
That refactor left the prior scripts unchanged.

The first new column, `retirementIndex`, is now complete. Column 7 stores
optional natural values, and fresh allocation starts at 8. Each identity has
an allocation-guarded domain clause for that column. Missing nodes read `none`;
allocated nodes retain arbitrary valid optional indices. The initial-state,
quorum-frame, observation, assignment, whole-trace, and JSON-to-script proofs
all cover the new field. Solver cases cover null versus zero, a `10^30` index
with an empty log, explicit absent nodes, conflicting observations, and
preservation across quorum steps. Invalid JSON values remain input errors.
The new domain clauses and fresh-symbol numbering intentionally change the
old scripts, so the pre-retirement hash manifest no longer applies.
`retirementCommittableIndex` now adds column 8, with fresh allocation starting
at 9. The same complete proof chain covers this field. The generated optional
observation matrix runs the same cases for both fields and checks that distinct
field values remain independent through a quorum step. No ordering or log-length
bounds were added. Domain correspondence now uses the `NodeDomain` structure
instead of repeating every field in an intermediate conjunction.
`retiredCommittedIndex` adds column 9, with fresh allocation starting at 10.
Its initial-state and full trace/script correspondence are complete.
The generated observation matrix now exercises all three retirement fields.
`votedFor` adds column 10 and an allocation-guarded optional-identity domain.
Fresh allocation now starts at 11. The initial-state, observation, assignment,
quorum-frame, and JSON-to-script proofs cover the field. The shared optional
observation generator exercises nulls, conflicting values, absent source nodes,
and frame preservation for both indices and identities. Identity cases use
21 declared nodes, self votes, and an absent target outside the bootstrap set.
No target-allocation or configuration-membership constraint was added.
`votesGranted` adds bitvector column 11, with fresh allocation starting at 12.
The identity universe determines its width, so no additional value-domain
constraint is needed. Initial realization, Model completeness, observation
equality, quorum preservation, and the JSON-to-script theorem cover the field.
The shared frame-case generator covers optional fields and vote sets.
Set-specific cases cover ordering, duplicates, 21 identities, and absent voters
outside the bootstrap set. `NativeValues` now proves empty-set encoding and
encoding injectivity. Normalize bitvector literals with `BitVec.ofNat_eq_ofNat`
before applying representation equalities if simplification changes `0` to `0#width`.
`preVotesGranted` adds bitvector column 12, with fresh allocation starting at 13.
The same proof chain covers this set, and the generated cases now run for
both vote sets. A separate case preserves distinct values for the two sets
across a quorum step.
`membershipState` adds integer column 13, constrained to codes 0 through 4.
Fresh allocation starts at 14. The existing membership equivalence now lives
in `Shared/Membership.lean`; `SymbolicModel.membershipEquiv` remains an alias
for compatibility. Native code uses this pure mapping without importing the
bounded codec. All five states have observation and quorum-frame cases.
An absent node reads `active`, but a membership observation does not imply
retirement-index values or bootstrap reachability. Initial realization and
the full JSON-to-script proof cover arbitrary membership states.
`sentIndex` adds nested integer-array column 14, with fresh allocation at 15.
`peerIndex` reads zero for an absent source and otherwise selects the peer cell.
`NativePeerEncoding.peer_domain_correct` proves that the actual quantified
SMT domain covers exactly the declared identities. Outside-universe cells are
ignored, not zeroed. The initial-state and full JSON-to-script proofs now cover
the table. Generated cases include independent rows and peers, self cells,
21 identities, absent peers, and indices of `10^30` with an empty source log.
`initialAssignment` proofs unfold `entryTy` to distinguish nested integer arrays
from nested entry arrays.
`matchIndex` adds nested array column 15, with fresh allocation starting at 16.
All local observations now have initial-state, frame, observation, and full
JSON-to-script correspondence. `instruction_has_encoding` proves total
classification of the local instruction type. `instruction_cases` reuses this
classification and the existing execution theorem instead of repeatedly
unfolding the compiler. Domain correspondence uses direct record construction:
general proof search exceeded the default heartbeat budget at this field count.
No proof budget was increased. The combined native suite has 30 passing tests,
including a trace observing every local field before and after quorum.

Next migrate global and queue state and the broader instruction type from
`NativeArrayVote`, then the remaining actions, before raw Python reducer
integration. Do not mark the full-model or raw-reducer assurance flags true.
The current runtime action is still only `checkQuorum`.

`NativeNatSet` is the first global-value unit. `natSetDomain` initially emitted
a finite-prefix one-bit-array constraint, including negative cells and the tail.
The Z3 migration replaces that constraint with a nonnegative limit and guards
membership reads by the extent. Decoding ignores raw cells outside that extent.
`nat_set_domain_correct` characterizes that expression. `natSetArray` requires
the domain proof before constructing a finite Model set, and the membership
and observation theorems are exact. `natSetAssignment` realizes every finite
natural-number set, preserving the seed's other symbols. Its chosen limit is a
proof witness, not a runtime bound inferred from observed transaction IDs.
Six new kernel-backed solver cases cover negative cells, the limit cell,
large indices, negative limits, and an empty prefix. The normal Sparse audit
includes this module. All four global JSON observation kinds are now wired.

The reference record is now named `Columns`, with projection `toColumns`.
Global references share this record and the existing symbol allocator.
`NodeColumnsRep` remains the node-specific representation relation.
The rename preserves all 150 Model-case scripts byte for byte.

`TypedDocument` now parameterizes the instruction family. `Decoded` is its
local-instruction specialization. `decodeDocumentWith` shares identity and
bootstrap validation, and `compileInstructionsWith` shares ordered emission,
indexed errors, and clause grouping. The existing decoder and driver specialize
these functions, retaining the JSON-to-script theorem and all 150 script hashes.
Use these functions for the broader `NativeArrayVote.Instruction` compiler
rather than copying either path.

Follow [Representation design priorities](README.md#representation-design-priorities):
start with the simplest representation to prove correct, using native SMT
arrays and live lengths. Measure representative solver workloads before
introducing more complex representations. Optimize measured bottlenecks only
when the solver-time gain justifies the additional correctness proof.
The existing sparse proof library is available work, not a requirement to
reuse its architecture in the revised encoder.

The first delivered native-array slice is described in
[Native-array prototype](README.md#native-array-prototype).
`Sparse/NativeArrayCheckQuorum.lean` proves direct-array execution equivalence
for the actual `checkQuorum` action and all local node-state observations. The standalone
`native_arrays.py` emitter uses native arrays and trace-sized identity sets.
Its printer is tested against actual Model guards, but is not covered by the
Lean theorem. Normal `lake build Sparse` includes the new axiom audit.

The FIFO correction is implemented in `CCFRaft.enqueue`, the source-local
queue correspondence, and existing encoder send accounting. Repeated equal
heartbeats and replies are retained. The guarded AppendEntries equality
branch is gone. See [FIFO Model sends](README.md#fifo-model-sends).

The native FIFO storage primitive is also implemented in
`Sparse/NativeArrayQueue.lean` and `native_queue_arrays.py`. It uses a total
array, head, and live length, with source-local send/dequeue correspondence.
Its ordered-trace theorem and delayed initial-array readback cover arbitrary
initial queues. Packet encoding and Model action guards are not part of this
storage helper. See [Native FIFO storage](README.md#native-fifo-storage).

Vote sends are integrated in `Sparse/NativeArrayVote.lean` and `native_arrays.py`.
The combined `exists_iff` theorem covers one arbitrary initial state for node
observations, `checkQuorum`, both vote sends, and source-local queue observations.
All seven packet variants are accepted as exact observations, including
AppendEntries payload lists. Source partitions constrain packet
sources, not destinations. The JSON adapter and SMT printer remain outside
the theorem. `NativeArrayVoteFixtureMain` derives 400 cases from actual Model
functions. See [Native vote sends](README.md#native-vote-sends).

The first 400-record vote case took about 3 ms to encode and 2.24 seconds to
solve. A combined trillion-entry log and trillion-message initial queue solved
in about 39 ms. No new representation optimization was needed for this slice.

`updateTerm` is also integrated into the shared trace theorem and emitter.
It reads the selected source head without consuming it. Requests allow unknown
senders, responses require allocated senders, and the action does not validate
the packet destination. These are actual Model behaviors, not added guards.
`NativeArrayTermFixtureMain` derives 168 cases from actual `Enabled` and `next`.
A combined 400-record vote-send and term-update trace across 100 identities
took about 3.7 ms to encode and 1.21 seconds to solve. See
[Native term updates and packet observations](README.md#native-term-updates-and-packet-observations).

All 14 local `NodeState` fields now have native representations and observations.
`Local.Rep` is complete decoded-record equality. Term updates explicitly clear
`votedFor` and `preVotesGranted`, while preserving `votesGranted`. Peer tables
and optional retirement indices retain their natural domains without imposing
reachability or log-length bounds.

The first eager full-state run took 10.4 seconds on the 400-record combined
benchmark. A retained constraint-removal experiment isolated unused peer-table
domains as the main cost. Fields now declare their original array and domain
on first read or write, retaining later references and earlier stores.
The same benchmark then solved in 1.13 seconds, with about 3.9 ms spent encoding.
The 540-case `NativeArrayNodeFixtureMain` compares complete Model records
before and after the six supported actions. See
[Native local node state](README.md#native-local-node-state).

Global observations now cover `hasJoined`, `preVoteStatus`,
`retirementCompleted`, and membership in `submittedTxIds`. They remain
independent of allocation. The shared frame correspondence preserves all global
fields alongside complete node records and source-local queues.
The Python reference uses a Boolean array with an unknown finite upper bound, not an
exhaustive transaction-ID universe. `NativeArrayNatSet` proves complete finite-set
representation, and `exists_submitted_array_iff` connects it to the same Model
execution. See [Native global state](README.md#native-global-state).

`timeout` and `becomePreVoteCandidate` are integrated with exact campaign
eligibility and complete state effects. A 400-case mode in
`NativeArrayVoteFixtureMain` compares configuration and signature frontiers
against actual Model guards. Repeated-timeout encoding took about 4.5 ms for
400 records and solved in 2.45 seconds. See
[Native election starts](README.md#native-election-starts).
The next election step, `becomeCandidate`, needs the active-configuration
majority reader. Leader promotion additionally changes logs and retirement
state. Neither is implemented yet.

Next work is still substantial: the remaining actions, receive and log mutation
integration, reducer integration, and full initial-state
materialization. Do not resume the old worker fan-out or claim full encoder
completion. Finish and measure one action or shared operation at a time.
The independent duplicate-suppression utilities are not Model send semantics.
The default build has pre-existing retirement-invariant proof failures in
`MachineGenerated/ReconfigurationPreservation.lean`, reproduced in an isolated
worktree at `45f1acbc8`. Do not weaken those proofs to make the build pass.

The required encoder contract, for the reduced Model trace, is:

```text
SAT(encode(trace)) <=> one concrete Model initial state has an execution
                       matching every ordered action and observation
```

Initial state is arbitrary, not necessarily reachable from bootstrap. Missing
observations do not mean absent nodes or empty queues. Discover state on demand.
Do not enumerate a million-entry initial ledger or expand predecessor expressions
through the trace. Historical constraints may accumulate; current-state summaries
must remain compact and have proved correspondence with the model.

Recorded actions are complete and their supplied order is authoritative for now.
Clock drift, reordering, and missing-action reconstruction are deferred.
The target is roughly 1-2 seconds warm SAT for 400 events. Unknown, timeout, and
encoding failure are not SAT or UNSAT verdicts.

`Sparse.ModelTrace.Satisfiable` now states this unbounded Model-side target.
Its entry predicate is `True`, and its ordered recursion uses the actual
`Enabled` and `next`. Adjacent observations share one boundary, and all actions
and observations share one unknown-value assignment.
Its input functions are semantic parameters, not finite parsed syntax.
`ModelInputSyntax` now supplies closed finite syntax over that contract.
It is not yet a parser or an SMT encoder.
Emitted action clauses remain unfinished. Raw-record interpretation is a
separate diagnostic concern outside the encoder theorem. In particular, raw
send attempts are not evidence of successful Model sends.

### Sparse proofs are in the repository working tree

The interrupted export is repaired. `Sparse/` contains 22 exported proof and
audit modules, with the reviewed theorem bodies preserved under new namespaces.
`Sparse.lean` imports the foundation audit and the separate queue audit.

```bash
python3 export_sparse_proofs.py --check
nice -n 10 lake build Sparse
```

The library includes exact sparse storage operations, source-local queue
completion and traces, all-17-action queue congruence, complete-packet and
node-set codecs, signed indices, finite readback, and joint configuration and
signature completion. These results have independent source reviews. They are
not a complete SMT serialization or full sparse Model composition proof.

New repository bridges extend that foundation:

| Module | Proved boundary |
| --- | --- |
| `Sparse/VersionedIntervals.lean` | One root-array family for all aligned range-copy versions and interval queries, with finitely many shared cut samples. |
| `Sparse/IntervalReadback.lean` | Flat demanded-read equations correspond to one root-array family. Its recursive closure constructor is a semantic reference, not the runtime path. |
| `Sparse/IntervalDemandPlan.lean` | A flattened descriptor table and visited worklist generate minimal closed demands, preserving exact requested-value completion. |
| `Sparse/IntervalEncoding.lean` | Typed point-read constraints and their rendered text correspond to one Int-valued root-array family, with symbolic indices, explicit nonnegative domains, and input-preserving fresh functions. |
| `Sparse/TypedIntervalEncoding.lean` | Typed point constraints for all five sorts correspond to one original assignment and one root family, reserving every constant/expectation symbol and preserving complete external functions. |
| `Sparse/TypedIntervalReadBlock.lean` | Arbitrary requests and a supplied base yield typed equations equivalent to one root family preserving every planned read. Installation preserves constants, selectors, and reserved external UFs. |
| `Sparse/TypedGraphAddress.lean` | Root/version resolution adds at most one root alias, preserves every old version on the same roots, and leaves endpoint/source-symbol metadata unchanged. Existing queries are not reindexed. |
| `Sparse/TypedJointPredicateEncoding.lean` | Formula and rendered-text satisfiability correspond to all Entry points and universal predicates over one original assignment and one shared root family. `Witness` adds guarded local existentials to that same family. |
| `Sparse/TypedJointContext.lean` | Installing any fresh Int block preserves the caller input, graph/query/point domains, concrete points/universals, and existential clauses on the same Entry root family. Reservation includes unused and disabled metadata. |
| `Sparse/ScalarExtension.lean` | Fresh Int scalar-block installation preserves all other constants, complete UFs, and selector interpretations. |
| `Sparse/IntervalPredicate.lean` | Explicit Int comparisons lower with generated locality and alias-preserving semantics. Deduplication before the cut/reference product preserves all planned-demand membership. |
| `Sparse/IntervalQueryEncoding.lean` | Rendered guarded universal Int queries are satisfiable iff one original assignment and one root-array family satisfy the input, nonnegative bounds, and all queries. |
| `Sparse/JointIntervalCompletion.lean` | One root family satisfies all universal queries while preserving every joint requested value, including arbitrary root/version points and inactive query-cut reads. |
| `Sparse/JointIntervalEncoding.lean` | Actual rendered point observations and universal Int queries are satisfiable iff one original assignment and one root family satisfy all of them. |
| `Sparse/IntervalQueries.lean` | Finite read equations and reference-local cut predicates correspond to one root-array family for every universal query, preserving requested cut values. |
| `Sparse/MonotoneIntervals.lean` | Joint finite-cut completion for one log with point facts, interval predicates, nondecreasing terms, and a current-term bound. |
| `Sparse/ModelTrace.lean` | One arbitrary initial State and shared Nat assignment satisfy ordered actual Model actions/observations. All-17-action queue congruence preserves the contract, including destination totals and configuration snapshots. |
| `Sparse/ModelInputSyntax.lean` | Closed finite syntax for every action and observation preserves one shared Nat assignment, finite unknown support, exact ground quoting, and the unrestricted ModelTrace execution contract. |
| `Sparse/ModelInputScalarEncoding.lean` | Nat, Bool zero tests, and optional Nat fields lower under one shared assignment. Exact full-block domains and reservation retain unused declarations; installation preserves existing frames under explicit Int-slot disjointness. |
| `Sparse/LogMatchSummary.lean` | Exact `findHighestPossibleMatch` summary, uniqueness, and zero-based EntryValue correspondence hold for arbitrary logs without term-ordering assumptions. |
| `Sparse/LogMatchEncoding.lean` | Two derived scalar bindings and universal anchor/suffix queries encode the actual clipped log-match reader. Formula/text existence keeps all caller constraints on one assignment and shared Entry root family. |
| `Sparse/StateFrame.lean` | Finite typed-reference domains correspond to relative realization against one supplied Entry root family, submitted set, and network. Realizations have one unique non-network frame. |
| `Sparse/StateFrameInitial.lean` | Canonical independent slots and fresh log roots represent every arbitrary actual Model state, preserving all old roots and outside-owned constants. Whole UFs and selector interpretations remain unchanged. |
| `Sparse/StateFrameEncoding.lean` | Fifteen allocation-guarded clauses encode exactly the existing numeric domains under the same assignment. Text execution returns the domain checker's Boolean result. |
| `Sparse/FrameObservationEncoding.lean` | Twelve observation leaves lower under one source assignment and relative frame realization. Absent local fields are fresh, globals independent, and unsupported observations/actions explicitly rejected. |
| `Sparse/ObservationTraceEncoding.lean` | Canonical source/frame allocation closes rendered-text satisfiability iff actual ModelInputSyntax.Satisfiable for every accepted observation-only trace, without initial-state restrictions. |
| `Sparse/ConfigurationSnapshot.lean` | Exact ordered positive-index Model snapshots and same-log completion using `2m+1` frontier-query records for `m` snapshot entries. |
| `Sparse/ConfigurationReaderEncoding.lean` | Two scalar bindings and content-only anchor/suffix queries characterize actual currentConfigurationAt on one supplied root family. Latest-at-length and exact source-symbol accounting are proved separately. |
| `Sparse/ConfigurationPublication.lean` | Separate local candidate for one configuration begin, successful empty callback send, and publication close on the same core-state chain. No production Model or raw-validator change. |
| `Sparse/EntryValue.lean` | Fixed nonrecursive content and entry values are bijective with actual Model values, with equality transport, decoded term ordering, guarded payload views, and pointwise array equivalence. |
| `Sparse/EntryPredicate.lean` | Cell-local comparisons, Content tests/selectors, mask operations, cardinality, and configuration majority lower under one assignment with finite-reference locality and exact symbol bounds. Raw signed and decoded natural order remain distinct. |
| `Sparse/EntrySelectorSemantics.lean` | Total wrong-constructor selector interpretations are represented without restriction. Correctly guarded reads are interpretation-independent, with strict branch-success requirements. |
| `Sparse/PacketIdentity.lean` | Complete packet equality/disequality is characterized by seven-tag headers, lengths, and bounded entry equality/mismatch. Both identity directions yield an injective finite key-class map. |
| `Sparse/PacketRealization.lean` | One unique complete packet family follows from valid flat descriptors and shared Entry reads. Identity depends only on complete headers, lengths, and live entries. |
| `Sparse/PacketQueueWitness.lean` | Exact finite packet-key identity yields whole-queue existence in both directions, with generated supports and fillers and one shared-read packet family. |
| `Sparse/AppendEntriesRanges.lean` | Actual send/receive index alignment. Enabled sends contain at most one entry; arbitrary initial packets remain unbounded. |
| `Sparse/FiniteMembership.lean` | One finite initial set for a complete membership/insert trace, preserving key aliases. |
| `Sparse/FiniteQueueTransport.lean` | Whole-queue existence transports through finite tracked-support equivalence and fresh fillers. Untracked contents may collapse, but no queue positions are lost. |
| `Sparse/QueueReadback.lean` | Fixed-plan finite read/scalar constraints correspond to one count-array heap and imply a concrete whole-queue execution. |
| `Sparse/QueuePlan.lean` | Constructs the plan and closed demands. Finite constraints hold iff one concrete queue of the supplied length executes the whole unconditional trace. |
| `Sparse/QueuePresence.lean` | Removes known-present sends with same-initial-queue equivalence, under possibly aliased keys and sound disequality. |
| `Sparse/QueueObservationBounds.lean` | Bounds initial source-local queue length using observed lengths and packets distinct from every earlier send. |
| `Sparse/QueueEncoding.lean` | Typed count-read formulas correspond to one root/store family, preserving symbolic aliases and pre-existing input formulas through fresh function allocation. |
| `Sparse/QueueScalarEncoding.lean` | Adds exact guards, windows, shared order, and nonnegative initial length under one assignment, preserving every reserved count function. |
| `Sparse/QueueInitialEncoding.lean` | Adds the initial prefix histogram and alias-aware distinct-key budget with a constructive assignment extension that preserves input, counts, windows, and order. |
| `Sparse/ConditionalQueueAccounting.lean` | Fixed-Boolean guarded replay equals selected cursor replay. Active pops and a pending peek give the exact bounded read histogram under shared-order agreement. |
| `Sparse/ConditionalQueueEncoding.lean` | Typed guard bindings preserve source terms/functions. Static annotation and a finite count grid yield one coherent guarded cursor replay with original guard/key interpretation. |
| `Sparse/ConditionalQueueTraceEncoding.lean` | Formula and actual rendered-text satisfiability correspond to one initial Int queue executing the selected trace under one original assignment, with exact initial length. |
| `Sparse/ConditionalQueueSpecialization.lean` | Input-proved Boolean guards select events for existing same-queue normalization. Unresolved guards retain the old formula exactly; formula/text existence and complete source preservation cover one arbitrary initial queue. |
| `Sparse/QueueTraceEncoding.lean` | The actual emitted formula and rendered text are satisfiable iff one initial Int queue of the interpreted length executes the whole unconditional event trace under the original input. |
| `Sparse/QueueSummaryEncoding.lean` | Proved presence normalization removes redundant sends before whole-queue emission, preserving the same initial queue and the original trace existence contract. |
| `Sparse/ReadbackHints.lean` | Unequal observed projection values justify key disequality and skipping a store. |
| `Sparse/Smt.lean` | Bool/Int terms and native node/content/entry unknowns, equality, conditionals, and unary functions lower to a strict interpreter. Symbol names are injective. |
| `Sparse/NativeSorts.lean` | All five constant sorts and 25 unary signatures, fixed schema availability, canonical text, and strict error handling have kernel regressions and an axiom audit. |
| `Sparse/NativeConstructors.lean` | Native literals, every Content constructor, Entry construction, and total Entry projections preserve typed evaluation through lowering and rendered text. |
| `Sparse/NativeSelectors.lean` | Structured Content testers and total payload selectors use one arbitrary shared interpretation. Matching-guard builders preserve interpretation independence under equal operand and fallback values. |
| `Sparse/NativeNodeOperations.lean` | Fixed 15-bit AND/OR/complement and static node membership match actual Finset operations through typed evaluation and rendered text. |
| `Sparse/NativeNodeSets.lean` | Derived set operations, mathematical cardinality, fixed-node filtering, and strict actual Model configuration majority have same-assignment formula/text meanings and exact symbol maxima. |
| `Sparse/SmtNodes.lean` | Canonical node masks have exactly 15 MSB-first bits and parse back to the original value. |
| `Sparse/SmtScript.lean` | Generates unique typed declarations and commands. Command evaluation preserves formula truth for the same assignment. |
| `Sparse/SmtText.lean` | Decodes exactly the canonical generated symbol names, with symbol-atom evaluation roundtrip for the existing renderer. |
| `Sparse/SmtNumerals.lean` | Decodes canonical decimal numerals for arbitrary Nat, with a roundtrip proof over the actual core renderer. |
| `Sparse/SmtExpressionText.lean` | Parses the existing expression renderer's output for arbitrary nesting, preserving structure and same-assignment evaluation without a depth cap. |
| `Sparse/SmtScriptText.lean` | Parses complete generated scripts back to their commands and preserves fixed-assignment truth, using the compiler's LF-separated subset. |
| `Sparse/SymbolBounds.lean` | Direct structural maxima equal the original symbol-set allocation bound. A kernel-proved compiler rewrite preserves fresh IDs without constructing those sets. |
| `Sparse/SymbolCollection.lean` | Tail-recursive hash-set collection equals `List.dedup` exactly, including last-occurrence order. The SmtScript compiler rewrite preserves declarations and text. |

`QueuePlan.generated_exists_iff` requires nonnegative initial length, tracked-key
coverage, lawful equality, and a fresh filler value. Its conservative ancestor
closure can be quadratic. The runtime emitters below cover unconditional and
conditional queue events.

Monotone completion does not change the arbitrary-initial-state contract above.
Restricting that contract to `SafetyInductiveInvariant` still requires one joint
invariant witness, including coherent proof-only histories. Local term and
frontier bounds alone do not establish that witness.

`ConfigurationReaderEncoding.meaning_correct` equates the emitted scalar
constraints and two universal query meanings with exact arithmetic bindings
and the actual current configuration at the requested frontier.
The result retains both index and mask, including physical empty masks and
positive-index bootstrap-equal masks. Index zero uses the selected Bootstrap.
Frontiers may exceed log length. No Entry term is constrained.
`latest_at_length` supplies the actual latest-configuration bridge.
The relation uses one supplied graph/root family, not a new completion witness.
Caller-context installation, rendered existence, frame integration, snapshots,
active unions, majority, and actions remain separate work.
`tests/test_sparse_configuration_reader.py` exercises 460 native cases through
one shared joint compiler. Controls include a finite content oracle, alternative
Bootstrap, raw signed terms, shared-reader conflicts, caller witnesses, source
aliases, high unused metadata, and million/trillion-entry sparse logs.

`StateFrame` has 662 reference occurrences in fixed-size tables, not necessarily
distinct IDs. It stores no expression history. Domains constrain allocated
local rows only, while scope checks retain dormant references.
Absent local lookup is exactly freshNodeState; joined, pre-vote, completion,
submitted, and network globals remain independent. Optional indices distinguish
none from some zero. Active negative codes are rejected.
Log decoding is proof-only and uses one supplied graph/root family.
Relative realization and uniqueness do not establish arbitrary-state coverage
for aliased IDs or fixed roots.
`StateFrameInitial` supplies canonical allocation and arbitrary-state coverage.
It reserves 585 Int, 30 Bool, and 47 Nodes slots in `[base, base+662)`.
Numeric IDs are distinct, not merely typed symbol pairs. Each row and peer
field is independent. Fifteen fresh log roots follow any supplied root prefix,
whose entire functions remain unchanged.
The assignment witness preserves outside-owned constants, including wrong-sort
constants within that numeric span, and all UFs and selectors. The caller must
reserve the scalar span away from source constants it needs to preserve.
`arbitrary_state_coverage` and `decode_original` cover every actual State,
including arbitrary network contents and inconsistent retirement metadata.
Concrete log encoding is proof-only. Fixed-root coverage retains explicit
compatibility; symbolic graph preservation remains a separate obligation.
`StateFrameEncoding` emits 42 numeric checks per row inside fifteen
allocation guards. Active owners require valid peer fields even when those
peers are unallocated. Dormant negative values remain legal unless their IDs
also serve an active row. Aliases are preserved.
The same-assignment formula and text theorems cover domains only. Scope,
graph/root consistency, queues, submitted sets, and actions are not encoded.
Native globals and local nonnumeric fields have no additional domain
constraints. Relative realization still takes one supplied G/R/Q/U.
`tests/test_sparse_state_frame.py` covers four fixed-size metadata cases through
trillion-valued reservations and 634 native domain cases. These include all
39 numeric columns on nodes 0 and 14, dormant values, aliases, and independent
global fields.

`FrameObservationEncoding` supports seven top-level observation constructors:
allocated, joined, role, currentTerm, commitIndex, logLength, and state.
The six nested state forms bring the total to twelve leaves.
`checkTrace` rejects every action and the five other observation constructors.
It preserves accepted order and duplicates, including adjacent contradictions.
The formula has n source-domain clauses, fifteen frame-domain clauses, and one
equality per observation. It allocates no new frame or source slots.
Its realization theorem remains relative to one supplied graph, root family,
network, and submitted set.

`ObservationTraceEncoding` closes that relative boundary with canonical
source slots `[0,n)` and frame slots `[n,n+662)`.
`jointly_representable` represents any given source assignment and actual
Model State together. No reachability, log-size, or queue-size bound is assumed.
`rendered_exists_iff` connects successful public `render` output directly to
`ModelInputSyntax.Satisfiable`, retaining one state and assignment for the
entire accepted trace. The forward proof chooses unobserved log contents,
queues, and submitted IDs only to construct an existential witness.
The reverse proof covers arbitrary values of those components.
Rejected inputs produce errors, not UNSAT scripts.
The interface consumes typed Lean syntax; JSON, actions, packet observations,
configuration observations, and raw CCF integration remain unfinished.
`tests/test_sparse_frame_observations.py` covers 140 native solver cases and
eight explicit rejections through relative and canonical public entry points.
These include shared numeric/zero-test values, independent absent globals,
source/frame separation, aliases, and million-entry log lengths.

`ModelInputSyntax` covers all 17 actions, all 12 top-level observations, and
their nested records. `NatAtom n` refers only to literals or `Fin n` slots.
`BoolAtom n` adds literals and explicit zero tests under the same total Nat
assignment. A shared value of 7 is still 7 numerically and false as a zero test.
There is no zero-or-one domain, dynamic unknown lookup, or function-valued leaf.
Nodes, sets, enums, Option tags, and finite list shapes are literal.
Distinct names have distinct slots but may denote equal values.

`evalTrace_congr` depends only on the finite set of actually used slots.
`instantiate_quote` embeds every ground trace, including disabled actions,
malformed expected packet destinations, some zero, and ordered duplicate
configuration indices. It neither repairs nor drops impossible observations.
`satisfiable_iff` quantifies one Nat assignment and one arbitrary actual State
for the entire ordered trace. Adjacent observations inspect one state.
Million-valued summaries retain fixed syntax size without constructing payloads.
String name resolution, parsing, and complete observation/action emission
remain separate. Arbitrary semantic ModelTrace functions need not have finite
support and are not claimed to belong to this syntax.

`scripts/generate_model_input_syntax.py` maintains the repetitive atom, record,
and constructor definitions. Its default mode and `--check` are nonmutating.
Explicit `--write` replaces a stale generated prefix atomically while preserving
the unique `-- Trace boundary.` marker and manual suffix exactly.
Both modes reject malformed markers and non-ASCII input. `--file` selects an
existing copy, and default paths are relative to the script's project.
The generator is not a runtime or build dependency.
`tests/test_model_input_generator.py` covers regeneration, nonmutation,
permissions, malformed input, and relocation.

`ModelInputScalarEncoding` reserves source Int slots `[base, base+n)`.
`sourceNat`, `sourceBool`, and `sourceOption` share one total Nat assignment.
Nat values use mathematical Int casts, not Entry signed codes. Optional values
use the existing none=0, some n=n+1 convention.
`encodeDomains` emits exactly n nonnegative clauses, including unused names.
Its formula and rendered text hold iff one total Nat assignment represents
every declared source slot. Distinct slots may hold equal values.
`ScalarExtension.install` supplies the assignment while preserving all UFs,
selectors, outside constants, and every non-Int constant.
Preserving an existing frame additionally requires `FrameDisjoint` over its
full Int-symbol inventory, including dormant fields.
The caller still owns placement relative to graph and other compiler metadata.
`tests/test_sparse_model_input_scalars.py` covers 170 native cases, including
shared zero tests, source aliases, unused negative declarations, optional zero,
and constant-size declarations at trillion-valued offsets.

`LogMatchEncoding` binds `clip = min(index, length)` and
`anchor = max(best-1, 0)` in two fresh scalar slots.
An eligible anchor and exclusion of later matches determine the exact reader
result. Both predicates are universal: `[anchor,best)` is empty at best=0
and a singleton otherwise, so the reader needs no existential position scalar.
Terms use decoded Entry ordering against a mathematical Nat threshold.
Source fields may alias, but negative values are rejected.
The public formula and rendered-text iffs keep one original assignment and one
root family satisfying the entire caller context and reader result.
The two slots must follow every source ID and the existing caller symbol and
metadata boundary. Installation preserves all caller points, queries, witness
clauses, complete UFs, and selectors.
The caller still connects the graph version and prefix length to its actual
StateFrame log. No NACK-handler refinement is claimed.
`tests/test_sparse_log_match.py` covers 423 finite-oracle cases and 23 additional
cases, including unsorted terms, conflicting readers, caller witnesses,
source aliases, and trillion-length single-point constraints.

Use `IntervalDemandPlan.plan` for executable dependency closure. The reference
constructor repeats shared ancestors exponentially. In one forced-clock run,
14 demands dropped from 6.21 seconds to 0.106 milliseconds; 400 versions with
401 demands took 40.2 milliseconds. These are planner-only measurements.
Visited-list membership remains linear, so no linear-time bound is claimed.
`Sparse/IntervalDemandFixtureMain.lean --benchmark` reproduces the new path.

`IntervalQueries` still forms a global-cut/reference-occurrence product before
memo deduplication. Locality avoids unreferenced versions but does not establish
minimal cross-position requests or fast compilation. Its arrays are total;
callers must encode physical log-length clipping explicitly.

`IntervalPredicate` removes occurrence duplicates before that product while
preserving its membership and the planner's dependency closure. Distinct cuts
still multiply distinct version references. Its typed comparisons use ordinary
Int order. Pointwise `ne` is not an existential mismatch.
The caller-supplied `zeroID` in this lower-level module is only metadata,
not an assertion that its value is zero.

`tests/test_sparse_interval_predicate.py` covers 144 comparisons across cell
and input operands, two position-alias controls, and request deduplication.
Repeating one cut ID and one cell self-equality predicate 400 times yields one
request and two planned demands in its shared-root case.

`IntervalEncoding` interprets graph endpoints and observation positions as
scalar symbol IDs, not literal indices. Equal-valued tokens share the same UF
read. All graph bounds and requested positions must be nonnegative, including
unused graph bounds. Cells remain unrestricted Int values.
Freshness covers the supplied input formula, not arbitrary external reservations.
The final spare function slot is preserved.

The 92 cases in `tests/test_sparse_interval_encoding.py` cover aliases, splice
boundaries, and sparse domains through actual emitted text. A million-root
universe and a trillion-valued index each require two demands in their fixtures.
The shared-ancestor case uses 400 versions and 401 demands, with both SAT and
UNSAT controls. These are point-read components, not full Raft traces.

`IntervalQueryEncoding` composes fresh zero allocation, guarded predicates,
and universal completion. It reserves input, graph, query, and operand IDs,
then preserves their original meanings through scalar and UF installation.
Global shared cuts handle overlapping queries and symbolic aliases.
Empty-reference predicates still emit guards, so a constant-false predicate
on a nonempty interval is rejected.

Its 187 native cases include 162 bound/alias combinations compared with a
finite-array oracle. Other cases cover hidden splice cuts, million-scale
domains, repeated queries, and 400 shared versions.
Passing a point-read formula as input does not identify its roots with this
compiler's fresh roots. Use `JointIntervalEncoding` for linked points and queries.
This Int compiler has no existential or Entry support. The typed Entry pipeline
below supplies both. Model integration remains open.
The composer must carry the full `nextFunctionId` reservation, including
unprinted slots, rather than scan only emitted declarations.

`JointIntervalCompletion` supplies the semantic joint witness. It adds every
point position to the shared cuts and checks every query at those extended
cuts. Point-only addresses enter the request list only at their own positions.
Completion preserves all requested values, including points outside intervals,
without dummy queries, successor scalars, or synthetic versions.
The value type needs no equality or inhabitant instance.
`tests/test_sparse_joint_interval.py` covers executable demand construction,
including 400 point positions and a million-root universe.

`JointIntervalEncoding` supplies typed allocation and rendered-text correspondence.
It reserves every point-position and expected-symbol ID, retains all point
equalities, and uses one shared read block with the full function reservation.
Its 311 native cases include 288 bound, point, and alias combinations checked
against a finite-array oracle. Point-only 400-position emission needs 800
demands, and one point in a million-root domain needs one demand.
The compiler and extracted universal helpers have an independent review.

`TypedIntervalEncoding` extends point emission to all five native/scalar sorts.
Graph constants and point expectations are typed input terms. Its allocator
includes even unused constants and metadata-only functions, and its reserved
UF range has no spare slot. The same assignment interprets all input terms,
and one shared root family satisfies every observation.
The 440 native cases include 360 typed splice controls, 16 nested constructor
and projection controls, eight selector/tester controls, eight nested mask
operation controls, and SAT/UNSAT cases for
400 Entry points and 400 shared versions. Those require 800 and 401 demands,
respectively. One point in a million-root universe still requires one demand.
Packet constraint emission remains open.
`EntryPredicate` supplies typed local predicates and a `LocalQuery` adapter.
Only version-cell leaves use the current position. External terms stay fixed.
Reference and symbol summaries retain inactive branches and remove duplicate
version references. Domain constraints, fresh allocation, and shared completion
belong to the later joint compiler.
Pointwise `ne` is not an existential mismatch. Its interior-mismatch regression
shows why checking only existing cuts can miss a difference between them.
`tests/test_sparse_entry_predicate.py` checks 620 emitted formulas against
independent Python comparisons, covering raw and decoded signed values, fixed
external operands, and complete Entry tag identity.
Another 550 cases cover cell-dependent Content tests, payloads, mask operations,
cardinality, majority, and fixed-condition filters with independent Python
oracles. Cardinality is mathematical Int. Transaction payload selectors still
return raw signed codes.
`filterByFixed` takes a Vector of fifteen external Bool Terms and retains all
their symbols. It does not bind a scan position. `guardedConfigurationMajority`
skips non-configurations but rejects genuine empty configurations.
The joint compiler's congruence proofs retain their original signatures.
Low-ID Content literals expose raw selector agreement without assuming equality
of unused selector-record fields. Fourteen joint native controls cover points,
universals, witnesses, wrong selectors, and inactive high-ID conditions.
`TypedIntervalReadBlock` provides the shared read block for the joint compiler.
It supports all five sorts, root/version requests, and an arbitrary UF base,
without expected-value proxies. The planner runs once, and every planned
read has a consistency equation and a nonnegative position.
The caller reserves `[base, base + roots + versions)`, including unused slots.
Installation from any root family preserves original constants, selectors,
and outside-range UFs. Input and graph terms require explicit freshness bounds.
`TypedJointPredicateEncoding` now emits joint Entry points and universals.
It reserves fresh zero and one complete root/version UF block, retaining all
original point equalities. Every query is checked at every shared cut, including
point positions. Its final formula/text iff uses one original assignment and
one root family. Empty intervals remain vacuous, but disabled bodies do not
remove domain or symbol reservations.
`tests/test_sparse_typed_joint.py` covers 590 scripts, including 576 comparisons
with an independent two-value array oracle. The 400-point and 400-version
controls use 806 and 1,604 planned reads. These are component cases, not a
full-trace performance result.
`TypedJointPredicateEncoding.Witness` adds guarded local existentials.
Each occurrence gets one nonnegative position. Referenced positions join every
universal's cuts, while each body reads its versions at that one position.
One completion preserves every point and witness. A body without references
adds no reads or witness cuts, but retains its bounds and enable implication.
Original bounds remain nonnegative even when disabled. The converse chooses
zero for disabled witnesses; the formula permits any nonnegative position.
`Witness.encode_exists_iff` and `Witness.rendered_exists_iff` use one original
assignment and one root family for points, universals, and all existentials.
Empty clause lists delegate to the old encoder and preserve its script.
For `n` clauses, reserve scalar IDs `[z, z+n+1)` and the entire UF interval
`[Witness.base ..., Witness.base ... + roots + versions)`.
`ScalarExtension` preserves complete UFs and selectors before the read-block
installer runs. Original constants outside the scalar block remain unchanged.
The same test module adds 1,165 witness scripts, including 1,152 finite-array
oracle cases. Controls cover interior mismatch, overlapping universal equality,
aliased witnesses, empty and disabled intervals, and source-symbol capture.

The chosen entry representation uses fixed native datatypes with signed
integer term/transaction fields and 15-bit node sets. `EntryValue` supplies
the exact value domain. Fixed native sorts and schema/text correspondence
are now integrated with the current queue and joint interval compilers.
`tests/test_sparse_native_sorts.py` supplies 73 real solver controls for unknowns,
equality, conditionals, and all unary signatures, plus 314 constructor and
Entry-projection controls. It checks all 32,768 node masks against independent
MSB-first formatting and rejects malformed masks. Scalar names and QF_UFLIA
scripts remain unchanged. Native scripts use ALL and the fixed schemas.
Missing, duplicate, dependency-invalid, and mismatched declarations remain
errors, including after false assertions.
`SmtScript.compileCached` shares symbol collection and required sorts across
schema selection and declarations. Its compiler rewrite proves exact command-list
equality. The 1,950 native fixtures compare rendered bytes with the uncached
command construction.
The 105 selector cases include proper-constructor identities, arbitrary
wrong-constructor values, matching-guard fallbacks, aliases, and independence
from ordinary user UFs.
The 512 mask cases compare AND, OR, complement, and all 15 membership positions
against independent Python bit operations. Complement is within the fixed
15-node universe, not the observed membership. Node 0 is the rightmost printed
bit. `NativeNodeOperations` proves actual Finset and text correspondence without
membership UFs.
`NativeNodeSets` adds set operations, cardinality, filtering, and the actual
single-configuration majority. Cardinality is mathematical Int in `[0,15]`.
Majority excludes outsiders, rejects ties, and fails for empty configurations.
Filters retain every predicate's symbols, including those under an empty mask.
Its 946 solver controls use independent Python set and bit-count calculations.
The builders introduce no sort, UF, assignment field, or fresh binding.
Cardinality repeats its operand 15 times. Majority repeats support 30 times
and configuration 45 times before those operands expand. This is a fixed
expansion, not a full-trace performance result.
Callers must still distinguish skipping a non-configuration from testing an
empty configuration. Active configurations and complete quorum readers remain
separate Model-integration obligations.

Native Term literals, all Content constructors, Entry construction, and total
Entry projections are integrated. Required-sort discovery includes native
operations without symbols, and raw schema preflight checks dead branches.
Content testers and payload selectors are integrated with the actual evaluator
and canonical text. Testers use structured `((_ is ccf_tx) value)` expressions.
Wrong-variant payload views return `none`. SMT selectors are total and
underspecified on wrong variants. `EntrySelectorSemantics` proves guarded
results independent of every such interpretation. The tester and selector
must use the same content operand, and both branches must evaluate successfully.
`Assignment.selectors` holds one arbitrary interpretation shared by all
occurrences. Assignment installers preserve it explicitly. Ordinary constant
and UF equality alone does not imply equality of terms containing selectors.
`NativeSelectors` connects matching-guard builders to the existing view laws,
requiring equal operand and fallback values across compared assignments.
Natural term ordering compares decoded values, never raw signed integers.

The session's `sparse-entry-representation-design.md` records three designs and
rerunnable probes. For 200 appends plus 200 point copies, fixed datatypes took
82 ms median SAT versus 10.6 seconds for the measured canonical-token scheme.
Those cvc5 process timings include startup and use a million-element initial
extent without materializing it. They do not measure the native Lean emitter
or full Raft traces.

`PacketIdentity` retains every active header field and every ordered payload
entry, including duplicate entries, terms, and configuration masks. Header
Nat fields remain bijective signed codes; lengths and positions are ordinary
Nat. The fixed-value theorem starts with coherent complete packets. It does
not construct packet witnesses from independent sparse projections.
`PacketRealization` constructs complete packet witnesses from one shared
Entry read family and flat descriptors. Its optional addresses allow empty
packets without dummy arrays. Nonempty payloads require an address, and
nonappend tags require zero payload length. Shared graph consistency remains
a composition premise. The unit has a target build and independent review.
Conditional equality/mismatch emission remains open. Initial packet payloads must not
be equated with current sender logs, and whole-array tail equality is not
finite-payload identity.

`FiniteQueueTransport` supplies generic whole-trace transport without a global
value equivalence. It separates every tracked key from all other values, while
allowing untracked values to share a fresh filler. Both directions preserve
initial queue length and multiplicities. The parent reviewed and built this
unit. `PacketQueueWitness` constructs the supports and fillers from complete
source-local packet occurrences with exact key-equality classes. Its shared-read
corollary retains descriptor validity and source conditions. Both directions
preserve one initial queue for the entire trace, including duplicate positions.
Destination need not equal the queue source. Packet-key constraints, conditional
events, and whole-network composition are still separate obligations.

Configuration snapshots are derived Model observations, not a mutable global
configuration variable. Empty positive-index snapshots do not remove implicit
configuration zero from Model quorum behavior. Raw snapshot fields remain
unwired: C++ callbacks can update the configuration cache and send before the
enclosing ledger action finishes. They need a phase-refinement mapping, not
reordering or discarded observations. Address-only changes also remain outside
the current Model projection.

The reproduced callback conflict also involves the send guard: after the Model
configuration action, the observed empty end-2 send is disabled because that
guard requires end 3. Observation placement alone cannot fix the conflict.
`ConfigurationPublication` supplies a bounded local alternative with a compact
frame derived from its preceding begin. It preserves the original Model action
path in idle and proves exact callback packet/enqueue effects.
Its callback is explicitly not an enabled original Model action.

This candidate requires one fresh peer, an active source before and after,
an in-range old commit, a matched enclosing write, and successful transport.
Raw send records describe attempts, not success evidence. Failure, interleaving,
general callbacks, raw pairing, and full C++ refinement remain unproved.
`Pending` alone is not a history certificate; execution must retain the
linked Step chain from idle. The arbitrary-state production contract is unchanged.

Presence normalization applies only to queue events. Callers must retain other
observations and rebuild references for retained events. Destination-wide length
observations do not imply these source-local bounds.

The count-only and count/scalar solver fixtures include SAT cases with
inconsistent initial counts to keep those boundaries explicit.
`QueueEncoding` summarizes the maximum demanded version for each syntactic key,
then expands that prefix once. The generated key/version pairs are unique.
Proofs preserve the old assertion membership and allocation bound, including
all observation equations. Distinct symbolic names still use shared UFs when
their values alias. Fixture metadata reports `query_pairs` to catch repeated
ancestor expansion.

The 400-event queue-only controls after this summary measured 1.419 seconds
for repeated-send SAT, 2.400 seconds for send/pop SAT, and 1.790 seconds for
unknown-million-length SAT. Each combines emission with the median of three
cvc5 process times. The cycle case still misses the two-second target.
Declaration construction accounts for 0.63-0.84 seconds in these runs.
These one-key fixtures do not establish full-Raft or multi-key performance.

Four-key 400-event controls exposed the remaining cost. Without presence
normalization, literal sends took 5.147 seconds SAT, unresolved symbolic sends
11.823 seconds, and symbolic send/pop cycles 5.651 seconds.
`QueueSummaryEncoding` now reuses `QueuePresence.normalize` with proved literal
differences and composes its same-initial-queue iff with the rendered-text iff.
It preserves every pop, peek, and length observation. No full Raft action or
external intermediate-version reference may be deleted through this API.

With `CCF_SPARSE_QUEUE_SUMMARIES=1`, the same four-key send traces encode five
queue events and take 15-17 ms SAT. The cycle retains all 400 events and still
takes 5.640 seconds. Normalization is included in emission time.
`CCF_SPARSE_QUEUE_KEYS=4` selects these cases in the existing scaling suite.
The 25 focused summary cases and all 486 finite-oracle cases pass alongside
the unnormalized controls. The new composition has an independent review.

The subsequent `SymbolCollection` compiler rewrite reduced four-key cycle
declaration construction from 2.414 seconds to 0.117 seconds with identical
400,062-byte scripts. Total SAT remains 3.412 seconds, including 1.161 seconds
of formula construction and 2.035 seconds in cvc5. Formula construction is
the next emitter bottleneck. Fifteen native cases compare the hash collector,
compiled collection, allocation bounds, and complete scripts against the
explicit old list algorithm.

`QueueInitialEncoding.encodeCached` then removes repeated count and scalar
construction across allocation stages. Its kernel-proved compiler equality
preserves the exact assertion list, IDs, reservations, and script bytes.
The permanent queue fixtures compare 24 cases with the original construction.
The parent four-key 400-event cycle run now takes 0.450 seconds for emission
and 2.520 seconds including cvc5, with the same 400,062-byte script.
The two-second target remains unmet. Count-formula construction accounts for
most remaining emitter time.

`QueueEncoding.countFormulaCached` now shares one flat array of recorded
operations across demand seeds and read equations. Array lookup and the
complete formula are proved equal to the original definitions. The permanent
cache fixture now checks 24 initial-compiler and 30 count-compiler cases.
Before native-sort integration, four-key cycle emission fell to 0.235 seconds
and emission plus cvc5 to 2.261 seconds. After integration, the same scalar
script takes 0.329 seconds to emit and 2.352 seconds including cvc5.
Schema discovery adds work but changes none of its 400,062 bytes.
Sharing schema and declaration discovery then reduced matched command
construction from 226 to 119 milliseconds, with identical bytes. The solver
rerun measured 0.240 seconds emission and 2.269 seconds total for SAT,
and 0.750 seconds total for UNSAT. The two-second SAT target remains unmet.
These remain component timings, not full-Raft performance.

`QueueInitialEncoding` adds initial prefix histograms and alias-aware budgets.
Its key list is syntactically unique. Distinct symbolic names remain separate
even when they denote the same value, and every `readHeads` occurrence remains.
It includes the last unconsumed peek without counting repeated earlier peeks
as extra initial occurrences. Its public entry point accepts no extra count
observations.
`tests/test_sparse_queue_encoding.py` uses the same opt-in environment as the
scalar fixtures.

`QueueTraceEncoding.rendered_exists_iff` closes the unconditional whole-queue
contract for that entry point. It derives count-graph and demand alignment,
tracked-key coverage, and a fresh filler. The converse preserves every original
constant and each input UF. Exact Int-cast queue-length equality rejects negative
initial lengths. No caller Plan, closure, filler, or capacity premise remains.
Peeks and length observations are included in the event trace. Extra count
observations, conditional events, complete packets, and Model states remain
outside this theorem.

`ConditionalQueueAccounting` supplies the first guarded semantic unit.
Inactive events preserve the cursor and read summary. Active pops advance
the head and clear the pending-peek flag. Active peeks set that flag.
The final peek contributes only below the nonnegative initial-length cutoff
and uses the shared final-head order cell.
The histogram equals the occurrence count in the selected `readHeads` prefix,
including repeated or aliased keys. The cursor corollary derives order agreement
from replay, without an additional initial-state invariant.
Its function-update summary is a semantic reference, not the runtime emitter.
`ConditionalQueueEncoding` binds original typed guards to flat references,
without asserting the guards themselves. It proves single-clause correspondence
for active updates and inactive count/head/tail identity, preserving original
terms and complete external functions through allocation. Guard event indices
are independent of count-write IDs. Supplied count states require explicit
source and target range proofs.
The trace block now preserves original event order and associates each write
with its original guard position. Its count grid has exactly writes times
tracked keys equations, including inactive writes.
One canonical total count family agrees with every tracked read and yields
one guarded cursor replay. Raw count UFs may still differ off-grid.
The 320-case kernel oracle covers aliases, inactive writes, and intervening
peeks. This is a replay soundness bridge, not a concrete-queue iff.
`ConditionalQueueTraceEncoding` closes the concrete-queue formula and text iff.
It counts only active pops below the initial-length cutoff and adds the final
pending peek only when its head is still in that prefix. The existing
alias-aware budget supplies one initial queue, not a witness per row or branch.
The converse retains original guard meanings, constants, and complete source
UFs. Its witness installer also preserves the complete selector interpretation.
The full auxiliary reservation ends at `nextBase`, including unused slots.
No initial capacity or key-distinctness premise is added.
The rectangular grid still has no performance clearance.
The queue test module adds 15 conditional regressions and 1,944 finite concrete
oracle cases covering every guard mask for the two-event matrix.
Million-entry controls emit fewer than 10,000 bytes without constructing a
million-element queue.

`Sparse/ConditionalQueueScaleMain.lean` supplies the frozen native conditional
baseline. `scripts/benchmark_conditional_queue.py` builds its 35 project C
modules against existing package native objects. It records source and C hashes,
the native binary hash, and package-object size and modification time.
It refuses changed inputs, missing artifacts, and overwritten evidence.
This is not a hermetic build or a package-source rebuild.
The [README benchmark commands](README.md#sparse-proof-foundation) use no
session-local scripts.

The baseline emitted all 54 cases at 40 and 400 events. All 27 small cases and
12 large cases have three successful solver processes. The remaining 15 large
cases were not started, not classified as timeouts or solver verdicts.
Every fixture starts empty. At 400 events, there are 399 writes and a final
length observation. Alternating guards enable 200 writes.
Emission timing excludes native startup and persistence. Solver medians include
startup, parsing, and solving in three fresh cvc5 processes.

| 400-event case | Script bytes | Warm emission ms | Solver median ms |
| --- | ---: | ---: | ---: |
| Four literal keys, alternating guards, SAT | 671098 | 29.779 | 1954.064 |
| Four symbolic keys, alternating guards, SAT | 740293 | 35.614 | 14382.216 |
| Four symbolic keys, all guards true, SAT | 740094 | 37.512 | 3922.183 |
| 199 symbolic keys, alternating guards, UNSAT | 31667475 | 1728.986 | 155693.653 |
| 399 symbolic sends, alternating guards, SAT | 61913978 | 3421.912 | Not run |

The count grid grows as writes times keys. Initial-prefix histograms and
alias checks add further products. These measurements fail the runtime target.
Session-only array prototypes reduce the four-symbolic-key alternating SAT
median to 1808.896 ms, but require `--arrays-exp` and have no encoding proof.
They support only an empty initial queue and are not the production encoder.
`ConditionalQueueSpecialization` now proves known-guard selection followed by
the existing queue normalization. Unknown guards retain the exact fallback.

The portable runner's `cycleDistinct` argument retains that name in evidence
paths. Native metadata calls the corresponding shape `cycle19` at 40 events
and `cycle199` at 400. The offline benchmark tests cover all 54 names.
The parent also ran fresh distinct-cycle SAT and UNSAT controls after fixing
this naming check. Audit reports that separate run as 2/54, not complete.

The specialization recognizes Bool literals, recursively negated guards, and
flat input facts asserting, negating, or equating a Bool symbol to a literal.
Both equality orientations work. It resolves every guard or falls back without
changing the old formula. Contradictory input remains contradictory even when
the resolver finds a first matching fact.
Resolved guards contain no UFs, so the existing summary allocator needs no
extra guard reservation. Unsupported terms, including inactive UF branches,
use the general path. Completeness preserves every source constant, complete
source UF functions, and the entire selector interpretation.

Six native four-key symbolic alternating controls cover 40 and 400 events,
with SAT, UNSAT, and alias-SAT demands at each size.
Every send is active and every pop is inactive in these controls.
At 400 events, 201 selected events normalize to five. All 400 original input
assertions remain, and the script shrinks from 740293 to 31442 bytes.
The worker measured 17.488 ms median SAT. A separate parent reproduction
measured 18.117 ms SAT, 15.265 ms UNSAT, and 20.620 ms alias SAT.
Complete warm emission was 1.328 ms for the parent SAT run, including selection
and normalization. The separately timed resolver took 0.489 ms and is already
included in that emission total.
These are empty-initial queue fixtures on a shared host, not full Model
performance results. The theorem itself requires no initial-emptiness premise.
Unknown guards and high-key products remain open.
The existing portable benchmark remains the frozen general-compiler baseline.
Specialized native source, hashes, scripts, and both sets of measurements are
in the session's `conditional-queue-specialization-probe/` directory.
`tests/test_sparse_conditional_specialization.py` adds 384 finite queue-oracle
cases and eleven edge cases covering exact fallback, source facts, duplicates,
contradictions, and symbolic million-entry initial lengths.

The initial-accounting fixtures include 20 focused cases and 486 two-event
cases compared with a concrete queue interpreter. Those pairs use nine event
forms, initial lengths from zero through two, and both alias partitions of two
keys. Reproduce them with `CCF_SPARSE_SMT_TESTS=1` and `CVC5`:

```bash
python3 -m unittest tests.test_sparse_queue_encoding
```

At 80 same-key events, the original accounting grids produced 741 KB for
repeated sends or 1 MB for alternating sends and pops. Both took about
2.35 seconds before solving. `SymbolBounds` reduced those one-run totals to
1.33 and 1.43 seconds, with unchanged script byte counts.
Syntactic-key deduplication then reduced them to 325 KB and 297 KB, both about
0.79 seconds. The whole-execution iffs remain unchanged.
Count-query ancestor prefixes still overlap in `QueueEncoding.syntaxQueries`;
each key's maximum demanded version is the next summary to prove.

`QueueEncoding.freshBase_eq_summary` is a kernel-proved `[csimp]` equality.
It retains the original specification and replaces compiled allocation calls
with a direct maximum. The native allocation fixtures compare the reference,
summary, and compiled bounds, including inactive branches and large IDs.
They also compare allocated script bytes.

`Sparse/QueueEncodingScaleMain.lean` profiles formula, declaration, and text
construction separately. The session's `queue-initial-scale-baseline.jsonl`,
`queue-initial-scale-phases.jsonl`, and `queue-initial-scale-summary.jsonl`
record the before/after evidence. These are emission-only measurements.
`queue-dedup-small-profile.jsonl` records the later key-dedup measurements.
No 400-event performance result follows from these smaller profiles.

`tests/test_sparse_queue_scaling.py` is separately enabled by
`CCF_SPARSE_QUEUE_SCALING=1`, with `CCF_SPARSE_QUEUE_EVENTS` defaulting to 400.
It uses `QueueEncodingScaleMain.lean --fixtures N` to emit six exact-N-event
SAT/UNSAT cases, including an unknown initial length fixed by million-element
observations. Reports combine measured emission with three-run median cvc5
process time. Lean startup and JSON transfer are outside the emission timer.
Correct verdicts are required; the runtime target is evaluated separately.

Generated scalar scripts now have text correspondence. Complete trace encoding
and solver implementation correctness remain separate obligations.
The real cvc5 fixtures in
`tests/test_sparse_smt.py` are opt-in through `CCF_SPARSE_SMT_TESTS=1` and `CVC5`;
they exercise explicit declarations and generated scripts, not a full trace
validator. Command evaluation distinguishes false assertions from malformed
scripts. It does not classify satisfiability across all assignments.

`export_sparse_proofs.py` and `Sparse/provenance.json` preserve the export's
source hashes and reversible proof-body mapping. Re-exporting needs the original
session files through `--source-dir`; checking and building do not. The exporter
refuses changed sources or destinations.

Solver experiments, their tests, and review reports remain in the `files/`
directory of session `a2575280-4399-475e-920a-ec0b48e8b85f`. Its
`check_sparse_prototypes.py` still rebuilds the original dependency graph and
rejects non-ASCII source or unexpected transitive axioms.

Full Model composition, emitted SMT correspondence, and production runtime
integration remain unfinished. Literal-packet fixtures are fast; fully unresolved
packet aliases still exceed the target. Additional count bounds are proved
redundant for the same heap, but the experiment slows 100-event symbolic SAT
from 3.54 seconds to 5.75 seconds and remains disabled. No full Raft performance
claim follows from these measurements.

Synthetic partial-header observations now support disequality specialization.
With four potentially aliased keys per header class, a 400-event SAT case drops
from 126.70 seconds to 2.50 seconds. An unknown-initial-length case with
million-scale observations still takes 8.63 seconds. These are queue-only
experiments, not matched CCF traces.

Git bundles contain committed repository files, not uncommitted additions.
Transfer session experiments and reports separately. Do not download replacement
tools or formatters without fresh authorization; the user declined a formatter
download during this work.

## Historical bounded-backend checkpoint

The remainder records the earlier implementation and its proof boundary.
Its bounded contract is not the new sparse delivery contract.

The guarded AppendEntries and control trace slices are complete. This document supersedes
the unfinished migration checkpoint in `f1c84033b`. Receive trace integration,
symbolic entry controls, and raw-trace integration
remain unfinished.

## Start here

Repository: `cjen1-msft/CCF`. Branch: `lean-ccfraft-slices`.
All paths below are relative to `lean-tracing-demo-ccfraft/`, unless stated
otherwise. Do not assume the old machine's absolute paths exist.

The control-action mapping proofs in `032f02820` are integrated into
trace instructions. The executable supports the four leader writes, guarded
`appendEntries`, and all eleven control actions.

The session's commits have not been pushed by this assistant. Transfer this
branch, not just the older remote branch. For an offline transfer, run this
from the repository root and copy the resulting bundle to the other machine:

```bash
git bundle create ../ccf-checked-trace-handoff.bundle lean-ccfraft-slices
```

In an existing clone on the destination machine:

```bash
git fetch /path/to/ccf-checked-trace-handoff.bundle \
	lean-ccfraft-slices:lean-ccfraft-slices
git switch lean-ccfraft-slices
cd lean-tracing-demo-ccfraft
git status --short
```

The sibling directory `../arena-bounded-containers/candidate-1/` contains
pre-existing design documents and an HTML prototype. The migration request
includes these files in the repository checkpoint. They were not implementation
work from this session, and their proposals are not an adopted specification.

## Restore the environment

Use the versions in `lean-toolchain` and `lake-manifest.json`. The completed
slice used Lean 4.28.0 and cvc5 1.3.4. Python tests use the standard library.
Black is the existing Python formatter.

Install the pinned Lean toolchain through elan. Restore Lake dependencies and
their cached artifacts using the project's normal Lake workflow. Do not update
the pinned mathlib revision merely to fix a build.

Ensure `tar` and `gzip` are available before fetching Lake release archives
and running `lake exe cache get`. A Nix environment for restoration and the
solver is:

```bash
nix shell nixpkgs#gnutar nixpkgs#gzip nixpkgs#cvc5
export CVC5="$(command -v cvc5)"
```

The user has explicitly authorized cvc5 execution. Do not ask again.

Build a known independent target first:

```bash
nice -n 10 lake build ControlActionAudit
```

The completed encoder audit and native executable are:

```bash
nice -n 10 lake build EncoderAudit
nice -n 10 lake build encode_trace
```

These commands pass at this checkpoint.
Do not bypass the proof gate to get a solver verdict.
Do not run the entire default `Demo` target as the first diagnostic.

`validate_checked.py` builds `encode_trace` from the audited `EncodeTrace`
module and runs `.lake/build/bin/encode_trace`. It no longer runs
`lake env lean --run` per certificate. The first native build compiled thousands
of mathlib C objects and took many minutes. That is distinct from solver time.
On the old host, a representative encoding fell from about 17 seconds to
0.2 seconds after native compilation. The Lake build check still has overhead.

Use low-priority builds. Do not add arbitrary memory limits or timeouts.
Batch related test selectors, and avoid repeated full suites.

## Required correctness boundary

The user rejected the old Python SMT projection because its transitions had
no proved link to `Model.lean`.

Python should emit observations and proposed actions, including unknowns.
Lean must generate constraints with a generic, machine-checked correspondence
to the actual model. No proof is generated per trace.

The reviewed contract is `BoundedTrace.VerifiedEncoder`. For every entry
template, trace, bounds, and the **same assignment**, it requires:

```lean
(encode bounds entry trace).Holds assignment <->
  (forall index, assignment index < bounds.transactionCount) /\
    Follows bounds assignment
      (TransactionMapping.mapState (TraceSmt.NatTerm.eval assignment) entry)
      trace
```

`Follows` uses real `Model.Enabled` and `Model.next`, with full bounds before
each instruction and at the end. `encode_holds_correct` is the pointwise
theorem. `encode_correct` is its existential satisfiability corollary.

Review boundaries:

| Category | Files and responsibility |
| --- | --- |
| Reviewed model-specific contracts | `Model.lean`, `TraceInstructions.lean`, `BoundedTrace.lean`, `BoundedState.lean`, `TransactionMapping.lean`, JSON decoders, `EncodeTrace.lean`, audit entry points |
| Machine-checked implementation | `MachineGenerated/` encoder, representation, equality, mapping and guarded-step proofs |
| Reviewed reusable infrastructure | `Shared/Smt.lean`, `SmtOrder.lean`, `Equality.lean`, `Guarded.lean`, SMT serialization, solver execution, core reduction |

The allowed proof axioms are `propext`, `Classical.choice`, and `Quot.sound`.
No `sorry`, new axioms, `native_decide`, unsafe extraction, or runtime bypasses.
The executable encoder must be computable.

The theorem covers the formula AST's meaning. JSON decoding, serialization,
the compiler, cvc5, and diagnostic provenance remain trusted. Labels and core
membership are not a second formal correspondence theorem.

## Completed commits

| Commit | Completed unit |
| --- | --- |
| `c04ceca25` | Full explicit entry templates, four leader writes, pointwise checked encoder, Python orchestration, causal core diagnostics, removal of retired code |
| `359931271` | Native audited encoder executable and build-cache invalidation |
| `bd9e59adc` | Generic list equality and exact symbolic entry and packet equality under transaction aliasing |
| `cf9b2ff2c` | Exact AppendEntries request mapping and conditional deduplication correction |
| `83f4ea642` | Executable guarded choices with generic evaluation, composition and queue-operation proofs |
| `50ed2728e` | Executable guarded AppendEntries step, aliasing regressions, shared tests in the audit |
| `032f02820` | Mapping and enabledness proofs for eleven control actions, with `ControlActionAudit` |
| `c60b54f81` | Guarded AppendEntries trace encoding and same-assignment correspondence |
| `2ca80ab43` | Truncated SMT natural subtraction for causal decreases |
| `f5907da7e` | Guarded receive enabledness and successor correspondence, all packet variants |
| `3c0bd951c` | Fixed-context core refinement and standalone source-linked explorer |
| `88f246b25` | Raw identifier normalization and exact partial-message observation contract |
| `9f7ddc1d7` | Stored retirement and pre-vote observation contract and decoder |
| `f8836d49c` | Compositional symbolic state, exact bounds, finite containers and SMT serialization |
| `9478d8430` | Generic symbolic trace composition and symbolic partial-message observations |
| `8f3dd1b1d` | Symbolic stored retirement and pre-vote observations |
| `c7fbf01ab` | Full-model symbolic trace contract and complete observation dispatch |
| `e28cc28aa` | Strict symbolic certificate decoder with six saved raw-trace regressions |
| `94850592f` | Typed intermediate names, owner-group equations, and strict serialization |
| `c83a33f11` | Whole-state causal naming with proved indexed trace composition |
| `efbafbaaa` | Symbolic assurance metadata and matching explorer contract links |
| `dd1bea352` | Coarse and fine symbolic output with matching constraint metadata |
| `e4f626a4b` | Exact named-definition comparison without repeated shared-tree traversal |
| `432ba9feb` | Proved conditional natural values with causal predicate retention |
| `a6274e2e8` | Shared solver reuse and restored PATH discovery in the raw runner |
| `b7fa4f6d0` | All eleven control actions, complete causal tracking, and send scaling regressions |
| `214a222af` | Exact memoized equality for independently allocated symbolic expression DAGs |
| `ff7faf2be` | Proved symbolic evaluation with an assignment-local cache |

The end-to-end CLI supports `clientRequest`,
`signCommittableMessages`, `changeConfiguration`,
`appendRetiredCommitted`, `appendEntries`, and all eleven control actions.
The expanded `check_checked.sh` gate passes 184 tests without skips,
including symbolic infrastructure and controls. Independent review closed the
causal-tracking and repeated-send scaling findings.

The general leader-write example returned SAT:

```bash
python3 validate_checked.py \
	Traces/LeaderWrites/bootstrap-writes.json \
	Artifacts/checked-traces/leader-writes --cvc5 "$CVC5"
```

The guarded AppendEntries step and full trace composition are now proved.
The general same-assignment `encode_holds_correct` theorem remains unchanged.

## Completed guarded trace slice

The general schema and reviewed interfaces include:

- `Instruction.appendEntries source destination batchEnd`.
- `Observation.queueLength node value`.
- A direct AppendEntries clause in `BoundedTrace.Follows`.
- General-schema JSON fields `node`, `destination`, and `batchEnd`.
- Queue-length observations through the observation decoder.
- Updated supported-action metadata and Python coverage text.
- `tests/test_replication_encoding.py` and `Traces/Replication/send.json`.

`MachineGenerated.TraceCertificateTests` passes, including required send
arguments and legacy-schema rejection. The persistent replication fixture
matches its Python builder and returns SAT. README coverage includes this slice.

Implementation files:

- `MachineGenerated/TraceEncoding.lean`
- `MachineGenerated/TraceEncodingProofs.lean`
- `Shared/Guarded.lean`
- `Shared/GuardedTests.lean`

These implement guarded-frame encoding, branch-specific binding namespaces,
queue-length tracking, and their proofs. Local AppendEntries tracking lemmas
require an allocated sender because `next` can allocate a sender even when
the action is disabled. The trace proof derives allocation from `Enabled`
and rejects disabled actions. The public theorem still covers arbitrary
entry templates.

## Preserve the guarded trace invariants

Keep one group for each instruction: group 0 is unknown domains, groups 1
through N are instructions, and the final group is final-state bounds.
Fine inspection must retain individually labelled field constraints.

Use `GuardedAppendEntries.step` and `step_correct`, not a copied transition.
Guarded state alternatives propagate through the whole trace. Bounds,
enabledness and observations must constrain the selected branch under the
same assignment.

Preserve these diagnostic properties:

- Existing log-length, transaction, retirement, allocation, join and sent-index
  bindings remain causal.
- An actual enqueue defines a named queue length from previous length plus
  one. A duplicate retains the previous length.
- Queue observations and capacity checks use the symbolic tracked length,
  not an additional constant physical-length constraint.
- Distinct branch histories get distinct slots for newly defined values.
  Ancestor bindings retain their original names and owners.
- Branches known to be true or false are simplified rather than multiplied.

`Formula.prepare` rejects conflicting definitions of the same group and slot.
Its definitions are unconditional total equations. Distinct branch-local
names are therefore essential. Inlining every name is not an acceptable fix
because it loses causal action attribution.

Run the repeatable proof, native-build, integration, and persistent-fixture gate:

```bash
CVC5="$CVC5" ./check_checked.sh
```

To run the persistent send example separately:

```bash
python3 validate_checked.py \
	Traces/Replication/send.json \
	Artifacts/checked-traces/replication --cvc5 "$CVC5"
```

Passing regressions cover semantic packet aliases, forced distinctness,
same-assignment queue observations, queue capacity, repeated heartbeats,
causal send cores, fine inspection, absent senders, and later writes after
a symbolic queue branch. Shared guard and trace correspondence changes
received separate independent reviews with no material findings.

## Remaining semantic work

`ControlActionMappingProofs.lean` exports `mapState_<action>` and
`enabled_mapState_<action>_iff` for:

`advanceCommitIndex`, `timeout`, `becomePreVoteCandidate`, `becomeCandidate`,
`requestVote`, `requestPreVote`, `checkQuorum`, `updateTerm`, `becomeLeader`,
`proposeVote`, and `advanceCommitIndexAndProposeVote`.

These arbitrary-state, non-injective mapping proofs are integrated into the
guarded encoder. Repairs cover copied fields, conditional commit
frontiers, retirement-completed sets, truncated term lookups, and downstream
guards and bounds. Queue deduplication also avoids spurious retransmission
writers. Both queue-update helpers retain the old length once and condition
only the increment. Duplicate control sends also reuse unchanged network and
tracking functions. The scaling regression checks binding traversal growth
before 24- and 48-send native cases, without wall-clock limits.
The complete 184-test gate passes, and independent review found no remaining
issues. Concrete receive integration is next.

### Receive

`receive` requires guarded semantics, not an unconditional mapping lemma.
`noConflictExtension` compares full entry prefixes. Two
syntactically different transaction terms can become equal after evaluation,
changing both enabledness and successor state.

`ReceiveMappingProofs.lean`, `GuardedReceive.lean`, and
`GuardedReceiveTests.lean` implement and prove exact guarded receive semantics.
The implementation uses direct symbolic prefix equality, not normalization.
`GuardedReceive.step state source destination` returns guarded enabledness
and successor fields. `step_enabledExpr_correct` and `step_correct` relate
them to real `Enabled` and `next` under the same arbitrary assignment.
The step has 100 executable regressions and a transitive allowed-axiom audit.

Trace integration remains pending. Constrain selected `enabledExpr` values
under their branch guards. Track consumption with `.sub oldQueueLength 1`;
deduplicate responses against the post-removal queue. For self-receives,
compose removal and response insertion on the same tracked queue.

The minimal regression has a follower with one transaction entry and a
two-entry request whose first transaction uses another unknown. Equal terms
do not imply equal transaction IDs. Aliasing can enable the extension while
a distinct assignment leaves it disabled. Same-term candidate step-down
must leave the request queued, as the actual model does.

### Symbolic entry controls and shapes

Only transaction IDs are unknown in the completed encoder. Roles, terms,
allocation, log shape and queue shape are explicit at entry. Guarded queue
alternatives after a send do not solve arbitrary symbolic entry states.

The compositional foundation is committed in `Shared/Symbolic*.lean`,
`Shared/BoundedContainer.lean`, and `MachineGenerated/Symbolic*.lean`.
It represents all 15 node slots, roles, scalar fields, finite sets, optional
fields, logs, and packet queues without whole-state alternatives.
`stateWithin_correct` proves exact agreement with full model bounds.
Inactive fields do not inherit scalar-domain restrictions, so an all-absent
empty state remains possible when scalar bounds are zero.

`freshEntry_complete` currently requires the recursive `Fits` capacity
predicate. The bridge from arbitrary bounded model states to that predicate,
and actual symbolic model transition encoding, remain unfinished.
`Shared.SymbolicTrace.encode_correct` composes adapters under the same
assignment. Each adapter must prove real model enabledness, successor, and
observation correspondence on bounded states. This generic theorem does not
replace the unfinished model adapters.

`BoundedSymbolicTrace.VerifiedEncoder` now states the actual-model symbolic
contract for arbitrary entry expressions. Structural holes have their own
types and capacity constraints. Explicit transaction names occupy indices
`entryWidth bounds + nameIndex` and alone receive transaction-domain constraints.
`MachineGenerated.SymbolicTraceEncoding.Adapter` requires exact rejection of
disabled actions and unbounded actual successors. Its successor theorem
requires representation only when the actual successor is bounded.
Every `Follows` suffix already requires these bounds, so this condition does
not weaken the public trace correspondence.

`Expr.named` evaluates its underlying expression under the same assignment.
Normalization retains the name. Grouped serialization gives each name a typed
constant and a total defining equality in its producer group.
The symbolic trace encoder names the initial state in group 0 and each
successor in its action group. Observations advance instruction numbering
without introducing state writes. `tests.test_symbolic_causality` checks that
an inconsistent counter trace retains its entry, writer, and observation
groups, and that removing any of them makes the constraints satisfiable.
This test covers shared composition, not the unfinished model transitions.

`Shared/SymbolicNamedScalingTests.lean` exercises repeated product updates
whose fields share the previous named state. Structural comparison of every
duplicate definition previously traversed those shared trees repeatedly.
The serializer now uses Lean's safe `withPtrEq` API with structural equality
as its fallback. `sameDefinition_correct` proves that the result is unchanged.
The 64-update fixture serializes to 24,544 bytes and cvc5 accepts it.

`Shared/SymbolicSharing.lean` adds opt-in typed equality for independently
allocated expression DAGs. Address hints select cache buckets, but every hit
still checks both typed expressions. The safe Lean API requires the result to
be independent of those hints. Equality proofs and the transitive axiom audit
cover that boundary. Separate doubled and overlapping DAGs at depth 64 compare
in about 2 ms in the fixture.

`Shared/SymbolicEvalMemo.lean` provides `Expr.evalMemo` and `Expr.evalMemoM`.
Cached values carry proofs for the assignment indexed by `EvaluationState`.
The same-assignment theorem preserves `Expr.eval`; names evaluate their
underlying definitions. Regressions cover all constructors, short-circuiting,
hash collisions, and independently allocated DAGs.

Run these committed units separately:

```bash
nice -n 10 lake build Shared.SymbolicSharingMain Shared.SymbolicEvalMemoMain
nice -n 10 lake env lean --run Shared/SymbolicSharingMain.lean
nice -n 10 lake env lean --run Shared/SymbolicEvalMemoMain.lean
```

These libraries do not complete symbolic Receive integration. Normalization
and serialization must also preserve sharing without losing useful selector
and sequence simplification. Native Receive execution remains a separate
gate; small DAG regressions do not establish its performance.

First-source queue selection uses a skipped-prefix accumulator. The earlier
implementation traversed its recursive result three times per level.
`Shared/SymbolicContainerScalingTests.lean` exercises complete selected-packet
results at capacities 16 and 32, with a 200 KB serialized-size ceiling.
`tests.test_symbolic_encoding` runs 13 cvc5 cases for operations, aliases,
15-node entries, partial packets, finite selectors, and zero bounds.

### Raw trace integration and explorer

`reduction.py` remains the only reducer. `validate.py` still uses the unproved
projection in `ccfraft_projection.py`. Do not restore the old `Reduction.lean`.

The raw reducer's partial observations do not supply a complete explicit entry
state. Connect it to the checked backend only after the missing symbolic entry
semantics exist. Unsupported syntax must fail explicitly, never fall back.
Remove the projection only after its live callers migrate.

`raw_normalization.py` preserves instruction order and provenance, converts
transaction names to shared unknowns, and retains correlation evidence
separately by instruction index. Node IDs must remain canonical slots 0 through
14 because renumbering would change the model's implicit bootstrap configuration.
AppendEntries summaries constrain payload length as `batchEnd - previousIndex`,
not the absolute batch end. Missing payloads and previous terms remain unobserved.
`TraceMessageSummary` and `SymbolicMessageSummary` prove the exact partial
observation against the first matching-source packet, not a later match.

The strict `ccfraft-symbolic-trace/v1` decoder accepts `entry: "symbolic"`,
all 17 model actions, and the complete symbolic observation type.
`NormalizedTrace.certificate(bounds)` supplies its input without fabricating
entry fields. Run `python3 -m unittest tests.test_symbolic_trace_decoding`
to parse all six saved normalized traces through Lean. This is a decode-only
check, not an execution or solver verdict.

The HTML explorer is implemented by `explore_checked.py`. It has three horizontal
panes: raw NDJSON, ordered reduced actions and observations with core
highlighting, and the reduced core. Selecting an action opens its detailed
constraints. `refine_checked.py` implements the second reduction stage inside
an existing group-level core, keeping all other reduced groups fixed even if
the solver's next core omits them. The static explorer precomputes these
refinements for core actions and switches views without a browser solver.
It displays raw files supplied with `--raw-trace`, using instruction provenance.
The raw-to-checked semantic integration is still pending; displaying raw text
does not establish that missing correspondence.

See README's "Explore a reduced core" section. The generator rejects malformed
metadata and stale or non-checked verdicts. Saved run artifacts themselves are
trusted inputs. Browser interaction regressions are in `tests.test_explorer`;
run them with Chromium on PATH. Missing browser support does not affect the
Lean proof gate.

## Data and diagnostic constraints

- Bounds on transactions, terms and indices are exclusive. Log and queue
  capacities are inclusive.
- Full bounds include all seven packet variants, queued payloads, every peer
  index, optional retirement indices and submitted transaction IDs.
- An absent node is not an allocated fresh node. Node tables have 15 slots.
- Entry templates need not be reachable or satisfy extra protocol invariants.
- Different unknown names may alias. Freshness uses evaluated submitted IDs.
- Non-injective mapping may merge submitted IDs and packet identities.
- `appendEntries` cannot use unconditional transaction-map commutation.
  Its guarded step preserves real sender updates but suppresses an enqueue
  when the evaluated packet is already queued.
- A reduced SMT core is not a replayable subsequence of model actions.
  Concrete state during encoding may depend on the full prefix.
- Structural guards are currently coarse clauses. Not every failed
  precondition has its own fine-grained label.

Live schemas remain `ccfraft-trace/v1`, `ccfraft-client-request/v1`, and
`ccfraft-client-request/v2`. Legacy schemas restrict actions to client
requests. The v1 bootstrap adapter derives term count 2, index count 1 and
queue capacity 0. General and v2 certificates declare all five bounds.

## Existing failures and cleanup

Full safety proofs in the default `Demo` target had failures reproduced
against the untouched starting commit. Do not attribute those failures to the
new encoder or repair them as an unrelated part of this migration.
`EncoderAudit`, `ControlActionAudit`, and targeted runtime tests are the
relevant checks for these slices. `RuntimeAudit` had also passed earlier.

Completed cleanup removed the old bootstrap-only encoder, 36 archived
prototype files, `bootstrap_from_checkpoint.py`, and the unused long-trace
probe. It moved 36 theorem blocks out of `Model.lean` into
`MachineGenerated/ModelProofs.lean` without changing model definitions.
Keep live legacy projection and runtime consumers until their replacements
are connected.

Ignored `.lake/` build products and `Artifacts/` solver outputs are not portable
source dependencies. Regenerate them. Session logs and task state are not
required to resume from this document.

## Checkpoint status

The last complete checked-encoder gate passed 184 tests with no skips and
returned SAT for the persistent send example. It includes the control
causality and repeated-send corrections. The two newer shared-DAG libraries
have separate proof, runtime, and independent-review results; the full gate
must run again after Receive and the symbolic model adapters are integrated.
`EncoderAudit` enforces the allowed proof axioms transitively.
The receive step is complete but not yet exposed as a trace instruction.
Resume from committed files, not old agent handles. Symbolic entry-state
lowering remains the prerequisite for migrating raw traces.
