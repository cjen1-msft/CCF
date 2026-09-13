# Resume the checked CCFRaft trace encoder

## Current direction: native-array exact encoding

### Immediate continuation: packet observations and response handlers

The user now prioritizes `requestVote`, receive requestVote, `appendEntries`,
receive appendEntries, and membership change. Vote sends, vote-request receive,
append sends, append-request receive, and membership change are public.
Continue the remaining actions needed by the saved captures.
Delegate mechanical proofs to `gpt-5.6-sol` with medium reasoning effort.
The main agent owns semantic lemmas. Build reusable proof components where
they remove repeated execution decomposition and assignment-extension repair.
This supersedes the earlier serial-only worker instruction.

Append-request receipt and membership change have whole-action Model and
exact native-step soundness and assignment completeness. Both are public.
Continue remaining Model actions and partial observations toward raw reduction.
Both assurance flags
remain false.

`advanceCommitIndex` was the first unsupported action in both saved captures,
at normalized step 12. Its private correspondence is now complete.
Commit `8ea3f37bb` adds whole-action Model soundness and canonical prefix and
suffix assignment stages. Commit `06624297a` composes assignment completeness
and exact native-step soundness and completeness. The parent build is in
`native-advance-commit-complete-parent-build.log`.
The proof constructs a satisfying assignment before applying independent
soundness to obtain a represented Model successor. It does not assume that
the initial state is reachable or that inactive tails are canonical.
Public dispatch and whole-trace integration are committed as `ea2e0ec5a`
and parent-owned.
The parent build passes in `native-public-commit-parent-build.log`.

The reusable commit components include `AllActive`, configuration-local
majority counting, `NativeMaximumSummary`, canonical maximum assignments,
bounded quantifier evaluation, and the 17-binding `writeRetirementRow`.
`NativeCommitExecution` extracts named constraints and exact checkpoint
counters from the actual runtime. Its final increment is `25 + 3 * width`.
All accepted commit proof modules are parent-owned.
The majority fixtures cover 200 cases at widths 1, 3, 17, 21, and 65.
The 127 highest-commit fixtures pin genuine joint-majority rejection,
ignored future configurations, and fallback to a lower eligible signature.
The private action has 43 Model cases, including 7 SAT cases, plus a
17-identity SAT/UNSAT pair. Disabled cases stop at the action.
Old `retiredCommitted` metadata may refresh to active and permit commit.
Public regressions cover commit followed by append sends and
duplicate heartbeats, a second disabled commit, and 17 declared identities.
The public Model matrix, strict input errors, sequence, explorer core, and
import boundary pass in `native-public-commit-final-tests.log`.
Private commit regressions and the existing public core sequence also pass
in `native-public-commit-and-signature-tests.log`.
`Traces/native_commit_advancement_conflict.json` attributes its contradiction
to owners `{7, 8}`.

`signCommittableMessages` is now public.
Commit `605cc2fb0` adds reusable leader-log append/refresh correspondence and
signature guards and full-frame Model updates. The parent build is in
`native-signature-foundations-build.log`.
Commit `15af9980b` adds exact native signature transition correspondence and
generic appended-row term correspondence. Commit `5a2e56556` adds the private
runtime and 50 actual-Model fixtures, including 8 SAT cases. Those pass in
`native-signature-and-public-commit-tests.log`.
The private compiler is `NativeSignCommittableFixtureMain`.
The pre-existing `NativeSignatureFixtureMain` remains the signature-index
scan fixture. Both suites pass in
`native-signature-new-and-existing-fixture-tests.log`.
Signature followed by public commit advancement passes in
`native-signature-commit-sequence-tests.log`, including a 17-identity case.
Attempting commit before the new current-term signature is UNSAT.
Whole-action signature soundness and assignment completeness are complete.
Public dispatch and both whole-trace proofs are complete.
Signature guards reject both old and refreshed
`retiredCommitted` membership and require a nonempty old log. Do not copy the
commit action's weaker old-membership guard.

Commit `51dbea2d8` extracts `retirementTail`, shared by commit and signature
writes. It reuses the existing retirement scans, `commitRowTerms`, and
`writeRetirementRow`. The full pre-refactor and post-refactor programs are
definitionally equal, proved in session artifact
`native_retirement_tail_equivalence.lean`. Both proofs and the private commit
correspondence build pass in `native-retirement-tail-refactor-build.log` and
`native-retirement-tail-equivalence.log`.
New signature proofs should use this shared tail, not duplicate the commit
action's execution and assignment bookkeeping.
Commit `ee09a189a` adds generic tail execution/constraint extraction and the
signature's two-definition prefix, including specific-assignment extension
and appended-row representation. Parent builds pass in
`native-retirement-tail-execution-parent-build.log` and
`native-signature-prefix-parent-build.log`.
The shared tail starts with four retirement witnesses, then guards, current
configuration, completed-retirement witnesses, and row writes. Its increment
is `23 + 3 * width`. Its input row need not be a snapshot of the frame:
signature writing supplies an already appended row.
`Traces/native_signature_append_conflict.json` has action owner 7 and
contradictory length observation 8. Its private UNSAT/corrected-SAT pair passes
in `native-signature-conflict-fixture-tests.log`. Public attribution to
the same owners now passes in `native-public-signature-tests.log`.
Commit `6085bf4ec` moves `NodeRowTerms.Bounded.mono` from the commit prefix to
`NativeNodeRowWritesEncoding`. The downstream public rebuild passes in
`native-shared-row-bounds-public-build.log`.

`NativeRetirementTailSound`, `NativeRetirementTailPrefixAssignment`, and
`NativeRetirementTailSuffixAssignment` are accepted as `a4366dfee`.
The prefix stops before guards; the suffix starts after guards.
Both assignment components take a represented input row, its symbol bounds,
and a separately bounded natural commit expression. Do not substitute a
frame snapshot for that supplied row.
Their parent builds pass in `native-retirement-tail-sound-parent-build.log`,
`native-retirement-tail-prefix-parent-build.log`, and
`native-retirement-tail-suffix-parent-build.log`.
Commit `3ebce072a` adds `NativeRetirementTailComplete` and whole-action
`NativeSignatureSound`. Generic completeness takes a caller-supplied proof
of the action's guards. Parent builds pass in
`native-retirement-tail-complete-parent-build.log` and
`native-signature-shared-row-build.log`.
`signature_prefix_row_rep` now shares appended-row reconstruction between
signature soundness and assignment construction.
Commit `4c30cb52f` adds exact native signature soundness and structural
preservation in `NativeSignCommittableEncoding`. Do not overwrite the
pre-existing signature-index module `NativeSignatureEncoding`.

Commit `1cfc56b4c` adds private signature completeness.
`NativeSignatureComplete.signature_assignment` composes the signature prefix
with generic tail completeness. `NativeSignCommittableEncoding.signature_complete`
then applies independent soundness and transports the represented successor to
the exact native `Sign` result. Both preserve the supplied assignment below
the original symbol counter. The parent build passes in
`native-signature-complete-parent-build.log`.
Commit `e3dc9a71d` makes commit execution reuse generic tail extraction.
It exposes `commit_tail_execution`, `commitTailStates`, and the actual tail run
for the commit proof consumers. Commits `890ca9b04` and `7a9aed408` make
commit soundness and both assignment stages reuse the generic tail proofs.
Their parent builds pass in `native-commit-shared-sound-parent-build.log`
and `native-commit-shared-assignments-parent-build.log`.

Mechanical workers retain separate files.
Worker `2a020198-af17-47bf-b45b-0b82864a50ad` completed public signature
integration and vote-response soundness, accepted in `40109af92`.
It now owns `NativeAppendResponseSound`.
Worker `a04f39b9-8aa6-4733-9c2c-228d7432032e` completed
`NativeQueuePatternEncoding`, including equivalence to the slower baseline,
and vote-response completeness, accepted in `705731c26`.
It now owns `NativeAppendResponseComplete`.
Worker `b53cfbd8-539b-4835-b9bf-32d4fb1d4892` completed Model correspondence
in `NativeArrayVoteResponse` and the exact native `receive_eq_write_pop`
bridge, accepted in `0547ae584`. Its append-response Model proofs are
accepted in `816ca46fd`; its append-response term proofs are accepted in
`f16fe45ab`. It is idle.
Worker
`af5d19d5-1186-4609-9b0b-4f224d4a4330` completed
`NativeAppendResponseExecution`, accepted in `03e5f7809`, and is idle.
Its vote-response row refactor is accepted
in `501abf1fc`, reusing the snapshot representation instead of reproving
unchanged fields. All accepted response statements are fixed.
The parent owns runtime, tests, docs, and all accepted modules.
Public signature integration is committed as `ba6aff545`.
The parent build passes in `native-public-signature-parent-build.log`.
Public Model, input-error, sequence, and explorer cases pass together with
private signature, old signature-index, commit, and core-sequence regressions
in `native-public-signature-tests.log`.
The earlier unsupported-signature result in
`native-signature-public-before-integration-tests.log` is superseded.

For the later `clientRequest` action, preserve the submitted-set tail
semantics. `NativeNatSet.natSetMember` masks membership by its live limit;
`natSetDomain` constrains only the nonnegative limit. Raw cells beyond that
limit are unconstrained. A store followed by increasing the limit can expose
stale tail bits as spurious submitted transactions. The insert encoding must
preserve old masked membership and add only the requested transaction.
Raw transaction names are shared unknowns, not distinct natural literals.
`raw_normalization.py` preserves repeated names and permits different names
to alias. The native instruction type currently fixes transactions to `Nat`
and its JSON decoders accept literals. Native client-request integration must
represent shared existential transaction values in Lean and preserve their
bindings across assignment extensions. Do not map different raw names to
distinct ordinal transaction IDs. This interface work remains unresolved.

Commit `36efa30f6` adds a private typed packet-pattern representation, SMT
terms, strict JSON decoding, and fixtures. All seven existing packet families
support optional fields. Only `kind` is required. Omitted fields stay
unconstrained; explicit `null`, unknown fields, and wrong-family fields fail.
Append patterns support `entriesLength` without supplying `prevLogTerm` or
entry contents. `native-packet-pattern-tests.log` records passing semantic
and malformed-input cases.
Commit `ca1a092ed` proves packet-pattern correspondence against actual Model
messages through a reusable optional-field lemma. Natural literals have
explicit `Nat` arguments rather than an inferred `Option.bind` coercion.
The parent build and packet/queue cases pass in
`native-packet-pattern-encoding-parent-build.log` and
`native-packet-pattern-proved-tests.log`.
`packet_pattern_term_correct` takes expected pattern, actual packet term,
assignment, locals, Model message, and equality to its `packetValue`.
It returns equality of term evaluation and `expected.matches message`.
Commit `2b76987e9` adds `NativeQueuePattern`,
`NativeQueuePatternFixtureMain`, and `test_queue_patterns`. These are parent-owned.
Their 126 cases cover FIFO bounds, large heads and lengths, and normalization
of malformed packets and mismatched sources.
The first implementation normalized the complete packet before matching each
field. Case 67 remained unsolved for at least 56 seconds. Applying the pattern
inside one packet-domain conditional reduced that script from 52,707 to 14,163
bytes and solved it in 10.337 ms. All 126 cases then passed in 6.888 seconds.
The invalid branch still matches the existing `defaultQueuePacket`; it does
not reject or repair the represented Model state.
Artifacts are `native-queue-pattern-baseline-67.smt2`,
`native-queue-pattern-baseline/`, `native-queue-pattern-conditional/`, and
`native-queue-pattern-comparison.json` in the session files directory.
`queue_pattern_correct` proves decoded-queue matching with only nonnegative
head and length premises. `queue_pattern_baseline_eval` proves unconditional
evaluation equality to the original normalization-before-matching expression.
The parent build passes in `native-queue-pattern-encoding-parent-build.log`.
Both statements preserve arbitrary raw cells, source mismatches, and inactive
tails. The optimized and baseline encodings have the same meaning.
Public integration is implemented but not committed yet.
The observation is `queuePattern` with the same
`source`, `destination`, `index`, and `value` envelope as `queuePoint`.
Existing complete-packet `queuePoint` decoding must remain strict.
The reducer's `firstMessageFrom` will use index zero, without inventing
unobserved packet fields.
Public pattern coverage and strict-input cases pass, as do the existing
complete-packet and queue-length cases. The explorer attributes the
contradictory observations to owners `{0, 1}`.
The pre-integration failure at instruction 1 with
`property not found: node`, from the unsupported kind's local-observation
fallback, is superseded. See `native-public-patterns-before-integration.log`.
The corrected SAT case exposed a separate solver bottleneck: its 12,737-byte
query remained unsolved 341 seconds after script creation. E-matching did
not resolve the unchanged query within 120 seconds.
The retained script and probes are in `native-public-pattern-corrected-baseline/`
and `pattern_domain_probe.py`. The packet log domain already requires canonical
inactive cells. Adding a redundant finite-array reconstruction implication
keeps that domain and leaves live entry contents unknown.
The Lean-emitted query is 14,335 bytes and solves in 16.136 ms.
`NativePacketArrayHint` implements the hint; `queuePatternDomain` uses it only
for append patterns with an explicit `entriesLength <= 32` and omitted `entries`.
Larger or unknown lengths retain the original quantified domain.
Boundary cases at 0, 1, 2, 8, 16, and 32 entries solve in 14-29 ms.
A length-33 SAT case and conflicts at lengths 33 and `10^30` also pass
through the fallback.
These are formula-expansion limits, not representation bounds.
Worker `59af956e-475e-495a-a970-a32160960217` owns
`NativePacketArrayHintEncoding` and `NativeQueuePatternEncoding`, proving
the new hint redundant and preserving both existing queue-pattern theorems.
The parent owns runtime, the three public integration files, tests, and docs.
Do not commit or declare public pattern completion until this proof and the
full public rebuild pass. Runtime results are in
`native-public-pattern-hint-tests.log` and
`native-public-pattern-hint-boundaries-tests.log`.

Commit `2fd560cee` adds the private vote-response runtime `NativeVoteResponse`,
shared by vote and pre-vote replies. It reuses `writeNodeRow` and FIFO pop,
with 18 fresh symbols.
This is the simple baseline, not a specialized single-column writer.
`NativeArrayVoteResponseFixtureMain` derives 120 cases from actual Model
enablement and next-state functions, including 76 enabled cases.
The Python `vote_response_traces` helper also mutates every post-state
observation in two tally cases, rejects wrong packet kinds and empty queues,
and exercises bit 16 in 17-identity vote and pre-vote tallies.
All 304 cases pass, including 78 SAT cases, in
`native-vote-response-complete-fixtures.log`.
`NativeReceiveVoteResponseFixtureMain` is the private compiler.
Commit `f679304e7` proves actual Model response correspondence and reusable
guard, row-write, and pop execution extraction. Commit `0b3e4610e` proves
SMT guard and conditional-row correspondence. Both parent builds pass in
`native-vote-response-foundations-parent-build.log` and
`native-vote-response-terms-parent-build.log`.
Whole-action vote-response soundness and exact native assignment completeness
are accepted in `40109af92` and `705731c26`.
The parent build passes in `native-vote-response-whole-action-parent-build.log`.
Public response dispatch remains pending.
Commit `a041d0251` retains `Traces/native_vote_response_tally_conflict.json`.
The private conflict and corrected `["a"]` tally pass in
`native-response-conflict-private-tests.log`.
The shared `vote_request_response_traces` generator covers duplicate request,
request receipt, and response receipt, including idempotent tally insertion
and rejection after the FIFO becomes empty. Its private cases pass in
`native-vote-round-trip-private-tests.log`.
Public response Model, input-error, round-trip, and explorer tests are prepared
but unstaged. The pre-integration public Model matrix fails on the unsupported
response action at instruction 85, recorded in
`native-public-vote-responses-before-integration.log`.
Unlike `updateTerm`, response receive does not require an allocated source.
An unallocated source's response is consumed without changing nodes, even
when its term is newer. With an allocated source, a newer reply to the wrong
role is ignored, while a newer reply to the expected candidate role is
disabled. Membership and pre-vote status are not response guards.

The append-response slice starts from `NativeArrayAppendResponse`.
Its Model correspondence is accepted in `816ca46fd`; the parent build passes
in `native-append-response-model-parent-build.log`.
Every NACK is handled, regardless of role
or term. Its sent cursor becomes
`max (min (findHighestPossibleMatch log lastLogIndex term) oldSent) oldMatch`.
Do not assume ordered terms, bounded cursors, or `oldMatch <= oldSent`.
A NACK can increase the sent cursor in an arbitrary initial state.
Current-term leader ACKs increase the match cursor with `max`; stale ACKs
and ACKs to other roles are ignored. Newer ACKs to leaders are disabled.
An unallocated source bypasses the handler and only consumes the packet.
Reuse `nackMatchTerm` in `NativeLogSummaryTerms.lean` and its existing
correspondence for the SMT scan rather than adding another maximum implementation.
Commit `d056140bb` adds the private `NativeAppendResponse` runtime, its Model
fixture generator, and `NativeReceiveAppendResponseFixtureMain`.
The runtime uses one unconditional NACK-match witness, the 16-binding row
writer, and the two-binding FIFO pop. Its increment is 19.
All 226 Model cases pass, including 194 SAT cases, in
`native-append-response-baseline-tests.log`. They cover empty and unsorted logs,
zero and large indices and terms, inconsistent cursors, source absence,
wrong recipients, and self-responses.
Commit `af3f79790` extracts `mutate_frame_observation` for both response families
and mutates every post-state observation in an ACK and a NACK case.
Both response suites pass in `native-response-shared-mutations-tests.log`.
Commit `f8998ddee` shares wrong-packet-kind and empty-FIFO rejection cases.
Both response suites pass in `native-response-shared-guards-tests.log`.
Execution extraction and append-response term correspondence are accepted
in `03e5f7809` and `f16fe45ab`. Their parent builds pass in
`native-append-response-execution-parent-build.log` and
`native-append-response-terms-parent-build.log`.
Whole-action SMT correspondence and public append-response dispatch are pending.

Raw reduction also emits per-identity `joined` observations. Their existing
Model meaning is membership in `state.hasJoined`, not current allocation.
The native API's whole-set `hasJoined` cannot represent one such observation
without inventing facts about other identities.
Public `joined` support is complete in `NativeArrayVote`, `NativeFrameEncode`,
and `NativeFrameStep`. Its strict shape is
`{"kind":"joined","node":"a","value":true}`.
The parent build passes in `native-public-joined-parent-build.log`.
Boolean, whole-set consistency, allocation-independent, widths 1, 3, 17, and 65,
membership-change, malformed-input, and explorer cases pass in
`native-public-joined-tests.log`, alongside existing joined-set and public
membership-change coverage. `Traces/native_joined_point_conflict.json`
attributes the contradiction to owners `{0, 1}`.
The parent owns these three public files. Preserve the accepted `joined` behavior.

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
  Public append receive is now wired, as recorded below.
- `NativeArrayAllocation` proves exact Model allocation for membership change.
  Existing rows survive; missing members become fresh nodes. Abstract reads
  stay unchanged because missing rows already read as fresh. The eventual
  encoder must still reset hidden raw cells before exposing a new allocation.
  `native-array-allocation-build.log` records the clean proof build.
- `NativeArrayChangeConfiguration` now proves membership-change guards,
  source-row updates, and full-frame Model correspondence given the exact
  configuration and retirement witnesses. Existing allocated rows survive.
  Added-peer cursors use the old log length. The public action is now wired.
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
`native-core-model-fixture-coverage.log`. Neither action is public yet.
All append receive and membership cases now pass against their private encoders.
Whole-action proofs and public wiring remain unfinished.
Wire both through `assert_model_traces` when their public actions land.

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
These completed modules are parent-owned.
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

Allocation, log length, commit, and log cells now use current column references.
Their initial symbols remain 0, 3, 4, and 6.
Entry observations normalize raw entries to their Model values.
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

Worker `a04f39b9-8aa6-4733-9c2c-228d7432032e` completed the four-column
reference migration in 31 native core and proof files. It is committed as
`a86ee60b1`, including repaired fixtures and the relocation regression.
The new fields are `allocated`, `logLength`, `commit`, and `logEntries`.
Preserve initial IDs 0, 3, 4, and 6 and the next-symbol counter 24.
Runtime readers must take current `Columns` explicitly, with no initial-column
default. The migration includes representation, reference bounds, assignment
transport, guards, packets, observations, and trace proofs. Initial domains
still use initial references. No new action is part of this migration.
The parent repaired the eight fixture callers with the guarded, idempotent
`files/migrate_native_fixture_columns.py`, after checking one hand migration.
`NativeRelocatedColumnsFixtureMain` compares every emitted clause before and
after relocating all columns, including live entries and mixed action histories.
The initial missing-field failure is in `native-relocated-columns-first-compile.log`.
Relocation now passes in `native-relocated-columns-tests.log`.
The independent public build and fixture rebuild pass in
`native-mutable-columns-parent-build.log` and
`native-mutable-columns-fixtures-build.log`. All 15 targeted methods pass in
337 seconds in `native-mutable-columns-regressions.log`.
Independent reviewer `8da02dde-1a84-4a0c-b100-47f49305f2fd` completed the
31-module core-diff review with no significant issues. The parent inspected
the result. All four new references also reject unallocated symbol IDs in
`native-relocated-columns-reference-tests.log`.
The worker's guarded core migration and initial inventory are in
`files/migrate_native_mutable_columns.py` and
`files/native-mutable-columns-inventory.txt`. The script covers mechanical
call-site changes; the proof repairs remain in the source diff.
The range, retirement-scalar, and response-packet encoders and fixtures have
been rebuilt against the new column interfaces.

`NativeArrayRetirementCompleted` and `NativeRetirementCompletedTerm` now prove
the global completed-retirement predicate using committed-prefix first-inclusion,
retirement, and retired-record witnesses. All four Model conditions remain,
including the absence of committed retired records and presence of a retirement
in the committed prefix. The independent build passes in
`native-retirement-completed-parent-build.log`. Its 720 Model-derived scripts
pass after proof integration in `native-retirement-completed-final-tests.log`.
These modules and their fixture are parent-owned.

The parent built new `NativeNodeRowWrites.lean` in
`native-node-row-writes-build.log`. It snapshots 15 local row terms, writes
16 fresh columns including allocation, then publishes their references together.
Whole-row writes favor one reusable proof for receive and allocation over
minimum store count. Optimize only if that cost becomes measurable.
The precheck requires every definition input symbol to precede the original
counter, so an initially invalid payload cannot capture a newly created symbol.
`NativeNodeRowWritesEncoding.lean` now proves snapshot representation,
allocation without a prior-presence premise, full-frame preservation,
reference bounds, execution shape, and specific-assignment extension.
The parent inspected the complete proof and independently built it in
`native-node-row-writes-parent-build.log`. Both row-write modules are parent-owned.
The parent retains the runtime and `NativeNodeRowWritesFixtureMain`.
Its 1,584 Model-derived scripts and 60 invalid-symbol cases pass in
`native-node-row-fixture-tests.log`. They cover direct replacement, absent-node
allocation, snapshots over poisoned hidden rows, repeated writes, every local
field, and preservation of other rows, globals, and duplicate queues.
Snapshot cases also copy noncanonical cells at negative and huge tail indices.
The final fixture and import-boundary run passes in `native-node-row-final-tests.log`.
The row writer is complete. Public append receive and membership change remain unwired.

The next shared scan uses `LogMatchSummary.StorageSummary` for the greatest
matching one-based index, with zero for no match. It supports bounded signatures,
committed configurations, and NACK term matching without temporary node columns.
`NativeMaxMatchEncoding.lean` proves the generic constraint and canonical witness
extraction. `NativeArrayLogSummaries.lean` relates that summary to existing native
signature and current-configuration predicates and their Model functions.
Both modules are parent-owned and independently built in
`native-log-summary-parent-build.log` and `native-array-log-summaries-parent-build.log`.
The parent also owns `NativeLogSummaryTerms.lean` and `NativeLogSummaryFixtureMain.lean`.
Their 4,160 scripts pass in `native-log-summary-fixture-tests.log`, including
noncanonical cells, mixed nested binders, wrong witnesses, and wrong configuration
members. The Python method is `test_explicit_log_summaries`.
`NativeLogSummaryEncoding.lean` now composes the concrete terms with these proofs,
including arbitrary-witness extraction and exact current-configuration members.
The parent inspected it and independently built it in
`native-log-summary-proof-parent-build.log`. All log-summary modules are parent-owned.

The parent built `NativeAppendReceiveTerms.lean`, which encodes packet selection,
the local handler branches, and exact receive guards. Its fixture reuses the
1,344 prepared Model traces and adds 72 raw queue cases. All 1,416 scripts pass
in `native-append-receive-guard-tests.log`. The fixture stops at the receive
boundary, so it establishes guard behavior, not poststate behavior.
`NativeAppendReceiveTermsEncoding.lean` proves correspondence for those terms,
including exact Model enablement under the selected-append restriction.
The parent inspected the full proof, added its missing module-level axiom gate,
and exposed the request-log representation lemma for later composition.
The runtime, proof, fixture, and Python registration are parent-owned.
Public append receive remains unwired.

The parent built `NativeAppendReceiveWrites.lean`. It reuses the row, queue-pop,
and queue-push writers, then selects original queues for candidate stepdown.
Only consuming cases update the destination's completed-retirement set.
`NativeAppendReceiveWritesEncoding.lean` proves full-frame soundness,
specific-assignment extension, exact 24-symbol execution, and reference bounds.
The parent inspected the complete proof and rebuilt it in
`native-append-receive-writes-parent-build.log`. The runtime, proof, and fixtures
are committed as `32d7f3c91`. `NativeAppendReceiveWritesFixtureMain` passes
2,436 scripts and 16 invalid-reference cases in `native-append-receive-writes-tests.log`.
The five enabled receive branches, self queues, duplicate replies, absent senders,
and preservation during stepdown are covered. Supplied rows still come from the
Model, so these cases do not yet cover the encoder's calculation of the new row.

`NativeArrayAppendReceiveFixtures` and `NativeNodeRowFixtureTerms` share existing
fixture data without importing executable entry points. The extraction is
committed as `cf54eba22`. The 1,344 generated receive traces are byte-identical
before and after extraction.

The parent built `NativeRetirementRefreshConstraints.lean`, composing the local
retirement, signature, and retired-record scans. No retirement forces no signature.
Retired records remain independent of retirement status.
Its fixture combines the scan assertions with the scalar refresh terms.
All 2,592 scripts pass in `native-retirement-refresh-constraints-tests.log`.
`NativeRetirementRefreshEncoding.lean` proves local refresh correspondence
and arbitrary-witness soundness. The parent inspected it and independently built
it in `native-retirement-refresh-parent-build.log`. The proof, constraints,
and fixture are parent-owned.

The parent built draft `NativeAppendReceive.lean`, composing guard, candidate-log
splice, commit signature, retirement scans, completed-node membership, response,
and writes. It is not public and has no complete action-encoding proof yet.
`NativeAppendReceiveFixtureMain` exercises it against the prepared Model traces.
`NativeAppendReceiveFixtureInstructions` shares the fixture-only decoder with
the guard fixture; it does not change the public instruction type.

The first full matrix spent over four minutes generating scripts before starting
Z3 and was stopped. A single extension case emitted 14,225,799 bytes in 8.31 seconds including
Lean startup. Five existing `define` operations now share the packet, grow flag,
candidate length, candidate entries, and candidate commit. The same case emits
531,854 bytes in 5.50 seconds and solves SAT. No array representation changed.
The baseline and shared profiles are `native-append-receive-baseline-profile.json`
and `native-append-receive-shared-profile.json`; the rerunnable profiling script is
`profile_native_append_receive.py` in the session files directory.
The shared-expression retry reached at least 624 solved cases. Case 508,
a candidate stepdown, took 149.65 seconds. It unnecessarily constrained unused
splice and scan witnesses. The draft now guards those constraints by their
actual uses: grow, accepted commit update, consuming retirement refresh, and
hinted NACK. Case 508 now takes 0.059 seconds and case 624 takes 0.071 seconds.
Both remain SAT. Shell `605` was stopped; its baseline metrics remain under
`native-internal-receive-fixtures`.
The guarded retry reached case 294, a self-receive extension, and became slow
again. Pinning its initial FIFO head to zero did not resolve it within two
minutes. That diagnostic was stopped without changing the representation.
Disabling Z3 E-matching solved the unchanged case in 0.132 seconds.
Shell `641` was stopped; its artifacts remain under
`native-internal-receive-guarded-fixtures`.
With `smt.ematching=false`, all 1,344 internal receive cases pass, including
334 SAT cases, in `native-mbqi-regressions.log`. That run then exposed `unknown`
on the existing `queue-push-preserves-other-cells` case.
`native_solver.py` now retries the unchanged script with E-matching enabled
only after `unknown`. It preserves first-attempt diagnostics as `.mbqi.stdout`
and `.mbqi.stderr`, records the retry, and measures total elapsed time.
Solver errors still fail immediately. A second `unknown` stays inconclusive.
The retry protocol failed first in `native-mbqi-retry-before.log` and passes
in `native-mbqi-retry-protocol-tests.log`.
All 17 resumed methods pass in 667 seconds in
`native-quantifier-retry-regressions.log`, covering quantified-array components,
all eight public action kinds, explorer cores, and all 2,436 receive-write cases.

`NativeAppendReceiveResponse` and `NativeAppendReceiveResponseEncoding` are
committed as `1131bcb07`. They prove ACK and NACK construction, including
arbitrary unused best-index witnesses. The NACK hint checks the last local term,
not the term at the requested previous index. The parent inspected the proof
and rebuilt it in `native-append-receive-response-parent-build.log`.
All 396 response scripts pass in `native-append-receive-response-tests.log`.
They include zero and positive matches, unordered terms, bounded matches,
ordinary NACKs, and negative or huge unused witnesses.
The private encoder now calls these helpers. All 1,344 Model traces pass again
in `native-internal-receive-response-integrated.log`.
`NativeArrayAppendReceiveHintFixtureMain` adds 110 full transitions using the
same response scenarios, with 55 SAT cases. They pass in
`native-internal-hinted-receive.log`, including absent senders and self queues.
The shared scenario extraction leaves all response scripts byte-identical.
The private encoder and both trace methods are committed as `8695f7c49`.
Whole-action soundness and completeness remain unfinished; do not expose the
action publicly or change either assurance flag.

`NativeMembershipTerms` and the fixture-only membership decoder are committed
as `9681215b7`. The guard uses the latest configuration at the old log length,
not the committed configuration. It checks source allocation and role, both
old and refreshed retirement state, a nonempty changed configuration, and
whether any newly added identity has already joined.
`NativeMembershipGuardFixtureMain` stops before post-state observations.
All 1,572 guard scripts pass, including 314 SAT cases, in
`native-membership-guard-tests.log`. `NativeMembershipTermsEncoding` now proves
the added set, appended log entry, and exact Model guard equivalence from
arbitrary current and retirement scan witnesses. It is committed as `52a8bd34d`.
The parent removed a duplicate bitset-equality lemma, inspected the full module,
and rebuilt it in `native-membership-terms-parent-build.log`.
The guard cases and import audit pass in `native-membership-terms-parent-tests.log`.
The private allocation writer and full membership encoder now pass Model-derived
regressions. Their whole-action correspondence proofs remain unfinished.

`NativeArrayAppendCandidate.lean` is committed as `2fa2a9ed2`.
It composes all consuming handler results for the selected log, commit, and
new-follower fields, using reusable branch-disjointness lemmas.
It also proves that candidate stepdown leaves this candidate row unchanged.
Inactive signature witnesses need no scan premise. The parent inspected the
full proof and rebuilt it in `native-array-append-candidate-parent-build.log`.
`NativeAppendReceiveCandidateTerms.lean` and
`NativeAppendReceiveCandidateEncoding.lean` are committed as `11f4f832e`.
They connect the guarded splice, selected-array definitions, and conditional
signature scan to the native candidate row. Inactive SMT signature integers
may be negative. The proof now constructs the 15-field row representation once.
The parent inspected and rebuilt it in `native-candidate-shared-parent-build.log`.
All 1,454 internal transitions and the import audit pass in
`native-candidate-integration-tests.log`. The 110 focused scripts remain
byte-identical after helper extraction.
`NativeAppendReceiveHandlerEncoding.lean` is committed as `d5fc50617`.
It composes the typed candidate and guarded NACK scan into the exact Model
local handler and response. The parent build and import audit pass in
`native-append-handler-parent-build.log` and `native-append-handler-import-tests.log`.
`NativeAppendReceiveLocalEncoding.lean` is committed as `24bf70d04`.
It composes the candidate, final row, and response from actual guarded constraints,
without execution bookkeeping. The parent inspected the complete module.
Its independent build and import audit pass in `native-append-local-parent-build.log`
and `native-append-local-import-tests.log`.

`NativeRetirementCompletedConstraints.lean` and
`NativeRetirementCompletedConstraintsEncoding.lean` are committed as `7fb76723b`.
The extracted loop preserves IDs and assertion order, with `1 + 3 * width`
fresh symbols. Both enabled and disabled specific-assignment extension are proved.
The enabled proof transports five bounded input expressions, then rebuilds
scan facts through semantic iff lemmas instead of expanding generated `Term.eval`.
The independent build passes in `native-completed-loop-complete-parent-build.log`.
`NativeRetirementCompletedConstraintsFixtureMain` passes 240 scripts and 20
future-reference rejections in `native-completed-loop-fixture-tests.log`.
It checks exact allocation/assertion counts, all five original-counter checks,
ignored tails, disabled constraints, and deliberately invalid active witnesses.
The fixture, all 1,454 private receive transitions, and the import audit pass
in `native-completed-loop-integration-tests.log`. The loop files are parent-owned.

`NativeRetirementCompletedEncoding.lean` now composes the actual current,
prefix-retirement, and retired-record constraints into one Model completed-node
bit, then a whole bitvector. Its `retirement_completed_constraints_complete`
constructs all three canonical witness families and proves every bit equation.
The parent inspected the whole module and independently built it in
`native-retirement-completed-full-parent-build.log`.
The existing 720-case fixture now also constrains
the current configuration through the real emitted scan and member decoder.
It and the import-boundary audit pass in
`native-retirement-completed-full-parent-tests.log`. The proof and fixture
are parent-owned.

`NativeAppendReceiveFrameEncoding.lean` is committed as `09a96838a`.
It connects the existing write-effect
proof to the Model receive step using the conditional stepdown/handler/refresh
facts, with both soundness and specific-assignment extension.
The parent build and import audit pass in `native-append-frame-parent-build.log`
and `native-append-frame-import-tests.log`.
Worker `af5d19d5-1186-4609-9b0b-4f224d4a4330` initially returned only compiling
declarations in `NativeAppendReceiveExecution.lean`, not an actual-run theorem.
That checkpoint was not accepted as a proof. The worker is idle with no owned files.
The parent reproduced the elaboration problem with a first-guard-only theorem:
`simp only [receiveAppend, get_bind_run] at run` did not finish after 240 seconds.
The parent stopped that probe. Replacing that line with
`rw [receiveAppend, get_bind_run] at run` compiled at the default budgets.
The reproducer is `files/AppendExecutionProbe.lean`, with the passing log
`native-append-first-bind-rewrite-probe.log`. Use shallow rewrites to expose the
outer action and `get`, rather than simplifying the entire generated body.
Worker B completed `receive_append_success` using this approach.
`NativeAppendReceiveExecution.lean` is committed as `dccdc4b74` after full parent
inspection, an independent build, and the import audit.
It derives all per-stage runs from the actual `receiveAppend` run.
Writer entry preserves the original columns and bootstrap, with counter
`before.next + 14 + 3 * width`. The final counter is `before.next + 38 + 3 * width`.
The parent build log is `native-append-execution-parent-build.log`.
`NativeAppendReceiveExecutionConstraints.lean` is committed as `c914eab56`.
It derives prefix constraints, prior-Holds, and reference preservation from the
actual run and final assertions. The parent inspected the module, rebuilt it in
`native-append-execution-constraints-parent-build.log`, and ran the import audit.
The parent composed `append_receive_execution_model_sound` in
`NativeAppendReceiveSound.lean`, committed as `ed9226cf1`.
Given the execution record and emitted prefix constraints, it derives the selected
request, Model enablement, and final-frame correspondence.
Completed-retirement bits remain arbitrary during stepdown.
The build and import audit pass in `native-append-execution-model-sound-build.log`
and `native-append-execution-model-sound-import-tests.log`.
`receive_append_model_sound` is committed as `34e9ed2f8`.
It derives the selected request, Model enablement, and final Model-next
representation from the actual encoder run and final assertions, given the
original frame, Model, and bootstrap representations.
The build and import audit pass in `native-append-whole-action-sound-build.log`
and `native-append-whole-action-sound-import-tests.log`.
Append receive remains private until exact native-step correspondence and public
trace integration are proved.
`NativeAppendReceiveLogAssignment.lean` is committed as `f47e0c2f1`.
It extends a supplied assignment through `entriesDefined`, preserving the original
frame and request and proving the selected candidate log representation.
The splice keeps raw live cells and uses the previous fresh-array value as its tail.
The parent inspected the complete proof, removed its copied assertion helper,
and rebuilt it in `native-append-log-assignment-parent-build.log`. The import audit passes.
`NativeAppendReceiveCommitAssignment.lean` is committed as `9ef7ff17d`.
It extends the supplied assignment from `entriesDefined` through `commitDefined`,
choosing the bounded-signature witness and defining a natural commit value.
It preserves the frame, packet, and selected log. Parent inspection, build, and
import audit pass in `native-append-commit-assignment-parent-build.log` and
`native-append-commit-assignment-import-tests.log`.
`NativeAppendReceiveRetirementAssignment.lean` is committed as `932f50595`.
It extends from `commitDefined` through `currentAsserted` using the canonical
four-witness and single-index helpers. It preserves the frame, request, log, and
commit, and supplies the unconditional current-index constraint.
Parent inspection, build, and import audit pass in
`native-append-retirement-assignment-parent-build.log` and
`native-append-retirement-assignment-import-tests.log`.
`NativeDefinitionsEncoding` now shares `assertion_holds`,
`assertion_extension_holds`, `fresh_holds`, `fresh_prior_holds`, and `define_holds`.
Commit `cf717f736` removes the repeated local copies from the append proofs.
Affected callers and the import audit pass in `native-shared-assertion-helpers-build.log`
and `native-shared-assertion-helpers-import-tests.log`.
`NativeAppendReceiveTailAssignment.lean` is committed as `7460aac22`.
It extends through the enabled or disabled completed-retirement loop and the NACK
witness, preserving the supplied assignment and original frame representation.
The parent inspected it and the current-prefix assembly, then built both in
`native-append-current-tail-parent-build.log`. The import audit passes.
`NativeArrayAppendNetwork.lean` is committed as `72304303c`.
It supplies the exact `ReceiveAppend` relation, Model enablement/correspondence,
and existence from an enabled selected request. Output compatibility also
preserves exact queues/globals and pointwise Model node values.
The parent inspected the diff and rebuilt it in
`native-array-append-transition-parent-build.log`; the import audit passes.
`NativeAppendReceiveEncoding.lean` is committed as `6b9be8933`.
`receive_append_frame_success` and `receive_append_complete` connect actual
encoder runs to the exact native step through shared Model-equivalence transport.
The parent build passes in `native-append-frame-correspondence-build.log`;
the import audit passes.
Public `receiveAppendEntries` is integrated in `NativeArrayVote.lean`,
`NativeFrameEncode.lean`, `NativeFrameStep.lean`, and `NativeFrameTrace.lean`.
The parent inspected all four diffs and built the public proofs, executable,
and affected Model fixtures in `native-public-append-receive-parent-build.log`.
The 1,454 public append-receive cases, input errors, explorer core attribution,
1,200 append-send cases, 480 vote-receive cases, and import audit pass in
`native-public-append-receive-tests.log`.
Public append receive is committed as `5077346b6`.
Generic `receive` remains rejected. Public membership integration is also
complete in the same four files, with strict set decoding and both trace proofs.
The parent inspected the diffs and built public proofs and fixtures in
`native-public-membership-parent-build.log`.
The 1,572 membership cases, input errors, set semantics, and explorer core pass
in `native-public-membership-tests.log`. That invocation was stopped during the
unconstrained 21-node experiment described below, not because of a failing core case.
The 184 public five-action sequences, the explicitly inactive 21-node case, and
110 append-hint regressions pass in `native-public-core-sequence-tests.log`.
All public compiler files are parent-owned.
Public membership and the five-action pipeline are committed as `38d10f664`.
`NativeFrameStep.lean` and `NativeFrameTrace.lean` now use named,
instruction-indexed `FrameInstructionRun` cases instead of nested disjunctions.
Runtime and final correspondence theorem statements are unchanged.
The parent inspected the diff and accepted the independent public build in
`native-frame-run-cases-parent-build.log`. This refactor is committed as `13bb131fe`.
The root `CHANGELOG.md` has an Unreleased demo entry; add its actual PR reference
when a PR exists. No PR has been opened.

`append_receive_prefix_constraints`, committed as `4a74a4892`, exposes the
existing backward constraint extraction before frame writes.
`append_receive_prefix_model_correct`, committed as `ef576f125`, derives the
output-row, response, completed-set, and Model-frame facts at that same boundary.
Both preserve the existing whole-action soundness API.
`NativeAppendReceiveComplete.append_receive_finish_assignment` is committed
as `31a9018d7`. Given a satisfying pre-write assignment, it assigns the write
outputs and proves representation of the actual Model next state.
The build and import audit pass in `native-append-finish-assignment-build.log`
and `native-append-finish-assignment-import-tests.log`.
This completes the write phase, not the whole-action completeness proof.
`NativeAppendReceiveComplete.append_receive_current_assignment` is accepted as
`3c99321d0`: Model-enabled input produces a satisfying assignment through
`currentAsserted`, with frame, request, log, and commit representations.
`receive_append_model_complete` is committed as `c7e57346a`.
It extends the supplied original assignment through the actual action and realizes
a native output representing the enabled Model next state.
Parent inspection, build, and import audit pass in
`native-append-whole-action-complete-parent-build.log` and
`native-append-whole-action-complete-import-tests.log`.
This proves existence of a native output, not yet correspondence to the native
frame chosen by a trace step. Use the shared Model-equivalence transport below
to close that gap. The native relation retains the existing FIFO operations,
but `FrameColumnsRep` observes decoded queues, not physical head equality.
The Complete module is parent-owned.
`receive_append_bootstrap` is committed as `9726e7d53` in
`NativeAppendReceiveExecution.lean`. It composes the actual prefix and writer
preservation proofs. The build passes in `native-append-bootstrap-build.log`.
`NativeAppendReceiveFinalRowTerms.lean` and
`NativeAppendReceiveFinalRowEncoding.lean` are committed as `158d506bb`.
They prove candidate stepdown and conditional local retirement refresh,
preserving candidate log and commit. Inactive scan values remain arbitrary.
The parent inspected the full proof and rebuilt it in
`native-append-final-row-parent-build.log`. The private encoder now uses the
helper; the 110 focused scripts remain byte-identical and the import audit passes.

The private `NativeAllocation.lean` runtime is committed as `2d9001571`.
It writes the existing
row snapshot, then sets allocation to the original allocation bit OR the
requested condition. Snapshot defaults reset hidden fields of newly allocated
nodes. Existing rows survive, and disabled missing nodes remain missing.
It uses 17 definitions per peer. No solver optimization is claimed.
`NativeAllocationFixtureMain` passes 4,416 Model-derived scripts, including
192 SAT cases and ten original-counter errors, in `native-allocation-fixture-tests.log`.
The cases cover all old and added masks, poisoned hidden fields, disabled nodes,
repeated allocation, arbitrary log tails, and every local field plus global and FIFO
mutations. Shared row scenarios remain byte-identical after extraction.
`NativeAllocationEncoding.lean` is committed as `e1afda2f4`.
Single-node and whole-set execution, reference preservation, soundness, and
specific-assignment extension are proved against `NativeArrayAllocation.allocate`.
The reusable masking lemma changes only allocation: hidden rows read fresh
defaults and have no live-entry obligations. It avoids re-proving row stores.
The parent inspected the complete module. Its independent build and import audit
pass in `native-allocation-parent-build.log` and `native-allocation-import-tests.log`.
The runtime, proof, and fixtures are parent-owned.
`NativeArrayChangeConfiguration.change_configuration_output_rep` is committed
as `b7b231fd4`. It accepts a source row through its Model equality rather than
requiring the exact retirement witness tuple. `change_configuration_rep`
reuses that frame proof. The parent build, including dependent membership
guard and row proofs, passes in `native-membership-frame-parent-build.log`.
`NativeNodeRowModelEncoding.lean` is committed as `b04c654dc`.
`NodeRowTerms.Rep.of_model_eq` transports row representations across equal
Model states without equating inactive log tails. The parent inspected and
rebuilt it in `native-node-row-model-parent-build.log`; the import audit passes.
Commit `ccc8c441b` adds `NodeColumnsRep.of_model_eq` and
`FrameColumnsRep.of_model_rep`. Allocation must agree separately from defaulted
local-row values. Frames representing the same Model state can share a columns
representation despite different dead log tails or physical queue heads.
`FrameColumnsRep.valid` derives source-partition validity from represented queues,
so `NativeArrayVote.realize_rep frame rep.valid` supplies a Model input when needed.
The parent builds pass in `native-node-model-transport-build.log` and
`native-frame-model-transport-build.log`; the import audit passes.
`NativeMembershipExecution.lean` is committed as `5a9ceaebe`.
It proves actual run decomposition, prior-Holds, and reference preservation.
The parent inspected the full module and replaced its local preservation helpers
with the shared rules. Its independent build and import audit pass in
`native-membership-execution-parent-build.log` and `native-membership-execution-import-tests.log`.
Offsets are current/previous/added/entries/length at `+0` through `+4`,
local witnesses at `+5` through `+8`, committed current at `+9`,
completed bits at `+10`, and the writer at `+11 + 3 * width`.
The final counter is `before.next + 29 + 20 * width`.
`NativeMembershipExecutionConstraints.lean` is committed as `b3e603131`.
It extracts prefix constraints before frame writes and exposes an actual-run
wrapper using final Holds.
`NativeMembershipSound.lean` is committed as `c6e79e735`.
It derives the previous configuration, added nodes, refreshed row, completed set,
and Model enablement from those constraints. `membership_change_model_sound`
proves whole-action Model soundness from the actual run and final Holds.
The parent build passes in `native-membership-whole-action-sound-build.log`.
`NativeMembershipRetirementAssignment.lean` is committed as `c260f6722`.
It extends the supplied assignment
from `initial.lengthDefined` through `suffix.guardsAsserted`, using canonical
retirement witnesses and Model-enabled membership guards.
Exact SSA bindings come from retained assertions, not live-log representation alone.
The parent inspected the complete proof and rebuilt it in
`native-membership-retirement-assignment-parent-build.log`; the import audit passes.
The file is parent-owned. Worker `a04f39b9-8aa6-4733-9c2c-228d7432032e` is idle.
Keep `NativeMembershipChange.lean` unchanged.
`NativeMembershipLogAssignment.lean` is committed as `8b20d6a5a`.
It constructs an assignment through `initial.lengthDefined` from the original
satisfying frame, deriving previous/added sets and the appended log representation.
The parent inspected the complete proof and rebuilt it in
`native-membership-log-assignment-parent-build.log`; the import audit passes.
Commit `b39691ba8` adds `membership_change_model_complete` and the exact native
`membership_change_complete` wrapper. All four accepted assignment stages compose
with agreement below the original counter. The parent inspected the composition
and built both modules in `native-membership-frame-complete-build.log`.
Both files are parent-owned; worker `af5d19d5-1186-4609-9b0b-4f224d4a4330` is idle.
`NativeMembershipTailAssignment.lean` is committed as `071676cb0`.
It extends from `suffix.guardsAsserted`
through the committed-current witness and completed-retirement loop to
`suffix.writerBefore`.
The parent inspected the complete proof and rebuilt it in
`native-membership-tail-assignment-parent-build.log`; the import audit passes.
Commit `fe88cd8a6` adds `node_row_snapshot_bounded` in
`NativeNodeRowWritesEncoding.lean`. The log and tail assignments reuse its field
bounds instead of unfolding snapshot representation choices themselves.
The parent inspected the diff and rebuilt both callers in
`native-snapshot-bounds-parent-build.log`; the import audit passes.
All three files are parent-owned; worker `2a020198-af17-47bf-b45b-0b82864a50ad` is idle.
`NativeMembershipComplete.membership_finish_assignment` is committed as
`d5e69756d`. It extends a satisfying pre-write assignment through the actual
allocation, source-row, and global writes. It reuses the pre-write Model facts.
The build and import audit pass in `native-membership-finish-assignment-build.log`
and `native-membership-finish-assignment-import-tests.log`.
Commit `9dc1092c0` adds `NativeArrayMembershipTransition.lean` and
`NativeMembershipChangeEncoding.lean`. The exact native membership relation
uses the existing update operation and proves Model correspondence and existence.
`membership_change_frame_success` now proves native-step soundness from actual
encoder assertions, using the shared Model-equivalence transport.
Bootstrap preservation is also proved. Builds pass in
`native-membership-transition-build.log` and `native-membership-frame-sound-build.log`;
the import audit passes. Assignment completeness is complete in `b39691ba8`;
public wiring is now covered by the integration results above.

The public append Model and hint tests reuse the existing 1,344 and 110 cases.
`test_public_model_membership_changes` reuses the existing 1,572 Model cases.
The original failing-first run is in
`native-core-public-failing-first.log`. Canonical minimal receive input still
falls through to the local decoder, reporting `property not found: node`;
see `native-public-receive-decoder-before.log`.
Both action input-error and explorer-core tests now pass publicly.
Membership configuration-set and all 184 five-action sequence cases also pass.
The 21-identity sequence explicitly observes the 18 added inactive identities
as unallocated; this is a trace condition, never an encoder default.
Commit `997954377` adds `Traces/native_append_receive_fifo_conflict.json`,
`Traces/native_membership_allocation_conflict.json`, and
`test_core_explorer_fixture_transitions`. Both contradictions and their corrected
traces pass against the private encoders in `native-core-explorer-fixture-tests.log`.
The public explorer tests will require instruction indices 8 and 9 in each core.
Both now pass with those requirements.

Scalability evidence: a 21-identity core sequence with 18 wholly unobserved
additional nodes ran for more than five minutes with E-matching disabled before
cancellation. Its 2,149,111-byte script is preserved as
`native-core-21-baseline.smt2`; E-matching returned unknown under a 30-second probe.
Adding explicit absence observations for those inactive nodes solved in 3,018 ms.
`native_core_width_probe.py` and `native-core-21-absent-probe/` preserve the
reproducer, input, scripts, and metrics. The two inputs differ; this is not a
representation optimization or evidence that arbitrary initial states solve quickly.
Do not silently assume unobserved nodes are absent. No solver or encoder runtime
was changed to make this test pass.
Worker `a04f39b9-8aa6-4733-9c2c-228d7432032e` is read-only, inventorying the remaining
Model actions and existing reducer observation requirements for the next slice.
`NativeMembershipChange.lean`, `NativeMembershipRowTerms.lean`, and
`NativeMembershipChangeFixtureMain.lean` are committed as `a006368c5`.
The private action composes the proved guards, new log entry, local and global
retirement scans, conditional allocation, source row, and global writes.
Added-peer sent cursors use the old log length.
All 1,572 full Model transitions pass, including 147 SAT cases, in
`native-membership-change-tests.log`. The parent build passes in
`native-membership-change-build.log`. Public membership remains unsupported.
`NativeMembershipRowEncoding.lean` is committed as `b87a7d314`.
It proves the old-length sent-index update and the source row's actual guarded
refresh, reusing row representation record updates rather than repeating fields.
The parent inspected the complete module. Its independent build and import audit
pass in `native-membership-row-parent-build.log` and
`native-membership-row-import-tests.log`. Whole-action correspondence remains pending.

`NativeMembershipWrites.lean` is committed as `d1ae8ef15`.
It extracts allocation, source-row replacement, and both global stores.
All row and bitvector inputs are checked against the original counter before
allocation starts. Its 15 future-ID rejections pass in
`native-membership-write-reference-tests.log`. All 1,572 membership scripts
and 184 combined sequences remain byte-identical after extraction.
`NativeMembershipWritesEncoding.lean` is committed as `06df11eac`.
It proves execution, reference preservation, full-frame soundness, and extension
of the supplied assignment, with exact growth `17 * width + 18`.
The parent removed duplicated row-bound reasoning through
`node_row_definition_values_bounded` and moved SSA preservation lemmas into
`NativeDefinitionsEncoding`. Completeness now follows one direct extension sequence.
The parent inspected the result and rebuilt affected append, allocation, and row
proofs in `native-membership-writes-parent-build.log`; the import audit passes.
Those three proof files and the runtime are parent-owned.
`NativeMembershipFrameEncoding.lean` is committed as `231d237e6`.
It composes write soundness and specific-assignment extension with actual Model
`changeConfiguration`, given the source-row and scan facts.
The parent inspected and rebuilt it in `native-membership-frame-encoding-parent-build.log`;
the import audit passes. Whole-action prefix composition remains unfinished.
`NativeRetirementRefreshAssignment.lean` is committed as `4a7060af2`.
It derives canonical choices from the represented log and assigns the four
consecutive local retirement witnesses while preserving the supplied assignment
and prior assertions. Only the atomic length and entries expressions are transported.
The parent inspected and rebuilt it in `native-retirement-assignment-parent-build.log`;
the import audit passes. Both action prefixes use that witness layout.
`NativeLogSummaryAssignment.lean` is committed as `386a78cc3`.
It supplies canonical single-integer witnesses for configuration, signature,
and NACK scans while preserving the supplied assignment and prior assertions.
The parent inspected the helpers and their semantic equivalences, then rebuilt
the module in `native-log-summary-assignment-parent-build.log`. The import audit passes.
`NativeLogSpliceAssignment.lean` is committed as `28465db0c`.
It extends the supplied assignment with a fresh array built by `spliceRawOutput`,
preserving raw live cells and allowing arbitrary tails. It also preserves prior assertions.
The parent inspected and rebuilt it in `native-log-splice-assignment-parent-build.log`;
the import audit passes.
`membership_guards_output_model_correct` in `NativeMembershipTermsEncoding.lean`
is committed as `a9ff095d0`. It accepts SSA-bound previous-configuration and
refreshed-membership expressions, using the established Model output row
instead of repeating the retirement witnesses.
The parent inspected and rebuilt the proof and guard fixture in
`native-membership-output-guard-parent-build.log`; the import audit passes.
The next dependencies are membership execution from A and append prefix
completeness from AF and B. Append whole-action soundness is complete.
Existing API statements and runtime files remain unchanged.

`NativeArrayCoreActionsFixtureMain` and `NativeCoreActionsFixtureMain` are
committed as `05b512bdc`. They exercise all five prioritized actions in one
private pipeline, with full observations after each step.
The 184 scripts include fresh and existing added nodes, successive configuration
changes, append ACKs and NACKs, term updates, and vote send/receive.
Four complete sequences are SAT. Repeating a configuration and re-adding an
already joined identity fail at the intended membership step.
The final-state mutations cover every local field, allocation, globals, and FIFOs.
`assert_internal_model_traces` shares the comparison runner across private
append, membership, and combined sequences. All four targeted methods pass in
490 seconds in `native-core-sequence-tests.log`.
No public decoder or assurance flag changed.

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
