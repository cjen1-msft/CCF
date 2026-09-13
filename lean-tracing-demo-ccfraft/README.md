# CCFRaft trace validation demo

This directory contains the bounded trace validator and work on a sparse exact
encoder for the CCFRaft Lean model.

## Aim of trace validation

Trace validation checks whether recorded implementation behavior is consistent
with our believed protocol Model, under explicit trace interpretation and
environment assumptions. Its purpose is to expose disagreements and trace them
back to recorded events and implementation code.

The intended encoder proof boundary is:

```text
SMT satisfiable <=> one Model execution satisfies all reduced actions
                   and observations under the stated assumptions
```

This is a target, not a claim that the full encoder is complete. It does not
prove that the reducer faithfully interprets the implementation.

The delivery design keeps raw reduction in Python. Lean owns the Model-level
encoder and SMT emission. Observation-driven specialization belongs in Lean:
the encoder asserts the observation and proves the specialized encoding under
that assertion. The reducer does not need to be implemented in Lean to provide
that premise. Source records, reduction rules, and event boundaries cross the
interface as provenance, not as proof of the reduction's correctness.

UNSAT means the recorded facts, reduction, assumptions, and Model are
inconsistent together. The cause may be an implementation bug, a Model bug,
a reduction bug, or an invalid assumption. UNSAT is not automatically evidence
of a production safety violation. SAT establishes consistency with the Model
for this trace, not correctness of the implementation in general.

Reduction must retain every recorded fact it can interpret faithfully, with
its source location and event boundary. Unsupported or ambiguous records must
produce explicit diagnostics rather than silent omission or repair. Conflicting
constraints should lead back to the relevant trace records and code so that the
cause can be investigated. Unknown, timeout, and validation or encoding errors
are separate outcomes, not SAT or UNSAT.

## Representation design priorities

The bounded representation trades ease of proving correctness against SMT
solver time. Start with the simplest representation whose correspondence to
the Model can be proved directly. The baseline should use native SMT arrays
and explicit live lengths rather than custom finite-point completion machinery.
This is the revised design direction, not a description of the completed code.

Measure that baseline on representative traces before adding optimizations.
If solver time is unacceptable, target the measured bottleneck. More complex
representations and harder preservation proofs are justified only by demonstrated
solver-time improvements. Each optimization must preserve satisfiability in
both directions under the same observations and assumptions. Dropping facts
or restricting possible executions is not a performance optimization.

### Native-array prototype

The public Lean encoder uses `Sparse/NativeFrameEncode.lean` and shares
local-state compilation with `Sparse/NativeEncode.lean`.
It accepts `checkQuorum`, `requestVote`, `requestPreVote`, `updateTerm`, `timeout`,
`becomePreVoteCandidate`, `appendEntries`, `receiveRequestVote`,
`receiveAppendEntries`, `changeConfiguration`, `advanceCommitIndex`, and
`signCommittableMessages`, plus the `allocated`, `role`, `newFollower`, `logLength`,
`commit`, `currentTerm`, `entry`, `retirementIndex`,
`retirementCommittableIndex`, `retiredCommittedIndex`, `votedFor`, and
`votesGranted`, `preVotesGranted`, `membershipState`, `sentIndex`, and `matchIndex`
observations. This covers all local observation kinds.
Both vote-send actions require declared `source` and `destination` identities.
They assert the Model's allocation, role, distinct-peer, and active-membership
guards, then append one packet to the directed FIFO. Sending the same packet
twice appends two copies. A disabled action is UNSAT, not an input error.
`appendEntries` requires declared `source` and `destination` identities and a
natural `batchEnd`. The Model requires
`batchEnd = min(sentIndex[destination] + 1, logLength)`.
The action asserts the Model's send guards, updates the cursor, and enqueues
the packet constructed from the original cursor. Repeated heartbeats remain
separate queue entries. This send frontier does not limit incoming packet size.
`receiveRequestVote` requires a declared `source`, a declared and allocated
`destination`, and a vote request at the selected queue head.
The request must name that destination and have no newer term.
It consumes one request, conditionally updates `votedFor`, and enqueues one
reply. Stale requests receive negative replies. Freshness uses the latest
signature, not the commit frontier. Unallocated senders and self receives
are allowed. A different packet kind makes this action UNSAT.
`receiveAppendEntries` requires declared `source` and `destination` identities,
an allocated destination, and an append request at that queue's head.
The request must name the destination and have no newer term.
A same-term candidate or pre-vote candidate steps down without consuming the
request or replying. Other enabled branches consume the request, send an ACK
or NACK, and refresh retirement metadata. NACKs also refresh that metadata.
`changeConfiguration` requires a declared `source` and a `configuration` list
of declared identities. The list is a set, so order and duplicates do not matter.
The Model rejects empty or unchanged configurations and newly added identities
already in `hasJoined`. The source must be an eligible allocated leader.
The action appends a configuration entry, refreshes retirement metadata, and
allocates newly added identities. New rows start with role `none`, not `follower`.
Other already-allocated nodes retain their local state. The source's sent cursor
for each added identity becomes the old log length.
`advanceCommitIndex` requires a declared `node` that is an allocated leader.
It selects the greatest newer current-term signature acknowledged by strict
majorities of the governing active configurations. It then advances commit
and refreshes the node's retirement metadata and completed-retirement set.
No eligible newer signature, or a refreshed `retiredCommitted` state, makes
the action UNSAT. The old membership state is not a guard.
Logs, queues, peer rows, and other globals remain unchanged.
`signCommittableMessages` requires a declared `node` that is an allocated
leader with a nonempty log. Both its old and refreshed membership must differ
from `retiredCommitted`. The action appends one current-term signature and
refreshes retirement metadata and the completed-retirement set. It preserves
the commit index, including when the old log already ends with a signature.
Commit advancement and signature writing share the same retirement scans,
guards stage, and row writer, with reusable soundness and assignment proofs.
Generic `receive` remains an input error.
`updateTerm` reads the directed queue head without consuming it. It requires an
allocated destination and a strictly newer packet term. Responses also require
an allocated source. It sets follower role, current term, and the new-follower
flag, clears `votedFor` and `preVotesGranted`, and preserves everything else.
Both campaign actions require a declared `node`. `timeout` increments its term,
sets candidate role, records its self-vote, and clears pre-votes.
`becomePreVoteCandidate` sets pre-vote-candidate role and its self pre-vote,
preserving its term, `votedFor`, and granted votes. Both preserve the
new-follower flag, logs, globals, and queues. Their guards enforce the Model's
role, membership, pre-vote status, and campaign-eligibility requirements.
Campaign writes reuse `NativeDefinitionsEncoding` for definition sequences,
fresh identifiers, assertion accumulation, and assignment extension.
This removes per-write execution bookkeeping without changing emitted scripts.
Core action proofs depend on state and initial-domain modules, not the public
instruction compiler. `NativeImportBoundaryTests` enforces that separation so
decoder changes do not rebuild the core action proofs.
All retirement fields accept a natural number or `null`. `votedFor` accepts
a declared identity or `null`. Both vote-set fields accept a list of declared
identities, interpreted as a set. `membershipState` accepts the five Model
membership-state names. Both peer-index fields require a declared `peer` and a natural
`value`. The global `hasJoined` observation accepts a `value` list of declared
identities, interpreted as a set. It does not require a `node` field or imply
that any node is allocated. Global `preVoteStatus` requires a declared `node`
and a `value` of `capable` or `enabled`, independently of allocation.
Global `joined` requires a declared `node` and Boolean `value`. It observes
only that identity's membership in `hasJoined`, without constraining other
identities or requiring allocation.
Global `retirementCompleted` requires a declared `node` and a `value` list of
declared identities. Neither the node nor the listed identities must be allocated.
Global `submittedTxId` requires a natural `txId` and Boolean `value`, indicating
whether that transaction belongs to the submitted set.
`queueLength` requires declared `source` and `destination` identities and a
natural `value`. Each directed pair has an independent length, including self
queues and queues between unallocated nodes. Unobserved queues remain arbitrary.
`queuePoint` adds a natural `index` and a complete packet `value`, using the
[packet fields shared with the reference prototype](#native-term-updates-and-packet-observations).
The index is relative to the live queue head. The packet's source must match
the source partition; its destination need not match the containing queue.
Duplicate packets at different positions remain distinct FIFO elements.
Missing fields, unknown identities, extra fields, and negative numbers are
input errors for `queuePoint`.
`queuePattern` uses the same envelope but accepts a partial packet `value`.
Only the packet's `kind` is required. Omitted packet fields stay unconstrained;
explicit `null`, unknown fields, and fields from another packet family are errors.
Append-request patterns also accept `entriesLength` without requiring `entries`
or `prevLogTerm`. If both `entriesLength` and `entries` are present, both constrain
the packet. An inconsistent pair makes the observation unsatisfiable.
For example, this observation requires one entry without fixing its contents:

```json
{"kind":"queuePattern","source":"a","destination":"b","index":0,
 "value":{"kind":"appendEntriesRequest","entriesLength":1}}
```

For observed lengths up to 32 with omitted entries, the encoder adds a
redundant array equality that copies the existing symbolic cells. It does not
choose entry contents or change packet validity. Larger and unknown lengths
retain the quantified encoding; 32 is not an input limit.

Other instructions are errors.
`native_lean.py` handles JSON input and solver execution. It delegates all SMT
construction to Lean, with no Python encoder fallback.
`native_solver.py` first runs Z3 with E-matching disabled. If Z3 returns
`unknown`, it retries the same script with E-matching enabled.
The retry preserves the first attempt's output in `.mbqi.stdout` and
`.mbqi.stderr` files and records the retry in the final diagnostics.
SAT and UNSAT are accepted only as solver verdicts. A second `unknown` remains
inconclusive, and solver errors are not retried.

```sh
lake build Sparse Sparse.NativeEncodeMain Sparse.NativeSmtFixtureMain
python3 native_lean.py reduced.json --output-dir /tmp/native-lean --z3 /path/to/z3
CCF_NATIVE_ARRAY_TESTS=1 Z3=/path/to/z3 python3 -m unittest discover -s tests -p test_native_lean_smt.py -v
```

The wrapper accepts ordinary JSON and rejects duplicate keys. The internal Lean
stdin interface requires canonical JSON with sorted keys and no interior
whitespace, which also prevents its parser from silently collapsing duplicates.
The output directory retains SMT, solver stdout, and solver stderr.
SAT, UNSAT, unknown, and encoding errors remain distinct outcomes.
The native runner uses Z3 explicitly, without a solver fallback. Lean emits the
unsat-core query alongside the assertion script. Python sends that query only
after UNSAT. Encoding and run artifacts use schema version 2 and identify Z3.
The explorer rejects version 1 artifacts rather than reusing older solver claims.

cvc5 1.3.4 returned incorrect UNSAT for a satisfiable constant-array and
configuration-selector fixture with unqualified pair constructors.
Adding the satisfying current-index equality
changed its answer to SAT, and its own proof checker aborted on the UNSAT result.
Explicit pair sorts remove that small failure. On a qualified large-commit
fixture, cvc5 still returns unknown after 30 seconds while Z3 returns SAT in 10 ms.
Z3 4.16.0 matches all 1,140 Model-derived membership cases.
The cvc5 alternative `--arrays-weak-equiv` rejects model generation and stalls
on large-index cases, so the native runner does not use it.
The older Python reference backend still uses cvc5 and is not the delivery path.

`Sparse/NativeSmt.lean` provides typed terms, scoped binders, native arrays,
arbitrary-width bitvectors, and product and sum datatypes. Symbolic constant-array
expressions remain deliberately absent. The original cvc5 backend rejected that syntax.
`Term.defaultValue` emits a ground literal for a sort's fixed default, including
constant arrays and nested datatypes. It cannot contain free symbols or bound
variables. A fresh array with a symbolic default can instead be constrained with
`forall`.
Sorts and terms now render through explicit S-expression trees.
Pair constructors carry their result sort explicitly, avoiding ambiguous
polymorphic constructor inference in nested packet expressions.
`NativeSyntaxProofs` proves that their emitted text parses back to those trees.
This round trip alone does not prove evaluation or declaration semantics.
`NativeNames` proves unique free-symbol names across recursive sorts and IDs,
separates them from bound names, and proves that a new named binder preserves
older scoped variable reads.
`NativeInterpretation` reads raw expression trees, rejecting wrong sorts and
arities. `NativeLowering.Term.render_eval` proves that parsing and interpreting
every emitted term gives its typed value. This covers operators, named binders,
arrays, bitvectors, products, and sums. It does not cover script commands,
declarations, or the datatype prelude.
`NativeScript` also builds script commands as explicit trees.
`NativeScriptSyntax` proves each command's text round trip and checks that a
declaration's parsed sort agrees with its symbol name. The emitted prelude
is pinned by a kernel proof.
`NativeScriptText` proves the whole emitted script parses to the exact command list,
including the final newline and all named assertions. The reader accepts the
generated one-command-per-line format, not arbitrary SMT-LIB layout.
`NativeReferences` proves that scanning the emitted expression trees finds
exactly the typed terms' free symbols. Every reference has a generated
declaration, and declaration names are unique.
`NativeScriptRun` interprets complete generated scripts. It requires the fixed
prelude, unique declarations before assertions, declared references, Boolean
assertions, and one final `check-sat`. Named wrappers must use the emitter's
indexed names. A false assertion does not hide a malformed later command.
`script_text_holds` equates this interpretation with typed assertion satisfaction.
`NativeSmtFixtureMain` carries kernel-checked expected verdicts for emitted
formulas. `NativeEncodeProofs` covers configuration selectors, bitset decoding,
and allocation-guarded read specialization.

The encoder also carries a proof that every assertion references only symbol
indices below its next fresh index. Definition inputs are checked before that
index advances, preventing self-referential definitions. `fresh_binding_exists`
proves that a fresh equality binding preserves satisfiability of the existing
typed assertions. This covers naming intermediate arrays without expanding
their predecessors into later expressions.
`NativeRenaming` provides capture-free binder insertion for nested array
domains. `Term.weaken_eval` preserves the original value under an added local
variable, including quantifiers and sum-match branches. Free symbols remain
unchanged, so the existing freshness invariant still applies.
`NativeLogValue` prepares finite packet payloads as a length and entry array.
Negative indices and tail cells contain the zero-term signature entry.
Both value round trips are proved, so equality of valid array values is
exactly equality of finite Model lists. This does not change node-log encoding
or add packet instructions to the public compiler yet.
`NativeLogMatch.log_matches_correct` proves exact packet-log observations from
the list length and one equality per supplied entry. The canonical tail domain
connects those finite checks to whole-value equality. This avoids constructing
an SMT constant array for each observed packet. Order and duplicate entries matter.
`NativePacketHeader` supplies the shared term, source, and destination codec.
Terms are natural numbers and identities belong to the declared universe.
Header decoding requires the domain proof; it does not wrap or default invalid
identities. Value round trips and literal equality are proved.
`NativePacketValue` composes that header with seven distinct payload alternatives.
Every Model message has a valid value, and every valid value decodes back
exactly, including append-entry logs. `NativePacketDomain` proves the emitted
payload and full-packet domains and the source selector.
Packet JSON observations are not wired yet.
`NativePacketMatch.packet_matches_correct` proves full packet equality from
the header and tagged payload. AppendEntries uses the finite log matcher.
The solver fixtures include a proved satisfying assignment for every packet
constructor, plus contradictions for changed headers, tags, payloads, and logs.
`NativeQueueScalars` encodes destination-first, source-second head and length arrays.
Each read computes `Int.toNat` from its raw integer cell, emitted as an `ite`.
This removes the need for a universal length domain. Negative raw cells encode
zero, but negative JSON length observations still fail input validation.
The initial-state proof realizes arbitrary lengths with source-correct packets,
without asserting those witness packets in SMT. Every Model frame has a
completeness assignment that stores its natural lengths unchanged.
The original finite-domain encoding took 50.6 seconds on a 21-node observation.
The proved decoded-length encoder takes 9.7 seconds on the same case.
Set `CCF_NATIVE_ARRAY_ARTIFACTS` when running `test_native_lean_smt.py` to retain
scripts, solver output, and per-formula `.metrics.json` files.
`NativeQueuePacket` gives raw packet cells a total internal interpretation.
Valid, source-correct cells retain their packets. Other raw cells represent a
zero-term, self-addressed ProposeVote packet. This is storage interpretation,
not recovery from malformed JSON input.
`NativeQueuePoint.model_queue_complete` proves that encoding and decoding
preserves every source-correct native FIFO, including duplicate packets.
Unobserved packets need not be default packets, and unused cells need no constraints.
`queuePoint` checks the live index and complete packet observation.
Its Boolean matching clauses avoid a datatype-valued conditional when the
observation excludes the default packet. The observation remains asserted.
These queue-point proofs are not yet connected to the public JSON compiler.
`NativeQueueColumns` now connects the complete queue storage to frame
realization and correspondence. `FrameColumnsRep` equates decoded live sequences,
without requiring equality of unused raw cells.

`NativeQuorumEncoding.current_configuration_model_correct` connects the exact
`currentCandidate` and `noLaterConfiguration` clauses used by the compiler to
`currentConfigurationAt`. The proof assumes matching live-log contents, length,
and commit index. It handles all integer scan positions and derives a natural
current-index witness from the asserted domain.
`configuration_guards_exists_correct` additionally covers the other-peer guard
and both existential index assignments without changing represented log state.
`NativeNodeEncoding` connects the shared guard expressions and both step-down
stores to actual Model enabledness and successor state, assuming represented
node columns and a matching Model state.
`NativeValues` proves round trips for node sets and valid entry values.
`NativeInitialEncoding.initial_assertions_model` realizes the initial domain
clauses as represented node columns and a Model state. Its witness supplies
fresh values for currently unobserved fields; the clauses do not require those
values. `model_initial_assertions` proves the converse for arbitrary Model
states, including states with non-fresh unobserved fields.
The JSON decoder now produces typed Model-level instructions and entries.
`NativeObservationEncoding.observation_model_correct` proves that the actual
clauses for the supported observations match the Model, under the
represented columns. Entry observations normalize raw cells to their Model
values, so later observations do not require the initial log-domain premises.
Initial domain assertions remain enforced at trace initialization.
`NativeCompilerEncoding` connects initial domains and observation clauses to
actual state-transformer execution, preserving prior assertions and column
references. It also proves the exact `checkQuorum` witness indices, bindings,
and resulting column versions. A satisfying assignment for that executed block
gives an enabled Model step and represented successor.
`NativeTraceEncoding.compiled_trace_model` composes the executed initial block
and shared typed trace driver into one Model execution. This is the soundness
direction for typed terms. `NativeTraceCompleteness.compiled_trace_iff` proves
both directions for successful typed compilation from the empty initial
assertion list, valid column references, and a matching bootstrap set.
The proof extends fresh assignments without changing earlier assertions,
represented columns, or initial domains. It covers the current `checkQuorum`
and observation subset, not the remaining Model actions or SMT text semantics.

[`NativeScriptTrace`](Sparse/NativeScriptTrace.lean) proves
`NativeEncode.compiled_script_iff`, which composes typed trace equivalence
with whole-script interpretation. Under the
same compilation and initial-state premises, the emitted text has a satisfying
assignment exactly when the supported Model trace has an execution.
The theorem covers named and unnamed scripts. It does not verify the solver.

[`NativeDecoded`](Sparse/NativeDecoded.lean) connects actual JSON compilation
to those premises. `decodeDocument` returns a positive identity width, a
nonempty bootstrap set, and typed instructions. `compileDecoded` uses the
shared initial-state constructor and trace driver.
`encode_document_iff` covers plain output; `encodeDetails_document_iff` covers
the script field returned to the explorer pipeline. Both equate script
satisfiability with `DocumentConsistent`, whose meaning uses the actual
decoder. This does not prove that a raw-event reducer interpreted the
implementation correctly, or verify Lean's JSON parser and IO runtime.

[`NativeFrameDecoded`](Sparse/NativeFrameDecoded.lean) extends this correspondence
to the public encoder, including `hasJoined`, `preVoteStatus`, `retirementCompleted`,
`submittedTxId`, `queueLength`, and exact `queuePoint` packets of all seven kinds.
`encodeFrame_document_iff` and `encodeFrameDetails_document_iff` cover the
actual plain and details outputs. `FrameDocumentConsistent` uses the broader
decoder and Model trace semantics. `NativeFrameColumns` realizes arbitrary
joined sets independently of allocation and bootstrap membership.
`NativeFrameTrace` composes local, global, and queue observations with
quorum, vote-send, vote-receive, append-send, term-update, and campaign steps without restricting
unobserved global state or queues.

This Lean encoder remains experimental. Remaining Model actions, observations,
and raw reducer integration are unfinished. The API's full-model assurance
flag remains false; current coverage is eight actions, sixteen local observation
kinds, all four global observation kinds, queue lengths, and exact packet points.
Partial packet observations remain unsupported.

`NativeLogTerm` constructs canonical packet logs from a ground default array
and one store per supplied entry. `NativePacketTerm` proves that complete
packet literals denote their Model values. Exact queue observations assert
that literal equality and the source partition, without repeating packet-log
domain quantifiers. The default-packet case also permits raw cells that the
total queue decoder maps to that packet. Both cases have correspondence proofs.
The public two-node append/quorum case solves in 58 ms; the 21-node case with
an index near `10^30` solves in 9.8 seconds. Both previously returned `unknown`.

`NativeSignatureEncoding` encodes the latest-signature scan.
Its scoped integer scan has correspondence with `maxCommittableIndex`,
including the zero sentinel, live-index guards, and exclusion of later signatures.
`NativeSignatureFixtureMain` generates 483 cases from actual Model results.
Campaigns are not yet accepted by the public Lean encoder.
`NativeQueuePush` proves that a store at head plus length appends exactly one
decoded packet, preserving duplicates and every other raw cell. This covers
the row update. `NativeQueueStoreEncoding` proves that actual `pushQueue`
execution allocates both column versions and realizes the complete native
network send, while preserving node state, globals, and other directed queues.
Its completeness proof extends any satisfying input assignment without changing
earlier symbols. This internal storage operation is not a public Model action.
`NativeQueueStoreFixtureMain` exercises six interleaved sends in each of 56
solver cases, including duplicates, self queues, huge offsets, and negative
raw head and length values. Five rejection cases cover fresh packet references.
`NativeMembershipEncoding` connects the scoped active-peer guard to
`activeNodeUnion`, including the implicit bootstrap configuration and later
physical configurations. Its witness need not identify a log entry when the
bootstrap branch succeeds. `NativeMembershipFixtureMain` checks 1,140 cases
against actual Model membership, including fixed invalid witnesses and
commit indices beyond the log.

`NativeVotePacket` constructs symbolic request-vote and pre-vote packets.
It takes the maximum of commit and the latest signature index, then reads that
entry's term. Zero and out-of-range indices read zero. The term read follows
the decoder's natural-number conversion, including negative raw cells.
`vote_packet_term_model_correct` connects the emitted packet to the actual Model
constructors under the asserted latest-signature condition.
`NativeVotePacketFixtureMain` generates 5,080 solver cases, including absent
nodes with nonempty raw storage, self-addressed packets, huge indices, and
negated packet equalities.
Current-term observations and outgoing packets read `Columns.currentTerm`.
It initially points to column 5. The matrix also tests a different term column
while deliberately giving the old column a conflicting value.
`NativeVoteGuards` proves enablement and fresh-witness completeness.
`NativeVoteSendEncoding` composes those guards with packet construction and
FIFO storage. Its proofs preserve all node fields, globals, and other queues.
The public compiler accepts both vote-send actions through the same
decoded-document correspondence theorem.

`NativeQueueHeadEncoding` proves reads of the decoded FIFO head, including
clamped raw offsets and invalid packet cells that decode to the default packet.
`NativeTermGuardEncoding` proves the `updateTerm` enabled guard against the Model.
Responses require an allocated source; requests do not. The destination must
be allocated, the queue nonempty, and the selected term strictly newer.
Its 216 solver cases include all packet kinds, stale terms, mismatched packet
destinations, empty queues, and invalid raw storage.
`NativeTermUpdateEncoding` proves all five writes, whole-frame soundness, and
assignment-extension completeness. The public decoded-document theorem includes
term updates. The 168 Model-derived term traces now run through the public
encoder with post-state observations, including the three election fields.
Mutation cases reject incorrect post-state values for every observed field,
and consecutive-update cases distinguish newer, equal, and older terms.
`NativeCampaignMember` bounds eligible configurations by the latest signature.
`NativeCampaignGuardEncoding` proves campaign enablement and fresh-witness
completeness, including the retirement-completed exception. Its 1,200
Model-derived guard cases cover both campaign actions, all roles and membership
states, allocation, pre-vote status, and configuration exclusion.
`NativeCampaignWrites` proves whole-frame write preservation and assignment
extension. `NativeCampaignEncoding` composes those writes with the guards.
Both public campaign actions participate in the decoded-document correspondence
theorem. The public matrix includes 400 complete Model campaign traces and
18 state-mutation and mixed campaign/vote/term-update cases.
Both actions currently emit five stores. Pre-vote writes back three unchanged
values to keep one proof path. This is a baseline, not a solver optimization.

All five prioritized actions are public. Remaining Model actions and partial
packet observations are still needed before raw reducer integration.
`NativeArrayVoteReceive` proves vote-handler and full-frame receive semantics.
`NativeVoteReceiveGuardEncoding` equates the request-specific guard with Model
receive enablement and the fact that the selected packet is a vote request.
It does not claim that every enabled receive is a vote request.
The symbolic reply uses the latest signature for freshness, not the commit
frontier. Its 1,728 solver cases cover grants, refusals, stale and newer terms,
allocation, mismatched recipients, duplicate queues, and raw head offsets.

`NativeArrayAppend` proves that the Model's enabled send frontier produces
zero or one entry. `NativeAppendPacket` uses that fact to construct canonical
packet logs without a quantified copy. `NativeEntryNormalize` re-encodes raw
node-log entries as their decoded Model values. The 2,538 solver cases cover
all entry kinds, arbitrary sent indices, absent nodes, moved term/cursor
columns, and negative raw terms and transaction IDs.
`NativeAppendGuardEncoding` proves exact send enablement and extends an
existing assignment with two membership witnesses. Its 1,216 Model-derived
solver cases include pending configurations, the retirement-completed
exception, invalid frontiers, absent nodes, and self sends.
`NativeAppendSendEncoding` composes these guards with the cursor store and
FIFO enqueue, including full-frame soundness and assignment extension.
Public decoding and both whole-trace proof directions support `appendEntries`.
The public regressions cover 1,200 Model-derived transitions, successive
cursor updates, duplicate heartbeats, input errors, and explorer core attribution.
Sequence cases include 21 declared nodes and append sends followed by a vote
request and term update, preserving the original append packets.

`NativeArrayLogRanges` proves live-range comparisons for arbitrary incoming
payload lengths. The Model's already-done and conflict branches compare terms.
The no-conflict extension branch compares complete entries.
`NativeArrayLogWrite` proves truncation and splice against Model list operations,
without constraining discarded tails. These lemmas supply the log semantics
for the private append receive encoder.
`NativeArrayAppendReceive` adds bounded commit, ACK and NACK correspondence,
and the nonconsuming candidate-stepdown branch. NACK matching reuses
`LogMatchSummary.StorageSummary` and does not assume ordered log terms.
`NativeArrayAppendHandlerCases` proves the complete local handler guards.
`NativeAppendReceiveTermsEncoding` proves their SMT encoding and exact receive
enablement, including packet kind, recipient, allocation, and nonempty FIFO checks.
`NativeArrayAppendNetwork` composes the state and FIFO effects, including
retirement refresh after consuming NACKs. `NativeLogRangeEncoding` and
`NativeLogSpliceEncoding` emit the live-range comparisons and copies.
`NativeRetirementRefreshTerms` emits the scalar retirement results from
canonical scan witnesses. `NativeRetirementRefreshEncoding` connects the combined
scan constraints to Model refresh outputs and extracts canonical witnesses from
arbitrary satisfying integers.
`NativeNodeRowWritesEncoding` proves whole-row replacement and allocation,
including full-frame preservation and extension of a particular prior assignment.
Snapshots use fresh defaults for absent nodes and preserve arbitrary log tails.
The writer checks all input references before allocating its 16 fresh columns.
`test_node_row_writes` exercises 1,584 Model-derived scripts and 60 invalid-reference
cases, including repeated writes through current column references.
`NativeAppendReceiveWritesEncoding` composes row replacement, FIFO pop and
reply, and the completed-retirement update. Its 24 fresh symbols preserve the
original queues and globals on candidate stepdown.
`NativeAppendReceiveResponseEncoding` proves ACK and NACK metadata.
Inactive best-index witnesses remain unconstrained. The NACK hint uses the
last local log term, not the term at the requested previous index.
The `NativeAppendReceive` encoder passes 1,454 Model-derived transition
scripts, including the focused hinted-NACK cases.
`NativeAppendReceiveSound.receive_append_model_sound` proves whole-action soundness:
the actual run and satisfying final assertions imply Model enablement and
representation of the next state, given the original frame and bootstrap representations.
`NativeAppendReceiveComplete.receive_append_model_complete` extends a supplied
satisfying input assignment for an enabled, selected request and realizes the Model
next state. `NativeAppendReceiveEncoding` proves soundness and assignment
completeness for the exact native successor chosen by trace semantics.
Public `receiveAppendEntries` has both whole-trace proof directions.
`Traces/native_append_receive_fifo_conflict.json` attributes a missing reply to
the receive action and the contradictory queue observation in the explorer.
`NativeNodeRowModelEncoding` shares row and whole-frame representation transport
across equal Model states. Allocation remains explicit. Inactive log tails and
physical queue heads need not agree because the representation observes live logs
and decoded FIFOs.
`NativeLogSummaryEncoding` proves bounded signatures, committed configuration
indices and members, and NACK matches for explicit candidate logs.
All three scans reuse `NativeMaxMatchEncoding`, with zero for no match.
Their proofs extract valid natural indices from arbitrary satisfying SMT integers.
`NativeRetirementCompletedEncoding` composes current-configuration and
committed-prefix scans into the exact Model completed-retirement bitvector.
It also constructs canonical witnesses satisfying all scan and bit constraints.
`NativeRetirementCompletedConstraintsEncoding` proves execution of the fresh-symbol
loop and extension of a specific assignment for enabled and disabled scans.
The loop checks inputs against its original counter and uses `1 + 3 * width`
fresh symbols. Its 240 solver cases include ignored tails and invalid witnesses.
`NativeQueuePopEncoding` proves directed FIFO removal and full-frame
assignment extension. Empty removal is total internally; receive guards
separately require a packet. The queue fixtures cover repeated pop/push,
duplicates, self queues, negative raw scalars, and large head offsets.
`NativeVoteReceiveWritesEncoding` composes the conditional vote update, FIFO
pop, and reply with full-frame correspondence and assignment extension.
Its 192 Model-derived transition cases include existing duplicate replies,
stale requests, unallocated senders, and self receives.
`NativeVoteReceiveEncoding` composes the guard, signature witness, and writes.
Public `receiveRequestVote` has both whole-trace proof directions.
Its 480 Model-derived cases include generic receives enabled for the wrong
packet kind, which the vote-specific action rejects. Sequence cases cover
duplicate replies and stale requests after `updateTerm`.

The `NativeMembershipChange` encoder passes 1,572 Model-derived
transition scripts, including 147 SAT cases. It appends the configuration,
refreshes retirement, allocates newly added identities, and sets their sent
cursors to the old log length. `NativeMembershipTermsEncoding` proves the
guards, and `NativeMembershipRowEncoding` proves the source-row terms.
`NativeMembershipSound.membership_change_model_sound` proves Model enablement
and next-state representation from the actual run and satisfying final assertions.
`NativeMembershipChangeEncoding` connects that result to the exact native
membership transition. `NativeMembershipComplete.membership_change_model_complete`
composes all assignment stages. `NativeMembershipChangeEncoding` then realizes
the particular native successor required by a trace, preserving the supplied
assignment below its original counter. Public `changeConfiguration` has both
whole-trace proof directions. `Traces/native_membership_allocation_conflict.json`
attributes a missing allocation to the membership action and its post-state observation.
`NativeAllocation` reuses row snapshots to reset hidden fields before exposing
missing nodes. Existing rows survive. The baseline uses 17 definitions per
declared identity and passes 4,416 Model-derived scripts, including repeated
allocation, disabled conditions, and full-frame mutations.
`NativeAllocationEncoding` proves single-node and whole-set soundness,
reference preservation, and extension of each starting assignment.
The public combined pipeline covers all five prioritized actions in
184 sequence scripts. These include successive configurations, append ACKs and
NACKs, term updates, and vote send/receive, with full observations after each step.
The 21-identity sequence observes its 18 inactive extra nodes as unallocated.
Leaving their allocation unobserved made solving exceed five minutes; adding
those observations solved in about three seconds. These are different traces,
not an encoder optimization. Unobserved initial state remains arbitrary.

`NativeOptional` supplies codecs for optional local-state observations.
Optional natural indices and node identities use `NativeSum NativeUnit Int`.
Invalid payloads fail decoding rather than becoming `none` or wrapping to
another identity. The module proves round trips, exact literal equality,
and emitted domain predicates. All retirement fields are wired through initial
state realization, observation compilation, and the JSON-to-script theorem.
Their values are not bounded by the log length. Observing `null` does not imply
that the node is allocated, but a non-null value requires an allocated node.
`votedFor` uses the same optional-value proofs with a finite-identity domain.
The target identity need not be allocated or belong to the bootstrap configuration.
Both vote sets use one bit per declared identity. Duplicate names and list
order do not change the set. An absent node reads an empty set, and recorded
voters need not be allocated or belong to the bootstrap configuration.
The two sets remain independent through `checkQuorum`.
Membership states share the existing finite enum mapping in `Shared/Membership.lean`.
An absent node reads `active`. Membership observations do not infer retirement
indices or bootstrap reachability.
Both peer-index fields use nested arrays indexed by node and peer. Their
natural-number domains cover only declared peers. Other cells are ignored, not forced to zero.
An absent source node reads zero, but the peer need not be allocated.
Indices can exceed the source log length.
`instruction_has_encoding` proves that every typed local instruction is either
`checkQuorum` or has an observation encoding. The solver suite includes a single
trace that observes every local field before and after quorum.
`NativeNatSet` encodes the submitted-transaction set as one-bit array cells and
an unknown finite limit. Membership requires a nonnegative index below the
limit and a cell containing one. Raw negative and tail cells are unconstrained;
decoding ignores them. The proofs establish exact membership and representation
of every finite natural-number set. Observed
transaction IDs do not bound the set, and missing IDs do not imply absence.
The original Boolean-cell representation returned `unknown` for a mixed-global
SAT case. Equivalent one-bit cells solved that case without weakening its
constraints. The solver suite retains that regression, including single-node
and 21-node variants.
The later universal zero-tail constraint made Z3 return `unknown` on an unrelated
append-packet observation. Extent-guarded membership removes that quantifier
without changing the decoded Model sets. Kernel-backed cases force raw tail
cells to one while proving that membership remains false.
`Encoding` now inherits its mutable column references from `Columns`.
Compiler frame proofs preserve that whole record, and the quorum result
specifies a record update for the two changed fields.
`NodeColumnsRep` and `observationClauses` take the same record. Trace proofs
carry the current record; initial realization uses the default record.
Allocation, log length, commit, and log entries now have current references too.
Their initial IDs remain 0, 3, 4, and 6, with the next-symbol counter at 24.
Existing public actions preserve those four references. The relocation
regression moves every column and fresh symbol together, then compares the
emitted clauses for each public action, observations, and a mixed history.
`TypedDocument`, `decodeDocumentWith`, and `compileInstructionsWith` share
identity validation, bootstrap decoding, indexed errors, and clause groups
between instruction families. The local encoder uses these same functions.
`preVoteStatus` uses an unguarded Boolean array. `NativeValues.pre_vote_bit_eq`
proves exact equality for its two Model values. Initial representation permits
both values for every identity, including absent nodes and identities outside
the bootstrap set. The global field and its distinct rows remain independent
of local fields and `hasJoined` through quorum steps.
`retirementCompleted` uses a node-indexed bitvector array with the same set
semantics as `hasJoined`. Each row can differ. These global sets do not imply
local retirement indices, membership states, or a joined-node history.

The older Python reference remains separate:
`native_arrays.py` accepts `checkQuorum`, `requestVote`, `requestPreVote`, and
`updateTerm`, plus `timeout` and `becomePreVoteCandidate`.
Node observations cover allocation and every local `NodeState` field.
Logs use length and exact live-entry observations. Source-local queues support
length and exact packet observations. Other instructions are errors.
It does not replace the full validator or consume raw CCF traces.

`Sparse/NativeArrayVote.lean` proves that the combined direct-array trace semantics
admit a state exactly when the same observations and actual Model actions admit
a Model execution. The initial state is arbitrary. The proof covers any finite
node type and leaves unobserved state unrestricted. The JSON adapter and
SMT-LIB printer are outside this theorem.

The input declares an exhaustive identity universe and a nonempty bootstrap
configuration. Its size is not fixed at 15. Every identity in an instruction or
entry payload must belong to that universe. Transaction IDs are natural numbers.
Entry observation indices are zero-based.

```json
{
  "nodes": ["a", "b"],
  "bootstrap": ["a", "b"],
  "instructions": [
    {"kind": "logLength", "node": "a", "value": 1000000},
    {"kind": "checkQuorum", "node": "a"},
    {"kind": "role", "node": "a", "value": "follower"}
  ]
}
```

An `entry` observation additionally has an `index` and a value such as
`{"term": 1, "content": {"reconfiguration": ["a", "b"]}}`. Other contents are
`"signature"`, `{"transaction": 7}`, and `{"retiredCommitted": ["a"]}`.
Other basic node observation kinds are `allocated`, `newFollower`, `commit`,
and `currentTerm`.
Role values use the Model names `none`, `follower`, `preVoteCandidate`,
`candidate`, and `leader`.

```bash
python3 native_arrays.py trace.json --output-dir native-output --cvc5 /path/to/cvc5
```

The command writes `trace.smt2`, solver stdout, and solver stderr to the output
directory, then prints JSON containing `status` and `solver_ms`. Clauses named
`event_I_J` refer to zero-based instruction `I`. Input and solver failures exit
with an error. `unknown` remains a separate solver status.

The emitter keeps named node-array versions and total Entry arrays with live
lengths. It never enumerates symbolic log positions. Tail entries are irrelevant,
and later observations constrain the same initial arrays. The prototype does
not yet provide an initial-state materialization command.

The solver uses `--arrays-exp --mbqi`. cvc5 1.3.4 returned `unknown` without these
options on the million-entry probe. With them, the initial run solved its
trillion-entry SAT case in about 16 ms. A synthetic trace with 400 records and
200 nodes took about 2.9 seconds, with about 3 ms spent encoding. Solver times
include process startup. These are not representative full-action trace benchmarks.

```bash
nice -n 10 lake build Sparse.NativeArrayCheckQuorumFixtureMain
CCF_NATIVE_ARRAY_TESTS=1 CVC5=/path/to/cvc5 \
  python3 -m unittest discover -s tests -p test_native_arrays.py -v
```

The fixture computes 150 expected verdicts from actual `CCFRaft.Enabled` guards.
Additional cases cover state framing, contradictory later observations, absent
defaults, live-tail separation, 21 identities, symbolic logs, and explicit input
rejection. `CCF_NATIVE_ARRAY_ARTIFACTS=/path/to/output` retains the emitted
formulas, solver output, and `measurements.json` for comparison.

### Native explorer API

`explorer_api.py` exposes one completed `native_lean.py` run as read-only JSON.
It does not use the older checked-backend explorer or claim full encoder proof.
Lean emits named clauses and half-open clause ranges for each instruction.
The initial-domain group has no instruction owner.

#### Run the API

```sh
lake build Sparse.NativeEncodeMain
python3 native_lean.py Traces/native_quorum_conflict.json --output-dir /tmp/native-explorer --z3 /path/to/z3
python3 explorer_api.py /tmp/native-explorer --port 8091
```

The example is synthetic reduced input, not a captured implementation trace.
It deliberately observes a leader after `checkQuorum` steps that node down, so
the result is UNSAT.
`Traces/native_vote_fifo_conflict.json` is another synthetic UNSAT example.
It sends the same vote packet twice into an empty queue, then claims length one.
The explorer core links the contradiction to both sends and the final observation.

The server binds only to `127.0.0.1`. For remote access, forward the port through
SSH. It reads a fixed snapshot at startup; restart it to inspect a newer run.

```sh
curl http://127.0.0.1:8091/api/run
curl 'http://127.0.0.1:8091/api/instructions?offset=0&limit=20'
curl http://127.0.0.1:8091/api/core
```

#### HTTP endpoints

| GET endpoint | Response |
| --- | --- |
| `/api/run` | Solver outcome, proof status, identity universe, counts, and endpoint links |
| `/api/input` | Exact reduced Model input |
| `/api/instructions?offset=0&limit=50` | Ordered instruction page and core membership |
| `/api/instructions/{index}` | One instruction and all of its emitted constraints |
| `/api/constraints/{name}` | One named constraint, its instruction owner, and core membership |
| `/api/core` | Solver-reported core and affected instruction indices |

`HEAD` returns the same headers without a body. Invalid parameters return 400,
missing items return 404, and writes return 405. Page limits range from 1 to 200.
The API has no solver-execution or filesystem-selection endpoint.

Native runs retain `input.json`, `encoding.json`, `trace.smt2`, solver stdout and
stderr, and a final `result.json` manifest. The loader rejects mixed or changed
artifacts, mismatched inputs, malformed clause ownership, unknown core labels,
and unsupported proof claims. Hashes check consistency, not authenticity; local
run artifacts remain trusted inputs.

SAT, UNSAT, and unknown remain distinct. The core is not minimized and is not a
replayable instruction subsequence. The API currently exposes reduced-input
provenance only; raw-event/code links depend on the unfinished reducer integration.

### Native local node state

The local representation covers all 14 fields of `Model.NodeState`.
`Local.Rep` requires equality of the complete decoded record, rather than
selected field equalities. The existing action proofs therefore preserve
every local field or account for its update.

Additional observations use the usual `kind`, `node`, and `value` fields:

| Kind | Value |
| --- | --- |
| `sentIndex`, `matchIndex` | A natural number. Also requires a `peer` identity. |
| `votedFor` | A declared identity or `null`. |
| `votesGranted`, `preVotesGranted` | A list of declared identities, interpreted as a set. |
| `membershipState` | `active`, `retirementOrdered`, `retirementSigned`, `retirementCompleted`, or `retiredCommitted`. |
| `retirementIndex`, `retirementCommittableIndex`, `retiredCommittedIndex` | A natural number or `null`. Zero and `null` are distinct. |

For example, `{"kind": "sentIndex", "node": "a", "peer": "b", "value": 99}`
observes one cell in a peer-index table. Peer indices need not fit within the
log. Votes may name unallocated identities. Retirement metadata need not
describe a reachable state. The prototype does not assume those invariants.

Absent nodes return the complete `freshNodeState`, including zero peer indices,
empty vote sets, no chosen voter, active membership, and absent retirement indices.
`updateTerm` clears `votedFor` and `preVotesGranted`, but preserves `votesGranted`.
`checkQuorum` preserves all three election fields.

Each field's initial array and domain constraints are declared on first read
or write. Later observations use the same initial column and intervening
stores. No observation creates a replacement initial state. This avoids
constraining unused peer tables while retaining their full natural-number
domains when used.

```bash
nice -n 10 lake build Sparse Sparse.NativeArrayNodeFixtureMain
CCF_NATIVE_ARRAY_TESTS=1 CVC5=/path/to/cvc5 \
  python3 -m unittest discover -s tests -p 'test_native*arrays.py' -v
```

The node fixture derives 540 cases from complete Model records before and
after the six supported actions. It covers all membership states, absent
nodes, optional values, nonempty vote sets, and peer indices beyond log length.
Declaring unused peer-table domains raised the 400-record combined benchmark
to 10.4 seconds. First-use declarations reduced it to 1.13 seconds, with about
3.9 ms spent encoding.
Global fields use the separate observations below.

### Native global state

Global observations share the same initial state and ordered execution as
node and queue observations:

| Kind | Fields besides `kind` |
| --- | --- |
| `hasJoined` | `value`: a set of declared node identities. |
| `preVoteStatus` | `node`, `value`: `capable` or `enabled`. |
| `retirementCompleted` | `node`, `value`: a set of declared node identities. |
| `submittedTxId` | `txId`: a natural number, `value`: a Boolean membership observation. |

For example, `{"kind": "submittedTxId", "txId": 1000000000000, "value": true}`
requires that transaction ID to have been submitted. Transaction IDs do not
need an exhaustive declared universe.

Global fields do not use absent-node defaults. An unallocated identity can
have enabled pre-votes, appear in join history, or have recorded completed
retirements. All six actions in the Python reference preserve global fields.
The public Lean encoder supports `checkQuorum`, `requestVote`, `requestPreVote`,
`updateTerm`, `timeout`, and `becomePreVoteCandidate`.

The Python reference uses Boolean cells for submitted transactions. The public
Lean encoder uses one-bit cells. Both have a symbolic natural upper bound.
Cells outside the finite nonnegative prefix denote absence. The bound is unknown,
not a cap supplied by the trace. `Sparse/NativeArrayNatSet.lean` proves that
this represents every finite set of natural-number IDs. The emitter does not
enumerate the prefix, even when an observed ID is a trillion.

`NativeArrayVote.exists_submitted_array_iff` connects that array's decoded set
to the same initial Model state as the remaining fields. That theorem excludes
JSON and SMT printing; `NativeFrameDecoded` covers the actual Lean compiler.
The Python reference's complete-state fixture includes
global observations before and after all six actions, including unallocated
identities and trillion-valued transaction IDs.

### Native election starts

`{"kind": "timeout", "node": "a"}` starts an ordinary election when pre-voting
is not enabled. It increments the term, changes the role to `candidate`,
sets `votedFor` to the node, replaces `votesGranted` with the self vote,
and clears `preVotesGranted`.

`{"kind": "becomePreVoteCandidate", "node": "a"}` requires enabled pre-voting.
It changes the role to `preVoteCandidate` and replaces `preVotesGranted` with
the self pre-vote. It preserves the term and ordinary vote fields.

Both actions require an allocated follower, candidate, or pre-vote candidate,
with membership other than `retiredCommitted`. The node must belong to an
active configuration no later than the last signature, or appear in its own
completed-retirement set. An active configuration after the last signature
does not authorize campaigning by itself.

The shared execution theorem includes both actions and their complete state
effects. Current-configuration and signature summaries are reused while their
input versions remain unchanged. `NativeArrayVoteFixtureMain` generates 400
Model-derived election-start cases with its `campaign` argument:

```bash
nice -n 10 lake build Sparse.NativeArrayVoteFixtureMain
lake env lean --run Sparse/NativeArrayVoteFixtureMain.lean campaign
CCF_NATIVE_ARRAY_TESTS=1 CVC5=/path/to/cvc5 \
  python3 -m unittest discover -s tests -p test_native_arrays.py -v
```

The initial 400-record repeated-timeout benchmark took about 4.5 ms to encode
and 2.45 seconds to solve. Pre-vote majority promotion through `becomeCandidate`
and promotion through `becomeLeader` are not yet supported.

### Native vote sends

Vote sends append to the queue selected by source and destination. They require
allocated endpoints, distinct identities, the matching candidate role, and
destination membership in the source's active configuration union. Both actions
leave node state unchanged. Equal sends occupy distinct queue positions.

```json
{
  "nodes": ["a", "b"],
  "bootstrap": ["a", "b"],
  "instructions": [
    {"kind": "role", "node": "a", "value": "candidate"},
    {"kind": "logLength", "node": "a", "value": 0},
    {"kind": "currentTerm", "node": "a", "value": 4},
    {"kind": "commit", "node": "a", "value": 0},
    {"kind": "queueLength", "source": "a", "destination": "b", "value": 0},
    {"kind": "requestVote", "source": "a", "destination": "b"},
    {"kind": "queuePoint", "source": "a", "destination": "b", "index": 0,
     "value": {"kind": "requestVoteRequest", "term": 4,
               "lastCommittableTerm": 0, "lastCommittableIndex": 0,
               "source": "a", "destination": "b"}}
  ]
}
```

For pre-votes, use role `preVoteCandidate` and action and packet kind
`requestPreVote`. Queue point indices are zero-based offsets from the live head.
The packet's last committable index is the maximum of the commit index and
the last signature index. Its term is zero if that index is zero or outside
the live log. Arbitrary initial state does not imply monotone log terms or
a commit index bounded by log length.

Initial queues remain arbitrary. All seven Model packet variants are available
to the solver and to explicit observations. Each live packet's source must match
its source partition.
A packet's destination need not match its containing queue, as the Model permits
malformed initial queues. Initial packet and entry tails remain irrelevant.

`NativeArrayVote.exists_iff` covers one initial Model state for the entire
combined node-and-queue trace. The theorem does not cover the Python adapter
or SMT printer. Configuration and signature readers share a scalar summary
only while their state-version keys match.

```bash
nice -n 10 lake build Sparse Sparse.NativeArrayVoteFixtureMain
CCF_NATIVE_ARRAY_TESTS=1 CVC5=/path/to/cvc5 \
  python3 -m unittest discover -s tests -p 'test_native*arrays.py' -v
```

The vote fixture derives 400 verdicts and packet snapshots from actual Model
functions. It covers both send actions, current and pending configurations,
signature and commit frontiers, nonmonotone terms, and initial duplicates.
Additional cases cover every initial packet variant's numeric domains,
late observations, malformed destinations, source isolation, and 21 identities.
The first combined trillion-entry log and trillion-message queue case took
about 39 ms to solve. A synthetic 400-record vote trace took about 3 ms to encode
and 2.24 seconds to solve. These are not full-action trace benchmarks.

### Native term updates and packet observations

`{"kind": "updateTerm", "source": "a", "destination": "b"}` reads the first
live packet from `a` in `b`'s queue. The destination must be allocated and its
current term must be lower than the packet term. Responses require an allocated
source. Requests, including vote proposals, do not.

The action leaves the packet queued. It changes the destination's current term
to the packet term, sets its role to `follower`, and sets `newFollower` to true.
Other nodes, logs, commit indices, and queues remain unchanged. Repeating the
action on the same packet fails its strict term guard.

Like `CCFRaft.newerMessage?`, this action does not validate the packet's
destination field. Receive handles that separately. Term updates are not a
replacement for receive, which is not yet supported by this prototype.
The shared `NativeArrayVote.exists_iff` theorem includes term updates in the
same execution as vote sends and observations.

Every `queuePoint` packet has `kind`, `term`, `source`, and `destination`.
Additional fields use these exact Model names:

| Packet kind | Additional fields |
| --- | --- |
| `appendEntriesRequest` | `prevLogIndex`, `prevLogTerm`, `entries`, `leaderCommit` |
| `appendEntriesResponse` | `success`, `lastLogIndex` |
| `requestVoteRequest` | `lastCommittableTerm`, `lastCommittableIndex` |
| `requestPreVote` | `lastCommittableTerm`, `lastCommittableIndex` |
| `requestVoteResponse` | `voteGranted` |
| `requestPreVoteResponse` | `voteGranted` |
| `proposeVoteRequest` | None |

`success` and `voteGranted` are Booleans. Numeric fields are natural numbers.
`entries` is an explicit list of entry values in the same format as log
observations. The emitter derives its length. Do not supply `entriesLength`.
Only listed payload entries are constrained. Array tails remain irrelevant,
including across repeated observations of one packet.

```bash
nice -n 10 lake build Sparse Sparse.NativeArrayTermFixtureMain
CCF_NATIVE_ARRAY_TESTS=1 CVC5=/path/to/cvc5 \
  python3 -m unittest discover -s tests -p 'test_native*arrays.py' -v
```

The term fixture derives 168 cases from actual `Enabled` and `next`, across
all packet kinds, endpoint allocation, term comparisons, and malformed
destinations. Other cases cover exact payloads, retained duplicate packets,
source-head selection, and contradictory later observations.
A 400-record trace combining vote sends and term updates across 100 identities
took about 3.7 ms to encode and 1.21 seconds to solve in the initial run.
The adapter and printer remain outside the Lean theorem.

### FIFO Model sends

`CCFRaft.enqueue` appends every successful send, including messages equal to
pending messages. This replaces the old `enqueueNoDup` behavior. The
source-local queue correspondence in `Sparse/Queue.lean` now preserves
duplicates too. Receiving removes the first message from the selected source.
It does not remove other equal messages.

This models successful FIFO emission. It does not model connection-establishment
buffer replacement, failed sends, or arbitrary network loss and reordering.
A raw send-attempt record still does not establish that a send succeeded.

The older guarded AppendEntries encoder no longer branches on packet equality.
Its mapping theorem holds even when two distinct symbolic packets decode to
equal packets. Queue-length expressions count every send and reply.
The generic `Shared` no-duplicate container helpers remain separate utilities,
not the Model's send operation.

```bash
nice -n 10 lake build Sparse MachineGenerated.FifoNetworkTests \
  MachineGenerated.GuardedAppendEntriesTests MachineGenerated.TraceEncodingProofs
```

`FifoNetworkTests` checks repeated sends, unaffected destinations, and an actual
execution that consumes two equal heartbeats and retains both equal replies.
The full default build has separate retirement-invariant proof failures in
`MachineGenerated/ReconfigurationPreservation.lean`. Those failures reproduce
on the preceding commit `45f1acbc8`, before the FIFO correction.

### Native FIFO storage

`Sparse/NativeArrayQueue.lean` represents a queue with a total message array,
a head index, and a live length. Enqueue stores at `head + length`. Dequeue
requires a matching live head and advances the head index. Neither operation
copies the queue or scans existing messages for equality.

The module proves ordered send, receive, length, and point observations
equivalent to finite-list execution from one arbitrary initial queue. Its
source-local network operations correspond to `CCFRaft.enqueue` and
`takeFirstFrom`. Initial-network realization requires every live message's
source to match its source partition.

`native_queue_arrays.QueueArray` emits these storage commands for a
caller-supplied SMT element sort. It accepts trusted generated SMT terms,
not raw trace input. The vote-send prototype integrates packet sorts and the
two vote-send guards. The printer remains outside the Lean theorem.

Named array versions retain earlier boundaries. Later observations can
constrain and materialize values in the original queue. Cells before the live
head and after the live end remain irrelevant. The readback regression queries
the original array after a receive and a later point observation.

```bash
nice -n 10 lake build Sparse.NativeArrayQueue
CCF_NATIVE_ARRAY_TESTS=1 CVC5=/path/to/cvc5 \
  python3 -m unittest discover -s tests -p test_native_queue_arrays.py -v
```

The suite runs 208 solver cases, including 196 finite-oracle combinations,
symbolic message aliases, source isolation, live bounds, and delayed readback.
The initial 400-operation run took about 0.6 ms to encode and 2.8 seconds to
solve. A trillion-element symbolic queue used 563 bytes of SMT and solved in
about 7 ms. These are storage-only measurements, not full-trace performance.
`CCF_NATIVE_ARRAY_ARTIFACTS` retains scripts and `queue-measurements.json`.

## Sparse proof foundation

`Sparse/` contains the reviewed semantic proofs for sparse logs, source-local
queues, integer and packet representations, and finite log summaries.
The entry point `Sparse.lean` imports their transitive axiom audits.

```bash
python3 export_sparse_proofs.py --check
nice -n 10 lake build Sparse
```

These commands use repository files and the pinned Lake dependencies. They do
not need the original session artifacts. `Sparse/provenance.json` records the
source hashes and proof-body hashes. The exporter changes namespaces and removes
diagnostic printing and the historical session command log.
The manifest retains original hashes when a proof is revised. Its explicit
`revision` record supplies a reason and the maintained proof hash. The FIFO
queue proof is such a revision, not a namespace-only copy of its old source.

New bridge modules add aligned multi-version interval completion, finite
membership traces, projection-backed readback hints, and typed scalar SMT terms.
They are ordinary repository source, separate from the exported snapshots.
`QueueReadback` connects finite equations to a whole queue execution under an
explicit plan and demand-closure invariant.
`QueuePlan.generated_exists_iff` constructs that plan and its closed demands.
For unconditional queue events, its finite constraints hold iff one concrete
queue of the supplied length executes the entire trace.
The theorem requires tracked-key coverage and a fresh filler value.
`QueuePresence` removes known-present sends while preserving the same initial
queue, even when distinct symbolic keys alias. `QueueObservationBounds` derives
initial-length bounds from source-local observations without assuming emptiness.
`MonotoneIntervals` adds monotone, term-bounded single-log completion. It does
not construct a full safety-invariant state.
`IntervalDemandPlan.plan` computes dependency closure with a flattened table
and a visited worklist. Use it instead of `IntervalReadback`'s recursive
reference constructor, which can repeat shared ancestors exponentially.
`IntervalQueries` composes demanded reads and finite-cut predicates into one
root-array witness. Its request list can still grow as cuts times references.
`IntervalPredicate` supplies typed Int comparisons and removes duplicate cut
IDs and version references before constructing their request product.
`IntervalEncoding` emits symbolic point-read constraints over Int-valued arrays.
Its rendered script is satisfiable iff one root-array family satisfies all
observations under the input formula and explicit nonnegative index constraints.
`IntervalQueryEncoding` emits guarded universal Int predicates with one shared
root-array witness and an exact rendered-text existence theorem.
`JointIntervalCompletion` proves joint completion with exact point preservation
on those same roots. `JointIntervalEncoding` emits both point observations and
universal queries with one root family and an exact rendered-text existence
theorem.
`TypedIntervalEncoding` now emits point constraints for all five SMT sorts,
including Entry-valued arrays. Constants and expectations use one original
assignment, and all points share one root family.
`EntryPredicate` supplies typed Entry comparisons, generated version references,
and locality proofs for the generic query interface. Raw signed-code ordering
and decoded natural ordering are explicit, separate choices.
Cell-local Content tests, payload selectors, mask operations, cardinality,
and configuration majority share those proofs. Filters take fifteen fixed
external conditions. Query bodies still have no scan-position operand.
`TypedIntervalReadBlock` accepts arbitrary root/version requests without point
expectations. Its flat equations preserve every planned read in one root family,
with explicit domains and caller-supplied symbol reservations.
`TypedGraphAddress` resolves root or version addresses to version IDs on the
same graph roots. It reuses a root alias or appends one, preserving all old
values, endpoint metadata, and source symbols. Prepare addresses before building
version-typed queries; this adapter does not reindex existing queries.
`TypedJointPredicateEncoding` emits Entry points and universal predicates
against one root family, with a formula and rendered-text existence iff.
It retains every point equality and checks each universal at point cuts.
Its `Witness` encoder adds guarded local existential clauses, including bounded
mismatch. Referenced witnesses add cuts to every universal, and one completion
preserves all witnesses and points. Empty clause lists retain the old scripts.
`TypedJointContext` preserves that entire caller context when a reader installs
a fresh Int scalar block. Input, graph metadata, points, universal queries, and
existential clauses retain the same meaning on the same root family.
`LogMatchEncoding` reuses this proof without changing its emitted scripts.
`EntryValue` supplies a fixed entry domain with signed integer scalars and
node-set bitvectors, bijective with Model entries. `Smt` now supports native
unknowns, equality, conditionals, and unary functions for nodes, content, and
entries. `NativeConstructors` adds exact 15-bit literals, all Content constructors,
Entry construction, and total Entry term/content projections. `NativeSelectors`
adds structured Content testers and total payload selectors.
`EntrySelectorSemantics` proves guarded payload reads independent of arbitrary
wrong-constructor selector values, without hiding failures in unused branches.
The SMT evaluator and text layer now use one shared, arbitrary selector
interpretation. Matching-guard builders reuse those laws.
`NativeNodeOperations` adds fixed-width AND, OR, complement, and static node
membership, with exact correspondence to Model node sets and rendered text.
`NativeNodeSets` derives set operations, mathematical cardinality, filtering,
and the actual single-configuration majority predicate. Empty configurations
and ties fail; supporters outside the configuration do not count.
Active-configuration scans and full quorum integration remain separate work.
`PacketIdentity` characterizes complete packet equality by tagged headers,
payload lengths, and bounded entry reads. It proves finite key-class
injectivity from both identity directions. `PacketRealization` constructs one
unique complete packet family from valid flat descriptors and shared Entry
reads. Graph consistency and emitted packet constraints remain separate work.
`FiniteQueueTransport` proves whole-queue transport using only an equivalence
between finite tracked supports and fresh fillers. Untracked values can collapse
to one filler without losing queue positions or initial multiplicities.
`PacketQueueWitness` derives those supports and fillers from complete
source-local packets. Exact key equality is still a required premise, not
an emitted packet constraint.
`ConfigurationSnapshot` characterizes complete positive-index Model snapshots
with finite frontier queries. Raw callback-phase mapping is still separate.
`ConfigurationReaderEncoding` emits two scalar bindings and two content-only
queries for the actual current configuration at a clipped log frontier.
Its same-assignment theorem uses one supplied root family. Physical empty
configurations and positive-index copies of the bootstrap mask remain distinct.
Entry terms do not affect this reader. Caller-context composition is separate.
`ConfigurationPublication` is a separate local candidate for one successful
leader callback. It preserves one linked begin/send/close chain but does not
change the Model or raw validator.
`ModelTrace` defines the unbounded target contract using the actual 17 Model
actions. One arbitrary initial state and one shared Nat assignment satisfy the
entire ordered trace. Queue partition congruence preserves its observations,
including destination totals and active configuration snapshots. Its input
functions are semantic parameters, not a decoder or finite SMT input syntax.
`ModelInputSyntax` adds closed finite syntax for every action and observation.
Nat fields use literals or declared unknown slots. Bool fields can test those
same Nat slots for zero without restricting their values to zero or one.
Ground quoting preserves every trace exactly, including invalid actions.
Its execution theorem retains one assignment and one arbitrary initial State.
Parsing and complete input encoding remain separate work.
`python3 scripts/generate_model_input_syntax.py --check` checks the generated prefix
without writing. Use `--write` after changing its schemas. The generator
preserves the manual trace-boundary definitions and proofs byte-for-byte.
`ModelInputScalarEncoding` lowers Nat, Bool zero tests, and optional Nat fields
under one source assignment. It reserves every declared slot, including unused
names, and rejects negative source values. Its source installer preserves
existing frame values under explicit Int-slot disjointness.
`StateFrame` stores typed scalar IDs and fixed-size tables, not expression
histories. Its finite domain check corresponds to a unique non-network state
for supplied shared log roots and a submitted set. Local domains apply only to
allocated nodes; absent lookup stays fresh while globals remain independent.
`StateFrameInitial` allocates 662 distinct scalar slots and fifteen fresh log
roots. Every arbitrary Model state has a representation while existing prefix
roots remain unchanged. Concrete log encoding is proof-only.
`StateFrameEncoding` emits the exact allocation-guarded numeric domains.
Its formula and rendered text agree with the finite domain checker.
Log, queue, submitted-set, and action constraints are separate.
`FrameObservationEncoding` emits allocated, joined, role, current-term,
commit-index, log-length, and all six nested state observations. Absent local
fields use actual fresh-node values; global fields remain independent.
Its checked adapter rejects every action and unsupported observation explicitly.
`ObservationTraceEncoding.render` supplies canonical source/frame allocation.
For every accepted observation-only trace, its rendered-text satisfiability
is equivalent to `ModelInputSyntax.Satisfiable` for that entire trace.
Both directions retain one source assignment and one arbitrary initial state.
This interface takes typed Lean input, not JSON or raw CCF records.
It does not yet encode actions, queue observations, or log-content observations.
`LogMatchSummary` characterizes the actual NACK log reader by a matching anchor
and exclusion of later matches. It handles unsorted terms and clipped bounds.
Its zero-based storage theorem uses decoded Entry terms, not raw signed order.
`LogMatchEncoding` emits that reader using two derived scalars and two universal
queries, without a separate anchor witness. Its formula and rendered-text
existence theorems retain the caller's points, queries, and witnesses on one
shared Entry root family. Connecting the reader to a StateFrame log and the
actual NACK handler remains separate.

`QueueEncoding` emits typed count-read constraints with alias-safe observations
and fresh function names. It summarizes each syntactic key's maximum demanded
version before expanding its prefix once, preserving every constraint.
`QueueScalarEncoding` adds queue guards, windows,
and shared packet order. `QueueInitialEncoding` adds the initial prefix histogram
and alias-aware count budget. It deduplicates syntactic keys without removing
events or initial-prefix occurrences, preserving the existing input, count,
and order functions. `QueueTraceEncoding` closes both directions for the actual rendered
script: satisfiability is equivalent to one initial Int queue executing the
entire unconditional event trace. It derives tracked-key coverage, alignment,
and a fresh filler without caller premises or a capacity bound.
Its initial compiler caches count and scalar formulas across allocation stages.
The compiler rewrite preserves the exact assertion list and generated IDs.
Complete packet keys remain separate work.
`ConditionalQueueAccounting` proves cursor replay for fixed Boolean guards
equivalent to replaying the selected events. Active pops and one pending peek
give the exact demanded initial-prefix histogram under shared-order agreement.
This is a semantic reference, not a guarded SMT compiler or runtime storage
representation. It does not provide typed guards or concrete-queue completion.
`ConditionalQueueEncoding` binds typed guards without asserting them and proves
one clause's active update or inactive count/head/tail identity. Its allocator
preserves original terms and complete external functions. Static annotation and
a finite count grid yield one coherent guarded cursor replay.
`ConditionalQueueTraceEncoding` composes that replay with active-pop accounting,
the final pending peek, and the alias-aware initial budget. Its formula and text
are satisfiable iff one initial queue executes the selected original trace.
Initial length is exact and unbounded. The rectangular grid has no performance
clearance.
`QueueSummaryEncoding` composes the whole-queue compiler with proved presence
normalization. It removes sends known to leave the queue unchanged, while
preserving the same initial queue and every pop, peek, and length observation.
Possible aliases invalidate remembered presence after a pop unless literal
inequality proves otherwise. This transforms queue events, not full Raft actions
or external references to intermediate count versions.
`ConditionalQueueSpecialization` selects guards established by literals or
explicit Boolean input facts, then uses that same queue normalization.
It retains the entire input. If any guard is unresolved, it returns the existing
conditional compiler's formula unchanged. Its existence theorem still covers
arbitrary initial queues. Existing runtime entry points do not select this
new compiler automatically.
`SymbolBounds` computes fresh IDs without constructing symbol sets. A proved
compiler rewrite preserves the original allocation bound exactly.

`SmtScript` declares each referenced typed symbol once and assembles assertions.
Its interpreter preserves formula truth for the same assignment.
Its compiler shares symbol and native-sort discovery across schema selection
and declarations, with a proof that the command list is unchanged.
`SymbolCollection` replaces repeated symbol-list scans with a hash-set pass.
Its exact list-equality theorem preserves the last-occurrence declaration order
and every script byte through a compiler rewrite.
`SmtText` and `SmtNumerals` prove exact decoding of generated symbol and decimal
numeral tokens.
`SmtExpressionText` parses emitted nested expressions and preserves their
evaluation under the same assignment.
`SmtScriptText` extends that correspondence to complete generated scripts.
The opt-in solver fixtures cover both explicit declarations and generated scripts:

```bash
CCF_SPARSE_SMT_TESTS=1 CVC5=/path/to/cvc5 \
	python3 -m unittest tests.test_sparse_smt tests.test_sparse_queue_encoding \
		tests.test_sparse_interval_encoding tests.test_sparse_interval_predicate \
		tests.test_sparse_interval_queries tests.test_sparse_joint_encoding \
		tests.test_sparse_native_sorts tests.test_sparse_typed_intervals \
		tests.test_sparse_entry_predicate tests.test_sparse_typed_joint \
		tests.test_sparse_model_input_scalars tests.test_sparse_conditional_specialization \
		tests.test_sparse_log_match tests.test_sparse_frame_observations \
		tests.test_sparse_configuration_reader
```

These fixtures cover emitted component constraints, not full trace correctness.
The native-sort cases cover all five constant sorts, all 25 unary signatures,
and native constructors, Entry projections, Content selectors, and node-mask
operations. They check all 32,768 node masks
against independent MSB-first formatting.
Scalar scripts retain QF_UFLIA text. Native scripts use ALL and fixed datatype
schemas, with dependency, declaration, and signature checks before evaluation.

The planner's runtime cases use the same opt-in flag:

```bash
CCF_SPARSE_SMT_TESTS=1 python3 -m unittest tests.test_sparse_interval_demands
nice -n 10 lake env lean --run Sparse/IntervalDemandFixtureMain.lean --benchmark
```

The benchmark measures demand planning only, not SMT generation or solving.

Queue emission has a separate phase profile for repeated-key traces:

```bash
nice -n 10 lake env lean --run Sparse/QueueEncodingScaleMain.lean 20 40 80
```

It reports formula, declaration, and text construction times without running a
solver. `tests.test_sparse_symbol_bounds` compares the optimized allocation
with the original algorithm under the same opt-in flag.

The explicit scaling suite runs SAT and UNSAT controls with exactly 400 events:

```bash
CCF_SPARSE_QUEUE_SCALING=1 CVC5=/path/to/cvc5 \
	python3 -m unittest tests.test_sparse_queue_scaling
```

`CCF_SPARSE_QUEUE_EVENTS` overrides the event count, with a minimum of three.
The suite reports one emission time plus the median of three cvc5 process
times. Cases cover repeated sends, send/pop cycles, and unknown initial length
constrained by million-element observations. These are queue-only measurements,
not full-Raft timings or a runtime pass threshold.
`CCF_SPARSE_QUEUE_KEYS=4` selects four-key literal and unresolved-symbolic cases.
`CCF_SPARSE_QUEUE_SUMMARIES=1` selects `QueueSummaryEncoding`; the event count
still includes all original events, with `encoded_events` reported separately.

For native conditional-queue measurements, use Python 3.11 or later and the
existing pinned Lean and package native artifacts:

```bash
python3 scripts/benchmark_conditional_queue.py --build
python3 scripts/benchmark_conditional_queue.py --cvc5 /path/to/cvc5
python3 scripts/benchmark_conditional_queue.py --audit
```

The default case has 40 events. `--events 400 --keys symbolic` selects the
four-key symbolic case. `--shape cycleDistinct` increases the key count, and
`--verdict unsat` selects its contradictory length control.
Use a fresh `--output` directory for another baseline. The tool refuses to
overwrite build or case evidence and does not download or rebuild packages.
It builds only the fixture's 35 project native modules, not the full library.
Cached package objects are checked by size and modification time, not rebuilt
or content-hashed. The build is not hermetic.

The fixture measures one warm emission and three fresh cvc5 processes.
`--audit` distinguishes completed, emission-only, partial, and missing cases.
Only `--audit --require-complete` requires all 54 cases. Every case here has an
empty initial queue, so this matrix does not cover general queue completion.
The baseline misses the runtime target. At 400 events, four symbolic keys with
alternating guards take 14.38 seconds median in cvc5. A 399-symbolic-key send
case emits 61.9 MB. Of 54 emitted cases, 39 have three solver runs and 15 were
not started. These are component measurements, not full Model traces.

The proved known-guard specialization reduces that same four-key 400-event
SAT control, with all pop guards false, to 18.12 ms in cvc5 and 1.33 ms for
warm native emission in a separate reproduction.
It selects 201 events and normalizes them to five,
while retaining all 400 input assertions. Unknown guards and high-key cases
remain outside this performance result. The native benchmark above measures
the unchanged baseline, not the specialization.

This is a proof library, not a complete sparse trace validator. Full Model
composition, full-trace SMT correspondence, and end-to-end performance remain
unfinished. The design and remaining work are in [HANDOFF.md](HANDOFF.md).

## Checked trace encoding

The checked encoder is a separate entry point:

```bash
python3 validate_checked.py \
  Traces/LeaderWrites/bootstrap-writes.json \
  Artifacts/checked-traces/leader-writes
```

Add `--cvc5 /path/to/cvc5` if cvc5 is not on `PATH`.

The runner builds `encode_trace` from the audited `EncodeTrace` module, then
runs that executable. Repeated encodings do not re-elaborate the Lean proofs.

The `ccfraft-trace/v1` schema accepts the four leader writes,
`appendEntries`, and all eleven control actions:
`advanceCommitIndex`, `timeout`, `becomePreVoteCandidate`, `becomeCandidate`,
`requestVote`, `requestPreVote`, `checkQuorum`, `updateTerm`, `becomeLeader`,
`proposeVote`, and `advanceCommitIndexAndProposeVote`.
Observations cover `role`, `currentTerm`, `logLength`, `queueLength`,
`commitIndex`, `allocated`, `joined`, and `submitted`.
The leader writes are `clientRequest`, `signCommittableMessages`,
`changeConfiguration`, and `appendRetiredCommitted`.
Single-node actions use `node`. Two-node actions use `node` for the source
and `destination` for the receiver. In particular, `updateTerm` updates the
destination from a newer queued message from the source; it does not take
an arbitrary term value. `clientRequest` supplies `transaction`,
`changeConfiguration` supplies a `configuration` array, and `appendEntries`
also supplies `batchEnd`. Entry can be the canonical bootstrap or an explicit
full-state template:

```bash
python3 validate_checked.py \
  Traces/ClientRequests/template.json \
  Artifacts/checked-client-requests/template
```

The v2 example has node 1 leading in term 7, a pre-existing log entry, and
symbolic old and new transaction IDs. Every other state field is explicit.
Unknown roles, terms, allocation, and queue shapes are not supported yet.
Other actions and raw NDJSON input remain unsupported. Unsupported syntax
is an error; the runner never falls back to the projected backend.

AppendEntries deduplication compares evaluated packets. Different transaction
unknowns can alias, so a send may retain the existing queue or append a packet.
The encoder carries these guarded alternatives through later actions and
observations under the same assignment. Constant guards collapse without
duplicating later frames. Queue-length observations use `node` to identify
the receiving queue.

Run the persistent send example:

```bash
python3 validate_checked.py \
	Traces/Replication/send.json \
	Artifacts/checked-traces/replication
```

The general schema declares exclusive `transaction_count`, `term_count`, and `index_count`
limits, plus inclusive `log_capacity` and `queue_capacity` limits. Bounds
apply before every instruction and at the end, including transaction payloads
inside queued AppendEntries messages. A bound violation produces UNSAT, not a
parse error. The older `ccfraft-client-request/v1` bootstrap and
`ccfraft-client-request/v2` template schemas remain accepted by the same encoder,
but retain their client-request-only action restrictions.

Transaction values are
natural numbers or references such as `{"unknown": "first"}` to names in the
`unknowns` array. Every occurrence of a name denotes the same value. All named
unknowns range from zero through `transaction_count - 1`. Different names may
denote the same value; client-request freshness is checked after evaluation.
JSON `null` is not a transaction unknown. It denotes an absent node slot or an
absent optional field where the schema permits one.

Every node-indexed table has exactly 15 entries in node-ID order. Template
field names match `Model.lean`, including votes, peer indices, all seven
message variants, and retirement metadata. The entry need not be reachable
from bootstrap: this is a bounded execution claim from the supplied template,
not a reachability claim. See `TraceStateJson.lean` for the exact JSON mapping.

`BoundedTrace.lean` is the reviewed execution contract.
`VerifiedEncoder` requires a single theorem, quantified over all supported
entries, traces, bounds, and assignments, connecting the actual formula to
that contract. Updates call `Model.next` on transaction-symbolic templates;
`TransactionMapping.lean` defines their evaluation into concrete model states.
The executable uses a value of this type and rejects unapproved proof axioms.
The proof is not regenerated for each input trace.

The assurance boundary is:

- Review the model, contracts, bounds, transaction mapping, JSON decoders,
  and `EncodeTrace.lean`, listed below.
- Lean checks representation roundtrips, transaction mapping, and encoding
  equivalence in `MachineGenerated/`.
- Review `Shared/Smt.lean`, `Shared/SmtOrder.lean`, solver execution, and core reduction
  as infrastructure. SMT serialization and cvc5 remain trusted.

The output includes `formula.smt2` and `constraint-map.json`. Each instruction
has a group ID and labelled component constraints. `--inspect-group N` changes
one action's assertion granularity without changing its meaning. Group indices
are recorded in the map; index 0 is the unknown-domain group, not an action.
In this mode, reduction removes only clauses of the selected action. Other
assertions in that run's solver core stay fixed. This does not yet reuse a
previously reduced high-level core. Use `refine_checked.py` for that second stage.
`instruction_index` is one-based, matching the existing reduction diagnostics.
Intermediate log lengths, terms, commit frontiers, accepted transaction IDs,
refreshed retirement indices and completion sets, allocation and join markers,
assigned sent indices, and queue lengths
have defining equalities in their action groups. Later constraints refer to these values
so the core can retain the actions that produced them.
A new enqueue defines the prior queue length plus one; a duplicate retains
the prior binding. Branch-local definitions have distinct names while references
to earlier actions keep their original names.
The equivalence theorem covers formula meaning. Diagnostic labels and their
source mapping are infrastructure metadata, not an additional proved claim.
Structural action guards are single clauses, so a failed guard does not yet
identify which model precondition failed.
A reduced SMT core is not a replayable subsequence of model actions: other
instructions can contribute concrete state used during encoding.

The runner writes the verdict to `result.json`. Reusing an output directory
replaces that run's artifacts, even if the new certificate is rejected.
Failures write `error.json` instead when the directory is writable.

SAT and UNSAT apply only to the supplied entry template and declared bounds.
They do not quantify over unspecified structural fields or establish an
unbounded result. The existing `validate.py` entry point still uses the
separate, unverified projection described below.

To run the focused checked-encoder gate:

```bash
./check_checked.sh
```

Set `CVC5` to an executable path if the solver is not on `PATH`.
The gate builds `ControlActionAudit`, `EncoderAudit`, and `encode_trace`,
runs the checked action, diagnostic, and explorer regressions, and requires SAT for the
persistent send example. Missing tools fail the gate rather than skip tests.
It does not build the unrelated safety proofs in `Demo`.

## Explore a reduced core

First produce a group-level checked run. Then generate its explorer:

```bash
python3 validate_checked.py \
	Traces/ClientRequests/wrong-log-length.json Artifacts/checked-traces/conflict
python3 explore_checked.py \
	Artifacts/checked-traces/conflict Artifacts/explorer/conflict.html
```

The standalone HTML has three panes: raw NDJSON, ordered actions and
observations, and the reduced core. Selecting an instruction shows its labelled
constraints and highlights its source lines. Pass `--raw-trace PATH` when the
certificate's instruction provenance refers to that file. Without a raw file,
the first pane says that the run starts from a certificate.

For each action remaining in an UNSAT core, the generator precomputes a
clause reduction with every other reduced group fixed. **Show reduced clauses**
displays that result; **Group view** returns to the high-level core. No discarded
group is restored. The report does not run a solver in the browser.
`--no-refine` omits clause reductions but retains full constraint inspection.
SAT and unknown runs show their status without a conflicting core.

To refine just one action without generating a report:

```bash
python3 refine_checked.py Artifacts/checked-traces/conflict \
	Artifacts/checked-traces/conflict-action-2 --inspect-group 2
```

The source directory remains unchanged. The refinement has its own formula,
constraint map, diagnosis, solver outputs, and result. The operation rejects
an action outside the reduced core or a formula that disagrees with its map.
Saved run artifacts remain trusted local inputs.

Both tools accept `--cvc5 PATH`. The explorer's `--workspace-uri` sets its
remote VS Code workspace link. The report embeds its data and needs no network
access except when you follow a source link.

## Review these files

The manual review boundary contains these files:

- `Model.lean` contains the model's types, state, and executable definitions,
  including `CCFRaft.Action`, `CCFRaft.Enabled`, and `CCFRaft.next`.
  Only inline proofs required to construct typed values remain here.
- `Properties.lean` defines the three consensus-safety claims.
- `reduction.py` defines the preprocessing and reduction rules.
- `TraceProperties.lean` defines `ValidEntryState`,
  `MidtraceSatisfiable`, `FormulaSatisfiable`, and `lowerTrace_correct`.
- `TraceInstructions.lean` defines typed instructions and observations.
- `BoundedTrace.lean` defines full-entry execution and the
  correctness requirement for its encoder.
- `BoundedState.lean` defines lossless finite state data and full-state bounds.
- `TransactionMapping.lean` defines transaction evaluation throughout a state.
- `TraceJson.lean`, `TraceStateJson.lean`, `LegacyClientRequestCertificate.lean`, and
  `TraceCertificate.lean` define the JSON mapping and v1 adapter.
- `EncodeTrace.lean` enforces the checked-encoder type and proof-axiom
  policy before emitting the formula and its constraint map.

The reducers separate three jobs:

1. Shared code parses and consumes the captured trace without changing its
   meaning.
2. Audited preprocessing groups or removes implementation events.
3. Audited reduction rules emit model actions and observations.

The reduction certificate has one ordered `steps` array. Each item is either:

```json
{"kind": "observation", "node": "2", "variable": "currentTerm", "value": 3}
```

or:

```json
{"kind": "action", "node": "2", "action": "receive", "source": "1"}
```

Array order defines the semantics. An observation reads the current state. An
action checks `Enabled` and advances the state with `next`.

Before every receive, the reducer emits a `firstMessageFrom` observation with
the packet fields available in the implementation trace. The Lean definition
means the first queued message from the chosen source equals that message.

## Do not manually review generated proofs

`MachineGenerated/` contains lowering code, proof bodies, and the inductive
model proof. An agent may replace these files. Lean must compile them without
`sorry` before the demo passes.

`MachineGenerated/ModelProofs.lean` contains the model's bootstrap, state-update,
retirement, and reachability lemmas. Proof consumers import this module for
the lemmas and their simplification rules. `Model.lean` does not import it.

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

The legacy `validate.py` backend checks only a projection of that claim.
`ccfraft_projection.py` models terms, roles, log lengths, commit indices, allocation,
and join state. It does not encode complete logs, messages, votes, or
configurations. Its `sat` and `unsat` results therefore do not yet establish
`MidtraceSatisfiable` for the complete model.

The projected backend checks the shape and ordering of `firstMessageFrom`, but
does not yet encode queues or message contents. The generated SMT file marks
that observation as an unencoded projection constraint.

`MachineGenerated/Lowering.lean` and
`MachineGenerated/LoweringProofs.lean` prove that the typed action
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

For repeated timing measurements, run:

```bash
python3 benchmark_pipeline.py --cvc5 /path/to/cvc5
```

The benchmark removes only this package's `.lake/build` directory for the
clean project build. It retains the pinned toolchain and dependency cache. It
then runs five interleaved capture and validation samples per trace and writes
raw samples plus median and p90 values to `Measurements/pipeline.json`.

Generate the colleague overview from those measurements with:

```bash
python3 generate_colleague_report.py
```

The output is `Report/colleague-overview.html`.

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

The Python reducer is the sole reducer implementation. Its deterministic JSON
certificate is the input to SMT lowering.

To reproduce the captured implementation traces, run:

```bash
./Shared/capture_traces.py --check
```

This command invokes `build/raft_driver` directly. It does not call the old
semantic preprocessor in `tests/raft_scenarios_runner.py`.

## Source checkpoint

The original CCFRaft model and proof came from commit `73292060d`.
Development continues in this directory. Git history retains the retired
prototype encoders, reports, and one-time checkpoint migration script.
