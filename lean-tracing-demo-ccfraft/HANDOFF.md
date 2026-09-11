# Resume the checked CCFRaft trace encoder

## Current direction: native-array exact encoding

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
`native_run.py`. Lean `encodeDetails` emits named SMT clauses and instruction
ranges from the actual compiled assertion array. `native_lean.py` retains the
exact input, encoding metadata, solver outputs, and a hash manifest written only
after a successful solver invocation. cvc5 supplies the core through
`--produce-unsat-cores --dump-unsat-cores`; Python does not construct SMT queries.
The API is read-only, binds to loopback, and serves a fixed startup snapshot.
It exposes run status, input, paginated instructions, named constraints, and the
solver core. It rejects mixed artifacts and never adopts old checked-backend
proof claims. `Traces/native_quorum_conflict.json` is a deliberate synthetic
UNSAT example, not a captured trace. Raw-event/code provenance still depends on
reducer integration. See README's "Native explorer API" section.

The first Lean encoder slice is now implemented in `Sparse/NativeEncode.lean`
and `Sparse/NativeEncodeMain.lean`, with `native_lean.py` as its JSON and solver
wrapper. It supports only `checkQuorum` and seven scalar/log observation kinds.
The Python reference still supports six actions and the broader observation
schema. Do not confuse these coverage levels or fall back to Python SMT emission.

`Sparse/NativeSmt.lean` now builds. Its denotation must remain reducible so that
Lean can resolve the underlying integer, Boolean, and bitvector instances.
The typed AST supports native arrays, scoped quantifiers, arbitrary-width bits,
products, and sums. cvc5 rejected symbolic `as const` array values, so that
constructor was removed. Use explicit quantified constraints for array resets.
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

The full Model-to-emitted-script theorem and renderer correctness are still
missing. No observation specialization is applied by the current compiler.
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

The next Lean slice must combine the configuration guards with allocation/role
and the state update. Initial-domain realization, the complete compiler/execution
correspondence, and the lowering/text proof remain.
Do not treat the conditional reader theorem as a full action or script proof.
Close those boundaries before migrating the remaining actions.

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
Submitted IDs use a Boolean array with an unknown finite upper bound, not an
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
