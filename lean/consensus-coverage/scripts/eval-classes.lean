module

meta import Consensus.Model
meta import all Consensus.Proofs.SafetyInvariant
public import Consensus.Model

/-!
# Evaluating generated coverage classes on the steps of concrete runs (partial, unproved)

For the step classes whose case split sits in the obligations `Ctx.leader_led` and
`Ctx.commit_backed`, and for four state classes of `committed_logs_comparable`, this script
decides, per step of a concrete run, whether the class holds, does not hold, or is unknown.
Each decision is a hand transcription of the generated proposition (see
`print-eval-classes.lean`): the newness condition of its `reach` definition and the conditions
of the case splits on its path. Conjuncts that are facts proved in scope at the case (for
example the `Backed` implications in the `commit_backed` kinds) are not evaluated: on a
reachable step they follow from the path conditions. The decisions are NOT proved equal to the
generated classes. Two approximations, both CLAIMED sound for runs of the model:

- `NodeState` equality compares the function fields `sentIndex` and `matchIndex` only on the
  run's nodes and one fresh identifier (the functions in runs are finite updates of constants);
- `Wins` (an existential over an intermediate candidate state that is not in the run) is decided
  through the proved `Summary.leader` fact when the post-role is primary, and is unknown when it
  is `none`.

The `Ctx` of a step is the one built from its action (actor, pre and post state, event).

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/eval-classes.lean
-/

namespace ConsensusCoverage.EvalClasses

open Consensus Consensus.Model.Node
open Consensus.Model (initialNodeState BOOTSTRAP_TERM)
open CCF (Finset)
open CCF.MultiNodeTransitionSystem (nodeState)

inductive Act where
  | local (node : NodeID) (input : Input)
  | deliver (source target : NodeID)

def initialState (configuration : Finset NodeID) (nodes : List NodeID) : Model.State :=
  { nodes := nodes.map fun node => (node, initialNodeState configuration node) }

def inputKind : Input → String
  | .append _ => "append"
  | .sendEntries _ _ => "sendEntries"
  | .timeout _ => "timeout"
  | .nominateSuccessor => "nominateSuccessor"
  | .initAsBackup _ => "initAsBackup"

def messageKind : Message → String
  | .appendEntriesRequest _ => "AE"
  | .appendEntriesResponse r => if r.success then "AE-ack" else "AE-nack"
  | .requestVoteRequest _ => "RV"
  | .requestVoteResponse r => if r.voteGranted then "RV-yes" else "RV-no"
  | .requestPreVoteRequest _ => "PV"
  | .requestPreVoteResponse r => if r.voteGranted then "PV-yes" else "PV-no"
  | .proposeRequestVoteRequest _ => "propose-RV"

def clientRequestCommits : List Act := [
  .local 0 (.append [{ content := .transaction 10 {} }]),
  .local 0 (.append [{ content := .signature }]),
  .local 0 (.sendEntries 1 3), .deliver 0 1, .deliver 1 0,
  .local 0 (.sendEntries 2 3), .deliver 0 2, .deliver 2 0,
  .local 0 (.sendEntries 1 3), .deliver 0 1, .deliver 1 0]

def reconfigureElectAndCommit (expected : List Entry) : List (List Act) := [
  [ .local 0 (.append [{ content := .transaction 10 {} }]),
    .local 0 (.append [{ content := .signature }]),
    .local 0 (.append [{ content := .transaction 20 { configuration := some {0, 1, 2} } }]),
    .local 0 (.append [{ content := .signature }]) ],
  [ .local 1 (.initAsBackup []), .local 2 (.initAsBackup (expected.take 3)) ],
  [ .deliver 0 1, .deliver 1 0, .deliver 0 2, .deliver 2 0 ],
  [ .local 0 (.sendEntries 1 5), .local 0 (.sendEntries 2 5),
    .deliver 0 1, .deliver 1 0, .deliver 0 2, .deliver 2 0 ],
  [ .local 0 (.sendEntries 1 5), .deliver 0 1, .deliver 1 0,
    .local 0 (.sendEntries 2 5), .deliver 0 2, .deliver 2 0 ],
  [ .local 1 (.timeout .election), .deliver 1 0, .deliver 0 1, .deliver 1 0, .deliver 0 1,
    .deliver 1 2, .deliver 2 1, .deliver 1 2, .deliver 2 1, .deliver 1 2, .deliver 2 1,
    .deliver 1 0, .deliver 0 1 ],
  [ .local 1 (.append [{ content := .transaction 30 {} }]),
    .local 1 (.append [{ content := .signature }]),
    .local 1 (.sendEntries 0 7), .deliver 1 0, .deliver 0 1,
    .local 1 (.sendEntries 2 7), .deliver 1 2, .deliver 2 1,
    .local 1 (.sendEntries 0 7), .deliver 1 0, .deliver 0 1 ] ]


/-- Three-valued result. -/
inductive Tri where | yes | no | unknown
deriving DecidableEq, Repr

def Tri.ofBool (b : Bool) : Tri := if b then .yes else .no

def Tri.and : Tri -> Tri -> Tri
  | .no, _ | _, .no => .no
  | .yes, .yes => .yes
  | _, _ => .unknown

/-- `NodeState` equality, the function fields compared on `probe` only. -/
def stEq (probe : List NodeID) (a b : NodeState) : Bool :=
  a.role == b.role && a.currentTerm == b.currentTerm && a.log == b.log
    && a.commitIndex == b.commitIndex && probe.all (fun n => a.sentIndex n == b.sentIndex n)
    && probe.all (fun n => a.matchIndex n == b.matchIndex n)
    && a.isNewFollower == b.isNewFollower && a.votedFor == b.votedFor
    && a.primaryKnown == b.primaryKnown && decide (a.votesGranted = b.votesGranted)
    && decide (a.preVotesGranted = b.preVotesGranted)
    && a.retiredCommittedIndex == b.retiredCommittedIndex

/-- `Advance self middle state`, with `stEq` for state equality. -/
def advance (probe : List NodeID) (self : NodeID) (middle state : NodeState) : Bool :=
  stEq probe state middle
    || (state.log == middle.log && state.currentTerm == middle.currentTerm
        && state.votedFor == middle.votedFor
        && probe.all (fun n => state.matchIndex n == middle.matchIndex n)
        && probe.all (fun n => state.sentIndex n == middle.sentIndex n)
        && decide (state.votesGranted = middle.votesGranted)
        && middle.commitIndex < state.commitIndex
        && state.commitIndex == highestCommittableIndex middle self
        && (state.role == middle.role || state.role == .none))

/-- The data of a step's `Ctx`, built from its action. -/
structure Step where
  before : Model.State
  after : Model.State
  actor : NodeID
  pre : NodeState
  post : NodeState
  event : Event

def isPrimary (r : Role) : Bool := r == .primary

/-- `Wins actor pre event post` (see the module comment). -/
def wins (s : Step) : Tri :=
  if s.post.role == .primary then
    .ofBool !(s.pre.role == .primary && s.post.currentTerm == s.pre.currentTerm)
  else if s.post.role == .none then .unknown
  else .no

def stepClasses (probe : List NodeID) (s : Step) : List (String × Tri) :=
  let new := !(s.before.nodes.any fun (n, st) => n == s.actor && stEq probe st s.post)
  let llNow := new && isPrimary s.post.role
  let llInl := llNow && isPrimary s.pre.role && s.post.currentTerm == s.pre.currentTerm
  let same := new && s.post.log == s.pre.log && s.post.commitIndex == s.pre.commitIndex
  let append := new && isPrimary s.pre.role && s.pre.log.isPrefixOf s.post.log
    && (s.post.log.drop s.pre.log.length).all (·.term == s.pre.currentTerm)
    && advance probe s.actor
      { s.pre with log := s.post.log, sentIndex := s.post.sentIndex } s.post
  let ackOf : Option (NodeID × AppendEntriesResponse) := match s.event with
    | .receive source (.appendEntriesResponse r) =>
      if new && isPrimary s.pre.role && r.success && r.term == s.pre.currentTerm
        && (let m := CCF.Function.update s.pre.matchIndex source
              (max (s.pre.matchIndex source) r.lastLogIndex)
            advance probe s.actor { s.pre with matchIndex := m } s.post)
      then some (source, r) else none
    | _ => none
  let ack := ackOf.isSome
  let middleMatch (source : NodeID) (r : AppendEntriesResponse) (v : NodeID) :=
    CCF.Function.update s.pre.matchIndex source (max (s.pre.matchIndex source) r.lastLogIndex) v
  let fixed := s.post.log == s.pre.log && s.post.currentTerm == s.pre.currentTerm
  let fromPos := match ackOf with
    | some (src, r) => fixed && src != s.actor && 0 < middleMatch src r src
    | none => false
  let fromNeg := match ackOf with
    | some (src, r) => fixed && probe.any fun v => v != s.actor && v != src && 0 < middleMatch src r v
    | none => false
  let maxL := match ackOf with
    | some (src, r) => fromPos && max (s.pre.matchIndex src) r.lastLogIndex == s.pre.matchIndex src
    | none => false
  let maxR := match ackOf with
    | some (src, r) => fromPos && max (s.pre.matchIndex src) r.lastLogIndex == r.lastLogIndex
    | none => false
  let accept := new && match s.event with
    | .receive _ (.appendEntriesRequest req) =>
      req.term == s.post.currentTerm && s.pre.currentTerm ≤ req.term
        && s.pre.commitIndex ≤ req.prevLogIndex && req.prevLogIndex ≤ s.pre.log.length
        && termAt s.pre.log req.prevLogIndex == req.prevLogTerm
        && s.post.log == Consensus.Proofs.Safety.acceptLog s.pre.log req
        && s.post.commitIndex == max s.pre.commitIndex
          (maxCommittableIndexUpTo s.post.log
            (min req.primaryCommit (req.prevLogIndex + req.entries.length)))
    | _ => false
  let elect := (Tri.ofBool new).and (wins s)
  let install := new && match s.event with
    | .internal (.initAsBackup entries) =>
      0 < entries.length && isSignatureAt entries entries.length
        && s.pre.role == .none && s.pre.currentTerm == 0 && s.pre.log.isEmpty
        && s.pre.commitIndex == 0 && s.post.log == entries
        && s.post.commitIndex == entries.length
        && s.post.currentTerm == termAt entries entries.length && s.post.role == .follower
    | _ => false
  [ ("step_leader_led_now_after_inl", .ofBool llNow),
    ("step_leader_led_leader_inl", .ofBool llInl),
    ("step_leader_led_leader_inr", .ofBool (llNow && !llInl)),
    ("step_commit_backed_now_after_inl", .ofBool new),
    ("step_commit_backed_kind_same", .ofBool same),
    ("step_commit_backed_kind_append", .ofBool append),
    ("step_commit_backed_kind_ack", .ofBool ack),
    ("step_commit_backed_fromSource_pos", .ofBool fromPos),
    ("step_commit_backed_max_eq_or_inl", .ofBool maxL),
    ("step_commit_backed_max_eq_or_inr", .ofBool maxR),
    ("step_commit_backed_fromSource_neg", .ofBool fromNeg),
    ("step_commit_backed_kind_accept", .ofBool accept),
    ("step_commit_backed_kind_elect", elect),
    ("step_commit_backed_eq_zero_or_pos_inl", elect.and (.ofBool (s.pre.commitIndex == 0))),
    ("step_commit_backed_eq_zero_or_pos_inr", elect.and (.ofBool (s.pre.commitIndex > 0))),
    ("step_commit_backed_kind_install", .ofBool install) ]

/-- State classes of `committed_logs_comparable` that are decidable without `Committed`. -/
def stateClasses (state : Model.State) : List (String × Tri) :=
  let commits := state.nodes.map (·.2.commitIndex)
  let zero := commits.any (· == 0)
  let pos := commits.any (· > 0)
  -- inr: some node with a positive commit index has a committed part (by `commit_backed`);
  -- with only zero commit indices it needs some committed part at all: unknown.
  let inr : Tri := if pos then .yes else .unknown
  [ ("state_committed_logs_comparable_left_backed_inl", .ofBool zero),
    ("state_committed_logs_comparable_left_backed_inr", inr),
    -- right_backed is reached after left_backed for a pair (left, right) of nodes
    ("state_committed_logs_comparable_right_backed_inl", .ofBool zero),
    ("state_committed_logs_comparable_right_backed_inr", inr) ]

def triStr : Tri -> String | .yes => "1" | .no => "0" | .unknown => "?"

/-- A step from an action, with its `Ctx` data. -/
def mkStep (configuration : Finset NodeID) (nodes : List NodeID) (state : Model.State)
    (act : Act) : Except String Step := do
  let system := Model.transitionSystem configuration nodes
  let (action, actor, event) ← match act with
    | .local node input => pure ((.local node input : Model.Action), node, Event.internal input)
    | .deliver source target =>
      match state.network.find? fun e => e.source == source && e.target == target with
      | some e => pure (.deliver e, target, Event.receive e.source e.payload)
      | none => throw "no pending message"
  let some after := system.step state action | throw "disabled action"
  let some pre := nodeState state actor | throw "missing node"
  let some post := nodeState after actor | throw "missing node"
  return { before := state, after, actor, pre, post, event }

def runSteps (configuration : Finset NodeID) (nodes : List NodeID) (start : Model.State)
    (acts : List Act) : Except String (List Step × Model.State) := do
  let mut state := start
  let mut out := []
  for a in acts do
    let s ← mkStep configuration nodes state a
    out := out ++ [s]
    state := s.after
  return (out, state)

def canonical : Except String (List Step) := do
  let (a, _) ← runSteps {0, 1, 2} [0, 1, 2] (initialState {0, 1, 2} [0, 1, 2]) clientRequestCommits
  let expected : List Entry := [
    { term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some {0} } },
    { term := BOOTSTRAP_TERM, content := .transaction 10 {} },
    { term := BOOTSTRAP_TERM, content := .signature },
    { term := BOOTSTRAP_TERM, content := .transaction 20 { configuration := some {0, 1, 2} } },
    { term := BOOTSTRAP_TERM, content := .signature } ]
  let mut state := initialState {0} [0, 1, 2]
  let mut out := a
  for acts in reconfigureElectAndCommit expected do
    let (b, s) ← runSteps {0} [0, 1, 2] state acts
    out := out ++ b
    state := s
  return out

def report (label : String) (steps : List Step) : IO Unit := do
  let probe : List NodeID := [0, 1, 2, 1000]
  let t0 ← IO.monoNanosNow
  let rows := steps.map fun s => (stateClasses s.before, stepClasses probe s, stateClasses s.after)
  -- force evaluation
  let total := rows.foldl (fun acc (a, b, c) => acc + a.length + b.length + c.length) 0
  let t1 ← IO.monoNanosNow
  IO.println s!"== {label}: {steps.length} steps, {total} class decisions, \
    {(t1 - t0) / 1000} us total"
  let names := (rows.head?.map (·.2.1.map (·.1))).getD []
  for n in names do
    let vals := rows.map fun (_, sig, _) => (sig.lookup n).getD .unknown
    IO.println s!"{vals.count .yes}\t{vals.count .no}\t{vals.count .unknown}\t{n}"
  let snames := ((rows.head?.map (·.1.map (·.1))).getD [])
  for n in snames do
    let vals := rows.map fun (_, _, post) => (post.lookup n).getD .unknown
    IO.println s!"{vals.count .yes}\t{vals.count .no}\t{vals.count .unknown}\t{n} (after-states)"
  let key (l : List (String × Tri)) := String.join (l.map (triStr ·.2))
  let ctxs := (rows.map fun (a, _, c) => [key a, key c]).flatten.eraseDups
  let sigs := (rows.map fun (_, b, _) => key b).eraseDups
  let obs := (rows.map fun (a, b, c) => s!"{key a} {key b} {key c}").eraseDups
  IO.println s!"distinct contexts {ctxs.length}: {ctxs}"
  IO.println s!"distinct signatures {sigs.length}"
  for sg in sigs do
    IO.println s!"  {(rows.filter fun (_, b, _) => key b == sg).length}\t{sg}"
  IO.println s!"distinct observations {obs.length}"
  for o in obs do
    IO.println s!"  {(rows.filter fun (a, b, c) => s!"{key a} {key b} {key c}" == o).length}\t{o}"

#eval show IO Unit from do
  match canonical with
  | .error e => throw (IO.userError e)
  | .ok steps => report "canonical traces" steps

end ConsensusCoverage.EvalClasses
