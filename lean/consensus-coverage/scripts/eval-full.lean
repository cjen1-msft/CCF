module

meta import Consensus.Model
meta import all Consensus.Proofs.SafetyInvariant
public import Consensus.Model

/-!
# Historical experiment: evaluating selected classes of the list-based proof

This hand transcription is not a classifier for the stepwise proof; for its proved
snapshot slice use `pair-coverage.lean`. For the earlier 29 state classes and the step
classes whose case split sits in the obligations
`Ctx.leader_led`, `Ctx.commit_backed`, `Ctx.election_safety`, `Ctx.canon_mono` and
`Ctx.completeness`, this script
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
    RUNS=100 LENGTH=60 lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/eval-full.lean

The state classes and the new step classes read a computable layer over the run's history
(`Hist`): grants, elections, canon logs, commit records and the `Committed` fixpoint.
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

def triStr : Tri -> String | .yes => "1" | .no => "0" | .unknown => "?"

def Tri.or : Tri -> Tri -> Tri
  | .yes, _ | _, .yes => .yes
  | .no, .no => .no
  | _, _ => .unknown

/-- `exact` decides the paths transcribed exactly; `approx` the paths only approximated: the
result is yes if `exact` is, otherwise unknown if `partial` is, otherwise no. -/
def Tri.paths (exact approx : Bool) : Tri :=
  if exact then .yes else if approx then .unknown else .no

/-! ## The computable layer: `Granted`, `Elected`, `Led`, `CanonNow`, `Canon`, `CommitStep`,
`Committed` over the prefixes of a run

A run is kept oldest first; `h_k` is the history whose newest state is `states[k]`. Every
existential of these definitions ranges over data of the run: suffixes of the history are
prefixes `h_k`; nodes and node states are those of `states`; `log`, `commit` and `term` of an
election are fixed by the candidate and leader states; voters are ids of the run (a non-member
cannot satisfy `GrantStep`/`Seen`), and since `hasQuorum` is monotone in the voter set (it is a
per-configuration majority) the largest qualifying set is tried; `index` and `base` range over
`0..log.length`; `part` is a prefix of a leader log. Records carry the `k` at which they first
hold, so a query at `h_k` filters on it. -/

structure Grant where
  k : Nat
  voter : NodeID
  cand : NodeID
  term : Nat
  granting : NodeState
  candSeen : Bool

structure Elect where
  k : Nat
  node : NodeID
  term : Nat
  log : List Entry
  commit : Nat

/-- A `CommitStep (h_k) leader state term base index` that also derives `Committed`: `fresh`
(base 0) and/or `chained` (a part committed in `h_(k-1)` no later than `term` contains
`state.log.take base`). One record per (k, leader, index), with the smallest such base. -/
structure CRec where
  k : Nat
  leader : NodeID
  term : Nat
  index : Nat
  part : List Entry
  fresh : Bool
  chained : Bool

structure Hist where
  config : Finset NodeID
  states : Array Model.State := #[]
  ids : List NodeID := []
  /-- (k, node, currentTerm, log) of every node state seen, first occurrence. -/
  seen : Array (Nat × NodeID × Nat × List Entry) := #[]
  grants : Array Grant := #[]
  elects : Array Elect := #[]
  /-- (k, node, term, log) with `CanonNow h_k node state term`, `state.log = log`. -/
  canons : Array (Nat × NodeID × Nat × List Entry) := #[]
  commits : Array CRec := #[]
  /-- (first k, term, part) with `Committed h_k term part`. -/
  committed : Array (Nat × Nat × List Entry) := #[]

def lookup (s : Model.State) (n : NodeID) : Option NodeState :=
  (s.nodes.find? (·.1 == n)).map (·.2)

def quorum (configs : List Configuration) (voters : List NodeID) : Bool :=
  !configs.isEmpty && configs.all fun cfg =>
    (cfg.nodes.val.filter (voters.contains ·)).length * 2 > cfg.nodes.val.length

namespace Hist

def initialPrimary (h : Hist) : NodeID := h.config.min?.getD 0

def led (h : Hist) (k : Nat) (node term : Nat) : Bool :=
  (term == BOOTSTRAP_TERM && node == h.initialPrimary)
    || h.elects.any fun e => e.k ≤ k && e.node == node && e.term == term

def elected (h : Hist) (k : Nat) (node term : Nat) : Bool :=
  h.elects.any fun e => e.k ≤ k && e.node == node && e.term == term

def electNow (h : Hist) (k : Nat) (node term : Nat) : Bool :=
  h.elects.any fun e => e.k == k && e.node == node && e.term == term

def granted (h : Hist) (k voter cand term : Nat) (req : RequestVoteRequest) : Bool :=
  h.grants.any fun g => g.k ≤ k && g.voter == voter && g.cand == cand && g.term == term
    && g.granting.currentTerm ≤ term && decide (voteLogUpToDate g.granting req) && g.candSeen

def isCommitted (h : Hist) (k t : Nat) (p : List Entry) : Bool :=
  h.committed.any fun (k', t', p') => k' ≤ k && t' == t && p' == p

def canonLogs (h : Hist) (k t : Nat) : List (NodeID × List Entry) :=
  (h.canons.toList.filter fun (k', _, t', _) => k' ≤ k && t' == t).map fun (_, n, _, l) => (n, l)

def push (h : Hist) (s : Model.State) : Hist := Id.run do
  let k := h.states.size
  let before? := h.states[k - 1]?
  let mut h := { h with states := h.states.push s, ids := (h.ids ++ s.nodes.map Prod.fst).eraseDups }
  if let (true, some before) := (decide (k > 0), before?) then
    for (voter, grantedSt) in s.nodes do
      match lookup before voter, grantedSt.votedFor with
      | some granting, some cand =>
        let term := grantedSt.currentTerm
        let candSeen := voter == cand
          || h.seen.any fun (k', n, t, _) => k' + 1 ≤ k && n == cand && t == term
        h := { h with grants := h.grants.push { k, voter, cand, term, granting, candSeen } }
      | _, _ => pure ()
  for (n, st) in s.nodes do
    unless h.seen.any (fun (_, n', t, l) => n' == n && t == st.currentTerm && l == st.log) do
      h := { h with seen := h.seen.push (k, n, st.currentTerm, st.log) }
  if let (true, some before) := (decide (k > 0), before?) then
    for (node, leader) in s.nodes do
      if let some candidate := lookup before node then
        let term := leader.currentTerm
        let log := candidate.log
        let commit := candidate.commitIndex
        let ok := commit ≤ log.length
          && (candidate.currentTerm < term
              || (candidate.currentTerm == term && candidate.role == .candidate))
          && (leader.role == .primary || leader.role == .none)
          && (log.take (maxCommittableIndex log)).isPrefixOf leader.log
          && 3 ≤ term
        if ok then
          let req := Consensus.Proofs.Safety.vals term log commit
          let voters := h.ids.filter fun v => h.granted k v node term req
          if quorum (activeConfigurations log commit) voters then
            h := { h with elects := h.elects.push { k, node, term, log, commit } }
  for (n, st) in s.nodes do
    if st.role != .candidate && h.led k n st.currentTerm then
      unless h.canons.any (fun (_, n', t, l) => n' == n && t == st.currentTerm && l == st.log) do
        h := { h with canons := h.canons.push (k, n, st.currentTerm, st.log) }
  let mut newCommits : Array CRec := #[]
  for (leader, st) in s.nodes do
    if st.role != .candidate && h.led k leader st.currentTerm then
      let term := st.currentTerm
      for index in List.range (st.log.length + 1) do
        if isSignatureAt st.log index && termAt st.log index == term then
          let part := st.log.take index
          let voters := h.ids.filter fun v =>
            h.seen.any fun (k', n, t, l) => k' ≤ k && n == v && t == term && part.isPrefixOf l
          let mut fresh := false
          let mut chained := false
          for base in List.range (index + 1) do
            let configs := (activeConfigurations st.log base).filter (·.index ≤ index)
            if quorum configs voters then
              if base == 0 then fresh := true
              if h.committed.any fun (k', e, p) =>
                  k' + 1 ≤ k && e ≤ term && (st.log.take base).isPrefixOf p then
                chained := true
          if fresh || chained then
            newCommits := newCommits.push { k, leader, term, index, part, fresh, chained }
  for r in newCommits do
    unless h.isCommitted k r.term r.part do
      h := { h with committed := h.committed.push (k, r.term, r.part) }
  return { h with commits := h.commits ++ newCommits }

def ofRun (config : Finset NodeID) (states : List Model.State) : Hist :=
  states.foldl push { config }

end Hist

/-! ## State classes (all 29) on `h_k`

The proof of `committed_logs_comparable` quantifies over two nodes `left`, `right` of the
newest state; every later witness (the backing part of each, the `Committed.shape` witness,
the earlier leader) is an existential of the class, so a class holds if SOME choice of them
takes its case. With `left = right` and the same part, every comparison case (`inl` and `inr`
of `committed_comparable`, `le_total`, `canon_chain`, `suffix_comparable`) holds as soon as
the comparison is reached. -/

def stateClasses (h : Hist) (k : Nat) : List (String × Tri) := Id.run do
  let some s := h.states[k]? | return []
  let backing (st : NodeState) : List (Nat × List Entry) :=
    (h.committed.toList.filter fun (k', _, p) =>
      k' ≤ k && (st.log.take st.commitIndex).isPrefixOf p).map fun (_, t, p) => (t, p)
  let zero := s.nodes.any fun (_, st) => st.commitIndex == 0
  let parts := (s.nodes.flatMap fun (_, st) => backing st).eraseDups
  let backed := !parts.isEmpty
  -- a pair of backing parts with different terms: the `lt` case of `inCanon`
  let lower := parts.filter fun (t, _) => parts.any fun (t', _) => t < t'
  let lt := !lower.isEmpty
  let records (t : Nat) (p : List Entry) :=
    h.commits.toList.filter fun r => r.k ≤ k && r.term == t && r.part == p
  let twoInl := lower.any fun (t, p) => (records t p).any fun r =>
    t == BOOTSTRAP_TERM && r.leader == h.initialPrimary
  let twoInr := lower.any fun (t, p) => (records t p).any fun r => h.elected r.k r.leader t
  let shapeFresh := parts.any fun (t, p) => (records t p).any (·.fresh)
  let shapeChained := parts.any fun (t, p) => (records t p).any (·.chained)
  let shapePast := parts.any fun (t, p) => k > 0 && h.isCommitted (k - 1) t p
  let b := Tri.ofBool
  return [
    ("state_committed_logs_comparable_left_backed_inl", b zero),
    ("state_committed_logs_comparable_left_backed_inr", b backed),
    ("state_committed_logs_comparable_right_backed_inl", b (backed && zero)),
    ("state_committed_logs_comparable_right_backed_inr", b backed),
    ("state_committed_logs_comparable_committed_comparable_inl", b backed),
    ("state_committed_logs_comparable_committed_comparable_inr", b backed),
    ("state_committed_comparable_le_total_inl", b backed),
    ("state_committed_comparable_le_total_inr", b backed),
    ("state_committed_comparable_eq_or_lt_of_le_inl", b backed),
    ("state_committed_comparable_eq_or_lt_of_le_inr", b lt),
    ("state_committed_comparable_canon_chain_inl", b backed),
    ("state_committed_comparable_canon_chain_inr", b backed),
    ("state_canon_chain_suffix_comparable_inl", b backed),
    ("state_canon_chain_suffix_comparable_inr", b backed),
    ("state_suffix_comparable_le_total_inl", b backed),
    ("state_suffix_comparable_le_total_inr", b backed),
    ("state_shape_committed_fresh", b shapeFresh),
    ("state_shape_committed_chained", b shapeChained),
    ("state_shape_committed_past", b shapePast),
    -- `termAt_take` at the shape index of the lower part: a signature index, never 0
    ("state_termAt_take_zero_pos", b false),
    ("state_termAt_take_zero_neg", b lt),
    ("state_two_le_led_inl", b twoInl),
    ("state_two_le_led_inr", b twoInr),
    -- reached in `prefix_committable` from `committed_in_canon`; the induction's head/tail
    -- are unbound existentials in the generated classes, so every case holds when reached
    ("state_signatureIndex_le_maxCommittableIndex_values_nil", b lt),
    ("state_signatureIndex_le_maxCommittableIndex_values_cons", b lt),
    ("state_signatureIndex_le_maxCommittableIndex_mem_cons_inl", b lt),
    ("state_signatureIndex_le_maxCommittableIndex_mem_cons_inr", b lt),
    ("state_signatureIndex_le_maxCommittableIndex_signature_pos", b lt),
    ("state_signatureIndex_le_maxCommittableIndex_signature_neg", b lt) ]

/-! ## Step classes of `election_safety`, `canon_mono`, `completeness` at the step
`h_(k-1) -> h_k` -/

def stepClasses2 (probe : List NodeID) (h : Hist) (k : Nat) (s : Step) : List (String × Tri) :=
  Id.run do
  let some after := h.states[k]? | return []
  let some before := h.states[k - 1]? | return []
  let t := s.post.currentTerm
  -- `Led` pairs after and before
  let ledPairs (k : Nat) : List (NodeID × Nat) :=
    ((h.ids.map fun n => (n, BOOTSTRAP_TERM)).filter fun (n, t) => h.led k n t)
      ++ (h.elects.toList.filter (·.k ≤ k)).map fun e => (e.node, e.term)
  let ledA := (ledPairs k).eraseDups
  let ledB (n t : Nat) := h.led (k - 1) n t
  let electNow (n t : Nat) := h.electNow k n t
  -- election_safety, path reach_56: a new pair of leaders of one term
  let triples := ledA.flatMap fun (n, t) =>
    (ledA.filter (·.2 == t)).filterMap fun (o, _) =>
      if !(ledB n t && ledB o t) then some (n, o, t) else none
  let inl56 := triples.any fun (n, o, t) => ledB n t || (electNow n t && ledB o t)
  let inr56 := triples.any fun (n, o, t) => electNow o t && (ledB n t || electNow n t)
  -- canon_mono subjects, path reach_8: (node, state) with the clause's hypotheses new
  let hyps (k : Nat) (n : NodeID) (st : NodeState) :=
    st.role != .candidate && h.led k n st.currentTerm
  let nowB (n : NodeID) (st : NodeState) := before.nodes.any fun (n', st') => n' == n && stEq probe st' st
  let subjects8 := after.nodes.filter fun (n, st) => hyps k n st && !(nowB n st && hyps (k - 1) n st)
  -- completeness instances new at this step
  let commA := h.committed.toList.filter (·.1 ≤ k)
  let electA := h.elects.toList.filter (·.k ≤ k)
  let newInst := commA.flatMap fun (_, ct, p) => (electA.filter fun e => ct < e.term).filterMap
    fun e => if !(h.isCommitted (k - 1) ct p && e.k + 1 ≤ k) then some (ct, p, e) else none
  let recsNow := h.commits.toList.filter (·.k == k)
  let derivedNow (ct : Nat) (p : List Entry) (fresh : Bool) :=
    recsNow.any fun r => r.term == ct && r.part == p && (if fresh then r.fresh else r.chained)
  -- canon_mono subjects via reach_9 (completeness -> canon_mono on the committing leader);
  -- its generated condition is truncated in print, so these subjects only give "unknown"
  let subjects9 := after.nodes.filter fun (n, st) =>
    recsNow.any fun r => r.leader == n && newInst.any fun (ct, p, _) => ct == r.term && p == r.part
      && hyps k n st
  let cmOf (sub : List (NodeID × NodeState)) : List Bool :=
    let nowInr := sub.any fun (n, st) => n != s.actor && nowB n st
    let canonInl := sub.any fun (_, st) => !(h.canonLogs (k - 1) st.currentTerm).isEmpty
    let canonInr := !sub.isEmpty
    let elInl := sub.any fun (n, st) => h.elected (k - 1) n st.currentTerm
    let elInr := sub.any fun (n, st) => electNow n st.currentTerm
    [!sub.isEmpty, canonInl, canonInr, elInl, elInr, nowInr]
  let cm8 := cmOf subjects8
  let cm9 := cmOf subjects9
  let cmNames := ["step_canon_mono_now_after_inl", "step_canon_mono_canon_after_inl",
    "step_canon_mono_canon_after_inr", "step_canon_mono_elected_after_inl",
    "step_canon_mono_elected_after_inr", "step_canon_mono_now_after_inr"]
  -- now_after_inl is the subject being (actor, post)
  let nowInl8 := subjects8.any fun (n, st) => n == s.actor && stEq probe st s.post
  let nowInl9 := subjects9.any fun (n, st) => n == s.actor && stEq probe st s.post
  let cm8 := cm8.set 0 nowInl8
  let cm9 := cm9.set 0 nowInl9
  let cmTri := (cm8.zip cm9).map fun (a, b) => Tri.paths a b
  -- election_safety via canon_mono (reach_57: subject (actor, post) with an old canon log of
  -- its term; reach_58: the same through reach_9) and via commit_backed accept (reach_59)
  let actorHyps := hyps k s.actor s.post
  let oldCanon := !(h.canonLogs (k - 1) t).isEmpty
  let p57 := nowInl8 && oldCanon
  let p58 := nowInl9 && oldCanon
  let acceptKind := ((stepClasses probe s).lookup "step_commit_backed_kind_accept") == some .yes
  let p59term : Option Nat := match s.event with
    | .receive source (.appendEntriesRequest req) =>
      if acceptKind && actorHyps
          && (h.canonLogs (k - 1) req.term).any (·.1 == source) then some req.term else none
    | _ => none
  -- on these paths the left leader is an old canon leader (so `Led` before), the right the actor
  let esInl := Tri.paths (inl56 || p57 || p59term.isSome) p58
  let esInr := Tri.paths (inr56 || (p57 && electNow s.actor t)
      || (p59term.any fun rt => electNow s.actor rt)) (p58 && electNow s.actor t)
  -- completeness
  let cFresh := newInst.any fun (ct, p, _) => derivedNow ct p true
  let cChained := newInst.any fun (ct, p, _) => derivedNow ct p false
  let cPast := newInst.any fun (ct, p, _) => h.isCommitted (k - 1) ct p
  return [ ("step_election_safety_led_after_inl", esInl),
    ("step_election_safety_led_after_inr", esInr) ]
    ++ cmNames.zip cmTri
    ++ [ ("step_completeness_committed_fresh", .ofBool cFresh),
      ("step_completeness_committed_chained", .ofBool cChained),
      ("step_completeness_committed_past", .ofBool cPast) ]

/-! ## Runs -/

/-- A run: its initial configuration and its steps (each with its before and after state). -/
structure Run where
  config : Finset NodeID
  steps : List Step

structure Row where
  run : Nat
  pre : List (String × Tri)
  sig : List (String × Tri)
  post : List (String × Tri)

def evalRun (probe : List NodeID) (i : Nat) (r : Run) : List Row := Id.run do
  let some first := r.steps.head? | return []
  let states := first.before :: r.steps.map (·.after)
  let h := Hist.ofRun r.config states
  let mut out := []
  for (s, k) in r.steps.zipIdx 1 do
    let row := Row.mk i (stateClasses h (k - 1))
      (stepClasses probe s ++ stepClasses2 probe h k s) (stateClasses h k)
    out := out ++ [row]
  return out

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

def mkStepAction (configuration : Finset NodeID) (nodes : List NodeID) (state : Model.State)
    (action : Model.Action) : Option Step := do
  let system := Model.transitionSystem configuration nodes
  let (actor, event) := match action with
    | .local node input => (node, Event.internal input)
    | .deliver e => (e.target, Event.receive e.source e.payload)
  let after ← system.step state action
  let pre ← nodeState state actor
  let post ← nodeState after actor
  return { before := state, after, actor, pre, post, event }

/-- The local inputs offered to node `n` in `state` (the walk's alphabet besides deliveries). -/
def alphabet (nodes : List NodeID) (state : Model.State) (n : NodeID) (i : Nat)
    : List Model.Action :=
  let len := ((nodeState state n).map (·.log.length)).getD 0
  let snapshots : List (List Entry) := nodes.filterMap fun p => do
    let st ← nodeState state p
    let m := maxCommittableIndex st.log
    if p != n && m > 0 then some (st.log.take m) else none
  [ .local n (.timeout .election), .local n (.timeout .checkQuorum),
    .local n (.append [{ content := .signature }]),
    .local n (.append [{ content := .transaction (10 * i) {} }]),
    .local n (.append [{ content := .transaction (10 * i + 1) { configuration := some {0, 1, 2} } }]),
    .local n (.append [{ content := .transaction (10 * i + 2) { configuration := some {0, 1} } }]),
    .local n (.append [{ content := .transaction (10 * i + 3) { configuration := some {1, 2} } }]),
    .local n .nominateSuccessor, .local n (.initAsBackup []) ]
  ++ snapshots.map (fun e => .local n (.initAsBackup e))
  ++ (nodes.filter (· != n)).map fun p => .local n (.sendEntries p len)

/-- Bounded random walks from the initial state of `configuration` with nodes `[0, 1, 2]`. At
each state the enabled actions are the deliveries of queued envelopes and `alphabet` for each
node (an action is enabled if the model's step function returns a state). With probability
2/3, when any delivery is enabled, a delivery is chosen uniformly among the enabled
deliveries; otherwise an action uniformly among all enabled actions. LCG seeded per call. -/
def randomRuns (configuration : Finset NodeID) (runs length : Nat) (seed : Nat) : List Run :=
  Id.run do
  let nodes : List NodeID := [0, 1, 2]
  let mut rng := seed
  let mut out : Array Run := #[]
  for _ in [0:runs] do
    let mut state := initialState configuration nodes
    let mut steps : Array Step := #[]
    for i in [0:length] do
      let locals := nodes.flatMap fun n => alphabet nodes state n i
      let candidates := (state.network.map (fun e => (.deliver e : Model.Action)) ++ locals).filterMap
        fun a => mkStepAction configuration nodes state a
      if candidates.isEmpty then break
      rng := (rng * 6364136223846793005 + 1442695040888963407) % 18446744073709551616
      let deliveries := candidates.filter fun st => match st.event with
        | .receive _ _ => true | _ => false
      let pool := if deliveries.isEmpty || (rng / 65536) % 3 == 0 then candidates else deliveries
      let some st := pool[(rng / 4294967296) % pool.length]? | break
      steps := steps.push st
      state := st.after
    out := out.push { config := configuration, steps := steps.toList }
  return out.toList

def canonical : Except String (List Run) := do
  let (a, _) ← runSteps {0, 1, 2} [0, 1, 2] (initialState {0, 1, 2} [0, 1, 2]) clientRequestCommits
  let expected : List Entry := [
    { term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some {0} } },
    { term := BOOTSTRAP_TERM, content := .transaction 10 {} },
    { term := BOOTSTRAP_TERM, content := .signature },
    { term := BOOTSTRAP_TERM, content := .transaction 20 { configuration := some {0, 1, 2} } },
    { term := BOOTSTRAP_TERM, content := .signature } ]
  let mut state := initialState {0} [0, 1, 2]
  let mut out := []
  for acts in reconfigureElectAndCommit expected do
    let (b, s) ← runSteps {0} [0, 1, 2] state acts
    out := out ++ b
    state := s
  return [{ config := {0, 1, 2}, steps := a }, { config := {0}, steps := out }]

/-! ## Report -/

def electionClauses : List String := ["leader_led", "election_safety"]
def logClauses : List String := ["canon_mono", "completeness", "commit_backed"]

def inClauses (cs : List String) (name : String) : Bool :=
  cs.any fun c => (name.splitOn s!"step_{c}_").length > 1

def key (l : List (String × Tri)) : String := String.join (l.map (triStr ·.2))

def summarise (title : String) (rows : List Row) (keep : String → Bool) : IO Unit := do
  let obsOf (r : Row) := s!"{key r.pre} {key (r.sig.filter (keep ·.1))} {key r.post}"
  let sigs := (rows.map fun r => key (r.sig.filter (keep ·.1))).eraseDups
  let obs := (rows.map obsOf).eraseDups
  IO.println s!"-- {title}: {sigs.length} distinct signatures, {obs.length} distinct observations"
  for sg in sigs do
    IO.println s!"  sig {(rows.filter fun r => key (r.sig.filter (keep ·.1)) == sg).length}\t{sg}"
  for o in obs do
    IO.println s!"  obs {(rows.filter fun r => obsOf r == o).length}\t{o}"

def report (label : String) (rows : List Row) (elapsedUs : Nat) : IO Unit := do
  let decisions := rows.foldl (fun acc r => acc + r.pre.length + r.sig.length + r.post.length) 0
  IO.println s!"== {label}: {rows.length} steps, {decisions} class decisions, {elapsedUs} us"
  let names := (rows.head?.map (·.sig.map (·.1))).getD []
  IO.println "yes\tno\tunknown\tstep class (signature order)"
  for n in names do
    let vals := rows.map fun r => (r.sig.lookup n).getD .unknown
    IO.println s!"{vals.count .yes}\t{vals.count .no}\t{vals.count .unknown}\t{n}"
  let snames := (rows.head?.map (·.pre.map (·.1))).getD []
  IO.println "yes\tno\tunknown\tstate class (context order), over the after-states"
  for n in snames do
    let vals := rows.map fun r => (r.post.lookup n).getD .unknown
    IO.println s!"{vals.count .yes}\t{vals.count .no}\t{vals.count .unknown}\t{n}"
  let ctxs := (rows.flatMap fun r => [key r.pre, key r.post]).eraseDups
  IO.println s!"distinct contexts {ctxs.length}"
  for c in ctxs do
    IO.println s!"  ctx {(rows.filter fun r => key r.post == c).length}\t{c}"
  summarise "all evaluated step classes" rows fun _ => true
  summarise "election safety (leader_led, election_safety)" rows (inClauses electionClauses)
  summarise "log safety (canon_mono, completeness, commit_backed)" rows (inClauses logClauses)

def timed (probe : List NodeID) (runs : List Run) : IO (List Row × Nat) := do
  let t0 ← IO.monoNanosNow
  let rows := (runs.zipIdx).flatMap fun (r, i) => evalRun probe i r
  let n := rows.foldl (fun acc (r : Row) => acc + (key r.pre).length + (key r.sig).length + (key r.post).length) 0
  let t1 ← IO.monoNanosNow
  if n == 0 then IO.println "empty"
  return (rows, (t1 - t0) / 1000)

#eval show IO Unit from do
  let probe : List NodeID := [0, 1, 2, 1000]
  match canonical with
  | .error e => throw (IO.userError e)
  | .ok runs =>
    let (rows, us) ← timed probe runs
    report "canonical traces" rows us
  let runs := (← IO.getEnv "RUNS").bind String.toNat? |>.getD 0
  let length := (← IO.getEnv "LENGTH").bind String.toNat? |>.getD 40
  if runs > 0 then
    let mut all : List Row := []
    let mut total := 0
    for (config, seed) in [(({0} : Finset NodeID), 42), ({0, 1}, 43), ({0, 1, 2}, 44)] do
      let rs := randomRuns config runs length seed
      let stuck := rs.filter (·.steps.length < length)
      IO.println s!"## initial configuration {config.val}: {rs.length} runs, {stuck.length} ended early with no enabled action, mean length {(rs.foldl (· + ·.steps.length) 0) / max 1 rs.length}"
      for r in stuck.take 2 do
        let last := (r.steps.getLast?.map (·.after)).getD (initialState config [0, 1, 2])
        IO.println s!"##   stuck after {r.steps.length} steps: roles {last.nodes.map fun (n, st) => (n, repr st.role, st.log.length, st.commitIndex)}, network {last.network.length}, last event {(r.steps.getLast?.map fun st => match st.event with | .internal i => inputKind i | .receive _ _ => "receive").getD ""}"
      let (rows, us) ← timed probe rs
      IO.println s!"## initial configuration {config.val}: {rows.length} steps, {us} us"
      report s!"random walks, initial configuration {config.val}, {runs} x up to {length}" rows us
      all := all ++ rows
      total := total + us
    report s!"random walks, all three initial configurations" all total

-- The evaluator's answers on the inputs of the Lean cross-checks (`crosscheck.lean`).
#eval show IO Unit from do
  let config : Finset NodeID := {0, 1, 2}
  let s0 := initialState config [0, 1, 2]
  let probe : List NodeID := [0, 1, 2, 1000]
  for a in [(.local 0 (.timeout .checkQuorum) : Model.Action), .local 0 (.sendEntries 1 1)] do
    let some st := mkStepAction config [0, 1, 2] s0 a | IO.println "disabled"
    for row in evalRun probe 0 { config, steps := [st] } do
      let pick (l : List (String × Tri)) (n : String) := triStr ((l.lookup n).getD .unknown)
      IO.println s!"crosscheck pre left_backed_inl={pick row.pre "state_committed_logs_comparable_left_backed_inl"} left_backed_inr={pick row.pre "state_committed_logs_comparable_left_backed_inr"} step leader_led_now_after_inl={pick row.sig "step_leader_led_now_after_inl"}"

end ConsensusCoverage.EvalClasses
