module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import MidTrace.Cut
meta import MidTrace.GenLower
meta import MidTrace.GroupJson
meta import MidTrace.InitInvariant
meta import MidTrace.SmtSession
meta import MidTrace.StateJson

public import MidTrace.Cut
public import MidTrace.GenLower
public import MidTrace.GroupJson
public import MidTrace.InitInvariant
public import MidTrace.SmtSession
public import MidTrace.StateJson

@[expose] public section

namespace Consensus.MidTrace.Tests.Validation

open Model.Node Gen

def node (c : Ctx) (s : NodeState) : GM SNode := do
  let role :=
    match s.role with
    | .none => ROLE_NONE
    | .follower => ROLE_FOLLOWER
    | .preVoteCandidate => ROLE_PREVOTE
    | .candidate => ROLE_CANDIDATE
    | .primary => ROLE_PRIMARY
  let code (o : Option Nat) := Smt.Tm.int ((o.map Int.ofNat).getD (-1))
  return {
    role := .int role,
    ct := .int s.currentTerm,
    log := ← literalLog c s.log,
    ci := .int s.commitIndex
    sent := c.nodes.toArray.map fun j => .int (s.sentIndex j)
    mi := c.nodes.toArray.map fun j => .int (s.matchIndex j)
    nf := .bool s.isNewFollower,
    vf := code s.votedFor,
    pk := .bool s.primaryKnown
    votes := c.bitsOf s.votesGranted,
    pv := c.bitsOf s.preVotesGranted,
    rci := code s.retiredCommittedIndex
  }

def message (c : Ctx) : Message → GM SMsg
  | .appendEntriesRequest r => do
      mkMsg c TAG_AE (.int r.term)
        [
          (M_PREV, .int r.prevLogIndex),
          (M_PREV_TERM, .int r.prevLogTerm),
          (M_PRIMARY_COMMIT, .int r.primaryCommit)
        ]
        (← literalLog c r.entries)
  | .appendEntriesResponse r =>
      mkMsg c TAG_AER (.int r.term)
        [(M_SUCCESS, .bool r.success), (M_LAST_LOG, .int r.lastLogIndex)]
  | .requestVoteRequest r =>
      mkMsg c TAG_RV (.int r.term)
        [
          (M_LC_TERM, .int r.lastCommittableTerm),
          (M_LC_INDEX, .int r.lastCommittableIndex)
        ]
  | .requestPreVoteRequest r =>
      mkMsg c TAG_RPV (.int r.term)
        [
          (M_LC_TERM, .int r.lastCommittableTerm),
          (M_LC_INDEX, .int r.lastCommittableIndex)
        ]
  | .requestVoteResponse r =>
      mkMsg c TAG_RVR (.int r.term) [(M_GRANTED, .bool r.voteGranted)]
  | .requestPreVoteResponse r =>
      mkMsg c TAG_RPVR (.int r.term) [(M_GRANTED, .bool r.voteGranted)]
  | .proposeRequestVoteRequest t => mkMsg c TAG_PROPOSE (.int t) []

/-- Run both independent checkers, requiring the expected verdict and clauses. -/
def checkBoth (h : Replay.Header) (s : Model.State) (reject : Option String := none)
    (rejectSymbolic := reject)
    : Except String Unit := do
  let c := { n := h.declared.length : Ctx }
  let build : GM Unit := do
    let nodes ← s.nodes.toArray.mapM fun (_, a) => node c a
    let msgs ← s.network.toArray.mapM fun e => do return (e, ← message c e.payload)
    InitInvariant.constrain c h.bootstrap nodes
    for (e, m) in msgs do
      InitInvariant.constrainMessage e.source e.target (fun i => nodes[i]!) (.bool true) m
  let (_, enc) := lower (build.run {}).2 {} #[(0, 127)]
  if let some (_, why) := enc.unsupported then throw why
  let concrete :=
    match InitInvariant.check h.bootstrap s with
    | .error why => some why
    | .ok () => none
  let symbolic := enc.falsified.map Prod.snd
  for (reason, expected) in [(concrete, reject), (symbolic, rejectSymbolic)] do
    unless reason == expected do
      throw s!"expected {expected}, got {reason}"

private def header : Replay.Header := { bootstrap := {0, 1}, declared := ["A", "B"] }

private def rejects : Except String Unit := do
  let h := header
  checkBoth h h.initial
  let a := Model.initialNodeState h.bootstrap 0
  let b := Model.initialNodeState h.bootstrap 1
  let state (x y : NodeState) : Model.State := { nodes := [(0, x), (1, y)] }
  let sig (t : Nat) : Entry := ⟨t, .signature⟩
  checkBoth h (state { a with currentTerm := 3, log := a.log ++ [sig 3, sig 2] } b)
    "node 0: terms_sorted"
  checkBoth h (state a a) "nodes 0, 1: election_safety"
  let bad := { h.initial with network := [⟨0, 1, .proposeRequestVoteRequest 3⟩] }
  checkBoth h bad "message_invariants: 0 -> 1"
  let committed (s : NodeState) (req : Nat) :=
    { s with log := a.log ++ [⟨2, .transaction req {}⟩, sig 2], commitIndex := 3 }
  checkBoth h (state (committed a 1) (committed b 2))
    "nodes 0, 1: committed_logs_comparable" "node 1: committed_logs_comparable"

/-- A declared log of length 128 with the bootstrap root, terms 3 on `[60, 64]` and a
signature of term `sigTerm` at 127; the rest is gap. -/
private def gapLog (c : Ctx) (h : Replay.Header) (sigTerm : Nat) : GM SList := do
  let l ← declareLog c (.int 128)
  let root :=
    entryRecord c (.int 2) (.transaction 0 { configuration := some h.bootstrap })
  let sig := entryRecord c (.int sigTerm) .signature
  let arrs ←
    l.arrs.mapIdxM
      fun i a => do
        let a ← store (← store a (.int 0) root[i]!) (.int 127) sig[i]!
        if i != E_TERM then return a
        [60, 61, 62, 63, 64].foldlM (fun a k => store a (.int k) (.int 3)) a
  return { l with arrs }

private def gaps : Except String Unit := do
  let h := header
  let c : Ctx := ⟨2⟩
  let primary := { (Model.initialNodeState h.bootstrap 0) with currentTerm := 3 }
  let candidate :=
    {
      primary with
        role := .candidate,
        currentTerm := 4,
        votedFor := some 1,
        votesGranted := {1},
        primaryKnown := false
    }
  let build := do
    let nodes ←
      #[primary, candidate].mapM
        fun s => do
          return { (← node c s) with ci := .int 128, log := ← gapLog c h 3 }
    InitInvariant.constrain c h.bootstrap nodes
  let (ls, enc) := lower (build.run {}).2 {} #[(0, 0), (60, 64), (127, 127)]
  if let some (_, why) := enc.unsupported then throw why
  if let some (_, why) := enc.falsified then throw why
  unless ls.probed > 0 && ls.enumerated.isEmpty do
    throw "term-3 gap was not summarized"

/-- Nodes 0 and 2 commit conflicting logs while node 1 commits nothing, so only the
shared committed log relates them. -/
private def conflicts : Except String Unit := do
  let h : Replay.Header := { bootstrap := {0, 1, 2}, declared := ["A", "B", "C"] }
  let init := Model.initialNodeState h.bootstrap
  let committed (s : NodeState) (req : Nat) :=
    {
      s with
        log := (init 0).log ++ [⟨2, .transaction req {}⟩, ⟨2, .signature⟩],
        commitIndex := 3
    }
  let state (x z : NodeState) : Model.State := { nodes := [(0, x), (1, init 1), (2, z)] }
  checkBoth h (state (committed (init 0) 1) (committed (init 2) 1))
  checkBoth h (state (committed (init 0) 1) (committed (init 2) 2))
    "nodes 0, 2: committed_logs_comparable" "node 2: committed_logs_comparable"
  -- The same conflict at index 127, with summarized gaps either side of `[60, 64]`.
  let c : Ctx := ⟨3⟩
  let build := do
    let nodes ←
      #[
        ({ init 0 with currentTerm := 3 }, 3),
        (init 1, 0),
        ({ init 2 with currentTerm := 4 }, 4)
      ].mapM
        fun (s, sigTerm) => do
          if sigTerm == 0 then return ← node c s
          return { (← node c s) with ci := .int 128, log := ← gapLog c h sigTerm }
    InitInvariant.constrain c h.bootstrap nodes
  let (ls, enc) := lower (build.run {}).2 {} #[(0, 0), (60, 64), (127, 127)]
  if let some (_, why) := enc.unsupported then throw why
  let reason := enc.falsified.map Prod.snd
  unless reason == some "node 2: committed_logs_comparable" do
    throw s!"expected the gap conflict to be rejected, got {reason}"
  unless ls.probed > 0 && ls.enumerated.isEmpty do
    throw "conflicting logs' gaps were not summarized"

private def roundTrip : Except String Unit := do
  let h := header
  let e : Entry :=
    ⟨4, .transaction 17 { configuration := some {1}, retirementConfirmations := {0} }⟩
  let s :=
    {
      (Model.initialNodeState h.bootstrap 0) with
        log := [e, ⟨4, .signature⟩],
        role := .preVoteCandidate,
        currentTerm := 4,
        sentIndex := (· + 1),
        matchIndex := (· + 2),
        isNewFollower := true,
        votedFor := some 0,
        votesGranted := {0},
        preVotesGranted := {1},
        retiredCommittedIndex := some 1,
        commitIndex := 2
    }
  let vote : RequestVoteRequest := ⟨4, 3, 7⟩
  let msgs : List Message :=
    [
      .appendEntriesRequest ⟨4, 2, 3, [e], 1⟩,
      .appendEntriesResponse ⟨4, true, 2⟩,
      .requestVoteRequest vote,
      .requestVoteResponse ⟨4, false⟩,
      .requestPreVoteRequest vote,
      .requestPreVoteResponse ⟨3, true⟩,
      .proposeRequestVoteRequest 4
    ]
  let state : Model.State :=
    { nodes := [(0, s), (1, s)], network := msgs.map (⟨0, 1, ·⟩) }
  let json := encodeState h state
  if (decodeState h (encodeState h { state with nodes := state.nodes.reverse })).isOk then
    throw "accepted nodes out of ID order"
  let decoded ← decodeState h (← Lean.Json.parse json.compress)
  let some actual := decoded.nodes.lookup 0 | throw "node missing from decoded state"
  unless actual.log == s.log
          && actual.retiredCommittedIndex == s.retiredCommittedIndex
          && (List.range 2).all
              (fun i =>
                actual.sentIndex i == s.sentIndex i
                && actual.matchIndex i == s.matchIndex i)
          && decoded.network == state.network
          && encodeState h decoded == json do
    throw "state round-trip mismatch"
  let undeclared : Entry := ⟨4, .transaction 1 { retirementConfirmations := {5} }⟩
  for bad
      in [
        { state with nodes := [(0, { s with votedFor := some 999 }), (1, s)] },
        { state with nodes := [(0, { s with log := [undeclared] }), (1, s)] },
        { state with network := [⟨0, 999, .proposeRequestVoteRequest 4⟩] },
        {
          state with
            network := [⟨0, 1, .appendEntriesRequest ⟨4, 2, 3, [undeclared], 1⟩⟩]
        }
      ] do
    if (decodeState h (encodeState h bad)).isOk then
      throw "accepted an undeclared node id"

deriving instance BEq for Replay.Origin, Replay.StateSnapshot

private def sameStep : Replay.Step → Replay.Step → Bool
  | .local n i, .local n' i' => n == n' && i == i'
  | .receive s d p, .receive s' d' p' => s == s' && d == d' && p == p'
  | .initAsBackup n i v, .initAsBackup n' i' v' => n == n' && i == i' && v == v'
  | _, _ => false

private def sameInstruction : Replay.Instruction → Replay.Instruction → Bool
  | .action s o, .action s' o' => sameStep s s' && o == o'
  | .observeNodeState n e o, .observeNodeState n' e' o' => n == n' && e == e' && o == o'
  | .observeSends ss o, .observeSends ss' o' =>
      ss.length == ss'.length
      && (ss.zip ss').all
          (fun (a, b) =>
            a.target == b.target && a.packet == b.packet && a.origin == b.origin)
      && o == o'
  | _, _ => false

private def sameGroup (a b : Replay.Group) : Bool :=
  a.node == b.node
  && a.start == b.start
  && a.m_ts == b.m_ts
  && a.ts == b.ts
  && a.instructions.size == b.instructions.size
  && (a.instructions.zip b.instructions).all fun (i, j) => sameInstruction i j

/-- Every group variant survives NDJSON, and any one line decodes on its own. -/
private def groupCodec : Except String Unit := do
  let h : Replay.Header := { bootstrap := {0}, declared := ["A", "B", "C"] }
  let o (rule : String) : Replay.Origin := ⟨"trace", 7, rule⟩
  let big := 4611686018427387905
  let entry : Entry :=
    ⟨big, .transaction 5 { configuration := some {0, 2}, retirementConfirmations := {1} }⟩
  let vote : Replay.Packet.RequestVote :=
    { term := 3, last_committable_idx := 2, term_of_last_committable_idx := 1 }
  let packets : List Replay.Packet :=
    [
      .appendEntries
        {
          term := big,
          prev_idx := 1,
          prev_term := 2,
          idx := 4,
          leader_commit_idx := 1,
          term_of_idx := 3,
          contains_new_view := true
        },
      .appendEntriesResponse { term := 3, last_log_idx := 4, success := "OK" },
      .requestVote vote,
      .requestPreVote vote,
      .requestVoteResponse { term := 3, vote_granted := true },
      .requestPreVoteResponse { term := 2, vote_granted := false },
      .proposeRequestVote { term := 4 }
    ]
  let inputs : List Input :=
    [
      .append
        [
          {
            content := .transaction 6 { retirementConfirmations := {2} },
            flushes := [(1, 4), (2, 3)]
          },
          { content := .signature }
        ],
      .sendEntries 2 9,
      .timeout .election,
      .timeout .checkQuorum,
      .nominateSuccessor,
      .initAsBackup [entry, ⟨3, .signature⟩]
    ]
  let snapshot : Replay.StateSnapshot :=
    {
      node_id := "A",
      current_view := some 3,
      last_idx := some 4,
      commit_idx := some 2,
      leadership_state := some "Leader",
      membership_state := some "Retired",
      committable_indices := some [3, 4],
      retirement_phase := some "Ordered",
      retirement_idx := some 4,
      retirement_committable_idx := some 4,
      retired_committed_idx := some 1
    }
  let steps : List Replay.Step :=
    inputs.map (.local "A" ·)
    ++ packets.map (.receive "B" "A" ·)
    ++ [.initAsBackup "C" 4 3]
  let instructions : Array Replay.Instruction :=
    (steps.map (.action · (o "step"))).toArray
    ++ #[
      .observeNodeState "A" snapshot (o "state"),
      .observeNodeState "B" { (default : Replay.StateSnapshot) with node_id := "B" }
        (o "bare"),
      .observeSends (packets.map (⟨"C", ·, o "send"⟩)) (o "sends")
    ]
  let groups : Array Replay.Group :=
    #[⟨"A", 3, 10, some 20, instructions⟩, ⟨"B", 0, 11, none, #[]⟩]
  let lines := groups.toList.map fun g => (encodeGroup h g).compress
  let (decodedHeader, decoded) ← decodeGroups ("\n".intercalate lines ++ "\n\n") ["A"]
  unless decodedHeader.declared == h.declared && decodedHeader.bootstrap == h.bootstrap do
    throw "header round-trip mismatch"
  unless decoded.size == groups.size
          && (decoded.zip groups).all fun (a, b) => sameGroup a b do
    throw "group round-trip mismatch"
  -- A slice names only its own nodes, so they are renumbered.
  let send : Replay.Group :=
    ⟨"A", 0, 0, none, #[.action (.local "A" (.sendEntries 2 9)) (o "send")]⟩
  let (sliced, #[resent]) ← decodeGroups (encodeGroup h send).compress
  | throw "expected one group"
  unless sliced.declared == ["A", "C"]
          && !sliced.bootstrap.Nonempty
          && sameGroup resent
              {
                send with
                  instructions := #[.action (.local "A" (.sendEntries 1 9)) (o "send")]
              } do
    throw "slice was not renumbered"
  for bad in ["", "\n \n", "{", (encodeGroup h { send with node := "" }).compress] do
    if (decodeGroups bad).isOk then throw s!"accepted bad groups {bad}"
  if (decodeGroups lines[1]! [""]).isOk then throw "accepted a blank bootstrap node"

/-- Parentheses in string literals and comments do not nest. -/
private def sexps : Except String Unit := do
  match Smt.parseSExps
          "(error \"unexpected ')' \"\"(\"\"\") ; (\n((v1 (- 2)) (v2 |a)b|))" with
  | #[
    .list #[.atom "error", .atom _],
    .list #[.list #[.atom "v1", v], .list #[_, .atom "|a)b|"]]
  ] =>
      unless v.toInt? == some (-2) do
        throw "negative value"
  | _ => throw "string, comment or quoted symbol misparsed"

private def cuts : Except String Unit := do
  let h := header
  let group (n : String) (t : Nat) (i : Replay.Instruction) : Replay.Group :=
    ⟨n, 0, t, none, #[i]⟩
  let sig :=
    group "A" 10 (.action (.local "A" (.append [{ content := .signature }])) default)
  let send := group "A" 9 (.action (.local "A" (.sendEntries 1 2)) default)
  let queues := #[#[sig, send]]
  for k in [:4] do
    let (s, pre, post) ← cutGroups h queues k
    unless pre.size == min k 2 && post.size == 2 - k do
      throw "wrong cut"
    checkBoth h s
    unless s.network.length == (if 2 <= k then 1 else 0) do
      throw "wrong pending packets"
  let ties :=
    orderGroups #[#[sig, send], #[{ sig with node := "B", ts := some 10, m_ts := 0 }]]
  unless ties.map (·.m_ts) == #[10, 9, 0] do
    throw "unstable head merge"

#eval IO.ofExcept rejects
#eval IO.ofExcept gaps
#eval IO.ofExcept conflicts
#eval IO.ofExcept roundTrip
#eval IO.ofExcept cuts
#eval IO.ofExcept sexps
#eval IO.ofExcept groupCodec

end Consensus.MidTrace.Tests.Validation
