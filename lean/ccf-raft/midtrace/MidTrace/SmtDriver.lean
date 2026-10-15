module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SmtModel
public import MidTrace.SymDriver

@[expose] public section

/-!
# SMT mid-trace validation

Encodes the suffix of a trace as one formula over an unknown initial state
(`SmtModel`), with every action guard and observation a hard assertion, and
asks an SMT solver for a model.

* `sat`: the model's initial state is replayed with `Replay.replayFrom`; the
  verdict is `valid` only if that replay passes.
* `unsat`: `invalid`. The formula over-approximates the model whenever the
  `cap` assumption is dropped, so an `unsat` core containing `cap` is
  rechecked without it.
* A hard assertion that folds to `false` while encoding decides `invalid`
  without calling the solver.
-/

namespace CCFRaft.MidTrace.Smt

open Lean CCFRaft.Replay CCFRaft.Model.Node

structure Settings where
  solver : String := "yices-smt2"
  invariants : Bool := true
  /-- Phantom messages per channel. -/
  Q : Nat := 32
  /-- Log cells beyond the largest index the suffix mentions. -/
  slack : Nat := 4
  refine : Bool := true
  /-- Name hard assertions and report an unsat core. -/
  explain : Bool := false
  /-- Fix the initial state to this one: a differential test of the encoding. -/
  pinned : Option ReplayState := none
  /-- Write the script to this path. -/
  dump : Option String := none

/-! ## Environment -/

/-- The largest natural number in `value`, ignoring origins. -/
partial def maxNat (value : Json) : Nat :=
  match value with
  | .num n => if n.exponent == 0 && n.mantissa >= 0 then n.mantissa.toNat else 0
  | .arr values => values.foldl (fun best value => max best (maxNat value)) 0
  | .obj fields =>
      fields.foldl
        (fun best key value => if key == "origin" then best else max best (maxNat value))
        0
  | _ => 0

def makeEnv (header : Header) (suffix : Array Json) (settings : Settings) : Env :=
  let names := header.declared.toArray
  let sorted :=
    ((List.range names.size).mergeSort fun a b => decide (names[a]! ≤ names[b]!)).toArray
  let ids :=
    suffix.foldl (fun found value => Sym.transactionIds value found) #["midtrace"]
  let txNames :=
    ids.foldl (fun table id => if table.contains id then table else table.push id) #[]
  let mentioned := suffix.foldl (fun best value => max best (maxNat value)) 0
  {
    header
    names
    sorted
    K := mentioned + settings.slack
    Q := settings.Q
    txNames
    boot := names.map fun name => decide (name ∈ header.bootstrap.configuration)
    preVote :=
      names.map fun name => decide (header.bootstrap.preVoteStatus name = .enabled)
    invariants := settings.invariants
  }

/-! ## System state -/

structure Sys where
  nodes : Array SNode
  initial : Array SNode
  chans : Std.HashMap (Nat × Nat) Chan := {}
  /-- Each channel's phantom count. -/
  initialP : Std.HashMap (Nat × Nat) Tm := {}

abbrev SM := StateT Sys EM

def entryInvariants (log : SLog) (ct : Tm) : EM Unit := do
  let K := (← read).K
  for k in [1:K + 1] do
    let cell := log.cells[k - 1]!
    let here ← present log k
    assumeInv (← impliesT here (← andL [← le (.int 1) cell.term, ← le cell.term ct]))
    if k >= 2 then
      assumeInv (← impliesT here (← le log.cells[k - 2]!.term cell.term))

def freshNode (self : Nat) : EM SNode := do
  let env ← read
  let n := env.n
  let role ← declare false ROLE_NONE ROLE_LEADER
  let ct ← declareNat
  let len ← declareNat
  assumeCap (← le len (.int env.K))
  let mut cells := #[]
  for _ in [0:env.K] do
    cells := cells.push (← freshEntry)
  let log : SLog := { len, cells }
  if env.invariants then entryInvariants log ct
  let _ := self
  return {
    role
    ct
    log
    ci := ← declareNat
    sent := ← (Array.range n).mapM fun _ => declareNat
    mi := ← (Array.range n).mapM fun _ => declareNat
    nf := ← declareBool
    vf := ← declare false (-1) n
    lk := ← declareBool
    votes := ← (Array.range n).mapM fun _ => declareBool
    pv := ← (Array.range n).mapM fun _ => declareBool
    rci := ← declare false (-1) INF
  }

/-! ### Pinned initial states -/

def roleCode : Role → Int
  | .none => ROLE_NONE
  | .follower => ROLE_FOLLOWER
  | .preVoteCandidate => ROLE_PRE_VOTE_CANDIDATE
  | .candidate => ROLE_CANDIDATE
  | .leader => ROLE_LEADER

def pinnedEntry (entry : Entry String String) : EM SEntry := do
  let env ← read
  let some value := knownEntry env (.int entry.term) entry.content
  | unsupported "pinned entry the encoding cannot represent"; return SEntry.dummy env.n
  return value

def pinnedNode (state : NodeState String String) : EM SNode := do
  let env ← read
  let n := env.n
  let entries ← state.log.toArray.mapM pinnedEntry
  let cells := (Array.range env.K).map fun k => entries[k]?.getD (SEntry.dummy n)
  let bits (nodes : Finset String) := bitsOf env nodes
  return {
    role := .int (roleCode state.role)
    ct := .int state.currentTerm
    log := { len := .int state.log.length, cells }
    ci := .int state.commitIndex
    sent := env.names.map fun name => .int (state.sentIndex name)
    mi := env.names.map fun name => .int (state.matchIndex name)
    nf := .bool state.isNewFollower
    vf :=
      .int
        (match state.votedFor with
          | none => -1
          | some name => ((env.names.idxOf? name).getD n : Nat))
    lk := .bool state.leaderKnown
    votes := bits state.votesGranted
    pv := bits state.preVotesGranted
    rci := .int ((state.retiredCommittedIndex.map Int.ofNat).getD (-1))
  }

def pinnedMsg (message : Message String String) : EM SMsg := do
  match message with
  | .appendEntriesRequest request =>
      let entries ← request.entries.toArray.mapM pinnedEntry
      return {
        kind := .int KIND_AE
        term := .int request.term
        a := .int request.prevLogIndex
        b := .int request.prevLogTerm
        c := .int request.leaderCommit
        count := .int entries.size
        ents := .list (← freshId) request.prevLogIndex entries
      }
  | .appendEntriesResponse response =>
      return {
        kind := .int KIND_AER
        term := .int response.term
        flag := .bool response.success
        a := .int response.lastLogIndex
      }
  | .requestVoteRequest request =>
      return {
        kind := .int KIND_RV
        term := .int request.term
        a := .int request.lastCommittableIndex
        b := .int request.lastCommittableTerm
      }
  | .requestPreVote request =>
      return {
        kind := .int KIND_RPV
        term := .int request.term
        a := .int request.lastCommittableIndex
        b := .int request.lastCommittableTerm
      }
  | .requestVoteResponse response =>
      return {
        kind := .int KIND_RVR,
        term := .int response.term,
        flag := .bool response.voteGranted
      }
  | .requestPreVoteResponse response =>
      return {
        kind := .int KIND_RPVR,
        term := .int response.term,
        flag := .bool response.voteGranted
      }
  | .proposeVoteRequest term => return { kind := .int KIND_PROPOSE, term := .int term }

def initialSys (pinned : Option ReplayState) : EM Sys := do
  let env ← read
  match pinned with
  | none =>
      let nodes ← (Array.range env.n).mapM freshNode
      return { nodes, initial := nodes }
  | some replay =>
      let nodes ←
        env.names.mapM
          fun name => do
            match (replay.state.nodes.lookup name) with
            | some state => pinnedNode state
            | none =>
                unsupported s!"pinned state has no node {name}"
                return default
      let mut chans : Std.HashMap (Nat × Nat) Chan := {}
      let mut initialP : Std.HashMap (Nat × Nat) Tm := {}
      for src in [0:env.n] do
        for dst in [0:env.n] do
          let pending := replay.pending env.names[src]! env.names[dst]!
          let mut phantoms : Std.HashMap Nat SMsg := {}
          for h : x in [0:pending.length] do
            phantoms := phantoms.insert x (← pinnedMsg pending[x].payload)
          let p : Tm := .int pending.length
          chans := chans.insert (src, dst) { p, phantoms }
          initialP := initialP.insert (src, dst) p
      return { nodes, initial := nodes, chans, initialP }

def chanOf (src dst : Nat) : SM Chan := do
  if let some ch := (← get).chans[(src, dst)]? then return ch
  let p ← declareNat
  assumeCap (← le p (.int (← read).Q))
  let ch : Chan := { p }
  modify
    fun sys =>
      {
        sys with
          chans := sys.chans.insert (src, dst) ch,
          initialP := sys.initialP.insert (src, dst) p
      }
  return ch

def setChan (src dst : Nat) (ch : Chan) : SM Unit :=
  modify fun sys => { sys with chans := sys.chans.insert (src, dst) ch }

/-- Runs a handler on node `self` and enqueues what it sends. -/
def runHandler (self : Nat) (handler : SNode → HM SNode) : SM Unit := do
  let st := (← get).nodes[self]!
  let (next, outs) ← liftM (m := EM) ((handler st).run (.bool true) |>.run #[])
  modify fun sys => { sys with nodes := sys.nodes.set! self next }
  for out in outs do
    let ch ← chanOf self out.dest
    setChan self out.dest (← ch.push out.cond out.msg)

/-! ## Observations -/

def canonicalNat (value : Json) : Option Nat :=
  match value with
  | .num n => if n.exponent == 0 && n.mantissa >= 0 then some n.mantissa.toNat else none
  | _ => none

/-- `t = value` for an observed natural number. -/
def eqNatJson (t : Tm) (value : Json) : OpM Tm := do
  match canonicalNat value with
  | some v => eqK t v
  | none => return .bool false

/-- `t = value` for an observed optional natural number, -1 meaning none. -/
def eqOptNatJson (t : Tm) (value : Json) : OpM Tm := do
  match value with
  | .null => eqK t (-1)
  | value => eqNatJson t value

def eqBoolJson (t : Tm) (value : Json) : OpM Tm := do
  match value with
  | .bool b => eqT t (.bool b)
  | _ => return .bool false

/-- Bits of an observed node list, which must list declared nodes in declaration order. -/
def nodeBits (env : Env) (value : Json) : Option (Array Tm) := do
  let .arr items := value | none
  let mut bits := falses env.n
  let mut last : Option Nat := none
  for item in items do
    let .str name := item | none
    let index ← env.names.idxOf? name
    if let some before := last then
      unless before < index do
        none
    last := some index
    bits := bits.set! index (.bool true)
  return bits

def objectOf (value : Json) : Option (List (String × Json)) :=
  (objectFields value).toOption

def exactKeys (fields : List (String × Json)) (expected : List String) : Bool :=
  fields.length == expected.length && fields.all fun (key, _) => key ∈ expected

def roleOf (name : String) : Option Int :=
  match name with
  | "none" => some ROLE_NONE
  | "follower" => some ROLE_FOLLOWER
  | "preVoteCandidate" => some ROLE_PRE_VOTE_CANDIDATE
  | "candidate" => some ROLE_CANDIDATE
  | "leader" => some ROLE_LEADER
  | _ => none

def phaseOf (name : String) : Option Int :=
  match name with
  | "active" => some PHASE_ACTIVE
  | "retirementOrdered" => some PHASE_ORDERED
  | "retirementSigned" => some PHASE_SIGNED
  | "retirementCompleted" => some PHASE_COMPLETED
  | "retiredCommitted" => some PHASE_RETIRED_COMMITTED
  | _ => none

def stringIs (value : Json) (f : String → Option Int) (t : Tm) : OpM Tm := do
  match value with
  | .str name =>
      match f name with
      | some code => eqK t code
      | none => return .bool false
  | _ => return .bool false

/-- Whether index `k` is in the observed strictly ascending list, if well formed. -/
def ascendingNats (value : Json) : Option (Array Nat) := do
  let .arr items := value | none
  let values ← items.mapM canonicalNat
  for i in [1:values.size] do
    unless values[i - 1]! < values[i]! do
      none
  return values

def committableIndicesIs (st : SNode) (value : Json) : EM Tm := do
  let K := (← read).K
  let some expected := ascendingNats value | return .bool false
  if expected.any (fun k => k == 0 || k > K) then return .bool false
  let mut parts := #[]
  for k in [1:K + 1] do
    let cell := st.log.cells[k - 1]!
    let actual ← andL [← lt st.ci (.int k), ← present st.log k, cell.sig]
    parts := parts.push (← eqT actual (.bool (expected.contains k)))
  parts := parts.push (← escapeOr (← fits st.log) (.bool true))
  andL parts.toList

/-- Observed active configurations other than the initial one. -/
def configurationsIs (st : SNode) (value : Json) : EM Tm := do
  let env ← read
  let .arr items := value | return .bool false
  let mut expected : Array (Nat × Array Tm) := #[]
  for item in items do
    let some fields := objectOf item | return .bool false
    unless exactKeys fields ["index", "nodes"] do
      return .bool false
    let some index := (fields.lookup "index").bind canonicalNat | return .bool false
    let some bits := (fields.lookup "nodes").bind (nodeBits env) | return .bool false
    if let some (before, _) := expected.back? then
      unless before < index do
        return .bool false
    if index == 0 || index > env.K then return .bool false
    expected := expected.push (index, bits)
  let cfgs ← configs st
  let mut parts := #[]
  for k in [1:env.K + 1] do
    let committedHere ← eqK cfgs.committedIndex k
    let pendingHere :=
      ((cfgs.pending.find? fun (index, _, _) => index == k).map fun (_, c, _) => c).getD
        (.bool false)
    let here ← orL [committedHere, pendingHere]
    match expected.find? fun (index, _) => index == k with
    | none => parts := parts.push (← notT here)
    | some (_, bits) =>
        parts := parts.push here
        let members ← iteBits committedHere cfgs.committed st.log.cells[k - 1]!.cfgBits
        parts := parts.push (← eqBits members bits)
  parts := parts.push (← escapeOr (← notT cfgs.escaped) (.bool true))
  andL parts.toList

def stateFieldIs (self : Nat) (st : SNode) (peer : Option Nat) (key : String)
    (value : Json)
    : EM Tm := do
  let env ← read
  match key with
  | "role" => stringIs value roleOf st.role
  | "currentTerm" => eqNatJson st.ct value
  | "logLength" => eqNatJson st.log.len value
  | "commitIndex" => eqNatJson st.ci value
  | "committableIndices" => committableIndicesIs st value
  | "configurations" => configurationsIs st value
  | "membershipState" => stringIs value phaseOf (← retirement st self).phase
  | "retirementIndex" => eqOptNatJson (← retirement st self).index value
  | "retirementCommittableIndex" =>
      eqOptNatJson (← retirement st self).committableIndex value
  | "retiredCommittedIndex" => eqOptNatJson st.rci value
  | "preVoteEnabled" => eqBoolJson (.bool env.preVote[self]!) value
  | "sentIndex" =>
      match peer with
      | some j => eqNatJson st.sent[j]! value
      | none => return .bool false
  | "matchIndex" =>
      match peer with
      | some j => eqNatJson st.mi[j]! value
      | none => return .bool false
  | _ => return .bool false

def effectOf (env : Env) (value : Json) : Option (Bool × Array Tm) := do
  let fields ← objectOf value
  match fields.lookup "kind" with
  | some (.str "configuration") =>
      unless exactKeys fields ["kind", "configuration"] do
        none
      return (true, ← (fields.lookup "configuration").bind (nodeBits env))
  | some (.str "retiredCommitted") =>
      unless exactKeys fields ["kind", "nodes"] do
        none
      return (false, ← (fields.lookup "nodes").bind (nodeBits env))
  | _ => none

def entryFieldIs (cell : SEntry) (index : Nat) (st : SNode) (key : String) (value : Json)
    : EM Tm := do
  let env ← read
  let isTx ← notT cell.sig
  match key with
  | "term" => eqNatJson cell.term value
  | "committed" => eqBoolJson (← le (.int index) st.ci) value
  | "kind" =>
      match value with
      | .str "transaction" => return isTx
      | .str "signature" => return cell.sig
      | _ => return .bool false
  | "transaction" =>
      match value with
      | .str id =>
          match env.txNames.idxOf? id with
          | some tx => andL [isTx, ← eqK cell.tx tx]
          | none => return .bool false
      | _ => return .bool false
  | "effects" =>
      let .arr items := value | return .bool false
      let some effects := items.mapM (effectOf env) | return .bool false
      let cfgIs (bits : Array Tm) : OpM Tm := do
        andL [cell.cfg, ← eqBits cell.cfgBits bits]
      let rcIs (bits : Array Tm) : OpM Tm := do
        andL [cell.rc, ← eqBits cell.rcBits bits]
      match effects.toList with
      | [] => andL [isTx, ← notT cell.cfg, ← notT cell.rc]
      | [(true, bits)] => andL [isTx, ← cfgIs bits, ← notT cell.rc]
      | [(false, bits)] => andL [isTx, ← notT cell.cfg, ← rcIs bits]
      | [(true, cfgBits), (false, rcBits)] => andL [isTx, ← cfgIs cfgBits, ← rcIs rcBits]
      | _ =>
          unsupported "entry observation with effects the encoding cannot represent"
          return .bool true
  | "configurations" =>
      let .arr items := value | return .bool false
      match items.toList with
      | [] => andL [isTx, ← notT cell.cfg]
      | [item] =>
          let some bits := nodeBits env item | return .bool false
          andL [isTx, cell.cfg, ← eqBits cell.cfgBits bits]
      | _ =>
          unsupported "entry observation with several configurations"
          return .bool true
  | _ => return .bool false

def msgKindOf (name : String) : Option Int :=
  match name with
  | "raft_append_entries" => some KIND_AE
  | "raft_append_entries_response" => some KIND_AER
  | "raft_request_vote" => some KIND_RV
  | "raft_request_vote_response" => some KIND_RVR
  | "raft_request_pre_vote" => some KIND_RPV
  | "raft_request_pre_vote_response" => some KIND_RPVR
  | "raft_propose_request_vote" => some KIND_PROPOSE
  | _ => none

/-- Packet keys in the order they are checked: the kind first, so later keys fold. -/
def packetOrder : List String :=
  [
    "msg",
    "term",
    "prev_idx",
    "idx",
    "prev_term",
    "leader_commit_idx",
    "success",
    "last_log_idx",
    "last_committable_idx",
    "term_of_last_committable_idx",
    "vote_granted",
    "contains_new_view",
    "term_of_idx"
  ]

def packetFieldIs (m : SMsg) (key : String) (value : Json) : EM Tm := do
  let kindIn (kinds : List Int) : OpM Tm := do
    orL (← kinds.mapM fun k => eqK m.kind k)
  match key with
  | "msg" => stringIs value msgKindOf m.kind
  | "term" => eqNatJson m.term value
  | "prev_idx" => andL [← kindIn [KIND_AE], ← eqNatJson m.a value]
  | "prev_term" => andL [← kindIn [KIND_AE], ← eqNatJson m.b value]
  | "idx" => andL [← kindIn [KIND_AE], ← eqNatJson (← addT m.a m.count) value]
  | "leader_commit_idx" => andL [← kindIn [KIND_AE], ← eqNatJson m.c value]
  | "term_of_idx" =>
      let isAe ← kindIn [KIND_AE]
      if (← norm isAe) == .bool false then return .bool false
      let last ← addT m.a m.count
      let lastTerm ← iteT (← lt (.int 0) m.count) (← entsTermAt m.ents last) m.b
      andL [isAe, ← eqNatJson lastTerm value]
  | "contains_new_view" => andL [← kindIn [KIND_AE], .bool (value == .bool false)]
  | "success" =>
      let flag ←
        match value with
        | .str "OK" => pure (Tm.bool true)
        | .str "FAIL" => pure (Tm.bool false)
        | _ => return .bool false
      andL [← kindIn [KIND_AER], ← eqT m.flag flag]
  | "last_log_idx" => andL [← kindIn [KIND_AER], ← eqNatJson m.a value]
  | "last_committable_idx" => andL [← kindIn [KIND_RV, KIND_RPV], ← eqNatJson m.a value]
  | "term_of_last_committable_idx" =>
      andL [← kindIn [KIND_RV, KIND_RPV], ← eqNatJson m.b value]
  | "vote_granted" => andL [← kindIn [KIND_RVR, KIND_RPVR], ← eqBoolJson m.flag value]
  | _ => return .bool false

/-! ## Instructions -/

def nodeIndex (name : String) : EM Nat := do
  return ((← read).names.idxOf? name).getD 0

/-- Runs `body`, or fails the instruction with the error it reports. -/
def orFail {α : Type} (result : Except String α) (body : α → SM Unit) : SM Unit := do
  match result with
  | .ok value => body value
  | .error error => falsify error

def observedFields (value : Json) (key : String)
    : Except String (List (String × Json)) := do
  let fields ← objectFields (← field value key)
  if fields.isEmpty then throw "observation must contain at least one field"
  return fields

def observeState (value : Json) : SM Unit := do
  let env ← read
  let header := env.header
  orFail
    (do
      keys value ["kind", "observation", "origin", "node", "peer", "fields"]
      let node ← nodeField header value "node"
      let peer ←
        match ← optionalField value "peer" with
        | some _ => some <$> nodeField header value "peer"
        | none => pure none
      return (node, peer, ← observedFields value "fields"))
    fun (node, peer, fields) => do
      let self ← nodeIndex node
      let peer ← peer.mapM fun name => (nodeIndex name : SM Nat)
      let st := (← get).nodes[self]!
      for (key, expected) in fields do
        require (← stateFieldIs self st peer key expected) s!"state {node}.{key}"

def observeEntry (value : Json) : SM Unit := do
  let env ← read
  let header := env.header
  orFail
    (do
      keys value ["kind", "observation", "origin", "node", "index", "fields"]
      let node ← nodeField header value "node"
      let index ← natField value "index"
      if index == 0 then throw "log entry index must be positive"
      return (node, index, ← observedFields value "fields"))
    fun (node, index, fields) => do
      let self ← nodeIndex node
      let st := (← get).nodes[self]!
      if index > env.K then
        unsupported "entry observation beyond the modelled log"
        return
      require (← present st.log index) s!"entry {node}[{index}] exists"
      let cell := st.log.cells[index - 1]!
      for (key, expected) in fields do
        require (← entryFieldIs cell index st key expected)
          s!"entry {node}[{index}].{key}"

inductive Selection where
  | at (index : Nat)
  | last

def observeMessage (value : Json) : SM Unit := do
  let env ← read
  let header := env.header
  orFail
    (do
      keys value
        [
          "kind",
          "observation",
          "origin",
          "source",
          "destination",
          "packet",
          "occurrence",
          "selection"
        ]
      let source ← nodeField header value "source"
      let destination ← nodeField header value "destination"
      let selection ←
        match ← optionalField value "selection" with
        | none => Selection.at <$> occurrence value
        | some selection => do
            if (← optionalField value "occurrence").isSome then
              throw "message observation cannot specify both selection and occurrence"
            match ← text selection with
            | "first" => pure (Selection.at 0)
            | "last" => pure Selection.last
            | name => throw s!"unsupported message selection '{name}'"
      let packet ← field value "packet"
      let _ ← stringField packet "msg"
      return (source, destination, selection, ← objectFields packet))
    fun (source, destination, selection, fields) => do
      let src ← nodeIndex source
      let dst ← nodeIndex destination
      let ch ← chanOf src dst
      let label := s!"message {source}->{destination}"
      let (m, ch) ←
        match selection with
        | .at k =>
            require (← ch.hasMoreThan k) s!"{label}: pending at occurrence {k}"
            liftM (m := EM) (ch.name (ch.pops + k))
        | .last =>
            require (← ch.hasMoreThan 0) s!"{label}: pending"
            liftM (m := EM) ch.last
      setChan src dst ch
      let ordered :=
        packetOrder.filterMap (fun key => (fields.lookup key).map (key, ·))
        ++ fields.filter fun (key, _) => !packetOrder.contains key
      for (key, expected) in ordered do
        require (← packetFieldIs m key expected) s!"{label}.{key}"

def pop (src dst : Nat) (what : String) : SM (SMsg) := do
  let ch ← chanOf src dst
  require (← ch.hasMoreThan 0) s!"{what}: no pending packet"
  let (m, ch) ← liftM (m := EM) (ch.name ch.pops)
  let ch ← ch.bind ch.pops s!"{what}: delivered packet"
  setChan src dst { ch with pops := ch.pops + 1 }
  return m

def runAction (value : Json) : SM Unit := do
  let env ← read
  orFail (parseAction env.header value)
    fun step => do
      match step with
      | .local node input =>
          let self ← nodeIndex node
          match input with
          | .append entries => runHandler self fun st => appendBatch st self entries
          | .sendEntries destination endIndex =>
              let dest ← nodeIndex destination
              runHandler self fun st => sendEntries st self dest endIndex
          | .timeout .election => runHandler self fun st => startElection st self
          | .timeout .checkQuorum => runHandler self fun st => checkQuorum st self
          | .nominateSuccessor => runHandler self fun st => nominate st self
      | .receive source destination =>
          let src ← nodeIndex source
          let dst ← nodeIndex destination
          let m ← pop src dst s!"receive {source}->{destination}"
          runHandler dst fun st => receive st dst src m
      | .drop source destination index =>
          if index != 0 then
            unsupported "drop of a packet other than the first"
            return
          let _ ←
            pop (← nodeIndex source) (← nodeIndex destination)
              s!"drop {source}->{destination}"

def runInstruction (value : Json) : SM Unit := do
  orFail (originLabel value)
    fun _ => do
      orFail (stringField value "kind")
        fun kind => do
          match kind with
          | "action" => runAction value
          | "observation" =>
              orFail (stringField value "observation")
                fun observation => do
                  match observation with
                  | "state" => observeState value
                  | "message" => observeMessage value
                  | "entry" => observeEntry value
                  | name => falsify s!"unsupported observation '{name}'"
          | kind => falsify s!"unsupported instruction kind '{kind}'"

/-! ## Encoding -/

structure Encoding where
  enc : Enc
  sys : Sys
  /-- Instructions encoded before a falsified or unsupported one stopped encoding. -/
  processed : Nat
  /-- Script lines emitted after each instruction. -/
  sizes : Array Nat := #[]

def encode (env : Env) (suffix : Array Json) (settings : Settings) : Encoding :=
  -- Narrowing by labelled assertions would hide them from unsat cores.
  let start : Enc :=
    { refine := settings.refine && !settings.explain, named := settings.explain }
  let run : EM (Sys × Nat × Array Nat) := do
    let cap ← declareBool
    let inv ← declareBool
    modify fun enc => { enc with capLit := cap, invLit := inv }
    let mut sys ← initialSys settings.pinned
    let mut processed := 0
    let mut sizes := #[]
    for h : i in [0:suffix.size] do
      modify fun enc => { enc with instruction := i }
      let ((), next) ← (runInstruction suffix[i]).run sys
      sys := next
      processed := i + 1
      let enc ← get
      sizes := sizes.push enc.out.size
      if enc.falsified.isSome || enc.unsupported.isSome then break
    -- Observed positions that were never delivered still constrain the channel.
    for ((src, dst), ch) in sys.chans.toList do
      let mut ch := ch
      for x in ch.heads.keys do
        ch ← ch.bind x s!"message {src}->{dst}: observed packet"
      sys := { sys with chans := sys.chans.insert (src, dst) ch }
    return (sys, processed, sizes)
  let ((sys, processed, sizes), enc) := (run.run env).run start
  { enc, sys, processed, sizes }

/-! ## Solver -/

inductive SExp where
  | atom (text : String)
  | list (items : Array SExp)
deriving Inhabited

partial def parseSExps (input : String) : Array SExp :=
  let chars := input.toList.toArray
  let rec go (i : Nat) (stack : List (Array SExp)) (out : Array SExp) : Array SExp :=
    if h : i < chars.size then
      let c := chars[i]
      if c == '(' then
        go (i + 1) (#[] :: stack) out
      else if c == ')' then
        match stack with
        | top :: rest =>
            let item := SExp.list top
            match rest with
            | parent :: more => go (i + 1) (parent.push item :: more) out
            | [] => go (i + 1) [] (out.push item)
        | [] => go (i + 1) [] out
      else if c.isWhitespace then
        go (i + 1) stack out
      else
        let rec word (j : Nat) : Nat :=
          if h : j < chars.size then
            let d := chars[j]
            if d == '(' || d == ')' || d.isWhitespace then j else word (j + 1)
          else
            j
        let j := word i
        let atom := SExp.atom (String.ofList (chars.extract i j).toList)
        match stack with
        | top :: rest => go j (top.push atom :: rest) out
        | [] => go j [] (out.push atom)
    else
      out
  go 0 [] #[]

def SExp.toInt? : SExp → Option Int
  | .atom "true" => some 1
  | .atom "false" => some 0
  | .atom text => text.toInt?
  | .list #[.atom "-", inner] => inner.toInt?.map (- ·)
  | _ => none

structure Session where
  child : IO.Process.Child { stdin := .piped, stdout := .piped, stderr := .piped }

def Session.send (session : Session) (text : String) : IO Unit := do
  session.child.stdin.putStr text
  session.child.stdin.flush

/-- Reads one balanced response. -/
partial def Session.response (session : Session) : IO String := do
  let mut text := ""
  let mut depth : Int := 0
  repeat
    let line ← session.child.stdout.getLine
    if line.isEmpty then break
    text := text ++ line
    for c in line.toList do
      if c == '(' then
        depth := depth + 1
      else if c == ')' then
        depth := depth - 1
    if depth <= 0 && !text.trimAscii.isEmpty then break
  return text.trimAscii.toString

def Session.check (session : Session) (assumptions : List String) : IO String := do
  session.send s!"(check-sat-assuming ({" ".intercalate assumptions}))\n"
  session.response

def Session.core (session : Session) : IO (Array String) := do
  session.send "(get-unsat-assumptions)\n"
  let response ← session.response
  match (parseSExps response)[0]? with
  | some (SExp.list items) =>
      return items.filterMap
        fun
        | .atom name => some name
        | _ => none
  | _ => return #[]

def Session.values (session : Session) (ids : Array Nat) : IO (Std.HashMap Nat Int) := do
  let mut values : Std.HashMap Nat Int := {}
  -- Batches keep responses small.
  let mut start := 0
  while start < ids.size do
    let batch := ids.extract start (start + 2000)
    start := start + 2000
    session.send
      s!"(get-value ({" ".intercalate (batch.toList.map fun id => s!"v{id}")}))\n"
    let response ← session.response
    if let some (SExp.list pairs) := (parseSExps response)[0]? then
      for pair in pairs do
        if let SExp.list #[.atom name, value] := pair then
          if let some id := (name.drop 1).toNat? then
            if let some v := value.toInt? then values := values.insert id v
  return values

/-! ## Witnesses -/

def refsOf (ts : Array Tm) : Array Nat :=
  ts.filterMap
    fun
    | .ref id => some id
    | _ => none

def entryTms (entry : SEntry) : Array Tm :=
  #[entry.term, entry.sig, entry.tx, entry.cfg, entry.rc] ++ entry.cfgBits ++ entry.rcBits

def nodeTms (st : SNode) : Array Tm :=
  #[st.role, st.ct, st.log.len, st.ci, st.nf, st.vf, st.lk, st.rci]
  ++ st.sent
  ++ st.mi
  ++ st.votes
  ++ st.pv
  ++ st.log.cells.flatMap entryTms

def msgTms (m : SMsg) : Array Tm := #[m.kind, m.term, m.a, m.b, m.c, m.flag, m.count]

/-- The entries of a phantom's unknown entry list that the encoding read. -/
def freshEntries (enc : Enc) (ents : Ents) : Array SEntry :=
  match ents with
  | .fresh id .. =>
      enc.entries.fold (init := #[])
        fun acc (owner, _) entry =>
          if owner == id then acc.push entry else acc
  | _ => #[]

structure Valuation where
  env : Env
  values : Std.HashMap Nat Int

def Valuation.int (v : Valuation) : Tm → Int
  | .int value => value
  | .bool value => if value then 1 else 0
  | .ref id => v.values.getD id 0

def Valuation.nat (v : Valuation) (t : Tm) : Nat := (v.int t).toNat

def Valuation.bool (v : Valuation) (t : Tm) : Bool := v.int t != 0

def Valuation.nodes (v : Valuation) (bits : Array Tm) : Finset String :=
  ((v.env.names.zip bits).filter fun (_, bit) => v.bool bit).map Prod.fst
  |>.toList.toFinset

def Valuation.entry (v : Valuation) (entry : SEntry) : Entry String String :=
  let content :=
    if v.bool entry.sig then
      .signature
    else
      let effects :=
        (if v.bool entry.cfg then
            [TransactionEffect.reconfiguration (v.nodes entry.cfgBits)]
          else
            [])
        ++ (if v.bool entry.rc then [.retiredCommitted (v.nodes entry.rcBits)] else [])
      .transaction (v.env.txNames.getD (v.nat entry.tx) "midtrace") effects
  { term := v.nat entry.term, content }

def Valuation.node (v : Valuation) (st : SNode) : NodeState String String :=
  let env := v.env
  let n := env.n
  let peer (values : Array Tm) (name : String) : Nat :=
    match env.names.idxOf? name with
    | some j => v.nat values[j]!
    | none => 0
  let len := v.nat st.log.len
  let role :=
    match v.int st.role with
    | 1 => Role.follower
    | 2 => .preVoteCandidate
    | 3 => .candidate
    | 4 => .leader
    | _ => .none
  let vf := v.int st.vf
  let rci := v.int st.rci
  {
    role
    currentTerm := v.nat st.ct
    log := ((st.log.cells.extract 0 len).map v.entry).toList
    commitIndex := v.nat st.ci
    sentIndex := peer st.sent
    matchIndex := peer st.mi
    isNewFollower := v.bool st.nf
    votedFor :=
      if vf < 0 then
        none
      else if vf.toNat < n then
        some env.names[vf.toNat]!
      else
        some "<other>"
    leaderKnown := v.bool st.lk
    votesGranted := v.nodes st.votes
    preVotesGranted := v.nodes st.pv
    retiredCommittedIndex := if rci < 0 then none else some rci.toNat
  }

def Valuation.message (v : Valuation) (enc : Enc) (m : SMsg) : Message String String :=
  let term := v.nat m.term
  match v.int m.kind with
  | 0 =>
      let prev := v.nat m.a
      let count := v.nat m.count
      let entries :=
        (List.range count).map
          fun i =>
            let k := prev + 1 + i
            match m.ents with
            | .fresh id .. =>
                match enc.entries[(id, k)]? with
                | some entry => v.entry entry
                | none => { term, content := .signature }
            | .list _ listed known =>
                match known[k - listed - 1]? with
                | some entry => v.entry entry
                | none => { term, content := .signature }
            | _ => { term, content := .signature }
      .appendEntriesRequest
        {
          term
          prevLogIndex := prev
          prevLogTerm := v.nat m.b
          entries
          leaderCommit := v.nat m.c
        }
  | 1 =>
      .appendEntriesResponse { term, success := v.bool m.flag, lastLogIndex := v.nat m.a }
  | 2 =>
      .requestVoteRequest
        { term, lastCommittableTerm := v.nat m.b, lastCommittableIndex := v.nat m.a }
  | 3 => .requestVoteResponse { term, voteGranted := v.bool m.flag }
  | 4 =>
      .requestPreVote
        { term, lastCommittableTerm := v.nat m.b, lastCommittableIndex := v.nat m.a }
  | 5 => .requestPreVoteResponse { term, voteGranted := v.bool m.flag }
  | _ => .proposeVoteRequest term

/-- Every initial-state term the witness reads. -/
def witnessRefs (encoding : Encoding) : Array Nat :=
  Id.run do
    let mut ids := #[]
    for st in encoding.sys.initial do
      ids := ids ++ refsOf (nodeTms st)
    for ((src, dst), p) in encoding.sys.initialP.toList do
      ids := ids ++ refsOf #[p]
      if let some ch := encoding.sys.chans[(src, dst)]? then
        for (_, m) in ch.phantoms.toList do
          ids := ids ++ refsOf (msgTms m)
          for entry in freshEntries encoding.enc m.ents do
            ids := ids ++ refsOf (entryTms entry)
    return ids

def witness (env : Env) (encoding : Encoding) (values : Std.HashMap Nat Int)
    : ReplayState :=
  let v : Valuation := { env, values }
  let nodes :=
    (List.range env.n).map fun i => (env.names[i]!, v.node encoding.sys.initial[i]!)
  let network :=
    encoding.sys.initialP.toList.flatMap
      fun ((src, dst), p) =>
        let ch := (encoding.sys.chans[(src, dst)]?).getD { p }
        (List.range (v.nat p)).map
          fun x =>
            let message :=
              match ch.phantoms[x]? with
              | some m => v.message encoding.enc m
              | none => .proposeVoteRequest 0
            { source := env.names[src]!, target := env.names[dst]!, payload := message }
  { state := { nodes, active := env.header.declared, network } }

/-! ## Verdicts -/

structure Outcome where
  verdict : Sym.Verdict
  detail : String
  processed : Nat
  encodeMs : Nat := 0
  solveMs : Nat := 0
  declared : Nat := 0
  defined : Nat := 0
  asserts : Nat := 0
  witness : Option ReplayState := none
  sizes : Array Nat := #[]
  K : Nat := 0

def describe (env : Env) (enc : Enc) (name : String) : Option String :=
  let _ := env
  (enc.labels.find? fun label => label.name == name).map
    fun label =>
      s!"instruction {label.instruction + 1}: {label.description}"

/-- Interactive-mode flags for the supported solvers. -/
def solverArgs (solver : String) : Array String :=
  let name := (solver.splitOn "/").getLast!
  if name.startsWith "yices" then
    #["--incremental"]
  else if name.startsWith "cvc5" then
    #["--incremental", "--lang=smt2"]
  else
    #["-in"]

def runOnce (header : Header) (suffix : Array Json) (settings : Settings)
    : IO Outcome := do
  let env := makeEnv header suffix settings
  let env :=
    match settings.pinned with
    | none => env
    | some replay =>
        let longest :=
          replay.state.nodes.foldl (fun best (_, st) => max best st.log.length) 0
        let widest :=
          (replay.live.map fun e => replay.pending e.source e.target |>.length).foldl max
            0
        let entryIds (entries : List (Entry String String)) : List String :=
          entries.filterMap
            fun entry =>
              match entry.content with
              | .transaction id _ => some id
              | .signature => none
        let ids :=
          (replay.state.nodes.flatMap fun (_, st) => entryIds st.log)
          ++ replay.live.flatMap
              fun envelope =>
                match envelope.payload with
                | .appendEntriesRequest request => entryIds request.entries
                | _ => []
        let txNames :=
          ids.foldl (fun table id => if table.contains id then table else table.push id)
            env.txNames
        { env with K := max env.K longest, Q := max env.Q widest, txNames }
  let start ← IO.monoMsNow
  let encoding := encode env suffix settings
  let enc := encoding.enc
  let encodeMs := (← IO.monoMsNow) - start
  let base : Outcome :=
    {
      verdict := .unknown
      detail := ""
      processed := encoding.processed
      encodeMs
      declared := enc.declared
      defined := enc.defined
      asserts := enc.out.size - enc.declared - enc.defined
      sizes := encoding.sizes
      K := env.K
    }
  if let some (index, description) := enc.falsified then
    return {
      base with
        verdict := .invalid, detail := s!"instruction {index + 1}: {description}"
    }
  if let some what := enc.unsupported then
    return { base with detail := s!"unsupported: {what}" }
  let script :=
    "(set-option :produce-unsat-assumptions true)\n(set-option :produce-models true)\n"
    ++ "(set-logic QF_LIA)\n"
    ++ "\n".intercalate enc.out.toList
    ++ "\n"
  if let some path := settings.dump then IO.FS.writeFile path script
  let child ←
    IO.Process.spawn
      {
        cmd := settings.solver
        args := solverArgs settings.solver
        stdin := .piped
        stdout := .piped
        stderr := .piped
      }
  let session : Session := { child }
  let solveStart ← IO.monoMsNow
  session.send script
  let cap := enc.capLit.smt
  let inv := enc.invLit.smt
  let guards := (enc.labels.map (·.name)).toList
  let answer ← session.check ([cap, inv] ++ guards)
  let mut outcome := base
  if answer == "sat" then
    let values ← session.values (witnessRefs encoding)
    let state := witness env encoding values
    outcome :=
      match replayFrom header state suffix with
      | .ok _ => { base with verdict := .valid, witness := some state }
      | .error error => { base with detail := s!"ENGINE-BUG witness rejected: {error}" }
  else if answer == "unsat" then
    let core ← session.core
    let mut capacity := core.contains cap
    let mut invariant := core.contains inv
    let mut final := core
    if capacity then
      let again ← session.check (inv :: guards)
      if again == "unsat" then
        final ← session.core
        capacity := false
        invariant := final.contains inv
      else
        outcome :=
          { base with detail := s!"capacity: unsat only within K={env.K} Q={env.Q}" }
    if !capacity then
      let reasons := (final.filterMap (describe env enc)).toList
      let why := if reasons.isEmpty then "" else s!" core: {"; ".intercalate reasons}"
      let assumption := if invariant then " (assuming invariants)" else ""
      outcome := { base with verdict := .invalid, detail := s!"unsat{assumption}{why}" }
  else
    let err ← session.child.stderr.readToEnd
    outcome := { base with detail := s!"solver: {answer} {err}" }
  session.send "(exit)\n"
  let (_, child) ← session.child.takeStdin
  let _ ← child.wait
  return { outcome with solveMs := (← IO.monoMsNow) - solveStart }

/-- Retries with larger capacities while the verdict depends on them. -/
def run (header : Header) (suffix : Array Json) (settings : Settings) : IO Outcome := do
  let mut settings := settings
  let mut outcome ← runOnce header suffix settings
  for _ in [0:2] do
    unless outcome.detail.startsWith "capacity" do
      break
    settings := { settings with Q := 4 * settings.Q, slack := 4 * settings.slack }
    let next ← runOnce header suffix settings
    outcome :=
      {
        next with
          encodeMs := outcome.encodeMs + next.encodeMs
          solveMs := outcome.solveMs + next.solveMs
      }
  return outcome

end CCFRaft.MidTrace.Smt
