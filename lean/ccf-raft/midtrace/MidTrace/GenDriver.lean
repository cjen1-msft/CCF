module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.GenModel
public import MidTrace.GenLower
public import MidTrace.SmtDriver

@[expose] public section

/-!
# Mid-trace validation through the generic pipeline

trace suffix -> `GenIr` (by running `GenModel` and the observations of
`Replay` on an unknown initial state) -> `GenLower` -> SMT solver.

The initial state ranges over every state within the declared bounds:

* index-like values (commit, sent and match indices, log and entry-list
  lengths, message indices) are at most `L`, the largest natural number the
  suffix mentions plus `slack`;
* each channel holds at most `Q` packets;
* log entries carry at most one effect.

Within those bounds the IR is satisfiable exactly when some initial state
replays the suffix. A `sat` answer is certified by replaying the solver's
initial state; `unsat` means invalid within the bounds.
-/

namespace CCFRaft.MidTrace.Gen

open Lean
open CCFRaft.MidTrace.Smt (Tm INF)
open CCFRaft.Model.Node (NodeState Role Entry EntryContent TransactionEffect Message)

structure Settings where
  solver : String := "yices-smt2"
  /-- Packets per channel in the initial state. -/
  Q : Nat := 4
  /-- Index bound beyond the largest natural number the suffix mentions. -/
  slack : Nat := 4
  refine : Bool := true
  /-- On INVALID, re-run once with `Q` and `slack` multiplied by this; 0 disables. -/
  retry : Nat := 4
  /-- Write the SMT script to this path. -/
  dump : Option String := none
  /-- Write the IR to this path. -/
  irDump : Option String := none
  /--
  The first instruction at which implied selector values are asked of the
  solver; later checks double the instruction. 0 disables.
  -/
  backbone : Nat := 32
  /-- Debugging: pins the initial packet count of these channels. -/
  fixLen : List ((Nat × Nat) × Nat) := []

structure Env where
  header : Replay.Header
  c : Ctx
  L : Nat
  Q : Nat
  fixLen : List ((Nat × Nat) × Nat) := []

def makeEnv (header : Replay.Header) (suffix : Array Json) (settings : Settings) : Env :=
  let names := header.declared.toArray
  let sorted :=
    ((List.range names.size).mergeSort fun a b => decide (names[a]! ≤ names[b]!)).toArray
  let rank :=
    (List.range sorted.size).foldl (fun rank i => rank.set! sorted[i]! i)
      (Array.replicate names.size 0)
  let ids := suffix.foldl (fun found value => Sym.transactionIds value found) #[]
  let txNames :=
    ids.foldl (fun table id => if table.contains id then table else table.push id) #[]
  let mentioned := suffix.foldl (fun best value => max best (Smt.maxNat value)) 0
  {
    header
    c :=
      {
        names
        sorted
        rank
        cfg0 := names.map fun name => decide (name ∈ header.bootstrap.configuration)
        preVote :=
          names.map fun name => decide (header.bootstrap.preVoteStatus name = .enabled)
        txNames
      }
    L := mentioned + settings.slack
    Q := settings.Q
    fixLen := settings.fixLen
  }

/-! ## Initial state -/

def entryBounds (c : Ctx) : Array (Int × Int) :=
  #[(0, INF), (0, 1), (0, c.ntx), (0, 1), (0, 1)] ++ Array.replicate c.n (0, 1)

def msgBounds (c : Ctx) (L : Int) : Array (Int × Int) :=
  #[
    (0, TAG_PROPOSE),
    (0, INF),
    (0, L),
    (0, INF),
    (0, L),
    (0, 1),
    (0, L),
    (0, INF),
    (0, L),
    (0, 1),
    (0, 0),
    (0, L)
  ]
  ++ entryBounds c

def freshNode (e : Env) : GM SNode := do
  let c := e.c
  let L : Int := e.L
  let arrs ←
    (c.entrySrts.zip (entryBounds c)).mapM fun (s, lo, hi) => declareArr (.arr s) lo hi
  let nats (hi : Int) : GM (Array Tm) :=
    (Array.range c.n).mapM fun _ => declare false 0 hi
  let bools : GM (Array Tm) := (Array.range c.n).mapM fun _ => declareBool
  return {
    role := ← declare false ROLE_NONE ROLE_LEADER
    ct := ← declare false 0 INF
    log := { arrs, off := .int 0, len := ← declare false 0 L }
    ci := ← declare false 0 L
    sent := ← nats (L + 1)
    mi := ← nats L
    nf := ← declareBool
    vf := ← declare false (-1) c.n
    lk := ← declareBool
    votes := ← bools
    pv := ← bools
    rci := ← declare false (-1) L
  }

/-- The channel's packets in the initial state: one unknown array per message field. -/
def freshChan (e : Env) : GM SList := do
  let c := e.c
  let arrs ←
    (c.msgSrts.zip (msgBounds c e.L)).mapIdxM
      fun f (s, lo, hi) =>
        if f == M_ENT_OFF then zeroArr (.arr s) else declareArr (.arr s) lo hi
  return { arrs, off := .int 0, len := ← declare false 0 e.Q }

/-! ## System state -/

structure Sys where
  nodes : Array SNode := #[]
  initial : Array SNode := #[]
  /-- Each channel's pending packets, oldest first. -/
  chans : Std.HashMap (Nat × Nat) SList := {}
  initialChans : Std.HashMap (Nat × Nat) SList := {}

abbrev DM := ReaderT Env (StateT Sys GM)

def nodeIndex (name : String) : DM Nat := do
  return ((← read).c.names.idxOf? name).getD 0

def chanOf (src dst : Nat) : DM SList := do
  if let some ch := (← getThe Sys).chans[(src, dst)]? then return ch
  let ch ← (freshChan (← read) : GM SList)
  let ch :=
    match (← read).fixLen.lookup (src, dst) with
    | some n => { ch with len := .int n }
    | none => ch
  modifyThe Sys
    fun sys =>
      {
        sys with
          chans := sys.chans.insert (src, dst) ch
          initialChans := sys.initialChans.insert (src, dst) ch
      }
  return ch

def setChan (src dst : Nat) (ch : SList) : DM Unit :=
  modifyThe Sys fun sys => { sys with chans := sys.chans.insert (src, dst) ch }

/-- Runs a step of node `self`: it must be enabled, and its sends are enqueued in order. -/
def runStep (self : Nat) (step : SNode → EM SNode) (what : String) : DM Unit := do
  let st := (← getThe Sys).nodes[self]!
  let (next, eff) ← ((step st).run {} : GM (SNode × Eff))
  require eff.ok s!"{what}: enabled"
  modifyThe Sys fun sys => { sys with nodes := sys.nodes.set! self next }
  for (pc, dst, msg) in eff.sends do
    setChan self dst (← (← chanOf self dst).pushIf pc msg)

/-- Removes the oldest pending packet. -/
def pop (src dst : Nat) (what : String) : DM SMsg := do
  let ch ← chanOf src dst
  require (← lt (.int 0) ch.len) s!"{what}: no pending packet"
  let m ← ch.get (.int 0)
  setChan src dst (← ch.drop (.int 1))
  return m

/-! ## Observations, as `Replay` checks them -/

def eqNatJson (t : Tm) (value : Json) : GM Tm := do
  match Smt.canonicalNat value with
  | some v => eqK t v
  | none => return .bool false

/-- An optional natural number coded as `-1` for none. -/
def eqCodeJson (t : Tm) (value : Json) : GM Tm := do
  match value with
  | .null => eqK t (-1)
  | value => eqNatJson t value

def eqOptJson (o : SOpt Tm) (value : Json) : GM Tm := do
  match value with
  | .null => notT o.isSome
  | value => andL [o.isSome, ← eqNatJson o.val value]

def eqBoolJson (t : Tm) (value : Json) : GM Tm := do
  match value with
  | .bool b => eqT t (.bool b)
  | _ => return .bool false

def stringIs (value : Json) (f : String → Option Int) (t : Tm) : GM Tm := do
  match value with
  | .str name =>
      match f name with
      | some code => eqK t code
      | none => return .bool false
  | _ => return .bool false

/-- The set a node list denotes, if it lists declared nodes in declaration order. -/
def nodeBits (c : Ctx) (value : Json) : Option (Array Bool) := do
  let .arr items := value | none
  let mut bits := Array.replicate c.n false
  let mut last : Option Nat := none
  for item in items do
    let .str name := item | none
    let index ← c.names.idxOf? name
    if let some before := last then
      unless before < index do
        none
    last := some index
    bits := bits.set! index true
  return bits

def eqBits (ts : Array Tm) (bits : Array Bool) : GM Tm := do
  andL (← (ts.zip bits).toList.mapM fun (t, b) => eqT t (.bool b))

def committableIndicesIs (st : SNode) (value : Json) : GM Tm := do
  let some expected := Smt.ascendingNats value | return .bool false
  let committable (k : Tm) : GM Tm := do
    andL [← lt st.ci k, ← isSignatureAt st.log k]
  let listed ←
    expected.toList.mapM
      fun k => do
        andL [← le (.int k) st.log.len, ← committable (.int k)]
  let exact ←
    foldAll (.int 1) st.log.len
      fun k => do
        orL [← orL (← expected.toList.mapM fun x => eqK k x), ← notT (← committable k)]
  andL (listed ++ [exact])

/-- Active configurations other than the initial one; position `p` has index `p`. -/
def configurationsIs (c : Ctx) (st : SNode) (value : Json) : GM Tm := do
  let .arr items := value | return .bool false
  let mut expected : Array (Nat × Array Bool) := #[]
  for item in items do
    let some fields := Smt.objectOf item | return .bool false
    unless Smt.exactKeys fields ["index", "nodes"] do
      return .bool false
    let some index := (fields.lookup "index").bind Smt.canonicalNat | return .bool false
    let some bits := (fields.lookup "nodes").bind (nodeBits c) | return .bool false
    if let some (before, _) := expected.back? then
      unless before < index do
        return .bool false
    if index == 0 then return .bool false
    expected := expected.push (index, bits)
  let active ← activeConfigurations c st.log st.ci
  let mut parts := #[]
  for (index, bits) in expected do
    let p : Tm := .int index
    let elem ← active.elem p
    parts :=
      parts.push
        (← andL
            [
              ← le p active.hi,
              ← active.mask p,
              ← eqBits (elem.extract C_NODES (C_NODES + c.n)) bits
            ])
  let exact ←
    foldAll (.int 1) active.hi
      fun p => do
        eqT (← active.mask p) (← orL (← expected.toList.mapM fun (x, _) => eqK p x))
  andL (parts.toList ++ [exact])

def stateFieldIs (c : Ctx) (self : Nat) (st : SNode) (peer : Option Nat) (key : String)
    (value : Json)
    : GM Tm := do
  match key with
  | "role" => stringIs value Smt.roleOf st.role
  | "currentTerm" => eqNatJson st.ct value
  | "logLength" => eqNatJson st.log.len value
  | "commitIndex" => eqNatJson st.ci value
  | "committableIndices" => committableIndicesIs st value
  | "configurations" => configurationsIs c st value
  | "membershipState" => stringIs value Smt.phaseOf (← st.retirement c self).phase
  | "retirementIndex" => eqOptJson (← st.retirement c self).index value
  | "retirementCommittableIndex" =>
      eqOptJson (← st.retirement c self).committableIndex value
  | "retiredCommittedIndex" => eqCodeJson st.rci value
  | "preVoteEnabled" => eqBoolJson (.bool c.preVote[self]!) value
  | "sentIndex" =>
      match peer with
      | some j => eqNatJson st.sent[j]! value
      | none => return .bool false
  | "matchIndex" =>
      match peer with
      | some j => eqNatJson st.mi[j]! value
      | none => return .bool false
  | _ => return .bool false

/-- A reconfiguration (`true`) or retired-committed effect, and its nodes. -/
def effectOf (c : Ctx) (value : Json) : Option (Bool × Array Bool) := do
  let fields ← Smt.objectOf value
  match fields.lookup "kind" with
  | some (.str "configuration") =>
      unless Smt.exactKeys fields ["kind", "configuration"] do
        none
      return (true, ← (fields.lookup "configuration").bind (nodeBits c))
  | some (.str "retiredCommitted") =>
      unless Smt.exactKeys fields ["kind", "nodes"] do
        none
      return (false, ← (fields.lookup "nodes").bind (nodeBits c))
  | _ => none

def entryFieldIs (c : Ctx) (entry : Array Tm) (index : Nat) (st : SNode) (key : String)
    (value : Json)
    : GM Tm := do
  let sig := entry[E_SIG]!
  let isTx ← notT sig
  let reconf ← andL [entry[E_HAS]!, ← notT entry[E_RET]!]
  let retCom ← andL [entry[E_HAS]!, entry[E_RET]!]
  let nodes := entry.extract E_NODES (E_NODES + c.n)
  match key with
  | "term" => eqNatJson entry[E_TERM]! value
  | "committed" => eqBoolJson (← le (.int index) st.ci) value
  | "kind" =>
      match value with
      | .str "transaction" => return isTx
      | .str "signature" => return sig
      | _ => return .bool false
  | "transaction" =>
      match value with
      | .str id =>
          match c.txNames.idxOf? id with
          | some tx => andL [isTx, ← eqK entry[E_TX]! tx]
          | none => return .bool false
      | _ => return .bool false
  | "effects" =>
      let .arr items := value | return .bool false
      let some effects := items.mapM (effectOf c) | return .bool false
      match effects.toList with
      | [] => andL [isTx, ← notT entry[E_HAS]!]
      | [(true, bits)] => andL [isTx, reconf, ← eqBits nodes bits]
      | [(false, bits)] => andL [isTx, retCom, ← eqBits nodes bits]
      | _ =>
          unsupported "entry observation with several effects"
          return .bool true
  | "configurations" =>
      let .arr items := value | return .bool false
      match items.toList with
      | [] => andL [isTx, ← notT reconf]
      | [item] =>
          let some bits := nodeBits c item | return .bool false
          andL [isTx, reconf, ← eqBits nodes bits]
      | _ =>
          unsupported "entry observation with several configurations"
          return .bool true
  | _ => return .bool false

def packetFieldIs (m : SMsg) (key : String) (value : Json) : GM Tm := do
  let tag := m[M_TAG]!
  let tagIn (tags : List Int) : GM Tm := do
    orL (← tags.mapM fun t => eqK tag t)
  match key with
  | "msg" => stringIs value Smt.msgKindOf tag
  | "term" => eqNatJson m[M_TERM]! value
  | "prev_idx" => andL [← tagIn [TAG_AE], ← eqNatJson m[M_PREV]! value]
  | "prev_term" => andL [← tagIn [TAG_AE], ← eqNatJson m[M_PREV_TERM]! value]
  | "idx" => andL [← tagIn [TAG_AE], ← eqNatJson (← addT m[M_PREV]! m[M_ENT_LEN]!) value]
  | "leader_commit_idx" => andL [← tagIn [TAG_AE], ← eqNatJson m[M_LEADER_COMMIT]! value]
  | "term_of_idx" =>
      let entries := msgEntries m
      let lastTerm ←
        iteT (← lt (.int 0) entries.len) (← entries.getF (← addK entries.len (-1)) E_TERM)
          m[M_PREV_TERM]!
      andL [← tagIn [TAG_AE], ← eqNatJson lastTerm value]
  | "contains_new_view" => andL [← tagIn [TAG_AE], .bool (value == .bool false)]
  | "success" =>
      let flag ←
        match value with
        | .str "OK" => pure (Tm.bool true)
        | .str "FAIL" => pure (Tm.bool false)
        | _ => return .bool false
      andL [← tagIn [TAG_AER], ← eqT m[M_SUCCESS]! flag]
  | "last_log_idx" => andL [← tagIn [TAG_AER], ← eqNatJson m[M_LAST_LOG]! value]
  | "last_committable_idx" =>
      andL [← tagIn [TAG_RV, TAG_RPV], ← eqNatJson m[M_LC_INDEX]! value]
  | "term_of_last_committable_idx" =>
      andL [← tagIn [TAG_RV, TAG_RPV], ← eqNatJson m[M_LC_TERM]! value]
  | "vote_granted" => andL [← tagIn [TAG_RVR, TAG_RPVR], ← eqBoolJson m[M_GRANTED]! value]
  | _ => return .bool false

/-! ## Instructions -/

/-- Runs `body`, or fails the instruction with the error it reports. -/
def orFail {α : Type} (result : Except String α) (body : α → DM Unit) : DM Unit := do
  match result with
  | .ok value => body value
  | .error error => falsify error

def observeState (value : Json) : DM Unit := do
  let e ← read
  orFail
    (do
      Replay.keys value ["kind", "observation", "origin", "node", "peer", "fields"]
      let node ← Replay.nodeField e.header value "node"
      let peer ←
        match ← Replay.optionalField value "peer" with
        | some _ => some <$> Replay.nodeField e.header value "peer"
        | none => pure none
      return (node, peer, ← Smt.observedFields value "fields"))
    fun (node, peer, fields) => do
      let self ← nodeIndex node
      let peer ← peer.mapM nodeIndex
      let st := (← getThe Sys).nodes[self]!
      for (key, expected) in fields do
        require (← stateFieldIs e.c self st peer key expected) s!"state {node}.{key}"

def observeEntry (value : Json) : DM Unit := do
  let e ← read
  orFail
    (do
      Replay.keys value ["kind", "observation", "origin", "node", "index", "fields"]
      let node ← Replay.nodeField e.header value "node"
      let index ← Replay.natField value "index"
      if index == 0 then throw "log entry index must be positive"
      return (node, index, ← Smt.observedFields value "fields"))
    fun (node, index, fields) => do
      let st := (← getThe Sys).nodes[← nodeIndex node]!
      let entry ← entryAt? st.log (.int index)
      require entry.isSome s!"entry {node}[{index}] exists"
      for (key, expected) in fields do
        require (← entryFieldIs e.c entry.val index st key expected)
          s!"entry {node}[{index}].{key}"

inductive Selection where
  | at (index : Nat)
  | last

def observeMessage (value : Json) : DM Unit := do
  let e ← read
  orFail
    (do
      Replay.keys value
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
      let source ← Replay.nodeField e.header value "source"
      let destination ← Replay.nodeField e.header value "destination"
      let selection ←
        match ← Replay.optionalField value "selection" with
        | none => Selection.at <$> Replay.occurrence value
        | some selection => do
            if (← Replay.optionalField value "occurrence").isSome then
              throw "message observation cannot specify both selection and occurrence"
            match ← Replay.text selection with
            | "first" => pure (Selection.at 0)
            | "last" => pure Selection.last
            | name => throw s!"unsupported message selection '{name}'"
      let packet ← Replay.field value "packet"
      let _ ← Replay.stringField packet "msg"
      return (source, destination, selection, ← Replay.objectFields packet))
    fun (source, destination, selection, fields) => do
      let ch ← chanOf (← nodeIndex source) (← nodeIndex destination)
      let label := s!"message {source}->{destination}"
      let m ←
        match selection with
        | .at k => do
            require (← lt (.int k) ch.len) s!"{label}: pending at occurrence {k}"
            ch.get (.int k)
        | .last => do
            require (← lt (.int 0) ch.len) s!"{label}: pending"
            ch.get (← addK ch.len (-1))
      -- The kind first, so that later keys lower against a known kind.
      let ordered :=
        Smt.packetOrder.filterMap (fun key => (fields.lookup key).map (key, ·))
        ++ fields.filter fun (key, _) => !Smt.packetOrder.contains key
      for (key, expected) in ordered do
        require (← packetFieldIs m key expected) s!"{label}.{key}"

def runAction (value : Json) : DM Unit := do
  let e ← read
  orFail (Replay.parseAction e.header value)
    fun step => do
      match step with
      | .local node input =>
          let self ← nodeIndex node
          runStep self (fun st => act e.c self st input) s!"{node}"
      | .receive source destination =>
          let src ← nodeIndex source
          let dst ← nodeIndex destination
          let m ← pop src dst s!"receive {source}->{destination}"
          runStep dst (fun st => receive e.c dst src st m)
            s!"receive {source}->{destination}"
      | .drop source destination index =>
          if index != 0 then
            unsupported "drop of a packet other than the first"
            return
          discard
          <| pop (← nodeIndex source) (← nodeIndex destination)
              s!"drop {source}->{destination}"

def runInstruction (value : Json) : DM Unit := do
  orFail (Replay.originLabel value)
    fun _ => do
      orFail (Replay.stringField value "kind")
        fun kind => do
          match kind with
          | "action" => runAction value
          | "observation" =>
              orFail (Replay.stringField value "observation")
                fun observation => do
                  match observation with
                  | "state" => observeState value
                  | "message" => observeMessage value
                  | "entry" => observeEntry value
                  | name => falsify s!"unsupported observation '{name}'"
          | kind => falsify s!"unsupported instruction kind '{kind}'"

/-- The IR of `suffix` from an unknown initial state, and how many instructions it covers. -/
def build (e : Env) (suffix : Array Json) : Ir × Sys × Nat :=
  let run : DM Nat := do
    let nodes ← (Array.range e.c.n).mapM fun _ => (freshNode e : GM SNode)
    modifyThe Sys fun sys => { sys with nodes, initial := nodes }
    let mut processed := 0
    for h : i in [0:suffix.size] do
      let action := (Replay.stringField suffix[i] "kind").toOption == some "action"
      setInstruction i action
      runInstruction suffix[i]
      processed := i + 1
      let ir ← getThe Ir
      if ir.falsified.isSome || ir.unsupported.isSome then break
    return processed
  let ((processed, sys), ir) := ((run.run e).run {}).run {}
  (ir, sys, processed)

/-! ## Witnesses -/

structure Valuation where
  c : Ctx
  memo : Std.HashMap Nat Val
  cells : Std.HashMap (Nat × Array Int × Int) Tm
  values : Std.HashMap Nat Int
  /-- A transaction identifier the suffix does not mention. -/
  other : String

def Valuation.smt (v : Valuation) : Tm → Int
  | .int value => value
  | .bool value => if value then 1 else 0
  | .ref id => v.values.getD id 0

/-- An initial-state scalar; unread unknowns are 0, which every bound admits. -/
def Valuation.int (v : Valuation) (t : Tm) : Int :=
  match t with
  | .ref id =>
      match v.memo[id]? with
      | some (.s s) => v.smt s
      | _ => 0
  | t => v.smt t

def Valuation.nat (v : Valuation) (t : Tm) : Nat := (v.int t).toNat

def Valuation.bool (v : Valuation) (t : Tm) : Bool := v.int t != 0

/-- Cell `k` below `path` of an unknown array. -/
def Valuation.cell (v : Valuation) (arr : Tm) (path : Array Int) (k : Int) : Int :=
  match arr with
  | .ref id => ((v.cells[(id, path, k)]?).map v.smt).getD 0
  | _ => 0

def Valuation.set (v : Valuation) (bit : Nat → Bool) : Finset String :=
  ((List.range v.c.n).filter bit |>.map fun j => v.c.names[j]!).toFinset

def Valuation.entry (v : Valuation) (arrs : Array Tm) (path : Array Int) (k : Int)
    : Entry String String :=
  let f (i : Nat) := v.cell arrs[i]! path k
  let nodes := v.set fun j => f (E_NODES + j) != 0
  let content :=
    if f E_SIG != 0 then
      .signature
    else
      let effects :=
        if f E_HAS != 0 then
          [ if f E_RET != 0 then
              TransactionEffect.retiredCommitted nodes
            else
              .reconfiguration nodes]
        else
          []
      .transaction (v.c.txNames.getD (f E_TX).toNat v.other) effects
  { term := (f E_TERM).toNat, content }

def Valuation.node (v : Valuation) (st : SNode) : NodeState String String :=
  let c := v.c
  let peer (values : Array Tm) (name : String) : Nat :=
    match c.names.idxOf? name with
    | some j => v.nat values[j]!
    | none => 0
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
    log := (List.range (v.nat st.log.len)).map fun k => v.entry st.log.arrs #[] k
    commitIndex := v.nat st.ci
    sentIndex := peer st.sent
    matchIndex := peer st.mi
    isNewFollower := v.bool st.nf
    votedFor :=
      if vf < 0 then
        none
      else if vf.toNat < c.n then
        some c.names[vf.toNat]!
      else
        some "<other>"
    leaderKnown := v.bool st.lk
    votesGranted := v.set fun j => v.bool st.votes[j]!
    preVotesGranted := v.set fun j => v.bool st.pv[j]!
    retiredCommittedIndex := if rci < 0 then none else some rci.toNat
  }

/-- Packet `x` of a channel's initial packets. -/
def Valuation.message (v : Valuation) (ch : SList) (x : Nat) : Message String String :=
  let f (i : Nat) := v.cell ch.arrs[i]! #[] x
  let term := (f M_TERM).toNat
  match f M_TAG with
  | 0 =>
      let entries := ch.arrs.extract M_ENTS ch.arrs.size
      .appendEntriesRequest
        {
          term
          prevLogIndex := (f M_PREV).toNat
          prevLogTerm := (f M_PREV_TERM).toNat
          entries := (List.range (f M_ENT_LEN).toNat).map fun i => v.entry entries #[x] i
          leaderCommit := (f M_LEADER_COMMIT).toNat
        }
  | 1 =>
      .appendEntriesResponse
        { term, success := f M_SUCCESS != 0, lastLogIndex := (f M_LAST_LOG).toNat }
  | 2 =>
      .requestVoteRequest
        {
          term
          lastCommittableTerm := (f M_LC_TERM).toNat
          lastCommittableIndex := (f M_LC_INDEX).toNat
        }
  | 3 => .requestVoteResponse { term, voteGranted := f M_GRANTED != 0 }
  | 4 =>
      .requestPreVote
        {
          term
          lastCommittableTerm := (f M_LC_TERM).toNat
          lastCommittableIndex := (f M_LC_INDEX).toNat
        }
  | 5 => .requestPreVoteResponse { term, voteGranted := f M_GRANTED != 0 }
  | _ => .proposeVoteRequest term

def witness (e : Env) (sys : Sys) (v : Valuation) : Replay.ReplayState :=
  let c := e.c
  let nodes := (List.range c.n).map fun i => (c.names[i]!, v.node sys.initial[i]!)
  let network :=
    sys.initialChans.toList.flatMap
      fun ((src, dst), ch) =>
        (List.range (v.nat ch.len)).map
          fun x =>
            {
              source := c.names[src]!, target := c.names[dst]!, payload := v.message ch x
            }
  { state := { nodes, active := e.header.declared, network } }

/-! ## Verdicts -/

structure Outcome where
  verdict : Sym.Verdict
  detail : String
  processed : Nat
  buildMs : Nat := 0
  lowerMs : Nat := 0
  solveMs : Nat := 0
  irNodes : Nat := 0
  smtLines : Nat := 0
  L : Nat := 0
  /-- IR nodes created by each instruction. -/
  irSizes : Array Nat := #[]
  /-- SMT terms at the start of each lowered instruction. -/
  smtSizes : Array (Nat × Nat) := #[]
  /-- Wide reads and folds: instruction, IR node, width. -/
  wide : Array (Nat × Nat × Int) := #[]
  /-- Time in backbone checks, included in `lowerMs`. -/
  probeMs : Nat := 0
  /-- Solver checks made for the backbone, and selectors they fixed. -/
  probes : Nat := 0
  pinned : Nat := 0
  witness : Option Replay.ReplayState := none

def runOnce (header : Replay.Header) (suffix : Array Json) (settings : Settings)
    : IO Outcome := do
  let e := makeEnv header suffix settings
  let start ← IO.monoMsNow
  let (ir, sys, processed) := build e suffix
  let irNodes := ir.nodes.size
  let buildMs := (← IO.monoMsNow) - start
  if let some path := settings.irDump then IO.FS.writeFile path ir.dump
  let irSizes :=
    ir.nodes.foldl
      (fun sizes node =>
        if node.instr < sizes.size then sizes.modify node.instr (· + 1) else sizes)
      (Array.replicate suffix.size 0)
  let base : Outcome :=
    { verdict := .unknown, detail := "", processed, buildMs, irNodes, L := e.L, irSizes }
  if let some (index, description) := ir.falsified then
    return {
      base with
        verdict := .invalid, detail := s!"instruction {index + 1}: {description}"
    }
  if let some what := ir.unsupported then
    return { base with detail := s!"unsupported: {what}" }
  let lowerStart ← IO.monoMsNow
  let session ← Smt.Session.spawn settings.solver
  let preamble := "(set-option :produce-models true)\n(set-logic QF_LIA)\n"
  session.send preamble
  let (ls, enc) := runLM ir lowerInit {} { refine := settings.refine }
  let mut ls := ls
  let mut enc := enc
  let mut sent := 0
  let mut nextCheck := settings.backbone
  let mut probeMs := 0
  let mut probes := 0
  let mut pinned := 0
  let mut early : Option String := none
  let flush (enc : Smt.Enc) (sent : Nat) : IO Nat := do
    if sent < enc.out.size then
      session.send ("\n".intercalate (enc.out.extract sent enc.out.size).toList ++ "\n")
    return enc.out.size
  for cmd in ir.cmds do
    if enc.falsified.isSome || enc.unsupported.isSome then break
    (ls, enc) := runLM ir (lowerCmd cmd) ls enc
    let .instr i _ := cmd | continue
    if nextCheck == 0 || i < nextCheck then continue
    nextCheck := 2 * i
    -- Backbone: pin each small-domain selector that the prefix forces.
    let hot :=
      enc.selectors.toArray.filter
        fun x =>
          let info := enc.infos[x]!
          info.lo < info.hi
    if hot.isEmpty then continue
    let probeStart ← IO.monoMsNow
    sent ← flush enc sent
    session.send "(check-sat)\n"
    probes := probes + 1
    let answer ← session.response
    if answer == "unsat" then
      early := some s!"instruction {i + 1}: the prefix is unsatisfiable"
      break
    if answer != "sat" then
      nextCheck := 0
      continue
    let model ← session.values hot
    for x in hot do
      let some m := model[x]? | continue
      let (lit, enc') := (Smt.eqK (.ref x) m).run enc
      enc := enc'
      let .ref b := lit | continue
      sent ← flush enc sent
      probes := probes + 1
      if (← session.check [s!"(not v{b})"]) == "unsat" then
        enc := ((Smt.require lit "backbone" (background := true)).run enc).2
        pinned := pinned + 1
    probeMs := probeMs + ((← IO.monoMsNow) - probeStart)
  let smtLines := enc.out.size
  let lowerMs := (← IO.monoMsNow) - lowerStart
  let base :=
    {
      base with
        lowerMs, smtLines, smtSizes := ls.sizes, wide := ls.wide, probeMs, probes, pinned
    }
  if let some detail := early then
    session.close
    return { base with verdict := .invalid, detail }
  if let some (index, description) := enc.falsified then
    session.close
    return {
      base with
        verdict := .invalid, detail := s!"instruction {index + 1}: {description}"
    }
  if let some what := enc.unsupported then
    session.close
    return { base with detail := s!"unsupported: {what}" }
  if let some path := settings.dump then
    IO.FS.writeFile path (preamble ++ "\n".intercalate enc.out.toList ++ "\n")
  let solveStart ← IO.monoMsNow
  discard <| flush enc sent
  session.send "(check-sat)\n"
  let answer ← session.response
  let mut outcome := base
  if answer == "sat" then
    let mut ids : Array Nat := #[]
    for h : id in [0:ir.nodes.size] do
      if let .var .. := ir.nodes[id].op then
        if let some (.s (.ref sid)) := ls.memo[id]? then ids := ids.push sid
    let mut cells : Std.HashMap (Nat × Array Int × Int) Tm := {}
    for (base, path, k, t) in ls.baseCells do
      cells := cells.insert (base, path, k) t
      if let .ref sid := t then ids := ids.push sid
    let values ← session.values ids
    let other :=
      (((List.range (e.c.ntx + 1)).map (s!"other{·}")).find?
        (!e.c.txNames.contains ·)).getD
        "other"
    let state := witness e sys { c := e.c, memo := ls.memo, cells, values, other }
    outcome :=
      match Replay.replayFrom header state suffix with
      | .ok _ => { base with verdict := .valid, witness := some state }
      | .error error => { base with detail := s!"ENGINE-BUG witness rejected: {error}" }
  else if answer == "unsat" then
    outcome :=
      { base with verdict := .invalid, detail := s!"unsat within L={e.L} Q={e.Q}" }
  else
    let err ← session.child.stderr.readToEnd
    outcome := { base with detail := s!"solver: {answer} {err}" }
  session.close
  return { outcome with solveMs := (← IO.monoMsNow) - solveStart }

/-- INVALID is relative to the bounds, so retry once with relaxed bounds. A VALID retry carries
a certified witness and therefore overrides the first answer. -/
def run (header : Replay.Header) (suffix : Array Json) (settings : Settings)
    : IO Outcome := do
  let first ← runOnce header suffix settings
  if first.verdict != .invalid || settings.retry == 0 then return first
  let relaxed ←
    runOnce header suffix
      {
        settings with
          Q := settings.Q * settings.retry, slack := settings.slack * settings.retry
      }
  let relaxed :=
    {
      relaxed with
        buildMs := first.buildMs + relaxed.buildMs
        lowerMs := first.lowerMs + relaxed.lowerMs
        solveMs := first.solveMs + relaxed.solveMs
    }
  match relaxed.verdict with
  | .valid =>
      return { relaxed with detail := s!"needed relaxed bounds; first: {first.detail}" }
  | .invalid =>
      return { relaxed with detail := s!"{relaxed.detail}; first: {first.detail}" }
  | .unknown =>
      return { first with detail := s!"{first.detail}; relaxed: {relaxed.detail}" }

end CCFRaft.MidTrace.Gen
