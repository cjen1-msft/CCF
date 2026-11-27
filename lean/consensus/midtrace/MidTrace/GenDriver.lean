module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter
public import MidTrace.GenLower
public import MidTrace.InitInvariant
public import MidTrace.SmtSession

@[expose] public section

namespace Consensus.MidTrace.Gen

open Replay (Group Packet StateSnapshot)
open Model.Node (Entry EntryContent Input Message NodeState)

structure Settings where
  solver : String := "yices-smt2"
  Q : Nat := 4
  slack : Nat := 4
  refine : Bool := true
  retry : Nat := 4
  backbone : Nat := 0
  gaps : Option GapFill := some .literal
  invariant : Bool := true
  reuse : Bool := true
  dump : Option String := none
  irDump : Option String := none
  /-- The solver time limit in seconds, if any. -/
  timeout : Option Nat := none

structure Env where
  header : Replay.Header
  c : Ctx
  L : Nat
  settings : Settings
  explicit : Array (Int × Int)

/-! Only log indices and lengths bound `L` and pick explicit intervals; terms, request IDs
and node IDs are not indices. -/

private def packetPoints : Packet → List Nat
  | .appendEntries p => [p.prev_idx, p.idx, p.leader_commit_idx]
  | .appendEntriesResponse p => [p.last_log_idx]
  | .requestVote p | .requestPreVote p => [p.last_committable_idx]
  | .requestVoteResponse _ | .requestPreVoteResponse _ | .proposeRequestVote _ => []

private def points : Replay.Instruction → List Nat
  | .observeNodeState _ s _ =>
      [
        s.last_idx,
        s.commit_idx,
        s.retirement_idx,
        s.retirement_committable_idx,
        s.retired_committed_idx
      ].reduceOption
      ++ s.committable_indices.getD []
  | .observeSends sends _ => sends.flatMap fun s => packetPoints s.packet
  | .action (.receive _ _ p) _ => packetPoints p
  | .action (.initAsBackup _ k _) _ => [k]
  | .action (.local _ (.append es)) _ =>
      es.length :: es.flatMap fun e => e.flushes.map Prod.snd
  | .action (.local _ (.sendEntries _ k)) _ => [k]
  | .action (.local _ (.initAsBackup es)) _ => [es.length]
  | .action (.local ..) _ => []

def explicitIntervals (mentioned : Array Nat) (slack : Nat) : Array (Int × Int) :=
  Id.run do
    let mut out : Array (Int × Int) := #[(0, 1 + slack)]
    for k in mentioned.qsort (· < ·) do
      let (a, b) := out.back!
      let lo : Int := k - (slack : Int)
      let hi : Int := k + slack
      if lo - b - 1 <= SMALL then
        out := out.pop.push (a, max b hi)
      else
        out := out.push (lo, hi)
    return out

@[no_expose]
def makeEnv (header : Replay.Header) (suffix : Array Group) (settings : Settings) : Env :=
  let nums := suffix.flatMap fun g => g.instructions.flatMap fun i => (points i).toArray
  {
    header,
    c := ⟨header.declared.length⟩,
    settings,
    L := nums.foldl max 0 + settings.slack,
    explicit :=
      if settings.gaps.isSome then explicitIntervals nums settings.slack else #[]
  }

/-- The backing arrays are retained separately from the masked arrays used by the model. -/
private def freshNode (e : Env) : GM (SNode × Array Tm) := do
  let index (hi : Nat) := declare false (some 0) (some hi)
  let (log, bases) ← declareLogWithBases e.c (← index e.L)
  let tab (m : GM Tm) := (Array.range e.c.n).mapM fun _ => m
  let st : SNode :=
    {
      role := ← declare false (some ROLE_NONE) (some ROLE_PRIMARY),
      ct := ← declareNat,
      log,
      ci := ← index e.L,
      sent := ← tab (index (e.L + 1)),
      mi := ← tab (index e.L),
      nf := ← declareBool,
      vf := ← declare false (some (-1)) (some (e.c.n - 1 : Nat)),
      pk := ← declareBool,
      votes := ← tab declareBool,
      pv := ← tab declareBool,
      rci := ← declare false (some (-1)) (some e.L)
    }
  return (st, bases)

private def freshMsg (e : Env) : GM (SMsg × Array Tm) := do
  let index := declare false (some 0) (some e.L)
  let (log, bases) ← declareLogWithBases e.c (← index)
  let prev ← index
  let msg ←
    mkMsg e.c TAG_AE (← declareNat)
      [
        (M_PREV, prev),
        (M_PREV_TERM, ← declareNat),
        (M_PRIMARY_COMMIT, ← index),
        (M_SUCCESS, ← declareBool),
        (M_LAST_LOG, ← index),
        (M_LC_TERM, ← declareNat),
        (M_LC_INDEX, ← index),
        (M_GRANTED, ← declareBool)
      ] (some { log with off := prev })
  return (msg.set! M_TAG (← declare false (some TAG_AE) (some TAG_PROPOSE)), bases)

/-- Only AE has payload not determined by the native packet. -/
private def packetFields (p : Packet) : Int × Nat × List (Nat × Tm) :=
  match p with
  | .appendEntries r =>
      (
        TAG_AE,
        r.term,
        [
          (M_PREV, .int r.prev_idx),
          (M_PREV_TERM, .int r.prev_term),
          (M_PRIMARY_COMMIT, .int r.leader_commit_idx)
        ]
      )
  | .appendEntriesResponse r =>
      (
        TAG_AER,
        r.term,
        [(M_LAST_LOG, .int r.last_log_idx), (M_SUCCESS, .bool (r.success == "OK"))]
      )
  | .requestVote r | .requestPreVote r =>
      (
        if p matches .requestVote _ then TAG_RV else TAG_RPV,
        r.term,
        [
          (M_LC_TERM, .int r.term_of_last_committable_idx),
          (M_LC_INDEX, .int r.last_committable_idx)
        ]
      )
  | .requestVoteResponse r | .requestPreVoteResponse r =>
      (
        if p matches .requestVoteResponse _ then TAG_RVR else TAG_RPVR,
        r.term,
        [(M_GRANTED, .bool r.vote_granted)]
      )
  | .proposeRequestVote r => (TAG_PROPOSE, r.term, [])

private def packetMatches (m : SMsg) (p : Packet) : GM Tm := do
  let (tag, term, fields) := packetFields p
  let mut parts := [← eqK m[M_TAG]! tag, ← eqK m[M_TERM]! term]
  for (i, v) in fields do
    parts := (← eqT m[i]! v) :: parts
  match p with
  | .appendEntries r =>
      if r.contains_new_view || r.idx < r.prev_idx then return .bool false
      let len := r.idx - r.prev_idx
      let last ←
        if len == 0 then
          pure m[M_PREV_TERM]!
        else
          -- Nonempty sends slice the zero-based node log at prev; initial slots use prev directly.
          select m[M_ENTS + E_TERM]! (.int (r.idx - 1))
      parts := (← eqK m[M_ENT_LEN]! len) :: (← eqK last r.term_of_idx) :: parts
  | .appendEntriesResponse r =>
      if r.success != "OK" && r.success != "FAIL" then return .bool false
  | _ => pure ()
  andL parts

private def committableIs (st : SNode) (indices : List Nat) : GM Tm := do
  let lo ← addK st.ci 1
  let empty (a b : Tm) := foldAll a b fun k => do notT (← isSignatureAt st.log k)
  let ends (f l : Nat) := do
    andL
      [
        ← le lo (.int f),
        ← isSignatureAt st.log (.int f),
        ← isSignatureAt st.log (.int l),
        ← empty lo (.int ((f : Int) - 1)),
        ← empty (.int (l + 1)) st.log.len
      ]
  match indices with
  | [] => empty lo st.log.len
  | [f] => ends f f
  | [f, l] => if f < l then ends f l else pure (.bool false)
  | _ => return .bool false

private def observeNodeState (c : Ctx) (self : Nat) (name : String) (st : SNode)
    (s : StateSnapshot)
    : GM Unit := do
  let ck t field := require t s!"state {name}.{field}"
  ck (.bool (s.node_id == name)) "node_id"
  if let some role := s.leadership_state then
    let codes :=
      [
        ("None", ROLE_NONE),
        ("Follower", ROLE_FOLLOWER),
        ("PreVoteCandidate", ROLE_PREVOTE),
        ("Candidate", ROLE_CANDIDATE),
        ("Leader", ROLE_PRIMARY)
      ]
    ck (← eqK st.role ((codes.lookup role).getD (-1))) "leadership_state"
  for (field, observed, t)
      in [
        ("current_view", s.current_view, st.ct),
        ("last_idx", s.last_idx, st.log.len),
        ("commit_idx", s.commit_idx, st.ci),
        ("retired_committed_idx", s.retired_committed_idx, st.rci)
      ] do
    if let some v := observed then ck (← eqK t v) field
  if let some indices := s.committable_indices then
    ck (← committableIs st indices) "committable_indices"
  if s.membership_state.isNone
      && s.retirement_phase.isNone
      && s.retirement_idx.isNone
      && s.retirement_committable_idx.isNone then
    return
  let r ← st.retirement c self
  if let some membership := s.membership_state then
    let active ← eqK r.phase PHASE_ACTIVE
    ck
      (← match membership with
          | "Active" => pure active
          | "Retired" => notT active
          | _ => pure (.bool false))
      "membership_state"
  if let some phase := s.retirement_phase then
    let codes :=
      [
        ("Ordered", PHASE_ORDERED),
        ("Signed", PHASE_SIGNED),
        ("Completed", PHASE_COMPLETED),
        ("RetiredCommitted", PHASE_RETIRED_COMMITTED)
      ]
    ck (← eqK r.phase ((codes.lookup phase).getD (-1))) "retirement_phase"
  for (field, observed, opt)
      in [
        ("retirement_idx", s.retirement_idx, r.index),
        ("retirement_committable_idx", s.retirement_committable_idx, r.committableIndex)
      ] do
    if let some v := observed then ck (← andL [opt.isSome, ← eqK opt.val v]) field

private structure Slot where
  msg : SMsg
  alive : Tm
  /-- Known for observed sends; absent for pre-cut envelopes. -/
  packet : Option Packet := none
deriving Inhabited

private abbrev Channel := Nat × Nat

/-- Lexicographic order on `(source, target)`. -/
private def Channel.lt (a b : Channel) : Bool :=
  a.1 < b.1 || (a.1 == b.1 && a.2 < b.2)

private structure InitialSlot where
  channel : Channel
  present : Tm
  msg : SMsg
  bases : Array Tm

private structure Sys where
  nodes : Array SNode := #[]
  initial : Array (SNode × Array Tm) := #[]
  initialSlots : Array InitialSlot := #[]
  pool : Std.HashMap Channel (Array Slot) := {}
  queued : Array (Tm × Nat × SMsg) := #[]

private abbrev DM := ReaderT Env (StateT Sys GM)

private def nodeId (name : String) : DM Nat := do
  match (← read).header.nodeId name with
  | .ok i => return i
  | .error why => falsify why; return 0

private def setPool (ch : Channel) (slots : Array Slot) : DM Unit :=
  modifyThe Sys fun s => { s with pool := s.pool.insert ch slots }

private def choose (n : Nat) (selector := false) : GM Tm :=
  if n <= 1 then
    pure (.int 0)
  else
    declare false (some 0) (some (n - 1 : Nat)) (selector := selector)

private def mux {α : Type} [Merge α] [Inhabited α] (values : Array α) (sel : Tm)
    : GM α := do
  let mut result := values[0]!
  for i in [1:values.size] do
    result ← Merge.merge (← eqK sel i) values[i]! result
  return result

private def observeSends (actor : Nat) (sends : List Replay.NativeSend) : DM Unit := do
  let expected ← sends.mapM fun s => do return (← nodeId s.target, s.packet)
  let queued := (← getThe Sys).queued
  for dst in (← read).c.nodes do
    let ps := expected.filterMap fun (d, p) => if d == dst then some p else none
    let qs := queued.filter fun (_, d, _) => d == dst
    if qs.size < ps.length then falsify "native send not queued"; return
    let mut slots := (← getThe Sys).pool.getD (actor, dst) #[]
    let mut picks : Array Tm := #[]
    for p in ps do
      let sel ← choose qs.size
      for prev in picks do
        require (← neT sel prev) "send used twice"
      picks := picks.push sel
      let msg ← mux (qs.map fun (_, _, m) => m) sel
      require (← packetMatches msg p) "send packet mismatch"
      slots := slots.push ⟨msg, .bool true, some p⟩
    for h : i in [:qs.size] do
      let used ← orL (← picks.toList.mapM (eqK · i))
      require (← eqT qs[i].1 used) "send multiplicity"
    setPool (actor, dst) slots
  modifyThe Sys fun s => { s with queued := #[] }

private def runStep (self : Nat) (step : SNode → EM SNode) (name : String) : DM Unit := do
  let st := (← getThe Sys).nodes[self]!
  let (next, eff) ← ((step st).run {} : GM (SNode × Eff))
  require eff.ok s!"disabled model action '{name}'"
  modifyThe Sys
    fun s => { s with nodes := s.nodes.set! self next, queued := s.queued ++ eff.sends }

private def deliver (src dst : Nat) (p : Packet) : DM Unit := do
  let c := (← read).c
  let ch := (src, dst)
  let mut slots := (← getThe Sys).pool.getD ch #[]
  let candidates :=
    slots.zipIdx.filter fun (s, _) => s.packet.all (· == p) && s.alive != .bool false
  if candidates.isEmpty then falsify "no pending packet"; return
  let sel ← choose candidates.size (selector := p matches .appendEntries _)
  let (tag, term, fields) := packetFields p
  let entries ←
    match p with
    | .appendEntries r => do
        let arrs ← mux (candidates.map fun (s, _) => (msgEntries s.msg).arrs) sel
        pure
          (some
            { arrs, off := .int r.prev_idx, len := .int (r.idx - r.prev_idx) : SList })
    | _ => pure none
  let delivered ← mkMsg c tag (.int term) fields entries
  let mut fromInitial := #[]
  for h : j in [:candidates.size] do
    let (s, i) := candidates[j]
    let chosen ← eqK sel j
    if s.packet.isNone then fromInitial := fromInitial.push chosen
    let matchesPacket ←
      if s.packet.isSome then pure (.bool true) else packetMatches s.msg p
    let ready ← andL [s.alive, matchesPacket]
    require (← impliesT chosen ready) "no matching pending packet"
    -- Initial slots on a channel are interchangeable (`s0.network` is a multiset),
    -- so break symmetry: consume them in index order. `ready`, not this, decides ambiguity.
    if s.packet.isNone && i > 0 then
      require (← impliesT chosen (← notT slots[i - 1]!.alive)) "initial slot order"
    -- Replay rejects ambiguity even if one choice would replay successfully.
    if let .appendEntries r := p then
      if candidates.size > 1 && r.prev_idx < r.idx then
        let same ←
          foldAll (.int r.prev_idx) (.int (r.idx - 1))
            fun k => do
              SSet.eqS (← (msgEntries delivered).arrs.mapM (select · k))
                (← (msgEntries s.msg).arrs.mapM (select · k))
        require (← impliesT ready same) "ambiguous delivery"
    slots := slots.set! i { s with alive := ← andL [s.alive, ← notT chosen] }
  -- Every present initial slot must be consumed. Check it here with the concrete
  -- packet window, but against its sender and target at the cut, not at delivery.
  if (← read).settings.invariant && !fromInitial.isEmpty then
    let initial := (← getThe Sys).initial
    InitInvariant.constrainMessage src dst (fun i => initial[i]!.1)
      (← orL fromInitial.toList) delivered
  setPool ch slots
  runStep dst (fun st => receive c dst src st delivered) "receive"

private def initFrom (self k view : Nat) : DM Unit := do
  let c := (← read).c
  let nodes := (← getThe Sys).nodes
  let log ←
    if k == 0 then do
      require (.bool (view == 0)) "nonzero empty prefix view"
      literalLog c []
    else do
      let sel ← choose nodes.size (selector := true)
      let mut prior : Tm := .bool false
      for h : i in [:nodes.size] do
        let s := nodes[i]
        let ok ←
          andL
            [
              ← le (.int k) s.ci,
              ← isSignatureAt s.log (.int k),
              ← eqK (← termAt s.log (.int k)) view
            ]
        -- With the invariant disabled eligible sources may disagree: replay takes the first.
        require (← impliesT (← eqK sel i) (← andL [ok, ← notT prior]))
          "no committed source"
        prior ← orL [prior, ok]
      mux (← nodes.mapM fun s => s.log.take (.int k)) sel
  runStep self (initAsBackup · log) "initAsBackup"

private def localStep (self : Nat) (input : Input) : DM Unit := do
  let c := (← read).c
  match input with
  | .sendEntries dst _ => if dst >= c.n then falsify "undeclared destination"; return
  | .append es =>
      for e in es do
        let m := e.content.metadata
        unless (m.configuration.getD ∅ ∪ m.retirementConfirmations).sort.all (· < c.n)
                && e.flushes.all (·.1 < c.n) do
          falsify "undeclared node in append"; return
  | .initAsBackup es =>
      unless es.all
              (fun e =>
                let m := e.content.metadata
                (m.configuration.getD ∅ ∪ m.retirementConfirmations).sort.all
                  (· < c.n)) do
        falsify "snapshot prefix names an undeclared node"; return
      let log ← literalLog c es
      let ok ←
        (← getThe Sys).nodes.mapM
          fun s => do
            let same ←
              foldAll (.int 0) (.int ((es.length : Int) - 1))
                fun k => do
                  SSet.eqS (← log.get k) (← s.log.get k)
            andL [← le log.len s.ci, ← le log.len s.log.len, same]
      require (← orL ok.toList) "not a committed prefix"
  | _ => pure ()
  runStep self (act c self · input) (Replay.Step.local "" input).name

private def build (e : Env) (suffix : Array Group) : Ir × Sys :=
  Id.run do
    let run : DM Unit := do
      if e.c.n == 0 && !suffix.isEmpty then falsify "no declared nodes"; return
      let initial ← (Array.range e.c.n).mapM fun _ => freshNode e
      let nodes := initial.map Prod.fst
      let mut counts : Std.HashMap Channel Nat := {}
      for g in suffix do
        for i in g.instructions do
          if let .action (.receive a b _) _ := i then
            let ch := (← nodeId a, ← nodeId b)
            counts := counts.insert ch (counts.getD ch 0 + 1)
      let mut initialSlots := #[]
      -- Sorted channels make the script and witness deterministic.
      -- Without `InitInvariant` and bounded pre-cut slots (`Q`), every delivered message
      -- in the suffix could be explained as coming from before the trace (`s0.network`),
      -- decoupling receives from post-cut sends.
      for (ch, count) in counts.toArray.qsort (fun a b => Channel.lt a.1 b.1) do
        let mut slots := #[]
        for _ in [:min count e.settings.Q] do
          let present ← declareBool
          if let some prev := slots.back? then
            require (← impliesT present prev.alive) "initial slot order"
          let (msg, bases) ← freshMsg e
          slots := slots.push ⟨msg, present, none⟩
          initialSlots := initialSlots.push (⟨ch, present, msg, bases⟩ : InitialSlot)
        setPool ch slots
      modifyThe Sys fun s => { s with nodes, initial, initialSlots }
      if e.settings.invariant then
        InitInvariant.constrain e.c e.header.bootstrap nodes
      let mut idx := 0
      for g in suffix do
        let actor ← nodeId g.node
        for i in g.instructions do
          setInstruction idx
          idx := idx + 1
          match i with
          | .action (.receive a b p) _ => deliver (← nodeId a) (← nodeId b) p
          | .action (.initAsBackup n k t) _ => initFrom (← nodeId n) k t
          | .action (.local n input) _ => localStep (← nodeId n) input
          | .observeNodeState n expected _ =>
              let self ← nodeId n
              observeNodeState e.c self n (← getThe Sys).nodes[self]! expected
          | .observeSends sends _ => observeSends actor sends
          if (← getThe Ir).falsified.isSome then return
      for (_, slots)
          in (← getThe Sys).pool.toArray.qsort (fun a b => Channel.lt a.1 b.1) do
        for s in slots do
          if s.packet.isNone then require (← notT s.alive) "unused initial packet"
    let ((_, sys), ir) := ((run.run e).run {}).run {}
    return (ir, sys)

private structure Valuation where
  explicit : Array (Int × Int)
  memo : Std.HashMap Nat Val
  cells : Std.HashMap (Nat × Int) Tm
  values : Std.HashMap Nat Int

private def Valuation.smt (v : Valuation) : Tm → Int
  | .ref i => v.values[i]!
  | .bool b => if b then 1 else 0
  | .int n => n

private def Valuation.scalar (v : Valuation) (t : Tm) : Int :=
  match t with
  | .ref i =>
      match v.memo[i]? with
      | some (.s s) => v.smt s
      | _ => 0 -- Unknown never lowered; zero is in every initial scalar domain.
  | _ => v.smt t

private def Valuation.log (v : Valuation) (n : Nat) (log : SList) (bases : Array Tm)
    : List Entry :=
  Id.run do
    let mut entries := #[]
    let mut prev := Model.BOOTSTRAP_TERM
    let off := (v.scalar log.off).toNat
    for k in [off:off + (v.scalar log.len).toNat] do
      let key := cellKey v.explicit k
      let field (i : Nat) (fallback : Int := 0) : Int :=
        match bases[i]! with
        | .ref id => (v.cells[(id, key)]?.map v.smt).getD fallback
        | _ => fallback
      let members (offset : Nat) :=
        CCF.Finset.ofList ((List.range n).filter fun j => field (offset + j) != 0)
      let term := (field E_TERM (if key != (k : Int) then prev else 0)).toNat
      let content :=
        if field E_SIG != 0 then
          .signature
        else
          EntryContent.transaction (field E_REQ).toNat
            {
              configuration :=
                if field E_HAS_CFG == 0 then none else some (members E_CFG_START),
              retirementConfirmations := members (E_RC_START n)
            }
      entries := entries.push (⟨term, content⟩ : Entry)
      prev := term
    return entries.toList

private def Valuation.node (v : Valuation) (n : Nat) (st : SNode) (bases : Array Tm)
    : NodeState :=
  let nat t := (v.scalar t).toNat
  let opt t := if v.scalar t < 0 then none else some (nat t)
  let bit t := v.scalar t != 0
  let role :=
    match v.scalar st.role with
    | 1 => .follower
    | 2 => .preVoteCandidate
    | 3 => .candidate
    | 4 => .primary
    | _ => Model.Node.Role.none
  let set (xs : Array Tm) := CCF.Finset.ofList ((List.range n).filter fun i => bit xs[i]!)
  let peer (xs : Array Tm) := fun i => (xs[i]?.map nat).getD 0
  {
    role,
    currentTerm := nat st.ct,
    log := v.log n st.log bases,
    commitIndex := nat st.ci,
    sentIndex := peer st.sent,
    matchIndex := peer st.mi,
    isNewFollower := bit st.nf,
    votedFor := opt st.vf,
    primaryKnown := bit st.pk,
    votesGranted := set st.votes,
    preVotesGranted := set st.pv,
    retiredCommittedIndex := opt st.rci
  }

private def Valuation.message (v : Valuation) (n : Nat) (slot : InitialSlot) : Message :=
  let f (i : Nat) := (v.scalar slot.msg[i]!).toNat
  let term := f M_TERM
  let vote : Model.Node.RequestVoteRequest :=
    { term, lastCommittableTerm := f M_LC_TERM, lastCommittableIndex := f M_LC_INDEX }
  let response : Model.Node.RequestVoteResponse :=
    { term, voteGranted := f M_GRANTED != 0 }
  match f M_TAG with
  | 0 =>
      .appendEntriesRequest
        {
          term,
          prevLogIndex := f M_PREV,
          prevLogTerm := f M_PREV_TERM,
          entries := v.log n (msgEntries slot.msg) slot.bases,
          primaryCommit := f M_PRIMARY_COMMIT
        }
  | 1 =>
      .appendEntriesResponse
        { term, success := f M_SUCCESS != 0, lastLogIndex := f M_LAST_LOG }
  | 2 => .requestVoteRequest vote
  | 3 => .requestVoteResponse response
  | 4 => .requestPreVoteRequest vote
  | 5 => .requestPreVoteResponse response
  | _ => .proposeRequestVoteRequest term

private def witness (session : Smt.Session) (ir : Ir) (ls : LState) (sys : Sys)
    : IO (Except String Model.State) := do
  let mut ids := #[]
  for h : i in [:ir.nodes.size] do
    if ir.nodes[i].op matches .var .. then
      if let some (.s (.ref sid)) := ls.memo[i]? then ids := ids.push sid
  let mut cells := {}
  for (id, path, k, t) in ls.baseCells do
    if path.isEmpty then
      cells := cells.insert (id, k) t
      if let .ref sid := t then ids := ids.push sid
  let values ←
    match ← session.values ids with
    | .ok values => pure values
    | .error why => return .error why
  let v : Valuation := ⟨ls.explicit, ls.memo, cells, values⟩
  let n := sys.initial.size
  return .ok
    {
      nodes := sys.initial.toList.mapIdx fun i (s, bases) => (i, v.node n s bases)
      network :=
        sys.initialSlots.toList.filterMap
          fun s =>
            if v.scalar s.present != 0 then
              some ⟨s.channel.1, s.channel.2, v.message n s⟩
            else
              none
    }

structure Outcome where
  verdict : Verdict := .unknown
  detail : String := ""
  assumptions : Assumptions
  witness : Option Model.State := none
  buildMs : Nat := 0
  lowerMs : Nat := 0
  probeMs : Nat := 0
  solveMs : Nat := 0
  certifyMs : Nat := 0
  irNodes : Nat := 0
  smtLines : Nat := 0
  probes : Nat := 0
  pinned : Nat := 0
  gapProbed : Nat := 0
  gapEnumerated : Nat := 0
  foldPoints : Nat := 0
  foldReused : Nat := 0
  scansSeeded : Nat := 0

private def flush (session : Smt.Session) (enc : Smt.Enc) (sent : Nat) : IO Nat := do
  if sent < enc.out.size then
    session.send ("\n".intercalate (enc.out.extract sent enc.out.size).toList ++ "\n")
  return enc.out.size

/-- A diagnostic at instruction `i` of the flattened suffix, located at its trace origin. -/
private def located (suffix : Array Group) (i : Nat) (why : String) : String :=
  match (suffix.flatMap (·.instructions))[i]? with
  | some instruction => s!"{instruction.origin.label}: {why} (instruction {i + 1})"
  | none => s!"instruction {i + 1}: {why}"

private def preamble := "(set-option :produce-models true)\n(set-logic QF_LIA)\n"

private def describe (answer : String) : String :=
  if answer.isEmpty then "no response" else answer

/-- Sets `script` to the SMT script once lowering ends, for `--dump`. -/
private def solve (session : Smt.Session) (e : Env) (ir : Ir) (sys : Sys)
    (suffix : Array Group) (base : Outcome) (script : IO.Ref (Option String))
    : IO Outcome := do
  let start ← IO.monoMsNow
  session.send preamble
  let mut enc : Smt.Enc := { refine := e.settings.refine }
  let mut ls : LState :=
    {
      explicit := e.explicit,
      fill := e.settings.gaps.getD .literal,
      reuse := e.settings.reuse
    }
  let mut sent := 0
  let mut next := e.settings.backbone
  let mut probes := 0
  let mut pinned := 0
  let mut probeMs := 0
  let mut early := none
  for cmd in ir.cmds do
    (ls, enc) := runLM ir (lowerCmd cmd) ls enc
    if enc.unsupported.isSome || enc.falsified.isSome then break
    if enc.out.size >= sent + 1024 then sent ← flush session enc sent
    let .instr i := cmd | continue
    if next == 0 || i < next then continue
    next := 2 * next
    -- A SAT alternative stays open for later checkpoints; a pinned selector is a singleton.
    let hot := enc.selectors.toArray.filter fun x => enc.infos[x]!.value?.isNone
    if hot.isEmpty then continue
    let t ← IO.monoMsNow
    sent ← flush session enc sent
    session.send "(check-sat)\n"
    probes := probes + 1
    match ← session.response with
    | "unsat" => early := some (located suffix i "unsatisfiable prefix before this")
    | "sat" =>
        let model ←
          match ← session.values hot with
          | .ok model => pure model
          | .error why => return { base with detail := s!"solver: {why}" }
        for x in hot do
          let some m := model[x]? | continue
          let (lit, enc') :=
            (Smt.eqT (.ref x) (Smt.literal enc.infos[x]!.isBool m)).run enc
          enc := enc'
          let .ref b := lit | continue
          sent ← flush session enc sent
          probes := probes + 1
          let answer ← session.check [s!"(not v{b})"]
          if Smt.failed answer then
            return { base with detail := s!"solver: {describe answer}" }
          if answer == "unsat" then
            enc := ((Smt.require lit "backbone").run enc).2
            pinned := pinned + 1
    | "unknown" => next := 0
    | answer => return { base with detail := s!"solver: {describe answer}" }
    probeMs := probeMs + ((← IO.monoMsNow) - t)
    if early.isSome then break
  let base :=
    {
      base with
        probes,
        pinned,
        probeMs,
        lowerMs := (← IO.monoMsNow) - start - probeMs,
        smtLines := enc.out.size,
        gapProbed := ls.probed,
        gapEnumerated := ls.enumerated.size,
        foldPoints := ls.points,
        foldReused := ls.reusedPoints,
        scansSeeded := ls.seededScans
    }
  if e.settings.dump.isSome then
    script.set
      (some
        <| preamble
            ++ "\n".intercalate enc.out.toList
            ++ (if enc.falsified.isSome then "\n(assert false)" else "")
            ++ "\n(check-sat)\n")
  if let some (i, why) := enc.unsupported then
    return { base with detail := s!"unsupported: {located suffix i why}" }
  if let some (i, why) := enc.falsified then early := some (located suffix i why)
  if let some detail := early then return { base with verdict := .invalidBounded, detail }
  let t ← IO.monoMsNow
  discard <| flush session enc sent
  session.send "(check-sat)\n"
  let answer ← session.response
  let base := { base with solveMs := (← IO.monoMsNow) - t }
  match answer with
  | "unsat" =>
      return {
        base with
          verdict := .invalidBounded, detail := "unsatisfiable within stated bounds"
      }
  | "sat" =>
      let t ← IO.monoMsNow
      let state ←
        match ← witness session ir ls sys with
        | .ok state => pure state
        | .error why => return { base with detail := s!"solver: {why}" }
      let result := do
        if e.settings.invariant then InitInvariant.check e.header.bootstrap state
        discard <| Replay.replayFrom e.header { state } suffix
      let base := { base with certifyMs := (← IO.monoMsNow) - t }
      match result with
      | .ok () => return { base with verdict := .validCertified, witness := some state }
      | .error why => return { base with detail := s!"ENGINE-BUG: {why}" }
  | _ => return { base with detail := s!"solver: {describe answer}" }

private def runOnce (header : Replay.Header) (suffix : Array Group) (settings : Settings)
    (retried : Bool)
    : IO Outcome := do
  let t ← IO.monoMsNow
  let e := makeEnv header suffix settings
  let (ir, sys) := build e suffix
  let gapPolicy :=
    match settings.gaps with
    | some .literal => "literal"
    | some .uniform => "uniform"
    | none => "off"
  let assumptions : Assumptions :=
    {
      Q := settings.Q,
      L := e.L,
      slack := settings.slack,
      gapPolicy,
      invariant := if settings.invariant then "on" else "off",
      retried,
      timeout := settings.timeout
    }
  let base : Outcome :=
    { assumptions, irNodes := ir.nodes.size, buildMs := (← IO.monoMsNow) - t }
  if let some path := settings.irDump then IO.FS.writeFile path ir.dump
  if let some (i, why) := ir.unsupported then
    return { base with detail := s!"unsupported: {located suffix i why}" }
  if let some (i, why) := ir.falsified then
    if let some path := settings.dump then
      IO.FS.writeFile path (preamble ++ "(assert false)\n(check-sat)\n")
    return { base with verdict := .invalidBounded, detail := located suffix i why }
  let session ←
    try
      Smt.Session.spawn settings.solver settings.timeout
    catch err =>
      return { base with detail := s!"solver: {err}" }
  let script ← IO.mkRef none
  let result ←
    try
      Except.ok <$> solve session e ir sys suffix base script
    catch err =>
      pure (.error s!"solver: {err}")
  let stderr ← session.close (abort := result.toOption.all (·.verdict == .unknown))
  let timedOut ← session.timedOut.get
  -- Outside the solver error handling, so a bad path fails like `--ir-dump`.
  if let some path := settings.dump then
    if let some text ← script.get then IO.FS.writeFile path text
  let withStderr (detail : String) :=
    if stderr.isEmpty then detail else s!"{detail}; stderr: {stderr.take 1000}"
  -- A solver killed at its time limit stops answering; say why rather than what failed.
  let why (detail : String) :=
    match settings.timeout with
    | some secs => if timedOut then s!"solver: timed out after {secs} s" else detail
    | none => detail
  match result with
  | .ok outcome =>
      if outcome.verdict == .unknown then
        return { outcome with detail := withStderr (why outcome.detail) }
      return outcome
  | .error detail => return { base with detail := withStderr (why detail) }

/-- UNSAT is bounded. Report the second verdict even when relaxing the bounds yields unknown. -/
@[no_expose]
def run (header : Replay.Header) (suffix : Array Group) (settings : Settings := {})
    : IO Outcome := do
  let first ← runOnce header suffix settings false
  if first.verdict != .invalidBounded || settings.retry <= 1 then return first
  let relaxed ←
    runOnce header suffix
      {
        settings with
          Q := settings.Q * settings.retry, slack := settings.slack * settings.retry
      }
      true
  return {
    relaxed with
      detail := s!"{relaxed.detail} (first attempt: {first.detail})".trimAscii.toString,
      buildMs := first.buildMs + relaxed.buildMs,
      lowerMs := first.lowerMs + relaxed.lowerMs,
      probeMs := first.probeMs + relaxed.probeMs,
      solveMs := first.solveMs + relaxed.solveMs,
      certifyMs := first.certifyMs + relaxed.certifyMs,
      irNodes := first.irNodes + relaxed.irNodes,
      smtLines := first.smtLines + relaxed.smtLines,
      probes := first.probes + relaxed.probes,
      pinned := first.pinned + relaxed.pinned,
      gapProbed := first.gapProbed + relaxed.gapProbed,
      gapEnumerated := first.gapEnumerated + relaxed.gapEnumerated,
      foldPoints := first.foldPoints + relaxed.foldPoints,
      foldReused := first.foldReused + relaxed.foldReused,
      scansSeeded := first.scansSeeded + relaxed.scansSeeded
  }

end Consensus.MidTrace.Gen
