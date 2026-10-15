module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SmtCore

@[expose] public section

/-!
# SMT encoding of the model

A direct transcription of `Model/Node.lean` over SMT terms. A node's state is
a record of terms; every `if` of the model becomes an `ite` over the two
branches' states (`branch`), and a send records the path condition under
which it happens. There is no case splitting: the solver sees one formula
whose models are the runs of the suffix.

Logs have `Env.K` cells; index `k` is cell `k - 1`. A log query that could
read beyond the cells returns a fresh value when the log is longer than
`K`, which over-approximates the model; the `cap` assumption excludes such
logs, so a model found under `cap` is exact.

Channels are queues of absolute positions: the first `p` positions hold
messages in flight at the cut (phantoms) and the rest are the suffix's sends
in order. Receives consume positions `0, 1, ...`, so the position of a
receive is known and only `p` and the conditions of earlier sends are
symbolic.
-/

namespace CCFRaft.MidTrace.Smt

open Lean CCFRaft.Replay CCFRaft.Model.Node

/-! ## Environment -/

structure Env where
  header : Header
  names : Array String
  /-- Node indices ordered by name: the order in which CCF iterates over peers. -/
  sorted : Array Nat
  /-- Log cells per node. -/
  K : Nat
  /-- Phantoms per channel. -/
  Q : Nat
  txNames : Array String
  boot : Array Bool
  preVote : Array Bool
  invariants : Bool

def Env.n (env : Env) : Nat := env.names.size

abbrev EM := ReaderT Env OpM

def ROLE_NONE : Int := 0
def ROLE_FOLLOWER : Int := 1
def ROLE_PRE_VOTE_CANDIDATE : Int := 2
def ROLE_CANDIDATE : Int := 3
def ROLE_LEADER : Int := 4

def KIND_AE : Int := 0
def KIND_AER : Int := 1
def KIND_RV : Int := 2
def KIND_RVR : Int := 3
def KIND_RPV : Int := 4
def KIND_RPVR : Int := 5
def KIND_PROPOSE : Int := 6

def PHASE_ACTIVE : Int := 0
def PHASE_ORDERED : Int := 1
def PHASE_SIGNED : Int := 2
def PHASE_COMPLETED : Int := 3
def PHASE_RETIRED_COMMITTED : Int := 4

def falses (n : Nat) : Array Tm := Array.replicate n (.bool false)

def unit (n i : Nat) : Array Tm := (falses n).set! i (.bool true)

def iteBits (c : Tm) (a b : Array Tm) : OpM (Array Tm) :=
  (a.zip b).mapM fun (x, y) => iteT c x y

def andBits (a b : Array Tm) : OpM (Array Tm) :=
  (a.zip b).mapM fun (x, y) => andL [x, y]

def eqBits (a b : Array Tm) : OpM Tm := do
  andL ((← (a.zip b).mapM fun (x, y) => eqT x y).toList)

/-! ## Entries -/

def SEntry.dummy (n : Nat) : SEntry :=
  {
    term := .int 0
    sig := .bool true
    tx := .int 0
    cfg := .bool false
    cfgBits := falses n
    rc := .bool false
    rcBits := falses n
  }

def iteEntry (c : Tm) (a b : SEntry) : OpM SEntry := do
  if a == b then return a
  match ← norm c with
  | .bool true => return a
  | .bool false => return b
  | c =>
      return {
        term := ← iteT c a.term b.term
        sig := ← iteT c a.sig b.sig
        tx := ← iteT c a.tx b.tx
        cfg := ← iteT c a.cfg b.cfg
        cfgBits := ← iteBits c a.cfgBits b.cfgBits
        rc := ← iteT c a.rc b.rc
        rcBits := ← iteBits c a.rcBits b.rcBits
      }

/-- An unknown entry; at most one reconfiguration then one retirement record. -/
def freshEntry : EM SEntry := do
  let env ← read
  let term ← declareNat
  let sig ← declareBool
  let tx ←
    if env.txNames.size <= 1 then
      pure (.int 0)
    else
      declare false 0 ((env.txNames.size - 1 : Nat) : Int)
  let notSig ← notT sig
  let cfg ← andL [notSig, ← declareBool]
  let rc ← andL [notSig, ← declareBool]
  let cfgBits ← (Array.range env.n).mapM fun _ => declareBool
  let rcBits ← (Array.range env.n).mapM fun _ => declareBool
  if env.invariants then
    assumeInv (← impliesT cfg (← orL cfgBits.toList))
    assumeInv (← impliesT rc (← orL rcBits.toList))
  return { term, sig, tx, cfg, cfgBits, rc, rcBits }

def bitsOf (env : Env) (nodes : Finset String) : Array Tm :=
  env.names.map fun name => .bool (decide (name ∈ nodes))

/-- A known entry, if the encoding can represent its effects. -/
def knownEntry (env : Env) (term : Tm) (content : EntryContent String String)
    : Option SEntry :=
  let base := { SEntry.dummy env.n with term }
  match content with
  | .signature => some base
  | .transaction id effects => do
      let tx ← env.txNames.idxOf? id
      let base := { base with sig := .bool false, tx := .int tx }
      match effects with
      | [] => some base
      | [.reconfiguration nodes] =>
          some { base with cfg := .bool true, cfgBits := bitsOf env nodes }
      | [.retiredCommitted nodes] =>
          some { base with rc := .bool true, rcBits := bitsOf env nodes }
      | [.reconfiguration nodes, .retiredCommitted retired] =>
          some
            {
              base with
                cfg := .bool true
                cfgBits := bitsOf env nodes
                rc := .bool true
                rcBits := bitsOf env retired
            }
      | _ => none

/-! ## Logs -/

structure SLog where
  len : Tm
  cells : Array SEntry
deriving Inhabited

def iteLog (c : Tm) (a b : SLog) : OpM SLog := do
  return {
    len := ← iteT c a.len b.len
    cells := ← (a.cells.zip b.cells).mapM fun (x, y) => iteEntry c x y
  }

def present (log : SLog) (k : Nat) : OpM Tm := le (.int k) log.len

def fits (log : SLog) : EM Tm := do
  le log.len (.int (← read).K)

/-- The highest cell index that may be present. -/
def topCell (log : SLog) : EM Nat := do
  let (_, hi) ← range log.len
  let K := (← read).K
  return if hi >= K then K else hi.toNat

/-- `topCell`, also bounded by `limit`. -/
def boundTop (log : SLog) (limit : Option Tm) : EM Nat := do
  let top ← topCell log
  match limit with
  | none => return top
  | some limit =>
      let (_, hi) ← range limit
      return if hi < 0 then 0 else min top hi.toNat

/-- Whether every entry up to `min len limit` is in a cell. -/
def bounded (log : SLog) (limit : Option Tm) : EM Tm := do
  match limit with
  | none => fits log
  | some limit => orL [← fits log, ← le limit (.int (← read).K)]

def limitLe (k : Nat) (limit : Option Tm) : OpM (List Tm) := do
  match limit with
  | none => return []
  | some limit => return [← le (.int k) limit]

/-- `exact` if the cells determine the value, else a fresh value. -/
def escapeTm (exact value : Tm) (fresh : OpM Tm) : OpM Tm := do
  match ← norm exact with
  | .bool true => return value
  | exact => iteT exact value (← fresh)

/-- An `or` over the cells, plus an unknown disjunct when they do not determine it. -/
def escapeOr (exact value : Tm) : OpM Tm := do
  match ← norm exact with
  | .bool true => return value
  | exact => orL [value, ← andL [← notT exact, ← declareBool]]

def termAtK (log : SLog) (k : Nat) : EM Tm := do
  if k == 0 then return .int 0
  let here ← present log k
  if here == .bool false then return .int 0
  if k <= (← read).K then
    iteT here log.cells[k - 1]!.term (.int 0)
  else
    iteT here (← declareNat) (.int 0)

/-- `f k` when `i = k`, by cases over the range of `i`; `escape` beyond the cells. -/
def selectIdx (i : Tm) (f : Nat → EM Tm) (escape : EM Tm) : EM Tm := do
  let K := (← read).K
  match ← norm i with
  | .int value =>
      if value <= 0 then f 0 else if value.toNat <= K then f value.toNat else escape
  | t =>
      let (lo, hi) ← range t
      let lo := (max lo 0).toNat
      let top : Nat := if hi > K then K else hi.toNat
      if top < lo then return ← escape
      let mut acc ← if hi > K then escape else f top
      let last := if hi > K then top + 1 else top
      for offset in [0:last - lo] do
        let k := last - 1 - offset
        acc ← iteT (← eqK t k) (← f k) acc
      return acc

def termAt (log : SLog) (i : Tm) : EM Tm :=
  selectIdx i (termAtK log)
    (do
      iteT (← le i log.len) (← declareNat) (.int 0))

/-- The highest signature index up to `min len frontier`, or zero. -/
def maxSigUpTo (log : SLog) (frontier : Option Tm) : EM Tm := do
  let top ← boundTop log frontier
  let mut r : Tm := .int 0
  for k in [1:top + 1] do
    let c ← andL ([← present log k, log.cells[k - 1]!.sig] ++ (← limitLe k frontier))
    r ← iteT c (.int k) r
  escapeTm (← bounded log frontier) r declareNat

def maxSig (log : SLog) : EM Tm := maxSigUpTo log none

/-- The first index above `after` whose entry satisfies `pred`, or -1. -/
def firstAfter (log : SLog) (after : Tm) (pred : SEntry → OpM Tm) : EM Tm := do
  let top ← topCell log
  let (lo, _) ← range after
  let start := (max (lo + 1) 1).toNat
  let mut r ← escapeTm (← fits log) (.int (-1)) (declare false (-1) INF)
  for offset in [0:top + 1 - start] do
    let k := top - offset
    let c ← andL [← lt after (.int k), ← present log k, ← pred log.cells[k - 1]!]
    r ← iteT c (.int k) r
  return r

/-- `findHighestPossibleMatch` -/
def highestMatch (log : SLog) (index term : Tm) : EM Tm := do
  let top ← boundTop log (some index)
  let mut r : Tm := .int 0
  for k in [1:top + 1] do
    let c ← andL [← le (.int k) index, ← present log k, ← le log.cells[k - 1]!.term term]
    r ← iteT c (.int k) r
  escapeTm (← bounded log (some index)) r declareNat

def takeLog (log : SLog) (count : Tm) : OpM SLog := do
  return { log with len := ← minT log.len count }

def appendEntry (log : SLog) (entry : SEntry) : EM SLog := do
  let K := (← read).K
  let (lo, hi) ← range log.len
  let mut cells := log.cells
  for k in [1:K + 1] do
    if (k - 1 : Int) < lo || hi < (k - 1 : Int) then continue
    cells := cells.set! (k - 1) (← iteEntry (← eqK log.len (k - 1)) entry cells[k - 1]!)
  let len ← addK log.len 1
  assumeCap (← le len (.int K))
  return { len, cells }

/-- The configuration in force up to `min len limit`, and its index. -/
def lastConfiguration (log : SLog) (limit : Option Tm) : EM (Array Tm × Tm) := do
  let env ← read
  let mut bits := env.boot.map Tm.bool
  let mut index : Tm := .int 0
  let top ← boundTop log limit
  for k in [1:top + 1] do
    let cell := log.cells[k - 1]!
    let c ← andL ([← present log k, cell.cfg] ++ (← limitLe k limit))
    if (← norm c) == .bool false then continue
    bits ← iteBits c cell.cfgBits bits
    index ← iteT c (.int k) index
  let exact ← bounded log limit
  if (← norm exact) != .bool true then
    bits ← bits.mapM fun bit => escapeTm exact bit declareBool
    index ← escapeTm exact index declareNat
  return (bits, index)

/-- Nodes in an entry up to `min len limit`, by `select`, or initially in `initial`. -/
def unionUpTo (log : SLog) (limit : Option Tm) (initial : Array Tm)
    (select : SEntry → Tm × Array Tm)
    : EM (Array Tm) := do
  let mut bits := initial
  let top ← boundTop log limit
  for k in [1:top + 1] do
    let (flag, members) := select log.cells[k - 1]!
    let c ← andL ([← present log k, flag] ++ (← limitLe k limit))
    if (← norm c) == .bool false then continue
    bits ← (bits.zip members).mapM fun (bit, member) => do orL [bit, ← andL [c, member]]
  let exact ← bounded log limit
  bits.mapM fun bit => escapeOr exact bit

def retiredCommittedNodes (log : SLog) (limit : Option Tm) : EM (Array Tm) := do
  unionUpTo log limit (falses (← read).n) fun cell => (cell.rc, cell.rcBits)

/-! ## Node state -/

structure SNode where
  role : Tm
  ct : Tm
  log : SLog
  ci : Tm
  sent : Array Tm
  mi : Array Tm
  nf : Tm
  /-- -1 for none, a node index, or `n` for a node outside the trace. -/
  vf : Tm
  lk : Tm
  votes : Array Tm
  pv : Array Tm
  /-- -1 for none. -/
  rci : Tm
deriving Inhabited

def iteNode (c : Tm) (a b : SNode) : OpM SNode := do
  match ← norm c with
  | .bool true => return a
  | .bool false => return b
  | c =>
      return {
        role := ← iteT c a.role b.role
        ct := ← iteT c a.ct b.ct
        log := ← iteLog c a.log b.log
        ci := ← iteT c a.ci b.ci
        sent := ← iteBits c a.sent b.sent
        mi := ← iteBits c a.mi b.mi
        nf := ← iteT c a.nf b.nf
        vf := ← iteT c a.vf b.vf
        lk := ← iteT c a.lk b.lk
        votes := ← iteBits c a.votes b.votes
        pv := ← iteBits c a.pv b.pv
        rci := ← iteT c a.rci b.rci
      }

structure Configs where
  /-- The last committed configuration and its index. -/
  committed : Array Tm
  committedIndex : Tm
  /-- Pending configurations: index, whether pending, members. -/
  pending : Array (Nat × Tm × Array Tm)
  /-- Whether pending configurations may lie beyond the cells. -/
  escaped : Tm

def configs (st : SNode) : EM Configs := do
  let (committed, committedIndex) ← lastConfiguration st.log (some st.ci)
  let top ← topCell st.log
  let mut pending := #[]
  for k in [1:top + 1] do
    let cell := st.log.cells[k - 1]!
    let c ← andL [← lt st.ci (.int k), ← present st.log k, cell.cfg]
    unless (← norm c) == .bool false do
      pending := pending.push (k, c, cell.cfgBits)
  return { committed, committedIndex, pending, escaped := ← notT (← fits st.log) }

def activeMembers (cfgs : Configs) : OpM (Array Tm) := do
  let mut bits := cfgs.committed
  for (_, c, members) in cfgs.pending do
    bits ← (bits.zip members).mapM fun (bit, member) => do orL [bit, ← andL [c, member]]
  let exact ← notT cfgs.escaped
  bits.mapM fun bit => escapeOr exact bit

def majority (support members : Array Tm) : OpM Tm := do
  lt (← countT members) (← doubleT (← countT (← andBits support members)))

def hasQuorum (cfgs : Configs) (support : Array Tm) : OpM Tm := do
  let mut parts := [← majority support cfgs.committed]
  for (_, c, members) in cfgs.pending do
    parts := parts ++ [← impliesT c (← majority support members)]
  if (← norm cfgs.escaped) != .bool false then
    parts := parts ++ [← orL [← notT cfgs.escaped, ← declareBool]]
  andL parts

def retirementIndex (log : SLog) (self : Nat) : EM Tm := do
  let env ← read
  let mut member : Tm := .bool env.boot[self]!
  let mut found : Tm := .bool false
  let mut index : Tm := .int (-1)
  let top ← topCell log
  for k in [1:top + 1] do
    let cell := log.cells[k - 1]!
    let active ← andL [← present log k, cell.cfg]
    if (← norm active) == .bool false then continue
    let removed ← andL [active, ← notT found, member, ← notT cell.cfgBits[self]!]
    found ← orL [found, removed]
    index ← iteT removed (.int k) index
    member ← iteT active cell.cfgBits[self]! member
  escapeTm (← orL [found, ← fits log]) index (declare false (-1) INF)

structure Retirement where
  index : Tm
  committableIndex : Tm
  phase : Tm

def retirement (st : SNode) (self : Nat) : EM Retirement := do
  let index ← retirementIndex st.log self
  let none_ ← lt index (.int 0)
  let committableIndex ←
    if (← norm none_) == .bool true then
      pure (.int (-1))
    else
      iteT none_ (.int (-1)) (← firstAfter st.log index fun cell => pure cell.sig)
  let phase ←
    iteT none_ (.int PHASE_ACTIVE)
      (← iteT (← le (.int 0) st.rci) (.int PHASE_RETIRED_COMMITTED)
          (← iteT (← le index st.ci) (.int PHASE_COMPLETED)
              (← iteT (← le (.int 0) committableIndex) (.int PHASE_SIGNED)
                  (.int PHASE_ORDERED))))
  return { index, committableIndex, phase }

def isRetiredCommitted (st : SNode) (self : Nat) : EM Tm := do
  eqK (← retirement st self).phase PHASE_RETIRED_COMMITTED

def retirementCompletedNodes (st : SNode) (cfgs : Configs) : EM (Array Tm) := do
  let env ← read
  let everMember ←
    unionUpTo st.log (some st.ci) (env.boot.map Tm.bool)
      fun cell =>
        (cell.cfg, cell.cfgBits)
  let retired ← retiredCommittedNodes st.log (some st.ci)
  (Array.range env.n).mapM
    fun j => do
      andL [everMember[j]!, ← notT cfgs.committed[j]!, ← notT retired[j]!]

def eligiblePeers (st : SNode) (cfgs : Configs) (self : Nat) : EM (Array Tm) := do
  let members ← activeMembers cfgs
  let completed ← retirementCompletedNodes st cfgs
  return ← (Array.range (← read).n).mapM
            fun j => do
              if j == self then pure (.bool false) else orL [members[j]!, completed[j]!]

def lastCommittableIndex (st : SNode) : EM Tm := do
  maxT st.ci (← maxSig st.log)

def campaignEligible (st : SNode) (cfgs : Configs) (self : Nat) : EM Tm := do
  let signed ← maxSig st.log
  let mut parts := [← andL [cfgs.committed[self]!, ← le cfgs.committedIndex signed]]
  for (k, c, members) in cfgs.pending do
    parts := parts ++ [← andL [c, members[self]!, ← le (.int k) signed]]
  if (← norm cfgs.escaped) != .bool false then
    parts := parts ++ [← andL [cfgs.escaped, ← declareBool]]
  orL parts

def latestMembershipIndex (cfgs : Configs) (node : Nat) : OpM Tm := do
  let mut r ← iteT cfgs.committed[node]! cfgs.committedIndex (.int 0)
  for (k, c, members) in cfgs.pending do
    r ← iteT (← andL [c, members[node]!]) (.int k) r
  escapeTm (← notT cfgs.escaped) r declareNat

def canStartElection (st : SNode) (cfgs : Configs) (self : Nat)
    : EM (List (Tm × String)) := do
  let role ←
    orL
      [
        ← eqK st.role ROLE_FOLLOWER,
        ← eqK st.role ROLE_PRE_VOTE_CANDIDATE,
        ← eqK st.role ROLE_CANDIDATE
      ]
  let members ← activeMembers cfgs
  let completed ← retirementCompletedNodes st cfgs
  let eligible ←
    orL [← andL [members[self]!, ← campaignEligible st cfgs self], completed[self]!]
  return [
    (role, "role cannot start an election"),
    (eligible, "not eligible to campaign"),
    (← notT (← isRetiredCommitted st self), "retired committed")
  ]

/-! ## Messages -/

/-- Entries of an AppendEntries message, by the receiver's log index. -/
inductive Ents where
  | none
  /-- The sender's log cells. -/
  | snap (id : Nat) (cells : Array SEntry)
  /-- Known entries after `prev`. -/
  | list (id : Nat) (prev : Nat) (entries : Array SEntry)
  /-- Unknown entries of a phantom, which satisfy the entry invariants. -/
  | fresh (id : Nat) (term prev prevTerm count : Tm)
  | ite (id : Nat) (c : Tm) (a b : Ents)
deriving Inhabited

def Ents.id : Ents → Nat
  | .none => 0
  | .snap id _ | .list id _ _ | .fresh id _ _ _ _ | .ite id _ _ _ => id

structure SMsg where
  kind : Tm
  term : Tm
  /-- AE prevLogIndex, AER lastLogIndex, RV/RPV lastCommittableIndex. -/
  a : Tm := .int 0
  /-- AE prevLogTerm, RV/RPV lastCommittableTerm. -/
  b : Tm := .int 0
  /-- AE leaderCommit. -/
  c : Tm := .int 0
  /-- AER success, RVR/RPVR voteGranted. -/
  flag : Tm := .bool false
  /-- AE number of entries. -/
  count : Tm := .int 0
  ents : Ents := .none
deriving Inhabited

def SMsg.dummy : SMsg := { kind := .int KIND_PROPOSE, term := .int 0 }

def iteEnts (c : Tm) (a b : Ents) : OpM Ents := do
  if a.id == b.id then return a
  match a, b with
  | .none, _ => return b
  | _, .none => return a
  | _, _ => return .ite (← freshId) c a b

def iteMsg (c : Tm) (x y : SMsg) : OpM SMsg := do
  match ← norm c with
  | .bool true => return x
  | .bool false => return y
  | c =>
      return {
        kind := ← iteT c x.kind y.kind
        term := ← iteT c x.term y.term
        a := ← iteT c x.a y.a
        b := ← iteT c x.b y.b
        c := ← iteT c x.c y.c
        flag := ← iteT c x.flag y.flag
        count := ← iteT c x.count y.count
        ents := ← iteEnts c x.ents y.ents
      }

def entryMemo (id k : Nat) : OpM (Option SEntry) := do
  return (← get).entries[(id, k)]?

def setEntryMemo (id k : Nat) (entry : SEntry) : OpM Unit :=
  modify fun enc => { enc with entries := enc.entries.insert (id, k) entry }

/-- The entry an AppendEntries message carries for log index `k`. -/
def entsAt (ents : Ents) (k : Nat) : EM SEntry := do
  let env ← read
  match ents with
  | .none => return SEntry.dummy env.n
  | .snap _ cells =>
      if 1 <= k && k <= env.K then return cells[k - 1]! else freshEntry
  | .list _ prev entries =>
      return  if k <= prev then
                SEntry.dummy env.n
              else
                entries[k - prev - 1]?.getD (SEntry.dummy env.n)
  | .fresh id term prev prevTerm count =>
      if let some entry ← entryMemo id k then return entry
      let entry ← freshEntry
      setEntryMemo id k entry
      if env.invariants then
        let carried (index : Nat) : OpM Tm := do
          andL [← lt prev (.int index), ← le (.int index) (← addT prev count)]
        assumeInv
          (← impliesT (← carried k)
              (← andL [← le (.int 1) entry.term, ← le entry.term term]))
        assumeInv
          (← impliesT (← andL [← eqK prev (k - 1), ← carried k])
              (← le prevTerm entry.term))
        if k >= 2 then
          if let some before ← entryMemo id (k - 1) then
            assumeInv
              (← impliesT (← andL [← carried (k - 1), ← carried k])
                  (← le before.term entry.term))
        if let some after ← entryMemo id (k + 1) then
          assumeInv
            (← impliesT (← andL [← carried k, ← carried (k + 1)])
                (← le entry.term after.term))
      return entry
  | .ite id c a b =>
      if let some entry ← entryMemo id k then return entry
      let entry ← iteEntry c (← entsAt a k) (← entsAt b k)
      setEntryMemo id k entry
      return entry

def entsTermAt (ents : Ents) (index : Tm) : EM Tm :=
  selectIdx index (fun k => do return (← entsAt ents k).term) declareNat

def freshMsg : EM SMsg := do
  let term ← declareNat
  let a ← declareNat
  let b ← declareNat
  let count ← declareNat
  return {
    kind := ← declare false 0 KIND_PROPOSE
    term
    a
    b
    c := ← declareNat
    flag := ← declareBool
    count
    ents := .fresh (← freshId) term a b count
  }

def snapshot (log : SLog) : OpM Ents := do
  return .snap (← freshId) log.cells

/-- `makeAppendEntriesRequest` -/
def appendEntriesTo (st : SNode) (dest : Nat) (endIndex : Tm) : EM SMsg := do
  let prev := st.sent[dest]!
  return {
    kind := .int KIND_AE
    term := st.ct
    a := prev
    b := ← termAt st.log prev
    c := st.ci
    count := ← maxT (.int 0) (← subT (← minT endIndex st.log.len) prev)
    ents := ← snapshot st.log
  }

def voteRequest (kind : Int) (st : SNode) : EM SMsg := do
  let index ← lastCommittableIndex st
  return { kind := .int kind, term := st.ct, a := index, b := ← termAt st.log index }

/-! ## Channels -/

structure Send where
  cond : Tm
  /-- The number of earlier sends that happened. -/
  rank : Tm
  rlo : Int
  rhi : Int
  msg : SMsg
deriving Inhabited

/--
A named channel position: a message with its own scalar constants, equal to
whichever of the mutually exclusive `alternatives` holds. Observations
narrow the constants before the equalities are emitted, so handlers run on
the observed message instead of a mux over every send that could be there.
-/
structure Head where
  msg : SMsg
  alternatives : Array (Tm × SMsg)
deriving Inhabited

structure Chan where
  /-- The number of messages in flight at the cut. -/
  p : Tm
  sends : Array Send := #[]
  total : Tm := .int 0
  /-- Positions consumed by receives and drops. -/
  pops : Nat := 0
  phantoms : Std.HashMap Nat SMsg := {}
  /-- Named positions whose equalities are not emitted yet. -/
  heads : Std.HashMap Nat Head := {}
deriving Inhabited

def Chan.push (ch : Chan) (cond : Tm) (msg : SMsg) : OpM Chan := do
  let (rlo, rhi) ← range ch.total
  return {
    ch with
      sends := ch.sends.push { cond, rank := ch.total, rlo, rhi, msg }
      total := ← addT ch.total (← iteT cond (.int 1) (.int 0))
  }

def Chan.phantom (ch : Chan) (x : Nat) : EM (SMsg × Chan) := do
  if let some msg := ch.phantoms[x]? then return (msg, ch)
  let msg ← freshMsg
  return (msg, { ch with phantoms := ch.phantoms.insert x msg })

/-- The send of rank `r`, assuming there is one. -/
def Chan.sendByRank (ch : Chan) (r : Tm) : OpM SMsg := do
  let (lo, hi) ← range r
  -- Ranks are non-decreasing; find the first send that can have rank `lo`.
  let mut low := 0
  let mut high := ch.sends.size
  while low < high do
    let mid := (low + high) / 2
    if ch.sends[mid]!.rhi < lo then low := mid + 1 else high := mid
  let mut candidates : Array Send := #[]
  let mut j := low
  while j < ch.sends.size && ch.sends[j]!.rlo <= hi do
    let send := ch.sends[j]!
    if (← norm send.cond) != .bool false then candidates := candidates.push send
    j := j + 1
  let some last := candidates.back? | return SMsg.dummy
  let mut acc := last.msg
  for offset in [1:candidates.size] do
    let send := candidates[candidates.size - 1 - offset]!
    acc ← iteMsg (← andL [send.cond, ← eqT send.rank r]) send.msg acc
  return acc

/-- The sends that can have rank `r`, each with the condition that it does. -/
def Chan.sendsByRank (ch : Chan) (r : Tm) : OpM (Array (Tm × SMsg)) := do
  let (lo, hi) ← range r
  let mut low := 0
  let mut high := ch.sends.size
  while low < high do
    let mid := (low + high) / 2
    if ch.sends[mid]!.rhi < lo then low := mid + 1 else high := mid
  let mut out := #[]
  let mut j := low
  while j < ch.sends.size && ch.sends[j]!.rlo <= hi do
    let send := ch.sends[j]!
    let selected ← andL [send.cond, ← eqT send.rank r]
    if (← norm selected) != .bool false then out := out.push (selected, send.msg)
    j := j + 1
  return out

/--
The mutually exclusive possibilities for the message at absolute position
`x`; one holds whenever the channel reaches `x`.
-/
def Chan.alternatives (ch : Chan) (x : Nat) : EM (Array (Tm × SMsg) × Chan) := do
  let Q := (← read).Q
  let isPhantom ← lt (.int x) ch.p
  let mut ch := ch
  let mut out := #[]
  if (← norm isPhantom) != .bool false then
    let (msg, next) ← ch.phantom x
    ch := next
    out := out.push (isPhantom, msg)
  if (← norm isPhantom) == .bool true then return (out, ch)
  match ← norm ch.p with
  | .int value => out := out ++ (← ch.sendsByRank (.int (x - value)))
  | p =>
      let (plo, phi) ← range p
      let vlo := max plo 0
      let vhi := min phi x
      if vhi > Q then
        out := out.push (← andL [← le (.int (Q + 1)) p, ← le p (.int x)], ← freshMsg)
      let mut v := vlo
      while v <= min vhi Q do
        let pv ← eqK p v
        for (selected, msg) in ← ch.sendsByRank (.int (x - v)) do
          out := out.push (← andL [pv, selected], msg)
        v := v + 1
  return (out, ch)

def unionRange (ts : Array Tm) : OpM (Int × Int) := do
  let mut lo := INF
  let mut hi := -INF
  for t in ts do
    let (l, h) ← range t
    lo := min lo l
    hi := max hi h
  return (lo, hi)

/-- A constant covering every value of `ts`. -/
def cover (ts : Array Tm) : OpM Tm := do
  if let some first := ts[0]? then
    let first ← norm first
    if ← ts.allM fun t => do return (← norm t) == first then return first
  if ← ts.allM isBoolTm then return ← declareBool
  let (lo, hi) ← unionRange ts
  declare false lo hi

/-- The message at absolute position `x`, named on first use. -/
def Chan.name (ch : Chan) (x : Nat) : EM (SMsg × Chan) := do
  if let some head := ch.heads[x]? then return (head.msg, ch)
  let (alternatives, ch) ← ch.alternatives x
  if alternatives.size == 1 then
    return (alternatives[0]!.2, ch)
  let msgs := alternatives.map (·.2)
  let some last := msgs.back? | return (SMsg.dummy, ch)
  let mut ents := last.ents
  for offset in [1:alternatives.size] do
    let (selected, msg) := alternatives[alternatives.size - 1 - offset]!
    ents ← iteEnts selected msg.ents ents
  let msg : SMsg :=
    {
      kind := ← cover (msgs.map (·.kind))
      term := ← cover (msgs.map (·.term))
      a := ← cover (msgs.map (·.a))
      b := ← cover (msgs.map (·.b))
      c := ← cover (msgs.map (·.c))
      flag := ← cover (msgs.map (·.flag))
      count := ← cover (msgs.map (·.count))
      ents
    }
  return (msg, { ch with heads := ch.heads.insert x { msg, alternatives } })

def SMsg.scalarsEq (x y : SMsg) : OpM Tm := do
  andL
    [
      ← eqT x.kind y.kind,
      ← eqT x.term y.term,
      ← eqT x.a y.a,
      ← eqT x.b y.b,
      ← eqT x.c y.c,
      ← eqT x.flag y.flag,
      ← eqT x.count y.count
    ]

/-- Emits the equalities of a named position; `description` labels them. -/
def Chan.bind (ch : Chan) (x : Nat) (description : String) : OpM Chan := do
  let some head := ch.heads[x]? | return ch
  for (selected, msg) in head.alternatives do
    require (← impliesT selected (← head.msg.scalarsEq msg)) description
  require (← orL (head.alternatives.map (·.1)).toList) description
  return { ch with heads := ch.heads.erase x }

/-- The message at absolute position `x`, assuming the channel reaches it. -/
def Chan.at (ch : Chan) (x : Nat) : EM (SMsg × Chan) := do
  let Q := (← read).Q
  let isPhantom ← lt (.int x) ch.p
  let mut ch := ch
  let mut phantom := SMsg.dummy
  if (← norm isPhantom) != .bool false then
    let (msg, next) ← ch.phantom x
    phantom := msg
    ch := next
  if (← norm isPhantom) == .bool true then return (phantom, ch)
  let sent ←
    match ← norm ch.p with
    | .int value => ch.sendByRank (.int (x - value))
    | p => do
        let (plo, phi) ← range p
        let vlo := max plo 0
        let vhi := min phi x
        let exactHi := min vhi Q
        let mut acc ← if vhi > Q then freshMsg else ch.sendByRank (.int (x - exactHi))
        let top := if vhi > Q then exactHi else exactHi - 1
        let mut v := top
        while v >= vlo do
          acc ← iteMsg (← eqK p v) (← ch.sendByRank (.int (x - v))) acc
          v := v - 1
        pure acc
  return (← iteMsg isPhantom phantom sent, ch)

/-- The last pending message, assuming there is one. -/
def Chan.last (ch : Chan) : EM (SMsg × Chan) := do
  let Q := (← read).Q
  let hasSend ← le (.int 1) ch.total
  let mut ch := ch
  let fromSends ←
    if (← norm hasSend) == .bool false then
      pure SMsg.dummy
    else
      ch.sendByRank (← addK ch.total (-1))
  if (← norm hasSend) == .bool true then return (fromSends, ch)
  let (plo, phi) ← range ch.p
  let vlo := max plo 1
  let exactHi := min phi Q
  let mut acc := SMsg.dummy
  if phi > Q then
    acc ← freshMsg
  else if exactHi >= vlo then
    let (msg, next) ← ch.phantom (exactHi - 1).toNat
    acc := msg
    ch := next
  let mut v := if phi > Q then exactHi else exactHi - 1
  while v >= vlo do
    let (msg, next) ← ch.phantom (v - 1).toNat
    ch := next
    acc ← iteMsg (← eqK ch.p v) msg acc
    v := v - 1
  return (← iteMsg hasSend fromSends acc, ch)

/-- Whether the channel has more than `k` pending messages. -/
def Chan.hasMoreThan (ch : Chan) (k : Nat) : OpM Tm := do
  le (.int (ch.pops + k + 1)) (← addT ch.p ch.total)

/-! ## Handlers -/

structure Out where
  dest : Nat
  cond : Tm
  msg : SMsg

/-- Handlers read the path condition and accumulate sends. -/
abbrev HM := ReaderT Tm (StateT (Array Out) EM)

def envH : HM Env := readThe Env

def pcH : HM Tm := readThe Tm

def send (dest : Nat) (msg : SMsg) : HM Unit := do
  let pc ← pcH
  unless (← norm pc) == .bool false do
    modifyThe (Array Out) (·.push { dest, cond := pc, msg })

def withPc {α : Type} (c : Tm) (body : HM α) : HM α := do
  let pc ← andL [← pcH, c]
  withTheReader Tm (fun _ => pc) body

def branch (c : Tm) (yes no : HM SNode) : HM SNode := do
  match ← norm c with
  | .bool true => yes
  | .bool false => no
  | c =>
      let a ← withPc c yes
      let b ← withPc (← notT c) no
      iteNode c a b

def whenT (c : Tm) (body : HM Unit) : HM Unit := do
  match ← norm c with
  | .bool true => body
  | .bool false => pure ()
  | c => withPc c body

/-- A guard of an action; a failing guard disables the action. -/
def guardT (c : Tm) (description : String) : HM Unit := do
  require (← impliesT (← pcH) c) description

def updateTerm (st : SNode) (term : Tm) : EM SNode := do
  let n := (← read).n
  iteNode (← lt st.ct term)
    {
      st with
        role := .int ROLE_FOLLOWER
        ct := term
        vf := .int (-1)
        lk := .bool false
        nf := .bool true
        pv := falses n
    }
    st

def highestCommittableIndex (st : SNode) (cfgs : Configs) (self : Nat) : EM Tm := do
  let n := (← read).n
  let top ← topCell st.log
  let mut r : Tm := .int 0
  for k in [1:top + 1] do
    let cell := st.log.cells[k - 1]!
    let base ←
      andL [← lt st.ci (.int k), ← present st.log k, cell.sig, ← eqT cell.term st.ct]
    if (← norm base) == .bool false then continue
    let support ←
      (Array.range n).mapM
        fun j =>
          if j == self then pure (.bool true) else le (.int k) st.mi[j]!
    r ← iteT (← andL [base, ← hasQuorum cfgs support]) (.int k) r
  escapeTm (← fits st.log) r declareNat

def commitThrough (st : SNode) (self : Nat) (commitIndex : Tm) : EM SNode := do
  let retired ← retiredCommittedNodes st.log (some commitIndex)
  let rci ←
    iteT (← le (.int 0) st.rci) st.rci (← iteT retired[self]! commitIndex (.int (-1)))
  return { st with ci := commitIndex, rci }

def nominateSuccessor (st : SNode) (self : Nat) : HM Unit := do
  let env ← envH
  let cfgs ← configs st
  let eligible ← eligiblePeers st cfgs self
  let mut has : Tm := .bool false
  let mut best : Tm := .int (-1)
  let mut bestMatch : Tm := .int 0
  let mut bestIndex : Tm := .int 0
  for j in env.sorted do
    if (← norm eligible[j]!) == .bool false then continue
    let m := st.mi[j]!
    let l ← latestMembershipIndex cfgs j
    let better ←
      andL
        [
          eligible[j]!,
          ← orL
              [← notT has, ← lt bestMatch m, ← andL [← eqT bestMatch m, ← le bestIndex l]]
        ]
    has ← orL [has, better]
    best ← iteT better (.int j) best
    bestMatch ← iteT better m bestMatch
    bestIndex ← iteT better l bestIndex
  for j in [0:env.n] do
    whenT (← andL [has, ← eqK best j])
      (send j { kind := .int KIND_PROPOSE, term := st.ct })

def advanceCommit (st : SNode) (self : Nat) : HM SNode := do
  let cfgs ← configs st
  let index ← highestCommittableIndex st cfgs self
  branch (← lt st.ci index)
    (do
      let committed ← commitThrough st self index
      branch (← isRetiredCommitted committed self)
        (do
          whenT (← eqK st.role ROLE_LEADER) (nominateSuccessor st self)
          return { committed with role := .int ROLE_NONE, lk := .bool false })
        (pure committed))
    (pure st)

def leaderState (st : SNode) : EM SNode := do
  let n := (← read).n
  let index ← lastCommittableIndex st
  let log ← iteLog (← lt (.int 0) st.ci) (← takeLog st.log index) st.log
  return {
    st with
      role := .int ROLE_LEADER
      log
      lk := .bool true
      sent := Array.replicate n log.len
      mi := Array.replicate n (.int 0)
  }

def becomeLeader (st : SNode) (self : Nat) : HM SNode := do
  let env ← envH
  let leader ← advanceCommit (← leaderState st) self
  let eligible ← eligiblePeers leader (← configs leader) self
  for j in env.sorted do
    whenT eligible[j]! (send j (← appendEntriesTo leader j leader.log.len))
  return leader

def electIfQuorum (st : SNode) (self : Nat) : HM SNode := do
  let cfgs ← configs st
  let c ←
    andL
      [
        ← eqK st.role ROLE_CANDIDATE,
        ← hasQuorum cfgs st.votes,
        ← notT (← isRetiredCommitted st self)
      ]
  branch c (becomeLeader st self) (pure st)

def broadcastToOthers (st : SNode) (self : Nat) (msg : SMsg) : HM Unit := do
  let env ← envH
  let members ← activeMembers (← configs st)
  for j in env.sorted do
    unless j == self do
      whenT members[j]! (send j msg)

def becomeCandidate (st : SNode) (self : Nat) : HM SNode := do
  let n := (← envH).n
  let candidate :=
    {
      st with
        role := .int ROLE_CANDIDATE
        ct := ← addK st.ct 1
        vf := .int self
        lk := .bool false
        votes := unit n self
        pv := falses n
    }
  let next ← electIfQuorum candidate self
  broadcastToOthers candidate self (← voteRequest KIND_RV candidate)
  return next

def becomePreVoteCandidate (st : SNode) (self : Nat) : HM SNode := do
  let n := (← envH).n
  let candidate :=
    { st with role := .int ROLE_PRE_VOTE_CANDIDATE, lk := .bool false, pv := unit n self }
  branch (← hasQuorum (← configs candidate) candidate.pv)
    (becomeCandidate candidate self)
    (do
      broadcastToOthers candidate self (← voteRequest KIND_RPV candidate)
      return candidate)

/-! ### Inputs -/

def appendBatch (st : SNode) (self : Nat) (entries : List (EntryContent String String))
    : HM SNode := do
  let env ← envH
  guardT (← eqK st.role ROLE_LEADER) "append: not leader"
  guardT (← notT (← isRetiredCommitted st self)) "append: retired committed"
  let mut st := st
  for content in entries do
    let some entry := knownEntry env st.ct content
    | unsupported "append: entry effects the encoding cannot represent"; return st
    match content with
    | .signature => guardT (← le (.int 1) st.log.len) "append: signature on an empty log"
    | .transaction _ [.reconfiguration _] =>
        let (previous, _) ← lastConfiguration st.log none
        guardT (← notT (← eqBits entry.cfgBits previous))
          "append: configuration equals the previous one"
        let eligible ← eligiblePeers st (← configs st) self
        let added ←
          (Array.range env.n).mapM
            fun j => do
              if j == self then
                pure (.bool false)
              else
                andL [entry.cfgBits[j]!, ← notT eligible[j]!]
        let configured :=
          {
            st with
              sent :=
                ← (Array.range env.n).mapM fun j => iteT added[j]! st.log.len st.sent[j]!
          }
        for j in env.sorted do
          whenT added[j]! (send j (← appendEntriesTo configured j st.log.len))
        st := configured
    | .transaction _ [.retiredCommitted _] =>
        let completed ← retirementCompletedNodes st (← configs st)
        let retired ← retiredCommittedNodes st.log none
        let mut allowed : List Tm := []
        for j in [0:env.n] do
          if entry.rcBits[j]! == .bool true then
            allowed := allowed ++ [← andL [completed[j]!, ← notT retired[j]!]]
        guardT (← andL allowed) "append: retirement record for a node not awaiting it"
    | .transaction _ [] => pure ()
    | _ =>
        unsupported "append: transaction with several effects"
        return st
    st := { st with log := ← appendEntry st.log entry }
  advanceCommit st self

def sendEntries (st : SNode) (self dest endIndex : Nat) : HM SNode := do
  let env ← envH
  if endIndex > env.K then
    unsupported "sendEntries beyond the modelled log"
    return st
  let prev := st.sent[dest]!
  let eligible ← eligiblePeers st (← configs st) self
  guardT (← eqK st.role ROLE_LEADER) "sendEntries: not leader"
  guardT eligible[dest]! "sendEntries: destination is not an eligible peer"
  guardT (← le prev (.int endIndex)) "sendEntries: end below the send frontier"
  guardT (← le (.int endIndex) st.log.len) "sendEntries: end beyond the log"
  let last ← termAtK st.log endIndex
  let mut same : List Tm := []
  for k in [1:endIndex + 1] do
    same :=
      same ++ [← impliesT (← lt prev (.int k)) (← eqT st.log.cells[k - 1]!.term last)]
  guardT (← andL same) "sendEntries: entries span several terms"
  guardT
    (← orL [← notT (← isRetiredCommitted st self), ← lt prev (.int endIndex)])
    "sendEntries: retired committed with nothing to send"
  send dest (← appendEntriesTo st dest (.int endIndex))
  return { st with sent := st.sent.set! dest (.int endIndex) }

def startElection (st : SNode) (self : Nat) : HM SNode := do
  for (c, description) in ← canStartElection st (← configs st) self do
    guardT c s!"election timeout: {description}"
  if (← envH).preVote[self]! then
    becomePreVoteCandidate st self
  else
    becomeCandidate st self

def checkQuorum (st : SNode) (self : Nat) : HM SNode := do
  let members ← activeMembers (← configs st)
  guardT (← eqK st.role ROLE_LEADER) "checkQuorum timeout: not leader"
  let others :=
    (members.toList.zip (List.range members.size)).filterMap
      fun (bit, j) =>
        if j == self then none else some bit
  guardT (← orL others) "checkQuorum timeout: no other members"
  return { st with role := .int ROLE_FOLLOWER, lk := .bool false }

def nominate (st : SNode) (self : Nat) : HM SNode := do
  guardT (← eqK st.role ROLE_LEADER) "nominateSuccessor: not leader"
  nominateSuccessor st self
  return st

/-! ### Receives -/

def hasTermConflict (st : SNode) (m : SMsg) : EM Tm := do
  let K := (← read).K
  let top ← topCell st.log
  let last ← addT m.a m.count
  let (plo, _) ← range m.a
  let (_, lastHi) ← range last
  let start := (max (plo + 1) 1).toNat
  let stop := if lastHi < 0 then 0 else min top lastHi.toNat
  let mut parts : List Tm := []
  for k in [start:stop + 1] do
    let carried ← andL [← lt m.a (.int k), ← present st.log k, ← le (.int k) last]
    if (← norm carried) == .bool false then continue
    let incoming ← entsAt m.ents k
    parts :=
      parts ++ [← andL [carried, ← notT (← eqT st.log.cells[k - 1]!.term incoming.term)]]
  let r ← orL parts
  escapeOr (← orL [← fits st.log, ← le last (.int K)]) r

def appendEntriesFromLeader (st : SNode) (self source : Nat) (m : SMsg) : HM SNode := do
  let K := (← envH).K
  let last ← addT m.a m.count
  let (lo, _) ← range st.log.len
  let (_, lastHi) ← range last
  let stop := if lastHi < 0 then 0 else min K lastHi.toNat
  let mut cells := st.log.cells
  for k in [(max (lo + 1) 1).toNat:stop + 1] do
    let c ← andL [← lt st.log.len (.int k), ← le (.int k) last]
    if (← norm c) == .bool false then continue
    cells := cells.set! (k - 1) (← iteEntry c (← entsAt m.ents k) cells[k - 1]!)
  let len ← maxT st.log.len last
  assumeCap (← le len (.int K))
  let log : SLog := { len, cells }
  let commitIndex ← maxT st.ci (← maxSigUpTo log (some (← minT m.c last)))
  let marker ← firstAfter log (.int 0) fun cell => andL [cell.rc, cell.rcBits[self]!]
  let firstNewSignature ←
    firstAfter log (← maxT st.log.len marker) fun cell => pure cell.sig
  let retirementCommitIndex ←
    iteT (← lt marker (.int 0)) commitIndex
      (← iteT (← lt firstNewSignature (.int 0)) commitIndex
          (← minT commitIndex firstNewSignature))
  let committed ← commitThrough { st with log } self retirementCommitIndex
  send source
    { kind := .int KIND_AER, term := committed.ct, flag := .bool true, a := last }
  commitThrough committed self commitIndex

def receiveAppendEntries (st : SNode) (self source : Nat) (m : SMsg) : HM SNode := do
  let st ←
    iteNode
      (← andL
          [
            ← eqT m.term st.ct,
            ← orL [← eqK st.role ROLE_CANDIDATE, ← eqK st.role ROLE_PRE_VOTE_CANDIDATE]
          ])
      { st with role := .int ROLE_FOLLOWER, nf := .bool true }
      st
  let matching ←
    orL [← eqK m.a 0, ← andL [← le m.a st.log.len, ← eqT (← termAt st.log m.a) m.b]]
  let stale ← lt m.term st.ct
  branch (← orL [stale, ← notT matching])
    (do
      let missing ← orL [stale, ← eqK (← termAt st.log m.a) 0]
      let hint ← highestMatch st.log m.a m.b
      let short : SMsg :=
        { kind := .int KIND_AER, term := st.ct, flag := .bool false, a := st.log.len }
      let retry : SMsg :=
        {
          kind := .int KIND_AER
          term := ← termAt st.log hint
          flag := .bool false
          a := hint
        }
      send source (← iteMsg missing short retry)
      return st)
    (do
      let st := { st with lk := .bool true }
      let conflict ← hasTermConflict st m
      branch (← orL [← lt m.a st.ci, ← andL [conflict, ← notT st.nf]])
        (pure st)
        (do
          let st ←
            iteNode conflict { st with log := ← takeLog st.log m.a, nf := .bool false } st
          appendEntriesFromLeader st self source m))

def receiveAppendEntriesResponse (st : SNode) (self source : Nat) (m : SMsg)
    : HM SNode := do
  branch (← eqK st.role ROLE_LEADER)
    (branch m.flag
      (branch (← eqT m.term st.ct)
        (advanceCommit { st with mi := st.mi.set! source (← maxT st.mi[source]! m.a) }
          self)
        (pure st))
      (do
        let retry ← highestMatch st.log m.a m.term
        let sent ← maxT (← minT retry st.sent[source]!) st.mi[source]!
        return { st with sent := st.sent.set! source sent }))
    (pure st)

def voteLogUpToDate (st : SNode) (m : SMsg) : EM Tm := do
  let signed ← maxSig st.log
  let signedTerm ← termAt st.log signed
  orL [← lt signedTerm m.b, ← andL [← eqT m.b signedTerm, ← le signed m.a]]

def receiveRequestVote (st : SNode) (source : Nat) (m : SMsg) : HM SNode := do
  let granted ←
    andL
      [
        ← eqT m.term st.ct,
        ← voteLogUpToDate st m,
        ← notT st.lk,
        ← orL [← eqK st.vf (-1), ← eqK st.vf source]
      ]
  send source { kind := .int KIND_RVR, term := st.ct, flag := granted }
  return { st with vf := ← iteT granted (.int source) st.vf }

def receiveRequestPreVote (st : SNode) (source : Nat) (m : SMsg) : HM SNode := do
  let granted ← andL [← eqT m.term st.ct, ← voteLogUpToDate st m]
  send source { kind := .int KIND_RPVR, term := st.ct, flag := granted }
  return st

def receiveRequestVoteResponse (st : SNode) (self source : Nat) (m : SMsg)
    : HM SNode := do
  let c ← andL [← eqK st.role ROLE_CANDIDATE, ← eqT m.term st.ct, m.flag]
  branch c (electIfQuorum { st with votes := st.votes.set! source (.bool true) } self)
    (pure st)

def receiveRequestPreVoteResponse (st : SNode) (self source : Nat) (m : SMsg)
    : HM SNode := do
  let c ← andL [← eqK st.role ROLE_PRE_VOTE_CANDIDATE, ← eqT m.term st.ct, m.flag]
  branch c
    (do
      let st := { st with pv := st.pv.set! source (.bool true) }
      branch (← hasQuorum (← configs st) st.pv) (becomeCandidate st self) (pure st))
    (pure st)

def receiveProposeVote (st : SNode) (self : Nat) (m : SMsg) : HM SNode := do
  let mut parts := [← eqT m.term st.ct]
  for (c, _) in ← canStartElection st (← configs st) self do
    parts := parts ++ [c]
  branch (← andL parts) (becomeCandidate st self) (pure st)

def receiveKind (kind : Int) (st : SNode) (self source : Nat) (m : SMsg) : HM SNode := do
  if kind == KIND_AE then
    receiveAppendEntries (← updateTerm st m.term) self source m
  else if kind == KIND_AER then
    let st ← iteNode (← eqK st.role ROLE_LEADER) (← updateTerm st m.term) st
    receiveAppendEntriesResponse st self source m
  else if kind == KIND_RV then
    receiveRequestVote (← updateTerm st m.term) source m
  else if kind == KIND_RVR then
    receiveRequestVoteResponse (← updateTerm st m.term) self source m
  else if kind == KIND_RPV then
    receiveRequestPreVote (← updateTerm st m.term) source m
  else if kind == KIND_RPVR then
    receiveRequestPreVoteResponse (← updateTerm st m.term) self source m
  else
    receiveProposeVote st self m

/-- `receive`, by cases over the possible kinds of `m`. -/
def receive (st : SNode) (self source : Nat) (m : SMsg) : HM SNode := do
  let (lo, hi) ← range m.kind
  let lo := max lo KIND_AE
  let hi := min hi KIND_PROPOSE
  if hi < lo then return st
  let kinds := (List.range (hi - lo + 1).toNat).map fun offset => lo + offset
  let rec go : List Int → HM SNode
    | [] => pure st
    | [kind] => receiveKind kind st self source m
    | kind :: rest => do
        branch (← eqK m.kind kind) (receiveKind kind st self source m) (go rest)
  go kinds

end CCFRaft.MidTrace.Smt
