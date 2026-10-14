module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SymState
public import Std.Data.HashMap

@[expose] public section

/-!
# Canonical future keys

Two worlds with equal keys have equivalent futures: they accept the same
continuations of the trace. The key covers each node's effective state (its
current fields, falling back to initial values and remaining domains), the
channels' pending messages, and the store projected onto the atoms those
mention, with atoms renamed in order of first occurrence. Overwritten initial
values and already-consumed pre-cut messages only matter for the witness, so
they are left out. For an open channel only the materialized messages and the
newest pending message are kept: either world can materialize a copy of any
message the other would deliver.

The projection is exact: integer atoms connected to mentioned atoms by a
disequality are included, and the submatrix of a closed DBM is the projection
of its difference constraints.
-/

namespace CCFRaft.MidTrace.Sym

open Lean CCFRaft.Model.Node

/-- A finite-domain unknown whose candidate list may be merged with another world's. -/
inductive Slot where
  | content (id : Nat)
  | role (node : Nat)
  | votedFor (node : Nat)
  | votes (node : Nat)
  | preVotes (node : Nat)
deriving BEq, Inhabited

structure KeyState where
  ints : Std.HashMap Nat Nat := {}
  intOrder : Array Nat := #[]
  contents : Std.HashMap Nat Nat := {}
  contentOrder : Array Nat := #[]
  out : String := ""
  slots : Array Slot := #[]
  /-- Sorted rendered candidates of each slot. -/
  cands : Array (List String) := #[]

abbrev K := StateM KeyState

/--
A world's canonical key, split into everything but the finite-domain slots
(`base`) and the slots' candidate sets in canonical order.
-/
structure WorldKey where
  base : String
  slots : Array Slot
  cands : Array (List String)

def renderCands (cands : List String) : String := String.intercalate "," cands

def WorldKey.full (key : WorldKey) : String :=
  key.base ++ "||" ++ String.intercalate "|" (key.cands.toList.map renderCands)

namespace Key

def emit (text : String) : K Unit := modify fun state => { state with out := state.out ++ text }

def intAtom (id : Nat) : K Nat := do
  if id == 0 then return 0
  modifyGet fun state =>
    match state.ints[id]? with
    | some k => (k, state)
    | none =>
        let k := state.intOrder.size + 1
        (k, { state with ints := state.ints.insert id k, intOrder := state.intOrder.push id })

def contentAtom (id : Nat) : K Nat :=
  modifyGet fun state =>
    match state.contents[id]? with
    | some k => (k, state)
    | none =>
        let k := state.contentOrder.size
        (k,
          {
            state with
              contents := state.contents.insert id k
              contentOrder := state.contentOrder.push id
          })

/-- Records a slot with the rendered candidates and emits a placeholder. -/
def slot (value : Slot) (cands : List String) : K Unit := do
  modify fun state =>
    {
      state with
        slots := state.slots.push value
        cands := state.cands.push (cands.mergeSort (· ≤ ·))
        out := state.out ++ "$"
    }

def sint (value : SInt) : K Unit := do
  emit s!"{← intAtom value.base}:{value.off},"

def optSInt (value : Option SInt) : K Unit :=
  match value with
  | some value => sint value
  | none => emit "?,"

def nodes (declared : List String) (set : Nodes) : String :=
  "{" ++ String.intercalate "," (declared.filter (· ∈ set)) ++ "}"

def effect (declared : List String) : TransactionEffect String → String
  | .reconfiguration set => "C" ++ nodes declared set
  | .retiredCommitted set => "R" ++ nodes declared set

def txId (table : Std.HashMap String Nat) (id : String) : String :=
  match table[id]? with
  | some k => s!"#{k}"
  | none => s!"T{id.length}:{id}"

def content (declared : List String) (table : Std.HashMap String Nat) : Content → String
  | .signature => "S"
  | .transaction id effects =>
      txId table id ++ "[" ++ String.intercalate ";" (effects.map (effect declared)) ++ "]"

abbrev Ctx := List String × Std.HashMap String Nat

def scontent (ctx : Ctx) : SContent → K Unit
  | .known value => emit ("K" ++ content ctx.1 ctx.2 value ++ ",")
  | .atom id => do emit s!"A{← contentAtom id},"

def entry (ctx : Ctx) (value : SEntry) : K Unit := do
  sint value.term
  scontent ctx value.content

def message (ctx : Ctx) : SMsg → K Unit
  | .appendEntries term previous previousTerm entries leaderCommit => do
      emit "AE("
      sint term; sint previous; sint previousTerm; sint leaderCommit
      for value in entries do entry ctx value
      emit ")"
  | .appendEntriesResponse term success lastLogIndex => do
      emit s!"AR{success}("; sint term; sint lastLogIndex; emit ")"
  | .requestVote term lastTerm lastIndex => do
      emit "RV("; sint term; sint lastTerm; sint lastIndex; emit ")"
  | .requestVoteResponse term granted => do
      emit s!"VR{granted}("; sint term; emit ")"
  | .requestPreVote term lastTerm lastIndex => do
      emit "PV("; sint term; sint lastTerm; sint lastIndex; emit ")"
  | .requestPreVoteResponse term granted => do
      emit s!"PR{granted}("; sint term; emit ")"
  | .proposeVote term => do
      emit "PP("; sint term; emit ")"

def roleName : Role → String
  | .none => "n"
  | .follower => "f"
  | .preVoteCandidate => "p"
  | .candidate => "c"
  | .leader => "l"

def node (ctx : Ctx) (i : Nat) (current initial : SNode) (dom : InitDom) : K Unit := do
  let declared := ctx.1
  match current.role <|> initial.role with
  | some role => emit (roleName role)
  | none => slot (.role i) (dom.role.map roleName)
  emit "|"
  optSInt (current.currentTerm <|> initial.currentTerm)
  match current.log <|> initial.log with
  | some log => do
      emit "L"
      for value in log do entry ctx value
  | none => emit "L?"
  emit "|"
  optSInt (current.commitIndex <|> initial.commitIndex)
  for k in [:current.sentIndex.size] do
    optSInt (current.sentIndex[k]! <|> initial.sentIndex[k]!)
  emit "|"
  for k in [:current.matchIndex.size] do
    optSInt (current.matchIndex[k]! <|> initial.matchIndex[k]!)
  emit s!"|{current.isNewFollower <|> initial.isNewFollower}"
  emit s!"|{current.leaderKnown <|> initial.leaderKnown}|"
  match current.votedFor <|> initial.votedFor with
  | some votedFor => emit s!"{votedFor}"
  | none => slot (.votedFor i) (dom.votedFor.map fun value => s!"{value}")
  emit "|"
  match current.votesGranted <|> initial.votesGranted with
  | some votes => emit (nodes declared votes)
  | none => slot (.votes i) (dom.votesGranted.map (nodes declared))
  emit "|"
  match current.preVotesGranted <|> initial.preVotesGranted with
  | some votes => emit (nodes declared votes)
  | none => slot (.preVotes i) (dom.preVotesGranted.map (nodes declared))
  emit "|"
  match current.retiredCommittedIndex <|> initial.retiredCommittedIndex with
  | some (some index) => do emit "r"; sint index
  | some none => emit "r-"
  | none => emit "r?"
  emit "#"

def store (ctx : Ctx) (value : Store) : K Unit := do
  -- Close the mentioned integer atoms under disequalities.
  let mut changed := true
  while changed do
    changed := false
    for (i, j, _) in value.diseqs do
      let state ← get
      let hasI := i == 0 || state.ints.contains i
      let hasJ := j == 0 || state.ints.contains j
      if hasI != hasJ then
        discard <| intAtom (if hasI then j else i)
        changed := true
  let state ← get
  let vars := #[0] ++ state.intOrder
  emit "D"
  for p in vars do
    for q in vars do
      let bound := value.dbm.get p q
      if bound >= INF then emit "i," else emit s!"{bound},"
  let renamed :=
    (value.diseqs.filterMap fun (i, j, c) =>
      if (i == 0 || state.ints.contains i) && (j == 0 || state.ints.contains j) then
        let i' := if i == 0 then 0 else state.ints[i]!
        let j' := if j == 0 then 0 else state.ints[j]!
        some (if i' < j' then (i', j', c) else (j', i', -c))
      else
        none)
  let sorted := (renamed.map fun (i, j, c) => s!"{i}/{j}/{c}").mergeSort (· ≤ ·)
  emit s!"N{sorted.eraseDups}"
  for id in state.contentOrder do
    slot (.content id) ((value.contents[id]!).map (content ctx.1 ctx.2))

end Key

/-- The canonical key of `world`'s future. -/
def worldKey (world : World) : WorldKey :=
  let ctx : Key.Ctx := (world.env.header.declared, world.env.txIds)
  let run : K Unit := do
    for i in [:world.nodes.size] do
      Key.node ctx i world.nodes[i]! world.initial[i]! world.doms[i]!
    for channel in world.channels do
      for value in channel.pre do Key.message ctx value
      if channel.isOpen then
        -- Once the materialized messages are consumed, an open channel can
        -- materialize a copy of anything another world would deliver, so only
        -- the newest pending message (seen by `last` observations) matters.
        Key.emit "O"
        match channel.post.getLast?, channel.tail with
        | some value, _ => Key.message ctx value
        | none, some value => Key.emit "T"; Key.message ctx value
        | none, none => pure ()
      else
        Key.emit "C"
        for value in channel.post do Key.message ctx value
      Key.emit "/"
    Key.store ctx world.store
  let state := (run.run {}).2
  { base := state.out, slots := state.slots, cands := state.cands }

/-! ## Merging -/

def unionInto {α : Type} [BEq α] (a b : List α) : List α :=
  a ++ b.filter fun value => !a.contains value

def mergeSortedCands (a b : List String) : List String :=
  (a ++ b).mergeSort (· ≤ ·) |>.eraseDups

def withDom (world : World) (i : Nat) (f : InitDom → InitDom) : World :=
  { world with doms := world.doms.modify i f }

/-- `world` with slot `mine` widened by the candidates of `other`'s slot `theirs`. -/
def mergeSlot (world : World) (mine : Slot) (other : World) (theirs : Slot) : World :=
  match mine, theirs with
  | .content id, .content id' =>
      {
        world with
          store :=
            {
              world.store with
                contents :=
                  world.store.contents.set! id
                    (unionInto world.store.contents[id]! other.store.contents[id']!)
            }
      }
  | .role i, .role _ =>
      withDom world i fun dom => { dom with role := unionInto dom.role other.doms[i]!.role }
  | .votedFor i, .votedFor _ =>
      withDom world i fun dom =>
        { dom with votedFor := unionInto dom.votedFor other.doms[i]!.votedFor }
  | .votes i, .votes _ =>
      withDom world i fun dom =>
        { dom with votesGranted := unionInto dom.votesGranted other.doms[i]!.votesGranted }
  | .preVotes i, .preVotes _ =>
      withDom world i fun dom =>
        { dom with preVotesGranted := unionInto dom.preVotesGranted other.doms[i]!.preVotesGranted }
  | _, _ => world

/--
Repeatedly merges worlds that agree on everything except one slot, replacing
them by one world whose slot allows the union of their candidates. The set of
concrete states represented is unchanged.
-/
def mergeGroup (group : Array (World × WorldKey)) : Array (World × WorldKey) := Id.run do
  if group.size <= 1 then return group
  let width := (group[0]?.map (·.2.slots.size)).getD 0
  -- Only positions whose candidates vary within the group can distinguish worlds.
  let first := (group[0]?.map (·.2.cands)).getD #[]
  let active := (List.range width).filter fun p =>
    group.any fun (_, key) => key.cands[p]! != first[p]!
  let mut items := group
  let mut changed := true
  while changed do
    changed := false
    for p in active do
      let mut index : Std.HashMap String Nat := {}
      let mut next : Array (World × WorldKey) := #[]
      for (world, key) in items do
        let rest :=
          String.intercalate "|" (active.filter (· != p) |>.map fun q => renderCands key.cands[q]!)
        match index[rest]? with
        | some j =>
            if let some (kept, keptKey) := next[j]? then
              let merged := mergeSlot kept keptKey.slots[p]! world key.slots[p]!
              let cands := mergeSortedCands keptKey.cands[p]! key.cands[p]!
              next := next.set! j (merged, { keptKey with cands := keptKey.cands.set! p cands })
              changed := true
        | none =>
            index := index.insert rest next.size
            next := next.push (world, key)
      items := next
  return items

/-- Merges worlds group by group, keeping groups in order of first appearance. -/
def mergeWorlds (items : Array (World × WorldKey)) : Array (World × WorldKey) := Id.run do
  let mut groupOf : Std.HashMap String Nat := {}
  let mut groups : Array (Array (World × WorldKey)) := #[]
  for item in items do
    match groupOf[item.2.base]? with
    | some g => groups := groups.modify g (·.push item)
    | none =>
        groupOf := groupOf.insert item.2.base groups.size
        groups := groups.push #[item]
  return groups.foldl (fun out group => out ++ mergeGroup group) #[]

end CCFRaft.MidTrace.Sym
