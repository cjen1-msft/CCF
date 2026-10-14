module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Std.Data.HashMap
public import CCFRaft.Replay

@[expose] public section

/-!
# Symbolic store for mid-trace validation

The unknown initial state is represented by atoms:

* integer atoms (entry terms, unobserved indices) live in a closed
  difference-bound matrix (DBM) plus a list of disequalities;
* content atoms (entry contents) carry an explicit list of remaining
  candidates, so every content constraint is unary.

`M` is a nondeterministic state monad over `World`: a query whose answer is not
determined by the store returns one result per feasible answer, each with the
answer added to its store.
-/

namespace CCFRaft.MidTrace.Sym

open Lean CCFRaft.Model.Node

abbrev Content := EntryContent String String

abbrev Nodes := Finset String

/-- Groups `items` by `f`, keeping first-occurrence order. -/
def partition {α β : Type} [BEq β] (f : α → β) (items : List α) : List (β × List α) :=
  items.foldl
    (fun groups item =>
      let key := f item
      if groups.any (fun (k, _) => k == key) then
        groups.map
          fun (k, members) => if k == key then (k, members ++ [item]) else (k, members)
      else
        groups ++ [(key, [item])])
    []

/-- `x_base + off`, where variable 0 is the constant zero. -/
structure SInt where
  base : Nat
  off : Int
deriving BEq, Repr, Inhabited

namespace SInt

def lit (value : Nat) : SInt := ⟨0, value⟩

def add (value : SInt) (delta : Int) : SInt := ⟨value.base, value.off + delta⟩

end SInt

def INF : Int := 4611686018427387904

/-- A closed DBM: `get i j` is the tightest known bound on `x_i - x_j`. -/
structure DBM where
  size : Nat := 1
  bounds : Array Int := #[0]
deriving BEq, Inhabited

namespace DBM

def get (dbm : DBM) (i j : Nat) : Int := dbm.bounds[i * dbm.size + j]!

def addVar (dbm : DBM) : DBM × Nat :=
  Id.run do
    let size := dbm.size + 1
    let mut bounds := Array.replicate (size * size) INF
    for i in [:dbm.size] do
      for j in [:dbm.size] do
        bounds := bounds.set! (i * size + j) (dbm.get i j)
    bounds := bounds.set! (dbm.size * size + dbm.size) 0
    return ({ size, bounds }, dbm.size)

/-- Adds `x_i - x_j <= c`, keeping the matrix closed; `none` if infeasible. -/
def addLe (dbm : DBM) (i j : Nat) (c : Int) : Option DBM :=
  if dbm.get i j <= c then
    some dbm
  else if dbm.get j i < INF && dbm.get j i + c < 0 then
    none
  else
    some
      (Id.run do
        let size := dbm.size
        let mut bounds := dbm.bounds
        for p in [:size] do
          let toI := dbm.get p i
          if toI < INF then
            for q in [:size] do
              let fromJ := dbm.get j q
              if fromJ < INF then
                let candidate := toI + c + fromJ
                if candidate < bounds[p * size + q]! then
                  bounds := bounds.set! (p * size + q) candidate
        return { dbm with bounds })

def lower (dbm : DBM) (i : Nat) : Int := - dbm.get 0 i

def upper (dbm : DBM) (i : Nat) : Option Int :=
  let bound := dbm.get i 0
  if bound >= INF then none else some bound

end DBM

structure Store where
  dbm : DBM := {}
  /-- `(i, j, c)` with `i < j` means `x_i - x_j != c`. -/
  diseqs : List (Nat × Nat × Int) := []
  contents : Array (List Content) := #[]
deriving BEq, Inhabited

namespace Store

def diseqsHold (dbm : DBM) (diseqs : List (Nat × Nat × Int)) : Bool :=
  diseqs.all fun (i, j, c) => !(dbm.get i j <= c && dbm.get j i <= -c)

/-- Adds `a <= b + k`. -/
def le (store : Store) (a b : SInt) (k : Int) : Option Store :=
  let c := b.off + k - a.off
  if a.base == b.base then
    if 0 <= c then some store else none
  else
    match store.dbm.addLe a.base b.base c with
    | none => none
    | some dbm =>
        if dbm == store.dbm then
          some store
        else if diseqsHold dbm store.diseqs then
          some { store with dbm }
        else
          none

def entailsLe (store : Store) (a b : SInt) (k : Int) : Bool :=
  store.dbm.get a.base b.base <= b.off + k - a.off

/-- `some answer` when `a <= b + k` is decided by the store. -/
def decideLe (store : Store) (a b : SInt) (k : Int) : Option Bool :=
  if store.entailsLe a b k then
    some true
  else if store.entailsLe b a (-k - 1) then
    some false
  else
    none

def normalize (a b : SInt) : Nat × Nat × Int :=
  -- x_a + a.off != x_b + b.off  <=>  x_a - x_b != b.off - a.off
  let c := b.off - a.off
  if a.base < b.base then (a.base, b.base, c) else (b.base, a.base, -c)

def decideEq (store : Store) (a b : SInt) : Option Bool :=
  if store.entailsLe a b 0 && store.entailsLe b a 0 then
    some true
  else if store.entailsLe a b (-1) || store.entailsLe b a (-1) then
    some false
  else if a.base != b.base && store.diseqs.contains (normalize a b) then
    some false
  else
    none

def eq (store : Store) (a b : SInt) : Option Store := do
  let store ← store.le a b 0
  store.le b a 0

def ne (store : Store) (a b : SInt) : Option Store :=
  match store.decideEq a b with
  | some true => none
  | some false => some store
  | none => some { store with diseqs := normalize a b :: store.diseqs }

/-- Inclusive range of `a`, if bounded above. -/
def range (store : Store) (a : SInt) : Int × Option Int :=
  (store.dbm.lower a.base + a.off, (store.dbm.upper a.base).map (· + a.off))

end Store

inductive SContent where
  | known (content : Content)
  | atom (id : Nat)
deriving BEq, Inhabited

structure SEntry where
  term : SInt
  content : SContent
deriving BEq, Inhabited

inductive SMsg where
  | appendEntries (term prevIndex prevTerm : SInt) (entries : List SEntry)
    (leaderCommit : SInt)
  | appendEntriesResponse (term : SInt) (success : Bool) (lastLogIndex : SInt)
  | requestVote (term lastCommittableTerm lastCommittableIndex : SInt)
  | requestVoteResponse (term : SInt) (granted : Bool)
  | requestPreVote (term lastCommittableTerm lastCommittableIndex : SInt)
  | requestPreVoteResponse (term : SInt) (granted : Bool)
  | proposeVote (term : SInt)
deriving BEq, Inhabited

/--
A node's state. `none` means "still the initial value", which is looked up in
(and lazily bound into) `World.initial`.
-/
structure SNode where
  role : Option Role := none
  currentTerm : Option SInt := none
  log : Option (Array SEntry) := none
  commitIndex : Option SInt := none
  sentIndex : Array (Option SInt)
  matchIndex : Array (Option SInt)
  isNewFollower : Option Bool := none
  votedFor : Option (Option String) := none
  leaderKnown : Option Bool := none
  votesGranted : Option (Finset String) := none
  preVotesGranted : Option (Finset String) := none
  retiredCommittedIndex : Option (Option SInt) := none
deriving BEq, Inhabited

/--
Messages on one channel: materialized pre-cut messages, whether more pre-cut
messages may follow them, then messages sent after the cut.
-/
structure Channel where
  pre : List SMsg := []
  isOpen : Bool := true
  post : List SMsg := []
  /-- Every materialized pre-cut message, in order, for the witness. -/
  initial : List SMsg := []
  /-- In a projection (`Env.projected`), the newest pre-cut message, seen by a
  `last` selection before any post-cut send; the witness places it after
  `initial`. -/
  tail : Option SMsg := none
deriving BEq, Inhabited

/-- Remaining candidates for finite-domain initial fields. -/
structure InitDom where
  role : List Role
  votedFor : List (Option String)
  votesGranted : List Nodes
  preVotesGranted : List Nodes
deriving Inhabited

structure Env where
  header : Replay.Header
  names : Array String
  /-- Node indices in ascending name order (`Finset.sort` order). -/
  sorted : List Nat
  /-- Candidate contents for an unknown entry. -/
  domain : List Content
  /-- Restrict the initial state with cheap reachable-state invariants. -/
  invariants : Bool := true
  /-- Short names for transaction ids that occur in the trace, used by world keys. -/
  txIds : Std.HashMap String Nat := {}
  /-- Deliver a materialized pre-cut copy instead of closing an open channel; see
  `messageAt`. -/
  phantoms : Bool := true
  /-- The instructions are one node's projection (`validateNodes`): channels
  are never closed, since a closed channel's post-cut messages were sent by
  another node whose actions are not replayed here. -/
  projected : Bool := false
  /-- Per node, the `logLength` values its state observations report, in order
  of first appearance: the initial lengths tried when the log is read first. -/
  logHints : Array (List Nat) := #[]
  /-- Most results one `bind` may produce; the rest become one unsupported result. -/
  budget : Nat := 100000

structure World where
  env : Env
  nodes : Array SNode
  initial : Array SNode
  doms : Array InitDom
  channels : Array Channel
  store : Store

inductive Res (α : Type) where
  | ok (value : α) (world : World)
  | dead (reason : String)
  | unsupported (reason : String)

def M (α : Type) : Type := World → List (Res α)

def Res.bind {α β : Type} (result : Res α) (next : α → World → List (Res β))
    : List (Res β) :=
  match result with
  | .ok value world => next value world
  | .dead reason => [.dead reason]
  | .unsupported reason => [.unsupported reason]

/-- `flatMap` that stops once more than `budget` results are produced. -/
def boundedFlatMap {α β : Type} (budget : Nat) (results : List (Res α))
    (next : α → World → List (Res β))
    : List (Res β) :=
  Id.run do
    let mut out : Array (Res β) := #[]
    for result in results do
      if out.size > budget then
        return (out.push (.unsupported "branch budget exceeded")).toList
      for value in result.bind next do
        out := out.push value
    return out.toList

instance : Monad M where
  pure value world := [.ok value world]
  bind action next world :=
    match action world with
    | [result] => result.bind next
    | results => boundedFlatMap world.env.budget results next

namespace M

def world : M World := fun world => [.ok world world]

def setWorld (world : World) : M Unit := fun _ => [.ok () world]

def modify (f : World → World) : M Unit := fun world => [.ok () (f world)]

def env : M Env := fun world => [.ok world.env world]

def die {α : Type} (reason : String) : M α := fun _ => [.dead reason]

def unsupported {α : Type} (reason : String) : M α := fun _ => [.unsupported reason]

def choose {α : Type} (options : List α) : M α :=
  fun world => options.map fun option => .ok option world

def ofExcept {α : Type} (result : Except String α) : M α :=
  match result with
  | .ok value => pure value
  | .error reason => die reason

def require (condition : Bool) (reason : String) : M Unit :=
  if condition then pure () else die reason

def andM (a b : M Bool) : M Bool := do
  if ← a then b else pure false

def orM (a b : M Bool) : M Bool := do
  if ← a then pure true else b

def notM (a : M Bool) : M Bool := do
  return !(← a)

def requireM (condition : M Bool) (reason : String) : M Unit := do
  if ← condition then pure () else die reason

def anyM {α : Type} (items : List α) (p : α → M Bool) : M Bool :=
  match items with
  | [] => pure false
  | item :: rest => orM (p item) (anyM rest p)

def allM {α : Type} (items : List α) (p : α → M Bool) : M Bool :=
  match items with
  | [] => pure true
  | item :: rest => andM (p item) (allM rest p)

def filterM {α : Type} (items : List α) (p : α → M Bool) : M (List α) :=
  match items with
  | [] => pure []
  | item :: rest => do
      let keep ← p item
      let rest ← filterM rest p
      return if keep then item :: rest else rest

/-! ## Integer atoms -/

def fresh : M SInt :=
  fun world =>
    let (dbm, id) := world.store.dbm.addVar
    [.ok ⟨id, 0⟩ { world with store := { world.store with dbm } }]

/-- Assume `a <= b + k`; dies if inconsistent. -/
def assumeLe (a b : SInt) (k : Int := 0) (reason : String := "constraint") : M Unit :=
  fun world =>
    match world.store.le a b k with
    | some store => [.ok () { world with store }]
    | none => [.dead reason]

def assumeEq (a b : SInt) (reason : String := "constraint") : M Unit :=
  fun world =>
    match world.store.eq a b with
    | some store => [.ok () { world with store }]
    | none => [.dead reason]

def freshNat : M SInt := do
  let value ← fresh
  assumeLe (SInt.lit 0) value
  return value

/-- `a <= b + k`, forking when undetermined. -/
def le (a b : SInt) (k : Int := 0) : M Bool :=
  fun world =>
    match world.store.decideLe a b k with
    | some answer => [.ok answer world]
    | none =>
        (match world.store.le a b k with
          | some store => [.ok true { world with store }]
          | none => [])
        ++ (match world.store.le b a (-k - 1) with
            | some store => [.ok false { world with store }]
            | none => [])

def lt (a b : SInt) : M Bool := le a b (-1)

def eq (a b : SInt) : M Bool :=
  fun world =>
    match world.store.decideEq a b with
    | some answer => [.ok answer world]
    | none =>
        (match world.store.eq a b with
          | some store => [.ok true { world with store }]
          | none => [])
        ++ (match world.store.ne a b with
            | some store => [.ok false { world with store }]
            | none => [])

def max (a b : SInt) : M SInt := do
  if ← le a b then pure b else pure a

def min (a b : SInt) : M SInt := do
  if ← le a b then pure a else pure b

/-- Forks over every value of `a`; `a` must be bounded. -/
def concrete (a : SInt) : M Nat :=
  fun world =>
    if a.base == 0 then
      if 0 <= a.off then [.ok a.off.toNat world] else [.dead "negative natural"]
    else
      let (low, high) := world.store.range a
      match high with
      | none => [.unsupported "concretizing an unbounded integer"]
      | some high =>
          let low := if low < 0 then 0 else low
          (List.range ((high - low + 1).toNat)).filterMap
            fun offset =>
              let value := low + offset
              match world.store.eq a ⟨0, value⟩ with
              | some store => some (.ok value.toNat { world with store })
              | none => none

/-! ## Content atoms -/

def freshContent : M SContent :=
  fun world =>
    let id := world.store.contents.size
    [.ok (.atom id)
      {
        world with
          store :=
            { world.store with contents := world.store.contents.push world.env.domain }
      }]

/-- `f content`, forking once per feasible answer. -/
def content {β : Type} [BEq β] (value : SContent) (f : Content → β) : M β :=
  fun world =>
    match value with
    | .known content => [.ok (f content) world]
    | .atom id =>
        match partition f world.store.contents[id]! with
        | [(answer, _)] => [.ok answer world]
        | groups =>
            groups.map
              fun (answer, members) =>
                .ok answer
                  {
                    world with
                      store :=
                        {
                          world.store with
                            contents := world.store.contents.set! id members
                        }
                  }

/-- `f` of a finite-domain value read with `get`, forking once per answer. -/
def pick {α β : Type} [BEq β] (get : World → List α) (set : World → List α → World)
    (f : α → β)
    : M β :=
  fun world =>
    match partition f (get world) with
    | [] => [.dead "empty domain"]
    | [(answer, _)] => [.ok answer world]
    | groups => groups.map fun (answer, members) => .ok answer (set world members)

end M

end CCFRaft.MidTrace.Sym
