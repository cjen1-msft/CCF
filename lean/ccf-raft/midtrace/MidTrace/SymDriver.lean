module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SymObs
public import MidTrace.SymKey
public import Std.Data.HashSet

@[expose] public section

/-!
# Mid-trace validation driver

Runs the instructions breadth-first over every world consistent with the
observations so far. A `valid` verdict is only returned after a concrete
initial state built from a surviving world passes `Replay.replayFrom`, so it
never depends on the symbolic engine being correct. `invalid` means every
branch died; any branch the engine could not follow turns that into `unknown`.
-/

namespace CCFRaft.MidTrace.Sym

open Lean CCFRaft.Model.Node CCFRaft.Replay

def allRoles : List Role := [.none, .follower, .preVoteCandidate, .candidate, .leader]

def subsets (nodes : List String) : List Nodes :=
  nodes.foldr (fun node rest => rest ++ rest.map (insert node)) [∅]

/-- Contents of unknown entries: at most one effect over nonempty declared sets. -/
def contentDomain (nodes : List String) : List Content :=
  let sets := (subsets nodes).filter (·.Nonempty)
  [.signature, .transaction "midtrace" []]
  ++ sets.map (fun set => .transaction "midtrace" [.reconfiguration set])
  ++ sets.map (fun set => .transaction "midtrace" [.retiredCommitted set])

/-- Every string under a `transaction` key in `value`. -/
partial def transactionIds (value : Json) (found : Array String) : Array String :=
  match value with
  | .arr values => values.foldl (fun found value => transactionIds value found) found
  | .obj fields =>
      fields.foldl
        (fun found key value =>
          match key, value with
          | "transaction", .str id => found.push id
          | _, value => transactionIds value found)
        found
  | _ => found

def makeEnv (header : Header) (suffix : Array Json) (invariants : Bool)
    (phantoms : Bool := true) : Env :=
  let names := header.declared.toArray
  let order := (List.range names.size).mergeSort fun a b => decide (names[a]! ≤ names[b]!)
  let ids := suffix.foldl (fun found value => transactionIds value found) #["midtrace"]
  let txIds := ids.foldl
    (fun table id => if table.contains id then table else table.insert id table.size) {}
  { header, names, sorted := order, domain := contentDomain header.declared, invariants, txIds,
    phantoms }

def initialWorld (env : Env) : World :=
  let n := env.size
  let declared := env.header.declared
  {
    env
    nodes := Array.replicate n (emptyNode n)
    initial := Array.replicate n (emptyNode n)
    doms :=
      Array.replicate n
        {
          role := allRoles
          votedFor := none :: some "<other>" :: declared.map some
          votesGranted := subsets declared
          preVotesGranted := subsets declared
        }
    channels := Array.replicate (n * n) {}
    store := {}
  }

/-! ## Witnesses -/

/-- A solution of the store's integer constraints, greedily from lower bounds. -/
def solve (store : Store) : Option (Array Int) := Id.run do
  let mut dbm := store.dbm
  let mut values : Array Int := Array.replicate dbm.size 0
  for v in [1:dbm.size] do
    let relevant := store.diseqs.filter fun (i, j, _) => Nat.max i j == v
    let mut candidate := max 0 (dbm.lower v)
    let mut chosen := false
    for _ in [:relevant.length + 1] do
      if let some high := dbm.upper v then
        if candidate > high then break
      let fixed := (dbm.addLe v 0 candidate).bind fun dbm => dbm.addLe 0 v (-candidate)
      if let some next := fixed then
        let assigned := values.set! v candidate
        if relevant.all fun (i, j, c) => assigned[i]! - assigned[j]! != c then
          dbm := next
          values := assigned
          chosen := true
          break
      candidate := candidate + 1
    if !chosen then return none
  return some values

structure Valuation where
  values : Array Int
  contents : Array Content

def Valuation.nat (valuation : Valuation) (value : SInt) : Nat :=
  (valuation.values[value.base]! + value.off).toNat

def Valuation.content (valuation : Valuation) : SContent → Content
  | .known content => content
  | .atom id => valuation.contents.getD id .signature

def Valuation.entry (valuation : Valuation) (entry : SEntry) : Entry String String :=
  { term := valuation.nat entry.term, content := valuation.content entry.content }

def Valuation.message (valuation : Valuation) : SMsg → Message String String
  | .appendEntries term previous previousTerm entries leaderCommit =>
      .appendEntriesRequest
        {
          term := valuation.nat term
          prevLogIndex := valuation.nat previous
          prevLogTerm := valuation.nat previousTerm
          entries := entries.map valuation.entry
          leaderCommit := valuation.nat leaderCommit
        }
  | .appendEntriesResponse term success lastLogIndex =>
      .appendEntriesResponse
        { term := valuation.nat term, success, lastLogIndex := valuation.nat lastLogIndex }
  | .requestVote term lastTerm lastIndex =>
      .requestVoteRequest
        {
          term := valuation.nat term
          lastCommittableTerm := valuation.nat lastTerm
          lastCommittableIndex := valuation.nat lastIndex
        }
  | .requestVoteResponse term granted =>
      .requestVoteResponse { term := valuation.nat term, voteGranted := granted }
  | .requestPreVote term lastTerm lastIndex =>
      .requestPreVote
        {
          term := valuation.nat term
          lastCommittableTerm := valuation.nat lastTerm
          lastCommittableIndex := valuation.nat lastIndex
        }
  | .requestPreVoteResponse term granted =>
      .requestPreVoteResponse { term := valuation.nat term, voteGranted := granted }
  | .proposeVote term => .proposeVoteRequest (valuation.nat term)

def Valuation.node (valuation : Valuation) (env : Env) (initial : SNode) (dom : InitDom)
    : NodeState String String :=
  let peer (values : Array (Option SInt)) (node : String) : Nat :=
    match env.index? node with
    | some k => ((values[k]!).map valuation.nat).getD 0
    | none => 0
  {
    role := initial.role.getD (dom.role.headD .follower)
    currentTerm := (initial.currentTerm.map valuation.nat).getD 0
    log := ((initial.log.getD #[]).map valuation.entry).toList
    commitIndex := (initial.commitIndex.map valuation.nat).getD 0
    sentIndex := peer initial.sentIndex
    matchIndex := peer initial.matchIndex
    isNewFollower := initial.isNewFollower.getD false
    votedFor := initial.votedFor.getD (dom.votedFor.headD none)
    leaderKnown := initial.leaderKnown.getD false
    votesGranted := initial.votesGranted.getD (dom.votesGranted.headD ∅)
    preVotesGranted := initial.preVotesGranted.getD (dom.preVotesGranted.headD ∅)
    retiredCommittedIndex := (initial.retiredCommittedIndex.getD none).map valuation.nat
  }

/-- A concrete initial state for `world`, if its integer constraints are solved greedily. -/
def witness (world : World) : Option ReplayState := do
  let values ← solve world.store
  let valuation : Valuation :=
    { values, contents := world.store.contents.map fun candidates => candidates.headD .signature }
  let env := world.env
  let n := env.size
  let nodes :=
    (List.range n).map fun i =>
      (env.name i, valuation.node env world.initial[i]! world.doms[i]!)
  let network :=
    (List.range (n * n)).flatMap fun c =>
      world.channels[c]!.initial.map fun message =>
        { source := env.name (c / n), target := env.name (c % n), payload := valuation.message message }
  return { state := { nodes, active := env.header.declared, network } }

/-! ## Breadth-first search -/

inductive Verdict where
  | valid
  | invalid
  | unknown
deriving BEq

def Verdict.name : Verdict → String
  | .valid => "VALID"
  | .invalid => "INVALID"
  | .unknown => "UNKNOWN"

structure Outcome where
  verdict : Verdict
  /-- Why the verdict is not `valid`, or the witness that certifies it. -/
  detail : String
  /-- Instructions processed before the search stopped. -/
  processed : Nat
  maxFrontier : Nat
  /-- Frontier size after each processed instruction. -/
  sizes : Array Nat := #[]
  witness : Option ReplayState := none

def note (reasons : Array String) (reason : String) : Array String :=
  if reasons.size < 3 && !reasons.contains reason then reasons.push reason else reasons

def certify (header : Header) (suffix : Array Json) (frontier : Array World)
    : Option ReplayState × String := Id.run do
  let mut failure := "no world has a solvable witness"
  for world in frontier.extract 0 16 do
    if let some state := witness world then
      match replayFrom header state suffix with
      | .ok _ => return (some state, "")
      | .error error => failure := s!"witness rejected: {error}"
  return (none, failure)

def validate (header : Header) (suffix : Array Json) (invariants : Bool) (cap : Nat)
    (dedup : Bool := true) (dumpAt : Option Nat := none) (phantoms : Bool := true)
    : Outcome := Id.run do
  let env := makeEnv header suffix invariants phantoms
  let mut frontier := #[initialWorld env]
  let mut maxFrontier := 1
  let mut sizes : Array Nat := #[]
  let mut unsupported : Array String := #[]
  for index in [:suffix.size] do
    let instruction := suffix[index]!
    let mut next : Array World := #[]
    let mut keyed : Array (World × WorldKey) := #[]
    let mut seen : Std.HashSet String := {}
    let mut dead : Array String := #[]
    for world in frontier do
      for result in runInstr instruction world do
        match result with
        | .ok _ world =>
            if dedup then
              let key := worldKey world
              let full := key.full
              unless seen.contains full do
                seen := seen.insert full
                keyed := keyed.push (world, key)
            else
              next := next.push world
        | .dead reason => dead := note dead reason
        | .unsupported reason => unsupported := note unsupported reason
    if dedup then
      next := (mergeWorlds keyed).map (·.1)
    maxFrontier := Nat.max maxFrontier next.size
    sizes := sizes.push next.size
    if dumpAt == some (index + 1) then
      let keys := (next.extract 0 8).map fun world => (worldKey world).full
      return {
        verdict := .unknown
        detail := "\n" ++ String.intercalate "\n" keys.toList
        processed := index + 1
        maxFrontier
        sizes
      }
    let label := (originLabel instruction).toOption.getD "?"
    if next.isEmpty then
      if unsupported.isEmpty then
        return {
          verdict := .invalid
          detail := s!"instruction {index + 1} at {label}: {dead.toList}"
          processed := index + 1
          maxFrontier
          sizes
        }
      else
        return {
          verdict := .unknown
          detail := s!"instruction {index + 1} at {label}: unsupported {unsupported.toList}, dead {dead.toList}"
          processed := index + 1
          maxFrontier
          sizes
        }
    if next.size > cap then
      return {
        verdict := .unknown
        detail := s!"instruction {index + 1} at {label}: frontier {next.size} exceeds {cap}"
        processed := index + 1
        maxFrontier
        sizes
      }
    frontier := next
  match certify header suffix frontier with
  | (some state, _) =>
      return {
        verdict := .valid
        detail := ""
        processed := suffix.size
        maxFrontier
        sizes
        witness := some state
      }
  | (none, failure) =>
      return {
        verdict := .unknown
        detail := s!"ENGINE-BUG: {failure}"
        processed := suffix.size
        maxFrontier
        sizes
      }

end CCFRaft.MidTrace.Sym
