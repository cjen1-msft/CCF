module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SymCore

@[expose] public section

/-!
# Symbolic node state

Accessors for node fields whose initial values are unknown, and symbolic
versions of the log and configuration queries in `NodeState.lean` and
`ClusterConfig.lean`. A field read before it is known binds a fresh atom in
`World.initial`; reading the log before a `logLength` observation is
unsupported.
-/

namespace CCFRaft.MidTrace.Sym

open Lean CCFRaft.Model.Node

namespace Env

def size (env : Env) : Nat := env.names.size

def name (env : Env) (i : Nat) : String := env.names[i]!

def index? (env : Env) (node : String) : Option Nat := env.names.findIdx? (· == node)

def config (env : Env) : InitialConfig String := env.header.bootstrap

def channel (env : Env) (source destination : Nat) : Nat := source * env.size + destination

end Env

def nameOf (i : Nat) : M String := do return (← M.env).name i

def indexOf (node : String) : M Nat := do
  match (← M.env).index? node with
  | some i => pure i
  | none => M.die s!"undeclared node '{node}'"

def emptyNode (n : Nat) : SNode :=
  { sentIndex := Array.replicate n none, matchIndex := Array.replicate n none }

def modifyInitial (i : Nat) (f : SNode → SNode) : M Unit :=
  M.modify fun world => { world with initial := world.initial.modify i f }

def modifyDom (i : Nat) (f : InitDom → InitDom) : M Unit :=
  M.modify fun world => { world with doms := world.doms.modify i f }

def initialOf (i : Nat) : M SNode := do return (← M.world).initial[i]!

/-! ## Finite-domain fields -/

def roleQ {β : Type} [BEq β] (i : Nat) (s : SNode) (f : Role → β) : M β :=
  match s.role with
  | some role => pure (f role)
  | none =>
      M.pick (fun world => world.doms[i]!.role)
        (fun world roles =>
          { world with doms := world.doms.modify i fun dom => { dom with role := roles } })
        f

def isRole (i : Nat) (s : SNode) (role : Role) : M Bool := roleQ i s (· == role)

def votedQ {β : Type} [BEq β] (i : Nat) (s : SNode) (f : Option String → β) : M β :=
  match s.votedFor with
  | some votedFor => pure (f votedFor)
  | none =>
      M.pick (fun world => world.doms[i]!.votedFor)
        (fun world values =>
          { world with doms := world.doms.modify i fun dom => { dom with votedFor := values } })
        f

def votesQ {β : Type} [BEq β] (i : Nat) (s : SNode) (f : Nodes → β) : M β :=
  match s.votesGranted with
  | some votes => pure (f votes)
  | none =>
      M.pick (fun world => world.doms[i]!.votesGranted)
        (fun world values =>
          {
            world with
              doms := world.doms.modify i fun dom => { dom with votesGranted := values }
          })
        f

def preVotesQ {β : Type} [BEq β] (i : Nat) (s : SNode) (f : Nodes → β) : M β :=
  match s.preVotesGranted with
  | some votes => pure (f votes)
  | none =>
      M.pick (fun world => world.doms[i]!.preVotesGranted)
        (fun world values =>
          {
            world with
              doms := world.doms.modify i fun dom => { dom with preVotesGranted := values }
          })
        f

/-- A Boolean field read through `get`, bound in `World.initial` on first use. -/
def boolField (i : Nat) (s : SNode) (get : SNode → Option Bool)
    (set : SNode → Bool → SNode) : M Bool := do
  match get s with
  | some value => pure value
  | none =>
      match get (← initialOf i) with
      | some value => pure value
      | none => do
          let value ← M.choose [false, true]
          modifyInitial i fun node => set node value
          pure value

def isNewFollower (i : Nat) (s : SNode) : M Bool :=
  boolField i s (·.isNewFollower) fun node value => { node with isNewFollower := some value }

def leaderKnown (i : Nat) (s : SNode) : M Bool :=
  boolField i s (·.leaderKnown) fun node value => { node with leaderKnown := some value }

/-! ## Integer fields and the log -/

def getLog (i : Nat) (s : SNode) : M (Array SEntry) := do
  match s.log with
  | some log => pure log
  | none =>
      match (← initialOf i).log with
      | some log => pure log
      | none => M.unsupported "log read before its length is observed"

/-- Invariant: the last log term is at most the current term. -/
def termInvariant (i : Nat) : M Unit := do
  unless (← M.env).invariants do return
  let initial ← initialOf i
  match initial.log, initial.currentTerm with
  | some log, some term =>
      match log.back? with
      | some entry => M.assumeLe entry.term term 0 "invariant: last log term <= current term"
      | none => pure ()
  | _, _ => pure ()

def getCt (i : Nat) (s : SNode) : M SInt := do
  match s.currentTerm with
  | some term => pure term
  | none =>
      match (← initialOf i).currentTerm with
      | some term => pure term
      | none => do
          let term ← M.freshNat
          modifyInitial i fun node => { node with currentTerm := some term }
          termInvariant i
          pure term

def getCi (i : Nat) (s : SNode) : M SInt := do
  match s.commitIndex with
  | some index => pure index
  | none =>
      match (← initialOf i).commitIndex with
      | some index => pure index
      | none => do
          let index ← M.freshNat
          modifyInitial i fun node => { node with commitIndex := some index }
          pure index

def getRci (i : Nat) (s : SNode) : M (Option SInt) := do
  match s.retiredCommittedIndex with
  | some value => pure value
  | none =>
      match (← initialOf i).retiredCommittedIndex with
      | some value => pure value
      | none => do
          let value ←
            if ← M.choose [false, true] then
              (some <$> M.freshNat : M (Option SInt))
            else
              pure none
          modifyInitial i fun node => { node with retiredCommittedIndex := some value }
          pure value

/-- Binds the initial log to `length` fresh entries. -/
def bindLog (i : Nat) (length : Nat) : M Unit := do
  let invariants := (← M.env).invariants
  let mut log : Array SEntry := #[]
  let mut previous : Option SInt := none
  for _ in [:length] do
    let term ← M.freshNat
    if invariants then
      M.assumeLe (SInt.lit 1) term 0 "invariant: entry terms are positive"
      if let some before := previous then
        M.assumeLe before term 0 "invariant: log terms are monotone"
    previous := some term
    log := log.push { term, content := ← M.freshContent }
  modifyInitial i fun node => { node with log := some log }
  termInvariant i

def peerField (i : Nat) (s : SNode) (peer : Nat) (get : SNode → Array (Option SInt))
    (set : SNode → Array (Option SInt) → SNode) : M SInt := do
  match (get s)[peer]! with
  | some value => pure value
  | none =>
      match (get (← initialOf i))[peer]! with
      | some value => pure value
      | none => do
          let value ← M.freshNat
          modifyInitial i fun node => set node ((get node).set! peer (some value))
          pure value

def getSent (i : Nat) (s : SNode) (peer : Nat) : M SInt :=
  peerField i s peer (·.sentIndex) fun node values => { node with sentIndex := values }

def getMatch (i : Nat) (s : SNode) (peer : Nat) : M SInt :=
  peerField i s peer (·.matchIndex) fun node values => { node with matchIndex := values }

/-! ## Log queries -/

def termAt (log : Array SEntry) (index : Nat) : SInt :=
  if index == 0 then SInt.lit 0 else (log[index - 1]?.map (·.term)).getD (SInt.lit 0)

/-- `min a cap` as a concrete index; `a` must be a natural. -/
def clamp (a : SInt) (cap : Nat) : M Nat := do
  if ← M.le (SInt.lit cap) a then pure cap else M.concrete a

/-- `termAt` at a symbolic index. -/
def termAtS (log : Array SEntry) (index : SInt) : M SInt := do
  return termAt log (← clamp index (log.size + 1))

def isSig (content : SContent) : M Bool := M.content content (· == .signature)

def isSigAt (log : Array SEntry) (index : Nat) : M Bool :=
  if index == 0 then pure false
  else
    match log[index - 1]? with
    | some entry => isSig entry.content
    | none => pure false

/-- The highest signature index at or below `limit`, or zero. -/
def maxSigUpTo (log : Array SEntry) (limit : Nat) : M Nat := do
  let mut index := Nat.min limit log.size
  while index > 0 do
    if ← isSig log[index - 1]!.content then return index
    index := index - 1
  return 0

def maxCommittableIndex (log : Array SEntry) : M Nat := maxSigUpTo log log.size

/-- The highest index at or below `min index log.size` whose term is at most `term`. -/
def findHighestPossibleMatch (log : Array SEntry) (index : Nat) (term : SInt) : M Nat := do
  let mut candidate := Nat.min index log.size
  while candidate > 0 do
    if ← M.le (termAt log candidate) term then return candidate
    candidate := candidate - 1
  return 0

/-- The first index above `after` whose content satisfies `predicate`. -/
def firstIndexAfter (log : Array SEntry) (after : Nat) (predicate : Content → Bool)
    : M (Option Nat) := do
  let mut index := after + 1
  while index <= log.size do
    if ← M.content log[index - 1]!.content predicate then return some index
    index := index + 1
  return none

def lastCommittableIndex (log : Array SEntry) (commitIndex : SInt) : M SInt := do
  M.max commitIndex (SInt.lit (← maxCommittableIndex log))

/-! ## Configurations -/

/-- A configuration's nodes: known, or the single configuration of a content atom. -/
inductive NSet where
  | known (nodes : Nodes)
  | atom (id : Nat)

def lastConfiguration (content : Content) : Nodes :=
  ((entryConfigurations content).getLast?).getD ∅

def NSet.query {β : Type} [BEq β] (set : NSet) (f : Nodes → β) : M β :=
  match set with
  | .known nodes => pure (f nodes)
  | .atom id => M.content (.atom id) fun content => f (lastConfiguration content)

structure Config where
  index : Nat
  nodes : NSet

/-- Configurations of an entry, in order. -/
def entryConfigs (content : SContent) : M (List NSet) :=
  match content with
  | .known content => pure ((entryConfigurations content).map .known)
  | .atom id => do
      match ← M.content content fun content => (entryConfigurations content).length with
      | 0 => pure []
      | 1 => pure [.atom id]
      | _ => M.unsupported "unknown entry with several configurations"

/-- The last configuration in the history of `log.take limit`. -/
def lastConfigUpTo (log : Array SEntry) (limit : Nat) : M Config := do
  let mut index := Nat.min limit log.size
  while index > 0 do
    let configs ← entryConfigs log[index - 1]!.content
    if let some nodes := configs.getLast? then return { index, nodes }
    index := index - 1
  return { index := 0, nodes := .known (← M.env).config.configuration }

/-- Every configuration of entries above `after`, in order. -/
def configsAfter (log : Array SEntry) (after : Nat) : M (List Config) := do
  let mut result := #[]
  for index in [after + 1:log.size + 1] do
    for nodes in ← entryConfigs log[index - 1]!.content do
      result := result.push { index, nodes }
  return result.toList

def activeConfigs (log : Array SEntry) (commitIndex : SInt) : M (List Config) := do
  let committed ← clamp commitIndex log.size
  return (← lastConfigUpTo log committed) :: (← configsAfter log committed)

def memberOf (configs : List Config) (node : String) : M Bool :=
  M.anyM configs fun config => config.nodes.query (node ∈ ·)

def configQuorum (config : Config) (support : Nodes) : M Bool :=
  config.nodes.query fun nodes =>
    decide (hasConfigurationMajority support { index := config.index, nodes })

def hasQuorum (configs : List Config) (support : Nodes) : M Bool :=
  M.allM configs fun config => configQuorum config support

def hasRetiredCommitted (node : String) (content : Content) : Bool :=
  content.effects.any fun effect =>
    match effect with
    | .retiredCommitted nodes => decide (node ∈ nodes)
    | .reconfiguration _ => false

/-- Whether `node ∈ retiredCommittedNodes (log.take limit)`. -/
def rcMem (log : Array SEntry) (limit : Nat) (node : String) : M Bool :=
  M.anyM ((List.range (Nat.min limit log.size)).map (log[·]!))
    fun entry => M.content entry.content (hasRetiredCommitted node)

/-- `none` when `node` is retired by this entry, else whether it is a member after it. -/
def retireStep (node : String) (inside : Bool) (content : Content) : Option Bool :=
  (entryConfigurations content).foldl
    (fun state nodes =>
      match state with
      | none => none
      | some inside => if inside && !decide (node ∈ nodes) then none else some (decide (node ∈ nodes)))
    (some inside)

/-- `retirementIndexInLog` for `log.take limit`. -/
def retirementIndex (log : Array SEntry) (limit : Nat) (node : String) : M (Option Nat) := do
  let mut inside := decide (node ∈ (← M.env).config.configuration)
  for index in [1:Nat.min limit log.size + 1] do
    match ← M.content log[index - 1]!.content (retireStep node inside) with
    | none => return some index
    | some next => inside := next
  return none

/-- Whether `node` is a member of the initial or some entry configuration in `log.take limit`. -/
def everMember (log : Array SEntry) (limit : Nat) (node : String) : M Bool := do
  if decide (node ∈ (← M.env).config.configuration) then return true
  M.anyM ((List.range (Nat.min limit log.size)).map (log[·]!))
    fun entry => M.content entry.content fun content =>
      (entryConfigurations content).any (node ∈ ·)

/--
`node ∈ retirementCompletedNodes`: absent from the last committed configuration,
present in an earlier committed one, and not retired-committed in the committed log.
-/
def retCompletedMem (log : Array SEntry) (commitIndex : SInt) (node : String) : M Bool := do
  let committed ← clamp commitIndex log.size
  let last ← lastConfigUpTo log committed
  M.andM (M.notM (last.nodes.query (node ∈ ·)))
    (M.andM (everMember log committed node) (M.notM (rcMem log committed node)))

/-- `peer ∈ eligiblePeers` of node `i` in state `s`. -/
def eligible (i : Nat) (s : SNode) (peer : Nat) : M Bool := do
  if peer == i then return false
  let log ← getLog i s
  let commitIndex ← getCi i s
  let name ← nameOf peer
  M.orM (do memberOf (← activeConfigs log commitIndex) name) (retCompletedMem log commitIndex name)

def eligiblePeersSorted (i : Nat) (s : SNode) : M (List Nat) := do
  M.filterM (← M.env).sorted (eligible i s)

def activeOthersSorted (i : Nat) (s : SNode) : M (List Nat) := do
  let configs ← activeConfigs (← getLog i s) (← getCi i s)
  M.filterM (← M.env).sorted fun peer => do
    if peer == i then return false
    memberOf configs (← nameOf peer)

/-- `(state.retirement config self).phase = .retiredCommitted`. -/
def isRetiredCommitted (i : Nat) (s : SNode) : M Bool := do
  if (← getRci i s).isNone then return false
  let log ← getLog i s
  return (← retirementIndex log log.size (← nameOf i)).isSome

def campaignEligible (i : Nat) (s : SNode) : M Bool := do
  let log ← getLog i s
  let configs ← activeConfigs log (← getCi i s)
  let signed ← maxCommittableIndex log
  let name ← nameOf i
  M.anyM configs fun config =>
    if config.index <= signed then config.nodes.query (name ∈ ·) else pure false

def canStartElection (i : Nat) (s : SNode) : M Bool := do
  let log ← getLog i s
  let commitIndex ← getCi i s
  let name ← nameOf i
  M.andM
    (roleQ i s fun role =>
      role == .follower || role == .preVoteCandidate || role == .candidate)
    (M.andM
      (M.orM
        (M.andM (do memberOf (← activeConfigs log commitIndex) name) (campaignEligible i s))
        (retCompletedMem log commitIndex name))
      (M.notM (isRetiredCommitted i s)))

end CCFRaft.MidTrace.Sym
