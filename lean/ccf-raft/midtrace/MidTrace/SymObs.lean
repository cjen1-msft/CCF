module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SymModel

@[expose] public section

/-!
# Symbolic instructions

Runs one replay instruction over a `World`. Observations become constraints on
the store (or kill the branch); actions run the symbolic model.

A channel is `pre ++ post`: `pre` holds materialized pre-cut messages and
`post` the messages sent after the cut. While a channel is open, unknown
pre-cut messages may follow `pre`. The first observation of an unknown
position forks: either the channel was exhausted (close it) or the observed
packet is a pre-cut message (materialize it from the packet).
-/

namespace CCFRaft.MidTrace.Sym

open Lean CCFRaft.Model.Node CCFRaft.Replay

def setNode (i : Nat) (s : SNode) : M Unit :=
  M.modify fun world => { world with nodes := world.nodes.set! i s }

def getChannel (c : Nat) : M Channel := do return (← M.world).channels[c]!

def setChannel (c : Nat) (channel : Channel) : M Unit :=
  M.modify fun world => { world with channels := world.channels.set! c channel }

def channelIndex (source destination : String) : M Nat := do
  return (← M.env).channel (← indexOf source) (← indexOf destination)

/-! ## Comparing observed fields -/

inductive SVal where
  | json (value : Json)
  | nat (value : SInt)

def checkNat (key : String) (expected : Json) (actual : SInt) : M Unit :=
  match expected.getNat? with
  | .ok value =>
      if expected == toJson value then
        M.assumeEq actual (SInt.lit value) s!"{key}: observed {expected.compress}"
      else
        M.die s!"{key}: observed {expected.compress}"
  | .error _ => M.die s!"{key}: observed {expected.compress}, which is not a natural"

def checkVal (key : String) (expected : Json) : SVal → M Unit
  | .json actual =>
      M.require (expected == actual)
        s!"{key}: observed {expected.compress}, canonical {actual.compress}"
  | .nat actual => checkNat key expected actual

/-- `checkFields` over symbolic values. -/
def checkObserved (observed : List (String × Json)) (actual : List (String × SVal)) : M Unit := do
  M.require (!observed.isEmpty) "observation must contain at least one field"
  for (key, expected) in observed do
    match actual.lookup key with
    | some value => checkVal key expected value
    | none => M.die s!"unsupported observation field '{key}'"

/-! ## Messages -/

def msgFields (message : SMsg) : List (String × SVal) :=
  let fields :=
    match message with
    | .appendEntries _ previous previousTerm entries leaderCommit =>
        [
          ("msg", .json (toJson "raft_append_entries")),
          ("prev_idx", .nat previous),
          ("prev_term", .nat previousTerm),
          ("idx", .nat (previous.add entries.length)),
          ("leader_commit_idx", .nat leaderCommit),
          ("term_of_idx", .nat ((entries.getLast?.map (·.term)).getD previousTerm)),
          ("contains_new_view", .json (toJson false))
        ]
    | .appendEntriesResponse _ success lastLogIndex =>
        [
          ("msg", .json (toJson "raft_append_entries_response")),
          ("success", .json (toJson (if success then "OK" else "FAIL"))),
          ("last_log_idx", .nat lastLogIndex)
        ]
    | .requestVote _ lastTerm lastIndex =>
        [
          ("msg", .json (toJson "raft_request_vote")),
          ("last_committable_idx", .nat lastIndex),
          ("term_of_last_committable_idx", .nat lastTerm)
        ]
    | .requestPreVote _ lastTerm lastIndex =>
        [
          ("msg", .json (toJson "raft_request_pre_vote")),
          ("last_committable_idx", .nat lastIndex),
          ("term_of_last_committable_idx", .nat lastTerm)
        ]
    | .requestVoteResponse _ granted =>
        [
          ("msg", .json (toJson "raft_request_vote_response")),
          ("vote_granted", .json (toJson granted))
        ]
    | .requestPreVoteResponse _ granted =>
        [
          ("msg", .json (toJson "raft_request_pre_vote_response")),
          ("vote_granted", .json (toJson granted))
        ]
    | .proposeVote _ => [("msg", .json (toJson "raft_propose_request_vote"))]
  ("term", .nat message.term) :: fields

/-- A packet field as a literal, or a fresh natural when absent. -/
def natOr (packet : Json) (key : String) : M SInt :=
  match packet.getObjVal? key with
  | .ok value =>
      match value.getNat? with
      | .ok n => pure (SInt.lit n)
      | .error _ => M.die s!"{key}: observed {value.compress}, which is not a natural"
  | .error _ => M.freshNat

def boolOr (packet : Json) (key : String) (decode : Json → Option Bool) : M Bool :=
  match packet.getObjVal? key with
  | .ok value =>
      match decode value with
      | some answer => pure answer
      | none => M.die s!"{key}: observed {value.compress}"
  | .error _ => M.choose [false, true]

def decodeSuccess (value : Json) : Option Bool :=
  if value == toJson "OK" then some true
  else if value == toJson "FAIL" then some false
  else none

def decodeBool (value : Json) : Option Bool := value.getBool?.toOption

/-- A pre-cut message that matches what is known of `packet`. -/
def materialize (packet : Json) : M SMsg := do
  let invariants := (← M.env).invariants
  let term ← natOr packet "term"
  match packet.getObjVal? "msg" with
  | .ok (.str "raft_append_entries") =>
      let some previous := (packet.getObjVal? "prev_idx" >>= Json.getNat?).toOption
        | M.unsupported "AppendEntries packet without prev_idx"
      let some last := (packet.getObjVal? "idx" >>= Json.getNat?).toOption
        | M.unsupported "AppendEntries packet without idx"
      M.require (previous <= last) "idx below prev_idx"
      let previousTerm ← natOr packet "prev_term"
      let leaderCommit ← natOr packet "leader_commit_idx"
      let count := last - previous
      let lastTerm := (packet.getObjVal? "term_of_idx" >>= Json.getNat?).toOption
      let mut entries : Array SEntry := #[]
      let mut before := previousTerm
      for k in [:count] do
        let entryTerm ←
          match lastTerm with
          | some value => if k + 1 == count then pure (SInt.lit value) else M.freshNat
          | none => M.freshNat
        if invariants then
          M.assumeLe (SInt.lit 1) entryTerm 0 "invariant: entry terms are positive"
          M.assumeLe before entryTerm 0 "invariant: entry terms are monotone"
        before := entryTerm
        entries := entries.push { term := entryTerm, content := ← M.freshContent }
      if invariants then
        M.assumeLe before term 0 "invariant: entry terms are at most the message term"
      return .appendEntries term (SInt.lit previous) previousTerm entries.toList leaderCommit
  | .ok (.str "raft_append_entries_response") =>
      return .appendEntriesResponse term (← boolOr packet "success" decodeSuccess)
        (← natOr packet "last_log_idx")
  | .ok (.str "raft_request_vote") =>
      let lastIndex ← natOr packet "last_committable_idx"
      return .requestVote term (← natOr packet "term_of_last_committable_idx") lastIndex
  | .ok (.str "raft_request_pre_vote") =>
      let lastIndex ← natOr packet "last_committable_idx"
      return .requestPreVote term (← natOr packet "term_of_last_committable_idx") lastIndex
  | .ok (.str "raft_request_vote_response") =>
      return .requestVoteResponse term (← boolOr packet "vote_granted" decodeBool)
  | .ok (.str "raft_request_pre_vote_response") =>
      return .requestPreVoteResponse term (← boolOr packet "vote_granted" decodeBool)
  | .ok (.str "raft_propose_request_vote") => return .proposeVote term
  | _ => M.die "packet has no known msg type"

/-- Removes the oldest pending message of channel `c`. -/
def popHead (c : Nat) : M SMsg := do
  let channel ← getChannel c
  match channel.pre with
  | message :: rest =>
      setChannel c { channel with pre := rest }
      pure message
  | [] =>
      let closed : M SMsg :=
        match channel.post with
        | message :: rest => do
            setChannel c { channel with isOpen := false, post := rest }
            pure message
        | [] => M.die "no pending packet"
      if channel.isOpen then
        if !(← M.env).projected && (← M.choose [true, false]) then closed
        else M.unsupported "unobserved pre-cut message"
      else
        closed

/-- The pending message at `index`, materializing a pre-cut message if needed.

At the head of an open channel the search may either close the channel (the
head is the oldest post-cut message `p`) or materialize a fresh pre-cut message
`m`. With `phantoms` only the latter is explored: the materialize branch
subsumes the close branch. Any solution of the close branch extends to one of
the materialize branch by setting `m` to the value of `p` (materialized fields
are unconstrained beyond the observed packet and the reachable-state
invariants, which `p` satisfies); afterwards the receiver's state agrees, and
the channel holds `p :: rest` instead of `rest` behind an open boundary, so each
later head delivery can again be a pre-cut copy and `last` selections see the
same message whenever the close branch's queue is non-empty. Pruning a
subsumed branch preserves both verdicts: a closed-branch witness implies a
materialize-branch witness, and every verdict is still certified by replay.
The search then never links a delivery to its send, which keeps worlds that
differ only in that choice from multiplying. -/
def messageAt (c : Nat) (index : Nat) (packet : Json) : M SMsg := do
  let channel ← getChannel c
  if h : index < channel.pre.length then return channel.pre[index]
  let fromPost : M SMsg :=
    match channel.post[index - channel.pre.length]? with
    | some message => pure message
    | none => M.die s!"no pending packet at occurrence {index}"
  if !channel.isOpen then return ← fromPost
  if index != channel.pre.length then
    return ← M.unsupported "observation beyond the materialized pre-cut messages"
  if !(← M.env).phantoms && (← M.choose [true, false]) then
    setChannel c { channel with isOpen := false }
    fromPost
  else
    let message ← materialize packet
    let channel ← getChannel c
    setChannel c
      { channel with pre := channel.pre ++ [message], initial := channel.initial ++ [message] }
    return message

/--
The newest pending message of channel `c`.

In a projection the destination's materialized messages are invisible, so
with no post-cut send the newest message is a pre-cut `tail`. Placing it after
every message the destination consumes keeps it pending, so this subsumes
the alternatives (an exhausted channel has no newest message at all).
-/
def lastMessage (c : Nat) (packet : Json) : M SMsg := do
  let channel ← getChannel c
  match channel.post.getLast? with
  | some message => pure message
  | none =>
      if (← M.env).projected then
        if let some message := channel.tail then return message
        let message ← materialize packet
        let channel ← getChannel c
        setChannel c { channel with tail := some message }
        return message
      let closed : M SMsg :=
        match channel.pre.getLast? with
        | some message => pure message
        | none => M.die "no pending packet"
      if !channel.isOpen then return ← closed
      if !(← M.env).projected && (← M.choose [true, false]) then
        setChannel c { channel with isOpen := false }
        closed
      else
        M.unsupported "last pending message is an unmaterialized pre-cut message"

def observeMessage (instruction : Json) : M Unit := do
  let header := (← M.env).header
  M.ofExcept
    (keys instruction
      ["kind", "observation", "origin", "source", "destination", "packet", "occurrence", "selection"])
  let source ← M.ofExcept (nodeField header instruction "source")
  let destination ← M.ofExcept (nodeField header instruction "destination")
  let c ← channelIndex source destination
  let packet ← M.ofExcept (field instruction "packet")
  let selection ← M.ofExcept (optionalField instruction "selection")
  let message ←
    match selection with
    | none => messageAt c (← M.ofExcept (occurrence instruction)) packet
    | some selection =>
        if (← M.ofExcept (optionalField instruction "occurrence")).isSome then
          M.die "message observation cannot specify both selection and occurrence"
        else
          match ← M.ofExcept (text selection) with
          | "first" => messageAt c 0 packet
          | "last" => lastMessage c packet
          | name => M.die s!"unsupported message selection '{name}'"
  discard <| M.ofExcept (stringField packet "msg")
  checkObserved (← M.ofExcept (objectFields packet)) (msgFields message)

/-! ## Node state -/

def members (header : Header) (nodes : Nodes) : Json :=
  toJson (header.declared.filter fun member => member ∈ nodes)

def stateKeys : List String :=
  [
    "role",
    "currentTerm",
    "logLength",
    "commitIndex",
    "retiredCommittedIndex",
    "preVoteEnabled",
    "sentIndex",
    "matchIndex",
    "committableIndices",
    "configurations",
    "retirementIndex",
    "membershipState",
    "retirementCommittableIndex"
  ]

def checkLogLength (i : Nat) (s : SNode) (expected : Json) : M Unit := do
  let some length := expected.getNat?.toOption
    | M.die s!"logLength: observed {expected.compress}"
  match s.log with
  | some log => M.require (log.size == length) s!"logLength: observed {length}, canonical {log.size}"
  | none =>
      match (← initialOf i).log with
      | some log =>
          M.require (log.size == length) s!"logLength: observed {length}, canonical {log.size}"
      | none => bindLog i length

def checkCommittable (i : Nat) (s : SNode) (expected : Json) : M Unit := do
  let log ← getLog i s
  let commitIndex ← getCi i s
  let some values := (expected.getArr? >>= fun values => values.toList.mapM Json.getNat?).toOption
    | M.die s!"committableIndices: observed {expected.compress}"
  M.require (expected == toJson values) s!"committableIndices: observed {expected.compress}"
  let sorted := (List.range' 1 log.size).filter (values.contains ·)
  M.require (sorted == values) s!"committableIndices: observed {expected.compress}"
  let (low, _) := (← M.world).store.range commitIndex
  let low := if low < 0 then 0 else low.toNat
  M.require (values.all (· > low)) s!"committableIndices: observed {expected.compress}"
  for k in [low + 1:log.size + 1] do
    let actual ← M.andM (M.lt commitIndex (SInt.lit k)) (isSigAt log k)
    M.require (actual == values.contains k) s!"committableIndices: index {k}"

def checkConfigurations (i : Nat) (s : SNode) (expected : Json) : M Unit := do
  let header := (← M.env).header
  let configs ← activeConfigs (← getLog i s) (← getCi i s)
  let configs := configs.filter (·.index != 0)
  let some observed := expected.getArr?.toOption
    | M.die s!"configurations: observed {expected.compress}"
  M.require (observed.size == configs.length) s!"configurations: observed {expected.compress}"
  for (config, item) in configs.zip observed.toList do
    let ok ← config.nodes.query fun nodes =>
      Json.mkObj [("index", toJson config.index), ("nodes", members header nodes)] == item
    M.require ok s!"configurations: observed {expected.compress}"

def checkRetirement (i : Nat) (s : SNode) (observed : List (String × Json)) : M Unit := do
  let get key := observed.lookup key
  unless ["retirementIndex", "membershipState", "retirementCommittableIndex"].any
      (get · |>.isSome) do
    return
  let log ← getLog i s
  let name ← nameOf i
  let index ← retirementIndex log log.size name
  if let some expected := get "retirementIndex" then
    M.require (expected == toJson index) s!"retirementIndex: observed {expected.compress}"
  let committable ←
    match index with
    | none => pure none
    | some index => firstIndexAfter log index (· == .signature)
  if let some expected := get "retirementCommittableIndex" then
    M.require (expected == toJson committable)
      s!"retirementCommittableIndex: observed {expected.compress}"
  if let some expected := get "membershipState" then
    let phase ←
      match index with
      | none => pure MembershipState.active
      | some index => do
          if (← getRci i s).isSome then pure .retiredCommitted
          else if ← M.le (SInt.lit index) (← getCi i s) then pure .retirementCompleted
          else if committable.isSome then pure .retirementSigned
          else pure .retirementOrdered
    M.require (expected == toJson (membershipName phase))
      s!"membershipState: observed {expected.compress}"

def observeState (instruction : Json) : M Unit := do
  let header := (← M.env).header
  M.ofExcept (keys instruction ["kind", "observation", "origin", "node", "peer", "fields"])
  let node ← M.ofExcept (nodeField header instruction "node")
  let i ← indexOf node
  let peer ←
    match ← M.ofExcept (optionalField instruction "peer") with
    | none => pure none
    | some _ => some <$> indexOf (← M.ofExcept (nodeField header instruction "peer"))
  let observed ← M.ofExcept (objectFields (← M.ofExcept (field instruction "fields")))
  M.require (!observed.isEmpty) "observation must contain at least one field"
  for (key, _) in observed do
    let peerKey := key == "sentIndex" || key == "matchIndex"
    M.require (key ∈ stateKeys && (!peerKey || peer.isSome))
      s!"unsupported observation field '{key}'"
  let get key := observed.lookup key
  let s := (← M.world).nodes[i]!
  if let some expected := get "role" then
    let ok ← roleQ i s fun role => toJson (roleName role) == expected
    M.require ok s!"role: observed {expected.compress}"
  if let some expected := get "currentTerm" then checkNat "currentTerm" expected (← getCt i s)
  if let some expected := get "logLength" then checkLogLength i s expected
  if let some expected := get "commitIndex" then checkNat "commitIndex" expected (← getCi i s)
  if let some expected := get "retiredCommittedIndex" then
    match ← getRci i s with
    | none => M.require (expected == Json.null) s!"retiredCommittedIndex: observed {expected.compress}"
    | some index => checkNat "retiredCommittedIndex" expected index
  if let some expected := get "preVoteEnabled" then
    let enabled := toJson (decide (header.bootstrap.preVoteStatus node = .enabled))
    M.require (expected == enabled) s!"preVoteEnabled: observed {expected.compress}"
  if let some peer := peer then
    if let some expected := get "sentIndex" then checkNat "sentIndex" expected (← getSent i s peer)
    if let some expected := get "matchIndex" then
      checkNat "matchIndex" expected (← getMatch i s peer)
  if let some expected := get "committableIndices" then checkCommittable i s expected
  if let some expected := get "configurations" then checkConfigurations i s expected
  checkRetirement i s observed

/-! ## Log entries -/

def contentFields (header : Header) (content : Content) : List (String × Json) :=
  match content with
  | .transaction transaction effects =>
      [
        ("kind", toJson "transaction"),
        ("transaction", toJson transaction),
        (
          "effects",
          Json.arr
            (effects.map
              fun effect =>
                match effect with
                | .reconfiguration configuration =>
                    Json.mkObj
                      [("kind", toJson "configuration"), ("configuration", members header configuration)]
                | .retiredCommitted nodes =>
                    Json.mkObj [("kind", toJson "retiredCommitted"), ("nodes", members header nodes)]).toArray
        ),
        ("configurations", Json.arr ((entryConfigurations content).map (members header)).toArray)
      ]
  | .signature => [("kind", toJson "signature")]

def rewriteContent (id : Nat) (f : Content → Content) : M Unit :=
  M.modify fun world =>
    {
      world with
        store :=
          {
            world.store with
              contents := world.store.contents.modify id fun candidates => (candidates.map f).eraseDups
          }
    }

/--
Transaction identifiers and effects are otherwise unconstrained, so an atom
observed with them takes the observed values.
-/
def rewriteObserved (header : Header) (content : SContent) (observed : List (String × Json))
    : M Unit := do
  let .atom id := content | return
  if let some (.str transaction) := observed.lookup "transaction" then
    rewriteContent id fun content =>
      match content with
      | .transaction _ effects => .transaction transaction effects
      | .signature => .signature
  if let some expected := observed.lookup "effects" then
    let parsed :=
      expected.getArr? >>= fun effects => effects.toList.mapM (parseEffect header)
    if let .ok effects := parsed then
      rewriteContent id fun content =>
        match content with
        | .transaction transaction _ => .transaction transaction effects
        | .signature => .signature

def observeEntry (instruction : Json) : M Unit := do
  let header := (← M.env).header
  M.ofExcept (keys instruction ["kind", "observation", "origin", "node", "index", "fields"])
  let node ← M.ofExcept (nodeField header instruction "node")
  let index ← M.ofExcept (natField instruction "index")
  M.require (index != 0) "log entry index must be positive"
  let i ← indexOf node
  let s := (← M.world).nodes[i]!
  let log ← getLog i s
  let some entry := log[index - 1]?
    | M.die s!"node '{node}' has no log entry at index {index}"
  let observed ← M.ofExcept (objectFields (← M.ofExcept (field instruction "fields")))
  M.require (!observed.isEmpty) "observation must contain at least one field"
  rewriteObserved header entry.content observed
  for (key, expected) in observed do
    match key with
    | "term" => checkNat key expected entry.term
    | "committed" =>
        match expected.getBool? with
        | .ok committed =>
            let actual ← M.le (SInt.lit index) (← getCi i s)
            M.require (actual == committed) s!"committed: observed {committed}"
        | .error _ => M.die s!"committed: observed {expected.compress}"
    | _ =>
        let ok ← M.content entry.content fun content =>
          (contentFields header content).lookup key == some expected
        M.require ok s!"{key}: observed {expected.compress}"

/-! ## Instructions -/

def runAction (instruction : Json) : M Unit := do
  let header := (← M.env).header
  let step ← M.ofExcept (parseAction header instruction)
  discard <| M.ofExcept (stringField instruction "action")
  match step with
  | .local node input =>
      let i ← indexOf node
      setNode i (← act i (← M.world).nodes[i]! input)
  | .receive source destination =>
      let message ← popHead (← channelIndex source destination)
      let source ← indexOf source
      let i ← indexOf destination
      setNode i (← receive i source (← M.world).nodes[i]! message)
  | .drop source destination occurrence =>
      if occurrence != 0 then
        M.unsupported "drop of a non-head message"
      else
        discard <| popHead (← channelIndex source destination)

def runInstr (instruction : Json) : M Unit := do
  discard <| M.ofExcept (originLabel instruction)
  match ← M.ofExcept (stringField instruction "kind") with
  | "action" => runAction instruction
  | "observation" =>
      match ← M.ofExcept (stringField instruction "observation") with
      | "state" => observeState instruction
      | "message" => observeMessage instruction
      | "entry" => observeEntry instruction
      | name => M.die s!"unsupported observation '{name}'"
  | kind => M.die s!"unsupported instruction kind '{kind}'"

end CCFRaft.MidTrace.Sym
