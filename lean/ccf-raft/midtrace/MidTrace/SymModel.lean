module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SymState

@[expose] public section

/-!
# Symbolic node steps

A transcription of `Model/Node.lean` over `SNode`. Each function mirrors the
model function of the same name; a failed `guard` kills the branch, and sends
append to the destination channel in model order.
-/

namespace CCFRaft.MidTrace.Sym

open Lean CCFRaft.Model.Node

def send (source destination : Nat) (message : SMsg) : M Unit :=
  M.modify
    fun world =>
      {
        world with
          channels :=
            world.channels.modify (world.env.channel source destination)
              fun channel => { channel with post := channel.post ++ [message] }
      }

def setAll (n : Nat) (value : SInt) : Array (Option SInt) :=
  Array.replicate n (some value)

def setAt (values : Array (Option SInt)) (peer : Nat) (value : SInt)
    : Array (Option SInt) :=
  values.set! peer (some value)

/-- The highest current-term signature above the commit index with a quorum, or zero. -/
def highestCommittable (i : Nat) (s : SNode) : M Nat := do
  let log ← getLog i s
  let commitIndex ← getCi i s
  let term ← getCt i s
  let configs ← activeConfigs log commitIndex
  let env ← M.env
  let mut index := log.size
  while index > 0 do
    if ← M.le (SInt.lit index) commitIndex then return 0
    let replicated (candidates : List Nat) : M Nodes := do
      let members ←
        M.filterM candidates
          fun peer =>
            if peer == i then
              pure true
            else do
              M.le (SInt.lit index) (← getMatch i s peer)
      return (members.map env.name).toFinset
    let ok ←
      M.andM (isSig log[index - 1]!.content)
        (M.andM (M.eq log[index - 1]!.term term)
          (M.allM configs
            fun config =>
              match config.nodes with
              | .known nodes => do
                  let candidates := env.sorted.filter fun peer => env.name peer ∈ nodes
                  configQuorum config (← replicated candidates)
              | .atom _ => do configQuorum config (← replicated env.sorted)))
    if ok then return index
    index := index - 1
  return 0

def latestMembershipIndex (configs : List Config) (node : String) : M Nat :=
  configs.foldlM
    (fun highest config => do
      if ← config.nodes.query (fun nodes => decide (node ∈ nodes)) then
        pure (Nat.max highest config.index)
      else
        pure highest)
    0

def findSuccessor (i : Nat) (s : SNode) : M (Option Nat) := do
  let configs ← activeConfigs (← getLog i s) (← getCi i s)
  let env ← M.env
  (← eligiblePeersSorted i s).foldlM
    (fun best candidate =>
      match best with
      | none => pure (some candidate)
      | some selected => do
          let selectedMatch ← getMatch i s selected
          let candidateMatch ← getMatch i s candidate
          let better ←
            M.orM (M.lt selectedMatch candidateMatch)
              (M.andM (M.eq selectedMatch candidateMatch)
                (do
                  let selectedIndex ← latestMembershipIndex configs (env.name selected)
                  let candidateIndex ← latestMembershipIndex configs (env.name candidate)
                  pure
                    (selectedIndex < candidateIndex
                      || (selectedIndex == candidateIndex
                          && decide (env.name selected < env.name candidate)))))
          pure (if better then some candidate else best))
    none

def nominateSuccessor (i : Nat) (s : SNode) : M Unit := do
  if let some successor ← findSuccessor i s then
    send i successor (.proposeVote (← getCt i s))

def commitThrough (i : Nat) (s : SNode) (commitIndex : SInt) : M SNode := do
  match ← getRci i s with
  | some _ => pure { s with commitIndex := some commitIndex }
  | none =>
      let log ← getLog i s
      let limit ← clamp commitIndex log.size
      let retired ← rcMem log limit (← nameOf i)
      pure
        {
          s with
            commitIndex := some commitIndex
            retiredCommittedIndex := some (if retired then some commitIndex else none)
        }

def advanceCommit (i : Nat) (s : SNode) : M SNode := do
  let index ← highestCommittable i s
  if ← M.le (SInt.lit index) (← getCi i s) then return s
  let committed ← commitThrough i s (SInt.lit index)
  if ← isRetiredCommitted i committed then
    if ← isRole i s .leader then nominateSuccessor i s
    return { committed with role := some .none, leaderKnown := some false }
  else
    return committed

def makeAppendEntries (i : Nat) (s : SNode) (destination endIndex : Nat) : M SMsg := do
  let log ← getLog i s
  let previous ← M.concrete (← getSent i s destination)
  return .appendEntries (← getCt i s) (SInt.lit previous) (termAt log previous)
    ((log.extract previous endIndex).toList) (← getCi i s)

def makeRequestVote (i : Nat) (s : SNode) : M (SInt × SInt × SInt) := do
  let log ← getLog i s
  let index ← lastCommittableIndex log (← getCi i s)
  return (← getCt i s, ← termAtS log index, index)

/-! ## Appending entries -/

def applyTransactionEffect (i : Nat) (txId : String)
    (applied : List (TransactionEffect String)) (s : SNode)
    (effect : TransactionEffect String)
    : M SNode := do
  let log ← getLog i s
  let term ← getCt i s
  let hookLog :=
    if applied.isEmpty then
      log
    else
      log.push { term, content := .known (.transaction txId applied) }
  let hook := { s with log := some hookLog }
  let env ← M.env
  match effect with
  | .reconfiguration nodes =>
      let previous ← lastConfigUpTo hookLog hookLog.size
      M.require (decide nodes.Nonempty) "guard: empty reconfiguration"
      M.requireM (M.notM (previous.nodes.query (· == nodes)))
        "guard: unchanged configuration"
      let added ←
        M.filterM env.sorted
          fun peer =>
            if peer == i || !decide (env.name peer ∈ nodes) then
              pure false
            else
              M.notM (eligible i hook peer)
      let configured :=
        {
          s with
            sentIndex :=
              added.foldl (fun values peer => setAt values peer (SInt.lit log.size))
                s.sentIndex
        }
      for peer in added do
        send i peer (← makeAppendEntries i configured peer log.size)
      return configured
  | .retiredCommitted nodes =>
      M.require (decide nodes.Nonempty) "guard: empty retiredCommitted"
      let commitIndex ← getCi i hook
      for node in env.sorted.map env.name do
        if node ∈ nodes then
          M.requireM
            (M.andM (retCompletedMem hookLog commitIndex node)
              (M.notM (rcMem hookLog hookLog.size node)))
            "guard: retiredCommitted node is not awaiting retirement commit"
      return s

def appendEntry (i : Nat) (s : SNode) (content : Content) : M SNode := do
  match content with
  | .transaction txId effects =>
      let (s, _) ←
        effects.foldlM
          (fun (s, applied) effect => do
            let s ← applyTransactionEffect i txId applied s effect
            return (s, applied ++ [effect]))
          (s, [])
      let log ← getLog i s
      return {
        s with
          log := some (log.push { term := ← getCt i s, content := .known content })
      }
  | .signature =>
      let log ← getLog i s
      M.require (!log.isEmpty) "guard: signature on an empty log"
      return {
        s with
          log := some (log.push { term := ← getCt i s, content := .known content })
      }

def appendBatch (i : Nat) (s : SNode) (entries : List Content) : M SNode := do
  M.requireM (isRole i s .leader) "guard: append on a non-leader"
  M.requireM (M.notM (isRetiredCommitted i s)) "guard: append on a retired-committed node"
  M.require (!entries.isEmpty) "guard: empty append"
  let appended ← entries.foldlM (appendEntry i) s
  advanceCommit i appended

def sendEntries (i : Nat) (s : SNode) (destination endIndex : Nat) : M SNode := do
  M.requireM (isRole i s .leader) "guard: sendEntries from a non-leader"
  let log ← getLog i s
  M.require (endIndex <= log.size) "guard: sendEntries beyond the log"
  let previousS ← getSent i s destination
  M.requireM (M.le previousS (SInt.lit endIndex))
    "guard: sendEntries below the send frontier"
  let previous ← M.concrete previousS
  let endTerm := termAt log endIndex
  M.requireM
    (M.allM (log.extract previous endIndex).toList fun entry => M.eq entry.term endTerm)
    "guard: sendEntries batch spans terms"
  M.requireM (eligible i s destination) "guard: sendEntries to an ineligible peer"
  M.requireM (M.orM (M.notM (isRetiredCommitted i s)) (pure (previous < endIndex)))
    "guard: empty sendEntries from a retired-committed node"
  send i destination (← makeAppendEntries i s destination endIndex)
  return { s with sentIndex := setAt s.sentIndex destination (SInt.lit endIndex) }

/-! ## Handling AppendEntries -/

def handleAppendEntriesFromLeader (i : Nat) (s : SNode) (previous : Nat)
    (entries : List SEntry) (leaderCommit : SInt)
    : M (SNode × SMsg) := do
  let log ← getLog i s
  let newLog := log ++ (entries.drop (log.size - previous)).toArray
  let commitIndex0 ← getCi i s
  let limit ←
    clamp (← M.min leaderCommit (SInt.lit (previous + entries.length))) newLog.size
  let commitIndex ← M.max commitIndex0 (SInt.lit (← maxSigUpTo newLog limit))
  let term ← getCt i s
  let response :=
    SMsg.appendEntriesResponse term true (SInt.lit (previous + entries.length))
  let withLog := { s with log := some newLog }
  if (← getRci i s).isSome then
    return ({ withLog with commitIndex := some commitIndex }, response)
  let name ← nameOf i
  let retirementCommitIndex ←
    match ← firstIndexAfter newLog 0 (hasRetiredCommitted name) with
    | none => pure commitIndex
    | some marker =>
        match ← firstIndexAfter newLog (Nat.max log.size marker) (· == .signature) with
        | none => pure commitIndex
        | some signature => M.min commitIndex (SInt.lit signature)
  let committed ← commitThrough i withLog retirementCommitIndex
  return (← commitThrough i committed commitIndex, response)

def handleAppendEntries (i source : Nat) (s : SNode) (term previousS previousTerm : SInt)
    (entries : List SEntry) (leaderCommit : SInt)
    : M SNode := do
  let currentTerm ← getCt i s
  let s ←
    if ← M.andM (M.eq term currentTerm)
          (roleQ i s fun role => role == .candidate || role == .preVoteCandidate) then
      pure { s with role := some .follower, isNewFollower := some true }
    else
      pure s
  let log ← getLog i s
  let previous ← M.concrete previousS
  let stale ← M.lt term currentTerm
  let rejected ←
    if stale then
      pure true
    else if previous == 0 then
      pure false
    else if previous > log.size then
      pure true
    else
      M.notM (M.eq (termAt log previous) previousTerm)
  if rejected then
    let noTerm ←
      if stale || previous == 0 || previous > log.size then
        pure true
      else
        M.eq (termAt log previous) (SInt.lit 0)
    if stale || noTerm then
      send i source (.appendEntriesResponse currentTerm false (SInt.lit log.size))
    else
      let lastLogIndex ← findHighestPossibleMatch log previous previousTerm
      send i source
        (.appendEntriesResponse (termAt log lastLogIndex) false (SInt.lit lastLogIndex))
    return s
  let s := { s with leaderKnown := some true }
  let conflict ←
    M.anyM ((log.extract previous log.size).toList.zip entries)
      fun (existing, incoming) =>
        M.notM (M.eq existing.term incoming.term)
  if ← M.orM (M.lt (SInt.lit previous) (← getCi i s))
        (M.andM (pure conflict) (M.notM (isNewFollower i s))) then
    return s
  let s :=
    if conflict then
      { s with log := some (log.extract 0 previous), isNewFollower := some false }
    else
      s
  let (next, response) ← handleAppendEntriesFromLeader i s previous entries leaderCommit
  send i source response
  return next

def handleAppendEntriesResponse (i source : Nat) (s : SNode) (term : SInt)
    (success : Bool) (lastLogIndex : SInt)
    : M SNode := do
  unless ← isRole i s .leader do
    return s
  if success then
    if ← M.eq term (← getCt i s) then
      let matched ← M.max (← getMatch i s source) lastLogIndex
      advanceCommit i { s with matchIndex := setAt s.matchIndex source matched }
    else
      return s
  else
    let log ← getLog i s
    let retry ← findHighestPossibleMatch log (← clamp lastLogIndex log.size) term
    let sent ← M.min (SInt.lit retry) (← getSent i s source)
    let sent ← M.max sent (← getMatch i s source)
    return { s with sentIndex := setAt s.sentIndex source sent }

/-! ## Elections -/

def voteLogUpToDate (i : Nat) (s : SNode) (lastTerm lastIndex : SInt) : M Bool := do
  let log ← getLog i s
  let signed ← maxCommittableIndex log
  let signedTerm := termAt log signed
  M.orM (M.lt signedTerm lastTerm)
    (M.andM (M.eq lastTerm signedTerm) (M.le (SInt.lit signed) lastIndex))

def handleRequestVote (i source : Nat) (s : SNode) (term lastTerm lastIndex : SInt)
    : M SNode := do
  let currentTerm ← getCt i s
  let sourceName ← nameOf source
  let granted ←
    M.andM (M.eq term currentTerm)
      (M.andM (voteLogUpToDate i s lastTerm lastIndex)
        (M.andM (M.notM (leaderKnown i s))
          (votedQ i s fun voted => voted == none || voted == some sourceName)))
  send i source (.requestVoteResponse currentTerm granted)
  return if granted then { s with votedFor := some (some sourceName) } else s

def handleRequestPreVote (i source : Nat) (s : SNode) (term lastTerm lastIndex : SInt)
    : M SNode := do
  let currentTerm ← getCt i s
  let granted ← M.andM (M.eq term currentTerm) (voteLogUpToDate i s lastTerm lastIndex)
  send i source (.requestPreVoteResponse currentTerm granted)
  return s

def leaderState (i : Nat) (s : SNode) : M SNode := do
  let log ← getLog i s
  let commitIndex ← getCi i s
  let log ←
    if ← M.lt (SInt.lit 0) commitIndex then do
      let index ← lastCommittableIndex log commitIndex
      pure (log.extract 0 (← clamp index log.size))
    else
      pure log
  let n := (← M.env).size
  return {
    s with
      role := some .leader
      log := some log
      leaderKnown := some true
      sentIndex := setAll n (SInt.lit log.size)
      matchIndex := setAll n (SInt.lit 0)
  }

def becomeLeader (i : Nat) (s : SNode) : M SNode := do
  let leader ← advanceCommit i (← leaderState i s)
  let size := (← getLog i leader).size
  for peer in ← eligiblePeersSorted i leader do
    send i peer (← makeAppendEntries i leader peer size)
  return leader

def knownConfigs (configs : List Config) : Option (List (Configuration String)) :=
  configs.mapM
    fun config =>
      match config.nodes with
      | .known nodes => some { index := config.index, nodes }
      | .atom _ => none

/-- `hasQuorum (activeConfigurations) votesGranted`. -/
def votesQuorum (i : Nat) (s : SNode) : M Bool := do
  let configs ← activeConfigs (← getLog i s) (← getCi i s)
  match s.votesGranted, knownConfigs configs with
  | some votes, _ => hasQuorum configs votes
  | none, some known =>
      votesQ i s
        fun votes =>
          known.all fun config => decide (hasConfigurationMajority votes config)
  | none, none => do hasQuorum configs (← votesQ i s id)

def electIfQuorum (i : Nat) (s : SNode) : M SNode := do
  if ← M.andM (isRole i s .candidate)
        (M.andM (votesQuorum i s) (M.notM (isRetiredCommitted i s))) then
    becomeLeader i s
  else
    return s

def becomeCandidate (i : Nat) (s : SNode) : M SNode := do
  let name ← nameOf i
  let candidate :=
    {
      s with
        role := some .candidate
        currentTerm := some ((← getCt i s).add 1)
        votedFor := some (some name)
        leaderKnown := some false
        votesGranted := some {name}
        preVotesGranted := some ∅
    }
  let (term, lastTerm, lastIndex) ← makeRequestVote i candidate
  let targets ← activeOthersSorted i candidate
  let next ← electIfQuorum i candidate
  for peer in targets do
    send i peer (.requestVote term lastTerm lastIndex)
  return next

def becomePreVoteCandidate (i : Nat) (s : SNode) : M SNode := do
  let name ← nameOf i
  let candidate :=
    {
      s with
        role := some .preVoteCandidate,
        leaderKnown := some false
        preVotesGranted := some {name}
    }
  let configs ← activeConfigs (← getLog i candidate) (← getCi i candidate)
  if ← hasQuorum configs {name} then
    becomeCandidate i candidate
  else
    let (term, lastTerm, lastIndex) ← makeRequestVote i candidate
    for peer in ← activeOthersSorted i candidate do
      send i peer (.requestPreVote term lastTerm lastIndex)
    return candidate

def startElection (i : Nat) (s : SNode) : M SNode := do
  M.requireM (canStartElection i s) "guard: cannot start an election"
  let env ← M.env
  if env.config.preVoteStatus (env.name i) == .enabled then
    becomePreVoteCandidate i s
  else
    becomeCandidate i s

def handleRequestVoteResponse (i source : Nat) (s : SNode) (term : SInt) (granted : Bool)
    : M SNode := do
  if !granted then return s
  if ← M.andM (isRole i s .candidate)
        (do
          M.eq term (← getCt i s)) then
    let sourceName ← nameOf source
    let votes ← votesQ i s (insert sourceName ·)
    electIfQuorum i { s with votesGranted := some votes }
  else
    return s

def handleRequestPreVoteResponse (i source : Nat) (s : SNode) (term : SInt)
    (granted : Bool)
    : M SNode := do
  if !granted then return s
  if ← M.andM (isRole i s .preVoteCandidate)
        (do
          M.eq term (← getCt i s)) then
    let sourceName ← nameOf source
    let votes ← preVotesQ i s (insert sourceName ·)
    let s := { s with preVotesGranted := some votes }
    let configs ← activeConfigs (← getLog i s) (← getCi i s)
    if ← hasQuorum configs votes then becomeCandidate i s else return s
  else
    return s

def checkQuorum (i : Nat) (s : SNode) : M SNode := do
  M.requireM (isRole i s .leader) "guard: checkQuorum on a non-leader"
  M.require (!(← activeOthersSorted i s).isEmpty) "guard: checkQuorum without peers"
  return { s with role := some .follower, leaderKnown := some false }

def handleProposeVote (i : Nat) (s : SNode) (term : SInt) : M SNode := do
  if ← M.andM
        (do
          M.eq term (← getCt i s))
        (canStartElection i s) then
    becomeCandidate i s
  else
    return s

def updateTerm (i : Nat) (s : SNode) (term : SInt) : M SNode := do
  if ← M.lt (← getCt i s) term then
    return {
      s with
        role := some .follower
        currentTerm := some term
        votedFor := some none
        leaderKnown := some false
        isNewFollower := some true
        preVotesGranted := some ∅
    }
  else
    return s

def SMsg.term : SMsg → SInt
  | .appendEntries term .. => term
  | .appendEntriesResponse term .. => term
  | .requestVote term .. => term
  | .requestVoteResponse term _ => term
  | .requestPreVote term .. => term
  | .requestPreVoteResponse term _ => term
  | .proposeVote term => term

def observeTerm (i : Nat) (s : SNode) (message : SMsg) : M SNode := do
  match message with
  | .proposeVote _ => return s
  | .appendEntriesResponse term .. =>
      if ← isRole i s .leader then updateTerm i s term else return s
  | _ => updateTerm i s message.term

def receive (i source : Nat) (s : SNode) (message : SMsg) : M SNode := do
  let s ← observeTerm i s message
  match message with
  | .appendEntries term previous previousTerm entries leaderCommit =>
      handleAppendEntries i source s term previous previousTerm entries leaderCommit
  | .appendEntriesResponse term success lastLogIndex =>
      handleAppendEntriesResponse i source s term success lastLogIndex
  | .requestVote term lastTerm lastIndex =>
      handleRequestVote i source s term lastTerm lastIndex
  | .requestVoteResponse term granted =>
      handleRequestVoteResponse i source s term granted
  | .requestPreVote term lastTerm lastIndex =>
      handleRequestPreVote i source s term lastTerm lastIndex
  | .requestPreVoteResponse term granted =>
      handleRequestPreVoteResponse i source s term granted
  | .proposeVote term => handleProposeVote i s term

def act (i : Nat) (s : SNode) (input : Input String String) : M SNode := do
  match input with
  | .append entries => appendBatch i s entries
  | .sendEntries destination endIndex =>
      sendEntries i s (← indexOf destination) endIndex
  | .timeout .election => startElection i s
  | .timeout .checkQuorum => checkQuorum i s
  | .nominateSuccessor =>
      M.requireM (isRole i s .leader) "guard: nominateSuccessor on a non-leader"
      nominateSuccessor i s
      return s

end CCFRaft.MidTrace.Sym
