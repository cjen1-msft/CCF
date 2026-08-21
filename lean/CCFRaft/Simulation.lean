import Mathlib.Tactic

import CCFRaft.Model

/-!
# Executable CCFRaft replays

These replays use `Model.Action`, `Model.Enabled`, and `Model.next`. They are
non-vacuity and bug-finding checks, not safety proofs.
-/

set_option autoImplicit false

namespace CCFRaft.Model

def runActions (start : Node) :
    State -> List Action -> Option State
  | state, [] => some state
  | state, action :: actions =>
      if actionEnabled state action then
        runActions start (next state action) actions
      else
        none

def runFromInitial (start : Node) (actions : List Action) : Option State :=
  runActions start (initialState start) actions

def continueRun
    (start : Node)
    (state : Option State)
    (actions : List Action) :
    Option State :=
  state.bind fun current => runActions start current actions

def appendRound
    (leader follower : Node)
    (requestKind : ReceiveKind) :
    List Action :=
  [
    .appendEntries leader follower,
    .receive follower leader requestKind,
    .receive leader follower .handleAppendEntriesResponseSuccess
  ]

def freshFollowerCatchUp
    (leader follower : Node)
    (targetLength : Nat) :
    List Action :=
  [
    .appendEntries leader follower,
    .receive follower leader .updateTerm,
    .receive follower leader .rejectAppendEntriesRequest,
    .receive leader follower .handleAppendEntriesResponseFailure
  ] ++
    (List.replicate targetLength
      (appendRound leader follower .appendEntriesNoConflict)).flatten

def existingFollowerCatchUp
    (leader follower : Node)
    (entryCount : Nat) :
    List Action :=
  (List.replicate entryCount
    (appendRound leader follower .appendEntriesNoConflict)).flatten

def heartbeat (leader follower : Node) : List Action :=
  appendRound leader follower .appendEntriesAlreadyDone

def voteRound (candidate voter : Node) : List Action :=
  [
    .requestVote candidate voter,
    .receive voter candidate .updateTerm,
    .receive voter candidate .handleRequestVoteRequest,
    .receive candidate voter .handleRequestVoteResponse
  ]

def configA (_ : Unit) : Configuration :=
  {0, 1, 2, 3, 4}

def configB (_ : Unit) : Configuration :=
  {5, 6, 7, 8, 9}

def configC (_ : Unit) : Configuration :=
  {10, 11, 12, 13, 14}

def firstConfigurationActions (_ : Unit) : List Action :=
  [
    .changeConfiguration 0 (configA ()),
    .clientRequest 0,
    .signCommittableMessages 0
  ] ++
    freshFollowerCatchUp 0 1 5 ++
    freshFollowerCatchUp 0 2 5 ++
    [.advanceCommitIndex 0]

def secondConfigurationActions (_ : Unit) : List Action :=
  [
    .changeConfiguration 0 (configB ()),
    .clientRequest 0,
    .signCommittableMessages 0
  ] ++
    existingFollowerCatchUp 0 1 3 ++
    existingFollowerCatchUp 0 2 3 ++
    freshFollowerCatchUp 0 5 8 ++
    freshFollowerCatchUp 0 6 8 ++
    freshFollowerCatchUp 0 7 8 ++
    [.advanceCommitIndex 0] ++
    heartbeat 0 5 ++
    heartbeat 0 6 ++
    heartbeat 0 7

def laterTermElectionActions (_ : Unit) : List Action :=
  [.timeout 5] ++
    voteRound 5 6 ++
    voteRound 5 7 ++
    [.becomeLeader 5]

def thirdConfigurationActions (_ : Unit) : List Action :=
  [
    .changeConfiguration 5 (configC ()),
    .clientRequest 5,
    .signCommittableMessages 5
  ] ++
    existingFollowerCatchUp 5 6 3 ++
    existingFollowerCatchUp 5 7 3 ++
    freshFollowerCatchUp 5 10 11 ++
    freshFollowerCatchUp 5 11 11 ++
    freshFollowerCatchUp 5 12 11 ++
    [.advanceCommitIndex 5] ++
    heartbeat 5 10 ++
    heartbeat 5 11 ++
    heartbeat 5 12

def forgedAck : Message :=
  {
    term := startTerm
    source := 1
    dest := 0
    body := .appendEntriesResponse true 100
  }

/--
An inductiveness-only countermodel. It is not a reachable execution:
`forgedAck` has no send history. It shows that state predicates alone cannot
preserve `MatchIndexBoundedByLogInv`; the proof needs causal response evidence.
-/
def forgedAckState : State :=
  let initial := initialState 0
  {
    initial with
    currentTerm := Function.update initial.currentTerm 1 startTerm
    messages := enqueue initial.messages forgedAck
  }

def receiveForgedAck : Action :=
  .receive 0 1 .handleAppendEntriesResponseSuccess

theorem forgedAck_enabled :
    Enabled forgedAckState receiveForgedAck := by
  decide

theorem forgedAck_before_bounded :
    MatchIndexBoundedByLogInv forgedAckState := by
  intro leader node leaderState sameTerm
  simp [forgedAckState, initialState] at leaderState
  subst leader
  fin_cases node <;>
    simp [forgedAckState, initialState] at sameTerm ⊢

theorem forgedAck_sender_term :
    forgedAck.term <=
      forgedAckState.currentTerm forgedAck.source := by
  decide

theorem forgedAck_after_not_bounded :
    Not
      (MatchIndexBoundedByLogInv
        (next forgedAckState receiveForgedAck)) := by
  intro bounded
  have leader :
      (next forgedAckState receiveForgedAck).leadershipState 0 =
        .leader := by
    decide
  have sameTerm :
      (next forgedAckState receiveForgedAck).currentTerm 0 =
        (next forgedAckState receiveForgedAck).currentTerm 1 := by
    decide
  have matchIndex :
      (next forgedAckState receiveForgedAck).matchIndex 0 1 = 100 := by
    decide
  have logLength :
      ((next forgedAckState receiveForgedAck).log 1).length = 0 := by
    decide
  have violation := bounded 0 1 leader sameTerm
  omega

end CCFRaft.Model

def requireReplayState
    (label : String)
    (replay : Unit -> Option CCFRaft.State) :
    IO CCFRaft.State := do
  match replay () with
  | some result => do
      IO.eprintln s!"{label} passed"
      pure result
  | none =>
      throw <| IO.userError s!"{label} reached a disabled action"

open CCFRaft.Model

def inspectInitialState (_ : Unit) : IO Unit := do
  let state := initialState 0
  IO.eprintln s!"initial log length: {(state.log 0).length}"

def runOneAction (_ : Unit) : IO Unit := do
  let result <- requireReplayState "one action" fun _ =>
    runFromInitial 0 [.clientRequest 0]
  if (result.log 0).length = 3 then
    pure ()
  else
    throw <| IO.userError "one action reached the wrong state"

def runFirstConfiguration (_ : Unit) : IO Unit := do
  IO.eprintln "starting first configuration"
  let first <- requireReplayState "first configuration" fun _ =>
    runFromInitial 0 (firstConfigurationActions ())
  if first.commitIndex 0 = 5 &&
      currentConfiguration (first.configurations 0) == configA () then
    IO.eprintln "first configuration state passed"
  else
    throw <| IO.userError "first configuration reached the wrong state"

def runFullReplay (_ : Unit) : IO Unit := do
  IO.eprintln "starting first configuration"
  let first <- requireReplayState "first configuration" fun _ =>
    runFromInitial 0 (firstConfigurationActions ())
  IO.eprintln "starting second configuration"
  let second <- requireReplayState "second configuration" fun _ =>
    runActions 0 first (secondConfigurationActions ())
  IO.eprintln "starting later-term election"
  let elected <- requireReplayState "later-term election" fun _ =>
    runActions 0 second (laterTermElectionActions ())
  IO.eprintln "starting third configuration"
  let third <- requireReplayState "third configuration" fun _ =>
    runActions 0 elected (thirdConfigurationActions ())
  if first.commitIndex 0 = 5 &&
      currentConfiguration (first.configurations 0) == configA () &&
      second.commitIndex 0 = 8 &&
      currentConfiguration (second.configurations 0) == configB () &&
      elected.currentTerm 5 = 3 &&
      elected.leadershipState 5 == .leader &&
      currentConfiguration (elected.configurations 5) == configB () &&
      third.commitIndex 5 = 11 &&
      third.leadershipState 5 == .leader &&
      third.membershipState 5 == .retirementCompleted &&
      currentConfiguration (third.configurations 5) == configC () then
    IO.eprintln "CCFRaft disjoint 5 -> 5 -> 5 replay passed"
  else
    throw <| IO.userError "CCFRaft replay reached the wrong final state"

def main : IO Unit := do
  IO.eprintln "CCFRaft replay executable started"
