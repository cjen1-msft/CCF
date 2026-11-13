module

meta import Consensus.Model
public import Consensus.Model

/-!
# Observations on the steps of the canonical action traces

Replays the action traces of `Consensus/Tests/CanonicalTraces.lean` (the action lists are
copied here) and prints, per step, observable features that correspond to the top-level case
splits of the safety proof's step cases: the action, the actor's role and term change, how the
actor's log changed (prefix of the old log, extension of it, or neither), commit progress, the
kinds of the messages sent, and how many nodes changed state. These are evidence about the
steps of a finite set of runs, not an evaluation of the generated classes.

Run from the repository root (the workspace is out of tree):

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/trace-observations.lean
-/

namespace ConsensusCoverage.TraceObservations

open Consensus Consensus.Model.Node
open Consensus.Model (initialNodeState BOOTSTRAP_TERM)
open CCF (Finset)
open CCF.MultiNodeTransitionSystem (nodeState)

inductive Act where
  | local (node : NodeID) (input : Input)
  | deliver (source target : NodeID)

def initialState (configuration : Finset NodeID) (nodes : List NodeID) : Model.State :=
  { nodes := nodes.map fun node => (node, initialNodeState configuration node) }

def inputKind : Input → String
  | .append _ => "append"
  | .sendEntries _ _ => "sendEntries"
  | .timeout _ => "timeout"
  | .nominateSuccessor => "nominateSuccessor"
  | .initAsBackup _ => "initAsBackup"

def messageKind : Message → String
  | .appendEntriesRequest _ => "AE"
  | .appendEntriesResponse r => if r.success then "AE-ack" else "AE-nack"
  | .requestVoteRequest _ => "RV"
  | .requestVoteResponse r => if r.voteGranted then "RV-yes" else "RV-no"
  | .requestPreVoteRequest _ => "PV"
  | .requestPreVoteResponse r => if r.voteGranted then "PV-yes" else "PV-no"
  | .proposeRequestVoteRequest _ => "propose-RV"

def roleStr : Role → String
  | .none => "none" | .follower => "follower" | .preVoteCandidate => "precandidate"
  | .candidate => "candidate" | .primary => "primary"

def logChange (pre post : List Entry) : String :=
  if post == pre then "same"
  else if pre.isPrefixOf post then "extend"
  else if post.isPrefixOf pre then "truncate"
  else "replace"

/-- One step's observation, and the state after it. -/
def observe (configuration : Finset NodeID) (nodes : List NodeID) (state : Model.State)
    (act : Act) : Except String (String × Model.State) := do
  let system := Model.transitionSystem configuration nodes
  let (action, actor, what) ← match act with
    | .local node input => pure ((.local node input : Model.Action), node, s!"local {inputKind input}")
    | .deliver source target =>
      match state.network.find? fun e => e.source == source && e.target == target with
      | some e => pure (.deliver e, target, s!"deliver {messageKind e.payload}")
      | none => throw "no pending message"
  let some after := system.step state action | throw "disabled action"
  let some pre := nodeState state actor | throw "missing node"
  let some post := nodeState after actor | throw "missing node"
  let changed := nodes.filter fun n =>
    match nodeState state n, nodeState after n with
    | some a, some b => !(a.role == b.role && a.currentTerm == b.currentTerm && a.log == b.log
        && a.commitIndex == b.commitIndex && a.votedFor == b.votedFor)
    | _, _ => true
  let delivered := match action with | .deliver _ => 1 | _ => 0
  let sentCount := after.network.length + delivered - state.network.length
  let sent := (after.network.drop (after.network.length - sentCount)).map (messageKind ·.payload)
  let sent := sent.toArray.qsort (· < ·) |>.toList
  let role := if pre.role == post.role then roleStr pre.role
    else s!"{roleStr pre.role}->{roleStr post.role}"
  let obs := s!"{what} | role {role} | term {if post.currentTerm > pre.currentTerm then "up" else "same"} \
    | log {logChange pre.log post.log} | commit {if post.commitIndex > pre.commitIndex then "up" else "same"} \
    | sent [{", ".intercalate sent}] | nodes changed {changed.length}"
  return (obs, after)

def run (name : String) (configuration : Finset NodeID) (nodes : List NodeID)
    (start : Model.State) (acts : List Act) : Except String (List String × Model.State) := do
  let mut state := start
  let mut out := []
  for (a, i) in acts.zipIdx do
    let (o, s) ← (observe configuration nodes state a).mapError (s!"{name} step {i + 1}: " ++ ·)
    out := out ++ [o]
    state := s
  return (out, state)

def clientRequestCommits : List Act := [
  .local 0 (.append [{ content := .transaction 10 {} }]),
  .local 0 (.append [{ content := .signature }]),
  .local 0 (.sendEntries 1 3), .deliver 0 1, .deliver 1 0,
  .local 0 (.sendEntries 2 3), .deliver 0 2, .deliver 2 0,
  .local 0 (.sendEntries 1 3), .deliver 0 1, .deliver 1 0]

def reconfigureElectAndCommit (expected : List Entry) : List (List Act) := [
  [ .local 0 (.append [{ content := .transaction 10 {} }]),
    .local 0 (.append [{ content := .signature }]),
    .local 0 (.append [{ content := .transaction 20 { configuration := some {0, 1, 2} } }]),
    .local 0 (.append [{ content := .signature }]) ],
  [ .local 1 (.initAsBackup []), .local 2 (.initAsBackup (expected.take 3)) ],
  [ .deliver 0 1, .deliver 1 0, .deliver 0 2, .deliver 2 0 ],
  [ .local 0 (.sendEntries 1 5), .local 0 (.sendEntries 2 5),
    .deliver 0 1, .deliver 1 0, .deliver 0 2, .deliver 2 0 ],
  [ .local 0 (.sendEntries 1 5), .deliver 0 1, .deliver 1 0,
    .local 0 (.sendEntries 2 5), .deliver 0 2, .deliver 2 0 ],
  [ .local 1 (.timeout .election), .deliver 1 0, .deliver 0 1, .deliver 1 0, .deliver 0 1,
    .deliver 1 2, .deliver 2 1, .deliver 1 2, .deliver 2 1, .deliver 1 2, .deliver 2 1,
    .deliver 1 0, .deliver 0 1 ],
  [ .local 1 (.append [{ content := .transaction 30 {} }]),
    .local 1 (.append [{ content := .signature }]),
    .local 1 (.sendEntries 0 7), .deliver 1 0, .deliver 0 1,
    .local 1 (.sendEntries 2 7), .deliver 1 2, .deliver 2 1,
    .local 1 (.sendEntries 0 7), .deliver 1 0, .deliver 0 1 ] ]

def all : Except String (List String) := do
  let (a, _) ← run "client request commits" {0, 1, 2} [0, 1, 2]
    (initialState {0, 1, 2} [0, 1, 2]) clientRequestCommits
  let expected : List Entry := [
    { term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some {0} } },
    { term := BOOTSTRAP_TERM, content := .transaction 10 {} },
    { term := BOOTSTRAP_TERM, content := .signature },
    { term := BOOTSTRAP_TERM, content := .transaction 20 { configuration := some {0, 1, 2} } },
    { term := BOOTSTRAP_TERM, content := .signature } ]
  let mut state := initialState {0} [0, 1, 2]
  let mut out := a
  for acts in reconfigureElectAndCommit expected do
    let (b, s) ← run "reconfigure, elect and commit" {0} [0, 1, 2] state acts
    out := out ++ b
    state := s
  return out

#eval show IO Unit from do
  match all with
  | .error e => throw (IO.userError e)
  | .ok obs =>
    IO.println s!"steps: {obs.length}"
    let mut counts : Std.HashMap String Nat := {}
    for o in obs do counts := counts.insert o (counts.getD o 0 + 1)
    IO.println s!"distinct observations: {counts.size}"
    for (o, n) in counts.toList.toArray.qsort (fun a b => a.1 < b.1) do
      IO.println s!"{n}\t{o}"

end ConsensusCoverage.TraceObservations
