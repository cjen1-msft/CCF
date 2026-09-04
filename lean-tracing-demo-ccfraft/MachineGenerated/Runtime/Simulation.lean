-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

/-!
# Bounded arbitrary-term Raft simulator

The adapter does not define protocol semantics. It materializes choices as
ordinary model actions, then calls `ExecutableTransitionSystem.applyAction`.
-/

namespace CCFRaft.Simulation

/-- Number of transaction IDs available to the bounded simulator. -/
def TX_COUNT : Nat := 64
/--
Default width proposed by the random reconfiguration scheduler. This is a
search heuristic, not a model-validity or bootstrap-cardinality constraint.
-/
def SCHEDULER_CONFIGURATION_TARGET_WIDTH : Nat := 5
/-- Finite transaction-ID type used only by simulation and replay. -/
abbrev TxId := Fin TX_COUNT
/-- Concrete finite state explored by the simulator. -/
abbrev SimState := State Node TxId
/-- Concrete finite action type explored by the simulator. -/
abbrev SimAction := Action Node TxId

variable [Bootstrap Node]

/-- Action families used for coverage telemetry. -/
inductive ActionFamily where
  | clientRequest
  | changeConfiguration
  | appendRetiredCommitted
  | signCommittableMessages
  | appendEntries
  | receive
  | advanceCommitIndex
  | timeout
  | becomePreVoteCandidate
  | becomeCandidate
  | requestVote
  | requestPreVote
  | checkQuorum
  | updateTerm
  | becomeLeader
  | proposeVote
  | advanceCommitIndexAndProposeVote
  deriving DecidableEq, Repr

/-- Raw simulator choices that materialize directly as semantic actions. -/
inductive Choice where
  | clientRequest (node : Node) (txId : TxId)
  | changeConfiguration (source : Node) (newConfiguration : Finset Node)
  | appendRetiredCommitted (node : Node)
  | signCommittableMessages (node : Node)
  | appendEntries (source destination : Node) (batchEnd : Nat)
  | receive (source destination : Node)
  | advanceCommitIndex (node : Node)
  | timeout (node : Node)
  | becomePreVoteCandidate (node : Node)
  | becomeCandidate (node : Node)
  | requestVote (source destination : Node)
  | requestPreVote (source destination : Node)
  | checkQuorum (node : Node)
  | updateTerm (source destination : Node)
  | becomeLeader (node : Node)
  | proposeVote (source destination : Node)
  | advanceCommitIndexAndProposeVote (source destination : Node)
  deriving DecidableEq

/-- Classify a simulator choice for coverage reporting. -/
def Choice.family : Choice -> ActionFamily
  | .clientRequest .. => .clientRequest
  | .changeConfiguration .. => .changeConfiguration
  | .appendRetiredCommitted .. => .appendRetiredCommitted
  | .signCommittableMessages .. => .signCommittableMessages
  | .appendEntries .. => .appendEntries
  | .receive .. => .receive
  | .advanceCommitIndex .. => .advanceCommitIndex
  | .timeout .. => .timeout
  | .becomePreVoteCandidate .. => .becomePreVoteCandidate
  | .becomeCandidate .. => .becomeCandidate
  | .requestVote .. => .requestVote
  | .requestPreVote .. => .requestPreVote
  | .checkQuorum .. => .checkQuorum
  | .updateTerm .. => .updateTerm
  | .becomeLeader .. => .becomeLeader
  | .proposeVote .. => .proposeVote
  | .advanceCommitIndexAndProposeVote .. =>
      .advanceCommitIndexAndProposeVote

/-- Convert a simulator choice into the exact model action it denotes. -/
def materialize (_state : SimState) : Choice -> Option SimAction
  | .clientRequest node txId => some (.clientRequest node txId)
  | .changeConfiguration source newConfiguration =>
      some (.changeConfiguration source newConfiguration)
  | .appendRetiredCommitted node =>
      some (.appendRetiredCommitted node)
  | .signCommittableMessages node =>
      some (.signCommittableMessages node)
  | .appendEntries source destination batchEnd =>
      some (.appendEntries source destination batchEnd)
  | .receive source destination => some (.receive source destination)
  | .advanceCommitIndex node => some (.advanceCommitIndex node)
  | .timeout node => some (.timeout node)
  | .becomePreVoteCandidate node =>
      some (.becomePreVoteCandidate node)
  | .becomeCandidate node => some (.becomeCandidate node)
  | .requestVote source destination =>
      some (.requestVote source destination)
  | .requestPreVote source destination =>
      some (.requestPreVote source destination)
  | .checkQuorum node => some (.checkQuorum node)
  | .updateTerm source destination =>
      some (.updateTerm source destination)
  | .becomeLeader node => some (.becomeLeader node)
  | .proposeVote source destination =>
      some (.proposeVote source destination)
  | .advanceCommitIndexAndProposeVote source destination =>
      some (.advanceCommitIndexAndProposeVote source destination)

/-- Every enabled finite model action has a corresponding simulator choice. -/
theorem materializeComplete
    (state : SimState)
    (action : SimAction)
    (_enabled : Enabled state action) :
    Exists fun choice =>
      materialize state choice = some action := by
  cases action with
  | clientRequest node txId =>
      exact ⟨.clientRequest node txId, rfl⟩
  | changeConfiguration source newConfiguration =>
      exact ⟨.changeConfiguration source newConfiguration, rfl⟩
  | appendRetiredCommitted node =>
      exact ⟨.appendRetiredCommitted node, rfl⟩
  | signCommittableMessages node =>
      exact ⟨.signCommittableMessages node, rfl⟩
  | appendEntries source destination batchEnd =>
      exact ⟨.appendEntries source destination batchEnd, rfl⟩
  | receive source destination =>
      exact ⟨.receive source destination, rfl⟩
  | advanceCommitIndex node =>
      exact ⟨.advanceCommitIndex node, rfl⟩
  | timeout node =>
      exact ⟨.timeout node, rfl⟩
  | becomePreVoteCandidate node =>
      exact ⟨.becomePreVoteCandidate node, rfl⟩
  | becomeCandidate node =>
      exact ⟨.becomeCandidate node, rfl⟩
  | requestVote source destination =>
      exact ⟨.requestVote source destination, rfl⟩
  | requestPreVote source destination =>
      exact ⟨.requestPreVote source destination, rfl⟩
  | checkQuorum node =>
      exact ⟨.checkQuorum node, rfl⟩
  | updateTerm source destination =>
      exact ⟨.updateTerm source destination, rfl⟩
  | becomeLeader node =>
      exact ⟨.becomeLeader node, rfl⟩
  | proposeVote source destination =>
      exact ⟨.proposeVote source destination, rfl⟩
  | advanceCommitIndexAndProposeVote source destination =>
      exact
        ⟨.advanceCommitIndexAndProposeVote source destination, rfl⟩

/-- Package materialization and its completeness proof for the generic engine. -/
def adapter :
    ExecutableTransitionSystem.SimulationAdapter
      (system (Node := Node) (TxId := TxId)) where
  Choice
  materialize
  complete := materializeComplete

/-- Executable enumeration of all fixed-world nodes in identifier order. -/
def allNodes : List Node :=
  List.ofFn fun node => node

/-- Executable enumeration of all bounded transaction IDs. -/
def allTxIds : List TxId :=
  List.ofFn fun txId => txId

set_option maxHeartbeats 800000

/-- Materialize finite function fields to keep long executable traces linear. -/
def compactState (state : SimState) : SimState :=
  let network := Array.ofFn state.network
  let preVoteStatus := Array.ofFn state.preVoteStatus
  let retirementCompleted := Array.ofFn state.retirementCompleted
  { state with
    network := fun node => network[node.val]'node.isLt
    preVoteStatus := fun node => preVoteStatus[node.val]'node.isLt
    retirementCompleted :=
      fun node => retirementCompleted[node.val]'node.isLt }

/-- Materializing the finite maps does not change the represented state. -/
theorem compactState_eq (state : SimState) :
    compactState state = state := by
  cases state with
  | mk nodes network submittedTxIds hasJoined preVoteStatus
      retirementCompleted =>
      simp only [compactState]
      congr 1
      · funext node
        simp
      · funext node
        simp
      · funext node
        simp

set_option maxHeartbeats 200000

/-- Every node occurs in the simulator's node enumeration. -/
@[simp]
theorem memAllNodes (node : Node) :
    node ∈ allNodes :=
  List.mem_ofFn.mpr ⟨node, rfl⟩

/-- Every bounded transaction ID occurs in its enumeration. -/
@[simp]
theorem memAllTxIds (txId : TxId) :
    txId ∈ allTxIds :=
  List.mem_ofFn.mpr ⟨txId, rfl⟩

/-- Check pairwise committed-prefix consistency. -/
def committedPrefixesCheck (state : SimState) : Bool :=
  allNodes.all fun left =>
    allNodes.all fun right =>
      decide (
        (state.nodes left).committedLog <+:
            (state.nodes right).committedLog \/
          (state.nodes right).committedLog <+:
            (state.nodes left).committedLog)

/-- Check that equal index/term observations identify equal prefixes. -/
def logMatchingCheck (state : SimState) : Bool :=
  allNodes.all fun left =>
    allNodes.all fun right =>
      (List.range
        (min
          (state.nodes left).log.length
          (state.nodes right).log.length + 1)).all fun index =>
        match
          entryAt? (state.nodes left).log index,
          entryAt? (state.nodes right).log index
        with
        | some leftEntry, some rightEntry =>
            if leftEntry.term = rightEntry.term then
              decide (
                (state.nodes left).log.take index =
                  (state.nodes right).log.take index)
            else
              true
        | _, _ => true

/-- Check monotonically increasing terms and local current-term bounds. -/
def logTermChecks (state : SimState) : Bool :=
  allNodes.all fun node =>
    let log := (state.nodes node).log
    (log.all fun entry =>
      decide (entry.term <= (state.nodes node).currentTerm)) &&
    (List.range log.length).all fun index =>
      match log[index]?, log[index + 1]? with
      | some earlier, some later => decide (earlier.term <= later.term)
      | _, _ => true

/-- Check at most one leader in each represented term. -/
def electionSafetyCheck (state : SimState) : Bool :=
  allNodes.all fun left =>
    allNodes.all fun right =>
      if (state.nodes left).role = .leader /\
          (state.nodes right).role = .leader /\
          (state.nodes left).currentTerm =
            (state.nodes right).currentTerm then
        decide (left = right)
      else
        true

/-- Check that every positive commit frontier points to a signature entry. -/
def committedFrontierSignatureCheck (state : SimState) : Bool :=
  allNodes.all fun node =>
    let nodeState := state.nodes node
    if nodeState.commitIndex = 0 then
      true
    else
      match entryAt? nodeState.log nodeState.commitIndex with
      | some entry => decide (entry.content = .signature)
      | none => false

/-- Check nonempty current configurations and their local log frontiers. -/
def configurationStateCheck (state : SimState) : Bool :=
  allNodes.all fun node =>
    let nodeState := state.nodes node
    let current := currentConfiguration nodeState
    decide current.nodes.Nonempty &&
      decide (current.index <= nodeState.commitIndex) &&
      (activeConfigurations nodeState).all fun configuration =>
        decide configuration.nodes.Nonempty &&
          decide (configuration.index <= nodeState.log.length)

/-- Check log-derived retirement metadata and completed-retirement tracking. -/
def retirementStateCheck (state : SimState) : Bool :=
  allNodes.all fun node =>
    let nodeState := state.nodes node
    let refreshed := refreshRetirementState node nodeState
    decide (nodeState.membershipState = refreshed.membershipState) &&
      decide (nodeState.retirementIndex = refreshed.retirementIndex) &&
      decide (
        nodeState.retirementCommittableIndex =
          refreshed.retirementCommittableIndex) &&
      decide (
        nodeState.retiredCommittedIndex = refreshed.retiredCommittedIndex) &&
      decide (
        nodeState.membershipState != .retiredCommitted ||
          nodeState.role = .follower) &&
      decide (
        state.retirementCompleted node =
          retirementCompletedNodes nodeState.log nodeState.commitIndex)

/-- Check selected executable state-local Raft safety conditions. -/
def stateChecks (state : SimState) : Bool :=
  (allNodes.all fun node =>
    decide (
      (state.nodes node).commitIndex <=
        (state.nodes node).log.length)) &&
  committedFrontierSignatureCheck state &&
  committedPrefixesCheck state &&
  logMatchingCheck state &&
  logTermChecks state &&
  electionSafetyCheck state &&
  configurationStateCheck state &&
  retirementStateCheck state

/-- Executably check committed-log monotonicity on one explored edge. -/
def edgeChecks (before after : SimState) : Bool :=
  allNodes.all fun node =>
    decide (
      (before.nodes node).committedLog <+:
        (after.nodes node).committedLog)

/-- State of the deterministic pseudo-random number generator. -/
structure Generator where
  state : UInt64

/-- Produce the next pseudo-random word and generator state. -/
def Generator.next (generator : Generator) : UInt64 × Generator :=
  let value :=
    generator.state * 6364136223846793005 + 1442695040888963407
  (value, { state := value })

/-- Choose an index below a bound, returning zero for an empty range. -/
def Generator.choose
    (generator : Generator)
    (bound : Nat) :
    Nat × Generator :=
  let (value, nextGenerator) := generator.next
  if bound = 0 then
    (0, nextGenerator)
  else
    (value.toNat % bound, nextGenerator)

/-- Enumerate every nonempty subset of the fixed 15-node world. -/
def configurationChoices : List (Finset Node) :=
  (allNodes.sublists.map fun nodes => nodes.toFinset).filter fun configuration =>
    decide configuration.Nonempty

/-- Enumerate action shapes using the supplied configuration candidates. -/
def candidateChoicesFor
    (state : SimState)
    (configurations : List (Finset Node)) : List Choice :=
  (allNodes.flatMap fun node =>
    allTxIds.map fun txId => .clientRequest node txId) ++
  ((allNodes.filter fun source =>
      (state.nodes source).role = .leader).flatMap fun source =>
    configurations.map fun configuration =>
      .changeConfiguration source configuration) ++
  (allNodes.map fun node => .appendRetiredCommitted node) ++
  (allNodes.map fun node => .signCommittableMessages node) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination =>
      .appendEntries
        source
        destination
        (min
          ((state.nodes source).sentIndex destination + 1)
          (state.nodes source).log.length)) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .receive source destination) ++
  (allNodes.map fun node => .advanceCommitIndex node) ++
  (allNodes.map fun node => .timeout node) ++
  (allNodes.map fun node => .becomePreVoteCandidate node) ++
  (allNodes.map fun node => .becomeCandidate node) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .requestVote source destination) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .requestPreVote source destination) ++
  (allNodes.map fun node => .checkQuorum node) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .updateTerm source destination) ++
  (allNodes.map fun node => .becomeLeader node) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination => .proposeVote source destination) ++
  (allNodes.flatMap fun source =>
    allNodes.map fun destination =>
      .advanceCommitIndexAndProposeVote source destination)

/-- Enumerate every bounded action shape that could be enabled in a state. -/
def candidateChoices (state : SimState) : List Choice :=
  candidateChoicesFor state configurationChoices

/-- Every enabled finite action appears in the simulator candidate list. -/
theorem candidateChoicesComplete
    (state : SimState)
    (action : SimAction)
    (enabled : Enabled state action) :
    Exists fun choice =>
      choice ∈ candidateChoices state /\
        materialize state choice = some action := by
  cases action with
  | clientRequest node txId =>
      refine ⟨.clientRequest node txId, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | changeConfiguration source newConfiguration =>
      have represented : newConfiguration ∈ configurationChoices := by
        let members := allNodes.filter fun node => node ∈ newConfiguration
        have membersSublist : List.Sublist members allNodes :=
          List.filter_sublist
        have membersEq : members.toFinset = newConfiguration := by
          ext node
          simp [members]
        unfold configurationChoices
        rw [List.mem_filter]
        constructor
        · exact
            List.mem_map.mpr
              ⟨members, List.mem_sublists.mpr membersSublist, membersEq⟩
        · simpa using enabled.2.2.2.1
      refine
        ⟨.changeConfiguration source newConfiguration, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor, represented, enabled.2.1]
  | appendRetiredCommitted node =>
      refine ⟨.appendRetiredCommitted node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | signCommittableMessages node =>
      refine ⟨.signCommittableMessages node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | appendEntries source destination batchEnd =>
      refine ⟨.appendEntries source destination batchEnd, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor, enabled.2.2.2]
  | receive source destination =>
      refine ⟨.receive source destination, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | advanceCommitIndex node =>
      refine ⟨.advanceCommitIndex node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | timeout node =>
      refine ⟨.timeout node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | becomePreVoteCandidate node =>
      refine ⟨.becomePreVoteCandidate node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | becomeCandidate node =>
      refine ⟨.becomeCandidate node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | requestVote source destination =>
      refine ⟨.requestVote source destination, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | requestPreVote source destination =>
      refine ⟨.requestPreVote source destination, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | checkQuorum node =>
      refine ⟨.checkQuorum node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | updateTerm source destination =>
      refine ⟨.updateTerm source destination, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | becomeLeader node =>
      refine ⟨.becomeLeader node, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | proposeVote source destination =>
      refine ⟨.proposeVote source destination, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]
  | advanceCommitIndexAndProposeVote source destination =>
      refine
        ⟨.advanceCommitIndexAndProposeVote source destination, ?_, rfl⟩
      simp [candidateChoices, candidateChoicesFor]

/-- Retain exactly the candidate choices enabled by the authoritative guard. -/
def enabledChoices (state : SimState) : List Choice :=
  candidateChoices state |>.filter fun choice =>
    match materialize state choice with
    | none => false
    | some action => decide (Enabled state action)

/-- The next disjoint five-node configuration not used by this execution. -/
def nextFreshConfiguration (state : SimState) : Finset Node :=
  ((allNodes.filter fun node => node ∉ state.hasJoined).take
    SCHEDULER_CONFIGURATION_TARGET_WIDTH).toFinset

/--
Keep random exploration responsive by proposing one fresh configuration.
`candidateChoicesComplete` remains the proof for the exhaustive action list.
-/
def schedulerChoices (state : SimState) : List Choice :=
  let configuration := nextFreshConfiguration state
  let configurations := if configuration.Nonempty then [configuration] else []
  candidateChoicesFor state configurations |>.filter fun choice =>
    match materialize state choice with
    | none => false
    | some action => decide (Enabled state action)

/-- Retain enabled choices belonging to one action family. -/
def familyChoices
    (family : ActionFamily)
    (choices : List Choice) : List Choice :=
  choices.filter fun choice => decide (choice.family = family)

/-- Prefer actions that advance elections, delivery, or replication. -/
def preferredChoices (state : SimState) : List Choice :=
  let enabled := schedulerChoices state
  let promotions := familyChoices .becomeLeader enabled
  let preVotePromotions := familyChoices .becomeCandidate enabled
  let preVoteTimeouts := familyChoices .becomePreVoteCandidate enabled
  let updates := familyChoices .updateTerm enabled
  let proposals :=
    (familyChoices .proposeVote enabled).filter fun choice =>
      match choice with
      | .proposeVote _ destination =>
          (state.nodes destination).role = .follower
      | _ => false
  let receives := familyChoices .receive enabled
  let votes := familyChoices .requestVote enabled
  let preVotes := familyChoices .requestPreVote enabled
  let candidateTimeouts :=
    (familyChoices .timeout enabled).filter fun choice =>
      match choice with
      | .timeout node => (state.nodes node).role = .candidate
      | _ => false
  let commits :=
    familyChoices .advanceCommitIndex enabled ++
      familyChoices .advanceCommitIndexAndProposeVote enabled
  let appends := familyChoices .appendEntries enabled
  let progressingAppends :=
    appends.filter fun choice =>
      match choice with
      | .appendEntries source destination batchEnd =>
          decide (
            (state.nodes source).sentIndex destination < batchEnd)
      | _ => false
  let clients := familyChoices .clientRequest enabled
  let reconfigurations :=
    familyChoices .changeConfiguration enabled
  let retirements :=
    familyChoices .appendRetiredCommitted enabled
  let signatures :=
    (familyChoices .signCommittableMessages enabled).filter fun choice =>
      match choice with
      | .signCommittableMessages node =>
          decide (
            maxCommittableIndex (state.nodes node).log <
              (state.nodes node).log.length)
      | _ => false
  let electionActive :=
    allNodes.any fun node =>
      (state.nodes node).role = .candidate \/
        (state.nodes node).role = .preVoteCandidate
  let aLeaderNeedsCurrentEntry :=
    allNodes.any fun node =>
      (state.nodes node).role = .leader /\
        !(state.nodes node).log.any fun entry =>
          entry.term = (state.nodes node).currentTerm
  if !promotions.isEmpty then promotions
  else if !preVotePromotions.isEmpty then preVotePromotions
  else if !updates.isEmpty then updates
  else if !receives.isEmpty then receives
  else if electionActive &&
      !(preVotes ++ votes ++ preVoteTimeouts ++ candidateTimeouts).isEmpty then
    preVotes ++ votes ++ preVoteTimeouts ++ candidateTimeouts
  else if !proposals.isEmpty then proposals
  else if aLeaderNeedsCurrentEntry && !clients.isEmpty then clients
  else if !reconfigurations.isEmpty then reconfigurations
  else if !retirements.isEmpty then retirements
  else if !signatures.isEmpty then signatures
  else if !commits.isEmpty then commits
  else if !progressingAppends.isEmpty then progressingAppends
  else enabled

/-- Randomly select one preferred enabled choice from the complete list. -/
def propose
    (state : SimState)
    (generator : Generator) :
    Option Choice × Generator :=
  let candidates := preferredChoices state
  let (index, generator) := generator.choose candidates.length
  (candidates[index]?, generator)

/-- Counts proposals, accepted actions, rejections, traces, and explored depth. -/
structure Telemetry where
  proposedClient : Nat := 0
  proposedReconfigure : Nat := 0
  proposedRetiredCommitted : Nat := 0
  proposedSign : Nat := 0
  proposedAppend : Nat := 0
  proposedReceive : Nat := 0
  proposedCommit : Nat := 0
  proposedTimeout : Nat := 0
  proposedPreVoteCandidate : Nat := 0
  proposedBecomeCandidate : Nat := 0
  proposedVote : Nat := 0
  proposedPreVote : Nat := 0
  proposedCheckQuorum : Nat := 0
  proposedUpdateTerm : Nat := 0
  proposedBecomeLeader : Nat := 0
  proposedProposeVote : Nat := 0
  proposedCommitAndProposeVote : Nat := 0
  takenClient : Nat := 0
  takenReconfigure : Nat := 0
  takenRetiredCommitted : Nat := 0
  takenSign : Nat := 0
  takenAppend : Nat := 0
  takenReceive : Nat := 0
  takenCommit : Nat := 0
  takenTimeout : Nat := 0
  takenPreVoteCandidate : Nat := 0
  takenBecomeCandidate : Nat := 0
  takenVote : Nat := 0
  takenPreVote : Nat := 0
  takenCheckQuorum : Nat := 0
  takenUpdateTerm : Nat := 0
  takenBecomeLeader : Nat := 0
  takenProposeVote : Nat := 0
  takenCommitAndProposeVote : Nat := 0
  rejected : Nat := 0
  traces : Nat := 0
  steps : Nat := 0
  maxDepth : Nat := 0
  deriving Repr

/-- Increment the proposal counter for one action family. -/
def Telemetry.proposed
    (telemetry : Telemetry)
    (family : ActionFamily) : Telemetry :=
  match family with
  | .clientRequest =>
      { telemetry with proposedClient := telemetry.proposedClient + 1 }
  | .changeConfiguration =>
      { telemetry with
          proposedReconfigure := telemetry.proposedReconfigure + 1 }
  | .appendRetiredCommitted =>
      { telemetry with
          proposedRetiredCommitted :=
            telemetry.proposedRetiredCommitted + 1 }
  | .signCommittableMessages =>
      { telemetry with proposedSign := telemetry.proposedSign + 1 }
  | .appendEntries =>
      { telemetry with proposedAppend := telemetry.proposedAppend + 1 }
  | .receive =>
      { telemetry with proposedReceive := telemetry.proposedReceive + 1 }
  | .advanceCommitIndex =>
      { telemetry with proposedCommit := telemetry.proposedCommit + 1 }
  | .timeout =>
      { telemetry with proposedTimeout := telemetry.proposedTimeout + 1 }
  | .becomePreVoteCandidate =>
      { telemetry with
          proposedPreVoteCandidate :=
            telemetry.proposedPreVoteCandidate + 1 }
  | .becomeCandidate =>
      { telemetry with
          proposedBecomeCandidate := telemetry.proposedBecomeCandidate + 1 }
  | .requestVote =>
      { telemetry with proposedVote := telemetry.proposedVote + 1 }
  | .requestPreVote =>
      { telemetry with proposedPreVote := telemetry.proposedPreVote + 1 }
  | .checkQuorum =>
      { telemetry with
          proposedCheckQuorum := telemetry.proposedCheckQuorum + 1 }
  | .updateTerm =>
      { telemetry with proposedUpdateTerm := telemetry.proposedUpdateTerm + 1 }
  | .becomeLeader =>
      { telemetry with
          proposedBecomeLeader := telemetry.proposedBecomeLeader + 1 }
  | .proposeVote =>
      { telemetry with
          proposedProposeVote := telemetry.proposedProposeVote + 1 }
  | .advanceCommitIndexAndProposeVote =>
      { telemetry with
          proposedCommitAndProposeVote :=
            telemetry.proposedCommitAndProposeVote + 1 }

/-- Increment the accepted-action counter for one action family. -/
def Telemetry.taken
    (telemetry : Telemetry)
    (family : ActionFamily) : Telemetry :=
  match family with
  | .clientRequest =>
      { telemetry with takenClient := telemetry.takenClient + 1 }
  | .changeConfiguration =>
      { telemetry with
          takenReconfigure := telemetry.takenReconfigure + 1 }
  | .appendRetiredCommitted =>
      { telemetry with
          takenRetiredCommitted := telemetry.takenRetiredCommitted + 1 }
  | .signCommittableMessages =>
      { telemetry with takenSign := telemetry.takenSign + 1 }
  | .appendEntries =>
      { telemetry with takenAppend := telemetry.takenAppend + 1 }
  | .receive =>
      { telemetry with takenReceive := telemetry.takenReceive + 1 }
  | .advanceCommitIndex =>
      { telemetry with takenCommit := telemetry.takenCommit + 1 }
  | .timeout =>
      { telemetry with takenTimeout := telemetry.takenTimeout + 1 }
  | .becomePreVoteCandidate =>
      { telemetry with
          takenPreVoteCandidate := telemetry.takenPreVoteCandidate + 1 }
  | .becomeCandidate =>
      { telemetry with
          takenBecomeCandidate := telemetry.takenBecomeCandidate + 1 }
  | .requestVote =>
      { telemetry with takenVote := telemetry.takenVote + 1 }
  | .requestPreVote =>
      { telemetry with takenPreVote := telemetry.takenPreVote + 1 }
  | .checkQuorum =>
      { telemetry with takenCheckQuorum := telemetry.takenCheckQuorum + 1 }
  | .updateTerm =>
      { telemetry with takenUpdateTerm := telemetry.takenUpdateTerm + 1 }
  | .becomeLeader =>
      { telemetry with
          takenBecomeLeader := telemetry.takenBecomeLeader + 1 }
  | .proposeVote =>
      { telemetry with
          takenProposeVote := telemetry.takenProposeVote + 1 }
  | .advanceCommitIndexAndProposeVote =>
      { telemetry with
          takenCommitAndProposeVote :=
            telemetry.takenCommitAndProposeVote + 1 }

/-- Serialize one semantic action as a stable replay line. -/
def renderAction : SimAction -> String
  | .clientRequest node txId =>
      s!"client,{node.val},{txId.val}"
  | .changeConfiguration source newConfiguration =>
      String.intercalate ","
        ("reconfigure" :: toString source.val ::
          (allNodes.filter fun node => node ∈ newConfiguration).map fun node =>
            toString node.val)
  | .appendRetiredCommitted node =>
      s!"retire-committed,{node.val}"
  | .signCommittableMessages node =>
      s!"sign,{node.val}"
  | .appendEntries source destination batchEnd =>
      s!"append,{source.val},{destination.val},{batchEnd}"
  | .receive source destination =>
      s!"receive,{source.val},{destination.val}"
  | .advanceCommitIndex node =>
      s!"commit,{node.val}"
  | .timeout node =>
      s!"timeout,{node.val}"
  | .becomePreVoteCandidate node =>
      s!"pre-timeout,{node.val}"
  | .becomeCandidate node =>
      s!"candidate,{node.val}"
  | .requestVote source destination =>
      s!"vote,{source.val},{destination.val}"
  | .requestPreVote source destination =>
      s!"pre-vote,{source.val},{destination.val}"
  | .checkQuorum node =>
      s!"quorum,{node.val}"
  | .updateTerm source destination =>
      s!"term,{source.val},{destination.val}"
  | .becomeLeader node =>
      s!"leader,{node.val}"
  | .proposeVote source destination =>
      s!"propose-vote,{source.val},{destination.val}"
  | .advanceCommitIndexAndProposeVote source destination =>
      s!"commit-propose,{source.val},{destination.val}"

/-- Serialize the model parameter required to replay the following actions. -/
def renderBootstrap (bootstrap : Bootstrap Node) : String :=
  String.intercalate ","
    ("bootstrap" :: toString bootstrap.leader.val ::
      (allNodes.filter fun node =>
        Membership.mem bootstrap.configuration node).map fun node =>
          toString node.val)

/-- Serialize every node's static pre-vote mode in identifier order. -/
def renderPreVoteStatus (bootstrap : Bootstrap Node) : String :=
  String.intercalate ","
    ("pre-vote-status" ::
      allNodes.map fun node =>
        match bootstrap.preVoteStatus node with
        | .capable => "capable"
        | .enabled => "enabled")

/-- Parse a natural number only when it lies below a given bound. -/
def parseBounded
    (bound : Nat)
    (raw : String) :
    Option Nat := do
  let value <- raw.toNat?
  if value < bound then some value else none

/-- Parse a node identifier from replay text. -/
def nodeOfString (raw : String) : Option Node := do
  let value <- raw.toNat?
  if within : value < NODE_COUNT then
    some ⟨value, within⟩
  else
    none

/-- Parse a bounded transaction ID from replay text. -/
def txIdOfString (raw : String) : Option TxId := do
  let value <- raw.toNat?
  if within : value < TX_COUNT then
    some ⟨value, within⟩
  else
    none

/-- Parse one replay line into a semantic action. -/
def parseAction (line : String) : Option SimAction := do
  match line.splitOn "," with
  | ["client", node, txId] =>
      let node <- nodeOfString node
      let txId <- txIdOfString txId
      some (.clientRequest node txId)
  | "reconfigure" :: source :: rawNodes =>
      let source <- nodeOfString source
      let nodes <- rawNodes.mapM nodeOfString
      if nodes.isEmpty then
        none
      else
        some (.changeConfiguration source nodes.toFinset)
  | ["retire-committed", node] =>
      let node <- nodeOfString node
      some (.appendRetiredCommitted node)
  | ["sign", node] =>
      let node <- nodeOfString node
      some (.signCommittableMessages node)
  | ["append", source, destination, batchEnd] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      let batchEnd <- batchEnd.toNat?
      some (.appendEntries source destination batchEnd)
  | ["receive", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.receive source destination)
  | ["commit", node] =>
      let node <- nodeOfString node
      some (.advanceCommitIndex node)
  | ["timeout", node] =>
      let node <- nodeOfString node
      some (.timeout node)
  | ["pre-timeout", node] =>
      let node <- nodeOfString node
      some (.becomePreVoteCandidate node)
  | ["candidate", node] =>
      let node <- nodeOfString node
      some (.becomeCandidate node)
  | ["vote", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.requestVote source destination)
  | ["pre-vote", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.requestPreVote source destination)
  | ["quorum", node] =>
      let node <- nodeOfString node
      some (.checkQuorum node)
  | ["term", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.updateTerm source destination)
  | ["leader", node] =>
      let node <- nodeOfString node
      some (.becomeLeader node)
  | ["propose-vote", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.proposeVote source destination)
  | ["commit-propose", source, destination] =>
      let source <- nodeOfString source
      let destination <- nodeOfString destination
      some (.advanceCommitIndexAndProposeVote source destination)
  | _ => none

/-- Parse a replay header into a valid bootstrap parameter. -/
def parseBootstrap (line : String) : Option (Bootstrap Node) := do
  match line.splitOn "," with
  | "bootstrap" :: rawLeader :: rawMembers =>
      let leader <- nodeOfString rawLeader
      let members <- rawMembers.mapM nodeOfString
      let configuration := members.toFinset
      if leaderMember : Membership.mem configuration leader then
        some {
          configuration
          leader
          leader_mem := leaderMember
        }
      else
        none
  | _ => none

/-- Parse the optional pre-vote-mode replay header. -/
def parsePreVoteStatus
    (bootstrap : Bootstrap Node)
    (line : String) :
    Option (Bootstrap Node) := do
  match line.splitOn "," with
  | "pre-vote-status" :: rawStatuses =>
      if rawStatuses.length != NODE_COUNT then
        none
      else
        let statuses <- rawStatuses.mapM fun raw =>
          match raw with
          | "capable" => some PreVoteStatus.capable
          | "enabled" => some PreVoteStatus.enabled
          | _ => none
        some {
          configuration := bootstrap.configuration
          leader := bootstrap.leader
          leader_mem := bootstrap.leader_mem
          preVoteStatus := fun node =>
            statuses[node.val]?.getD .capable
        }
  | _ => none

/-- A replay file carries its bootstrap parameter and ordered actions. -/
structure ReplayTrace where
  bootstrap : Bootstrap Node
  actions : List SimAction

/--
Parse an optional bootstrap header followed by actions. Headerless traces use
the canonical default bootstrap for backward compatibility.
-/
def parseReplayLines (lines : List String) : Except String ReplayTrace := do
  let (bootstrap, actionLines) <-
    match lines with
    | [] => pure (defaultBootstrap, [])
    | first :: remaining =>
        match first.splitOn "," with
        | "bootstrap" :: _ =>
            let some bootstrap := parseBootstrap first
              | throw s!"invalid bootstrap trace line: {first}"
            pure (bootstrap, remaining)
        | _ => pure (defaultBootstrap, lines)
  let (bootstrap, actionLines) <-
    match actionLines with
    | statusLine :: remaining =>
        match statusLine.splitOn "," with
        | "pre-vote-status" :: _ =>
            let some bootstrap := parsePreVoteStatus bootstrap statusLine
              | throw s!"invalid pre-vote status line: {statusLine}"
            pure (bootstrap, remaining)
        | _ => pure (bootstrap, actionLines)
    | [] => pure (bootstrap, [])
  let actions <- actionLines.mapM fun line => do
    let some action := parseAction line
      | throw s!"invalid trace line: {line}"
    pure action
  pure { bootstrap, actions }

/-- Write a self-contained replay trace in action execution order. -/
def writeReplayTrace
    (path : System.FilePath)
    (bootstrap : Bootstrap Node)
    (actions : List SimAction) :
    IO Unit :=
  IO.FS.writeFile path
    (String.intercalate "\n"
      (renderBootstrap bootstrap ::
        renderPreVoteStatus bootstrap ::
        actions.map renderAction) ++ "\n")

/-- Write reverse-accumulated simulator actions as a self-contained trace. -/
def writeTrace (path : System.FilePath) (actions : List SimAction) : IO Unit :=
  writeReplayTrace path (inferInstanceAs (Bootstrap Node)) actions.reverse

/-- Replay semantic actions from the initial state while checking invariants. -/
def replayActions
    (actions : List SimAction) :
    Except String SimState :=
  actions.foldlM (init := (initialState : SimState)) fun state action => do
    let some nextState :=
      (system (Node := Node) (TxId := TxId)).applyAction state action
      | throw s!"disabled action: {renderAction action}"
    let nextState := compactState nextState
    if !stateChecks nextState then
      throw s!"state invariant failed after: {renderAction action}"
    if !edgeChecks state nextState then
      throw s!"edge invariant failed after: {renderAction action}"
    pure nextState

/-- Parse and replay a semantic action trace. -/
def replayFile (path : System.FilePath) : IO UInt32 := do
  let content <- IO.FS.readFile path
  let lines := content.splitOn "\n" |>.filter (· != "")
  let trace <-
    match parseReplayLines lines with
    | .ok trace => pure trace
    | .error message =>
        IO.eprintln message
        return 2
  let _ : Bootstrap Node := trace.bootstrap
  match replayActions trace.actions with
  | .ok state =>
      let commitIndices :=
        allNodes.map fun node => (state.nodes node).commitIndex
      let leaderNodes :=
        allNodes.filter fun node => (state.nodes node).role = .leader
      let leaders := leaderNodes.map Fin.val
      let currentConfigurationIndices :=
        allNodes.map fun node =>
          (currentConfiguration (state.nodes node)).index
      let leaderCurrentConfigurations :=
        leaderNodes.map fun node =>
          let current :=
            currentConfiguration (state.nodes node)
          (node.val,
            (allNodes.filter fun member => member ∈ current.nodes).map Fin.val)
      let activeConfigurationIndices :=
        allNodes.map fun node =>
          (activeConfigurations (state.nodes node)).map Configuration.index
      let joined :=
        (allNodes.filter fun node => node ∈ state.hasJoined).map Fin.val
      IO.println
        s!"replayed {trace.actions.length} arbitrary-term Raft actions; max term={
          (allNodes.map fun node =>
            (state.nodes node).currentTerm).foldl max 0}; commit indices={
          repr commitIndices}; leaders={repr leaders}; current configuration indices={
          repr currentConfigurationIndices}; leader current configurations={
          repr leaderCurrentConfigurations}; active configuration indices={
          repr activeConfigurationIndices}; joined={repr joined}"
      return 0
  | .error message =>
      IO.eprintln message
      return 1

/-- Explore traces until the deadline, restarting at the requested depth. -/
partial def simulateLoop
    (deadlineMs : Nat)
    (maxDepth : Nat)
    (generator : Generator)
    (state : SimState)
    (depth : Nat)
    (trace : List SimAction)
    (telemetry : Telemetry) :
    IO (Telemetry × Generator) := do
  let now <- IO.monoMsNow
  if now >= deadlineMs then
    return (telemetry, generator)
  let state :=
    if depth >= maxDepth then
      (initialState : SimState)
    else state
  let depth := if depth >= maxDepth then 0 else depth
  let trace := if depth = 0 then [] else trace
  let telemetry :=
    if depth = 0 then
      { telemetry with traces := telemetry.traces + 1 }
    else telemetry
  let (choice?, generator) := propose state generator
  let some choice := choice?
    | simulateLoop
        deadlineMs maxDepth generator
        (initialState : SimState) 0 [] telemetry
  let telemetry := telemetry.proposed choice.family
  let some action := materialize state choice
    | simulateLoop deadlineMs maxDepth generator state depth trace
        { telemetry with rejected := telemetry.rejected + 1 }
  match (system (Node := Node) (TxId := TxId)).applyAction state action with
  | none =>
      simulateLoop deadlineMs maxDepth generator state depth trace
        { telemetry with rejected := telemetry.rejected + 1 }
  | some nextState =>
      let nextState := compactState nextState
      let trace := action :: trace
      if !stateChecks nextState || !edgeChecks state nextState then
        let path : System.FilePath := "ccf-raft-failure.trace"
        writeTrace path trace
        throw <| IO.userError s!"Raft invariant failure; replay {path}"
      let nextDepth := depth + 1
      let telemetry :=
        { telemetry.taken choice.family with
          steps := telemetry.steps + 1
          maxDepth := max telemetry.maxDepth nextDepth }
      simulateLoop
        deadlineMs maxDepth generator nextState nextDepth trace telemetry

/-- Run bounded randomized exploration for the requested duration. -/
def simulate
    (durationMs seed maxDepth : Nat) :
    IO UInt32 := do
  let start <- IO.monoMsNow
  let (telemetry, _) <-
    simulateLoop
      (start + durationMs)
      maxDepth
      { state := UInt64.ofNat seed }
      (initialState : SimState)
      0
      []
      {}
  IO.println s!"{repr telemetry}"
  return 0

end CCFRaft.Simulation
