-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAllocation
import Sparse.NativeArrayLogWrite
import Sparse.NativeArrayRetirement
import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArrayChangeConfiguration

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def configurationEntry (row : Local N T) (newConfiguration : Finset N) : Entry N T :=
  { term := row.currentTerm, content := .reconfiguration newConfiguration }

def configurationLog (row : Local N T) (newConfiguration : Finset N) : Log N T :=
  Log.ofList [configurationEntry row newConfiguration]

def addedNodes (newConfiguration previousConfiguration : Finset N) : Finset N :=
  newConfiguration \ previousConfiguration

def appendRow (row : Local N T) (newConfiguration previousConfiguration : Finset N) :
    Local N T :=
  let added := addedNodes newConfiguration previousConfiguration
  { row with
    log := NativeArrayLogWrite.append row.log (configurationLog row newConfiguration)
    sentIndex := fun peer => if peer ∈ added then row.log.length else row.sentIndex peer }

def changeRow (row : Local N T) (newConfiguration previousConfiguration : Finset N)
    (retirement signature retired : Option Nat) : Local N T :=
  NativeArrayRetirement.refresh
    (appendRow row newConfiguration previousConfiguration) retirement signature retired

def enabled (frame : NativeArrayVote.Frame N T) (source : N)
    (newConfiguration previousConfiguration : Finset N)
    (retirement signature retired : Option Nat) : Prop :=
  let row := get frame.nodes source
  let added := addedNodes newConfiguration previousConfiguration
  (frame.nodes source).isSome = true /\
    row.role = .leader /\
    row.membershipState ≠ .retiredCommitted /\
    newConfiguration.Nonempty /\
    newConfiguration ≠ previousConfiguration /\
    (∀ node ∈ added, node ∉ frame.globals.hasJoined) /\
    (changeRow row newConfiguration previousConfiguration retirement signature retired).membershipState ≠
      .retiredCommitted

def changeConfiguration (frame : NativeArrayVote.Frame N T) (source : N)
    (newConfiguration previousConfiguration : Finset N)
    (retirement signature retired : Option Nat) (completed : Finset N) :
    NativeArrayVote.Frame N T :=
  let added := addedNodes newConfiguration previousConfiguration
  let row := changeRow (get frame.nodes source) newConfiguration previousConfiguration
    retirement signature retired
  { frame with
    nodes := Function.update (NativeArrayAllocation.allocate frame.nodes added) source (some row)
    globals :=
      { frame.globals with
        hasJoined := frame.globals.hasJoined ∪ added
        retirementCompleted := Function.update frame.globals.retirementCompleted source completed } }

theorem latest_configuration_at_length (row : Local N T) :
    latestConfiguration row.toModel =
      currentConfigurationAt row.log.decode row.log.length := by
  unfold latestConfiguration currentConfigurationAt
  have same (configurations : List (Configuration N))
      (bounds : forall configuration, configuration ∈ configurations ->
        configuration.index <= row.log.length) (initial : Configuration N) :
      configurations.foldl (fun _ configuration => configuration) initial =
        configurations.foldl (fun current configuration =>
          if configuration.index <= row.log.length then configuration else current) initial := by
    induction configurations generalizing initial with
    | nil => rfl
    | cons configuration rest ih =>
      simp only [List.foldl_cons, if_pos (bounds configuration (by simp))]
      exact ih (fun item member => bounds item (List.mem_cons_of_mem _ member)) configuration
  exact same _ (fun configuration member => by
    simpa only [Log.decode_length] using
      (configurationsInLog_index_bounds row.log.decode member).2) _

@[simp] theorem configuration_log_decode (row : Local N T) (newConfiguration : Finset N) :
    (configurationLog row newConfiguration).decode = [configurationEntry row newConfiguration] := by
  simp [configurationLog]

theorem append_row_correct (row : Local N T)
    (newConfiguration previousConfiguration : Finset N) :
    (appendRow row newConfiguration previousConfiguration).toModel =
      { row.toModel with
        log := row.toModel.log ++
          [{ term := row.toModel.currentTerm, content := .reconfiguration newConfiguration }]
        sentIndex := fun peer =>
          if peer ∈ newConfiguration \ previousConfiguration then
            row.toModel.log.length
          else
            row.toModel.sentIndex peer } := by
  simp [appendRow, addedNodes, Local.toModel, NativeArrayLogWrite.append_correct,
    configurationEntry]

theorem change_row_correct (row : Local N T) (source : N)
    (newConfiguration previousConfiguration : Finset N)
    (retirement signature retired : Option Nat)
    (retirementCorrect :
      retirementIndexInLog source
        (appendRow row newConfiguration previousConfiguration).log.decode = retirement)
    (signatureCorrect :
      retirement.bind (retirementCommittableIndexInLog
        (appendRow row newConfiguration previousConfiguration).log.decode) = signature)
    (retiredCorrect :
      retiredCommittedIndexInLog source
        (appendRow row newConfiguration previousConfiguration).log.decode = retired) :
    (changeRow row newConfiguration previousConfiguration retirement signature retired).toModel =
      refreshRetirementState source
        { row.toModel with
          log := row.toModel.log ++
            [{ term := row.toModel.currentTerm, content := .reconfiguration newConfiguration }]
          sentIndex := fun peer =>
            if peer ∈ newConfiguration \ previousConfiguration then
              row.toModel.log.length
            else
              row.toModel.sentIndex peer } := by
  rw [changeRow, NativeArrayRetirement.refresh_correct _ source retirement signature retired
    retirementCorrect signatureCorrect retiredCorrect,
    append_row_correct]

theorem enabled_correct (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (newConfiguration previousConfiguration : Finset N) (previousIndex : Nat)
    (retirement signature retired : Option Nat)
    (current : CurrentIndex (get frame.nodes source).log
      (get frame.nodes source).log.length previousIndex)
    (atPrevious :
      NativeArrayConfiguration.At (get frame.nodes source).log previousIndex previousConfiguration)
    (retirementCorrect : retirementIndexInLog source
      (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode = retirement)
    (signatureCorrect : retirement.bind (retirementCommittableIndexInLog
      (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode) = signature)
    (retiredCorrect : retiredCommittedIndexInLog source
      (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode = retired) :
    enabled frame source newConfiguration previousConfiguration retirement signature retired <->
      CCFRaft.Enabled state (.changeConfiguration source newConfiguration) := by
  have fields := get_rep frame.nodes state rep.nodes source
  have previous :
      (latestConfiguration (state.nodes source)).nodes = previousConfiguration := by
    rw [<- fields, latest_configuration_at_length]
    exact congrArg Configuration.nodes
      ((NativeArrayConfiguration.current_configuration_correct
        (get frame.nodes source).log (get frame.nodes source).log.length
        previousIndex previousConfiguration).mp ⟨current, atPrevious⟩)
  have changed := change_row_correct (get frame.nodes source) source
    newConfiguration previousConfiguration retirement signature retired
    retirementCorrect signatureCorrect retiredCorrect
  simp only [enabled, CCFRaft.Enabled, previous]
  rw [<- allocated_rep frame.nodes state rep.nodes source, <- fields, rep.globals]
  simp only [NativeArrayVote.Globals.ofModel, addedNodes]
  have changedMembership := congrArg NodeState.membershipState changed
  simp only [Local.toModel] at changedMembership
  rw [changedMembership]
  rfl

theorem change_configuration_output_rep
    (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (newConfiguration previousConfiguration : Finset N)
    (output : Local N T) (completed : Finset N)
    (previousCorrect :
      (latestConfiguration (state.nodes source)).nodes = previousConfiguration)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          (appendRow (get frame.nodes source) newConfiguration previousConfiguration).toModel)
    (completedCorrect :
      completed = retirementCompletedNodes
        (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode
        (get frame.nodes source).commit) :
    ({ frame with
      nodes := Function.update
        (NativeArrayAllocation.allocate frame.nodes
          (newConfiguration \ previousConfiguration))
        source (some output)
      globals :=
        { frame.globals with
          hasJoined := frame.globals.hasJoined ∪
            (newConfiguration \ previousConfiguration)
          retirementCompleted :=
            Function.update frame.globals.retirementCompleted source completed } }).Rep
      (CCFRaft.next state (.changeConfiguration source newConfiguration)) := by
  let oldRow := get frame.nodes source
  let added := addedNodes newConfiguration previousConfiguration
  have fields : oldRow.toModel = state.nodes source :=
    get_rep frame.nodes state rep.nodes source
  have appendedCorrect := append_row_correct oldRow newConfiguration previousConfiguration
  have outputCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm,
                 content := .reconfiguration newConfiguration }]
            sentIndex := fun peer =>
              if peer ∈ newConfiguration \ previousConfiguration then
                (state.nodes source).log.length
              else
                (state.nodes source).sentIndex peer } := by
    rw [rowCorrect, appendedCorrect, fields]
  have completedState : retirementCompletedNodes
      ((state.nodes source).log ++
        [{ term := (state.nodes source).currentTerm,
           content := .reconfiguration newConfiguration }])
      (state.nodes source).commitIndex = completed := by
    rw [completedCorrect, <- fields]
    have sameLog := congrArg NodeState.log appendedCorrect
    exact congrArg
      (fun entries => retirementCompletedNodes entries oldRow.toModel.commitIndex)
      sameLog.symm
  have allocatedRep := NativeArrayAllocation.allocate_rep frame.nodes state rep.nodes added
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      simp [CCFRaft.next, previousCorrect, State.node?, updateNode, Local.Rep, outputCorrect]
    · simpa [oldRow, added, CCFRaft.next, previousCorrect, State.node?, updateNode, same]
        using allocatedRep peer
  · simpa [CCFRaft.next, previousCorrect] using rep.queues
  · rw [rep.globals]
    simp [CCFRaft.next, previousCorrect, NativeArrayVote.Globals.ofModel,
      refreshRetirementCompleted, completedState]

theorem change_configuration_rep (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (newConfiguration previousConfiguration : Finset N) (previousIndex : Nat)
    (retirement signature retired : Option Nat) (completed : Finset N)
    (current : CurrentIndex (get frame.nodes source).log
      (get frame.nodes source).log.length previousIndex)
    (atPrevious :
      NativeArrayConfiguration.At (get frame.nodes source).log previousIndex previousConfiguration)
    (retirementCorrect : retirementIndexInLog source
      (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode = retirement)
    (signatureCorrect : retirement.bind (retirementCommittableIndexInLog
      (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode) = signature)
    (retiredCorrect : retiredCommittedIndexInLog source
      (appendRow (get frame.nodes source) newConfiguration previousConfiguration).log.decode = retired)
    (completedCorrect : retirementCompletedNodes
      ((get frame.nodes source).toModel.log ++
        [{ term := (get frame.nodes source).toModel.currentTerm,
           content := .reconfiguration newConfiguration }])
      (get frame.nodes source).toModel.commitIndex = completed) :
    (changeConfiguration frame source newConfiguration previousConfiguration
      retirement signature retired completed).Rep
      (CCFRaft.next state (.changeConfiguration source newConfiguration)) := by
  let oldRow := get frame.nodes source
  let changed := changeRow oldRow newConfiguration previousConfiguration retirement signature retired
  have fields : oldRow.toModel = state.nodes source :=
    get_rep frame.nodes state rep.nodes source
  have previous :
      (latestConfiguration (state.nodes source)).nodes = previousConfiguration := by
    rw [<- fields, latest_configuration_at_length]
    exact congrArg Configuration.nodes
      ((NativeArrayConfiguration.current_configuration_correct oldRow.log oldRow.log.length
        previousIndex previousConfiguration).mp ⟨current, atPrevious⟩)
  apply change_configuration_output_rep frame state rep source newConfiguration
    previousConfiguration changed completed previous
  · simpa [changed, changeRow] using
      (NativeArrayRetirement.refresh_correct
        (appendRow oldRow newConfiguration previousConfiguration) source
        retirement signature retired retirementCorrect signatureCorrect retiredCorrect)
  · rw [<- completedCorrect]
    have appendedCorrect := append_row_correct oldRow newConfiguration previousConfiguration
    have sameLog := congrArg NodeState.log appendedCorrect
    exact congrArg
      (fun entries => retirementCompletedNodes entries oldRow.toModel.commitIndex)
      sameLog.symm

end CCFRaft.NativeArrayChangeConfiguration

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayChangeConfiguration).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
