-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ConfigurationSnapshot
import MachineGenerated.ModelProofs

set_option autoImplicit false

/-!
Direct-array baseline for one actual action and its observations.
Arrays are total functions; only live log positions denote Model entries.
Concrete list reconstruction is proof-only. Node cardinality is a parameter.
The SMT-LIB printer is exercised separately, not verified by this module.
-/

namespace CCFRaft.NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

structure Log (N T : Type) where
  length : Nat
  entries : Nat -> Entry N T

def Log.decode (log : Log N T) : List (Entry N T) :=
  List.ofFn (fun i : Fin log.length => log.entries i.val)

def Log.ofList (entries : List (Entry N T)) : Log N T :=
  { length := entries.length
    entries := fun i => entries[i]?.getD { term := 0, content := .signature } }

@[simp] theorem Log.decode_length (log : Log N T) : log.decode.length = log.length := by
  simp [Log.decode]

@[simp] theorem Log.decode_ofList (entries : List (Entry N T)) :
    (Log.ofList entries).decode = entries := by
  simp [Log.ofList, Log.decode, List.ofFn_getElem]

theorem Log.entry_correct (log : Log N T) (index : Nat) (expected : Entry N T) :
    (index < log.length /\ log.entries index = expected) <->
      log.decode[index]? = some expected := by
  by_cases live : index < log.length
  · simp [Log.decode, live]
  · simp [Log.decode, live]

def Reconfiguration (log : Log N T) (index : Nat) (nodes : Finset N) : Prop :=
  0 < index /\ index <= log.length /\
    (log.entries (index - 1)).content = .reconfiguration nodes

theorem reconfiguration_correct (log : Log N T) (index : Nat) (nodes : Finset N) :
    Reconfiguration log index nodes <->
      Sparse.Configuration.Reconfig log.decode index nodes := by
  by_cases positive : 0 < index
  · by_cases within : index <= log.length
    · have live : index - 1 < log.length := by omega
      simp [Reconfiguration, Sparse.Configuration.Reconfig, entryAt?, Log.decode,
        positive, Nat.ne_of_gt positive, within, live]
    · constructor
      · intro h; exact False.elim (within h.2.1)
      · intro h
        have bound := Sparse.Configuration.reconfig_bounds h
        simp only [Log.decode_length] at bound
        exact False.elim (within bound.2)
  · have zero : index = 0 := by omega
    simp [Reconfiguration, Sparse.Configuration.Reconfig, entryAt?, zero]

def CurrentIndex (log : Log N T) (commit index : Nat) : Prop :=
  index <= min commit log.length /\
    (index = 0 \/ exists nodes, Reconfiguration log index nodes) /\
    (forall candidate nodes, index < candidate -> candidate <= min commit log.length ->
      Not (Reconfiguration log candidate nodes))

theorem current_index_correct (log : Log N T) (commit index : Nat) :
    CurrentIndex log commit index <->
      (currentConfigurationAt log.decode commit).index = index := by
  constructor
  · intro h
    rcases h.2.1 with zero | physical
    · have result : currentConfigurationAt log.decode commit = implicitConfiguration := by
        apply (Sparse.Configuration.currentConfigurationAt_exclusion_iff _ _ _).mpr
        refine ⟨by simpa [implicitConfiguration, zero] using h.1,
          Or.inl ⟨rfl, rfl⟩, ?_⟩
        intro candidate nodes lower upper found
        exact h.2.2 candidate nodes (by simpa [implicitConfiguration, zero] using lower)
          (by simpa using upper) ((reconfiguration_correct _ _ _).mpr found)
      simp [result, implicitConfiguration, zero]
    · rcases physical with ⟨nodes, physical⟩
      have result : currentConfigurationAt log.decode commit = { index, nodes } := by
        apply (Sparse.Configuration.currentConfigurationAt_exclusion_iff _ _ _).mpr
        refine ⟨by simpa using h.1, Or.inr ((reconfiguration_correct _ _ _).mp physical), ?_⟩
        intro candidate nodes lower upper found
        exact h.2.2 candidate nodes lower (by simpa using upper)
          ((reconfiguration_correct _ _ _).mpr found)
      rw [result]
  · intro same
    have h := (Sparse.Configuration.currentConfigurationAt_exclusion_iff
      log.decode commit (currentConfigurationAt log.decode commit)).mp rfl
    refine ⟨by simpa [same] using h.1, ?_, ?_⟩
    · rcases h.2.1 with zero | physical
      · exact Or.inl (same.symm.trans zero.1)
      · exact Or.inr ⟨_, (reconfiguration_correct _ _ _).mpr (by simpa [same] using physical)⟩
    · intro candidate nodes lower upper found
      exact h.2.2 candidate nodes (by simpa [same] using lower) (by simpa using upper)
        ((reconfiguration_correct _ _ _).mp found)

def OtherAt (log : Log N T) (current : Nat) (node : N) : Prop :=
  (current = 0 /\ exists peer, peer ∈ INITIAL_CONFIGURATION /\ peer ≠ node) \/
    exists index nodes, current <= index /\ Reconfiguration log index nodes /\
      exists peer, peer ∈ nodes /\ peer ≠ node

theorem mem_union (configurations : List (Configuration N)) (initial : Finset N) (peer : N) :
    peer ∈ configurations.foldl (fun nodes configuration => nodes ∪ configuration.nodes) initial <->
      peer ∈ initial \/ exists configuration, configuration ∈ configurations /\ peer ∈ configuration.nodes := by
  induction configurations generalizing initial with
  | nil => simp
  | cons first rest ih =>
    simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons]
    aesop

theorem other_at_correct (log : Log N T) (state : NodeState N T) (node : N)
    (same : state.log = log.decode) :
    OtherAt log (currentConfiguration state).index node <->
      ((activeNodeUnion state).erase node).Nonempty := by
  have empty (peer : N) : peer ∈ (∅ : Finset N) ↔ False := by simp
  simp only [Finset.Nonempty, Finset.mem_erase, activeNodeUnion, mem_union,
    empty, false_or, activeConfigurations, List.mem_filter,
    decide_eq_true_eq, allConfigurations, List.mem_cons]
  constructor
  · intro h
    rcases h with ⟨zero, peer, member, different⟩ | ⟨index, nodes, lower, physical, peer, member, different⟩
    · exact ⟨peer, different, implicitConfiguration,
        ⟨Or.inl rfl, by simp [implicitConfiguration, zero]⟩, member⟩
    · refine ⟨peer, different, { index, nodes }, ⟨Or.inr ?_, lower⟩, member⟩
      rw [same, Sparse.ConfigurationSnapshot.mem_configurations_iff]
      exact (reconfiguration_correct _ _ _).mp physical
  · rintro ⟨peer, different, configuration, ⟨member, lower⟩, included⟩
    rcases member with implicit | physical
    · subst configuration
      exact Or.inl ⟨by simpa [implicitConfiguration] using lower, peer, included, different⟩
    · refine Or.inr ⟨configuration.index, configuration.nodes, lower, ?_, peer, included, different⟩
      apply (reconfiguration_correct _ _ _).mpr
      rw [same, Sparse.ConfigurationSnapshot.mem_configurations_iff] at physical
      exact physical

structure Local (N T : Type) where
  role : Role
  isNewFollower : Bool
  commit : Nat
  log : Log N T
  currentTerm : Nat
  sentIndex : N -> Nat
  matchIndex : N -> Nat
  votedFor : Option N
  votesGranted : Finset N
  preVotesGranted : Finset N
  membershipState : MembershipState
  retirementIndex : Option Nat
  retirementCommittableIndex : Option Nat
  retiredCommittedIndex : Option Nat

def Local.ofModel (state : NodeState N T) : Local N T :=
  { role := state.role, isNewFollower := state.isNewFollower,
    commit := state.commitIndex, log := Log.ofList state.log, currentTerm := state.currentTerm,
    sentIndex := state.sentIndex, matchIndex := state.matchIndex, votedFor := state.votedFor,
    votesGranted := state.votesGranted, preVotesGranted := state.preVotesGranted,
    membershipState := state.membershipState, retirementIndex := state.retirementIndex,
    retirementCommittableIndex := state.retirementCommittableIndex,
    retiredCommittedIndex := state.retiredCommittedIndex }

def Local.toModel (row : Local N T) : NodeState N T :=
  { role := row.role, isNewFollower := row.isNewFollower,
    commitIndex := row.commit, log := row.log.decode, currentTerm := row.currentTerm,
    sentIndex := row.sentIndex, matchIndex := row.matchIndex, votedFor := row.votedFor,
    votesGranted := row.votesGranted, preVotesGranted := row.preVotesGranted,
    membershipState := row.membershipState, retirementIndex := row.retirementIndex,
    retirementCommittableIndex := row.retirementCommittableIndex,
    retiredCommittedIndex := row.retiredCommittedIndex }

def Local.fresh : Local N T := Local.ofModel freshNodeState

def Local.Rep (row : Local N T) (state : NodeState N T) : Prop :=
  row.toModel = state

abbrev Arrays (N T : Type) := N -> Option (Local N T)

def get (arrays : Arrays N T) (node : N) : Local N T :=
  (arrays node).getD Local.fresh

def Rep (arrays : Arrays N T) (state : State N T) : Prop :=
  forall node, Option.Rel Local.Rep (arrays node) (state.node? node)

def enabled (arrays : Arrays N T) (node : N) : Prop :=
  (arrays node).isSome = true /\ (get arrays node).role = .leader /\
    exists current, CurrentIndex (get arrays node).log (get arrays node).commit current /\
      OtherAt (get arrays node).log current node

def step (arrays : Arrays N T) (node : N) : Arrays N T :=
  Function.update arrays node (some { get arrays node with role := .follower, isNewFollower := true })

theorem get_rep (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state) (node : N) :
    (get arrays node).toModel = state.nodes node := by
  have related := rep node
  cases left : arrays node <;> cases right : state.node? node <;>
    simp_all [get, State.node?, NodeStore.get, Local.Rep, Local.fresh,
      Local.ofModel, Local.toModel, freshNodeState, Log.decode]

theorem allocated_rep (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state) (node : N) :
    (arrays node).isSome = true <-> state.allocated node := by
  have related := rep node
  cases left : arrays node <;> cases right : state.node? node <;>
    simp_all [State.allocated, NodeStore.allocated, State.node?]

theorem enabled_correct (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state) (node : N) :
    enabled arrays node <-> CCFRaft.Enabled state (.checkQuorum node) := by
  have fields := get_rep arrays state rep node
  simp only [enabled, CCFRaft.Enabled, allocated_rep arrays state rep node,
    show (get arrays node).role = (state.nodes node).role from congrArg NodeState.role fields]
  apply and_congr Iff.rfl
  apply and_congr Iff.rfl
  simp only [current_index_correct]
  rw [show (get arrays node).log.decode = (state.nodes node).log from congrArg NodeState.log fields,
    show (get arrays node).commit = (state.nodes node).commitIndex from congrArg NodeState.commitIndex fields]
  simp only [exists_eq_left']
  exact other_at_correct _ _ node (congrArg NodeState.log fields).symm

theorem step_correct (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state) (node : N) :
    Rep (step arrays node) (CCFRaft.next state (.checkQuorum node)) := by
  intro peer
  by_cases same : peer = node
  · subst peer
    have fields := get_rep arrays state rep node
    simp [step, CCFRaft.next, stepDownState, State.node?, updateNode, Local.Rep,
      ← fields, Local.toModel]
  · simpa [step, CCFRaft.next, stepDownState, State.node?, updateNode, same] using rep peer

def ofModel (state : State N T) : Arrays N T :=
  fun node => (state.node? node).map Local.ofModel

theorem of_model_rep (state : State N T) : Rep (ofModel state) state := by
  intro node
  cases found : state.node? node <;>
    simp [ofModel, found, Local.Rep, Local.ofModel, Local.toModel]

noncomputable def realize [Fintype N] (arrays : Arrays N T) : State N T :=
  { nodes := NodeStore.ofFinset (Finset.univ.filter fun node => (arrays node).isSome)
      (fun node => (get arrays node).toModel)
    network := fun _ => [], submittedTxIds := {}, hasJoined := {} }

theorem realize_rep [Fintype N] (arrays : Arrays N T) : Rep arrays (realize arrays) := by
  intro node
  cases found : arrays node with
  | none => simp [realize, State.node?, found]
  | some row => simp [realize, State.node?, found, get, Local.Rep, Local.toModel]

inductive Instruction (N T : Type) where
  | allocated (node : N) (expected : Bool)
  | role (node : N) (expected : Role)
  | newFollower (node : N) (expected : Bool)
  | logLength (node : N) (expected : Nat)
  | commit (node : N) (expected : Nat)
  | currentTerm (node : N) (expected : Nat)
  | sentIndex (node peer : N) (expected : Nat)
  | matchIndex (node peer : N) (expected : Nat)
  | votedFor (node : N) (expected : Option N)
  | votesGranted (node : N) (expected : Finset N)
  | preVotesGranted (node : N) (expected : Finset N)
  | membershipState (node : N) (expected : MembershipState)
  | retirementIndex (node : N) (expected : Option Nat)
  | retirementCommittableIndex (node : N) (expected : Option Nat)
  | retiredCommittedIndex (node : N) (expected : Option Nat)
  | entry (node : N) (index : Nat) (expected : Entry N T)
  | checkQuorum (node : N)

def follows (arrays : Arrays N T) : List (Instruction N T) -> Prop
  | [] => True
  | .allocated node expected :: rest => (arrays node).isSome = expected /\ follows arrays rest
  | .role node expected :: rest => (get arrays node).role = expected /\ follows arrays rest
  | .newFollower node expected :: rest => (get arrays node).isNewFollower = expected /\ follows arrays rest
  | .logLength node expected :: rest => (get arrays node).log.length = expected /\ follows arrays rest
  | .commit node expected :: rest => (get arrays node).commit = expected /\ follows arrays rest
  | .currentTerm node expected :: rest => (get arrays node).currentTerm = expected /\ follows arrays rest
  | .sentIndex node peer expected :: rest => (get arrays node).sentIndex peer = expected /\ follows arrays rest
  | .matchIndex node peer expected :: rest => (get arrays node).matchIndex peer = expected /\ follows arrays rest
  | .votedFor node expected :: rest => (get arrays node).votedFor = expected /\ follows arrays rest
  | .votesGranted node expected :: rest => (get arrays node).votesGranted = expected /\ follows arrays rest
  | .preVotesGranted node expected :: rest => (get arrays node).preVotesGranted = expected /\ follows arrays rest
  | .membershipState node expected :: rest => (get arrays node).membershipState = expected /\ follows arrays rest
  | .retirementIndex node expected :: rest => (get arrays node).retirementIndex = expected /\ follows arrays rest
  | .retirementCommittableIndex node expected :: rest =>
      (get arrays node).retirementCommittableIndex = expected /\ follows arrays rest
  | .retiredCommittedIndex node expected :: rest =>
      (get arrays node).retiredCommittedIndex = expected /\ follows arrays rest
  | .entry node index expected :: rest =>
    (index < (get arrays node).log.length /\ (get arrays node).log.entries index = expected) /\
      follows arrays rest
  | .checkQuorum node :: rest => enabled arrays node /\ follows (step arrays node) rest

def modelFollows (state : State N T) : List (Instruction N T) -> Prop
  | [] => True
  | .allocated node expected :: rest => (state.node? node).isSome = expected /\ modelFollows state rest
  | .role node expected :: rest => (state.nodes node).role = expected /\ modelFollows state rest
  | .newFollower node expected :: rest => (state.nodes node).isNewFollower = expected /\ modelFollows state rest
  | .logLength node expected :: rest => (state.nodes node).log.length = expected /\ modelFollows state rest
  | .commit node expected :: rest => (state.nodes node).commitIndex = expected /\ modelFollows state rest
  | .currentTerm node expected :: rest => (state.nodes node).currentTerm = expected /\ modelFollows state rest
  | .sentIndex node peer expected :: rest => (state.nodes node).sentIndex peer = expected /\ modelFollows state rest
  | .matchIndex node peer expected :: rest => (state.nodes node).matchIndex peer = expected /\ modelFollows state rest
  | .votedFor node expected :: rest => (state.nodes node).votedFor = expected /\ modelFollows state rest
  | .votesGranted node expected :: rest => (state.nodes node).votesGranted = expected /\ modelFollows state rest
  | .preVotesGranted node expected :: rest => (state.nodes node).preVotesGranted = expected /\ modelFollows state rest
  | .membershipState node expected :: rest => (state.nodes node).membershipState = expected /\ modelFollows state rest
  | .retirementIndex node expected :: rest => (state.nodes node).retirementIndex = expected /\ modelFollows state rest
  | .retirementCommittableIndex node expected :: rest =>
      (state.nodes node).retirementCommittableIndex = expected /\ modelFollows state rest
  | .retiredCommittedIndex node expected :: rest =>
      (state.nodes node).retiredCommittedIndex = expected /\ modelFollows state rest
  | .entry node index expected :: rest => (state.nodes node).log[index]? = some expected /\ modelFollows state rest
  | .checkQuorum node :: rest =>
    CCFRaft.Enabled state (.checkQuorum node) /\ modelFollows (CCFRaft.next state (.checkQuorum node)) rest

theorem follows_correct (trace : List (Instruction N T)) (arrays : Arrays N T) (state : State N T)
    (rep : Rep arrays state) : follows arrays trace <-> modelFollows state trace := by
  induction trace generalizing arrays state with
  | nil => rfl
  | cons instruction rest ih =>
    cases instruction
    case allocated node expected =>
      have same : (arrays node).isSome = (state.node? node).isSome := by
        have related := rep node
        cases left : arrays node <;> cases right : state.node? node <;> simp_all
      simp only [follows, modelFollows, same, ih arrays state rep]
    case logLength node expected =>
      have fields := get_rep arrays state rep node
      have same := congrArg (fun row => row.log.length) fields
      change (get arrays node).log.decode.length = (state.nodes node).log.length at same
      simp only [Log.decode_length] at same
      simp only [follows, modelFollows, same, ih arrays state rep]
    case entry node index expected =>
      simp only [follows, modelFollows, Log.entry_correct,
        ← get_rep arrays state rep node, Local.toModel, ih arrays state rep]
    case checkQuorum node =>
      exact and_congr (enabled_correct arrays state rep node)
        (ih _ _ (step_correct arrays state rep node))
    case sentIndex node peer expected =>
      simp only [follows, modelFollows, ← get_rep arrays state rep node, Local.toModel, ih arrays state rep]
    case matchIndex node peer expected =>
      simp only [follows, modelFollows, ← get_rep arrays state rep node, Local.toModel, ih arrays state rep]
    all_goals
      rename_i node expected
      simp only [follows, modelFollows, ← get_rep arrays state rep node, Local.toModel, ih arrays state rep]

theorem exists_iff [Fintype N] (trace : List (Instruction N T)) :
    (exists arrays, follows arrays trace) <-> exists state, modelFollows state trace := by
  constructor
  · rintro ⟨arrays, held⟩
    exact ⟨realize arrays, (follows_correct trace arrays _ (realize_rep arrays)).mp held⟩
  · rintro ⟨state, held⟩
    exact ⟨ofModel state, (follows_correct trace _ state (of_model_rep state)).mpr held⟩

end CCFRaft.NativeArrayCheckQuorum

run_cmd do
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayCheckQuorum).isPrefixOf name then
      if let .axiomInfo _ := info then throwError "explicit axiom: {name}"
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
