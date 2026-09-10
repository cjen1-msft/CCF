-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt
import Model
import MachineGenerated.HandlerProofs

set_option autoImplicit false

namespace CCFRaft.ControlTraceConfigurations

open TraceSmt

structure Snapshot (holes : Nat) where
  configuration : Configuration Node
  position : NatTerm holes
  present : NatTerm holes

def literals {holes : Nat} (configurations : List (Configuration Node)) : List (Snapshot holes) :=
  configurations.map fun configuration =>
    { configuration, position := .literal configuration.index, present := .literal 1 }

def selected {holes : Nat} (assignment : Fin holes -> Nat) (snapshots : List (Snapshot holes)) :
    List (Configuration Node) :=
  (snapshots.filter fun snapshot => snapshot.present.eval assignment == 1).map Snapshot.configuration

theorem selected_cons {holes : Nat} (assignment : Fin holes -> Nat)
    (snapshot : Snapshot holes) (snapshots : List (Snapshot holes)) :
    selected assignment (snapshot :: snapshots) =
      if snapshot.present.eval assignment = 1 then snapshot.configuration :: selected assignment snapshots
      else selected assignment snapshots := by
  by_cases present : snapshot.present.eval assignment = 1 <;> simp [selected, present]

structure Correct {holes : Nat} (assignment : Fin holes -> Nat)
    (configurations : List (Configuration Node)) (snapshots : List (Snapshot holes)) : Prop where
  positions : ∀ snapshot ∈ snapshots, snapshot.position.eval assignment = snapshot.configuration.index
  presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1
  selected : selected assignment snapshots = configurations

theorem literals_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (configurations : List (Configuration Node)) :
    Correct assignment configurations (literals configurations) := by
  constructor
  · simp [literals, NatTerm.eval]
  · simp [literals, NatTerm.eval]
  · simp [selected, literals, List.filter_map, Function.comp_def, NatTerm.eval]

def append {holes : Nat} (snapshots : List (Snapshot holes))
    (configuration : Configuration Node) (position : NatTerm holes) (group slot : Nat) :
    List (Snapshot holes) :=
  snapshots ++ [{ configuration, position, present := .named group slot "configuration present" (.literal 1) }]

def appendPure {holes : Nat} (snapshots : List (Snapshot holes))
    (configuration : Configuration Node) (position : NatTerm holes) : List (Snapshot holes) :=
  snapshots ++ [{ configuration, position, present := .literal 1 }]

theorem appendPure_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (configurations : List (Configuration Node)) (snapshots : List (Snapshot holes))
    (correct : Correct assignment configurations snapshots)
    (configuration : Configuration Node) (position : NatTerm holes)
    (index : position.eval assignment = configuration.index) :
    Correct assignment (configurations ++ [configuration]) (appendPure snapshots configuration position) := by
  constructor
  · intro snapshot member
    simp only [appendPure, List.mem_append, List.mem_singleton] at member
    rcases member with member | rfl
    · exact correct.positions snapshot member
    · exact index
  · intro snapshot member
    simp only [appendPure, List.mem_append, List.mem_singleton] at member
    rcases member with member | rfl
    · exact correct.presence snapshot member
    · simp [NatTerm.eval]
  · simp [selected, appendPure, NatTerm.eval, ← correct.selected]

theorem append_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (configurations : List (Configuration Node)) (snapshots : List (Snapshot holes))
    (correct : Correct assignment configurations snapshots)
    (configuration : Configuration Node) (position : NatTerm holes) (group slot : Nat)
    (index : position.eval assignment = configuration.index) :
    Correct assignment (configurations ++ [configuration]) (append snapshots configuration position group slot) := by
  constructor
  · intro snapshot member
    simp only [append, List.mem_append, List.mem_singleton] at member
    rcases member with member | rfl
    · exact correct.positions snapshot member
    · exact index
  · intro snapshot member
    simp only [append, List.mem_append, List.mem_singleton] at member
    rcases member with member | rfl
    · exact correct.presence snapshot member
    · simp [NatTerm.eval]
  · simp [selected, append, NatTerm.eval, ← correct.selected]

def minTerm {holes : Nat} (left right : NatTerm holes) : NatTerm holes :=
  .sub left (.sub left right)

def within {holes : Nat} (position limit : NatTerm holes) : NatTerm holes :=
  minTerm (.literal 1) (.sub (.add limit (.literal 1)) position)

def truncate {holes : Nat} (snapshots : List (Snapshot holes)) (limit : NatTerm holes)
    (group : Nat) (slot : Nat -> Nat) : List (Snapshot holes) :=
  snapshots.zipIdx |>.map fun (snapshot, index) =>
    { snapshot with
      present := .named group (slot index) "configuration retained"
        (minTerm snapshot.present (within snapshot.position limit)) }

def truncatePure {holes : Nat} (snapshots : List (Snapshot holes)) (limit : NatTerm holes) : List (Snapshot holes) :=
  snapshots.map fun snapshot =>
    { snapshot with present := minTerm snapshot.present (within snapshot.position limit) }

@[simp]
theorem minTerm_eval {holes : Nat} (assignment : Fin holes -> Nat) (left right : NatTerm holes) :
    (minTerm left right).eval assignment = min (left.eval assignment) (right.eval assignment) := by
  simp only [minTerm, NatTerm.eval]
  omega

@[simp]
theorem within_eval {holes : Nat} (assignment : Fin holes -> Nat) (position limit : NatTerm holes) :
    (within position limit).eval assignment =
      if position.eval assignment ≤ limit.eval assignment then 1 else 0 := by
  simp only [within, minTerm_eval, NatTerm.eval]
  split_ifs <;> omega

theorem truncate_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (configurations : List (Configuration Node)) (snapshots : List (Snapshot holes))
    (correct : Correct assignment configurations snapshots)
    (limit : NatTerm holes) (group : Nat) (slot : Nat -> Nat) :
    Correct assignment (configurations.filter fun cfg => cfg.index ≤ limit.eval assignment)
      (truncate snapshots limit group slot) := by
  have members (snapshot : Snapshot holes) (index : Nat) (member : (snapshot, index) ∈ snapshots.zipIdx) :
      snapshot ∈ snapshots := by
    have projected : snapshot ∈ snapshots.zipIdx.map Prod.fst :=
      List.mem_map.mpr ⟨(snapshot, index), member, rfl⟩
    simpa using projected
  constructor
  · intro snapshot member
    unfold truncate at member
    obtain ⟨⟨old, index⟩, archived, rfl⟩ := List.mem_map.mp member
    exact correct.positions old (members old index archived)
  · intro snapshot member
    unfold truncate at member
    obtain ⟨⟨old, index⟩, archived, rfl⟩ := List.mem_map.mp member
    have bit := correct.presence old (members old index archived)
    simp only [NatTerm.eval, minTerm_eval, within_eval]
    split_ifs <;> omega
  · rw [← correct.selected]
    unfold selected truncate
    simp only [List.filter_map, List.map_map, Function.comp_def, NatTerm.eval,
      minTerm_eval, within_eval]
    calc
      _ = (snapshots.zipIdx.filter (fun pair =>
          decide (pair.1.configuration.index ≤ limit.eval assignment) &&
            pair.1.present.eval assignment == 1)).map (fun pair => pair.1.configuration) := by
        congr 1
        apply List.filter_congr
        intro pair member
        have position := correct.positions pair.1 (members pair.1 pair.2 member)
        have bit := correct.presence pair.1 (members pair.1 pair.2 member)
        rcases bit with bit | bit <;>
          by_cases below : pair.1.configuration.index ≤ limit.eval assignment <;>
          simp [position, bit, below]
      _ = ((snapshots.zipIdx.map Prod.fst).filter (fun snapshot =>
          decide (snapshot.configuration.index ≤ limit.eval assignment) &&
            snapshot.present.eval assignment == 1)).map Snapshot.configuration := by
        rw [List.filter_map, List.map_map]
        rfl
      _ = _ := by simp

theorem truncatePure_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (configurations : List (Configuration Node)) (snapshots : List (Snapshot holes))
    (correct : Correct assignment configurations snapshots) (limit : NatTerm holes) :
    Correct assignment (configurations.filter fun cfg => cfg.index ≤ limit.eval assignment)
      (truncatePure snapshots limit) := by
  constructor
  · intro snapshot member
    obtain ⟨old, archived, rfl⟩ := List.mem_map.mp member
    exact correct.positions old archived
  · intro snapshot member
    obtain ⟨old, archived, rfl⟩ := List.mem_map.mp member
    have bit := correct.presence old archived
    simp only [minTerm_eval, within_eval]
    split_ifs <;> omega
  · rw [← correct.selected]
    simp only [selected, truncatePure, List.filter_map, List.map_map, Function.comp_def,
      minTerm_eval, within_eval]
    congr 1
    rw [List.filter_filter]
    apply List.filter_congr
    intro snapshot member
    have position := correct.positions snapshot member
    have bit := correct.presence snapshot member
    rcases bit with bit | bit <;>
      by_cases below : snapshot.configuration.index ≤ limit.eval assignment <;>
        simp [position, bit, below]

theorem configurationsFrom_lower_bound {TxId : Type}
    (log : List (Entry Node TxId)) (start : Nat) :
    ∀ cfg ∈ configurationsInLogFrom start log, start ≤ cfg.index := by
  induction log generalizing start with
  | nil => simp [configurationsInLogFrom]
  | cons entry rest ih =>
      have remaining : ∀ cfg ∈ configurationsInLogFrom (start + 1) rest, start ≤ cfg.index :=
        fun cfg member => Nat.le_trans (by omega) (ih (start + 1) cfg member)
      cases content : entry.content <;> simpa [configurationsInLogFrom, content] using remaining

theorem configurationsFrom_take {TxId : Type} (log : List (Entry Node TxId)) (start limit : Nat) :
    configurationsInLogFrom start (log.take limit) =
      (configurationsInLogFrom start log).filter fun cfg => cfg.index < start + limit := by
  induction log generalizing start limit with
  | nil => simp [configurationsInLogFrom]
  | cons entry rest ih =>
      cases limit with
      | zero =>
          simp only [List.take_zero, configurationsInLogFrom, Nat.add_zero]
          simpa using configurationsFrom_lower_bound (entry :: rest) start
      | succ limit =>
          cases content : entry.content <;>
            simp [configurationsInLogFrom, content, ih, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

theorem allConfigurations_take {TxId : Type} (log : List (Entry Node TxId)) (limit : Nat) :
    allConfigurations (log.take limit) =
      (allConfigurations log).filter fun cfg => cfg.index ≤ limit := by
  simp only [allConfigurations, configurationsInLog, configurationsFrom_take,
    List.filter_cons, implicitConfiguration, Nat.zero_le, decide_true, if_true]
  congr 1
  apply List.filter_congr
  intro cfg _
  simp only [Nat.add_comm 1, Nat.lt_succ_iff]

def lastValue {holes : Nat} (snapshots : List (Snapshot holes))
    (predicate : Configuration Node -> Bool) (initial : NatTerm holes) : NatTerm holes :=
  snapshots.foldl (fun value snapshot =>
    .add (minTerm snapshot.present (.literal (if predicate snapshot.configuration then 1 else 0)))
      (minTerm (.sub (.literal 1) snapshot.present) value)) initial

theorem lastValue_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (snapshots : List (Snapshot holes))
    (presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1)
    (predicate : Configuration Node -> Bool) (initial : Configuration Node) (value : NatTerm holes)
    (initialCorrect : value.eval assignment = if predicate initial then 1 else 0) :
    (lastValue snapshots predicate value).eval assignment =
      if predicate ((selected assignment snapshots).foldl (fun _ cfg => cfg) initial) then 1 else 0 := by
  induction snapshots generalizing initial value with
  | nil => simpa [lastValue, selected] using initialCorrect
  | cons snapshot rest ih =>
      have bit := presence snapshot (by simp)
      have restBits : ∀ snapshot ∈ rest, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1 :=
        fun snapshot member => presence snapshot (List.mem_cons_of_mem _ member)
      unfold lastValue
      rw [List.foldl_cons]
      rcases bit with absent | present
      · have nextCorrect :
          (NatTerm.add (minTerm snapshot.present (.literal (if predicate snapshot.configuration then 1 else 0)))
            (minTerm (.sub (.literal 1) snapshot.present) value)).eval assignment =
            if predicate initial then 1 else 0 := by
          cases result : predicate initial <;> simp [NatTerm.eval, minTerm_eval, absent, initialCorrect, result]
        simpa [selected, absent] using ih restBits initial _ nextCorrect
      · have nextCorrect :
          (NatTerm.add (minTerm snapshot.present (.literal (if predicate snapshot.configuration then 1 else 0)))
            (minTerm (.sub (.literal 1) snapshot.present) value)).eval assignment =
            if predicate snapshot.configuration then 1 else 0 := by
          cases result : predicate snapshot.configuration <;> simp [NatTerm.eval, minTerm_eval, present, result]
        simpa [selected, present] using ih restBits snapshot.configuration _ nextCorrect

theorem currentConfiguration_filtered {TxId : Type} (state : NodeState Node TxId) :
    ((allConfigurations state.log).filter fun cfg => cfg.index ≤ state.commitIndex).foldl
      (fun _ cfg => cfg) implicitConfiguration = currentConfiguration state := by
  have fold (configurations : List (Configuration Node)) (initial : Configuration Node) :
      (configurations.filter fun cfg => cfg.index ≤ state.commitIndex).foldl (fun _ cfg => cfg) initial =
        configurations.foldl (fun previous cfg => if cfg.index ≤ state.commitIndex then cfg else previous) initial := by
    induction configurations generalizing initial with
    | nil => rfl
    | cons cfg rest ih =>
        by_cases committed : cfg.index ≤ state.commitIndex <;> simp [committed, ih]
  simp [allConfigurations, fold, implicitConfiguration, currentConfiguration, currentConfigurationAt]

def lastIndexValue {holes : Nat} (snapshots : List (Snapshot holes)) (initial : NatTerm holes) : NatTerm holes :=
  snapshots.foldl (fun previous snapshot =>
    (Expr.equal snapshot.present (.literal 1)).ite snapshot.position previous) initial

theorem lastIndexValue_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (snapshots : List (Snapshot holes))
    (positions : ∀ snapshot ∈ snapshots, snapshot.position.eval assignment = snapshot.configuration.index)
    (presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1)
    (initial : Configuration Node) (value : NatTerm holes) (initialCorrect : value.eval assignment = initial.index) :
    (lastIndexValue snapshots value).eval assignment =
      ((selected assignment snapshots).foldl (fun _ cfg => cfg) initial).index := by
  induction snapshots generalizing initial value with
  | nil => simpa [lastIndexValue, selected] using initialCorrect
  | cons snapshot rest ih =>
      have position := positions snapshot (by simp)
      have bit := presence snapshot (by simp)
      have restPositions := fun snapshot member => positions snapshot (List.mem_cons_of_mem _ member)
      have restPresence := fun snapshot member => presence snapshot (List.mem_cons_of_mem _ member)
      unfold lastIndexValue
      rw [List.foldl_cons]
      rcases bit with absent | present
      · have nextCorrect :
          ((Expr.equal snapshot.present (.literal 1)).ite snapshot.position value).eval assignment = initial.index := by
          simp [Expr.ite_eval, Expr.Holds, NatTerm.eval, absent, initialCorrect]
        simpa [selected_cons, absent] using ih restPositions restPresence initial _ nextCorrect
      · have nextCorrect :
          ((Expr.equal snapshot.present (.literal 1)).ite snapshot.position value).eval assignment = snapshot.configuration.index := by
          simp [Expr.ite_eval, Expr.Holds, NatTerm.eval, present, position]
        simpa [selected_cons, present] using ih restPositions restPresence snapshot.configuration _ nextCorrect

theorem maximum_le {α : Type} (values : List α) (predicate : α -> Prop) [DecidablePred predicate]
    (index : α -> Nat) (initial bound : Nat) :
    values.foldl (fun best value => if predicate value then max best (index value) else best) initial ≤ bound ↔
      initial ≤ bound ∧ ∀ value ∈ values, predicate value → index value ≤ bound := by
  induction values generalizing initial with
  | nil => simp
  | cons value rest ih =>
      by_cases accepted : predicate value <;>
        simp [List.foldl_cons, ih, accepted, max_le_iff, and_assoc]
      all_goals tauto

theorem le_maximum {α : Type} (values : List α) (predicate : α -> Prop) [DecidablePred predicate]
    (index : α -> Nat) (initial bound : Nat) :
    bound ≤ values.foldl (fun best value => if predicate value then max best (index value) else best) initial ↔
      bound ≤ initial ∨ ∃ value ∈ values, predicate value ∧ bound ≤ index value := by
  induction values generalizing initial with
  | nil => simp
  | cons value rest ih =>
      by_cases accepted : predicate value <;>
        simp [List.foldl_cons, ih, accepted, le_max_iff, or_assoc]

end CCFRaft.ControlTraceConfigurations
