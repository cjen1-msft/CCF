-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ControlTraceConfigurations

set_option autoImplicit false

namespace CCFRaft.ControlTraceRetirement

open TraceSmt ControlTraceConfigurations

def maxTerm {holes : Nat} (left right : NatTerm holes) : NatTerm holes :=
  .add left (.sub right left)

@[simp]
theorem maxTerm_eval {holes : Nat} (assignment : Fin holes -> Nat) (left right : NatTerm holes) :
    (maxTerm left right).eval assignment = max (left.eval assignment) (right.eval assignment) := by
  simp only [maxTerm, NatTerm.eval]
  omega

def removalValue {holes : Nat} (node : Node) :
    List (Snapshot holes) -> NatTerm holes -> NatTerm holes
  | [], _ => .literal 0
  | snapshot :: rest, previous =>
      let included := decide (node ∈ snapshot.configuration.nodes)
      let removed := if included then .literal 0 else minTerm previous snapshot.present
      let nextPrevious := if included then maxTerm previous snapshot.present else previous
      maxTerm removed (removalValue node rest nextPrevious)

theorem removalValue_correct {holes : Nat} (assignment : Fin holes -> Nat) (node : Node)
    (snapshots : List (Snapshot holes))
    (presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1)
    (included : Bool) (previous : NatTerm holes)
    (initial : previous.eval assignment = if included then 1 else 0) :
    (removalValue node snapshots previous).eval assignment =
      if (retirementIndexFromConfigurations node included (selected assignment snapshots)).isSome then 1 else 0 := by
  induction snapshots generalizing included previous with
  | nil => simp [removalValue, selected, NatTerm.eval, retirementIndexFromConfigurations]
  | cons snapshot rest ih =>
      have bit := presence snapshot (by simp)
      have restBits : ∀ snapshot ∈ rest, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1 :=
        fun snapshot member => presence snapshot (List.mem_cons_of_mem _ member)
      cases included <;> rcases bit with bit | bit <;>
        by_cases member : node ∈ snapshot.configuration.nodes <;>
        simp [removalValue, selected, member, bit, initial, NatTerm.eval,
          retirementIndexFromConfigurations, ih restBits]
      all_goals split_ifs <;> omega

def retiredExpr {holes : Nat}
    (node : Node) (snapshots : List (Snapshot holes)) (log : List (Entry Node (NatTerm holes)))
    (position : Nat -> NatTerm holes) (commit : NatTerm holes) : Expr holes :=
  .and (.equal (removalValue node snapshots (.literal 0)) (.literal 1))
    (match retiredCommittedIndexInLog node log with
    | none => .boolean false
    | some index => .not (.lessThan commit (position index)))

theorem retiredExpr_correct {holes : Nat} (assignment : Fin holes -> Nat) (node : Node)
    (state : NodeState Node (NatTerm holes)) (snapshots : List (Snapshot holes))
    (history : Correct assignment (allConfigurations state.log) snapshots)
    (position : Nat -> NatTerm holes) (positions : ∀ index, (position index).eval assignment = index)
    (commit : NatTerm holes) (committed : commit.eval assignment = state.commitIndex) :
    (retiredExpr node snapshots state.log position commit).Holds assignment ↔
      (refreshRetirementState node state).membershipState = .retiredCommitted := by
  have removal := removalValue_correct assignment node snapshots history.presence false (.literal 0) (by rfl)
  rw [history.selected] at removal
  change (removalValue node snapshots (.literal 0)).eval assignment =
    (if (retirementIndexInLog node state.log).isSome then 1 else 0) at removal
  cases retiring : retirementIndexInLog node state.log <;>
    cases recorded : retiredCommittedIndexInLog node state.log <;>
      simp [retiredExpr, Expr.Holds, NatTerm.eval, removal, retiring, recorded,
        positions, committed, refreshRetirementState]
  all_goals split_ifs <;> simp_all

def priorMemberValue {holes : Nat} (node : Node) (current : NatTerm holes) :
    List (Snapshot holes) -> NatTerm holes
  | [] => .literal 0
  | snapshot :: rest =>
      maxTerm
        (minTerm snapshot.present
          (minTerm (within (.add snapshot.position (.literal 1)) current)
            (.literal (if node ∈ snapshot.configuration.nodes then 1 else 0))))
        (priorMemberValue node current rest)

theorem priorMemberValue_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (node : Node) (current : NatTerm holes) (snapshots : List (Snapshot holes))
    (positions : ∀ snapshot ∈ snapshots, snapshot.position.eval assignment = snapshot.configuration.index)
    (presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = 0 ∨ snapshot.present.eval assignment = 1) :
    (priorMemberValue node current snapshots).eval assignment =
      if ∃ cfg ∈ selected assignment snapshots, cfg.index < current.eval assignment ∧ node ∈ cfg.nodes then 1 else 0 := by
  induction snapshots with
  | nil => simp [priorMemberValue, selected, NatTerm.eval]
  | cons snapshot rest ih =>
      have position := positions snapshot (by simp)
      have bit := presence snapshot (by simp)
      have restPositions := fun snapshot member => positions snapshot (List.mem_cons_of_mem _ member)
      have restPresence := fun snapshot member => presence snapshot (List.mem_cons_of_mem _ member)
      rw [priorMemberValue, maxTerm_eval, minTerm_eval, minTerm_eval, within_eval]
      rw [ih restPositions restPresence]
      rcases bit with bit | bit <;>
        by_cases earlier : snapshot.configuration.index < current.eval assignment <;>
        by_cases member : node ∈ snapshot.configuration.nodes <;>
        simp [selected_cons, NatTerm.eval, position, bit, earlier, member, Nat.add_one_le_iff]
      all_goals split_ifs <;> omega

def recordedValue {holes : Nat}
    (node : Node) (position : Nat -> NatTerm holes) (commit : NatTerm holes) :
    Nat -> List (Entry Node (NatTerm holes)) -> NatTerm holes
  | _, [] => .literal 0
  | index, entry :: rest =>
      let remaining := recordedValue node position commit (index + 1) rest
      match entry.content with
      | .retiredCommitted nodes =>
          maxTerm
            (minTerm (within (position index) commit) (.literal (if node ∈ nodes then 1 else 0)))
            remaining
      | _ => remaining

theorem recordedValue_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (node : Node) (position : Nat -> NatTerm holes) (commit : NatTerm holes)
    (positions : ∀ index, (position index).eval assignment = index)
    (log : List (Entry Node (NatTerm holes))) (start : Nat) :
    (recordedValue node position commit start log).eval assignment =
      if node ∈ retiredCommittedNodesUpToFrom (commit.eval assignment) start log then 1 else 0 := by
  induction log generalizing start with
  | nil => simp [recordedValue, retiredCommittedNodesUpToFrom, NatTerm.eval]
  | cons entry rest ih =>
      cases content : entry.content <;>
        by_cases committed : start ≤ commit.eval assignment <;>
        simp [recordedValue, retiredCommittedNodesUpToFrom, content, ih, committed, positions, NatTerm.eval]
      all_goals split_ifs <;> simp_all <;> omega

def completedValue {holes : Nat}
    (node : Node) (snapshots : List (Snapshot holes)) (log : List (Entry Node (NatTerm holes)))
    (position : Nat -> NatTerm holes) (commit current currentMember : NatTerm holes) : NatTerm holes :=
  minTerm (priorMemberValue node current snapshots)
    (minTerm (.sub (.literal 1) currentMember)
      (minTerm (.sub (.literal 1) (recordedValue node position commit 1 log))
        (removalValue node (truncatePure snapshots commit) (.literal 0))))

theorem previouslyConfigured_member (node : Node) (configurations : List (Configuration Node))
    (current : Nat) (initial : Finset Node) :
    node ∈ configurations.foldl
      (fun nodes cfg => if cfg.index < current then nodes ∪ cfg.nodes else nodes) initial ↔
      node ∈ initial ∨ ∃ cfg ∈ configurations, cfg.index < current ∧ node ∈ cfg.nodes := by
  induction configurations generalizing initial with
  | nil => simp
  | cons cfg rest ih =>
      by_cases earlier : cfg.index < current <;>
        simp [List.foldl_cons, ih, earlier, or_assoc, and_assoc]
      all_goals tauto

theorem completedValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (node : Node) (state : NodeState Node (NatTerm holes))
    (snapshots : List (Snapshot holes)) (history : Correct assignment (allConfigurations state.log) snapshots)
    (position : Nat -> NatTerm holes) (positions : ∀ index, (position index).eval assignment = index)
    (commit current currentMember : NatTerm holes)
    (committed : commit.eval assignment = state.commitIndex)
    (currentIndex : current.eval assignment = (currentConfiguration state).index)
    (currentNodes : currentMember.eval assignment = if node ∈ (currentConfiguration state).nodes then 1 else 0) :
    (completedValue node snapshots state.log position commit current currentMember).eval assignment =
      if node ∈ retirementCompletedNodes state.log state.commitIndex then 1 else 0 := by
  have prior := priorMemberValue_correct assignment node current snapshots history.positions history.presence
  rw [history.selected, currentIndex] at prior
  have truncated := truncatePure_correct assignment _ _ history commit
  rw [committed, ← allConfigurations_take] at truncated
  have removal := removalValue_correct assignment node _ truncated.presence false (.literal 0) (by rfl)
  rw [truncated.selected] at removal
  change (removalValue node (truncatePure snapshots commit) (.literal 0)).eval assignment =
    (if (retirementIndexInLog node (state.log.take state.commitIndex)).isSome then 1 else 0) at removal
  simp only [completedValue, minTerm_eval, NatTerm.eval, prior, currentNodes,
    recordedValue_correct assignment node position commit positions, committed, removal,
    retirementCompletedNodes, Finset.mem_filter, Finset.mem_sdiff, previouslyConfigured_member,
    Finset.notMem_empty, false_or, retiredCommittedNodesUpTo]
  simp only [currentConfiguration]
  split_ifs <;> simp_all <;> omega

end CCFRaft.ControlTraceRetirement
