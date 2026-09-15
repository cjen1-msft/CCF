-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Shared.SmtOrder

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceQueue

open TraceSmt

structure Snapshot (holes : Nat) where
  packet : Message Node (NatTerm holes)
  live : Bool
  present : NatTerm holes

def selected {holes : Nat} (snapshots : List (Snapshot holes)) :
    List (Message Node (NatTerm holes)) :=
  (snapshots.filter (·.live)).map (·.packet)

structure Correct {holes : Nat} (assignment : Fin holes -> Nat)
    (queue : List (Message Node (NatTerm holes))) (snapshots : List (Snapshot holes)) : Prop where
  presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = if snapshot.live then 1 else 0
  selected : selected snapshots = queue

def literals {holes : Nat} (queue : List (Message Node (NatTerm holes))) : List (Snapshot holes) :=
  queue.map fun packet => { packet, live := true, present := .literal 1 }

theorem literals_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (queue : List (Message Node (NatTerm holes))) :
    Correct assignment queue (literals queue) := by
  constructor
  · simp [literals, NatTerm.eval]
  · simp [selected, literals, List.filter_map, Function.comp_def]

def added {holes : Nat} (group : Nat) (slot : Nat -> Nat) :
    Nat -> List (Message Node (NatTerm holes)) -> List (Snapshot holes)
  | _, [] => []
  | index, packet :: rest =>
      { packet, live := true, present := .named group (slot index) "packet present" (.literal 1) } ::
        added group slot (index + 1) rest

def reconcile {holes : Nat} (group : Nat) (slot : Nat -> Nat) (consumed : NatTerm holes) :
    Nat -> List (Snapshot holes) -> List (Message Node (NatTerm holes)) -> List (Snapshot holes)
  | index, [], queue => added group slot index queue
  | index, snapshot :: rest, queue =>
      if !snapshot.live then snapshot :: reconcile group slot consumed (index + 1) rest queue
      else
        match queue with
        | packet :: tail =>
            if snapshot.packet = packet then snapshot :: reconcile group slot consumed (index + 1) rest tail
            else
              { snapshot with
                live := false
                present := .sub snapshot.present (.named group (slot index) "packet consumed" consumed) } ::
                reconcile group slot consumed (index + 1) rest queue
        | [] =>
            { snapshot with
              live := false
              present := .sub snapshot.present (.named group (slot index) "packet consumed" consumed) } ::
              reconcile group slot consumed (index + 1) rest []

theorem added_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (group : Nat) (slot : Nat -> Nat) (index : Nat) (queue : List (Message Node (NatTerm holes))) :
    Correct assignment queue (added group slot index queue) := by
  induction queue generalizing index with
  | nil => constructor <;> simp [added, selected]
  | cons packet rest ih =>
      constructor
      · intro snapshot member
        simp only [added, List.mem_cons] at member
        rcases member with rfl | member
        · rfl
        · exact (ih _).presence _ member
      · simpa [added, selected] using congrArg (List.cons packet) (ih (index + 1)).selected

theorem reconcile_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (group : Nat) (slot : Nat -> Nat) (consumed : NatTerm holes) (consumedCorrect : consumed.eval assignment = 1) (index : Nat)
    (snapshots : List (Snapshot holes)) (queue : List (Message Node (NatTerm holes)))
    (presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = if snapshot.live then 1 else 0) :
    Correct assignment queue (reconcile group slot consumed index snapshots queue) := by
  induction snapshots generalizing index queue with
  | nil => exact added_correct assignment group slot index queue
  | cons snapshot rest ih =>
      have head := presence snapshot (by simp)
      have tail : ∀ value ∈ rest, value.present.eval assignment = if value.live then 1 else 0 :=
        fun value member => presence value (List.mem_cons_of_mem _ member)
      have recPresence (queue : List (Message Node (NatTerm holes))) :=
        (ih (index + 1) queue tail).presence
      have recSelected (queue : List (Message Node (NatTerm holes))) :=
        (ih (index + 1) queue tail).selected
      cases live : snapshot.live <;> cases queue with
      | nil =>
          constructor
          · simpa [reconcile, live, head, live ▸ head, NatTerm.eval, consumedCorrect] using recPresence []
          · simpa [reconcile, live, selected] using recSelected []
      | cons packet remaining =>
          by_cases same : snapshot.packet = packet <;>
            constructor <;>
            simp_all [reconcile, selected, NatTerm.eval, consumedCorrect, List.mem_cons, forall_eq_or_imp,
              recPresence, recSelected]
          all_goals exact recPresence _

def firstValue {holes : Nat} (source : Node)
    (value : Message Node (NatTerm holes) -> NatTerm holes) (fallback : NatTerm holes) :
    List (Snapshot holes) -> NatTerm holes
  | [] => fallback
  | snapshot :: rest =>
      if snapshot.packet.source = source then
        (Expr.equal snapshot.present (.literal 1)).ite (value snapshot.packet)
          (firstValue source value fallback rest)
      else firstValue source value fallback rest

theorem firstValue_correct {holes : Nat} (assignment : Fin holes -> Nat) (source : Node)
    (value : Message Node (NatTerm holes) -> NatTerm holes) (fallback : NatTerm holes)
    (snapshots : List (Snapshot holes))
    (presence : ∀ snapshot ∈ snapshots, snapshot.present.eval assignment = if snapshot.live then 1 else 0) :
    (firstValue source value fallback snapshots).eval assignment =
      (((selected snapshots).find? (fun packet => packet.source == source)).map
        (fun packet => (value packet).eval assignment)).getD (fallback.eval assignment) := by
  induction snapshots with
  | nil => rfl
  | cons snapshot rest ih =>
      have head := presence snapshot (by simp)
      have tail := ih (fun value member => presence value (List.mem_cons_of_mem _ member))
      cases live : snapshot.live <;>
        by_cases same : snapshot.packet.source = source <;>
          simp_all [firstValue, selected, Expr.ite_eval, Expr.Holds, NatTerm.eval]

theorem find_takeFirst {holes : Nat} (source : Node) (queue : List (Message Node (NatTerm holes))) :
    queue.find? (fun packet => packet.source == source) =
      (takeFirstFrom source queue).map (·.1) := by
  induction queue with
  | nil => rfl
  | cons packet rest ih =>
      by_cases same : packet.source = source
      · simp [takeFirstFrom, same]
      · cases remaining : takeFirstFrom source rest <;> simp_all [takeFirstFrom]

theorem firstValue_takeFirst {holes : Nat} (assignment : Fin holes -> Nat) (source : Node)
    (queue : List (Message Node (NatTerm holes))) (snapshots : List (Snapshot holes))
    (correct : Correct assignment queue snapshots)
    (value : Message Node (NatTerm holes) -> NatTerm holes) (fallback : NatTerm holes) :
    (firstValue source value fallback snapshots).eval assignment =
      ((takeFirstFrom source queue).map (fun pair => (value pair.1).eval assignment)).getD
        (fallback.eval assignment) := by
  rw [firstValue_correct assignment source value fallback snapshots correct.presence,
    correct.selected, find_takeFirst]
  cases takeFirstFrom source queue <;> rfl

end CCFRaft.ReceiveTraceQueue
