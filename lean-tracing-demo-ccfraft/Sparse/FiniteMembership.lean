-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.Sparse.FiniteMembership

variable {A : Type} [DecidableEq A]

inductive Event (A : Type) where
  | insert (key : A)
  | observe (key : A) (present : Bool)

def Event.key : Event A -> A
  | .insert key | .observe key _ => key

def keys (trace : List (Event A)) : Finset A :=
  (trace.map Event.key).toFinset

def Uses (tracked : Finset A) : List (Event A) -> Prop
  | [] => True
  | event :: rest => Membership.mem tracked event.key /\ Uses tracked rest

def concreteFollows (members : Finset A) : List (Event A) -> Prop
  | [] => True
  | .insert key :: rest => concreteFollows (insert key members) rest
  | .observe key present :: rest =>
    decide (Membership.mem members key) = present /\ concreteFollows members rest

def symbolicFollows (membership : A -> Bool) : List (Event A) -> Prop
  | [] => True
  | .insert key :: rest =>
    symbolicFollows (Function.update membership key true) rest
  | .observe key present :: rest =>
    membership key = present /\ symbolicFollows membership rest

def Agrees (tracked : Finset A) (membership : A -> Bool) (members : Finset A) : Prop :=
  forall key, Membership.mem tracked key ->
    membership key = decide (Membership.mem members key)

theorem agrees_insert (tracked : Finset A) (membership : A -> Bool)
    (members : Finset A) (inserted : A) (agrees : Agrees tracked membership members) :
    Agrees tracked (Function.update membership inserted true) (insert inserted members) := by
  intro key known
  by_cases same : key = inserted
  next => subst key; simp
  next => simp [same, agrees key known]

theorem follows_transfer (tracked : Finset A) (trace : List (Event A))
    (uses : Uses tracked trace) (membership : A -> Bool) (members : Finset A)
    (agrees : Agrees tracked membership members) :
    symbolicFollows membership trace <-> concreteFollows members trace := by
  induction trace generalizing membership members with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | insert key =>
      exact ih uses.2 _ _ (agrees_insert tracked membership members key agrees)
    | observe key present =>
      change (membership key = present /\ symbolicFollows membership rest) <->
        (decide (Membership.mem members key) = present /\ concreteFollows members rest)
      rw [agrees key uses.1]
      exact and_congr Iff.rfl (ih uses.2 membership members agrees)

-- Only proof witnesses use this finite set; the encoder retains unknown membership.
def complete (tracked : Finset A) (membership : A -> Bool) : Finset A :=
  tracked.filter fun key => membership key = true

theorem complete_agrees (tracked : Finset A) (membership : A -> Bool) :
    Agrees tracked membership (complete tracked membership) := by
  intro key known
  simp [complete, known]

theorem uses_keys (trace : List (Event A)) : Uses (keys trace) trace := by
  have all : forall rest : List (Event A),
      (forall event, Membership.mem rest event -> Membership.mem (keys trace) event.key) ->
        Uses (keys trace) rest := by
    intro rest present
    induction rest with
    | nil => trivial
    | cons event rest ih =>
      exact And.intro (present event (by simp))
        (ih fun other member => present other (by simp [member]))
  apply all trace
  intro event present
  simp only [keys, List.mem_toFinset, List.mem_map]
  exact Exists.intro event (And.intro present rfl)

theorem finite_trace_exists_iff (trace : List (Event A)) :
    (exists membership : A -> Bool, symbolicFollows membership trace) <->
      (exists members : Finset A, concreteFollows members trace) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro membership follows =>
      exact Exists.intro (complete (keys trace) membership)
        ((follows_transfer (keys trace) trace (uses_keys trace) membership _
          (complete_agrees (keys trace) membership)).mp follows)
  next =>
    intro witness
    cases witness with
    | intro members follows =>
      let membership := fun key => decide (Membership.mem members key)
      exact Exists.intro membership
        ((follows_transfer (keys trace) trace (uses_keys trace) membership members
          (fun _ _ => rfl)).mpr follows)

theorem inserted_key_cannot_be_absent (key : A) (membership : A -> Bool) :
    Not (symbolicFollows membership [.insert key, .observe key false]) := by
  simp [symbolicFollows]

theorem arbitrary_initial_presence (key : A) :
    exists membership : A -> Bool, symbolicFollows membership [.observe key true] := by
  exact Exists.intro (fun _ => true) (And.intro rfl True.intro)

theorem client_request_submitted {N T : Type}
    [DecidableEq N] [DecidableEq T] [Bootstrap N]
    (state : State N T) (node : N) (transaction : T) :
    (CCFRaft.next state (.clientRequest node transaction)).submittedTxIds =
      insert transaction state.submittedTxIds := rfl

theorem client_request_fresh {N T : Type}
    [DecidableEq N] [DecidableEq T] [Bootstrap N]
    (state : State N T) (node : N) (transaction : T)
    (enabled : Enabled state (.clientRequest node transaction)) :
    Not (Membership.mem state.submittedTxIds transaction) :=
  enabled.2.2.2.1

end CCFRaft.Sparse.FiniteMembership

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.FiniteMembership.follows_transfer,
      ``CCFRaft.Sparse.FiniteMembership.finite_trace_exists_iff,
      ``CCFRaft.Sparse.FiniteMembership.inserted_key_cannot_be_absent,
      ``CCFRaft.Sparse.FiniteMembership.arbitrary_initial_presence,
      ``CCFRaft.Sparse.FiniteMembership.client_request_submitted,
      ``CCFRaft.Sparse.FiniteMembership.client_request_fresh] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
  Lean.logInfo "Finite membership completion audit passed."
