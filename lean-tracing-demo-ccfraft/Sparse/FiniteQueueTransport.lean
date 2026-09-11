import Sparse.CountedQueue

set_option autoImplicit false

namespace CCFRaft.Sparse.FiniteQueueTransport

open QueueStream (Event concreteFollows)
open CountedQueue (Uses)

variable {A B : Type}

def mapEvent (f : A -> B) : Event A -> Event B
  | .send key => .send (f key)
  | .pop key => .pop (f key)
  | .peek key => .peek (f key)
  | .length length => .length length

def mapTrace (f : A -> B) (trace : List (Event A)) : List (Event B) :=
  trace.map (mapEvent f)

def Separates (keys : Finset A) (f : A -> B) : Prop :=
  forall key, Membership.mem keys key -> forall value, f value = f key <-> value = key

theorem map_mem_iff (keys : Finset A) (f : A -> B) (separates : Separates keys f)
    (queue : List A) (key : A) (tracked : Membership.mem keys key) :
    Membership.mem (queue.map f) (f key) <-> Membership.mem queue key := by
  simp [List.mem_map, separates key tracked]

theorem map_head_iff (keys : Finset A) (f : A -> B) (separates : Separates keys f)
    (queue : List A) (key : A) (tracked : Membership.mem keys key) :
    (queue.map f).head? = some (f key) <-> queue.head? = some key := by
  cases queue <;> simp [separates key tracked]

variable [DecidableEq A] [DecidableEq B]

theorem concreteFollows_map (keys : Finset A) (f : A -> B) (separates : Separates keys f)
    (queue : List A) (trace : List (Event A)) (uses : Uses keys trace) :
    concreteFollows (queue.map f) (mapTrace f trace) <-> concreteFollows queue trace := by
  induction trace generalizing queue with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send key =>
      by_cases present : Membership.mem queue key
      next =>
        have mapped := (map_mem_iff keys f separates queue key uses.1).mpr present
        simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows,
          present, mapped, if_true] using ih queue uses.2
      next =>
        have absent : Not (Membership.mem (queue.map f) (f key)) :=
          fun member => present ((map_mem_iff keys f separates queue key uses.1).mp member)
        simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows,
          present, absent, if_false, List.map_append, List.map_nil] using ih (queue ++ [key]) uses.2
    | pop key =>
      have tails : (queue.map f).tail = queue.tail.map f := by cases queue <;> rfl
      simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows, tails] using
        and_congr (map_head_iff keys f separates queue key uses.1) (ih queue.tail uses.2)
    | peek key =>
      exact and_congr (map_head_iff keys f separates queue key uses.1) (ih queue uses.2)
    | length length =>
      simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows, List.length_map] using
        and_congr (Iff.rfl : queue.length = length <-> queue.length = length) (ih queue uses)

omit [DecidableEq A] [DecidableEq B] in
theorem uses_map (keys : Finset A) (targets : Finset B) (f : A -> B)
    (covered : forall key, Membership.mem keys key -> Membership.mem targets (f key))
    (trace : List (Event A)) (uses : Uses keys trace) :
    Uses targets (mapTrace f trace) := by
  induction trace with
  | nil => trivial
  | cons event rest ih =>
    cases event with
    | send key | pop key | peek key => exact And.intro (covered key uses.1) (ih uses.2)
    | length length => exact ih uses

omit [DecidableEq A] [DecidableEq B] in
theorem trace_inverse_on (keys : Finset A) (f : A -> B) (g : B -> A)
    (inverse : forall key, Membership.mem keys key -> g (f key) = key)
    (trace : List (Event A)) (uses : Uses keys trace) :
    mapTrace g (mapTrace f trace) = trace := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send key | pop key | peek key =>
      simpa only [mapTrace, List.map_cons, mapEvent, inverse key uses.1] using
        congrArg (List.cons _) (ih uses.2)
    | length length =>
      simpa only [mapTrace, List.map_cons, mapEvent] using congrArg (List.cons _) (ih uses)

def supportMap (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (filler : B) (value : A) : B :=
  if member : Membership.mem keys value then (equiv (Subtype.mk value member)).val else filler

omit [DecidableEq B] in
theorem support_map_tracked (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (filler : B) (key : A) (tracked : Membership.mem keys key) :
    supportMap keys targets equiv filler key = (equiv (Subtype.mk key tracked)).val := by
  simp only [supportMap, dif_pos tracked]

omit [DecidableEq B] in
theorem support_map_outside (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (filler : B) (value : A) (outside : Not (Membership.mem keys value)) :
    supportMap keys targets equiv filler value = filler := by
  simp only [supportMap, dif_neg outside]

omit [DecidableEq B] in
theorem support_map_covered (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (filler : B) (key : A) (tracked : Membership.mem keys key) :
    Membership.mem targets (supportMap keys targets equiv filler key) := by
  rw [support_map_tracked keys targets equiv filler key tracked]
  exact (equiv (Subtype.mk key tracked)).property

omit [DecidableEq B] in
theorem support_map_separates (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (filler : B) (fresh : Not (Membership.mem targets filler)) :
    Separates keys (supportMap keys targets equiv filler) := by
  intro key tracked value
  constructor
  next =>
    intro equal
    rw [support_map_tracked keys targets equiv filler key tracked] at equal
    by_cases member : Membership.mem keys value
    next =>
      rw [support_map_tracked keys targets equiv filler value member] at equal
      exact congrArg Subtype.val (equiv.injective (Subtype.ext equal))
    next =>
      rw [support_map_outside keys targets equiv filler value member] at equal
      have target_member := (equiv (Subtype.mk key tracked)).property
      rw [Eq.symm equal] at target_member
      exact False.elim (fresh target_member)
  next => intro equal; rw [equal]

theorem support_map_inverse_on (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (sourceFiller : A) (targetFiller : B) (key : A) (tracked : Membership.mem keys key) :
    supportMap targets keys equiv.symm sourceFiller (supportMap keys targets equiv targetFiller key) = key := by
  rw [support_map_tracked keys targets equiv targetFiller key tracked]
  rw [support_map_tracked targets keys equiv.symm sourceFiller _
    (equiv (Subtype.mk key tracked)).property]
  exact congrArg Subtype.val (equiv.symm_apply_apply (Subtype.mk key tracked))

theorem concrete_exists_support_iff (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (sourceFiller : A) (sourceFresh : Not (Membership.mem keys sourceFiller))
    (targetFiller : B) (targetFresh : Not (Membership.mem targets targetFiller))
    (length : Int) (trace : List (Event A)) (uses : Uses keys trace) :
    (exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace) <->
    (exists queue : List B, (queue.length : Int) = length /\
      concreteFollows queue (mapTrace (supportMap keys targets equiv targetFiller) trace)) := by
  have forward_separates := support_map_separates keys targets equiv targetFiller targetFresh
  have backward_separates := support_map_separates targets keys equiv.symm sourceFiller sourceFresh
  constructor
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      exact Exists.intro (queue.map (supportMap keys targets equiv targetFiller))
        (And.intro (by simpa using spec.1)
          ((concreteFollows_map keys _ forward_separates queue trace uses).mpr spec.2))
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      have mapped_uses := uses_map keys targets (supportMap keys targets equiv targetFiller)
        (support_map_covered keys targets equiv targetFiller) trace uses
      have follows := (concreteFollows_map targets (supportMap targets keys equiv.symm sourceFiller)
        backward_separates queue _ mapped_uses).mpr spec.2
      rw [trace_inverse_on keys _ _ (support_map_inverse_on keys targets equiv sourceFiller targetFiller) trace uses] at follows
      exact Exists.intro (queue.map (supportMap targets keys equiv.symm sourceFiller))
        (And.intro (by simpa using spec.1) follows)

omit [DecidableEq B] in
theorem support_map_outside_queue (keys : Finset A) (targets : Finset B)
    (equiv : Equiv { value : A // Membership.mem keys value } { value : B // Membership.mem targets value })
    (filler : B) (queue : List A)
    (outside : forall value, Membership.mem queue value -> Not (Membership.mem keys value)) :
    queue.map (supportMap keys targets equiv filler) = List.replicate queue.length filler := by
  induction queue with
  | nil => rfl
  | cons value rest ih =>
    have head_outside := outside value (by simp)
    have rest_outside := fun value member => outside value (List.mem_cons_of_mem _ member)
    simp only [List.map_cons, List.length_cons, List.replicate_succ,
      support_map_outside keys targets equiv filler value head_outside, ih rest_outside]

theorem empty_support_map (f : A -> B) (queue : List A) (trace : List (Event A))
    (uses : Uses ({} : Finset A) trace) :
    concreteFollows (queue.map f) (mapTrace f trace) <-> concreteFollows queue trace :=
  concreteFollows_map {} f (by intro key tracked; simp at tracked) queue trace uses

theorem length_only_map (f : A -> B) (queue : List A) (lengths : List Nat) :
    concreteFollows (queue.map f) (mapTrace f (lengths.map Event.length)) <->
      concreteFollows queue (lengths.map Event.length) := by
  apply empty_support_map
  induction lengths with
  | nil => trivial
  | cons length rest ih => exact ih

theorem collapsing_map_regression :
    let f : Nat -> Bool := fun value => decide (value = 0)
    Not (Function.Injective f) /\
      concreteFollows ([0, 1, 2, 1].map f) (mapTrace f [.send 0, .peek 0, .pop 0, .length 3]) := by
  dsimp only
  constructor
  next =>
    intro injective
    have different : (1 : Nat) = 2 := injective (by decide)
    omega
  next =>
    exact (concreteFollows_map ({0} : Finset Nat) (fun value => decide (value = 0))
      (by simp [Separates]) [0, 1, 2, 1] [.send 0, .peek 0, .pop 0, .length 3]
      (by simp [Uses])).mpr (by simp [concreteFollows])

end CCFRaft.Sparse.FiniteQueueTransport

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.FiniteQueueTransport).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.FiniteQueueTransport: allowed-axiom gate passed."
