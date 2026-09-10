import Sparse.QueueStream

set_option autoImplicit false

namespace CCFRaft.Sparse.QueuePresence

open QueueStream (Event concreteFollows)

variable {K A : Type} [DecidableEq K] [DecidableEq A]

def realizeEvent (value : K -> A) : Event K -> Event A
  | .send key => .send (value key)
  | .pop key => .pop (value key)
  | .peek key => .peek (value key)
  | .length size => .length size

def realize (value : K -> A) (trace : List (Event K)) : List (Event A) :=
  trace.map (realizeEvent value)

def Present (value : K -> A) (known : Finset K) (queue : List A) : Prop :=
  forall key, Membership.mem known key -> Membership.mem queue (value key)

def SoundDifferences (value : K -> A) (different : K -> K -> Bool) : Prop :=
  forall left right, different left right = true -> Not (value left = value right)

def normalize (different : K -> K -> Bool) (known : Finset K) :
    List (Event K) -> List (Event K)
  | [] => []
  | .send key :: rest =>
    let later := normalize different (insert key known) rest
    if Membership.mem known key then later else .send key :: later
  | .pop key :: rest =>
    .pop key :: normalize different (known.filter (fun item => different item key)) rest
  | .peek key :: rest => .peek key :: normalize different known rest
  | .length size :: rest => .length size :: normalize different known rest

theorem present_after_send (value : K -> A) (known : Finset K) (queue : List A)
    (key : K) (present : Present value known queue) :
    Present value (insert key known)
      (if Membership.mem queue (value key) then queue else queue ++ [value key]) := by
  intro item member
  cases Finset.mem_insert.mp member with
  | inl same =>
    subst item
    split
    next member => exact member
    next => simp
  | inr old =>
    have member := present item old
    split
    next => exact member
    next => exact List.mem_append_left _ member

omit [DecidableEq K] [DecidableEq A] in
theorem present_after_pop (value : K -> A) (different : K -> K -> Bool)
    (sound : SoundDifferences value different) (known : Finset K) (queue : List A)
    (key : K) (present : Present value known queue)
    (observed : queue.head? = some (value key)) :
    Present value (known.filter (fun item => different item key)) queue.tail := by
  intro item member
  have selected := Finset.mem_filter.mp member
  have unequal := sound item key selected.2
  have available := present item selected.1
  cases queue with
  | nil => simp at observed
  | cons first rest =>
    have same : first = value key := Option.some.inj observed
    simp only [List.mem_cons] at available
    cases available with
    | inl equal => exact False.elim (unequal (equal.trans same))
    | inr remaining => exact remaining

theorem normalize_correct (value : K -> A) (different : K -> K -> Bool)
    (sound : SoundDifferences value different) (trace : List (Event K))
    (known : Finset K) (queue : List A) (present : Present value known queue) :
    concreteFollows queue (realize value (normalize different known trace)) <->
      concreteFollows queue (realize value trace) := by
  induction trace generalizing known queue with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send key =>
      have updated := present_after_send value known queue key present
      by_cases remembered : Membership.mem known key
      next =>
        have available := present key remembered
        simp only [available, if_true] at updated
        simpa only [normalize, remembered, if_true, realize, List.map_cons,
          realizeEvent, concreteFollows, available] using
          ih (insert key known) queue updated
      next =>
        simpa only [normalize, remembered, if_false, realize, List.map_cons,
          realizeEvent, concreteFollows] using
          ih (insert key known)
            (if Membership.mem queue (value key) then queue else queue ++ [value key]) updated
    | pop key =>
      change (queue.head? = some (value key) /\
          concreteFollows queue.tail
            (realize value (normalize different
              (known.filter (fun item => different item key)) rest))) <->
        (queue.head? = some (value key) /\ concreteFollows queue.tail (realize value rest))
      by_cases observed : queue.head? = some (value key)
      next =>
        simp only [observed, true_and]
        exact ih _ queue.tail (present_after_pop value different sound known queue key
          present observed)
      next => simp only [observed, false_and]
    | peek key =>
      change (queue.head? = some (value key) /\
          concreteFollows queue (realize value (normalize different known rest))) <->
        (queue.head? = some (value key) /\ concreteFollows queue (realize value rest))
      rw [ih known queue present]
    | length size =>
      change (queue.length = size /\
          concreteFollows queue (realize value (normalize different known rest))) <->
        (queue.length = size /\ concreteFollows queue (realize value rest))
      rw [ih known queue present]

theorem normalize_from_unknown_correct (value : K -> A) (different : K -> K -> Bool)
    (sound : SoundDifferences value different) (trace : List (Event K)) (queue : List A) :
    concreteFollows queue (realize value (normalize different {} trace)) <->
      concreteFollows queue (realize value trace) :=
  normalize_correct value different sound trace {} queue (by simp [Present])

theorem repeated_send_regression :
    normalize (fun _ _ : Nat => false) {} [.send 1, .send 1, .length 1] =
      [.send 1, .length 1] := by
  rfl

theorem possible_alias_pop_regression :
    normalize (fun _ _ : Nat => false) {} [.send 1, .pop 2, .send 1] =
      [.send 1, .pop 2, .send 1] := by
  rfl

theorem distinct_pop_regression :
    normalize (fun left right : Nat => left != right) {}
      [.send 1, .pop 2, .send 1] = [.send 1, .pop 2] := by
  rfl

theorem aliased_pop_requires_send :
    concreteFollows ([] : List Nat)
      (realize (fun _ : Nat => 0) [.send 1, .pop 2, .send 1, .length 1]) /\
    Not (concreteFollows ([] : List Nat)
      (realize (fun _ : Nat => 0) [.send 1, .pop 2, .length 1])) := by
  simp [realize, realizeEvent, concreteFollows]

end CCFRaft.Sparse.QueuePresence

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueuePresence).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueuePresence: allowed-axiom gate passed."
