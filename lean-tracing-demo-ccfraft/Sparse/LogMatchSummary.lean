-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.EntryValue

set_option autoImplicit false

/-!
Exact summaries of the actual Model NACK reader, without log-term ordering
assumptions. The finite candidate set is a proof device, not a runtime emitter.
Zero is the no-match result; a positive result names a one-based log position.
-/

namespace CCFRaft.Sparse.LogMatchSummary

variable {N T : Type}

noncomputable def candidates (log : List (Entry N T)) (index threshold : Nat) : Finset Nat :=
  (Finset.range (min index log.length + 1)).filter
    (fun candidate => 0 < candidate /\ termAt log candidate <= threshold)

theorem candidate_mem (log : List (Entry N T)) (index threshold candidate : Nat) :
    Membership.mem (candidates log index threshold) candidate <->
      0 < candidate /\ candidate <= min index log.length /\ termAt log candidate <= threshold := by
  simp [candidates, and_left_comm, and_assoc]

theorem result_eq_sup (log : List (Entry N T)) (index threshold : Nat) :
    findHighestPossibleMatch log index threshold = (candidates log index threshold).sup id := by
  let predicate := fun candidate => decide (0 < candidate /\ termAt log candidate <= threshold)
  have filtered :
      findHighestPossibleMatch log index threshold =
        ((List.range (min index log.length + 1)).filter predicate).foldl max 0 := by
    rw [List.foldl_filter]
    simp only [findHighestPossibleMatch, predicate, decide_eq_true_eq]
  rw [filtered, List.foldl_eq_foldr]
  have folded := List.foldr_sup_eq_sup_toFinset
    ((List.range (min index log.length + 1)).filter predicate)
  have same :
      ((List.range (min index log.length + 1)).filter predicate).toFinset =
        candidates log index threshold := by
    ext candidate
    simp [candidates, predicate]
  rw [same] at folded
  simpa using folded

theorem result_bound (log : List (Entry N T)) (index threshold : Nat) :
    findHighestPossibleMatch log index threshold <= min index log.length := by
  rw [result_eq_sup]
  exact Finset.sup_le fun candidate member => (candidate_mem log index threshold candidate).mp member |>.2.1

theorem candidate_le_result (log : List (Entry N T)) (index threshold candidate : Nat)
    (positive : 0 < candidate) (within : candidate <= min index log.length)
    (hit : termAt log candidate <= threshold) :
    candidate <= findHighestPossibleMatch log index threshold := by
  rw [result_eq_sup]
  exact Finset.le_sup (f := id)
    ((candidate_mem log index threshold candidate).mpr (And.intro positive (And.intro within hit)))

theorem positive_result_matches (log : List (Entry N T)) (index threshold : Nat)
    (positive : 0 < findHighestPossibleMatch log index threshold) :
    termAt log (findHighestPossibleMatch log index threshold) <= threshold := by
  have nonempty : (candidates log index threshold).Nonempty := by
    by_contra empty
    have absent := Finset.not_nonempty_iff_eq_empty.mp empty
    rw [result_eq_sup, absent, Finset.sup_empty] at positive
    exact Nat.not_lt_zero _ positive
  have member : Membership.mem (candidates log index threshold)
      ((candidates log index threshold).sup id) := by
    simpa using (Finset.sup_mem_of_nonempty (f := id) nonempty)
  rw [<- result_eq_sup] at member
  exact ((candidate_mem log index threshold _).mp member).2.2

def Summary (log : List (Entry N T)) (index threshold best : Nat) : Prop :=
  best <= min index log.length /\
    (0 < best -> termAt log best <= threshold) /\
    forall candidate, best < candidate -> candidate <= min index log.length ->
      Not (termAt log candidate <= threshold)

theorem result_summary (log : List (Entry N T)) (index threshold : Nat) :
    Summary log index threshold (findHighestPossibleMatch log index threshold) := by
  refine And.intro (result_bound log index threshold)
    (And.intro (positive_result_matches log index threshold) ?_)
  intro candidate larger within hit
  have dominates := candidate_le_result log index threshold candidate (by omega) within hit
  omega

theorem summary_unique (log : List (Entry N T)) (index threshold left right : Nat)
    (a : Summary log index threshold left) (b : Summary log index threshold right) :
    left = right := by
  apply Nat.le_antisymm
  next =>
    by_contra greater
    have larger : right < left := by omega
    exact b.2.2 left larger a.1 (a.2.1 (by omega))
  next =>
    by_contra greater
    have larger : left < right := by omega
    exact a.2.2 right larger b.1 (b.2.1 (by omega))

theorem result_iff (log : List (Entry N T)) (index threshold best : Nat) :
    findHighestPossibleMatch log index threshold = best <-> Summary log index threshold best := by
  constructor
  next =>
    intro equal
    rw [<- equal]
    exact result_summary log index threshold
  next =>
    intro summary
    exact summary_unique log index threshold _ best (result_summary log index threshold) summary

theorem result_zero_iff (log : List (Entry N T)) (index threshold : Nat) :
    findHighestPossibleMatch log index threshold = 0 <->
      Not (exists candidate, 0 < candidate /\ candidate <= min index log.length /\
        termAt log candidate <= threshold) := by
  rw [result_iff]
  constructor
  next =>
    intro summary witness
    cases witness with
    | intro candidate spec => exact summary.2.2 candidate spec.1 spec.2.1 spec.2.2
  next =>
    intro absent
    refine And.intro (Nat.zero_le _) (And.intro (by omega) ?_)
    intro candidate positive within hit
    exact absent (Exists.intro candidate (And.intro positive (And.intro within hit)))

theorem positive_result_iff (log : List (Entry N T)) (index threshold best : Nat)
    (positive : 0 < best) :
    findHighestPossibleMatch log index threshold = best <->
      best <= min index log.length /\ termAt log best <= threshold /\
        forall candidate, best < candidate -> candidate <= min index log.length ->
          Not (termAt log candidate <= threshold) := by
  rw [result_iff]
  simp only [Summary, positive, true_implies]

-- The anchor is at best - 1; the excluded suffix is [best, min index length).
-- Lengths and positions are ordinary naturals, never signed natural codes.
def StorageSummary (length index best : Nat) (eligible : Nat -> Prop) : Prop :=
  best <= min index length /\
    (0 < best -> eligible (best - 1)) /\
    forall position, best <= position -> position < min index length ->
      Not (eligible position)

theorem array_term (log : ArrayLog.ArrayLog) (candidate : Nat)
    (positive : 0 < candidate) (within : candidate <= log.length) :
    termAt log.decode candidate = (log.entries (candidate - 1)).term := by
  have live : candidate - 1 < log.length := by omega
  simp [termAt, ArrayLog.model_entryAt, ArrayLog.ArrayLog.read,
    Nat.ne_of_gt positive, live]

theorem summary_storage_iff (log : ArrayLog.ArrayLog) (index threshold best : Nat) :
    Summary log.decode index threshold best <->
      StorageSummary log.length index best
        (fun position => (log.entries position).term <= threshold) := by
  simp only [Summary, StorageSummary, ArrayLog.decode_length]
  constructor
  next =>
    intro summary
    refine And.intro summary.1 (And.intro ?_ ?_)
    next =>
      intro positive
      rw [<- array_term log best positive (by omega)]
      exact summary.2.1 positive
    next =>
      intro position after within hit
      apply summary.2.2 (position + 1) (by omega) (by omega)
      simpa only [array_term log (position + 1) (by omega) (by omega),
        Nat.add_sub_cancel] using hit
  next =>
    intro summary
    refine And.intro summary.1 (And.intro ?_ ?_)
    next =>
      intro positive
      rw [array_term log best positive (by omega)]
      exact summary.2.1 positive
    next =>
      intro candidate larger within hit
      apply summary.2.2 (candidate - 1) (by omega) (by omega)
      rw [<- array_term log candidate (by omega) (by omega)]
      exact hit

theorem array_result_iff (log : ArrayLog.ArrayLog) (index threshold best : Nat) :
    findHighestPossibleMatch log.decode index threshold = best <->
      StorageSummary log.length index best
        (fun position => (log.entries position).term <= threshold) := by
  rw [result_iff, summary_storage_iff]

-- decode supplies a proof witness only. No runtime code should materialize it.
theorem entry_value_result_iff (length : Nat) (cells : Nat -> EntryValue.Entry)
    (index threshold best : Nat) :
    findHighestPossibleMatch
        ({ length, entries := fun position => EntryValue.decodeEntry (cells position) } :
          ArrayLog.ArrayLog).decode index threshold = best <->
      StorageSummary length index best
        (fun position => BijectiveIntegerLog.smtDecode (cells position).term <= (threshold : Int)) := by
  simpa only [StorageSummary, EntryValue.term_bound_iff] using
    (array_result_iff
      { length, entries := fun position => EntryValue.decodeEntry (cells position) }
      index threshold best)

namespace Regression

def entry (term : Nat) : Entry Node Nat := { term, content := .signature }

theorem unsorted :
    findHighestPossibleMatch [entry 2, entry 9, entry 1, entry 8] 4 2 = 3 := by decide +kernel

theorem boundaries :
    findHighestPossibleMatch ([] : List (Entry Node Nat)) 100 0 = 0 /\
    findHighestPossibleMatch [entry 0] 0 0 = 0 /\
    findHighestPossibleMatch [entry 0] 100 0 = 1 /\
    findHighestPossibleMatch [entry 2, entry 9, entry 1] 2 2 = 1 /\
    findHighestPossibleMatch [entry 2, entry 9, entry 1] 100 2 = 3 /\
    findHighestPossibleMatch [entry 3, entry 8] 100 2 = 0 /\
    findHighestPossibleMatch [entry 2, entry 2, entry 2] 3 2 = 3 := by decide +kernel

theorem arbitrary_contents (a b c : EntryContent Node Nat) :
    findHighestPossibleMatch
      [{ term := 2, content := a }, { term := 9, content := b }, { term := 1, content := c }]
      3 2 = 3 := rfl

theorem decoded_order :
    BijectiveIntegerLog.smtDecode (-1) = 1 /\
    Not (BijectiveIntegerLog.smtDecode (-1) <= (0 : Int)) /\
    (-1 : Int) <= 0 /\
    StorageSummary 3 10 2
      (fun position => BijectiveIntegerLog.smtDecode
        (if position = 1 then 0 else -1) <= (0 : Int)) := by
  refine And.intro ?_ (And.intro ?_ (And.intro ?_ ?_))
  all_goals try decide +kernel
  refine And.intro (by decide +kernel) (And.intro ?_ ?_)
  next => intro _; decide +kernel
  next =>
    intro position after within
    have position_eq : position = 2 := by omega
    subst position
    decide +kernel

end Regression

end CCFRaft.Sparse.LogMatchSummary

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.LogMatchSummary).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit LogMatchSummary axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"LogMatchSummary: {checked} declarations passed the allowed-axiom gate."
