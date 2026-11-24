module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import ConsensusCoverage.ReachPath
public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-!
# Two-bit basis for the generated state questions

These are equivalences of the closed generated predicates, even on arbitrary
frames. In particular a node at index zero can witness `Backing` if there is
a ghost committed part: its empty prefix fits. No reachability or invariant
assumption is needed to decode the answers.
-/

namespace ConsensusCoverage.StateBasis

open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Classes

-- Like the generated dispatcher, this interface talks about the private proof
-- frame imported above; it does not change the safety proof's module boundary.
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Some current node has commit index zero. -/
public def Zero (f : Frame) : Prop :=
  ∃ n st, (n, st) ∈ f.current.nodes ∧ st.commitIndex = 0

/-- Some current node's committed prefix fits in a ghost committed part. -/
public def Backing (f : Frame) : Prop :=
  ∃ n st term part, (n, st) ∈ f.current.nodes ∧ Committed f term part ∧
    st.committedLog <+: part

/-- Decode a state question from the truth values of the two basis predicates. -/
@[expose] public def decode (zero backing : Prop) : StateBranch → Prop
  | .committed_logs_comparable_left_backed_inl => zero
  | .committed_logs_comparable_right_backed_inl => zero ∧ backing
  | _ => backing

section
variable [Config.InitialConfiguration]

private abbrev nilPath (f : Frame) : Prop :=
  (reach% state_signatureIndex_le_maxCommittableIndex_values_nil[0]) f

private abbrev signedPath (f : Frame) (log : List Entry) (i : Nat) : Prop :=
  (reach% state_signatureIndex_le_maxCommittableIndex_mem_cons_inl[0]) f log i

private theorem left_inl (f : Frame) :
    state_committed_logs_comparable_left_backed_inl f ↔ Zero f := by
  constructor
  · rintro ⟨n, st, mem, _, _, zero⟩
    exact ⟨n, st, mem, zero⟩
  · rintro ⟨n, st, mem, zero⟩
    exact ⟨n, st, mem, 0, Or.inl zero, zero⟩

private theorem left_inr (f : Frame) :
    state_committed_logs_comparable_left_backed_inr f ↔ Backing f := by
  constructor
  · rintro ⟨n, st, mem, _, _, ⟨term, part, committed, _, pref⟩, _⟩
    exact ⟨n, st, term, part, mem, committed, pref⟩
  · rintro ⟨n, st, term, part, mem, committed, pref⟩
    have w := And.intro committed (And.intro (Nat.le_refl term) pref)
    exact ⟨n, st, mem, term, Or.inr ⟨term, part, w⟩, ⟨term, part, w⟩, term,
      ⟨part, w⟩, part, w, w.1, w.2, w.2⟩

private theorem right_inl (f : Frame) :
    state_committed_logs_comparable_right_backed_inl f ↔ Zero f ∧ Backing f := by
  constructor
  · rintro ⟨n, m, st, other, mem, mem', _, _, ⟨term, part, committed, _, pref⟩, _, _, _, _, _,
      _, _, _, ⟨_, _, zero⟩⟩
    exact ⟨⟨m, other, mem', zero⟩, ⟨n, st, term, part, mem, committed, pref⟩⟩
  · rintro ⟨⟨m, other, mem', zero⟩, ⟨n, st, term, part, mem, committed, pref⟩⟩
    have w := And.intro committed (And.intro (Nat.le_refl term) pref)
    exact ⟨n, m, st, other, mem, mem', term, Or.inr ⟨term, part, w⟩,
      ⟨term, part, w⟩, term, ⟨part, w⟩, part, w, w.1, w.2, w.2.1, w.2.2, 0, Or.inl zero,
      zero⟩

-- The two nodes and the two committed parts in these generated telescopes
-- need not differ. One backing witness suffices, using prefix reflexivity.
private theorem backing_pair (f : Frame) :
    (state_committed_logs_comparable_right_backed_inr f ↔ Backing f) ∧
    (state_committed_logs_comparable_committed_comparable_inl f ↔ Backing f) ∧
    (state_committed_logs_comparable_committed_comparable_inr f ↔ Backing f) := by
  refine ⟨?_, ?_, ?_⟩ <;>
    (constructor
     · rintro ⟨n, _, st, _, mem, _, _, _, ⟨term, part, committed, _, pref⟩, _⟩
       exact ⟨n, st, term, part, mem, committed, pref⟩
     · rintro ⟨n, st, term, part, mem, committed, pref⟩
       have w := And.intro committed (And.intro (Nat.le_refl term) pref)
       have somePart : ∃ p, Committed f term p ∧ term ≤ term ∧ st.committedLog <+: p :=
         ⟨part, w⟩
       have earlier : ∃ k p, Committed f k p ∧ k ≤ term ∧ st.committedLog <+: p :=
         ⟨term, part, w⟩
       refine ⟨n, n, st, st, mem, mem, term, Or.inr earlier, earlier, term, somePart, part,
         w, w.1, w.2, w.2.1, w.2.2, term, Or.inr earlier, earlier, term, somePart, part,
         w, w.1, w.2, w.2.1, ?_⟩
       first | exact w.2.2 | exact ⟨w.2.2, List.prefix_refl part⟩)

private theorem nilPath_iff (f : Frame) : nilPath f ↔ Backing f := by
  change (((state_committed_logs_comparable_right_backed_inr f ∧ True) ∧ True) ∧ True) ↔ _
  simp only [and_true, (backing_pair f).1]

private theorem backing_of_path {f : Frame} {log : List Entry} {index : Nat}
    (h : signedPath f log index) : Backing f := by
  obtain ⟨_, _, ⟨⟨reached, _⟩, _⟩, _⟩ := h
  exact (backing_pair f).1.mp reached

-- The generated telescope has forgotten the link between
-- these log arguments and the backing witnesses. The singleton is sufficient.
private def signedLog : List Entry := [⟨0, .signature⟩]

private theorem signed_reach (f : Frame) (h : Backing f) : signedPath f signedLog 1 :=
  ⟨signedLog, signedLog, ⟨⟨(backing_pair f).1.mpr h, trivial⟩, signedLog, signedLog, rfl, rfl⟩,
    List.prefix_refl _, rfl, rfl, rfl⟩

omit [Config.InitialConfiguration] in
private theorem best_le_fold (log : List Entry) (values : List Nat) (best : Nat) :
    best ≤ values.foldl (fun b i => if isSignatureAt log i then max b i else b) best := by
  induction values generalizing best with
  | nil => exact Nat.le_refl _
  | cons i rest ih =>
    rw [List.foldl_cons]
    split
    · exact Nat.le_trans (Nat.le_max_left _ _) (ih _)
    · exact ih _

/-- Decode every constructor of the generated enum. -/
public theorem ctx_iff_decode (f : Frame) (b : StateBranch) :
    ctx f b ↔ decode (Zero f) (Backing f) b := by
  cases b with
  | committed_logs_comparable_left_backed_inl => exact left_inl f
  | committed_logs_comparable_left_backed_inr => exact left_inr f
  | committed_logs_comparable_right_backed_inl => exact right_inl f
  | committed_logs_comparable_right_backed_inr => exact (backing_pair f).1
  | committed_logs_comparable_committed_comparable_inl => exact (backing_pair f).2.1
  | committed_logs_comparable_committed_comparable_inr => exact (backing_pair f).2.2
  | signatureIndex_le_maxCommittableIndex_values_nil =>
    constructor
    · rintro (⟨reached, _⟩ | ⟨_, _, reached, _⟩)
      · exact (nilPath_iff f).mp reached
      · exact backing_of_path reached
    · intro h
      exact Or.inl ⟨(nilPath_iff f).mpr h, trivial⟩
  | signatureIndex_le_maxCommittableIndex_values_cons =>
    constructor
    · rintro (⟨_, _, reached, _⟩ | ⟨_, _, reached, _⟩) <;>
        exact backing_of_path reached
    · intro h
      exact Or.inl ⟨signedLog, 1, signed_reach f h, [], by simp, rfl, Nat.le_refl _,
        best_le_fold signedLog⟩
  | signatureIndex_le_maxCommittableIndex_mem_cons_inl =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 1, [], by simp, by simp, rfl, rfl, Nat.le_refl _,
        best_le_fold signedLog⟩
  | signatureIndex_le_maxCommittableIndex_signature_pos =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 1, [], by simp, 0, by simp, rfl, by simp, 1, [],
        Nat.le_refl, rfl, rfl, Nat.le_refl _, rfl⟩
  | signatureIndex_le_maxCommittableIndex_signature_neg =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 1, [], by simp, 0, by simp, rfl, by simp, 0, [],
        Nat.le_refl, by decide, rfl, Nat.le_refl _, rfl⟩
  | signatureIndex_le_maxCommittableIndex_mem_cons_inr =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 0, [1], fun best _ => Nat.le_max_right best 1,
        by simp, by simp, rfl, Nat.le_refl _, best_le_fold signedLog⟩

end

/-- The left `inl` and `inr` are probes for the two bits, even when comparing
frames under different initial configurations. -/
public theorem ctx_equiv_iff (cfg cfg' : Config.InitialConfiguration) (f g : Frame) :
    (∀ b, @ctx cfg f b ↔ @ctx cfg' g b) ↔
      (Zero f ↔ Zero g) ∧ (Backing f ↔ Backing g) := by
  constructor
  · intro h
    have probe (b : StateBranch) : decode (Zero f) (Backing f) b ↔
        decode (Zero g) (Backing g) b :=
      (@ctx_iff_decode cfg f b).symm.trans ((h b).trans (@ctx_iff_decode cfg' g b))
    exact ⟨probe .committed_logs_comparable_left_backed_inl,
      probe .committed_logs_comparable_left_backed_inr⟩
  · rintro ⟨zero, backing⟩ b
    rw [@ctx_iff_decode cfg f b, @ctx_iff_decode cfg' g b]
    cases b <;> simp only [decode, zero, backing]

end ConsensusCoverage.StateBasis
