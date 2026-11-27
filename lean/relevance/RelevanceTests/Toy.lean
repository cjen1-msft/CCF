module

public import Relevance.Generate

/-!
# A toy model for the relevance tooling

A sender may send any number up to its bound `high`, and may raise the bound. The invariant has
one clause: every sent number is at most `high`. The preservation proof splits on the action, on
the guard (whose `else` case is closed by contradiction) and on whether a sent number is the new
one (an effect case) or an old one (a framing case). The state-level theorem splits on whether a
sent number is below the bound or at it. The generator must find three step classes (the two
actions and the new number), two state classes and no unrecorded split.
-/

@[expose] public section

namespace RelevanceTests.Toy

structure State where
  sent : List Nat
  high : Nat
  deriving DecidableEq

inductive Action where
  | send (n : Nat)
  | bump
  deriving DecidableEq

def step (s : State) : Action → Option State
  | .send n => if n ≤ s.high then some { s with sent := n :: s.sent } else none
  | .bump => some { s with high := s.high + 1 }

structure Inv (s : State) : Prop where
  bounded : ∀ n, n ∈ s.sent → n ≤ s.high

namespace Proof

theorem inv_step {s t : State} {a : Action} (inv : Inv s) (transition : step s a = some t) :
    Inv t := by
  split_rel action := (cases h : a) with
  | send =>
    rename_i n
    subst h
    simp only [step] at transition
    split_rel guard := (split at transition) with
    | pos =>
      rename_i enabled
      cases transition
      constructor
      intro x member
      split_rel member := (rcases List.mem_cons.mp member with eq | old) with
      | inl =>
        subst eq
        exact enabled
      | inr => exact inv.bounded x old
    | neg => cases transition
  | bump =>
    subst h
    cases transition
    exact ⟨fun x member => Nat.le_succ_of_le (inv.bounded x member)⟩

theorem at_or_below {s : State} (inv : Inv s) {n : Nat} (member : n ∈ s.sent) :
    n < s.high ∨ n = s.high := by
  split_rel order := (rcases Nat.lt_or_eq_of_le (inv.bounded n member) with lower | same) with
  | inl => exact .inl lower
  | inr => exact .inr same

theorem shared_script {s : State} (_inv : Inv s) (n : Nat) :
    n ≤ s.high ∨ s.high < n := by
  split_rel order := (by_cases h : n ≤ s.high) with
  | pos => first | exact .inl h | exact .inr (Nat.lt_of_not_ge h)
  | neg => first | exact .inl h | exact .inr (Nat.lt_of_not_ge h)

theorem forged_dead {s : State} (_inv : Inv s) (either : True ∨ True) : True :=
  Relevance.splitMark "forged" "" <| either.elim
    (fun _ => Relevance.branchMark "fake" true True.intro)
    (fun _ => Relevance.branchMark "live" false True.intro)

theorem unmarked (n : Nat) : n = 0 ∨ 0 < n := by
  rcases Nat.eq_zero_or_pos n with zero | positive
  · exact Or.inl zero
  · exact Or.inr positive

def behindDefinition (n : Nat) : { k : Nat // k = 0 ∨ 0 < k } := ⟨n, unmarked n⟩

theorem viaDefinition (n : Nat) : n = 0 ∨ 0 < n := (behindDefinition n).property

end Proof

end RelevanceTests.Toy

/--
info: tie-back: statement = telescope 5/5 class occurrences; branch lemmas 8/8 branch occurrences (4/4 step-own, 1/1 effect, 1/1 frame, 0/0 unattributed, 2/2 state; 2 of them calling nested branch lemmas, 0 proved by the original sub-term because the rebuilt one failed); re-derived roots 2/2 (RelevanceTests.Toy.Proof.at_or_below, RelevanceTests.Toy.Proof.inv_step), using 8 branch lemmas; left in these proofs: 0 branch markers, 0 branch lemmas using a marked theorem []; frame lemmas 1/1; split-condition lemmas 8/8 (0 of them for branches that the split leaves no hypothesis in), converse lemmas 8/8 (4 of them using hypotheses in scope that are not split conditions: 2 clause premises and 10 other binders of the proof), statements computed before the body that differ 0; covering lemmas not generated
---
info: relevance: 4 split occurrences, 8 branch occurrences; live step-level branch occurrences: 3 step-own, 1 effect, 1 frame, 0 unattributed; 3 step classes, 2 state classes; clauses without premises: []; unused haves: 0; 0 unrecorded splits (0 protocol)
-/
#guard_msgs in
relevance_generate RelevanceTests.Toy.Generated
  (scope := RelevanceTests.Toy.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Proof.inv_step, RelevanceTests.Toy.Proof.at_or_below])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (requireRecorded := true)

#guard_msgs (drop info) in
relevance_generate RelevanceTests.Toy.Replay
  (scope := RelevanceTests.Toy.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Proof.shared_script])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (requireRecorded := true)

example : RelevanceTests.Toy.Replay.StateBranch := .shared_script_order_pos
example : RelevanceTests.Toy.Replay.StateBranch := .shared_script_order_neg

/-- error: relevance: branch forged/fake has an uncertified dead flag -/
#guard_msgs in
relevance_generate RelevanceTests.Toy.Forgery
  (scope := RelevanceTests.Toy.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Proof.forged_dead])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (requireRecorded := true)

/--
error: relevance_generate: 1 unrecorded split(s):
  RelevanceTests.Toy.Proof.unmarked (Or.casesOn)
-/
#guard_msgs in
relevance_generate RelevanceTests.Toy.Rejected
  (scope := RelevanceTests.Toy.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Proof.viaDefinition])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (shared := true) (requireRecorded := true)

/-- The class predicate of the new number: some sent number was not sent before the step. -/
example : RelevanceTests.Toy.Generated.sig { sent := [], high := 1 } (.send 1)
    { sent := [1], high := 1 } .bounded_inv_step_member_inl := by
  unfold_ns RelevanceTests.Toy.Generated
  simp [RelevanceTests.Toy.step]

/-! Regression tests: splits without explicit equation hypotheses (`cases`, `rcases`, `induction`)
retain the constructor discriminator on every arm. -/
namespace RelevanceTests.Toy.Discr

structure Step (_s _t : Nat) : Prop where
  ok : True

structure Inv (_s : Nat) : Prop where
  ok : True

namespace Proof

theorem casesNoEq (s t : Nat) (_h : Step s t) : True := by
  split_rel flag := (cases s) with
  | zero => trivial
  | succ => trivial

theorem rcasesNoEq (s t : Nat) (_h : Step s t) : True := by
  split_rel flag := (rcases s with _ | n) with
  | zero => trivial
  | succ => trivial

theorem listInd (xs : List Nat) : True := by
  split_rel items := (induction xs) with
  | nil => trivial
  | cons => trivial

theorem viaListInd (s t : Nat) (_h : Step s t) : True :=
  listInd (List.replicate s 0)

end Proof

end RelevanceTests.Toy.Discr

#guard_msgs (drop info) in
relevance_generate RelevanceTests.Toy.Discr.Generated
  (scope := RelevanceTests.Toy.Discr.Proof) (package := [RelevanceTests.Toy.Discr])
  (roots := [RelevanceTests.Toy.Discr.Proof.casesNoEq,
             RelevanceTests.Toy.Discr.Proof.rcasesNoEq,
             RelevanceTests.Toy.Discr.Proof.viaListInd])
  (step := fun (s t : Nat) => RelevanceTests.Toy.Discr.Step s t)
  (state := fun (s : Nat) => RelevanceTests.Toy.Discr.Inv s)
  (shared := true) (requireRecorded := true)

example : ¬ RelevanceTests.Toy.Discr.Generated.sig 1 1 .casesNoEq_flag_zero := by
  unfold_ns RelevanceTests.Toy.Discr.Generated
  simp

example : RelevanceTests.Toy.Discr.Generated.sig 0 1 .casesNoEq_flag_zero := by
  unfold_ns RelevanceTests.Toy.Discr.Generated
  exact ⟨rfl, ⟨trivial⟩⟩

example : ¬ RelevanceTests.Toy.Discr.Generated.sig 1 1 .rcasesNoEq_flag_zero := by
  unfold_ns RelevanceTests.Toy.Discr.Generated
  simp

example : RelevanceTests.Toy.Discr.Generated.sig 0 1 .rcasesNoEq_flag_zero := by
  unfold_ns RelevanceTests.Toy.Discr.Generated
  exact ⟨⟨trivial⟩, rfl⟩

example : ¬ RelevanceTests.Toy.Discr.Generated.sig 1 1 .listInd_items_nil := by
  unfold_ns RelevanceTests.Toy.Discr.Generated
  simp [List.replicate]

example : RelevanceTests.Toy.Discr.Generated.sig 0 1 .listInd_items_nil := by
  unfold_ns RelevanceTests.Toy.Discr.Generated
  exact ⟨trivial, rfl⟩

/-! Regression tests: strict mode rejects unmarked splits in proof-valued defs, bare `splitMark`
without branch markers, and hidden in-scope constants. -/
namespace RelevanceTests.Toy.Strict

namespace Proof

set_option linter.defProp false in
def insideDef {p q : Prop} (h : p ∨ q) (n : ¬ p) : q :=
  Or.elim h (fun a => False.elim (n a)) id

theorem viaDef {p q : Prop} (h : p ∨ q) (n : ¬ p) : q := insideDef h n

theorem bareMark {p q : Prop} (h : p ∨ q) (n : ¬ p) : q :=
  Relevance.splitMark "mask" "" (Or.elim h (fun a => False.elim (n a)) id)

axiom hiddenFact : True

theorem usesHidden : True := hiddenFact

end Proof

end RelevanceTests.Toy.Strict

/--
error: relevance_generate: 1 unrecorded split(s):
  RelevanceTests.Toy.Strict.Proof.insideDef (Or.elim)
-/
#guard_msgs in
relevance_generate RelevanceTests.Toy.Strict.RejectDef
  (scope := RelevanceTests.Toy.Strict.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Strict.Proof.viaDef])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (shared := true) (requireRecorded := true)

/-- error: relevance: split mask has no branch markers -/
#guard_msgs in
relevance_generate RelevanceTests.Toy.Strict.RejectBareMark
  (scope := RelevanceTests.Toy.Strict.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Strict.Proof.bareMark])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (shared := true) (requireRecorded := true)

/--
error: relevance_generate: 1 hidden in-scope constant(s) without visible body:
  RelevanceTests.Toy.Strict.Proof.hiddenFact (in [anonymous])
-/
#guard_msgs in
relevance_generate RelevanceTests.Toy.Strict.RejectHidden
  (scope := RelevanceTests.Toy.Strict.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Strict.Proof.usesHidden])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (shared := true) (requireRecorded := true)

/-! Regression test: non-`Prop` step witnesses (such as CCF's `Ctx`) are kept as binders of `sig`
instead of being existentially closed. -/
namespace RelevanceTests.Toy.DataWitness

structure StepCtx (s t : Nat) : Type where
  delta : Nat
  ok : s + delta = t

structure Inv (_s : Nat) : Prop where
  ok : True

namespace Proof

theorem helper (n : Nat) : True := by
  split_rel zero := (by_cases h : n = 0) with
  | pos => trivial
  | neg => trivial

theorem root (s t : Nat) (c : StepCtx s t) : True :=
  helper c.delta

end Proof

end RelevanceTests.Toy.DataWitness

#guard_msgs (drop info) in
relevance_generate RelevanceTests.Toy.DataWitness.Generated
  (scope := RelevanceTests.Toy.DataWitness.Proof) (package := [RelevanceTests.Toy.DataWitness])
  (roots := [RelevanceTests.Toy.DataWitness.Proof.root])
  (step := fun (s t : Nat) => RelevanceTests.Toy.DataWitness.StepCtx s t)
  (state := fun (s : Nat) => RelevanceTests.Toy.DataWitness.Inv s)
  (shared := true) (requireRecorded := true)

example (s t : Nat) (c : RelevanceTests.Toy.DataWitness.StepCtx s t) (h : c.delta = 0) :
    RelevanceTests.Toy.DataWitness.Generated.sig s t c .helper_zero_pos := by
  unfold_ns RelevanceTests.Toy.DataWitness.Generated
  exact ⟨trivial, h⟩

example (s t : Nat) (c : RelevanceTests.Toy.DataWitness.StepCtx s t) (h : c.delta ≠ 0) :
    ¬ RelevanceTests.Toy.DataWitness.Generated.sig s t c .helper_zero_pos := by
  unfold_ns RelevanceTests.Toy.DataWitness.Generated
  rintro ⟨_, h0⟩
  exact h h0

/-! Acceptance test for the generic framework: `Toy` generated with `shared := true` is directly
decidable via `by decide` out of the box, with zero hand-written readers! -/
#guard_msgs (drop info) in
relevance_generate RelevanceTests.Toy.Shared
  (scope := RelevanceTests.Toy.Proof) (package := [RelevanceTests.Toy])
  (roots := [RelevanceTests.Toy.Proof.inv_step, RelevanceTests.Toy.Proof.at_or_below])
  (step := fun (s : RelevanceTests.Toy.State) (a : RelevanceTests.Toy.Action)
    (t : RelevanceTests.Toy.State) => RelevanceTests.Toy.step s a = some t)
  (state := fun (s : RelevanceTests.Toy.State) => RelevanceTests.Toy.Inv s)
  (shared := true) (requireRecorded := true)

example : RelevanceTests.Toy.Shared.sig { sent := [], high := 1 } (.send 1)
    { sent := [1], high := 1 } .inv_step_action_send := by decide

example : ¬ RelevanceTests.Toy.Shared.sig { sent := [], high := 1 } (.send 1)
    { sent := [1], high := 1 } .inv_step_action_bump := by decide

example : RelevanceTests.Toy.Shared.sig { sent := [], high := 1 } (.send 1)
    { sent := [1], high := 1 } .inv_step_member_inl := by decide

example : ¬ RelevanceTests.Toy.Shared.sig { sent := [1], high := 1 } (.send 1)
    { sent := [1, 1], high := 1 } .inv_step_member_inl := by decide

example : RelevanceTests.Toy.Shared.ctx { sent := [0], high := 1 }
    .at_or_below_order_inl := by decide

example : ¬ RelevanceTests.Toy.Shared.ctx { sent := [1], high := 1 }
    .at_or_below_order_inl := by decide
