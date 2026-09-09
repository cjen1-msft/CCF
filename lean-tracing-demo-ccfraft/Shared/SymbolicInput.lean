-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicData
import Shared.BoundedContainer

set_option autoImplicit false

namespace Symbolic

-- A capacity is selected by sequence type; products and sums stay field-local.
abbrev Capacities := Ty → Nat

def inputWidth (capacity : Capacities) : Ty → Nat
  | .nat | .bool => 1
  | .unit => 0
  | .pair a b => inputWidth capacity a + inputWidth capacity b
  | .sum a b => 1 + inputWidth capacity a + inputWidth capacity b
  | .seq a => 1 + capacity (.seq a) * inputWidth capacity a

def fresh (capacity : Capacities) : (s : Ty) → Nat → Expr s
  | .nat, start => .unknown start
  | .bool, start => .eq (.unknown start) (.nat 0)
  | .unit, _ => .unit
  | .pair a b, start =>
      .pair (fresh capacity a start) (fresh capacity b (start + inputWidth capacity a))
  | .sum a b, start =>
      .ite (.eq (.unknown start) (.nat 0))
        (.inl (fresh capacity a (start + 1)))
        (.inr (fresh capacity b (start + 1 + inputWidth capacity a)))
  | .seq a, start =>
      -- Observe Expr.length, not the raw selector, which is clipped to capacity.
      Container.input (.unknown start) <| Vector.ofFn fun i : Fin (capacity (.seq a)) =>
        fresh capacity a (start + 1 + i.val * inputWidth capacity a)

def Fits (capacity : Capacities) : (s : Ty) → s.Value → Prop
  | .nat, _ | .bool, _ | .unit, _ => True
  | .pair a b, (x, y) => Fits capacity a x ∧ Fits capacity b y
  | .sum a _, .inl x => Fits capacity a x
  | .sum _ b, .inr y => Fits capacity b y
  | .seq a, xs => xs.length ≤ capacity (.seq a) ∧ ∀ x ∈ xs, Fits capacity a x

theorem fresh_fits (capacity : Capacities) (s : Ty) (start : Nat) (ρ : Assignment) :
    Fits capacity s ((fresh capacity s start).eval ρ) := by
  induction s generalizing start with
  | nat | bool | unit => trivial
  | pair a b ha hb => exact ⟨ha _, hb _⟩
  | sum a b ha hb =>
      simp only [fresh, Expr.eval]
      split <;> simp_all [Fits]
  | seq a ha =>
      simp only [fresh, Container.input_correct, Fits]
      constructor
      · simp
      · intro x hx
        have hm := List.mem_of_mem_take hx
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp hm
        simp only [Vector.toList_ofFn, List.mem_ofFn] at he
        obtain ⟨i, rfl⟩ := he
        exact ha _

-- Only the selected sum payload and live prefix contribute to the witness.
def Realizes (capacity : Capacities) (ρ : Assignment) :
    (s : Ty) → Nat → s.Value → Prop
  | .nat, start, n => ρ start = n
  | .bool, start, b => decide (ρ start = 0) = b
  | .unit, _, _ => True
  | .pair a b, start, (x, y) =>
      Realizes capacity ρ a start x ∧
        Realizes capacity ρ b (start + inputWidth capacity a) y
  | .sum a _, start, .inl x =>
      ρ start = 0 ∧ Realizes capacity ρ a (start + 1) x
  | .sum a b, start, .inr y =>
      ρ start ≠ 0 ∧ Realizes capacity ρ b (start + 1 + inputWidth capacity a) y
  | .seq a, start, xs =>
      ρ start = xs.length ∧ xs.length ≤ capacity (.seq a) ∧
        ∀ i : Fin xs.length,
          Realizes capacity ρ a (start + 1 + i.val * inputWidth capacity a) xs[i]

theorem fresh_realizes (capacity : Capacities) (ρ : Assignment)
    (s : Ty) (start : Nat) (v : s.Value)
    (h : Realizes capacity ρ s start v) :
    (fresh capacity s start).eval ρ = v := by
  induction s generalizing start with
  | nat => exact h
  | bool => exact h
  | unit => exact Subsingleton.elim _ _
  | pair a b ha hb =>
      rcases v with ⟨x, y⟩
      exact congrArg₂ Prod.mk (ha _ x h.1) (hb _ y h.2)
  | sum a b ha hb =>
      cases v with
      | inl x => simp [fresh, Expr.eval, h.1, ha _ x h.2]
      | inr y => simp [fresh, Expr.eval, h.1, hb _ y h.2]
  | seq a ha =>
      rcases h with ⟨hl, hc, hv⟩
      simp only [fresh, Container.input_correct, Expr.eval, hl]
      apply List.ext_getElem
      · simp [hc]
      · intro i hleft hright
        simp only [List.getElem_take, List.getElem_map, Vector.getElem_toList,
          Vector.getElem_ofFn]
        exact ha _ _ (hv ⟨i, hright⟩)

theorem realizes_congr (capacity : Capacities) (s : Ty) (start : Nat)
    (v : s.Value) (ρ σ : Assignment)
    (same : ∀ i, start ≤ i → i < start + inputWidth capacity s → ρ i = σ i)
    (h : Realizes capacity ρ s start v) :
    Realizes capacity σ s start v := by
  induction s generalizing start with
  | nat => simpa [Realizes, ← same start (by omega) (by simp [inputWidth])] using h
  | bool => simpa [Realizes, ← same start (by omega) (by simp [inputWidth])] using h
  | unit => trivial
  | pair a b ha hb =>
      rcases v with ⟨x, y⟩
      simp only [inputWidth] at same
      exact ⟨ha _ x (fun i hlo hhi => same i hlo (by omega)) h.1,
        hb _ y (fun i hlo hhi => same i (by omega) (by omega)) h.2⟩
  | sum a b ha hb =>
      have root := same start (by omega) (by simp [inputWidth])
      simp only [inputWidth] at same
      cases v with
      | inl x =>
          exact ⟨root ▸ h.1, ha _ x (fun i hlo hhi => same i (by omega) (by omega)) h.2⟩
      | inr y =>
          exact ⟨root ▸ h.1, hb _ y (fun i hlo hhi => same i (by omega) (by omega)) h.2⟩
  | seq a ha =>
      obtain ⟨hl, hc, hv⟩ := h
      refine ⟨(same start (by omega) (by simp [inputWidth])) ▸ hl, hc, ?_⟩
      intro j
      apply ha _ _ ?_ (hv j)
      intro i hlo hhi
      apply same i (by omega)
      have hp := Nat.mul_le_mul_right (inputWidth capacity a)
        (show j.val + 1 ≤ capacity (.seq a) by omega)
      simp only [inputWidth]
      nlinarith

private theorem assemble {ι : Type} (lo width : ι → Nat) (value : ι → Assignment)
    (disjoint : ∀ i j k, lo i ≤ k → k < lo i + width i →
      lo j ≤ k → k < lo j + width j → i = j) :
    ∃ ρ : Assignment, ∀ i k, lo i ≤ k → k < lo i + width i → ρ k = value i k := by
  classical
  let ρ : Assignment := fun k =>
    if h : ∃ i, lo i ≤ k ∧ k < lo i + width i then value h.choose k else 0
  refine ⟨ρ, ?_⟩
  intro i k hlo hhi
  have h : ∃ i, lo i ≤ k ∧ k < lo i + width i := ⟨i, hlo, hhi⟩
  have heq := disjoint h.choose i k h.choose_spec.1 h.choose_spec.2 hlo hhi
  simp [ρ, h, heq]

theorem realizes_exists (capacity : Capacities) (s : Ty) (start : Nat)
    (v : s.Value) (fits : Fits capacity s v) :
    ∃ ρ : Assignment, Realizes capacity ρ s start v := by
  classical
  induction s generalizing start with
  | nat => exact ⟨fun _ => v, rfl⟩
  | bool =>
      refine ⟨fun _ => if v then 0 else 1, ?_⟩
      cases v <;> rfl
  | unit => exact ⟨fun _ => 0, trivial⟩
  | pair a b ha hb =>
      rcases v with ⟨x, y⟩
      obtain ⟨ρa, hρa⟩ := ha start x fits.1
      obtain ⟨ρb, hρb⟩ := hb (start + inputWidth capacity a) y fits.2
      let ρ : Assignment := fun i => if i < start + inputWidth capacity a then ρa i else ρb i
      refine ⟨ρ, ?_, ?_⟩
      · exact realizes_congr capacity a start x ρa ρ
          (fun i _ hhi => by simp [ρ, hhi]) hρa
      · exact realizes_congr capacity b _ y ρb ρ
          (fun i hlo _ => by simp [ρ, show ¬i < start + inputWidth capacity a by omega]) hρb
  | sum a b ha hb =>
      cases v with
      | inl x =>
          obtain ⟨ρa, hρa⟩ := ha (start + 1) x fits
          let ρ : Assignment := fun i => if i = start then 0 else ρa i
          refine ⟨ρ, by simp [ρ], ?_⟩
          exact realizes_congr capacity a _ x ρa ρ
            (fun i hlo _ => by simp [ρ, show i ≠ start by omega]) hρa
      | inr y =>
          obtain ⟨ρb, hρb⟩ := hb (start + 1 + inputWidth capacity a) y fits
          let ρ : Assignment := fun i => if i = start then 1 else ρb i
          refine ⟨ρ, by simp [ρ], ?_⟩
          exact realizes_congr capacity b _ y ρb ρ
            (fun i hlo _ => by simp [ρ, show i ≠ start by omega]) hρb
  | seq a ha =>
      have each (j : Fin v.length) :
          ∃ ρ : Assignment, Realizes capacity ρ a
            (start + 1 + j.val * inputWidth capacity a) v[j] :=
        ha _ _ (fits.2 _ (List.getElem_mem j.isLt))
      let values := fun j => (each j).choose
      obtain ⟨σ, hσ⟩ := assemble
        (fun j : Fin v.length => start + 1 + j.val * inputWidth capacity a)
        (fun _ => inputWidth capacity a) values (by
          intro i j k ilo ihi jlo jhi
          apply Fin.ext
          by_contra h
          rcases lt_or_gt_of_ne h with hij | hji
          · have hm := Nat.mul_le_mul_right (inputWidth capacity a)
              (show i.val + 1 ≤ j.val by omega)
            nlinarith
          · have hm := Nat.mul_le_mul_right (inputWidth capacity a)
              (show j.val + 1 ≤ i.val by omega)
            nlinarith)
      let ρ : Assignment := fun i => if i = start then v.length else σ i
      refine ⟨ρ, by simp [ρ], fits.1, ?_⟩
      intro j
      apply realizes_congr capacity a _ _ (values j) ρ ?_ (each j).choose_spec
      intro i hlo hhi
      simp only [ρ, if_neg (show i ≠ start by omega)]
      exact (hσ j i hlo hhi).symm

theorem fresh_surjective (capacity : Capacities) (s : Ty) (start : Nat)
    (v : s.Value) (fits : Fits capacity s v) :
    ∃ ρ : Assignment, (fresh capacity s start).eval ρ = v := by
  obtain ⟨ρ, hρ⟩ := realizes_exists capacity s start v fits
  exact ⟨ρ, fresh_realizes capacity ρ s start v hρ⟩

def allocate (capacity : Capacities) (s : Ty) : StateM Nat (Expr s) := do
  let start ← get
  set (start + inputWidth capacity s)
  pure (fresh capacity s start)

theorem allocate_run (capacity : Capacities) (s : Ty) (start : Nat) :
    (allocate capacity s).run start =
      (fresh capacity s start, start + inputWidth capacity s) := rfl

end Symbolic
