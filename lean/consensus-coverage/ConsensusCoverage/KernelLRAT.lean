module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

/-!
# Kernel-only RUP/LRAT residual checker

Certifies that a propositional CNF (upper-bound constraints conjoined with the
negation of witnessed rows) is unsatisfiable, using a self-contained RUP/LRAT
checker whose verification reduces directly via `decide +kernel` with **no**
`native_decide` and **no** `Lean.ofReduceBool`.

Every theorem built with `KernelLRAT` depends only on the standard Lean axioms
`[propext, Classical.choice, Quot.sound]`.
-/

namespace ConsensusCoverage.KernelLRAT

public abbrev Lit := Nat × Bool
public abbrev Clause := List Lit
public abbrev Formula := List Clause

@[expose] public def evalLit (env : Nat → Bool) (l : Lit) : Bool :=
  env l.1 == l.2

@[expose] public def evalClause (env : Nat → Bool) (c : Clause) : Bool :=
  c.any (evalLit env)

@[expose] public def evalFormula (env : Nat → Bool) (f : Formula) : Bool :=
  f.all (evalClause env)

/-- Block a concrete bitvector `row` over variables `0 .. row.length - 1`: a clause asserting
that `env` differs from `row` on at least one coordinate. -/
@[expose] public def blockRowClause (row : List Bool) : Clause :=
  (row.zipIdx).map fun (b, i) => (i, !b)

/-- One step of a RUP/LRAT refutation certificate (0-indexed clause IDs into `f`). -/
public inductive Step where
  | addRup (clause : Clause) (hints : List Nat)
  | addEmpty (hints : List Nat)
  deriving Repr, DecidableEq

@[expose] public def litStatus (assign : List (Nat × Bool)) (l : Lit) : Option Bool :=
  match assign.lookup l.1 with
  | none => none
  | some v => some (v == l.2)

/-- Propagate a clause against an association-list assignment:
`some none` on conflict, `some (some u)` on unit, `none` if satisfied or >= 2 unassigned. -/
@[expose] public def unitProp (assign : List (Nat × Bool)) (c : Clause) : Option (Option Lit) :=
  go c none
where
  go : Clause → Option Lit → Option (Option Lit)
    | [], unit => some unit
    | l :: rest, unit =>
      match litStatus assign l with
      | some true => none
      | some false => go rest unit
      | none =>
        match unit with
        | none => go rest (some l)
        | some _ => none

@[expose] public def checkRupHints (f : Formula) (assign : List (Nat × Bool)) : List Nat → Bool
  | [] => false
  | idx :: rest =>
    match f[idx]? with
    | none => false
    | some c =>
      match unitProp assign c with
      | none => false
      | some none => true
      | some (some (v, pol)) => checkRupHints f ((v, pol) :: assign) rest

@[expose] public def negAssign (c : Clause) : List (Nat × Bool) :=
  c.map fun (v, pol) => (v, !pol)

/-- Verify a multi-step RUP/LRAT refutation of `f` purely functionally (reducible by
`decide +kernel` without `native_decide`). -/
@[expose] public def checkProof (f : Formula) : List Step → Bool
  | [] => false
  | .addEmpty hints :: _ => checkRupHints f [] hints
  | .addRup c hints :: rest =>
    if checkRupHints f (negAssign c) hints then
      checkProof (f ++ [c]) rest
    else false

private def Agree (env : Nat → Bool) (assign : List (Nat × Bool)) : Prop :=
  ∀ v b, assign.lookup v = some b → env v = b

private theorem litStatus_eq (env : Nat → Bool) (assign : List (Nat × Bool))
    (h : Agree env assign) (l : Lit) (b : Bool) (hs : litStatus assign l = some b) :
    evalLit env l = b := by
  unfold litStatus at hs
  cases hl : assign.lookup l.1 with
  | none => simp [hl] at hs
  | some v =>
    simp [hl] at hs
    have hv := h l.1 v hl
    simp [evalLit, hv, hs]

private theorem unitProp_go_sound (env : Nat → Bool) (assign : List (Nat × Bool))
    (h : Agree env assign) (c : Clause) (acc : Option Lit) (res : Option Lit)
    (hc : evalClause env c = true ∨ (∃ u, acc = some u ∧ evalLit env u = true))
    (hu : unitProp.go assign c acc = some res) :
    ∃ u, res = some u ∧ evalLit env u = true := by
  induction c generalizing acc with
  | nil =>
    simp [unitProp.go] at hu
    rcases hc with h1 | ⟨u, ha, he⟩
    · simp [evalClause] at h1
    · exact ⟨u, hu ▸ ha, he⟩
  | cons l rest ih =>
    simp only [unitProp.go] at hu
    cases hst : litStatus assign l with
    | some b =>
      cases b with
      | true => simp [hst] at hu
      | false =>
        simp [hst] at hu
        have hlf : evalLit env l = false := litStatus_eq env assign h l false hst
        apply ih acc _ hu
        rcases hc with h1 | h2
        · left; simpa [evalClause, hlf] using h1
        · right; exact h2
    | none =>
      cases acc with
      | none =>
        simp [hst] at hu
        apply ih (some l) _ hu
        rcases hc with h1 | ⟨u, ha, _⟩
        · simp only [evalClause, List.any_cons, Bool.or_eq_true] at h1
          rcases h1 with hl | hr
          · right; exact ⟨l, rfl, hl⟩
          · left; exact hr
        · cases ha
      | some _ => simp [hst] at hu

private theorem unitProp_sound (env : Nat → Bool) (assign : List (Nat × Bool))
    (h : Agree env assign) (c : Clause) (hc : evalClause env c = true) :
    match unitProp assign c with
    | none => True
    | some none => False
    | some (some u) => evalLit env u = true := by
  cases hu : unitProp assign c with
  | none => trivial
  | some res =>
    have ⟨u, hres, he⟩ := unitProp_go_sound env assign h c none res (Or.inl hc) hu
    subst hres
    exact he

private theorem agree_cons (env : Nat → Bool) (assign : List (Nat × Bool))
    (h : Agree env assign) (v : Nat) (pol : Bool) (hev : env v = pol) :
    Agree env ((v, pol) :: assign) := by
  intro w b hl
  simp only [List.lookup] at hl
  cases hvw : (w == v) with
  | true =>
    simp [hvw] at hl
    have : w = v := beq_iff_eq.mp hvw
    subst this
    rw [← hl]
    exact hev
  | false =>
    simp [hvw] at hl
    exact h w b hl

private theorem checkRupHints_sound (env : Nat → Bool) (f : Formula)
    (hf : evalFormula env f = true) (assign : List (Nat × Bool)) (ha : Agree env assign)
    (hints : List Nat) (ok : checkRupHints f assign hints = true) : False := by
  induction hints generalizing assign with
  | nil => simp [checkRupHints] at ok
  | cons idx rest ih =>
    simp only [checkRupHints] at ok
    cases hget : f[idx]? with
    | none => simp [hget] at ok
    | some c =>
      simp only [hget] at ok
      have hmem : c ∈ f := List.mem_of_getElem? hget
      have hc : evalClause env c = true := (List.all_eq_true.mp hf) c hmem
      have hup := unitProp_sound env assign ha c hc
      cases hu : unitProp assign c with
      | none => simp [hu] at ok
      | some res =>
        rw [hu] at hup ok
        cases res with
        | none => exact hup
        | some u =>
          have hev : env u.1 = u.2 := beq_iff_eq.mp hup
          exact ih ((u.1, u.2) :: assign) (agree_cons env assign ha u.1 u.2 hev) ok

private theorem negAssign_agree (env : Nat → Bool) (c : Clause)
    (hc : evalClause env c = false) : Agree env (negAssign c) := by
  induction c with
  | nil => intro v b hl; simp [negAssign] at hl
  | cons l rest ih =>
    simp only [evalClause, List.any_cons, Bool.or_eq_false_iff] at hc
    have hlf : env l.1 = !l.2 := by
      cases h1 : env l.1 <;> cases h2 : l.2 <;> simp [evalLit, h1, h2] at hc ⊢
    exact agree_cons env (negAssign rest) (ih hc.2) l.1 (!l.2) hlf

/-- Soundness theorem: any accepted RUP/LRAT proof certifies `evalFormula env f ≠ true`. -/
public theorem checkProof_sound (env : Nat → Bool) (f : Formula) (steps : List Step)
    (hf : evalFormula env f = true) (ok : checkProof f steps = true) : False := by
  induction steps generalizing f with
  | nil => simp [checkProof] at ok
  | cons s rest ih =>
    cases s with
    | addEmpty hints =>
      simp only [checkProof] at ok
      exact checkRupHints_sound env f hf [] (fun _ _ h => by simp at h) hints ok
    | addRup c hints =>
      simp only [checkProof] at ok
      cases hrup : checkRupHints f (negAssign c) hints with
      | false => simp [hrup] at ok
      | true =>
        simp only [hrup, ↓reduceIte] at ok
        have hc : evalClause env c = true := by
          cases hce : evalClause env c with
          | true => rfl
          | false =>
            exact (checkRupHints_sound env f hf (negAssign c)
              (negAssign_agree env c hce) hints hrup).elim
        have hf' : evalFormula env (f ++ [c]) = true := by
          rw [evalFormula, List.all_append, Bool.and_eq_true]
          exact ⟨hf, by simp [hc]⟩
        exact ih (f ++ [c]) hf' ok

public theorem eval_blockRowClause_of_false {row : List Bool} {env : Nat → Bool}
    (h : evalClause env (blockRowClause row) = false) :
    ∀ (i : Nat) (hi : i < row.length), env i = row[i] := by
  intro i hi
  unfold blockRowClause evalClause at h
  simp only [List.any_eq_false, List.mem_map, Prod.exists, forall_exists_index, and_imp] at h
  have hmem : (row[i], i) ∈ row.zipIdx := by
    have hidx : i < row.zipIdx.length := by simp [hi]
    have hget : row.zipIdx[i] = (row[i], i) := by simp
    rw [← hget]
    exact List.getElem_mem hidx
  have hne := h (i, !row[i]) row[i] i hmem rfl
  cases hri : row[i] <;> cases hei : env i <;> simp [evalLit, hri, hei] at hne ⊢

/-- Core residual-closure theorem: if every real assignment satisfies `upper`, and
`upper ++ (rows.map blockRowClause)` has an accepted RUP/LRAT refutation `steps`,
then the assignment's `len`-bit vector lies in `rows`. -/
public theorem mem_rows_of_checkProof {rows : List (List Bool)} {upper : Formula}
    {steps : List Step}
    (ok : checkProof (upper ++ rows.map blockRowClause) steps = true)
    (env : Nat → Bool) (hUpper : evalFormula env upper = true)
    (len : Nat) (hLen : ∀ r ∈ rows, r.length = len) :
    (List.ofFn (fun i : Fin len => env i.val)) ∈ rows := by
  exact Classical.byContradiction fun hNotMem => by
    apply checkProof_sound env (upper ++ rows.map blockRowClause) steps _ ok
    rw [evalFormula, List.all_append, Bool.and_eq_true]
    refine ⟨hUpper, ?_⟩
    rw [List.all_eq_true]
    intro c hc
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hc
    cases hEval : evalClause env (blockRowClause r) with
    | true => rfl
    | false =>
      exfalso
      apply hNotMem
      have hagree := eval_blockRowClause_of_false hEval
      have hrl := hLen r hr
      have heq : List.ofFn (fun j : Fin len => env j.val) = r := by
        apply List.ext_getElem
        · simp [hrl]
        · intro k hk1 hk2
          simp only [List.getElem_ofFn]
          exact hagree k hk2
      rw [heq]
      exact hr

/-! Self-tests: positive multi-step closure and negative rejection of a corrupted certificate. -/
section SelfTests

private def sampleFormula : Formula := [
  [(0, false), (1, true), (2, true)],
  [(0, true)],
  [(1, false)],
  [(2, false)]]

private theorem sample_unsat (env : Nat → Bool) (h : evalFormula env sampleFormula = true) :
    False :=
  checkProof_sound env sampleFormula [.addEmpty [1, 2, 3, 0]] h (by decide +kernel)

-- Corrupted hint must fail the kernel checker (`checkProof` returns `false`, not `true`).
private theorem corrupted_rejected :
    checkProof sampleFormula [.addEmpty [1, 2]] = false := by
  decide +kernel

-- Full multi-step residual closure demo: 2-bit table where bit 0 = bit 1 (rows FF, TT).
private def eqUpper : Formula := [[(0, false), (1, true)], [(0, true), (1, false)]]
private def eqRows : List (List Bool) := [[false, false], [true, true]]

private theorem eq_closed (env : Nat → Bool) (h : evalFormula env eqUpper = true) :
    (List.ofFn (fun i : Fin 2 => env i.val)) ∈ eqRows :=
  mem_rows_of_checkProof (rows := eqRows) (upper := eqUpper)
    (steps := [.addRup [(0, true)] [2, 1], .addEmpty [4, 0, 3]])
    (by decide +kernel) env h 2 (by decide)

end SelfTests

end ConsensusCoverage.KernelLRAT
