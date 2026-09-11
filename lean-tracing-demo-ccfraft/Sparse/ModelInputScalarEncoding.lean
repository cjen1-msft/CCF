-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ModelInputSyntax
import Sparse.StateFrameEncoding
import Sparse.ScalarExtension

set_option autoImplicit false

/-!
Source scalars use mathematical Int casts, not Entry raw codes. Every declared
source slot has a nonnegative domain, whether or not the syntax mentions it.
One total ModelTrace assignment interprets numeric atoms and their zero tests.
No observations, actions, parser, or state-completion encoder is defined here.
-/

namespace CCFRaft.Sparse.ModelInputScalarEncoding

open Smt (Assignment Term Symbol Ty)
open ModelInputSyntax (NatAtom BoolAtom)
open ModelTrace (UnknownNatAssignment)

variable {n : Nat}

def sourceRef (base : Nat) (index : Fin n) : StateFrame.ConstRef .int :=
  { id := base + index.val }

def highwater (base n : Nat) : Nat := base + n

theorem source_ref_injective (base : Nat) :
    Function.Injective (sourceRef (n := n) base) := by
  intro left right same
  have ids := congrArg StateFrame.ConstRef.id same
  apply Fin.ext
  simpa [sourceRef] using ids

theorem source_ref_bounds (base : Nat) (index : Fin n) :
    base <= (sourceRef base index).id /\
      (sourceRef base index).id < highwater base n := by
  have bound := index.isLt
  simp only [sourceRef, highwater]
  omega

theorem reserved_iff (base n id : Nat) :
    (exists index : Fin n, (sourceRef base index).id = id) <->
      base <= id /\ id < highwater base n := by
  constructor
  next =>
    intro found
    cases found with
    | intro index same =>
      rw [<- same]
      exact source_ref_bounds base index
  next =>
    intro inside
    refine Exists.intro (Fin.mk (id - base) (by simp only [highwater] at inside; omega)) ?_
    simp only [sourceRef]
    omega

def SourceRep (assignment : Assignment) (base n : Nat) (rho : UnknownNatAssignment) : Prop :=
  forall index : Fin n, (sourceRef base index).eval assignment = (rho index.val : Int)

def sourceNat (base : Nat) : NatAtom n -> Term .int
  | .literal value => .integer (value : Int)
  | .unknown index => StateFrameEncoding.refTerm (sourceRef base index)

def sourceBool (base : Nat) : BoolAtom n -> Term .bool
  | .literal value => .boolean value
  | .isZero value => .equal (sourceNat base value) (.integer 0)

def sourceOption (base : Nat) : Option (NatAtom n) -> Term .int
  | none => .integer 0
  | some value => .add (sourceNat base value) (.integer 1)

theorem source_nat_eval (assignment : Assignment) (base : Nat) (rho : UnknownNatAssignment)
    (rep : SourceRep assignment base n rho) (value : NatAtom n) :
    (sourceNat base value).eval assignment = (value.eval rho : Int) := by
  cases value with
  | literal _ => rfl
  | unknown index => exact rep index

theorem source_bool_eval (assignment : Assignment) (base : Nat) (rho : UnknownNatAssignment)
    (rep : SourceRep assignment base n rho) (value : BoolAtom n) :
    (sourceBool base value).eval assignment = value.eval rho := by
  cases value with
  | literal _ => rfl
  | isZero value =>
    simp [sourceBool, Term.eval, source_nat_eval assignment base rho rep, BoolAtom.eval]

theorem source_option_eval (assignment : Assignment) (base : Nat) (rho : UnknownNatAssignment)
    (rep : SourceRep assignment base n rho) (value : Option (NatAtom n)) :
    (sourceOption base value).eval assignment =
      StateFrame.optionNatCode (value.map (NatAtom.eval rho)) := by
  cases value with
  | none => rfl
  | some value =>
    simp [sourceOption, Term.eval, source_nat_eval assignment base rho rep,
      StateFrame.optionNatCode]

def Domains (assignment : Assignment) (base n : Nat) : Prop :=
  forall index : Fin n, 0 <= (sourceRef base index).eval assignment

def encodeDomains (base n : Nat) : SmtScript.Formula :=
  List.ofFn fun index : Fin n => StateFrameEncoding.nonnegative (sourceRef base index)

theorem formula_correct (assignment : Assignment) (base n : Nat) :
    SmtScript.Holds assignment (encodeDomains base n) <-> Domains assignment base n := by
  unfold SmtScript.Holds encodeDomains
  rw [List.forall_mem_ofFn_iff]
  simp [StateFrameEncoding.nonnegative, StateFrameEncoding.refTerm,
    Term.eval, Domains, StateFrame.ConstRef.eval]

theorem domains_iff_source_rep (assignment : Assignment) (base n : Nat) :
    Domains assignment base n <-> exists rho, SourceRep assignment base n rho := by
  constructor
  next =>
    intro valid
    refine Exists.intro (fun id => (assignment.constant .int (base + id)).toNat) ?_
    intro index
    exact (Int.toNat_of_nonneg (valid index)).symm
  next =>
    intro found index
    cases found with
    | intro rho rep =>
      rw [rep index]
      exact Int.natCast_nonneg _

theorem formula_iff_source_rep (assignment : Assignment) (base n : Nat) :
    SmtScript.Holds assignment (encodeDomains base n) <->
      exists rho, SourceRep assignment base n rho :=
  (formula_correct assignment base n).trans (domains_iff_source_rep assignment base n)

theorem text_iff_source_rep (assignment : Assignment) (base n : Nat) :
    SmtScriptText.runText assignment (SmtScript.render (encodeDomains base n)) = some true <->
      exists rho, SourceRep assignment base n rho :=
  (SmtScriptText.formula_text_iff assignment (encodeDomains base n)).symm.trans
    (formula_iff_source_rep assignment base n)

theorem source_rep_unique_on_block (assignment : Assignment) (base : Nat)
    (left right : UnknownNatAssignment)
    (hl : SourceRep assignment base n left) (hr : SourceRep assignment base n right)
    (index : Fin n) : left index.val = right index.val := by
  exact Int.ofNat_inj.mp ((hl index).symm.trans (hr index))

theorem formula_length (base n : Nat) : (encodeDomains base n).length = n :=
  List.length_ofFn

theorem domain_symbols (base n : Nat) (symbol : Symbol) :
    Membership.mem (SmtScript.symbols (encodeDomains base n)) symbol <->
      exists index : Fin n, symbol = (sourceRef base index).symbol := by
  simp only [SmtScript.symbols, List.mem_dedup, List.mem_flatMap]
  constructor
  next =>
    intro found
    cases found with
    | intro term facts =>
      cases List.mem_ofFn.mp facts.1 with
      | intro index same =>
        subst term
        refine Exists.intro index ?_
        simpa [StateFrameEncoding.nonnegative, StateFrameEncoding.refTerm,
          SmtScript.termSymbols, StateFrame.ConstRef.symbol] using facts.2
  next =>
    intro found
    cases found with
    | intro index same =>
      subst symbol
      refine Exists.intro (StateFrameEncoding.nonnegative (sourceRef base index))
        (And.intro (List.mem_ofFn.mpr (Exists.intro index rfl)) ?_)
      simp [StateFrameEncoding.nonnegative, StateFrameEncoding.refTerm,
        SmtScript.termSymbols, StateFrame.ConstRef.symbol]

theorem source_rep_congr (assignment : Assignment) (base : Nat)
    (left right : UnknownNatAssignment)
    (same : forall index : Fin n, left index.val = right index.val) :
    SourceRep assignment base n left <-> SourceRep assignment base n right := by
  apply forall_congr'
  intro index
  rw [same index]

theorem install_source_rep (original : Assignment) (base n : Nat) (rho : UnknownNatAssignment) :
    SourceRep
      (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int)))
      base n rho :=
  fun index => ScalarExtension.at_index original base _ index

theorem install_domains (original : Assignment) (base n : Nat) (rho : UnknownNatAssignment) :
    SmtScript.Holds
      (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int)))
      (encodeDomains base n) :=
  (formula_iff_source_rep _ base n).mpr
    (Exists.intro rho (install_source_rep original base n rho))

theorem install_outside (original : Assignment) (base n : Nat) (rho : UnknownNatAssignment)
    (ty : Ty) (id : Nat) (outside : id < base \/ highwater base n <= id) :
    (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int))).constant
      ty id = original.constant ty id :=
  ScalarExtension.outside original base _ ty id outside

theorem install_other_sort (original : Assignment) (base n : Nat) (rho : UnknownNatAssignment)
    (ty : Ty) (id : Nat) (other : Not (ty = .int)) :
    (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int))).constant
      ty id = original.constant ty id := by
  cases ty with
  | int => exact False.elim (other rfl)
  | bool | nodes | content | entry => rfl

theorem install_nonconstants (original : Assignment) (base n : Nat) (rho : UnknownNatAssignment) :
    (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int))).unary =
      original.unary /\
    (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int))).selectors =
      original.selectors :=
  And.intro (ScalarExtension.unary_preserved original base _)
    (ScalarExtension.selectors_preserved original base _)

-- Other sorts may share numeric IDs with the source block without being overwritten.
def FrameDisjoint {roots versions : Nat} (base n : Nat) (frame : StateFrame.Frame roots versions) :
    Prop :=
  forall id, Membership.mem frame.symbols (.constant .int id) ->
    id < base \/ highwater base n <= id

theorem install_frame_agree {roots versions : Nat} (original : Assignment) (base n : Nat)
    (rho : UnknownNatAssignment) (frame : StateFrame.Frame roots versions)
    (separate : FrameDisjoint base n frame) :
    StateFrame.Agree frame.symbols
      (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int)))
      original := by
  intro ty id member
  by_cases integer : ty = .int
  next =>
    subst ty
    exact install_outside original base n rho .int id (separate id member)
  next => exact install_other_sort original base n rho ty id integer

theorem install_frame_rep {roots versions : Nat} (original : Assignment) (base n : Nat)
    (rho : UnknownNatAssignment) (graph : StateFrame.Graph roots versions)
    (arrays : StateFrame.Roots roots) (submitted : Finset Nat)
    (frame : StateFrame.Frame roots versions) (state : StateFrame.ModelState)
    (separate : FrameDisjoint base n frame) :
    StateFrame.Rep
      (ScalarExtension.install original base (fun index : Fin n => (rho index.val : Int)))
      graph arrays submitted frame state <->
    StateFrame.Rep original graph arrays submitted frame state :=
  StateFrame.rep_congr graph arrays submitted frame state
    (install_frame_agree original base n rho frame separate)

theorem negative_declared_rejected (assignment : Assignment) (base : Nat) (index : Fin n)
    (negative : (sourceRef base index).eval assignment < 0) :
    Not (SmtScript.Holds assignment (encodeDomains base n)) := by
  intro accepted
  exact (not_lt_of_ge ((formula_correct assignment base n).mp accepted index)) negative

namespace Regression

theorem shared_numeric_bool_two (original : Assignment) :
    let assignment := ScalarExtension.install original 10 (fun _ : Fin 1 => (2 : Int))
    SourceRep assignment 10 1 (fun _ => 2) /\
    SmtScript.Holds assignment (encodeDomains 10 1) /\
    (sourceNat 10 (.unknown (0 : Fin 1))).eval assignment = 2 /\
    (sourceBool 10 (.isZero (.unknown (0 : Fin 1)))).eval assignment = false := by
  dsimp only
  have rep := install_source_rep original 10 1 (fun _ => 2)
  refine And.intro rep (And.intro (install_domains original 10 1 (fun _ => 2)) (And.intro ?_ ?_))
  next => exact source_nat_eval _ 10 _ rep (.unknown 0)
  next => exact source_bool_eval _ 10 _ rep (.isZero (.unknown 0))

theorem distinct_names_equal_values (original : Assignment) (base : Nat) :
    Not (sourceRef base (0 : Fin 2) = sourceRef base (1 : Fin 2)) /\
    let assignment := ScalarExtension.install original base (fun _ : Fin 2 => (7 : Int))
    SourceRep assignment base 2 (fun _ => 7) /\
    (sourceNat base (.unknown (0 : Fin 2))).eval assignment =
      (sourceNat base (.unknown (1 : Fin 2))).eval assignment := by
  constructor
  next =>
    intro same
    have impossible := source_ref_injective base same
    exact (by decide : Not ((0 : Fin 2) = 1)) impossible
  next =>
    dsimp only
    have rep := install_source_rep original base 2 (fun _ => 7)
    refine And.intro rep ?_
    exact (source_nat_eval _ base _ rep (.unknown 0)).trans
      (source_nat_eval _ base _ rep (.unknown 1)).symm

theorem negative_unused (assignment : Assignment) (negative : assignment.constant .int 12 = -1) :
    (sourceNat 10 (.literal 1 : NatAtom 3)).eval assignment = 1 /\
    Not (SmtScript.Holds assignment (encodeDomains 10 3)) := by
  refine And.intro rfl (negative_declared_rejected assignment 10 (2 : Fin 3) ?_)
  change assignment.constant .int 12 < 0
  rw [negative]
  decide

theorem unused_reserved :
    SmtScript.termSymbols (sourceNat 10 (.unknown (0 : Fin 3))) = [.constant .int 10] /\
    Membership.mem (SmtScript.symbols (encodeDomains 10 3)) (.constant .int 12) /\
    highwater 10 3 = 13 := by
  exact And.intro rfl (And.intro ((domain_symbols 10 3 _).mpr (Exists.intro 2 rfl)) rfl)

theorem none_some_zero (assignment : Assignment) (base : Nat) :
    (sourceOption base (none : Option (NatAtom n))).eval assignment = 0 /\
    (sourceOption base (some (.literal 0) : Option (NatAtom n))).eval assignment = 1 := by
  constructor <;> rfl

theorem expected_nat_one (assignment : Assignment) (base : Nat) :
    sourceNat base (.literal 1 : NatAtom n) = .integer 1 /\
    Not ((sourceNat base (.literal 1 : NatAtom n)).eval assignment = -1) := by
  constructor
  next => rfl
  next =>
    change Not ((1 : Int) = -1)
    decide

theorem literal_constant_shape (base value : Nat) :
    sourceNat base (.literal value : NatAtom n) = .integer (value : Int) /\
    SmtScript.termSymbols (sourceNat base (.literal value : NatAtom n)) = [] := by
  constructor <;> rfl

theorem million_literal (base : Nat) :
    (sourceNat base (.literal 1000000 : NatAtom n)).lower =
      .atom (.numeral 1000000) := rfl

theorem empty_block (assignment : Assignment) (base : Nat) :
    SmtScript.Holds assignment (encodeDomains base 0) :=
  (formula_correct assignment base 0).mpr fun index => Fin.elim0 index

theorem nonoverlap_endpoints (original : Assignment) (rho : UnknownNatAssignment) (ty : Ty) :
    (ScalarExtension.install original 10 (fun index : Fin 3 => (rho index.val : Int))).constant
      ty 9 = original.constant ty 9 /\
    (ScalarExtension.install original 10 (fun index : Fin 3 => (rho index.val : Int))).constant
      ty 13 = original.constant ty 13 :=
  And.intro (install_outside original 10 3 rho ty 9 (Or.inl (by decide)))
    (install_outside original 10 3 rho ty 13 (Or.inr (by decide)))

theorem overlapping_ref_changes (original : Assignment) (different : Not (original.constant .int 10 = 2)) :
    Not ((sourceRef 10 (0 : Fin 1)).eval
      (ScalarExtension.install original 10 (fun _ : Fin 1 => (2 : Int))) =
      (sourceRef 10 (0 : Fin 1)).eval original) := by
  intro same
  apply different
  exact same.symm.trans (install_source_rep original 10 1 (fun _ => 2) 0)

end Regression

end CCFRaft.Sparse.ModelInputScalarEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ModelInputScalarEncoding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit ModelInputScalarEncoding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ModelInputScalarEncoding: {checked} declarations passed the transitive axiom gate."
