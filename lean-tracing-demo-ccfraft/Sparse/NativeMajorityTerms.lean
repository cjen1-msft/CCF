-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeValues

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

private def sumTerms {context : List Ty} : List (Term context .int) -> Term context .int
  | [] => .integer 0
  | value :: rest => .add value (sumTerms rest)

def countNodesTerm {context : List Ty} {width : PNat}
    (predicate : Fin width -> Term context .bool) : Term context .int :=
  sumTerms (List.ofFn fun node : Fin width =>
    .ite (predicate node) (.integer 1) (.integer 0))

def bitCardinalityTerm {context : List Ty} {width : PNat}
    (value : Term context (.bits width)) : Term context .int :=
  countNodesTerm fun node => .bit value node

def configurationMajorityTerm {context : List Ty} {width : PNat}
    (configuration : Term context (.bits width))
    (support : Fin width -> Term context .bool) : Term context .bool :=
  let hits := countNodesTerm fun node => .and (.bit configuration node) (support node)
  .not (.le (.add hits hits) (bitCardinalityTerm configuration))

private theorem sum_terms_eval {context : List Ty} (terms : List (Term context .int))
    (assignment : Assignment) (locals : Locals context) :
    (sumTerms terms).eval assignment locals =
      (terms.map (Term.eval assignment locals)).sum := by
  induction terms with
  | nil => rfl
  | cons value rest ih => simp [sumTerms, Term.eval, ih]

private theorem sum_terms_bounded {context : List Ty}
    (terms : List (Term context .int)) (limit : Nat)
    (bounded : forall term, term ∈ terms ->
      term.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (sumTerms terms).symbols.all (fun symbol => symbol.2 < limit) = true := by
  induction terms with
  | nil => simp [sumTerms, Term.symbols]
  | cons value rest ih =>
      simp only [sumTerms, Term.symbols, List.all_append, Bool.and_eq_true]
      exact ⟨bounded value (by simp), ih (fun term member =>
        bounded term (by simp [member]))⟩

theorem count_nodes_term_bounded {context : List Ty} {width : PNat}
    (predicate : Fin width -> Term context .bool) (limit : Nat)
    (bounded : forall node,
      (predicate node).symbols.all (fun symbol => symbol.2 < limit) = true) :
    (countNodesTerm predicate).symbols.all
      (fun symbol => symbol.2 < limit) = true := by
  unfold countNodesTerm
  apply sum_terms_bounded
  intro term member
  rw [List.mem_ofFn] at member
  obtain ⟨node, rfl⟩ := member
  simpa [Term.symbols] using bounded node

theorem bit_cardinality_term_bounded {context : List Ty} {width : PNat}
    (value : Term context (.bits width)) (limit : Nat)
    (bounded :
      value.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (bitCardinalityTerm value).symbols.all
      (fun symbol => symbol.2 < limit) = true := by
  apply count_nodes_term_bounded
  intro node
  simpa [Term.symbols] using bounded

theorem configuration_majority_term_bounded {context : List Ty} {width : PNat}
    (configuration : Term context (.bits width))
    (support : Fin width -> Term context .bool) (limit : Nat)
    (configurationBounded :
      configuration.symbols.all (fun symbol => symbol.2 < limit) = true)
    (supportBounded : forall node,
      (support node).symbols.all (fun symbol => symbol.2 < limit) = true) :
    (configurationMajorityTerm configuration support).symbols.all
      (fun symbol => symbol.2 < limit) = true := by
  have hitsBounded :
      (countNodesTerm fun node =>
        .and (.bit configuration node) (support node)).symbols.all
          (fun symbol => symbol.2 < limit) = true := by
    apply count_nodes_term_bounded
    intro node
    simp [Term.symbols, configurationBounded, supportBounded node]
  have totalBounded :=
    bit_cardinality_term_bounded configuration limit configurationBounded
  simp [configurationMajorityTerm, Term.symbols, hitsBounded, totalBounded]

theorem count_nodes_term_eval {context : List Ty} {width : PNat}
    (predicate : Fin width -> Term context .bool)
    (assignment : Assignment) (locals : Locals context) :
    (countNodesTerm predicate).eval assignment locals =
      ((Finset.univ.filter fun node =>
        (predicate node).eval assignment locals = true).card : Int) := by
  unfold countNodesTerm
  rw [sum_terms_eval, List.map_ofFn, List.sum_ofFn]
  simp only [Function.comp_def, Term.eval]
  rw [Finset.sum_boole]

theorem bit_cardinality_term_eval {context : List Ty} {width : PNat}
    (value : Term context (.bits width))
    (assignment : Assignment) (locals : Locals context) :
    (bitCardinalityTerm value).eval assignment locals =
      ((decodeBits (value.eval assignment locals)).card : Int) := by
  rw [bitCardinalityTerm, count_nodes_term_eval]
  congr 1

theorem configuration_majority_term_eval {context : List Ty} {width : PNat}
    (configuration : Term context (.bits width))
    (supportTerm : Fin width -> Term context .bool)
    (assignment : Assignment) (locals : Locals context)
    (configurationNodes : Finset (Fin width)) (support : Fin width -> Prop)
    [DecidablePred support]
    (sameConfiguration :
      configuration.eval assignment locals = encodeBits configurationNodes)
    (sameSupport : forall node,
      (supportTerm node).eval assignment locals = true <-> support node) :
    (configurationMajorityTerm configuration supportTerm).eval assignment locals =
      decide ((configurationNodes.filter support).card * 2 > configurationNodes.card) := by
  have hits :
      (Finset.univ.filter fun node =>
        ((Term.and (.bit configuration node) (supportTerm node)).eval
          assignment locals = true)) =
        configurationNodes.filter support := by
    ext node
    have bitMember :
        (encodeBits configurationNodes).getLsbD node.val = true <->
          node ∈ configurationNodes := by
      rw [encode_bits_bit, decide_eq_true_eq]
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Term.eval,
      Bool.and_eq_true, sameConfiguration, sameSupport, bitMember]
  have total :
      decodeBits (configuration.eval assignment locals) = configurationNodes := by
    rw [sameConfiguration, decode_encode_bits]
  have arithmetic (hitCount totalCount : Nat) :
      Not ((hitCount : Int) + (hitCount : Int) <= (totalCount : Int)) <->
        hitCount * 2 > totalCount := by
    omega
  change Bool.not (decide (
    (countNodesTerm fun node =>
      .and (.bit configuration node) (supportTerm node)).eval assignment locals +
    (countNodesTerm fun node =>
      .and (.bit configuration node) (supportTerm node)).eval assignment locals <=
    (bitCardinalityTerm configuration).eval assignment locals)) = _
  rw [count_nodes_term_eval, bit_cardinality_term_eval, hits, total]
  simp only [<- decide_not, arithmetic]

@[simp] theorem configuration_majority_term_empty_eval {context : List Ty}
    {width : PNat} (configuration : Term context (.bits width))
    (supportTerm : Fin width -> Term context .bool)
    (assignment : Assignment) (locals : Locals context)
    (emptyConfiguration :
      configuration.eval assignment locals =
        encodeBits (∅ : Finset (Fin width))) :
    (configurationMajorityTerm configuration supportTerm).eval assignment locals =
      false := by
  let support : Fin width -> Prop := fun node =>
    (supportTerm node).eval assignment locals = true
  rw [configuration_majority_term_eval configuration supportTerm assignment locals
    ∅ support emptyConfiguration (fun _ => Iff.rfl)]
  simp

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
