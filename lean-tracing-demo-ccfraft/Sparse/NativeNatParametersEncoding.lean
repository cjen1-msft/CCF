-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNatParameters
import Sparse.NativeDefinitionsEncoding
import Sparse.NativeFrameColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def natParameterDomainClauses : Nat -> Nat -> List (Expr .bool)
  | _, 0 => []
  | base, count + 1 =>
      .le (.integer 0) (.free .int base) ::
        natParameterDomainClauses (base + 1) count

theorem nat_parameter_domain_clauses_correct (assignment : Assignment)
    (base count : Nat) :
    Holds (natParameterDomainClauses base count) assignment <->
      forall index : Fin count,
        0 <= assignment .int (base + index.val) := by
  induction count generalizing base with
  | zero =>
    simp [natParameterDomainClauses, Holds]
  | succ count inductionHypothesis =>
    have split :
        Holds
            (.le (.integer 0) (.free .int base) ::
              natParameterDomainClauses (base + 1) count)
            assignment <->
          (.le (.integer 0) (.free .int base) : Expr .bool).eval
              assignment Locals.empty = true /\
            Holds (natParameterDomainClauses (base + 1) count) assignment := by
      simp [Holds, or_imp, forall_and]
    rw [natParameterDomainClauses, split]
    constructor
    · rintro ⟨first, rest⟩ index
      refine Fin.cases ?_ (fun tail => ?_) index
      · simpa [Term.eval] using first
      · have tailDomain :=
          (inductionHypothesis (base + 1)).mp rest tail
        have sameId :
            (base + 1) + tail.val = base + tail.succ.val := by
          rw [Fin.val_succ]
          omega
        rw [sameId] at tailDomain
        exact tailDomain
    · intro domains
      refine ⟨?_, (inductionHypothesis (base + 1)).mpr ?_⟩
      · simpa [Term.eval] using domains 0
      · intro index
        have sameId :
            (base + 1) + index.val = base + index.succ.val := by
          rw [Fin.val_succ]
          omega
        rw [sameId]
        exact domains index.succ

structure NatParametersResult {width : PNat} (count : Nat)
    (before after : Encoding width) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = before.toColumns
  next : after.next = before.next + count
  clauses : after.assertions.toList =
    before.assertions.toList ++ natParameterDomainClauses before.next count

theorem declare_nat_parameters_success {width : PNat} (count : Nat)
    (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after)) :
    NatParametersResult count before after := by
  induction count generalizing before after with
  | zero =>
    simp only [declareNatParameters, StateT.run, pure] at run
    have same := congrArg Prod.snd (Except.ok.inj run)
    dsimp only at same
    subst after
    constructor <;> simp [natParameterDomainClauses]
  | succ count inductionHypothesis =>
    simp only [declareNatParameters] at run
    obtain ⟨id, freshState, freshRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨unused, asserted, assertionRun, remainingRun⟩ :=
      (bind_run _ _ _ _ _).mp run
    cases unused
    obtain ⟨idEq, freshNext, freshBootstrap, freshColumns, freshClauses⟩ :=
      fresh_success before freshState id freshRun
    obtain ⟨assertionFrame, assertionClauses⟩ :=
      assertion_success _ freshState asserted assertionRun
    have remaining := inductionHypothesis asserted after remainingRun
    constructor
    · exact remaining.bootstrap.trans
        (assertionFrame.bootstrap.trans freshBootstrap)
    · exact remaining.columns.trans
        (assertionFrame.columns.trans freshColumns)
    · rw [remaining.next, assertionFrame.next, freshNext]
      omega
    · rw [remaining.clauses, assertionClauses, Array.toList_push,
        freshClauses, idEq, assertionFrame.next, freshNext]
      simp [natParameterDomainClauses, List.append_assoc]

theorem declare_nat_parameters_holds {width : PNat} (count : Nat)
    (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (natParameterDomainClauses before.next count) assignment := by
  rw [(declare_nat_parameters_success count before after run).clauses]
  simp [Holds, or_imp, forall_and]

theorem declare_nat_parameters_prior_holds {width : PNat} (count : Nat)
    (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment :=
  (declare_nat_parameters_holds count before after run assignment).mp holds |>.1

theorem declare_nat_parameters_references {width : PNat} (count : Nat)
    (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  have result := declare_nat_parameters_success count before after run
  cases valid
  constructor <;> simp only [result.columns, result.next] <;> omega

theorem declare_nat_parameters_sound {width : PNat} (count : Nat)
    (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    exists values : Fin count -> Nat,
      NatParametersRep assignment before.next values := by
  have domains :=
    (nat_parameter_domain_clauses_correct assignment before.next count).mp
      ((declare_nat_parameters_holds count before after run assignment).mp holds |>.2)
  let values : Fin count -> Nat :=
    fun index => (assignment .int (before.next + index.val)).toNat
  refine ⟨values, fun index => ?_⟩
  exact (Int.toNat_of_nonneg (domains index)).symm

theorem nat_parameters_assignment (assignment : Assignment) (base : Nat)
    {count : Nat} (values : Fin count -> Nat) :
    exists extended : Assignment,
      assignment.AgreesBelow base extended /\
        NatParametersRep extended base values := by
  induction count generalizing assignment base with
  | zero =>
    exact ⟨assignment, fun _ _ _ => rfl, fun index => Fin.elim0 index⟩
  | succ count inductionHypothesis =>
    let first := assignment.set .int base (values 0 : Int)
    have firstAgreement : assignment.AgreesBelow base first :=
      assignment.agrees_below_set base .int base (values 0 : Int) (le_refl _)
    obtain ⟨extended, tailAgreement, tailRep⟩ :=
      inductionHypothesis first (base + 1) (fun index => values index.succ)
    have agreement : assignment.AgreesBelow base extended :=
      firstAgreement.trans (tailAgreement.restrict (by omega))
    refine ⟨extended, agreement, ?_⟩
    intro index
    refine Fin.cases ?_ (fun tail => ?_) index
    · change extended .int base = (values 0 : Int)
      have same := tailAgreement .int base (by omega)
      rw [<- same]
      simp [first, Assignment.set]
    · change extended .int (base + (tail.val + 1)) =
        (values tail.succ : Int)
      have represented := tailRep tail
      have sameId : (base + 1) + tail.val = base + (tail.val + 1) := by
        omega
      rw [<- sameId]
      exact represented

theorem declare_nat_parameters_complete {width : PNat} (count : Nat)
    (values : Fin count -> Nat) (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      NatParametersRep extended before.next values := by
  obtain ⟨extended, agreement, rep⟩ :=
    nat_parameters_assignment assignment before.next values
  have previous : Holds before.assertions.toList extended :=
    before.holds_agrees_below assignment extended holds agreement
  have domains :
      Holds (natParameterDomainClauses before.next count) extended :=
    (nat_parameter_domain_clauses_correct extended before.next count).mpr
      (fun index => by rw [rep index]; exact Int.natCast_nonneg _)
  exact ⟨extended, agreement,
    (declare_nat_parameters_holds count before after run extended).mpr
      ⟨previous, domains⟩,
    rep⟩

theorem NatArgument.term_eval {count : Nat} (assignment : Assignment)
    (base : Nat) (values : Fin count -> Nat)
    (rep : NatParametersRep assignment base values)
    (argument : NatArgument count) :
    (argument.term base).eval assignment Locals.empty =
      (argument.value values : Int) := by
  cases argument with
  | literal value => simp [NatArgument.term, NatArgument.value, Term.eval]
  | parameter index =>
    simpa [NatArgument.term, NatArgument.value, Term.eval] using rep index

theorem NatArgument.term_bounded {count : Nat} (base boundary : Nat)
    (argument : NatArgument count) (bound : base + count <= boundary) :
    (argument.term base).symbols.all
      (fun symbol => symbol.2 < boundary) = true := by
  cases argument with
  | literal value => simp [NatArgument.term, Term.symbols]
  | parameter index =>
    simp [NatArgument.term, Term.symbols]
    omega

theorem NatParametersRep.agrees_below {count : Nat}
    (left right : Assignment) (base boundary : Nat)
    (values : Fin count -> Nat)
    (rep : NatParametersRep left base values)
    (bound : base + count <= boundary)
    (same : left.AgreesBelow boundary right) :
    NatParametersRep right base values := by
  intro index
  rw [<- same .int (base + index.val) (by omega)]
  exact rep index

theorem declare_nat_parameters_frame {width : PNat} (count : Nat)
    (before after : Encoding width)
    (run : (declareNatParameters count).run before = .ok ((), after))
    (left right : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep left before.toColumns frame)
    (valid : ReferencesValid before)
    (same : left.AgreesBelow before.next right) :
    FrameColumnsRep right after.toColumns frame := by
  have transported := rep.agrees_below before left right frame valid same
  simpa only [(declare_nat_parameters_success count before after run).columns]
    using transported

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
