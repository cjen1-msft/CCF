module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCLogSites
import all ConsensusCoverage.HandReadersTrunkCSent
import all ConsensusCoverage.HandReadersTrunkCCommit
import all ConsensusCoverage.HandReadersTrunkAAdvance
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkCLogSites

namespace ConsensusCoverage.HandReadersTrunkC.LogSites

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open Lean Meta Elab Command HandReadersA ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1200000

private abbrev Origin := NodeID → NodeState → NodeState → Prop

private theorem identityJoin (l c s : Origin) (h : ∀ n m st, l n m st ↔ c n m st ∨ s n m st)
    (g : NodeID → NodeState → Prop) :
    (∃ n m, l n m m ∧ g n m) ↔ (∃ n m, c n m m ∧ g n m) ∨ (∃ n m, s n m m ∧ g n m) := by
  simp only [h,or_and_right,exists_or]

private theorem strictJoin (l c s : Origin) (h : ∀ n m st, l n m st ↔ c n m st ∨ s n m st)
    (g : Origin) : (∃ n m st, l n m st ∧ g n m st) ↔
    (∃ n m st, c n m st ∧ g n m st) ∨ (∃ n m st, s n m st ∧ g n m st) := by
  simp only [h,or_and_right,exists_or]

private theorem combine {a b c d x y : Prop} (h : x ↔ a ∨ b) (k : y ↔ c ∨ d) :
    (x ∨ y) ↔ (a ∨ c) ∨ (b ∨ d) := by grind

run_cmd liftTermElabM do
  for (n,c,s,lemma) in [( ``step_log_advance_inr,``step_commit_le_advance_inr,``step_sentIndex_advance_inr,``strictJoin),
      (``step_log_advance_inl,``step_commit_le_advance_inl,``step_sentIndex_advance_inl,``identityJoin)] do
    let children (name : Name) : MetaM (Array Name) := do return ReachPath.children name.getPrefix (←getConstInfo name).value!
    let ls ← children n
    let cs ← children c
    let ss ← children s
    lambdaTelescope (←getConstInfo n).value! fun xs p => do
      let rec tail (k : Nat) (a : Expr) (vs : Array Expr) : MetaM Expr :=
        match k with
        | 0 => mkLambdaFVars vs a.appArg!
        | k+1 => withLocalDeclD `w (a.getArg! 0) fun w => tail k (a.appArg!.beta #[w]) (vs.push w)
      let g ←tail (if lemma == ``strictJoin then 3 else 2) (p.getArg! 0) #[]
      let sites := ls.mapIdx fun i l => mkAppN (mkConst lemma) ((#[l,cs[i]!,ss[i]!,siteName l].map
        fun name => mkAppN (mkConst name) xs).push g)
      let mut pf := sites.back!
      for v in sites.toList.dropLast.reverse do pf ←mkAppM ``combine #[v,pf]
      let rhs := mkApp2 (mkConst ``Or) (mkAppN (mkConst c) xs) (mkAppN (mkConst s) xs)
      addDecl (.thmDecl {
        name := siteName n,levelParams := [],type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,rhs])
        value := ←mkLambdaFVars xs pf })

def identity : Exact .log_advance_inl where
  eval := fun cfg pre act post past => HandReadersTrunkA.Batch.commitIdentity.eval cfg pre act post past ||
    Sent.identity.eval cfg pre act post past
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Bool.or_eq_true,←HandReadersTrunkA.Batch.commitIdentity.eq_label s,←Sent.identity.eq_label s]
    simp only [label_true,holds,sig_iff]
    exact Iff.step_log_advance_inl _ _ _

def strict : Exact .log_advance_inr where
  eval := Batch.commitStrict.eval
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have no : ¬ sig s.context .sentIndex_advance_inr := by
      intro h
      have yes := (label_true s (.step .sentIndex_advance_inr)).mpr ((sig_iff _ _).mpr h)
      rw [PromotionImpossibleB.sent_advance] at yes
      contradiction
    rw [←Batch.commitStrict.eq_label s]
    apply Bool.eq_iff_iff.mpr
    simp only [label_true,holds,sig_iff]
    exact (Iff.step_log_advance_inr _ _ _).trans (or_iff_left no)

end ConsensusCoverage.HandReadersTrunkC.LogSites
