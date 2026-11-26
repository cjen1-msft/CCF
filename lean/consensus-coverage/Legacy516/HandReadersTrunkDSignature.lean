module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDSignatureSites
import all ConsensusCoverage.HandReadersTrunkDSignatureTransport
import all ConsensusCoverage.HandReadersTrunkDSignatureErased
import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.HandReadersTrunkDSignatureGate
import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.HandReadersTrunkAPrefix
import all ConsensusCoverage.HandReadersTrunkALimit
import all ConsensusCoverage.DeepSignedCases
import all ConsensusCoverage.ReadersExtra
import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDSignatureSites

namespace ConsensusCoverage.HandReadersTrunkD.Signed

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 1700000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

local macro "fold_branch" : term => `(by
  constructor
  · rintro ⟨l,i,site,h⟩
    refine ⟨l,i,site,?_⟩
    repeat' first | change Exists _ at h; obtain ⟨_,h⟩ := h | change _ ∧ _ at h; obtain ⟨_,h⟩ := h
    constructor <;> assumption
  · rintro ⟨l,i,site,sg,bound⟩
    have up := DeepSignedCases.above l
    first
    | exact ⟨l,i,site,[],by simp,sg,bound,up⟩
    | exact ⟨l,i,site,[],by simp,by simp,sg,bound,up⟩
    | exact ⟨l,i,site,[],by simp,0,by simp,by simp,sg,bound,by simp [sg]⟩
    | exact ⟨l,i,site,[],by simp,0,by simp,by simp,[],by simp,sg,bound,by simp [sg]⟩
    | exact ⟨l,i,site,[],by simp,0,by simp,by simp,i,[],by simp,sg,sg,bound,by simp [sg]⟩
    | exact ⟨l,i,site,[],by simp,0,by simp,by simp,0,[],by simp,by simp [isSignatureAt,entryAt?],sg,bound,by simp [sg]⟩
    | refine ⟨l,i,site,0,[i],?_,by simp,by simp,sg,bound,up⟩
      simpa [sg] using fun best => Nat.le_max_right best i)

run_cmd liftTermElabM do
  let indexed ←indexedSites
  let erased ←erasedSites
  for q in [``step_signatureIndex_le_maxCommittableIndex_values_nil,``step_signatureIndex_le_maxCommittableIndex_values_cons,
      ``step_signatureIndex_le_maxCommittableIndex_mem_cons_inl,``step_signatureIndex_le_maxCommittableIndex_mem_cons_inr,
      ``step_signatureIndex_le_maxCommittableIndex_signature_pos,``step_signatureIndex_le_maxCommittableIndex_signature_neg] do
    lambdaTelescope (←getConstInfo q).value! fun xs body=>do
      let arms := choices body
      let k := indexed.size
      let mut proofs := []
      for j in [:arms.length/k] do
        let mut ps := []
        for i in [:k] do
          let a := arms[j*k+i]!
          let r := indexed[i]!
          let es := mkAppN (mkConst erased[i]!) xs
          let h ← if a == es then pure (mkApp (mkConst ``Iff.rfl) es) else do
            let root := mkAppN (mkConst r) xs
            let name := (ns++`Induction).str (q.getString! ++ toString j)
            unless (←getEnv).contains name do
              withLocalDeclD `R (←inferType root) fun w=>do
                let left := a.replace fun v=>if v == root then some w else none
                let ty ←mkAppM ``Iff #[left,←liftValid w]
                let pf ←Elab.Term.elabTermEnsuringType (←`(fold_branch)) ty
                Elab.Term.synthesizeSyntheticMVarsNoPostponing
                let v ←mkLambdaFVars #[w] (←instantiateMVars pf)
                addDecl (.thmDecl {name,levelParams:=[],type:=←inferType v,value:=v})
            mkAppM ``Iff.trans #[mkApp (mkConst name) root,mkAppN (mkConst (siteIff r)) xs]
          ps:=ps++[h]
        proofs:=proofs++[ps]
      let lhs := mkAppN (mkConst q) xs
      let rhs := mkAppN (mkConst ``Erased) xs
      let es := choices ((←getConstInfo ``Erased).value!.beta xs)
      let links := proofs.flatten
      let fw ←arms.zipIdx.mapM fun (a,i)=>withLocalDeclD `h a fun h=>do
        let pr ←mkAppM ``Iff.mp #[links[i]!,h]
        mkLambdaFVars #[h] (←HandReadersBFactor.into (disj es) pr (i%k) k)
      let bw ←es.zipIdx.mapM fun (e,i)=>withLocalDeclD `h e fun h=>do
        let pr ←mkAppM ``Iff.mpr #[links[i]!,h]
        mkLambdaFVars #[h] (←HandReadersBFactor.into body pr i arms.length)
      let mp ←withLocalDeclD `h lhs fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf body h rhs fw)
      let mpr ←withLocalDeclD `h rhs fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf (disj es) h lhs bw)
      addDecl (.thmDecl {
        name:=(ns++`Equiv).str q.getString!,levelParams:=[],type:=←mkForallFVars xs (←mkAppM ``Iff #[lhs,rhs])
        value:=←mkLambdaFVars xs (←mkAppM ``Iff.intro #[mp,mpr])})

private def electedCommit : Reader := actorRead fun _ pre _ post=>
  decide (pre.role ≠ .primary ∧ post.role = .primary ∧ 0 < pre.commitIndex)

def reader : Reader := fun cfg before act after past=>
  HandReadersTrunkA.Loop.signedPrefix.eval cfg before act after past ||
    electedCommit cfg before act after past ||
    (ReadersAtoms.ofXAction cfg before after past act).any fun x=>
      HandReadersElection.Rank.view .ahead x || HandReadersElection.Rank.view .tied x ||
      (gate cfg before act after past && @Compiled.R.NonRanking ⟨cfg⟩ x)

def exactReader (k : DeepSignedCases.FoldCase) : Exact (DeepSignedCases.column k) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x,made,ok⟩ := ReadersAtoms.ofXAction_matches s
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,made,Option.any_some]
    simp only [Bool.or_eq_true,Bool.and_eq_true,←HandReadersTrunkA.Loop.signedPrefix.eq_label s,
      label_true,holds,sig_iff,HandReadersElection.Rank.view_iff s.context ok,←rank_partition,gateAt,
      Compiled.R.NonRanking_iff _ _ _ x ok,electedCommit,actorRead_at,decide_eq_true_eq]
    have h : sig s.context (DeepSignedCases.column k) ↔ Erased s.frame s.after s.context := by
      cases k
      all_goals first
        | exact Equiv.step_signatureIndex_le_maxCommittableIndex_values_nil ..
        | exact Equiv.step_signatureIndex_le_maxCommittableIndex_values_cons ..
        | exact Equiv.step_signatureIndex_le_maxCommittableIndex_mem_cons_inl ..
        | exact Equiv.step_signatureIndex_le_maxCommittableIndex_mem_cons_inr ..
        | exact Equiv.step_signatureIndex_le_maxCommittableIndex_signature_pos ..
        | exact Equiv.step_signatureIndex_le_maxCommittableIndex_signature_neg ..
    have quick (was : s.context.pre.role ≠ .primary) (now : s.context.post.role = .primary)
        (pos : 0 < s.context.pre.commitIndex) : Erased s.frame s.after s.context :=
      (Equiv.step_signatureIndex_le_maxCommittableIndex_values_nil ..).mp
        (.inl (DeepSignedCases.roots s.context was now pos).1)
    rw [h]
    have exact' := erased_iff s.frame s.after s.context
    have historical := nonRankingGate s.frame s.after s.context
    constructor
    · intro e
      rcases exact'.mp e with deep | signed | rank
      · exact .inr (.inr ⟨historical deep,deep⟩)
      · exact .inl (.inl signed)
      · exact .inr (.inl rank)
    · rintro ((signed | ⟨was,now,pos⟩) | rank | ⟨_,deep⟩)
      · exact exact'.mpr (.inr (.inl signed))
      · exact quick was now pos
      · exact exact'.mpr (.inr (.inr rank))
      · exact exact'.mpr (.inl deep)

end ConsensusCoverage.HandReadersTrunkD.Signed
