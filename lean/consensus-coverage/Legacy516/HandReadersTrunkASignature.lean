module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkALimit
import all ConsensusCoverage.HandReadersTrunkAPrefix
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor
public meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.HandReadersTrunkA.Loop

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile FollowerFoldCasesB

set_option maxRecDepth 8192
set_option maxHeartbeats 1200000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev SignedLog (R : NodeID → Nat → Prop) (log : List Entry) :=
  ∃ right, Pair R log right ∧ ¬maxCommittableIndex log = 0 ∧ log <+: right ∧ 0 < maxCommittableIndex log

private structure Bounds (R : NodeID → Nat → Prop) (C : List Entry → Prop) : Prop where
  size : ∀ log, C log → ∃ n l, R n l ∧ log.length ≤ l
  one : ∀ n l, R n l → 1 ≤ l → C [sg]
  two : ∀ n l, R n l → 2 ≤ l → C [sg,sg]

private theorem bounds (R : NodeID → Nat → Prop) : Bounds R (SignedLog R) where
  size _ h := let ⟨_,p,_⟩ := h; pairAt p
  one _ _ h le := ⟨_,signedPair h le,by decide,List.prefix_refl _,by decide⟩
  two _ _ h le := ⟨_,twoPair h le,by decide,List.prefix_refl _,by decide⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev DirectOrigin := (reach% step_fromLeader_loop_entries_cons[0]) f t c

private theorem directOrigin {st log l}
    (h : (reach% step_maxCommittableIndexPositiveIsSignature_values_cons[0,0,0]) f t c st log l) :
    ∃ n, DirectOrigin c n l := by
  obtain ⟨self,q,call,_,_,_,_,_,_,_,_,_,_,rfl⟩ := h
  refine ⟨self,q,?_,rfl⟩
  rcases call with ⟨z,o,a,p,clear,clear',seen,ready,safe,_⟩ |
    ⟨z,o,a,p,i,found,found',seen,ready,safe,lo,_⟩
  · exact .inl ⟨z,o,a,p,clear,clear',seen,ready,safe⟩
  · exact .inr ⟨z,o,a,p,i,found,found',seen,ready,safe,lo⟩

private theorem firstBounds : Bounds (DirectOrigin c)
    ((reach% step_maxCommittableIndexPositiveIsSignature_values_cons[0]) f t c) where
  size log h := by
    rcases h with ⟨big,l,⟨_,origin,_⟩,_,rfl⟩ | sig
    · obtain ⟨n,r⟩ := directOrigin c origin
      exact ⟨n,l,r,List.length_take_le _ _⟩
    · exact (bounds (DirectOrigin c)).size log sig
  one n l h le := .inr ((bounds (DirectOrigin c)).one n l h le)
  two n l h le := .inr ((bounds (DirectOrigin c)).two n l h le)
end

private theorem positiveBound {R C} (b : Bounds R C) {log} (c : C log) (pos : 0 < maxCommittableIndex log) :
    ∃ n l, R n l ∧ 1 ≤ l := by
  obtain ⟨n,l,h,len⟩ := b.size log c
  have := Ledger.maxCommittableIndexBounded log
  exact ⟨n,l,h,by omega⟩

private theorem strictBound {R C} (b : Bounds R C) {log head best} (c : C log)
    (h : isSignatureAt log head = true) (g : isSignatureAt log best = true) (lt : ¬best ≤ head) :
    ∃ n l, R n l ∧ 2 ≤ l := by
  obtain ⟨n,l,r,len⟩ := b.size log c
  obtain ⟨_,found,_⟩ := Ledger.isSignatureAtTrue g
  have := Ledger.entryAtSomeIndexBound found
  have nz : head ≠ 0 := by rintro rfl; contradiction
  exact ⟨n,l,r,by omega⟩

open Lean Meta Elab Command Term in
local elab "signature_equiv " q:ident " bound " k:num " using " pr:term : command => liftTermElabM do
  let n ← realizeGlobalConstNoOverloadWithInfo q
  let cs := ReachPath.children n.getPrefix (←getConstInfo n).value!
  let loop := ``step_fromLeader_loop_entries_cons
  let rs := ReachPath.children n.getPrefix (←getConstInfo loop).value!
  lambdaTelescope (←getConstInfo n).value! fun xs p => do
    let c0 := mkAppN (mkConst cs[0]!) xs
    let r0 := mkAppN (mkConst rs[0]!) xs
    let cty ← inferType c0
    withLocalDeclD `R (←inferType r0) fun r => withLocalDeclD `C cty fun c => do
      let lhs := (p.getArg! 0).replace fun e => if e == c0 then some c else none
      let bound := mkAppN (mkConst ``Bounded) (xs.push (mkNatLit k.getNat))
      let rhs := ((←unfoldDefinition? bound).get!.getArg! 0).replace fun e => if e == r0 then some r else none
      let ty ← mkArrow (←mkAppM ``Bounds #[r,c]) (←mkAppM ``Iff #[lhs,rhs])
      let pf ← elabTermEnsuringType pr ty
      synthesizeSyntheticMVarsNoPostponing
      let gen ← mkLambdaFVars #[r,c] (←instantiateMVars pf)
      let mut ps := #[]
      for i in [:rs.size] do
        let ri := mkAppN (mkConst rs[i]!) xs
        let ci := mkAppN (mkConst cs[i]!) xs
        let b := if i == 0 then mkAppN (mkConst ``firstBounds) xs else mkApp (mkConst ``bounds) ri
        ps := ps.push (mkAppN gen #[ri,ci,b])
      let mut eq := ps.back!
      for h in ps.toList.dropLast.reverse do eq ← mkAppM ``or_congr #[h,eq]
      addDecl (.thmDecl {
        name := (`ConsensusCoverage.HandReadersTrunkA.Loop.Equiv).str n.getString!,levelParams := []
        type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,bound])
        value := ←mkLambdaFVars xs eq })

signature_equiv step_maxCommittableIndexPositiveIsSignature_values_cons bound 1 using
  fun b => ⟨fun ⟨_,c,_,_,pos⟩ => positiveBound b c pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],b.one n l h le,[],fun _ h => h,by decide⟩⟩
signature_equiv step_maxCommittableIndexPositiveIsSignature_headValid_pos bound 1 using
  fun b => ⟨fun ⟨_,c,_,_,_,_,_,_,pos⟩ => positiveBound b c pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],b.one n l h le,1,[],fun _ h => h,0,.inl rfl,rfl,by decide⟩⟩
signature_equiv step_maxCommittableIndexPositiveIsSignature_headValid_neg bound 1 using
  fun b => ⟨fun ⟨_,c,_,_,_,_,_,_,pos⟩ => positiveBound b c pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],b.one n l h le,0,[],fun _ h => h,0,.inl rfl,by decide,by decide⟩⟩
signature_equiv step_maxCommittableIndexPositiveIsSignature_bestValid_inl bound 1 using
  fun b => ⟨fun ⟨_,c,_,_,_,_,_,pos⟩ => positiveBound b c pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],b.one n l h le,1,[],fun _ h => h,.inl trivial,rfl,by decide⟩⟩
signature_equiv step_maxCommittableIndexPositiveIsSignature_bestValid_inr bound 1 using
  fun b => ⟨fun ⟨_,c,_,_,_,_,_,_,_,pos⟩ => positiveBound b c pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],b.one n l h le,1,[],fun _ h => h,1,.inr rfl,rfl,rfl,by decide⟩⟩
signature_equiv step_maxCommittableIndexPositiveIsSignature_bestLeHead_pos bound 1 using
  fun b => ⟨fun ⟨_,c,_,_,_,_,_,_,_,_,pos⟩ => positiveBound b c pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],b.one n l h le,1,[],fun _ h => h,1,.inr rfl,rfl,rfl,Nat.le_refl _,by decide⟩⟩
signature_equiv step_maxCommittableIndexPositiveIsSignature_bestLeHead_neg bound 2 using
  fun b => ⟨fun ⟨_,c,_,_,_,_,_,hd,best,lt,_⟩ => strictBound b c hd best lt,
    fun ⟨n,l,h,le⟩ => ⟨[sg,sg],b.two n l h le,1,[],fun _ h => h,2,.inr rfl,rfl,rfl,by decide,by decide⟩⟩

private theorem nilFirst [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) :
    (reach% step_maxCommittableIndexPositiveIsSignature_values_nil[0]) f t c ↔
      ∃ n l, DirectOrigin c n l ∧ 1 ≤ l := by
  constructor
  · rintro (⟨st,log,l,call,pos,le,_⟩ | ⟨log,right,p,nz,sub,pos⟩)
    · obtain ⟨n,h⟩ := directOrigin c call
      change 0 < max st.commitIndex (maxCommittableIndexUpTo log l) at pos
      have hi := Ledger.maxCommittableIndexBounded (log.take l)
      have size := List.length_take_le l log
      unfold maxCommittableIndexUpTo at le pos
      exact ⟨n,l,h,by omega⟩
    · exact positiveBound (bounds (DirectOrigin c)) ⟨right,p,nz,sub,pos⟩ pos
  · rintro ⟨n,l,h,le⟩
    exact .inr ⟨[sg],(bounds (DirectOrigin c)).one n l h le⟩

private theorem nilOther (R : NodeID → Nat → Prop) :
    (∃ log, SignedLog R log) ↔ ∃ n l, R n l ∧ 1 ≤ l := by
  refine ⟨fun ⟨_,r,p,nz,sub,pos⟩ => positiveBound (bounds R) ⟨r,p,nz,sub,pos⟩ pos,
    fun ⟨n,l,h,le⟩ => ⟨[sg],(bounds R).one n l h le⟩⟩

open Lean Meta Elab Command in
run_cmd liftTermElabM do
  let n := ``step_maxCommittableIndexPositiveIsSignature_values_nil
  let loop := ``step_fromLeader_loop_entries_cons
  let rs := ReachPath.children n.getPrefix (←getConstInfo loop).value!
  lambdaTelescope (←getConstInfo n).value! fun xs _ => do
    let mut es := #[mkAppN (mkConst ``nilFirst) xs]
    for r in rs.toList.tail! do es := es.push (mkApp (mkConst ``nilOther) (mkAppN (mkConst r) xs))
    let mut eq := es.back!
    for h in es.toList.dropLast.reverse do eq ← mkAppM ``or_congr #[h,eq]
    addDecl (.thmDecl {
      name := (`ConsensusCoverage.HandReadersTrunkA.Loop.Equiv).str n.getString!,levelParams := []
      type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,mkAppN (mkConst ``Bounded) (xs.push (mkNatLit 1))])
      value := ←mkLambdaFVars xs eq })

end ConsensusCoverage.HandReadersTrunkA.Loop
