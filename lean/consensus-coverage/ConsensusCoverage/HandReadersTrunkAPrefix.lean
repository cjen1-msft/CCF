module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkALimit
import all ConsensusCoverage.HandReadersTrunkALoop
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkA.Loop

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile FollowerFoldCasesB

set_option maxRecDepth 8192
set_option maxHeartbeats 1000000

open Lean Meta Elab Command in
run_cmd liftTermElabM do
  let n := ``step_maxCommittableIndex_le_of_prefix_zero_pos
  let r := (ReachPath.children n.getPrefix (←getConstInfo n).value!)[0]!
  let m := ``step_fromLeader_loop_entries_cons
  let ch := (ReachPath.children m.getPrefix (←getConstInfo m).value!)[0]!
  lambdaTelescope (←getConstInfo r).value! fun xs body => do
    let ctx := xs.extract 0 4
    withLocalDeclD `R (←inferType (mkAppN (mkConst ch) ctx)) fun R => do
      let value ← mkLambdaFVars (#[R] ++ xs.extract 4 6) (←replaceCallers ctx #[ch] #[R] body)
      addDecl (.defnDecl {
        name := `ConsensusCoverage.HandReadersTrunkA.Loop.Pair,levelParams := [],type := ←inferType value
        value,hints := .abbrev,safety := .safe })

private theorem pairOf {R : NodeID → Nat → Prop} {n l} (h : R n l) (pre : List Entry) :
    Pair R ((pre ++ [sg]).take l) ((pre ++ [sg]).take l) := by
  let j := max (state pre).commitIndex (maxCommittableIndexUpTo ((state pre).log ++ [sg]) l)
  obtain ⟨r,b,k,re,roles⟩ := Ledger.NodeState.recordCommit_eq n
    {state pre with log := (state pre).log ++ [sg]} j
  refine ⟨pre ++ [sg],(pre ++ [sg]) ++ [],l,?_,List.prefix_append _ [],rfl,by simp⟩
  refine ⟨n,h,sg,[],Ledger.fromLeader_loop n l [],state pre,rfl,?_⟩
  repeat' first
    | assumption
    | rfl
    | exact Or.inl rfl
    | exact Or.inr rfl
    | exact Nat.le_refl _
    | exact Nat.le_max_left _ _
    | exact Nat.zero_le _
    | apply And.intro
    | refine Exists.intro r ?_
    | refine Exists.intro b ?_
    | refine Exists.intro k ?_
    | refine Exists.intro j ?_
  all_goals simp only [List.foldl_nil,List.append_nil,j]

private theorem pairAt {R : NodeID → Nat → Prop} {left right} (p : Pair R left right) :
    ∃ n l, R n l ∧ left.length ≤ l := by
  obtain ⟨small,_,l,⟨n,live,_⟩,_,rfl,_⟩ := p
  exact ⟨n,l,live,List.length_take_le _ _⟩

private theorem noSig (l : Nat) : maxCommittableIndex (List.replicate l tx) = 0 := by
  apply Nat.eq_zero_of_not_pos
  intro pos
  obtain ⟨e,mem,yes⟩ := Ledger.isSignatureAtTrue (Ledger.maxCommittableIndexPositiveIsSignature pos)
  unfold entryAt? at mem
  split at mem
  · contradiction
  · have member := (List.mem_replicate.mp (List.mem_of_getElem? mem)).2
    subst e
    contradiction

private theorem zeroPair {R : NodeID → Nat → Prop} {n l} (h : R n l) :
    ∃ left right, Pair R left right ∧ maxCommittableIndex left = 0 ∧ left <+: right := by
  let log := List.replicate l tx
  have cut : (log ++ [sg]).take l = log := by
    have eq : log.length = l := List.length_replicate
    rw [List.take_append_of_le_length (Nat.le_of_eq eq.symm), ←eq,List.take_length]
  exact ⟨_,_,pairOf h log,by rw [cut]; exact noSig l,List.prefix_refl _⟩

private theorem signedPair {R : NodeID → Nat → Prop} {n l} (h : R n l) (k : 1 ≤ l) :
    Pair R [sg] [sg] := by
  simpa only [List.nil_append,List.take_of_length_le (show [sg].length ≤ l from k)] using pairOf h []

private theorem twoPair {R : NodeID → Nat → Prop} {n l} (h : R n l) (k : 2 ≤ l) :
    Pair R [sg,sg] [sg,sg] := by
  simpa only [List.cons_append,List.nil_append,List.take_of_length_le (show [sg,sg].length ≤ l from k)]
    using pairOf h [sg]

private theorem whenZero (R : NodeID → Nat → Prop) :
    (∃ left right, Pair R left right ∧ maxCommittableIndex left = 0 ∧ left <+: right) ↔
      ∃ n l, R n l ∧ 0 ≤ l := by
  exact ⟨fun ⟨_,_,p,_⟩ => let ⟨n,l,r,_⟩ := pairAt p; ⟨n,l,r,Nat.zero_le _⟩,
    fun ⟨_,_,r,_⟩ => zeroPair r⟩

private theorem whenPos (R : NodeID → Nat → Prop) :
    (∃ left right, Pair R left right ∧ ¬maxCommittableIndex left = 0 ∧ left <+: right) ↔
      ∃ n l, R n l ∧ 1 ≤ l := by
  constructor
  · rintro ⟨left,_,p,nz,_⟩
    obtain ⟨n,l,h,length⟩ := pairAt p
    have ge := Ledger.maxCommittableIndexBounded left
    exact ⟨n,l,h,by omega⟩
  · rintro ⟨_,_,h,le⟩
    exact ⟨[sg],[sg],signedPair h le,by decide,List.prefix_refl _⟩

open Lean Meta Elab Command in
run_cmd liftTermElabM do
  let n := ``step_fromLeader_loop_entries_cons
  let cs := ReachPath.children n.getPrefix (←getConstInfo n).value!
  for (q,h,k) in [( ``step_maxCommittableIndex_le_of_prefix_zero_pos, ``whenZero,0),
      (``step_maxCommittableIndex_le_of_prefix_zero_neg, ``whenPos,1)] do
    lambdaTelescope (←getConstInfo q).value! fun xs _ => do
      let proof (r : Name) := mkApp (mkConst h) (mkAppN (mkConst r) xs)
      let mut eq := proof cs.back!
      for r in cs.toList.dropLast.reverse do eq ← mkAppM ``or_congr #[proof r,eq]
      addDecl (.thmDecl {
        name := (`ConsensusCoverage.HandReadersTrunkA.Loop.Equiv).str q.getString!,levelParams := []
        type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst q) xs,mkAppN (mkConst ``Bounded) (xs.push (mkNatLit k))])
        value := ←mkLambdaFVars xs eq })

def zeroPrefix := exactBounded .maxCommittableIndex_le_of_prefix_zero_pos 0
  (fun c => Equiv.step_maxCommittableIndex_le_of_prefix_zero_pos _ _ c)
def signedPrefix := exactBounded .maxCommittableIndex_le_of_prefix_zero_neg 1
  (fun c => Equiv.step_maxCommittableIndex_le_of_prefix_zero_neg _ _ c)

end ConsensusCoverage.HandReadersTrunkA.Loop
