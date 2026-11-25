module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AssistAcceptedA
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkC.Fold

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open Lean Meta Elab Command HandReadersTrunkA AssistAcceptedA FollowerFoldCasesB

set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

def check (retired : Bool) (n : NodeID) (st : NodeState) (q : AppendEntriesRequest) :=
  let result := (handleAppendEntiresFromPrimary n st q).1
  decide (result.role = if retired then .none else (middle n st q).role)

-- Isolate the common, caller-independent suffix of the two role witnesses.
run_cmd liftTermElabM do
  for (n,out) in [( ``step_handleAppendEntiresFromPrimary_eq_roleCase__inl,
      `ConsensusCoverage.HandReadersTrunkC.Fold.Same), (``step_handleAppendEntiresFromPrimary_eq_roleCase__inr,
      `ConsensusCoverage.HandReadersTrunkC.Fold.Retired)] do
    lambdaTelescope (←getConstInfo n).value! fun _ p => do
      let rec peel (k : Nat) (a : Expr) (vs : Array Expr) : MetaM Expr :=
        match k with
        | 0 => mkLambdaFVars vs a.appArg!
        | k+1 => withLocalDeclD a.appArg!.bindingName! (a.getArg! 0) fun w => peel k (a.appArg!.beta #[w]) (vs.push w)
      let v ← peel 3 (HandReadersBFactor.disjuncts p).head! #[]
      addDecl (.defnDecl {
        name := out,levelParams := [],type := ←inferType v,value := v
        hints := .abbrev,safety := .safe })

private abbrev Local (r : Bool) := if r then Retired else Same

private theorem local_iff (retired : Bool) (self : NodeID) (st : NodeState) (q : AppendEntriesRequest) :
    Local retired self st q ↔ check retired self st q := by
  let entries := q.entries.drop (st.log.length - q.prevLogIndex)
  let mid := middle self st q
  let stop := max mid.commitIndex (maxCommittableIndexUpTo mid.log (limit q))
  have out : (handleAppendEntiresFromPrimary self st q).1 = mid.recordCommit self stop := rfl
  constructor
  · intro h
    cases retired
    all_goals
      obtain ⟨j,_,a,_,b,_,k,_,fold,_,_,_,_,_,ar,_,hr,re,_⟩ := h
      change mid = _ at fold
      simp only [check,decide_eq_true_eq,out,Bool.false_eq_true,ite_false,ite_true]
      change (mid.recordCommit self (max mid.commitIndex (maxCommittableIndexUpTo mid.log (limit q)))).role = _
      first | change _ = mid.role | skip
      rw [fold]
      have result := congrArg NodeState.role re
      exact result
  · intro yes
    obtain ⟨j,a,b,k,fold,roles,lo,hi⟩ := Ledger.fromLeader_loop self (limit q) entries st
    let m := {st with log := st.log ++ entries,commitIndex := j,retiredCommittedIndex := a,role := b,primaryKnown := k}
    have eq : mid = m := fold
    obtain ⟨ar,br,hr,re,choices⟩ := Ledger.NodeState.recordCommit_eq self m
      (max m.commitIndex (maxCommittableIndexUpTo m.log (limit q)))
    have roleEq : (handleAppendEntiresFromPrimary self st q).1.role = br := by
      rw [out]; dsimp only [stop]; rw [eq]; exact congrArg NodeState.role re
    cases retired <;> simp only [check,decide_eq_true_eq,Bool.false_eq_true,ite_false,ite_true,roleEq] at yes
    all_goals
      refine ⟨j,⟨_,_,_,fold,roles,lo,hi⟩,a,⟨_,_,fold,roles,lo,hi⟩,b,⟨_,fold,roles,lo,hi⟩,
        k,⟨fold,roles,lo,hi⟩,fold,⟨roles,lo,hi⟩,roles,⟨lo,hi⟩,lo,hi,ar,⟨br,hr,re,choices⟩,hr,?_,?_⟩
      first | (change br = mid.role at yes; rw [eq] at yes; exact yes ▸ re) | exact yes ▸ re
      first | exact .inl trivial | exact .inr trivial

private def guarded (r : Bool) (R : NodeID → NodeState → AppendEntriesRequest → Prop) :=
  ∃ n st q, R n st q ∧ check r n st q

private theorem guardSite (r : Bool) (R : NodeID → NodeState → AppendEntriesRequest → Prop) :
    (∃ n st q, R n st q ∧ Local r n st q) ↔ guarded r R :=
  exists_congr fun n => exists_congr fun st => exists_congr fun q => and_congr_right fun _ => local_iff r n st q

run_cmd liftTermElabM do
  for (n,r,name) in [( ``step_handleAppendEntiresFromPrimary_eq_roleCase__inl,false,`SameSummary),
      (``step_handleAppendEntiresFromPrimary_eq_roleCase__inr,true,`RetiredSummary)] do
    let cs := ReachPath.children n.getPrefix (←getConstInfo n).value!
    let summary := `ConsensusCoverage.HandReadersTrunkC.Fold ++ name
    lambdaTelescope (←getConstInfo n).value! fun xs _ => do
      let h (i : Name) := mkApp2 (mkConst ``guardSite) (toExpr r) (mkAppN (mkConst i) xs)
      let sites ← cs.mapM fun i => do
        return (←unfoldDefinition? (mkApp2 (mkConst ``guarded) (toExpr r) (mkAppN (mkConst i) xs))).get!
      let mut pf := h cs.back!
      for i in cs.toList.dropLast.reverse do pf ← mkAppM ``or_congr #[h i,pf]
      let v ← mkLambdaFVars xs (Factor.disj sites.toList.tail!)
      addDecl (.defnDecl {
        name := summary,levelParams := [],type := ←inferType v,value := v
        hints := .abbrev,safety := .safe })
      let rhs := mkApp2 (mkConst ``Or) sites[0]! (mkAppN (mkConst summary) xs)
      addDecl (.thmDecl {
        name := summary.appendAfter "_iff",levelParams := []
        type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,rhs]),value := ←mkLambdaFVars xs pf })

end ConsensusCoverage.HandReadersTrunkC.Fold
