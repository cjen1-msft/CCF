module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkALoop
import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkA.Loop

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses HandReadersA ActionProfile

set_option maxRecDepth 8192
set_option maxHeartbeats 1200000

private def limit : Event → Nat
  | .receive _ (.appendEntriesRequest q) => min q.primaryCommit (q.prevLogIndex + q.entries.length)
  | _ => 0

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem requestLimit {self src z q} (h : Request.Call f t c self src z q) :
    min q.primaryCommit (q.prevLogIndex + q.entries.length) = limit c.event := by
  rw [((Request.call_iff c _ _ _ _).mp h).2.1]; rfl

private theorem directLimit {self lim} (h : (reach% step_fromLeader_loop_entries_cons[0]) f t c self lim) :
    lim = limit c.event := by
  obtain ⟨q,call,rfl⟩ := h
  change (reach% step_fromLeader_loop_entries_cons[0,0,0]) f t c self q at call
  rcases call with ⟨z,o,_⟩ | ⟨z,o,_⟩
  all_goals
    obtain ⟨_,_,ev,_⟩ := observedCall c o
    rw [ev]; rfl
end

private theorem addBound {R : NodeID → Nat → Prop} (n v : Nat) (h : ∀ a b, R a b → b = v) :
    (∃ a b, R a b ∧ n ≤ b) ↔ (∃ a b, R a b) ∧ n ≤ v := by grind

open Lean Meta Elab Command Term in
run_cmd liftTermElabM do
  let n := ``step_fromLeader_loop_entries_cons
  let cs := ReachPath.children n.getPrefix (←getConstInfo n).value!
  let stops := ReachPath.children n.getPrefix (←getConstInfo ``step_aeReply_conflict_none).value!
  let rs ← HandReadersBFactor.roots
  let mut pin : Std.HashMap Name Name := {}
  for r in stops do
    let name := (`ConsensusCoverage.HandReadersTrunkA.Loop.Pin).str r.getString!
    lambdaTelescope (←getConstInfo r).value! fun xs body => do
      let part ← HandReadersBFactor.splitAt rs (xs.extract 0 4) body
      withLocalDeclD `h (mkAppN (mkConst r) xs) fun h => do
        let yes ← mkAppM ``Iff.mp #[part.proof,h] >>= fun p => mkAppM ``And.right #[p]
        let pf ← mkAppM ``requestLimit #[xs[3]!,yes]
        let p ← mkLambdaFVars (xs.push h) pf
        addDecl (.thmDecl { name,levelParams := [],type := ←inferType p,value := p })
    pin := pin.insert r name
  lambdaTelescope (←getConstInfo cs[0]!).value! fun args _ => do
    let xs := args.extract 0 4
    let ev ← mkAppM ``Ctx.event #[xs[3]!]
    let lim ← mkAppM ``limit #[ev]
    withLocalDeclD `k (mkConst ``Nat) fun k => do
      let mut es := #[]
      let mut proofs := #[]
      for (r,i) in cs.toList.zipIdx do
        let pred := mkAppN (mkConst r) xs
        let names := (←(Factor.sources stops (mkAppN (mkConst r) args)).run' {}).toArray
        let shape ← if i == 0 then pure (mkAppN (mkConst ``directLimit) xs) else do
          let ss := names.map fun r => mkAppN (mkConst r) xs
          let hs := names.map fun r => mkAppN (mkConst pin[r]!) xs
          let ty ← replaceCallers xs names ss (mkAppN (mkConst r) args)
          let eq ← mkEq args[5]! lim
          let ty ← mkForallFVars (args.extract 4 6) (←mkArrow ty eq)
          let p0 ← exprToSyntax hs[0]!
          let p1 ← exprToSyntax hs.back!
          let pr ← if names.size == 1 then `(by
            rintro a b ⟨q,h,eq⟩
            apply eq.trans
            rcases h with ⟨src,z,o,_⟩ | ⟨src,z,o,_⟩ <;> exact $p0 a src z q o)
            else `(by
            rintro a b ⟨q,h,eq⟩
            apply eq.trans
            rcases h with ⟨src,z,o,_⟩ | ⟨src,z,o,_⟩ | ⟨src,z,o,_⟩ | ⟨src,z,o,_⟩ <;>
              first | exact $p0 a src z q o | exact $p1 a src z q o)
          let pf ← elabTermEnsuringType pr ty
          synthesizeSyntheticMVarsNoPostponing
          pure (←instantiateMVars pf)
        let bound ← mkAppOptM ``addBound #[some pred,some k,some lim,some shape]
        let p ← inferType bound
        es := es.push (p.getArg! 0)
        proofs := proofs.push bound
      let mut pf := proofs.back!
      for h in proofs.toList.dropLast.reverse do
        pf ← mkAppM ``or_congr #[h,pf]
        let rhs := (←inferType pf).appArg!
        let join ← mkAppOptM ``or_and_right #[(rhs.getArg! 0).getArg! 0,rhs.appArg!.getArg! 0,rhs.appArg!.appArg!]
        pf ← mkAppM ``Iff.trans #[pf,←mkAppM ``Iff.symm #[join]]
      let vars := xs.push k
      let name := `ConsensusCoverage.HandReadersTrunkA.Loop.Bounded
      addDecl (.defnDecl {
        name,levelParams := [],type := ←mkForallFVars vars (mkSort .zero)
        value := ←mkLambdaFVars vars (Factor.disj es.toList),hints := .abbrev,safety := .safe })
      let rhs := mkApp2 (mkConst ``And) (mkAppN (mkConst ``Live) xs) (←mkAppM ``LE.le #[k,lim])
      addDecl (.thmDecl {
        name := `ConsensusCoverage.HandReadersTrunkA.Loop.bounded_iff,levelParams := []
        type := ←mkForallFVars vars (←mkAppM ``Iff #[mkAppN (mkConst name) vars,rhs])
        value := ←mkLambdaFVars vars pf })

def exactBounded (b : Classes.StepBranch) (k : Nat) (h : ∀ [Config.InitialConfiguration] {f : Frame} {t : State}
    (c : Ctx f t), sig c b ↔ Bounded f t c k) : Exact b :=
  Request.exactOfTail b (fun n st q => accepted n st q && decide (k ≤ min q.primaryCommit (q.prevLogIndex+q.entries.length)))
    fun s => by
      letI : Config.InitialConfiguration := ⟨s.cfg⟩
      rw [h,bounded_iff,live_iff]
      change (_ ∧ ∃ src q, _ ∧ accepted _ _ q = true) ∧ _ ↔ _
      simp only [Bool.and_eq_true,decide_eq_true_eq]
      constructor
      · rintro ⟨⟨live,src,q,ev,yes⟩,le⟩
        rw [ev] at le
        exact ⟨live,src,q,ev,yes,le⟩
      · rintro ⟨live,src,q,ev,yes,le⟩
        exact ⟨⟨live,src,q,ev,yes⟩,ev ▸ le⟩

end ConsensusCoverage.HandReadersTrunkA.Loop
