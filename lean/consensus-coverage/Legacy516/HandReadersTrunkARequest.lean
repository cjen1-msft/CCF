module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkA.Request

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile AssistReplyA

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

-- Extract just the handler arguments once the transition has been pinned.
open Lean Meta Elab Command in
run_cmd liftTermElabM do
  let n := ``step_aeReply_conflict_none
  let r := (ReachPath.children n.getPrefix (← getConstInfo n).value!)[0]!
  let rs ← HandReadersBFactor.roots
  lambdaTelescope (← getConstInfo r).value! fun xs body => do
    let part ← HandReadersBFactor.splitAt rs (xs.extract 0 4) body
    addDecl (.defnDecl {
      name := `ConsensusCoverage.HandReadersTrunkA.Request.Call, levelParams := []
      type := ← mkForallFVars xs (mkSort .zero), value := ← mkLambdaFVars xs part.tail
      hints := .abbrev, safety := .safe })

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

theorem call_iff (n src : NodeID) (z : NodeState) (q : AppendEntriesRequest) :
    Call f t c n src z q ↔ n = c.actor ∧ c.event = .receive src (.appendEntriesRequest q) ∧
      z = observed c.pre q := by
  constructor
  · rintro (⟨_,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,h,_,_,rfl⟩ |
      ⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,h⟩)
    all_goals exact ⟨rfl,ev,(by first | exact h.2.symm | exact h.symm)⟩
  · rintro ⟨rfl,ev,rfl⟩
    obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
    · exact .inl ⟨c.pre,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,raised,raised.1,raised.2,raised.2⟩
    · rw [show observed c.pre q = c.pre from stable.2]
      exact .inr ⟨⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,stable.1,stable.2⟩
end

def exactOfTail (b : Classes.StepBranch) (test : NodeID → NodeState → AppendEntriesRequest → Bool)
    (iff : ∀ s : Step, letI : Config.InitialConfiguration := ⟨s.cfg⟩
      sig s.context b ↔ HandReadersBGate.Source s.context ∧ ∃ src q,
        s.context.event = .receive src (.appendEntriesRequest q) ∧ test s.context.actor s.context.pre q) :
    Exact b where
  eval := fun cfg pre act post past =>
    let yes := actorRead (fun n st ev _ => match ev with
      | .receive _ (.appendEntriesRequest q) => test n st q
      | _ => false) cfg pre act post past
    yes && HandReadersBGate.active cfg pre act post past
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,iff, Bool.and_eq_true, actorRead_at, HandReadersBGate.live, and_comm]
    apply and_congr_left
    intro _
    cases s.context.event with
    | internal => simp
    | receive n m => cases m <;> simp [and_assoc]

end ConsensusCoverage.HandReadersTrunkA.Request
