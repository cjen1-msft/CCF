module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.FollowerArmsB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile SolvedWitnesses DeepSchedulesB FollowerFoldCasesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

private theorem erased [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (seed : Loop c 1 2) : (reach% step_fromLeader_loop_entries_nil[0]) f t c := by
  obtain ⟨q, entry, _⟩ := seed
  change (reach% step_fromLeader_loop_entries_cons[0,0,0]) f t c 1 q at entry
  rcases entry with ⟨st, obs, rest⟩ | ⟨st, obs, rest⟩
  all_goals
    obtain ⟨before, src, m, recv, suffix⟩ := obs
    have drop : (reach% step_fromLeader_loop_entries_nil[0,0,0,0]) f t c st q :=
      ⟨1, before, src, m, recv, suffix⟩
  · exact Or.inl ⟨st, q, drop, rest⟩
  · exact Or.inr ⟨st, q, drop, rest⟩

local macro "finish_fold" : tactic => `(tactic|
  repeat' first
    | rfl
    | exact Or.inl rfl
    | exact Or.inr rfl
    | exact Nat.le_refl _
    | exact Nat.le_max_left _ _
    | exact Nat.le_max_right _ _
    | exact Nat.zero_le _
    | apply And.intro
    | refine Exists.intro (none : Option Nat) ?_
    | refine Exists.intro Role.none ?_
    | refine Exists.intro false ?_
    | refine Exists.intro (2 : Nat) ?_
    | decide +kernel)

public def questions : List Classes.StepBranch :=
  [.fromLeader_loop_entries_nil, .fromLeader_loop_entries_cons, .fromLeader_loop_signature_pos,
   .fromLeader_loop_signature_neg, .fromLeader_loop_roleCase_inl, .fromLeader_loop_roleCase_inr]

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {b : Classes.StepBranch} (mem : b ∈ questions) (seed : Loop c 1 2) : sig c b := by
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl
  all_goals left
  · exact erased seed
  · exact ⟨1, 2, seed, [], Ledger.fromLeader_loop 1 2 []⟩
  · exact ⟨1, 2, seed, sg, [], Ledger.fromLeader_loop 1 2 [], state [], rfl, Nat.le_refl _⟩
  · exact ⟨1, 2, seed, tx, [], Ledger.fromLeader_loop 1 2 [], state [], by decide +kernel, Nat.le_refl _⟩
  all_goals
    refine ⟨1, 2, seed, sg, [], Ledger.fromLeader_loop 1 2 [], state [sg], rfl, ?_⟩
    finish_fold

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample copyCommit 4 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr (casesOf mem copyLoop))⟩

end ConsensusCoverage.FollowerArmsB
