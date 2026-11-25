module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.NominationRetirementB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

-- The batch invariant constrains the term of every new entry, but does not
-- require the generalized accumulator to be the handler's actual output.
private def extra (self : NodeID) (term : Nat) : List Entry :=
  [⟨term, .transaction 42 {retirementConfirmations := {self}}⟩, ⟨term, .signature⟩,
   ⟨term, .transaction 43 {configuration := some ∅}⟩]

private def middle (self : NodeID) (s : NodeState) :=
  {s with log := s.log ++ extra self s.currentTerm}

private theorem recorded (self : NodeID) (s : NodeState)
    (ahead : s.commitIndex < highestCommittableIndex s self) :
    Advance self s (s.recordCommit self (highestCommittableIndex s self)) := by
  obtain ⟨_, _, _, eq, role⟩ := Ledger.NodeState.recordCommit_eq self s (highestCommittableIndex s self)
  rw [eq]
  exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl, rfl, ahead, rfl, role⟩

private theorem noTarget [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (s : BatchArmsB.Seed c) (m : NodeState) (eq : m = middle s.self s.before)
    (ahead : m.commitIndex < highestCommittableIndex m s.self)
    (retired : (m.recordCommit s.self (highestCommittableIndex m s.self)).isRetiredCommitted s.self)
    (missing : findSuccessor m s.self = none) : step_nominate_sends_successor_none f t c := by
  have valid : BatchState s.self s.before m [] := by
    refine ⟨⟨extra s.self s.before.currentTerm, s.before.sentIndex, eq, ?_⟩, by simp⟩
    intro e member
    simp only [extra, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl <;> rfl
  have source : (reach% step_nominate_sends_successor_none[6,1]) f t c s.self m :=
    Or.inr (.inl ⟨s.before, s.contents, s.entered, s.guards, s.guards.1, s.guards.2,
      s.guards, [], valid, BatchArmsB.start s⟩)
  have leader : m.role = .primary := eq ▸ s.guards.1
  iterate 6 right
  exact Or.inl ⟨s.self, m, Or.inr ⟨source, Nat.not_le_of_lt ahead, retired, leader, recorded _ _ ahead⟩,
    leader, leader, leader, fun _ h => by rw [missing] at h; cases h⟩

public theorem occurs : ∃ s : Step, label s (.step .nominate_sends_successor_none) = true := by
  let a := ReceiveCasesB.asSample solo 0 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  let s := BatchArmsB.seedOf (c := a.s.context) (x := a.x) a.ok
    (by decide +kernel) (by decide +kernel) (by decide +kernel)
  let m := middle a.x.base.actor a.x.base.pre
  have witness := noTarget s m rfl (by decide +kernel) (by decide +kernel) (by decide +kernel)
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr witness)⟩

end ConsensusCoverage.NominationRetirementB
