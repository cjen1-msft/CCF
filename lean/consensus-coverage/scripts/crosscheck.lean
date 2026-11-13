module

meta import Lean
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-!
# Cross-checks of the hand-transcribed evaluator against the generated classes

Each theorem states, in Lean, that a generated class holds (or does not hold) on a small
concrete state or step, and the comment gives the evaluator's answer on the same input
(`eval-full.lean`). The evaluator itself is not proved; these are spot checks of its
transcription.

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/crosscheck.lean
-/

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

namespace ConsensusCoverage.CrossCheck

def config : CCF.Finset NodeID := {0, 1, 2}

instance : Config.InitialConfiguration := ⟨config⟩

def s0 : Model.State :=
  { nodes := [0, 1, 2].map fun node => (node, initialNodeState config node) }

/-- Evaluator: `yes` on the initial history (context `1000...`, first canonical state). -/
theorem left_backed_inl_initial :
    Classes.state_committed_logs_comparable_left_backed_inl [s0] :=
  ⟨0, initialNodeState config 0, by simp [Now, s0], 0, Or.inl rfl, rfl⟩

theorem no_signature_initial (node index : NodeID) :
    isSignatureAt (initialNodeState config node).log index = false := by
  by_cases h : node = 0
  · subst h
    have hlog : (initialNodeState config 0).log =
        [{ term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some config } }] := by
      decide +revert
    rw [hlog]
    rcases index with _ | _ | i <;> simp [isSignatureAt, entryAt?, EntryContent.isSignature]
  · have : (initialNodeState config node).log = [] := by
      simp only [initialNodeState]
      rw [ite_eq_right]
      intro hmin
      exact h (Option.some.inj ((show config.min? = some 0 by decide).symm.trans hmin)).symm
    rw [this]
    simp [isSignatureAt, entryAt?]

theorem not_committed_initial (term : Nat) (part : List Entry) :
    ¬ Committed [s0] term part := by
  intro h
  cases h with
  | past old => cases old
  | fresh step | chained step =>
    obtain ⟨⟨now, -⟩, -, -, sig, -⟩ := step
    simp only [Now, s0, List.map_cons, List.map_nil, List.mem_cons, Prod.mk.injEq,
      List.not_mem_nil, or_false] at now
    rcases now with ⟨-, rfl⟩ | ⟨-, rfl⟩ | ⟨-, rfl⟩ <;> simp [no_signature_initial] at sig

/-- Evaluator: `no` on the initial history. -/
theorem left_backed_inr_initial :
    ¬ Classes.state_committed_logs_comparable_left_backed_inr [s0] := by
  rintro ⟨-, -, -, -, -, ⟨_, _, h, -⟩, -⟩
  exact not_committed_initial _ _ h

/-- The step: node 0 (the bootstrap primary) times out on its quorum check in the initial
state and steps down. -/
def s1 : Model.State :=
  match (transitionSystem config [0, 1, 2]).step s0 (.local 0 (.timeout .checkQuorum)) with
  | some s => s
  | none => s0

theorem s1_enabled :
    ((transitionSystem config [0, 1, 2]).step s0 (.local 0 (.timeout .checkQuorum))).isSome := by
  rfl

theorem s1_primaries :
    s1.nodes.filter (fun p => p.2.role == .primary) = [] := by
  rfl


/-- Evaluator: `no` (the actor's post state is a follower; no node is primary after). -/
theorem leader_led_now_after_inl_s1 (rest : History) :
    ¬ Classes.step_leader_led_now_after_inl [0, 1, 2] s1 s0 rest := by
  rintro ⟨-, -, -, ⟨-, n, st, now, role, -⟩, -⟩
  have : (n, st) ∈ s1.nodes.filter (fun p => p.2.role == .primary) :=
    List.mem_filter.mpr ⟨now, by simp [role]⟩
  simp [s1_primaries] at this

end ConsensusCoverage.CrossCheck

#print axioms ConsensusCoverage.CrossCheck.left_backed_inl_initial
#print axioms ConsensusCoverage.CrossCheck.left_backed_inr_initial
#print axioms ConsensusCoverage.CrossCheck.leader_led_now_after_inl_s1
