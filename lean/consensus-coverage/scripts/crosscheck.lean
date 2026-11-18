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

/-- Evaluator: `yes` on the initial state. -/
theorem left_backed_inl_initial :
    Classes.state_committed_logs_comparable_left_backed_inl (Frame.start s0) :=
  ⟨0, initialNodeState config 0, by simp [Now, Frame.start, s0], 0, Or.inl rfl, rfl⟩

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
    ¬ Committed (Frame.start s0) term part := by
  rintro (old | ⟨n, st, base, index, step, _, _⟩)
  · exact old
  · obtain ⟨⟨now, _⟩, _, _, sig, _⟩ := step
    simp only [s0, List.map_cons, List.map_nil, List.mem_cons, Prod.mk.injEq,
      List.not_mem_nil, or_false] at now
    rcases now with ⟨-, rfl⟩ | ⟨-, rfl⟩ | ⟨-, rfl⟩ <;> simp [no_signature_initial] at sig

/-- Evaluator: `no` on the initial state. -/
theorem left_backed_inr_initial :
    ¬ Classes.state_committed_logs_comparable_left_backed_inr (Frame.start s0) := by
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
theorem leader_led_now_after_inl_s1 (f : Frame) :
    ¬ Classes.step_leader_led_now_after_inl f s1 := by
  rintro ⟨-, -, -, ⟨-, n, st, now, role, -⟩, -⟩
  have : (n, st) ∈ s1.nodes.filter (fun p => p.2.role == .primary) :=
    List.mem_filter.mpr ⟨now, by simp [role]⟩
  simp [s1_primaries] at this

/-! A positive check needs the actual local transition and the invariant before it. -/

def a2 : Model.Action := .local 0 (.sendEntries 1 1)

def r2 := (Model.Node.step (CCF.Capabilities.record 0) 0 (initialNodeState config 0)
  (.internal (.sendEntries 1 1))).run {}

def post2 : NodeState := match r2 with
  | some (post, _) => post
  | none => initialNodeState config 0

def out2 : CCF.Outputs NodeID Message Notification := match r2 with
  | some (_, outputs) => outputs
  | none => {}

/-- The step: node 0 (the bootstrap primary) sends entries to node 1 and records it. -/
def s2 : Model.State := ((transitionSystem config [0, 1, 2]).step s0 a2).getD s0

theorem s2_step : (transitionSystem Config.INITIAL_CONFIGURATION [0, 1, 2]).step s0 a2 = some s2 := by
  rfl

theorem initialized : (transitionSystem Config.INITIAL_CONFIGURATION [0, 1, 2]).init s0 :=
  ⟨⟨0, by decide⟩, rfl, by
    simp [s0, protocol, Config.INITIAL_CONFIGURATION] <;> exact ⟨rfl, rfl, rfl⟩⟩

def tr2 : LocalTransition s0 s2 where
  actor := 0
  pre := initialNodeState config 0
  post := post2
  event := .internal (.sendEntries 1 1)
  outputs := out2
  pending := []
  found := rfl
  ran := rfl
  nodesEq := rfl
  networkEq := rfl
  pendingSub := nofun
  source := Or.inl ⟨_, rfl, rfl⟩
  available := fun _ eq => by cases eq

def ctx2 : Ctx (Frame.start s0) s2 := ⟨tr2, inv_initial initialized⟩

/-- Evaluator: `yes` (the actor is primary after, and its state changed: `sentIndex 1`). -/
theorem leader_led_now_after_inl_s2 :
    Classes.step_leader_led_now_after_inl (Frame.start s0) s2 := by
  have now : Now ((Frame.start s0).advance s2) 0 post2 := by
    change (0, post2) ∈ s2.nodes
    rw [tr2.nodesEq]
    exact List.mem_cons_self ..
  have role : post2.role = .primary := rfl
  have fresh : ¬ (Now (Frame.start s0) 0 post2 ∧ post2.role = .primary) := by
    rintro ⟨old, -⟩
    simp only [Now, Frame.start, s0, List.map_cons, List.map_nil, List.mem_cons, Prod.mk.injEq,
      List.not_mem_nil, or_false] at old
    rcases old with ⟨-, h⟩ | ⟨h, -⟩ | ⟨h, -⟩
    · have : post2.sentIndex 1 = (initialNodeState config 0).sentIndex 1 := by rw [h]
      exact absurd this (by decide)
    all_goals exact absurd h (by decide)
  exact ⟨ctx2, 0, post2, ⟨ctx2, 0, post2, now, role, fresh, rfl, rfl, rfl⟩,
    ⟨rfl, rfl⟩, rfl, rfl, now, role⟩

end ConsensusCoverage.CrossCheck

#print axioms ConsensusCoverage.CrossCheck.left_backed_inl_initial
#print axioms ConsensusCoverage.CrossCheck.left_backed_inr_initial
#print axioms ConsensusCoverage.CrossCheck.leader_led_now_after_inl_s1
#print axioms ConsensusCoverage.CrossCheck.leader_led_now_after_inl_s2
