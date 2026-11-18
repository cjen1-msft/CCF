module

meta import Consensus.Model
meta import ConsensusCoverage.PairQuestions
public import ConsensusCoverage.PairQuestions
import all ConsensusCoverage.PairQuestions
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.PairQuestions

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

private abbrev config : CCF.Finset NodeID := {0, 1}
private instance : Config.InitialConfiguration := ⟨config⟩

private inductive Command where
  | input (node : NodeID) (input : Input)
  | deliver (source target : NodeID)

private def Command.resolve (s : Model.State) : Command → Option Model.Action
  | .input n i => some (.local n i)
  | .deliver n k => (s.network.find? fun e => e.source == n && e.target == k).map .deliver

private def initial (nodes : List NodeID) : Model.State :=
  {nodes := nodes.map fun n => (n, initialNodeState config n)}

private def schedule : List Command := [
  .input 0 (.append [{content := .signature}]), .input 0 (.sendEntries 1 2),
  .deliver 0 1, .deliver 1 0, .input 0 (.sendEntries 1 2), .deliver 0 1, .deliver 1 0,
  .input 0 (.timeout .checkQuorum), .input 1 (.timeout .election),
  .deliver 1 0, .deliver 0 1, .deliver 1 0, .deliver 0 1]

private def replay (nodes : List NodeID) (s : Model.State) :
    List Command → Option (List (Bool × Bool × Bool))
  | [] => some []
  | cmd :: rest => do
    let act ← cmd.resolve s
    let t ← (transitionSystem config nodes).step s act
    return label s t :: (← replay nodes t rest)

public def Occurs (row : Bool × Bool × Bool) : Prop :=
  ∃ (cfg : CCF.Finset NodeID) (nodes : List NodeID) (s t : Model.State) (act : Model.Action),
    (transitionSystem cfg nodes).Reachable s ∧
      (transitionSystem cfg nodes).step s act = some t ∧ label s t = row

private theorem run_occurs {nodes : List NodeID} {s : Model.State} {cmds es}
    (reach : (transitionSystem config nodes).Reachable s) (h : replay nodes s cmds = some es) :
    ∀ e ∈ es, Occurs e := by
  induction cmds generalizing s es with
  | nil => cases h; simp
  | cons cmd rest ih =>
    simp only [replay, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
    obtain ⟨act, _, t, step, tail, followed, eq⟩ := h
    cases eq
    intro e mem
    rcases List.mem_cons.1 mem with rfl | old
    · exact ⟨config,nodes,s,t,act,reach,step,rfl⟩
    · exact ih (.step reach step) followed e old

private def covers : Bool :=
  match replay [0,1] (initial [0,1]) schedule, replay [0,1,2] (initial [0,1,2]) schedule with
  | some a, some b => table.all fun row => row ∈ a ∨ row ∈ b
  | _, _ => false

private theorem initialized (ns : List NodeID) (distinct : ns.Nodup) :
    (transitionSystem config ns).Reachable (initial ns) := by
  apply CCF.TransitionSystem.Reachable.initial
  refine ⟨⟨0, by decide⟩, ?_, ?_⟩ <;> simp [initial, protocol, Function.comp_def, distinct]

set_option maxRecDepth 8192 in
private theorem covers_true : covers = true := by decide +kernel

/-- Every row occurs, and no other row occurs, on a step of the original CCF machine. -/
public theorem exact (row : Bool × Bool × Bool) : row ∈ table ↔ Occurs row := by
  constructor
  · intro member
    have h := covers_true
    unfold covers at h
    split at h
    · rename_i _ _ left right
      rcases of_decide_eq_true (List.all_eq_true.1 h _ member) with hl | hr
      · exact run_occurs (initialized _ (by decide)) left _ hl
      · exact run_occurs (initialized _ (by decide)) right _ hr
    · cases h
  · rintro ⟨cfg,nodes,s,t,act,reach,stepped,rfl⟩
    letI : Config.InitialConfiguration := ⟨cfg⟩
    obtain ⟨h, prev⟩ := exec_of_reachable (nodes := nodes) (state := s) reach
    exact complete (rest := h) (.step prev (action := act) stepped)

end ConsensusCoverage.PairQuestions
