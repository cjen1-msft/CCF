module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReachPath

/-!
# Concrete schedule witnesses

Replay lists the initial snapshot followed by every post-state, in chronological
order, or returns `none` on the first disabled action. Check a small replay with
`rfl` (or kernel decision for decidable checks). Replay itself does not check
initialization: supply `Schedule.Valid` (nonempty configuration and distinct
node IDs) to obtain a `Schedule.step`. Its index is zero-based and its past is
newest first, as required by `ActionProfile.Step`.

For a positive answer, supply a concrete context recording the same action and
prove its solved predicate; do not compute the classical `ActionProfile.label`.
For a negative answer, use `EventSupport.label_false` for an excluded action
tag, a general impossibility lemma, or a proved exact reader. Failure to find a
positive witness is not a negative certificate.
-/

namespace ConsensusCoverage

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option autoImplicit false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public structure Schedule where
  cfg : CCF.Finset NodeID
  nodes : List NodeID
  actions : List Model.Action

namespace Schedule

@[expose] public def Valid (s : Schedule) : Prop := s.cfg.Nonempty ∧ s.nodes.Nodup

public instance (s : Schedule) : Decidable s.Valid :=
  inferInstanceAs (Decidable (s.cfg.Nonempty ∧ s.nodes.Nodup))

@[expose] public def initial (s : Schedule) : Model.State :=
  { nodes := s.nodes.map fun n => (n, initialNodeState s.cfg n) }

public theorem initialized (s : Schedule) (valid : s.Valid) :
    (transitionSystem s.cfg s.nodes).init s.initial := by
  refine ⟨valid.1, ?_, ?_⟩
  · simp [initial, Function.comp_def]
  · simpa [initial, protocol, Function.comp_def] using valid.2

/-- Replay a suffix from any snapshot. Use `replay` to start at initialization. -/
@[expose] public def replayFrom (s : Schedule) (before : Model.State) :
    List Model.Action → Option (List Model.State)
  | [] => some [before]
  | a :: rest => do
    let after ← networkStep s.cfg before a
    let tail ← replayFrom s after rest
    return before :: tail

@[expose] public def replay (s : Schedule) : Option (List Model.State) :=
  replayFrom s s.initial s.actions

private theorem replayFrom_shape (s : Schedule) {before : Model.State} {acts : List Model.Action}
    {states : List Model.State} (ok : replayFrom s before acts = some states) :
    states.length = acts.length + 1 ∧ states.head? = some before := by
  induction acts generalizing before states with
  | nil =>
    have eq : [before] = states := Option.some.inj ok
    subst states
    exact ⟨rfl, rfl⟩
  | cons a rest ih =>
    cases ran : networkStep s.cfg before a with
    | none => simp [replayFrom, ran] at ok
    | some after =>
      cases tail : replayFrom s after rest with
      | none => simp [replayFrom, ran, tail] at ok
      | some ts =>
        have eq : before :: ts = states := by simpa [replayFrom, ran, tail] using ok
        subst states
        exact ⟨by simp [(ih tail).1], rfl⟩

public theorem replay_length (s : Schedule) {states : List Model.State}
    (ok : s.replay = some states) : states.length = s.actions.length + 1 :=
  (replayFrom_shape s ok).1

public theorem replay_head (s : Schedule) {states : List Model.State}
    (ok : s.replay = some states) : states.head? = some s.initial :=
  (replayFrom_shape s ok).2

private theorem replayFrom_sound (s : Schedule) {before : Model.State} {acts : List Model.Action}
    {states past : List Model.State} (run : StateCoverage.Run s.cfg s.nodes before past)
    (ok : replayFrom s before acts = some states) (i : Nat) (hi : i < acts.length) :
    have len := (replayFrom_shape s ok).1
    StateCoverage.Run s.cfg s.nodes (states[i]'(by omega)) ((states.take i).reverse ++ past) ∧
      (transitionSystem s.cfg s.nodes).step (states[i]'(by omega)) acts[i] =
        some (states[i + 1]'(by omega)) := by
  induction acts generalizing before states past i with
  | nil => simp at hi
  | cons a rest ih =>
    cases ran : networkStep s.cfg before a with
    | none => simp [replayFrom, ran] at ok
    | some after =>
      cases tail : replayFrom s after rest with
      | none => simp [replayFrom, ran, tail] at ok
      | some ts =>
        have eq : before :: ts = states := by simpa [replayFrom, ran, tail] using ok
        subst states
        cases i with
        | zero =>
          have head := (replayFrom_shape s tail).2
          cases ts with
          | nil => simp at head
          | cons t ts =>
            have eq : t = after := Option.some.inj head
            subst t
            exact ⟨run, ran⟩
        | succ i =>
          have h : i < rest.length := by simpa using hi
          simpa only [List.getElem_cons_succ, List.take_succ_cons, List.reverse_cons,
            List.append_assoc, List.singleton_append] using ih (.step run ran) tail i h

/-- The indexed snapshots, action and earlier snapshots form an actual run. -/
public theorem replay_sound (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) :
    have len := s.replay_length ok
    StateCoverage.Run s.cfg s.nodes (states[i.val]'(by have := i.isLt; omega))
      (states.take i.val).reverse ∧
    (transitionSystem s.cfg s.nodes).step (states[i.val]'(by have := i.isLt; omega))
      s.actions[i.val] = some (states[i.val + 1]'(by have := i.isLt; omega)) := by
  simpa only [List.append_nil] using
    replayFrom_sound s (.initial (s.initialized valid)) ok i.val i.isLt

/-- Construct the recorded step without reducing its soundness proof. -/
@[expose] public def step (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) : ActionProfile.Step :=
  have len := s.replay_length ok
  { cfg := s.cfg
    nodes := s.nodes
    before := states[i.val]'(by have := i.isLt; omega)
    past := (states.take i.val).reverse
    act := s.actions[i.val]
    after := states[i.val + 1]'(by have := i.isLt; omega)
    run := (s.replay_sound valid ok i).1
    ran := (s.replay_sound valid ok i).2 }

@[simp] public theorem step_cfg (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) :
    (s.step valid ok i).cfg = s.cfg := rfl

@[simp] public theorem step_before (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) :
    have len := s.replay_length ok
    (s.step valid ok i).before = states[i.val]'(by have := i.isLt; omega) := rfl

@[simp] public theorem step_past (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) :
    (s.step valid ok i).past = (states.take i.val).reverse := rfl

@[simp] public theorem step_act (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) :
    (s.step valid ok i).act = s.actions[i.val] := rfl

@[simp] public theorem step_after (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (i : Fin s.actions.length) :
    have len := s.replay_length ok
    (s.step valid ok i).after = states[i.val + 1]'(by have := i.isLt; omega) := rfl

@[expose] public def lastStep (s : Schedule) (valid : s.Valid) {states : List Model.State}
    (ok : s.replay = some states) (nonempty : s.actions ≠ []) : ActionProfile.Step :=
  s.step valid ok ⟨s.actions.length - 1, by
    have := List.length_pos_iff.mpr nonempty
    omega⟩

/-- Supply a context with the recorded action and witnesses for the solved predicate. -/
public theorem label_true_of_solved (s : ActionProfile.Step) (b : Classes.StepBranch)
    (c : @Ctx ⟨s.cfg⟩ s.frame s.after) (recorded : @ActionContext.action ⟨s.cfg⟩ _ _ c = s.act)
    (witness : @SolvedWitnesses.sig ⟨s.cfg⟩ _ _ c b) :
    ActionProfile.label s (.step b) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have same := (s.context_eq c).1 recorded
  exact (ActionProfile.label_true s (.step b)).2
    ((SolvedWitnesses.sig_iff s.context b).2 (same ▸ witness))

private def send : Schedule := ⟨{0, 1}, [0, 1], [.local 0 (.sendEntries 1 1)]⟩

private theorem sendValid : send.Valid := by decide +kernel

private def sendAfter : Model.State :=
  (networkStep send.cfg send.initial (.local 0 (.sendEntries 1 1))).getD send.initial

private theorem sendReplayed : send.replay = some [send.initial, sendAfter] := rfl

private def sendTwice : Schedule := { send with actions := send.actions ++ send.actions }

private theorem sendTwiceValid : sendTwice.Valid := sendValid

private def sendTwiceAfter : Model.State :=
  (networkStep send.cfg sendAfter (.local 0 (.sendEntries 1 1))).getD sendAfter

private theorem sendTwiceReplayed :
    sendTwice.replay = some [send.initial, sendAfter, sendTwiceAfter] := rfl

example :
    (sendTwice.step sendTwiceValid sendTwiceReplayed ⟨1, by decide⟩).past = [send.initial] :=
  rfl

example : ({ send with actions := [.local 2 (.sendEntries 1 1)] } : Schedule).replay = none :=
  rfl

private def sendStep : ActionProfile.Step := send.lastStep sendValid sendReplayed (by decide)

private def sendLocal := (Model.Node.step (CCF.Capabilities.record 0) 0
  (initialNodeState send.cfg 0) (.internal (.sendEntries 1 1))).run {}

private def sendPost : NodeState := (sendLocal.map Prod.fst).getD (initialNodeState send.cfg 0)

private def sendOutputs : CCF.Outputs NodeID Message Notification := (sendLocal.map Prod.snd).getD {}

local instance : Config.InitialConfiguration := ⟨send.cfg⟩

private def sendContext : Ctx sendStep.frame sendStep.after where
  tr :=
    { actor := 0
      pre := initialNodeState send.cfg 0
      post := sendPost
      event := .internal (.sendEntries 1 1)
      outputs := sendOutputs
      pending := []
      found := rfl
      ran := rfl
      nodesEq := rfl
      networkEq := rfl
      pendingSub := nofun
      source := .inl ⟨_, rfl, rfl⟩
      available := fun _ eq => by cases eq }
  inv := inv_initial (send.initialized sendValid)

private theorem sendNow : Now (sendStep.frame.advance sendStep.after) 0 sendPost :=
  List.mem_cons_self ..

private theorem sendFresh : ¬ Now sendStep.frame 0 sendPost := by
  intro old
  change (0, sendPost) ∈ send.initial.nodes at old
  have stateEq : sendPost = initialNodeState send.cfg 0 := by
    simpa [send, initial] using old
  have eq := congrArg (fun st : NodeState => st.sentIndex 1) stateEq
  exact (show (1 : Nat) ≠ 0 by decide) eq

private theorem sendLeader : ActionProfile.label sendStep (.step .leader_led_now_after_inl) = true := by
  apply label_true_of_solved sendStep _ sendContext rfl
  change SolvedWitnesses.step_leader_led_now_after_inl _ _ sendContext
  refine ⟨?_, sendNow, rfl⟩
  reach_unfold SolvedWitnesses.step_leader_led_now_after_inl[0]
  exact ⟨sendNow, rfl, fun h => sendFresh h.1, rfl⟩

private def sendEnvelope : Model.Envelope :=
  sendOutputs.outgoing.head (by decide +kernel)

private def sendRequest : AppendEntriesRequest :=
  ⟨BOOTSTRAP_TERM, 0, 0, (initialNodeState send.cfg 0).log, 0⟩

private theorem sendMessage :
    ActionProfile.label sendStep (.step .new_message_h_appendEntriesRequest) = true := by
  apply label_true_of_solved sendStep _ sendContext rfl
  change SolvedWitnesses.step_new_message_h_appendEntriesRequest _ _ sendContext
  have mem : sendEnvelope ∈ sendContext.sent := by
    change sendEnvelope ∈ sendOutputs.outgoing
    exact List.head_mem _
  have ⟨source, ok⟩ := Summary.sends sendContext.sum sendEnvelope mem
  refine ⟨sendEnvelope, ?_, source, ok, sendRequest, rfl, rfl, mem⟩
  have pending : Pending (sendStep.frame.advance sendStep.after) sendEnvelope := mem
  have fresh : ¬ Pending sendStep.frame sendEnvelope := List.not_mem_nil
  reach_unfold SolvedWitnesses.step_new_message_h_appendEntriesRequest[0]
  refine ⟨?_, mem, pending, rfl⟩
  reach_unfold SolvedWitnesses.step_new_message_h_appendEntriesRequest[0, 0]
  exact ⟨pending, fresh, rfl⟩

end Schedule
end ConsensusCoverage
