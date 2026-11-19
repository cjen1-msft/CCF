module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.StutterProfile
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-! Sending an already queued heartbeat can change the protocol state without
changing any generated proof answer at the step or either endpoint. -/

namespace ConsensusCoverage.InertProfile

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open StutterProfile (SameSupport UnsignedUnvoted diagonal)

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

/-- Node states and queue support are unchanged. In the unsigned/unvoted class
this also preserves log evidence in the actual initialized fold. -/
public theorem label_eq (s : ActionProfile.Step) (support : SameSupport s.before s.after)
    (quiet : UnsignedUnvoted s.before) :
    ActionProfile.label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) :=
  StutterProfile.label_eq_of_support s support (StutterProfile.step_stable_of_nodes s support.1 quiet)

private def packet (src dst : NodeID) (st : NodeState) (last : Nat) : Model.Envelope :=
  ⟨src, dst, .appendEntriesRequest (makeAppendEntriesRequest st dst last)⟩

/-- A sufficient check for a *validated* step: an unsigned/unvoted state and a
local `sendEntries` whose end is the current send index and whose exact
envelope is already pending. It is not an enabledness check. -/
public def gate (s : Model.State) : Model.Action → Bool
  | .local src (.sendEntries dst last) =>
    match nodeState s src with
    | none => false
    | some st =>
      st.sentIndex dst == last && s.network.contains (packet src dst st last) &&
        s.nodes.all (fun (_, n) => n.votedFor.isNone && n.log.all (! ·.content.isSignature))
  | _ => false

private theorem sendResult (src dst : NodeID) (st : NodeState) (last : Nat) :
    Sends (fun post sent =>
      post = {st with sentIndex := CCF.Function.update st.sentIndex dst last} ∧
      sent = [packet src dst st last]) (sendEntries (Capabilities.record src) src st dst last) := by
  unfold sendEntries
  apply Sends.guard_bind
  intro _
  apply Sends.bind' (Sends.send _ _ _)
  rintro _ _ rfl
  exact Sends.pure' ⟨rfl, rfl⟩

private theorem replace_eq {state : Model.State} {src : NodeID} {st : NodeState}
    (distinct : (state.nodes.map Prod.fst).Nodup) (found : nodeState state src = some st) :
    Concrete.replaceNode state.nodes src st = state.nodes := by
  unfold Concrete.replaceNode
  refine (List.map_congr_left (g := id) ?_).trans (List.map_id _)
  rintro ⟨n, x⟩ mem
  by_cases eq : n = src
  · subst n
    have same := state_unique distinct mem (Concrete.mem_of_nodeState found)
    simp [same]
  · simp [eq]

private theorem send_shape {cfg ns src dst last before after st past}
    (run : StateCoverage.Run cfg ns before past)
    (ran : (transitionSystem cfg ns).step before (.local src (.sendEntries dst last)) = some after)
    (found : nodeState before src = some st) (atIndex : st.sentIndex dst = last) :
    after.nodes = before.nodes ∧ after.network = before.network ++ [packet src dst st last] := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨pre, post, outputs, loc, acted, result⟩ := Concrete.step_local ran
  have same := Option.some.inj (loc.symm.trans found)
  subst pre
  obtain ⟨_, outgoing, postEq, sent⟩ := sendResult src dst st last _ _ _ acted
  have postSame : post = st := by rw [postEq, ← atIndex, CCF.Function.update_eq_self]
  have distinct := (@StateCoverage.run_inv ‹_› _ _ _ run).distinct
  have nodes : (before.nodes.map Prod.fst).Nodup := by
    simpa only [StateCoverage.frame_current] using distinct
  refine ⟨?_, ?_⟩
  · rw [result, postSame]
    exact replace_eq nodes found
  · rw [result]
    change before.network ++ outputs.outgoing = _
    rw [outgoing, sent]
    rfl

private theorem gateData {s : Model.State} {a : Model.Action} (passes : gate s a = true) :
    ∃ src dst last st, a = .local src (.sendEntries dst last) ∧ nodeState s src = some st ∧
      st.sentIndex dst = last ∧ packet src dst st last ∈ s.network ∧ UnsignedUnvoted s := by
  cases a with
  | deliver => simp [gate] at passes
  | «local» src i =>
    cases i <;> try simp [gate] at passes
    case sendEntries dst last =>
      cases found : nodeState s src with
      | none => simp [found] at passes
      | some st =>
        simp only [found, Bool.and_eq_true, beq_iff_eq] at passes
        exact ⟨src, dst, last, st, rfl, found, passes.1.1, of_decide_eq_true passes.1.2,
          StutterProfile.unsigned_check passes.2⟩

/-- A passing recorded step adds one occurrence of an existing envelope,
without changing any node state. -/
public theorem gate_effect (s : ActionProfile.Step) (passes : gate s.before s.act = true) :
    SameSupport s.before s.after ∧ s.after.network.length = s.before.network.length + 1 := by
  obtain ⟨src, dst, last, st, action, found, atIndex, queued, _⟩ := gateData passes
  have ran := s.ran
  rw [action] at ran
  have ⟨nodes, network⟩ := send_shape s.run ran found atIndex
  constructor
  · refine ⟨nodes, ?_⟩
    intro e
    simp only [network, List.mem_append, List.mem_singleton]
    exact ⟨fun h => h.elim id (· ▸ queued), Or.inl⟩
  · simp [network]

/-- Use the gate only after checking the recorded action. This gives every
answer, including the endpoints computed with the original history. -/
public theorem gate_sound (s : ActionProfile.Step) (passes : gate s.before s.act = true) :
    ActionProfile.label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) := by
  obtain ⟨_, _, _, _, _, _, _, _, quiet⟩ := gateData passes
  exact label_eq s (gate_effect s passes).1 quiet

private abbrev cfg : FullProfile.Configuration := {0, 1}
private abbrev nodes : List NodeID := [0, 1]

private def initial : Model.State :=
  {nodes := nodes.map fun n => (n, initialNodeState cfg n)}

private theorem initialized : (transitionSystem cfg nodes).init initial := by
  exact ⟨by decide, by decide, by simp [initial, protocol, nodes]⟩

private def send : Model.Action := .local 0 (.sendEntries 1 0)

private def first : Option Model.State := (transitionSystem cfg nodes).step initial send
private theorem first_ok : first.isSome := by decide +kernel
private def queued : Model.State := first.get first_ok

private def second : Option Model.State := (transitionSystem cfg nodes).step queued send
private theorem second_ok : second.isSome := by decide +kernel
private def doubled : Model.State := second.get second_ok

private def witnessStep : ActionProfile.Step :=
  ⟨cfg, nodes, queued, [initial], send, doubled,
    .step (.initial initialized) (Option.some_get _).symm, (Option.some_get _).symm⟩

private def heartbeat : Model.Envelope :=
  ⟨0, 1, .appendEntriesRequest ⟨BOOTSTRAP_TERM, 0, 0, [], 0⟩⟩

/-- Two sends from a voter to another voter. The second successful send
changes the packet count from one to two, with the same empty AppendEntries
envelope. All 433 step answers are false and both state keys are `(true,false)`. -/
public theorem duplicate_heartbeat_witness :
    ∃ s : ActionProfile.Step, s.cfg = {0, 1} ∧ s.nodes = [0, 1] ∧
      s.act = .local 0 (.sendEntries 1 0) ∧ gate s.before s.act = true ∧
      s.before.network = [⟨0, 1, .appendEntriesRequest ⟨BOOTSTRAP_TERM, 0, 0, [], 0⟩⟩] ∧
      s.after.network = s.before.network ++ s.before.network ∧
      s.after ≠ s.before ∧ SameSupport s.before s.after ∧
      ActionProfile.label s = diagonal (ProofContexts.answers (true, false)) := by
  have passes : gate witnessStep.before witnessStep.act = true := by decide +kernel
  have key : StateCoverage.read cfg queued [initial] = (true, false) := by decide +kernel
  have beforeQ : queued.network = [heartbeat] := rfl
  have afterQ : doubled.network = queued.network ++ queued.network := rfl
  have ⟨support, longer⟩ := gate_effect witnessStep passes
  have changed : witnessStep.after ≠ witnessStep.before := by
    intro eq
    rw [eq] at longer
    omega
  exact ⟨witnessStep, rfl, rfl, rfl, passes, beforeQ, afterQ, changed, support,
    (gate_sound witnessStep passes).trans (congrArg (diagonal ∘ ProofContexts.answers) key)⟩

end ConsensusCoverage.InertProfile
