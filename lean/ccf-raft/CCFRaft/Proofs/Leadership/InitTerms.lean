module

public import CCFRaft.Liveness.Assumptions.Round
public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Proofs.Replication.Lead

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Terms carried by outstanding packets

Every envelope a node sends carries a term no newer than the sender's own term
after the step, and a node's term never decreases. So an outstanding packet
carries a term no newer than its sender's current term. While every participant
stays at or below a term, every packet between participants does too, and the
first step that moves a participant past it starts a round.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary (sent_summary term_mono)
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasNetwork (pending)

variable [Config.InitialConfiguration]

/-- An envelope a step sends carries at most the sender's new term, when the
sender's log holds no newer term. -/
theorem Summary.sent_term_le {self : NodeID} {before : NodeState}
    {event : Model.Node.Event} {after : NodeState} {sent : List Model.Envelope}
    (summary : Summary self before event after sent)
    (logLe : forall index, termAt after.log index <= after.currentTerm)
    {envelope : Model.Envelope} (member : envelope ∈ sent)
    : envelope.payload.term <= after.currentTerm := by
  obtain ⟨_, ok⟩ := Summary.sends summary envelope member
  cases h : envelope.payload with
  | appendEntriesRequest request =>
      simp only [h] at ok
      have := ok.1.2.1
      simp only [Message.term]
      omega
  | appendEntriesResponse response =>
      simp only [h] at ok
      simp only [Message.term]
      rcases ok.1 with eq | ⟨index, eq⟩
      · omega
      · have := logLe index
        omega
  | requestVoteRequest request =>
      simp only [h] at ok
      have := ok.1
      simp only [Message.term]
      omega
  | requestVoteResponse response =>
      simp only [h] at ok
      have := ok.1
      simp only [Message.term]
      omega
  | requestPreVoteRequest request =>
      simp only [h, Message.term] at ok ⊢
      omega
  | requestPreVoteResponse response =>
      simp only [h, Message.term] at ok ⊢
      omega
  | proposeRequestVoteRequest proposed =>
      simp only [h] at ok
      have := ok.1
      simp only [Message.term]
      omega

section Trace

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- An outstanding packet carries at most its sender's current term. -/
theorem pending_term_le {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {packet : Packet}
    (member : packet ∈ pending point)
    : exists state,
        nodeState (proto point) packet.envelope.source = some state
        /\ packet.envelope.payload.term <= state.currentTerm := by
  obtain ⟨sent, lt, sentAt⟩ := admissible.pending_sent found member
  obtain ⟨actor, event, state, next, sends, nextFound, summary, emitted⟩ :=
    sent_summary admissible sentAt
  obtain ⟨sourceEq, _⟩ := Summary.sends summary _ emitted
  obtain ⟨sentPoint, sentFound, nodeFound⟩ := Trace.nodeAt_eq_some.mp nextFound
  obtain ⟨rest, exec⟩ := history_at admissible sentFound
  have logLe : forall index, termAt next.log index <= next.currentTerm :=
    termAt_le_term (good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _))
      (now_of_found nodeFound)
  have sentLe := Summary.sent_term_le summary logLe emitted
  obtain ⟨later, laterFound, grows⟩ := term_mono admissible lt nextFound found
  obtain ⟨point', found', laterNode⟩ := Trace.nodeAt_eq_some.mp laterFound
  rw [found, Option.some.injEq] at found'
  subst found'
  rw [sourceEq]
  exact ⟨later, laterNode, sentLe.trans grows⟩

end Trace

/-! ## Rounds -/

section Rounds

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- Every participant is at or below `term` at index `c`. -/
def Low (trace : Trace W Liveness.Event) (participants : Finset NodeID) (c term : Nat)
    : Prop :=
  forall point node state,
    trace.stateAt c = some point
    -> node ∈ participants
    -> nodeState (proto point) node = some state
    -> state.currentTerm <= term

variable {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)
  {participants : Finset NodeID}

include admissible

/-- A step that moves a participant past a term bounding every participant starts
a round. -/
theorem roundStart_of_low {c term : Nat} (low : Low trace participants c term)
    {step : CCF.Execution.Step W Liveness.Event} (stepped : trace.stepAt c = some step)
    {node : NodeID} (member : node ∈ participants) {state : NodeState}
    (nodeFound : nodeState (proto step.after) node = some state)
    (raised : term < state.currentTerm)
    : RoundStart trace participants c term where
  low := low
  messages :=
    fun point packet found queued sourceIn _ => by
      obtain ⟨state, nodeFound, le⟩ := pending_term_le admissible found queued
      exact le.trans (low point _ state found sourceIn nodeFound)
  raise := ⟨step, node, state, stepped, member, nodeFound, raised⟩

/-- Without a round start at `c`, a term bounding every participant keeps
bounding them after the step. -/
theorem Low.step {c term : Nat} (low : Low trace participants c term)
    (none : Not (RoundStart trace participants c term))
    : Low trace participants (c + 1) term := by
  intro point node state found member nodeFound
  obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
  by_contra raised
  exact none (roundStart_of_low admissible low stepped member nodeFound (by omega))

/-- Without round starts from `c` up to `last`, a term bounding every
participant at `c` keeps bounding them through `last`. -/
theorem Low.later {c term : Nat} (low : Low trace participants c term) {last : Nat}
    (le : c <= last)
    (none
      : forall index,
          c <= index -> index < last -> Not (RoundStart trace participants index term))
    : Low trace participants last term := by
  induction last, le using Nat.le_induction with
  | base => exact low
  | succ last le ih =>
      exact (ih fun index lower upper => none index lower (by omega)).step admissible
        (none last le (by omega))

end Rounds

end CCFRaft.Proofs.Leadership
