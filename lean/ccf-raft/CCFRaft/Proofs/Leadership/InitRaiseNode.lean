module

public import CCFRaft.Proofs.Leadership.InitTerms
public import CCFRaft.Proofs.Leadership.FirstReset

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Local transition facts for INIT without a primary.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety

variable [Config.InitialConfiguration]

/-- A node that can start an election has a protocol role. -/
theorem eligible_not_none {state : NodeState} {node : NodeID}
    (eligible : canStartElection state node)
    : Not (state.role = .none) := by
  rcases eligible.1 with role | role | role <;> simp [role]

/-- An election's resulting state is primary or has retired. -/
theorem wins_role {self : NodeID} {before after : NodeState}
    {event : Model.Node.Event} (wins : Wins self before event after)
    : after.role = .primary \/ after.role = .none := by
  obtain ⟨candidate, _, _, advance⟩ := wins
  rcases Advance.role advance with role | role
  · exact Or.inl (by simpa [primaryState] using role)
  · exact Or.inr role

/-- Sending AppendEntries witnesses a primary before or after the step,
unless the sender retires during that step. -/
theorem append_sender {self : NodeID} {before after : NodeState}
    {event : Model.Node.Event} {sent : List Model.Envelope}
    (summary : Summary self before event after sent) {envelope : Model.Envelope}
    {request : AppendEntriesRequest} (member : envelope ∈ sent)
    (payload : envelope.payload = .appendEntriesRequest request)
    (active : Not (after.role = .none))
    : envelope.source = self
      /\ request.term = after.currentTerm
      /\ ((before.role = .primary /\ before.currentTerm = request.term)
          \/ (after.role = .primary /\ after.currentTerm = request.term)) := by
  obtain ⟨source, sent⟩ := CCFRaft.Proofs.Safety.Summary.sends summary envelope member
  simp only [payload] at sent
  refine ⟨source, sent.1.2.1, ?_⟩
  rcases sent.2.2 with ⟨primary, term⟩ | wins
  · exact Or.inl ⟨primary, term.symm.trans sent.1.2.1.symm⟩
  · exact Or.inr ⟨(wins_role wins).resolve_right active, sent.1.2.1.symm⟩

/-- Without a primary or accepted AppendEntries, neither log nor commit index changes. -/
theorem ledger_kept {self : NodeID} {before after : NodeState}
    {event : Model.Node.Event} {sent : List Model.Envelope}
    (summary : Summary self before event after sent)
    (notPrimary : Not (before.role = .primary))
    (afterNotPrimary : Not (after.role = .primary))
    (active : Not (after.role = .none))
    (noAppend
      : forall source request,
          event = .receive source (.appendEntriesRequest request)
          -> Not (request.term = after.currentTerm))
    : after.log = before.log /\ after.commitIndex = before.commitIndex := by
  cases CCFRaft.Proofs.Safety.Summary.kind summary with
  | same log commit => exact ⟨log, commit⟩
  | append _ _ primary _ _ _ => exact (notPrimary primary).elim
  | ack _ _ _ primary _ _ _ => exact (notPrimary primary).elim
  | accept source request received accepted =>
      exact (noAppend source request received accepted.1).elim
  | elect wins => exact ((wins_role wins).elim afterNotPrimary active).elim

/-- The exact list emitted by a broadcast to the active members. -/
def broadcast (self : NodeID) (state : NodeState) (message : Message)
    : List Model.Envelope :=
  ((state.activeMembers.erase self).sort).map
    fun target => { source := self, target, payload := message }

/-- A send loop emits exactly one envelope per listed target. -/
theorem send_loop (self : NodeID) (message : Message) (targets : List NodeID)
    : Sends
        (fun _ sent =>
          sent = targets.map fun target => { source := self, target, payload := message })
        (forIn targets PUnit.unit
          fun destination _ => do
            (Capabilities.record self : Caps).send message destination
            pure (ForInStep.yield PUnit.unit)) := by
  induction targets with
  | nil => exact Sends.pure' rfl
  | cons head tail ih =>
      rw [List.forIn_cons]
      refine Sends.bind'
        (Q :=
          fun step sent =>
            step = ForInStep.yield PUnit.unit
            /\ sent = [{ source := self, target := head, payload := message }])
        (Sends.bind' (Sends.send _ _ _)
          fun _ sent eq => Sends.pure' ⟨rfl, by simpa using eq⟩)
        fun step sent ⟨stepEq, eq⟩ => ?_
      subst stepEq eq
      exact Sends.mono ih fun _ later eq => by subst eq; simp

/-- Broadcasting sends to every other active member. -/
theorem broadcast_exact (self : NodeID) (state : NodeState) (message : Message)
    : Sends (fun _ sent => sent = broadcast self state message)
        (broadcastToOthers (Capabilities.record self) self state message) := by
  unfold broadcastToOthers broadcast
  exact Sends.bind' (send_loop self message _)
    fun _ sent eq => Sends.pure' (by simpa using eq)

/-- Every other active member occurs in the exact broadcast. -/
theorem mem_broadcast {self target : NodeID} {state : NodeState} {message : Message}
    (member : target ∈ state.activeMembers) (different : Not (target = self))
    : { source := self, target, payload := message } ∈ broadcast self state message := by
  simp only [broadcast, List.mem_map, Finset.mem_sort]
  exact ⟨target, Finset.mem_erase.mpr ⟨different, member⟩, rfl⟩

/-- A non-raising timeout starts a pre-vote and broadcasts its request. -/
theorem timeout_outcome (self : NodeID) (state : NodeState)
    : Sends
        (fun after sent =>
          after.currentTerm <= state.currentTerm
          -> after = preVoteState self state
              /\ sent
                  = broadcast self state
                      (.requestPreVoteRequest (makeRequestVoteRequest state)))
        (startElection (Capabilities.record self) state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.mono (becomeCandidate_kept self _) fun after _ ⟨_, raised⟩ cap => ?_
    simp only at raised
    omega
  · refine Sends.bind' (broadcast_exact self _ _) fun _ sent eq => Sends.pure' ?_
    intro _
    refine ⟨rfl, ?_⟩
    simpa [broadcast, NodeState.activeMembers, NodeState.activeConfigurations,
      NodeState.committedLog, makeRequestVoteRequest, lastCommittableTerm,
      lastCommittableIndex] using eq

end CCFRaft.Proofs.Leadership.InitRaise
