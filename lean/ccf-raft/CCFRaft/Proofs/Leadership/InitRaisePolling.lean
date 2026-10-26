module

public import CCFRaft.Proofs.Leadership.InitRaiseBest

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Pre-votes accumulate while a capped participant cannot time out or receive
current-term AppendEntries.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety

variable [Config.InitialConfiguration]

/-- A polling node keeps its role and votes without obtaining a quorum. -/
def Polls (before after : NodeState) : Prop :=
  after.role = .preVoteCandidate
  /\ before.preVotesGranted ⊆ after.preVotesGranted
  /\ Not (hasQuorum after.activeConfigurations after.preVotesGranted)

/-- A polling node can stay unchanged. -/
theorem Polls.refl (state : NodeState) (role : state.role = .preVoteCandidate)
    (noQuorum : Not (hasQuorum state.activeConfigurations state.preVotesGranted))
    : Polls state state :=
  ⟨role, Finset.Subset.refl _, noQuorum⟩

/-- A message at or below the receiver's term leaves term observation unchanged. -/
theorem observe_capped (state : NodeState) (message : Message)
    (cap : message.term <= state.currentTerm)
    : observeTerm state message = state := by
  cases message with
  | appendEntriesResponse response =>
      simp only [observeTerm]
      split
      · exact updateTerm_of_le cap
      · rfl
  | proposeRequestVoteRequest _ => rfl
  | _ => exact updateTerm_of_le cap

section Steps

variable (self : NodeID)
local notation "caps" => (Capabilities.record self : Caps)

/-- A capped candidacy is impossible because creating it increases the term. -/
theorem candidate_not_capped (state : NodeState)
    {P : NodeState -> List Model.Envelope -> Prop}
    : Sends (fun after sent => after.currentTerm <= state.currentTerm -> P after sent)
        (becomeCandidate caps state self) := by
  exact Sends.mono (becomeCandidate_kept self state) fun _ _ result cap => by
    omega

/-- A non-raising timeout starts polling with its self-vote and without a quorum. -/
theorem timeout_polling (state : NodeState)
    : Sends
        (fun after _ =>
          after.currentTerm <= state.currentTerm
          -> after.role = .preVoteCandidate
              /\ self ∈ after.preVotesGranted
              /\ Not (hasQuorum after.activeConfigurations after.preVotesGranted))
        (startElection caps state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ _ _ => ?_
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => candidate_not_capped self _) fun noQuorum => ?_
  exact Sends.bind' (broadcast_sends self _ _) fun _ _ _ =>
    Sends.pure' (fun _ => ⟨rfl, Finset.mem_singleton_self _, noQuorum⟩)

/-- Polling survives receptions until a new term or a current-term AppendEntries arrives. -/
theorem receive_polling (state : NodeState) (source : NodeID) (message : Message)
    (role : state.role = .preVoteCandidate)
    (noQuorum : Not (hasQuorum state.activeConfigurations state.preVotesGranted))
    (cap : message.term <= state.currentTerm)
    (old
      : forall request,
          message = .appendEntriesRequest request -> request.term < state.currentTerm)
    : Sends (fun after _ => after.currentTerm <= state.currentTerm -> Polls state after)
        (receive caps self source state message) := by
  have same := Polls.refl state role noQuorum
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (fun _ => same)) fun _ => ?_
  rw [observe_capped state message cap]
  cases message with
  | appendEntriesRequest request =>
      have older := old request rfl
      unfold handleAppendEntriesRequest
      simp only [ne_of_lt older, false_and, ite_false, older, true_or, ite_true]
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (fun _ => same)
  | appendEntriesResponse response =>
      simp only [handleAppendEntriesResponse, role, ne_eq, reduceCtorEq,
        not_false_eq_true, bne_iff_ne, ite_true]
      exact Sends.pure' (fun _ => same)
  | requestVoteRequest request =>
      unfold handleRequestVoteRequest
      refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
      intro _
      split <;> exact ⟨role, Finset.Subset.refl _, noQuorum⟩
  | requestPreVoteRequest request =>
      unfold handleRequestPreVoteRequest
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (fun _ => same)
  | requestVoteResponse response =>
      simp only [handleRequestVoteResponse, role, reduceCtorEq, false_and, ite_false]
      exact Sends.pure' (fun _ => same)
  | requestPreVoteResponse response =>
      unfold handleRequestPreVoteResponse
      refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (fun _ => same)
      refine Sends.ite' (fun _ => candidate_not_capped self _) fun notQuorum => ?_
      exact Sends.pure' (fun _ => ⟨role, Finset.subset_insert _ _, notQuorum⟩)
  | proposeRequestVoteRequest term =>
      unfold handleProposeRequestVoteRequest
      exact Sends.ite' (fun _ => candidate_not_capped self _) fun _ =>
        Sends.pure' (fun _ => same)

/-- A polling node has no enabled local action other than an election timeout. -/
theorem local_polling (state : NodeState) (input : Input)
    (role : state.role = .preVoteCandidate)
    (notTimeout : Not (input = .timeout .election))
    : Sends (fun after _ => after.currentTerm <= state.currentTerm -> Polls state after)
        (act caps self state input) := by
  have notPrimary : Not (state.role = .primary) := by rw [role]; simp
  cases input with
  | timeout kind =>
      cases kind with
      | election => exact (notTimeout rfl).elim
      | checkQuorum =>
          simp only [act]
          unfold checkQuorum
          exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed.1).elim
  | append entries =>
      simp only [act]
      unfold appendBatch
      exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed.1).elim
  | sendEntries destination ends =>
      simp only [act]
      unfold sendEntries
      exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed.1).elim
  | nominateSuccessor =>
      simp only [act]
      unfold nominateSuccessor
      exact Sends.bind' Sends.guard' fun _ _ ⟨allowed, _⟩ => (notPrimary allowed).elim

/-- A capped polling node counts a granted response from an eligible peer. -/
theorem response_counted (state : NodeState) (source : NodeID)
    (response : RequestVoteResponse) (role : state.role = .preVoteCandidate)
    (peer : source ∈ eligiblePeers state self) (term : response.term = state.currentTerm)
    (granted : response.voteGranted = true)
    : Sends
        (fun after _ =>
          after.currentTerm <= state.currentTerm -> source ∈ after.preVotesGranted)
        (receive caps self source state (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun no => by simp [peer] at no) fun _ => ?_
  rw [observe_capped state _ (by simp only [Message.term, term]; exact le_rfl)]
  simp only [handleRequestPreVoteResponse, role, term, granted, and_self, ite_true]
  exact Sends.ite' (fun _ => candidate_not_capped self _) fun _ =>
    Sends.pure' (fun _ => Finset.mem_insert_self _ _)

/-- A same-term up-to-date pre-vote gets a granted response from an unaware node. -/
theorem request_granted (state : NodeState) (source : NodeID)
    (request : RequestVoteRequest) (term : request.term = state.currentTerm)
    (fresh : voteLogUpToDate state request) (unknown : state.primaryKnown = false)
    : Sends
        (fun after sent =>
          after = state
          /\ sent
              = [{
                  source := self,
                  target := source,
                  payload :=
                    .requestPreVoteResponse
                      { term := state.currentTerm, voteGranted := true }
                }])
        (receive caps self source state (.requestPreVoteRequest request)) := by
  simp only [receive]
  refine Sends.ite' (fun no => by simp at no) fun _ => ?_
  rw [observe_capped state _ (by simp only [Message.term, term]; exact le_rfl)]
  simp only [handleRequestPreVoteRequest, term, fresh, unknown, Bool.not_false, and_self,
    decide_true]
  exact Sends.bind' (Sends.send _ _ _)
    fun _ sent eq => Sends.pure' ⟨rfl, by simpa using eq⟩

end Steps

section Trace

open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

/-- A node-local input comes from the corresponding recorded local event. -/
theorem internal_event {step : Execution.Step W Liveness.Event} {action : Model.Action}
    {actor : NodeID} {input : Input} {event : Model.Node.Event}
    (selected : step.action.action = some action)
    (acts : CCFRaft.Proofs.StablePrimary.Acts action actor event)
    (internal : event = .internal input)
    : step.action = .local actor input := by
  cases eq : step.action with
  | «local» node localInput =>
      simp only [eq, Liveness.Event.action, Option.some.injEq] at selected
      subst action
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal
      rw [actorEq]
  | deliver packet =>
      simp only [eq, Liveness.Event.action, Option.some.injEq] at selected
      subst action
      rw [acts.2] at internal
      cases internal
  | _ => simp [eq, Liveness.Event.action] at selected

include admissible

/-- Until another timeout, capped polling survives and only gains votes.
Its failure to reach a quorum follows from the cap on terms. -/
theorem polling_later {start since last term : Nat} {duration : Real}
    {participants : Finset NodeID} {first point : W} {node : NodeID}
    {initial state : NodeState} (good : GoodPeriod trace start duration participants)
    (afterStart : start <= since) (firstFound : trace.stateAt since = some first)
    (initialFound : nodeState (proto first) node = some initial)
    (initialTerm : initial.currentTerm = term) (member : node ∈ participants)
    (initialRole : initial.role = .preVoteCandidate)
    (initialQuorum : Not (hasQuorum initial.activeConfigurations initial.preVotesGranted))
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (noTimeout
      : forall index step,
          since <= index
          -> index < last
          -> trace.stepAt index = some step
          -> Not (step.action = .local node (.timeout .election)))
    (old
      : forall index step packet request,
          since <= index
          -> index < last
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .deliver packet
          -> packet.envelope.target = node
          -> packet.envelope.payload = .appendEntriesRequest request
          -> request.term < term)
    (later : since <= last) (within : Within trace start duration last)
    (found : trace.stateAt last = some point)
    (stateFound : nodeState (proto point) node = some state)
    : state.role = .preVoteCandidate
      /\ initial.preVotesGranted ⊆ state.preVotesGranted
      /\ Not (hasQuorum state.activeConfigurations state.preVotesGranted) := by
  refine admissible.coherent.induction (start := since)
    (motive := fun index point => index <= last
      -> forall state, nodeState (proto point) node = some state
      -> state.role = .preVoteCandidate
        /\ initial.preVotesGranted ⊆ state.preVotesGranted
        /\ Not (hasQuorum state.activeConfigurations state.preVotesGranted))
    (fun point found _ state stateFound => ?_)
    (fun index step lower stepped held before state stateFound => ?_)
    last point later found le_rfl state stateFound
  · rw [firstFound, Option.some.injEq] at found
    subst point
    rw [initialFound, Option.some.injEq] at stateFound
    subst state
    exact ⟨initialRole, Finset.Subset.refl _, initialQuorum⟩
  · have beforeWithin := within_before admissible within found
      (afterStart.trans lower) (by omega : index <= last)
    have nextWithin := within_before admissible within found
      (by omega : start <= index + 1) before
    cases selected : step.action.action with
    | none =>
        rw [admissible.stutter stepped selected] at stateFound
        exact held (by omega) state stateFound
    | some action =>
        obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
        rcases tr.mem_after (Concrete.mem_of_nodeState stateFound) with ⟨rfl, rfl⟩ | ⟨_, mem⟩
        · have previous := held (by omega) tr.pre tr.found
          obtain ⟨pre, preFound, preTerm⟩ := top_stays admissible firstFound initialFound initialTerm
            member lower (admissible.before stepped) (low index beforeWithin)
          rw [tr.found, Option.some.injEq] at preFound
          subst pre
          have cap := low (index + 1) nextWithin step.after tr.actor tr.post
            (Trace.stateAt_succ_of_stepAt stepped) member stateFound
          have outcome : Sends (fun after _ => after.currentTerm <= tr.pre.currentTerm -> Polls tr.pre after)
              (Model.Node.step (Capabilities.record tr.actor) tr.actor tr.pre tr.event) := by
            cases eventEq : tr.event with
            | internal input =>
                exact local_polling tr.actor tr.pre input previous.1
                  (fun eq => by
                    have localEvent := internal_event selected acts eventEq
                    rw [eq] at localEvent
                    exact noTimeout index step lower (by omega) stepped localEvent)
            | receive source message =>
                obtain ⟨packet, delivered, target, sourceEq, payload⟩ :=
                  received_packet selected acts eventEq
                have targetIn : packet.envelope.target ∈ participants := target ▸ member
                have sourceIn := good.isolated index step packet.envelope beforeWithin stepped
                  (by rw [delivered]; rfl) targetIn
                have queued := admissible.consumed_pending stepped (by rw [delivered]; rfl)
                obtain ⟨sender, senderFound, sentCap⟩ :=
                  pending_term_le admissible (admissible.before stepped) queued
                have senderCap := low index beforeWithin step.before packet.envelope.source sender
                  (admissible.before stepped) sourceIn senderFound
                have capped : message.term <= tr.pre.currentTerm := by
                  rw [payload] at sentCap
                  omega
                exact receive_polling tr.actor tr.pre source message previous.1
                  previous.2.2 capped
                  (fun request eq => by
                    rw [preTerm]
                    exact old index step packet request lower (by omega) beforeWithin
                      stepped delivered target (payload.trans eq))
          obtain ⟨_, _, result⟩ := outcome {} _ _ tr.ran
          have polls := result (by omega)
          exact ⟨polls.1, previous.2.1.trans polls.2.1, polls.2.2⟩
        · exact held (by omega) state
            (Direct.nodeState_of_mem (Direct.keys_nodup (admissible.reachable_before stepped)) mem)

end Trace

end CCFRaft.Proofs.Leadership.InitRaise
