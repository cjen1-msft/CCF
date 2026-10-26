module

public import CCFRaft.Proofs.Duel.SplitFrozen

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The leaderless round: resets without timeouts

A participant that does not time out in `term + 1` is reset into `term + 1` at most
twice in the round: when it adopts `term + 1`, and when it grants its one vote of
`term + 1`. A candidate of `term + 1` asks each participant once, and a delivery
consumes its packet.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

namespace Resets

open CCF
open CCFRaft.Proofs.Safety

/-- A vote request. -/
def IsVote : Message -> Bool
  | .requestVoteRequest _ => true
  | _ => false

/-- A vote request to `target`. -/
def Aimed (target : NodeID) (e : Model.Envelope) : Bool :=
  (e.target == target) && IsVote e.payload

/-- No vote request is sent. -/
def Quiet (sent : List Model.Envelope) : Prop :=
  forall e, e ∈ sent -> IsVote e.payload = false

/-- At most one vote request is sent to `target`. -/
def Once (target : NodeID) (sent : List Model.Envelope) : Prop :=
  sent.countP (Aimed target) <= 1

theorem Quiet.count {sent : List Model.Envelope} (quiet : Quiet sent) (target : NodeID)
    : sent.countP (Aimed target) = 0 := by
  rw [List.countP_eq_zero]
  intro e member
  simp [Aimed, quiet e member]

theorem Quiet.once {sent : List Model.Envelope} (quiet : Quiet sent) (target : NodeID)
    : Once target sent := by
  unfold Once
  rw [quiet.count]
  omega

theorem broadcast_once (self target : NodeID) (state : NodeState)
    (request : RequestVoteRequest)
    : Once target (Racing.Broadcast self state (.requestVoteRequest request)) := by
  unfold Once Racing.Broadcast
  rw [List.countP_map]
  have nodup := Finset.sort_nodup (state.activeMembers.erase self) (· <= ·)
  have count := List.nodup_iff_count_le_one.mp nodup target
  rw [List.count_eq_countP] at count
  refine le_trans (le_of_eq ?_) count
  congr 1
  funext x
  simp [Aimed, IsVote]

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem advance_quiet (middle : NodeState)
    : Sends (fun _ sent => Quiet sent) (advanceCommit caps middle self) :=
  Sends.mono (advanceCommit_sends self middle)
    fun _ _ ⟨_, proposals⟩ e member => by
      rw [(proposals e member).2]
      rfl

theorem becomePrimary_quiet (candidate : NodeState)
    : Sends (fun _ sent => Quiet sent) (becomePrimary caps self candidate) :=
  Sends.mono (becomePrimary_sends self candidate)
    fun _ _ ⟨_, starts⟩ e member => by
      rcases starts e member with ⟨_, payload⟩ | ⟨_, _, request, payload, _⟩ <;>
        rw [payload] <;> rfl

theorem electIfQuorum_quiet (candidate : NodeState)
    : Sends (fun _ sent => Quiet sent) (electIfQuorum caps self candidate) := by
  unfold electIfQuorum
  exact Sends.ite' (fun _ => becomePrimary_quiet self candidate)
    fun _ => Sends.pure' (by simp [Quiet])

theorem becomeCandidate_once (target : NodeID) (state : NodeState)
    : Sends (fun _ sent => Once target sent) (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_quiet self _) fun _ won quiet => ?_
  refine Sends.bind' (Racing.broadcast_exact self _ _) fun _ later eq => Sends.pure' ?_
  have := broadcast_once self target (freshCandidate self state)
    (makeRequestVoteRequest (freshCandidate self state))
  unfold Once at this ⊢
  rw [List.append_nil, List.countP_append, quiet.count, eq]
  simpa [freshCandidate] using this

theorem broadcast_quiet (state : NodeState) (request : RequestVoteRequest)
    : Sends (fun _ sent => Quiet sent)
        (broadcastToOthers caps self state (.requestPreVoteRequest request)) :=
  Sends.mono (broadcast_sends self state _)
    fun _ _ sent e member => by
      rw [(sent e member).2.2]
      rfl

/-- A step that is not a non-election internal input sends each node at most one
vote request. -/
theorem step_once (target : NodeID) (before : NodeState) (event : Model.Node.Event)
    (notInternal : forall input, event = .internal input -> input = .timeout .election)
    : Sends (fun _ sent => Once target sent)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases notInternal input rfl
      simp only [Model.Node.step, act]
      unfold startElection
      refine Sends.bind' Sends.guard' fun _ _ ⟨_, empty⟩ => ?_
      subst empty
      unfold becomePreVoteCandidate
      refine Sends.ite' (fun _ => ?_) fun _ => ?_
      · exact Sends.mono (becomeCandidate_once self target _) fun _ _ once => by
          simpa using once
      · refine Sends.bind' (broadcast_quiet self _ _) fun _ _ quiet =>
          Sends.pure' ?_
        simpa using quiet.once target
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          simp only [Model.Node.step, receive]
          rcases observe_bumping before (message := .appendEntriesRequest request) trivial
            with ⟨_, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
          · refine Sends.mono (aeStep self source _ request (le_refl _))
              fun _ _ step => Quiet.once ?_ target
            intro e member
            rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩
                | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;>
              simp only [List.mem_singleton, List.not_mem_nil] at member <;>
              subst member <;> rfl
          · refine Sends.mono (aeStep self source _ request le)
              fun _ _ step => Quiet.once ?_ target
            intro e member
            rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩
                | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;>
              simp only [List.mem_singleton, List.not_mem_nil] at member <;>
              subst member <;> rfl
      | appendEntriesResponse response =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp [Once])) fun _ => ?_
          simp only [handleAppendEntriesResponse]
          refine Sends.ite' (fun _ => Sends.pure' (by simp [Once])) fun _ => ?_
          refine Sends.ite'
            (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp [Once]))
            fun _ => Sends.pure' (by simp [Once])
          exact Sends.mono (advance_quiet self _) fun _ _ quiet => quiet.once target
      | requestVoteRequest request =>
          simp only [Model.Node.step, receive, handleRequestVoteRequest]
          refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' ?_
          subst eq
          simp [Once, Aimed, IsVote]
      | requestVoteResponse response =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp [Once])) fun _ => ?_
          simp only [handleRequestVoteResponse]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp [Once])
          exact Sends.mono (electIfQuorum_quiet self _) fun _ _ quiet => quiet.once target
      | requestPreVoteRequest request =>
          simp only [Model.Node.step, receive, handleRequestPreVoteRequest]
          refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' ?_
          subst eq
          simp [Once, Aimed, IsVote]
      | requestPreVoteResponse response =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp [Once])) fun _ => ?_
          simp only [handleRequestPreVoteResponse]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp [Once])
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp [Once])
          exact becomeCandidate_once self target _
      | proposeRequestVoteRequest term =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp [Once])) fun _ => ?_
          simp only [observeTerm, handleProposeRequestVoteRequest]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp [Once])
          exact becomeCandidate_once self target _

end Steps

/-- A vote request of term `t` from `source` to `target`. -/
def Hit (source target : NodeID) (t : Nat) (e : Model.Envelope) : Bool :=
  (e.source == source)
  && (e.target == target)
  && match e.payload with
      | .requestVoteRequest request => request.term == t
      | _ => false

theorem hit_aimed {source target : NodeID} {t : Nat} {e : Model.Envelope}
    (hit : Hit source target t e = true)
    : Aimed target e = true := by
  unfold Hit at hit
  unfold Aimed
  cases payload : e.payload <;> simp_all [IsVote]

theorem countP_batch (f : Model.Envelope -> Bool) (emitted : List Model.Envelope)
    (first : Nat) (sentAt : Real)
    : (Packet.batch emitted first sentAt).countP (fun packet => f packet.envelope)
      = emitted.countP f := by
  unfold Packet.batch
  rw [List.countP_map]
  have := List.countP_map (p := f) (f := Prod.fst) (l := emitted.zipIdx first)
  rw [List.zipIdx_map_fst] at this
  rw [this]
  rfl

theorem countP_erase (f : Packet -> Bool) {packet : Packet}
    : forall {pending : List Packet},
        (pending.map Packet.id).Nodup
        -> packet ∈ pending
        -> (pending.eraseP packet.sameIdentity).countP f + (if f packet then 1 else 0)
            = pending.countP f
  | [], _, member => by cases member
  | head :: tail, nodup, member => by
      rw [List.map_cons, List.nodup_cons] at nodup
      by_cases same : packet.sameIdentity head = true
      · rw [List.eraseP_cons_of_pos same]
        have idEq : packet.id = head.id := by simpa [Packet.sameIdentity] using same
        have eq : packet = head := by
          rcases List.mem_cons.mp member with eq | inTail
          · exact eq
          · exact absurd (idEq ▸ List.mem_map_of_mem (f := Packet.id) inTail) nodup.1
        subst eq
        rw [List.countP_cons]
      · rw [List.eraseP_cons_of_neg same, List.countP_cons, List.countP_cons]
        have inTail : packet ∈ tail := by
          rcases List.mem_cons.mp member with eq | inTail
          · subst eq
            simp [Packet.sameIdentity] at same
          · exact inTail
        have := countP_erase f nodup.2 inTail
        omega

end Resets

open HasNetwork (pending issued)

/-- `node` is in `term + 1` at `point`. -/
def AtTerm (point : W) (node : NodeID) (term : Nat) : Prop :=
  exists state, nodeState (proto point) node = some state /\ state.currentTerm = term + 1

/-- The pending vote requests of `term + 1` from `source` to `node`. -/
def votes (point : W) (source node : NodeID) (term : Nat) : Nat :=
  (pending point).countP fun packet => Resets.Hit source node (term + 1) packet.envelope

/-- `node` voted in `term + 1` for a participant `voter` of `term + 1`, with no
vote request of `voter` to `node` pending. -/
def Granted (participants : Finset NodeID) (point : W) (node : NodeID) (term : Nat)
    : Prop :=
  exists state voter,
    nodeState (proto point) node = some state
    /\ state.currentTerm = term + 1
    /\ state.votedFor = some voter
    /\ voter ∈ participants
    /\ AtTerm point voter term
    /\ votes point voter node term = 0

/-- The packet a step consumes counted as a vote request of `term + 1` from `source`
to `node`. -/
def taken (step : CCF.Execution.Step W Liveness.Event) (source node : NodeID) (term : Nat)
    : Nat :=
  match step.action.consumedPacket with
  | some packet => if Resets.Hit source node (term + 1) packet.envelope then 1 else 0
  | none => 0

/-- A step moves `node` into `term + 1`. -/
def Raised (step : CCF.Execution.Step W Liveness.Event) (node : NodeID) (term : Nat)
    : Prop :=
  exists pre post,
    nodeState (proto step.before) node = some pre
    /\ nodeState (proto step.after) node = some post
    /\ pre.currentTerm ≠ term + 1
    /\ post.currentTerm = term + 1

/-- The resets the round counts at step `index`. -/
def ResetAt (trace : Trace W Liveness.Event) (index : Nat) (node : NodeID) (term : Nat)
    : Prop :=
  exists step state,
    trace.stepAt index = some step
    /\ ElectionReset step node
    /\ nodeState (proto step.after) node = some state
    /\ state.currentTerm = term + 1

theorem priorResets_succ {trace : Trace W Liveness.Event} {c index : Nat} {node : NodeID}
    {term : Nat} (le : c <= index)
    : priorResets trace c (index + 1) node term
      <= priorResets trace c index node term
          + (open Classical in
              if ResetAt trace index node term then 1 else 0) := by
  classical
  unfold priorResets
  rw [Nat.Ico_succ_right_eq_insert_Ico le, Finset.filter_insert]
  split
  · rename_i reset
    have r : ResetAt trace index node term := reset
    simp only [r, ↓reduceIte]
    exact Finset.card_insert_le _ _
  · rename_i reset
    have r : Not (ResetAt trace index node term) := reset
    simp only [r, ↓reduceIte]
    omega

theorem count_ledger {config : Finset NodeID} {nodes : List NodeID}
    {trace : Trace W Liveness.Event}
    (admissible : CCFRaft.Proofs.Liveness.Admissible config nodes trace) {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {emitted : List Model.Envelope}
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch emitted (issued step.before) (time step.before))
    (source node : NodeID) (term : Nat)
    : votes step.after source node term + taken step source node term
      = votes step.before source node term
        + emitted.countP (Resets.Hit source node (term + 1)) := by
  unfold votes taken
  rw [ledger, List.countP_append, Resets.countP_batch]
  unfold Liveness.Event.remaining
  cases consumed : step.action.consumedPacket with
  | none => simp only; omega
  | some packet =>
      simp only
      have := Resets.countP_erase
        (fun packet => Resets.Hit source node (term + 1) packet.envelope)
        (admissible.ids_nodup (admissible.before stepped))
        (admissible.consumed_pending stepped consumed)
      omega

theorem hit_facts {source target : NodeID} {t : Nat} {e : Model.Envelope}
    (hit : Resets.Hit source target t e = true)
    : e.source = source
      /\ e.target = target
      /\ exists request, e.payload = .requestVoteRequest request /\ request.term = t := by
  unfold Resets.Hit at hit
  cases payload : e.payload <;> simp_all

theorem wins_role {self : NodeID} {before after : NodeState} {event : Model.Node.Event}
    (wins : Safety.Wins self before event after)
    : after.role = .primary \/ after.isRetiredCommitted self := by
  obtain ⟨candidate, _, _, advance⟩ := wins
  rcases advance with ⟨rfl, _⟩ | ⟨_, _, _, _, _, _, _, _, role | ⟨_, retired⟩⟩
  · exact Or.inl (by simp [primaryState])
  · exact Or.inl (by rw [role]; simp [primaryState])
  · exact Or.inr retired

/-- A step sends at most one vote request of `term + 1` from a participant to a
node, and only when it moves the participant into `term + 1`. -/
theorem emitted_hits {step : CCF.Execution.Step W Liveness.Event} {actor : NodeID}
    {pre post : NodeState} {event : Model.Node.Event}
    {outputs : CCF.Outputs NodeID Message Notification}
    (preFound : nodeState (proto step.before) actor = some pre)
    (postFound : nodeState (proto step.after) actor = some post)
    (ran
      : (Model.Node.step (CCF.Capabilities.record actor) actor pre event).run {}
        = some (post, outputs))
    {source node : NodeID} {term : Nat}
    : outputs.outgoing.countP (Resets.Hit source node (term + 1))
      <= (open Classical in
          if Raised step source term then 1 else 0) := by
  classical
  have sum := Racing.sends_run (Safety.summary actor pre event) ran
  by_cases zero : outputs.outgoing.countP (Resets.Hit source node (term + 1)) = 0
  · omega
  obtain ⟨e, member, hit⟩ := List.countP_pos_iff.mp (Nat.pos_of_ne_zero zero)
  obtain ⟨sourceEq, _, request, payload, requestTerm⟩ := hit_facts hit
  have ok := Safety.Summary.sends sum e member
  unfold Safety.SendOK at ok
  obtain ⟨actorEq, rest⟩ := ok
  rw [payload] at rest
  obtain ⟨termEq, raises, _⟩ := rest
  rw [sourceEq] at actorEq
  subst actorEq
  have raised : Raised step source term :=
    ⟨pre, post, preFound, postFound, by omega, by omega⟩
  simp only [raised, ↓reduceIte]
  have once : Resets.Once node outputs.outgoing := by
    by_cases internal : exists input, event = .internal input /\ input ≠ .timeout .election
    · exfalso
      obtain ⟨input, eventEq, other⟩ := internal
      rcases Safety.Summary.term_cause sum with le | ⟨_, fresh⟩ | ⟨_, _, eventIs, _⟩
      · omega
      · rcases fresh with eventIs | ⟨_, _, eventIs, _⟩ | ⟨_, eventIs⟩ <;>
          rw [eventEq] at eventIs <;> cases eventIs
        exact other rfl
      · rw [eventEq] at eventIs
        cases eventIs
    · exact Racing.sends_run
        (Resets.step_once source node pre event fun input eventEq => by
          by_contra other
          exact internal ⟨input, eventEq, other⟩)
        ran
  exact le_trans (List.countP_mono_left fun e _ hit => Resets.hit_aimed hit) once

/-- No AppendEntries of `term + 1` or above from a participant to `node` is pending. -/
def Entries (participants : Finset NodeID) (point : W) (node : NodeID) (term : Nat)
    : Prop :=
  forall packet request,
    packet ∈ pending point
    -> packet.envelope.source ∈ participants
    -> packet.envelope.target = node
    -> packet.envelope.payload = .appendEntriesRequest request
    -> request.term <= term

/-- A step keeps `node` in `term + 1` with its vote. -/
def KeepsVote (step : CCF.Execution.Step W Liveness.Event) (node : NodeID) (term : Nat)
    : Prop :=
  forall state,
    nodeState (proto step.before) node = some state
    -> state.currentTerm = term + 1
    -> exists state',
        nodeState (proto step.after) node = some state'
        /\ state'.currentTerm = term + 1
        /\ forall voter, state.votedFor = some voter -> state'.votedFor = some voter

theorem not_raised {step : CCF.Execution.Step W Liveness.Event} {node : NodeID}
    {term : Nat} (atBefore : AtTerm step.before node term)
    : Not (Raised step node term) := by
  rintro ⟨pre, _, preFound, _, preNe, _⟩
  obtain ⟨state, found, termEq⟩ := atBefore
  rw [preFound, Option.some.injEq] at found
  subst found
  exact preNe termEq

open Classical in
/-- The bound on the resets of `node` so far: one for adopting `term + 1`, one for
granting its vote. -/
noncomputable def bound (participants : Finset NodeID) (point : W) (node : NodeID)
    (term : Nat)
    : Nat :=
  (if AtTerm point node term then 1 else 0)
  + (if Granted participants point node term then 1 else 0)

/-- The round invariant for `node` at `index`. -/
structure Inv (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term index : Nat) (point : W) (node : NodeID)
    : Prop where
  resets : priorResets trace c index node term <= bound participants point node term
  once
    : forall source,
        source ∈ participants
        -> votes point source node term
            <= (open Classical in
                if AtTerm point source term then 1 else 0)
  entries : Entries participants point node term

section Invariant

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)

include setup

theorem RoundSetup.at_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1)) {source : NodeID}
    (sourceIn : source ∈ participants) (atBefore : AtTerm step.before source term)
    : AtTerm step.after source term := by
  obtain ⟨state, found, termEq⟩ := atBefore
  rcases selected : step.action.action with _ | action
  · exact ⟨state, by rw [setup.admissible.stutter stepped selected]; exact found, termEq⟩
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, _, ran, _⟩ :=
    setup.view stepped selected
  by_cases eq : source = actor
  · subst eq
    rw [found, Option.some.injEq] at preFound
    subst preFound
    have sum := Racing.sends_run (Safety.summary source state event) ran
    have le := capped.2 (index + 1) step.after source post capped.1 le_rfl
      (Trace.stateAt_succ_of_stepAt stepped) sourceIn postFound
    exact ⟨post, postFound, by have := Safety.Summary.term_le sum; omega⟩
  · exact ⟨state, by rw [others source eq]; exact found, termEq⟩

theorem RoundSetup.votes_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (source node : NodeID)
    : votes step.after source node term + taken step source node term
      <= votes step.before source node term
          + (open Classical in
              if Raised step source term then 1 else 0) := by
  classical
  rcases selected : step.action.action with _ | action
  · obtain ⟨_, _, emitted, emittedEq, _, ledger⟩ := setup.admissible.delivery.next stepped
    simp only [selected, Option.some.injEq] at emittedEq
    subst emittedEq
    have := count_ledger setup.admissible stepped ledger source node term
    simp only [List.countP_nil] at this
    omega
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, _, _, ran, ledger⟩ :=
    setup.view stepped selected
  have := count_ledger setup.admissible stepped ledger source node term
  have hits := emitted_hits (step := step) (source := source) (node := node) (term := term)
    preFound postFound ran
  omega

theorem RoundSetup.keeps_vote {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1)) {node : NodeID}
    (nodeIn : node ∈ participants)
    : KeepsVote step node term := by
  intro state found termEq
  rcases selected : step.action.action with _ | action
  · exact ⟨state, by rw [setup.admissible.stutter stepped selected]; exact found, termEq,
      fun _ eq => eq⟩
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, _, ran, _⟩ :=
    setup.view stepped selected
  by_cases eq : node = actor
  · subst eq
    rw [found, Option.some.injEq] at preFound
    subst preFound
    have sum := Racing.sends_run (Safety.summary node state event) ran
    have le := capped.2 (index + 1) step.after node post capped.1 le_rfl
      (Trace.stateAt_succ_of_stepAt stepped) nodeIn postFound
    have ge := Safety.Summary.term_le sum
    exact ⟨post, postFound, by omega, Safety.Summary.vote_keep sum (by omega)⟩
  · exact ⟨state, by rw [others node eq]; exact found, termEq, fun _ eq => eq⟩

theorem RoundSetup.granted_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1)) {node : NodeID}
    (keeps : KeepsVote step node term)
    (granted : Granted participants step.before node term)
    : Granted participants step.after node term := by
  classical
  obtain ⟨state, voter, found, termEq, voted, voterIn, voterAt, none⟩ := granted
  obtain ⟨state', found', termEq', voted'⟩ := keeps state found termEq
  have counted := setup.votes_step stepped voter node
  simp only [not_raised voterAt, ↓reduceIte] at counted
  exact ⟨
    state',
    voter,
    found',
    termEq',
    voted' voter voted,
    voterIn,
    setup.at_step stepped capped voterIn voterAt,
    by omega
  ⟩

theorem RoundSetup.entries_step {origin : W} (originFound : trace.stateAt c = some origin)
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event} (le : c <= index)
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (timeLe
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (old : Entries participants step.before node term)
    : Entries participants step.after node term := by
  intro packet request member sourceIn targetEq payload
  rcases selected : step.action.action with _ | action
  · exact old packet request (setup.pending_env stepped selected member) sourceIn targetEq
      payload
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, _, _, ran, ledger⟩ :=
    setup.view stepped selected
  rcases Racing.pending_after_cases ledger member with before | ⟨new, _⟩
  · exact old packet request before sourceIn targetEq payload
  have sum := Racing.sends_run (Safety.summary actor pre event) ran
  have ok := Safety.Summary.sends sum _ new
  unfold Safety.SendOK at ok
  obtain ⟨actorEq, rest⟩ := ok
  rw [payload] at rest
  obtain ⟨aeOk, _, cause⟩ := rest
  have termEq : request.term = post.currentTerm := aeOk.2.1
  have actorIn : actor ∈ participants := actorEq ▸ sourceIn
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have postLe :=
    capped.2 (index + 1) step.after actor post capped.1 le_rfl afterFound actorIn postFound
  by_contra high
  have postEq : post.currentTerm = term + 1 := by omega
  have timeStep := (setup.admissible.timing.next stepped).1
  rcases cause with ⟨role, same⟩ | wins
  · exact noElection index step.before actor pre (capped.down le (by omega)) beforeFound
      (by linarith) actorIn preFound (by omega) role
  · rcases wins_role wins with role | retired
    · exact noElection (index + 1) step.after actor post capped afterFound (by linarith)
        actorIn postFound postEq role
    · exact setup.active (index + 1) step.after actor post
        (setup.inside originFound (index + 1) step.after (by omega) afterFound
          (by linarith))
        afterFound actorIn postFound retired

theorem RoundSetup.bound_mono {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1)) {node : NodeID}
    (nodeIn : node ∈ participants)
    : bound participants step.before node term
      <= bound participants step.after node term := by
  classical
  unfold bound
  have keeps := setup.keeps_vote stepped capped nodeIn
  by_cases atBefore : AtTerm step.before node term
  · have atAfter := setup.at_step stepped capped nodeIn atBefore
    by_cases granted : Granted participants step.before node term
    · have granted' := setup.granted_step stepped capped keeps granted
      simp only [atBefore, atAfter, granted, granted', ↓reduceIte, le_refl]
    · simp only [atBefore, atAfter, granted, ↓reduceIte]
      split <;> omega
  · have notGranted : Not (Granted participants step.before node term) :=
      fun ⟨state, _, found, termEq, _⟩ => atBefore ⟨state, found, termEq⟩
    simp only [atBefore, notGranted, ↓reduceIte]
    omega

theorem RoundSetup.once_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1)) {node : NodeID}
    (old
      : forall source,
          source ∈ participants
          -> votes step.before source node term
              <= (open Classical in
                  if AtTerm step.before source term then 1 else 0))
    : forall source,
        source ∈ participants
        -> votes step.after source node term
            <= (open Classical in
                if AtTerm step.after source term then 1 else 0) := by
  classical
  intro source sourceIn
  have counted := setup.votes_step stepped source node
  have prev := old source sourceIn
  by_cases raised : Raised step source term
  · obtain ⟨pre, post, preFound, postFound, preNe, postEq⟩ := raised
    have notAt : Not (AtTerm step.before source term) := fun ⟨state, found, termEq⟩ => by
      rw [preFound, Option.some.injEq] at found
      subst found
      exact preNe termEq
    have atAfter : AtTerm step.after source term := ⟨post, postFound, postEq⟩
    have raised : Raised step source term := ⟨pre, post, preFound, postFound, preNe, postEq⟩
    simp only [notAt, ↓reduceIte] at prev
    simp only [raised, ↓reduceIte] at counted
    simp only [atAfter, ↓reduceIte]
    omega
  · simp only [raised, ↓reduceIte] at counted
    by_cases atBefore : AtTerm step.before source term
    · simp only [setup.at_step stepped capped sourceIn atBefore, ↓reduceIte]
      simp only [atBefore, ↓reduceIte] at prev
      omega
    · simp only [atBefore, ↓reduceIte] at prev
      omega

theorem RoundSetup.inv_start {origin : W} (originFound : trace.stateAt c = some origin)
    {node : NodeID} (nodeIn : node ∈ participants)
    : Inv trace participants c term c origin node where
  resets := by simp [priorResets]
  once := by
    intro source sourceIn
    have : votes origin source node term = 0 := by
      unfold votes
      rw [List.countP_eq_zero]
      intro packet member hit
      obtain ⟨sourceEq, targetEq, request, payload, requestTerm⟩ := hit_facts hit
      have := setup.round.messages origin packet originFound member (sourceEq ▸ sourceIn)
        (targetEq ▸ nodeIn)
      rw [payload] at this
      simp only [Message.term] at this
      omega
    omega
  entries := by
    intro packet request member sourceIn targetEq payload
    have := setup.round.messages origin packet originFound member sourceIn (targetEq ▸ nodeIn)
    rw [payload] at this
    simpa [Message.term] using this

theorem RoundSetup.resets_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (within : Within trace start duration index) {node : NodeID}
    (nodeIn : node ∈ participants) (quiet : Not (TermTimeout trace term index node))
    (old : Inv trace participants c term index step.before node)
    : priorResets trace c (index + 1) node term
      <= bound participants step.after node term := by
  classical
  have succ := priorResets_succ (trace := trace) (node := node) (term := term) le
  have mono := setup.bound_mono stepped capped nodeIn
  have prev := old.resets
  by_cases reset : ResetAt trace index node term
  swap
  · simp only [reset, ↓reduceIte] at succ
    omega
  simp only [reset, ↓reduceIte] at succ
  obtain ⟨step', state, stepped', electionReset, postFound, postEq⟩ := reset
  rw [stepped, Option.some.injEq] at stepped'
  subst stepped'
  have atAfter : AtTerm step.after node term := ⟨state, postFound, postEq⟩
  by_cases atBefore : AtTerm step.before node term
  swap
  · have notGranted : Not (Granted participants step.before node term) :=
      fun ⟨state, _, found, termEq, _⟩ => atBefore ⟨state, found, termEq⟩
    unfold bound at prev ⊢
    simp only [atBefore, notGranted, atAfter, ↓reduceIte] at prev ⊢
    omega
  have atBefore' := atBefore
  obtain ⟨pre, preFound, preEq⟩ := atBefore
  unfold ElectionReset at electionReset
  split at electionReset
  · rename_i actor kind action
    subst electionReset
    cases kind
    · exact absurd ⟨step, pre, stepped, action, preFound, preEq⟩ quiet
    · exact absurd action (setup.period.noQuorumChecks index step actor within stepped nodeIn)
  · rename_i packet action
    obtain ⟨targetEq, rest⟩ := electionReset
    rw [preFound] at rest
    simp only [postFound] at rest
    have member : packet ∈ pending step.before :=
      setup.admissible.consumed_pending stepped (by simp [action, Liveness.Event.consumedPacket])
    have sourceIn : packet.envelope.source ∈ participants :=
      setup.period.isolated index step packet.envelope within stepped
        (by simp [action, Liveness.Event.delivered]) (targetEq ▸ nodeIn)
    rcases rest with higher | rest
    · have := capped.2 (index + 1) step.after node state capped.1 le_rfl
        (Trace.stateAt_succ_of_stepAt stepped) nodeIn postFound
      omega
    split at rest
    · rename_i request payload
      have := old.entries packet request member sourceIn targetEq payload
      rcases rest with lt | ⟨eq, _⟩ <;> omega
    · rename_i request payload
      obtain ⟨termEq, upToDate, unknown, voted⟩ := rest
      set source := packet.envelope.source with sourceDef
      have hit : Resets.Hit source node (term + 1) packet.envelope = true := by
        unfold Resets.Hit
        simp [targetEq, payload, ← termEq, preEq, sourceDef]
      have positive : 0 < votes step.before source node term :=
        List.countP_pos_iff.mpr ⟨packet, member, hit⟩
      have once := old.once source sourceIn
      by_cases sourceAt : AtTerm step.before source term
      swap
      · simp only [sourceAt, ↓reduceIte] at once
        omega
      simp only [sourceAt, ↓reduceIte] at once
      have notGranted : Not (Granted participants step.before node term) := by
        rintro ⟨state', voter, found', _, voted', _, _, none⟩
        rw [preFound, Option.some.injEq] at found'
        subst found'
        rcases voted with voted | voted <;> rw [voted] at voted'
        · cases voted'
        · cases voted'
          omega
      have taken1 : taken step source node term = 1 := by
        unfold taken
        simp [action, Liveness.Event.consumedPacket, hit]
      have counted := setup.votes_step stepped source node
      simp only [not_raised sourceAt, ↓reduceIte] at counted
      have selected : step.action.action = some (.deliver packet.envelope) := by
        simp [action, Liveness.Event.action]
      obtain ⟨actor, pre', post, event, outputs, preFound', postFound', _, cause, ran, _⟩ :=
        setup.view stepped selected
      rcases cause with ⟨input, eventEq, _⟩ | ⟨other, eventEq, actorEq, eventIs⟩
      · rw [action] at eventEq
        cases eventEq
      rw [action] at eventEq
      cases eventEq
      rw [targetEq] at actorEq
      subst actorEq
      rw [preFound, Option.some.injEq] at preFound'
      subst preFound'
      rw [postFound, Option.some.injEq] at postFound'
      subst postFound'
      rw [eventIs, payload] at ran
      obtain ⟨middle, granted, observed, _, grantedIff, afterEq, _⟩ :=
        Racing.sends_run (Racing.voteRequest_receive node source pre request) ran
      have middleEq : middle = pre := by
        rcases observed with eq | ⟨lt, _⟩
        · exact eq
        · omega
      subst middleEq
      have grantedEq : granted = true :=
        grantedIff.mpr ⟨termEq.symm, upToDate, by simpa using unknown, voted⟩
      subst grantedEq
      have grantedAfter : Granted participants step.after node term :=
        ⟨state, source, postFound, postEq, by rw [afterEq]; rfl, sourceIn,
          setup.at_step stepped capped sourceIn sourceAt, by omega⟩
      unfold bound at prev ⊢
      simp only [atBefore', notGranted, atAfter, grantedAfter, ↓reduceIte] at prev ⊢
      omega
    · exact rest.elim
  · exact electionReset.elim

theorem RoundSetup.inv_at {origin : W} (originFound : trace.stateAt c = some origin)
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    {index : Nat} {point : W} (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (nodeIn : node ∈ participants)
    (quiet
      : forall earlier,
          c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier node))
    : forall i,
        c <= i
        -> i <= index
        -> forall here,
            trace.stateAt i = some here -> Inv trace participants c term i here node := by
  intro i le
  induction i, le using Nat.le_induction with
  | base =>
      intro _ here hereFound
      rw [originFound, Option.some.injEq] at hereFound
      subst hereFound
      exact setup.inv_start originFound nodeIn
  | succ i le ih =>
      intro bound here hereFound
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp hereFound
      have beforeFound := setup.admissible.before stepped
      have old := ih (by omega) step.before beforeFound
      have cappedHere := capped.down (by omega) bound
      have afterLe := setup.admissible.time_le bound hereFound found
      have stepLe := (setup.admissible.timing.next stepped).1
      have within :=
        setup.inside originFound i step.before le beforeFound (by linarith)
      exact {
        resets :=
          setup.resets_step le stepped cappedHere within nodeIn (quiet i le (by omega))
            old
        once := setup.once_step stepped cappedHere old.once
        entries :=
          setup.entries_step originFound noElection le stepped cappedHere (by linarith)
            old.entries
      }

end Invariant

/-- A participant without a timeout in `term + 1` before `index` has been reset into
`term + 1` at most twice. -/
theorem RoundSetup.resets_le_two
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    {index : Nat} {point : W} (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants)
    (quiet
      : forall earlier,
          c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier node))
    : priorResets trace c index node term <= 2 := by
  classical
  have inv := setup.inv_at originFound noElection capped found timeLe member quiet index
    capped.1 le_rfl point found
  have := inv.resets
  unfold bound at this
  split at this <;> split at this <;> omega

end CCFRaft.Proofs.Duel.Round
