module

public import CCFRaft.Proofs.Leadership.AnchorNode
public import CCFRaft.Proofs.Leadership.NoSelf
public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Proofs.Liveness.Timers

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Every eligible node has reset its election timer

`timerModel` leaves initial deadlines unconstrained, so a node's deadline is
bounded only after its first `ElectionReset`. This module shows that a node that
may start an election has had one. Initially every node is pristine: without a
role, the primary, or a follower with an empty log. A pristine node cannot start
an election, since an empty log holds no configuration. A step stays pristine
unless it resets the timer: a node leaves `none` or `primary` for `follower` only
by adopting a newer term or failing a quorum check, and a follower first fills
its log by accepting an AppendEntries request that passes its log check.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary (Acts)
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)

/-! ## Node level -/

/-- A state that cannot start an election and has not had to reset its timer. -/
def Pristine (state : NodeState) : Prop :=
  state.role = .none
  \/ state.role = .primary
  \/ (state.role = .follower /\ state.log = [])

theorem Pristine.not_eligible {state : NodeState} {self : NodeID}
    (pristine : Pristine state)
    : Not (canStartElection state self) := by
  rintro ⟨role, member, _⟩
  rcases pristine with r | r | ⟨_, log⟩
  · rcases role with x | x | x <;> rw [r] at x <;> cases x
  · rcases role with x | x | x <;> rw [r] at x <;> cases x
  · rcases member with m | m <;>
      simp [NodeState.signedActiveConfigurations, NodeState.activeConfigurations,
        activeConfigurations, configurationHistory, log, configurationMembers,
        NodeState.retirementCompletedNodes, NodeState.committedLog] at m

/-- The node-local form of `ElectionReset`. -/
def Reset (before : NodeState) (event : Model.Node.Event) (after : NodeState) : Prop :=
  (exists kind, event = .internal (.timeout kind))
  \/ exists source message,
      event = .receive source message
      /\ (before.currentTerm < after.currentTerm
          \/ exists request,
              message = .appendEntriesRequest request
              /\ (before.currentTerm < request.term
                  \/ (before.currentTerm = request.term
                      /\ (before.role = .candidate
                          \/ before.role = .preVoteCandidate
                          \/ termAt before.log request.prevLogIndex
                              = request.prevLogTerm))))

/-- A node without a role or a primary becomes a follower only with a newer term
or on a timeout. -/
def Wake (before : NodeState) (event : Model.Node.Event) (after : NodeState) : Prop :=
  (before.role = .none \/ before.role = .primary)
  -> after.role = .follower
  -> before.currentTerm < after.currentTerm
      \/ exists kind, event = .internal (.timeout kind)

/-- A handler run from `z` keeps its term at least, and keeps a state without a
role or a primary in one of those roles. -/
def Inert (z after : NodeState) : Prop :=
  z.currentTerm <= after.currentTerm
  /\ ((z.role = .none \/ z.role = .primary)
      -> after.role = .none \/ after.role = .primary)

theorem Inert.refl (z : NodeState) : Inert z z := ⟨le_rfl, id⟩

theorem Inert.step {z middle after : NodeState} (inert : Inert z middle)
    (term : after.currentTerm = middle.currentTerm)
    (role : after.role = middle.role \/ after.role = .none)
    : Inert z after := by
  refine ⟨term ▸ inert.1, fun start => ?_⟩
  rcases role with eq | eq
  · rw [eq]
    exact inert.2 start
  · exact Or.inl eq

/-- Inert from a role that is neither absent nor primary, with the term kept or raised. -/
theorem Inert.active {z after : NodeState} (term : z.currentTerm <= after.currentTerm)
    (active : Not (z.role = .none) /\ Not (z.role = .primary))
    : Inert z after :=
  ⟨term, fun start => (start.elim active.1 active.2).elim⟩

theorem observe_cases (before : NodeState) (message : Message)
    : observeTerm before message = before
      \/ before.currentTerm < (observeTerm before message).currentTerm := by
  cases message <;> simp only [observeTerm, updateTerm] <;> (try split_ifs) <;>
    simp_all [becomeAwareOfNewTerm]

theorem Inert.wake_self {before after : NodeState} {event : Model.Node.Event}
    (inert : Inert before after)
    : Wake before event after := by
  intro start follower
  rcases inert.2 start with r | r <;> rw [r] at follower <;> cases follower

theorem Inert.wake {before z after : NodeState} {source : NodeID} {message : Message}
    (observed : z = before \/ before.currentTerm < z.currentTerm) (inert : Inert z after)
    : Wake before (.receive source message) after := by
  intro start follower
  rcases observed with rfl | lt
  · rcases inert.2 start with r | r <;> rw [r] at follower <;> cases follower
  · exact Or.inl (lt_of_lt_of_le lt inert.1)

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem advanceCommit_inert {z : NodeState} (middle : NodeState) (inert : Inert z middle)
    : Sends (fun after _ => Inert z after) (advanceCommit caps middle self) :=
  Sends.mono (advanceCommit_sends self middle)
    fun _ _ ⟨advance, _⟩ => inert.step advance.term advance.role

theorem ae_inert (source : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    : Sends (fun after _ => Inert z after)
        (handleAppendEntriesRequest caps self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have wInert : Inert z w := by
    rw [← hw]
    split
    · rename_i h
      refine ⟨by simp [becomeAwareOfNewTerm, h.1], fun start => ?_⟩
      rcases h.2 with c | c <;> rcases start with s | s <;> rw [c] at s <;> cases s
    · exact Inert.refl z
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.ite' (fun _ => ?_) fun _ => ?_ <;>
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' wInert
  refine Sends.ite' (fun _ => Sends.pure' wInert) fun _ => ?_
  have tail : forall v : NodeState, Inert z v
      -> Sends (fun after _ => Inert z after)
          (do
            let (state, response) := handleAppendEntiresFromPrimary self v r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            return state : NodeEffect _) := by
    intro v inert
    obtain ⟨term, _, _, _, role, _⟩ := fromLeader_spec self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    rw [hres] at term role
    simp only [hres]
    exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (inert.step term role)
  split
  · exact tail _ wInert
  · exact tail _ wInert

theorem aeResponse_inert (z : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends (fun after _ => Inert z after)
        (handleAppendEntriesResponse caps self z source response) := by
  unfold handleAppendEntriesResponse
  refine Sends.ite' (fun _ => Sends.pure' (Inert.refl z)) fun _ => ?_
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Inert.refl z)
  exact Sends.ite' (fun _ => advanceCommit_inert self _ (Inert.refl z)) fun _ =>
    Sends.pure' (Inert.refl z)

theorem voteRequest_inert (z : NodeState) (source : NodeID) (request : RequestVoteRequest)
    : Sends (fun after _ => Inert z after)
        (handleRequestVoteRequest caps z source request) := by
  unfold handleRequestVoteRequest
  exact Sends.bind' (Sends.send _ _ _)
    fun _ _ _ =>
      Sends.pure' (by split <;> exact Inert.refl z)

theorem voteResponse_inert (z : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (fun after _ => Inert z after)
        (handleRequestVoteResponse caps self z source response) := by
  unfold handleRequestVoteResponse
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (Inert.refl z)
  refine Sends.mono (electIfQuorum_kept self _) fun _ _ ⟨_, term⟩ => ?_
  exact Inert.active (le_of_eq term.symm) (by rw [won.1]; simp)

theorem preVoteRequest_inert (z : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends (fun after _ => Inert z after)
        (handleRequestPreVoteRequest caps z source request) := by
  unfold handleRequestPreVoteRequest
  exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (Inert.refl z)

theorem preVoteResponse_inert (z : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (fun after _ => Inert z after)
        (handleRequestPreVoteResponse caps self z source response) := by
  unfold handleRequestPreVoteResponse
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (Inert.refl z)
  have active : Not (z.role = .none) /\ Not (z.role = .primary) := by rw [won.1]; simp
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Inert.active le_rfl active)
  exact Sends.mono (becomeCandidate_kept self _)
    fun _ _ ⟨_, term⟩ =>
      Inert.active (by rw [term]; exact Nat.le_succ _) active

theorem proposeVote_inert (z : NodeState) (term : Nat)
    : Sends (fun after _ => Inert z after)
        (handleProposeRequestVoteRequest caps z self term) := by
  unfold handleProposeRequestVoteRequest
  refine Sends.ite' (fun start => ?_) fun _ => Sends.pure' (Inert.refl z)
  have active : Not (z.role = .none) /\ Not (z.role = .primary) := by
    rcases start.2.1 with r | r | r <;> rw [r] <;> simp
  exact Sends.mono (becomeCandidate_kept self _)
    fun _ _ ⟨_, raised⟩ =>
      Inert.active (by rw [raised]; exact Nat.le_succ _) active

theorem receive_wake (before : NodeState) (source : NodeID) (message : Message)
    : Sends (fun after _ => Wake before (.receive source message) after)
        (receive caps self source before message) := by
  have observed := observe_cases before message
  have lift : forall {m : NodeEffect NodeState},
      Sends (fun after _ => Inert (observeTerm before message) after) m
      -> Sends (fun after _ => Wake before (.receive source message) after) m :=
    fun handled => Sends.mono handled fun _ _ inert => Inert.wake observed inert
  simp only [receive]
  refine Sends.ite'
    (fun _ => Sends.pure' (Inert.wake (Or.inl rfl) (Inert.refl before))) fun _ => ?_
  cases message with
  | appendEntriesRequest request => exact lift (ae_inert self source _ request)
  | appendEntriesResponse response => exact lift (aeResponse_inert self _ source response)
  | requestVoteRequest request => exact lift (voteRequest_inert self _ source request)
  | requestVoteResponse response => exact lift (voteResponse_inert self _ source response)
  | requestPreVoteRequest request =>
      exact lift (preVoteRequest_inert self _ source request)
  | requestPreVoteResponse response =>
      exact lift (preVoteResponse_inert self _ source response)
  | proposeRequestVoteRequest term => exact lift (proposeVote_inert self _ term)

theorem act_wake (before : NodeState) (input : Input)
    : Sends (fun after _ => Wake before (.internal input) after)
        (act caps self before input) := by
  have inert : forall {m : NodeEffect NodeState},
      Sends (fun after _ => Inert before after) m
      -> Sends (fun after _ => Wake before (.internal input) after) m :=
    fun handled => Sends.mono handled fun _ _ inert => inert.wake_self
  cases input with
  | append contents =>
      refine inert ?_
      simp only [act]
      unfold appendBatch
      refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
      subst empty
      refine Sends.bind'
        (Sends.mono
          (Sends.foldlM' (I := BatchState self before)
            (fun value sent' item batch =>
              appendEntry_batch self before value sent' item batch)
            contents before [] (BatchState.start self before))
          fun _ _ done => by simpa using done)
        fun appended _ batch => ?_
      obtain ⟨⟨entries, sentIndex, rfl, _, _⟩, _⟩ := batch
      exact advanceCommit_inert self _ (Inert.refl before)
  | sendEntries destination batchEnds =>
      refine inert ?_
      simp only [act]
      refine Sends.mono (sendEntries_pass self before destination batchEnds)
        fun after _ pass => ?_
      rw [pass.state]
      exact Inert.refl before
  | timeout kind =>
      exact Sends.mono (act_off self before (.timeout kind)) fun _ _ _ _ _ =>
        Or.inr ⟨kind, rfl⟩
  | nominateSuccessor =>
      refine inert ?_
      simp only [act]
      exact Sends.mono (nominate_sends self before) fun _ _ ⟨eq, _⟩ => eq ▸ Inert.refl before

theorem step_wake (before : NodeState) (event : Model.Node.Event)
    : Sends (fun after _ => Wake before event after)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input => exact act_wake self before input
  | receive source message => exact receive_wake self before source message

end Steps

theorem LocalTransition.wake {before after : Model.State}
    (transition : LocalTransition before after)
    : Wake transition.pre transition.event transition.post := by
  obtain ⟨new, eq, holds⟩ :=
    step_wake transition.actor transition.pre transition.event {} _ _ transition.ran
  exact holds

/-- A pristine node stays pristine over a step that does not reset its timer. -/
theorem pristine_step {self : NodeID} {before after : NodeState}
    {event : Model.Node.Event} {sent : List Model.Envelope} (pristine : Pristine before)
    (summary : Summary self before event after sent) (wake : Wake before event after)
    (quiet : Not (Reset before event after))
    : Pristine after := by
  have flat : Not (before.currentTerm < after.currentTerm) := by
    intro lt
    cases event with
    | receive source message => exact quiet (Or.inr ⟨source, message, rfl, Or.inl lt⟩)
    | internal input =>
        rcases (CCFRaft.Proofs.Safety.Summary.term_cause summary) with le | ⟨_, fresh⟩ | ⟨_, _, eq, _⟩
        · omega
        · rcases fresh with eq | ⟨_, _, eq, _⟩ | ⟨_, eq⟩
          · exact quiet (Or.inl ⟨_, eq⟩)
          · cases eq
          · cases eq
        · cases eq
  have notCandidate : Not (before.role = .candidate) := by
    intro r
    rcases pristine with p | p | ⟨p, _⟩ <;> rw [r] at p <;> cases p
  have notPre : Not (before.role = .preVoteCandidate) := by
    intro r
    rcases pristine with p | p | ⟨p, _⟩ <;> rw [r] at p <;> cases p
  cases hr : after.role with
  | none => exact Or.inl hr
  | primary => exact Or.inr (Or.inl hr)
  | candidate =>
      obtain ⟨_, _, _, ⟨_, raised, _⟩ | ⟨kept, _⟩⟩ := CCFRaft.Proofs.Safety.Summary.candidate summary hr
      · omega
      · exact (notCandidate kept).elim
  | preVoteCandidate =>
      obtain ⟨_, kept | eq⟩ := CCFRaft.Proofs.Safety.Summary.pre_vote summary hr
      · exact (notPre kept).elim
      · exact (quiet (Or.inl ⟨_, eq⟩)).elim
  | follower =>
      rcases pristine with r | r | ⟨r, log⟩
      · rcases wake (Or.inl r) hr with lt | ⟨kind, eq⟩
        · exact (flat lt).elim
        · exact (quiet (Or.inl ⟨kind, eq⟩)).elim
      · rcases wake (Or.inr r) hr with lt | ⟨kind, eq⟩
        · exact (flat lt).elim
        · exact (quiet (Or.inl ⟨kind, eq⟩)).elim
      · cases CCFRaft.Proofs.Safety.Summary.kind summary with
        | same same _ => exact Or.inr (Or.inr ⟨hr, same.trans log⟩)
        | append _ _ leader _ _ _ =>
            rw [r] at leader
            cases leader
        | ack _ _ _ leader _ _ _ =>
            rw [r] at leader
            cases leader
        | accept source request received accepted =>
            refine (quiet (Or.inr ⟨source, _, received, Or.inr ⟨request, rfl, ?_⟩⟩)).elim
            rcases Nat.lt_or_eq_of_le accepted.2.1 with lt | eq
            · exact Or.inl lt
            · exact Or.inr ⟨eq, Or.inr (Or.inr accepted.2.2.2.2.1)⟩
        | elect elected =>
            obtain ⟨_, _, _, advance⟩ := elected
            rcases advance.role with eq | eq <;> rw [hr] at eq <;>
              simp [primaryState] at eq

/-! ## Trace level -/

section Trace

variable [Config.InitialConfiguration]

theorem pristine_initial (node : NodeID)
    : Pristine (Model.initialNodeState Config.INITIAL_CONFIGURATION node) := by
  simp only [Pristine, Model.initialNodeState]
  split_ifs <;> simp

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}

theorem electionReset_of_reset {step : CCF.Execution.Step W Liveness.Event}
    {action : Model.Action} {actor : NodeID} {event : Model.Node.Event}
    {pre post : NodeState} (selected : step.action.action = some action)
    (acts : Acts action actor event)
    (preFound : nodeState (proto step.before) actor = some pre)
    (postFound : nodeState (proto step.after) actor = some post)
    (reset : Reset pre event post)
    : ElectionReset step actor := by
  unfold ElectionReset
  cases hact : step.action with
  | «local» node input =>
      rw [hact] at selected
      simp only [Liveness.Event.action, Option.some.injEq] at selected
      subst selected
      obtain ⟨rfl, rfl⟩ := acts
      rcases reset with ⟨kind, eq⟩ | ⟨_, _, eq, _⟩
      · cases eq
        rfl
      · cases eq
  | deliver packet =>
      rw [hact] at selected
      simp only [Liveness.Event.action, Option.some.injEq] at selected
      subst selected
      obtain ⟨rfl, rfl⟩ := acts
      rcases reset with ⟨kind, eq⟩ | ⟨source, message, eq, cause⟩
      · cases eq
      · cases eq
        refine ⟨rfl, ?_⟩
        simp only [preFound, postFound]
        rcases cause with lt | ⟨request, payload, ae⟩
        · exact Or.inl lt
        · right
          rw [payload]
          exact ae
  | drop packet => simp [hact, Liveness.Event.action] at selected
  | crash node => simp [hact, Liveness.Event.action] at selected
  | idle => simp [hact, Liveness.Event.action] at selected

variable
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Every node is pristine or has had an election-timer reset. -/
theorem pristine_or_reset {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    : Pristine state
      \/ exists earlier reset,
          earlier < index
          /\ trace.stepAt earlier = some reset
          /\ ElectionReset reset node := by
  refine admissible.coherent.induction (start := 0)
    (motive := fun index point =>
      forall node state,
        nodeState (proto point) node = some state
        -> Pristine state
            \/ exists earlier reset,
                earlier < index /\ trace.stepAt earlier = some reset
                /\ ElectionReset reset node)
    (fun point found node state nodeFound => ?_)
    (fun index step _ stepped held node state nodeFound => ?_) index point (Nat.zero_le _)
    found node state nodeFound
  · simp only [Trace.stateAt_zero, Option.some.injEq] at found
    subst found
    have init : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init
        (proto trace.initial) := admissible.protocol.init
    have eq : state = Model.initialNodeState Config.INITIAL_CONFIGURATION node :=
      init.2.2.2.2 (node, state) (Concrete.mem_of_nodeState nodeFound)
    exact Or.inl (eq ▸ pristine_initial node)
  · have lift : (exists earlier reset,
          earlier < index /\ trace.stepAt earlier = some reset /\ ElectionReset reset node)
        -> exists earlier reset,
            earlier < index + 1 /\ trace.stepAt earlier = some reset
            /\ ElectionReset reset node :=
      fun ⟨earlier, reset, lt, at_, resets⟩ =>
        ⟨earlier, reset, Nat.lt_succ_of_lt lt, at_, resets⟩
    by_cases resets : ElectionReset step node
    · exact Or.inr ⟨index, step, Nat.lt_succ_self _, stepped, resets⟩
    cases selected : step.action.action with
    | none =>
        rw [admissible.stutter stepped selected] at nodeFound
        exact (held node state nodeFound).imp_right lift
    | some action =>
        obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
        rcases tr.mem_after (Concrete.mem_of_nodeState nodeFound)
          with ⟨rfl, rfl⟩ | ⟨_, member⟩
        · rcases held _ _ tr.found with pristine | earlier
          · exact Or.inl (pristine_step pristine tr.summary (LocalTransition.wake tr) fun reset =>
              resets (electionReset_of_reset selected acts tr.found nodeFound reset))
          · exact Or.inr (lift earlier)
        · have found := Direct.nodeState_of_mem
            (Direct.keys_nodup (admissible.reachable_before stepped)) member
          exact (held node state found).imp_right lift

/-- A node that may start an election has had an election-timer reset. -/
theorem eligible_reset {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    (can : canStartElection state node)
    : exists earlier reset,
        earlier < index
        /\ trace.stepAt earlier = some reset
        /\ ElectionReset reset node :=
  (pristine_or_reset admissible found nodeFound).resolve_left
    fun pristine =>
      pristine.not_eligible can

/-- After an election-timer reset, the node's deadline stays within an election
timeout of the current time. -/
theorem deadline_le_of_reset [HasTimers W] {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {earlier : Nat}
    {reset : CCF.Execution.Step W Liveness.Event} {node : NodeID}
    (resetAt : trace.stepAt earlier = some reset) (resets : ElectionReset reset node)
    {index : Nat} {point : W} (after : earlier < index)
    (found : trace.stateAt index = some point)
    : deadline point node <= time point + electionTimeout :=
  admissible.coherent.induction
    (start := earlier + 1)
    (motive := fun _ point => deadline point node <= time point + electionTimeout)
    (fun point found => by
      rw [Trace.stateAt_succ_of_stepAt resetAt, Option.some.injEq] at found
      subst found
      have drawn := (((timers.next resetAt) node).1 resets).2
      have elapsed := (admissible.timing.next resetAt).1
      linarith)
    (fun _ step _ stepped held => by
      have elapsed := (admissible.timing.next stepped).1
      by_cases stepResets : ElectionReset step node
      · have drawn := (((timers.next stepped) node).1 stepResets).2
        linarith
      · rw [((timers.next stepped) node).2.1 stepResets]
        linarith)
    index point after found

/-- A node that may start an election is due within an election timeout. -/
theorem eligible_deadline [HasTimers W] {electionTimeout : Real}
    (timers : trace.Valid (timerModel electionTimeout)) {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {node : NodeID} {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    (can : canStartElection state node)
    : deadline point node <= time point + electionTimeout := by
  obtain ⟨_, _, lt, resetAt, resets⟩ := eligible_reset admissible found nodeFound can
  exact deadline_le_of_reset admissible timers resetAt resets lt found

end Trace

end CCFRaft.Proofs.Leadership
