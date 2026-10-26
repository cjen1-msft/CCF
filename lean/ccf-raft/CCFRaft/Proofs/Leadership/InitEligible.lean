module

public import CCFRaft.Proofs.Direct.AppendOnly
public import CCFRaft.Proofs.Leadership.ConfiguredWindow
public import CCFRaft.Proofs.Leadership.FirstReset
public import CCFRaft.Proofs.Replication.Commit
public import CCFRaft.Proofs.Replication.Sane

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A node keeps a role until its retirement commits

Only `recordCommit` clears a role, and only when the node's retirement commits
in that call. So a step that ends without a role either started without one, or
ends with the node's retirement committed. A later truncation in the same
AppendEntries handler can uncommit a retirement, but the truncation runs before
the handler records any commit.
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

/-! ## Node level -/

/-- A handler run from `z` keeps a role, unless it commits the node's retirement. -/
def Roled (self : NodeID) (z after : NodeState) : Prop :=
  Not (z.role = .none) -> Not (after.role = .none) \/ after.isRetiredCommitted self

theorem Roled.same {self : NodeID} {z after : NodeState} (role : after.role = z.role)
    : Roled self z after :=
  fun active => Or.inl (role ▸ active)

theorem Roled.some {self : NodeID} {z after : NodeState} (role : Not (after.role = .none))
    : Roled self z after :=
  fun _ => Or.inl role

theorem Roled.advance {self : NodeID} {z middle after : NodeState}
    (keep : Not (z.role = .none) -> Not (middle.role = .none))
    (advance : Advance self middle after)
    : Roled self z after := by
  intro active
  rcases advance.retired with role | ⟨_, retired⟩
  · exact Or.inl (role ▸ keep active)
  · exact Or.inr retired

theorem Roled.latched {self : NodeID} {z middle after : NodeState}
    (keep : Not (z.role = .none) -> Not (middle.role = .none))
    (latched : Latched self middle after)
    : Roled self z after := by
  intro active
  rcases latched with ⟨role, _⟩ | retired
  · exact Or.inl (role ▸ keep active)
  · exact Or.inr retired

theorem observe_role (before : NodeState) (message : Message)
    : observeTerm before message = before
      \/ (observeTerm before message).role = .follower := by
  cases message <;> simp only [observeTerm, updateTerm] <;> (try split_ifs) <;>
    simp_all [becomeAwareOfNewTerm]

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem electIfQuorum_roled (z candidate : NodeState)
    (keep : Not (z.role = .none) -> Not (candidate.role = .none))
    : Sends (fun after _ => Roled self z after) (electIfQuorum caps self candidate) :=
  Sends.mono (electIfQuorum_sends self candidate)
    fun _ _ result => by
      rcases result with ⟨rfl, _⟩ | ⟨_, _, advance, _⟩
      · exact fun active => Or.inl (keep active)
      · exact Roled.advance (fun _ => by simp [primaryState]) advance

theorem becomeCandidate_roled (z state : NodeState)
    : Sends (fun after _ => Roled self z after) (becomeCandidate caps state self) :=
  Sends.mono (becomeCandidate_sends self state)
    fun _ _ result => by
      rcases result with ⟨rfl, _⟩ | ⟨_, advance, _⟩
      · exact Roled.some (by simp [freshCandidate])
      · exact Roled.advance (fun _ => by simp [primaryState]) advance

theorem ae_roled (source : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    : Sends (fun after _ => Roled self z after)
        (handleAppendEntriesRequest caps self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have wKeep : Not (z.role = .none) -> Not (w.role = .none) := by
    rw [← hw]
    split
    · intro _
      simp [becomeAwareOfNewTerm]
    · exact id
  have wRoled : Roled self z w := fun active => Or.inl (wKeep active)
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.ite' (fun _ => ?_) fun _ => ?_ <;>
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' wRoled
  refine Sends.ite' (fun _ => Sends.pure' fun active => Or.inl (wKeep active)) fun _ => ?_
  have tail : forall v : NodeState, (Not (z.role = .none) -> Not (v.role = .none))
      -> Sends (fun after _ => Roled self z after)
          (do
            let (state, response) := handleAppendEntiresFromPrimary self v r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            return state : NodeEffect _) := by
    intro v keep
    have latched := fromPrimary_latched self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    rw [hres] at latched
    simp only [hres]
    exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (Roled.latched keep latched)
  split
  · exact tail _ wKeep
  · exact tail _ wKeep

theorem aeResponse_roled (z : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends (fun after _ => Roled self z after)
        (handleAppendEntriesResponse caps self z source response) := by
  unfold handleAppendEntriesResponse
  refine Sends.ite' (fun _ => Sends.pure' (Roled.same rfl)) fun _ => ?_
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Roled.same rfl)
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Roled.same rfl)
  exact Sends.mono (advanceCommit_sends self _) fun _ _ ⟨advance, _⟩ =>
    Roled.advance (fun a => by exact a) advance

theorem voteRequest_roled (z : NodeState) (source : NodeID) (request : RequestVoteRequest)
    : Sends (fun after _ => Roled self z after)
        (handleRequestVoteRequest caps z source request) := by
  unfold handleRequestVoteRequest
  exact Sends.bind' (Sends.send _ _ _)
    fun _ _ _ => Sends.pure' (by split <;> exact Roled.same rfl)

theorem voteResponse_roled (z : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (fun after _ => Roled self z after)
        (handleRequestVoteResponse caps self z source response) := by
  unfold handleRequestVoteResponse
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (Roled.same rfl)
  exact electIfQuorum_roled self z _ fun _ => by simp [won.1]

theorem preVoteRequest_roled (z : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends (fun after _ => Roled self z after)
        (handleRequestPreVoteRequest caps z source request) := by
  unfold handleRequestPreVoteRequest
  exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (Roled.same rfl)

theorem preVoteResponse_roled (z : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends (fun after _ => Roled self z after)
        (handleRequestPreVoteResponse caps self z source response) := by
  unfold handleRequestPreVoteResponse
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (Roled.same rfl)
  exact Sends.ite' (fun _ => becomeCandidate_roled self z _) fun _ =>
    Sends.pure' (Roled.same rfl)

theorem proposeVote_roled (z : NodeState) (term : Nat)
    : Sends (fun after _ => Roled self z after)
        (handleProposeRequestVoteRequest caps z self term) := by
  unfold handleProposeRequestVoteRequest
  exact Sends.ite' (fun _ => becomeCandidate_roled self z _) fun _ =>
    Sends.pure' (Roled.same rfl)

theorem receive_roled (before : NodeState) (source : NodeID) (message : Message)
    : Sends (fun after _ => Roled self before after)
        (receive caps self source before message) := by
  have lift : forall {m : NodeEffect NodeState},
      Sends (fun after _ => Roled self (observeTerm before message) after) m
      -> Sends (fun after _ => Roled self before after) m :=
    fun handled => Sends.mono handled fun _ _ roled active => by
      rcases observe_role before message with eq | follower
      · exact roled (by rw [eq]; exact active)
      · exact roled (by simp [follower])
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (Roled.same rfl)) fun _ => ?_
  cases message with
  | appendEntriesRequest request => exact lift (ae_roled self source _ request)
  | appendEntriesResponse response => exact lift (aeResponse_roled self _ source response)
  | requestVoteRequest request => exact lift (voteRequest_roled self _ source request)
  | requestVoteResponse response => exact lift (voteResponse_roled self _ source response)
  | requestPreVoteRequest request =>
      exact lift (preVoteRequest_roled self _ source request)
  | requestPreVoteResponse response =>
      exact lift (preVoteResponse_roled self _ source response)
  | proposeRequestVoteRequest term => exact lift (proposeVote_roled self _ term)

theorem act_roled (before : NodeState) (input : Input)
    : Sends (fun after _ => Roled self before after) (act caps self before input) := by
  cases input with
  | append contents =>
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
      exact Sends.mono (advanceCommit_sends self _) fun _ _ ⟨advance, _⟩ =>
        Roled.advance (fun a => by exact a) advance
  | sendEntries destination batchEnds =>
      simp only [act]
      refine Sends.mono (sendEntries_pass self before destination batchEnds)
        fun after _ pass => ?_
      rw [pass.state]
      exact Roled.same rfl
  | timeout kind =>
      cases kind with
      | election =>
          simp only [act]
          unfold startElection
          refine Sends.bind' Sends.guard' fun _ _ _ => ?_
          unfold becomePreVoteCandidate
          dsimp only
          refine Sends.ite' (fun _ => becomeCandidate_roled self before _) fun _ => ?_
          exact Sends.bind' (broadcast_sends self _ _)
            fun _ _ _ =>
              Sends.pure' (Roled.some (by simp))
      | checkQuorum =>
          simp only [act]
          unfold checkQuorum
          exact Sends.bind' Sends.guard' fun _ _ _ => Sends.pure' (Roled.some (by simp))
  | nominateSuccessor =>
      simp only [act]
      exact Sends.mono (nominate_sends self before) fun _ _ ⟨eq, _⟩ => eq ▸ Roled.same rfl

theorem step_roled (before : NodeState) (event : Model.Node.Event)
    : Sends (fun after _ => Roled self before after)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input => exact act_roled self before input
  | receive source message => exact receive_roled self before source message

end Steps

theorem LocalTransition.roled {before after : Model.State}
    (transition : LocalTransition before after)
    : Roled transition.actor transition.pre transition.post := by
  obtain ⟨new, eq, holds⟩ :=
    step_roled transition.actor transition.pre transition.event {} _ _ transition.ran
  exact holds

/-! ## Committed configurations -/

section Committed

variable [Config.InitialConfiguration]

/-- A log holds a configuration at or below the commit index exactly when its
committed prefix holds one. -/
theorem committed_iff {local_ : NodeState}
    : (exists configuration,
        configuration ∈ configurationHistory local_.log
        /\ configuration.index <= local_.commitIndex)
      <-> Not (configurationHistory local_.committedLog = []) := by
  constructor
  · rintro ⟨configuration, member, le⟩ empty
    have := mem_history_take.mpr ⟨member, le⟩
    simp only [NodeState.committedLog] at empty
    rw [empty] at this
    cases this
  · intro nonempty
    obtain ⟨configuration, member⟩ := List.exists_mem_of_ne_nil _ nonempty
    exact ⟨configuration, mem_history_take.mp member⟩

/-- A participant with a committed configuration under a fixed membership that
includes it is a member of its own signed active configurations. -/
theorem member_signed {participants members : Finset NodeID} {state : Model.State}
    (membership : Membership participants members state) {node : NodeID}
    {local_ : NodeState} (mem : (node, local_) ∈ state.nodes)
    (nodeIn : node ∈ participants) (inMembers : node ∈ members)
    (frontier : Direct.CommitFrontier local_)
    (committed : Not (configurationHistory local_.committedLog = []))
    : node ∈ configurationMembers local_.signedActiveConfigurations := by
  obtain ⟨active, _, _⟩ := membership node local_ mem nodeIn
  obtain ⟨rest, split, _⟩ := activeConfigurations_last committed
  set head := (configurationHistory (local_.log.take local_.commitIndex)).getLast committed
  have headActive : head ∈ local_.activeConfigurations := by
    simp only [NodeState.activeConfigurations]
    rw [split]
    exact List.mem_cons_self
  have headIndex : head.index <= local_.commitIndex :=
    (mem_history_take.mp (List.getLast_mem committed)).2
  have signed : head ∈ local_.signedActiveConfigurations := by
    simp only [NodeState.signedActiveConfigurations, List.mem_filter]
    exact ⟨headActive, decide_eq_true (le_trans headIndex frontier.truncateToSignature)⟩
  exact mem_configurationMembers signed (by rw [active head headActive]; exact inMembers)

end Committed

/-! ## Trace level -/

section Trace

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A node of `anchor` with a role at the start of a window keeps one throughout,
as no anchor node has its retirement committed. -/
theorem roled_window {start : Nat} {duration : Real} {anchor : Finset NodeID}
    (active : Window.AnchorActive trace start duration anchor) {node : NodeID}
    (member : node ∈ anchor)
    (initially
      : forall first state,
          trace.stateAt start = some first
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
    {index : Nat} {point : W} (within : Within trace start duration index)
    (found : trace.stateAt index = some point) {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    : Not (state.role = .none) := by
  refine admissible.coherent.induction (start := start)
    (motive :=
      fun index point =>
        Within trace start duration index
        -> forall state,
            nodeState (proto point) node = some state -> Not (state.role = .none))
    (fun point found _ state nodeFound => initially point state found nodeFound)
    (fun index step after stepped held within' state nodeFound => ?_) index point within.1
    found within state nodeFound
  have earlier : Within trace start duration index :=
    ⟨after, fun first point firstFound found' => by
      have := admissible.time_le (Nat.le_succ _) found' (Trace.stateAt_succ_of_stepAt stepped)
      have := within'.2 first step.after firstFound (Trace.stateAt_succ_of_stepAt stepped)
      linarith⟩
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected] at nodeFound
      exact held earlier state nodeFound
  | some action =>
      obtain ⟨tr, _, _⟩ := transition_acts (admissible.step stepped selected)
      rcases tr.mem_after (Concrete.mem_of_nodeState nodeFound)
        with ⟨rfl, rfl⟩ | ⟨_, mem⟩
      · rcases LocalTransition.roled tr (held earlier _ tr.found) with roled | retired
        · exact roled
        · exact (active (index + 1) step.after tr.actor tr.post within'
            (Trace.stateAt_succ_of_stepAt stepped) member nodeFound retired).elim
      · exact held earlier state (Direct.nodeState_of_mem
          (Direct.keys_nodup (admissible.reachable_before stepped)) mem)

/-- A committed configuration stays committed. -/
theorem committed_later {start : Nat} {node : NodeID}
    (initially
      : forall first state,
          trace.stateAt start = some first
          -> nodeState (proto first) node = some state
          -> Not (configurationHistory state.committedLog = []))
    {index : Nat} {point : W} (afterStart : start <= index)
    (found : trace.stateAt index = some point) {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    : Not (configurationHistory state.committedLog = []) := by
  refine admissible.coherent.induction (start := start)
    (motive := fun index point =>
      forall state, nodeState (proto point) node = some state
        -> Not (configurationHistory state.committedLog = []))
    (fun point found state nodeFound => initially point state found nodeFound)
    (fun index step _ stepped held state nodeFound => ?_) index point afterStart
    found state nodeFound
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected] at nodeFound
      exact held state nodeFound
  | some action =>
      have step' := admissible.step stepped selected
      have distinct := Direct.keys_nodup (admissible.reachable_before stepped)
      obtain ⟨tr, _, _⟩ := transition_acts step'
      have afterMem := Concrete.mem_of_nodeState nodeFound
      obtain ⟨old, oldMem⟩ : exists old, (node, old) ∈ (proto step.before).nodes := by
        rcases tr.mem_after afterMem with ⟨rfl, _⟩ | ⟨_, mem⟩
        · exact ⟨_, tr.pre_mem⟩
        · exact ⟨_, mem⟩
      obtain ⟨more, eq⟩ := Direct.committed_log_step distinct step' oldMem afterMem
      have grown := configurationHistory_append old.committedLog more
      rw [eq] at grown
      intro empty
      rw [empty] at grown
      exact held old (Direct.nodeState_of_mem distinct oldMem)
        (List.prefix_nil.mp grown)

/-- In a good period from a fixed membership that includes the participants, with
committed configurations and roles at its start and no participant's retirement
committed in it, every participant other than a primary may start an election. -/
theorem eligible_window {start : Nat} {duration : Real}
    {participants members : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    (membership
      : forall first,
          trace.stateAt start = some first
          -> Membership participants members (proto first))
    (subset : participants ⊆ members)
    (configured
      : forall first,
          trace.stateAt start = some first
          -> ConfigurationCommitted participants (proto first))
    (roled
      : forall first node state,
          trace.stateAt start = some first
          -> node ∈ participants
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
    (active : Window.AnchorActive trace start duration participants) {index : Nat}
    {point : W} (within : Within trace start duration index)
    (found : trace.stateAt index = some point) {node : NodeID}
    (member : node ∈ participants) {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    (notPrimary : Not (state.role = .primary))
    : canStartElection state node := by
  have mem := Concrete.mem_of_nodeState nodeFound
  have hasRole := roled_window admissible active member
    (fun first state found nodeFound => roled first node state found member nodeFound)
    within found nodeFound
  have committed := committed_later admissible
    (fun first state found nodeFound =>
      committed_iff.mp (configured first found node state (Concrete.mem_of_nodeState nodeFound)
        member))
    within.1 found nodeFound
  have frontier :=
    Direct.commitFrontier_invariant.reachable (admissible.reachable found) node state mem
  refine ⟨?_, Or.inl ?_, active index point node state within found member nodeFound⟩
  · cases h : state.role with
    | none => exact (hasRole h).elim
    | primary => exact (notPrimary h).elim
    | follower => exact Or.inl rfl
    | preVoteCandidate => exact Or.inr (Or.inl rfl)
    | candidate => exact Or.inr (Or.inr rfl)
  · exact member_signed (Membership.window admissible good membership index point within found)
      mem member (subset member) frontier committed

end Trace

end CCFRaft.Proofs.Leadership
