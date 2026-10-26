module

public import CCFRaft.Proofs.Duel.RoundDefs

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# One duel round: what a step sends

NOT IMPORTED BY `Properties`. Handler facts for `Duel.Round`: a pre-vote request
comes only from an election timeout, in the sender's term; a granted pre-vote
response answers a pre-vote request of its term; and a vote proposal comes only
from a nomination or from a step that leaves its sender retired-committed.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCF
open Model.Node
open CCFRaft.Proofs.Safety

/-- Messages a round tracks by their cause. -/
def Tracked : Message -> Prop
  | .requestPreVoteRequest _ => True
  | .requestPreVoteResponse _ => True
  | .proposeRequestVoteRequest _ => True
  | _ => False

/-- Why a step may send `envelope`, for pre-votes and vote proposals. -/
def RoundSend (self : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    (envelope : Model.Envelope)
    : Prop :=
  (forall request,
    envelope.payload = .requestPreVoteRequest request
    -> event = .internal (.timeout .election) /\ request.term = before.currentTerm)
  /\ (forall response,
        envelope.payload = .requestPreVoteResponse response
        -> response.voteGranted = true
        -> exists request,
            event = .receive envelope.target (.requestPreVoteRequest request)
            /\ request.term = response.term)
  /\ forall term,
      envelope.payload = .proposeRequestVoteRequest term
      -> event = .internal .nominateSuccessor \/ after.isRetiredCommitted self

/-- A send that is untracked, or a vote proposal from a retired-committed node. -/
def Benign (self : NodeID) (after : NodeState) (envelope : Model.Envelope) : Prop :=
  Not (Tracked envelope.payload)
  \/ ((exists term, envelope.payload = .proposeRequestVoteRequest term)
      /\ after.isRetiredCommitted self)

theorem RoundSend.plain {self : NodeID} {before after : NodeState} {event : Event}
    {envelope : Model.Envelope} (plain : Not (Tracked envelope.payload))
    : RoundSend self before event after envelope := by
  refine ⟨fun _ eq => ?_, fun _ eq => ?_, fun _ eq => ?_⟩ <;>
    rw [eq] at plain <;> exact (plain trivial).elim

theorem Benign.round {self : NodeID} {before after : NodeState} {event : Event}
    {envelope : Model.Envelope} (benign : Benign self after envelope)
    : RoundSend self before event after envelope := by
  rcases benign with plain | ⟨⟨term, payload⟩, retired⟩
  · exact RoundSend.plain plain
  · refine ⟨fun _ eq => ?_, fun _ eq => ?_, fun _ _ => Or.inr retired⟩ <;>
      rw [payload] at eq <;> cases eq

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem advance_benign (middle : NodeState)
    : Sends (fun after sent => forall e, e ∈ sent -> Benign self after e)
        (advanceCommit caps middle self) :=
  Sends.mono
    (Sends.and' (advanceCommit_sends self middle) (advanceCommit_retires self middle))
    fun _ _ ⟨⟨_, proposals⟩, retires⟩ e member =>
      Or.inr ⟨⟨_, (proposals e member).2⟩, retires (List.ne_nil_of_mem member)⟩

theorem becomePrimary_benign (candidate : NodeState)
    : Sends (fun after sent => forall e, e ∈ sent -> Benign self after e)
        (becomePrimary caps self candidate) := by
  unfold becomePrimary
  refine Sends.bind' (advance_benign self _) fun leader sent held => ?_
  refine Sends.bind' (Q := fun _ later => forall e, e ∈ later -> Not (Tracked e.payload))
    (Sends.forIn' fun peer _ _ => ?_) fun _ later beats => Sends.pure' fun e member => ?_
  · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member => ?_
    simp only [eq, List.append_nil, List.mem_singleton] at member
    subst member
    exact id
  · rcases List.mem_append.mp (by simpa using member) with old | new
    · exact held e old
    · exact Or.inl (beats e new)

theorem electIfQuorum_benign (candidate : NodeState)
    : Sends (fun after sent => forall e, e ∈ sent -> Benign self after e)
        (electIfQuorum caps self candidate) := by
  unfold electIfQuorum
  exact Sends.ite' (fun _ => becomePrimary_benign self candidate)
    fun _ => Sends.pure' (by simp)

theorem becomeCandidate_benign (state : NodeState)
    : Sends (fun after sent => forall e, e ∈ sent -> Benign self after e)
        (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_benign self (freshCandidate self state))
    fun next sent held => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ later requests => Sends.pure' ?_
  intro e member
  rcases List.mem_append.mp (by simpa using member) with old | new
  · exact held e old
  · refine Or.inl ?_
    rw [(requests e new).2.2]
    exact id

theorem appendEntry_plain (state : NodeState) (content : EntryContent)
    : Sends (fun (_ : NodeState) sent => forall e, e ∈ sent -> Not (Tracked e.payload))
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' (by simp)
    · refine Sends.guard_bind fun _ => ?_
      refine Sends.guard_bind fun _ => ?_
      refine Sends.bind'
        (Sends.forIn' (R := fun e => Not (Tracked e.payload)) fun _ _ _ =>
          Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e member => ?_)
        fun _ _ done => Sends.pure' fun e member => done e (by simpa using member)
      subst eq
      simp only [List.append_nil, List.mem_singleton] at member
      subst member
      exact id

/-- Every step's pre-votes and vote proposals have a `RoundSend` cause. -/
theorem round_sends (before : NodeState) (event : Event)
    : Sends (fun after sent => forall e, e ∈ sent -> RoundSend self before event after e)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents =>
          simp only [Model.Node.step, act]
          unfold appendBatch
          refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
          subst empty
          refine Sends.bind'
            (Sends.foldlM_mem
              (I :=
                fun (_ : NodeState) (sent : List Model.Envelope) =>
                  forall e, e ∈ sent -> Not (Tracked e.payload))
              contents
              (fun value sent item _ held =>
                Sends.mono (appendEntry_plain self value item)
                  fun _ later fresh e mem => by
                    rcases List.mem_append.mp mem with old | new
                    · exact held e old
                    · exact fresh e new)
              before []
              (by simp))
            fun appended sent held => ?_
          refine Sends.mono (advance_benign self appended) fun _ later benign e mem => ?_
          rcases List.mem_append.mp (by simpa using mem) with old | new
          · exact RoundSend.plain (held e old)
          · exact (benign e new).round
      | sendEntries destination batchEnds =>
          simp only [Model.Node.step, act]
          refine Sends.mono (sendEntries_pass self before destination batchEnds)
            fun _ sent pass e member => ?_
          obtain ⟨batch, _, rfl⟩ := pass.sends e member
          exact RoundSend.plain id
      | timeout kind =>
          cases kind with
          | election =>
              simp only [Model.Node.step, act]
              unfold startElection
              refine Sends.bind' Sends.guard' fun _ _ ⟨_, empty⟩ => ?_
              subst empty
              unfold becomePreVoteCandidate
              refine Sends.ite' (fun _ => ?_) fun _ => ?_
              · exact Sends.mono (becomeCandidate_benign self _) fun _ _ benign e member =>
                  (benign e (by simpa using member)).round
              · refine Sends.bind' (broadcast_sends self _ _) fun _ _ sent =>
                  Sends.pure' fun e member => ?_
                have payload := (sent e (by simpa using member)).2.2
                refine ⟨fun request eq => ⟨rfl, ?_⟩, fun _ eq => ?_, fun _ eq => ?_⟩
                · rw [payload] at eq
                  cases eq
                  rfl
                · rw [payload] at eq
                  cases eq
                · rw [payload] at eq
                  cases eq
          | checkQuorum =>
              simp only [Model.Node.step, act]
              unfold checkQuorum
              exact Sends.bind' Sends.guard'
                fun _ _ ⟨_, empty⟩ => by
                  subst empty
                  exact Sends.pure' (by simp)
      | nominateSuccessor =>
          simp only [Model.Node.step, act]
          refine Sends.mono (nominate_sends self before) fun _ _ ⟨_, _, proposals⟩ e member => ?_
          have payload := (proposals e member).2
          refine ⟨fun _ eq => ?_, fun _ eq => ?_, fun _ _ => Or.inl rfl⟩ <;>
            rw [payload] at eq <;> cases eq
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          simp only [Model.Node.step, receive]
          rcases observe_bumping before (message := .appendEntriesRequest request) trivial
            with ⟨_, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
          · refine Sends.mono (aeStep self source _ request (le_refl _))
              fun _ _ step e member => RoundSend.plain ?_
            rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩
                | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;>
              simp only [List.mem_singleton, List.not_mem_nil] at member <;>
              subst member <;> exact id
          · refine Sends.mono (aeStep self source _ request le)
              fun _ _ step e member => RoundSend.plain ?_
            rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩
                | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;>
              simp only [List.mem_singleton, List.not_mem_nil] at member <;>
              subst member <;> exact id
      | appendEntriesResponse response =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
          simp only [handleAppendEntriesResponse]
          refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
          refine Sends.ite'
            (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp))
            fun _ => Sends.pure' (by simp)
          exact Sends.mono (advance_benign self _) fun _ _ benign e member =>
            (benign e member).round
      | requestVoteRequest request =>
          simp only [Model.Node.step, receive, handleRequestVoteRequest]
          refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e member => ?_
          subst eq
          simp only [List.append_nil, List.mem_singleton] at member
          subst member
          exact RoundSend.plain id
      | requestVoteResponse response =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
          simp only [handleRequestVoteResponse]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
          exact Sends.mono (electIfQuorum_benign self _) fun _ _ benign e member =>
            (benign e member).round
      | requestPreVoteRequest request =>
          simp only [Model.Node.step, receive, handleRequestPreVoteRequest]
          refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e member => ?_
          subst eq
          simp only [List.append_nil, List.mem_singleton] at member
          subst member
          refine ⟨fun _ eq => ?_, fun response eq granted => ?_, fun _ eq => ?_⟩
          · cases eq
          · cases eq
            refine ⟨request, rfl, ?_⟩
            simp only [decide_eq_true_eq] at granted
            exact granted.1
          · cases eq
      | requestPreVoteResponse response =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
          simp only [handleRequestPreVoteResponse]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
          exact Sends.mono (becomeCandidate_benign self _) fun _ _ benign e member =>
            (benign e member).round
      | proposeRequestVoteRequest term =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
          simp only [observeTerm, handleProposeRequestVoteRequest]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
          exact Sends.mono (becomeCandidate_benign self _) fun _ _ benign e member =>
            (benign e member).round

/-- A step that raises its sender's term to `after.currentTerm` either received a
message of at least that term, or broadcast a vote request of at least that term to
the sender's other active members. -/
def Raise (self : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  before.currentTerm < after.currentTerm
  -> (exists source message,
        event = .receive source message /\ after.currentTerm <= message.term)
      \/ exists request : RequestVoteRequest,
          after.currentTerm <= request.term
          /\ forall target,
              target ∈ before.activeMembers.erase self
              -> { source := self, target, payload := .requestVoteRequest request } ∈ sent

theorem candidacy_broadcasts {before state after : NodeState} {sent : List Model.Envelope}
    (candidacy : Racing.Candidacy self state after sent)
    (keeps : Racing.Keeps before state) (le : before.currentTerm <= state.currentTerm)
    : exists request : RequestVoteRequest,
        before.currentTerm < request.term
        /\ forall target,
            target ∈ before.activeMembers.erase self
            -> { source := self, target, payload := .requestVoteRequest request }
                ∈ sent := by
  obtain ⟨won, _, sentEq⟩ := candidacy
  refine ⟨makeRequestVoteRequest (freshCandidate self state), ?_, fun target member => ?_⟩
  · simp only [makeRequestVoteRequest, freshCandidate]
    omega
  · rw [sentEq]
    refine List.mem_append_right _ (Racing.mem_broadcast.mpr ⟨target, ?_, rfl⟩)
    rw [(keeps.trans (Racing.keeps_fresh self state)).members]
    exact member

/-- The weak form of `Raise`: a raise without a message of its term broadcasts a
vote request above the old term. -/
def RaiseWeak (self : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  before.currentTerm < after.currentTerm
  -> (exists source message,
        event = .receive source message /\ after.currentTerm <= message.term)
      \/ exists request : RequestVoteRequest,
          before.currentTerm < request.term
          /\ forall target,
              target ∈ before.activeMembers.erase self
              -> { source := self, target, payload := .requestVoteRequest request } ∈ sent

theorem raise_generic (before : NodeState) (event : Event)
    (fresh : Not (FreshCause before event))
    : Sends (RaiseWeak self before event) (Model.Node.step caps self before event) :=
  Sends.mono (summary self before event)
    fun _ _ sum lt => by
      rcases Summary.term_cause sum with le | ⟨_, cause⟩ | message
      · omega
      · exact absurd cause fresh
      · exact Or.inl message

theorem raise_weak (before : NodeState) (event : Event)
    : Sends (RaiseWeak self before event) (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | timeout kind =>
          cases kind with
          | election =>
              refine Sends.mono (Racing.startElection_outcome self before)
                fun after sent ⟨_, outcome⟩ lt => ?_
              split at outcome
              · exact Or.inr (candidacy_broadcasts self outcome ⟨rfl, rfl, rfl⟩ le_rfl)
              · rw [outcome.1] at lt
                simp [preVoteState] at lt
          | checkQuorum =>
              exact raise_generic self before _ (by simp [FreshCause])
      | _ => exact raise_generic self before _ (by simp [FreshCause])
  | receive source message =>
      cases message with
      | requestPreVoteResponse response =>
          refine Sends.mono (Racing.preVoteResponse_receive self source before response)
            fun after sent ⟨middle, observed, rest⟩ lt => ?_
          have middleLe : before.currentTerm <= middle.currentTerm := by
            rcases observed with rfl | ⟨bump, rfl⟩
            · exact le_rfl
            · simp only [bumpedState]
              omega
          have bumped : before.currentTerm < middle.currentTerm
              -> middle.currentTerm <= response.term := by
            rcases observed with rfl | ⟨_, rfl⟩
            · intro h
              omega
            · intro _
              simp [bumpedState]
          split at rest
          · unfold Racing.PreVoted at rest
            split at rest
            · exact Or.inr (candidacy_broadcasts self rest (observed.keeps.trans ⟨rfl, rfl, rfl⟩)
                middleLe)
            · rw [rest.1] at lt ⊢
              exact Or.inl ⟨source, _, rfl, by simpa [Message.term] using bumped lt⟩
          · rw [rest.1] at lt ⊢
            exact Or.inl ⟨source, _, rfl, by simpa [Message.term] using bumped lt⟩
      | proposeRequestVoteRequest term =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' fun lt => absurd lt (lt_irrefl _))
            fun _ => ?_
          simp only [observeTerm, handleProposeRequestVoteRequest]
          refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' fun lt => absurd lt (lt_irrefl _)
          exact Sends.mono (Racing.becomeCandidate_candidacy self before)
            fun _ _ candidacy _ =>
              Or.inr (candidacy_broadcasts self candidacy (Racing.Keeps.refl _) le_rfl)
      | _ => exact raise_generic self before _ (by simp [FreshCause])

/-- Every step's raise has a `Raise` cause. -/
theorem raise_sends (before : NodeState) (event : Event)
    : Sends (Raise self before event) (Model.Node.step caps self before event) :=
  Sends.mono (Sends.and' (summary self before event) (raise_weak self before event))
    fun _ _ ⟨sum, weak⟩ lt => by
      rcases weak lt with message | ⟨request, above, sends⟩
      · exact Or.inl message
      · rcases Summary.term_cause sum with le | ⟨eq, _⟩ | message
        · omega
        · exact Or.inr ⟨request, by omega, sends⟩
        · exact Or.inl message

end Steps

end CCFRaft.Proofs.Duel.Round
