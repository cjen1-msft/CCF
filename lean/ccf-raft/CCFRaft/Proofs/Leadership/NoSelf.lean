module

public import CCFRaft.Proofs.Safety.Summary
public import CCFRaft.Proofs.Liveness.Network

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# No node sends to itself

Every envelope a node sends names it as the source and goes to another node,
except a reply, which goes back to the source of the received message. A
broadcast skips its sender, AppendEntries go to eligible peers, and a nominated
successor is an eligible peer. So no packet of an admissible execution is
addressed to its sender: none is at the start, and a reply goes back to the
sender of a packet that was not addressed to its own sender.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open HasProtocol (proto)
open HasNetwork (pending)

/-- Every envelope of `sent` is from `self` to another node. -/
abbrev Off (self : NodeID) (sent : List Model.Envelope) : Prop :=
  forall e, e ∈ sent -> e.source = self /\ Not (e.target = self)

/-- Every envelope of `sent` is from `self`, to another node or back to `source`. -/
abbrev Toward (self source : NodeID) (sent : List Model.Envelope) : Prop :=
  forall e, e ∈ sent -> e.source = self /\ (Not (e.target = self) \/ e.target = source)

theorem off_nil (self : NodeID) : Off self [] := fun _ member => by cases member

theorem toward_nil (self source : NodeID) : Toward self source [] :=
  fun _ member => by
    cases member

theorem toward_back {self source : NodeID} {payload : Message}
    : Toward self source [{ source := self, target := source, payload }] := by
  intro e member
  rw [List.mem_singleton] at member
  subst member
  exact ⟨rfl, Or.inr rfl⟩

theorem off_append {self : NodeID} {first second : List Model.Envelope}
    (left : Off self first) (right : Off self second)
    : Off self (first ++ second) := by
  intro e member
  rcases List.mem_append.mp member with old | new
  · exact left e old
  · exact right e new

theorem Off.toward {self source : NodeID} {sent : List Model.Envelope}
    (off : Off self sent)
    : Toward self source sent :=
  fun e member =>
    ⟨(off e member).1, Or.inl (off e member).2⟩

/-- A fold that keeps or replaces its accumulator by an item ends with the
initial value or an item. -/
theorem foldl_select {f : Option NodeID -> NodeID -> Option NodeID}
    (select : forall best item, f best item = best \/ f best item = some item)
    : forall (items : List NodeID) (init : Option NodeID) (chosen : NodeID),
        items.foldl f init = some chosen -> init = some chosen \/ chosen ∈ items
  | [], _, _, found => Or.inl found
  | item :: items, init, chosen, found => by
      rcases foldl_select select items (f init item) chosen found with first | later
      · rcases select init item with same | picked
        · exact Or.inl (same ▸ first)
        · rw [picked, Option.some.injEq] at first
          exact Or.inr (first ▸ List.mem_cons_self)
      · exact Or.inr (List.mem_cons_of_mem _ later)

/-- A nominated successor is an eligible peer, so not the nominating node. -/
theorem findSuccessor_ne {state : NodeState} {self successor : NodeID}
    (found : findSuccessor state self = some successor)
    : Not (successor = self) := by
  unfold findSuccessor at found
  dsimp only at found
  rcases foldl_select (fun best item => by
      cases best with
      | none => exact Or.inr rfl
      | some selected =>
          dsimp only
          split
          · exact Or.inr rfl
          · exact Or.inl rfl) _ none successor found with none_ | member
  · cases none_
  · rw [Finset.mem_sort] at member
    exact (Finset.mem_erase.mp member).1

section Effects

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem nominate_off (state : NodeState)
    : Sends (fun _ sent => Off self sent) (nominateSuccessor caps state self) := by
  unfold nominateSuccessor
  refine Sends.bind' Sends.guard' fun _ _ ⟨_, empty⟩ => ?_
  subst empty
  split
  · next successor found =>
      exact Sends.bind' (Sends.send _ _ _)
        fun _ sent eq =>
          Sends.pure'
            (by
              intro e member
              simp only [eq, List.nil_append, List.append_nil, List.mem_singleton]
                at member
              subst member
              exact ⟨rfl, findSuccessor_ne found⟩)
  · exact Sends.pure' (off_nil self)

theorem advanceCommit_off (middle : NodeState)
    : Sends (fun _ sent => Off self sent) (advanceCommit caps middle self) := by
  unfold advanceCommit
  dsimp only
  refine Sends.ite' (fun _ => Sends.pure' (off_nil self)) fun _ => ?_
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (off_nil self))
    fun _ => Sends.pure' (off_nil self)
  exact Sends.bind' (nominate_off self _)
    fun _ sent off =>
      Sends.pure' (by simpa using off)

theorem broadcast_off (state : NodeState) (message : Message)
    : Sends (fun _ sent => Off self sent) (broadcastToOthers caps self state message) :=
  Sends.mono (broadcast_sends self state message)
    fun _ _ sent e member =>
      ⟨(sent e member).1, (sent e member).2.1⟩

theorem becomePrimary_off (candidate : NodeState)
    : Sends (fun _ sent => Off self sent) (becomePrimary caps self candidate) := by
  unfold becomePrimary
  refine Sends.bind' (advanceCommit_off self _) fun _ sent off => ?_
  refine Sends.bind' (Q := fun _ later => Off self later)
    (Sends.forIn' (R := fun e => e.source = self /\ Not (e.target = self))
      fun peer _ member => ?_)
    fun _ later beats => Sends.pure' (by simpa using off_append off beats)
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member' => ?_
  simp only [eq, List.append_nil, List.mem_singleton] at member'
  subst member'
  simp [Finset.mem_sort, eligiblePeers] at member
  exact ⟨rfl, member.1⟩

theorem electIfQuorum_off (candidate : NodeState)
    : Sends (fun _ sent => Off self sent) (electIfQuorum caps self candidate) := by
  unfold electIfQuorum
  exact Sends.ite' (fun _ => becomePrimary_off self candidate) fun _ =>
    Sends.pure' (off_nil self)

theorem becomeCandidate_off (state : NodeState)
    : Sends (fun _ sent => Off self sent) (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_off self _) fun _ sent off => ?_
  exact Sends.bind' (broadcast_off self _ _)
    fun _ later off' =>
      Sends.pure' (by simpa using off_append off off')

theorem startElection_off (state : NodeState)
    : Sends (fun _ sent => Off self sent) (startElection caps state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ =>
    Sends.mono (becomeCandidate_off self _) fun _ _ off => by simpa using off) fun _ => ?_
  exact Sends.bind' (broadcast_off self _ _)
    fun _ sent off =>
      Sends.pure' (by simpa using off)

theorem checkQuorum_off (state : NodeState)
    : Sends (fun _ sent => Off self sent) (checkQuorum state self) := by
  unfold checkQuorum
  exact Sends.bind' Sends.guard'
    fun _ sent ⟨_, empty⟩ =>
      Sends.pure' (by subst empty; exact off_nil self)

theorem sendEntries_off (state : NodeState) (destination : NodeID) (batchEnds : List Nat)
    : Sends (fun _ sent => Off self sent)
        (sendEntries caps self state destination batchEnds) :=
  Sends.mono (sendEntries_pass self state destination batchEnds)
    fun _ _ pass e member => by
      obtain ⟨batch, _, rfl⟩ := pass.sends e member
      have peer := pass.eligible
      simp [eligiblePeers] at peer
      exact ⟨rfl, peer.1⟩

theorem appendEntry_off (state : NodeState) (content : EntryContent)
    : Sends (fun _ sent => Off self sent) (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' (off_nil self)
    · refine Sends.guard_bind fun _ => ?_
      refine Sends.guard_bind fun _ => ?_
      refine Sends.bind'
        (Sends.forIn' (R := fun e => e.source = self /\ Not (e.target = self))
          fun peer _ member =>
            Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e mem => ?_)
        fun _ _ done => Sends.pure' (by simpa using done)
      subst eq
      simp only [List.append_nil, List.mem_singleton] at mem
      subst mem
      rw [Finset.mem_sort] at member
      exact ⟨rfl, (Finset.mem_erase.mp member).1⟩

theorem appendBatch_off (state : NodeState) (contents : List EntryContent)
    : Sends (fun _ sent => Off self sent) (appendBatch caps self state contents) := by
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind'
    (Sends.mono
      (Sends.foldlM' (I := fun (_ : NodeState) sent => Off self sent)
        (fun value _ item off =>
          Sends.mono (appendEntry_off self value item) fun _ _ off' => off_append off off')
        contents state [] (off_nil self))
      fun _ _ done => by simpa using done)
    fun _ sent off => ?_
  exact Sends.mono (advanceCommit_off self _) fun _ later off' => by
    simpa using off_append off off'

theorem act_off (state : NodeState) (input : Input)
    : Sends (fun _ sent => Off self sent) (act caps self state input) := by
  cases input with
  | append contents => exact appendBatch_off self state contents
  | sendEntries destination batchEnds =>
      exact sendEntries_off self state destination batchEnds
  | timeout kind =>
      cases kind with
      | election => exact startElection_off self state
      | checkQuorum => exact checkQuorum_off self state
  | nominateSuccessor => exact nominate_off self state

theorem appendEntriesRequest_toward (source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : Sends (fun _ sent => Toward self source sent)
        (handleAppendEntriesRequest caps self source state request) := by
  unfold handleAppendEntriesRequest
  dsimp only
  repeat'
    first
    | exact Sends.pure' (toward_nil self source)
    | exact Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
        Sends.pure' (by rw [eq, List.append_nil]; exact toward_back)
    | split

theorem receive_toward (source : NodeID) (state : NodeState) (message : Message)
    : Sends (fun _ sent => Toward self source sent)
        (receive caps self source state message) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (toward_nil self source)) fun _ => ?_
  have lift := fun {α : Type} {m : NodeEffect α}
      (off : Sends (fun _ sent => Off self sent) m) =>
    Sends.mono off fun _ _ (done : Off self _) => done.toward (source := source)
  cases message with
  | appendEntriesRequest request =>
      exact appendEntriesRequest_toward self source _ request
  | requestVoteRequest request =>
      simp only [handleRequestVoteRequest]
      exact Sends.bind' (Sends.send _ _ _)
        fun _ sent eq =>
          Sends.pure' (by rw [eq, List.append_nil]; exact toward_back)
  | requestPreVoteRequest request =>
      simp only [handleRequestPreVoteRequest]
      exact Sends.bind' (Sends.send _ _ _)
        fun _ sent eq =>
          Sends.pure' (by rw [eq, List.append_nil]; exact toward_back)
  | _ =>
      simp only [handleAppendEntriesResponse, handleRequestVoteResponse,
        handleRequestPreVoteResponse, handleProposeRequestVoteRequest]
      repeat'
        first
        | exact lift (advanceCommit_off self _)
        | exact lift (electIfQuorum_off self _)
        | exact lift (becomeCandidate_off self _)
        | exact Sends.pure' (toward_nil self source)
        | refine Sends.ite' (fun _ => ?_) fun _ => ?_

end Effects

/-- Every envelope a protocol action emits is from its actor, to another node or
back to the source of the delivered envelope. -/
theorem outgoing_away {state : Model.State} {action : Model.Action}
    {emitted : List Model.Envelope} (out : outgoing state action = some emitted)
    {e : Model.Envelope} (member : e ∈ emitted)
    : match action with
      | .local node _ => e.source = node /\ Not (e.target = node)
      | .deliver envelope =>
          e.source = envelope.target
          /\ (Not (e.target = envelope.target) \/ e.target = envelope.source) := by
  unfold outgoing at out
  cases action with
  | «local» node input =>
      simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at out
      obtain ⟨before, _, pair, ran, eq⟩ := out
      obtain ⟨_, effects⟩ := pair
      simp only [Option.pure_def, Option.some.injEq] at eq
      subst eq
      obtain ⟨new, outEq, off⟩ := act_off node before input {} _ _ ran
      simp only [List.nil_append] at outEq
      exact off e (outEq ▸ member)
  | deliver envelope =>
      simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at out
      obtain ⟨before, _, pair, ran, eq⟩ := out
      obtain ⟨_, effects⟩ := pair
      simp only [Option.pure_def, Option.some.injEq] at eq
      subst eq
      obtain ⟨new, outEq, toward⟩ :=
        receive_toward envelope.target envelope.source before envelope.payload {} _ _ ran
      simp only [List.nil_append] at outEq
      exact toward e (outEq ▸ member)

section Trace

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {system : CCF.TransitionSystem Model.State Model.Action}
  {trace : Trace W Liveness.Event}

/-- No outstanding packet of an admissible execution is addressed to its sender. -/
theorem pending_not_self (admissible : CCFRaft.Proofs.Liveness.Admissible system trace)
    : forall {index : Nat} {point : W},
        trace.stateAt index = some point
        -> forall packet,
            packet ∈ pending point
            -> Not (packet.envelope.target = packet.envelope.source)
  | 0, point, found, packet, member => by
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      rw [admissible.delivery.init.1] at member
      cases member
  | index + 1, point, found, packet, member => by
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      by_cases old : packet ∈ pending step.before
      · exact pending_not_self admissible (admissible.before stepped) packet old
      obtain ⟨step', action, emitted, stepped', selected, out, emits, _⟩ :=
        admissible.sentAt_emitted ⟨step, stepped, member, old⟩
      rw [stepped, Option.some.injEq] at stepped'
      subst stepped'
      have away := outgoing_away out emits
      cases action with
      | «local» node input =>
          obtain ⟨source, other⟩ := away
          rw [source]
          exact other
      | deliver envelope =>
          obtain ⟨source, other⟩ := away
          intro same
          rw [source] at same
          rcases other with other | back
          · exact other same
          · cases event : step.action with
            | deliver delivered =>
                rw [event] at selected
                simp only [Event.action, Option.some.injEq] at selected
                cases selected
                have consumed := admissible.consumed_pending stepped
                  (packet := delivered) (by rw [event]; rfl)
                exact pending_not_self admissible (admissible.before stepped) _ consumed
                  (same.symm.trans back)
            | _ => rw [event] at selected; simp [Event.action] at selected

end Trace

end CCFRaft.Proofs.Leadership
