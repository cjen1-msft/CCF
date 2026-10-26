module

public import CCFRaft.Proofs.Duel.RaceRun

@[expose] public section

/-!
# One step of the race

Helpers for `race_won`: how a step changes the winner, the other participants and the
packets between participants while the race is running.
-/

namespace CCFRaft.Proofs.Duel.Racing

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

theorem upToDate_term {state : NodeState} {request : RequestVoteRequest} {term : Nat}
    : voteLogUpToDate state { request with term } <-> voteLogUpToDate state request :=
  Iff.rfl

theorem keeps_preVote (self : NodeID) (state : NodeState)
    : Keeps state (preVoteState self state) :=
  ⟨rfl, rfl, rfl⟩

theorem keeps_fresh (self : NodeID) (state : NodeState)
    : Keeps state (freshCandidate self state) :=
  ⟨rfl, rfl, rfl⟩

omit [HasProtocol W Model.State] [HasLive W] [HasTimers W] in
/-- A packet after a step was pending before it, or was sent by it at its time. -/
theorem pending_after_cases {outputs : CCF.Outputs NodeID Message Notification}
    {step : CCF.Execution.Step W Liveness.Event}
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
              (time step.before))
    {packet : Packet} (member : packet ∈ pending step.after)
    : packet ∈ pending step.before
      \/ (packet.envelope ∈ outputs.outgoing /\ packet.sentAt = time step.before) := by
  rw [ledger, List.mem_append] at member
  rcases member with old | new
  · left
    unfold Liveness.Event.remaining at old
    split at old
    · exact List.mem_of_mem_eraseP old
    · exact old
  · obtain ⟨ordinal, found, _, sentEq⟩ := Packet.mem_batch.mp new
    exact Or.inr ⟨List.mem_of_getElem? found, sentEq⟩

omit [HasProtocol W Model.State] [HasLive W] [HasTimers W] in
/-- An envelope a step sends is pending after it, sent at its time. -/
theorem pending_of_sent {outputs : CCF.Outputs NodeID Message Notification}
    {step : CCF.Execution.Step W Liveness.Event}
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
              (time step.before))
    {envelope : Model.Envelope} (member : envelope ∈ outputs.outgoing)
    : exists packet,
        packet ∈ pending step.after
        /\ packet.envelope = envelope
        /\ packet.sentAt = time step.before := by
  obtain ⟨ordinal, found⟩ := List.getElem?_of_mem member
  refine ⟨⟨HasNetwork.issued step.before + ordinal, envelope, time step.before⟩, ?_, rfl,
    rfl⟩
  rw [ledger, List.mem_append]
  exact Or.inr (Packet.mem_batch.mpr ⟨ordinal, found, rfl, rfl⟩)

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- Observing a term of at most `cap` keeps what the race keeps of a node. -/
theorem Other.observed {origin : W} {winner node : NodeID} {term cap observedTerm : Nat}
    {before after : NodeState} (other : Other origin winner term cap node before)
    (observed : Observed before observedTerm after) (le : observedTerm <= cap)
    : Other origin winner term cap node after := by
  obtain ⟨⟨initial, initialFound, keeps, pkKeep⟩, notPrimary, capBound, top⟩ := other
  rcases observed with rfl | ⟨_, rfl⟩
  · exact ⟨⟨initial, initialFound, keeps, pkKeep⟩, notPrimary, capBound, top⟩
  · exact ⟨⟨initial, initialFound, keeps.trans (keeps_bumped _ _), fun _ => rfl⟩,
      by simp [bumpedState], by simp only [bumpedState]; omega,
      fun _ => by simp [bumpedState]⟩

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A participant other than the winner, receiving a hopeless node's pre-vote request,
at most observes its term, and replies with an allowed response. -/
theorem hopeless_request {participants : Finset NodeID} {origin : W}
    {winner node : NodeID} {term : Nat} {base : RequestVoteRequest}
    {before after : NodeState} {envelope : Model.Envelope}
    {outputs : CCF.Outputs NodeID Message Notification} {initial : NodeState}
    (member : node ∈ participants)
    (initialFound : nodeState (proto origin) node = some initial)
    (keeps : Keeps initial before)
    (request
      : envelope.source ≠ winner
        /\ Hopeless participants origin envelope.source
        /\ exists requestTerm requester,
            nodeState (proto origin) envelope.source = some requester
            /\ envelope.payload
                = .requestPreVoteRequest
                    { makeRequestVoteRequest requester with term := requestTerm }
            /\ requestTerm <= term)
    (ran
      : (receive (CCF.Capabilities.record node) node envelope.source before
          envelope.payload).run
          {}
        = some (after, outputs))
    : envelope.payload.term <= term
      /\ Observed before envelope.payload.term after
      /\ forall e,
          e ∈ outputs.outgoing
          -> e.source = node
              /\ e.payload.term = after.currentTerm
              /\ Allowed participants origin winner base term e := by
  obtain ⟨sourceNe, hopeless, requestTerm, requester, requesterFound, payloadEq, le⟩ :=
    request
  rw [payloadEq] at ran ⊢
  obtain ⟨observed, _, sentEq⟩ :=
    sends_run (preVoteRequest_receive node envelope.source before _) ran
  refine ⟨le, observed, fun e sent => ?_⟩
  rw [sentEq, List.mem_singleton] at sent
  subst sent
  refine ⟨rfl, rfl, ?_⟩
  by_cases granted
      : requestTerm = after.currentTerm
        /\ voteLogUpToDate after { makeRequestVoteRequest requester with term := requestTerm }
        /\ !after.primaryKnown
  · refine Or.inr (Or.inr (Or.inr (Or.inr ⟨sourceNe, hopeless, ⟨requestTerm, ?_, le⟩, ?_⟩)))
    · have grantedEq := granted.1
      rw [← grantedEq]
      simp [granted]
    · intro other otherFound
      rw [requesterFound, Option.some.injEq] at otherFound
      subst otherFound
      have upToDate := ((keeps.trans observed.keeps).upToDate _).mp granted.2.1
      unfold PreVoters
      exact Finset.mem_insert_of_mem (Finset.mem_union_right _
        (Finset.mem_filter.mpr ⟨member, initial, initialFound, upToDate_term.mp upToDate⟩))
  · refine Or.inl ?_
    simp only [Inert]
    simpa using granted

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A participant other than the winner, receiving an allowed packet, keeps what the race
keeps of it, and its replies are allowed. -/
theorem other_receive {participants : Finset NodeID} {origin : W} {winner node : NodeID}
    {term cap : Nat} {base : RequestVoteRequest} {before after : NodeState}
    {envelope : Model.Envelope} {outputs : CCF.Outputs NodeID Message Notification}
    (other : Other origin winner term cap node before)
    (bounded : Bounded participants origin term node before)
    (member : node ∈ participants) (ne : node ≠ winner)
    (targetEq : envelope.target = node)
    (allowed : Allowed participants origin winner base term envelope)
    (termLe : envelope.payload.term <= cap)
    (ran
      : (receive (CCF.Capabilities.record node) node envelope.source before
          envelope.payload).run
          {}
        = some (after, outputs))
    : Other origin winner term cap node after
      /\ Bounded participants origin term node after
      /\ forall e,
          e ∈ outputs.outgoing
          -> e.source = node
              /\ e.payload.term <= cap
              /\ Allowed participants origin winner base term e := by
  have otherCopy := other
  obtain ⟨⟨initial, initialFound, keeps, pkKeep⟩, notPrimary, capBound, top⟩ := other
  rcases allowed with inert | ⟨sourceEq, _, pre | vote⟩ | ⟨targetW, _⟩ | request
    | ⟨_, hopeless, ⟨grantTerm, payloadEq, grantLe⟩, preVoter⟩
  · obtain ⟨sentNil, observed⟩ :=
      sends_run (inert_receive node envelope.source before envelope.payload inert notPrimary)
        ran
    exact ⟨otherCopy.observed observed termLe, bounded.observed observed, by simp [sentNil]⟩
  · rw [pre] at ran termLe
    obtain ⟨observed, _, sentEq⟩ :=
      sends_run (preVoteRequest_receive node envelope.source before _) ran
    have afterOther : Other origin winner term cap node after :=
      otherCopy.observed observed termLe
    refine ⟨afterOther, bounded.observed observed, fun e member => ?_⟩
    rw [sentEq, List.mem_singleton] at member
    subst member
    refine ⟨rfl, afterOther.2.2.1, ?_⟩
    by_cases granted
        : term = after.currentTerm /\ voteLogUpToDate after { base with term := term }
            /\ !after.primaryKnown
    · have grantedEq := granted.1
      refine Or.inr (Or.inr (Or.inl ⟨sourceEq, Or.inl ?_⟩))
      rw [← grantedEq]
      simp [granted]
    · refine Or.inl ?_
      simp only [Inert]
      simpa using granted
  · rw [vote] at ran termLe
    obtain ⟨middle, granted, observed, _, grantedIff, afterEq, sentEq⟩ :=
      sends_run (voteRequest_receive node envelope.source before _) ran
    have middleOther : Other origin winner term cap node middle :=
      otherCopy.observed observed termLe
    have afterOther : Other origin winner term cap node after := by
      subst afterEq
      cases granted
      · exact middleOther
      · obtain ⟨⟨i, f, k, p⟩, r, c, t⟩ := middleOther
        refine ⟨⟨i, f, k, p⟩, r, c, fun h => ?_⟩
        obtain ⟨follower, pk, _⟩ := t h
        exact ⟨follower, pk, Or.inr (by simp [sourceEq])⟩
    have afterBounded : Bounded participants origin term node after := by
      have middleBounded := bounded.observed observed
      subst afterEq
      cases granted
      · exact middleBounded
      · exact middleBounded
    refine ⟨afterOther, afterBounded, fun e member => ?_⟩
    rw [sentEq, List.mem_singleton] at member
    subst member
    refine ⟨rfl, middleOther.2.2.1, ?_⟩
    cases granted
    · exact Or.inl (by simp [Inert])
    · have := (grantedIff.mp rfl).1
      refine Or.inr (Or.inr (Or.inl ⟨sourceEq, Or.inr ?_⟩))
      simp only at this ⊢
      rw [← this]
  · exact absurd (targetW ▸ targetEq).symm ne
  · obtain ⟨le, observed, outs⟩ := hopeless_request member initialFound keeps request ran
    exact ⟨otherCopy.observed observed (by omega), bounded.observed observed,
      fun e sent => by have := outs e sent; exact ⟨this.1, by
        rw [this.2.1]; exact (otherCopy.observed observed (by omega)).2.2.1, this.2.2⟩⟩
  · rw [targetEq] at hopeless preVoter
    rw [payloadEq] at ran termLe
    simp only [Message.term] at termLe
    obtain ⟨middle, observed, outcome⟩ :=
      sends_run (preVoteResponse_receive node envelope.source before _) ran
    split at outcome
    · rename_i condition
      obtain ⟨_, role, termEq, _⟩ := condition
      have middleEq : middle = before := by
        rcases observed with rfl | ⟨_, rfl⟩
        · rfl
        · simp [bumpedState] at role
      subst middleEq
      have sub
          : insert envelope.source middle.preVotesGranted
            ⊆ PreVoters participants origin node initial :=
        Finset.insert_subset (preVoter initial initialFound)
          (bounded hopeless (by simp only at termEq; omega) initial initialFound)
      unfold PreVoted at outcome
      split at outcome
      · rename_i quorum
        exact absurd quorum (Hopeless.not_quorum hopeless initialFound keeps sub)
      · obtain ⟨rfl, sentNil⟩ := outcome
        exact ⟨⟨⟨initial, initialFound, keeps, pkKeep⟩, notPrimary, capBound, top⟩,
          fun _ _ other otherFound => by
            rw [initialFound, Option.some.injEq] at otherFound
            subst otherFound
            exact sub, by simp [sentNil]⟩
    · obtain ⟨rfl, sentNil⟩ := outcome
      exact ⟨otherCopy.observed observed (by omega), bounded.observed observed,
        by simp [sentNil]⟩

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A capable voter grants the winner's pre-vote request. -/
theorem voter_preVote {origin : W} {winner voter : NodeID} {term : Nat}
    {base : RequestVoteRequest} {before after : NodeState} {voterState : NodeState}
    {outputs : CCF.Outputs NodeID Message Notification}
    (other : Other origin winner term term voter before)
    (voterFound : nodeState (proto origin) voter = some voterState)
    (upToDate : voteLogUpToDate voterState base)
    (unknown : voterState.primaryKnown = false)
    (ran
      : (receive (CCF.Capabilities.record voter) voter winner before
          (.requestPreVoteRequest { base with term := term })).run
          {}
        = some (after, outputs))
    : outputs.outgoing
      = [{
          source := voter
          target := winner
          payload := .requestPreVoteResponse { term := term, voteGranted := true }
        }] := by
  obtain ⟨⟨initial, initialFound, keeps, pkKeep⟩, _, capBound, _⟩ := other
  rw [voterFound, Option.some.injEq] at initialFound
  subst initialFound
  obtain ⟨observed, termLe, sentEq⟩ :=
    sends_run (preVoteRequest_receive voter winner before _) ran
  have facts : after.currentTerm = term /\ Keeps voterState after
      /\ after.primaryKnown = false := by
    rcases observed with rfl | ⟨lt, rfl⟩
    · exact ⟨by simp only at termLe; omega, keeps, pkKeep unknown⟩
    · exact ⟨rfl, keeps.trans (keeps_bumped _ _), rfl⟩
  obtain ⟨termEq, keeps', pk⟩ := facts
  rw [sentEq, termEq]
  have := (keeps'.upToDate { base with term := term }).mpr upToDate
  simp [this, pk]

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A capable voter grants the winner's vote request. -/
theorem voter_vote {origin : W} {winner voter : NodeID} {term : Nat}
    {base : RequestVoteRequest} {before after : NodeState} {voterState : NodeState}
    {outputs : CCF.Outputs NodeID Message Notification}
    (other : Other origin winner term (term + 1) voter before)
    (voterFound : nodeState (proto origin) voter = some voterState)
    (upToDate : voteLogUpToDate voterState base)
    (unknown : voterState.primaryKnown = false)
    (ran
      : (receive (CCF.Capabilities.record voter) voter winner before
          (.requestVoteRequest { base with term := term + 1 })).run
          {}
        = some (after, outputs))
    : outputs.outgoing
      = [{
          source := voter
          target := winner
          payload := .requestVoteResponse { term := term + 1, voteGranted := true }
        }] := by
  obtain ⟨⟨initial, initialFound, keeps, pkKeep⟩, _, capBound, top⟩ := other
  rw [voterFound, Option.some.injEq] at initialFound
  subst initialFound
  obtain ⟨middle, granted, observed, termLe, grantedIff, _, sentEq⟩ :=
    sends_run (voteRequest_receive voter winner before _) ran
  have facts : middle.currentTerm = term + 1 /\ Keeps voterState middle
      /\ middle.primaryKnown = false
      /\ (middle.votedFor = none \/ middle.votedFor = some winner) := by
    rcases observed with rfl | ⟨lt, rfl⟩
    · have termEq : middle.currentTerm = term + 1 := by
        simp only at termLe; omega
      obtain ⟨_, _, voted⟩ := top termEq
      exact ⟨termEq, keeps, pkKeep unknown, voted⟩
    · exact ⟨rfl, keeps.trans (keeps_bumped _ _), rfl, Or.inl rfl⟩
  obtain ⟨termEq, keeps', pk, voted⟩ := facts
  have yes : granted = true :=
    grantedIff.mpr ⟨termEq.symm, (keeps'.upToDate _).mpr upToDate, pk, voted⟩
  rw [sentEq, termEq, yes]

section Lemmas

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  {electionTimeout maxDelay : Real} {participants : Finset NodeID} {first : Nat}
  {winner : NodeID} {term : Nat}
  (s : Setup nodes trace electionTimeout maxDelay participants first winner term)

include s

namespace Setup

theorem initial_below : forall entry, entry ∈ s.initial.log -> entry.term <= term := by
  obtain ⟨rest, exec⟩ := history_at s.admissible s.originFound
  have inv := good_of_exec exec _ List.suffix_rfl (List.cons_ne_nil _ _)
  intro entry member
  have := inv.terms winner s.initial (now_of_found s.initialFound) entry member
  rwa [s.initialTerm] at this

end Setup

end Lemmas

end CCFRaft.Proofs.Duel.Racing
