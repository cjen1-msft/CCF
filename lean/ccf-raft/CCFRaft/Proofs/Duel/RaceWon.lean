module

public import CCFRaft.Proofs.Duel.RaceStep

@[expose] public section

/-!
# The race is won

`race_won`: the invariant `Setup.Running` holds at every step until the winner is
primary, and it cannot last past `4 * maxDelay` after the race starts.
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

/-- The packets a voter's progress may rest on. -/
def Tracked (winner voter : NodeID) (packet : Packet) : Prop :=
  (packet.envelope.source = winner /\ packet.envelope.target = voter)
  \/ (packet.envelope.source = voter /\ packet.envelope.target = winner)

omit [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W] in
theorem Progress.keep {before after : W} {winner voter : NodeID}
    {granted granted' : Finset NodeID} {request response : Message} {sent maxDelay : Real}
    (progress : Progress before winner voter granted request response sent maxDelay)
    (sub : granted ⊆ granted')
    (keep
      : forall packet,
          packet ∈ pending before
          -> Tracked winner voter packet
          -> packet ∈ pending after)
    : Progress after winner voter granted' request response sent maxDelay := by
  rcases progress with member | ⟨packet, pend, ⟨envEq, sentEq⟩ | ⟨envEq, sentLe⟩⟩
  · exact Or.inl (sub member)
  · exact Or.inr ⟨packet, keep packet pend (Or.inl (by simp [envEq])), Or.inl ⟨envEq, sentEq⟩⟩
  · exact Or.inr ⟨packet, keep packet pend (Or.inr (by simp [envEq])), Or.inr ⟨envEq, sentLe⟩⟩

theorem mem_broadcast {self : NodeID} {state : NodeState} {message : Message}
    {e : Model.Envelope}
    : e ∈ Broadcast self state message
      <-> exists target,
            target ∈ state.activeMembers.erase self
            /\ e = { source := self, target, payload := message } := by
  unfold Broadcast
  simp only [List.mem_map, Finset.mem_sort]
  constructor
  · rintro ⟨target, member, rfl⟩
    exact ⟨target, member, rfl⟩
  · rintro ⟨target, member, rfl⟩
    exact ⟨target, member, rfl⟩

section Lemmas

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  {electionTimeout maxDelay : Real} {participants : Finset NodeID} {first : Nat}
  {winner : NodeID} {term : Nat}
  (s : Setup nodes trace electionTimeout maxDelay participants first winner term)

include s

namespace Setup

/-- A packet left pending by a step was pending before it, unless the step sent it. -/
theorem pending_env {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (selected : step.action.action = none)
    {packet : Packet} (member : packet ∈ pending step.after)
    : packet ∈ pending step.before := by
  obtain ⟨_, _, emitted, emittedEq, _, ledger⟩ := s.admissible.delivery.next stepped
  simp only [selected, Option.some.injEq] at emittedEq
  subst emittedEq
  rw [ledger] at member
  simp only [Packet.batch, List.zipIdx_nil, List.map_nil, List.append_nil] at member
  unfold Liveness.Event.remaining at member
  split at member
  · exact List.mem_of_mem_eraseP member
  · exact member

/-- Packets between the winner and a voter survive every step but their delivery. -/
theorem tracked_kept {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {voter : NodeID}
    (voterIn : voter ∈ participants) {packet : Packet}
    (member : packet ∈ pending step.before) (tracked : Tracked winner voter packet)
    (notDelivered : step.action ≠ .deliver packet)
    : packet ∈ pending step.after := by
  refine s.kept stepped member fun consumed => ?_
  cases event : step.action with
  | deliver delivered =>
      simp only [event, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
      exact notDelivered (by rw [event, consumed])
  | drop dropped =>
      simp only [event, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
      apply s.period.lossless index step dropped within stepped event
      rw [consumed]
      rcases tracked with ⟨src, tgt⟩ | ⟨src, tgt⟩ <;> rw [src, tgt]
      · exact ⟨s.winnerIn, voterIn⟩
      · exact ⟨voterIn, s.winnerIn⟩
  | _ => simp [event, Liveness.Event.consumedPacket] at consumed

/-- An environment step keeps what the race keeps. -/
theorem Common.env {index : Nat} {step : CCF.Execution.Step W Liveness.Event} {cap : Nat}
    (le : first <= index) (stepped : trace.stepAt index = some step)
    (selected : step.action.action = none) (common : s.Common step.before cap)
    : s.Common step.after cap where
  deadlines := s.deadlines_after le stepped common.deadlines
  nodes node state member ne found := by
    rw [s.admissible.stutter stepped selected] at found
    exact common.nodes node state member ne found
  granted node state member ne found := by
    rw [s.admissible.stutter stepped selected] at found
    exact common.granted node state member ne found
  packets packet member source target :=
    common.packets packet (s.pending_env stepped selected member) source target

/-- A protocol step of a node outside the participants keeps what the race keeps,
leaves the winner alone, and keeps every voter's progress: it changes only its actor
and sends only from it, and no packet it consumes is between participants. -/
theorem foreign_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {cap : Nat} (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {actor : NodeID}
    (isActor : step.action.actor = some actor) (outside : actor ∉ participants)
    (common : s.Common step.before cap) {granted : Finset NodeID}
    {request response : Message} {sent : Real}
    : s.Common step.after cap
      /\ nodeState (proto step.after) winner = nodeState (proto step.before) winner
      /\ forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress step.before winner voter granted request response sent maxDelay
          -> Progress step.after winner voter granted request response sent maxDelay := by
  obtain ⟨actor', pre, _, outputs, _, _, others, ran, ledger⟩ :=
    protocol_view s.admissible stepped selected
  have facts : actor' = actor /\ forall e, e ∈ outputs.outgoing -> e.source = actor' := by
    rcases ran with ⟨input, eq, ran⟩ | ⟨packet, eq, targetEq, ran⟩
    · rw [eq] at isActor
      simp only [Liveness.Event.actor, Option.some.injEq] at isActor
      exact ⟨isActor, fun e member =>
        (CCFRaft.Proofs.Safety.Summary.sends
          (sends_run (CCFRaft.Proofs.Safety.summary actor' pre (.internal input)) ran) e
          member).1⟩
    · rw [eq] at isActor
      simp only [Liveness.Event.actor, Option.some.injEq] at isActor
      exact ⟨targetEq.symm.trans isActor, fun e member =>
        (CCFRaft.Proofs.Safety.Summary.sends
          (sends_run (CCFRaft.Proofs.Safety.summary actor' pre
            (.receive packet.envelope.source packet.envelope.payload)) ran) e member).1⟩
  obtain ⟨actorEq, sources⟩ := facts
  have notActor : forall node, node ∈ participants -> node ≠ actor' :=
    fun node member eq => outside ((eq.trans actorEq) ▸ member)
  refine ⟨
    ⟨
      s.deadlines_after le stepped common.deadlines,
      ?_,
      ?_,
      ?_
    ⟩,
    others winner (notActor winner s.winnerIn),
    ?_
  ⟩
  · intro node state member ne found
    rw [others node (notActor node member)] at found
    exact common.nodes node state member ne found
  · intro node state member ne found
    rw [others node (notActor node member)] at found
    exact common.granted node state member ne found
  · intro packet member source target
    rcases pending_after_cases ledger member with old | ⟨new, _⟩
    · exact common.packets packet old source target
    · exact absurd (sources _ new) (notActor _ source)
  · intro voter voterIn voterNe progress
    have voterPart := (s.voterFacts voter voterIn voterNe).1
    exact progress.keep (Finset.Subset.refl _) fun packet member tracked =>
      s.tracked_kept within stepped voterPart member tracked fun eq => by
        rw [eq] at isActor
        simp only [Liveness.Event.actor, Option.some.injEq] at isActor
        have targetIn : packet.envelope.target ∈ participants := by
          rcases tracked with ⟨_, target⟩ | ⟨_, target⟩ <;> rw [target]
          · exact voterPart
          · exact s.winnerIn
        exact notActor _ targetIn (isActor.trans actorEq.symm)

/-- Delivering a packet to a node other than the winner keeps what the race
keeps, leaves the winner alone, and keeps every voter's progress, given that a voter
answers the request of the phase with its grant. -/
theorem deliver_other {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {cap : Nat} (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (ne : packet.envelope.target ≠ winner)
    (common : s.Common step.before cap) {granted : Finset NodeID}
    {request response : Message} {sent : Real}
    (grants
      : forall voter before after outputs,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Other s.origin winner term cap voter before
          -> (receive (CCF.Capabilities.record voter) voter winner before request).run {}
              = some (after, outputs)
          -> outputs.outgoing
              = [{ source := voter, target := winner, payload := response }])
    : s.Common step.after cap
      /\ nodeState (proto step.after) winner = nodeState (proto step.before) winner
      /\ forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress step.before winner voter granted request response sent maxDelay
          -> Progress step.after winner voter granted request response sent maxDelay := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    simp [event, Liveness.Event.action]
  by_cases inside : packet.envelope.target ∈ participants
  swap
  · exact s.foreign_step le within stepped selected (by simp [event, Liveness.Event.actor])
      inside common
  have sourceIn : packet.envelope.source ∈ participants :=
    s.period.isolated index step packet.envelope within stepped
      (by simp [event, Liveness.Event.delivered]) inside
  obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
    protocol_view s.admissible stepped selected
  obtain ⟨delivered, eventEq, targetEq, ran⟩ : exists delivered, step.action = .deliver delivered
      /\ delivered.envelope.target = actor
      /\ (receive (CCF.Capabilities.record actor) actor delivered.envelope.source pre
            delivered.envelope.payload).run {} = some (post, outputs) := by
    rcases ran with ⟨input, eq, _⟩ | found
    · rw [event] at eq
      cases eq
    · exact found
  rw [event, Liveness.Event.deliver.injEq] at eventEq
  subst eventEq
  subst targetEq
  have alive : packet.envelope.target ∈ live step.before :=
    s.admissible.actor_live stepped (by simp [event, Liveness.Event.actor])
  have member : packet ∈ pending step.before := by
    have := (s.admissible.delivery.next stepped).1
    simpa [event, Liveness.Event.consumedPacket] using this
  obtain ⟨termLe, allowed⟩ := common.packets packet member sourceIn inside
  have otherBefore := common.nodes _ pre inside ne preFound
  obtain ⟨otherAfter, boundedAfter, outs⟩ :=
    other_receive otherBefore (common.granted _ pre inside ne preFound) inside ne rfl allowed
      termLe ran
  refine ⟨⟨s.deadlines_after le stepped common.deadlines, ?_, ?_, ?_⟩,
    (others winner ne.symm), ?_⟩
  · intro node state member' ne' found
    by_cases same : node = packet.envelope.target
    · subst same
      rw [postFound, Option.some.injEq] at found
      exact found ▸ otherAfter
    · rw [others node same] at found
      exact common.nodes node state member' ne' found
  · intro node state member' ne' found
    by_cases same : node = packet.envelope.target
    · subst same
      rw [postFound, Option.some.injEq] at found
      exact found ▸ boundedAfter
    · rw [others node same] at found
      exact common.granted node state member' ne' found
  · intro packet' member' source' target'
    rcases pending_after_cases ledger member' with old | ⟨new, _⟩
    · exact common.packets packet' old source' target'
    · exact (outs _ new).2
  · intro voter voterIn voterNe progress
    have voterPart := (s.voterFacts voter voterIn voterNe).1
    rcases progress with grantedIn | ⟨tracked, pend, ⟨envEq, sentEq⟩ | ⟨envEq, sentLe⟩⟩
    · exact Or.inl grantedIn
    · by_cases same : tracked = packet
      · subst same
        rw [envEq] at ran otherBefore
        simp only at ran otherBefore
        have sentOut := grants voter pre post outputs voterIn voterNe otherBefore ran
        have sentMem
            : ({ source := voter, target := winner, payload := response } : Model.Envelope)
              ∈ outputs.outgoing := by
          simp [sentOut]
        obtain ⟨reply, replyIn, replyEnv, replySent⟩ := pending_of_sent ledger sentMem
        have := s.delay_at (s.admissible.before stepped) pend alive
        refine Or.inr ⟨reply, replyIn, Or.inr ⟨replyEnv, ?_⟩⟩
        rw [replySent, ← sentEq]
        exact this
      · exact Or.inr ⟨tracked, s.tracked_kept within stepped voterPart pend
          (Or.inl (by simp [envEq])) (fun eq => same (by rw [event] at eq; cases eq; rfl)),
          Or.inl ⟨envEq, sentEq⟩⟩
    · have : tracked ≠ packet := by
        rintro rfl
        exact ne (by rw [envEq])
      exact Or.inr ⟨tracked, s.tracked_kept within stepped voterPart pend
          (Or.inr (by simp [envEq])) (fun eq => this (by rw [event] at eq; cases eq; rfl)),
          Or.inr ⟨envEq, sentLe⟩⟩

/-- A step of the winner alone keeps what the race keeps of the others, if what it
sends is allowed. -/
theorem Common.winner_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {cap : Nat} (le : first <= index) (stepped : trace.stepAt index = some step)
    {outputs : CCF.Outputs NodeID Message Notification}
    (others
      : forall node,
          node ≠ winner
          -> nodeState (proto step.after) node = nodeState (proto step.before) node)
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
              (time step.before))
    (outs
      : forall e,
          e ∈ outputs.outgoing
          -> e.payload.term <= cap /\ Allowed participants s.origin winner s.base term e)
    (common : s.Common step.before cap)
    : s.Common step.after cap where
  deadlines := s.deadlines_after le stepped common.deadlines
  nodes node state member ne found := by
    rw [others node ne] at found
    exact common.nodes node state member ne found
  granted node state member ne found := by
    rw [others node ne] at found
    exact common.granted node state member ne found
  packets packet member source target := by
    rcases pending_after_cases ledger member with old | ⟨new, _⟩
    · exact common.packets packet old source target
    · exact outs _ new

/-- The step at which the winner becomes primary of `term + 1` ends the race. -/
theorem won_at {candidateIndex index : Nat} {candidatePoint : W}
    {step : CCF.Execution.Step W Liveness.Event} (firstLe : first <= candidateIndex)
    (candidateLe : candidateIndex <= index)
    (candidateFound : trace.stateAt candidateIndex = some candidatePoint)
    (low
      : forall node state,
          node ∈ participants
          -> nodeState (proto candidatePoint) node = some state
          -> state.currentTerm <= term)
    (candidateTime : time candidatePoint <= time s.origin + 2 * maxDelay)
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step)
    (stepTime : time step.before <= time candidatePoint + 2 * maxDelay)
    (busy : Not (step.action = .idle)) {outputs : CCF.Outputs NodeID Message Notification}
    (others
      : forall node,
          node ≠ winner
          -> nodeState (proto step.after) node = nodeState (proto step.before) node)
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
              (time step.before))
    (outs
      : forall e,
          e ∈ outputs.outgoing
          -> e.payload.term <= term + 1
              /\ e.payload ≠ .proposeRequestVoteRequest (term + 1))
    (common : s.Common step.before (term + 1)) {post : NodeState}
    (postFound : nodeState (proto step.after) winner = some post)
    (primary : post.role = .primary) (postTerm : post.currentTerm = term + 1)
    : Won trace electionTimeout maxDelay participants first (index + 1) winner term := by
  have after : trace.stateAt (index + 1) = some step.after :=
    Trace.stateAt_succ_of_stepAt stepped
  have timeEq : time step.after = time step.before := (s.admissible.timing.next stepped).2 busy
  refine ⟨
    ⟨
      s.origin,
      step.after,
      s.originFound,
      after,
      by omega,
      by linarith,
      ?_,
      post,
      postFound,
      primary,
      postTerm
    ⟩,
    ?_,
    ?_,
    ?_
  ⟩
  · exact s.stays_live within stepped s.winnerIn
      (s.participants_live within (s.admissible.before stepped) s.winnerIn)
  · intro point node state found member nodeFound
    rw [after, Option.some.injEq] at found
    subst found
    by_cases same : node = winner
    · subst same
      rw [postFound, Option.some.injEq] at nodeFound
      subst nodeFound
      simp [primary, postTerm]
    · rw [others node same] at nodeFound
      obtain ⟨_, _, capLe, top⟩ := common.nodes node state member same nodeFound
      refine ⟨capLe, fun pre => ?_⟩
      by_contra notLt
      have := (top (by omega)).1
      rw [pre] at this
      cases this
  · intro point packet found member source target
    rw [after, Option.some.injEq] at found
    subst found
    rcases pending_after_cases ledger member with old | ⟨new, _⟩
    · obtain ⟨termLe, allowed⟩ := common.packets packet old source target
      refine ⟨termLe, fun eq => ?_⟩
      rcases allowed with inert | ⟨_, _, pre | vote⟩ | ⟨_, pre | vote⟩
        | ⟨_, _, _, _, _, request, _⟩ | ⟨_, _, ⟨_, grant, _⟩, _⟩ <;>
        rw [eq] at * <;> simp_all [Inert]
    · exact outs _ new
  · intro leaderPoint later step' node state found le' stepped' member timeout nodeFound
      termEq
    rw [after, Option.some.injEq] at found
    subst found
    have fresh := term_fresh s.admissible s.timers candidateFound low later step'.before node
      state (by omega) (s.admissible.before stepped') member nodeFound termEq
    have due := ((s.timers.next stepped') node).2.2 timeout
    linarith

/-- The winner becomes a candidate of `term + 1` at `index`: it wins at once, or the
vote phase starts with its vote requests in flight. -/
theorem candidacy_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) (busy : Not (step.action = .idle))
    (timeBefore : time step.before <= time s.origin + 2 * maxDelay)
    {outputs : CCF.Outputs NodeID Message Notification}
    (others
      : forall node,
          node ≠ winner
          -> nodeState (proto step.after) node = nodeState (proto step.before) node)
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
              (time step.before))
    (common : s.Common step.before term)
    (winnerDeadline : s.margin < deadline step.after winner)
    {pre candidate post : NodeState}
    (preFound : nodeState (proto step.before) winner = some pre)
    (preTerm : pre.currentTerm = term) (keeps : Keeps s.initial candidate)
    (candidateTerm : candidate.currentTerm = term)
    (postFound : nodeState (proto step.after) winner = some post)
    (candidacy : Candidacy winner candidate post outputs.outgoing)
    : Won trace electionTimeout maxDelay participants first (index + 1) winner term
      \/ (s.Common step.after (term + 1) /\ s.Voting step.after (time step.before)) := by
  have beforeFound := s.admissible.before stepped
  have low : forall node state, node ∈ participants
      -> nodeState (proto step.before) node = some state -> state.currentTerm <= term := by
    intro node state member found
    by_cases same : node = winner
    · subst same
      rw [preFound, Option.some.injEq] at found
      subst found
      omega
    · exact (common.nodes node state member same found).2.2.1
  obtain ⟨won, elect, sentEq⟩ := candidacy
  have freshKeeps : Keeps s.initial (freshCandidate winner candidate) :=
    keeps.trans (keeps_fresh _ _)
  have requestEq : makeRequestVoteRequest (freshCandidate winner candidate)
      = { s.base with term := term + 1 } := by
    rw [freshKeeps.request]
    simp [freshCandidate, candidateTerm, base]
  have broadcastFacts : forall e, e ∈ Broadcast winner (freshCandidate winner candidate)
        (.requestVoteRequest (makeRequestVoteRequest (freshCandidate winner candidate)))
      -> e.payload.term <= term + 1 /\ Allowed participants s.origin winner s.base term e := by
    intro e member
    obtain ⟨target, targetIn, rfl⟩ := mem_broadcast.mp member
    refine ⟨by simp [requestEq, Message.term], Or.inr (Or.inl ⟨rfl, ?_, Or.inr ?_⟩)⟩
    · exact (Finset.ne_of_mem_erase targetIn)
    · simp only [requestEq]
  unfold Elect at elect
  split at elect
  · rename_i cond
    have below : Below (freshCandidate winner candidate) := by
      intro entry member
      rw [freshKeeps.1] at member
      have := s.initial_below entry member
      simp only [freshCandidate, candidateTerm]
      omega
    obtain ⟨primary, termEq, wins⟩ := elect below
    left
    refine s.won_at le (le_refl index) beforeFound low timeBefore within stepped
      (by linarith [s.nonnegative]) busy others ledger ?_ (Common.mono s common) postFound
      primary (by simp [termEq, freshCandidate, candidateTerm])
    intro e member
    rw [sentEq, List.mem_append] at member
    rcases member with fromWin | fromBroadcast
    · obtain ⟨_, request, payloadEq, requestTerm⟩ := wins e fromWin
      simp [payloadEq, Message.term, requestTerm, freshCandidate, candidateTerm]
    · obtain ⟨termLe, allowed⟩ := broadcastFacts e fromBroadcast
      refine ⟨termLe, fun eq => ?_⟩
      rcases allowed with inert | ⟨_, _, pv | v⟩ | ⟨_, pv | v⟩
        | ⟨_, _, _, _, _, request, _⟩ | ⟨_, _, ⟨_, grant, _⟩, _⟩ <;>
        rw [eq] at * <;> simp_all [Inert]
  · rename_i cond
    obtain ⟨postEq, wonNil⟩ := elect
    subst wonNil
    rw [List.nil_append] at sentEq
    rw [postEq] at postFound
    right
    refine ⟨Common.winner_step s le stepped others ledger
      (fun e member => broadcastFacts e (sentEq ▸ member)) (Common.mono s common),
      winnerDeadline, _, postFound, rfl, by simp [freshCandidate, candidateTerm], freshKeeps,
      by simp [freshCandidate], ?_, ?_⟩
    · intro quorum
      exact cond ⟨rfl, quorum, fun retired =>
        s.notRetired ((freshKeeps.retired winner).mp retired)⟩
    · intro voter voterIn voterNe
      obtain ⟨_, member, _⟩ := s.voterFacts voter voterIn voterNe
      have sentMem
          : (⟨winner, voter, .requestVoteRequest { s.base with term := term + 1 }⟩
              : Model.Envelope)
            ∈ outputs.outgoing := by
        rw [sentEq, mem_broadcast]
        refine ⟨voter, ?_, by rw [requestEq]⟩
        rwa [freshKeeps.members]
      obtain ⟨packet, member', envEq, sentAt⟩ := pending_of_sent ledger sentMem
      exact Or.inr ⟨packet, member', Or.inl ⟨envEq, sentAt⟩⟩

/-- A local step while the race runs: only a primary acts on anything but an election
timeout, and no timer but a hopeless participant's is due before the margin. A hopeless
participant's timeout starts a pre-vote that cannot reach a quorum. -/
theorem local_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event} {cap : Nat}
    (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {node : NodeID} {input : Input}
    (event : step.action = .local node input) (capLe : cap <= term + 1)
    (common : s.Common step.before cap) (timeLe : time step.before <= s.margin)
    (winnerDeadline : s.margin < deadline step.before winner)
    (winnerRole
      : forall state,
          nodeState (proto step.before) winner = some state -> state.role ≠ .primary)
    {granted : Finset NodeID} {request response : Message} {sent : Real}
    : s.Common step.after cap
      /\ nodeState (proto step.after) winner = nodeState (proto step.before) winner
      /\ forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress step.before winner voter granted request response sent maxDelay
          -> Progress step.after winner voter granted request response sent maxDelay := by
  have selected : step.action.action = some (.local node input) := by
    simp [event, Liveness.Event.action]
  by_cases inside : node ∈ participants
  swap
  · exact s.foreign_step le within stepped selected (by simp [event, Liveness.Event.actor])
      inside common
  obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
    protocol_view s.admissible stepped selected
  obtain ⟨ran, actorEq⟩ : (act (CCF.Capabilities.record node) node pre input).run {}
      = some (post, outputs) /\ actor = node := by
    rcases ran with ⟨input', eq, ran⟩ | ⟨_, eq, _⟩
    · rw [event, Liveness.Event.local.injEq] at eq
      obtain ⟨rfl, rfl⟩ := eq
      exact ⟨ran, rfl⟩
    · rw [event] at eq
      cases eq
  rw [actorEq] at preFound postFound others
  have timeout : input = .timeout .election := by
    by_contra timeout
    have primary := act_primary node timeout ran
    by_cases same : node = winner
    · subst same
      exact winnerRole pre preFound primary
    · exact (common.nodes node pre inside same preFound).2.1 primary
  subst timeout
  have due := ((s.timers.next stepped) node).2.2 event
  have same : node ≠ winner := by
    rintro rfl
    linarith
  obtain ⟨hopeless, termNe⟩
      : Hopeless participants s.origin node /\ pre.currentTerm ≠ term + 1 := by
    by_contra notHopeless
    have := common.deadlines node pre inside same preFound fun hopeless => by
      by_contra termNe
      exact notHopeless ⟨hopeless, termNe⟩
    linarith
  obtain ⟨⟨initial, initialFound, keeps, _⟩, _, capBound, _⟩ :=
    common.nodes node pre inside same preFound
  have keeps' : Keeps initial (preVoteState node pre) := keeps.trans (keeps_preVote _ _)
  have sub : (preVoteState node pre).preVotesGranted
      ⊆ PreVoters participants s.origin node initial := by
    simp only [preVoteState, Finset.singleton_subset_iff, PreVoters]
    exact Finset.mem_insert_self _ _
  simp only [act] at ran
  obtain ⟨_, outcome⟩ := sends_run (startElection_outcome node pre) ran
  split at outcome
  · rename_i quorum
    exact absurd quorum (Hopeless.not_quorum hopeless initialFound keeps' sub)
  obtain ⟨postEq, sentEq⟩ := outcome
  subst post
  have requestEq := keeps'.request
  refine ⟨⟨s.deadlines_after le stepped common.deadlines, ?_, ?_, ?_⟩,
    others winner (fun eq => same eq.symm), ?_⟩
  · intro node' state member ne found
    by_cases eq : node' = node
    · subst eq
      rw [postFound, Option.some.injEq] at found
      subst found
      exact ⟨⟨initial, initialFound, keeps', fun _ => rfl⟩, by simp [preVoteState],
        capBound, fun eq => absurd eq termNe⟩
    · rw [others node' eq] at found
      exact common.nodes node' state member ne found
  · intro node' state member ne found
    by_cases eq : node' = node
    · subst eq
      rw [postFound, Option.some.injEq] at found
      subst found
      intro _ _ other otherFound
      rw [initialFound, Option.some.injEq] at otherFound
      subst otherFound
      exact sub
    · rw [others node' eq] at found
      exact common.granted node' state member ne found
  · intro packet member source target
    rcases pending_after_cases ledger member with old | ⟨new, _⟩
    · exact common.packets packet old source target
    rw [sentEq] at new
    obtain ⟨target, _, envEq⟩ := mem_broadcast.mp new
    rw [envEq]
    refine ⟨capBound,
      Or.inr (Or.inr (Or.inr (Or.inl ⟨same, hopeless, pre.currentTerm, initial, initialFound,
        by rw [requestEq]; rfl, by omega⟩)))⟩
  · intro voter voterIn voterNe progress
    have voterPart := (s.voterFacts voter voterIn voterNe).1
    exact progress.keep (Finset.Subset.refl _) fun packet member tracked =>
      s.tracked_kept within stepped voterPart member tracked fun eq => by
        rw [event] at eq
        cases eq

/-- A delivery to the winner keeps a voter's progress, if the voter's own grant is
counted. -/
theorem progress_winner {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (target : packet.envelope.target = winner)
    {voter : NodeID} (voterIn : voter ∈ s.voters) (voterNe : voter ≠ winner)
    {granted granted' : Finset NodeID} {request response : Message} {sent : Real}
    (progress : Progress step.before winner voter granted request response sent maxDelay)
    (sub : granted ⊆ granted')
    (got : packet.envelope = ⟨voter, winner, response⟩ -> voter ∈ granted')
    : Progress step.after winner voter granted' request response sent maxDelay := by
  have voterPart := (s.voterFacts voter voterIn voterNe).1
  rcases progress with member | ⟨tracked, pend, ⟨envEq, sentEq⟩ | ⟨envEq, sentLe⟩⟩
  · exact Or.inl (sub member)
  · have ne : tracked ≠ packet := by
      rintro rfl
      exact voterNe (by rw [← target, envEq])
    exact Or.inr ⟨tracked, s.tracked_kept within stepped voterPart pend
      (Or.inl (by simp [envEq])) (fun eq => ne (by rw [event] at eq; cases eq; rfl)),
      Or.inl ⟨envEq, sentEq⟩⟩
  · by_cases same : tracked = packet
    · subst same
      exact Or.inl (got envEq)
    · exact Or.inr ⟨tracked, s.tracked_kept within stepped voterPart pend
        (Or.inr (by simp [envEq])) (fun eq => same (by rw [event] at eq; cases eq; rfl)),
        Or.inr ⟨envEq, sentLe⟩⟩

/-- A delivery, seen as a run of its target's handler. -/
theorem deliver_view {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet)
    : exists pre post,
    exists outputs : CCF.Outputs NodeID Message Notification,
      nodeState (proto step.before) packet.envelope.target = some pre
      /\ nodeState (proto step.after) packet.envelope.target = some post
      /\ (forall node,
            node ≠ packet.envelope.target
            -> nodeState (proto step.after) node = nodeState (proto step.before) node)
      /\ (receive (CCF.Capabilities.record packet.envelope.target) packet.envelope.target
            packet.envelope.source pre packet.envelope.payload).run
            {}
          = some (post, outputs)
      /\ pending step.after
          = step.action.remaining (pending step.before)
            ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
                (time step.before)
      /\ packet ∈ pending step.before
      /\ packet.envelope.target ∈ live step.before := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    simp [event, Liveness.Event.action]
  obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
    protocol_view s.admissible stepped selected
  rcases ran with ⟨input, eq, _⟩ | ⟨delivered, eq, targetEq, ran⟩
  · rw [event] at eq
    cases eq
  rw [event, Liveness.Event.deliver.injEq] at eq
  subst eq targetEq
  refine ⟨
    pre,
    post,
    outputs,
    preFound,
    postFound,
    others,
    ran,
    ledger,
    ?_,
    s.admissible.actor_live stepped (by simp [event, Liveness.Event.actor])
  ⟩
  have := (s.admissible.delivery.next stepped).1
  simpa [event, Liveness.Event.consumedPacket] using this

/-- A delivery to the winner while it polls. -/
theorem polling_winner {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (target : packet.envelope.target = winner)
    (common : s.Common step.before term) (polling : s.Polling step.before)
    (timeBefore : time step.before <= time s.origin + 2 * maxDelay)
    : (s.Common step.after term /\ s.Polling step.after)
      \/ Won trace electionTimeout maxDelay participants first (index + 1) winner term
      \/ (s.Common step.after (term + 1) /\ s.Voting step.after (time step.before)) := by
  obtain ⟨pre, post, outputs, preFound, postFound, others, ran, ledger, member, _⟩ :=
    s.deliver_view stepped event
  have targetIn : packet.envelope.target ∈ participants := target ▸ s.winnerIn
  have sourceIn : packet.envelope.source ∈ participants :=
    s.period.isolated index step packet.envelope within stepped
      (by simp [event, Liveness.Event.delivered]) targetIn
  rw [target] at preFound postFound others ran
  obtain ⟨deadlineGt, state, stateFound, role, termEq, keeps, selfIn, noQuorum, progress⟩ :=
    polling
  rw [preFound, Option.some.injEq] at stateFound
  subst state
  obtain ⟨termLe, allowed⟩ := common.packets packet member sourceIn targetIn
  have deadlineAfter := s.margin_after le stepped deadlineGt
  have busy : Not (step.action = .idle) := by rw [event]; simp
  -- The winner unchanged, having sent nothing.
  have stay : post = pre
      -> (forall e, e ∈ outputs.outgoing
          -> e.payload.term <= term /\ Allowed participants s.origin winner s.base term e)
      -> (forall voter, voter ∈ s.voters -> voter ≠ winner
          -> packet.envelope
              = ⟨voter, winner, .requestPreVoteResponse { term := term, voteGranted := true }⟩
          -> voter ∈ pre.preVotesGranted)
      -> s.Common step.after term /\ s.Polling step.after := by
    intro postEq outs got
    subst post
    refine ⟨Common.winner_step s le stepped others ledger outs common,
      deadlineAfter, pre, postFound, role, termEq, keeps, selfIn, noQuorum,
      fun voter voterIn voterNe => s.progress_winner within stepped event target voterIn
        voterNe (progress voter voterIn voterNe) (Finset.Subset.refl _)
        (got voter voterIn voterNe)⟩
  rcases allowed with inert | ⟨_, targetNe, _⟩ | ⟨_, grant | grant⟩ | request
    | ⟨targetNe, _⟩
  · obtain ⟨sentNil, observed⟩ :=
      sends_run (inert_receive winner packet.envelope.source pre packet.envelope.payload inert
        (by rw [role]; simp)) ran
    have postEq : post = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · omega
    refine Or.inl (stay postEq (by simp [sentNil]) fun voter _ _ envEq => ?_)
    rw [envEq] at inert
    simp [Inert] at inert
  · exact absurd target targetNe
  · rw [grant] at ran
    obtain ⟨middle, observed, outcome⟩ :=
      sends_run (preVoteResponse_receive winner packet.envelope.source pre _) ran
    have middleEq : middle = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · simp only at lt
        omega
    subst middle
    have eligible : forall voter, voter ∈ s.voters -> voter ≠ winner
        -> voter ∈ eligiblePeers pre winner := by
      intro voter voterIn voterNe
      rw [keeps.peers]
      exact (s.voterFacts voter voterIn voterNe).2.2.1
    split at outcome
    · rename_i cond
      unfold PreVoted at outcome
      split at outcome
      · exact Or.inr (s.candidacy_step le within stepped busy timeBefore others ledger
          common deadlineAfter preFound termEq (keeps.trans ⟨rfl, rfl, rfl⟩)
          termEq postFound outcome)
      · rename_i quorum
        obtain ⟨postEq, sentNil⟩ := outcome
        subst postEq
        refine Or.inl ⟨Common.winner_step s le stepped others ledger (by simp [sentNil]) common,
          deadlineAfter, _, postFound, role, termEq, keeps, Finset.mem_insert_of_mem selfIn,
          quorum, fun voter voterIn voterNe => s.progress_winner within stepped event target
            voterIn voterNe (progress voter voterIn voterNe) (Finset.subset_insert _ _)
            fun envEq => ?_⟩
        rw [envEq]
        exact Finset.mem_insert_self _ _
    · rename_i cond
      obtain ⟨postEq, sentNil⟩ := outcome
      refine Or.inl (stay postEq (by simp [sentNil]) fun voter voterIn voterNe envEq => ?_)
      exfalso
      apply cond
      rw [envEq]
      exact ⟨eligible voter voterIn voterNe, role, termEq.symm, rfl⟩
  · rw [grant] at termLe
    simp [Message.term] at termLe
  · obtain ⟨_, _, _, _, _, payloadEq, _⟩ := id request
    obtain ⟨le', observed, outs⟩ :=
      hopeless_request s.winnerIn s.initialFound keeps request ran
    have postEq : post = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · omega
    refine Or.inl (stay postEq (fun e member => ?_) fun voter _ _ envEq => ?_)
    · obtain ⟨_, termEq', allowed⟩ := outs e member
      exact ⟨by rw [termEq', postEq, termEq], allowed⟩
    · have := congrArg (fun e : Model.Envelope => e.payload) envEq
      simp [payloadEq] at this
  · exact absurd target targetNe

/-- A delivery to the winner while it collects votes. -/
theorem voting_winner {index candidateIndex : Nat} {candidatePoint : W}
    {step : CCF.Execution.Step W Liveness.Event} (le : first <= index)
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (target : packet.envelope.target = winner)
    (firstLe : first <= candidateIndex) (candidateLe : candidateIndex <= index)
    (candidateFound : trace.stateAt candidateIndex = some candidatePoint)
    (low
      : forall node state,
          node ∈ participants
          -> nodeState (proto candidatePoint) node = some state
          -> state.currentTerm <= term)
    (candidateTime : time candidatePoint <= time s.origin + 2 * maxDelay)
    (stepTime : time step.before <= time candidatePoint + 2 * maxDelay)
    (common : s.Common step.before (term + 1))
    (voting : s.Voting step.before (time candidatePoint))
    : (s.Common step.after (term + 1) /\ s.Voting step.after (time candidatePoint))
      \/ Won trace electionTimeout maxDelay participants first (index + 1) winner
          term := by
  obtain ⟨pre, post, outputs, preFound, postFound, others, ran, ledger, member, _⟩ :=
    s.deliver_view stepped event
  have targetIn : packet.envelope.target ∈ participants := target ▸ s.winnerIn
  have sourceIn : packet.envelope.source ∈ participants :=
    s.period.isolated index step packet.envelope within stepped
      (by simp [event, Liveness.Event.delivered]) targetIn
  rw [target] at preFound postFound others ran
  obtain ⟨deadlineGt, state, stateFound, role, termEq, keeps, selfIn, noQuorum, progress⟩ :=
    voting
  rw [preFound, Option.some.injEq] at stateFound
  subst state
  obtain ⟨termLe, allowed⟩ := common.packets packet member sourceIn targetIn
  have deadlineAfter := s.margin_after le stepped deadlineGt
  have busy : Not (step.action = .idle) := by rw [event]; simp
  have stay : post = pre
      -> (forall e, e ∈ outputs.outgoing
          -> e.payload.term <= term + 1 /\ Allowed participants s.origin winner s.base term e)
      -> (forall voter, voter ∈ s.voters -> voter ≠ winner
          -> packet.envelope
              = ⟨voter, winner, .requestVoteResponse { term := term + 1, voteGranted := true }⟩
          -> voter ∈ pre.votesGranted)
      -> s.Common step.after (term + 1) /\ s.Voting step.after (time candidatePoint) := by
    intro postEq outs got
    subst post
    exact ⟨Common.winner_step s le stepped others ledger outs common,
      deadlineAfter, pre, postFound, role, termEq, keeps, selfIn, noQuorum,
      fun voter voterIn voterNe => s.progress_winner within stepped event target voterIn
        voterNe (progress voter voterIn voterNe) (Finset.Subset.refl _)
        (got voter voterIn voterNe)⟩
  rcases allowed with inert | ⟨_, targetNe, _⟩ | ⟨_, grant | grant⟩ | request
    | ⟨targetNe, _⟩
  · obtain ⟨sentNil, observed⟩ :=
      sends_run (inert_receive winner packet.envelope.source pre packet.envelope.payload inert
        (by rw [role]; simp)) ran
    have postEq : post = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · omega
    refine Or.inl (stay postEq (by simp [sentNil]) fun voter _ _ envEq => ?_)
    rw [envEq] at inert
    simp [Inert] at inert
  · exact absurd target targetNe
  · rw [grant] at ran
    obtain ⟨middle, observed, outcome⟩ :=
      sends_run (preVoteResponse_receive winner packet.envelope.source pre _) ran
    have middleEq : middle = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · simp only at lt
        omega
    subst middle
    split at outcome
    · rename_i cond
      exact absurd cond.2.1 (by rw [role]; simp)
    obtain ⟨postEq, sentNil⟩ := outcome
    refine Or.inl (stay postEq (by simp [sentNil]) fun voter _ _ envEq => ?_)
    have payloadEq := congrArg (fun e : Model.Envelope => e.payload) envEq
    rw [grant] at payloadEq
    simp at payloadEq
  · rw [grant] at ran
    obtain ⟨middle, observed, outcome⟩ :=
      sends_run (voteResponse_receive winner packet.envelope.source pre _) ran
    have middleEq : middle = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · simp only at lt
        omega
    subst middle
    split at outcome
    · rename_i cond
      unfold Elect at outcome
      split at outcome
      · obtain ⟨primary, postTerm, wins⟩ := outcome (by
          intro entry member
          have := s.initial_below entry (keeps.1 ▸ member)
          simp only [termEq]
          omega)
        refine Or.inr (s.won_at firstLe candidateLe candidateFound low candidateTime within
          stepped stepTime busy others ledger ?_ common postFound primary
          (by simpa [termEq] using postTerm))
        intro e member
        obtain ⟨_, request, payloadEq, requestTerm⟩ := wins e member
        simp [payloadEq, Message.term, requestTerm, termEq]
      · rename_i notWon
        obtain ⟨postEq, sentNil⟩ := outcome
        subst post
        refine Or.inl ⟨Common.winner_step s le stepped others ledger (by simp [sentNil]) common,
          deadlineAfter, _, postFound, role, termEq, keeps, Finset.mem_insert_of_mem selfIn,
          fun quorum => notWon ⟨role, quorum, fun retired =>
            s.notRetired ((keeps.retired winner).mp retired)⟩,
          fun voter voterIn voterNe => s.progress_winner within stepped event target
            voterIn voterNe (progress voter voterIn voterNe) (Finset.subset_insert _ _)
            fun envEq => ?_⟩
        rw [envEq]
        exact Finset.mem_insert_self _ _
    · rename_i cond
      obtain ⟨postEq, sentNil⟩ := outcome
      refine Or.inl (stay postEq (by simp [sentNil]) fun voter voterIn voterNe envEq => ?_)
      exfalso
      apply cond
      rw [envEq]
      refine ⟨?_, role, termEq.symm, rfl⟩
      rw [keeps.peers]
      exact (s.voterFacts voter voterIn voterNe).2.2.1
  · obtain ⟨_, _, _, _, _, payloadEq, _⟩ := id request
    obtain ⟨le', observed, outs⟩ :=
      hopeless_request s.winnerIn s.initialFound keeps request ran
    have postEq : post = pre := by
      rcases observed with rfl | ⟨lt, _⟩
      · rfl
      · omega
    refine Or.inl (stay postEq (fun e member => ?_) fun voter _ _ envEq => ?_)
    · obtain ⟨_, termEq', allowed⟩ := outs e member
      exact ⟨by rw [termEq', postEq, termEq], allowed⟩
    · have := congrArg (fun e : Model.Envelope => e.payload) envEq
      simp [payloadEq] at this
  · exact absurd target targetNe

theorem alive_after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step)
    : forall node, node ∈ participants -> node ∈ live step.after :=
  fun _ member =>
    s.stays_live within stepped member
      (s.participants_live within (s.admissible.before stepped) member)

theorem within_of_time {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step)
    (timeLe : time step.after <= time s.origin + 4 * maxDelay)
    : Within trace s.start s.duration (index + 1) := by
  refine ⟨Nat.le_succ_of_le within.1, fun start point startFound found => ?_⟩
  rw [s.periodFound, Option.some.injEq] at startFound
  rw [Trace.stateAt_succ_of_stepAt stepped, Option.some.injEq] at found
  subst start point
  linarith [s.covers]

theorem running_polling {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) (common : s.Common step.after term)
    (polling : s.Polling step.after)
    : s.Running (index + 1) := by
  have found := Trace.stateAt_succ_of_stepAt stepped
  obtain ⟨_, state, _, _, _, keeps, selfIn, noQuorum, progress⟩ := id polling
  have timeLe := s.progress_time found keeps selfIn noQuorum progress (s.alive_after within stepped)
  exact ⟨
    step.after,
    found,
    by omega,
    s.within_of_time within stepped (by linarith [s.nonnegative]),
    Or.inl ⟨common, polling, timeLe⟩
  ⟩

theorem running_voting {index candidateIndex : Nat} {candidatePoint : W}
    {step : CCF.Execution.Step W Liveness.Event} (le : first <= index)
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) (firstLe : first <= candidateIndex)
    (candidateLe : candidateIndex <= index)
    (candidateFound : trace.stateAt candidateIndex = some candidatePoint)
    (candidateTime : time candidatePoint <= time s.origin + 2 * maxDelay)
    (low
      : forall node state,
          node ∈ participants
          -> nodeState (proto candidatePoint) node = some state
          -> state.currentTerm <= term)
    (common : s.Common step.after (term + 1))
    (voting : s.Voting step.after (time candidatePoint))
    : s.Running (index + 1) := by
  have found := Trace.stateAt_succ_of_stepAt stepped
  obtain ⟨_, state, _, _, _, keeps, selfIn, noQuorum, progress⟩ := id voting
  have timeLe := s.progress_time found keeps selfIn noQuorum progress (s.alive_after within stepped)
  exact ⟨
    step.after,
    found,
    by omega,
    s.within_of_time within stepped (by linarith [s.nonnegative]),
    Or.inr
      ⟨
        candidateIndex,
        candidatePoint,
        firstLe,
        by omega,
        candidateFound,
        candidateTime,
        low,
        common,
        voting,
        timeLe
      ⟩
  ⟩

/-- An environment step keeps the winner and its voters' progress. -/
theorem winner_env {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) (selected : step.action.action = none)
    (busy : forall packet, step.action ≠ .deliver packet) {granted : Finset NodeID}
    {request response : Message} {sent : Real}
    : (s.margin < deadline step.before winner -> s.margin < deadline step.after winner)
      /\ nodeState (proto step.after) winner = nodeState (proto step.before) winner
      /\ forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress step.before winner voter granted request response sent maxDelay
          -> Progress step.after winner voter granted request response sent maxDelay :=
  ⟨
    s.margin_after le stepped,
    by rw [s.admissible.stutter stepped selected],
    fun voter voterIn voterNe progress =>
      progress.keep (Finset.Subset.refl _)
        fun packet member tracked =>
          s.tracked_kept within stepped (s.voterFacts voter voterIn voterNe).1 member
            tracked (busy packet)
  ⟩

/-- One step of a running race: it is still running after, or won. -/
theorem running_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (running : s.Running index) (stepped : trace.stepAt index = some step)
    : s.Running (index + 1)
      \/ Won trace electionTimeout maxDelay participants first (index + 1) winner
          term := by
  obtain ⟨point, found, firstLt, within, phase⟩ := running
  have le : first <= index := by omega
  rw [s.admissible.before stepped, Option.some.injEq] at found
  subst point
  rcases phase with ⟨common, polling, timeLe⟩
      | ⟨candidateIndex, candidatePoint, firstLe, candidateLt, candidateFound, candidateTime,
          low, common, voting, timeLe⟩
  · -- Polling.
    have role : forall state, nodeState (proto step.before) winner = some state
        -> state.role ≠ .primary := by
      obtain ⟨_, state, found, role, _⟩ := polling
      intro state' found'
      rw [found, Option.some.injEq] at found'
      subst found'
      rw [role]
      simp
    cases event : step.action with
    | «local» node input =>
        obtain ⟨deadlineGt, state, stateFound, winnerRole, termEq, keeps, selfIn, noQuorum,
          progress⟩ := id polling
        obtain ⟨common', winnerSame, progress'⟩ :=
          s.local_step le within stepped event (by omega) common
            (by unfold margin; linarith [s.nonnegative]) deadlineGt role
            (granted := state.preVotesGranted)
            (request := .requestPreVoteRequest { s.base with term := term })
            (response := .requestPreVoteResponse { term := term, voteGranted := true })
            (sent := time s.origin)
        exact Or.inl (s.running_polling le within stepped common' ⟨s.margin_after le stepped
          deadlineGt, state, winnerSame ▸ stateFound, winnerRole, termEq, keeps, selfIn, noQuorum,
          fun voter voterIn voterNe =>
            progress' voter voterIn voterNe (progress voter voterIn voterNe)⟩)
    | deliver packet =>
        by_cases target : packet.envelope.target = winner
        · rcases s.polling_winner le within stepped event target common polling timeLe with
            ⟨common', polling'⟩ | won | ⟨common', voting'⟩
          · exact Or.inl (s.running_polling le within stepped common' polling')
          · exact Or.inr won
          · refine Or.inl (s.running_voting le within stepped le (le_refl index)
              (s.admissible.before stepped) timeLe ?_ common' voting')
            intro node state member nodeFound
            by_cases same : node = winner
            · subst same
              obtain ⟨_, state', found', _, termEq, _⟩ := polling
              rw [found', Option.some.injEq] at nodeFound
              subst nodeFound
              omega
            · exact (common.nodes node state member same nodeFound).2.2.1
        · obtain ⟨deadlineGt, state, stateFound, role, termEq, keeps, selfIn, noQuorum,
            progress⟩ := polling
          obtain ⟨common', winnerSame, progress'⟩ :=
            s.deliver_other le within stepped event target common
              (granted := state.preVotesGranted) (sent := time s.origin)
              fun voter before after outputs voterIn voterNe other ran => by
                obtain ⟨_, _, _, voterState, voterFound, upToDate, unknown⟩ :=
                  s.voterFacts voter voterIn voterNe
                exact voter_preVote other voterFound upToDate unknown ran
          exact Or.inl (s.running_polling le within stepped common' ⟨s.margin_after le stepped
            deadlineGt, state, winnerSame ▸ stateFound, role, termEq, keeps, selfIn, noQuorum,
            fun voter voterIn voterNe =>
              progress' voter voterIn voterNe (progress voter voterIn voterNe)⟩)
    | _ =>
        have selected : step.action.action = none := by simp [event, Liveness.Event.action]
        have busy : forall packet, step.action ≠ .deliver packet := by simp [event]
        obtain ⟨deadlineGt, state, stateFound, role, termEq, keeps, selfIn, noQuorum,
          progress⟩ := polling
        obtain ⟨deadline', same, progress'⟩ := s.winner_env le within stepped selected busy
          (granted := state.preVotesGranted)
          (request := .requestPreVoteRequest { s.base with term := term })
          (response := .requestPreVoteResponse { term := term, voteGranted := true })
          (sent := time s.origin)
        exact Or.inl (s.running_polling le within stepped (common.env s le stepped selected)
          ⟨deadline' deadlineGt, state, same ▸ stateFound, role, termEq, keeps, selfIn,
            noQuorum, fun voter voterIn voterNe =>
              progress' voter voterIn voterNe (progress voter voterIn voterNe)⟩)
  · -- Voting.
    have candidateLe : candidateIndex <= index := by omega
    have role : forall state, nodeState (proto step.before) winner = some state
        -> state.role ≠ .primary := by
      obtain ⟨_, state, found, role, _⟩ := voting
      intro state' found'
      rw [found, Option.some.injEq] at found'
      subst found'
      rw [role]
      simp
    cases event : step.action with
    | «local» node input =>
        obtain ⟨deadlineGt, state, stateFound, winnerRole, termEq, keeps, selfIn, noQuorum,
          progress⟩ := id voting
        obtain ⟨common', winnerSame, progress'⟩ :=
          s.local_step le within stepped event (le_refl _) common
            (by unfold margin; linarith [s.nonnegative]) deadlineGt role
            (granted := state.votesGranted)
            (request := .requestVoteRequest { s.base with term := term + 1 })
            (response := .requestVoteResponse { term := term + 1, voteGranted := true })
            (sent := time candidatePoint)
        exact Or.inl (s.running_voting le within stepped firstLe candidateLe
          candidateFound candidateTime low common' ⟨s.margin_after le stepped deadlineGt,
            state, winnerSame ▸ stateFound, winnerRole, termEq, keeps, selfIn, noQuorum,
            fun voter voterIn voterNe =>
              progress' voter voterIn voterNe (progress voter voterIn voterNe)⟩)
    | deliver packet =>
        by_cases target : packet.envelope.target = winner
        · rcases s.voting_winner le within stepped event target firstLe candidateLe
            candidateFound low candidateTime timeLe common voting with
            ⟨common', voting'⟩ | won
          · exact Or.inl (s.running_voting le within stepped firstLe candidateLe
              candidateFound candidateTime low common' voting')
          · exact Or.inr won
        · obtain ⟨deadlineGt, state, stateFound, role, termEq, keeps, selfIn, noQuorum,
            progress⟩ := voting
          obtain ⟨common', winnerSame, progress'⟩ :=
            s.deliver_other le within stepped event target common
              (granted := state.votesGranted) (sent := time candidatePoint)
              fun voter before after outputs voterIn voterNe other ran => by
                obtain ⟨_, _, _, voterState, voterFound, upToDate, unknown⟩ :=
                  s.voterFacts voter voterIn voterNe
                exact voter_vote other voterFound upToDate unknown ran
          exact Or.inl (s.running_voting le within stepped firstLe candidateLe
            candidateFound candidateTime low common' ⟨s.margin_after le stepped deadlineGt,
              state, winnerSame ▸ stateFound, role, termEq, keeps, selfIn, noQuorum,
              fun voter voterIn voterNe =>
                progress' voter voterIn voterNe (progress voter voterIn voterNe)⟩)
    | _ =>
        have selected : step.action.action = none := by simp [event, Liveness.Event.action]
        have busy : forall packet, step.action ≠ .deliver packet := by simp [event]
        obtain ⟨deadlineGt, state, stateFound, role, termEq, keeps, selfIn, noQuorum,
          progress⟩ := voting
        obtain ⟨deadline', same, progress'⟩ := s.winner_env le within stepped selected busy
          (granted := state.votesGranted)
          (request := .requestVoteRequest { s.base with term := term + 1 })
          (response := .requestVoteResponse { term := term + 1, voteGranted := true })
          (sent := time candidatePoint)
        exact Or.inl (s.running_voting le within stepped firstLe candidateLe candidateFound
          candidateTime low (common.env s le stepped selected)
          ⟨deadline' deadlineGt, state, same ▸ stateFound, role, termEq, keeps, selfIn,
            noQuorum, fun voter voterIn voterNe =>
              progress' voter voterIn voterNe (progress voter voterIn voterNe)⟩)

theorem low_of_common {point : W} (common : s.Common point term) {state : NodeState}
    (found : nodeState (proto point) winner = some state)
    (termEq : state.currentTerm = term)
    : forall node state,
        node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm <= term := by
  intro node state' member nodeFound
  by_cases same : node = winner
  · subst same
    rw [found, Option.some.injEq] at nodeFound
    subst nodeFound
    omega
  · exact (common.nodes node state' member same nodeFound).2.2.1

theorem common_origin : s.Common s.origin term where
  deadlines node state member ne found high :=
    s.race.margin s.origin node s.originFound member ne
      fun hopeless => by
        have := (s.race.settled s.origin node state s.originFound member found).1
        have := high hopeless
        omega
  granted node state _ _ found _ _ initial initialFound := by
    rw [found, Option.some.injEq] at initialFound
    subst initialFound
    intro voter member
    unfold PreVoters
    exact Finset.mem_insert_of_mem (Finset.mem_union_left _ member)
  nodes node state member _ found := by
    obtain ⟨termLe, notPrimary⟩ :=
      s.race.settled s.origin node state s.originFound member found
    exact ⟨⟨state, found, Keeps.refl _, id⟩, notPrimary, termLe, fun eq => by omega⟩
  packets packet member source target := by
    obtain ⟨termLe, inert | request | grant⟩ :=
      s.race.inert s.origin packet s.originFound member source target
    · exact ⟨termLe, Or.inl inert⟩
    · exact ⟨termLe, Or.inr (Or.inr (Or.inr (Or.inl request)))⟩
    · exact ⟨termLe, Or.inr (Or.inr (Or.inr (Or.inr grant)))⟩

theorem within_first : Within trace s.start s.duration first := by
  refine ⟨s.startLe, fun start point startFound found => ?_⟩
  rw [s.periodFound, Option.some.injEq] at startFound
  rw [s.originFound, Option.some.injEq] at found
  subst start point
  linarith [s.covers, s.nonnegative]

/-- The winner's timeout at `first` starts the race. -/
theorem base_step {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt first = some step)
    : s.Running (first + 1)
      \/ Won trace electionTimeout maxDelay participants first (first + 1) winner
          term := by
  have event := s.race.timeout step stepped
  have beforeFound := s.admissible.before stepped
  have beforeEq : step.before = s.origin := by
    rw [s.originFound, Option.some.injEq] at beforeFound
    exact beforeFound.symm
  have selected : step.action.action = some (.local winner (.timeout .election)) := by
    simp [event, Liveness.Event.action]
  obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
    protocol_view s.admissible stepped selected
  obtain ⟨input, eq, ran⟩ : exists input, step.action = .local actor input
      /\ (act (CCF.Capabilities.record actor) actor pre input).run {}
          = some (post, outputs) := by
    rcases ran with found | ⟨_, eq, _⟩
    · exact found
    · rw [event] at eq
      cases eq
  rw [event, Liveness.Event.local.injEq] at eq
  obtain ⟨rfl, rfl⟩ := eq
  simp only [act] at ran
  obtain ⟨_, outcome⟩ := sends_run (startElection_outcome winner pre) ran
  have preEq : pre = s.initial := by
    rw [beforeEq, s.initialFound, Option.some.injEq] at preFound
    exact preFound.symm
  subst pre
  have common : s.Common step.before term := beforeEq ▸ s.common_origin
  have busy : Not (step.action = .idle) := by rw [event]; simp
  have timeBefore : time step.before <= time s.origin + 2 * maxDelay := by
    rw [beforeEq]
    linarith [s.nonnegative]
  have winnerDeadline : s.margin < deadline step.after winner := by
    have reset : ElectionReset step winner := by simp [ElectionReset, event]
    have := ((s.timers.next stepped) winner).1 reset
    unfold margin
    rw [beforeEq] at this
    linarith [this.1, s.ratio]
  have keeps : Keeps s.initial (preVoteState winner s.initial) := keeps_preVote _ _
  have low := s.low_of_common common preFound s.initialTerm
  split at outcome
  · rcases s.candidacy_step (le_refl first) s.within_first stepped busy timeBefore others
      ledger common winnerDeadline preFound s.initialTerm keeps s.initialTerm postFound
      outcome with won | ⟨common', voting⟩
    · exact Or.inr won
    · exact Or.inl (s.running_voting (le_refl first) s.within_first stepped (le_refl first)
        (le_refl first) beforeFound timeBefore low common' voting)
  · rename_i quorum
    obtain ⟨postEq, sentEq⟩ := outcome
    subst post
    have requestEq : makeRequestVoteRequest (preVoteState winner s.initial)
        = { s.base with term := term } := by
      rw [keeps.request]
      simp [preVoteState, s.initialTerm, base]
    have outs : forall e, e ∈ outputs.outgoing
        -> e.payload.term <= term /\ Allowed participants s.origin winner s.base term e := by
      intro e member
      rw [sentEq] at member
      obtain ⟨target, targetIn, rfl⟩ := mem_broadcast.mp member
      refine ⟨by simp [requestEq, Message.term], Or.inr (Or.inl ⟨rfl, ?_, Or.inl ?_⟩)⟩
      · exact Finset.ne_of_mem_erase targetIn
      · simp only [requestEq]
    refine Or.inl (s.running_polling (le_refl first) s.within_first stepped
      (Common.winner_step s (le_refl first) stepped others ledger outs common)
      ⟨winnerDeadline, _, postFound, rfl, by simp [preVoteState, s.initialTerm], keeps,
        by simp [preVoteState], quorum, fun voter voterIn voterNe => ?_⟩)
    obtain ⟨_, member, _⟩ := s.voterFacts voter voterIn voterNe
    have sentMem
        : (⟨winner, voter, .requestPreVoteRequest { s.base with term := term }⟩
            : Model.Envelope)
          ∈ outputs.outgoing := by
      rw [sentEq, mem_broadcast]
      refine ⟨voter, ?_, by rw [requestEq]⟩
      rwa [keeps.members]
    obtain ⟨packet, member', envEq, sentAt⟩ := pending_of_sent ledger sentMem
    exact Or.inr ⟨packet, member', Or.inl ⟨envEq, by rw [sentAt, beforeEq]⟩⟩

theorem running_time {index : Nat} (running : s.Running index) {point : W}
    (found : trace.stateAt index = some point)
    : time point <= time s.origin + 4 * maxDelay := by
  obtain ⟨point', found', _, _, phase⟩ := running
  rw [found, Option.some.injEq] at found'
  subst point'
  rcases phase with ⟨_, _, timeLe⟩ | ⟨_, _, _, _, _, candidateTime, _, _, _, timeLe⟩
  · linarith [s.nonnegative]
  · linarith

/-- The race is won: time diverges, and it cannot run past `4 * maxDelay`. -/
theorem eventually (diverges : TimeDiverges trace)
    : exists leaderIndex,
        Won trace electionTimeout maxDelay participants first leaderIndex winner
          term := by
  obtain ⟨far, point, found, ge⟩ := diverges (time s.origin + 4 * maxDelay + 1)
  have firstLt : first < far := by
    by_contra notLt
    have := s.admissible.time_le (by omega) found s.originFound
    linarith [s.nonnegative]
  have claim : forall k, first + 1 + k <= far
      -> (exists leaderIndex, Won trace electionTimeout maxDelay participants first leaderIndex winner term)
          \/ s.Running (first + 1 + k) := by
    intro k
    induction k with
    | zero =>
        intro _
        obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt firstLt found
        rcases s.base_step stepped with running | won
        · exact Or.inr running
        · exact Or.inl ⟨_, won⟩
    | succ k ih =>
        intro le
        rcases ih (by omega) with won | running
        · exact Or.inl won
        obtain ⟨step, stepped⟩ :=
          Trace.stepAt_of_stateAt_lt (index := first + 1 + k) (by omega) found
        rcases s.running_step running stepped with running' | won
        · exact Or.inr running'
        · exact Or.inl ⟨_, won⟩
  rcases claim (far - first - 1) (by omega) with won | running
  · exact won
  · have eq : first + 1 + (far - first - 1) = far := by omega
    rw [eq] at running
    have := s.running_time running found
    linarith

end Setup

end Lemmas

section Main

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}

omit [HasTimers W] in
/-- A recorded election timeout runs under `canStartElection`. -/
theorem timeout_can
    (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (event : step.action = .local node (.timeout .election))
    : exists state,
        nodeState (proto step.before) node = some state
        /\ canStartElection state node := by
  have selected : step.action.action = some (.local node (.timeout .election)) := by
    simp [event, Liveness.Event.action]
  obtain ⟨actor, pre, post, outputs, preFound, _, _, ran, _⟩ :=
    protocol_view admissible stepped selected
  rcases ran with ⟨input, eq, ran⟩ | ⟨_, eq, _⟩
  · rw [event, Liveness.Event.local.injEq] at eq
    obtain ⟨rfl, rfl⟩ := eq
    simp only [act] at ran
    exact ⟨pre, preFound, (sends_run (startElection_outcome node pre) ran).1⟩
  · rw [event] at eq
    cases eq

/-- (b) A race with a margin, started by a recorded timeout, is won within four
message delays, and the win is fresh for half an election timeout less two delays.
`4 * maxDelay < electionTimeout / 2` keeps the timers the race itself resets beyond
the margin. -/
theorem race_won {electionTimeout maxDelay : Real} {participants : Finset NodeID}
    {first : Nat} {winner : NodeID} {term : Nat}
    (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout)) (diverges : TimeDiverges trace)
    (nonnegative : 0 <= maxDelay) (ratio : 4 * maxDelay < electionTimeout / 2)
    (race : Race trace electionTimeout maxDelay participants first winner term)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt first = some step)
    : exists leaderIndex,
        Won trace electionTimeout maxDelay participants first leaderIndex winner
          term := by
  have originFound := admissible.before stepped
  obtain ⟨initial, initialFound, can⟩ :=
    timeout_can admissible stepped (race.timeout step stepped)
  obtain ⟨winnerIn, state, stateFound, initialTerm⟩ := race.competes step.before originFound
  rw [initialFound, Option.some.injEq] at stateFound
  subst state
  obtain ⟨voters, quorate, voterFacts⟩ :=
    race.capable step.before initial originFound initialFound
  obtain ⟨start, duration, periodOrigin, period, startLe, periodFound, covers⟩ :=
    race.covered step.before originFound
  exact Setup.eventually
    { admissible, delay, timers, nonnegative, ratio, race, origin := step.before,
      originFound, initial, initialFound, initialTerm, notRetired := can.2.2, winnerIn,
      voters, quorate, voterFacts, start, duration, period, startLe, periodOrigin,
      periodFound, covers }
    diverges

end Main

end CCFRaft.Proofs.Duel.Racing
