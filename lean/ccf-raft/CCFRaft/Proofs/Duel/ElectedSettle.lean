module

public import CCFRaft.Proofs.Duel.ElectedVoters

@[expose] public section

set_option linter.unusedSectionVars false

namespace CCFRaft.Proofs.Duel.Elected

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCFRaft.Proofs.Duel.Round

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]
  [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {E d jump duration : Real} {start c term : Nat}
  {participants members : Finset NodeID}
  (setup : RoundShort nodes trace E d jump start duration participants members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (capped
    : forall i p,
        c <= i
        -> trace.stateAt i = some p
        -> time p <= time origin + 4 * d
        -> Capped trace participants c term i)

include setup originFound capped

/-- A voter's term and vote are preserved throughout the capped part of the round. -/
theorem vote_kept {first : Nat} {initial : W} {node leader : NodeID} {state : NodeState}
    (firstLe : c <= first) (initialFound : trace.stateAt first = some initial)
    (member : node ∈ participants)
    (nodeFound : nodeState (proto initial) node = some state)
    (termEq : state.currentTerm = term + 1) (vote : state.votedFor = some leader)
    : forall index point,
        first <= index
        -> trace.stateAt index = some point
        -> time point <= time origin + 4 * d
        -> exists state,
            nodeState (proto point) node = some state
            /\ state.currentTerm = term + 1
            /\ state.votedFor = some leader := by
  intro index point le found early
  induction index, le using Nat.le_induction generalizing point with
  | base =>
      rw [initialFound, Option.some.injEq] at found
      subst point
      exact ⟨state, nodeFound, termEq, vote⟩
  | succ index le ih =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeFound := setup.admissible.before stepped
      obtain ⟨previous, previousFound, previousTerm, previousVote⟩ :=
        ih step.before beforeFound
          (le_trans (setup.admissible.timing.next stepped).1 early)
      rcases selected : step.action.action with _ | action
      · exact ⟨previous, by rw [setup.admissible.stutter stepped selected]; exact previousFound,
          previousTerm, previousVote⟩
      obtain ⟨rest, ctx, _, _⟩ := ctx_at setup.admissible stepped selected
      by_cases same : node = ctx.actor
      · subst node
        have eq := ctx.now_pre (now_of_found previousFound)
        subst previous
        have postFound := found_of_now ctx.exec ctx.post_now
        have high := (capped (index + 1) step.after (by omega)
          (Trace.stateAt_succ_of_stepAt stepped) early).2 (index + 1) step.after ctx.actor
          ctx.post (by omega) le_rfl (Trace.stateAt_succ_of_stepAt stepped) member postFound
        have mono := CCFRaft.Proofs.Safety.Summary.term_le ctx.sum
        have sameTerm : ctx.post.currentTerm = ctx.pre.currentTerm := by omega
        exact ⟨ctx.post, postFound, by omega,
          CCFRaft.Proofs.Safety.Summary.vote_keep ctx.sum sameTerm leader previousVote⟩
      · exact ⟨previous,
          found_of_now ctx.exec (ctx.now_other same (now_of_found previousFound)),
          previousTerm, previousVote⟩

/-- A known follower or primary remains known, with the same role and term. -/
theorem known_kept {first : Nat} {initial : W} {node : NodeID} {state : NodeState}
    (firstLe : c <= first) (initialFound : trace.stateAt first = some initial)
    (member : node ∈ participants)
    (nodeFound : nodeState (proto initial) node = some state)
    (termEq : state.currentTerm = term + 1) (known : state.primaryKnown = true)
    (role : state.role = .follower \/ state.role = .primary)
    : forall index point,
        first <= index
        -> trace.stateAt index = some point
        -> time point <= time origin + 4 * d
        -> exists after,
            nodeState (proto point) node = some after
            /\ after.currentTerm = term + 1
            /\ after.primaryKnown = true
            /\ after.role = state.role := by
  intro index point le found early
  induction index, le using Nat.le_induction generalizing point with
  | base =>
      rw [initialFound, Option.some.injEq] at found
      subst point
      exact ⟨state, nodeFound, termEq, known, rfl⟩
  | succ index le ih =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeFound := setup.admissible.before stepped
      have earlyBefore : time step.before <= time origin + 4 * d :=
        le_trans (setup.admissible.timing.next stepped).1 early
      obtain ⟨previous, previousFound, previousTerm, previousKnown, previousRole⟩ :=
        ih step.before beforeFound earlyBefore
      rcases selected : step.action.action with _ | action
      · exact ⟨previous, by rw [setup.admissible.stutter stepped selected]; exact previousFound,
          previousTerm, previousKnown, previousRole⟩
      obtain ⟨rest, ctx, acts, _⟩ := ctx_at setup.admissible stepped selected
      by_cases same : node = ctx.actor
      · subst node
        have eq := ctx.now_pre (now_of_found previousFound)
        subst previous
        have postFound := found_of_now ctx.exec ctx.post_now
        have high := (capped (index + 1) step.after (by omega)
          (Trace.stateAt_succ_of_stepAt stepped) early).2 (index + 1) step.after ctx.actor
          ctx.post (by omega) le_rfl (Trace.stateAt_succ_of_stepAt stepped) member postFound
        have mono := CCFRaft.Proofs.Safety.Summary.term_le ctx.sum
        rcases (Leadership.LocalTransition.anchorStep ctx.tr).keep previousKnown
            (previousRole ▸ role) with (⟨keptRole, keptKnown⟩ | retired) | exempt
        · exact ⟨ctx.post, postFound, by omega, keptKnown.trans previousKnown,
            keptRole.trans previousRole⟩
        · exact (setup.active (index + 1) step.after ctx.actor ctx.post
            (within setup originFound (by omega) (Trace.stateAt_succ_of_stepAt stepped) early)
            (Trace.stateAt_succ_of_stepAt stepped) member postFound retired).elim
        · exact (no_exempt setup originFound ctx (by omega) stepped earlyBefore selected acts
            (capped index step.before (by omega) beforeFound earlyBefore)
            member previousTerm exempt).elim
      · exact ⟨previous,
          found_of_now ctx.exec (ctx.now_other same (now_of_found previousFound)),
          previousTerm, previousKnown, previousRole⟩

omit capped in
/-- The packet timing hypothesis excludes protocol pre-vote grants as well. -/
theorem no_grants
    (lateGrants
      : forall index point packet,
          c <= index
          -> trace.stateAt index = some point
          -> time point <= time origin + 4 * d
          -> packet ∈ pending point
          -> packet.envelope.source ∈ participants
          -> packet.envelope.target ∈ participants
          -> packet.envelope.payload
              = .requestPreVoteResponse { term := term + 1, voteGranted := true }
          -> time origin + E / 2 <= packet.sentAt)
    {index : Nat} {point : W} (le : c <= index)
    (found : trace.stateAt index = some point) (early : time point <= time origin + 4 * d)
    : forall e,
        e ∈ (proto point).network
        -> e.source ∈ participants
        -> e.target ∈ participants
        -> Not
            (e.payload
              = .requestPreVoteResponse { term := term + 1, voteGranted := true }) := by
  apply network_since setup originFound (P := fun e =>
    Not (e.payload = .requestPreVoteResponse { term := term + 1, voteGranted := true }))
    ?_ ?_ index point le found early
  · intro e low payload
    rw [payload] at low
    change term + 1 <= term at low
    omega
  · intro i step action rest ctx le stepped early selected _ out e sent sourceIn targetIn payload
    obtain ⟨packet, ⟨sentStep, sentAt, queued, _⟩, envelopeEq, sentTime⟩ :=
      setup.admissible.sentAt_of_emitted stepped selected out sent
    rw [stepped, Option.some.injEq] at sentAt
    subst sentStep
    have late := lateGrants (i + 1) step.after packet (by omega)
      (Trace.stateAt_succ_of_stepAt stepped) early queued
      (envelopeEq ▸ sourceIn) (envelopeEq ▸ targetIn) (by rw [envelopeEq, payload])
    have mono := (setup.admissible.timing.next stepped).1
    rw [sentTime] at late
    linarith [setup.ratio]

omit capped in
/-- A participant remains live across a step that starts in the good window,
even if an idle step carries time beyond its end. -/
theorem live_after {index : Nat} {step : Execution.Step W Liveness.Event}
    (bounded : Within trace start duration index)
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (member : node ∈ participants)
    : node ∈ live step.after := by
  have alive := setup.period.participantsLive index step.before node bounded
    (setup.admissible.before stepped) member
  by_contra dead
  have crashed := setup.admissible.crashes stepped alive dead
  have next := setup.admissible.within_after bounded stepped
    (fun idle => by rw [crashed] at idle; cases idle)
  exact dead (setup.period.participantsLive (index + 1) step.after node next
    (Trace.stateAt_succ_of_stepAt stepped) member)

omit capped in
/-- Every sufficiently early packet between participants is delivered strictly
before the step crossing the settling deadline. -/
theorem delivered_before {win stop : Nat} {crossing : Execution.Step W Liveness.Event}
    {packet : Packet} (winLe : c <= win) (winStop : win < stop)
    (sent : trace.SentAt win packet)
    (crossed : trace.stepAt stop = some crossing)
    (near : time crossing.before <= time origin + 4 * d)
    (far : time origin + 4 * d < time crossing.after)
    (sentEarly : packet.sentAt <= time origin + 3 * d)
    (sourceIn : packet.envelope.source ∈ participants)
    (targetIn : packet.envelope.target ∈ participants)
    : exists index step,
        win < index
        /\ index < stop
        /\ trace.stepAt index = some step
        /\ step.action = .deliver packet := by
  obtain ⟨sentStep, sentAt, queued, _⟩ := sent
  have crossFound := Trace.stateAt_succ_of_stepAt crossed
  have crossBefore := setup.admissible.before crossed
  have bounded := within setup originFound (by omega) crossBefore
    (by linarith [setup.ratio])
  have notQueued : Not (packet ∈ pending crossing.after) := by
    intro queued
    have late := CCFRaft.Proofs.Liveness.pending_deadline setup.delay crossFound queued
      (live_after setup originFound bounded crossed targetIn)
    linarith
  obtain ⟨index, le, lt, ⟨before, beforeFound, pending⟩, outside⟩ :=
    CCFRaft.Proofs.Liveness.exists_exit
      (holds := fun i => exists p, trace.stateAt i = some p /\ packet ∈ pending p)
      (by omega : win + 1 <= stop + 1)
      ⟨sentStep.after, Trace.stateAt_succ_of_stepAt sentAt, queued⟩
      (by
        rintro ⟨p, pf, queued⟩
        rw [crossFound, Option.some.injEq] at pf
        subst p
        exact notQueued queued)
  obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt lt crossFound
  rw [setup.admissible.before stepped, Option.some.injEq] at beforeFound
  subst before
  have consumed := setup.admissible.consumed_of_left stepped pending (fun after =>
    outside ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, after⟩)
  have withinIndex := Leadership.within_of_le setup.admissible bounded crossBefore
    (by have := setup.startLe; omega) (by omega : index <= stop)
  have delivery : step.action = .deliver packet := by
    cases eventEq : step.action with
    | deliver p =>
        simp only [eventEq, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
        exact congrArg Liveness.Event.deliver consumed
    | drop p =>
        simp only [eventEq, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
        subst p
        exact (setup.period.lossless index step packet withinIndex stepped eventEq
          ⟨sourceIn, targetIn⟩).elim
    | _ => simp [eventEq, Liveness.Event.consumedPacket] at consumed
  refine ⟨index, step, by omega, ?_, stepped, delivery⟩
  by_contra h
  have eq : index = stop := by omega
  subst index
  rw [crossed, Option.some.injEq] at stepped
  subst step
  have busy : Not (crossing.action = .idle) := by rw [delivery]; simp
  have same := (setup.admissible.timing.next crossed).2 busy
  linarith

end CCFRaft.Proofs.Duel.Elected
