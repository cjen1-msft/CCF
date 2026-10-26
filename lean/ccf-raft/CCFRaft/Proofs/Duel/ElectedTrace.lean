module

public import CCFRaft.Proofs.Duel.RoundInv
public import CCFRaft.Proofs.Duel.ElectedNet
public import CCFRaft.Proofs.Duel.ElectedNode
public import CCFRaft.Proofs.Leadership.ConfiguredWindow

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

include setup originFound

/-- The first four delays after the round starts are inside the good period. -/
theorem within {index : Nat} {point : W} (le : c <= index)
    (found : trace.stateAt index = some point)
    (early : time point <= time origin + 4 * d)
    : Within trace start duration index :=
  setup.inside origin originFound index point le found early

/-- Restrict the good period to the round's first four delays. -/
theorem good : GoodPeriod trace c (4 * d) participants := by
  have inside : forall index, Within trace c (4 * d) index
      -> Within trace start duration index := by
    intro index bounded
    refine ⟨setup.startLe.trans bounded.1, ?_⟩
    intro first last firstFound lastFound
    exact (within setup originFound bounded.1 lastFound
      (bounded.2 origin last originFound lastFound)).2 first last firstFound lastFound
  exact {
    participantsLive := fun i p n w => setup.period.participantsLive i p n (inside i w)
    quorum := fun i p n s w => setup.period.quorum i p n s (inside i w)
    noReconfiguration := fun i s n es w =>
      setup.period.noReconfiguration i s n es (inside i w)
    noNominations := fun i s n w => setup.period.noNominations i s n (inside i w)
    noQuorumChecks := fun i s n w => setup.period.noQuorumChecks i s n (inside i w)
    lossless := fun i s p w => setup.period.lossless i s p (inside i w)
    isolated := fun i s e w => setup.period.isolated i s e (inside i w)
  }

/-- Fixed membership propagates from the round start, not the window start. -/
theorem membership {index : Nat} {point : W} (le : c <= index)
    (found : trace.stateAt index = some point)
    (early : time point <= time origin + 4 * d)
    : Liveness.Membership participants members (proto point) := by
  apply Leadership.Membership.window setup.admissible (good setup originFound)
    setup.membership index point ?_ found
  refine ⟨le, ?_⟩
  intro first last firstFound lastFound
  rw [originFound, Option.some.injEq] at firstFound
  rw [found, Option.some.injEq] at lastFound
  subst first last
  exact early

/-- A participant in the new term cannot time out during the first half-timeout. -/
theorem no_timeout {index : Nat} {step : Execution.Step W Liveness.Event}
    {node : NodeID} {state : NodeState} (le : c <= index)
    (stepped : trace.stepAt index = some step)
    (early : time step.before < time origin + E / 2)
    (member : node ∈ participants)
    (found : nodeState (proto step.before) node = some state)
    (termEq : state.currentTerm = term + 1)
    : Not (step.action = .local node (.timeout .election)) := by
  intro timeout
  have fresh := Racing.term_fresh setup.admissible setup.timers originFound
    (fun n s m f => setup.round.low origin n s originFound m f)
    index step.before node state le (setup.admissible.before stepped) member found termEq
  have due := ((setup.timers.next stepped) node).2.2 timeout
  linarith

/-- Before half a timeout there are no pre-vote candidates in the new term. -/
theorem no_pre_vote
    : forall index point node state,
        c <= index
        -> trace.stateAt index = some point
        -> time point < time origin + E / 2
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1
        -> Not (state.role = .preVoteCandidate) := by
  intro index
  induction index with
  | zero =>
      intro point node state le found early member nodeFound termEq role
      have eq : c = 0 := by omega
      subst c
      have low := setup.round.low point node state found member nodeFound
      omega
  | succ index ih =>
      intro point node state le found early member nodeFound termEq role
      by_cases atStart : c = index + 1
      · rw [← atStart] at found
        have low := setup.round.low point node state found member nodeFound
        omega
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeFound := setup.admissible.before stepped
      have earlyBefore : time step.before < time origin + E / 2 :=
        lt_of_le_of_lt (setup.admissible.timing.next stepped).1 early
      rcases selected : step.action.action with _ | action
      · rw [setup.admissible.stutter stepped selected] at nodeFound
        exact ih step.before node state (by omega) beforeFound earlyBefore member
          nodeFound termEq role
      obtain ⟨rest, ctx, acts, _⟩ := ctx_at setup.admissible stepped selected
      rcases ctx.now_after (now_of_found (rest := proto step.before :: rest) nodeFound)
        with ⟨actorEq, postEq⟩ | ⟨_, previous⟩
      · subst node state
        obtain ⟨sameTerm, priorRole | timeout⟩ :=
          CCFRaft.Proofs.Safety.Summary.pre_vote ctx.sum role
        · exact ih step.before ctx.actor ctx.pre (by omega) beforeFound earlyBefore
            member ctx.tr.found (sameTerm ▸ termEq) priorRole
        · exact no_timeout setup originFound (by omega) stepped earlyBefore member
            ctx.tr.found (sameTerm ▸ termEq)
            (Racing.local_of_internal selected acts timeout)
      · exact ih step.before node state (by omega) beforeFound earlyBefore member
          (found_of_now ctx.prior previous) termEq role

/-- A time boundary has a last recorded state on its near side. -/
theorem boundary (bound : Real) (nonnegative : 0 <= bound)
    : exists index step,
        c <= index
        /\ trace.stepAt index = some step
        /\ time step.before <= time origin + bound
        /\ time origin + bound < time step.after := by
  obtain ⟨far, point, found, late⟩ := setup.diverges (time origin + bound + 1)
  have farLe : c <= far := by
    by_contra h
    have := setup.admissible.time_le (by omega : far <= c) found originFound
    linarith
  obtain ⟨index, le, lt, ⟨before, beforeFound, early⟩, outside⟩ :=
    CCFRaft.Proofs.Liveness.exists_exit
      (holds := fun i => exists p, trace.stateAt i = some p
        /\ time p <= time origin + bound)
      farLe ⟨origin, originFound, by linarith⟩ (by
        rintro ⟨p, pf, early⟩
        rw [found, Option.some.injEq] at pf
        subst p
        linarith)
  obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt lt found
  rw [setup.admissible.before stepped, Option.some.injEq] at beforeFound
  subst before
  refine ⟨index, step, le, stepped, early, ?_⟩
  by_contra h
  exact outside ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, by linarith⟩

/-- The protocol network contains only old envelopes or envelopes actually sent
since the round started, even when the packet ledger forgets dropped packets. -/
theorem network_since {P : Model.Envelope -> Prop}
    (initial : forall e, e.payload.term <= term -> P e)
    (emitted
      : forall index step action rest
                (ctx : Ctx nodes (proto step.after) (proto step.before) rest),
          c <= index
          -> trace.stepAt index = some step
          -> time step.after <= time origin + 4 * d
          -> step.action.action = some action
          -> StablePrimary.Acts action ctx.actor ctx.event
          -> outgoing (proto step.before) action = some ctx.tr.outputs.outgoing
          -> forall e,
              e ∈ ctx.tr.outputs.outgoing
              -> e.source ∈ participants
              -> e.target ∈ participants
              -> P e)
    : forall index point,
        c <= index
        -> trace.stateAt index = some point
        -> time point <= time origin + 4 * d
        -> forall e,
            e ∈ (proto point).network
            -> e.source ∈ participants
            -> e.target ∈ participants
            -> P e := by
  intro index
  induction index with
  | zero =>
      intro point le found _ e queued sourceIn _
      have eq : c = 0 := by omega
      subst c
      obtain ⟨sender, now, termLe⟩ := network_terms (setup.admissible.reachable found) e queued
      obtain ⟨rest, exec⟩ := history_at setup.admissible found
      exact initial e (termLe.trans
        (setup.round.low point e.source sender found sourceIn (found_of_now exec now)))
  | succ index ih =>
      intro point le found early e queued sourceIn targetIn
      by_cases atStart : c = index + 1
      · rw [← atStart] at found
        obtain ⟨sender, now, termLe⟩ := network_terms (setup.admissible.reachable found) e queued
        obtain ⟨rest, exec⟩ := history_at setup.admissible found
        exact initial e (termLe.trans
          (setup.round.low point e.source sender found sourceIn (found_of_now exec now)))
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have earlyBefore : time step.before <= time origin + 4 * d :=
        le_trans (setup.admissible.timing.next stepped).1 early
      rcases selected : step.action.action with _ | action
      · rw [setup.admissible.stutter stepped selected] at queued
        exact ih step.before (by omega) (setup.admissible.before stepped) earlyBefore
          e queued sourceIn targetIn
      obtain ⟨rest, ctx, acts, out⟩ := ctx_at setup.admissible stepped selected
      rcases ctx.tr.mem_network queued with old | new
      · exact ih step.before (by omega) (setup.admissible.before stepped) earlyBefore
          e old sourceIn targetIn
      · exact emitted index step action rest ctx (by omega) stepped early selected
          acts out e new sourceIn targetIn

/-- No proposal of the newly elected term is in flight during settling. -/
theorem no_proposals {index : Nat} {point : W}
    (le : c <= index) (found : trace.stateAt index = some point)
    (early : time point <= time origin + 4 * d)
    : forall e,
        e ∈ (proto point).network
        -> e.source ∈ participants
        -> e.target ∈ participants
        -> Not (e.payload = .proposeRequestVoteRequest (term + 1)) := by
  apply network_since setup originFound (P := fun e =>
    Not (e.payload = .proposeRequestVoteRequest (term + 1))) ?_ ?_ index point le found early
  · intro e low payload
    rw [payload] at low
    change term + 1 <= term at low
    omega
  · intro index step action rest ctx le stepped early selected acts _ e sent sourceIn _ payload
    have actorIn : ctx.actor ∈ participants :=
      (CCFRaft.Proofs.Safety.Summary.sends ctx.sum e sent).1 ▸ sourceIn
    rcases ElectedStep.proposals (LocalTransition.electedStep ctx.tr) e sent _ payload with
      nomination | retired
    · exact setup.period.noNominations index step ctx.actor
        (within setup originFound le (setup.admissible.before stepped)
          (le_trans (setup.admissible.timing.next stepped).1 early))
        stepped (Racing.local_of_internal selected acts nomination)
    · exact setup.active (index + 1) step.after ctx.actor ctx.post
        (within setup originFound (Nat.le_succ_of_le le)
          (Trace.stateAt_succ_of_stepAt stepped) early)
        (Trace.stateAt_succ_of_stepAt stepped) actorIn
        (found_of_now ctx.exec ctx.post_now) retired

omit originFound in
/-- A cap on nodes also caps protocol messages, including dropped envelopes. -/
theorem capped_messages {index : Nat} {point : W}
    (found : trace.stateAt index = some point)
    (cap : Capped trace participants c term index)
    : forall e,
        e ∈ (proto point).network
        -> e.source ∈ participants
        -> e.payload.term <= term + 1 := by
  intro e queued sourceIn
  obtain ⟨sender, now, termLe⟩ := network_terms (setup.admissible.reachable found) e queued
  obtain ⟨rest, exec⟩ := history_at setup.admissible found
  exact termLe.trans (cap.2 index point e.source sender cap.1 le_rfl found sourceIn
    (found_of_now exec now))

/-- A participant cannot receive an exceptional event while latched in the
new term and while the round remains capped. -/
theorem no_exempt {index : Nat} {step : Execution.Step W Liveness.Event}
    {action : Model.Action} {rest : History}
    (ctx : Ctx nodes (proto step.after) (proto step.before) rest)
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (early : time step.before <= time origin + 4 * d)
    (selected : step.action.action = some action)
    (acts : StablePrimary.Acts action ctx.actor ctx.event)
    (cap : Capped trace participants c term index)
    (member : ctx.actor ∈ participants) (termEq : ctx.pre.currentTerm = term + 1)
    : Not (Leadership.Exempt ctx.pre ctx.event) := by
  have bounded := within setup originFound le (setup.admissible.before stepped) early
  have sourceIn : forall source message, ctx.event = .receive source message
      -> source ∈ participants := by
    intro source message eventEq
    obtain ⟨envelope, actionEq, targetEq, sourceEq, _⟩ := acts_receive acts eventEq
    subst action
    exact sourceEq ▸ setup.period.isolated index step envelope bounded stepped
      (delivered_of_action selected) (targetEq ▸ member)
  rintro (timeout | check | ⟨source, message, eventEq, raised⟩ | ⟨source, eventEq⟩)
  · exact no_timeout setup originFound le stepped (by linarith [setup.ratio]) member
      ctx.tr.found termEq
      (Racing.local_of_internal selected acts timeout)
  · exact setup.period.noQuorumChecks index step ctx.actor bounded stepped member
      (Racing.local_of_internal selected acts check)
  · obtain ⟨e, queued, sourceEq, _, payload⟩ := ctx.received eventEq
    have high := capped_messages setup (setup.admissible.before stepped) cap e queued
      (sourceEq ▸ sourceIn source message eventEq)
    rw [payload] at high
    omega
  · obtain ⟨e, queued, sourceEq, targetEq, payload⟩ := ctx.received eventEq
    exact no_proposals setup originFound le (setup.admissible.before stepped) early
      e queued (sourceEq ▸ sourceIn _ _ eventEq) (targetEq ▸ member)
      (by rw [payload, termEq])

end CCFRaft.Proofs.Duel.Elected
