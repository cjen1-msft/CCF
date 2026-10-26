module

public import CCFRaft.Proofs.Duel.ElectedTrace

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

variable [Config.InitialConfiguration]

/-- Nodes seen in a protocol execution are still present at its head. -/
theorem seen_current {nodes : List NodeID} {current : Model.State} {rest : History}
    (exec : Exec nodes (current :: rest)) {node : NodeID} {state : NodeState}
    (seen : Seen (current :: rest) node state)
    : exists now, Now (current :: rest) node now := by
  generalize eq : current :: rest = history at exec seen
  induction exec generalizing current rest with
  | initial initialized =>
      cases eq
      obtain ⟨_, mem, now⟩ := seen
      simp only [List.mem_singleton] at mem
      subst mem
      exact ⟨state, now⟩
  | @step before after tail action prior stepped ih =>
      cases eq
      obtain ⟨point, mem, now⟩ := seen
      rcases List.mem_cons.mp mem with rfl | old
      · exact ⟨state, now⟩
      obtain ⟨previous, previousNow⟩ := ih rfl ⟨point, old, now⟩
      obtain ⟨tr⟩ := LocalTransition.ofStep stepped
      by_cases same : node = tr.actor
      · exact ⟨tr.post, same ▸ tr.post_mem⟩
      · exact ⟨previous, tr.other_mem previousNow same⟩

/-- A granted vote is still recorded when the voter's term is capped. -/
theorem granted_current {nodes : List NodeID} {current : Model.State} {rest : History}
    (exec : Exec nodes (current :: rest)) {voter leader : NodeID} {term : Nat}
    {request : RequestVoteRequest}
    (granted : Granted (current :: rest) voter leader term request)
    (cap : forall state, Now (current :: rest) voter state -> state.currentTerm <= term)
    : exists state,
        Now (current :: rest) voter state
        /\ state.currentTerm = term
        /\ state.votedFor = some leader := by
  obtain ⟨after, before, tail, suffix, granting, state, _, now, _, termEq, vote, _⟩ := granted
  have seen : Seen (current :: rest) voter state :=
    ⟨after, suffix.subset List.mem_cons_self, now⟩
  obtain ⟨present, presentNow⟩ := seen_current exec seen
  have inv := good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have recorded := inv.vote_record voter present state leader presentNow seen vote
  have high := cap present presentNow
  refine ⟨present, presentNow, ?_⟩
  rcases recorded with raised | ⟨same, recorded⟩
  · omega
  · exact ⟨same.symm.trans termEq, recorded⟩

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]
  [HasNetwork W] [HasTimers W] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {E d jump duration : Real} {start c term : Nat}
  {participants members : Finset NodeID}
  (setup : RoundSetup nodes trace E d jump start duration participants members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)

include setup originFound

/-- A participant in the round's new term has not entered role `none`. -/
theorem no_none
    : forall index point node state,
        c <= index
        -> trace.stateAt index = some point
        -> time point < time origin + E / 2
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1
        -> Not (state.role = .none) := by
  intro index
  induction index with
  | zero =>
      intro point node state le found _ member nodeFound termEq _
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
      obtain ⟨rest, ctx, _, _⟩ := ctx_at setup.admissible stepped selected
      rcases ctx.now_after (now_of_found (rest := proto step.before :: rest) nodeFound)
        with ⟨actorEq, postEq⟩ | ⟨_, previous⟩
      · subst node state
        rcases ElectedStep.none (LocalTransition.electedStep ctx.tr) role with
          ⟨priorRole, sameTerm⟩ | retired
        · exact ih step.before ctx.actor ctx.pre (by omega) beforeFound earlyBefore
            member ctx.tr.found (sameTerm ▸ termEq) priorRole
        · exact setup.active (index + 1) step.after ctx.actor ctx.post
            (within setup originFound le (Trace.stateAt_succ_of_stepAt stepped) early.le)
            (Trace.stateAt_succ_of_stepAt stepped) member nodeFound retired
      · exact ih step.before node state (by omega) beforeFound earlyBefore member
          (found_of_now ctx.prior previous) termEq role

/-- A campaign adds only its self-vote or a vote delivered from a participant. -/
theorem campaign_subset {index : Nat} {step : Execution.Step W Liveness.Event}
    {action : Model.Action} {rest : History}
    (ctx : Ctx nodes (proto step.after) (proto step.before) rest)
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (early : time step.before < time origin + E / 2)
    (selected : step.action.action = some action)
    (acts : StablePrimary.Acts action ctx.actor ctx.event)
    (member : ctx.actor ∈ participants) {candidate : NodeState}
    (campaign : Campaign ctx.actor ctx.pre ctx.event candidate)
    (termEq : candidate.currentTerm = term + 1)
    (old
      : ctx.pre.role = .candidate
        -> ctx.pre.currentTerm = term + 1
        -> ctx.pre.votesGranted ⊆ participants)
    : candidate.votesGranted ⊆ participants := by
  obtain ⟨_, _, _, ⟨_, _, _, votes, _⟩ | ⟨role, same, _, votes⟩⟩ := campaign
  · simpa [votes] using member
  · intro voter voterIn
    rcases votes voter voterIn with prior | ⟨response, eventEq, _, _⟩
    · exact old role (same ▸ termEq) prior
    · obtain ⟨e, actionEq, targetEq, sourceEq, _⟩ := acts_receive acts eventEq
      subst action
      exact sourceEq ▸ setup.period.isolated index step e
        (within setup originFound le (setup.admissible.before stepped) early.le)
        stepped (delivered_of_action selected) (targetEq ▸ member)

/-- Every vote counted by a participant's new-term candidacy is from the period. -/
theorem candidate_subset
    : forall index point node state,
        c <= index
        -> trace.stateAt index = some point
        -> time point < time origin + E / 2
        -> node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1
        -> state.role = .candidate
        -> state.votesGranted ⊆ participants := by
  intro index
  induction index with
  | zero =>
      intro point node state le found _ member nodeFound termEq _
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
        exact campaign_subset setup originFound ctx (by omega) stepped earlyBefore
          selected acts member (CCFRaft.Proofs.Safety.Summary.candidate ctx.sum role)
          termEq (fun role termEq => ih step.before ctx.actor ctx.pre (by omega)
            beforeFound earlyBefore member ctx.tr.found termEq role)
      · exact ih step.before node state (by omega) beforeFound earlyBefore member
          (found_of_now ctx.prior previous) termEq role

/-- An early primary has a first winning step after the round start. -/
theorem first_win {index : Nat} {point : W} {leader : NodeID} {state : NodeState}
    (le : c <= index) (found : trace.stateAt index = some point)
    (member : leader ∈ participants)
    (leaderFound : nodeState (proto point) leader = some state)
    (primary : state.role = .primary) (termEq : state.currentTerm = term + 1)
    : exists win step action rest,
    exists ctx : Ctx nodes (proto step.after) (proto step.before) rest,
      c <= win
      /\ win < index
      /\ trace.stepAt win = some step
      /\ step.action.action = some action
      /\ StablePrimary.Acts action ctx.actor ctx.event
      /\ outgoing (proto step.before) action = some ctx.tr.outputs.outgoing
      /\ ctx.actor = leader
      /\ ctx.post.role = .primary
      /\ ctx.post.currentTerm = term + 1
      /\ Not (ctx.pre.role = .primary /\ ctx.pre.currentTerm = term + 1)
      /\ Wins ctx.actor ctx.pre ctx.event ctx.post := by
  classical
  let Leads (i : Nat) := exists p s, trace.stateAt i = some p
    /\ nodeState (proto p) leader = some s /\ s.role = .primary
    /\ s.currentTerm = term + 1
  have initially : Not (Leads c) := by
    rintro ⟨p, s, f, nf, _, te⟩
    have low := setup.round.low p leader s f member nf
    omega
  have atEnd : Not (Not (Leads index)) :=
    fun h => h ⟨point, state, found, leaderFound, primary, termEq⟩
  obtain ⟨win, after, before, notLed, led⟩ :=
    CCFRaft.Proofs.Liveness.exists_exit (holds := fun i => Not (Leads i)) le initially atEnd
  have led : Leads (win + 1) := Classical.not_not.mp led
  obtain ⟨p, s, pf, sf, role, te⟩ := led
  obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp pf
  have beforeFound := setup.admissible.before stepped
  rcases selected : step.action.action with _ | action
  · rw [setup.admissible.stutter stepped selected] at sf
    exact (notLed ⟨step.before, s, beforeFound, sf, role, te⟩).elim
  obtain ⟨rest, ctx, acts, out⟩ := ctx_at setup.admissible stepped selected
  rcases ctx.now_after (now_of_found (rest := proto step.before :: rest) sf)
    with ⟨actorEq, postEq⟩ | ⟨_, previous⟩
  · subst leader s
    have notPrimary : Not (ctx.pre.role = .primary /\ ctx.pre.currentTerm = term + 1) :=
      fun h => notLed ⟨step.before, ctx.pre, beforeFound, ctx.tr.found, h⟩
    refine ⟨win, step, action, rest, ctx, after, before, stepped, selected, acts, out,
      rfl, role, te, notPrimary, ?_⟩
    rcases CCFRaft.Proofs.Safety.Summary.leader ctx.sum role with old | won
    · exact (notPrimary ⟨old.1, old.2 ▸ te⟩).elim
    · exact won
  · exact (notLed ⟨step.before, s, beforeFound, found_of_now ctx.prior previous,
      role, te⟩).elim

end CCFRaft.Proofs.Duel.Elected
