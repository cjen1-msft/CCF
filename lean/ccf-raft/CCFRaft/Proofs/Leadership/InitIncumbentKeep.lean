module

public import CCFRaft.Proofs.Leadership.InitIncumbentNode
public import CCFRaft.Proofs.Duel.ElectedNet

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Preservation inside an incumbent's capped time window.
-/

namespace CCFRaft.Proofs.Leadership.InitIncumbent

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)
  {start : Nat} {duration : Real} {participants members : Finset NodeID} {term : Nat}

include admissible

/-- A capped primary remains primary in the active, quorum-check-free window. -/
theorem primary_kept
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    {first : W} (firstFound : trace.stateAt start = some first)
    {leader : NodeID} {state : NodeState} (member : leader ∈ participants)
    (nodeFound : nodeState (proto first) leader = some state)
    (stateTerm : state.currentTerm = term) (primary : state.role = .primary)
    {index : Nat} {point : W} (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.currentTerm = term
        /\ state.role = .primary := by
  have keep
      : forall index point,
          start <= index
          -> trace.stateAt index = some point
          -> Within trace start duration index
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary :=
    admissible.coherent.induction
      (start := start)
      (motive :=
        fun index point =>
          Within trace start duration index
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
      (fun point found _ => by
        rw [firstFound, Option.some.injEq] at found
        subst point
        exact ⟨state, nodeFound, stateTerm, primary⟩)
      (fun index step after stepped held within => by
        have beforeWithin := InitRaise.within_before admissible within
          (Trace.stateAt_succ_of_stepAt stepped) after (Nat.le_succ _)
        obtain ⟨pre, preFound, preTerm, preRole⟩ := held beforeWithin
        cases selected : step.action.action with
        | none =>
            exact ⟨
              pre,
              by rw [admissible.stutter stepped selected]; exact preFound,
              preTerm,
              preRole
            ⟩
        | some action =>
            obtain ⟨rest, ctx, acts, _⟩ := ctx_at admissible stepped selected
            by_cases same : leader = ctx.actor
            · subst leader
              have eq := ctx.now_pre (now_of_found preFound)
              subst pre
              have postFound := found_of_now ctx.exec ctx.post_now
              have cap := low (index + 1) within step.after ctx.actor ctx.post
                (Trace.stateAt_succ_of_stepAt stepped) member postFound
              have mono := CCFRaft.Proofs.Safety.Summary.term_le ctx.sum
              have postTerm : ctx.post.currentTerm = term := by omega
              refine ⟨ctx.post, postFound, postTerm, ?_⟩
              rcases CCFRaft.Proofs.Safety.Summary.role_keep ctx.sum preRole
                (postTerm.trans preTerm.symm) with kept | retired | quorum | ⟨source, request, received, rterm⟩
              · exact kept
              · exact (active (index + 1) step.after ctx.actor ctx.post within
                  (Trace.stateAt_succ_of_stepAt stepped) member postFound retired).elim
              · have event := InitRaise.internal_event selected acts quorum
                exact (good.noQuorumChecks index step ctx.actor beforeWithin stepped member event).elim
              · obtain ⟨envelope, pending, _, target, payload⟩ := ctx.received received
                have lead : Lead nodes (proto step.before :: rest) ctx.actor term ctx.pre :=
                  ⟨ctx.prior, ctx.pre_now, preRole, preTerm⟩
                have different := (lead.request pending payload (rterm.trans preTerm)).2.1
                exact (different target).elim
            · exact ⟨pre, found_of_now ctx.exec (ctx.now_other same (now_of_found preFound)),
                preTerm, preRole⟩)
  exact keep index point within.1 found within

/-- A primary of the incumbent term is the incumbent itself. -/
theorem primary_unique {index : Nat} {point : W} {leader node : NodeID}
    {primary state : NodeState} (found : trace.stateAt index = some point)
    (leaderFound : nodeState (proto point) leader = some primary)
    (leaderRole : primary.role = .primary) (leaderTerm : primary.currentTerm = term)
    (nodeFound : nodeState (proto point) node = some state)
    (role : state.role = .primary) (stateTerm : state.currentTerm = term)
    : node = leader := by
  obtain ⟨rest, exec⟩ := history_at admissible found
  have lead : Lead nodes (proto point :: rest) leader term primary :=
    ⟨exec, now_of_found leaderFound, leaderRole, leaderTerm⟩
  have led := lead.inv.leader_led node state (now_of_found nodeFound) role
  rw [stateTerm] at led
  exact lead.unique led

omit admissible in
/-- A non-raising proposal cannot change a node. -/
theorem proposal_same (self source : NodeID) (before : NodeState) (proposed : Nat)
    : Sends (fun after _ => after.currentTerm <= before.currentTerm -> after = before)
        (receive (Capabilities.record self) self source before
          (.proposeRequestVoteRequest proposed)) := by
  change Sends _ (handleProposeRequestVoteRequest (Capabilities.record self) before self proposed)
  unfold handleProposeRequestVoteRequest
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (fun _ => rfl)
  exact Sends.mono (becomeCandidate_kept self before)
    fun _ _ ⟨_, raised⟩ bounded =>
      (by omega)

/-- A current-term follower cannot resume campaigning without timing out. -/
theorem follower_kept
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (roled
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> Not (state.role = .none))
    {leader : NodeID}
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {first index : Nat} {initial point : W} {node : NodeID} {state : NodeState}
    (initialFound : trace.stateAt first = some initial) (member : node ∈ participants)
    (different : Not (node = leader))
    (nodeFound : nodeState (proto initial) node = some state)
    (stateTerm : state.currentTerm = term) (follower : state.role = .follower)
    (lower : start <= first) (later : first <= index)
    (found : trace.stateAt index = some point)
    (within : Within trace start duration index)
    (noTimeout
      : forall i step,
          first <= i
          -> i < index
          -> trace.stepAt i = some step
          -> Not (step.action = .local node (.timeout .election)))
    : exists state,
        nodeState (proto point) node = some state
        /\ state.currentTerm = term
        /\ state.role = .follower := by
  induction index, later using Nat.le_induction generalizing point with
  | base =>
      rw [initialFound, Option.some.injEq] at found
      subst point
      exact ⟨state, nodeFound, stateTerm, follower⟩
  | succ index later ih =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeWithin := InitRaise.within_before admissible within
        (Trace.stateAt_succ_of_stepAt stepped) (by omega) (Nat.le_succ _)
      obtain ⟨pre, preFound, preTerm, preRole⟩ := ih (admissible.before stepped)
        beforeWithin (fun i s lo hi at_ => noTimeout i s lo (by omega) at_)
      cases selected : step.action.action with
      | none =>
          exact ⟨
            pre,
            by rw [admissible.stutter stepped selected]; exact preFound,
            preTerm,
            preRole
          ⟩
      | some action =>
          obtain ⟨rest, ctx, acts, _⟩ := ctx_at admissible stepped selected
          by_cases same : node = ctx.actor
          · subst node
            have eq := ctx.now_pre (now_of_found preFound)
            subst pre
            have postFound := found_of_now ctx.exec ctx.post_now
            have cap := low (index + 1) within step.after ctx.actor ctx.post
              (Trace.stateAt_succ_of_stepAt stepped) member postFound
            have mono := CCFRaft.Proofs.Safety.Summary.term_le ctx.sum
            have postTerm : ctx.post.currentTerm = term := by omega
            refine ⟨ctx.post, postFound, postTerm, ?_⟩
            cases role : ctx.post.role with
            | follower => rfl
            | none =>
                exact (roled (index + 1) step.after ctx.actor ctx.post within
                  (Trace.stateAt_succ_of_stepAt stepped) member postFound role).elim
            | primary =>
                obtain ⟨primary, primaryFound, primaryTerm, primaryRole⟩ :=
                  leads (index + 1) step.after within (Trace.stateAt_succ_of_stepAt stepped)
                exact (different (primary_unique admissible (Trace.stateAt_succ_of_stepAt stepped)
                  primaryFound primaryRole primaryTerm postFound role postTerm)).elim
            | candidate =>
                obtain ⟨_, _, _, ⟨_, raised, _⟩ | ⟨old, _⟩⟩ :=
                  CCFRaft.Proofs.Safety.Summary.candidate ctx.sum role
                · omega
                · rw [preRole] at old; cases old
            | preVoteCandidate =>
                obtain ⟨_, old | timeout⟩ := CCFRaft.Proofs.Safety.Summary.pre_vote ctx.sum role
                · rw [preRole] at old; cases old
                · exact (noTimeout index step later (Nat.lt_succ_self _) stepped
                    (InitRaise.internal_event selected acts timeout)).elim
          · exact ⟨pre, found_of_now ctx.exec (ctx.now_other same (now_of_found preFound)),
              preTerm, preRole⟩

/-- A known follower keeps its knowledge while capped and before its next timeout. -/
theorem settled_kept (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    {first index : Nat} {initial point : W} {node : NodeID} {state : NodeState}
    (initialFound : trace.stateAt first = some initial) (member : node ∈ participants)
    (nodeFound : nodeState (proto initial) node = some state)
    (stateTerm : state.currentTerm = term) (follower : state.role = .follower)
    (known : state.primaryKnown = true) (lower : start <= first) (later : first <= index)
    (found : trace.stateAt index = some point)
    (within : Within trace start duration index)
    (noTimeout
      : forall i step,
          first <= i
          -> i < index
          -> trace.stepAt i = some step
          -> Not (step.action = .local node (.timeout .election)))
    : exists state,
        nodeState (proto point) node = some state
        /\ state.currentTerm = term
        /\ state.role = .follower
        /\ state.primaryKnown = true := by
  induction index, later using Nat.le_induction generalizing point with
  | base =>
      rw [initialFound, Option.some.injEq] at found
      subst point
      exact ⟨state, nodeFound, stateTerm, follower, known⟩
  | succ index later ih =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeWithin := InitRaise.within_before admissible within
        (Trace.stateAt_succ_of_stepAt stepped) (by omega) (Nat.le_succ _)
      obtain ⟨pre, preFound, preTerm, preRole, preKnown⟩ := ih (admissible.before stepped)
        beforeWithin (fun i s lo hi at_ => noTimeout i s lo (by omega) at_)
      cases selected : step.action.action with
      | none =>
          exact ⟨
            pre,
            by rw [admissible.stutter stepped selected]; exact preFound,
            preTerm,
            preRole,
            preKnown
          ⟩
      | some action =>
          obtain ⟨rest, ctx, acts, _⟩ := ctx_at admissible stepped selected
          by_cases same : node = ctx.actor
          · subst node
            have eq := ctx.now_pre (now_of_found preFound)
            subst pre
            have postFound := found_of_now ctx.exec ctx.post_now
            have cap := low (index + 1) within step.after ctx.actor ctx.post
              (Trace.stateAt_succ_of_stepAt stepped) member postFound
            have mono := CCFRaft.Proofs.Safety.Summary.term_le ctx.sum
            have postTerm : ctx.post.currentTerm = term := by omega
            refine ⟨ctx.post, postFound, postTerm, ?_⟩
            rcases (LocalTransition.anchorStep ctx.tr).keep preKnown (Or.inl preRole)
              with (⟨role, known⟩ | retired) | exempt
            · exact ⟨role.trans preRole, known.trans preKnown⟩
            · exact (active (index + 1) step.after ctx.actor ctx.post within
                (Trace.stateAt_succ_of_stepAt stepped) member postFound retired).elim
            · rcases exempt with timeout | quorum | ⟨source, message, received, raised⟩ |
                ⟨source, received⟩
              · exact (noTimeout index step later (Nat.lt_succ_self _) stepped
                  (InitRaise.internal_event selected acts timeout)).elim
              · exact (good.noQuorumChecks index step ctx.actor beforeWithin stepped member
                  (InitRaise.internal_event selected acts quorum)).elim
              · obtain ⟨packet, delivered, target, _, payload⟩ :=
                  InitRaise.received_packet selected acts received
                have queued := admissible.consumed_pending stepped
                  (show step.action.consumedPacket = some packet by rw [delivered]; rfl)
                have sourceIn := good.isolated index step packet.envelope beforeWithin stepped
                  (by rw [delivered]; rfl) (target ▸ member)
                obtain ⟨sender, senderFound, sentLe⟩ := pending_term_le admissible
                  (admissible.before stepped) queued
                have senderLe := low index beforeWithin step.before _ sender
                  (admissible.before stepped) sourceIn senderFound
                rw [payload] at sentLe
                change ctx.pre.currentTerm < message.term at raised
                omega
              · have ran := ctx.tr.ran
                rw [received] at ran
                obtain ⟨_, _, same⟩ :=
                  proposal_same ctx.actor source ctx.pre ctx.pre.currentTerm {} _ _ ran
                change ctx.post.currentTerm <= ctx.pre.currentTerm -> ctx.post = ctx.pre at same
                have eq := same (by omega)
                rw [eq]
                exact ⟨preRole, preKnown⟩
          · exact ⟨pre, found_of_now ctx.exec (ctx.now_other same (now_of_found preFound)),
              preTerm, preRole, preKnown⟩

end CCFRaft.Proofs.Leadership.InitIncumbent
