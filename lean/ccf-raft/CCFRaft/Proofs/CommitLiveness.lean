module

public import CCFRaft.Proofs.Liveness
public import CCFRaft.Proofs.Safety.Commit

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Commit liveness from signature commitment

Reduces `Properties.commit_liveness` to a single replication obligation
(`request_committed`): a stable primary's current-term signature is eventually
committed.
The reduction reuses the safety invariant, so a primary keeps its log
for as long as it stays primary in the same term.
-/

namespace CCFRaft.Proofs.CommitLiveness

open CCFRaft.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Direct (Keeps)
open HasProtocol (proto)

/-! ## Protocol steps -/

section Steps

variable [Config.InitialConfiguration]

/-- A node that is primary in the same term at both ends keeps its earlier log. -/
theorem primary_log_prefix {nodes : List NodeID} {history history' : List Model.State}
    {before after : Model.State}
    (exec : Exec nodes (before :: history)) (exec' : Exec nodes (after :: history'))
    (suffix : (before :: history) <:+ (after :: history'))
    {leader : NodeID} {old new : NodeState}
    (oldFound : nodeState before leader = some old)
    (newFound : nodeState after leader = some new)
    (oldPrimary : old.role = .primary) (newPrimary : new.role = .primary)
    (sameTerm : old.currentTerm = new.currentTerm)
    : old.log <+: new.log := by
  have inv := good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have inv' := good_of_exec exec' _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have oldNow : Now (before :: history) leader old := Concrete.mem_of_nodeState oldFound
  have newNow : Now (after :: history') leader new := Concrete.mem_of_nodeState newFound
  have canon : Canon (before :: history) old.currentTerm old.log :=
    ⟨_, List.suffix_refl _, leader, old,
      ⟨oldNow, rfl, by rw [oldPrimary]; decide,
        inv.leader_led leader old oldNow oldPrimary⟩, rfl⟩
  have led := inv'.leader_led leader new newNow newPrimary
  exact (inv'.canon_mono leader new newNow (by rw [newPrimary]; decide) led).1 _
    (sameTerm ▸ canon.mono suffix)

/-- The actor of a local step is found afterwards with its new state. -/
theorem local_step_found {nodes : List NodeID} {before after : Model.State}
    {node : NodeID} {input : Input}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable before)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.local node input)
        = some after)
    : exists state next outputs,
        nodeState before node = some state
        /\ (act (Capabilities.record node) node state input).run {} = some (next, outputs)
        /\ nodeState after node = some next := by
  have distinct := Direct.keys_nodup (TransitionSystem.Reachable.step reachable stepped)
  obtain ⟨state, next, outputs, found, ran, rfl⟩ := Concrete.step_local stepped
  refine ⟨state, next, outputs, found, ran, Direct.nodeState_of_mem distinct ?_⟩
  exact List.mem_map.mpr ⟨(node, state), Concrete.mem_of_nodeState found, by simp⟩

end Steps

/-! ## Appending entries -/

section Append

variable (caps : Caps) (self : NodeID)

theorem appendEntry_log (state : NodeState) (content : EntryContent)
    : Keeps
        (fun after =>
          after.log = state.log ++ [{ term := state.currentTerm, content }]
          /\ after.currentTerm = state.currentTerm)
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ⟨rfl, rfl⟩
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

end Append

/-- Entries appended at the current term, in order. -/
abbrev appended (term : Nat) (contents : List EntryContent) : List Entry :=
  contents.map fun content => { term, content }

theorem foldAppend_log (self : NodeID)
    : forall (contents : List EntryContent) (state : NodeState),
        Keeps
          (fun after =>
            after.log = state.log ++ appended state.currentTerm contents
            /\ after.currentTerm = state.currentTerm)
          (contents.foldlM (appendEntry (Capabilities.record self) self) state)
  | [], state => by
      simp only [List.foldlM_nil]
      exact Keeps.pure' ⟨by simp, rfl⟩
  | content :: rest, state => by
      simp only [List.foldlM_cons]
      exact Keeps.bind' (appendEntry_log _ self state content) fun middle ⟨log, term⟩ =>
        (foldAppend_log self rest middle).mono fun _ ⟨log', term'⟩ =>
          ⟨by rw [log', log, term]; simp, term'.trans term⟩

/-- Commit advancement never touches the log or the term. -/
theorem advanceCommit_log (self : NodeID) (state : NodeState)
    : Keeps (fun after => after.log = state.log /\ after.currentTerm = state.currentTerm)
        (advanceCommit (Capabilities.record self) state self) := by
  intro outputs result after ran
  obtain ⟨_, _, advance, _⟩ := advanceCommit_sends self state outputs result after ran
  rcases advance with ⟨rfl, _⟩ | ⟨log, term, _⟩
  · exact ⟨rfl, rfl⟩
  · exact ⟨log, term⟩

theorem append_log (self : NodeID) (state : NodeState) (contents : List EntryContent)
    : Keeps
        (fun after =>
          after.log = state.log ++ appended state.currentTerm contents
          /\ after.currentTerm = state.currentTerm)
        (act (Capabilities.record self) self state (.append contents)) := by
  unfold act appendBatch
  refine Keeps.seq' fun _ => ?_
  exact Keeps.bind' (foldAppend_log self contents state) fun middle ⟨log, term⟩ =>
    (advanceCommit_log self middle).mono fun _ ⟨log', term'⟩ =>
      ⟨log'.trans log, term'.trans term⟩

theorem entryAt_appended (log : List Entry) (term : Nat) (contents : List EntryContent)
    (position : Nat) (within : position < contents.length)
    : entryAt? (log ++ appended term contents) (log.length + position + 1)
      = some { term, content := contents[position] } := by
  simp [entryAt?, within]

/-! ## Reaching a covering signature -/

section Recorded

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event}

/-- With no signature due, a stable primary's whole log is covered by its latest
signature, which is from the current term. -/
theorem signed_of_not_due {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} {point : W}
    (le : start <= index) (found : trace.stateAt index = some point) {state : NodeState}
    (nodeFound : nodeState (proto point) leader = some state)
    (notDue : Not (SignatureDue point leader))
    (nonempty : Not (state.log = []))
    : isSignatureAt state.log state.log.length = true
      /\ termAt state.log state.log.length = term := by
  obtain ⟨live, state', nodeFound', primary, currentTerm, active⟩ := stable.leads le found
  rw [nodeFound, Option.some.injEq] at nodeFound'
  subst nodeFound'
  have covered : maxCommittableIndex state.log = state.log.length
      /\ maxCommittableTerm state.log = term := by
    by_contra uncovered
    have bounded := Ledger.maxCommittableIndexBounded state.log
    exact notDue ⟨live, state, nodeFound, primary, active, by grind⟩
  have positive : 0 < maxCommittableIndex state.log := by
    rw [covered.1]; exact List.length_pos_iff.mpr nonempty
  have signature := Ledger.maxCommittableIndexPositiveIsSignature positive
  rw [covered.1] at signature
  refine ⟨signature, ?_⟩
  have := covered.2
  unfold maxCommittableTerm at this
  rwa [covered.1] at this

variable [Config.InitialConfiguration] {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Environment-only events leave the history unchanged; protocol events extend it. -/
theorem history_extends {index later : Nat} (le : index <= later) {first last : W}
    (firstFound : trace.stateAt index = some first)
    (lastFound : trace.stateAt later = some last) {history : List Model.State}
    (exec : Exec nodes (proto first :: history))
    : exists history',
        Exec nodes (proto last :: history')
        /\ (proto first :: history) <:+ (proto last :: history') :=
  admissible.coherent.induction
    (start := index)
    (motive :=
      fun _ point =>
        exists history',
          Exec nodes (proto point :: history')
          /\ (proto first :: history) <:+ (proto point :: history'))
    (fun point found => by
      rw [firstFound, Option.some.injEq] at found
      subst found
      exact ⟨history, exec, List.suffix_refl _⟩)
    (fun _ step _ stepped ⟨history', exec', suffix⟩ => by
      cases selected : step.action.action with
      | none =>
          rw [admissible.stutter stepped selected]
          exact ⟨history', exec', suffix⟩
      | some action =>
          exact ⟨_, .step exec' (admissible.step stepped selected),
            suffix.trans (List.suffix_cons _ _)⟩)
    later last le lastFound

/-- A stable primary keeps every entry it ever had while it leads. -/
theorem stable_log_prefix {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index later : Nat}
    (afterStart : start <= index) (le : index <= later) {old new : NodeState}
    (oldFound : trace.nodeAt index leader = some old)
    (newFound : trace.nodeAt later leader = some new)
    : old.log <+: new.log := by
  obtain ⟨first, firstFound, oldFound'⟩ := Trace.nodeAt_eq_some.mp oldFound
  obtain ⟨last, lastFound, newFound'⟩ := Trace.nodeAt_eq_some.mp newFound
  obtain ⟨history, exec⟩ := exec_of_reachable (admissible.reachable firstFound)
  obtain ⟨history', exec', suffix⟩ := history_extends admissible le firstFound lastFound exec
  have laterStart := Nat.le_trans afterStart le
  exact primary_log_prefix exec exec' suffix oldFound' newFound'
    (stable.primary afterStart oldFound) (stable.primary laterStart newFound)
    ((stable.current afterStart oldFound).trans (stable.current laterStart newFound).symm)

/-- After a signing append the primary's log has a current-term signature past its
previous end. -/
theorem signs_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader : NodeID}
    (signs : Signs step leader)
    : exists before after signature,
        trace.nodeAt index leader = some before
        /\ trace.nodeAt (index + 1) leader = some after
        /\ before.log.length < signature
        /\ isSignatureAt after.log signature = true
        /\ termAt after.log signature = before.currentTerm := by
  obtain ⟨entries, action, member⟩ := signs
  obtain ⟨before, after, _, found, ran, found'⟩ :=
    local_step_found (admissible.reachable_before stepped)
      (admissible.step stepped (by rw [action]; rfl))
  obtain ⟨log, _⟩ := append_log leader before entries _ _ _ ran
  obtain ⟨position, within, signature⟩ := List.mem_iff_getElem.mp member
  have entry := entryAt_appended before.log before.currentTerm entries position within
  refine ⟨
    before,
    after,
    before.log.length + position + 1,
    by rw [Trace.nodeAt_of_stateAt (admissible.before stepped), found],
    by rw [Trace.nodeAt_of_stateAt (Trace.stateAt_succ_of_stepAt stepped), found'],
    by omega,
    ?_,
    ?_
  ⟩
  · simp [isSignatureAt, log, entry, signature, EntryContent.isSignature]
  · simp [termAt, log, entry]

/-- Any entry of a stable primary's log is eventually followed by a current-term
signature, either already there or appended by the signature task. -/
theorem covering_signature {bound : Option Real}
    (signing : trace.SignatureScheduling bound) {start : Nat} {leader : NodeID}
    {term : Nat} (stable : StableLeader trace start leader term) {index : Nat}
    (afterStart : start <= index) {state : NodeState}
    (found : trace.nodeAt index leader = some state) {position : Nat}
    (within : position < state.log.length)
    : exists later after signature,
        index <= later
        /\ trace.nodeAt later leader = some after
        /\ position < signature
        /\ isSignatureAt after.log signature = true
        /\ termAt after.log signature = term := by
  obtain ⟨point, pointFound, nodeFound⟩ := Trace.nodeAt_eq_some.mp found
  have settled : forall later laterPoint after,
      index <= later
      -> trace.stateAt later = some laterPoint
      -> nodeState (proto laterPoint) leader = some after
      -> Not (SignatureDue laterPoint leader)
      -> exists later after signature,
          index <= later
          /\ trace.nodeAt later leader = some after
          /\ position < signature
          /\ isSignatureAt after.log signature = true
          /\ termAt after.log signature = term := by
    intro later laterPoint after le laterFound nodeFound' notDue
    have laterNode : trace.nodeAt later leader = some after := by
      rw [Trace.nodeAt_of_stateAt laterFound, nodeFound']
    have grown := (stable_log_prefix admissible stable afterStart le found laterNode).length_le
    obtain ⟨signature, signatureTerm⟩ :=
      signed_of_not_due stable (Nat.le_trans afterStart le) laterFound nodeFound' notDue
        (List.ne_nil_of_length_pos (by omega))
    exact ⟨later, after, after.log.length, le, laterNode, by omega, signature, signatureTerm⟩
  by_cases due : SignatureDue point leader
  · obtain ⟨later, laterPoint, le, laterFound, _, outcome⟩ :=
      signing leader index point pointFound due
    rcases outcome with notDue | ⟨step, stepped, signs⟩
    · obtain ⟨_, after, nodeFound', _⟩ := stable.leads (Nat.le_trans afterStart le) laterFound
      exact settled later laterPoint after le laterFound nodeFound' notDue
    · obtain ⟨before, after, signature, beforeFound, afterFound, past, isSignature,
          signatureTerm⟩ :=
        signs_step admissible stepped signs
      have grown := (stable_log_prefix admissible stable afterStart le found beforeFound).length_le
      exact ⟨later + 1, after, signature, by omega, afterFound, by omega, isSignature,
        signatureTerm.trans (stable.current (Nat.le_trans afterStart le) beforeFound)⟩
  · exact settled index point state (Nat.le_refl _) pointFound nodeFound due

/-! ## Reaching the request -/

/-- A submitted request reaches the primary's log. -/
theorem request_present {start : Nat} {leader : NodeID} {request : ReqID}
    (submitted : Submitted trace start leader request)
    : exists index state,
        start <= index
        /\ trace.nodeAt index leader = some state
        /\ HasRequest state.log request := by
  obtain ⟨index, point, le, found, ⟨state, nodeFound, present⟩ | ⟨step, entries, stepped,
      action, member⟩⟩ := submitted
  · exact ⟨index, state, le, by rw [Trace.nodeAt_of_stateAt found, nodeFound], present⟩
  · obtain ⟨before, after, _, _, ran, found'⟩ :=
      local_step_found (admissible.reachable_before stepped)
        (admissible.step stepped (by rw [action]; rfl))
    obtain ⟨log, _⟩ := append_log leader before entries _ _ _ ran
    refine ⟨index + 1, after, Nat.le_succ_of_le le,
      by rw [Trace.nodeAt_of_stateAt (Trace.stateAt_succ_of_stepAt stepped), found'],
      { term := before.currentTerm, content := .transaction request {} }, ?_, {}, rfl⟩
    rw [log]
    exact List.mem_append_right _ (List.mem_map.mpr ⟨_, member, rfl⟩)

/-! ## The reduction -/

/-- A submitted request is committed once the stable primary commits each of its
current-term signatures: the request reaches the primary's log, a covering
current-term signature follows, and committing that signature commits the request
because the primary never loses entries while it leads. -/
theorem request_committed {bound : Option Real}
    (signing : trace.SignatureScheduling bound) {start : Nat} {leader : NodeID}
    {term : Nat} {request : ReqID} (stable : StableLeader trace start leader term)
    (submitted : Submitted trace start leader request)
    (commits
      : forall index state signature,
          start <= index
          -> trace.nodeAt index leader = some state
          -> isSignatureAt state.log signature = true
          -> termAt state.log signature = term
          -> exists later after,
              index <= later
              /\ trace.nodeAt later leader = some after
              /\ signature <= after.commitIndex)
    : exists index, RequestCommitted trace leader request index := by
  obtain ⟨index, state, afterStart, found, entry, member, metadata, content⟩ :=
    request_present admissible submitted
  obtain ⟨position, within, entryAt⟩ := List.mem_iff_getElem.mp member
  obtain ⟨signed, signer, signature, le, foundSigned, covers, isSignature, signatureTerm⟩ :=
    covering_signature admissible signing stable afterStart found within
  obtain ⟨later, committer, le', foundLater, committed⟩ :=
    commits signed signer signature (Nat.le_trans afterStart le) foundSigned isSignature
      signatureTerm
  have kept :=
    stable_log_prefix admissible stable afterStart (Nat.le_trans le le') found foundLater
  obtain ⟨point, pointFound, nodeFound⟩ := Trace.nodeAt_eq_some.mp foundLater
  refine ⟨later, point, committer, pointFound, nodeFound, entry, ?_, metadata, content⟩
  have inLater : position < committer.log.length := lt_of_lt_of_le within kept.length_le
  refine List.mem_iff_getElem.mpr ⟨position, ?_, ?_⟩
  · simp only [NodeState.committedLog, List.length_take]
    omega
  · simp only [NodeState.committedLog, List.getElem_take]
    rw [← kept.getElem within]
    exact entryAt

end Recorded

end CCFRaft.Proofs.CommitLiveness
