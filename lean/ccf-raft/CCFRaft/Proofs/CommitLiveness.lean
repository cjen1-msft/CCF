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
open CCFRaft.Proofs.Direct (Keeps)

/-! ## Threading a safety history along a timed execution -/

section History

variable [Config.InitialConfiguration]

/-- Environment-only events leave the history unchanged; protocol events extend it. -/
theorem history_extends {trace : Trace} {nodes : List NodeID}
    (valid : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes) {index : Nat}
    {history : List Model.State} (exec : Exec nodes (trace.state index :: history))
    : forall later,
        index <= later
        -> exists history',
            Exec nodes (trace.state later :: history')
            /\ (trace.state index :: history) <:+ (trace.state later :: history') := by
  intro later le
  induction later, le using Nat.le_induction with
  | base => exact ⟨history, exec, List.suffix_refl _⟩
  | succ later _ ih =>
      obtain ⟨history', exec', suffix⟩ := ih
      cases selected : (trace.event later).action with
      | none =>
          rw [valid.stutter later selected]
          exact ⟨history', exec', suffix⟩
      | some action =>
          exact ⟨_, .step exec' (valid.step later action selected),
            suffix.trans (List.suffix_cons _ _)⟩

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

end History

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

/-! ## Steps of a timed execution -/

section Steps

variable [Config.InitialConfiguration]

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

/-- A stable primary keeps every entry it ever had during the execution. -/
theorem stable_log_prefix {trace : Trace} {nodes : List NodeID}
    (valid : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)
    {leader : NodeID} {term : Nat} (stable : LeadsThroughout trace leader term)
    {index later : Nat} (le : index <= later) {old new : NodeState}
    (oldFound : nodeState (trace.state index) leader = some old)
    (newFound : nodeState (trace.state later) leader = some new)
    : old.log <+: new.log := by
  obtain ⟨history, exec⟩ := exec_of_reachable (CCFRaft.Proofs.Liveness.reachable valid index)
  obtain ⟨history', exec', suffix⟩ := history_extends valid exec later le
  obtain ⟨_, oldState, oldFound', oldPrimary, oldTerm, _⟩ := stable index
  obtain ⟨_, newState, newFound', newPrimary, newTerm, _⟩ := stable later
  rw [oldFound, Option.some.injEq] at oldFound'
  rw [newFound, Option.some.injEq] at newFound'
  subst oldFound' newFound'
  exact primary_log_prefix exec exec' suffix oldFound newFound oldPrimary newPrimary
    (oldTerm.trans newTerm.symm)

/-- After a signing append the primary's log has a current-term signature past its
previous end. -/
theorem signs_step {trace : Trace} {nodes : List NodeID}
    (valid : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)
    {leader : NodeID} {index : Nat} (signs : trace.Signs leader index)
    : exists before after signature,
        nodeState (trace.state index) leader = some before
        /\ nodeState (trace.state (index + 1)) leader = some after
        /\ before.log.length < signature
        /\ isSignatureAt after.log signature = true
        /\ termAt after.log signature = before.currentTerm := by
  obtain ⟨entries, event, member⟩ := signs
  have stepped := valid.step index _ (by rw [event]; rfl)
  obtain ⟨before, after, _, found, ran, found'⟩ :=
    local_step_found (CCFRaft.Proofs.Liveness.reachable valid index) stepped
  obtain ⟨log, _⟩ := append_log leader before entries _ _ _ ran
  obtain ⟨position, within, signature⟩ := List.mem_iff_getElem.mp member
  have entry := entryAt_appended before.log before.currentTerm entries position within
  refine ⟨
    before,
    after,
    before.log.length + position + 1,
    found,
    found',
    by omega,
    ?_,
    ?_
  ⟩
  · simp [isSignatureAt, log, entry, signature, EntryContent.isSignature]
  · simp [termAt, log, entry]

end Steps

/-! ## Reaching a covering signature -/

/-- With no signature due, a stable primary's whole log is covered by its latest
signature, which is from the current term. -/
theorem signed_of_not_due {trace : Trace} {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) {index : Nat} {state : NodeState}
    (found : nodeState (trace.state index) leader = some state)
    (notDue : Not (trace.SignatureDue leader index))
    (nonempty : Not (state.log = []))
    : isSignatureAt state.log state.log.length = true
      /\ termAt state.log state.log.length = term := by
  obtain ⟨live, state', found', primary, currentTerm, active⟩ := stable index
  rw [found, Option.some.injEq] at found'
  subst found'
  have covered : maxCommittableIndex state.log = state.log.length
      /\ maxCommittableTerm state.log = term := by
    by_contra uncovered
    have bounded := Ledger.maxCommittableIndexBounded state.log
    exact notDue ⟨live, state, found, primary, active, by grind⟩
  have positive : 0 < maxCommittableIndex state.log := by
    rw [covered.1]; exact List.length_pos_iff.mpr nonempty
  have signature := Ledger.maxCommittableIndexPositiveIsSignature positive
  rw [covered.1] at signature
  refine ⟨signature, ?_⟩
  have := covered.2
  unfold maxCommittableTerm at this
  rwa [covered.1] at this

/-- Any entry of a stable primary's log is eventually followed by a current-term
signature, either already there or appended within the signature interval. -/
theorem covering_signature (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {term : Nat} (valid : model.FairFrom trace) (stable : LeadsThroughout trace leader term)
    {index : Nat} {state : NodeState}
    (found : nodeState (trace.state index) leader = some state)
    {position : Nat} (within : position < state.log.length)
    : exists later after signature,
        index <= later
        /\ nodeState (trace.state later) leader = some after
        /\ position < signature
        /\ isSignatureAt after.log signature = true
        /\ termAt after.log signature = term := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  have settled : forall later after,
      index <= later
      -> nodeState (trace.state later) leader = some after
      -> Not (trace.SignatureDue leader later)
      -> exists later after signature,
          index <= later
          /\ nodeState (trace.state later) leader = some after
          /\ position < signature
          /\ isSignatureAt after.log signature = true
          /\ termAt after.log signature = term := by
    intro later after le found' notDue
    have grown := (stable_log_prefix execution stable le found found').length_le
    obtain ⟨signature, signatureTerm⟩ :=
      signed_of_not_due stable found' notDue (List.ne_nil_of_length_pos (by omega))
    exact ⟨later, after, after.log.length, le, found', by omega, signature, signatureTerm⟩
  by_cases due : trace.SignatureDue leader index
  · obtain ⟨later, le, notDue | signs⟩ := valid.signatures index leader due
    · obtain ⟨_, after, found', -⟩ := stable later
      exact settled later after le found' notDue
    · obtain ⟨before, after, signature, found', found'', past, isSignature, signatureTerm⟩ :=
        signs_step execution signs
      have grown := (stable_log_prefix execution stable le found found').length_le
      obtain ⟨_, before', foundBefore, _, beforeTerm, _⟩ := stable later
      rw [found', Option.some.injEq] at foundBefore
      subst foundBefore
      exact ⟨later + 1, after, signature, by omega, found'', by omega, isSignature,
        signatureTerm.trans beforeTerm⟩
  · exact settled index state le_rfl found due

/-! ## Reaching the request -/

/-- A submitted request reaches the stable primary's log. -/
theorem request_present (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {request : ReqID} (valid : model.FairFrom trace)
    (submitted : Submitted trace 0 leader request)
    : exists index state,
        nodeState (trace.state index) leader = some state
        /\ HasRequest state.log request := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  obtain ⟨later, _, ⟨state, found', present⟩ | ⟨entries, event, member⟩⟩ := submitted
  · exact ⟨later, state, found', present⟩
  · have stepped := execution.step later _ (by rw [event]; rfl)
    obtain ⟨before, after, _, _, ran, found'⟩ :=
      local_step_found (CCFRaft.Proofs.Liveness.reachable execution later) stepped
    obtain ⟨log, _⟩ := append_log leader before entries _ _ _ ran
    refine ⟨later + 1, after, found',
      { term := before.currentTerm, content := .transaction request {} }, ?_, {}, rfl⟩
    rw [log]
    exact List.mem_append_right _ (List.mem_map.mpr ⟨_, member, rfl⟩)

/-! ## The reduction -/

/-- A submitted request is committed once the stable primary commits each of its
current-term signatures: the request reaches the primary's log, a covering
current-term signature follows, and committing that signature commits the request
because the primary never loses entries while it leads. -/
theorem request_committed (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {term : Nat} {request : ReqID} (valid : model.FairFrom trace)
    (stable : LeadsThroughout trace leader term)
    (submitted : Submitted trace 0 leader request)
    (commits
      : forall index state signature,
          nodeState (trace.state index) leader = some state
          -> isSignatureAt state.log signature = true
          -> termAt state.log signature = term
          -> exists later after,
              index <= later
              /\ nodeState (trace.state later) leader = some after
              /\ signature <= after.commitIndex)
    : exists index, RequestCommitted trace leader request index := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  obtain ⟨index, state, found, entry, member, metadata, content⟩ :=
    request_present model valid submitted
  obtain ⟨position, within, entryAt⟩ := List.mem_iff_getElem.mp member
  obtain ⟨signed, signer, signature, le, foundSigned, covers, isSignature, signatureTerm⟩ :=
    covering_signature model valid stable found within
  obtain ⟨later, committer, le', foundLater, committed⟩ :=
    commits signed signer signature foundSigned isSignature signatureTerm
  have kept := stable_log_prefix execution stable (le.trans le') found foundLater
  refine ⟨later, committer, foundLater, entry, ?_, metadata, content⟩
  have inLater : position < committer.log.length := lt_of_lt_of_le within kept.length_le
  refine List.mem_iff_getElem.mpr ⟨position, ?_, ?_⟩
  · simp only [NodeState.committedLog, List.length_take]
    omega
  · simp only [NodeState.committedLog, List.getElem_take]
    rw [← kept.getElem within]
    exact entryAt

end CCFRaft.Proofs.CommitLiveness
