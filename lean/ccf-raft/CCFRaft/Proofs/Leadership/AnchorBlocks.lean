module

public import CCFRaft.Proofs.Leadership.AnchorKeep

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# One step keeps every countable quorum blocked

`Blocks` is kept by a step among participants. A step writes a configuration into
its actor's log only from an AppendEntries it receives, at the index the request
places it, so a configuration above a threshold in a participant's log was above
it in the sender's log or in the request. A new AppendEntries carries entries of
its sender's log at their indices. A configuration becomes active at the actor
only above its old commit index, or it was active before.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety

/-! ## Configurations by entry -/

/-- A configuration of a log is a configuration entry at its index. -/
theorem mem_history_iff {log : List Entry} {configuration : Configuration}
    : configuration ∈ configurationHistory log
      <-> exists i entry,
            log[i]? = some entry
            /\ entry.content.metadata.configuration = some configuration.nodes
            /\ configuration.index = i + 1 := by
  unfold configurationHistory
  rw [List.mem_filterMap]
  constructor
  · rintro ⟨⟨entry, index⟩, member, eq⟩
    obtain ⟨nodes, some, rfl⟩ := Option.map_eq_some_iff.mp eq
    obtain ⟨le, get⟩ := List.mem_zipIdx_iff_le_and_getElem?_sub.mp member
    refine ⟨index - 1, entry, by simpa using get, some, ?_⟩
    dsimp only at le ⊢
    omega
  · rintro ⟨i, entry, get, some, indexEq⟩
    refine ⟨(entry, i + 1),
      List.mem_zipIdx_iff_le_and_getElem?_sub.mpr ⟨by omega, by simpa using get⟩, ?_⟩
    obtain ⟨index, nodes⟩ := configuration
    dsimp only at some indexEq ⊢
    rw [some, indexEq]
    rfl

theorem getElem?_of_prefix {α : Type} {small large : List α} (sub : small <+: large)
    {i : Nat} {a : α} (found : small[i]? = some a)
    : large[i]? = some a := by
  obtain ⟨tail, rfl⟩ := sub
  rw [List.getElem?_append_left (List.getElem?_eq_some_iff.mp found).1]
  exact found

/-- A configuration of a log's prefix is one of the log. -/
theorem history_of_prefix {small large : List Entry} (sub : small <+: large)
    {configuration : Configuration} (member : configuration ∈ configurationHistory small)
    : configuration ∈ configurationHistory large := by
  obtain ⟨i, entry, get, some, indexEq⟩ := mem_history_iff.mp member
  exact mem_history_iff.mpr ⟨i, entry, getElem?_of_prefix sub get, some, indexEq⟩

/-- A configuration of entries placed after `offset` in a log is one of the log,
at its index shifted by `offset`. -/
theorem history_of_entries {log entries : List Entry} {offset : Nat}
    (sub : entries <+: log.drop offset) {configuration : Configuration}
    (member : configuration ∈ configurationHistory entries)
    : exists placed,
        placed ∈ configurationHistory log
        /\ placed.nodes = configuration.nodes
        /\ placed.index = offset + configuration.index := by
  obtain ⟨i, entry, get, some, indexEq⟩ := mem_history_iff.mp member
  have found := getElem?_of_prefix sub get
  rw [List.getElem?_drop] at found
  refine ⟨{ index := offset + i + 1, nodes := configuration.nodes },
    mem_history_iff.mpr ⟨offset + i, entry, found, some, rfl⟩, rfl, ?_⟩
  dsimp only
  omega

/-- A configuration active in a log that agrees with another up to `k`, at a
commit index of at least `k`, lies above `k` or is active in the other at `k`. -/
theorem active_cases {log log' : List Entry} {k k' : Nat} (le : k <= k')
    (agree : log'.take k = log.take k) {configuration : Configuration}
    (member : configuration ∈ activeConfigurations log' k')
    : k < configuration.index \/ configuration ∈ activeConfigurations log k := by
  by_cases high : k < configuration.index
  · exact Or.inl high
  refine Or.inr ?_
  obtain ⟨later', eq', above'⟩ := configurationHistory_split log' k
  obtain ⟨later, eq, above⟩ := configurationHistory_split log k
  rw [agree] at eq'
  have small
      : forall other, other ∈ configurationHistory (log.take k) -> other.index <= k := by
    intro other otherIn
    have := configurationHistory_index_le _ otherIn
    rw [List.length_take] at this
    omega
  have committed
      : forall rest : List Configuration,
          (forall other, other ∈ rest -> k < other.index)
          -> ((configurationHistory (log.take k) ++ rest).filter
                fun other => other.index <= k)
              = configurationHistory (log.take k) := by
    intro rest above
    rw [filter_index_append le_rfl above]
    exact List.filter_eq_self.mpr fun other otherIn => by simpa using small other otherIn
  unfold activeConfigurations at member ⊢
  dsimp only at member ⊢
  rw [eq'] at member
  rw [eq, committed later above]
  have mono := length_filter_index_mono (configurationHistory (log.take k) ++ later') le
  rw [committed later' above'] at mono
  generalize configurationHistory (log.take k) = front at member mono small ⊢
  generalize ((front ++ later').filter fun other => other.index <= k').length = many
    at member mono
  rw [List.drop_append, List.mem_append] at member
  rw [List.drop_append, List.mem_append]
  rcases member with inFront | inLater
  · refine Or.inl ?_
    have split : front.drop (many - 1)
        = (front.drop (front.length - 1)).drop (many - 1 - (front.length - 1)) := by
      rw [List.drop_drop]
      congr 1
      omega
    rw [split] at inFront
    exact List.mem_of_mem_drop inFront
  · exact absurd (above' _ (List.mem_of_mem_drop inLater)) high

/-! ## Where a step's entries come from -/

theorem conflictIndex_ge {log : List Entry} {request : AppendEntriesRequest} {index : Nat}
    (eq : conflictIndex log request = some index)
    : request.prevLogIndex + 1 <= index := by
  unfold conflictIndex at eq
  obtain ⟨⟨pair, position⟩, found, rfl⟩ := Option.map_eq_some_iff.mp eq
  exact (List.mem_zipIdx (List.mem_of_find?_eq_some found)).1

/-- An entry of an accepted log is the follower's, or the request's at its index. -/
theorem acceptLog_source {log : List Entry} {request : AppendEntriesRequest}
    (prev : request.prevLogIndex <= log.length) {i : Nat} {entry : Entry}
    (found : (acceptLog log request)[i]? = some entry)
    : log[i]? = some entry
      \/ (request.prevLogIndex <= i
          /\ request.entries[i - request.prevLogIndex]? = some entry) := by
  obtain ⟨kept, eq, sub, keptLe⟩
      : exists kept : List Entry,
          acceptLog log request
            = kept ++ request.entries.drop (kept.length - request.prevLogIndex)
          /\ kept <+: log /\ request.prevLogIndex <= kept.length := by
    unfold acceptLog
    cases h : conflictIndex log request with
    | none => exact ⟨log, rfl, List.prefix_refl _, prev⟩
    | some index =>
        have := conflictIndex_ge h
        refine ⟨log.take (index - 1), rfl, List.take_prefix _ _, ?_⟩
        rw [List.length_take]
        omega
  rw [eq] at found
  have facts : kept <+: log /\ request.prevLogIndex <= kept.length := ⟨sub, keptLe⟩
  by_cases inKept : i < kept.length
  · rw [List.getElem?_append_left inKept] at found
    exact Or.inl (getElem?_of_prefix facts.1 found)
  · rw [List.getElem?_append_right (by omega), List.getElem?_drop] at found
    refine Or.inr ⟨by omega, ?_⟩
    rw [← found]
    congr 1
    omega

section Handlers

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

/-- Receiving AppendEntries runs `AEStep` on a state with the receiver's log. -/
theorem receive_ae_any (source : NodeID) (before : NodeState)
    (request : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          exists aware : NodeState,
            aware.log = before.log
            /\ AEStep self source (awareState aware request) request after sent)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  have le : request.term
      <= (observeTerm before (.appendEntriesRequest request)).currentTerm := by
    rcases observe_bumping before (message := .appendEntriesRequest request) trivial
      with ⟨_, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
    · simp [bumpedState, Message.term]
    · exact le
  exact Sends.mono (aeStep self source _ request le) fun _ _ step =>
    ⟨_, Concrete.observeTerm_log _ _, step⟩

end Handlers

variable [Config.InitialConfiguration]

section Step

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest)

/-- A configuration entry in the actor's log after a step was there before, or
comes from a received AppendEntries at its index, when the step appends no
configuration. -/
theorem log_source
    (plain
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content, content ∈ contents -> content.metadata.configuration = none)
    {i : Nat} {entry : Entry} (found : c.post.log[i]? = some entry)
    (configured : entry.content.metadata.configuration.isSome)
    : c.pre.log[i]? = some entry
      \/ exists source request,
          c.event = .receive source (.appendEntriesRequest request)
          /\ request.prevLogIndex <= i
          /\ request.entries[i - request.prevLogIndex]? = some entry := by
  have prefixed : c.post.log <+: c.pre.log -> c.pre.log[i]? = some entry := fun sub =>
    getElem?_of_prefix sub found
  have ran := c.tr.ran
  have elect : Wins c.actor c.pre c.event c.post -> c.pre.log[i]? = some entry :=
    fun wins => by
      obtain ⟨candidate, campaign, _, logEq, _⟩ := Wins.facts wins
      refine prefixed ?_
      rw [logEq, ← campaign.2.1]
      exact primaryState_log_prefix candidate
  cases eventEq : c.tr.event with
  | internal input =>
      rw [eventEq] at ran
      by_cases appending : exists contents, input = .append contents
      · obtain ⟨contents, rfl⟩ := appending
        obtain ⟨log, _⟩ := CommitLiveness.append_log c.tr.actor c.tr.pre contents _ _ _ ran
        have log' : c.post.log = c.pre.log ++ CommitLiveness.appended c.pre.currentTerm contents :=
          log
        rw [log'] at found
        by_cases inPre : i < c.pre.log.length
        · rw [List.getElem?_append_left inPre] at found
          exact Or.inl found
        · rw [List.getElem?_append_right (by omega)] at found
          obtain ⟨content, contentIn, rfl⟩ :=
            List.mem_map.mp (List.mem_of_getElem? found)
          have := plain contents eventEq content contentIn
          simp [this] at configured
      · refine Or.inl ?_
        cases Summary.kind c.sum with
        | same log _ => exact prefixed (log ▸ List.prefix_refl _)
        | append _ _ primary _ _ _ =>
            have kept := act_log c.tr.actor c.tr.pre input primary
              (fun contents eq => appending ⟨contents, eq⟩) _ _ _ ran
            exact prefixed (kept ▸ List.prefix_refl _)
        | ack _ _ received _ _ _ _ =>
            have := eventEq.symm.trans received
            cases this
        | accept _ _ received _ =>
            have := eventEq.symm.trans received
            cases this
        | elect wins => exact elect wins
  | receive source message =>
      rw [eventEq] at ran
      by_cases isRequest : exists request, message = .appendEntriesRequest request
      · obtain ⟨request, rfl⟩ := isRequest
        simp only [Model.Node.step] at ran
        obtain ⟨_, _, aware, awareLog, step⟩ :=
          receive_ae_any c.tr.actor source c.tr.pre request _ _ _ ran
        have log' := awareState_log aware request
        rw [awareLog] at log'
        rcases step with ⟨_, postEq, _⟩ | ⟨_, _, _, postEq, _⟩
            | ⟨_, matches_, _, _, _, _, logEq, _⟩
        · refine Or.inl (prefixed ?_)
          show c.tr.post.log <+: _
          rw [postEq, log']
        · refine Or.inl (prefixed ?_)
          show c.tr.post.log <+: _
          rw [postEq]
          exact log' ▸ List.prefix_refl _
        · have prev : request.prevLogIndex <= c.pre.log.length := by
            have := matches_.1
            rw [log'] at this
            exact this
          have found' : (acceptLog c.pre.log request)[i]? = some entry := by
            have : c.tr.post.log = acceptLog c.tr.pre.log request := by rw [logEq, log']
            rw [← this]
            exact found
          rcases acceptLog_source prev found' with old | ⟨le, get⟩
          · exact Or.inl old
          · exact Or.inr ⟨source, request, eventEq, le, get⟩
      · refine Or.inl ?_
        cases Summary.kind c.sum with
        | same log _ => exact prefixed (log ▸ List.prefix_refl _)
        | append _ _ primary _ _ _ =>
            simp only [Model.Node.step] at ran
            have kept := receive_log c.tr.actor c.tr.pre source message primary
              (fun request eq => (isRequest ⟨request, eq⟩).elim) _ _ _ ran
            exact prefixed (kept ▸ List.prefix_refl _)
        | ack _ _ _ _ _ _ advance =>
            exact prefixed (Advance.log advance ▸ List.prefix_refl _)
        | accept _ request received _ =>
            have := eventEq.symm.trans received
            simp only [Event.receive.injEq] at this
            exact (isRequest ⟨request, this.2⟩).elim
        | elect wins => exact elect wins

/-- Clauses two and three of `Configured` for the threshold `k`. -/
def AboveConfigured (P : Finset NodeID -> Prop) (participants : Finset NodeID) (k : Nat)
    (state : Model.State)
    : Prop :=
  (forall holder held,
    (holder, held) ∈ state.nodes
    -> holder ∈ participants
    -> forall configuration,
        configuration ∈ configurationHistory held.log
        -> k < configuration.index
        -> P configuration.nodes)
  /\ (forall envelope request,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> envelope.payload = .appendEntriesRequest request
        -> forall configuration,
            configuration ∈ configurationHistory request.entries
            -> k < request.prevLogIndex + configuration.index
            -> P configuration.nodes)

theorem AboveConfigured.mono {P : Finset NodeID -> Prop} {participants : Finset NodeID}
    {k k' : Nat} {state : Model.State} (above : AboveConfigured P participants k state)
    (le : k <= k')
    : AboveConfigured P participants k' state :=
  ⟨
    fun holder held now holderIn configuration member high =>
      above.1 holder held now holderIn configuration member (by omega),
    fun envelope request queued sourceIn targetIn payload configuration member high =>
      above.2 envelope request queued sourceIn targetIn payload configuration member
        (by omega)
  ⟩

variable {P : Finset NodeID -> Prop} {participants : Finset NodeID}
  (isolated
    : c.actor ∈ participants
      -> forall source message,
          c.event = .receive source message -> source ∈ participants)
  (plain
    : forall contents,
        c.event = .internal (.append contents)
        -> forall content, content ∈ contents -> content.metadata.configuration = none)

include isolated plain

/-- A step among participants keeps every configuration above `k` satisfying `P`. -/
theorem AboveConfigured.step {k : Nat} (above : AboveConfigured P participants k before)
    : AboveConfigured P participants k after := by
  have held
      : forall holder held,
          (holder, held) ∈ after.nodes
          -> holder ∈ participants
          -> forall configuration,
              configuration ∈ configurationHistory held.log
              -> k < configuration.index
              -> P configuration.nodes := by
    intro holder held now holderIn configuration member high
    rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · have actorIn : c.actor ∈ participants := same ▸ holderIn
      obtain ⟨i, entry, get, some, indexEq⟩ := mem_history_iff.mp member
      rcases log_source c plain get (by simp [some])
          with old | ⟨source, request, eventEq, le, get'⟩
      · exact above.1 c.actor c.pre c.pre_now actorIn configuration
          (mem_history_iff.mpr ⟨i, entry, old, some, indexEq⟩) high
      · obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eventEq
        exact above.2 envelope request pending (sourceEq ▸ isolated actorIn _ _ eventEq)
          (targetEq ▸ actorIn) payload
          { index := i - request.prevLogIndex + 1, nodes := configuration.nodes }
          (mem_history_iff.mpr ⟨i - request.prevLogIndex, entry, get', some, rfl⟩)
          (by dsimp only; omega)
    · exact above.1 holder held old holderIn configuration member high
  refine ⟨held, fun envelope request queued sourceIn targetIn payload configuration member
    high => ?_⟩
  rcases c.tr.mem_network queued with old | new
  · exact above.2 envelope request old sourceIn targetIn payload configuration member high
  · obtain ⟨sourceEq, ok⟩ := Summary.sends c.sum envelope new
    simp only [payload] at ok
    obtain ⟨placed, placedIn, nodesEq, indexEq⟩ := history_of_entries ok.1.2.2.2.2.1 member
    rw [← nodesEq]
    exact held c.actor c.post c.post_now (sourceEq ▸ sourceIn) placed placedIn (by omega)

/-- A step among participants keeps every configuration they can count votes in
satisfying `P`, when it appends no configuration. -/
theorem Configured.step (blocks : Configured P participants before)
    : Configured P participants after := by
  intro node local_ now nodeIn
  rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
  · have actorIn : c.actor ∈ participants := same ▸ nodeIn
    obtain ⟨active, above, sent⟩ := blocks c.actor c.pre c.pre_now actorIn
    have aboveAfter := AboveConfigured.step c isolated plain (k := c.pre.commitIndex)
      ⟨above, sent⟩
    have extends_ := CCFRaft.Proofs.Direct.extends_step c.tr.ran
    have commitLe : c.pre.commitIndex <= c.post.commitIndex := extends_.1
    have mono := aboveAfter.mono commitLe
    refine ⟨fun configuration member => ?_, mono.1, mono.2⟩
    have agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex := by
      have frontier := c.frontier_pre
      have sub : c.pre.log.take c.pre.commitIndex <+: c.post.log := extends_.2
      rw [take_eq_of_prefix sub (by rw [List.length_take]; omega), List.take_take,
        Nat.min_self]
    rcases active_cases commitLe agree member with high | old
    · exact aboveAfter.1 c.actor c.post c.post_now actorIn configuration
        ((activeConfigurations_sublist _ _).subset member) high
    · exact active configuration old
  · obtain ⟨active, above, sent⟩ := blocks node local_ old nodeIn
    have aboveAfter := AboveConfigured.step c isolated plain (k := local_.commitIndex)
      ⟨above, sent⟩
    exact ⟨active, aboveAfter.1, aboveAfter.2⟩

/-- A step among participants keeps every quorum they can count blocked by the
anchor, when it appends no configuration. -/
theorem Blocks.step {anchor : Finset NodeID} (blocks : Blocks participants anchor before)
    : Blocks participants anchor after :=
  Configured.step c isolated plain blocks

end Step

end CCFRaft.Proofs.Leadership
