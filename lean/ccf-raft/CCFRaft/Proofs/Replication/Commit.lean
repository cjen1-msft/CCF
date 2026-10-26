module

public import CCFRaft.Proofs.Replication.Peer
public import CCFRaft.Proofs.Replication.Owing

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Signature commitment

Take a current-term signature covering the requested position.
If it never commits, the active configurations at or before it settle.
Peers of a live quorum in those configurations eventually acknowledge the signature, and another acknowledgement commits it.
If the primary alone covers them, a retirement confirmation is due and its scheduled append commits the signature instead.
The proof uses the original recorded trace and a start index, including when the trace is finite.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)
open HasProtocol (proto)

namespace CCFRaft.Proofs.Replication

theorem mem_configurationMembers {configurations : List Configuration}
    {configuration : Configuration} (member : configuration ∈ configurations)
    {node : NodeID} (inNodes : node ∈ configuration.nodes)
    : node ∈ configurationMembers configurations := by
  unfold configurationMembers
  suffices general
      : forall (acc : Finset NodeID) (configurations : List Configuration),
          (forall other, other ∈ acc
            -> other ∈ configurations.foldl (fun nodes next => nodes ∪ next.nodes) acc)
          /\ (configuration ∈ configurations
            -> node ∈ configurations.foldl (fun nodes next => nodes ∪ next.nodes) acc) from
    (general ∅ configurations).2 member
  intro acc configurations
  induction configurations generalizing acc with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, List.mem_cons]
      refine ⟨fun other inAcc => (ih _).1 _ (Finset.mem_union_left _ inAcc), ?_⟩
      rintro (rfl | inTail)
      · exact (ih _).1 _ (Finset.mem_union_right _ inNodes)
      · exact (ih _).2 inTail

theorem le_length_of_isSignatureAt {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : 0 < index /\ index <= log.length := by
  constructor
  · by_contra zero
    simp [isSignatureAt, entryAt?, show index = 0 by omega] at signature
  · by_contra beyond
    have none : log[index - 1]? = none := List.getElem?_eq_none (by omega)
    simp [isSignatureAt, entryAt?, none] at signature

theorem isSignatureAt_of_prefix {small large : List Entry} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : isSignatureAt large index = isSignatureAt small index := by
  have same : entryAt? large index = entryAt? small index := by
    obtain ⟨rest, rfl⟩ := sub
    unfold entryAt?
    split
    · rfl
    · rw [List.getElem?_append_left (by omega)]
  unfold isSignatureAt
  rw [same]

theorem hasQuorum_of_cover {configurations : List Configuration}
    {small large : Finset NodeID} (quorum : hasQuorum configurations small)
    (cover
      : forall configuration,
          configuration ∈ configurations
          -> forall node, node ∈ small -> node ∈ configuration.nodes -> node ∈ large)
    : hasQuorum configurations large := by
  refine ⟨quorum.1, List.all_eq_true.mpr fun configuration member => ?_⟩
  have majority := hasQuorum_majority quorum member
  simp only [hasConfigurationMajority, decide_eq_true_eq] at majority ⊢
  have sub : small ∩ configuration.nodes ⊆ large ∩ configuration.nodes := by
    intro node inter
    rw [Finset.mem_inter] at inter ⊢
    exact ⟨cover configuration member node inter.1 inter.2, inter.2⟩
  have := Finset.card_le_card sub
  omega

/-! ## Appends rerun the commit scan -/

section Append

open CCFRaft.Proofs.Direct

theorem appendEntry_fields (self : NodeID) (state : NodeState) (content : EntryContent)
    : Keeps
        (fun after =>
          after.log = state.log ++ [{ term := state.currentTerm, content }]
          /\ after.currentTerm = state.currentTerm
          /\ after.commitIndex = state.commitIndex
          /\ after.matchIndex = state.matchIndex)
        (appendEntry (Capabilities.record self) self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ⟨rfl, rfl, rfl, rfl⟩
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

/-- `activeConfigurations_append`, with the appended configurations beyond the old log. -/
theorem activeConfigurations_extend {log : List Entry} {commit : Nat}
    (frontier : commit <= log.length) (extra : List Entry)
    : exists rest,
        activeConfigurations (log ++ extra) commit
          = activeConfigurations log commit ++ rest
        /\ forall configuration,
            configuration ∈ rest -> log.length < configuration.index := by
  obtain ⟨rest, split, later⟩ := configurationHistory_split (log ++ extra) log.length
  rw [List.take_left' rfl] at split
  refine ⟨rest, ?_, later⟩
  unfold activeConfigurations
  have bound := length_filter_le (configurationHistory log) commit
  simp only [split, filter_index_append frontier later]
  rw [List.drop_append_of_le_length (by omega)]

/-- Appending entries keeps a signature ready for the commit scan. -/
theorem ready_append {before after : NodeState} {self : NodeID} {covering : Nat}
    (ready : SignatureReady before self covering)
    (frontier : before.commitIndex <= before.log.length) {extra : List Entry}
    (log : after.log = before.log ++ extra)
    (term : after.currentTerm = before.currentTerm)
    (commit : after.commitIndex = before.commitIndex)
    (matched : after.matchIndex = before.matchIndex)
    : SignatureReady after self covering := by
  obtain ⟨inLog, isSignature, termEq, quorum⟩ := ready
  have sub : before.log <+: after.log := ⟨extra, log.symm⟩
  obtain ⟨rest, activeEq, later⟩ := activeConfigurations_extend frontier extra
  have activeEq' : after.activeConfigurations = before.activeConfigurations ++ rest := by
    unfold NodeState.activeConfigurations
    rw [log, commit]
    exact activeEq
  refine ⟨le_trans inLog sub.length_le, ?_, ?_, ?_⟩
  · rw [isSignatureAt_of_prefix sub inLog]
    exact isSignature
  · rw [termAt_of_prefix sub inLog, term]
    exact termEq
  · unfold NodeState.activeMembers at quorum ⊢
    rw [activeEq', filter_index_append inLog later, matched]
    refine hasQuorum_mono quorum fun node member => ?_
    rw [Finset.mem_filter] at member ⊢
    refine ⟨?_, member.2⟩
    obtain ⟨configuration, inConfigurations, inNodes⟩ := mem_configurationMembers_iff.mp member.1
    exact mem_configurationMembers (List.mem_append_left _ inConfigurations) inNodes

/-- The commit scan commits a ready signature. -/
theorem advanceCommit_ready (self : NodeID) (middle : NodeState) {covering : Nat}
    (ready : SignatureReady middle self covering)
    : Keeps (fun after => covering <= after.commitIndex)
        (advanceCommit (Capabilities.record self) middle self) := by
  have high := CCFRaft.Proofs.Liveness.highestCommittableIndex_ge middle self covering ready
  unfold advanceCommit
  dsimp only
  refine Keeps.ite' (fun le => Keeps.pure' ?_) fun ahead => ?_
  · by_contra lt
    have := high (by omega)
    omega
  · have recorded
        : covering
          <= (middle.recordCommit self (highestCommittableIndex middle self)).commitIndex := by
      rw [CCFRaft.Proofs.Ledger.NodeState.recordCommit_commitIndex]
      by_cases committed : covering <= middle.commitIndex
      · omega
      · exact high (by omega)
    exact Keeps.ite'
      (fun _ => Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' recorded)
        fun _ => Keeps.pure' recorded)
      fun _ => Keeps.pure' recorded

/-- A primary's append reruns the commit scan, which commits a ready signature. -/
theorem append_ready (self : NodeID) (before : NodeState) (contents : List EntryContent)
    {covering : Nat} (ready : SignatureReady before self covering)
    (frontier : before.commitIndex <= before.log.length)
    : Keeps (fun after => covering <= after.commitIndex)
        (act (Capabilities.record self) self before (.append contents)) := by
  unfold act appendBatch
  refine Keeps.seq' fun _ => ?_
  refine Keeps.bind'
    (Keeps.foldlM'
      (P :=
        fun state =>
          SignatureReady state self covering /\ state.commitIndex <= state.log.length)
      (fun value item held =>
        (appendEntry_fields self value item).mono
          fun next ⟨log, term, commit, matched⟩ =>
            ⟨
              ready_append held.1 held.2 log term commit matched,
              by
                rw [commit, log, List.length_append]
                have := held.2
                omega
            ⟩)
      contents before ⟨ready, frontier⟩)
    fun middle held => advanceCommit_ready self middle held.1

end Append

/-- A majority of a configuration other than the primary alone includes another node. -/
theorem other_member {support : Finset NodeID} {configuration : Configuration}
    {leader : NodeID} (majority : hasConfigurationMajority support configuration)
    (notAlone : Not (configuration.nodes = {leader}))
    : exists node,
        node ∈ support /\ node ∈ configuration.nodes /\ Not (node = leader) := by
  unfold hasConfigurationMajority at majority
  generalize configuration.nodes = nodes at majority notAlone ⊢
  by_contra none
  simp only [not_exists, not_and, not_not] at none
  have sub : support ∩ nodes ⊆ {leader} := by
    intro node member
    rw [Finset.mem_inter] at member
    exact Finset.mem_singleton.mpr (none node member.1 member.2)
  have small := Finset.card_le_card sub
  rw [Finset.card_singleton] at small
  obtain ⟨node, member⟩ := Finset.card_pos.mp (show 0 < (support ∩ nodes).card by omega)
  have same := Finset.mem_singleton.mp (sub member)
  rw [same] at member
  apply notAlone
  symm
  apply Finset.eq_of_subset_of_card_le
  · intro other inSingleton
    rw [Finset.mem_singleton.mp inSingleton]
    exact (Finset.mem_inter.mp member).2
  · rw [Finset.card_singleton]
    have := Finset.card_le_card (Finset.inter_subset_right (s₁ := support) (s₂ := nodes))
    omega

section Recorded

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- An append commits a signature already ready for the commit scan. -/
theorem append_commits_trace {leader : NodeID} {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {entries : List EntryContent}
    (event : step.action = .local leader (.append entries)) {state : NodeState}
    (found : nodeState (proto step.before) leader = some state) {signature : Nat}
    (ready : SignatureReady state leader signature)
    : exists after,
        trace.nodeAt (index + 1) leader = some after
        /\ signature <= after.commitIndex := by
  obtain ⟨before, after, outputs, found', ran, found''⟩ :=
    CCFRaft.Proofs.CommitLiveness.local_step_found (admissible.reachable_before stepped)
      (admissible.step stepped (by rw [event]; rfl))
  rw [found, Option.some.injEq] at found'
  subst found'
  have frontier := commit_le_length admissible (by rw [admissible.nodeAt_before stepped, found])
  exact ⟨
    after,
    by rw [Trace.nodeAt_succ stepped, found''],
    append_ready leader _ entries ready frontier _ _ _ ran
  ⟩

/-- Below a fixed log frontier, the primary's active configurations settle to a
fixed nonempty prefix followed by configurations beyond that frontier. -/
theorem active_settles {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {signed : Nat}
    (afterStart : start <= signed) {state : NodeState}
    (found : trace.nodeAt signed leader = some state) {covering : Nat}
    (within : covering <= state.log.length)
    (nonempty : configurationHistory (state.log.take covering) ≠ [])
    (below
      : forall index state,
          signed <= index
          -> trace.nodeAt index leader = some state
          -> state.commitIndex <= covering)
    : exists settled primary current,
        signed <= settled
        /\ trace.nodeAt settled leader = some primary
        /\ current ≠ []
        /\ (forall configuration,
              configuration ∈ current -> configuration.index <= covering)
        /\ forall index state,
            settled <= index
            -> trace.nodeAt index leader = some state
            -> exists rest,
                state.activeConfigurations = current ++ rest
                /\ forall configuration,
                    configuration ∈ rest -> covering < configuration.index := by
  let history := configurationHistory (state.log.take covering)
  let count (point : W) : Nat :=
    ((nodeState (proto point) leader).map fun state =>
      (history.filter fun configuration => configuration.index <= state.commitIndex).length).getD 0
  have count_eq {point : W} {state : NodeState}
      (found : nodeState (proto point) leader = some state)
      : count point = (history.filter fun configuration => configuration.index <= state.commitIndex).length := by
    simp [count, found]
  have split : forall index current,
      signed <= index -> trace.nodeAt index leader = some current
      -> exists rest, configurationHistory current.log = history ++ rest
        /\ forall configuration, configuration ∈ rest -> covering < configuration.index := by
    intro index current le found'
    obtain ⟨rest, eq, later⟩ :=
      configurationHistory_of_prefix
        ((List.take_prefix covering _).trans (stable_log_prefix admissible stable afterStart le found found'))
    rw [List.length_take_of_le within] at later
    exact ⟨rest, eq, later⟩
  obtain ⟨first, firstFound, _⟩ := Trace.nodeAt_eq_some.mp found
  obtain ⟨settled, point, after, settledFound, constant⟩ :=
    Trace.settles_of_monotone firstFound (measure := fun _ point => count point)
      (fun earlier later before after le laterLe beforeFound afterFound => by
        obtain ⟨_, old, oldFound, _⟩ := stable.leads (afterStart.trans le) beforeFound
        obtain ⟨_, new, newFound, _⟩ := stable.leads (by omega) afterFound
        rw [count_eq oldFound, count_eq newFound]
        exact length_filter_index_mono history
          (commit_mono admissible laterLe
            (by rw [Trace.nodeAt_of_stateAt beforeFound, oldFound])
            (by rw [Trace.nodeAt_of_stateAt afterFound, newFound])))
      (fun index point le pointFound => by
        obtain ⟨_, current, currentFound, _⟩ := stable.leads (afterStart.trans le) pointFound
        rw [count_eq currentFound]
        exact length_filter_le history current.commitIndex)
  obtain ⟨_, primary, primaryFound, _⟩ := stable.leads (afterStart.trans after) settledFound
  refine ⟨
    settled,
    primary,
    history.drop (count point - 1),
    after,
    by rw [Trace.nodeAt_of_stateAt settledFound, primaryFound],
    ?_,
    ?_,
    ?_
  ⟩
  · rw [ne_eq, List.drop_eq_nil_iff]
    have := length_filter_le history primary.commitIndex
    have : 0 < history.length := List.length_pos_of_ne_nil nonempty
    rw [count_eq primaryFound]
    omega
  · intro configuration member
    have := configurationHistory_index_le _ (List.mem_of_mem_drop member)
    rw [List.length_take] at this
    omega
  · intro index current le currentFound
    obtain ⟨last, lastFound, lastNode⟩ := Trace.nodeAt_eq_some.mp currentFound
    obtain ⟨rest, eq, later⟩ := split index current (by omega) currentFound
    refine ⟨rest, ?_, later⟩
    unfold NodeState.activeConfigurations
    rw [activeConfigurations_split eq later (below index current (by omega) currentFound) nonempty]
    rw [← count_eq lastNode, constant index last le lastFound]

/-- A signature commits when a fixed set of live participants covers every active
configuration from the given recorded index on. -/
theorem signature_commits_quorum
    {heartbeatBound signatureBound confirmationBound : Option Real}
    (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (signatures : trace.SignatureScheduling signatureBound)
    (confirmations : trace.RetirementConfirmedScheduling confirmationBound)
    {start : Nat} {leader : NodeID} {term : Nat} {quorum participants : Finset NodeID}
    (stable : StableLeader trace start leader term)
    (alive
      : forall index point,
          trace.stateAt index = some point -> quorum ⊆ HasLive.live point)
    (within : quorum ⊆ participants) (fair : FairLoss trace (insert leader participants))
    {index : Nat} (afterStart : start <= index) {state : NodeState} {signature : Nat}
    (majority
      : forall later state,
          index <= later
          -> trace.nodeAt later leader = some state
          -> hasQuorum state.activeConfigurations quorum)
    (found : trace.nodeAt index leader = some state)
    (isSignature : isSignatureAt state.log signature = true)
    : exists later after,
        index <= later
        /\ trace.nodeAt later leader = some after
        /\ signature <= after.commitIndex := by
  obtain ⟨positive, bound⟩ := le_length_of_isSignatureAt isSignature
  obtain ⟨signed, signer, covering, le, foundSigned, covers, isCovering, coveringTerm⟩ :=
    CCFRaft.Proofs.CommitLiveness.covering_signature admissible signatures stable afterStart found
      (position := state.log.length - 1) (by omega)
  have reachBound := (le_length_of_isSignatureAt isCovering).2
  by_contra never
  simp only [not_exists, not_and, not_le] at never
  have below : forall later state,
      signed <= later -> trace.nodeAt later leader = some state -> state.commitIndex <= covering := by
    intro later state le' found'
    have := never later state (by omega) found'
    omega
  have nonempty : configurationHistory (signer.log.take covering) ≠ [] := by
    have sub : state.log <+: signer.log.take covering := by
      have pre := List.prefix_iff_eq_take.mp (stable_log_prefix admissible stable afterStart le found foundSigned)
      rw [List.prefix_iff_eq_take, List.take_take, Nat.min_eq_left (by omega)]
      exact pre
    obtain ⟨rest, eq, _⟩ := configurationHistory_of_prefix sub
    rw [eq]
    intro empty
    apply (majority index state le_rfl found).1
    have := (List.append_eq_nil_iff.mp empty).1
    exact List.sublist_nil.mp (this ▸ activeConfigurations_sublist _ _)
  obtain ⟨settled, primary, current, after, settledFound, currentNonempty, inside, shape⟩ :=
    active_settles admissible stable (afterStart.trans le) foundSigned reachBound nonempty below
  let stableAt : StableLeader trace settled leader term :=
    stable.later (by omega) (Trace.stateAt_of_nodeAt settledFound)
  have reachAt : covering <= primary.log.length :=
    reachBound.trans (stable_log_prefix admissible stable (afterStart.trans le) after foundSigned settledFound).length_le
  have eligible : forall peer, Not (peer = leader) -> peer ∈ configurationMembers current
      -> forall later state, settled <= later -> trace.nodeAt later leader = some state
        -> peer ∈ eligiblePeers state leader := by
    intro peer different member later state le' found'
    obtain ⟨rest, eq, _⟩ := shape later state le' found'
    simp only [eligiblePeers, Finset.mem_erase]
    refine ⟨different, Finset.mem_union_left _ ?_⟩
    show peer ∈ configurationMembers state.activeConfigurations
    rw [eq]
    obtain ⟨configuration, inCurrent, inNodes⟩ := mem_configurationMembers_iff.mp member
    exact mem_configurationMembers (List.mem_append_left _ inCurrent) inNodes
  have leaderIn : leader ∈ insert leader participants := Finset.mem_insert_self _ _
  have peerIn (peer : NodeID) (member : peer ∈ quorum) : peer ∈ insert leader participants :=
    Finset.mem_insert_of_mem (within member)
  have peerLive (peer : NodeID) (member : peer ∈ quorum)
      : forall index point, settled <= index -> trace.stateAt index = some point
        -> peer ∈ HasLive.live point :=
    fun index point _ found => alive index point found member
  have reaches : forall peer, peer ∈ quorum -> Not (peer = leader)
      -> peer ∈ configurationMembers current
      -> exists stop, (exists point, trace.stateAt stop = some point)
        /\ forall later state, stop <= later -> trace.nodeAt later leader = some state
          -> covering <= state.matchIndex peer := by
    intro peer member different inCurrent
    obtain ⟨stop, point, _, pointFound, lower⟩ :=
      match_reaches admissible stableAt different heartbeats (peerLive peer member)
        (eligible peer different inCurrent) fair leaderIn (peerIn peer member)
        (Nat.le_refl _) settledFound reachAt
    exact ⟨stop, ⟨point, pointFound⟩, lower⟩
  classical
  by_cases shared :
    exists configuration, configuration ∈ current /\ Not (configuration.nodes = {leader})
  swap
  · have alone : forall configuration, configuration ∈ current -> configuration.nodes = {leader} := by
      intro configuration member
      by_contra different
      exact shared ⟨configuration, member, different⟩
    have readyAt : forall later state,
        settled <= later -> trace.nodeAt later leader = some state -> SignatureReady state leader covering := by
      intro later state le' found'
      have grown := stable_log_prefix admissible stable (afterStart.trans le) (by omega) foundSigned found'
      obtain ⟨rest, activeEq, beyond⟩ := shape later state le' found'
      refine ⟨le_trans reachBound grown.length_le, ?_, ?_, ?_⟩
      · rw [isSignatureAt_of_prefix grown reachBound]
        exact isCovering
      · rw [termAt_of_prefix grown reachBound, stable.current (by omega) found', coveringTerm]
      · unfold NodeState.activeMembers
        rw [activeEq, filter_index_split inside beyond]
        have own : hasQuorum current {leader} :=
          ⟨currentNonempty, List.all_eq_true.mpr fun configuration member => by
            simp [hasConfigurationMajority, alone configuration member]⟩
        refine hasQuorum_of_cover own fun configuration member node single inNodes => ?_
        rw [Finset.mem_filter]
        exact ⟨mem_configurationMembers (List.mem_append_left _ member) inNodes,
          Or.inl (Finset.mem_singleton.mp single)⟩
    have dueAt : forall later point, settled <= later -> trace.stateAt later = some point
        -> ConfirmationDue point leader := by
      intro later point le' found'
      obtain ⟨leaderLive, state, nodeFound, primary, _, notRetired⟩ :=
        stable.leads (by omega) found'
      have nodeAt : trace.nodeAt later leader = some state := by
        rw [Trace.nodeAt_of_stateAt found', nodeFound]
      obtain ⟨_, isSig, termEq, _⟩ := readyAt later state le' nodeAt
      obtain ⟨rest, activeEq, beyond⟩ := shape later state le' nodeAt
      obtain ⟨configuration, inCurrent⟩ := List.exists_mem_of_ne_nil _ currentNonempty
      have uncommitted := never later state (by omega) nodeAt
      refine ⟨leaderLive, state, nodeFound, primary, notRetired,
        confirmation_owed admissible nodeAt primary
          ⟨by omega, isSig, termEq, ⟨configuration, ?_, inside configuration inCurrent⟩, ?_⟩⟩
      · rw [activeEq]
        exact List.mem_append_left _ inCurrent
      · intro other member bounded
        rw [activeEq] at member
        rcases List.mem_append.mp member with inCurrent' | inRest
        · exact alone other inCurrent'
        · have := beyond other inRest
          omega
    obtain ⟨point, pointFound⟩ := Trace.stateAt_of_nodeAt settledFound
    obtain ⟨later, step, le', stepped, entries, event, _⟩ :=
      (confirmations leader).fires pointFound dueAt
    obtain ⟨_, state, stateFound, _⟩ :=
      stable.leads (by omega) (admissible.before stepped)
    have nodeAt : trace.nodeAt later leader = some state := by
      rw [admissible.nodeAt_before stepped, stateFound]
    obtain ⟨committer, foundCommitter, committed⟩ :=
      append_commits_trace admissible stepped event stateFound (readyAt later state le' nodeAt)
    have := never (later + 1) committer (by omega) foundCommitter
    omega
  choose! stopOf stopSpec using reaches
  obtain ⟨rest, activeEq, _⟩ := shape settled primary le_rfl settledFound
  obtain ⟨configuration, inCurrent, notAlone⟩ := shared
  have inActive : configuration ∈ primary.activeConfigurations := by
    rw [activeEq]
    exact List.mem_append_left _ inCurrent
  obtain ⟨witness, witnessIn, witnessNodes, witnessOther⟩ :=
    other_member (hasQuorum_majority (majority settled primary (by omega) settledFound) inActive) notAlone
  have witnessMember := mem_configurationMembers inCurrent witnessNodes
  obtain ⟨delivery, step, packet, deliveryLe, stepped, event, source, target, matched⟩ :=
    fair witness leader _ (peerIn witness witnessIn) leaderIn
      (acks_sent admissible stableAt witnessOther heartbeats (peerLive witness witnessIn)
        (eligible witness witnessOther witnessMember) fair leaderIn (peerIn witness witnessIn)
        (Nat.le_refl _) settledFound reachAt)
      (max settled (quorum.sup stopOf))
  cases payload : packet.envelope.payload with
  | appendEntriesResponse response =>
      rw [payload] at matched
      obtain ⟨newer, success, _⟩ := matched
      obtain ⟨_, state, stateFound, _⟩ :=
        stable.leads (by omega) (admissible.before stepped)
      have nodeAt : trace.nodeAt delivery leader = some state := by
        rw [admissible.nodeAt_before stepped, stateFound]
      have grown := stable_log_prefix admissible stable (afterStart.trans le) (by omega) foundSigned nodeAt
      obtain ⟨rest, activeEq, later⟩ := shape delivery state (by omega) nodeAt
      have ready : SignatureReady state leader covering := by
        refine ⟨le_trans reachBound grown.length_le, ?_, ?_, ?_⟩
        · rw [isSignatureAt_of_prefix grown reachBound]
          exact isCovering
        · rw [termAt_of_prefix grown reachBound, stable.current (by omega) nodeAt, coveringTerm]
        · have quorumAt := majority delivery state (by omega) nodeAt
          unfold NodeState.activeMembers
          rw [activeEq] at quorumAt ⊢
          rw [filter_index_split inside later]
          have currentQuorum : hasQuorum current quorum :=
            ⟨currentNonempty, List.all_eq_true.mpr fun configuration member =>
              List.all_eq_true.mp quorumAt.2 configuration (List.mem_append_left _ member)⟩
          refine hasQuorum_of_cover currentQuorum
            fun configuration member node inQuorum inNodes => ?_
          rw [Finset.mem_filter]
          refine ⟨mem_configurationMembers (List.mem_append_left _ member) inNodes, ?_⟩
          by_cases same : node = leader
          · exact Or.inl same
          · have := Finset.le_sup (f := stopOf) inQuorum
            exact Or.inr ((stopSpec node inQuorum same (mem_configurationMembers member inNodes)).2
              delivery state (by omega) nodeAt)
      obtain ⟨committer, foundCommitter, committed⟩ :=
        ack_commits_trace admissible stable (by omega) stepped event target payload success newer nodeAt
          (by rw [source]; exact eligible witness witnessOther witnessMember delivery state (by omega) nodeAt)
          ready
      have := never (delivery + 1) committer (by omega) foundCommitter
      omega
  | _ =>
      rw [payload] at matched
      exact matched.elim

/-- A signature in the stable primary's log eventually commits, even if it is from
an older term. Crash-stop availability leaves a fixed live quorum after some
recorded state; this argument does not assume the recording is infinite. -/
theorem signature_commits {heartbeatBound signatureBound confirmationBound : Option Real}
    (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (signatures : trace.SignatureScheduling signatureBound)
    (confirmations : trace.RetirementConfirmedScheduling confirmationBound) {start : Nat}
    {leader : NodeID} {term : Nat} {participants : Finset NodeID}
    (stable : StableLeader trace start leader term)
    (live : LiveQuorum trace leader participants)
    (fair : FairLoss trace (insert leader participants)) {index : Nat}
    (afterStart : start <= index) {state : NodeState} {signature : Nat}
    (found : trace.nodeAt index leader = some state)
    (isSignature : isSignatureAt state.log signature = true)
    : exists later after,
        index <= later
        /\ trace.nodeAt later leader = some after
        /\ signature <= after.commitIndex := by
  obtain ⟨quorumFrom, quorumPoint, quorumFound, quorumAt⟩ := live
  obtain ⟨first, firstFound, _⟩ := Trace.nodeAt_eq_some.mp found
  have combined : exists point, trace.stateAt (max index quorumFrom) = some point := by
    rcases Nat.le_total index quorumFrom with le | le
    · exact ⟨quorumPoint, by rwa [Nat.max_eq_right le]⟩
    · exact ⟨first, by rwa [Nat.max_eq_left le]⟩
  obtain ⟨first, firstFound⟩ := combined
  have shrinks : forall earlier later before after,
      earlier <= later -> trace.stateAt earlier = some before -> trace.stateAt later = some after
      -> HasLive.live after ∩ participants ⊆ HasLive.live before ∩ participants :=
    fun _ _ _ _ le found found' =>
      Finset.inter_subset_inter_right (admissible.live_anti le found found')
  obtain ⟨stop, point, stopLe, stopFound, constant⟩ :=
    Trace.settles_of_antitone firstFound
      (measure := fun _ point => (HasLive.live point ∩ participants).card)
      (fun earlier later before after _ le found found' =>
        Finset.card_le_card (shrinks earlier later before after le found found'))
  have settledLive : forall later last,
      stop <= later -> trace.stateAt later = some last
      -> HasLive.live last ∩ participants = HasLive.live point ∩ participants := by
    intro later last le found'
    exact Finset.eq_of_subset_of_card_le (shrinks stop later point last le stopFound found')
      (by rw [constant later last le found'])
  have alive : forall later last, trace.stateAt later = some last
      -> HasLive.live point ∩ participants ⊆ HasLive.live last := by
    intro later last found'
    rcases Nat.le_total later stop with le | le
    · exact (shrinks later stop last point le found' stopFound).trans Finset.inter_subset_left
    · rw [← settledLive later last le found']
      exact Finset.inter_subset_left
  obtain ⟨primary, primaryFound⟩ := stable.found (by omega) stopFound
  have bound := (le_length_of_isSignatureAt isSignature).2
  have grown := stable_log_prefix admissible stable afterStart (by omega) found primaryFound
  obtain ⟨later, after, le, afterFound, committed⟩ :=
    signature_commits_quorum admissible heartbeats signatures confirmations stable alive
      Finset.inter_subset_right fair (by omega)
      (fun later state le found' => by
        obtain ⟨last, lastFound, lastNode⟩ := Trace.nodeAt_eq_some.mp found'
        rw [← settledLive later last le lastFound]
        exact quorumAt later last state (by omega) lastFound lastNode)
      primaryFound (by rw [isSignatureAt_of_prefix grown bound]; exact isSignature)
  exact ⟨later, after, by omega, afterFound, committed⟩

/-- `Properties.commit_liveness`: leadership need only be stable from `start`, and
the independent scheduling constraints may be timed or untimed. -/
theorem commit_liveness
    {heartbeatBound signatureBound confirmationBound : Option Real}
    (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (signatures : trace.SignatureScheduling signatureBound)
    (confirmations : trace.RetirementConfirmedScheduling confirmationBound)
    {start : Nat} {leader : NodeID} {term : Nat} {participants : Finset NodeID}
    (stable : StableLeader trace start leader term)
    (live : LiveQuorum trace leader participants)
    (fair : FairLoss trace (insert leader participants))
    {request : ReqID} (submitted : Submitted trace start leader request)
    : exists index, RequestCommitted trace leader request index :=
  CCFRaft.Proofs.CommitLiveness.request_committed admissible signatures stable submitted
    fun _ _ _ afterStart found isSignature _ =>
      signature_commits admissible heartbeats signatures confirmations stable live fair
        afterStart found isSignature

end Recorded

end CCFRaft.Proofs.Replication
