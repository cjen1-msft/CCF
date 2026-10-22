module

public import CCFRaft.Proofs.Replication.Peer
public import CCFRaft.Proofs.Replication.Owing
public import CCFRaft.Proofs.Shift

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Signature commitment

Signature commitment, and so `Properties.commit_liveness`.
Take a current-term signature covering the given one. If it is never committed,
the commit index stays below it, so the configurations at or before it that
remain active eventually stop changing. If one of them has a member other than
the primary, every peer of the live quorum in them acknowledges the signature,
and the next acknowledgement commits it. Otherwise the primary alone makes the
signature ready, so a retirement confirmation is due (`confirmation_owed`), and
the append that eventually confirms it commits the signature.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary

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

/-- An append by the primary commits a signature that is ready for the commit scan. -/
theorem append_commits_trace (model : LivenessModel) {trace : Trace}
    (valid : model.FairFrom trace) {leader : NodeID} {index : Nat}
    {entries : List EntryContent}
    (event : trace.event index = .local leader (.append entries)) {state : NodeState}
    (found : nodeState (trace.state index) leader = some state)
    (frontier : state.commitIndex <= state.log.length) {signature : Nat}
    (ready : SignatureReady state leader signature)
    : exists after,
        nodeState (trace.state (index + 1)) leader = some after
        /\ signature <= after.commitIndex := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  obtain ⟨before, after, outputs, found', ran, found''⟩ :=
    CCFRaft.Proofs.CommitLiveness.local_step_found
      (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ (by rw [event]; rfl))
  rw [found, Option.some.injEq] at found'
  subst found'
  exact ⟨after, found'', append_ready leader _ entries ready frontier _ _ _ ran⟩

/-- A stable primary keeps making productive sends to a peer that stays live and,
from some point on, eligible. -/
theorem productive_sends (model : LivenessModel) {trace : Trace}
    (valid : model.FairFrom trace) {leader peer : NodeID} {term joined : Nat}
    (stable : LeadsThroughout trace leader term)
    (live : forall index, peer ∈ trace.live index)
    (eligible
      : forall index state,
          joined <= index
          -> nodeState (trace.state index) leader = some state
          -> peer ∈ eligiblePeers state leader)
    : Often (trace.ProductiveSend leader peer) := by
  have due : forall index, joined <= index -> trace.PeerDue leader peer index := by
    intro index le
    obtain ⟨leaderLive, state, found, primary, _, notRetired⟩ := stable index
    exact ⟨leaderLive, live index, state, found, primary, notRetired,
      eligible index state le found⟩
  intro cutoff
  obtain ⟨later, after, sends⟩ :=
    valid.heartbeats (max cutoff joined) leader peer (due _ (le_max_right _ _))
  rcases sends with stopped | productive
  · exact (stopped (due later (by omega))).elim
  · exact ⟨later, by omega, productive⟩

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

section Settle

variable [Config.InitialConfiguration] {trace : Trace} {nodes : List NodeID}
  (execution : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)

include execution

/-- While the stable primary's commit index stays within a prefix of its log, its
active configurations settle: a fixed nonempty list of configurations within the
prefix, followed by configurations beyond it. -/
theorem active_settles {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) {signed covering : Nat}
    (within : covering <= (stable.state signed).log.length)
    (nonempty : configurationHistory ((stable.state signed).log.take covering) ≠ [])
    (below
      : forall index, signed <= index -> (stable.state index).commitIndex <= covering)
    : exists settled current,
        signed <= settled
        /\ current ≠ []
        /\ (forall configuration,
              configuration ∈ current -> configuration.index <= covering)
        /\ forall index,
            settled <= index
            -> exists rest,
                (stable.state index).activeConfigurations = current ++ rest
                /\ forall configuration,
                    configuration ∈ rest -> covering < configuration.index := by
  have split
      : forall index, signed <= index
        -> exists rest,
            configurationHistory (stable.state index).log
              = configurationHistory ((stable.state signed).log.take covering) ++ rest
            /\ forall configuration, configuration ∈ rest -> covering < configuration.index := by
    intro index le
    obtain ⟨rest, eq, later⟩ :=
      configurationHistory_of_prefix
        ((List.take_prefix covering _).trans (stable_prefix execution stable le))
    rw [List.length_take_of_le within] at later
    exact ⟨rest, eq, later⟩
  obtain ⟨settled, after, constant⟩ :=
    eventually_const
      (f := fun index =>
        ((configurationHistory ((stable.state signed).log.take covering)).filter
          fun configuration => configuration.index <= (stable.state index).commitIndex).length)
      (start := signed)
      (bound := (configurationHistory ((stable.state signed).log.take covering)).length)
      (fun index _ =>
        length_filter_index_mono _ (commit_mono execution stable (Nat.le_succ index)))
      (fun _ _ => length_filter_le _ _)
  refine ⟨
    settled,
    (configurationHistory ((stable.state signed).log.take covering)).drop
      (((configurationHistory ((stable.state signed).log.take covering)).filter
          fun configuration =>
            configuration.index <= (stable.state settled).commitIndex).length
        - 1),
    after,
    ?_,
    fun configuration member => ?_,
    fun index le => ?_
  ⟩
  · rw [ne_eq, List.drop_eq_nil_iff]
    have := length_filter_le (configurationHistory ((stable.state signed).log.take covering))
      (stable.state settled).commitIndex
    have := List.length_pos_of_ne_nil nonempty
    omega
  · have := configurationHistory_index_le _ (List.mem_of_mem_drop member)
    rw [List.length_take] at this
    omega
  · obtain ⟨rest, eq, later⟩ := split index (by omega)
    refine ⟨rest, ?_, later⟩
    unfold NodeState.activeConfigurations
    rw [activeConfigurations_split eq later (below index (by omega)) nonempty]
    rw [constant index le]

end Settle

/-- `signature_commits` for a fixed quorum that is live throughout and a majority
from the given index on. -/
theorem signature_commits_quorum (model : LivenessModel) {trace : Trace}
    {leader : NodeID} {term : Nat} {quorum participants : Finset NodeID}
    (valid : model.FairFrom trace) (stable : LeadsThroughout trace leader term)
    (alive : forall index, quorum ⊆ trace.live index) (within : quorum ⊆ participants)
    (fair : FairLoss trace (insert leader participants))
    {index : Nat} {state : NodeState} {signature : Nat}
    (majority
      : forall later state,
          index <= later
          -> nodeState (trace.state later) leader = some state
          -> hasQuorum state.activeConfigurations quorum)
    (found : nodeState (trace.state index) leader = some state)
    (isSignature : isSignatureAt state.log signature = true)
    : exists later after,
        index <= later
        /\ nodeState (trace.state later) leader = some after
        /\ signature <= after.commitIndex := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  have stateEq := stable.state_eq found
  subst stateEq
  obtain ⟨positive, bound⟩ := le_length_of_isSignatureAt isSignature
  obtain ⟨signed, signer, covering, le, foundSigned, covers, isCovering, coveringTerm⟩ :=
    CCFRaft.Proofs.CommitLiveness.covering_signature model valid stable found
      (position := (stable.state index).log.length - 1) (by omega)
  rw [stable.state_eq foundSigned] at isCovering coveringTerm
  have reachBound := (le_length_of_isSignatureAt isCovering).2
  by_contra never
  simp only [not_exists, not_and, not_le] at never
  have below : forall later, signed <= later -> (stable.state later).commitIndex <= covering := by
    intro later le'
    have := never later _ (by omega) (stable.found later)
    omega
  have nonempty : configurationHistory ((stable.state signed).log.take covering) ≠ [] := by
    have sub : (stable.state index).log <+: (stable.state signed).log.take covering := by
      have pre := List.prefix_iff_eq_take.mp (stable_prefix execution stable le)
      rw [List.prefix_iff_eq_take, List.take_take, Nat.min_eq_left (by omega)]
      exact pre
    obtain ⟨rest, eq, _⟩ := configurationHistory_of_prefix sub
    rw [eq]
    intro empty
    apply (majority index _ le_rfl (stable.found index)).1
    have := (List.append_eq_nil_iff.mp empty).1
    exact List.sublist_nil.mp (this ▸ activeConfigurations_sublist _ _)
  obtain ⟨settled, current, after, currentNonempty, inside, shape⟩ :=
    active_settles execution stable reachBound nonempty below
  have eligible
      : forall peer, Not (peer = leader) -> peer ∈ configurationMembers current
        -> forall later, settled <= later -> peer ∈ eligiblePeers (stable.state later) leader := by
    intro peer different member later le'
    obtain ⟨rest, eq, _⟩ := shape later le'
    simp only [eligiblePeers, Finset.mem_erase]
    refine ⟨different, Finset.mem_union_left _ ?_⟩
    show peer ∈ configurationMembers (stable.state later).activeConfigurations
    rw [eq]
    obtain ⟨configuration, inCurrent, inNodes⟩ := mem_configurationMembers_iff.mp member
    exact mem_configurationMembers (List.mem_append_left _ inCurrent) inNodes
  have leaderIn : leader ∈ insert leader participants := Finset.mem_insert_self _ _
  have conditions
      : forall peer, peer ∈ quorum -> Not (peer = leader)
        -> peer ∈ configurationMembers current
        -> peer ∈ insert leader participants
          /\ Often (trace.ProductiveSend leader peer)
          /\ forall later state,
              settled <= later
              -> nodeState (trace.state later) peer = some state
              -> state.currentTerm <= term := by
    intro peer peerQuorum different member
    have eligibleAt
        : forall later state, settled <= later
          -> nodeState (trace.state later) leader = some state
          -> peer ∈ eligiblePeers state leader := by
      intro later state le' found'
      rw [stable.state_eq found']
      exact eligible peer different member later le'
    have peerLive : forall later, peer ∈ trace.live later := fun later => alive later peerQuorum
    have peerIn : peer ∈ insert leader participants :=
      Finset.mem_insert_of_mem (within peerQuorum)
    exact ⟨peerIn, productive_sends model valid stable peerLive eligibleAt,
      peer_term_le model valid stable fair leaderIn peerIn peerLive eligibleAt⟩
  have reaches
      : forall peer, peer ∈ quorum -> Not (peer = leader)
        -> peer ∈ configurationMembers current
        -> exists stop, forall later,
            stop <= later -> covering <= (stable.state later).matchIndex peer := by
    intro peer peerQuorum different member
    obtain ⟨peerIn, productive, termLe⟩ := conditions peer peerQuorum different member
    exact match_reaches execution stable different (eligible peer different member) fair
      leaderIn peerIn productive termLe reachBound
  classical
  by_cases shared :
    exists configuration, configuration ∈ current /\ Not (configuration.nodes = {leader})
  swap
  · have alone
        : forall configuration, configuration ∈ current -> configuration.nodes = {leader} := by
      intro configuration member
      by_contra different
      exact shared ⟨configuration, member, different⟩
    have readyAt
        : forall later, settled <= later
          -> SignatureReady (stable.state later) leader covering := by
      intro later le'
      have grown := stable_prefix execution stable (show signed <= later by omega)
      obtain ⟨rest, activeEq, beyond⟩ := shape later le'
      refine ⟨le_trans reachBound grown.length_le, ?_, ?_, ?_⟩
      · rw [isSignatureAt_of_prefix grown reachBound]
        exact isCovering
      · rw [termAt_of_prefix grown reachBound, stable.current, coveringTerm]
      · unfold NodeState.activeMembers
        rw [activeEq, filter_index_split inside beyond]
        have own : hasQuorum current {leader} :=
          ⟨currentNonempty, List.all_eq_true.mpr fun configuration member => by
            simp [hasConfigurationMajority, alone configuration member]⟩
        refine hasQuorum_of_cover own fun configuration member node single inNodes => ?_
        rw [Finset.mem_filter]
        exact ⟨mem_configurationMembers (List.mem_append_left _ member) inNodes,
          Or.inl (Finset.mem_singleton.mp single)⟩
    have dueAt : forall later, settled <= later -> trace.ConfirmationDue leader later := by
      intro later le'
      obtain ⟨leaderLive, current', found', primary, _, notRetired⟩ := stable later
      have same := stable.state_eq found'
      subst same
      obtain ⟨_, isSig, termEq, _⟩ := readyAt later le'
      obtain ⟨rest, activeEq, beyond⟩ := shape later le'
      obtain ⟨configuration, inCurrent⟩ := List.exists_mem_of_ne_nil _ currentNonempty
      have uncommitted := never later _ (by omega) found'
      refine ⟨leaderLive, _, found', primary, notRetired,
        confirmation_owed model valid found' primary
          ⟨by omega, isSig, termEq, ⟨configuration, ?_, inside configuration inCurrent⟩, ?_⟩⟩
      · rw [activeEq]
        exact List.mem_append_left _ inCurrent
      · intro other member bounded
        rw [activeEq] at member
        rcases List.mem_append.mp member with inCurrent' | inRest
        · exact alone other inCurrent'
        · have := beyond other inRest
          omega
    obtain ⟨later, le', notDue | confirms⟩ :=
      valid.confirmations settled leader (dueAt settled le_rfl)
    · exact notDue (dueAt later le')
    · obtain ⟨entries, event, _⟩ := confirms
      have grown := stable_prefix execution stable (show signed <= later by omega)
      have frontier
          : (stable.state later).commitIndex <= (stable.state later).log.length :=
        le_trans (below later (by omega)) (le_trans reachBound grown.length_le)
      obtain ⟨committer, foundCommitter, committed⟩ :=
        append_commits_trace model valid event (stable.found later) frontier (readyAt later le')
      have := never (later + 1) committer (by omega) foundCommitter
      omega
  choose! stopOf stopSpec using reaches
  obtain ⟨rest, activeEq, _⟩ := shape settled le_rfl
  obtain ⟨configuration, inCurrent, notAlone⟩ := shared
  have inActive : configuration ∈ (stable.state settled).activeConfigurations := by
    rw [activeEq]
    exact List.mem_append_left _ inCurrent
  obtain ⟨witness, witnessIn, witnessNodes, witnessOther⟩ :=
    other_member
      (hasQuorum_majority (majority settled _ (by omega) (stable.found settled)) inActive)
      notAlone
  have witnessMember := mem_configurationMembers inCurrent witnessNodes
  obtain ⟨witnessIn', productive, termLe⟩ :=
    conditions witness witnessIn witnessOther witnessMember
  obtain ⟨delivery, packet, deliveryLe, event, source, target, matched⟩ :=
    fair witness leader _ witnessIn' leaderIn
      (acks_sent execution stable witnessOther (eligible witness witnessOther witnessMember) fair
        leaderIn witnessIn' productive termLe reachBound)
      (max settled (quorum.sup stopOf))
  cases payload : packet.envelope.payload with
  | appendEntriesResponse response =>
      rw [payload] at matched
      obtain ⟨newer, success, _⟩ := matched
      have grown := stable_prefix execution stable (show signed <= delivery by omega)
      obtain ⟨rest, activeEq, later⟩ := shape delivery (by omega)
      have ready : SignatureReady (stable.state delivery) leader covering := by
        refine ⟨le_trans reachBound grown.length_le, ?_, ?_, ?_⟩
        · rw [isSignatureAt_of_prefix grown reachBound]
          exact isCovering
        · rw [termAt_of_prefix grown reachBound, stable.current, coveringTerm]
        · have quorumAt := majority delivery _ (by omega) (stable.found delivery)
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
            exact Or.inr (stopSpec node inQuorum same (mem_configurationMembers member inNodes)
              delivery (by omega))
      obtain ⟨committer, foundCommitter, committed⟩ :=
        ack_commits_trace model valid stable event target payload success newer
          (stable.found delivery)
          (by rw [source]; exact eligible witness witnessOther witnessMember delivery (by omega))
          ready
      have := never (delivery + 1) committer (by omega) foundCommitter
      omega
  | _ =>
      rw [payload] at matched
      exact matched.elim

/-- A signature in the stable primary's log is eventually committed. The premise
does not require it to be from the primary's term. Live participants only
decrease, so from some point on they are a fixed quorum. -/
theorem signature_commits (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {term : Nat} {participants : Finset NodeID} (valid : model.FairFrom trace)
    (stable : LeadsThroughout trace leader term)
    (live : LiveQuorum trace leader participants)
    (fair : FairLoss trace (insert leader participants)) {index : Nat} {state : NodeState}
    {signature : Nat} (found : nodeState (trace.state index) leader = some state)
    (isSignature : isSignatureAt state.log signature = true)
    : exists later after,
        index <= later
        /\ nodeState (trace.state later) leader = some after
        /\ signature <= after.commitIndex := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  obtain ⟨start, quorumAt⟩ := live
  have shrinks
      : forall first second, first <= second
        -> trace.live second ∩ participants ⊆ trace.live first ∩ participants := by
    intro first second le
    induction second, le using Nat.le_induction with
    | base => exact Finset.Subset.refl _
    | succ second _ ih =>
        exact (Finset.inter_subset_inter_right
          (CCFRaft.Proofs.Liveness.live_decreases execution second)).trans ih
  obtain ⟨stop, _, constant⟩ :=
    eventually_const
      (f := fun index => (trace.live 0 ∩ participants).card
        - (trace.live index ∩ participants).card)
      (start := 0) (bound := (trace.live 0 ∩ participants).card)
      (fun index _ => by
        have := Finset.card_le_card (shrinks index (index + 1) (Nat.le_succ _))
        have := Finset.card_le_card (shrinks 0 index (Nat.zero_le _))
        omega)
      (fun _ _ => Nat.sub_le _ _)
  have settledLive
      : forall later, stop <= later
        -> trace.live later ∩ participants = trace.live stop ∩ participants := by
    intro later le
    have same := constant later le
    have := Finset.card_le_card (shrinks 0 later (Nat.zero_le _))
    have := Finset.card_le_card (shrinks 0 stop (Nat.zero_le _))
    exact Finset.eq_of_subset_of_card_le (shrinks stop later le) (by omega)
  have alive : forall later, trace.live stop ∩ participants ⊆ trace.live later := by
    intro later
    rcases Nat.le_total later stop with le | le
    · exact (shrinks later stop le).trans Finset.inter_subset_left
    · rw [← settledLive later le]
      exact Finset.inter_subset_left
  have stateEq := stable.state_eq found
  subst stateEq
  have bound := (le_length_of_isSignatureAt isSignature).2
  have grown :=
    stable_prefix execution stable (Nat.le_max_left index (max stop start))
  obtain ⟨later, after, le, foundAfter, committed⟩ :=
    signature_commits_quorum model valid stable alive Finset.inter_subset_right fair
      (index := max index (max stop start))
      (fun later state le found => by
        rw [← settledLive later (by omega)]
        exact quorumAt later state (by omega) found)
      (stable.found _) (by rw [isSignatureAt_of_prefix grown bound]; exact isSignature)
  exact ⟨later, after, by omega, foundAfter, committed⟩

/-- Commit liveness for a primary that is stable throughout. -/
theorem commit_liveness_stable (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {term : Nat} {participants : Finset NodeID} {request : ReqID}
    (valid : model.FairFrom trace) (stable : LeadsThroughout trace leader term)
    (live : LiveQuorum trace leader participants)
    (fair : FairLoss trace (insert leader participants))
    (submitted : Submitted trace 0 leader request)
    : exists index, RequestCommitted trace leader request index :=
  CCFRaft.Proofs.CommitLiveness.request_committed model valid stable submitted
    fun _ _ _ found isSignature _ =>
      signature_commits model valid stable live fair found isSignature

/-- `Properties.commit_liveness`: the primary need only be stable, and the request
submitted, from index `start` on. The proof works on the suffix from `start`. -/
theorem commit_liveness (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {term : Nat} {participants : Finset NodeID} {request : ReqID} {start : Nat}
    (valid : model.Fair trace) (stable : StableLeader trace start leader term)
    (live : LiveQuorum trace leader participants)
    (fair : FairLoss trace (insert leader participants))
    (submitted : Submitted trace start leader request)
    : exists index, RequestCommitted trace leader request index := by
  have valid := valid.fairFrom
  obtain ⟨quorumFrom, quorumAt⟩ := live
  obtain ⟨submittedAt, after, present⟩ := submitted
  have same : start + (submittedAt - start) = submittedAt := by omega
  have shifted : Submitted (trace.shift start) 0 leader request := by
    refine ⟨submittedAt - start, Nat.zero_le _, ?_⟩
    rcases present with ⟨state, found, has⟩ | ⟨entries, event, member⟩
    · exact Or.inl ⟨state, by simpa only [Trace.shift, same] using found, has⟩
    · refine Or.inr ⟨entries, ?_, member⟩
      rw [Shift.local_shift, same]
      exact event
  obtain ⟨index, committed⟩ :=
    commit_liveness_stable model (Shift.fair_shift valid start)
      (fun index => stable (start + index) (Nat.le_add_right _ _))
      ⟨quorumFrom, fun index state le found => quorumAt (start + index) state (by omega) found⟩
      (Shift.fair_loss_shift valid.execution fair start) shifted
  exact ⟨start + index, committed⟩

end CCFRaft.Proofs.Replication
