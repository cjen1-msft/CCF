import CCFRaft.Properties

/-!
# CCFRaft proofs

The full reachable-state theorem is derived only after proving
`Properties.FullInductivenessObligation`; no assumption is introduced for that
obligation.
-/

set_option autoImplicit false

namespace CCFRaft.Proofs

open Model
open Properties

@[simp]
theorem initial_LogInv (start : Node) :
    LogInv (initialState start) := by
  intro i j
  by_cases hi : i = start <;>
    by_cases hj : j = start <;>
      simp [committed, initialState, hi, hj, isLogPrefix, logPrefix,
        startLog]

@[simp]
theorem initial_MoreThanOneLeaderInv (start : Node) :
    MoreThanOneLeaderInv (initialState start) := by
  intro i j _ hi hj
  simp [initialState] at hi hj
  exact hi.trans hj.symm

@[simp]
theorem initial_SignatureInv (start : Node) :
    SignatureInv (initialState start) := by
  intro node positive
  by_cases h : node = start
  · subst node
    simp [initialState, startLog, entryAt?]
  · simp [initialState, h] at positive

theorem initial_AppendEntriesResponseBoundInv (start : Node) :
    AppendEntriesResponseBoundInv (initialState start) := by
  intro dest source message messageQueued
  simp [initialState] at messageQueued

theorem initial_ConfigurationsWellFormedInv (start : Node) :
    ConfigurationsWellFormedInv (initialState start) := by
  intro node
  by_cases h : node = start
  · subst node
    simp [increasingConfigurationIndices, configurationsBoundedBy,
      initialState, startLog]
  · simp [increasingConfigurationIndices, configurationsBoundedBy,
      initialState, startLog, h]

theorem initial_MessagesWellFormedInv (start : Node) :
    MessagesWellFormedInv (initialState start) := by
  intro dest source message messageQueued
  simp [initialState] at messageQueued

theorem initial_NoLeaderBeforeInitialTermInv (start : Node) :
    NoLeaderBeforeInitialTermInv (initialState start) := by
  intro node lowerTerm
  by_cases nodeIsStart : node = start
  · subst node
    simp [initialState, startTerm] at lowerTerm
  · have role :
        (initialState start).leadershipState node = .none := by
      simp [initialState, nodeIsStart]
    rw [role]
    decide

theorem initial_LogTermsAtLeastStartInv (start : Node) :
    LogTermsAtLeastStartInv (initialState start) := by
  intro node entry member
  by_cases nodeIsStart : node = start
  · subst node
    simp [initialState, startLog] at member
    rcases member with isFirst | isSecond
    · subst entry
      exact Nat.le_refl _
    · subst entry
      exact Nat.le_refl _
  · simp [initialState, nodeIsStart] at member

theorem initial_CandidateTermNotInLogInv (start : Node) :
    CandidateTermNotInLogInv (initialState start) := by
  intro candidate candidateState
  by_cases candidateIsStart : candidate = start <;>
    simp [initialState, candidateIsStart] at candidateState

theorem initial_ElectionSafetyInv (start : Node) :
    ElectionSafetyInv (initialState start) := by
  intro leader leaderState node different
  simp [initialState] at leaderState
  subst leader
  by_cases nodeIsStart : node = start
  · subst node
    simp at different
  · simp [initialState, nodeIsStart, electionTermFold, startLog]

theorem initial_LogMatchingInv (start : Node) :
    LogMatchingInv (initialState start) := by
  intro first second different index positive bounded _
  by_cases firstIsStart : first = start <;>
    by_cases secondIsStart : second = start
  · subst first
    subst second
    simp at different
  · simp [initialState, firstIsStart, secondIsStart] at bounded
    omega
  · simp [initialState, firstIsStart, secondIsStart] at bounded
    omega
  · simp [initialState, firstIsStart, secondIsStart] at bounded
    omega

theorem initial_QuorumLogInv (start : Node) :
    QuorumLogInv (initialState start) := by
  intro node configurationsNonempty quorum quorumIsMajority
  by_cases nodeIsStart : node = start
  · subst node
    simp [initialState, currentConfiguration, isQuorum] at quorumIsMajority
    rcases quorumIsMajority.1 with
      quorumEmpty | quorumSingleton
    · subst quorum
      simp at quorumIsMajority
    · subst quorum
      refine ⟨start, by simp, ?_⟩
      simp [committed, initialState, isLogPrefix, logPrefix, startLog]
  · have emptyConfigurations :
        (initialState start).configurations node = [] := by
      simp [initialState, nodeIsStart]
    rw [emptyConfigurations] at configurationsNonempty
    change false = true at configurationsNonempty
    exact False.elim (Bool.noConfusion configurationsNonempty)

theorem initial_LeaderCompletenessInv (start : Node) :
    LeaderCompletenessInv (initialState start) := by
  intro leader leaderState node different lowerTerm
  simp [initialState] at leaderState
  subst leader
  by_cases nodeIsStart : node = start
  · subst node
    simp at different
  · simp [committed, initialState, nodeIsStart, isLogPrefix, logPrefix]

theorem initial_MonoTermInv (start : Node) :
    MonoTermInv (initialState start) := by
  intro dest source message messageQueued
  simp [initialState] at messageQueued

theorem initial_MonoLogInv (start : Node) :
    MonoLogInv (initialState start) := by
  intro node nonempty
  by_cases nodeIsStart : node = start
  · subst node
    simp [initialState, startLog, monoLogEntries]
  · have emptyLog : (initialState start).log node = [] := by
      simp [initialState, nodeIsStart]
    rw [emptyLog] at nonempty
    change false = true at nonempty
    exact False.elim (Bool.noConfusion nonempty)

theorem initial_LogConfigurationConsistentInv (start : Node) :
    LogConfigurationConsistentInv (initialState start) := by
  intro node
  by_cases nodeIsStart : node = start
  · subst node
    simp [initialState, startLog, configurationsMatchLog,
      noCommittedReconfigurationAfterCurrent,
      uncommittedReconfigurationsAreActive, logReconfigurationAt?,
      configurationAt?, entryAt?]
    constructor
    · intro index afterCurrent committed
      have indexIsSignature : index = 2 := by
        omega
      subst index
      simp
    · intro index afterCommit inLog configuration
      exact False.elim ((Nat.not_lt_of_ge inLog) afterCommit)
  · simp [initialState, nodeIsStart]

theorem initial_ReplicationInv (start : Node) :
    ReplicationInv (initialState start) := by
  refine ⟨start, ?_, {start}, ?_, {start}, ?_⟩
  · intro other
    by_cases otherIsStart : other = start <;>
      simp [initialState, otherIsStart]
  · simp [lastCommittedConfiguration?, committed, initialState, startLog,
      indices, logReconfigurationAt?, entryAt?, logPrefix, List.range,
      List.range.loop]
  · simp [isQuorum, committed, initialState, startLog, isLogPrefix,
      logPrefix]

theorem initial_MatchIndexBoundedByLogInv (start : Node) :
    MatchIndexBoundedByLogInv (initialState start) := by
  intro leader node leaderState sameTerm
  simp [initialState] at leaderState
  subst leader
  simp [initialState]

theorem initial_StateSafety (start : Node) :
    StateSafety (initialState start) :=
  {
    logSafety := initial_LogInv start
    oneLeaderPerTerm := initial_MoreThanOneLeaderInv start
    candidateFreshTerm := initial_CandidateTermNotInLogInv start
    electionSafety := initial_ElectionSafetyInv start
    logMatching := initial_LogMatchingInv start
    quorumLog := initial_QuorumLogInv start
    leaderCompleteness := initial_LeaderCompletenessInv start
    signatures := initial_SignatureInv start
    messageTerms := initial_MonoTermInv start
    monotonicLogs := initial_MonoLogInv start
    configurations := initial_LogConfigurationConsistentInv start
    replication := initial_ReplicationInv start
    boundedMatchIndex := initial_MatchIndexBoundedByLogInv start
  }

theorem initial_InductiveInvariant (start : Node) :
    InductiveInvariant (initialState start) :=
  {
    safety := initial_StateSafety start
    responseBounds := initial_AppendEntriesResponseBoundInv start
    configurationsWellFormed := initial_ConfigurationsWellFormedInv start
    messagesWellFormed := initial_MessagesWellFormedInv start
    noEarlyLeader := initial_NoLeaderBeforeInitialTermInv start
    logTermsStartAtInitial := initial_LogTermsAtLeastStartInv start
  }

theorem initialInductiveInvariantObligation :
    InitialInductiveInvariantObligation :=
  initial_InductiveInvariant

theorem increasing_configurationsToIndex
    (configurations : List ConfigurationAt)
    (index : Nat)
    (increasing : increasingConfigurationIndices configurations) :
    increasingConfigurationIndices
      (configurationsToIndex configurations index) := by
  exact List.Pairwise.filter _ increasing

theorem increasing_configurationsFromIndex
    (configurations : List ConfigurationAt)
    (index : Nat)
    (increasing : increasingConfigurationIndices configurations) :
    increasingConfigurationIndices
      (configurationsFromIndex configurations index) := by
  exact List.Pairwise.filter _ increasing

theorem bounded_configurationsToIndex
    (configurations : List ConfigurationAt)
    (oldLogLength index : Nat)
    (bounded :
      configurationsBoundedBy configurations oldLogLength) :
    configurationsBoundedBy
      (configurationsToIndex configurations index)
      index := by
  intro configuration member
  simp [configurationsToIndex] at member
  exact ⟨(bounded configuration member.1).1, member.2⟩

theorem bounded_configurationsFromIndex
    (configurations : List ConfigurationAt)
    (logLength index : Nat)
    (bounded :
      configurationsBoundedBy configurations logLength) :
    configurationsBoundedBy
      (configurationsFromIndex configurations index)
      logLength := by
  intro configuration member
  simp [configurationsFromIndex] at member
  exact bounded configuration member.1

theorem increasing_append_configuration
    (configurations : List ConfigurationAt)
    (configuration : ConfigurationAt)
    (increasing : increasingConfigurationIndices configurations)
    (afterAll :
      forall existing,
        existing ∈ configurations ->
          existing.index < configuration.index) :
    increasingConfigurationIndices
      (configurations ++ [configuration]) := by
  rw [increasingConfigurationIndices, List.pairwise_append]
  exact
    ⟨increasing, by simp, fun existing member _ newMember => by
      simp at newMember
      subst newMember
      exact afterAll existing member⟩

theorem bounded_append_configuration
    (configurations : List ConfigurationAt)
    (configuration : ConfigurationAt)
    (oldLogLength newLogLength : Nat)
    (bounded :
      configurationsBoundedBy configurations oldLogLength)
    (oldWithinNew : oldLogLength <= newLogLength)
    (configurationPositive : 0 < configuration.index)
    (configurationWithin : configuration.index <= newLogLength) :
    configurationsBoundedBy
      (configurations ++ [configuration])
      newLogLength := by
  intro existing member
  simp at member
  rcases member with oldMember | isNew
  · exact
      ⟨(bounded existing oldMember).1,
        Nat.le_trans (bounded existing oldMember).2 oldWithinNew⟩
  · subst existing
    exact ⟨configurationPositive, configurationWithin⟩

theorem mem_upsertConfiguration
    (configurations : List ConfigurationAt)
    (update existing : ConfigurationAt)
    (member :
      existing ∈ upsertConfiguration configurations update) :
    Or (existing = update) (existing ∈ configurations) := by
  induction configurations with
  | nil =>
      simp [upsertConfiguration] at member
      exact Or.inl member
  | cons head tail inductionHypothesis =>
      by_cases beforeHead : update.index < head.index
      · rw [upsertConfiguration, if_pos beforeHead] at member
        rw [List.mem_cons, List.mem_cons] at member
        rcases member with isUpdate | isHead | inTail
        · exact Or.inl isUpdate
        · exact Or.inr (by simp [isHead])
        · exact Or.inr (by simp [inTail])
      · by_cases sameIndex : update.index = head.index
        · rw [upsertConfiguration, if_neg beforeHead, if_pos sameIndex]
            at member
          rw [List.mem_cons] at member
          rcases member with isUpdate | inTail
          · exact Or.inl isUpdate
          · exact Or.inr (by simp [inTail])
        · rw [upsertConfiguration, if_neg beforeHead, if_neg sameIndex]
            at member
          rw [List.mem_cons] at member
          rcases member with isHead | inUpdatedTail
          · exact Or.inr (by simp [isHead])
          · rcases inductionHypothesis inUpdatedTail with isUpdate | inTail
            · exact Or.inl isUpdate
            · exact Or.inr (by simp [inTail])

theorem increasing_upsertConfiguration
    (configurations : List ConfigurationAt)
    (update : ConfigurationAt)
    (increasing : increasingConfigurationIndices configurations) :
    increasingConfigurationIndices
      (upsertConfiguration configurations update) := by
  induction configurations with
  | nil =>
      simp [upsertConfiguration, increasingConfigurationIndices]
  | cons head tail inductionHypothesis =>
      rw [increasingConfigurationIndices] at increasing ⊢
      rw [List.pairwise_cons] at increasing
      simp only [upsertConfiguration]
      split
      · apply List.Pairwise.cons
        · intro existing member
          simp at member
          rcases member with isHead | inTail
          · subst existing
            assumption
          · exact Nat.lt_trans (by assumption) (increasing.1 _ inTail)
        · exact List.Pairwise.cons increasing.1 increasing.2
      · split
        · apply List.Pairwise.cons
          · intro existing inTail
            have sameIndex : update.index = head.index := by omega
            rw [sameIndex]
            exact increasing.1 existing inTail
          · exact increasing.2
        · apply List.Pairwise.cons
          · intro existing member
            rcases
              mem_upsertConfiguration tail update existing member with
              isUpdate | inTail
            · subst existing
              omega
            · exact increasing.1 existing inTail
          · exact inductionHypothesis increasing.2

theorem bounded_upsertConfiguration
    (configurations : List ConfigurationAt)
    (update : ConfigurationAt)
    (logLength : Nat)
    (bounded :
      configurationsBoundedBy configurations logLength)
    (updatePositive : 0 < update.index)
    (updateWithin : update.index <= logLength) :
    configurationsBoundedBy
      (upsertConfiguration configurations update)
      logLength := by
  intro existing member
  rcases
    mem_upsertConfiguration configurations update existing member with
    isUpdate | oldMember
  · subst existing
    exact ⟨updatePositive, updateWithin⟩
  · exact bounded existing oldMember

theorem increasing_overrideConfigurations
    (configurations updates : List ConfigurationAt)
    (increasing : increasingConfigurationIndices configurations) :
    increasingConfigurationIndices
      (overrideConfigurations configurations updates) := by
  induction updates generalizing configurations with
  | nil =>
      simpa [overrideConfigurations] using increasing
  | cons update rest inductionHypothesis =>
      simp [overrideConfigurations, List.foldl_cons]
      apply inductionHypothesis
      exact increasing_upsertConfiguration configurations update increasing

theorem bounded_overrideConfigurations
    (configurations updates : List ConfigurationAt)
    (logLength : Nat)
    (bounded :
      configurationsBoundedBy configurations logLength)
    (updatesBounded :
      configurationsBoundedBy updates logLength) :
    configurationsBoundedBy
      (overrideConfigurations configurations updates)
      logLength := by
  induction updates generalizing configurations with
  | nil =>
      simpa [overrideConfigurations] using bounded
  | cons update rest inductionHypothesis =>
      simp [overrideConfigurations, List.foldl_cons]
      apply inductionHypothesis
      · apply bounded_upsertConfiguration configurations update logLength
          bounded
        · exact (updatesBounded update (by simp)).1
        · exact (updatesBounded update (by simp)).2
      · intro existing member
        exact updatesBounded existing (by simp [member])

theorem mem_configurationsInEntriesAux
    (firstIndex : Nat)
    (entries : List Entry)
    (configuration : ConfigurationAt)
    (member :
      configuration ∈ configurationsInEntriesAux firstIndex entries) :
    And
      (firstIndex <= configuration.index)
      (configuration.index < firstIndex + entries.length) := by
  induction entries generalizing firstIndex with
  | nil =>
      simp [configurationsInEntriesAux] at member
  | cons entry rest inductionHypothesis =>
      cases content : entry.content with
      | entry =>
          simp [configurationsInEntriesAux, content] at member
          have := inductionHypothesis (firstIndex + 1) member
          constructor
          · exact Nat.le_trans (by omega) this.1
          · simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
              this.2
      | signature =>
          simp [configurationsInEntriesAux, content] at member
          have := inductionHypothesis (firstIndex + 1) member
          constructor
          · exact Nat.le_trans (by omega) this.1
          · simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
              this.2
      | reconfiguration nodes =>
          simp [configurationsInEntriesAux, content] at member
          rcases member with isHead | inTail
          · subst configuration
            simp
          · have := inductionHypothesis (firstIndex + 1) inTail
            constructor
            · exact Nat.le_trans (by omega) this.1
            · simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
                this.2

theorem increasing_configurationsInEntriesAux
    (firstIndex : Nat)
    (entries : List Entry) :
    increasingConfigurationIndices
      (configurationsInEntriesAux firstIndex entries) := by
  induction entries generalizing firstIndex with
  | nil =>
      simp [configurationsInEntriesAux, increasingConfigurationIndices]
  | cons entry rest inductionHypothesis =>
      cases content : entry.content with
      | entry =>
          simpa [configurationsInEntriesAux, content] using
            inductionHypothesis (firstIndex + 1)
      | signature =>
          simpa [configurationsInEntriesAux, content] using
            inductionHypothesis (firstIndex + 1)
      | reconfiguration nodes =>
          rw [increasingConfigurationIndices]
          simp [configurationsInEntriesAux, content, List.pairwise_cons]
          constructor
          · intro configuration member
            have bounds :=
              mem_configurationsInEntriesAux
                (firstIndex + 1)
                rest
                configuration
                member
            omega
          · exact inductionHypothesis (firstIndex + 1)

theorem increasing_configurationsInEntries
    (firstIndex : Nat)
    (entries : List Entry) :
    increasingConfigurationIndices
      (configurationsInEntries firstIndex entries) :=
  increasing_configurationsInEntriesAux firstIndex entries

theorem bounded_configurationsInEntries
    (previousIndex : Nat)
    (entries : List Entry) :
    configurationsBoundedBy
      (configurationsInEntries (previousIndex + 1) entries)
      (previousIndex + entries.length) := by
  intro configuration member
  have bounds :=
    mem_configurationsInEntriesAux
      (previousIndex + 1)
      entries
      configuration
      member
  omega

theorem configurationsBoundedBy_mono
    (configurations : List ConfigurationAt)
    (oldLength newLength : Nat)
    (bounded : configurationsBoundedBy configurations oldLength)
    (lengthMonotonic : oldLength <= newLength) :
    configurationsBoundedBy configurations newLength := by
  intro configuration member
  exact
    ⟨(bounded configuration member).1,
      Nat.le_trans (bounded configuration member).2 lengthMonotonic⟩

theorem configurationsWellFormed_of_unchangedConfigurations
    (before after : State)
    (wellFormed : ConfigurationsWellFormedInv before)
    (configurationsUnchanged :
      forall node,
        after.configurations node = before.configurations node)
    (logLengthMonotonic :
      forall node,
        (before.log node).length <= (after.log node).length) :
    ConfigurationsWellFormedInv after := by
  intro node
  rw [configurationsUnchanged node]
  exact
    ⟨(wellFormed node).1,
      configurationsBoundedBy_mono
        (before.configurations node)
        (before.log node).length
        (after.log node).length
        (wellFormed node).2
        (logLengthMonotonic node)⟩

theorem timeout_preserves_ConfigurationsWellFormedInv
    (state : State)
    (candidate : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.timeout candidate)) := by
  apply configurationsWellFormed_of_unchangedConfigurations state _ wellFormed
  · intro node
    simp [next, rawNext, nextTimeout]
  · intro node
    simp [next, rawNext, nextTimeout]

theorem requestVote_preserves_ConfigurationsWellFormedInv
    (state : State)
    (source dest : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.requestVote source dest)) := by
  apply configurationsWellFormed_of_unchangedConfigurations state _ wellFormed
  · intro node
    simp [next, rawNext, nextRequestVote]
  · intro node
    simp [next, rawNext, nextRequestVote]

theorem appendEntries_preserves_ConfigurationsWellFormedInv
    (state : State)
    (source dest : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.appendEntries source dest)) := by
  apply configurationsWellFormed_of_unchangedConfigurations state _ wellFormed
  · intro node
    simp [next, rawNext, nextAppendEntries]
  · intro node
    simp [next, rawNext, nextAppendEntries]

theorem clientRequest_preserves_ConfigurationsWellFormedInv
    (state : State)
    (leader : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.clientRequest leader)) := by
  apply configurationsWellFormed_of_unchangedConfigurations state _ wellFormed
  · intro node
    simp [next, rawNext, nextClientRequest]
  · intro node
    by_cases nodeIsLeader : node = leader
    · subst node
      simp [next, rawNext, nextClientRequest, updateNode]
    · simp [next, rawNext, nextClientRequest, updateNode, nodeIsLeader]

theorem sign_preserves_ConfigurationsWellFormedInv
    (state : State)
    (leader : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.signCommittableMessages leader)) := by
  apply configurationsWellFormed_of_unchangedConfigurations state _ wellFormed
  · intro node
    simp [next, rawNext, nextSignCommittableMessages]
  · intro node
    by_cases nodeIsLeader : node = leader
    · subst node
      simp [next, rawNext, nextSignCommittableMessages, updateNode]
    · simp [next, rawNext, nextSignCommittableMessages, updateNode,
        nodeIsLeader]

theorem changeConfiguration_preserves_ConfigurationsWellFormedInv
    (state : State)
    (leader : Node)
    (configuration : Configuration)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.changeConfiguration leader configuration)) := by
  intro node
  by_cases nodeIsLeader : node = leader
  · subst node
    let nextLog :=
      state.log leader ++
        [{
          term := state.currentTerm leader
          content := .reconfiguration configuration
        }]
    let nextConfiguration : ConfigurationAt :=
      { index := nextLog.length, nodes := configuration }
    have targetWellFormed :
        And
          (increasingConfigurationIndices
            (state.configurations leader ++ [nextConfiguration]))
          (configurationsBoundedBy
            (state.configurations leader ++ [nextConfiguration])
            nextLog.length) := by
      constructor
      · apply increasing_append_configuration
          (state.configurations leader)
          nextConfiguration
          (wellFormed leader).1
        intro existing member
        have existingBound := (wellFormed leader).2 existing member
        dsimp [nextConfiguration, nextLog]
        simp
        omega
      · apply bounded_append_configuration
          (state.configurations leader)
          nextConfiguration
          (state.log leader).length
          nextLog.length
          (wellFormed leader).2
        · dsimp [nextLog]
          simp
        · dsimp [nextConfiguration, nextLog]
          simp
        · exact Nat.le_refl _
    simpa [next, rawNext, nextChangeConfiguration, updateNode,
      nextLog, nextConfiguration] using targetWellFormed
  · simpa [next, rawNext, nextChangeConfiguration, updateNode,
      nodeIsLeader] using wellFormed node

theorem becomeLeader_preserves_ConfigurationsWellFormedInv
    (state : State)
    (leader : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.becomeLeader leader)) := by
  intro node
  by_cases nodeIsLeader : node = leader
  · subst node
    let nextLog := committable state leader
    have targetWellFormed :
        And
          (increasingConfigurationIndices
            (configurationsToIndex
              (state.configurations leader)
              nextLog.length))
          (configurationsBoundedBy
            (configurationsToIndex
              (state.configurations leader)
              nextLog.length)
            nextLog.length) :=
      ⟨increasing_configurationsToIndex
          (state.configurations leader)
          nextLog.length
          (wellFormed leader).1,
        bounded_configurationsToIndex
          (state.configurations leader)
          (state.log leader).length
          nextLog.length
          (wellFormed leader).2⟩
    simpa [next, rawNext, nextBecomeLeader, updateNode, nextLog] using
      targetWellFormed
  · simpa [next, rawNext, nextBecomeLeader, updateNode, nodeIsLeader] using
      wellFormed node

theorem advanceCommitIndex_preserves_ConfigurationsWellFormedInv
    (state : State)
    (leader : Node)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (next state (.advanceCommitIndex leader)) := by
  intro node
  by_cases nodeIsLeader : node = leader
  · subst node
    let nextCommitIndex := highestCommittableIndex state leader
    let nextConfigurations :=
      match nextConfigurationIndex? (state.configurations leader) with
      | some nextIndex =>
          if nextIndex <= nextCommitIndex then
            configurationsFromIndex
              (state.configurations leader)
              (lastConfigurationToIndex
                (state.configurations leader)
                nextCommitIndex)
          else
            state.configurations leader
      | none => state.configurations leader
    have targetWellFormed :
        And
          (increasingConfigurationIndices nextConfigurations)
          (configurationsBoundedBy
            nextConfigurations
            (state.log leader).length) := by
      dsimp [nextConfigurations]
      cases nextIndex :
          nextConfigurationIndex? (state.configurations leader) with
      | none =>
          simpa [nextIndex] using wellFormed leader
      | some index =>
          by_cases committed : index <= nextCommitIndex
          · simp [committed]
            exact
              ⟨increasing_configurationsFromIndex
                  (state.configurations leader)
                  (lastConfigurationToIndex
                    (state.configurations leader)
                    nextCommitIndex)
                  (wellFormed leader).1,
                bounded_configurationsFromIndex
                  (state.configurations leader)
                  (state.log leader).length
                  (lastConfigurationToIndex
                    (state.configurations leader)
                    nextCommitIndex)
                  (wellFormed leader).2⟩
          · simpa [committed] using wellFormed leader
    simpa [next, rawNext, nextAdvanceCommitIndex, updateNode,
      nextCommitIndex, nextConfigurations] using targetWellFormed
  · simpa [next, rawNext, nextAdvanceCommitIndex, updateNode,
      nodeIsLeader] using wellFormed node

theorem conflictRollback_preserves_ConfigurationsWellFormedInv
    (state : State)
    (dest : Node)
    (previousIndex : Nat)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (conflictRollback state dest previousIndex) := by
  intro node
  by_cases nodeIsDest : node = dest
  · subst node
    let nextLog := (state.log dest).take previousIndex
    have targetWellFormed :
        And
          (increasingConfigurationIndices
            (configurationsToIndex
              (state.configurations dest)
              nextLog.length))
          (configurationsBoundedBy
            (configurationsToIndex
              (state.configurations dest)
              nextLog.length)
            nextLog.length) :=
      ⟨increasing_configurationsToIndex
          (state.configurations dest)
          nextLog.length
          (wellFormed dest).1,
        bounded_configurationsToIndex
          (state.configurations dest)
          (state.log dest).length
          nextLog.length
          (wellFormed dest).2⟩
    simpa [conflictRollback, updateNode, nextLog] using
      targetWellFormed
  · simpa [conflictRollback, updateNode, nodeIsDest] using
      wellFormed node

theorem appendEntriesAlreadyDone_preserves_ConfigurationsWellFormedInv
    (state : State)
    (message : Message)
    (previousIndex : Nat)
    (entries : List Entry)
    (leaderCommitIndex : Nat)
    (wellFormed : ConfigurationsWellFormedInv state) :
    ConfigurationsWellFormedInv
      (nextAppendEntriesAlreadyDone
        state message previousIndex entries leaderCommitIndex) := by
  intro node
  by_cases nodeIsDest : node = message.dest
  · subst node
    let requestEndIndex := previousIndex + entries.length
    let nextCommitIndex :=
      max
        (maxCommittableIndexAt
          (state.log message.dest)
          (min leaderCommitIndex requestEndIndex))
        (state.commitIndex message.dest)
    let nextConfigurationIndex :=
      lastConfigurationToIndex
        (state.configurations message.dest)
        nextCommitIndex
    have targetWellFormed :
        And
          (increasingConfigurationIndices
            (configurationsFromIndex
              (state.configurations message.dest)
              nextConfigurationIndex))
          (configurationsBoundedBy
            (configurationsFromIndex
              (state.configurations message.dest)
              nextConfigurationIndex)
            (state.log message.dest).length) :=
      ⟨increasing_configurationsFromIndex
          (state.configurations message.dest)
          nextConfigurationIndex
          (wellFormed message.dest).1,
        bounded_configurationsFromIndex
          (state.configurations message.dest)
          (state.log message.dest).length
          nextConfigurationIndex
          (wellFormed message.dest).2⟩
    simpa [nextAppendEntriesAlreadyDone, updateNode, requestEndIndex,
      nextCommitIndex, nextConfigurationIndex] using targetWellFormed
  · simpa [nextAppendEntriesAlreadyDone, updateNode, nodeIsDest] using
      wellFormed node

theorem appendEntriesNoConflict_preserves_ConfigurationsWellFormedInv
    (state : State)
    (message : Message)
    (previousIndex : Nat)
    (entries : List Entry)
    (leaderCommitIndex : Nat)
    (wellFormed : ConfigurationsWellFormedInv state)
    (noConflict :
      appendEntriesNoConflictGuard
        state message.dest previousIndex entries = true) :
    ConfigurationsWellFormedInv
      (nextAppendEntriesNoConflict
        state message previousIndex entries leaderCommitIndex) := by
  simp [appendEntriesNoConflictGuard] at noConflict
  intro node
  by_cases nodeIsDest : node = message.dest
  · subst node
    let nextLog :=
      (state.log message.dest).take previousIndex ++ entries
    have nextLogLength :
        nextLog.length = previousIndex + entries.length := by
      simp [nextLog, Nat.min_eq_left noConflict.1.1.2]
    have oldLogWithin :
        (state.log message.dest).length <= nextLog.length := by
      rw [nextLogLength]
      exact Nat.le_of_lt noConflict.1.2
    let updates :=
      configurationsInEntries (previousIndex + 1) entries
    let extendedConfigurations :=
      overrideConfigurations
        (state.configurations message.dest)
        updates
    let requestEndIndex := previousIndex + entries.length
    let nextCommitIndex :=
      max
        (maxCommittableIndexAt
          nextLog
          (min leaderCommitIndex requestEndIndex))
        (state.commitIndex message.dest)
    let nextConfigurationIndex :=
      lastConfigurationToIndex extendedConfigurations nextCommitIndex
    have extendedWellFormed :
        And
          (increasingConfigurationIndices extendedConfigurations)
          (configurationsBoundedBy
            extendedConfigurations
            nextLog.length) := by
      constructor
      · apply increasing_overrideConfigurations
          (state.configurations message.dest)
          updates
          (wellFormed message.dest).1
      · apply bounded_overrideConfigurations
          (state.configurations message.dest)
          updates
          nextLog.length
        · exact configurationsBoundedBy_mono
            (state.configurations message.dest)
            (state.log message.dest).length
            nextLog.length
            (wellFormed message.dest).2
            oldLogWithin
        · dsimp [updates]
          rw [nextLogLength]
          exact bounded_configurationsInEntries previousIndex entries
    have targetWellFormed :
        And
          (increasingConfigurationIndices
            (configurationsFromIndex
              extendedConfigurations
              nextConfigurationIndex))
          (configurationsBoundedBy
            (configurationsFromIndex
              extendedConfigurations
              nextConfigurationIndex)
            nextLog.length) :=
      ⟨increasing_configurationsFromIndex
          extendedConfigurations
          nextConfigurationIndex
          extendedWellFormed.1,
        bounded_configurationsFromIndex
          extendedConfigurations
          nextLog.length
          nextConfigurationIndex
          extendedWellFormed.2⟩
    simpa [nextAppendEntriesNoConflict, updateNode, nextLog, updates,
      extendedConfigurations, requestEndIndex, nextCommitIndex,
      nextConfigurationIndex] using targetWellFormed
  · simpa [nextAppendEntriesNoConflict, updateNode, nodeIsDest] using
      wellFormed node

theorem receive_preserves_ConfigurationsWellFormedInv
    (state : State)
    (dest source : Node)
    (kind : ReceiveKind)
    (wellFormed : ConfigurationsWellFormedInv state)
    (enabled : Enabled state (.receive dest source kind)) :
    ConfigurationsWellFormedInv
      (next state (.receive dest source kind)) := by
  cases hmessage : headMessage? state dest source with
  | none =>
      simpa [next, rawNext, nextReceive, hmessage] using wellFormed
  | some message =>
      cases kind with
      | appendEntriesAlreadyDone =>
          cases hbody : message.body with
          | appendEntriesRequest previousIndex previousTerm entries commitIndex =>
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                appendEntriesAlreadyDone_preserves_ConfigurationsWellFormedInv
                  state
                  message
                  previousIndex
                  entries
                  commitIndex
                  wellFormed
          | _ =>
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                wellFormed
      | appendEntriesNoConflict =>
          cases hbody : message.body with
          | appendEntriesRequest previousIndex previousTerm entries commitIndex =>
              have branchEnabled := enabled
              simp [Enabled, actionEnabled, hmessage, receiveBranchEnabled,
                hbody] at branchEnabled
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                appendEntriesNoConflict_preserves_ConfigurationsWellFormedInv
                  state
                  message
                  previousIndex
                  entries
                  commitIndex
                  wellFormed
                  branchEnabled.2.2
          | _ =>
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                wellFormed
      | appendEntriesConflictThenAlreadyDone =>
          cases hbody : message.body with
          | appendEntriesRequest previousIndex previousTerm entries commitIndex =>
              have branchEnabled := enabled
              simp [Enabled, actionEnabled, hmessage, receiveBranchEnabled,
                hbody] at branchEnabled
              have destMatches : message.dest = dest := branchEnabled.1.1
              subst dest
              have rolledWellFormed :=
                conflictRollback_preserves_ConfigurationsWellFormedInv
                  state
                  message.dest
                  previousIndex
                  wellFormed
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                appendEntriesAlreadyDone_preserves_ConfigurationsWellFormedInv
                  (conflictRollback state message.dest previousIndex)
                  message
                  previousIndex
                  entries
                  commitIndex
                  rolledWellFormed
          | _ =>
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                wellFormed
      | appendEntriesConflictThenNoConflict =>
          cases hbody : message.body with
          | appendEntriesRequest previousIndex previousTerm entries commitIndex =>
              have branchEnabled := enabled
              simp [Enabled, actionEnabled, hmessage, receiveBranchEnabled,
                hbody] at branchEnabled
              have destMatches : message.dest = dest := branchEnabled.1.1
              subst dest
              have rolledWellFormed :=
                conflictRollback_preserves_ConfigurationsWellFormedInv
                  state
                  message.dest
                  previousIndex
                  wellFormed
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                appendEntriesNoConflict_preserves_ConfigurationsWellFormedInv
                  (conflictRollback state message.dest previousIndex)
                  message
                  previousIndex
                  entries
                  commitIndex
                  rolledWellFormed
                  branchEnabled.2.2
          | _ =>
              simpa [next, rawNext, nextReceive, hmessage, hbody] using
                wellFormed
      | _ =>
          cases hbody : message.body <;>
            simp_all [ConfigurationsWellFormedInv, next, rawNext,
              nextReceive]
          all_goals
            split <;> simp_all

theorem configurationsWellFormed_step
    (state : State)
    (action : Action)
    (wellFormed : ConfigurationsWellFormedInv state)
    (enabled : Enabled state action) :
    ConfigurationsWellFormedInv (next state action) := by
  cases action with
  | timeout candidate =>
      exact timeout_preserves_ConfigurationsWellFormedInv
        state candidate wellFormed
  | requestVote source dest =>
      exact requestVote_preserves_ConfigurationsWellFormedInv
        state source dest wellFormed
  | appendEntries source dest =>
      exact appendEntries_preserves_ConfigurationsWellFormedInv
        state source dest wellFormed
  | becomeLeader leader =>
      exact becomeLeader_preserves_ConfigurationsWellFormedInv
        state leader wellFormed
  | clientRequest leader =>
      exact clientRequest_preserves_ConfigurationsWellFormedInv
        state leader wellFormed
  | signCommittableMessages leader =>
      exact sign_preserves_ConfigurationsWellFormedInv
        state leader wellFormed
  | changeConfiguration leader configuration =>
      exact changeConfiguration_preserves_ConfigurationsWellFormedInv
        state leader configuration wellFormed
  | advanceCommitIndex leader =>
      exact advanceCommitIndex_preserves_ConfigurationsWellFormedInv
        state leader wellFormed
  | receive dest source kind =>
      exact receive_preserves_ConfigurationsWellFormedInv
        state dest source kind wellFormed enabled

/-- Initial-state checkpoint for three public safety invariants. -/
theorem initialSafetyCheckpoint (start : Node) :
    And
      (LogInv (initialState start))
      (And
        (MoreThanOneLeaderInv (initialState start))
        (SignatureInv (initialState start))) := by
  exact
    ⟨initial_LogInv start,
      initial_MoreThanOneLeaderInv start,
      initial_SignatureInv start⟩

@[simp]
theorem enqueue_preserves_MessageChannelsWellFormed
    (messages : NodeMatrix (List Message))
    (message : Message)
    (wellFormed : MessageChannelsWellFormed messages) :
    MessageChannelsWellFormed (enqueue messages message) := by
  intro dest source queued queuedMem
  by_cases destMatches : dest = message.dest
  · subst dest
    by_cases sourceMatches : source = message.source
    · subst source
      by_cases duplicate :
          (messages message.dest message.source).any
            (fun existing => existing == message)
      · simp [enqueue, update₂, duplicate] at queuedMem
        exact wellFormed _ _ queued queuedMem
      · simp [enqueue, update₂, duplicate] at queuedMem
        rcases queuedMem with queuedMem | queuedIsMessage
        · exact wellFormed _ _ queued queuedMem
        · subst queued
          exact ⟨rfl, rfl⟩
    · simp [enqueue, update₂, sourceMatches] at queuedMem
      exact wellFormed _ _ queued queuedMem
  · simp [enqueue, update₂, destMatches] at queuedMem
    exact wellFormed _ _ queued queuedMem

@[simp]
theorem discard_preserves_MessageChannelsWellFormed
    (messages : NodeMatrix (List Message))
    (message : Message)
    (wellFormed : MessageChannelsWellFormed messages) :
    MessageChannelsWellFormed (discard messages message) := by
  intro dest source queued queuedMem
  by_cases destMatches : dest = message.dest
  · subst dest
    by_cases sourceMatches : source = message.source
    · subst source
      simp [Model.discard, update₂] at queuedMem
      exact wellFormed _ _ queued (List.mem_of_mem_erase queuedMem)
    · simp [Model.discard, update₂, sourceMatches] at queuedMem
      exact wellFormed _ _ queued queuedMem
  · simp [Model.discard, update₂, destMatches] at queuedMem
    exact wellFormed _ _ queued queuedMem

@[simp]
theorem reply_preserves_MessageChannelsWellFormed
    (messages : NodeMatrix (List Message))
    (response request : Message)
    (wellFormed : MessageChannelsWellFormed messages) :
    MessageChannelsWellFormed (reply messages response request) := by
  apply discard_preserves_MessageChannelsWellFormed
  exact enqueue_preserves_MessageChannelsWellFormed _ _ wellFormed

theorem enqueue_preserves_MonoTermInv
    (state : State)
    (message : Message)
    (monoTerm : MonoTermInv state)
    (messageBound :
      message.term <= state.currentTerm message.source) :
    forall dest source queued,
      queued ∈ (enqueue state.messages message) dest source ->
        queued.term <= state.currentTerm queued.source := by
  intro dest source queued queuedMem
  by_cases destMatches : dest = message.dest
  · subst dest
    by_cases sourceMatches : source = message.source
    · subst source
      by_cases duplicate :
          (state.messages message.dest message.source).any
            (fun existing => existing == message)
      · simp [enqueue, update₂, duplicate] at queuedMem
        exact monoTerm _ _ queued queuedMem
      · simp [enqueue, update₂, duplicate] at queuedMem
        rcases queuedMem with queuedMem | queuedIsMessage
        · exact monoTerm _ _ queued queuedMem
        · subst queued
          exact messageBound
    · simp [enqueue, update₂, sourceMatches] at queuedMem
      exact monoTerm _ _ queued queuedMem
  · simp [enqueue, update₂, destMatches] at queuedMem
    exact monoTerm _ _ queued queuedMem

theorem discard_preserves_MonoTermInv
    (state : State)
    (message : Message)
    (monoTerm : MonoTermInv state) :
    forall dest source queued,
      queued ∈ (Model.discard state.messages message) dest source ->
        queued.term <= state.currentTerm queued.source := by
  intro dest source queued queuedMem
  by_cases destMatches : dest = message.dest
  · subst dest
    by_cases sourceMatches : source = message.source
    · subst source
      simp [Model.discard, update₂] at queuedMem
      exact monoTerm _ _ queued (List.mem_of_mem_erase queuedMem)
    · simp [Model.discard, update₂, sourceMatches] at queuedMem
      exact monoTerm _ _ queued queuedMem
  · simp [Model.discard, update₂, destMatches] at queuedMem
    exact monoTerm _ _ queued queuedMem

theorem reply_preserves_MonoTermInv
    (state : State)
    (response request : Message)
    (monoTerm : MonoTermInv state)
    (responseBound :
      response.term <= state.currentTerm response.source) :
    forall dest source queued,
      queued ∈ (reply state.messages response request) dest source ->
        queued.term <= state.currentTerm queued.source := by
  intro dest source queued queuedMem
  apply
    discard_preserves_MonoTermInv
      { state with messages := enqueue state.messages response }
      request
  · intro queuedDest queuedSource existing existingMem
    exact enqueue_preserves_MonoTermInv
      state response monoTerm responseBound
      queuedDest queuedSource existing existingMem
  · exact queuedMem

theorem monoTerm_of_currentTerm_mono
    (before after : State)
    (monoTerm : MonoTermInv before)
    (messagesUnchanged : after.messages = before.messages)
    (termsMonotonic :
      forall node,
        before.currentTerm node <= after.currentTerm node) :
    MonoTermInv after := by
  intro dest source message messageQueued
  rw [messagesUnchanged] at messageQueued
  exact Nat.le_trans
    (monoTerm dest source message messageQueued)
    (termsMonotonic message.source)

theorem monoTerm_of_discard
    (before after : State)
    (message : Message)
    (monoTerm : MonoTermInv before)
    (messagesAfter :
      after.messages = Model.discard before.messages message)
    (termsAfter : after.currentTerm = before.currentTerm) :
    MonoTermInv after := by
  intro dest source queued queuedMem
  rw [messagesAfter] at queuedMem
  rw [termsAfter]
  exact
    discard_preserves_MonoTermInv
      before message monoTerm
      dest source queued queuedMem

theorem monoTerm_of_reply
    (before after : State)
    (response request : Message)
    (monoTerm : MonoTermInv before)
    (responseBound :
      response.term <= before.currentTerm response.source)
    (messagesAfter :
      after.messages = reply before.messages response request)
    (termsAfter : after.currentTerm = before.currentTerm) :
    MonoTermInv after := by
  intro dest source queued queuedMem
  rw [messagesAfter] at queuedMem
  rw [termsAfter]
  exact
    reply_preserves_MonoTermInv
      before response request monoTerm responseBound
      dest source queued queuedMem

theorem entryAt?_mem
    (entries : List Entry)
    (index : Nat)
    (entry : Entry)
    (atIndex : entryAt? entries index = some entry) :
    entry ∈ entries := by
  unfold entryAt? at atIndex
  split at atIndex
  · contradiction
  · exact List.mem_of_getElem? atIndex

theorem monoLogEntries_member_le_lastTerm
    (entries : List Entry)
    (entry : Entry)
    (mono : monoLogEntries entries)
    (member : entry ∈ entries) :
    entry.term <=
      (entries.getLast?.map fun current => current.term).getD 0 := by
  induction entries generalizing entry with
  | nil =>
      simp at member
  | cons first rest inductionHypothesis =>
      cases rest with
      | nil =>
          simp at member
          subst entry
          simp
      | cons second tail =>
          simp [monoLogEntries] at mono
          simp at member
          rcases member with isFirst | inTail
          · subst entry
            have firstLeSecond : first.term <= second.term := by
              rcases mono.1 with sameTerm | laterTerm
              · exact Nat.le_of_eq sameTerm
              · exact Nat.le_of_lt laterTerm.1
            have secondLeLast :=
              inductionHypothesis
                second
                mono.2
                (by simp)
            exact Nat.le_trans firstLeSecond (by simpa using secondLeLast)
          · exact inductionHypothesis entry mono.2 (by simpa using inTail)

theorem logEntryTerm_le_currentTerm
    (state : State)
    (monoLog : MonoLogInv state)
    (node : Node)
    (index : Nat)
    (entry : Entry)
    (atIndex : entryAt? (state.log node) index = some entry) :
    entry.term <= state.currentTerm node := by
  have member := entryAt?_mem (state.log node) index entry atIndex
  cases logShape : state.log node with
  | nil =>
      rw [logShape] at member
      simp at member
  | cons first rest =>
      have nodeMono := monoLog node (by
        rw [logShape]
        rfl)
      exact Nat.le_trans
        (monoLogEntries_member_le_lastTerm
          (state.log node)
          entry
          nodeMono.2
          member)
        nodeMono.1

theorem appendEntriesRejectResponse_term_le_current
    (state : State)
    (message response : Message)
    (previousIndex previousTerm : Nat)
    (monoLog : MonoLogInv state)
    (logTerms : LogTermsAtLeastStartInv state)
    (responseEq :
      appendEntriesRejectResponse?
        state message previousIndex previousTerm = some response) :
    response.term <= state.currentTerm response.source := by
  unfold appendEntriesRejectResponse? at responseEq
  dsimp only at responseEq
  split at responseEq
  · contradiction
  · split at responseEq
    · have responseIsCurrent := Option.some.inj responseEq
      subst response
      simp
    · split at responseEq
      · contradiction
      · let comparisonTerm :=
          if previousIndex = 0 ||
              (state.log message.dest).length < previousIndex then
            0
          else
            (state.log message.dest).getLast?.map (·.term) |>.getD 0
        change
          (if comparisonTerm = previousTerm then
            none
          else if comparisonTerm = 0 then
            some
              {
                term := state.currentTerm message.dest
                source := message.dest
                dest := message.source
                body :=
                  .appendEntriesResponse false
                    (state.log message.dest).length
              }
          else
            let lastIndex :=
              findHighestPossibleMatch
                (state.log message.dest)
                previousIndex
                previousTerm
            let responseTerm :=
              if lastIndex = 0 then
                startTerm
              else
                (entryAt? (state.log message.dest) lastIndex).map
                    (·.term) |>.getD startTerm
            some
              {
                term := responseTerm
                source := message.dest
                dest := message.source
                body := .appendEntriesResponse false lastIndex
              }) =
            some response at responseEq
        by_cases sameTerm : comparisonTerm = previousTerm
        · simp [sameTerm] at responseEq
        · simp [sameTerm] at responseEq
          by_cases zeroComparison : comparisonTerm = 0
          · simp [zeroComparison] at responseEq
            subst response
            simp
          · simp [zeroComparison] at responseEq
            subst response
            let lastIndex :=
              findHighestPossibleMatch
                (state.log message.dest)
                previousIndex
                previousTerm
            have startLeCurrent :
                startTerm <= state.currentTerm message.dest := by
              by_cases invalidPrevious :
                  previousIndex = 0 ||
                    (state.log message.dest).length < previousIndex
              · simp [comparisonTerm, invalidPrevious] at zeroComparison
              · simp [comparisonTerm, invalidPrevious] at zeroComparison
                cases lastEntry : (state.log message.dest).getLast? with
                | none =>
                    simp [lastEntry] at zeroComparison
                | some entry =>
                    have decomposition :=
                      List.getLast?_eq_some_iff.mp lastEntry
                    rcases decomposition with ⟨logEntries, logShape⟩
                    have entryMember :
                        entry ∈ state.log message.dest := by
                      rw [logShape]
                      simp
                    have startLeEntry :=
                      logTerms message.dest entry entryMember
                    have nodeMono :=
                      monoLog message.dest (by
                        rw [logShape]
                        cases logEntries <;> rfl)
                    have entryLeCurrent :
                        entry.term <= state.currentTerm message.dest := by
                      simpa [lastEntry] using nodeMono.1
                    exact Nat.le_trans startLeEntry entryLeCurrent
            change
              (if lastIndex = 0 then
                startTerm
              else
                (entryAt? (state.log message.dest) lastIndex).map
                    (·.term) |>.getD startTerm) <=
                state.currentTerm message.dest
            split
            · exact startLeCurrent
            · cases responseEntry :
                  entryAt? (state.log message.dest) lastIndex with
              | none =>
                  simp
                  exact startLeCurrent
              | some entry =>
                  simp
                  exact logEntryTerm_le_currentTerm
                    state
                    monoLog
                    message.dest
                    lastIndex
                    entry
                    responseEntry

theorem monoTerm_step
    (state : State)
    (action : Action)
    (monoTerm : MonoTermInv state)
    (monoLog : MonoLogInv state)
    (logTerms : LogTermsAtLeastStartInv state)
    (enabled : Enabled state action) :
    MonoTermInv (next state action) := by
  cases action with
  | timeout candidate =>
      apply monoTerm_of_currentTerm_mono state _ monoTerm
      · rfl
      · intro node
        by_cases nodeIsCandidate : node = candidate
        · subst node
          simp [next, rawNext, nextTimeout]
        · simp [next, rawNext, nextTimeout, nodeIsCandidate]
  | requestVote source dest =>
      intro queuedDest queuedSource queued queuedMem
      simpa [next, rawNext, nextRequestVote] using
        enqueue_preserves_MonoTermInv
          state
          (requestVoteMessage state source dest)
          monoTerm
          (by simp [requestVoteMessage])
          queuedDest queuedSource queued queuedMem
  | appendEntries source dest =>
      intro queuedDest queuedSource queued queuedMem
      simpa [next, rawNext, nextAppendEntries] using
        enqueue_preserves_MonoTermInv
          state
          (appendEntriesMessage state source dest)
          monoTerm
          (by simp [appendEntriesMessage])
          queuedDest queuedSource queued queuedMem
  | becomeLeader leader =>
      apply monoTerm_of_currentTerm_mono state _ monoTerm
      · rfl
      · intro node
        simp [next, rawNext, nextBecomeLeader]
  | clientRequest leader =>
      apply monoTerm_of_currentTerm_mono state _ monoTerm
      · rfl
      · intro node
        simp [next, rawNext, nextClientRequest]
  | signCommittableMessages leader =>
      apply monoTerm_of_currentTerm_mono state _ monoTerm
      · rfl
      · intro node
        simp [next, rawNext, nextSignCommittableMessages]
  | changeConfiguration leader configuration =>
      apply monoTerm_of_currentTerm_mono state _ monoTerm
      · rfl
      · intro node
        simp [next, rawNext, nextChangeConfiguration]
  | advanceCommitIndex leader =>
      apply monoTerm_of_currentTerm_mono state _ monoTerm
      · rfl
      · intro node
        simp [next, rawNext, nextAdvanceCommitIndex]
  | receive dest source kind =>
      cases hmessage : headMessage? state dest source with
      | none =>
          simpa [next, rawNext, nextReceive, hmessage] using monoTerm
      | some message =>
          have enabledDetails := enabled
          simp [Enabled, actionEnabled, hmessage] at enabledDetails
          have destMatches : message.dest = dest := enabledDetails.1.1
          have sourceMatches : message.source = source :=
            enabledDetails.1.2
          cases kind with
          | updateTerm =>
              apply monoTerm_of_currentTerm_mono state _ monoTerm
              · simp [next, rawNext, nextReceive, hmessage]
              · intro node
                have newerTerm :
                    state.currentTerm message.dest < message.term := by
                  simpa [receiveBranchEnabled, updateTermEnabled] using
                    enabledDetails.2
                by_cases nodeIsDest : node = dest
                · subst node
                  simpa [next, rawNext, nextReceive, hmessage,
                    destMatches] using Nat.le_of_lt newerTerm
                · simp [next, rawNext, nextReceive, hmessage,
                    nodeIsDest]
          | handleRequestVoteRequest =>
              cases hbody : message.body with
              | requestVoteRequest lastTerm lastIndex isPreVote =>
                  let grant :=
                    requestVoteGranted
                      state dest source message.term lastTerm lastIndex
                  let response : Message :=
                    {
                      term := state.currentTerm dest
                      source := dest
                      dest := source
                      body := .requestVoteResponse grant isPreVote
                    }
                  apply monoTerm_of_reply
                    state _ response message monoTerm (by simp [response])
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      grant, response]
                  · simp [next, rawNext, nextReceive, hmessage, hbody]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    destMatches, sourceMatches] using
                    monoTerm
          | rejectAppendEntriesRequest =>
              cases hbody : message.body with
              | appendEntriesRequest previousIndex previousTerm entries
                  commitIndex =>
                  cases responseCase :
                      appendEntriesRejectResponse?
                        state message previousIndex previousTerm with
                  | none =>
                      simpa [next, rawNext, nextReceive, hmessage, hbody,
                        destMatches, sourceMatches, responseCase] using monoTerm
                  | some response =>
                      apply monoTerm_of_reply
                        state _ response message monoTerm
                        (appendEntriesRejectResponse_term_le_current
                          state
                          message
                          response
                          previousIndex
                          previousTerm
                          monoLog
                          logTerms
                          responseCase)
                      · simp [next, rawNext, nextReceive, hmessage, hbody,
                          responseCase]
                      · simp [next, rawNext, nextReceive, hmessage, hbody,
                          responseCase]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    destMatches, sourceMatches] using
                    monoTerm
          | appendEntriesAlreadyDone =>
              cases hbody : message.body with
              | appendEntriesRequest previousIndex previousTerm entries
                  commitIndex =>
                  let response : Message :=
                    {
                      term := state.currentTerm dest
                      source := dest
                      dest := source
                      body :=
                        .appendEntriesResponse true
                          (previousIndex + entries.length)
                    }
                  apply monoTerm_of_reply
                    state _ response message monoTerm (by simp [response])
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      destMatches, sourceMatches,
                      nextAppendEntriesAlreadyDone, response]
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      nextAppendEntriesAlreadyDone]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    destMatches, sourceMatches] using
                    monoTerm
          | appendEntriesNoConflict =>
              cases hbody : message.body with
              | appendEntriesRequest previousIndex previousTerm entries
                  commitIndex =>
                  let nextLog :=
                    (state.log dest).take previousIndex ++ entries
                  let response : Message :=
                    {
                      term := state.currentTerm dest
                      source := dest
                      dest := source
                      body := .appendEntriesResponse true nextLog.length
                    }
                  apply monoTerm_of_reply
                    state _ response message monoTerm (by simp [response])
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      destMatches, sourceMatches,
                      nextAppendEntriesNoConflict, nextLog, response]
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      nextAppendEntriesNoConflict]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    destMatches, sourceMatches] using
                    monoTerm
          | appendEntriesConflictThenAlreadyDone =>
              cases hbody : message.body with
              | appendEntriesRequest previousIndex previousTerm entries
                  commitIndex =>
                  let response : Message :=
                    {
                      term := state.currentTerm dest
                      source := dest
                      dest := source
                      body :=
                        .appendEntriesResponse true
                          (previousIndex + entries.length)
                    }
                  apply monoTerm_of_reply
                    state _ response message monoTerm (by simp [response])
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      destMatches, sourceMatches,
                      nextAppendEntriesAlreadyDone, conflictRollback,
                      response]
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      nextAppendEntriesAlreadyDone, conflictRollback]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    destMatches, sourceMatches] using
                    monoTerm
          | appendEntriesConflictThenNoConflict =>
              cases hbody : message.body with
              | appendEntriesRequest previousIndex previousTerm entries
                  commitIndex =>
                  let rolled := conflictRollback state dest previousIndex
                  let nextLog := (rolled.log dest).take previousIndex ++ entries
                  let response : Message :=
                    {
                      term := state.currentTerm dest
                      source := dest
                      dest := source
                      body := .appendEntriesResponse true nextLog.length
                    }
                  apply monoTerm_of_reply
                    state _ response message monoTerm (by simp [response])
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      destMatches, sourceMatches,
                      nextAppendEntriesNoConflict, conflictRollback, rolled,
                      nextLog, response]
                  · simp [next, rawNext, nextReceive, hmessage, hbody,
                      nextAppendEntriesNoConflict, conflictRollback]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    destMatches, sourceMatches] using
                    monoTerm
          | returnToFollower =>
              cases hbody : message.body <;>
                simpa [next, rawNext, nextReceive, hmessage, hbody,
                  destMatches, sourceMatches, MonoTermInv] using monoTerm
          | dropIgnored =>
              apply monoTerm_of_discard state _ message monoTerm
              · simp [next, rawNext, nextReceive, hmessage]
              · simp [next, rawNext, nextReceive, hmessage]
          | handleRequestVoteResponse =>
              cases hbody : message.body with
              | requestVoteResponse voteGranted isPreVote =>
                  apply monoTerm_of_discard state _ message monoTerm
                  · cases voteGranted <;>
                      simp [next, rawNext, nextReceive, hmessage, hbody]
                  · simp [next, rawNext, nextReceive, hmessage, hbody]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    MonoTermInv] using monoTerm
          | dropRequestVoteResponseOutOfState =>
              apply monoTerm_of_discard state _ message monoTerm
              · simp [next, rawNext, nextReceive, hmessage]
              · simp [next, rawNext, nextReceive, hmessage]
          | dropRequestVoteResponseStale =>
              apply monoTerm_of_discard state _ message monoTerm
              · simp [next, rawNext, nextReceive, hmessage]
              · simp [next, rawNext, nextReceive, hmessage]
          | handleAppendEntriesResponseSuccess =>
              cases hbody : message.body with
              | appendEntriesResponse success lastLogIndex =>
                  apply monoTerm_of_discard state _ message monoTerm
                  · simp [next, rawNext, nextReceive, hmessage, hbody]
                  · simp [next, rawNext, nextReceive, hmessage, hbody]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    MonoTermInv] using monoTerm
          | handleAppendEntriesResponseFailure =>
              cases hbody : message.body with
              | appendEntriesResponse success lastLogIndex =>
                  apply monoTerm_of_discard state _ message monoTerm
                  · simp [next, rawNext, nextReceive, hmessage, hbody]
                  · simp [next, rawNext, nextReceive, hmessage, hbody]
              | _ =>
                  simpa [next, rawNext, nextReceive, hmessage, hbody,
                    MonoTermInv] using monoTerm
          | dropAppendEntriesResponseOutOfState =>
              apply monoTerm_of_discard state _ message monoTerm
              · simp [next, rawNext, nextReceive, hmessage]
              · simp [next, rawNext, nextReceive, hmessage]
          | dropAppendEntriesResponseStale =>
              apply monoTerm_of_discard state _ message monoTerm
              · simp [next, rawNext, nextReceive, hmessage]
              · simp [next, rawNext, nextReceive, hmessage]

theorem messagesWellFormed_step
    (state : State)
    (action : Action)
    (wellFormed : MessagesWellFormedInv state) :
    MessagesWellFormedInv (next state action) := by
  cases action with
  | timeout candidate =>
      simpa [MessagesWellFormedInv, next, rawNext, nextTimeout] using
        wellFormed
  | requestVote source dest =>
      simpa [MessagesWellFormedInv, next, rawNext, nextRequestVote] using
        enqueue_preserves_MessageChannelsWellFormed
          state.messages
          (requestVoteMessage state source dest)
          wellFormed
  | appendEntries source dest =>
      simpa [MessagesWellFormedInv, next, rawNext, nextAppendEntries] using
        enqueue_preserves_MessageChannelsWellFormed
          state.messages
          (appendEntriesMessage state source dest)
          wellFormed
  | becomeLeader leader =>
      simpa [MessagesWellFormedInv, next, rawNext, nextBecomeLeader] using
        wellFormed
  | clientRequest leader =>
      simpa [MessagesWellFormedInv, next, rawNext, nextClientRequest] using
        wellFormed
  | signCommittableMessages leader =>
      simpa [MessagesWellFormedInv, next, rawNext,
        nextSignCommittableMessages] using wellFormed
  | changeConfiguration leader configuration =>
      simpa [MessagesWellFormedInv, next, rawNext,
        nextChangeConfiguration] using wellFormed
  | advanceCommitIndex leader =>
      simpa [MessagesWellFormedInv, next, rawNext,
        nextAdvanceCommitIndex] using wellFormed
  | receive dest source kind =>
      cases hmessage : headMessage? state dest source with
      | none =>
          simpa [MessagesWellFormedInv, next, rawNext, nextReceive,
            hmessage] using wellFormed
      | some message =>
          cases kind <;>
            cases hbody : message.body <;>
              simp_all [MessagesWellFormedInv, next, rawNext, nextReceive,
                nextAppendEntriesAlreadyDone, nextAppendEntriesNoConflict,
                conflictRollback]
          all_goals
            split <;> simp_all

theorem termDelta
    (state : State)
    (action : Action)
    (_enabled : Enabled state action) :
    TermDelta state (next state action) := by
  constructor
  intro node
  cases action with
  | timeout candidate =>
      by_cases h : node = candidate
      · subst node
        simp [next, rawNext, nextTimeout]
      · simp [next, rawNext, nextTimeout, h]
  | requestVote source dest =>
      simp [next, rawNext, nextRequestVote]
  | appendEntries source dest =>
      simp [next, rawNext, nextAppendEntries]
  | becomeLeader leader =>
      simp [next, rawNext, nextBecomeLeader]
  | clientRequest leader =>
      simp [next, rawNext, nextClientRequest]
  | signCommittableMessages leader =>
      simp [next, rawNext, nextSignCommittableMessages]
  | changeConfiguration leader configuration =>
      simp [next, rawNext, nextChangeConfiguration]
  | advanceCommitIndex leader =>
      simp [next, rawNext, nextAdvanceCommitIndex]
  | receive dest source kind =>
      cases hmessage : headMessage? state dest source with
      | none =>
          simp [next, rawNext, nextReceive, hmessage]
      | some message =>
          cases kind <;>
            cases hbody : message.body <;>
              simp_all [next, rawNext, nextReceive, Enabled,
                actionEnabled, receiveBranchEnabled, updateTermEnabled,
                nextAppendEntriesAlreadyDone, nextAppendEntriesNoConflict,
                conflictRollback]
          all_goals
            split <;> simp_all
          all_goals
            rw [← _enabled.1.1]
            exact Nat.le_of_lt _enabled.2

theorem monotonicTerm_step
    (state : State)
    (action : Action)
    (enabled : Enabled state action) :
    MonotonicTermProp state (next state action) :=
  (termDelta state action enabled).monotonic

theorem reachable_currentTerm_lowerBound
    (start : Node)
    {state : State}
    (reachable : Reachable start state) :
    forall node,
      (initialState start).currentTerm node <= state.currentTerm node := by
  apply
    ExecutableTransitionSystem.reachableInvariant
      (system start)
      (Invariant := fun current =>
        forall node,
          (initialState start).currentTerm node <=
            current.currentTerm node)
  · intro node
    exact Nat.le_refl _
  · intro current action inductionHypothesis enabled node
    exact
      Nat.le_trans
        (inductionHypothesis node)
        (monotonicTerm_step current action enabled node)
  · exact reachable

/--
Kernel-checked reachable-step theorem for `MonotonicTermProp` over every
enabled selected action.
-/
theorem reachable_MonotonicTermProp
    (start : Node)
    {state : State}
    (_reachable : Reachable start state)
    {action : Action}
    (enabled : Enabled state action) :
    MonotonicTermProp state (next state action) :=
  monotonicTerm_step state action enabled

theorem commitIndexDelta
    (state : State)
    (action : Action)
    (_enabled : Enabled state action) :
    CommitIndexDelta state (next state action) := by
  constructor
  intro node
  cases action with
  | timeout candidate =>
      simp [next, rawNext, nextTimeout]
  | requestVote source dest =>
      simp [next, rawNext, nextRequestVote]
  | appendEntries source dest =>
      simp [next, rawNext, nextAppendEntries]
  | becomeLeader leader =>
      simp [next, rawNext, nextBecomeLeader]
  | clientRequest leader =>
      simp [next, rawNext, nextClientRequest]
  | signCommittableMessages leader =>
      simp [next, rawNext, nextSignCommittableMessages]
  | changeConfiguration leader configuration =>
      simp [next, rawNext, nextChangeConfiguration]
  | advanceCommitIndex leader =>
      simp [Enabled, actionEnabled] at _enabled
      by_cases h : node = leader
      · subst node
        simp [next, rawNext, nextAdvanceCommitIndex]
        exact Nat.le_of_lt _enabled.2
      · simp [next, rawNext, nextAdvanceCommitIndex, h]
  | receive dest source kind =>
      cases hmessage : headMessage? state dest source with
      | none =>
          simp [next, rawNext, nextReceive, hmessage]
      | some message =>
          cases kind <;>
            cases hbody : message.body <;>
              simp_all [next, rawNext, nextReceive,
                nextAppendEntriesAlreadyDone, nextAppendEntriesNoConflict,
                conflictRollback]
          all_goals
            split <;> simp_all

theorem monotonicCommitIndex_step
    (state : State)
    (action : Action)
    (enabled : Enabled state action) :
    MonotonicCommitIndexProp state (next state action) :=
  (commitIndexDelta state action enabled).monotonic

theorem reachable_MonotonicCommitIndexProp
    (start : Node)
    {state : State}
    (_reachable : Reachable start state)
    {action : Action}
    (enabled : Enabled state action) :
    MonotonicCommitIndexProp state (next state action) :=
  monotonicCommitIndex_step state action enabled

theorem reachable_commitIndex_lowerBound
    (start : Node)
    {state : State}
    (reachable : Reachable start state) :
    forall node,
      (initialState start).commitIndex node <= state.commitIndex node := by
  apply
    ExecutableTransitionSystem.reachableInvariant
      (system start)
      (Invariant := fun current =>
        forall node,
          (initialState start).commitIndex node <=
            current.commitIndex node)
  · intro node
    exact Nat.le_refl _
  · intro current action inductionHypothesis enabled node
    exact
      Nat.le_trans
        (inductionHypothesis node)
        (monotonicCommitIndex_step current action enabled node)
  · exact reachable

theorem matchIndexDelta
    (state : State)
    (action : Action)
    (_enabled : Enabled state action) :
    MatchIndexDelta state action (next state action) := by
  constructor
  cases action with
  | becomeLeader leader =>
      simp [MonotonicMatchIndexProp]
  | timeout candidate =>
      intro i j
      simp [next, rawNext, nextTimeout]
  | requestVote source dest =>
      intro i j
      simp [next, rawNext, nextRequestVote]
  | appendEntries source dest =>
      intro i j
      simp [next, rawNext, nextAppendEntries]
  | clientRequest leader =>
      intro i j
      simp [next, rawNext, nextClientRequest]
  | signCommittableMessages leader =>
      intro i j
      simp [next, rawNext,
        nextSignCommittableMessages]
  | changeConfiguration leader configuration =>
      intro i j
      simp [next, rawNext,
        nextChangeConfiguration]
  | advanceCommitIndex leader =>
      intro i j
      simp [next, rawNext,
        nextAdvanceCommitIndex]
  | receive dest source kind =>
      intro i j
      cases hmessage : headMessage? state dest source with
      | none =>
          simp [next, rawNext, nextReceive,
            hmessage]
      | some message =>
          cases kind <;>
            cases hbody : message.body <;>
              simp_all [next, rawNext,
                nextReceive, nextAppendEntriesAlreadyDone,
                nextAppendEntriesNoConflict, conflictRollback, update₂]
          all_goals
            split <;> simp_all
          all_goals
            by_cases hj : j = source
            · subst j
              simp
            · simp [hj]

theorem monotonicMatchIndex_step
    (state : State)
    (action : Action)
    (enabled : Enabled state action) :
    MonotonicMatchIndexProp state action (next state action) :=
  (matchIndexDelta state action enabled).monotonic

theorem monotonicDelta
    (state : State)
    (action : Action)
    (enabled : Enabled state action) :
    MonotonicDelta state action (next state action) :=
  {
    terms := termDelta state action enabled
    commits := commitIndexDelta state action enabled
    matchIndices := matchIndexDelta state action enabled
  }

theorem reachable_MonotonicMatchIndexProp
    (start : Node)
    {state : State}
    (_reachable : Reachable start state)
    {action : Action}
    (enabled : Enabled state action) :
    MonotonicMatchIndexProp state action (next state action) :=
  monotonicMatchIndex_step state action enabled

end CCFRaft.Proofs

#print axioms CCFRaft.Proofs.initialSafetyCheckpoint
#print axioms CCFRaft.Proofs.initialInductiveInvariantObligation
#print axioms CCFRaft.Proofs.reachable_MonotonicTermProp
#print axioms CCFRaft.Proofs.reachable_currentTerm_lowerBound
#print axioms CCFRaft.Proofs.reachable_MonotonicCommitIndexProp
#print axioms CCFRaft.Proofs.reachable_commitIndex_lowerBound
#print axioms CCFRaft.Proofs.reachable_MonotonicMatchIndexProp
