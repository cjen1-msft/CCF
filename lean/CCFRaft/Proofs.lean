-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties

set_option autoImplicit false

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

/-- Every list is a prefix of itself. -/
theorem prefixRefl {Alpha : Type} (values : List Alpha) :
    values <+: values :=
  ⟨[], by simp⟩

/-- Taking the length of a known prefix recovers that prefix. -/
theorem prefixEqTake
    {Alpha : Type}
    {head values : List Alpha}
    (isPrefix : head <+: values) :
    values.take head.length = head := by
  rw [List.prefix_iff_eq_take] at isPrefix
  exact isPrefix.symm

/-- Two lists agree through any index lying inside their shared prefix. -/
theorem takeEqOfPrefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {count : Nat}
    (within : count <= left.length) :
    left.take count = right.take count := by
  rw [List.prefix_iff_eq_take] at isPrefix
  rw [isPrefix, List.take_take, Nat.min_eq_left within]

/-- Two prefixes of the same list are prefixes of each other. -/
theorem prefixesComparable
    {Alpha : Type}
    {left right common : List Alpha}
    (leftPrefix : left <+: common)
    (rightPrefix : right <+: common) :
    left <+: right \/ right <+: left := by
  by_cases leftShorter : left.length <= right.length
  · left
    have leftEq : right.take left.length = left := by
      calc
        right.take left.length =
            common.take left.length :=
          takeEqOfPrefix rightPrefix leftShorter
        _ = left := prefixEqTake leftPrefix
    have takenPrefix := List.take_prefix left.length right
    rwa [leftEq] at takenPrefix
  · right
    have rightShorter : right.length <= left.length := by omega
    have rightEq : left.take right.length = right := by
      calc
        left.take right.length =
            common.take right.length :=
          takeEqOfPrefix leftPrefix rightShorter
        _ = right := prefixEqTake rightPrefix
    have takenPrefix := List.take_prefix right.length left
    rwa [rightEq] at takenPrefix

/-- Any two strict majorities of the fixed five-node network intersect. -/
theorem fiveNodeMajoritiesIntersect
    (left right : Finset Node)
    (leftMajority : left.card * 2 > NODE_COUNT)
    (rightMajority : right.card * 2 > NODE_COUNT) :
    (left ∩ right).Nonempty := by
  by_contra noIntersection
  have intersectionEmpty :
      left ∩ right = ∅ :=
    Finset.not_nonempty_iff_eq_empty.mp noIntersection
  have disjoint : Disjoint left right :=
    Finset.disjoint_iff_inter_eq_empty.mpr intersectionEmpty
  have unionCard :
      (left ∪ right).card = left.card + right.card :=
    Finset.card_union_of_disjoint disjoint
  have unionBound :
      (left ∪ right).card <= NODE_COUNT := by
    simpa [NODE_COUNT] using Finset.card_le_univ (left ∪ right)
  have leftAtLeastThree : 3 <= left.card := by
    simp [NODE_COUNT] at leftMajority
    omega
  have rightAtLeastThree : 3 <= right.card := by
    simp [NODE_COUNT] at rightMajority
    omega
  omega

/-- A successful one-based lookup proves the index lies within the log. -/
theorem entryAtSomeIndexBound
    {log : List (Entry TxId)}
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? log index = some entry) :
    index <= log.length := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rename_i indexNotZero
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, _⟩
    omega

/-- Every supporting invariant holds in the empty initial state. -/
theorem initialSystemInductiveInvariant :
    SystemInductiveInvariant (initialState : State TxId) := by
  constructor
  · simp [CommitIndicesBounded, initialState, initialNodeState]
  · intro node
    exact prefixRefl []
  · simp [TermsAreOne, initialState, initialNodeState]
  · simp [LeaderTxIdsUnique, initialState, initialNodeState]
  · simp [LeaderTxIdsSubmitted, initialState, initialNodeState]
  · simp [QueuedRequestsMatchLeader, initialState]
  · simp [QueuedVoteMessagesSafe, initialState]
  · simp [SentIndicesBounded, initialState, initialNodeState]
  · simp [MatchIndicesBounded, initialState, initialNodeState]
  · simp [CurrentTermsValid, initialState, initialNodeState]
  · simp [TermOneLeaderIsInitial, initialState, initialNodeState]
  · simp [InitialNodeTermOneIsLeader, initialState, initialNodeState]
  · intro node candidate
    by_cases nodeEq : node = LEADER <;>
      simp [initialState, initialNodeState, nodeEq] at candidate
  · simp [VotedForTermTwo, initialState, initialNodeState]
  · simp [VotesGrantedSound, initialState, initialNodeState]
  · intro node leader termTwo
    simp [initialState, initialNodeState, TERM_ONE] at termTwo
  · simp [MatchIndexDescribesPrefix, initialState, initialNodeState]
  · simp [InitialLeaderCommitHasMajority, initialState, initialNodeState]
  · simp [InitialNodeNotCandidate, initialState, initialNodeState]

/-- A node's committed log is a prefix of the leader log. -/
theorem committedLogPrefixLeader
    {state : State TxId}
    (core : SystemInductiveInvariant state)
    (node : Node) :
    (state.nodes node).committedLog <+:
      (state.nodes LEADER).log := by
  exact
    (List.take_prefix
      (state.nodes node).commitIndex
      (state.nodes node).log).trans
      (core.logsPrefixLeader node)

/-- The system invariant implies pairwise committed-log prefix comparability. -/
theorem systemInductiveInvariantCommittedLogsPrefix
    {state : State TxId}
    (core : SystemInductiveInvariant state) :
    CommittedLogsPrefix state := by
  intro left right
  exact
    prefixesComparable
      (committedLogPrefixLeader core left)
      (committedLogPrefixLeader core right)

/-- Prefix agreement with the leader implies Raft log matching. -/
theorem systemInductiveInvariantLogMatching
    {state : State TxId}
    (core : SystemInductiveInvariant state) :
    LogMatching state := by
  intro left right index leftEntry rightEntry leftFound rightFound sameTerm
  have leftBound := entryAtSomeIndexBound leftFound
  have rightBound := entryAtSomeIndexBound rightFound
  calc
    (state.nodes left).log.take index =
        (state.nodes LEADER).log.take index :=
      takeEqOfPrefix (core.logsPrefixLeader left) leftBound
    _ = (state.nodes right).log.take index :=
      (takeEqOfPrefix (core.logsPrefixLeader right) rightBound).symm

/-- Log matching makes equal index and term imply equal transaction ID. -/
theorem systemInductiveInvariantSameIndexSameTermSameTxId
    {state : State TxId}
    (core : SystemInductiveInvariant state) :
    SameIndexSameTermSameTxId state := by
  intro left right index leftEntry rightEntry leftFound rightFound sameTerm
  have matching :=
    systemInductiveInvariantLogMatching core
      left right index leftEntry rightEntry leftFound rightFound sameTerm
  have leftBound := entryAtSomeIndexBound leftFound
  have rightBound := entryAtSomeIndexBound rightFound
  have indexPositive : 0 < index := by
    by_contra notPositive
    have indexZero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at leftFound
  have lookupEqual :
      entryAt?
          ((state.nodes left).log.take index)
          index =
        entryAt?
          ((state.nodes right).log.take index)
          index := by
    rw [matching]
  have leftTakeFound :
      entryAt?
          ((state.nodes left).log.take index)
          index =
        some leftEntry := by
    unfold entryAt? at leftFound ⊢
    simp only [indexPositive.ne', ↓reduceIte] at leftFound ⊢
    rw [List.getElem?_take_of_lt (by omega)]
    exact leftFound
  have rightTakeFound :
      entryAt?
          ((state.nodes right).log.take index)
          index =
        some rightEntry := by
    unfold entryAt? at rightFound ⊢
    simp only [indexPositive.ne', ↓reduceIte] at rightFound ⊢
    rw [List.getElem?_take_of_lt (by omega)]
    exact rightFound
  rw [leftTakeFound, rightTakeFound] at lookupEqual
  exact congrArg Entry.txId (Option.some.inj lookupEqual)

/-- Since every entry is in term one, terms are monotonic along every log. -/
theorem systemInductiveInvariantMonoLog
    {state : State TxId}
    (core : SystemInductiveInvariant state) :
    MonoLog state := by
  intro node earlier later earlierEntry laterEntry _ earlierFound laterFound
  have earlierMember : earlierEntry ∈ (state.nodes node).log := by
    unfold entryAt? at earlierFound
    split at earlierFound
    · simp_all
    · rw [List.getElem?_eq_some_iff] at earlierFound
      rcases earlierFound with ⟨within, value⟩
      rw [← value]
      exact List.getElem_mem within
  have laterMember : laterEntry ∈ (state.nodes node).log := by
    unfold entryAt? at laterFound
    split at laterFound
    · simp_all
    · rw [List.getElem?_eq_some_iff] at laterFound
      rcases laterFound with ⟨within, value⟩
      rw [← value]
      exact List.getElem_mem within
  rw [
    core.termsAreOne node earlierEntry earlierMember,
    core.termsAreOne node laterEntry laterMember
  ]

/-- The invariant's vote majorities imply at most one leader per term. -/
theorem systemInductiveInvariantElectionSafety
    {state : State TxId}
    (core : SystemInductiveInvariant state) :
    ElectionSafety state := by
  intro left right leftLeader rightLeader sameTerm
  rcases core.currentTermsValid left with leftTermOne | leftTermTwo
  · have rightTermOne : (state.nodes right).currentTerm = TERM_ONE :=
      sameTerm.symm.trans leftTermOne
    exact
      (core.termOneLeaderIsInitial left leftLeader leftTermOne).trans
        (core.termOneLeaderIsInitial right rightLeader rightTermOne).symm
  · have rightTermTwo : (state.nodes right).currentTerm = 2 :=
      sameTerm.symm.trans leftTermTwo
    have leftMajority :=
      core.termTwoLeadersHaveMajority left leftLeader leftTermTwo
    have rightMajority :=
      core.termTwoLeadersHaveMajority right rightLeader rightTermTwo
    have intersection :=
      fiveNodeMajoritiesIntersect
        (state.nodes left).votesGranted
        (state.nodes right).votesGranted
        leftMajority
        rightMajority
    rcases intersection with ⟨voter, voterInBoth⟩
    have voterInLeft := (Finset.mem_inter.mp voterInBoth).1
    have voterInRight := (Finset.mem_inter.mp voterInBoth).2
    have leftVote :=
      (core.votesGrantedSound left voter voterInLeft).2.1
    have rightVote :=
      (core.votesGrantedSound right voter voterInRight).2.1
    exact Option.some.inj (leftVote.symm.trans rightVote)

/-- A term-two election intersects the majority backing node zero's commit. -/
theorem systemInductiveInvariantTermTwoLeaderCompleteness
    {state : State TxId}
    (core : SystemInductiveInvariant state) :
    TermTwoLeaderCompleteness state := by
  intro leader leaderRole leaderTermTwo
  rcases core.initialLeaderCommitHasMajority with commitZero | commitMajority
  · simp [NodeState.committedLog, commitZero]
  · have electionMajority :=
      core.termTwoLeadersHaveMajority
        leader leaderRole leaderTermTwo
    have intersection :=
      fiveNodeMajoritiesIntersect
        (acknowledgingNodes
          state LEADER (state.nodes LEADER).commitIndex)
        (state.nodes leader).votesGranted
        commitMajority
        electionMajority
    rcases intersection with ⟨voter, voterInBoth⟩
    have voterAcknowledges :=
      (Finset.mem_inter.mp voterInBoth).1
    have voterElected :=
      (Finset.mem_inter.mp voterInBoth).2
    have voterPrefixLeader :=
      (core.votesGrantedSound leader voter voterElected).2.2
    have committedPrefixVoter :
        (state.nodes LEADER).committedLog <+:
          (state.nodes voter).log := by
      simp only [
        acknowledgingNodes,
        Finset.mem_filter,
        Finset.mem_univ,
        true_and
      ] at voterAcknowledges
      rcases voterAcknowledges with voterIsLeader | matchCoversCommit
      · subst voter
        exact List.take_prefix _ _
      · have matchEquality :=
          core.matchIndexDescribesPrefix voter
        have commitEquality :
            (state.nodes LEADER).log.take
                (state.nodes LEADER).commitIndex =
              (state.nodes voter).log.take
                (state.nodes LEADER).commitIndex := by
          have taken :=
            congrArg
              (List.take (state.nodes LEADER).commitIndex)
              matchEquality
          simpa [
            List.take_take,
            Nat.min_eq_left matchCoversCommit
          ] using taken
        rw [NodeState.committedLog, commitEquality]
        exact List.take_prefix _ _
    exact committedPrefixVoter.trans voterPrefixLeader

/-- Any term-one leader is the original node-zero leader. -/
theorem termOneLeaderImpliesInitialLeader
    {state : State TxId}
    (core : SystemInductiveInvariant state)
    {node : Node}
    (isLeader : (state.nodes node).role = .leader)
    (termOne : (state.nodes node).currentTerm = TERM_ONE) :
    node = LEADER := by
  exact core.termOneLeaderIsInitial node isLeader termOne

/-- Appending an entry does not change terms at existing indices. -/
theorem termAtAppendOfBound
    (log : List (Entry TxId))
    (entry : Entry TxId)
    {index : Nat}
    (within : index <= log.length) :
    termAt (log ++ [entry]) index = termAt log index := by
  unfold termAt entryAt?
  by_cases indexZero : index = 0
  · simp [indexZero]
  · simp only [indexZero, ↓reduceIte]
    rw [List.getElem?_append_left (by omega)]

/-- An old request snapshot remains valid when the leader appends later entries. -/
theorem requestMatchesLeaderAfterAppend
    {state : State TxId}
    {entry : Entry TxId}
    {request : AppendEntriesRequest TxId}
    (requestMatches : RequestMatchesLeader state request) :
    RequestMatchesLeader
      { state with
        nodes :=
          updateNode state.nodes LEADER
            { state.nodes LEADER with
              log := (state.nodes LEADER).log ++ [entry] } }
      request := by
  rcases requestMatches with
    ⟨source, destination, term, previousBound, endBound, previousTerm, entries⟩
  refine
    ⟨source, destination, term, ?_, ?_, ?_, ?_⟩
  · simp only [updateNode, Function.update_self]
    simp
    omega
  · simp only [updateNode, Function.update_self]
    simp
    omega
  · simpa [updateNode] using
      previousTerm.trans
        (termAtAppendOfBound
          (state.nodes LEADER).log entry previousBound).symm
  · simp only [updateNode, Function.update_self]
    rw [
      List.take_append_of_le_length endBound,
      List.take_append_of_le_length previousBound
    ]
    exact entries

/-- A fresh client request preserves every supporting invariant. -/
theorem clientRequestPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (txId : TxId)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.clientRequest node txId)) :
    SystemInductiveInvariant (next state (.clientRequest node txId)) := by
  have nodeEq : node = LEADER :=
    termOneLeaderImpliesInitialLeader core enabled.1 enabled.2.1
  subst node
  have leaderTermOne :
      (state.nodes LEADER).currentTerm = TERM_ONE :=
    enabled.2.1
  have fresh : txId ∉ state.submittedTxIds := enabled.2.2
  have notInLeader :
      txId ∉ (state.nodes LEADER).log.map Entry.txId := by
    intro inLog
    rw [List.mem_map] at inLog
    rcases inLog with ⟨entry, entryInLog, entryTx⟩
    apply fresh
    rw [← entryTx]
    exact core.leaderTxIdsSubmitted entry entryInLog
  constructor
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      have oldBound := core.commitIndicesBounded LEADER
      simpa [next, updateNode] using Nat.le.step oldBound
    · simpa [next, updateNode, Function.update, candidateEq] using
        core.commitIndicesBounded candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      exact prefixRefl _
    · have oldPrefix := core.logsPrefixLeader candidate
      simpa [next, updateNode, Function.update, candidateEq] using
        oldPrefix.trans (List.prefix_append _ _)
  · intro candidate candidateEntry candidateEntryIn
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next, updateNode] at candidateEntryIn
      rcases candidateEntryIn with oldEntry | newEntry
      · exact core.termsAreOne LEADER candidateEntry oldEntry
      · simpa [newEntry] using leaderTermOne
    · have oldEntry :
          candidateEntry ∈ (state.nodes candidate).log := by
        simpa [next, updateNode, Function.update, candidateEq] using
          candidateEntryIn
      exact core.termsAreOne candidate candidateEntry oldEntry
  · simp only [
      LeaderTxIdsUnique,
      next,
      updateNode,
      Function.update_self,
      List.map_append,
      List.map_cons,
      List.map_nil
    ]
    rw [List.nodup_append]
    refine ⟨core.leaderTxIdsUnique, by simp, ?_⟩
    intro existing existingIn appended appendedIn
    simp only [List.mem_singleton] at appendedIn
    subst appended
    intro existingEq
    subst existing
    exact notInLeader existingIn
  · intro candidateEntry candidateEntryIn
    simp [next, updateNode] at candidateEntryIn
    rcases candidateEntryIn with oldEntry | newEntry
    · exact Finset.mem_insert_of_mem
        (core.leaderTxIdsSubmitted candidateEntry oldEntry)
    · subst candidateEntry
      simp [next]
  · intro destination message messageIn
    have oldMessage :
        message ∈ state.network destination := by
      simpa [next] using messageIn
    have safe := core.queuedRequestsMatchLeader destination message oldMessage
    constructor
    · exact safe.1
    · cases message with
      | appendEntriesResponse response =>
          rcases safe.2 with
            ⟨responseDestination, responseSource, responseTerm,
              responseBound, responsePrefix⟩
          exact
            ⟨responseDestination, responseSource, responseTerm,
              by simpa [next, updateNode] using Nat.le.step responseBound,
              by
                intro success
                simpa [
                  next,
                  updateNode,
                  responseSource,
                  List.take_append_of_le_length responseBound
                ] using responsePrefix success⟩
      | appendEntriesRequest request =>
          exact requestMatchesLeaderAfterAppend safe.2
      | requestVoteRequest request => trivial
      | requestVoteResponse response => trivial
  · intro destination message messageIn
    have oldMessage :
        message ∈ state.network destination := by
      simpa [next] using messageIn
    have safe := core.queuedVoteMessagesSafe destination message oldMessage
    cases message with
    | appendEntriesRequest request => trivial
    | appendEntriesResponse response => trivial
    | requestVoteRequest request =>
        by_cases sourceEq : request.source = LEADER
        · have sourceTermTwo := safe.2.2.1
          rw [sourceEq, leaderTermOne] at sourceTermTwo
          simp [TERM_ONE] at sourceTermTwo
        · simpa [
            RequestVoteRequestSafe,
            next,
            updateNode,
            Function.update,
            sourceEq
          ] using safe
    | requestVoteResponse response =>
        have sourceNe :
            Not (response.source = LEADER) := by
          intro sourceEq
          have sourceTermTwo := safe.2.2.1
          rw [sourceEq, leaderTermOne] at sourceTermTwo
          simp [TERM_ONE] at sourceTermTwo
        have destinationNe :
            Not (response.destination = LEADER) := by
          intro destinationEq
          have destinationTermTwo := safe.2.2.2.1
          rw [destinationEq, leaderTermOne] at destinationTermTwo
          simp [TERM_ONE] at destinationTermTwo
        simpa [
          RequestVoteResponseSafe,
          next,
          updateNode,
          Function.update,
          sourceNe,
          destinationNe
        ] using safe
  · intro candidate
    have oldBound := core.sentIndicesBounded candidate
    simpa [SentIndicesBounded, next, updateNode] using Nat.le.step oldBound
  · intro candidate
    have oldBound := core.matchIndicesBounded candidate
    simpa [MatchIndicesBounded, next, updateNode] using Nat.le.step oldBound
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      exact Or.inl leaderTermOne
    · simpa [next, updateNode, Function.update, candidateEq] using
        core.currentTermsValid candidate
  · intro candidate leader termOne
    by_cases candidateEq : candidate = LEADER
    · exact candidateEq
    · exact
        core.termOneLeaderIsInitial candidate
          (by simpa [next, updateNode, Function.update, candidateEq] using leader)
          (by simpa [next, updateNode, Function.update, candidateEq] using termOne)
  · simpa [InitialNodeTermOneIsLeader, next, updateNode] using
      core.initialNodeTermOneIsLeader
  · intro candidate candidateRole
    have candidateNe : Not (candidate = LEADER) := by
      intro candidateEq
      subst candidate
      have leaderRole : (state.nodes LEADER).role = .candidate := by
        simpa [next, updateNode] using candidateRole
      exact Role.noConfusion (enabled.1.symm.trans leaderRole)
    simpa [next, updateNode, Function.update, candidateNe] using
      core.candidatesSelfVote candidate
        (by simpa [next, updateNode, Function.update, candidateNe] using
          candidateRole)
  · intro voter candidate voted
    by_cases voterEq : voter = LEADER
    · subst voter
      have oldVote :
          (state.nodes LEADER).votedFor = some candidate := by
        simpa [next, updateNode] using voted
      have termTwo := core.votedForTermTwo LEADER candidate oldVote
      rw [leaderTermOne] at termTwo
      simp [TERM_ONE] at termTwo
    · exact
        (by
          have oldVote :
              (state.nodes voter).votedFor = some candidate := by
            simpa [next, updateNode, Function.update, voterEq] using voted
          have termTwo := core.votedForTermTwo voter candidate oldVote
          simpa [next, updateNode, Function.update, voterEq] using termTwo)
  · intro candidate voter voterIn
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      have oldIn :
          voter ∈ (state.nodes LEADER).votesGranted := by
        simpa [next, updateNode] using voterIn
      have sound := core.votesGrantedSound LEADER voter oldIn
      rw [leaderTermOne] at sound
      simp [TERM_ONE] at sound
    · have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [next, updateNode, Function.update, candidateEq] using voterIn
      have sound := core.votesGrantedSound candidate voter oldIn
      have voterNe : Not (voter = LEADER) := by
        intro voterEq
        subst voter
        have termTwo := core.votedForTermTwo LEADER candidate sound.2.1
        rw [leaderTermOne] at termTwo
        simp [TERM_ONE] at termTwo
      simpa [
        next,
        updateNode,
        Function.update,
        candidateEq,
        voterNe
      ] using sound
  · intro candidate leader termTwo
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      exfalso
      simpa [next, updateNode, leaderTermOne, TERM_ONE] using termTwo
    · exact
        (by
          have majority :=
            core.termTwoLeadersHaveMajority candidate
              (by simpa [next, updateNode, Function.update, candidateEq] using leader)
              (by simpa [next, updateNode, Function.update, candidateEq] using termTwo)
          simpa [
            hasElectionMajority,
            next,
            updateNode,
            Function.update,
            candidateEq
          ] using majority)
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next, updateNode]
    · have oldEquality := core.matchIndexDescribesPrefix candidate
      have bound := core.matchIndicesBounded candidate
      have leaderTakeUnchanged :
          ((state.nodes LEADER).log ++
              [({ term := (state.nodes LEADER).currentTerm
                  txId := txId } : Entry TxId)]).take
              ((state.nodes LEADER).matchIndex candidate) =
            (state.nodes LEADER).log.take
              ((state.nodes LEADER).matchIndex candidate) :=
        List.take_append_of_le_length bound
      simp only [
        next,
        updateNode_same,
        updateNode_of_ne _ _ _ _ candidateEq
      ]
      exact leaderTakeUnchanged.trans oldEquality
  · simpa [InitialLeaderCommitHasMajority, next, updateNode] using
      core.initialLeaderCommitHasMajority
  · simpa [InitialNodeNotCandidate, next, updateNode] using
      core.initialNodeNotCandidate

/-- A bounded AppendEntries slice has exactly `batchEnd - previousIndex` entries. -/
theorem messageEntriesLength
    (log : List (Entry TxId))
    {previousIndex batchEnd : Nat}
    (ordered : previousIndex <= batchEnd)
    (within : batchEnd <= log.length) :
    (messageEntries log previousIndex batchEnd).length =
      batchEnd - previousIndex := by
  simp [
    messageEntries,
    List.length_take,
    List.length_drop,
    Nat.min_eq_left
  ]
  omega

/-- A request built by an enabled leader send is a valid leader-log snapshot. -/
theorem makeAppendEntriesRequestMatchesLeader
    {state : State TxId}
    {source destination : Node}
    {batchEnd : Nat}
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    RequestMatchesLeader state
      (makeAppendEntriesRequest state source destination batchEnd) := by
  have sourceEq : source = LEADER :=
    termOneLeaderImpliesInitialLeader core enabled.1 enabled.2.1
  subst source
  have leaderTermOne :
      (state.nodes LEADER).currentTerm = TERM_ONE :=
    enabled.2.1
  rcases enabled with ⟨_, termOne, different, batchEndEq⟩
  let previousIndex := (state.nodes LEADER).sentIndex destination
  have previousBound :
      previousIndex <= (state.nodes LEADER).log.length :=
    core.sentIndicesBounded destination
  have previousBeforeEnd : previousIndex <= batchEnd := by
    rw [batchEndEq]
    simp [previousIndex]
    omega
  have endWithin : batchEnd <= (state.nodes LEADER).log.length := by
    rw [batchEndEq]
    exact min_le_right _ _
  have entriesLength :
      (messageEntries
        (state.nodes LEADER).log previousIndex batchEnd).length =
        batchEnd - previousIndex :=
    messageEntriesLength
      (state.nodes LEADER).log previousBeforeEnd endWithin
  refine
    ⟨rfl, Ne.symm different, termOne,
      core.sentIndicesBounded destination, ?_, rfl, ?_⟩
  · simp only [makeAppendEntriesRequest]
    rw [entriesLength]
    omega
  · change
      (state.nodes LEADER).log.take
          (previousIndex +
            (messageEntries
              (state.nodes LEADER).log previousIndex batchEnd).length) =
        (state.nodes LEADER).log.take previousIndex ++
          messageEntries
            (state.nodes LEADER).log previousIndex batchEnd
    rw [entriesLength]
    have sumEq : previousIndex + (batchEnd - previousIndex) = batchEnd := by
      omega
    simpa [messageEntries, sumEq] using
      (List.take_add
        (l := (state.nodes LEADER).log)
        (i := previousIndex)
        (j := batchEnd - previousIndex))

/-- A message after enqueue was either already present or is the new message. -/
theorem memEnqueueNoDup
    (network : Node -> List (Message TxId))
    (newMessage message : Message TxId)
    (destination : Node)
    (member : message ∈ enqueueNoDup network newMessage destination) :
    message ∈ network destination \/
      (destination = newMessage.destination /\ message = newMessage) := by
  unfold enqueueNoDup at member
  by_cases duplicate : newMessage ∈ network newMessage.destination
  · simp [duplicate] at member
    exact Or.inl member
  · simp [duplicate] at member
    by_cases destinationEq : destination = newMessage.destination
    · subst destination
      simp at member
      rcases member with oldMember | newMember
      · exact Or.inl oldMember
      · exact Or.inr ⟨rfl, newMember⟩
    · have oldMember :
          message ∈ network destination := by
        simpa [updateQueue, Function.update, destinationEq] using member
      exact Or.inl oldMember

/-- Selecting a source message returns that source and preserves queue membership. -/
theorem takeFirstFromSound
    {source : Node}
    {queue remaining : List (Message TxId)}
    {selected : Message TxId}
    (taken :
      takeFirstFrom source queue = some (selected, remaining)) :
    selected.source = source /\
      selected ∈ queue /\
      (forall message, message ∈ remaining -> message ∈ queue) := by
  induction queue generalizing selected remaining with
  | nil =>
      simp [takeFirstFrom] at taken
  | cons head tail inductionHypothesis =>
      unfold takeFirstFrom at taken
      split at taken
      · rename_i headSource
        simp at taken
        rcases taken with ⟨selectedEq, remainingEq⟩
        subst selected
        subst remaining
        refine ⟨headSource, by simp, ?_⟩
        intro message member
        exact List.mem_cons_of_mem head member
      · rename_i headNotSource
        split at taken
        · contradiction
        · rename_i selectedTail tailRemaining tailTaken
          simp at taken
          rcases taken with ⟨selectedEq, remainingEq⟩
          subst selected
          subst remaining
          have sound := inductionHypothesis tailTaken
          refine ⟨sound.1, by simp [sound.2.1], ?_⟩
          intro message member
          simp at member
          rcases member with headEq | tailMember
          · subst message
            simp
          · exact List.mem_cons_of_mem _ (sound.2.2 message tailMember)

/-- Every member of a prefix is also a member of the larger list. -/
theorem memOfPrefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {value : Alpha}
    (member : value ∈ left) :
    value ∈ right := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  simp [member]

/-- Applying a safe request extension still yields a prefix of the leader log. -/
theorem requestExtensionPrefixLeader
    {state : State TxId}
    {node : Node}
    {request : AppendEntriesRequest TxId}
    (nodePrefix : (state.nodes node).log <+: (state.nodes LEADER).log)
    (requestSafe : RequestMatchesLeader state request)
    (previousWithin :
      request.prevLogIndex <= (state.nodes node).log.length) :
    (state.nodes node).log.take request.prevLogIndex ++ request.entries <+:
      (state.nodes LEADER).log := by
  have previousEqual :=
    takeEqOfPrefix nodePrefix previousWithin
  have requestPrefix :=
    List.take_prefix
      (request.prevLogIndex + request.entries.length)
      (state.nodes LEADER).log
  rw [previousEqual]
  rw [← requestSafe.2.2.2.2.2.2]
  exact requestPrefix

/-- Facts guaranteed after successfully handling an AppendEntries request. -/
structure RequestHandlerPost
    (system : State TxId)
    (before after : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (response : AppendEntriesResponse) : Prop where
  logPrefixLeader : after.log <+: (system.nodes LEADER).log
  commitBounded : after.commitIndex <= after.log.length
  committedMonotonic :
    before.committedLog <+: after.committedLog
  termsAreOne :
    forall entry, entry ∈ after.log -> entry.term = TERM_ONE
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  logMonotonic : before.log <+: after.log
  logUnchangedIfTermTwo :
    before.currentTerm = 2 -> after.log = before.log
  responseSafe :
    ResponseMatchesLeader
      { system with
        nodes := updateNode system.nodes request.destination after }
      response

/-- Raising a commit frontier with `max` extends the old committed prefix. -/
theorem takeMaxCommitMonotonic
    (log : List (Entry TxId))
    {oldCommit leaderCommit : Nat}
    (oldBound : oldCommit <= log.length) :
    log.take oldCommit <+:
      log.take (max oldCommit (min log.length leaderCommit)) := by
  have oldLe :
      oldCommit <= max oldCommit (min log.length leaderCommit) :=
    Nat.le_max_left _ _
  have taken :=
    List.take_prefix oldCommit
      (log.take (max oldCommit (min log.length leaderCommit)))
  simpa [List.take_take, Nat.min_eq_left oldLe] using taken

/-- Every entry carried by a safe request belongs to term one. -/
theorem requestEntriesTermOne
    {system : State TxId}
    {request : AppendEntriesRequest TxId}
    (core : SystemInductiveInvariant system)
    (requestSafe : RequestMatchesLeader system request) :
    forall entry,
      entry ∈ request.entries ->
        entry.term = TERM_ONE := by
  intro entry entryIn
  have inCombined :
      entry ∈
        (system.nodes LEADER).log.take request.prevLogIndex ++
          request.entries := by
    simp [entryIn]
  have inTaken :
      entry ∈
        (system.nodes LEADER).log.take
          (request.prevLogIndex + request.entries.length) := by
    rw [requestSafe.2.2.2.2.2.2]
    exact inCombined
  exact core.termsAreOne LEADER entry (List.mem_of_mem_take inTaken)

/-- A conflict-free extension retains the follower's entire old log. -/
theorem noConflictExtensionPreservesLog
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (extension : noConflictExtension state request) :
    state.log <+:
      state.log.take request.prevLogIndex ++ request.entries := by
  have suffixEq :
      state.log.drop request.prevLogIndex =
        request.entries.take
          (state.log.length - request.prevLogIndex) := by
    have overlap := extension.2.2.2
    have dropLength :
        (state.log.drop request.prevLogIndex).length =
          state.log.length - request.prevLogIndex := by
      simp
    rw [← dropLength, List.take_length] at overlap
    simpa [List.length_drop] using overlap
  have suffixPrefix :
      state.log.drop request.prevLogIndex <+: request.entries := by
    rw [suffixEq]
    exact List.take_prefix _ _
  rcases suffixPrefix with ⟨tail, tailEq⟩
  refine ⟨tail, ?_⟩
  calc
    state.log ++ tail =
        (state.log.take request.prevLogIndex ++
          state.log.drop request.prevLogIndex) ++ tail := by
            rw [List.take_append_drop]
    _ =
        state.log.take request.prevLogIndex ++
          (state.log.drop request.prevLogIndex ++ tail) := by
            rw [← List.append_assoc, List.take_append_drop]
    _ = state.log.take request.prevLogIndex ++ request.entries := by
      rw [tailEq]

/-- Two term-one logs cannot trigger the differing-term conflict branch. -/
theorem noReachableTermConflict
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (core : SystemInductiveInvariant system)
    (requestSafe : RequestMatchesLeader system request) :
    Not (hasTermConflict (system.nodes destination) request) := by
  intro conflict
  let overlap := overlapLength (system.nodes destination) request
  let left :=
    ((system.nodes destination).log.drop request.prevLogIndex).take overlap
  let right := request.entries.take overlap
  have leftTerms :
      left.map Entry.term = List.replicate left.length TERM_ONE := by
    rw [List.map_eq_replicate_iff]
    intro entry member
    exact core.termsAreOne destination entry
      (List.mem_of_mem_drop (List.mem_of_mem_take member))
  have rightTerms :
      right.map Entry.term = List.replicate right.length TERM_ONE := by
    rw [List.map_eq_replicate_iff]
    intro entry member
    exact requestEntriesTermOne core requestSafe entry
      (List.mem_of_mem_take member)
  have leftLength : left.length = overlap := by
    simp [
      left,
      overlap,
      overlapLength,
      List.length_take,
      List.length_drop
    ]
  have rightLength : right.length = overlap := by
    simp [
      right,
      overlap,
      overlapLength,
      List.length_take
    ]
  have leftTerms' :
      left.map Entry.term = List.replicate overlap TERM_ONE := by
    simpa [leftLength] using leftTerms
  have rightTerms' :
      right.map Entry.term = List.replicate overlap TERM_ONE := by
    simpa [rightLength] using rightTerms
  apply conflict.2
  exact leftTerms'.trans rightTerms'.symm

/-- The NACK match search never returns an index past the searched log. -/
theorem findHighestPossibleMatchBoundedByLog
    (log : List (Entry TxId))
    (index term : Nat) :
    findHighestPossibleMatch log index term <= log.length := by
  unfold findHighestPossibleMatch
  let values := List.range (min index log.length + 1)
  let choose :=
    fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best
  have allBounded :
      forall candidate,
        candidate ∈ values ->
          candidate <= log.length := by
    intro candidate member
    simp [values] at member
    omega
  have foldBounded :
      forall (candidates : List Nat) (best : Nat),
        (forall candidate, candidate ∈ candidates ->
          candidate <= log.length) ->
        best <= log.length ->
        candidates.foldl choose best <= log.length := by
    intro candidates
    induction candidates with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best candidatesBound bestBound
        apply inductionHypothesis
        · intro candidate member
          exact candidatesBound candidate (by simp [member])
        · have headBound := candidatesBound head (by simp)
          simp only [choose]
          split <;> omega
  change values.foldl choose 0 <= log.length
  exact foldBounded values 0 allBounded (by omega)

/-- A valid nonzero index in an all-term-one log has term one. -/
theorem termAtEqTermOne
    {log : List (Entry TxId)}
    {index : Nat}
    (positive : 0 < index)
    (bounded : index <= log.length)
    (termsAreOne :
      forall entry, entry ∈ log -> entry.term = TERM_ONE) :
    termAt log index = TERM_ONE := by
  unfold termAt entryAt?
  simp only [positive.ne', ↓reduceIte]
  rw [List.getElem?_eq_getElem (by omega)]
  simp
  exact termsAreOne _ (List.getElem_mem (by omega))

/-- A nonempty all-term-one log reports term one at its final index. -/
theorem lastTermEqOne
    {log : List (Entry TxId)}
    (nonempty : Not (log = []))
    (termsAreOne :
      forall entry, entry ∈ log -> entry.term = TERM_ONE) :
    termAt log log.length = TERM_ONE := by
  apply termAtEqTermOne
  · exact List.length_pos_iff_ne_nil.mpr nonempty
  · exact le_refl _
  · exact termsAreOne

/-- The RequestVote up-to-date check makes the voter log a candidate prefix. -/
theorem voteLogUpToDateImpliesPrefix
    {state : State TxId}
    {request : RequestVoteRequest}
    (core : SystemInductiveInvariant state)
    (requestSafe : RequestVoteRequestSafe state request)
    (upToDate : voteLogUpToDate (state.nodes request.destination) request) :
    (state.nodes request.destination).log <+:
      (state.nodes request.source).log := by
  let voterLog := (state.nodes request.destination).log
  let candidateLog := (state.nodes request.source).log
  have comparable :=
    prefixesComparable
      (core.logsPrefixLeader request.destination)
      (core.logsPrefixLeader request.source)
  rcases comparable with voterPrefix | candidatePrefix
  · exact voterPrefix
  · have candidateLength :
        request.lastLogIndex = candidateLog.length :=
      requestSafe.2.2.2.2.2
    have candidateTerm :
        request.lastLogTerm = termAt candidateLog candidateLog.length := by
      simpa [candidateLog] using requestSafe.2.2.2.2.1
    have voterLengthLe : voterLog.length <= candidateLog.length := by
      rcases upToDate with newerTerm | sameTerm
      · by_contra notLe
        have candidateNonempty : Not (candidateLog = []) := by
          intro empty
          have candidateTermZero :
              request.lastLogTerm = 0 := by
            simpa [candidateLog, empty] using candidateTerm
          rw [candidateTermZero] at newerTerm
          omega
        have voterNonempty : Not (voterLog = []) := by
          intro empty
          simp [voterLog, empty] at notLe
        have candidateLast :=
          lastTermEqOne candidateNonempty
            (core.termsAreOne request.source)
        have voterLast :=
          lastTermEqOne voterNonempty
            (core.termsAreOne request.destination)
        rw [candidateTerm, candidateLast, voterLast] at newerTerm
        omega
      · rw [candidateLength] at sameTerm
        exact sameTerm.2
    have logsEqual :=
      candidatePrefix.eq_of_length_le voterLengthLe
    simpa [logsEqual]

/-- An enabled RequestVote send captures the candidate's current log summary. -/
theorem makeRequestVoteRequestSafe
    {state : State TxId}
    {source destination : Node}
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    RequestVoteRequestSafe state
      (makeRequestVoteRequest state source destination) := by
  have selfVote := core.candidatesSelfVote source enabled.1
  exact
    ⟨enabled.2.1, enabled.2.2, enabled.2.1, selfVote.2.1, rfl, rfl⟩

/-- A NACK generated from safe state has metadata bounded by the leader log. -/
theorem failureResponseSafe
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (core : SystemInductiveInvariant system)
    (requestSafe : RequestMatchesLeader system request) :
    ResponseMatchesLeader system
      (failureResponse (system.nodes destination) request) := by
  have destinationPrefix := core.logsPrefixLeader destination
  have currentTermValid :
      (system.nodes destination).currentTerm ∈
        ({TERM_ONE, 2} : Finset Nat) := by
    rcases core.currentTermsValid destination with termOne | termTwo
    · simp [termOne]
    · simp [termTwo]
  let previousTerm :=
    if request.prevLogIndex = 0 then
      0
    else if request.prevLogIndex > (system.nodes destination).log.length then
      0
    else
      termAt
        (system.nodes destination).log
        (system.nodes destination).log.length
  by_cases stale : request.term < (system.nodes destination).currentTerm
  · simp [
      ResponseMatchesLeader,
      failureResponse,
      stale,
      requestSafe.1,
      requestSafe.2.1,
      currentTermValid,
      destinationPrefix.length_le
    ]
  · by_cases previousTermZero : previousTerm = 0
    · simp [
        ResponseMatchesLeader,
        failureResponse,
        stale,
        previousTerm,
        previousTermZero,
        requestSafe.1,
        requestSafe.2.1,
        currentTermValid,
        destinationPrefix.length_le
      ]
    · let matchIndex :=
        findHighestPossibleMatch
          (system.nodes destination).log
          request.prevLogIndex
          request.prevLogTerm
      have matchBound :
          matchIndex <= (system.nodes destination).log.length :=
        findHighestPossibleMatchBoundedByLog
          (system.nodes destination).log
          request.prevLogIndex
          request.prevLogTerm
      by_cases matchIndexZero : matchIndex = 0
      · simp [
          ResponseMatchesLeader,
          failureResponse,
          stale,
          previousTerm,
          previousTermZero,
          matchIndex,
          matchIndexZero,
          requestSafe.1,
          requestSafe.2.1,
          destinationPrefix.length_le
        ]
      · have matchTerm :
            termAt (system.nodes destination).log matchIndex = TERM_ONE :=
          termAtEqTermOne
            (Nat.pos_of_ne_zero matchIndexZero)
            matchBound
            (core.termsAreOne destination)
        simp [
          ResponseMatchesLeader,
          failureResponse,
          stale,
          previousTerm,
          previousTermZero,
          matchIndex,
          matchIndexZero,
          matchTerm,
          requestSafe.1,
          requestSafe.2.1,
          le_trans matchBound destinationPrefix.length_le
        ]

/-- Conflict truncation is unreachable while every log entry has term one. -/
theorem conflictAppendEntriesRequestDisabled
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (core : SystemInductiveInvariant system)
    (requestSafe : RequestMatchesLeader system request) :
    conflictAppendEntriesRequest? (system.nodes destination) request = none := by
  unfold conflictAppendEntriesRequest?
  simp [noReachableTermConflict core requestSafe]

/-- Every successful request-handler branch establishes the common postconditions. -/
theorem handleAppendEntriesRequestPreserves
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (core : SystemInductiveInvariant system)
    (requestDestination : request.destination = destination)
    (requestSafe : RequestMatchesLeader system request)
    (handled :
      handleAppendEntriesRequest? (system.nodes destination) request =
        some (after, response)) :
    RequestHandlerPost
      system (system.nodes destination) after request response := by
  have requestDestinationNeLeader :
      Not (request.destination = LEADER) :=
    requestSafe.2.1
  have leaderNeRequestDestination :
      Not (LEADER = request.destination) :=
    Ne.symm requestDestinationNeLeader
  have leaderNeDestination : Not (LEADER = destination) := by
    intro leaderEq
    apply requestDestinationNeLeader
    rw [requestDestination, leaderEq]
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have afterEq := congrArg Prod.fst pairEq
      have responseEq := congrArg Prod.snd pairEq
      dsimp at afterEq responseEq
      subst after
      subst response
      have destinationPrefix := core.logsPrefixLeader destination
      have destinationBound := core.commitIndicesBounded destination
      constructor
      · exact destinationPrefix
      · exact destinationBound
      · exact prefixRefl _
      · exact core.termsAreOne destination
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · exact prefixRefl _
      · intro _
        rfl
      · simpa [
          requestDestination,
          leaderNeDestination,
          requestDestinationNeLeader,
          leaderNeRequestDestination,
          updateNode
        ] using
          (failureResponseSafe
            (destination := destination) core requestSafe)
    · contradiction
  · rename_i rejected
    unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      split at handled
      · rename_i alreadyState alreadyResponse already
        unfold appendEntriesAlreadyDone? at already
        split at already
        · rename_i alreadyDone
          have pairEq :=
            (Option.some.inj already).trans (Option.some.inj handled)
          have afterEq := congrArg Prod.fst pairEq
          have responseEq := congrArg Prod.snd pairEq
          dsimp at afterEq responseEq
          subst after
          subst response
          constructor
          · exact core.logsPrefixLeader destination
          · simp [committedFromLeader]
            exact core.commitIndicesBounded destination
          · exact
              takeMaxCommitMonotonic
                (system.nodes destination).log
                (core.commitIndicesBounded destination)
          · exact core.termsAreOne destination
          · rfl
          · rfl
          · rfl
          · rfl
          · rfl
          · rfl
          · exact prefixRefl _
          · intro _
            rfl
          · refine
              ⟨requestSafe.1,
                requestSafe.2.1,
                by
                  have currentTermOne :=
                    accepted.1.symm.trans requestSafe.2.2.1
                  simp [
                    successResponse,
                    currentTermOne
                  ], ?_, ?_⟩
            · simp [successResponse]
              simpa [
                requestDestinationNeLeader,
                leaderNeRequestDestination,
                updateNode,
                Function.update
              ] using
                requestSafe.2.2.2.2.1
            · intro _
              have responseWithinFollower :
                  request.prevLogIndex + request.entries.length <=
                    (system.nodes destination).log.length := by
                rcases alreadyDone with entriesEmpty | entriesPresent
                · simp [entriesEmpty]
                  rcases accepted.2.2.1 with previousZero | previousPresent
                  · omega
                  · exact previousPresent.1
                · exact entriesPresent.1
              have equalTake :=
                takeEqOfPrefix
                  (core.logsPrefixLeader destination)
                  responseWithinFollower
              simpa [
                successResponse,
                updateNode,
                Function.update,
                requestSafe.1,
                requestDestinationNeLeader,
                leaderNeRequestDestination,
                requestDestination,
                leaderNeDestination
              ] using equalTake.symm
        · contradiction
      · rename_i already
        split at handled
        · rename_i extendedState extendedResponse extended
          unfold noConflictAppendEntriesRequest? at extended
          split at extended
          · rename_i extension
            have pairEq :=
              (Option.some.inj extended).trans (Option.some.inj handled)
            have afterEq := congrArg Prod.fst pairEq
            have responseEq := congrArg Prod.snd pairEq
            dsimp at afterEq responseEq
            subst after
            subst response
            have newPrefix :=
              requestExtensionPrefixLeader
                (core.logsPrefixLeader destination)
                requestSafe
                extension.2.1
            have previousAboveCommit : (system.nodes destination).commitIndex <=
                request.prevLogIndex :=
              accepted.2.2.2
            have oldCommitPrefixNew :
                (system.nodes destination).committedLog <+:
                  (system.nodes destination).log.take
                    request.prevLogIndex ++ request.entries := by
              have taken :=
                (List.take_prefix
                  (system.nodes destination).commitIndex
                  ((system.nodes destination).log.take
                    request.prevLogIndex)).trans
                    (List.prefix_append
                      ((system.nodes destination).log.take
                        request.prevLogIndex)
                      request.entries)
              simpa [
                NodeState.committedLog,
                List.take_take,
                Nat.min_eq_left previousAboveCommit
              ] using taken
            have oldCommitBoundNew :
                (system.nodes destination).commitIndex <=
                  ((system.nodes destination).log.take
                    request.prevLogIndex ++ request.entries).length := by
              simp [
                List.length_append,
                List.length_take,
                Nat.min_eq_left extension.2.1
              ]
              omega
            have oldCommittedLength :
                (system.nodes destination).committedLog.length =
                  (system.nodes destination).commitIndex := by
              simp [
                NodeState.committedLog,
                List.length_take,
                Nat.min_eq_left
                  (core.commitIndicesBounded destination)
              ]
            have oldCommittedEq :
                (system.nodes destination).committedLog =
                  ((system.nodes destination).log.take
                    request.prevLogIndex ++ request.entries).take
                      (system.nodes destination).commitIndex := by
              rw [List.prefix_iff_eq_take] at oldCommitPrefixNew
              rw [oldCommittedLength] at oldCommitPrefixNew
              exact oldCommitPrefixNew
            constructor
            · exact newPrefix
            · simp [
                committedFromLeader,
                List.length_append,
                List.length_take,
                Nat.min_eq_left extension.2.1
              ]
              omega
            · rw [oldCommittedEq]
              exact
                takeMaxCommitMonotonic
                  ((system.nodes destination).log.take
                    request.prevLogIndex ++ request.entries)
                  oldCommitBoundNew
            · intro entry member
              exact core.termsAreOne LEADER entry
                (memOfPrefix newPrefix member)
            · rfl
            · rfl
            · rfl
            · rfl
            · rfl
            · rfl
            · exact
                noConflictExtensionPreservesLog
                  (system.nodes destination) request extension
            · intro termTwo
              have termOne :=
                accepted.1.symm.trans requestSafe.2.2.1
              rw [termOne] at termTwo
              simp [TERM_ONE] at termTwo
            · refine
                ⟨requestSafe.1,
                  requestSafe.2.1,
                  by
                    have currentTermOne :=
                      accepted.1.symm.trans requestSafe.2.2.1
                    simp [
                      successResponse,
                      currentTermOne
                    ], ?_, ?_⟩
              · simpa [
                  successResponse,
                  updateNode,
                  Function.update,
                  requestDestinationNeLeader,
                  leaderNeRequestDestination,
                  List.length_append,
                  List.length_take,
                  Nat.min_eq_left extension.2.1
                ] using newPrefix.length_le
              · intro _
                have leaderTake := prefixEqTake newPrefix
                have newLengthLe :
                    ((system.nodes destination).log.take
                          request.prevLogIndex).length +
                        request.entries.length <=
                      request.prevLogIndex + request.entries.length := by
                  simp [
                    List.length_take,
                    Nat.min_eq_left extension.2.1
                  ]
                have followerTake :
                    (List.take request.prevLogIndex
                          (system.nodes destination).log ++
                        request.entries).take
                        (request.prevLogIndex + request.entries.length) =
                      List.take request.prevLogIndex
                          (system.nodes destination).log ++
                        request.entries :=
                  List.take_of_length_le
                    (by simpa [List.length_append] using newLengthLe)
                simpa [
                  successResponse,
                  updateNode,
                  Function.update,
                  requestSafe.1,
                  requestDestinationNeLeader,
                  leaderNeRequestDestination,
                  requestDestination,
                  leaderNeDestination,
                  List.length_append,
                  List.length_take,
                  Nat.min_eq_left extension.2.1,
                  followerTake
                ] using leaderTake
          · contradiction
        · rename_i extended
          split at handled
          · simp at handled
          · rename_i truncated conflict
            have impossible :
                False := by
              unfold conflictAppendEntriesRequest? at conflict
              split at conflict
              · rename_i conflictEnabled
                exact
                  noReachableTermConflict core requestSafe
                    conflictEnabled.1
              · contradiction
            exact impossible.elim
    · contradiction

/-- Updating a node through AppendEntries preserves every existing vote snapshot. -/
theorem requestHandlerPreservesVoteMessageSafe
    {state : State TxId}
    {destination : Node}
    {before after : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (post : RequestHandlerPost state before after request response)
    (beforeEq : before = state.nodes destination)
    {message : Message TxId}
    (safe :
      match message with
      | .requestVoteRequest request => RequestVoteRequestSafe state request
      | .requestVoteResponse voteResponse =>
          RequestVoteResponseSafe state voteResponse
      | _ => True) :
    match message with
    | .requestVoteRequest request =>
        RequestVoteRequestSafe
          { state with nodes := updateNode state.nodes destination after }
          request
    | .requestVoteResponse voteResponse =>
        RequestVoteResponseSafe
          { state with nodes := updateNode state.nodes destination after }
          voteResponse
    | _ => True := by
  subst before
  cases message with
  | appendEntriesRequest _ => trivial
  | appendEntriesResponse _ => trivial
  | requestVoteRequest request =>
      by_cases sourceEq : request.source = destination
      · have sourceTermTwo := safe.2.2.1
        have destinationTermTwo :
            (state.nodes destination).currentTerm = 2 := by
          simpa [sourceEq] using sourceTermTwo
        have logUnchanged :=
          post.logUnchangedIfTermTwo destinationTermTwo
        simpa [
          RequestVoteRequestSafe,
          sourceEq,
          post.currentTermUnchanged,
          post.votedForUnchanged,
          logUnchanged
        ] using safe
      · simpa [
          RequestVoteRequestSafe,
          updateNode,
          Function.update,
          sourceEq
        ] using safe
  | requestVoteResponse voteResponse =>
      by_cases sourceEq : voteResponse.source = destination
      · have sourceTermTwo := safe.2.2.1
        have destinationTermTwo :
            (state.nodes destination).currentTerm = 2 := by
          simpa [sourceEq] using sourceTermTwo
        have logUnchanged :=
          post.logUnchangedIfTermTwo destinationTermTwo
        by_cases candidateEq : voteResponse.destination = destination
        · simpa [
            RequestVoteResponseSafe,
            sourceEq,
            candidateEq,
            post.currentTermUnchanged,
            post.votedForUnchanged,
            logUnchanged
          ] using safe
        · simpa [
            RequestVoteResponseSafe,
            sourceEq,
            candidateEq,
            post.currentTermUnchanged,
            post.votedForUnchanged,
            logUnchanged,
            updateNode,
            Function.update
          ] using safe
      · by_cases candidateEq : voteResponse.destination = destination
        · have candidateTermTwo := safe.2.2.2.1
          have destinationTermTwo :
              (state.nodes destination).currentTerm = 2 := by
            simpa [candidateEq] using candidateTermTwo
          have logUnchanged :=
            post.logUnchangedIfTermTwo destinationTermTwo
          simpa [
            RequestVoteResponseSafe,
            sourceEq,
            candidateEq,
            post.currentTermUnchanged,
            logUnchanged,
            updateNode,
            Function.update
          ] using safe
        · simpa [
            RequestVoteResponseSafe,
            sourceEq,
            candidateEq,
            updateNode,
            Function.update
          ] using safe

/-- Extending one follower log preserves snapshots from older ACKs. -/
theorem requestHandlerPreservesResponseSafe
    {state : State TxId}
    {destination : Node}
    {before after : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {handlerResponse response : AppendEntriesResponse}
    (post :
      RequestHandlerPost
        state before after request handlerResponse)
    (beforeEq : before = state.nodes destination)
    (leaderNeDestination : Not (LEADER = destination))
    (safe : ResponseMatchesLeader state response) :
    ResponseMatchesLeader
      { state with nodes := updateNode state.nodes destination after }
      response := by
  subst before
  rcases safe with
    ⟨responseDestination, responseSource, responseTerm,
      responseBound, responsePrefix⟩
  refine
    ⟨responseDestination, responseSource, responseTerm,
      by
        simpa [updateNode, Function.update, leaderNeDestination] using
          responseBound, ?_⟩
  intro success
  by_cases sourceEq : response.source = destination
  · have sourceBound :
        response.lastLogIndex <=
          (state.nodes destination).log.length := by
      have lengths :=
        congrArg List.length (responsePrefix success)
      simp [
        sourceEq,
        List.length_take,
        Nat.min_eq_left responseBound
      ] at lengths
      omega
    have sourceTake :=
      takeEqOfPrefix post.logMonotonic sourceBound
    calc
      ({ state with
          nodes := updateNode state.nodes destination after }.nodes LEADER).log.take
          response.lastLogIndex =
          (state.nodes LEADER).log.take response.lastLogIndex := by
            simp [updateNode, Function.update, leaderNeDestination]
      _ = (state.nodes response.source).log.take response.lastLogIndex :=
        responsePrefix success
      _ =
          ({ state with
            nodes := updateNode state.nodes destination after }.nodes
              response.source).log.take response.lastLogIndex := by
            simpa [sourceEq, updateNode, Function.update] using sourceTake
  · simpa [
      updateNode,
      Function.update,
      leaderNeDestination,
      sourceEq
    ] using responsePrefix success

/-- Extending a follower retains every prefix named by the leader's match index. -/
theorem requestHandlerPreservesMatchIndexPrefix
    {state : State TxId}
    {destination : Node}
    {before after : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (core : SystemInductiveInvariant state)
    (post : RequestHandlerPost state before after request response)
    (beforeEq : before = state.nodes destination)
    (leaderNeDestination : Not (LEADER = destination)) :
    MatchIndexDescribesPrefix
      { state with nodes := updateNode state.nodes destination after } := by
  subst before
  intro peer
  by_cases peerEq : peer = destination
  · subst peer
    let index := (state.nodes LEADER).matchIndex destination
    have oldEquality := core.matchIndexDescribesPrefix destination
    have leaderBound := core.matchIndicesBounded destination
    have followerBound :
        index <= (state.nodes destination).log.length := by
      have lengths := congrArg List.length oldEquality
      simp [
        index,
        List.length_take,
        Nat.min_eq_left leaderBound
      ] at lengths
      omega
    have followerTake :=
      takeEqOfPrefix post.logMonotonic followerBound
    calc
      ({ state with
          nodes := updateNode state.nodes destination after }.nodes LEADER).log.take
          (({ state with
            nodes := updateNode state.nodes destination after }.nodes LEADER).matchIndex
              destination) =
          (state.nodes LEADER).log.take index := by
            simp [
              index, updateNode, Function.update, leaderNeDestination
            ]
      _ = (state.nodes destination).log.take index := oldEquality
      _ = after.log.take index := followerTake
      _ =
          ({ state with
            nodes := updateNode state.nodes destination after }.nodes
              destination).log.take
            (({ state with
              nodes := updateNode state.nodes destination after }.nodes LEADER).matchIndex
                destination) := by
            simp [
              index, updateNode, Function.update, leaderNeDestination
            ]
  · simpa [
      updateNode,
      Function.update,
      leaderNeDestination,
      peerEq
    ] using core.matchIndexDescribesPrefix peer

/-- Facts guaranteed after the leader handles an AppendEntries response. -/
structure ResponseHandlerPost
    (system : State TxId)
    (before after : NodeState TxId)
    (response : AppendEntriesResponse) : Prop where
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  sentIndicesBounded :
    forall node,
      after.sentIndex node <= (system.nodes LEADER).log.length
  matchIndicesBounded :
    forall node,
      after.matchIndex node <= (system.nodes LEADER).log.length
  matchIndicesMonotonic :
    forall node,
      (system.nodes LEADER).matchIndex node <= after.matchIndex node
  matchIndicesDescribePrefix :
    forall node,
      after.log.take (after.matchIndex node) =
        (system.nodes node).log.take (after.matchIndex node)

/-- Updating leader replication indices preserves every queued ACK snapshot. -/
theorem responseHandlerPreservesResponseSafe
    {system : State TxId}
    {before after : NodeState TxId}
    {handledResponse response : AppendEntriesResponse}
    (post : ResponseHandlerPost system before after handledResponse)
    (beforeEq : before = system.nodes LEADER)
    (safe : ResponseMatchesLeader system response) :
    ResponseMatchesLeader
      { system with nodes := updateNode system.nodes LEADER after }
      response := by
  subst before
  simpa [
    ResponseMatchesLeader,
    updateNode,
    Function.update,
    safe.2.1,
    post.logUnchanged
  ] using safe

/-- Updating leader replication indices preserves every queued vote snapshot. -/
theorem responseHandlerPreservesVoteMessageSafe
    {system : State TxId}
    {before after : NodeState TxId}
    {handledResponse : AppendEntriesResponse}
    (post : ResponseHandlerPost system before after handledResponse)
    (beforeEq : before = system.nodes LEADER)
    {message : Message TxId}
    (safe :
      match message with
      | .requestVoteRequest request => RequestVoteRequestSafe system request
      | .requestVoteResponse response =>
          RequestVoteResponseSafe system response
      | _ => True) :
    match message with
    | .requestVoteRequest request =>
        RequestVoteRequestSafe
          { system with nodes := updateNode system.nodes LEADER after }
          request
    | .requestVoteResponse response =>
        RequestVoteResponseSafe
          { system with nodes := updateNode system.nodes LEADER after }
          response
    | _ => True := by
  subst before
  cases message with
  | appendEntriesRequest _ => trivial
  | appendEntriesResponse _ => trivial
  | requestVoteRequest request =>
      by_cases sourceEq : request.source = LEADER
      · simpa [
          RequestVoteRequestSafe,
          updateNode,
          Function.update,
          sourceEq,
          post.currentTermUnchanged,
          post.votedForUnchanged,
          post.logUnchanged
        ] using safe
      · simpa [
          RequestVoteRequestSafe,
          updateNode,
          Function.update,
          sourceEq
        ] using safe
  | requestVoteResponse response =>
      by_cases sourceEq : response.source = LEADER
      · by_cases destinationEq : response.destination = LEADER
        · simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            destinationEq,
            post.currentTermUnchanged,
            post.votedForUnchanged,
            post.logUnchanged
          ] using safe
        · simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            destinationEq,
            post.currentTermUnchanged,
            post.votedForUnchanged,
            post.logUnchanged
          ] using safe
      · by_cases destinationEq : response.destination = LEADER
        · simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            destinationEq,
            post.currentTermUnchanged,
            post.logUnchanged
          ] using safe
        · simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            destinationEq
          ] using safe

/-- The response-side match search is bounded by the leader log. -/
theorem findHighestPossibleMatchBounded
    (log : List (Entry TxId))
    (index term : Nat) :
    findHighestPossibleMatch log index term <= log.length := by
  unfold findHighestPossibleMatch
  let values := List.range (min index log.length + 1)
  let choose :=
    fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best
  have allBounded :
      forall candidate,
        candidate ∈ values ->
          candidate <= log.length := by
    intro candidate member
    simp [values] at member
    omega
  have foldBounded :
      forall (candidates : List Nat) (best : Nat),
        (forall candidate, candidate ∈ candidates ->
          candidate <= log.length) ->
        best <= log.length ->
        candidates.foldl choose best <= log.length := by
    intro candidates
    induction candidates with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best candidatesBound bestBound
        apply inductionHypothesis
        · intro candidate member
          exact candidatesBound candidate (by simp [member])
        · have headBound := candidatesBound head (by simp)
          simp only [choose]
          split <;> omega
  change values.foldl choose 0 <= log.length
  exact foldBounded values 0 allBounded (by omega)

/-- ACK and NACK handling preserve logs and keep replication indices bounded. -/
theorem handleAppendEntriesResponsePreserves
    {system : State TxId}
    {response : AppendEntriesResponse}
    {after : NodeState TxId}
    (core : SystemInductiveInvariant system)
    (responseSafe : ResponseMatchesLeader system response)
    (handled :
      handleAppendEntriesResponse? (system.nodes LEADER) response =
        some after) :
    ResponseHandlerPost system (system.nodes LEADER) after response := by
  unfold handleAppendEntriesResponse? at handled
  split at handled
  · rename_i success
    simp at handled
    subst after
    constructor
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · intro node
      exact core.sentIndicesBounded node
    · intro node
      by_cases nodeEq : node = response.source
      · subst node
        simp only [updateIndex_same]
        change
          max
              ((system.nodes LEADER).matchIndex response.source)
              response.lastLogIndex <=
            (system.nodes LEADER).log.length
        exact
          max_le
            (core.matchIndicesBounded response.source)
            responseSafe.2.2.2.1
      · simpa [updateIndex, Function.update, nodeEq] using
          core.matchIndicesBounded node
    · intro node
      by_cases nodeEq : node = response.source
      · subst node
        simp
      · simp [updateIndex, Function.update, nodeEq]
    · intro node
      by_cases nodeEq : node = response.source
      · subst node
        simp only [updateIndex_same]
        by_cases oldLe :
            (system.nodes LEADER).matchIndex response.source <=
              response.lastLogIndex
        · rw [max_eq_right oldLe]
          exact responseSafe.2.2.2.2 success.1
        · rw [max_eq_left (Nat.le_of_not_ge oldLe)]
          exact core.matchIndexDescribesPrefix response.source
      · simpa [updateIndex, Function.update, nodeEq] using
          core.matchIndexDescribesPrefix node
  · split at handled
    · simp at handled
      subst after
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · exact core.sentIndicesBounded
      · exact core.matchIndicesBounded
      · intro node
        exact Nat.le_refl _
      · exact core.matchIndexDescribesPrefix
    · split at handled
      · rename_i failure
        simp at handled
        subst after
        constructor
        · rfl
        · rfl
        · rfl
        · rfl
        · rfl
        · rfl
        · intro node
          by_cases nodeEq : node = response.source
          · subst node
            simp only [updateIndex_same]
            change
              max
                  (min
                    (findHighestPossibleMatch
                      (system.nodes LEADER).log
                      response.lastLogIndex
                      response.term)
                    ((system.nodes LEADER).sentIndex response.source))
                  ((system.nodes LEADER).matchIndex response.source) <=
                (system.nodes LEADER).log.length
            exact
              max_le
                (le_trans
                  (min_le_right _ _)
                  (core.sentIndicesBounded response.source))
                (core.matchIndicesBounded response.source)
          · simpa [updateIndex, Function.update, nodeEq] using
              core.sentIndicesBounded node
        · intro node
          exact core.matchIndicesBounded node
        · intro node
          exact Nat.le_refl _
        · intro node
          exact core.matchIndexDescribesPrefix node
      · contradiction

/-- Removing one selected message preserves safety of every remaining message. -/
theorem queuedMessagesSafeAfterRemove
    {state : State TxId}
    {source destination : Node}
    {selected : Message TxId}
    {remaining : List (Message TxId)}
    (core : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (selected, remaining)) :
    forall queuedDestination message,
      message ∈
        updateQueue state.network destination remaining queuedDestination ->
        message.destination = queuedDestination /\
          match message with
          | .appendEntriesRequest request =>
              RequestMatchesLeader state request
          | .appendEntriesResponse response =>
              ResponseMatchesLeader state response
          | .requestVoteRequest _ => True
          | .requestVoteResponse _ => True := by
  have sound := takeFirstFromSound taken
  intro queuedDestination message member
  by_cases destinationEq : queuedDestination = destination
  · subst queuedDestination
    have inRemaining : message ∈ remaining := by
      simpa using member
    exact
      core.queuedRequestsMatchLeader
        destination message (sound.2.2 message inRemaining)
  · have oldMember : message ∈ state.network queuedDestination := by
      simpa [updateQueue, Function.update, destinationEq] using member
    exact
      core.queuedRequestsMatchLeader
        queuedDestination message oldMember

/-- Removing one selected message preserves safety of remaining vote messages. -/
theorem queuedVoteMessagesSafeAfterRemove
    {state : State TxId}
    {source destination : Node}
    {selected : Message TxId}
    {remaining : List (Message TxId)}
    (core : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (selected, remaining)) :
    forall queuedDestination message,
      message ∈
        updateQueue state.network destination remaining queuedDestination ->
        match message with
        | .requestVoteRequest request => RequestVoteRequestSafe state request
        | .requestVoteResponse response => RequestVoteResponseSafe state response
        | _ => True := by
  have sound := takeFirstFromSound taken
  intro queuedDestination message member
  by_cases destinationEq : queuedDestination = destination
  · subst queuedDestination
    have inRemaining : message ∈ remaining := by
      simpa using member
    exact
      core.queuedVoteMessagesSafe
        destination message (sound.2.2 message inRemaining)
  · have oldMember : message ∈ state.network queuedDestination := by
      simpa [updateQueue, Function.update, destinationEq] using member
    exact
      core.queuedVoteMessagesSafe
        queuedDestination message oldMember

/-- Every queued message in slice two carries either term one or term two. -/
theorem queuedMessageTermValid
    {state : State TxId}
    (core : SystemInductiveInvariant state)
    {destination : Node}
    {message : Message TxId}
    (member : message ∈ state.network destination) :
    message.term = TERM_ONE \/ message.term = 2 := by
  cases message with
  | appendEntriesRequest request =>
      have safe :=
        core.queuedRequestsMatchLeader destination
          (.appendEntriesRequest request) member
      exact Or.inl safe.2.2.2.1
  | appendEntriesResponse response =>
      have safe :=
        core.queuedRequestsMatchLeader destination
          (.appendEntriesResponse response) member
      simpa [TERM_ONE] using safe.2.2.2.1
  | requestVoteRequest request =>
      have safe :=
        core.queuedVoteMessagesSafe destination
          (.requestVoteRequest request) member
      exact Or.inr safe.1
  | requestVoteResponse response =>
      have safe :=
        core.queuedVoteMessagesSafe destination
          (.requestVoteResponse response) member
      exact Or.inr safe.1

/-- Facts guaranteed after handling a safe RequestVote request. -/
structure VoteRequestHandlerPost
    (system : State TxId)
    (destination : Node)
    (before after : NodeState TxId)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  currentTermTwo : after.currentTerm = 2
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  votedForUpdate :
    after.votedFor = before.votedFor \/
      (before.votedFor = none /\
        after.votedFor = some request.source)
  responseSafe :
    RequestVoteResponseSafe
      { system with nodes := updateNode system.nodes destination after }
      response

/-- A safe RequestVote request either preserves the vote or records its candidate. -/
theorem handleRequestVoteRequestPreserves
    {system : State TxId}
    {destination : Node}
    {request : RequestVoteRequest}
    {after : NodeState TxId}
    {response : RequestVoteResponse}
    (core : SystemInductiveInvariant system)
    (requestDestination : request.destination = destination)
    (requestSafe : RequestVoteRequestSafe system request)
    (handled :
      handleRequestVoteRequest? (system.nodes destination) request =
        some (after, response)) :
    VoteRequestHandlerPost
      system destination (system.nodes destination) after request response := by
  subst destination
  unfold handleRequestVoteRequest? at handled
  split at handled
  · rename_i termCurrent
    let grant : Bool :=
      decide (
        request.term = (system.nodes request.destination).currentTerm /\
          voteLogUpToDate (system.nodes request.destination) request /\
          ((system.nodes request.destination).votedFor = none \/
            (system.nodes request.destination).votedFor = some request.source))
    have destinationTermTwo :
        (system.nodes request.destination).currentTerm = 2 := by
      have valid := core.currentTermsValid request.destination
      rcases valid with termOne | termTwo
      · simp [requestSafe.1, termOne, TERM_ONE] at termCurrent
      · exact termTwo
    have sourceNeDestination :
        Not (request.source = request.destination) :=
      requestSafe.2.1
    have destinationNeSource :
        Not (request.destination = request.source) :=
      Ne.symm requestSafe.2.1
    by_cases granted : grant = true
    · have grantFacts :
          request.term = (system.nodes request.destination).currentTerm /\
            voteLogUpToDate (system.nodes request.destination) request /\
            ((system.nodes request.destination).votedFor = none \/
              (system.nodes request.destination).votedFor =
                some request.source) := by
        simpa [grant, Bool.decide_eq_true] using granted
      have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      constructor
      · simp [grantFacts]
      · simp [grantFacts]
      · simpa [grantFacts] using destinationTermTwo
      · simp [grantFacts]
      · simp [grantFacts]
      · simp [grantFacts]
      · simp [grantFacts]
      · simp [grantFacts]
      · rcases grantFacts.2.2 with noVote | sameVote
        · exact Or.inr ⟨noVote, by simp [grantFacts]⟩
        · left
          simp [grantFacts, sameVote]
      · refine
          ⟨destinationTermTwo, destinationNeSource,
            by
              simpa [grantFacts, updateNode] using
                destinationTermTwo,
            by
              simpa [
                updateNode,
                Function.update,
                grantFacts,
                sourceNeDestination
              ] using requestSafe.2.2.1, ?_⟩
        intro _
        constructor
        · simp [grantFacts, updateNode]
        · simpa [
            updateNode,
            Function.update,
            grantFacts,
            sourceNeDestination
          ] using
            voteLogUpToDateImpliesPrefix
              core requestSafe grantFacts.2.1
    · have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      have notGrantFacts :
          Not (
            request.term =
                (system.nodes request.destination).currentTerm /\
              voteLogUpToDate
                (system.nodes request.destination) request /\
              ((system.nodes request.destination).votedFor = none \/
                (system.nodes request.destination).votedFor =
                  some request.source)) := by
        intro facts
        apply granted
        simp [grant, facts]
      constructor
      · simp [notGrantFacts]
      · simp [notGrantFacts]
      · simpa [notGrantFacts] using destinationTermTwo
      · simp [notGrantFacts]
      · simp [notGrantFacts]
      · simp [notGrantFacts]
      · simp [notGrantFacts]
      · simp [notGrantFacts]
      · left
        simp [notGrantFacts]
      · simp [
          RequestVoteResponseSafe,
          notGrantFacts,
          destinationNeSource,
          requestSafe.2.2.1,
          destinationTermTwo,
          sourceNeDestination,
          updateNode,
          Function.update
        ]
  · simp at handled

/-- Recording a vote preserves every previously safe queued vote snapshot. -/
theorem voteRequestHandlerPreservesVoteMessageSafe
    {system : State TxId}
    {destination : Node}
    {request : RequestVoteRequest}
    {after : NodeState TxId}
    {response : RequestVoteResponse}
    (post :
      VoteRequestHandlerPost
        system destination (system.nodes destination) after request response)
    {message : Message TxId}
    (safe :
      match message with
      | .requestVoteRequest queued => RequestVoteRequestSafe system queued
      | .requestVoteResponse queued =>
          RequestVoteResponseSafe system queued
      | _ => True) :
    match message with
    | .requestVoteRequest queued =>
        RequestVoteRequestSafe
          { system with nodes := updateNode system.nodes destination after }
          queued
    | .requestVoteResponse queued =>
        RequestVoteResponseSafe
          { system with nodes := updateNode system.nodes destination after }
          queued
    | _ => True := by
  cases message with
  | appendEntriesRequest _ => trivial
  | appendEntriesResponse _ => trivial
  | requestVoteRequest queued =>
      by_cases sourceEq : queued.source = destination
      · have oldVote := safe.2.2.2.1
        have voteUnchanged : after.votedFor =
            (system.nodes destination).votedFor := by
          rcases post.votedForUpdate with unchanged | changed
          · exact unchanged
          · rw [sourceEq, changed.1] at oldVote
            contradiction
        simpa [
          RequestVoteRequestSafe,
          updateNode,
          Function.update,
          sourceEq,
          post.currentTermUnchanged,
          post.logUnchanged,
          voteUnchanged
        ] using safe
      · simpa [
          RequestVoteRequestSafe,
          updateNode,
          Function.update,
          sourceEq
        ] using safe
  | requestVoteResponse queued =>
      by_cases sourceEq : queued.source = destination
      · by_cases granted : queued.voteGranted = true
        · have oldVote := (safe.2.2.2.2 granted).1
          have voteUnchanged : after.votedFor =
              (system.nodes destination).votedFor := by
            rcases post.votedForUpdate with unchanged | changed
            · exact unchanged
            · rw [sourceEq, changed.1] at oldVote
              contradiction
          have candidateNe : Not (queued.destination = destination) := by
            intro candidateEq
            apply safe.2.1
            exact sourceEq.trans candidateEq.symm
          simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            candidateNe,
            granted,
            post.currentTermUnchanged,
            post.logUnchanged,
            voteUnchanged
          ] using safe
        · have candidateNe : Not (queued.destination = destination) := by
            intro candidateEq
            apply safe.2.1
            exact sourceEq.trans candidateEq.symm
          simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            candidateNe,
            granted,
            post.currentTermUnchanged
          ] using safe
      · by_cases candidateEq : queued.destination = destination
        · simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            candidateEq,
            post.currentTermUnchanged,
            post.logUnchanged
          ] using safe
        · simpa [
            RequestVoteResponseSafe,
            updateNode,
            Function.update,
            sourceEq,
            candidateEq
          ] using safe

/-- Facts guaranteed after tallying a RequestVote response. -/
structure VoteResponseHandlerPost
    (before after : NodeState TxId)
    (response : RequestVoteResponse) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  votesUpdate :
    after.votesGranted = before.votesGranted \/
      (response.voteGranted = true /\
        before.role = .candidate /\
        after.votesGranted =
          insert response.source before.votesGranted)

/-- Tallying a response changes only the candidate's recorded vote set. -/
theorem handleRequestVoteResponsePreserves
    {before after : NodeState TxId}
    {response : RequestVoteResponse}
    (handled :
      handleRequestVoteResponse? before response = some after) :
    VoteResponseHandlerPost before after response := by
  unfold handleRequestVoteResponse? at handled
  split at handled
  · simp at handled
    subst after
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩
  · split at handled
    · rename_i currentCandidate
      split at handled
      · rename_i granted
        simp at handled
        subst after
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl,
          Or.inr ⟨granted, currentCandidate.2, rfl⟩⟩
      · simp at handled
        subst after
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩
    · simp at handled
      subst after
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩

/-- A successful newer-message lookup identifies the queued message and order. -/
theorem newerMessageSound
    {state : State TxId}
    {source destination : Node}
    {selected : Message TxId}
    (found : newerMessage? state source destination = some selected) :
    Exists fun remaining =>
      takeFirstFrom source (state.network destination) =
        some (selected, remaining) /\
      (state.nodes destination).currentTerm < selected.term := by
  unfold newerMessage? at found
  cases taken :
      takeFirstFrom source (state.network destination) with
  | none =>
      simp [taken] at found
  | some result =>
      rcases result with ⟨message, remaining⟩
      simp only [taken, Option.bind_some] at found
      by_cases newer :
          (state.nodes destination).currentTerm < message.term
      · have selectedEq : message = selected := by
          simpa [newer] using found
        subst selected
        exact ⟨remaining, rfl, newer⟩
      · simp [newer] at found

/-- Sending one entry or heartbeat preserves the system invariant. -/
theorem appendEntriesPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    SystemInductiveInvariant (next state (.appendEntries source destination batchEnd)) := by
  have sourceEq : source = LEADER :=
    termOneLeaderImpliesInitialLeader core enabled.1 enabled.2.1
  subst source
  have leaderTermOne :
      (state.nodes LEADER).currentTerm = TERM_ONE :=
    enabled.2.1
  let request :=
    makeAppendEntriesRequest state LEADER destination batchEnd
  have requestSafe : RequestMatchesLeader state request :=
    makeAppendEntriesRequestMatchesLeader core enabled
  constructor
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, request] using core.commitIndicesBounded LEADER
    · simpa [next, request, candidateEq] using
        core.commitIndicesBounded candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, request] using core.logsPrefixLeader LEADER
    · simpa [next, request, candidateEq] using
        core.logsPrefixLeader candidate
  · intro candidate entry entryIn
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      have oldEntry :
          entry ∈ (state.nodes LEADER).log := by
        simpa [next, request] using entryIn
      exact core.termsAreOne LEADER entry oldEntry
    · have oldEntry :
          entry ∈ (state.nodes candidate).log := by
        simpa [next, request, candidateEq] using entryIn
      exact core.termsAreOne candidate entry oldEntry
  · simpa [LeaderTxIdsUnique, next, request] using
      core.leaderTxIdsUnique
  · simpa [LeaderTxIdsSubmitted, next, request] using
      core.leaderTxIdsSubmitted
  · intro queuedDestination message messageIn
    have member :
        message ∈
          enqueueNoDup state.network
            (.appendEntriesRequest request)
            queuedDestination := by
      simpa [next, request] using messageIn
    rcases
      memEnqueueNoDup
        state.network
        (.appendEntriesRequest request)
        message
        queuedDestination
        member
      with oldMessage | newMessage
    · have oldSafe :=
        core.queuedRequestsMatchLeader
          queuedDestination message oldMessage
      constructor
      · exact oldSafe.1
      · cases message with
        | appendEntriesRequest oldRequest =>
            simpa [
              next,
              request,
              RequestMatchesLeader,
              updateNode
            ] using oldSafe.2
        | appendEntriesResponse oldResponse =>
            simpa [
              next,
              request,
              ResponseMatchesLeader,
              updateNode,
              Function.update,
              oldSafe.2.2.1
            ] using oldSafe.2
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
    · rcases newMessage with ⟨destinationEq, messageEq⟩
      subst queuedDestination
      subst message
      exact ⟨rfl, requestSafe⟩
  · intro queuedDestination message messageIn
    have member :
        message ∈
          enqueueNoDup state.network
            (.appendEntriesRequest request)
            queuedDestination := by
      simpa [next, request] using messageIn
    rcases
      memEnqueueNoDup
        state.network
        (.appendEntriesRequest request)
        message
        queuedDestination
        member
      with oldMessage | newMessage
    · have oldSafe :=
        core.queuedVoteMessagesSafe
          queuedDestination message oldMessage
      cases message with
      | appendEntriesRequest oldRequest => trivial
      | appendEntriesResponse oldResponse => trivial
      | requestVoteRequest voteRequest =>
          by_cases sourceEq : voteRequest.source = LEADER
          · have sourceTermTwo := oldSafe.2.2.1
            rw [sourceEq, leaderTermOne] at sourceTermTwo
            simp [TERM_ONE] at sourceTermTwo
          · simpa [
              RequestVoteRequestSafe,
              next,
              request,
              updateNode,
              Function.update,
              sourceEq
            ] using oldSafe
      | requestVoteResponse voteResponse =>
          have sourceNe : Not (voteResponse.source = LEADER) := by
            intro sourceEq
            have sourceTermTwo := oldSafe.2.2.1
            rw [sourceEq, leaderTermOne] at sourceTermTwo
            simp [TERM_ONE] at sourceTermTwo
          have destinationNe : Not (voteResponse.destination = LEADER) := by
            intro destinationEq
            have destinationTermTwo := oldSafe.2.2.2.1
            rw [destinationEq, leaderTermOne] at destinationTermTwo
            simp [TERM_ONE] at destinationTermTwo
          simpa [
            RequestVoteResponseSafe,
            next,
            request,
            updateNode,
            Function.update,
            sourceNe,
            destinationNe
          ] using oldSafe
    · rcases newMessage with ⟨_, messageEq⟩
      subst message
      trivial
  · intro candidate
    by_cases candidateEq : candidate = destination
    · subst candidate
      have batchEndBound :
          batchEnd <= (state.nodes LEADER).log.length := by
        rw [enabled.2.2.2]
        exact min_le_right _ _
      simpa [
        next,
        updateNode,
        updateIndex,
        Function.update,
        request
      ] using batchEndBound
    · simpa [
        next,
        updateNode,
        updateIndex,
        Function.update,
        candidateEq,
        request
      ] using core.sentIndicesBounded candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, request] using core.matchIndicesBounded LEADER
    · simpa [next, request, candidateEq] using
        core.matchIndicesBounded candidate
  · intro node
    by_cases nodeEq : node = LEADER
    · subst node
      exact Or.inl leaderTermOne
    · simpa [next, request, updateNode, Function.update, nodeEq] using
        core.currentTermsValid node
  · intro node leader termOne
    by_cases nodeEq : node = LEADER
    · exact nodeEq
    · exact core.termOneLeaderIsInitial node
        (by simpa [next, request, updateNode, Function.update, nodeEq] using leader)
        (by simpa [next, request, updateNode, Function.update, nodeEq] using termOne)
  · simpa [InitialNodeTermOneIsLeader, next, request, updateNode] using
      core.initialNodeTermOneIsLeader
  · intro node candidate
    by_cases nodeEq : node = LEADER
    · subst node
      have impossible :
          (state.nodes LEADER).role = .candidate := by
        simpa [next, request, updateNode] using candidate
      exact Role.noConfusion (enabled.1.symm.trans impossible)
    · have oldCandidate :
          (state.nodes node).role = .candidate := by
        simpa [next, request, updateNode, Function.update, nodeEq] using candidate
      simpa [next, request, updateNode, Function.update, nodeEq] using
        core.candidatesSelfVote node oldCandidate
  · intro voter candidate vote
    by_cases voterEq : voter = LEADER
    · subst voter
      have oldVote :
          (state.nodes LEADER).votedFor = some candidate := by
        simpa [next, request, updateNode] using vote
      simpa [next, request, updateNode] using
        core.votedForTermTwo LEADER candidate oldVote
    · have oldVote :
          (state.nodes voter).votedFor = some candidate := by
        simpa [next, request, updateNode, Function.update, voterEq] using vote
      simpa [next, request, updateNode, Function.update, voterEq] using
        core.votedForTermTwo voter candidate oldVote
  · intro candidate voter voterIn
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      have oldIn :
          voter ∈ (state.nodes LEADER).votesGranted := by
        simpa [next, request, updateNode] using voterIn
      by_cases voterEq : voter = LEADER
      · subst voter
        simpa [next, request, updateNode] using
          core.votesGrantedSound LEADER LEADER oldIn
      · simpa [next, request, updateNode, Function.update, voterEq] using
          core.votesGrantedSound LEADER voter oldIn
    · have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [next, request, updateNode, Function.update, candidateEq] using voterIn
      by_cases voterEq : voter = LEADER
      · subst voter
        simpa [next, request, updateNode, Function.update, candidateEq] using
          core.votesGrantedSound candidate LEADER oldIn
      · simpa [
          next, request, updateNode, Function.update, candidateEq, voterEq
        ] using core.votesGrantedSound candidate voter oldIn
  · intro node leader termTwo
    by_cases nodeEq : node = LEADER
    · subst node
      have impossible := leaderTermOne
      have termTwo' :
          (state.nodes LEADER).currentTerm = 2 := by
        simpa [next, request, updateNode] using termTwo
      rw [impossible] at termTwo'
      simp [TERM_ONE] at termTwo'
    · have majority :=
        core.termTwoLeadersHaveMajority node
          (by simpa [next, request, updateNode, Function.update, nodeEq] using leader)
          (by simpa [next, request, updateNode, Function.update, nodeEq] using termTwo)
      simpa [hasElectionMajority, next, request, updateNode, Function.update, nodeEq]
        using majority
  · intro node
    by_cases nodeEq : node = LEADER
    · subst node
      simp [next, request, updateNode]
    · simpa [next, request, updateNode, Function.update, nodeEq] using
        core.matchIndexDescribesPrefix node
  · simpa [InitialLeaderCommitHasMajority, next, request, updateNode] using
      core.initialLeaderCommitHasMajority
  · simpa [InitialNodeNotCandidate, next, request, updateNode] using
      core.initialNodeNotCandidate

/-- Processing any enabled request or response preserves the system invariant. -/
theorem receivePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    SystemInductiveInvariant (next state (.receive source destination)) := by
  unfold Enabled at enabled
  cases receiveResult :
      handleReceive? state source destination with
  | none =>
      simp [receiveResult] at enabled
  | some resultingState =>
      have nextEq :
          next state (.receive source destination) = resultingState := by
        simp [next, receiveResult]
      rw [nextEq]
      unfold handleReceive? at receiveResult
      split at receiveResult
      · contradiction
      · rename_i selected remaining taken
        split at receiveResult
        · contradiction
        · rename_i destinationMatches
          split at receiveResult
          · contradiction
          rename_i notNewer
          split at receiveResult
          · rename_i request
            split at receiveResult
            · contradiction
            · rename_i nextNode response handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have selectedSafe :=
                core.queuedRequestsMatchLeader
                  destination
                  (.appendEntriesRequest request)
                  selectedSound.2.1
              have requestDestination :
                  request.destination = destination :=
                selectedSafe.1
              have requestSafe :
                  RequestMatchesLeader state request :=
                selectedSafe.2
              have destinationNeLeader :
                  Not (destination = LEADER) := by
                intro destinationEq
                apply requestSafe.2.1
                rw [requestDestination, destinationEq]
              have leaderNeDestination :
                  Not (LEADER = destination) :=
                Ne.symm destinationNeLeader
              have post :=
                handleAppendEntriesRequestPreserves
                  core requestDestination requestSafe handled
              constructor
              · intro candidate
                by_cases candidateEq : candidate = destination
                · subst candidate
                  simpa using post.commitBounded
                · simpa [candidateEq] using
                    core.commitIndicesBounded candidate
              · intro candidate
                by_cases candidateEq : candidate = destination
                · subst candidate
                  simpa [leaderNeDestination] using post.logPrefixLeader
                · simpa [candidateEq, leaderNeDestination] using
                    core.logsPrefixLeader candidate
              · intro candidate entry entryIn
                by_cases candidateEq : candidate = destination
                · subst candidate
                  exact post.termsAreOne entry (by simpa using entryIn)
                · exact
                    core.termsAreOne candidate entry
                      (by simpa [candidateEq] using entryIn)
              · simpa [LeaderTxIdsUnique, leaderNeDestination] using
                  core.leaderTxIdsUnique
              · simpa [LeaderTxIdsSubmitted, leaderNeDestination] using
                  core.leaderTxIdsSubmitted
              · intro queuedDestination message messageIn
                have member :
                    message ∈
                      enqueueNoDup
                        (updateQueue state.network destination remaining)
                        (.appendEntriesResponse response)
                        queuedDestination := by
                  simpa [reply] using messageIn
                rcases
                  memEnqueueNoDup
                    (updateQueue state.network destination remaining)
                    (.appendEntriesResponse response)
                    message
                    queuedDestination
                    member
                  with oldMessage | newMessage
                · have oldSafe :=
                    queuedMessagesSafeAfterRemove
                      core taken queuedDestination message oldMessage
                  constructor
                  · exact oldSafe.1
                  · cases message with
                    | appendEntriesRequest oldRequest =>
                        simpa [
                          RequestMatchesLeader,
                          updateNode,
                          Function.update,
                          leaderNeDestination
                        ] using oldSafe.2
                    | appendEntriesResponse oldResponse =>
                        simpa [reply] using
                          requestHandlerPreservesResponseSafe
                            post rfl leaderNeDestination oldSafe.2
                    | requestVoteRequest _ => trivial
                    | requestVoteResponse _ => trivial
                · rcases newMessage with
                    ⟨queuedDestinationEq, messageEq⟩
                  subst queuedDestination
                  subst message
                  exact
                    ⟨rfl, by
                      simpa [
                        ResponseMatchesLeader,
                        updateNode,
                        Function.update,
                        leaderNeDestination,
                        requestDestination
                      ] using post.responseSafe⟩
              · intro queuedDestination message messageIn
                have member :
                    message ∈
                      enqueueNoDup
                        (updateQueue state.network destination remaining)
                        (.appendEntriesResponse response)
                        queuedDestination := by
                  simpa [reply] using messageIn
                rcases
                  memEnqueueNoDup
                    (updateQueue state.network destination remaining)
                    (.appendEntriesResponse response)
                    message
                    queuedDestination
                    member
                  with oldMessage | newMessage
                · have oldSafe :=
                    queuedVoteMessagesSafeAfterRemove
                      core taken queuedDestination message oldMessage
                  cases message with
                  | appendEntriesRequest _ => trivial
                  | appendEntriesResponse _ => trivial
                  | requestVoteRequest request =>
                      simpa [reply] using
                        requestHandlerPreservesVoteMessageSafe
                          (message := .requestVoteRequest request)
                          post rfl oldSafe
                  | requestVoteResponse response =>
                      simpa [reply] using
                        requestHandlerPreservesVoteMessageSafe
                          (message := .requestVoteResponse response)
                          post rfl oldSafe
                · rcases newMessage with ⟨_, messageEq⟩
                  subst message
                  trivial
              · intro candidate
                simpa [leaderNeDestination] using
                  core.sentIndicesBounded candidate
              · intro candidate
                simpa [leaderNeDestination] using
                  core.matchIndicesBounded candidate
              · intro candidate
                by_cases candidateEq : candidate = destination
                · subst candidate
                  have oldValid := core.currentTermsValid destination
                  rw [← post.currentTermUnchanged] at oldValid
                  simpa [updateNode] using oldValid
                · simpa [updateNode, Function.update, candidateEq] using
                    core.currentTermsValid candidate
              · intro candidate leader termOne
                apply core.termOneLeaderIsInitial candidate
                · by_cases candidateEq : candidate = destination
                  · subst candidate
                    simpa [post.roleUnchanged] using leader
                  · simpa [candidateEq] using leader
                · by_cases candidateEq : candidate = destination
                  · subst candidate
                    simpa [post.currentTermUnchanged] using termOne
                  · simpa [candidateEq] using termOne
              · intro termOne
                have oldTermOne :
                    (state.nodes LEADER).currentTerm = TERM_ONE := by
                  simpa [
                    updateNode,
                    Function.update,
                    leaderNeDestination
                  ] using termOne
                have oldLeader :=
                  core.initialNodeTermOneIsLeader oldTermOne
                simpa [
                  updateNode,
                  Function.update,
                  leaderNeDestination
                ] using oldLeader
              · intro candidate candidateRole
                by_cases candidateEq : candidate = destination
                · subst candidate
                  have oldCandidate :
                      (state.nodes destination).role = .candidate := by
                    simpa [post.roleUnchanged] using candidateRole
                  have oldSelf :=
                    core.candidatesSelfVote destination oldCandidate
                  simpa [
                    post.currentTermUnchanged,
                    post.votedForUnchanged,
                    post.votesGrantedUnchanged,
                    updateNode
                  ] using oldSelf
                · simpa [updateNode, Function.update, candidateEq] using
                    core.candidatesSelfVote candidate
                      (by
                        simpa [
                          updateNode,
                          Function.update,
                          candidateEq
                        ] using candidateRole)
              · intro voter candidate voted
                by_cases voterEq : voter = destination
                · subst voter
                  have oldVote :
                      (state.nodes destination).votedFor = some candidate := by
                    simpa [post.votedForUnchanged] using voted
                  have oldTermTwo :=
                    core.votedForTermTwo destination candidate oldVote
                  simpa [post.currentTermUnchanged] using oldTermTwo
                · have oldVote :
                      (state.nodes voter).votedFor = some candidate := by
                    simpa [
                      updateNode,
                      Function.update,
                      voterEq
                    ] using voted
                  have oldTermTwo :=
                    core.votedForTermTwo voter candidate oldVote
                  simpa [
                    updateNode,
                    Function.update,
                    voterEq
                  ] using oldTermTwo
              · intro candidate voter voterIn
                by_cases candidateEq : candidate = destination
                · subst candidate
                  have oldIn :
                      voter ∈ (state.nodes destination).votesGranted := by
                    simpa [post.votesGrantedUnchanged] using voterIn
                  have oldSound :=
                    core.votesGrantedSound destination voter oldIn
                  have logUnchanged :=
                    post.logUnchangedIfTermTwo oldSound.1
                  by_cases voterEq : voter = destination
                  · subst voter
                    simpa [
                      post.currentTermUnchanged,
                      post.votedForUnchanged,
                      post.votesGrantedUnchanged,
                      logUnchanged,
                      updateNode
                    ] using oldSound
                  · simpa [
                      post.currentTermUnchanged,
                      post.votesGrantedUnchanged,
                      logUnchanged,
                      updateNode,
                      Function.update,
                      voterEq
                    ] using oldSound
                · have oldIn :
                      voter ∈ (state.nodes candidate).votesGranted := by
                    simpa [candidateEq] using voterIn
                  have oldSound :=
                    core.votesGrantedSound candidate voter oldIn
                  by_cases voterEq : voter = destination
                  · subst voter
                    have logUnchanged :=
                      post.logUnchangedIfTermTwo
                        (core.votedForTermTwo
                          destination candidate oldSound.2.1)
                    simpa [
                      candidateEq,
                      post.currentTermUnchanged,
                      post.votedForUnchanged,
                      logUnchanged,
                      updateNode
                    ] using oldSound
                  · simpa [
                      updateNode,
                      Function.update,
                      candidateEq,
                      voterEq
                    ] using oldSound
              · intro candidate leader termTwo
                have oldLeader :
                    (state.nodes candidate).role = .leader := by
                  by_cases candidateEq : candidate = destination
                  · subst candidate
                    simpa [post.roleUnchanged] using leader
                  · simpa [candidateEq] using leader
                have oldTermTwo :
                    (state.nodes candidate).currentTerm = 2 := by
                  by_cases candidateEq : candidate = destination
                  · subst candidate
                    simpa [post.currentTermUnchanged] using termTwo
                  · simpa [candidateEq] using termTwo
                have majority :=
                  core.termTwoLeadersHaveMajority candidate
                    oldLeader oldTermTwo
                by_cases candidateEq : candidate = destination
                · subst candidate
                  simpa [
                    hasElectionMajority,
                    post.votesGrantedUnchanged
                  ] using majority
                · simpa [hasElectionMajority, candidateEq] using majority
              · intro candidate
                simpa [reply] using
                  requestHandlerPreservesMatchIndexPrefix
                    core post rfl leaderNeDestination candidate
              · simpa [
                  InitialLeaderCommitHasMajority,
                  hasMajorityAt,
                  acknowledgingNodes,
                  updateNode,
                  Function.update,
                  leaderNeDestination
                ]
                  using core.initialLeaderCommitHasMajority
              · simpa [
                  InitialNodeNotCandidate, reply, updateNode,
                  Function.update, leaderNeDestination
                ] using core.initialNodeNotCandidate
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i nextNode handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have selectedSafe :=
                core.queuedRequestsMatchLeader
                  destination
                  (.appendEntriesResponse response)
                  selectedSound.2.1
              have responseDestination :
                  response.destination = destination :=
                selectedSafe.1
              have responseSafe :
                  ResponseMatchesLeader state response :=
                selectedSafe.2
              have responseDestinationEq :
                  response.destination = LEADER :=
                responseSafe.1
              have destinationEq : destination = LEADER :=
                responseDestination.symm.trans responseSafe.1
              cases destinationEq
              have post :=
                handleAppendEntriesResponsePreserves
                  core responseSafe
                    (by simpa [responseSafe.1] using handled)
              constructor
              · intro candidate
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  simpa [
                    post.commitIndexUnchanged,
                    post.logUnchanged
                  ] using
                    core.commitIndicesBounded LEADER
                · simpa [candidateEq] using
                    core.commitIndicesBounded candidate
              · intro candidate
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  simpa [post.logUnchanged] using
                    core.logsPrefixLeader LEADER
                · simpa [
                    candidateEq,
                    post.logUnchanged
                  ] using
                    core.logsPrefixLeader candidate
              · intro candidate entry entryIn
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  exact
                    core.termsAreOne LEADER entry
                      (by
                        simpa [
                          post.logUnchanged
                        ] using entryIn)
                · exact
                    core.termsAreOne candidate entry
                      (by
                        simpa [candidateEq] using
                          entryIn)
              · simpa [
                  LeaderTxIdsUnique,
                  post.logUnchanged
                ] using
                  core.leaderTxIdsUnique
              · simpa [
                  LeaderTxIdsSubmitted,
                  post.logUnchanged
                ] using
                  core.leaderTxIdsSubmitted
              · intro queuedDestination message messageIn
                have oldSafe :=
                  queuedMessagesSafeAfterRemove
                    core taken queuedDestination message
                      (by simpa using messageIn)
                constructor
                · exact oldSafe.1
                · cases message with
                  | appendEntriesRequest oldRequest =>
                      simpa [
                        RequestMatchesLeader,
                        post.logUnchanged
                      ] using oldSafe.2
                  | appendEntriesResponse oldResponse =>
                      simpa using
                        responseHandlerPreservesResponseSafe
                          post rfl oldSafe.2
                  | requestVoteRequest _ => trivial
                  | requestVoteResponse _ => trivial
              · intro queuedDestination message messageIn
                have oldSafe :=
                  queuedVoteMessagesSafeAfterRemove
                    core taken queuedDestination message
                      (by simpa using messageIn)
                cases message with
                | appendEntriesRequest _ => trivial
                | appendEntriesResponse _ => trivial
                | requestVoteRequest request =>
                    simpa using
                      responseHandlerPreservesVoteMessageSafe
                        (message := .requestVoteRequest request)
                        post rfl oldSafe
                | requestVoteResponse voteResponse =>
                    simpa using
                      responseHandlerPreservesVoteMessageSafe
                        (message := .requestVoteResponse voteResponse)
                        post rfl oldSafe
              · simpa [
                  SentIndicesBounded,
                  post.logUnchanged
                ] using post.sentIndicesBounded
              · simpa [
                  MatchIndicesBounded,
                  post.logUnchanged
                ] using post.matchIndicesBounded
              · intro node
                by_cases nodeEq : node = LEADER
                · subst node
                  have oldValid := core.currentTermsValid LEADER
                  rw [← post.currentTermUnchanged] at oldValid
                  simpa [updateNode] using oldValid
                · simpa [
                    updateNode,
                    Function.update,
                    nodeEq
                  ] using core.currentTermsValid node
              · intro node leader termOne
                apply core.termOneLeaderIsInitial node
                · by_cases nodeEq : node = LEADER
                  · subst node
                    simpa [
                      updateNode,
                      post.roleUnchanged
                    ] using leader
                  · simpa [
                      updateNode,
                      Function.update,
                      nodeEq
                    ] using leader
                · by_cases nodeEq : node = LEADER
                  · subst node
                    simpa [
                      updateNode,
                      post.currentTermUnchanged
                    ] using termOne
                  · simpa [
                      updateNode,
                      Function.update,
                      nodeEq
                    ] using termOne
              · intro termOne
                have oldTermOne :
                    (state.nodes LEADER).currentTerm = TERM_ONE := by
                  simpa [
                    updateNode,
                    post.currentTermUnchanged
                  ] using termOne
                have oldLeader :=
                  core.initialNodeTermOneIsLeader oldTermOne
                simpa [
                  updateNode,
                  post.roleUnchanged
                ] using oldLeader
              · intro node candidate
                by_cases nodeEq : node = LEADER
                · subst node
                  have oldCandidate :
                      (state.nodes LEADER).role = .candidate := by
                    simpa [
                      updateNode,
                      post.roleUnchanged
                    ] using candidate
                  have oldSelf :=
                    core.candidatesSelfVote LEADER oldCandidate
                  simpa [
                    updateNode,
                    post.currentTermUnchanged,
                    post.votedForUnchanged,
                    post.votesGrantedUnchanged
                  ] using oldSelf
                · simpa [
                    updateNode,
                    Function.update,
                    nodeEq
                  ] using core.candidatesSelfVote node
                    (by
                      simpa [
                        updateNode,
                        Function.update,
                        nodeEq
                      ] using candidate)
              · intro voter candidate voted
                by_cases voterEq : voter = LEADER
                · subst voter
                  have oldVote :
                      (state.nodes LEADER).votedFor = some candidate := by
                    simpa [
                      updateNode,
                      post.votedForUnchanged
                    ] using voted
                  have oldTerm :=
                    core.votedForTermTwo LEADER candidate oldVote
                  simpa [
                    updateNode,
                    post.currentTermUnchanged
                  ] using oldTerm
                · have oldVote :
                      (state.nodes voter).votedFor = some candidate := by
                    simpa [
                      updateNode,
                      Function.update,
                      voterEq
                    ] using voted
                  simpa [
                    updateNode,
                    Function.update,
                    voterEq
                  ] using core.votedForTermTwo voter candidate oldVote
              · intro candidate voter voterIn
                have oldIn :
                    voter ∈ (state.nodes candidate).votesGranted := by
                  by_cases candidateEq : candidate = LEADER
                  · subst candidate
                    simpa [
                      updateNode,
                      post.votesGrantedUnchanged
                    ] using voterIn
                  · simpa [
                      updateNode,
                      Function.update,
                      candidateEq
                    ] using voterIn
                have oldSound :=
                  core.votesGrantedSound candidate voter oldIn
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  by_cases voterEq : voter = LEADER
                  · subst voter
                    simpa [
                      updateNode,
                      post.currentTermUnchanged,
                      post.votedForUnchanged,
                      post.logUnchanged
                    ] using oldSound
                  · simpa [
                      updateNode,
                      Function.update,
                      voterEq,
                      post.currentTermUnchanged,
                      post.logUnchanged
                    ] using oldSound
                · by_cases voterEq : voter = LEADER
                  · subst voter
                    simpa [
                      updateNode,
                      Function.update,
                      candidateEq,
                      post.votedForUnchanged,
                      post.logUnchanged
                    ] using oldSound
                  · simpa [
                      updateNode,
                      Function.update,
                      candidateEq,
                      voterEq
                    ] using oldSound
              · intro node leader termTwo
                have oldLeader :
                    (state.nodes node).role = .leader := by
                  by_cases nodeEq : node = LEADER
                  · subst node
                    simpa [
                      updateNode,
                      post.roleUnchanged
                    ] using leader
                  · simpa [
                      updateNode,
                      Function.update,
                      nodeEq
                    ] using leader
                have oldTermTwo :
                    (state.nodes node).currentTerm = 2 := by
                  by_cases nodeEq : node = LEADER
                  · subst node
                    simpa [
                      updateNode,
                      post.currentTermUnchanged
                    ] using termTwo
                  · simpa [
                      updateNode,
                      Function.update,
                      nodeEq
                    ] using termTwo
                have oldMajority :=
                  core.termTwoLeadersHaveMajority node oldLeader oldTermTwo
                by_cases nodeEq : node = LEADER
                · subst node
                  simpa [
                    hasElectionMajority,
                    updateNode,
                    post.votesGrantedUnchanged
                  ] using oldMajority
                · simpa [
                    hasElectionMajority,
                    updateNode,
                    Function.update,
                    nodeEq
                  ] using oldMajority
              · intro node
                by_cases nodeEq : node = LEADER
                · subst node
                  simpa [
                    updateNode,
                    post.logUnchanged
                  ] using post.matchIndicesDescribePrefix LEADER
                · simpa [
                    updateNode,
                    Function.update,
                    nodeEq
                  ] using post.matchIndicesDescribePrefix node
              · rcases core.initialLeaderCommitHasMajority with zero | majority
                · left
                  simpa [
                    post.commitIndexUnchanged
                  ] using zero
                · right
                  let updated : State TxId :=
                    { state with
                      nodes := updateNode state.nodes LEADER nextNode
                      network :=
                        updateQueue state.network LEADER remaining }
                  have subset :
                      acknowledgingNodes state LEADER
                          (state.nodes LEADER).commitIndex ⊆
                        acknowledgingNodes updated LEADER
                          (updated.nodes LEADER).commitIndex := by
                    intro peer member
                    simp only [
                      acknowledgingNodes,
                      Finset.mem_filter,
                      Finset.mem_univ,
                      true_and
                    ] at member ⊢
                    rcases member with peerEq | acknowledged
                    · exact Or.inl peerEq
                    · right
                      simpa [
                        updated,
                        post.commitIndexUnchanged,
                        post.logUnchanged
                      ] using
                        le_trans acknowledged
                          (post.matchIndicesMonotonic peer)
                  have cardLe := Finset.card_le_card subset
                  have updatedMajority :
                      hasMajorityAt updated LEADER
                        (updated.nodes LEADER).commitIndex := by
                    unfold hasMajorityAt at majority ⊢
                    omega
                  simpa [updated] using
                    updatedMajority
              · simpa [
                  InitialNodeNotCandidate, updateNode,
                  post.roleUnchanged
                ] using core.initialNodeNotCandidate
          · rename_i request
            split at receiveResult
            · contradiction
            · rename_i nextNode response handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have selectedSafe :=
                core.queuedVoteMessagesSafe
                  destination
                  (.requestVoteRequest request)
                  selectedSound.2.1
              have requestDestination :
                  request.destination = destination := by
                have queuedSafe :=
                  core.queuedRequestsMatchLeader
                    destination
                    (.requestVoteRequest request)
                    selectedSound.2.1
                exact queuedSafe.1
              have post :=
                handleRequestVoteRequestPreserves
                  core requestDestination selectedSafe handled
              have votedForSomePreserved :
                  forall candidate,
                    (state.nodes destination).votedFor = some candidate ->
                      nextNode.votedFor = some candidate := by
                intro candidate oldVote
                rcases post.votedForUpdate with unchanged | changed
                · exact unchanged.trans oldVote
                · rw [changed.1] at oldVote
                  contradiction
              have roleEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).role =
                      (state.nodes node).role := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.roleUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have currentTermEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).currentTerm =
                      (state.nodes node).currentTerm := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.currentTermUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have logEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).log =
                      (state.nodes node).log := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.logUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have commitEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).commitIndex =
                      (state.nodes node).commitIndex := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.commitIndexUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have sentEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).sentIndex =
                      (state.nodes node).sentIndex := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.sentIndexUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have matchEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).matchIndex =
                      (state.nodes node).matchIndex := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.matchIndexUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have votesEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).votesGranted =
                      (state.nodes node).votesGranted := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.votesGrantedUnchanged
                · simp [updateNode, Function.update, nodeEq]
              constructor
              · simpa only [CommitIndicesBounded, commitEq, logEq] using
                  core.commitIndicesBounded
              · simpa only [LogsPrefixLeader, logEq] using
                  core.logsPrefixLeader
              · simpa only [TermsAreOne, logEq] using core.termsAreOne
              · simpa only [LeaderTxIdsUnique, logEq] using
                  core.leaderTxIdsUnique
              · simpa only [LeaderTxIdsSubmitted, logEq] using
                  core.leaderTxIdsSubmitted
              · intro queuedDestination message messageIn
                have member :
                    message ∈
                      enqueueNoDup
                        (updateQueue state.network destination remaining)
                        (.requestVoteResponse response)
                        queuedDestination := by
                  simpa using messageIn
                rcases
                  memEnqueueNoDup
                    (updateQueue state.network destination remaining)
                    (.requestVoteResponse response)
                    message queuedDestination member
                  with oldMessage | newMessage
                · have oldSafe :=
                    queuedMessagesSafeAfterRemove
                      core taken queuedDestination message oldMessage
                  constructor
                  · exact oldSafe.1
                  · cases message with
                    | appendEntriesRequest oldRequest =>
                        simpa only [RequestMatchesLeader, logEq] using
                          oldSafe.2
                    | appendEntriesResponse oldResponse =>
                        simpa only [ResponseMatchesLeader, logEq] using
                          oldSafe.2
                    | requestVoteRequest _ => trivial
                    | requestVoteResponse _ => trivial
                · rcases newMessage with ⟨destinationEq, messageEq⟩
                  subst queuedDestination
                  subst message
                  trivial
              · intro queuedDestination message messageIn
                have member :
                    message ∈
                      enqueueNoDup
                        (updateQueue state.network destination remaining)
                        (.requestVoteResponse response)
                        queuedDestination := by
                  simpa using messageIn
                rcases
                  memEnqueueNoDup
                    (updateQueue state.network destination remaining)
                    (.requestVoteResponse response)
                    message queuedDestination member
                  with oldMessage | newMessage
                · have oldSafe :=
                    queuedVoteMessagesSafeAfterRemove
                      core taken queuedDestination message oldMessage
                  cases message with
                  | appendEntriesRequest _ => trivial
                  | appendEntriesResponse _ => trivial
                  | requestVoteRequest queued =>
                      simpa using
                        voteRequestHandlerPreservesVoteMessageSafe
                          (message := .requestVoteRequest queued)
                          post oldSafe
                  | requestVoteResponse queued =>
                      simpa using
                        voteRequestHandlerPreservesVoteMessageSafe
                          (message := .requestVoteResponse queued)
                          post oldSafe
                · rcases newMessage with ⟨_, messageEq⟩
                  subst message
                  simpa using post.responseSafe
              · simpa only [SentIndicesBounded, sentEq, logEq] using
                  core.sentIndicesBounded
              · simpa only [MatchIndicesBounded, matchEq, logEq] using
                  core.matchIndicesBounded
              · simpa only [CurrentTermsValid, currentTermEq] using
                  core.currentTermsValid
              · simpa only [
                  TermOneLeaderIsInitial, roleEq, currentTermEq
                ] using core.termOneLeaderIsInitial
              · simpa only [
                  InitialNodeTermOneIsLeader, roleEq, currentTermEq
                ] using core.initialNodeTermOneIsLeader
              · intro node candidateRole
                by_cases nodeEq : node = destination
                · subst node
                  have oldCandidate :
                      (state.nodes destination).role = .candidate := by
                    simpa [updateNode, post.roleUnchanged] using candidateRole
                  have oldSelf :=
                    core.candidatesSelfVote destination oldCandidate
                  refine ⟨?_, ?_, ?_⟩
                  · simpa [updateNode, post.currentTermUnchanged] using oldSelf.1
                  · simpa [updateNode] using
                      votedForSomePreserved destination oldSelf.2.1
                  · simpa [updateNode, post.votesGrantedUnchanged] using
                      oldSelf.2.2
                · simpa [updateNode, Function.update, nodeEq] using
                    core.candidatesSelfVote node
                      (by simpa [updateNode, Function.update, nodeEq] using
                        candidateRole)
              · intro voter candidate voted
                by_cases voterEq : voter = destination
                · subst voter
                  simpa [updateNode] using post.currentTermTwo
                · simpa [updateNode, Function.update, voterEq] using
                    core.votedForTermTwo voter candidate
                      (by simpa [updateNode, Function.update, voterEq] using
                        voted)
              · intro candidate voter voterIn
                have oldIn :
                    voter ∈ (state.nodes candidate).votesGranted := by
                  by_cases candidateEq : candidate = destination
                  · subst candidate
                    simpa [updateNode, post.votesGrantedUnchanged] using voterIn
                  · simpa [updateNode, Function.update, candidateEq] using
                      voterIn
                have oldSound :=
                  core.votesGrantedSound candidate voter oldIn
                by_cases candidateEq : candidate = destination
                · subst candidate
                  by_cases voterEq : voter = destination
                  · subst voter
                    exact
                      ⟨by simpa [updateNode, post.currentTermUnchanged] using
                          oldSound.1,
                        by simpa [updateNode] using
                          votedForSomePreserved destination oldSound.2.1,
                        by simpa [updateNode, post.logUnchanged] using
                          oldSound.2.2⟩
                  · exact
                      ⟨by simpa [updateNode, post.currentTermUnchanged] using
                          oldSound.1,
                        by simpa [updateNode, Function.update, voterEq] using
                          oldSound.2.1,
                        by simpa [
                          updateNode, Function.update, voterEq,
                          post.logUnchanged
                        ] using oldSound.2.2⟩
                · by_cases voterEq : voter = destination
                  · subst voter
                    exact
                      ⟨by simpa [updateNode, Function.update, candidateEq] using
                          oldSound.1,
                        by simpa [updateNode] using
                          votedForSomePreserved candidate oldSound.2.1,
                        by simpa [
                          updateNode, Function.update, candidateEq,
                          post.logUnchanged
                        ] using oldSound.2.2⟩
                  · simpa [
                      updateNode, Function.update, candidateEq, voterEq
                    ] using oldSound
              · simpa only [
                  TermTwoLeadersHaveMajority, roleEq, currentTermEq,
                  hasElectionMajority, votesEq
                ] using core.termTwoLeadersHaveMajority
              · simpa only [
                  MatchIndexDescribesPrefix, logEq, matchEq
                ] using core.matchIndexDescribesPrefix
              · simpa only [
                  InitialLeaderCommitHasMajority,
                  hasMajorityAt, acknowledgingNodes, commitEq, matchEq
                ] using core.initialLeaderCommitHasMajority
              · simpa only [InitialNodeNotCandidate, roleEq] using
                  core.initialNodeNotCandidate
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i nextNode handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have selectedQueuedSafe :=
                core.queuedRequestsMatchLeader
                  destination
                  (.requestVoteResponse response)
                  selectedSound.2.1
              have responseDestination :
                  response.destination = destination :=
                selectedQueuedSafe.1
              have responseSafe :=
                core.queuedVoteMessagesSafe
                  destination
                  (.requestVoteResponse response)
                  selectedSound.2.1
              have post :=
                handleRequestVoteResponsePreserves handled
              have roleEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).role =
                      (state.nodes node).role := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.roleUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have currentTermEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).currentTerm =
                      (state.nodes node).currentTerm := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.currentTermUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have logEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).log =
                      (state.nodes node).log := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.logUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have commitEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).commitIndex =
                      (state.nodes node).commitIndex := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.commitIndexUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have sentEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).sentIndex =
                      (state.nodes node).sentIndex := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.sentIndexUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have matchEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).matchIndex =
                      (state.nodes node).matchIndex := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.matchIndexUnchanged
                · simp [updateNode, Function.update, nodeEq]
              have votedForEq :
                  forall node,
                    (updateNode state.nodes destination nextNode node).votedFor =
                      (state.nodes node).votedFor := by
                intro node
                by_cases nodeEq : node = destination
                · subst node
                  simpa [updateNode] using post.votedForUnchanged
                · simp [updateNode, Function.update, nodeEq]
              constructor
              · simpa only [CommitIndicesBounded, commitEq, logEq] using
                  core.commitIndicesBounded
              · simpa only [LogsPrefixLeader, logEq] using
                  core.logsPrefixLeader
              · simpa only [TermsAreOne, logEq] using core.termsAreOne
              · simpa only [LeaderTxIdsUnique, logEq] using
                  core.leaderTxIdsUnique
              · simpa only [LeaderTxIdsSubmitted, logEq] using
                  core.leaderTxIdsSubmitted
              · intro queuedDestination message messageIn
                have oldSafe :=
                  queuedMessagesSafeAfterRemove
                    core taken queuedDestination message
                      (by simpa using messageIn)
                constructor
                · exact oldSafe.1
                · cases message with
                  | appendEntriesRequest request =>
                      simpa only [RequestMatchesLeader, logEq] using oldSafe.2
                  | appendEntriesResponse queued =>
                      simpa only [ResponseMatchesLeader, logEq] using oldSafe.2
                  | requestVoteRequest _ => trivial
                  | requestVoteResponse _ => trivial
              · intro queuedDestination message messageIn
                have oldSafe :=
                  queuedVoteMessagesSafeAfterRemove
                    core taken queuedDestination message
                      (by simpa using messageIn)
                cases message with
                | appendEntriesRequest _ => trivial
                | appendEntriesResponse _ => trivial
                | requestVoteRequest request =>
                    simpa only [
                      RequestVoteRequestSafe, currentTermEq, votedForEq, logEq
                    ] using oldSafe
                | requestVoteResponse queued =>
                    simpa only [
                      RequestVoteResponseSafe, currentTermEq, votedForEq, logEq
                    ] using oldSafe
              · simpa only [SentIndicesBounded, sentEq, logEq] using
                  core.sentIndicesBounded
              · simpa only [MatchIndicesBounded, matchEq, logEq] using
                  core.matchIndicesBounded
              · simpa only [CurrentTermsValid, currentTermEq] using
                  core.currentTermsValid
              · simpa only [
                  TermOneLeaderIsInitial, roleEq, currentTermEq
                ] using core.termOneLeaderIsInitial
              · simpa only [
                  InitialNodeTermOneIsLeader, roleEq, currentTermEq
                ] using core.initialNodeTermOneIsLeader
              · intro node candidate
                have oldCandidate :
                    (state.nodes node).role = .candidate := by
                  simpa only [roleEq] using candidate
                have oldSelf :=
                  core.candidatesSelfVote node oldCandidate
                refine ⟨?_, ?_, ?_⟩
                · simpa only [currentTermEq] using oldSelf.1
                · simpa only [votedForEq] using oldSelf.2.1
                · by_cases nodeEq : node = destination
                  · subst node
                    rcases post.votesUpdate with unchanged | inserted
                    · simpa [updateNode, unchanged] using oldSelf.2.2
                    · simpa [updateNode, inserted.2.2] using
                        Finset.mem_insert_of_mem oldSelf.2.2
                  · simpa [updateNode, Function.update, nodeEq] using
                      oldSelf.2.2
              · simpa only [VotedForTermTwo, votedForEq, currentTermEq] using
                  core.votedForTermTwo
              · intro candidate voter voterIn
                by_cases candidateEq : candidate = destination
                · subst candidate
                  rcases post.votesUpdate with unchanged | inserted
                  · have oldIn :
                        voter ∈ (state.nodes destination).votesGranted := by
                      simpa [updateNode, unchanged] using voterIn
                    have oldSound :=
                      core.votesGrantedSound destination voter oldIn
                    simpa only [currentTermEq, votedForEq, logEq] using
                      oldSound
                  · have member :
                        voter = response.source \/
                          voter ∈ (state.nodes destination).votesGranted := by
                      simpa [updateNode, inserted.2.2] using voterIn
                    rcases member with newVoter | oldVoter
                    · subst voter
                      have destinationTermTwo :
                          (state.nodes destination).currentTerm = 2 := by
                        rw [← responseDestination]
                        exact responseSafe.2.2.2.1
                      have voterVote :=
                        (responseSafe.2.2.2.2 inserted.1).1
                      rw [responseDestination] at voterVote
                      have voterPrefix :=
                        (responseSafe.2.2.2.2 inserted.1).2
                      rw [responseDestination] at voterPrefix
                      exact
                        ⟨by simpa only [currentTermEq] using
                            destinationTermTwo,
                          by simpa only [votedForEq] using
                            voterVote,
                          by simpa only [logEq] using
                            voterPrefix⟩
                    · have oldSound :=
                        core.votesGrantedSound destination voter oldVoter
                      simpa only [currentTermEq, votedForEq, logEq] using
                        oldSound
                · have oldIn :
                      voter ∈ (state.nodes candidate).votesGranted := by
                    simpa [updateNode, Function.update, candidateEq] using
                      voterIn
                  have oldSound :=
                    core.votesGrantedSound candidate voter oldIn
                  simpa only [currentTermEq, votedForEq, logEq] using oldSound
              · intro node leader termTwo
                have oldLeader :
                    (state.nodes node).role = .leader := by
                  simpa only [roleEq] using leader
                have oldTermTwo :
                    (state.nodes node).currentTerm = 2 := by
                  simpa only [currentTermEq] using termTwo
                have oldMajority :=
                  core.termTwoLeadersHaveMajority node oldLeader oldTermTwo
                by_cases nodeEq : node = destination
                · subst node
                  rcases post.votesUpdate with unchanged | inserted
                  · simpa [hasElectionMajority, updateNode, unchanged] using
                      oldMajority
                  · rw [inserted.2.1] at oldLeader
                    contradiction
                · simpa [
                    hasElectionMajority, updateNode, Function.update, nodeEq
                  ] using oldMajority
              · simpa only [
                  MatchIndexDescribesPrefix, logEq, matchEq
                ] using core.matchIndexDescribesPrefix
              · simpa only [
                  InitialLeaderCommitHasMajority,
                  hasMajorityAt, acknowledgingNodes, commitEq, matchEq
                ] using core.initialLeaderCommitHasMajority
              · simpa only [InitialNodeNotCandidate, roleEq] using
                  core.initialNodeNotCandidate

/-- The computed commit frontier never exceeds the leader log length. -/
theorem highestCommittableIndexBounded
    (state : State TxId)
    (leader : Node) :
    highestCommittableIndex state leader <=
      (state.nodes leader).log.length := by
  unfold highestCommittableIndex
  let candidates := List.range ((state.nodes leader).log.length + 1)
  let choose :=
    fun best index =>
      if index > (state.nodes leader).commitIndex /\
          termAt (state.nodes leader).log index =
            (state.nodes leader).currentTerm /\
          hasMajorityAt state leader index then
        max best index
      else
        best
  have allBounded :
      forall index,
        index ∈ candidates ->
          index <= (state.nodes leader).log.length := by
    intro index member
    simp [candidates] at member
    omega
  have foldBounded :
      forall (values : List Nat) (best : Nat),
        (forall index, index ∈ values ->
          index <= (state.nodes leader).log.length) ->
        best <= (state.nodes leader).log.length ->
        values.foldl choose best <=
          (state.nodes leader).log.length := by
    intro values
    induction values with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best valuesBound bestBound
        apply inductionHypothesis
        · intro index member
          exact valuesBound index (by simp [member])
        · have headBound := valuesBound head (by simp)
          simp only [choose]
          split <;> omega
  change candidates.foldl choose 0 <= (state.nodes leader).log.length
  exact foldBounded candidates 0 allBounded (by omega)

/-- A newly selected commit frontier satisfies the term and majority guards. -/
theorem highestCommittableIndexValid
    (state : State TxId)
    (leader : Node)
    (advances :
      (state.nodes leader).commitIndex <
        highestCommittableIndex state leader) :
    termAt
        (state.nodes leader).log
        (highestCommittableIndex state leader) =
      (state.nodes leader).currentTerm /\
      hasMajorityAt state leader
        (highestCommittableIndex state leader) := by
  unfold highestCommittableIndex at advances ⊢
  let leaderState := state.nodes leader
  let valid :=
    fun index =>
      index > leaderState.commitIndex /\
        termAt leaderState.log index = leaderState.currentTerm /\
        hasMajorityAt state leader index
  let choose :=
    fun best index =>
      if valid index then max best index else best
  have foldValid :
      forall (values : List Nat) (best : Nat),
        (best = 0 \/ valid best) ->
        let result := values.foldl choose best
        result = 0 \/ valid result := by
    intro values
    induction values with
    | nil =>
        intro best bestValid
        exact bestValid
    | cons head tail inductionHypothesis =>
        intro best bestValid
        apply inductionHypothesis
        simp only [choose]
        by_cases headValid : valid head
        · simp [headValid]
          rcases bestValid with bestZero | bestIsValid
          · subst best
            exact Or.inr headValid
          · by_cases bestLeHead : best <= head
            · right
              simpa [max_eq_right bestLeHead] using headValid
            · right
              have headLeBest : head <= best := by omega
              simpa [max_eq_left headLeBest] using bestIsValid
        · simp [headValid, bestValid]
  have resultValid :=
    foldValid (List.range (leaderState.log.length + 1)) 0 (Or.inl rfl)
  rcases resultValid with resultZero | resultValid
  · rw [resultZero] at advances
    omega
  · exact ⟨resultValid.2.1, resultValid.2.2⟩

/-- Advancing the leader commit index preserves every supporting invariant. -/
theorem advanceCommitPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.advanceCommitIndex node)) :
    SystemInductiveInvariant (next state (.advanceCommitIndex node)) := by
  have nodeEq : node = LEADER :=
    termOneLeaderImpliesInitialLeader core enabled.1 enabled.2.1
  subst node
  have roleEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).role =
          (state.nodes candidate).role := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have currentTermEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have logEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have sentEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have matchEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have votedForEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have votesEq :
      forall candidate,
        ((next state (.advanceCommitIndex LEADER)).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  constructor
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next] using
        highestCommittableIndexBounded state LEADER
    · simpa [next, candidateEq] using
        core.commitIndicesBounded candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next] using core.logsPrefixLeader LEADER
    · simpa [next, candidateEq] using core.logsPrefixLeader candidate
  · intro candidate entry entryIn
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      exact core.termsAreOne LEADER entry (by simpa [next] using entryIn)
    · exact
        core.termsAreOne candidate entry
          (by simpa [next, candidateEq] using entryIn)
  · simpa [LeaderTxIdsUnique, next] using core.leaderTxIdsUnique
  · simpa [LeaderTxIdsSubmitted, next] using
      core.leaderTxIdsSubmitted
  · intro destination message member
    have oldSafe := core.queuedRequestsMatchLeader destination message
      (by simpa [next] using member)
    constructor
    · exact oldSafe.1
    · cases message with
      | appendEntriesRequest request =>
          simpa only [RequestMatchesLeader, logEq] using oldSafe.2
      | appendEntriesResponse response =>
          simpa only [ResponseMatchesLeader, logEq] using oldSafe.2
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
  · intro destination message member
    have oldSafe := core.queuedVoteMessagesSafe destination message
      (by simpa [next] using member)
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse _ => trivial
    | requestVoteRequest request =>
        simpa only [
          RequestVoteRequestSafe, currentTermEq, votedForEq, logEq
        ] using oldSafe
    | requestVoteResponse response =>
        simpa only [
          RequestVoteResponseSafe, currentTermEq, votedForEq, logEq
        ] using oldSafe
  · simpa only [SentIndicesBounded, sentEq, logEq] using
      core.sentIndicesBounded
  · simpa only [MatchIndicesBounded, matchEq, logEq] using
      core.matchIndicesBounded
  · simpa only [CurrentTermsValid, currentTermEq] using
      core.currentTermsValid
  · simpa only [TermOneLeaderIsInitial, roleEq, currentTermEq] using
      core.termOneLeaderIsInitial
  · simpa only [InitialNodeTermOneIsLeader, roleEq, currentTermEq] using
      core.initialNodeTermOneIsLeader
  · simpa only [
      CandidatesSelfVote, roleEq, currentTermEq, votedForEq, votesEq
    ] using core.candidatesSelfVote
  · simpa only [VotedForTermTwo, votedForEq, currentTermEq] using
      core.votedForTermTwo
  · simpa only [
      VotesGrantedSound, votesEq, currentTermEq, votedForEq, logEq
    ] using core.votesGrantedSound
  · simpa only [
      TermTwoLeadersHaveMajority, roleEq, currentTermEq,
      hasElectionMajority, votesEq
    ] using
      core.termTwoLeadersHaveMajority
  · simpa only [MatchIndexDescribesPrefix, logEq, matchEq] using
      core.matchIndexDescribesPrefix
  · right
    exact
      (highestCommittableIndexValid state LEADER enabled.2.2).2
  · simpa [InitialNodeNotCandidate, next] using
      core.initialNodeNotCandidate

/-- Timing out one follower starts a local term-two candidacy and self-vote. -/
theorem timeoutPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.timeout node)) :
    SystemInductiveInvariant (next state (.timeout node)) := by
  have nodeNeLeader : Not (node = LEADER) := by
    intro nodeEq
    subst node
    have leaderRole :=
      core.initialNodeTermOneIsLeader enabled.2
    exact Role.noConfusion (enabled.1.symm.trans leaderRole)
  have leaderNeNode : Not (LEADER = node) :=
    Ne.symm nodeNeLeader
  have logEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have commitEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have sentEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have matchEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  constructor
  · simpa only [CommitIndicesBounded, commitEq, logEq] using
      core.commitIndicesBounded
  · simpa only [LogsPrefixLeader, logEq] using
      core.logsPrefixLeader
  · simpa only [TermsAreOne, logEq] using core.termsAreOne
  · simpa only [LeaderTxIdsUnique, logEq] using
      core.leaderTxIdsUnique
  · simpa only [LeaderTxIdsSubmitted, logEq] using
      core.leaderTxIdsSubmitted
  · intro destination message member
    have oldSafe := core.queuedRequestsMatchLeader destination message
      (by simpa [next] using member)
    constructor
    · exact oldSafe.1
    · cases message with
      | appendEntriesRequest request =>
          simpa only [RequestMatchesLeader, logEq] using oldSafe.2
      | appendEntriesResponse response =>
          simpa only [ResponseMatchesLeader, logEq] using oldSafe.2
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
  · intro destination message member
    have oldSafe := core.queuedVoteMessagesSafe destination message
      (by simpa [next] using member)
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse _ => trivial
    | requestVoteRequest request =>
        by_cases sourceEq : request.source = node
        · have sourceTermTwo := oldSafe.2.2.1
          rw [sourceEq, enabled.2] at sourceTermTwo
          simp [TERM_ONE] at sourceTermTwo
        · simpa [
            RequestVoteRequestSafe,
            next,
            updateNode,
            Function.update,
            sourceEq
          ] using oldSafe
    | requestVoteResponse response =>
        have sourceNe : Not (response.source = node) := by
          intro sourceEq
          have sourceTermTwo := oldSafe.2.2.1
          rw [sourceEq, enabled.2] at sourceTermTwo
          simp [TERM_ONE] at sourceTermTwo
        have destinationNe : Not (response.destination = node) := by
          intro destinationEq
          have destinationTermTwo := oldSafe.2.2.2.1
          rw [destinationEq, enabled.2] at destinationTermTwo
          simp [TERM_ONE] at destinationTermTwo
        simpa [
          RequestVoteResponseSafe,
          next,
          updateNode,
          Function.update,
          sourceNe,
          destinationNe
        ] using oldSafe
  · simpa only [SentIndicesBounded, sentEq, logEq] using
      core.sentIndicesBounded
  · simpa only [MatchIndicesBounded, matchEq, logEq] using
      core.matchIndicesBounded
  · intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      right
      simp [next, enabled.2, TERM_ONE]
    · simpa [next, updateNode, Function.update, candidateEq] using
        core.currentTermsValid candidate
  · intro candidate leader termOne
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next] at leader
    · exact
        core.termOneLeaderIsInitial candidate
          (by simpa [next, updateNode, Function.update, candidateEq] using leader)
          (by simpa [next, updateNode, Function.update, candidateEq] using termOne)
  · intro termOne
    have oldTermOne :
        (state.nodes LEADER).currentTerm = TERM_ONE := by
      simpa [next, updateNode, Function.update, leaderNeNode] using termOne
    have oldLeader :=
      core.initialNodeTermOneIsLeader oldTermOne
    simpa [next, updateNode, Function.update, leaderNeNode] using oldLeader
  · intro candidate candidateRole
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next, enabled.2, TERM_ONE]
    · have oldCandidate :
          (state.nodes candidate).role = .candidate := by
        simpa [next, updateNode, Function.update, candidateEq] using
          candidateRole
      simpa [next, updateNode, Function.update, candidateEq] using
        core.candidatesSelfVote candidate oldCandidate
  · intro voter candidate vote
    by_cases voterEq : voter = node
    · subst voter
      simp [next] at vote
      rcases vote with rfl
      simp [next, enabled.2, TERM_ONE]
    · have oldVote :
          (state.nodes voter).votedFor = some candidate := by
        simpa [next, updateNode, Function.update, voterEq] using vote
      simpa [next, updateNode, Function.update, voterEq] using
        core.votedForTermTwo voter candidate oldVote
  · intro candidate voter voterIn
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next] at voterIn
      rcases voterIn with rfl
      simp [next, enabled.2, TERM_ONE]
    · have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [next, updateNode, Function.update, candidateEq] using voterIn
      have oldSound := core.votesGrantedSound candidate voter oldIn
      have voterNe : Not (voter = node) := by
        intro voterEq
        subst voter
        have termTwo := core.votedForTermTwo node candidate oldSound.2.1
        rw [enabled.2] at termTwo
        simp [TERM_ONE] at termTwo
      simpa [
        next, updateNode, Function.update, candidateEq, voterNe
      ] using oldSound
  · intro candidate leader termTwo
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next] at leader
    · have majority :=
        core.termTwoLeadersHaveMajority candidate
          (by simpa [next, updateNode, Function.update, candidateEq] using leader)
          (by simpa [next, updateNode, Function.update, candidateEq] using termTwo)
      simpa [
        hasElectionMajority, next, updateNode, Function.update, candidateEq
      ] using majority
  · simpa only [MatchIndexDescribesPrefix, logEq, matchEq] using
      core.matchIndexDescribesPrefix
  · simpa only [
      InitialLeaderCommitHasMajority, hasMajorityAt,
      acknowledgingNodes, commitEq, matchEq
    ] using
      core.initialLeaderCommitHasMajority
  · simpa [
      InitialNodeNotCandidate, next, updateNode,
      Function.update, leaderNeNode
    ] using core.initialNodeNotCandidate

/-- Sending RequestVote preserves state invariants and enqueues a safe snapshot. -/
theorem requestVotePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    SystemInductiveInvariant (next state (.requestVote source destination)) := by
  let request := makeRequestVoteRequest state source destination
  have requestSafe : RequestVoteRequestSafe state request :=
    makeRequestVoteRequestSafe core enabled
  constructor
  · simpa [CommitIndicesBounded, next, request] using
      core.commitIndicesBounded
  · simpa [LogsPrefixLeader, next, request] using core.logsPrefixLeader
  · simpa [TermsAreOne, next, request] using core.termsAreOne
  · simpa [LeaderTxIdsUnique, next, request] using
      core.leaderTxIdsUnique
  · simpa [LeaderTxIdsSubmitted, next, request] using
      core.leaderTxIdsSubmitted
  · intro queuedDestination message member
    have enqueued :
        message ∈
          enqueueNoDup state.network
            (.requestVoteRequest request) queuedDestination := by
      simpa [next, request] using member
    rcases memEnqueueNoDup
        state.network (.requestVoteRequest request)
        message queuedDestination enqueued with old | new
    · exact core.queuedRequestsMatchLeader queuedDestination message old
    · rcases new with ⟨queuedDestinationEq, rfl⟩
      subst queuedDestination
      exact ⟨rfl, trivial⟩
  · intro queuedDestination message member
    have enqueued :
        message ∈
          enqueueNoDup state.network
            (.requestVoteRequest request) queuedDestination := by
      simpa [next, request] using member
    rcases memEnqueueNoDup
        state.network (.requestVoteRequest request)
        message queuedDestination enqueued with old | new
    · exact core.queuedVoteMessagesSafe queuedDestination message old
    · rcases new with ⟨queuedDestinationEq, rfl⟩
      subst queuedDestination
      exact requestSafe
  · simpa [SentIndicesBounded, next, request] using core.sentIndicesBounded
  · simpa [MatchIndicesBounded, next, request] using
      core.matchIndicesBounded
  · simpa [CurrentTermsValid, next, request] using core.currentTermsValid
  · simpa [TermOneLeaderIsInitial, next, request] using
      core.termOneLeaderIsInitial
  · simpa [InitialNodeTermOneIsLeader, next, request] using
      core.initialNodeTermOneIsLeader
  · simpa [CandidatesSelfVote, next, request] using core.candidatesSelfVote
  · simpa [VotedForTermTwo, next, request] using core.votedForTermTwo
  · simpa [VotesGrantedSound, next, request] using core.votesGrantedSound
  · simpa [TermTwoLeadersHaveMajority, next, request] using
      core.termTwoLeadersHaveMajority
  · simpa [MatchIndexDescribesPrefix, next, request] using
      core.matchIndexDescribesPrefix
  · simpa [InitialLeaderCommitHasMajority, next, request] using
      core.initialLeaderCommitHasMajority
  · simpa [InitialNodeNotCandidate, next, request] using
      core.initialNodeNotCandidate

/-- Observing a newer message locally advances only the destination term. -/
theorem updateTermPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.updateTerm source destination)) :
    SystemInductiveInvariant (next state (.updateTerm source destination)) := by
  cases found : newerMessage? state source destination with
  | none =>
      simp [Enabled, found] at enabled
  | some selected =>
      have sound := newerMessageSound found
      rcases sound with ⟨remaining, taken, newer⟩
      have selectedMember :=
        (takeFirstFromSound taken).2.1
      have selectedTermValid :=
        queuedMessageTermValid core selectedMember
      have oldTermOne :
          (state.nodes destination).currentTerm = TERM_ONE := by
        rcases core.currentTermsValid destination with oldOne | oldTwo
        · exact oldOne
        · rcases selectedTermValid with selectedOne | selectedTwo
          · rw [oldTwo, selectedOne] at newer
            simp [TERM_ONE] at newer
          · rw [oldTwo, selectedTwo] at newer
            omega
      have selectedTermTwo : selected.term = 2 := by
        rcases selectedTermValid with selectedOne | selectedTwo
        · rw [oldTermOne, selectedOne] at newer
          omega
        · exact selectedTwo
      have nextEq :
          next state (.updateTerm source destination) =
            { state with
              nodes :=
                updateNode state.nodes destination
                  { state.nodes destination with
                    role := .follower
                    currentTerm := selected.term
                    votedFor := none
                    isNewFollower := true } } := by
        simp [next, found]
      rw [nextEq]
      have logEq :
          forall node,
            (updateNode state.nodes destination
                { state.nodes destination with
                  role := .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } node).log =
              (state.nodes node).log := by
        intro node
        by_cases nodeEq : node = destination
        · subst node
          simp [updateNode]
        · simp [updateNode, Function.update, nodeEq]
      have commitEq :
          forall node,
            (updateNode state.nodes destination
                { state.nodes destination with
                  role := .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } node).commitIndex =
              (state.nodes node).commitIndex := by
        intro node
        by_cases nodeEq : node = destination
        · subst node
          simp [updateNode]
        · simp [updateNode, Function.update, nodeEq]
      have sentEq :
          forall node,
            (updateNode state.nodes destination
                { state.nodes destination with
                  role := .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } node).sentIndex =
              (state.nodes node).sentIndex := by
        intro node
        by_cases nodeEq : node = destination
        · subst node
          simp [updateNode]
        · simp [updateNode, Function.update, nodeEq]
      have matchEq :
          forall node,
            (updateNode state.nodes destination
                { state.nodes destination with
                  role := .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } node).matchIndex =
              (state.nodes node).matchIndex := by
        intro node
        by_cases nodeEq : node = destination
        · subst node
          simp [updateNode]
        · simp [updateNode, Function.update, nodeEq]
      have votesEq :
          forall node,
            (updateNode state.nodes destination
                { state.nodes destination with
                  role := .follower
                  currentTerm := selected.term
                  votedFor := none
                  isNewFollower := true } node).votesGranted =
              (state.nodes node).votesGranted := by
        intro node
        by_cases nodeEq : node = destination
        · subst node
          simp [updateNode]
        · simp [updateNode, Function.update, nodeEq]
      constructor
      · simpa only [CommitIndicesBounded, commitEq, logEq] using
          core.commitIndicesBounded
      · simpa only [LogsPrefixLeader, logEq] using core.logsPrefixLeader
      · simpa only [TermsAreOne, logEq] using core.termsAreOne
      · simpa only [LeaderTxIdsUnique, logEq] using core.leaderTxIdsUnique
      · simpa only [LeaderTxIdsSubmitted, logEq] using
          core.leaderTxIdsSubmitted
      · intro queuedDestination message member
        have oldSafe :=
          core.queuedRequestsMatchLeader queuedDestination message
            (by simpa using member)
        constructor
        · exact oldSafe.1
        · cases message with
          | appendEntriesRequest request =>
              simpa only [RequestMatchesLeader, logEq] using oldSafe.2
          | appendEntriesResponse response =>
              simpa only [ResponseMatchesLeader, logEq] using oldSafe.2
          | requestVoteRequest _ => trivial
          | requestVoteResponse _ => trivial
      · intro queuedDestination message member
        have oldSafe := core.queuedVoteMessagesSafe queuedDestination message
          (by simpa using member)
        cases message with
        | appendEntriesRequest _ => trivial
        | appendEntriesResponse _ => trivial
        | requestVoteRequest request =>
            by_cases requestSourceEq : request.source = destination
            · have requestTermTwo := oldSafe.2.2.1
              rw [requestSourceEq, oldTermOne] at requestTermTwo
              simp [TERM_ONE] at requestTermTwo
            · simpa [
                RequestVoteRequestSafe,
                updateNode,
                Function.update,
                requestSourceEq
              ] using oldSafe
        | requestVoteResponse response =>
            have responseSourceNe : Not (response.source = destination) := by
              intro responseSourceEq
              have responseTermTwo := oldSafe.2.2.1
              rw [responseSourceEq, oldTermOne] at responseTermTwo
              simp [TERM_ONE] at responseTermTwo
            have responseDestinationNe :
                Not (response.destination = destination) := by
              intro responseDestinationEq
              have responseTermTwo := oldSafe.2.2.2.1
              rw [responseDestinationEq, oldTermOne] at responseTermTwo
              simp [TERM_ONE] at responseTermTwo
            simpa [
              RequestVoteResponseSafe,
              updateNode,
              Function.update,
              responseSourceNe,
              responseDestinationNe
            ] using oldSafe
      · simpa only [SentIndicesBounded, sentEq, logEq] using
          core.sentIndicesBounded
      · simpa only [MatchIndicesBounded, matchEq, logEq] using
          core.matchIndicesBounded
      · intro node
        by_cases nodeEq : node = destination
        · subst node
          right
          simpa [selectedTermTwo]
        · simpa [updateNode, Function.update, nodeEq] using
            core.currentTermsValid node
      · intro node leader termOne
        by_cases nodeEq : node = destination
        · subst node
          simp at leader
        · exact core.termOneLeaderIsInitial node
            (by simpa [updateNode, Function.update, nodeEq] using leader)
            (by simpa [updateNode, Function.update, nodeEq] using termOne)
      · intro termOne
        by_cases leaderEq : LEADER = destination
        · rw [leaderEq] at termOne
          simp [selectedTermTwo, updateNode] at termOne
          contradiction
        · have oldLeader := core.initialNodeTermOneIsLeader
            (by simpa [updateNode, Function.update, leaderEq] using termOne)
          simpa [updateNode, Function.update, leaderEq] using oldLeader
      · intro node candidate
        by_cases nodeEq : node = destination
        · subst node
          simp at candidate
        · have oldCandidate :
              (state.nodes node).role = .candidate := by
            simpa [updateNode, Function.update, nodeEq] using candidate
          simpa [updateNode, Function.update, nodeEq] using
            core.candidatesSelfVote node oldCandidate
      · intro voter candidate vote
        by_cases voterEq : voter = destination
        · subst voter
          simp at vote
        · have oldVote :
              (state.nodes voter).votedFor = some candidate := by
            simpa [updateNode, Function.update, voterEq] using vote
          simpa [updateNode, Function.update, voterEq] using
            core.votedForTermTwo voter candidate oldVote
      · intro candidate voter voterIn
        have oldIn :
            voter ∈ (state.nodes candidate).votesGranted := by
          by_cases candidateEq : candidate = destination
          · subst candidate
            simpa [updateNode] using voterIn
          · simpa [updateNode, Function.update, candidateEq] using voterIn
        have oldSound := core.votesGrantedSound candidate voter oldIn
        by_cases candidateEq : candidate = destination
        · subst candidate
          rw [oldTermOne] at oldSound
          simp [TERM_ONE] at oldSound
        · have voterNe : Not (voter = destination) := by
            intro voterEq
            subst voter
            have termTwo :=
              core.votedForTermTwo destination candidate oldSound.2.1
            rw [oldTermOne] at termTwo
            simp [TERM_ONE] at termTwo
          simpa [
            updateNode, Function.update, candidateEq, voterNe
          ] using oldSound
      · intro node leader termTwo
        by_cases nodeEq : node = destination
        · subst node
          simp at leader
        · have majority :=
            core.termTwoLeadersHaveMajority node
              (by simpa [updateNode, Function.update, nodeEq] using leader)
              (by simpa [updateNode, Function.update, nodeEq] using termTwo)
          simpa [
            hasElectionMajority, updateNode, Function.update, nodeEq
          ] using majority
      · simpa only [MatchIndexDescribesPrefix, logEq, matchEq] using
          core.matchIndexDescribesPrefix
      · simpa only [
          InitialLeaderCommitHasMajority, hasMajorityAt,
          acknowledgingNodes, commitEq, matchEq
        ] using
          core.initialLeaderCommitHasMajority
      · by_cases leaderEq : LEADER = destination
        · simp [
            InitialNodeNotCandidate, updateNode,
            Function.update, leaderEq
          ]
        · simpa [
            InitialNodeNotCandidate, updateNode,
            Function.update, leaderEq
          ] using core.initialNodeNotCandidate

/-- Promoting a majority-backed candidate establishes a term-two leader. -/
theorem becomeLeaderPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.becomeLeader node)) :
    SystemInductiveInvariant (next state (.becomeLeader node)) := by
  have nodeNeLeader : Not (node = LEADER) := by
    intro nodeEq
    subst node
    exact core.initialNodeNotCandidate enabled.1
  have leaderNeNode : Not (LEADER = node) :=
    Ne.symm nodeNeLeader
  have currentTermEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have logEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have commitEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have sentEq :
      ((next state (.becomeLeader node)).nodes LEADER).sentIndex =
        (state.nodes LEADER).sentIndex := by
    simp [next, updateNode, Function.update, leaderNeNode]
  have matchEq :
      ((next state (.becomeLeader node)).nodes LEADER).matchIndex =
        (state.nodes LEADER).matchIndex := by
    simp [next, updateNode, Function.update, leaderNeNode]
  have votedForEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  have votesEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next]
    · simp [next, updateNode, Function.update, candidateEq]
  constructor
  · simpa only [CommitIndicesBounded, commitEq, logEq] using
      core.commitIndicesBounded
  · simpa only [LogsPrefixLeader, logEq] using core.logsPrefixLeader
  · simpa only [TermsAreOne, logEq] using core.termsAreOne
  · simpa only [LeaderTxIdsUnique, logEq] using core.leaderTxIdsUnique
  · simpa only [LeaderTxIdsSubmitted, logEq] using
      core.leaderTxIdsSubmitted
  · intro destination message member
    have oldSafe := core.queuedRequestsMatchLeader destination message
      (by simpa [next] using member)
    constructor
    · exact oldSafe.1
    · cases message with
      | appendEntriesRequest request =>
          simpa only [RequestMatchesLeader, logEq] using oldSafe.2
      | appendEntriesResponse response =>
          simpa only [ResponseMatchesLeader, logEq] using oldSafe.2
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
  · intro destination message member
    have oldSafe := core.queuedVoteMessagesSafe destination message
      (by simpa [next] using member)
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse _ => trivial
    | requestVoteRequest request =>
        simpa only [
          RequestVoteRequestSafe, currentTermEq, votedForEq, logEq
        ] using oldSafe
    | requestVoteResponse response =>
        simpa only [
          RequestVoteResponseSafe, currentTermEq, votedForEq, logEq
        ] using oldSafe
  · simpa only [SentIndicesBounded, sentEq, logEq] using
      core.sentIndicesBounded
  · simpa only [MatchIndicesBounded, matchEq, logEq] using
      core.matchIndicesBounded
  · simpa only [CurrentTermsValid, currentTermEq] using
      core.currentTermsValid
  · intro candidate leader termOne
    by_cases candidateEq : candidate = node
    · subst candidate
      have termTwo :
          ((next state (.becomeLeader node)).nodes node).currentTerm = 2 := by
        simpa [next] using enabled.2.1
      rw [termOne] at termTwo
      simp [TERM_ONE] at termTwo
    · exact core.termOneLeaderIsInitial candidate
        (by simpa [next, updateNode, Function.update, candidateEq] using leader)
        (by simpa [next, updateNode, Function.update, candidateEq] using termOne)
  · intro termOne
    have oldTermOne :
        (state.nodes LEADER).currentTerm = TERM_ONE := by
      simpa only [currentTermEq] using termOne
    have oldLeader := core.initialNodeTermOneIsLeader oldTermOne
    simpa [next, updateNode, Function.update, leaderNeNode] using oldLeader
  · intro candidate candidateRole
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next] at candidateRole
    · have oldCandidate :
          (state.nodes candidate).role = .candidate := by
        simpa [next, updateNode, Function.update, candidateEq] using
          candidateRole
      simpa [next, updateNode, Function.update, candidateEq] using
        core.candidatesSelfVote candidate oldCandidate
  · simpa only [VotedForTermTwo, votedForEq, currentTermEq] using
      core.votedForTermTwo
  · simpa only [
      VotesGrantedSound, votesEq, currentTermEq, votedForEq, logEq
    ] using core.votesGrantedSound
  · intro candidate leader termTwo
    by_cases candidateEq : candidate = node
    · subst candidate
      simpa [next, hasElectionMajority] using enabled.2.2
    · have majority :=
        core.termTwoLeadersHaveMajority candidate
          (by simpa [next, updateNode, Function.update, candidateEq] using leader)
          (by simpa [next, updateNode, Function.update, candidateEq] using termTwo)
      simpa [next, hasElectionMajority, updateNode, Function.update, candidateEq]
        using majority
  · simpa only [MatchIndexDescribesPrefix, logEq, matchEq] using
      core.matchIndexDescribesPrefix
  · simpa only [
      InitialLeaderCommitHasMajority, hasMajorityAt,
      acknowledgingNodes, commitEq, matchEq
    ] using
      core.initialLeaderCommitHasMajority
  · simpa [
      InitialNodeNotCandidate, next, updateNode,
      Function.update, leaderNeNode
    ] using core.initialNodeNotCandidate

/-- A receive transition never shrinks any node's committed log. -/
theorem receiveCommittedLogMonotonicity
    (state : State TxId)
    (source destination : Node)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    CommittedLogMonotonicity
      state
      (next state (.receive source destination)) := by
  unfold Enabled at enabled
  cases receiveResult :
      handleReceive? state source destination with
  | none =>
      simp [receiveResult] at enabled
  | some resultingState =>
      have nextEq :
          next state (.receive source destination) = resultingState := by
        simp [next, receiveResult]
      rw [nextEq]
      unfold handleReceive? at receiveResult
      split at receiveResult
      · contradiction
      · rename_i selected remaining taken
        split at receiveResult
        · contradiction
        · rename_i destinationMatches
          split at receiveResult
          · contradiction
          rename_i notNewer
          split at receiveResult
          · rename_i request
            split at receiveResult
            · contradiction
            · rename_i nextNode response handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have selectedSafe :=
                core.queuedRequestsMatchLeader
                  destination
                  (.appendEntriesRequest request)
                  selectedSound.2.1
              have post :=
                handleAppendEntriesRequestPreserves
                  core selectedSafe.1 selectedSafe.2 handled
              intro candidate
              by_cases candidateEq : candidate = destination
              · subst candidate
                simpa using post.committedMonotonic
              · simp [NodeState.committedLog, candidateEq]
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i nextNode handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have selectedSafe :=
                core.queuedRequestsMatchLeader
                  destination
                  (.appendEntriesResponse response)
                  selectedSound.2.1
              have responseSafe :
                  ResponseMatchesLeader state response :=
                selectedSafe.2
              have responseDestination :
                  response.destination = destination :=
                selectedSafe.1
              have destinationEq : destination = LEADER :=
                responseDestination.symm.trans responseSafe.1
              subst destination
              have post :=
                handleAppendEntriesResponsePreserves
                  core responseSafe
                    (by simpa [responseSafe.1] using handled)
              intro candidate
              by_cases candidateEq : candidate = LEADER
              · subst candidate
                simp [
                  NodeState.committedLog,
                  responseSafe.1,
                  post.logUnchanged,
                  post.commitIndexUnchanged
                ]
              · simp [
                  NodeState.committedLog,
                  responseSafe.1,
                  candidateEq
                ]
          · rename_i request
            split at receiveResult
            · contradiction
            · rename_i nextNode response handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have selectedSound := takeFirstFromSound taken
              have voteSafe :=
                core.queuedVoteMessagesSafe
                  destination
                  (.requestVoteRequest request)
                  selectedSound.2.1
              have queuedSafe :=
                core.queuedRequestsMatchLeader
                  destination
                  (.requestVoteRequest request)
                  selectedSound.2.1
              have post :=
                handleRequestVoteRequestPreserves
                  core queuedSafe.1 voteSafe handled
              intro candidate
              by_cases candidateEq : candidate = destination
              · subst candidate
                simp [
                  NodeState.committedLog,
                  post.logUnchanged,
                  post.commitIndexUnchanged
                ]
              · simp [NodeState.committedLog, candidateEq]
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i nextNode handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              have post :=
                handleRequestVoteResponsePreserves handled
              intro candidate
              by_cases candidateEq : candidate = destination
              · subst candidate
                simp [
                  NodeState.committedLog,
                  post.logUnchanged,
                  post.commitIndexUnchanged
                ]
              · simp [NodeState.committedLog, candidateEq]

/-- Every enabled action preserves committed-log append-only behavior. -/
theorem nextCommittedLogMonotonicity
    (state : State TxId)
    (action : Action TxId)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state action) :
    CommittedLogMonotonicity state (next state action) := by
  cases action with
  | clientRequest node txId =>
      have nodeEq : node = LEADER :=
        termOneLeaderImpliesInitialLeader core enabled.1 enabled.2.1
      subst node
      intro candidate
      by_cases candidateEq : candidate = LEADER
      · subst candidate
        have unchanged :
            ((next state (.clientRequest LEADER txId)).nodes LEADER).committedLog =
              (state.nodes LEADER).committedLog := by
          simp only [next, updateNode_same, NodeState.committedLog]
          exact
            List.take_append_of_le_length
              (core.commitIndicesBounded LEADER)
        rw [unchanged]
      · simp [next, NodeState.committedLog, candidateEq]
  | appendEntries source destination batchEnd =>
      intro candidate
      by_cases candidateEq : candidate = source
      · subst candidate
        simp [next, NodeState.committedLog]
      · simp [next, NodeState.committedLog, candidateEq]
  | receive source destination =>
      exact
        receiveCommittedLogMonotonicity
          state source destination core enabled
  | advanceCommitIndex node =>
      have nodeEq : node = LEADER :=
        termOneLeaderImpliesInitialLeader core enabled.1 enabled.2.1
      subst node
      intro candidate
      by_cases candidateEq : candidate = LEADER
      · subst candidate
        have oldLe :
            (state.nodes LEADER).commitIndex <=
              highestCommittableIndex state LEADER :=
          Nat.le_of_lt enabled.2.2
        have taken :=
          List.take_prefix
            (state.nodes LEADER).commitIndex
            ((state.nodes LEADER).log.take
              (highestCommittableIndex state LEADER))
        simpa [
          next,
          NodeState.committedLog,
          List.take_take,
          Nat.min_eq_left oldLe
        ] using taken
      · simp [next, NodeState.committedLog, candidateEq]
  | timeout node =>
      intro candidate
      by_cases candidateEq : candidate = node
      · subst candidate
        simp [next, NodeState.committedLog]
      · simp [next, NodeState.committedLog, candidateEq]
  | requestVote source destination =>
      intro candidate
      simp [next, NodeState.committedLog]
  | updateTerm source destination =>
      intro candidate
      by_cases candidateEq : candidate = destination
      · subst candidate
        simp only [next]
        split <;> simp [NodeState.committedLog]
      · simp only [next]
        split <;> simp [NodeState.committedLog, candidateEq]
  | becomeLeader node =>
      intro candidate
      by_cases candidateEq : candidate = node
      · subst candidate
        simp [next, NodeState.committedLog]
      · simp [next, NodeState.committedLog, candidateEq]

/-- A client request changes only the node receiving that request. -/
theorem clientRequestFrame
    (state : State TxId)
    (node : Node)
    (txId : TxId) :
    OtherNodesUnchanged
      node state (next state (.clientRequest node txId)) := by
  intro candidate different
  simp [next, different]

/-- Sending AppendEntries changes only the source node's local bookkeeping. -/
theorem appendEntriesFrame
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat) :
    OtherNodesUnchanged
      source state (next state (.appendEntries source destination batchEnd)) := by
  intro candidate different
  simp [next, different]

/-- Commit advancement changes only the acting leader. -/
theorem advanceCommitIndexFrame
    (state : State TxId)
    (node : Node) :
    OtherNodesUnchanged
      node state (next state (.advanceCommitIndex node)) := by
  intro candidate different
  simp [next, different]

/-- Timing out changes only the node starting the election. -/
theorem timeoutFrame
    (state : State TxId)
    (node : Node) :
    OtherNodesUnchanged
      node state (next state (.timeout node)) := by
  intro candidate different
  simp [next, different]

/-- Sending RequestVote changes no node-local protocol state. -/
theorem requestVoteFrame
    (state : State TxId)
    (source destination : Node) :
    forall candidate,
      (next state (.requestVote source destination)).nodes candidate =
        state.nodes candidate := by
  intro candidate
  simp [next]

/-- Observing a newer term changes only the receiving node. -/
theorem updateTermFrame
    (state : State TxId)
    (source destination : Node) :
    OtherNodesUnchanged
      destination state (next state (.updateTerm source destination)) := by
  intro candidate different
  simp only [next]
  split <;> simp [different]

/-- Leader promotion changes only the promoted candidate. -/
theorem becomeLeaderFrame
    (state : State TxId)
    (node : Node) :
    OtherNodesUnchanged
      node state (next state (.becomeLeader node)) := by
  intro candidate different
  simp [next, different]

/-- Receiving a message changes only the destination node. -/
theorem receiveFrame
    (state : State TxId)
    (source destination : Node) :
    OtherNodesUnchanged
      destination state (next state (.receive source destination)) := by
  intro candidate different
  change
    ((handleReceive? state source destination).getD state).nodes candidate =
      state.nodes candidate
  cases resultEq :
      handleReceive? state source destination with
  | none =>
      simp [resultEq]
  | some result =>
      simp only [resultEq, Option.getD_some]
      unfold handleReceive? at resultEq
      split at resultEq
      · contradiction
      · split at resultEq
        · contradiction
        · split at resultEq
          · contradiction
          split at resultEq <;> split at resultEq
          · contradiction
          · have stateEq := Option.some.inj resultEq
            rw [← stateEq]
            simp [different]
          · contradiction
          · have stateEq := Option.some.inj resultEq
            rw [← stateEq]
            simp [different]
          · contradiction
          · have stateEq := Option.some.inj resultEq
            rw [← stateEq]
            simp [different]
          · contradiction
          · have stateEq := Option.some.inj resultEq
            rw [← stateEq]
            simp [different]

/-- Case-split dispatcher proving every enabled action preserves the invariant. -/
theorem nextPreservesSystemInductiveInvariant
    (state : State TxId)
    (action : Action TxId)
    (core : SystemInductiveInvariant state)
    (enabled : Enabled state action) :
    SystemInductiveInvariant (next state action) := by
  cases action with
  | clientRequest node txId =>
      exact clientRequestPreservesSystemInductiveInvariant state node txId core enabled
  | appendEntries source destination batchEnd =>
      exact
        appendEntriesPreservesSystemInductiveInvariant
          state source destination batchEnd core enabled
  | receive source destination =>
      exact receivePreservesSystemInductiveInvariant state source destination core enabled
  | advanceCommitIndex node =>
      exact advanceCommitPreservesSystemInductiveInvariant state node core enabled
  | timeout node =>
      exact timeoutPreservesSystemInductiveInvariant state node core enabled
  | requestVote source destination =>
      exact
        requestVotePreservesSystemInductiveInvariant
          state source destination core enabled
  | updateTerm source destination =>
      exact
        updateTermPreservesSystemInductiveInvariant
          state source destination core enabled
  | becomeLeader node =>
      exact becomeLeaderPreservesSystemInductiveInvariant state node core enabled

/-- The supporting invariant holds in every reachable slice-two state. -/
theorem reachableSystemInductiveInvariant
    {state : State TxId}
    (reachable : Reachable state) :
    SystemInductiveInvariant state :=
  ExecutableTransitionSystem.reachableInvariant
    (system (TxId := TxId))
    initialSystemInductiveInvariant
    nextPreservesSystemInductiveInvariant
    reachable

/-- Every enabled edge leaving a reachable state extends committed logs. -/
theorem reachableStepCommittedLogMonotonicity
    {state : State TxId}
    (reachable : Reachable state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    CommittedLogMonotonicity state (next state action) :=
  nextCommittedLogMonotonicity
    state action (reachableSystemInductiveInvariant reachable) enabled

/-- All reachable committed logs are pairwise prefix-comparable. -/
theorem reachableCommittedLogsPrefix
    {state : State TxId}
    (reachable : Reachable state) :
    CommittedLogsPrefix state :=
  systemInductiveInvariantCommittedLogsPrefix
    (reachableSystemInductiveInvariant reachable)

/-- Every reachable state satisfies Raft log matching. -/
theorem reachableLogMatching
    {state : State TxId}
    (reachable : Reachable state) :
    LogMatching state :=
  systemInductiveInvariantLogMatching
    (reachableSystemInductiveInvariant reachable)

/-- Equal index and term identify equal transaction IDs in reachable states. -/
theorem reachableSameIndexSameTermSameTxId
    {state : State TxId}
    (reachable : Reachable state) :
    SameIndexSameTermSameTxId state :=
  systemInductiveInvariantSameIndexSameTermSameTxId
    (reachableSystemInductiveInvariant reachable)

/-- Terms are monotonic in every reachable node log. -/
theorem reachableMonoLog
    {state : State TxId}
    (reachable : Reachable state) :
    MonoLog state :=
  systemInductiveInvariantMonoLog
    (reachableSystemInductiveInvariant reachable)

/-- Every reachable state has at most one leader in each term. -/
theorem reachableElectionSafety
    {state : State TxId}
    (reachable : Reachable state) :
    ElectionSafety state :=
  systemInductiveInvariantElectionSafety
    (reachableSystemInductiveInvariant reachable)

/-- Every reachable term-two leader contains node zero's committed prefix. -/
theorem reachableTermTwoLeaderCompleteness
    {state : State TxId}
    (reachable : Reachable state) :
    TermTwoLeaderCompleteness state :=
  systemInductiveInvariantTermTwoLeaderCompleteness
    (reachableSystemInductiveInvariant reachable)

/-- Bundle all public state-safety theorems for a reachable state. -/
theorem reachableConsensusSafety
    {state : State TxId}
    (reachable : Reachable state) :
    ConsensusSafety state where
  committedLogsPrefix := reachableCommittedLogsPrefix reachable
  logMatching := reachableLogMatching reachable
  sameIndexSameTermSameTxId :=
    reachableSameIndexSameTermSameTxId reachable
  monoLog := reachableMonoLog reachable
  electionSafety := reachableElectionSafety reachable
  termTwoLeaderCompleteness :=
    reachableTermTwoLeaderCompleteness reachable

end CCFRaft
