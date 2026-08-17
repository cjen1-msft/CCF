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
theorem initialCoreInvariant :
    CoreInvariant (initialState : State TxId) := by
  constructor
  · simp [CommitIndicesBounded, initialState, initialNodeState]
  · intro node
    exact prefixRefl []
  · simp [TermsAreOne, initialState, initialNodeState]
  · simp [LeaderTxIdsUnique, initialState, initialNodeState]
  · simp [LeaderTxIdsSubmitted, initialState, initialNodeState]
  · simp [QueuedRequestsMatchLeader, initialState]
  · simp [SentIndicesBounded, initialState, initialNodeState]
  · simp [MatchIndicesBounded, initialState, initialNodeState]
  · simp [RolesFixed, initialState, initialNodeState]
  · simp [CurrentTermsAreOne, initialState, initialNodeState]

/-- A node's committed log is a prefix of the leader log. -/
theorem committedLogPrefixLeader
    {state : State TxId}
    (core : CoreInvariant state)
    (node : Node) :
    (state.nodes node).committedLog <+:
      (state.nodes LEADER).log := by
  exact
    (List.take_prefix
      (state.nodes node).commitIndex
      (state.nodes node).log).trans
      (core.logsPrefixLeader node)

/-- The core invariant implies pairwise committed-log prefix comparability. -/
theorem coreCommittedLogsPrefix
    {state : State TxId}
    (core : CoreInvariant state) :
    CommittedLogsPrefix state := by
  intro left right
  exact
    prefixesComparable
      (committedLogPrefixLeader core left)
      (committedLogPrefixLeader core right)

/-- Prefix agreement with the leader implies Raft log matching. -/
theorem coreLogMatching
    {state : State TxId}
    (core : CoreInvariant state) :
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
theorem coreSameIndexSameTermSameTxId
    {state : State TxId}
    (core : CoreInvariant state) :
    SameIndexSameTermSameTxId state := by
  intro left right index leftEntry rightEntry leftFound rightFound sameTerm
  have matching :=
    coreLogMatching core
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
theorem coreMonoLog
    {state : State TxId}
    (core : CoreInvariant state) :
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

/-- Under fixed roles, any node in the leader role is node zero. -/
theorem roleLeaderImpliesNodeLeader
    {state : State TxId}
    (core : CoreInvariant state)
    {node : Node}
    (isLeader : (state.nodes node).role = .leader) :
    node = LEADER := by
  have fixed := core.rolesFixed node
  by_cases nodeEq : node = LEADER
  · exact nodeEq
  · simp [nodeEq] at fixed
    exact False.elim (Role.noConfusion (fixed.symm.trans isLeader))

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
theorem clientRequestPreservesCoreInvariant
    (state : State TxId)
    (node : Node)
    (txId : TxId)
    (core : CoreInvariant state)
    (enabled : Enabled state (.clientRequest node txId)) :
    CoreInvariant (next state (.clientRequest node txId)) := by
  have nodeEq : node = LEADER :=
    roleLeaderImpliesNodeLeader core enabled.1
  subst node
  have fresh : txId ∉ state.submittedTxIds := enabled.2
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
      · simpa [newEntry] using core.currentTermsAreOne LEADER
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
            ⟨responseDestination, responseSource, responseTerm, responseBound⟩
          exact
            ⟨responseDestination, responseSource, responseTerm,
              by simpa [next, updateNode] using Nat.le.step responseBound⟩
      | appendEntriesRequest request =>
          exact requestMatchesLeaderAfterAppend safe.2
  · intro candidate
    have oldBound := core.sentIndicesBounded candidate
    simpa [SentIndicesBounded, next, updateNode] using Nat.le.step oldBound
  · intro candidate
    have oldBound := core.matchIndicesBounded candidate
    simpa [MatchIndicesBounded, next, updateNode] using Nat.le.step oldBound
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, updateNode] using core.rolesFixed LEADER
    · simpa [next, updateNode, Function.update, candidateEq] using
        core.rolesFixed candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, updateNode] using core.currentTermsAreOne LEADER
    · simpa [next, updateNode, Function.update, candidateEq] using
        core.currentTermsAreOne candidate

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
    (core : CoreInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    RequestMatchesLeader state
      (makeAppendEntriesRequest state source destination batchEnd) := by
  have sourceEq : source = LEADER :=
    roleLeaderImpliesNodeLeader core enabled.1
  subst source
  rcases enabled with ⟨_, different, batchEndEq⟩
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
    ⟨rfl, Ne.symm different, core.currentTermsAreOne LEADER,
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
  responseSafe : ResponseMatchesLeader system response

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
    (core : CoreInvariant system)
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

/-- Two term-one logs cannot trigger the differing-term conflict branch. -/
theorem noReachableTermConflict
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (core : CoreInvariant system)
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

/-- A NACK generated from safe state has metadata bounded by the leader log. -/
theorem failureResponseSafe
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (core : CoreInvariant system)
    (requestSafe : RequestMatchesLeader system request) :
    ResponseMatchesLeader system
      (failureResponse (system.nodes destination) request) := by
  have requestTerm :
      request.term = (system.nodes destination).currentTerm := by
    rw [
      requestSafe.2.2.1,
      core.currentTermsAreOne destination
    ]
  have destinationPrefix := core.logsPrefixLeader destination
  let previousTerm :=
    if request.prevLogIndex = 0 then
      0
    else if request.prevLogIndex > (system.nodes destination).log.length then
      0
    else
      termAt
        (system.nodes destination).log
        (system.nodes destination).log.length
  by_cases previousTermZero : previousTerm = 0
  · simp [
      ResponseMatchesLeader,
      failureResponse,
      requestTerm,
      previousTerm,
      previousTermZero,
      requestSafe.1,
      requestSafe.2.1,
      core.currentTermsAreOne destination,
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
        requestTerm,
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
        requestTerm,
        previousTerm,
        previousTermZero,
        matchIndex,
        matchIndexZero,
        matchTerm,
        requestSafe.1,
        requestSafe.2.1,
        le_trans matchBound destinationPrefix.length_le
      ]

/-- Conflict truncation returns `none` throughout this single-term slice. -/
theorem conflictAppendEntriesRequestDisabled
    {system : State TxId}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (core : CoreInvariant system)
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
    (core : CoreInvariant system)
    (requestDestination : request.destination = destination)
    (requestSafe : RequestMatchesLeader system request)
    (handled :
      handleAppendEntriesRequest? (system.nodes destination) request =
        some (after, response)) :
    RequestHandlerPost system (system.nodes destination) after response := by
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
      · exact failureResponseSafe core requestSafe
    · contradiction
  · rename_i rejected
    unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      split at handled
      · rename_i alreadyState alreadyResponse already
        unfold appendEntriesAlreadyDone? at already
        split at already
        · have pairEq :=
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
          · refine
              ⟨requestSafe.1,
                requestSafe.2.1,
                core.currentTermsAreOne destination, ?_⟩
            simp [successResponse]
            exact requestSafe.2.2.2.2.1
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
            · refine
                ⟨requestSafe.1,
                  requestSafe.2.1,
                  core.currentTermsAreOne destination, ?_⟩
              simpa [
                successResponse,
                List.length_append,
                List.length_take,
                Nat.min_eq_left extension.2.1
              ] using newPrefix.length_le
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

/-- Facts guaranteed after the leader handles an AppendEntries response. -/
structure ResponseHandlerPost
    (system : State TxId)
    (before after : NodeState TxId)
    (response : AppendEntriesResponse) : Prop where
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  sentIndicesBounded :
    forall node,
      after.sentIndex node <= (system.nodes LEADER).log.length
  matchIndicesBounded :
    forall node,
      after.matchIndex node <= (system.nodes LEADER).log.length

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
    (core : CoreInvariant system)
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
            responseSafe.2.2.2
      · simpa [updateIndex, Function.update, nodeEq] using
          core.matchIndicesBounded node
  · split at handled
    · rename_i failure
      simp at handled
      subst after
      constructor
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
    · contradiction

/-- Removing one selected message preserves safety of every remaining message. -/
theorem queuedMessagesSafeAfterRemove
    {state : State TxId}
    {source destination : Node}
    {selected : Message TxId}
    {remaining : List (Message TxId)}
    (core : CoreInvariant state)
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
              ResponseMatchesLeader state response := by
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

/-- Sending one entry or heartbeat preserves the core invariant. -/
theorem appendEntriesPreservesCoreInvariant
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (core : CoreInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    CoreInvariant (next state (.appendEntries source destination batchEnd)) := by
  have sourceEq : source = LEADER :=
    roleLeaderImpliesNodeLeader core enabled.1
  subst source
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
    · exact
        core.queuedRequestsMatchLeader
          queuedDestination message oldMessage
    · rcases newMessage with ⟨destinationEq, messageEq⟩
      subst queuedDestination
      subst message
      exact ⟨rfl, requestSafe⟩
  · intro candidate
    by_cases candidateEq : candidate = destination
    · subst candidate
      have batchEndBound :
          batchEnd <= (state.nodes LEADER).log.length := by
        rw [enabled.2.2]
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
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, request] using core.rolesFixed LEADER
    · simpa [next, request, candidateEq] using core.rolesFixed candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next, request] using core.currentTermsAreOne LEADER
    · simpa [next, request, candidateEq] using
        core.currentTermsAreOne candidate

/-- Processing any enabled request or response preserves the core invariant. -/
theorem receivePreservesCoreInvariant
    (state : State TxId)
    (source destination : Node)
    (core : CoreInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    CoreInvariant (next state (.receive source destination)) := by
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
                        simpa [
                          ResponseMatchesLeader,
                          updateNode,
                          Function.update,
                          leaderNeDestination
                        ] using oldSafe.2
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
                        leaderNeDestination
                      ] using post.responseSafe⟩
              · intro candidate
                simpa [leaderNeDestination] using
                  core.sentIndicesBounded candidate
              · intro candidate
                simpa [leaderNeDestination] using
                  core.matchIndicesBounded candidate
              · intro candidate
                by_cases candidateEq : candidate = destination
                · subst candidate
                  simpa using post.roleUnchanged.trans
                    (core.rolesFixed destination)
                · simpa [candidateEq] using core.rolesFixed candidate
              · intro candidate
                by_cases candidateEq : candidate = destination
                · subst candidate
                  simpa using post.currentTermUnchanged.trans
                    (core.currentTermsAreOne destination)
                · simpa [candidateEq] using
                    core.currentTermsAreOne candidate
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
              subst destination
              have post :=
                handleAppendEntriesResponsePreserves
                  core responseSafe
                    (by simpa [responseSafe.1] using handled)
              constructor
              · intro candidate
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  simpa [
                    responseDestinationEq,
                    post.commitIndexUnchanged,
                    post.logUnchanged
                  ] using
                    core.commitIndicesBounded LEADER
                · simpa [responseDestinationEq, candidateEq] using
                    core.commitIndicesBounded candidate
              · intro candidate
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  simpa [responseDestinationEq, post.logUnchanged] using
                    core.logsPrefixLeader LEADER
                · simpa [
                    responseDestinationEq,
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
                          responseDestinationEq,
                          post.logUnchanged
                        ] using entryIn)
                · exact
                    core.termsAreOne candidate entry
                      (by
                        simpa [responseDestinationEq, candidateEq] using
                          entryIn)
              · simpa [
                  LeaderTxIdsUnique,
                  responseDestinationEq,
                  post.logUnchanged
                ] using
                  core.leaderTxIdsUnique
              · simpa [
                  LeaderTxIdsSubmitted,
                  responseDestinationEq,
                  post.logUnchanged
                ] using
                  core.leaderTxIdsSubmitted
              · intro queuedDestination message messageIn
                have oldSafe :=
                  queuedMessagesSafeAfterRemove
                    core taken queuedDestination message
                      (by simpa [responseDestinationEq] using messageIn)
                constructor
                · exact oldSafe.1
                · cases message with
                  | appendEntriesRequest oldRequest =>
                      simpa [
                        RequestMatchesLeader,
                        responseDestinationEq,
                        post.logUnchanged
                      ] using oldSafe.2
                  | appendEntriesResponse oldResponse =>
                      simpa [
                        ResponseMatchesLeader,
                        responseDestinationEq,
                        post.logUnchanged
                      ] using oldSafe.2
              · simpa [
                  SentIndicesBounded,
                  responseDestinationEq,
                  post.logUnchanged
                ] using post.sentIndicesBounded
              · simpa [
                  MatchIndicesBounded,
                  responseDestinationEq,
                  post.logUnchanged
                ] using post.matchIndicesBounded
              · intro candidate
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  simpa [
                    responseDestinationEq,
                    post.roleUnchanged
                  ] using core.rolesFixed LEADER
                · simpa [responseDestinationEq, candidateEq] using
                    core.rolesFixed candidate
              · intro candidate
                by_cases candidateEq : candidate = LEADER
                · subst candidate
                  simpa [
                    responseDestinationEq,
                    post.currentTermUnchanged
                  ] using
                    core.currentTermsAreOne LEADER
                · simpa [responseDestinationEq, candidateEq] using
                    core.currentTermsAreOne candidate

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

/-- Advancing the leader commit index preserves every supporting invariant. -/
theorem advanceCommitPreservesCoreInvariant
    (state : State TxId)
    (node : Node)
    (core : CoreInvariant state)
    (enabled : Enabled state (.advanceCommitIndex node)) :
    CoreInvariant (next state (.advanceCommitIndex node)) := by
  have nodeEq : node = LEADER :=
    roleLeaderImpliesNodeLeader core enabled.1
  subst node
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
  · simpa [QueuedRequestsMatchLeader, next] using
      core.queuedRequestsMatchLeader
  · simpa [SentIndicesBounded, next] using core.sentIndicesBounded
  · simpa [MatchIndicesBounded, next] using core.matchIndicesBounded
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next] using core.rolesFixed LEADER
    · simpa [next, candidateEq] using core.rolesFixed candidate
  · intro candidate
    by_cases candidateEq : candidate = LEADER
    · subst candidate
      simpa [next] using core.currentTermsAreOne LEADER
    · simpa [next, candidateEq] using
        core.currentTermsAreOne candidate

/-- A receive transition never shrinks any node's committed log. -/
theorem receiveCommittedLogMonotonicity
    (state : State TxId)
    (source destination : Node)
    (core : CoreInvariant state)
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

/-- Every enabled action preserves committed-log append-only behavior. -/
theorem nextCommittedLogMonotonicity
    (state : State TxId)
    (action : Action TxId)
    (core : CoreInvariant state)
    (enabled : Enabled state action) :
    CommittedLogMonotonicity state (next state action) := by
  cases action with
  | clientRequest node txId =>
      have nodeEq : node = LEADER :=
        roleLeaderImpliesNodeLeader core enabled.1
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
        roleLeaderImpliesNodeLeader core enabled.1
      subst node
      intro candidate
      by_cases candidateEq : candidate = LEADER
      · subst candidate
        have oldLe :
            (state.nodes LEADER).commitIndex <=
              highestCommittableIndex state LEADER :=
          Nat.le_of_lt enabled.2
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
        · split at resultEq <;> split at resultEq
          · contradiction
          · have stateEq := Option.some.inj resultEq
            rw [← stateEq]
            simp [different]
          · contradiction
          · have stateEq := Option.some.inj resultEq
            rw [← stateEq]
            simp [different]

/-- Case-split dispatcher proving every enabled action preserves the invariant. -/
theorem nextPreservesCoreInvariant
    (state : State TxId)
    (action : Action TxId)
    (core : CoreInvariant state)
    (enabled : Enabled state action) :
    CoreInvariant (next state action) := by
  cases action with
  | clientRequest node txId =>
      exact clientRequestPreservesCoreInvariant state node txId core enabled
  | appendEntries source destination batchEnd =>
      exact
        appendEntriesPreservesCoreInvariant
          state source destination batchEnd core enabled
  | receive source destination =>
      exact receivePreservesCoreInvariant state source destination core enabled
  | advanceCommitIndex node =>
      exact advanceCommitPreservesCoreInvariant state node core enabled

/-- The supporting invariant holds in every reachable slice-one state. -/
theorem reachableCoreInvariant
    {state : State TxId}
    (reachable : Reachable state) :
    CoreInvariant state :=
  ExecutableTransitionSystem.reachableInvariant
    (system (TxId := TxId))
    initialCoreInvariant
    nextPreservesCoreInvariant
    reachable

/-- Every enabled edge leaving a reachable state extends committed logs. -/
theorem reachableStepCommittedLogMonotonicity
    {state : State TxId}
    (reachable : Reachable state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    CommittedLogMonotonicity state (next state action) :=
  nextCommittedLogMonotonicity
    state action (reachableCoreInvariant reachable) enabled

/-- All reachable committed logs are pairwise prefix-comparable. -/
theorem reachableCommittedLogsPrefix
    {state : State TxId}
    (reachable : Reachable state) :
    CommittedLogsPrefix state :=
  coreCommittedLogsPrefix (reachableCoreInvariant reachable)

/-- Every reachable state satisfies Raft log matching. -/
theorem reachableLogMatching
    {state : State TxId}
    (reachable : Reachable state) :
    LogMatching state :=
  coreLogMatching (reachableCoreInvariant reachable)

/-- Equal index and term identify equal transaction IDs in reachable states. -/
theorem reachableSameIndexSameTermSameTxId
    {state : State TxId}
    (reachable : Reachable state) :
    SameIndexSameTermSameTxId state :=
  coreSameIndexSameTermSameTxId (reachableCoreInvariant reachable)

/-- Terms are monotonic in every reachable node log. -/
theorem reachableMonoLog
    {state : State TxId}
    (reachable : Reachable state) :
    MonoLog state :=
  coreMonoLog (reachableCoreInvariant reachable)

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

end CCFRaft
