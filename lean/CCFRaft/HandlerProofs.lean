-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model

set_option autoImplicit false

/-!
# Reusable handler proofs

Common log lookup and AppendEntries handler facts.
-/

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

/-! ## Generic list, quorum, and message facts -/

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

/-- A successful one-based lookup is membership evidence. -/
theorem entryAt_mem
    {log : List (Entry TxId)}
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? log index = some entry) :
    entry ∈ log := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, value⟩
    rw [← value]
    exact List.getElem_mem within

/-- A successful lookup is unchanged when the log is extended at the end. -/
theorem entryAt_of_prefix
    {left right : List (Entry TxId)}
    (isPrefix : left <+: right)
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? left index = some entry) :
    entryAt? right index = some entry := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  unfold entryAt? at found ⊢
  by_cases zero : index = 0
  · simp [zero] at found
  · simp only [zero, ↓reduceIte] at found ⊢
    have within : index - 1 < left.length := by
      rw [List.getElem?_eq_some_iff] at found
      exact found.1
    rw [List.getElem?_append_left within]
    exact found

/-- A bounded AppendEntries batch has exactly `batchEnd - previousIndex` entries. -/
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

/-! ## Generic commit-frontier facts -/

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

/-! ## Generic local-handler facts -/

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
    · simp at handled
      subst after
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩
    · rename_i candidateRole
      split at handled
      · rename_i currentTerm
        split at handled
        · rename_i granted
          simp at handled
          subst after
          exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl,
            Or.inr ⟨granted, by simpa using candidateRole, rfl⟩⟩
        · simp at handled
          subst after
          exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩
      · contradiction

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

/-- Failure-response routing and the failure bit do not depend on its NACK index. -/
theorem failureResponseMetadata
    (before : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    (failureResponse before request).source = request.destination /\
      (failureResponse before request).destination = request.source /\
      (failureResponse before request).success = false := by
  unfold failureResponse
  split
  · exact ⟨rfl, rfl, rfl⟩
  · dsimp
    split
    · exact ⟨rfl, rfl, rfl⟩
    · split
      · exact ⟨rfl, rfl, rfl⟩
      · split <;> exact ⟨rfl, rfl, rfl⟩

/-- A follower commit learned from a request stays below the advertised
leader frontier, apart from an already committed local prefix. -/
theorem committedFromLeader_le_max_leaderCommit
    (before : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (newLog : List (Entry TxId)) :
    committedFromLeader before request newLog <=
    max before.commitIndex request.leaderCommit := by
  unfold committedFromLeader
  exact
    max_le_max_left before.commitIndex
    ((min_le_right
      newLog.length
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length))).trans
      (min_le_left
        request.leaderCommit
        (request.prevLogIndex + request.entries.length)))

/-- A follower commit learned from a request stays below the request's
verified end, apart from an already committed local prefix. -/
theorem committedFromLeader_le_max_requestEnd
    (before : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (newLog : List (Entry TxId)) :
    committedFromLeader before request newLog <=
    max before.commitIndex
      (request.prevLogIndex + request.entries.length) := by
  unfold committedFromLeader
  exact
    max_le_max_left before.commitIndex
    ((min_le_right
      newLog.length
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length))).trans
      (min_le_right
        request.leaderCommit
        (request.prevLogIndex + request.entries.length)))

/-- State facts needed from the AppendEntries request handler in both phases. -/
structure AppendRequestLocalPost
    (before after : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (response : AppendEntriesResponse) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  logShape :
    after.log = before.log \/
      after.log = before.log.take request.prevLogIndex \/
      after.log = before.log.take request.prevLogIndex ++ request.entries
  logUnchangedOrPreviousBound :
    after.log = before.log \/
      request.prevLogIndex <= before.log.length
  logUnchangedOrPreviousMatches :
    after.log = before.log \/
      request.prevLogIndex = 0 \/
        termAt before.log request.prevLogIndex =
          request.prevLogTerm
  logUnchangedOrCurrentTerm :
    after.log = before.log \/
      request.term = before.currentTerm
  previousCommittedPrefix :
    before.committedLog <+: after.log
  commitIndexBounded :
    before.commitIndex <= before.log.length ->
      after.commitIndex <= after.log.length
  commitIndexMonotone :
    before.commitIndex <= after.commitIndex
  commitRequestEndBound :
    after.commitIndex <=
      max before.commitIndex
        (request.prevLogIndex + request.entries.length)
  commitUpperBound :
    after.commitIndex <= max before.commitIndex request.leaderCommit
  responseSource : response.source = request.destination
  responseDestination : response.destination = request.source
  successfulIndexBound :
    response.success = true ->
      response.lastLogIndex <=
        request.prevLogIndex + request.entries.length
  successfulCurrentTerm :
    response.success = true ->
      request.term = before.currentTerm
  commitAdvancedSuccessful :
    before.commitIndex < after.commitIndex ->
      response.success = true
  successfulUnchangedEntryTerms :
    response.success = true ->
      after.log = before.log ->
        ((before.log.drop request.prevLogIndex).take
            request.entries.length).map Entry.term =
          request.entries.map Entry.term
  successfulLogOk :
    response.success = true ->
      logOk before request
  successfulResponseTerm :
    response.success = true ->
      response.term = before.currentTerm
  successfulIndexExact :
    response.success = true ->
      response.lastLogIndex =
        request.prevLogIndex + request.entries.length
  failedResponse :
    response.success = false ->
      response = failureResponse before request
  failedStateUnchanged :
    response.success = false ->
      after = before
  failedRequestNotNewer :
    response.success = false ->
      request.term <= before.currentTerm
  failedSameTermNotLogOk :
    response.success = false ->
      request.term = before.currentTerm ->
        Not (logOk before request)

/-- Every successful AppendEntries handler branch has the common local shape. -/
theorem handleAppendEntriesRequestLocalPost
    {before after : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (handled :
      handleAppendEntriesRequest? before request = some (after, response)) :
    AppendRequestLocalPost before after request response := by
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
      have metadata := failureResponseMetadata before request
      exact
        ⟨rfl, rfl, rfl, rfl, rfl, rfl,
          Or.inl rfl, Or.inl rfl, Or.inl rfl,
          Or.inl rfl, List.take_prefix _ _,
          (by intro bound; exact bound),
          le_rfl,
          le_max_left _ _,
          le_max_left _ _,
          metadata.1,
          metadata.2.1,
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro advanced; omega),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro _; rfl),
          (by intro _; rfl),
          (by
            intro _
            rcases ‹request.term < before.currentTerm \/
                (request.term = before.currentTerm /\
                  before.role = .follower /\
                  Not (logOk before request))› with stale | same
            · omega
            · omega),
          (by
            intro _ equal
            rcases ‹request.term < before.currentTerm \/
                (request.term = before.currentTerm /\
                  before.role = .follower /\
                  Not (logOk before request))› with stale | same
            · omega
            · exact same.2.2)⟩
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      split at handled
      · rename_i alreadyState alreadyResponse already
        unfold appendEntriesAlreadyDone? at already
        split at already
        · rename_i truncatedAlreadyDone
          have pairEq :=
            (Option.some.inj already).trans (Option.some.inj handled)
          have afterEq := congrArg Prod.fst pairEq
          have responseEq := congrArg Prod.snd pairEq
          dsimp at afterEq responseEq
          subst after
          subst response
          simp only [committedFromLeader]
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl,
              Or.inl rfl, Or.inl rfl, Or.inl rfl,
              Or.inl rfl, List.take_prefix _ _,
              (by
                intro bound
                simp only [committedFromLeader]
                omega),
              le_max_left _ _,
              committedFromLeader_le_max_requestEnd
                before request before.log,
              committedFromLeader_le_max_leaderCommit
                before request before.log,
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by intro; exact accepted.1,
              by simp [successResponse],
              (by
                intro _ _
                have done : alreadyDone before request := by assumption
                rcases done with empty | represented
                · simp [empty]
                · exact represented.2),
              by intro; exact accepted.2.2.1,
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse]⟩
        · contradiction
      · split at handled
        · rename_i extendedState extendedResponse extended
          unfold noConflictAppendEntriesRequest? at extended
          split at extended
          · have pairEq :=
              (Option.some.inj extended).trans (Option.some.inj handled)
            have afterEq := congrArg Prod.fst pairEq
            have responseEq := congrArg Prod.snd pairEq
            dsimp at afterEq responseEq
            subst after
            subst response
            simp only [committedFromLeader]
            exact
              ⟨rfl, rfl, rfl, rfl, rfl, rfl,
                Or.inr (Or.inr rfl),
                Or.inr ‹noConflictExtension before request›.2.1,
                Or.inr (by
                  rcases accepted.2.2.1 with zero | present
                  · exact Or.inl zero
                  · exact Or.inr present.2),
                Or.inr accepted.1,
                (by
                  unfold NodeState.committedLog
                  have first :
                      before.log.take before.commitIndex <+:
                        before.log.take request.prevLogIndex := by
                    rw [List.prefix_take_iff]
                    constructor
                    · exact List.take_prefix _ _
                    · simp only [List.length_take]
                      omega
                  exact first.trans
                    (List.prefix_append
                      (before.log.take request.prevLogIndex)
                      request.entries)),
                (by
                  intro bound
                  simp only [committedFromLeader, List.length_append,
                    List.length_take]
                  have previousBound :=
                    ‹noConflictExtension before request›.2.1
                  omega),
                le_max_left _ _,
                committedFromLeader_le_max_requestEnd
                  before request
                    (before.log.take request.prevLogIndex ++
                      request.entries),
                committedFromLeader_le_max_leaderCommit
                  before request
                    (before.log.take request.prevLogIndex ++
                      request.entries),
                by simp [successResponse],
                by simp [successResponse],
                by
                  intro
                  simp only [successResponse]
                  have previousBound :=
                    ‹noConflictExtension before request›.2.1
                  simp [List.length_take, previousBound],
                by intro; exact accepted.1,
                by simp [successResponse],
                (by
                  intro _ same
                  have logEq :
                      before.log =
                        before.log.take request.prevLogIndex ++
                          request.entries := same.symm
                  nth_rewrite 1 [logEq]
                  simp [
                    List.drop_append_of_le_length,
                    ‹noConflictExtension before request›.2.1]),
                by intro; exact accepted.2.2.1,
                by simp [successResponse],
                (by
                  intro
                  simp [
                    successResponse, List.length_take,
                    ‹noConflictExtension before request›.2.1]),
                by simp [successResponse],
                by simp [successResponse],
                by simp [successResponse],
                by simp [successResponse]⟩
          · contradiction
        · split at handled
          · contradiction
          · rename_i truncated conflict
            unfold conflictAppendEntriesRequest? at conflict
            split at conflict
            · have truncatedEq := Option.some.inj conflict
              subst truncated
              split at handled
              · rename_i alreadyState alreadyResponse already
                unfold appendEntriesAlreadyDone? at already
                split at already
                · rename_i truncatedAlreadyDone
                  have pairEq :=
                    (Option.some.inj already).trans
                      (Option.some.inj handled)
                  have afterEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at afterEq responseEq
                  subst after
                  subst response
                  simp only [committedFromLeader]
                  exact
                    ⟨rfl, rfl, rfl, rfl, rfl, rfl,
                      Or.inr (Or.inl rfl),
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · exact present.1),
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · exact Or.inl zero
                        · exact Or.inr present.2),
                      Or.inr accepted.1,
                      (by
                        unfold NodeState.committedLog
                        rw [List.prefix_take_iff]
                        constructor
                        · exact List.take_prefix _ _
                        · simp [List.length_take]
                          omega),
                      (by
                        intro bound
                        simp only [committedFromLeader, List.length_take]
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · omega),
                      le_max_left _ _,
                      committedFromLeader_le_max_requestEnd
                        before request
                          (before.log.take request.prevLogIndex),
                      committedFromLeader_le_max_leaderCommit
                        before request
                          (before.log.take request.prevLogIndex),
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by intro; exact accepted.1,
                      by simp [successResponse],
                      (by
                        intro _ same
                        have done :
                            alreadyDone
                              { before with
                                log := before.log.take request.prevLogIndex
                                isNewFollower := false }
                              request := by
                          assumption
                        rcases done with empty | represented
                        · simp [empty]
                        · rw [← same]
                          exact represented.2),
                      by intro; exact accepted.2.2.1,
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse]⟩
                · contradiction
              · unfold noConflictAppendEntriesRequest? at handled
                split at handled
                · have pairEq := Option.some.inj handled
                  have afterEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at afterEq responseEq
                  subst after
                  subst response
                  simp only [committedFromLeader]
                  refine
                    ⟨rfl, rfl, rfl, rfl, rfl, rfl, ?_,
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · exact present.1),
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · exact Or.inl zero
                        · exact Or.inr present.2),
                      Or.inr accepted.1,
                      (by
                        unfold NodeState.committedLog
                        simp only [List.take_take, Nat.min_self]
                        have first :
                            before.log.take before.commitIndex <+:
                              before.log.take request.prevLogIndex := by
                          rw [List.prefix_take_iff]
                          constructor
                          · exact List.take_prefix _ _
                          · simp only [List.length_take]
                            omega
                        exact first.trans
                          (List.prefix_append
                            (before.log.take request.prevLogIndex)
                            request.entries)),
                      (by
                        intro bound
                        simp only [committedFromLeader, List.length_append,
                          List.length_take, List.take_take]
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · omega),
                      le_max_left _ _,
                      committedFromLeader_le_max_requestEnd
                        before request
                          ((before.log.take request.prevLogIndex).take
                              request.prevLogIndex ++
                            request.entries),
                      committedFromLeader_le_max_leaderCommit
                        before request
                          ((before.log.take request.prevLogIndex).take
                              request.prevLogIndex ++
                            request.entries),
                      by simp [successResponse],
                      by simp [successResponse],
                      by
                        intro
                        simp only [successResponse]
                        have previousBound : request.prevLogIndex <=
                            (before.log.take request.prevLogIndex).length := by
                          rcases accepted.2.2.1 with zero | present
                          · simp [zero]
                          · simp [List.length_take, present.1]
                        simp [List.length_take, previousBound],
                      by intro; exact accepted.1,
                      by simp [successResponse],
                      (by
                        intro _ same
                        have logEq :
                            before.log =
                              (before.log.take request.prevLogIndex).take
                                  request.prevLogIndex ++ request.entries :=
                          same.symm
                        nth_rewrite 1 [logEq]
                        have previousBound :
                            request.prevLogIndex <= before.log.length := by
                          rcases accepted.2.2.1 with zero | present
                          · omega
                          · exact present.1
                        simp [
                          List.take_take, List.length_take, previousBound]),
                      by intro; exact accepted.2.2.1,
                      by simp [successResponse],
                      (by
                        intro
                        have previousBound :
                            request.prevLogIndex <= before.log.length := by
                          rcases accepted.2.2.1 with zero | present
                          · omega
                          · exact present.1
                        simp [
                          successResponse, List.take_take,
                          List.length_take, previousBound]),
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse]⟩
                  right
                  right
                  simp [List.take_take]
                · contradiction
            · contradiction
    · contradiction

/-- A node which is already a leader can only take a rejecting request branch. -/
theorem handleAppendEntriesRequestLeaderUnchanged
    {before after : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (leader : before.role = .leader)
    (handled :
      handleAppendEntriesRequest? before request = some (after, response)) :
    after = before := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have beforeAfter := congrArg Prod.fst pairEq
      dsimp at beforeAfter
      exact beforeAfter.symm
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      exact Role.noConfusion (accepted.2.1.symm.trans leader)
    · contradiction

end CCFRaft
