-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.HandlerProofs

set_option autoImplicit false

/-!
# Arbitrary-term Raft inductive proof

The proof keeps arbitrary-term election history in logical witnesses.  Runtime
state and transition semantics remain exactly `CCFRaft.system`.
-/

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

/-- Restricting evidence preserves its actual commit and ACK support. -/
theorem commitEvidenceRestrictValid
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    {shorterLength : Nat}
    (valid : evidence.Valid supportedPrefix)
    (shorter : shorterLength <= evidence.supportedLength) :
    (evidence.restrict shorterLength).Valid
      (evidence.history.take shorterLength) := by
  rcases valid with
    ⟨frontierBound, frontierTerm, supportedBound, _,
      majority, members, frontierSignature⟩
  exact
    ⟨by simpa [CommitEvidence.restrict] using frontierBound,
      by simpa [CommitEvidence.restrict] using frontierTerm,
      by simpa [CommitEvidence.restrict] using
        Nat.le_trans shorter supportedBound,
      by simp [CommitEvidence.restrict],
      by simpa [CommitEvidence.restrict] using majority,
      by
        intro member memberIn
        simpa [CommitEvidence.restrict] using
          members member memberIn,
      by simpa [CommitEvidence.restrict] using frontierSignature⟩

/-- A valid evidence exposes its supported prefix as a canonical take. -/
theorem commitEvidencePrefix
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (valid : evidence.Valid supportedPrefix) :
    evidence.history.take evidence.supportedLength =
      supportedPrefix :=
  valid.2.2.2.1

/-- Every live node/request evidence slot exposes a valid evidence. -/
theorem knownCommitEvidenceValid
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (facts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix) :
    evidence.Valid supportedPrefix := by
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, storedKnown, prefixEq⟩
    rcases facts.nodePositive node positive with
      ⟨storedEvidence, stored, valid, _, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    simpa [prefixEq] using valid
  · rcases requestKnown with
      ⟨destination, request, member, positive, storedKnown, prefixEq⟩
    rcases facts.requestPositive destination request member positive with
      ⟨storedEvidence, stored, valid, _, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    simpa [prefixEq] using valid

/-- Every live evidence supports a nonempty prefix. -/
theorem knownCommitEvidenceSupportedLengthPositive
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (facts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix) :
    0 < evidence.supportedLength := by
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, storedKnown, _⟩
    rcases facts.nodePositive node positive with
      ⟨storedEvidence, stored, _, supportedLength, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    omega
  · rcases requestKnown with
      ⟨destination, request, member, positive, storedKnown, _⟩
    rcases facts.requestPositive destination request member positive with
      ⟨storedEvidence, stored, _, supportedLength, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    omega

/-- Frame changes preserve commit evidence when committed prefixes do not change. -/
theorem commitEvidenceFrame
    (state after : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (facts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (commitEq :
      forall node,
        (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (committedEq :
      forall node,
        (after.nodes node).committedLog =
          (state.nodes node).committedLog)
    (termMonotone :
      forall node,
        (state.nodes node).currentTerm <=
          (after.nodes node).currentTerm)
    (networkSubset :
      forall destination request,
        Message.appendEntriesRequest request ∈ after.network destination ->
          Message.appendEntriesRequest request ∈ state.network destination) :
    CommitEvidenceFacts
      after appendHistory nodeEvidence requestEvidence := by
  constructor
  · intro node zero
    exact facts.nodeZero node (by simpa [commitEq] using zero)
  · intro node positive
    have oldPositive :
        0 < (state.nodes node).commitIndex := by
      simpa [commitEq] using positive
    rcases facts.nodePositive node oldPositive with
      ⟨evidence, stored, valid, lengthEq, termBound⟩
    exact
      ⟨evidence, stored,
        by simpa [committedEq] using valid,
        by simpa [commitEq] using lengthEq,
        Nat.le_trans termBound (termMonotone node)⟩
  · intro destination request member zero
    exact
      facts.requestZero destination request
        (networkSubset destination request member) zero
  · intro destination request member positive
    exact
      facts.requestPositive destination request
        (networkSubset destination request member) positive

/-- A future-member frame either maps to the old state or proves the result. -/
def FutureMemberFrameResult
    (state after : State TxId)
    (evidence : CommitEvidence TxId)
    (candidate member : Node)
    (targetTerm : Nat) : Prop :=
  ((state.nodes candidate).currentTerm < targetTerm /\
    member ∈ futureElectionVoters state candidate targetTerm /\
    (state.nodes candidate).log <+: (after.nodes candidate).log) \/
  evidence.history.take evidence.commitFrontier <+:
    (after.nodes candidate).log

/-- A relaxed voter in a frame either maps back or proves the result. -/
def RelaxedMemberFrameResult
    (state after : State TxId)
    (evidence : CommitEvidence TxId)
    (candidate member : Node) : Prop :=
  ((state.nodes candidate).role = .candidate /\
      evidence.commitTerm <
        (state.nodes candidate).currentTerm /\
      (forall entry,
        entry ∈ (state.nodes candidate).log ->
          entry.term < (state.nodes candidate).currentTerm) /\
      member ∈ relaxedElectionVoters state candidate /\
      (state.nodes candidate).log <+:
        (after.nodes candidate).log) \/
    evidence.history.take evidence.commitFrontier <+:
      (after.nodes candidate).log

/-- Same-term queued comparability either maps back or is proved directly. -/
def SameTermQueuedFrameResult
    (state : State TxId)
    (oldAppendHistory newAppendHistory :
      AppendEntriesRequest TxId -> List (Entry TxId))
    (evidence : CommitEvidence TxId)
    (destination : Node)
    (request : AppendEntriesRequest TxId) : Prop :=
  (Message.appendEntriesRequest request ∈ state.network destination /\
    oldAppendHistory request = newAppendHistory request) \/
    newAppendHistory request <+: evidence.history \/
      evidence.history.take evidence.commitFrontier <+:
        newAppendHistory request

/-- Frame preservation for the member-wise prospective commit witness. -/
theorem prospectiveCommitEvidenceFrame
    (state after : State TxId)
    (oldAppendHistory newAppendHistory :
      AppendEntriesRequest TxId -> List (Entry TxId))
    (oldNodeEvidence newNodeEvidence : NodeCommitEvidence TxId)
    (oldRequestEvidence newRequestEvidence : RequestCommitEvidence TxId)
    (elections : ElectionHistory TxId)
    (oldFacts :
      ProspectiveCommitEvidenceFacts
        state oldAppendHistory oldNodeEvidence oldRequestEvidence elections)
    (knownBack :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix ->
          KnownCommitEvidence
            state oldAppendHistory oldNodeEvidence oldRequestEvidence
            evidence supportedPrefix)
    (currentBack :
      forall member,
        (state.nodes member).log <+:
          (after.nodes member).log)
    (sameTermQueuedBack :
      forall evidence supportedPrefix destination request,
        KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix ->
        Message.appendEntriesRequest request ∈ after.network destination ->
        evidence.commitTerm = request.term ->
          SameTermQueuedFrameResult
            state oldAppendHistory newAppendHistory
              evidence destination request)
    (relaxedBack :
      forall evidence supportedPrefix candidate member,
        KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix ->
        (after.nodes candidate).role = .candidate ->
        evidence.commitTerm < (after.nodes candidate).currentTerm ->
        (forall entry,
          entry ∈ (after.nodes candidate).log ->
            entry.term < (after.nodes candidate).currentTerm) ->
        member ∈ evidence.ackQuorum ->
        member ∈ relaxedElectionVoters after candidate ->
          RelaxedMemberFrameResult
            state after evidence candidate member) :
    ProspectiveCommitEvidenceFacts
      after newAppendHistory newNodeEvidence newRequestEvidence elections := by
  constructor
  · intro evidence supportedPrefix known
    exact
      oldFacts.commitTermPositive
        evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
  · intro evidence supportedPrefix known term record recorded newer
    exact
      oldFacts.electionClosure
        evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
          term record recorded newer
  · intro evidence supportedPrefix known member ackMember
    exact
      (oldFacts.currentMember
        evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
          member ackMember).trans
        (currentBack member)
  · intro evidence supportedPrefix known destination request queued sameTerm
    rcases
        sameTermQueuedBack
          evidence supportedPrefix destination request
            known queued sameTerm with
      old | direct
    · simpa [old.2] using
        oldFacts.sameTermQueuedComparable
          evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            destination request old.1 sameTerm
    · exact direct
  · intro evidence supportedPrefix known candidate member role newer
      entriesBefore ackMember relaxed
    rcases
        relaxedBack
          evidence supportedPrefix candidate member known role newer
            entriesBefore ackMember relaxed with
      old | direct
    · rcases old with
        ⟨oldRole, oldNewer, oldEntriesBefore,
          oldRelaxed, logPrefix⟩
      exact
        (oldFacts.relaxedSupporterCarriesFrontier
          evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            candidate member oldRole oldNewer oldEntriesBefore
            ackMember oldRelaxed).trans logPrefix
    · exact direct

/-- Live evidence in a frame state came from the corresponding old slot. -/
theorem knownCommitEvidenceFrameBack
    (state after : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (commitEq :
      forall node,
        (after.nodes node).commitIndex =
          (state.nodes node).commitIndex)
    (committedEq :
      forall node,
        (after.nodes node).committedLog =
          (state.nodes node).committedLog)
    (networkSubset :
      forall destination request,
        Message.appendEntriesRequest request ∈ after.network destination ->
          Message.appendEntriesRequest request ∈ state.network destination)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        after appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix) :
    KnownCommitEvidence
      state appendHistory nodeEvidence requestEvidence
        evidence supportedPrefix := by
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, stored, prefixEq⟩
    exact Or.inl
      ⟨node,
        by simpa [commitEq] using positive,
        stored,
        by simpa [committedEq] using prefixEq⟩
  · rcases requestKnown with
      ⟨destination, request, member, positive, stored, prefixEq⟩
    exact Or.inr
      ⟨destination, request,
        networkSubset destination request member,
        positive, stored, prefixEq⟩

/-- The proof-only node evidence selected by AppendEntries receive. -/
def appendRequestNodeEvidence
    (state : State TxId)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId) :
    NodeCommitEvidence TxId :=
  Function.update nodeEvidence destination
    (if nextNode.commitIndex =
        (state.nodes destination).commitIndex then
      nodeEvidence destination
    else
      (requestEvidence request).map fun evidence =>
        evidence.restrict nextNode.commitIndex)

/--
AppendEntries receive retains the destination's old evidence when commit
does not advance, and otherwise restricts the request's advertised
evidence to the newly learned frontier.
-/
theorem appendRequestCommitEvidenceFacts
    (state : State TxId)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (afterNetwork : Node -> List (Message TxId))
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (facts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (oldCommitBound :
      (state.nodes destination).commitIndex <=
        (state.nodes destination).log.length)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response))
    (requestMember :
      Message.appendEntriesRequest request ∈
        state.network destination)
    (advancedHistory :
      (state.nodes destination).commitIndex < nextNode.commitIndex ->
        nextNode.committedLog =
          (appendHistory request).take nextNode.commitIndex)
    (networkSubset :
      forall queuedDestination queuedRequest,
        Message.appendEntriesRequest queuedRequest ∈
            afterNetwork queuedDestination ->
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination) :
    CommitEvidenceFacts
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := afterNetwork }
      appendHistory
        (appendRequestNodeEvidence
          state destination request nextNode
            nodeEvidence requestEvidence)
        requestEvidence := by
  let post :=
    CCFRaft.handleAppendEntriesRequestLocalPost handled
  let newNodeEvidence : NodeCommitEvidence TxId :=
    appendRequestNodeEvidence
      state destination request nextNode nodeEvidence requestEvidence
  change
    CommitEvidenceFacts
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := afterNetwork }
      appendHistory newNodeEvidence requestEvidence
  constructor
  · intro node zero
    by_cases same : node = destination
    · subst node
      have nextZero : nextNode.commitIndex = 0 := by
        simpa [updateNode] using zero
      have oldZero :
          (state.nodes destination).commitIndex = 0 := by
        have monotone := post.commitIndexMonotone
        omega
      have unchanged :
          nextNode.commitIndex =
            (state.nodes destination).commitIndex := by
        omega
      have oldNone := facts.nodeZero destination oldZero
      simp [
        newNodeEvidence, appendRequestNodeEvidence, unchanged, oldNone
      ]
    · have oldZero :
          (state.nodes node).commitIndex = 0 := by
        simpa [updateNode, Function.update, same] using zero
      have oldNone := facts.nodeZero node oldZero
      simpa [
        newNodeEvidence, appendRequestNodeEvidence,
        Function.update, same
      ] using oldNone
  · intro node positive
    by_cases same : node = destination
    · subst node
      have nextPositive : 0 < nextNode.commitIndex := by
        simpa [updateNode] using positive
      by_cases unchanged :
          nextNode.commitIndex =
            (state.nodes destination).commitIndex
      · have oldPositive :
            0 < (state.nodes destination).commitIndex := by
          omega
        rcases facts.nodePositive destination oldPositive with
          ⟨evidence, stored, valid, supportedLength, termBound⟩
        have committedEq :
            nextNode.committedLog =
              (state.nodes destination).committedLog := by
          have prefixEq :=
            CCFRaft.prefixEqTake post.previousCommittedPrefix
          have oldLength :
              (state.nodes destination).committedLog.length =
                (state.nodes destination).commitIndex := by
            simp [
              NodeState.committedLog, List.length_take,
              Nat.min_eq_left oldCommitBound
            ]
          unfold NodeState.committedLog
          rw [unchanged]
          rw [oldLength] at prefixEq
          exact prefixEq
        exact
          ⟨evidence,
            by simp [
              newNodeEvidence, appendRequestNodeEvidence,
              unchanged, stored
            ],
            by simpa [committedEq] using valid,
            by simpa [unchanged] using supportedLength,
            by simpa [post.currentTermUnchanged] using termBound⟩
      · have advanced :
            (state.nodes destination).commitIndex <
              nextNode.commitIndex := by
          have monotone := post.commitIndexMonotone
          omega
        have succeeded : response.success = true :=
          post.commitAdvancedSuccessful advanced
        have withinLeaderCommit :
            nextNode.commitIndex <= request.leaderCommit := by
          rcases le_max_iff.mp post.commitUpperBound with old | learned
          · omega
          · exact learned
        have leaderCommitPositive : 0 < request.leaderCommit := by
          omega
        rcases
            facts.requestPositive
              destination request requestMember leaderCommitPositive with
          ⟨evidence, stored, valid, supportedLength, termBound⟩
        have restrictedValid :
            (evidence.restrict nextNode.commitIndex).Valid
              nextNode.committedLog := by
          have validRestricted :=
            commitEvidenceRestrictValid valid
              (by simpa [supportedLength] using withinLeaderCommit)
          have historyTake :
              evidence.history.take nextNode.commitIndex =
                (appendHistory request).take nextNode.commitIndex := by
            have evidencePrefix :
                evidence.history.take request.leaderCommit =
                  (appendHistory request).take request.leaderCommit := by
              simpa [supportedLength] using valid.2.2.2.1
            calc
              evidence.history.take nextNode.commitIndex =
                  (evidence.history.take request.leaderCommit).take
                    nextNode.commitIndex := by
                      simp [List.take_take, Nat.min_eq_left withinLeaderCommit]
              _ =
                  ((appendHistory request).take request.leaderCommit).take
                    nextNode.commitIndex := by
                      rw [evidencePrefix]
              _ =
                  (appendHistory request).take nextNode.commitIndex := by
                      simp [List.take_take, Nat.min_eq_left withinLeaderCommit]
          simpa [advancedHistory advanced, historyTake] using
            validRestricted
        exact
          ⟨evidence.restrict nextNode.commitIndex,
            by simp [
              newNodeEvidence, appendRequestNodeEvidence,
              unchanged, stored
            ],
            by simpa [updateNode] using restrictedValid,
            by simp [CommitEvidence.restrict],
            by
              have requestCurrent :
                  request.term =
                    (state.nodes destination).currentTerm :=
                post.successfulCurrentTerm succeeded
              simpa [
                post.currentTermUnchanged, requestCurrent
              ] using termBound⟩
    · have oldPositive :
          0 < (state.nodes node).commitIndex := by
        simpa [updateNode, Function.update, same] using positive
      rcases facts.nodePositive node oldPositive with
        ⟨evidence, stored, valid, supportedLength, termBound⟩
      exact
        ⟨evidence,
          by simpa [
            newNodeEvidence, appendRequestNodeEvidence,
            Function.update, same
          ] using stored,
          by simpa [
            updateNode, Function.update, same,
            NodeState.committedLog
          ] using valid,
          by simpa [
            updateNode, Function.update, same
          ] using supportedLength,
          by simpa [
            updateNode, Function.update, same
          ] using termBound⟩
  · intro queuedDestination queuedRequest member zero
    exact
      facts.requestZero queuedDestination queuedRequest
        (networkSubset queuedDestination queuedRequest member) zero
  · intro queuedDestination queuedRequest member positive
    exact
      facts.requestPositive queuedDestination queuedRequest
        (networkSubset queuedDestination queuedRequest member) positive

/-- A successful one-based lookup identifies an entry in the underlying log. -/
theorem entryAtSomeMember
    {log : List (Entry TxId)}
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? log index = some entry) :
    entry ∈ log := by
  unfold entryAt? at found
  split at found
  · simp at found
  · rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, valueEq⟩
    have member : log[index - 1] ∈ log :=
      List.getElem_mem within
    rw [valueEq] at member
    exact member

/-- Membership exposes a positive one-based lookup. -/
theorem memberEntryAt
    {log : List (Entry TxId)}
    {entry : Entry TxId}
    (member : entry ∈ log) :
    Exists fun index => entryAt? log index = some entry := by
  rcases List.mem_iff_get.mp member with ⟨index, found⟩
  refine ⟨index.val + 1, ?_⟩
  unfold entryAt?
  simp only [Nat.add_eq_zero, one_ne_zero, and_false, ↓reduceIte]
  rw [List.getElem?_eq_some_iff]
  exact ⟨by omega, by simpa using found⟩

/-- Every positive in-bounds one-based index has a concrete entry. -/
theorem entryAtSomeOfPositiveBound
    {log : List (Entry TxId)}
    {index : Nat}
    (positive : 0 < index)
    (within : index <= log.length) :
    Exists fun entry => entryAt? log index = some entry := by
  refine ⟨log[index - 1], ?_⟩
  unfold entryAt?
  simp only [positive.ne', ↓reduceIte]
  rw [List.getElem?_eq_some_iff]
  exact ⟨by omega, rfl⟩

/-- Taking beyond a one-based lookup leaves that lookup unchanged. -/
theorem entryAtTake_of_le
    {log : List (Entry TxId)}
    {index count : Nat}
    (within : index <= count) :
    entryAt? (log.take count) index = entryAt? log index := by
  by_cases zero : index = 0
  · simp [entryAt?, zero]
  · unfold entryAt?
    simp only [zero, ↓reduceIte]
    rw [List.getElem?_take]
    split
    · rfl
    · omega

/-- Taking beyond an index leaves its term lookup unchanged. -/
theorem termAtTakeOfLe
    {log : List (Entry TxId)}
    {index count : Nat}
    (within : index <= count) :
    termAt (log.take count) index = termAt log index := by
  unfold termAt
  rw [entryAtTake_of_le within]

/-- Taking through the latest signature retains exactly that committable index. -/
theorem maxCommittableIndexTakeMax
    (log : List (Entry TxId)) :
    maxCommittableIndex (log.take (maxCommittableIndex log)) =
      maxCommittableIndex log := by
  by_cases zero : maxCommittableIndex log = 0
  · rw [zero]
    rfl
  apply Nat.le_antisymm
  · exact
      (maxCommittableIndexBounded
        (log.take (maxCommittableIndex log))).trans
        (by simp)
  · exact
      signatureIndex_le_maxCommittableIndex
        (isSignatureAt_take_of_le le_rfl
          (maxCommittableIndexPositiveIsSignature
            (Nat.pos_of_ne_zero zero)))

/-- Taking through the latest signature retains its committable term. -/
theorem maxCommittableTermTakeMax
    (log : List (Entry TxId)) :
    maxCommittableTerm (log.take (maxCommittableIndex log)) =
      maxCommittableTerm log := by
  unfold maxCommittableTerm
  rw [maxCommittableIndexTakeMax]
  exact termAtTakeOfLe le_rfl

/-- An exact committable snapshot lies inside the larger log's signature prefix. -/
theorem committablePrefixOfMaxTake
    {snapshot log : List (Entry TxId)}
    (isPrefix : snapshot <+: log)
    (snapshotCommittable :
      maxCommittableIndex snapshot = snapshot.length) :
    snapshot <+: log.take (maxCommittableIndex log) := by
  have lengthBound :
      snapshot.length <= maxCommittableIndex log := by
    rw [← snapshotCommittable]
    exact maxCommittableIndex_le_of_prefix isPrefix
  rw [List.prefix_iff_eq_take]
  calc
    snapshot =
        log.take snapshot.length := (prefixEqTake isPrefix).symm
    _ =
        (log.take (maxCommittableIndex log)).take snapshot.length := by
      simp [List.take_take, Nat.min_eq_left lengthBound]

/-- A prefix ending in a signature lies inside the larger log's signature prefix. -/
theorem signatureEndedPrefixOfMaxTake
    {snapshot log : List (Entry TxId)}
    (isPrefix : snapshot <+: log)
    (signature : isSignatureAt snapshot snapshot.length = true) :
    snapshot <+: log.take (maxCommittableIndex log) := by
  apply committablePrefixOfMaxTake isPrefix
  apply Nat.le_antisymm
  · exact maxCommittableIndexBounded snapshot
  · exact signatureIndex_le_maxCommittableIndex signature

/-- Taking through a known signature produces a prefix ending at that signature. -/
theorem signatureAtTakeLength
    {log : List (Entry TxId)}
    {index : Nat}
    (signature : isSignatureAt log index = true) :
    isSignatureAt (log.take index) (log.take index).length = true := by
  have indexBound : index <= log.length := by
    rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
    exact entryAtSomeIndexBound found
  simpa [List.length_take, Nat.min_eq_left indexBound] using
    isSignatureAt_take_of_le le_rfl signature

/-- A strict majority of the fixed node set is nonempty. -/
theorem majorityNonempty
    (quorum : Finset Node)
    (majority : quorum.card * 2 > NODE_COUNT) :
    quorum.Nonempty := by
  by_contra empty
  rw [Finset.not_nonempty_iff_eq_empty.mp empty] at majority
  simp at majority

/-- Two strict majorities of the five-node configuration intersect. -/
theorem majoritiesIntersect
    (left right : Finset Node)
    (leftMajority : left.card * 2 > NODE_COUNT)
    (rightMajority : right.card * 2 > NODE_COUNT) :
    (left ∩ right).Nonempty :=
  CCFRaft.fiveNodeMajoritiesIntersect
    left right leftMajority rightMajority

/-- Every prefix supported by valid evidence lies inside its ACK frontier. -/
theorem validEvidenceSupportedPrefixFrontier
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (valid : evidence.Valid supportedPrefix) :
    supportedPrefix <+:
      evidence.history.take evidence.commitFrontier := by
  rcases valid with
    ⟨_, _, supportedBound, supportedEq, _⟩
  rw [← supportedEq, List.prefix_take_iff]
  exact
    ⟨List.take_prefix evidence.supportedLength evidence.history,
      Nat.le_trans
        (List.length_take_le
          evidence.supportedLength evidence.history)
        supportedBound⟩

/--
Ballot ancestry puts a known evidence frontier in every active leader whose
term is not older than the commit term.  At the same term, one ACK member
identifies the shared canonical history.  At a higher term, ownership exposes
the leader's election record, whose promotion log contains the frontier by
`electionClosure` and is the ancestor of the active leader history.
-/
theorem knownCommitEvidenceActiveLeaderContainsFrontier
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {leader member : Node}
    (leaderRole : (state.nodes leader).role = .leader)
    (termRelation :
      evidence.commitTerm <= (state.nodes leader).currentTerm)
    (ackMember : member ∈ evidence.ackQuorum) :
    evidence.history.take evidence.commitFrontier <+:
      (state.nodes leader).log := by
  let evidencePrefix :=
    evidence.history.take evidence.commitFrontier
  have valid := knownCommitEvidenceValid evidenceFacts known
  have supportedPositive :=
    knownCommitEvidenceSupportedLengthPositive evidenceFacts known
  have frontierPositive : 0 < evidence.commitFrontier := by
    have supportedBound := valid.2.2.1
    omega
  have prefixLength :
      evidencePrefix.length = evidence.commitFrontier := by
    simp only [evidencePrefix, List.length_take]
    rw [Nat.min_eq_left valid.1]
  rcases
      entryAtSomeOfPositiveBound frontierPositive valid.1 with
    ⟨frontierEntry, historyFound⟩
  have frontierEntryTerm :
      frontierEntry.term = evidence.commitTerm := by
    simpa [termAt, historyFound] using valid.2.1
  have prefixFound :
      entryAt? evidencePrefix evidence.commitFrontier =
        some frontierEntry := by
    rw [entryAtTake_of_le le_rfl]
    exact historyFound
  have memberCovered :=
    prospectiveFacts.currentMember
      evidence supportedPrefix known member ackMember
  have memberFound :
      entryAt? (state.nodes member).log evidence.commitFrontier =
        some frontierEntry :=
    CCFRaft.entryAt_of_prefix memberCovered prefixFound
  rcases
      ownership.logEntryAgreement
        member evidence.commitFrontier frontierEntry memberFound with
    ⟨_canonicalFound, memberAgreed⟩
  have prefixCanonical :
      evidencePrefix =
        (canonicalHistory evidence.commitTerm).take
          evidence.commitFrontier := by
    calc
      evidencePrefix =
          (state.nodes member).log.take evidence.commitFrontier := by
        have covered := CCFRaft.prefixEqTake memberCovered
        rw [prefixLength] at covered
        exact covered.symm
      _ =
          (canonicalHistory frontierEntry.term).take
            evidence.commitFrontier :=
        memberAgreed
      _ =
          (canonicalHistory evidence.commitTerm).take
            evidence.commitFrontier := by rw [frontierEntryTerm]
  by_cases newer :
      evidence.commitTerm < (state.nodes leader).currentTerm
  · have owned :=
      ownership.activeLeader leader leaderRole
    rcases
        electionFacts.ownerRecorded
          (state.nodes leader).currentTerm leader owned with
      bootstrap | recorded
    · rw [bootstrap.1] at newer
      have positive :=
        prospectiveFacts.commitTermPositive
          evidence supportedPrefix known
      omega
    · rcases recorded with
        ⟨record, recordStored, _recordLeader⟩
      have promotionPrefix :=
        prospectiveFacts.electionClosure
          evidence supportedPrefix known
            (state.nodes leader).currentTerm record
            recordStored newer
      have canonicalPrefix :=
        promotionPrefix.trans
          (electionFacts.promotionCanonical
            (state.nodes leader).currentTerm record recordStored)
      rw [ownership.activeLeaderHistory leader leaderRole] at canonicalPrefix
      exact canonicalPrefix
  · have sameTerm :
        evidence.commitTerm =
          (state.nodes leader).currentTerm := by
      omega
    rw [List.prefix_iff_eq_take]
    calc
      evidencePrefix =
          (canonicalHistory evidence.commitTerm).take
            evidence.commitFrontier :=
        prefixCanonical
      _ =
          (state.nodes leader).log.take evidence.commitFrontier := by
        rw [sameTerm, ownership.activeLeaderHistory leader leaderRole]
      _ =
          (state.nodes leader).log.take evidencePrefix.length := by
        rw [prefixLength]

/--
Ballot ancestry also derives containment for a higher-term queued
AppendEntries history.  Queued metadata identifies the term owner, the frozen
election record inherits the evidence frontier through `electionClosure`, and
`ElectionQueuedHistoryFacts` carries that promotion ancestry into the queued
history.  Equal terms remain governed by `sameTermQueuedComparable`.
-/
theorem knownCommitEvidenceQueuedAppendContainsFrontier
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (electionQueuedFacts :
      ElectionQueuedHistoryFacts state appendHistory elections)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (queued :
      Message.appendEntriesRequest request ∈ state.network destination)
    (newer : evidence.commitTerm < request.term) :
    evidence.history.take evidence.commitFrontier <+:
      appendHistory request := by
  rcases ownership.queuedAppendMetadata destination request queued with
    ⟨owned, _entriesBounded⟩
  rcases
      electionFacts.ownerRecorded request.term request.source owned with
    bootstrap | recorded
  · rw [bootstrap.1] at newer
    have positive :=
      prospectiveFacts.commitTermPositive
        evidence supportedPrefix known
    omega
  · rcases recorded with
      ⟨record, recordStored, _recordLeader⟩
    exact
      (prospectiveFacts.electionClosure
        evidence supportedPrefix known request.term record
          recordStored newer).trans
        (electionQueuedFacts
          destination request queued record recordStored)

/-- Nodes whose current logs contain one node's committed log. -/
def committedHolders
    (state : State TxId)
    (node : Node) : Finset Node :=
  Finset.univ.filter fun holder =>
    (state.nodes node).committedLog <+:
      (state.nodes holder).log

/-- `QuorumLog` implies that the holder set of every committed log is a majority. -/
theorem committedHoldersMajority
    {state : State TxId}
    (quorumLog : QuorumLog state)
    (node : Node) :
    (committedHolders state node).card * 2 > NODE_COUNT := by
  by_contra notMajority
  have holderSmall :
      (committedHolders state node).card <= 2 := by
    simp [NODE_COUNT] at notMajority
    omega
  let complement :=
    Finset.univ \ committedHolders state node
  have holderSubset :
      committedHolders state node ⊆ Finset.univ :=
    Finset.subset_univ _
  have complementCard :
      complement.card =
        NODE_COUNT - (committedHolders state node).card := by
    simp [
      complement,
      Finset.card_sdiff_of_subset holderSubset,
      NODE_COUNT
    ]
  have complementMajority :
      complement.card * 2 > NODE_COUNT := by
    rw [complementCard]
    simp [NODE_COUNT]
    omega
  rcases quorumLog node complement complementMajority with
    ⟨witness, inComplement, contains⟩
  have inHolders :
      witness ∈ committedHolders state node := by
    simpa [committedHolders] using contains
  exact (Finset.mem_sdiff.mp inComplement).2 inHolders

/-- Quorum coverage directly yields pairwise committed-log comparability. -/
theorem quorumLogCommittedLogsPrefix
    {state : State TxId}
    (quorumLog : QuorumLog state) :
    CommittedLogsPrefix state := by
  intro left right
  have leftMajority := committedHoldersMajority quorumLog left
  have rightMajority := committedHoldersMajority quorumLog right
  rcases majoritiesIntersect
      (committedHolders state left)
      (committedHolders state right)
      leftMajority rightMajority with
    ⟨witness, member⟩
  have leftPrefix :
      (state.nodes left).committedLog <+:
        (state.nodes witness).log := by
    simpa [committedHolders] using (Finset.mem_inter.mp member).1
  have rightPrefix :
      (state.nodes right).committedLog <+:
        (state.nodes witness).log := by
    simpa [committedHolders] using (Finset.mem_inter.mp member).2
  exact CCFRaft.prefixesComparable leftPrefix rightPrefix

/-- Persistent vote history and intersecting election quorums imply uniqueness. -/
theorem voteHistoryElectionSafety
    {state : State TxId}
    {history : VoteHistory}
    (termsPositive : CurrentTermsPositive state)
    (leaders : LeadersHaveElectionMajority state)
    (votes : VoteHistoryFacts state history) :
    ElectionSafety state := by
  intro left right leftRole rightRole sameTerm
  rcases leaders left leftRole with leftBootstrap | leftMajority
  · rcases leaders right rightRole with rightBootstrap | rightMajority
    · exact leftBootstrap.1.trans rightBootstrap.1.symm
    · have rightTermOne :
          (state.nodes right).currentTerm = TERM_ONE :=
        sameTerm.symm.trans leftBootstrap.2
      rcases majorityNonempty
          (state.nodes right).votesGranted rightMajority with
        ⟨voter, voterIn⟩
      have counted :=
        votes.counted right voter (Or.inr rightRole) voterIn
      rw [rightTermOne, votes.bootstrapEmpty voter] at counted
      contradiction
  · rcases leaders right rightRole with rightBootstrap | rightMajority
    · have leftTermOne :
          (state.nodes left).currentTerm = TERM_ONE :=
        sameTerm.trans rightBootstrap.2
      rcases majorityNonempty
          (state.nodes left).votesGranted leftMajority with
        ⟨voter, voterIn⟩
      have counted :=
        votes.counted left voter (Or.inr leftRole) voterIn
      rw [leftTermOne, votes.bootstrapEmpty voter] at counted
      contradiction
    · rcases majoritiesIntersect
          (state.nodes left).votesGranted
          (state.nodes right).votesGranted
          leftMajority rightMajority with
        ⟨voter, member⟩
      have leftVote :=
        votes.counted left voter (Or.inr leftRole)
          (Finset.mem_inter.mp member).1
      have rightVote :=
        votes.counted right voter (Or.inr rightRole)
          (Finset.mem_inter.mp member).2
      rw [sameTerm] at leftVote
      exact Option.some.inj (leftVote.symm.trans rightVote)

/-- Classify a successful lookup after appending one entry. -/
theorem entryAtAppendSingleton
    {log : List (Entry TxId)}
    {newEntry foundEntry : Entry TxId}
    {index : Nat}
    (found :
      entryAt? (log ++ [newEntry]) index = some foundEntry) :
    ((index <= log.length /\
        entryAt? log index = some foundEntry) \/
      (index = log.length + 1 /\ foundEntry = newEntry)) := by
  have positive : 0 < index := by
    by_contra notPositive
    have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at found
  unfold entryAt? at found
  simp only [positive.ne', ↓reduceIte] at found
  by_cases oldIndex : index - 1 < log.length
  · left
    constructor
    · omega
    · unfold entryAt?
      simp only [positive.ne', ↓reduceIte]
      simpa [List.getElem?_append_left oldIndex] using found
  · right
    have appendedIndex : index - 1 = log.length := by
      have within :
          index - 1 < (log ++ [newEntry]).length := by
        rw [List.getElem?_eq_some_iff] at found
        exact found.1
      simp at within
      omega
    constructor
    · omega
    · rw [List.getElem?_append_right (by omega)] at found
      simp [appendedIndex] at found
      exact found.symm

/-- Appending a suffix does not change a one-based lookup inside the base. -/
theorem entryAtAppend_of_le_length
    {base suffix : List (Entry TxId)}
    {index : Nat}
    (within : index <= base.length) :
    entryAt? (base ++ suffix) index = entryAt? base index := by
  unfold entryAt?
  split
  · rfl
  · rw [List.getElem?_append_left]
    omega

/-- A lookup after an appended base is the corresponding suffix lookup. -/
theorem entryAtAppend_right
    {base suffix : List (Entry TxId)}
    {index : Nat}
    (afterBase : base.length < index) :
    entryAt? (base ++ suffix) index =
      entryAt? suffix (index - base.length) := by
  have positive : 0 < index := by omega
  have suffixPositive : 0 < index - base.length := by omega
  unfold entryAt?
  simp only [
    positive.ne', suffixPositive.ne', ↓reduceIte
  ]
  rw [List.getElem?_append_right (by omega)]
  congr 1
  omega

/-- Dropping and bounding a slice preserves lookups represented in it. -/
theorem entryAtDropTake
    {log : List (Entry TxId)}
    {previous index count : Nat}
    (afterPrevious : previous < index)
    (withinSlice : index <= previous + count) :
    entryAt? ((log.drop previous).take count) (index - previous) =
      entryAt? log index := by
  have positive : 0 < index := by omega
  have slicePositive : 0 < index - previous := by omega
  unfold entryAt?
  simp only [
    positive.ne', slicePositive.ne', ↓reduceIte
  ]
  rw [List.getElem?_take]
  split
  · rw [List.getElem?_drop]
    congr 1
    omega
  · rename_i outside
    exact False.elim (outside (by omega))

/-- Equal term projections give equal terms at matching successful lookups. -/
theorem entryTermsEqualOfMappedTerms
    {left right : List (Entry TxId)}
    {index : Nat}
    {leftEntry rightEntry : Entry TxId}
    (terms : left.map Entry.term = right.map Entry.term)
    (leftFound : entryAt? left index = some leftEntry)
    (rightFound : entryAt? right index = some rightEntry) :
    leftEntry.term = rightEntry.term := by
  have positive : 0 < index := by
    by_contra notPositive
    have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at leftFound
  have pointwise :=
    congrArg (fun values => values[index - 1]?) terms
  unfold entryAt? at leftFound rightFound
  simp only [positive.ne', ↓reduceIte] at leftFound rightFound
  simpa [List.getElem?_map, leftFound, rightFound] using pointwise

/-- Appending a suffix does not change the term inside the base. -/
theorem termAtAppend_of_le_length
    {base suffix : List (Entry TxId)}
    {index : Nat}
    (within : index <= base.length) :
    termAt (base ++ suffix) index = termAt base index := by
  unfold termAt
  rw [entryAtAppend_of_le_length within]

/-- A positive term lookup exposes the underlying entry. -/
theorem termAtPositiveEntry
    {log : List (Entry TxId)}
    {index : Nat}
    (positive : 0 < termAt log index) :
    Exists fun entry =>
      entryAt? log index = some entry /\
        entry.term = termAt log index := by
  unfold termAt at positive ⊢
  cases found : entryAt? log index with
  | none =>
      simp [found] at positive
  | some entry =>
      exact
        ⟨entry, by simpa [found], by simp [found]⟩

/-- Canonical snapshots with the same final term are ordered by final index. -/
theorem canonicalHistoriesPrefixOfSameLastTerm
    (canonicalHistory : Nat -> List (Entry TxId))
    {left right : List (Entry TxId)}
    (leftCanonical : HistoryCanonical canonicalHistory left)
    (rightCanonical : HistoryCanonical canonicalHistory right)
    (leftNonempty : Not (left = []))
    (lengthLe : left.length <= right.length)
    (lastTermEq :
      termAt left left.length = termAt right right.length) :
    left <+: right := by
  have leftPositive : 0 < left.length :=
    List.length_pos_iff_ne_nil.mpr leftNonempty
  have rightPositive : 0 < right.length := by omega
  rcases
      entryAtSomeOfPositiveBound leftPositive le_rfl with
    ⟨leftEntry, leftFound⟩
  rcases
      entryAtSomeOfPositiveBound rightPositive le_rfl with
    ⟨rightEntry, rightFound⟩
  rcases leftCanonical left.length leftEntry leftFound with
    ⟨leftCanonicalFound, leftAgreed⟩
  rcases rightCanonical right.length rightEntry rightFound with
    ⟨rightCanonicalFound, rightAgreed⟩
  have entryTermEq : leftEntry.term = rightEntry.term := by
    simpa [termAt, leftFound, rightFound] using lastTermEq
  have leftEq :
      left =
        (canonicalHistory leftEntry.term).take left.length := by
    simpa using leftAgreed
  have rightEq :
      right =
        (canonicalHistory rightEntry.term).take right.length := by
    simpa using rightAgreed
  calc
    left =
        (canonicalHistory leftEntry.term).take left.length :=
      leftEq
    _ =
        (canonicalHistory rightEntry.term).take left.length := by
          rw [entryTermEq]
    _ <+:
        (canonicalHistory rightEntry.term).take right.length := by
          rw [List.prefix_take_iff]
          exact
            ⟨List.take_prefix left.length _,
              Nat.le_trans (List.length_take_le _ _)
                lengthLe⟩
    _ = right := rightEq.symm

/--
When a handled AppendEntries request advances commit, the corrected
request-end bound and canonical history agreement identify the exact learned
committed prefix.
-/
theorem handledAppendRequestAdvancedCommittedHistory
    (state : State TxId)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (requestMember :
      Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (oldCommitBound :
      (state.nodes destination).commitIndex <=
        (state.nodes destination).log.length)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response))
    (advanced :
      (state.nodes destination).commitIndex < nextNode.commitIndex) :
    nextNode.committedLog =
      (appendHistory request).take nextNode.commitIndex := by
  let post :=
    CCFRaft.handleAppendEntriesRequestLocalPost handled
  have succeeded : response.success = true :=
    post.commitAdvancedSuccessful advanced
  have nextBound : nextNode.commitIndex <= nextNode.log.length :=
    post.commitIndexBounded oldCommitBound
  have withinEnd :
      nextNode.commitIndex <=
        request.prevLogIndex + request.entries.length := by
    rcases le_max_iff.mp post.commitRequestEndBound with old | learned
    · omega
    · exact learned
  have nextPositive : 0 < nextNode.commitIndex := by omega
  have previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length := by
    rcases post.successfulLogOk succeeded with zero | present
    · omega
    · exact present.1
  have historyPreviousBound :
      request.prevLogIndex <= (appendHistory request).length := by
    exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
  have previousAgreement :
      (state.nodes destination).log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · have previousPositive : 0 < request.prevLogIndex := by omega
      rcases
          entryAtSomeOfPositiveBound previousPositive previousBound with
        ⟨nodeEntry, nodeFound⟩
      rcases
          entryAtSomeOfPositiveBound
            previousPositive historyPreviousBound with
        ⟨historyEntry, historyFound⟩
      have nodeTerm :
          nodeEntry.term = request.prevLogTerm := by
        rcases post.successfulLogOk succeeded with impossible | present
        · exact False.elim (zero impossible)
        · simpa [termAt, nodeFound] using present.2
      have historyTerm :
          historyEntry.term = request.prevLogTerm := by
        simpa [termAt, historyFound] using snapshot.2.1.symm
      rcases
          ownership.logEntryAgreement
            destination request.prevLogIndex nodeEntry nodeFound with
        ⟨_, nodeAgreed⟩
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember
              request.prevLogIndex historyEntry historyFound with
        ⟨_, historyAgreed⟩
      calc
        (state.nodes destination).log.take request.prevLogIndex =
            (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
          nodeAgreed
        _ =
            (canonicalHistory historyEntry.term).take
              request.prevLogIndex := by
          rw [nodeTerm, historyTerm]
        _ = (appendHistory request).take request.prevLogIndex :=
          historyAgreed.symm
  have nextPreviousAgreement :
      nextNode.log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    have nextOldPrevious :
        nextNode.log.take request.prevLogIndex =
          (state.nodes destination).log.take request.prevLogIndex := by
      rcases post.logShape with same | truncated | extended
      · rw [same]
      · rw [truncated]
        simp
      · rw [extended]
        simp [List.length_take, previousBound]
    exact nextOldPrevious.trans previousAgreement
  have takeAgreement :
      nextNode.log.take nextNode.commitIndex =
        (appendHistory request).take nextNode.commitIndex := by
    by_cases withinPrevious :
        nextNode.commitIndex <= request.prevLogIndex
    · calc
        nextNode.log.take nextNode.commitIndex =
            (nextNode.log.take request.prevLogIndex).take
              nextNode.commitIndex := by
                simp [List.take_take, Nat.min_eq_left withinPrevious]
        _ =
            ((appendHistory request).take request.prevLogIndex).take
              nextNode.commitIndex := by
                rw [nextPreviousAgreement]
        _ = (appendHistory request).take nextNode.commitIndex := by
              simp [List.take_take, Nat.min_eq_left withinPrevious]
    · have afterPrevious :
          request.prevLogIndex < nextNode.commitIndex := by omega
      rcases post.logShape with same | truncated | extended
      · have nodeFound :
            Exists fun entry =>
              entryAt? (state.nodes destination).log
                nextNode.commitIndex = some entry := by
          rw [same] at nextBound
          exact
            entryAtSomeOfPositiveBound nextPositive
              nextBound
        rcases nodeFound with ⟨nodeEntry, nodeFound⟩
        rcases
            entryAtSomeOfPositiveBound nextPositive
              (Nat.le_trans withinEnd snapshot.1) with
          ⟨historyEntry, historyFound⟩
        have offsetPositive :
            0 < nextNode.commitIndex - request.prevLogIndex := by omega
        have requestFound :
            entryAt? request.entries
                (nextNode.commitIndex - request.prevLogIndex) =
              some historyEntry := by
          have inTaken :
              entryAt?
                  ((appendHistory request).take
                    (request.prevLogIndex + request.entries.length))
                  nextNode.commitIndex =
                some historyEntry := by
            rw [entryAtTake_of_le withinEnd]
            exact historyFound
          rw [snapshot.2.2] at inTaken
          have previousLength :
              ((appendHistory request).take request.prevLogIndex).length =
                request.prevLogIndex := by
            simp [List.length_take, historyPreviousBound]
          rw [
            entryAtAppend_right
              (base := (appendHistory request).take request.prevLogIndex)
              (suffix := request.entries)
              (by simpa [previousLength] using afterPrevious),
            previousLength
          ] at inTaken
          exact inTaken
        have localSliceFound :
            entryAt?
                (((state.nodes destination).log.drop request.prevLogIndex).take
                  request.entries.length)
                (nextNode.commitIndex - request.prevLogIndex) =
              some nodeEntry := by
          rw [entryAtDropTake afterPrevious withinEnd]
          exact nodeFound
        have sameTerm :
            nodeEntry.term = historyEntry.term :=
          entryTermsEqualOfMappedTerms
            (post.successfulUnchangedEntryTerms succeeded same)
            localSliceFound requestFound
        rcases
            ownership.logEntryAgreement
              destination nextNode.commitIndex nodeEntry nodeFound with
          ⟨_, nodeAgreed⟩
        rcases
            ownership.queuedHistoryEntryAgreement
              destination request requestMember
                nextNode.commitIndex historyEntry historyFound with
          ⟨_, historyAgreed⟩
        rw [same]
        calc
          (state.nodes destination).log.take nextNode.commitIndex =
              (canonicalHistory nodeEntry.term).take
                nextNode.commitIndex :=
            nodeAgreed
          _ =
              (canonicalHistory historyEntry.term).take
                nextNode.commitIndex := by rw [sameTerm]
          _ = (appendHistory request).take nextNode.commitIndex :=
            historyAgreed.symm
      · have truncatedLength :
            nextNode.log.length <= request.prevLogIndex := by
          rw [truncated]
          simp
        omega
      · rw [extended]
        calc
          ((state.nodes destination).log.take request.prevLogIndex ++
              request.entries).take nextNode.commitIndex =
              ((appendHistory request).take request.prevLogIndex ++
                request.entries).take nextNode.commitIndex := by
                rw [previousAgreement]
          _ =
              ((appendHistory request).take
                (request.prevLogIndex + request.entries.length)).take
                  nextNode.commitIndex := by
                    rw [snapshot.2.2]
          _ = (appendHistory request).take nextNode.commitIndex := by
                simp [List.take_take, Nat.min_eq_left withinEnd]
  simpa [NodeState.committedLog] using takeAgreement

/-- A shared prefix covering the complete request makes the request already
present in the destination log. -/
theorem appendRequestAlreadyDoneOfSharedPrefix
    {before : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {history sharedPrefix : List (Entry TxId)}
    (snapshot : RequestSnapshots history request)
    (beforePrefix : sharedPrefix <+: before.log)
    (historyPrefix : sharedPrefix <+: history)
    (covers :
      request.prevLogIndex + request.entries.length <= sharedPrefix.length) :
    alreadyDone before request := by
  right
  constructor
  · exact Nat.le_trans covers beforePrefix.length_le
  · have beforeTake :
        before.log.take
            (request.prevLogIndex + request.entries.length) =
          history.take
            (request.prevLogIndex + request.entries.length) := by
      calc
        before.log.take
              (request.prevLogIndex + request.entries.length) =
            sharedPrefix.take
              (request.prevLogIndex + request.entries.length) :=
          (CCFRaft.takeEqOfPrefix beforePrefix covers).symm
        _ =
            history.take
              (request.prevLogIndex + request.entries.length) :=
          CCFRaft.takeEqOfPrefix historyPrefix covers
    have exactEntries :
        (before.log.drop request.prevLogIndex).take
            request.entries.length =
          request.entries := by
      have dropped :=
        congrArg (List.drop request.prevLogIndex) beforeTake
      rw [snapshot.2.2] at dropped
      have previousBound :
          request.prevLogIndex <= history.length := by
        exact Nat.le_trans
          (Nat.le_add_right _ _) snapshot.1
      simpa [
        List.drop_take,
        List.length_take,
        previousBound
      ] using dropped
    rw [exactEntries]

/-- A successful handler cannot shorten a prefix shared by the destination
and the immutable request history. -/
theorem successfulAppendRequestSharedPrefixLength
    {before nextNode : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    {history sharedPrefix : List (Entry TxId)}
    (snapshot : RequestSnapshots history request)
    (beforePrefix : sharedPrefix <+: before.log)
    (historyPrefix : sharedPrefix <+: history)
    (handled :
      handleAppendEntriesRequest? before request =
        some (nextNode, response))
    (success : response.success = true) :
    sharedPrefix.length <= nextNode.log.length := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have responseEq := congrArg Prod.snd pairEq
      dsimp at responseEq
      subst response
      have failed := (CCFRaft.failureResponseMetadata before request).2.2
      rw [failed] at success
      contradiction
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · split at handled
      · rename_i alreadyState alreadyResponse alreadyResult
        unfold appendEntriesAlreadyDone? at alreadyResult
        split at alreadyResult
        · have pairEq :=
            (Option.some.inj alreadyResult).trans
              (Option.some.inj handled)
          have nextEq := congrArg Prod.fst pairEq
          dsimp at nextEq
          subst nextNode
          simpa using beforePrefix.length_le
        · contradiction
      · split at handled
        · rename_i extendedState extendedResponse extensionResult
          unfold noConflictAppendEntriesRequest? at extensionResult
          split at extensionResult
          · rename_i extension
            have pairEq :=
              (Option.some.inj extensionResult).trans
                (Option.some.inj handled)
            have nextEq := congrArg Prod.fst pairEq
            dsimp at nextEq
            subst nextNode
            rcases extension with ⟨_, _, shorter, _⟩
            have prefixBound : sharedPrefix.length <
                request.prevLogIndex + request.entries.length :=
              lt_of_le_of_lt beforePrefix.length_le shorter
            simp only [List.length_append, List.length_take]
            omega
          · contradiction
        · split at handled
          · contradiction
          · rename_i truncated conflictResult
            unfold conflictAppendEntriesRequest? at conflictResult
            split at conflictResult
            · rename_i conflict
              have truncatedEq := Option.some.inj conflictResult
              subst truncated
              split at handled
              · rename_i alreadyState alreadyResponse alreadyResult
                unfold appendEntriesAlreadyDone? at alreadyResult
                split at alreadyResult
                · rcases conflict.1.1 with nonempty
                  rename_i already
                  rcases already with empty | bounded
                  · exact False.elim (nonempty empty)
                  · have entriesPositive :
                        0 < request.entries.length :=
                      List.length_pos_iff_ne_nil.mpr nonempty
                    have endBeforePrevious :
                        request.prevLogIndex +
                            request.entries.length <=
                          request.prevLogIndex := by
                      exact Nat.le_trans bounded.1 (List.length_take_le _ _)
                    omega
                · contradiction
              · unfold noConflictAppendEntriesRequest? at handled
                split at handled
                · have pairEq :=
                    Option.some.inj handled
                  have nextEq := congrArg Prod.fst pairEq
                  dsimp at nextEq
                  subst nextNode
                  have prefixBound :
                      sharedPrefix.length <=
                        request.prevLogIndex + request.entries.length := by
                    by_contra notBounded
                    have already :=
                      appendRequestAlreadyDoneOfSharedPrefix
                        snapshot beforePrefix historyPrefix
                          (by omega)
                    have impossible :=
                      ‹appendEntriesAlreadyDone? before request = none›
                    simp [appendEntriesAlreadyDone?, already] at impossible
                  have previousBound :
                      request.prevLogIndex <= before.log.length := by
                    rcases
                        ‹request.term = before.currentTerm /\
                          before.role = .follower /\
                          logOk before request /\
                          request.prevLogIndex >= before.commitIndex›.2.2.1 with
                      zero | present
                    · omega
                    · exact present.1
                  simpa [
                    List.length_append,
                    List.length_take,
                    previousBound
                  ] using prefixBound
                · contradiction
            · contradiction
    · contradiction

/-- Successful handling retains every prefix shared by the old destination log
and the immutable queued request history. -/
theorem handledAppendRequestRetainsSharedPrefix
    (state : State TxId)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (requestMember :
      Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response))
    (success : response.success = true)
    {sharedPrefix : List (Entry TxId)}
    (beforePrefix :
      sharedPrefix <+: (state.nodes destination).log)
    (historyPrefix :
      sharedPrefix <+: appendHistory request) :
    sharedPrefix <+: nextNode.log := by
  let post :=
    CCFRaft.handleAppendEntriesRequestLocalPost handled
  have prefixBound :
      sharedPrefix.length <= nextNode.log.length :=
    successfulAppendRequestSharedPrefixLength
      snapshot beforePrefix historyPrefix handled success
  have previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length := by
    rcases post.successfulLogOk success with zero | present
    · omega
    · exact present.1
  have historyPreviousBound :
      request.prevLogIndex <= (appendHistory request).length := by
    exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
  have previousAgreement :
      (state.nodes destination).log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · have previousPositive : 0 < request.prevLogIndex := by omega
      rcases
          entryAtSomeOfPositiveBound previousPositive previousBound with
        ⟨nodeEntry, nodeFound⟩
      rcases
          entryAtSomeOfPositiveBound
            previousPositive historyPreviousBound with
        ⟨historyEntry, historyFound⟩
      have nodeTerm :
          nodeEntry.term = request.prevLogTerm := by
        rcases post.successfulLogOk success with impossible | present
        · exact False.elim (zero impossible)
        · simpa [termAt, nodeFound] using present.2
      have historyTerm :
          historyEntry.term = request.prevLogTerm := by
        simpa [termAt, historyFound] using snapshot.2.1.symm
      rcases
          ownership.logEntryAgreement
            destination request.prevLogIndex nodeEntry nodeFound with
        ⟨_, nodeAgreed⟩
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember
              request.prevLogIndex historyEntry historyFound with
        ⟨_, historyAgreed⟩
      calc
        (state.nodes destination).log.take request.prevLogIndex =
            (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
          nodeAgreed
        _ =
            (canonicalHistory historyEntry.term).take
              request.prevLogIndex := by
          rw [nodeTerm, historyTerm]
        _ = (appendHistory request).take request.prevLogIndex :=
          historyAgreed.symm
  rcases post.logShape with same | truncated | extended
  · simpa [same] using beforePrefix
  · rw [truncated]
    have withinPrevious : sharedPrefix.length <= request.prevLogIndex := by
      rw [truncated] at prefixBound
      simpa [List.length_take, previousBound] using prefixBound
    rw [List.prefix_take_iff]
    exact ⟨beforePrefix, withinPrevious⟩
  · have fullAgreement :
        nextNode.log =
          (appendHistory request).take
            (request.prevLogIndex + request.entries.length) := by
      calc
        nextNode.log =
            (state.nodes destination).log.take request.prevLogIndex ++
              request.entries :=
          extended
        _ =
            (appendHistory request).take request.prevLogIndex ++
              request.entries := by rw [previousAgreement]
        _ =
            (appendHistory request).take
              (request.prevLogIndex + request.entries.length) :=
          snapshot.2.2.symm
    rw [fullAgreement, List.prefix_take_iff]
    constructor
    · exact historyPrefix
    · simpa [fullAgreement, List.length_take, snapshot.1] using prefixBound

/-- If the receive path did not step down a candidate, handling an
AppendEntries request leaves every active node unchanged. -/
theorem handleAppendEntriesRequestActiveUnchanged
    {before nextNode : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (notStepped : returnToFollowerState? before request = none)
    (handled :
      handleAppendEntriesRequest? before request =
        some (nextNode, response))
    (active :
      before.role = .candidate \/ before.role = .leader) :
    nextNode = before := by
  rcases active with candidate | leader
  · let post := CCFRaft.handleAppendEntriesRequestLocalPost handled
    by_cases succeeded : response.success = true
    · have sameTerm := post.successfulCurrentTerm succeeded
      unfold returnToFollowerState? at notStepped
      simp [sameTerm, candidate] at notStepped
    · have failed : response.success = false :=
        Bool.eq_false_of_not_eq_true succeeded
      exact post.failedStateUnchanged failed
  · exact
      CCFRaft.handleAppendEntriesRequestLeaderUnchanged
        leader handled

/-- Every successful response acknowledges an index present in the resulting
destination log. -/
theorem successfulAppendResponseIndexWithinLog
    {before nextNode : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (handled :
      handleAppendEntriesRequest? before request =
        some (nextNode, response))
    (success : response.success = true) :
    response.lastLogIndex <= nextNode.log.length := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have responseEq := congrArg Prod.snd pairEq
      dsimp at responseEq
      subst response
      have failed := (CCFRaft.failureResponseMetadata before request).2.2
      rw [failed] at success
      contradiction
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · split at handled
      · rename_i alreadyState alreadyResponse alreadyResult
        unfold appendEntriesAlreadyDone? at alreadyResult
        split at alreadyResult
        · rename_i already
          have pairEq :=
            (Option.some.inj alreadyResult).trans
              (Option.some.inj handled)
          have nextEq := congrArg Prod.fst pairEq
          have responseEq := congrArg Prod.snd pairEq
          dsimp at nextEq responseEq
          subst nextNode
          subst response
          simp only [successResponse]
          rcases already with empty | represented
          · have previousBound :
                request.prevLogIndex <= before.log.length := by
              rcases
                  ‹request.term = before.currentTerm /\
                    before.role = .follower /\
                    logOk before request /\
                    request.prevLogIndex >= before.commitIndex›.2.2.1 with
                zero | present
              · omega
              · exact present.1
            simp [empty]
            exact previousBound
          · exact represented.1
        · contradiction
      · split at handled
        · rename_i extendedState extendedResponse extensionResult
          unfold noConflictAppendEntriesRequest? at extensionResult
          split at extensionResult
          · rename_i extension
            have pairEq :=
              (Option.some.inj extensionResult).trans
                (Option.some.inj handled)
            have nextEq := congrArg Prod.fst pairEq
            have responseEq := congrArg Prod.snd pairEq
            dsimp at nextEq responseEq
            subst nextNode
            subst response
            simp [
              successResponse,
              List.length_take,
              extension.2.1
            ]
          · contradiction
        · split at handled
          · contradiction
          · rename_i truncated conflictResult
            unfold conflictAppendEntriesRequest? at conflictResult
            split at conflictResult
            · have truncatedEq := Option.some.inj conflictResult
              subst truncated
              split at handled
              · rename_i alreadyState alreadyResponse alreadyResult
                unfold appendEntriesAlreadyDone? at alreadyResult
                split at alreadyResult
                · rename_i already
                  have pairEq :=
                    (Option.some.inj alreadyResult).trans
                      (Option.some.inj handled)
                  have nextEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at nextEq responseEq
                  subst nextNode
                  subst response
                  simp only [successResponse]
                  rcases already with empty | represented
                  · exact False.elim
                      (‹hasTermConflict before request /\
                        before.isNewFollower = true›.1.1 empty)
                  · exact represented.1
                · contradiction
              · unfold noConflictAppendEntriesRequest? at handled
                split at handled
                · rename_i extension
                  have pairEq := Option.some.inj handled
                  have nextEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at nextEq responseEq
                  subst nextNode
                  subst response
                  simp [
                    successResponse,
                    List.length_take,
                    extension.2.1
                  ]
                · contradiction
            · contradiction
    · contradiction

/-- A successful request already represented in the destination log leaves
that log unchanged. -/
theorem successfulAlreadyDoneAppendLogUnchanged
    {before nextNode : NodeState TxId}
    {request : AppendEntriesRequest TxId}
    {response : AppendEntriesResponse}
    (already : alreadyDone before request)
    (handled :
      handleAppendEntriesRequest? before request =
        some (nextNode, response))
    (success : response.success = true) :
    nextNode.log = before.log := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have responseEq := congrArg Prod.snd pairEq
      dsimp at responseEq
      subst response
      have failed := (CCFRaft.failureResponseMetadata before request).2.2
      rw [failed] at success
      contradiction
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · split at handled
      · rename_i alreadyState alreadyResponse alreadyResult
        unfold appendEntriesAlreadyDone? at alreadyResult
        simp [already] at alreadyResult
        have pairEq :=
          alreadyResult.trans (Option.some.inj handled)
        have nextEq := congrArg Prod.fst pairEq
        simpa using (congrArg NodeState.log nextEq).symm
      · rename_i noAlready
        unfold appendEntriesAlreadyDone? at noAlready
        simp [already] at noAlready
    · contradiction

/-- A successful selected request materialises the corresponding source-log
prefix in the destination log. -/
theorem handledAppendRequestAcknowledgesSourcePrefix
    (state : State TxId)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (requestMember :
      Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response))
    (success : response.success = true)
    (sourceRole :
      (state.nodes request.source).role = .leader)
    (requestTerm :
      request.term =
        (state.nodes request.source).currentTerm)
    {index : Nat}
    (acknowledged : index <= response.lastLogIndex) :
    (state.nodes request.source).log.take index <+: nextNode.log := by
  let post := CCFRaft.handleAppendEntriesRequestLocalPost handled
  have withinEnd :
      index <= request.prevLogIndex + request.entries.length := by
    exact Nat.le_trans acknowledged (post.successfulIndexBound success)
  have historyBound : index <= (appendHistory request).length :=
    Nat.le_trans withinEnd snapshot.1
  have sourceHistory :=
    ownership.queuedActiveSourceHistory
      destination request requestMember requestTerm sourceRole
  have sourceTake :
      (state.nodes request.source).log.take index =
        (appendHistory request).take index :=
    (CCFRaft.takeEqOfPrefix sourceHistory historyBound).symm
  have nextBound : index <= nextNode.log.length :=
    Nat.le_trans acknowledged
      (successfulAppendResponseIndexWithinLog handled success)
  have previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length := by
    rcases post.successfulLogOk success with zero | present
    · omega
    · exact present.1
  have historyPreviousBound :
      request.prevLogIndex <= (appendHistory request).length := by
    exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
  have previousAgreement :
      (state.nodes destination).log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · have previousPositive : 0 < request.prevLogIndex := by omega
      rcases
          entryAtSomeOfPositiveBound previousPositive previousBound with
        ⟨nodeEntry, nodeFound⟩
      rcases
          entryAtSomeOfPositiveBound
            previousPositive historyPreviousBound with
        ⟨historyEntry, historyFound⟩
      have nodeTerm :
          nodeEntry.term = request.prevLogTerm := by
        rcases post.successfulLogOk success with impossible | present
        · exact False.elim (zero impossible)
        · simpa [termAt, nodeFound] using present.2
      have historyTerm :
          historyEntry.term = request.prevLogTerm := by
        simpa [termAt, historyFound] using snapshot.2.1.symm
      rcases
          ownership.logEntryAgreement
            destination request.prevLogIndex nodeEntry nodeFound with
        ⟨_, nodeAgreed⟩
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember
              request.prevLogIndex historyEntry historyFound with
        ⟨_, historyAgreed⟩
      calc
        (state.nodes destination).log.take request.prevLogIndex =
            (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
          nodeAgreed
        _ =
            (canonicalHistory historyEntry.term).take
              request.prevLogIndex := by
          rw [nodeTerm, historyTerm]
        _ = (appendHistory request).take request.prevLogIndex :=
          historyAgreed.symm
  have nextPreviousAgreement :
      nextNode.log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    have nextOldPrevious :
        nextNode.log.take request.prevLogIndex =
          (state.nodes destination).log.take request.prevLogIndex := by
      rcases post.logShape with same | truncated | extended
      · rw [same]
      · rw [truncated]
        simp
      · rw [extended]
        simp [List.length_take, previousBound]
    exact nextOldPrevious.trans previousAgreement
  have takeAgreement :
      nextNode.log.take index =
        (appendHistory request).take index := by
    by_cases withinPrevious : index <= request.prevLogIndex
    · calc
        nextNode.log.take index =
            (nextNode.log.take request.prevLogIndex).take index := by
          simp [List.take_take, Nat.min_eq_left withinPrevious]
        _ =
            ((appendHistory request).take request.prevLogIndex).take
              index := by rw [nextPreviousAgreement]
        _ = (appendHistory request).take index := by
          simp [List.take_take, Nat.min_eq_left withinPrevious]
    · have afterPrevious : request.prevLogIndex < index := by omega
      have indexPositive : 0 < index := by omega
      rcases post.logShape with same | truncated | extended
      · have nodeFound :
            Exists fun entry =>
              entryAt? (state.nodes destination).log index = some entry := by
          rw [same] at nextBound
          exact entryAtSomeOfPositiveBound indexPositive nextBound
        rcases nodeFound with ⟨nodeEntry, nodeFound⟩
        rcases
            entryAtSomeOfPositiveBound indexPositive historyBound with
          ⟨historyEntry, historyFound⟩
        have requestFound :
            entryAt? request.entries
                (index - request.prevLogIndex) =
              some historyEntry := by
          have inTaken :
              entryAt?
                  ((appendHistory request).take
                    (request.prevLogIndex + request.entries.length))
                  index =
                some historyEntry := by
            rw [entryAtTake_of_le withinEnd]
            exact historyFound
          rw [snapshot.2.2] at inTaken
          have previousLength :
              ((appendHistory request).take request.prevLogIndex).length =
                request.prevLogIndex := by
            simp [List.length_take, historyPreviousBound]
          rw [
            entryAtAppend_right
              (base := (appendHistory request).take request.prevLogIndex)
              (suffix := request.entries)
              (by simpa [previousLength] using afterPrevious),
            previousLength
          ] at inTaken
          exact inTaken
        have localSliceFound :
            entryAt?
                (((state.nodes destination).log.drop
                    request.prevLogIndex).take request.entries.length)
                (index - request.prevLogIndex) =
              some nodeEntry := by
          rw [entryAtDropTake afterPrevious withinEnd]
          exact nodeFound
        have sameTerm :
            nodeEntry.term = historyEntry.term :=
          entryTermsEqualOfMappedTerms
            (post.successfulUnchangedEntryTerms success same)
            localSliceFound requestFound
        rcases
            ownership.logEntryAgreement
              destination index nodeEntry nodeFound with
          ⟨_, nodeAgreed⟩
        rcases
            ownership.queuedHistoryEntryAgreement
              destination request requestMember
                index historyEntry historyFound with
          ⟨_, historyAgreed⟩
        rw [same]
        calc
          (state.nodes destination).log.take index =
              (canonicalHistory nodeEntry.term).take index :=
            nodeAgreed
          _ =
              (canonicalHistory historyEntry.term).take index := by
            rw [sameTerm]
          _ = (appendHistory request).take index :=
            historyAgreed.symm
      · have truncatedLength :
            nextNode.log.length <= request.prevLogIndex := by
          rw [truncated]
          exact List.length_take_le _ _
        omega
      · rw [extended]
        calc
          ((state.nodes destination).log.take request.prevLogIndex ++
              request.entries).take index =
              ((appendHistory request).take request.prevLogIndex ++
                request.entries).take index := by
            rw [previousAgreement]
          _ =
              ((appendHistory request).take
                (request.prevLogIndex + request.entries.length)).take
                  index := by rw [snapshot.2.2]
          _ = (appendHistory request).take index := by
            simp [List.take_take, Nat.min_eq_left withinEnd]
  rw [List.prefix_iff_eq_take]
  have sourceBound :
      index <= (state.nodes request.source).log.length :=
    Nat.le_trans historyBound sourceHistory.length_le
  simp only [List.length_take, Nat.min_eq_left sourceBound]
  exact sourceTake.trans takeAgreement.symm

/-- A handled request leaves every destination entry on its owned canonical
history, including entries copied from an immutable queued snapshot. -/
theorem handledAppendRequestCanonicalAgreement
    (state : State TxId)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (requestMember :
      Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    forall index entry,
      entryAt? nextNode.log index = some entry ->
        entryAt? (canonicalHistory entry.term) index = some entry /\
          nextNode.log.take index =
            (canonicalHistory entry.term).take index := by
  let post :=
    CCFRaft.handleAppendEntriesRequestLocalPost handled
  intro index entry found
  by_cases succeeded : response.success = true
  · have previousBound :
        request.prevLogIndex <= (state.nodes destination).log.length := by
      rcases post.successfulLogOk succeeded with zero | present
      · omega
      · exact present.1
    have historyPreviousBound :
        request.prevLogIndex <= (appendHistory request).length := by
      exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
    have previousAgreement :
        (state.nodes destination).log.take request.prevLogIndex =
          (appendHistory request).take request.prevLogIndex := by
      by_cases zero : request.prevLogIndex = 0
      · simp [zero]
      · have previousPositive : 0 < request.prevLogIndex := by omega
        rcases
            entryAtSomeOfPositiveBound previousPositive previousBound with
          ⟨nodeEntry, nodeFound⟩
        rcases
            entryAtSomeOfPositiveBound
              previousPositive historyPreviousBound with
          ⟨historyEntry, historyFound⟩
        have nodeTerm :
            nodeEntry.term = request.prevLogTerm := by
          rcases post.successfulLogOk succeeded with impossible | present
          · exact False.elim (zero impossible)
          · simpa [termAt, nodeFound] using present.2
        have historyTerm :
            historyEntry.term = request.prevLogTerm := by
          simpa [termAt, historyFound] using snapshot.2.1.symm
        rcases
            ownership.logEntryAgreement
              destination request.prevLogIndex nodeEntry nodeFound with
          ⟨_, nodeAgreed⟩
        rcases
            ownership.queuedHistoryEntryAgreement
              destination request requestMember
                request.prevLogIndex historyEntry historyFound with
          ⟨_, historyAgreed⟩
        calc
          (state.nodes destination).log.take request.prevLogIndex =
              (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
            nodeAgreed
          _ =
              (canonicalHistory historyEntry.term).take
                request.prevLogIndex := by
            rw [nodeTerm, historyTerm]
          _ = (appendHistory request).take request.prevLogIndex :=
            historyAgreed.symm
    rcases post.logShape with same | truncated | extended
    · rw [same] at found ⊢
      exact
        ownership.logEntryAgreement destination index entry found
    · have indexBound : index <= request.prevLogIndex := by
        have within := entryAtSomeIndexBound found
        rw [truncated] at within
        simp at within
        exact within.1
      have oldFound :
          entryAt? (state.nodes destination).log index = some entry := by
        rw [← entryAtTake_of_le indexBound]
        simpa [truncated] using found
      rcases
          ownership.logEntryAgreement
            destination index entry oldFound with
        ⟨canonicalFound, agreed⟩
      exact
        ⟨canonicalFound,
          by
            rw [truncated]
            simpa [
              List.take_take, Nat.min_eq_left indexBound
            ] using agreed⟩
    · have fullAgreement :
          nextNode.log =
            (appendHistory request).take
              (request.prevLogIndex + request.entries.length) := by
        calc
          nextNode.log =
              (state.nodes destination).log.take request.prevLogIndex ++
                request.entries :=
            extended
          _ =
              (appendHistory request).take request.prevLogIndex ++
                request.entries := by rw [previousAgreement]
          _ =
              (appendHistory request).take
                (request.prevLogIndex + request.entries.length) :=
            snapshot.2.2.symm
      have indexBound :
          index <= request.prevLogIndex + request.entries.length := by
        have within := entryAtSomeIndexBound found
        rw [fullAgreement] at within
        simpa [List.length_take, snapshot.1] using within
      have historyFound :
          entryAt? (appendHistory request) index = some entry := by
        rw [fullAgreement, entryAtTake_of_le indexBound] at found
        exact found
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember index entry historyFound with
        ⟨canonicalFound, agreed⟩
      exact
        ⟨canonicalFound,
          by
            rw [fullAgreement]
            simpa [
              List.take_take, Nat.min_eq_left indexBound
            ] using agreed⟩
  · have failed : response.success = false := by
      cases value : response.success
      · rfl
      · exact False.elim (succeeded value)
    have unchanged := post.failedStateUnchanged failed
    subst nextNode
    exact ownership.logEntryAgreement destination index entry found

/-- Canonical term histories directly imply state-local log matching. -/
theorem canonicalHistoriesLogMatching
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners) :
    LogMatching state := by
  intro left right index leftEntry rightEntry leftFound rightFound sameTerm
  rcases
      ownership.logEntryAgreement left index leftEntry leftFound with
    ⟨_, leftAgreed⟩
  rcases
      ownership.logEntryAgreement right index rightEntry rightFound with
    ⟨_, rightAgreed⟩
  calc
    (state.nodes left).log.take index =
        (canonicalHistory leftEntry.term).take index :=
      leftAgreed
    _ = (canonicalHistory rightEntry.term).take index := by rw [sameTerm]
    _ = (state.nodes right).log.take index :=
      rightAgreed.symm

/-- Canonical history monotonicity transfers to every represented node log. -/
theorem canonicalHistoriesMonoLog
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners) :
    MonoLog state := by
  intro node earlier later earlierEntry laterEntry order
      earlierFound laterFound
  rcases
      ownership.logEntryAgreement node later laterEntry laterFound with
    ⟨canonicalLater, agreed⟩
  have earlierInNodeTake :
      entryAt? ((state.nodes node).log.take later) earlier =
        some earlierEntry := by
    rw [entryAtTake_of_le order.le]
    exact earlierFound
  have earlierInCanonicalTake :
      entryAt? ((canonicalHistory laterEntry.term).take later) earlier =
        some earlierEntry := by
    rw [← agreed]
    exact earlierInNodeTake
  have earlierInCanonical :
      entryAt? (canonicalHistory laterEntry.term) earlier =
        some earlierEntry := by
    rw [← entryAtTake_of_le order.le]
    exact earlierInCanonicalTake
  exact
    ownership.canonicalMonoLog laterEntry.term
      earlier later earlierEntry laterEntry order
        earlierInCanonical canonicalLater

/--
Canonical agreement locates a local log entry in its canonical history, whose
entry-owner fact then supplies the term owner.
-/
theorem termOwnershipLogEntryOwner
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    {node : Node}
    {entry : Entry TxId}
    (member : entry ∈ (state.nodes node).log) :
    Exists fun owner => owners entry.term = some owner := by
  rcases memberEntryAt member with ⟨index, found⟩
  rcases ownership.logEntryAgreement node index entry found with
    ⟨canonicalFound, _⟩
  exact
    ownership.canonicalEntryOwner
      entry.term index entry canonicalFound

/--
An owned term is either the bootstrap term or has the strict majority recorded
by its immutable election record.
-/
theorem electionHistoryOwnerProvenance
    {state : State TxId}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {term : Nat}
    {owner : Node}
    (owned : owners term = some owner) :
    ((term = TERM_ONE /\ owner = INITIAL_LEADER) \/
      hasHistoricalElectionMajority votes term owner) := by
  rcases electionFacts.ownerRecorded term owner owned with
    bootstrap | recorded
  · exact Or.inl bootstrap
  · right
    rcases recorded with ⟨record, recordStored, recordLeader⟩
    have subset :
        record.quorum ⊆ historicalElectionVoters votes term owner := by
      intro voter member
      simp only [
        historicalElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      rw [← recordLeader]
      exact electionFacts.voted term record voter recordStored member
    have cardBound := Finset.card_le_card subset
    have majority :=
      electionFacts.majority term record recordStored
    unfold hasHistoricalElectionMajority
    omega

/--
Canonical agreement for a frozen voter log transfers canonical monotonicity
to that exact election-record snapshot.
-/
theorem electionHistoryVoterMono
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {term : Nat}
    {record : ElectionRecord TxId}
    {voter : Node}
    (recorded : elections term = some record)
    (member : voter ∈ record.quorum) :
    MonoHistory (record.voterLog voter) := by
  intro earlier later earlierEntry laterEntry order
      earlierFound laterFound
  rcases
      electionFacts.voterCanonical
        term record voter recorded member later laterEntry laterFound with
    ⟨canonicalLater, agreed⟩
  have earlierInVoterTake :
      entryAt? ((record.voterLog voter).take later) earlier =
        some earlierEntry := by
    rw [entryAtTake_of_le order.le]
    exact earlierFound
  have earlierInCanonicalTake :
      entryAt? ((canonicalHistory laterEntry.term).take later) earlier =
        some earlierEntry := by
    rw [← agreed]
    exact earlierInVoterTake
  have earlierInCanonical :
      entryAt? (canonicalHistory laterEntry.term) earlier =
        some earlierEntry := by
    rw [← entryAtTake_of_le order.le]
    exact earlierInCanonicalTake
  exact
    ownership.canonicalMonoLog laterEntry.term
      earlier later earlierEntry laterEntry order
        earlierInCanonical canonicalLater

/--
A recorded voter cannot remain below the recorded term: its retained vote
would otherwise contradict the vote history's empty-future property.
-/
theorem electionHistoryVoterTerm
    {state : State TxId}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {term : Nat}
    {record : ElectionRecord TxId}
    {voter : Node}
    (recorded : elections term = some record)
    (member : voter ∈ record.quorum) :
    term <= (state.nodes voter).currentTerm := by
  by_contra notBounded
  have future :=
    voteFacts.future voter term (Nat.lt_of_not_ge notBounded)
  rw [electionFacts.voted term record voter recorded member] at future
  contradiction

/--
A candidate's persistent self-vote cannot belong to the empty bootstrap vote
history, so every candidate term is strictly above the bootstrap term.
-/
theorem candidatesSelfVoteAboveBootstrap
    {state : State TxId}
    {votes : VoteHistory}
    (termsPositive : CurrentTermsPositive state)
    (selfVotes : CandidatesSelfVote state)
    (voteFacts : VoteHistoryFacts state votes) :
    CandidatesAboveBootstrap state := by
  intro candidate role
  have positive := termsPositive candidate
  have selfVote := (selfVotes candidate role).1
  have currentVote := voteFacts.current candidate
  rw [selfVote] at currentVote
  have termNe :
      Not ((state.nodes candidate).currentTerm = TERM_ONE) := by
    intro termEq
    rw [termEq, voteFacts.bootstrapEmpty candidate] at currentVote
    contradiction
  omega

/-- Canonical agreement restricts to every prefix. -/
theorem historyCanonicalOfPrefix
    {canonicalHistory : Nat -> List (Entry TxId)}
    {shorter history : List (Entry TxId)}
    (canonical : HistoryCanonical canonicalHistory history)
    (isPrefix : shorter <+: history) :
    HistoryCanonical canonicalHistory shorter := by
  intro index entry found
  have historyFound :=
    CCFRaft.entryAt_of_prefix isPrefix found
  rcases canonical index entry historyFound with
    ⟨canonicalFound, agreed⟩
  exact
    ⟨canonicalFound,
      (CCFRaft.takeEqOfPrefix isPrefix
        (entryAtSomeIndexBound found)).trans agreed⟩

/-- Log-term monotonicity restricts to every prefix. -/
theorem monoHistoryOfPrefix
    {shorter history : List (Entry TxId)}
    (mono : MonoHistory history)
    (isPrefix : shorter <+: history) :
    MonoHistory shorter := by
  intro earlier later earlierEntry laterEntry order
      earlierFound laterFound
  exact
    mono earlier later earlierEntry laterEntry order
      (CCFRaft.entryAt_of_prefix isPrefix earlierFound)
      (CCFRaft.entryAt_of_prefix isPrefix laterFound)

/-- Extending a monotone history cannot decrease its final term. -/
theorem termAtLastMonotoneOfPrefix
    {shorter history : List (Entry TxId)}
    (isPrefix : shorter <+: history)
    (mono : MonoHistory history) :
    termAt shorter shorter.length <= termAt history history.length := by
  by_cases shorterEmpty : shorter = []
  · simp [shorterEmpty, termAt, entryAt?]
  have shorterPositive : 0 < shorter.length :=
    List.length_pos_iff_ne_nil.mpr shorterEmpty
  rcases
      entryAtSomeOfPositiveBound shorterPositive le_rfl with
    ⟨shorterLast, shorterFound⟩
  have historyPositive : 0 < history.length :=
    lt_of_lt_of_le shorterPositive isPrefix.length_le
  rcases
      entryAtSomeOfPositiveBound historyPositive le_rfl with
    ⟨historyLast, historyFound⟩
  have shorterFoundInHistory :
      entryAt? history shorter.length = some shorterLast :=
    CCFRaft.entryAt_of_prefix isPrefix shorterFound
  have termOrder : shorterLast.term <= historyLast.term := by
    by_cases sameLength : shorter.length = history.length
    · rw [sameLength] at shorterFoundInHistory
      exact
        (congrArg Entry.term
          (Option.some.inj
            (shorterFoundInHistory.symm.trans historyFound))).le
    · exact
        mono shorter.length history.length shorterLast historyLast
          (lt_of_le_of_ne isPrefix.length_le sameLength)
          shorterFoundInHistory historyFound
  simpa [termAt, shorterFound, historyFound] using termOrder

/-- Extending a monotone history cannot decrease its latest signature term. -/
theorem maxCommittableTermMonotoneOfPrefix
    {shorter history : List (Entry TxId)}
    (isPrefix : shorter <+: history)
    (mono : MonoHistory history) :
    maxCommittableTerm shorter <= maxCommittableTerm history := by
  let shorterIndex := maxCommittableIndex shorter
  let historyIndex := maxCommittableIndex history
  have indexOrder : shorterIndex <= historyIndex := by
    exact maxCommittableIndex_le_of_prefix isPrefix
  change termAt shorter shorterIndex <= termAt history historyIndex
  by_cases shorterZero : shorterIndex = 0
  · simp [maxCommittableTerm, shorterIndex, shorterZero, termAt, entryAt?]
  have shorterPositive : 0 < shorterIndex := Nat.pos_of_ne_zero shorterZero
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature
          (log := shorter) shorterPositive) with
    ⟨shorterEntry, shorterFound, _⟩
  have shorterFound' :
      entryAt? shorter shorterIndex = some shorterEntry := by
    simpa [shorterIndex] using shorterFound
  have shorterFoundInHistory :
      entryAt? history shorterIndex = some shorterEntry :=
    CCFRaft.entryAt_of_prefix isPrefix shorterFound
  by_cases sameIndex : shorterIndex = historyIndex
  · rw [← sameIndex]
    simp [termAt, shorterFound', shorterFoundInHistory]
  have historyPositive : 0 < historyIndex := lt_of_lt_of_le shorterPositive indexOrder
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature
          (log := history) historyPositive) with
    ⟨historyEntry, historyFound, _⟩
  have historyFound' :
      entryAt? history historyIndex = some historyEntry := by
    simpa [historyIndex] using historyFound
  have termOrder :=
    mono shorterIndex historyIndex shorterEntry historyEntry
      (lt_of_le_of_ne indexOrder sameIndex)
      shorterFoundInHistory historyFound'
  simpa [termAt, shorterFound', historyFound'] using termOrder

/-- A signature-only commit frontier is no later than the latest signature. -/
theorem lastCommittableIndex_eq_maxCommittableIndex
    (state : NodeState TxId)
    (committedSignature :
      0 < state.commitIndex ->
        isSignatureAt state.log state.commitIndex = true) :
    lastCommittableIndex state = maxCommittableIndex state.log := by
  unfold lastCommittableIndex
  apply max_eq_right
  by_cases zero : state.commitIndex = 0
  · omega
  exact
    signatureIndex_le_maxCommittableIndex
      (committedSignature (Nat.pos_of_ne_zero zero))

/-- A signature-only commit does not alter the latest-signature election term. -/
theorem lastCommittableTerm_eq_maxCommittableTerm
    (state : NodeState TxId)
    (committedSignature :
      0 < state.commitIndex ->
        isSignatureAt state.log state.commitIndex = true) :
    lastCommittableTerm state = maxCommittableTerm state.log := by
  simp [
    lastCommittableTerm, maxCommittableTerm,
    lastCommittableIndex_eq_maxCommittableIndex
      state committedSignature
  ]

/-- Election frontier fields depend only on the log and commit index. -/
theorem lastCommittableIndexFrame
    {before after : NodeState TxId}
    (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex) :
    lastCommittableIndex after = lastCommittableIndex before := by
  simp [lastCommittableIndex, logEq, commitEq]

/-- Election frontier terms frame with the log and commit index. -/
theorem lastCommittableTermFrame
    {before after : NodeState TxId}
    (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex) :
    lastCommittableTerm after = lastCommittableTerm before := by
  simp [
    lastCommittableTerm, logEq,
    lastCommittableIndexFrame logEq commitEq
  ]

/-- A signature-only committed frontier lies within the latest signature. -/
theorem commitIndex_le_maxCommittableIndex
    (state : NodeState TxId)
    (committedSignature :
      0 < state.commitIndex ->
        isSignatureAt state.log state.commitIndex = true) :
    state.commitIndex <= maxCommittableIndex state.log := by
  by_cases zero : state.commitIndex = 0
  · omega
  exact
    signatureIndex_le_maxCommittableIndex
      (committedSignature (Nat.pos_of_ne_zero zero))

/-- A voter accepting one committable prefix also accepts any monotone extension. -/
theorem voteLogUpToDateOfCandidatePrefix
    (voter : NodeState TxId)
    (source destination : Node)
    {candidatePrefix candidateHistory : List (Entry TxId)}
    (isPrefix : candidatePrefix <+: candidateHistory)
    (mono : MonoHistory candidateHistory)
    (upToDate :
      voteLogUpToDate voter
        { term := voter.currentTerm
          lastCommittableTerm := maxCommittableTerm candidatePrefix
          lastCommittableIndex := maxCommittableIndex candidatePrefix
          source
          destination }) :
    voteLogUpToDate voter
      { term := voter.currentTerm
        lastCommittableTerm := maxCommittableTerm candidateHistory
        lastCommittableIndex := maxCommittableIndex candidateHistory
        source
        destination } := by
  have termMonotone :=
    maxCommittableTermMonotoneOfPrefix isPrefix mono
  have indexMonotone :=
    maxCommittableIndex_le_of_prefix isPrefix
  unfold voteLogUpToDate at upToDate ⊢
  simp only at upToDate ⊢
  rcases upToDate with newer | same
  · left
    omega
  · by_cases termStrict :
        maxCommittableTerm candidatePrefix <
          maxCommittableTerm candidateHistory
    · left
      omega
    · right
      omega

/-- A candidate accepted against a longer voter log also passes its prefix. -/
theorem voteLogUpToDateOfVoterPrefix
    {beforeLog afterLog : List (Entry TxId)}
    (isPrefix : beforeLog <+: afterLog)
    (mono : MonoHistory afterLog)
    (before after : NodeState TxId)
    (request : RequestVoteRequest)
    (beforeLogEq : before.log = beforeLog)
    (afterLogEq : after.log = afterLog)
    (upToDate : voteLogUpToDate after request) :
    voteLogUpToDate before request := by
  have termMonotone :=
    maxCommittableTermMonotoneOfPrefix isPrefix mono
  have indexMonotone :=
    maxCommittableIndex_le_of_prefix isPrefix
  unfold voteLogUpToDate at upToDate ⊢
  rw [beforeLogEq]
  rw [afterLogEq] at upToDate
  rcases upToDate with newer | same
  · left
    omega
  · by_cases termStrict :
        maxCommittableTerm beforeLog <
          maxCommittableTerm afterLog
    · left
      omega
    · right
      omega

/-- Replying to one AppendEntries request cannot introduce another request. -/
theorem appendRequestMemberBeforeReply
    (state : State TxId)
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining)) :
    forall queuedDestination queuedRequest,
      Message.appendEntriesRequest queuedRequest ∈
          reply state.network destination remaining response queuedDestination ->
        Message.appendEntriesRequest queuedRequest ∈
          state.network queuedDestination := by
  intro queuedDestination queuedRequest member
  rcases
      memEnqueueNoDup
        (updateQueue state.network destination remaining)
        (.appendEntriesResponse response)
        (.appendEntriesRequest queuedRequest)
        queuedDestination
        (by simpa [reply] using member) with
    old | new
  · by_cases destinationEq : queuedDestination = destination
    · subst queuedDestination
      have remainingMember :
          Message.appendEntriesRequest queuedRequest ∈ remaining := by
        simpa [updateQueue] using old
      exact
        (takeFirstFromSound taken).2.2
          (.appendEntriesRequest queuedRequest) remainingMember
    · simpa [
        updateQueue, Function.update, destinationEq
      ] using old
  · simp at new

/--
The evidence component of AppendEntries receive is fully preserved:
unchanged commits retain their node evidence, while advances inherit a
request evidence restricted to the request-end-bounded learned prefix.
-/
theorem receiveAppendRequestCommitEvidenceFacts
    (state : State TxId)
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (commitBounded : CommitIndicesBounded state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining))
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    CommitEvidenceFacts
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := reply state.network destination remaining response }
      appendHistory
        (appendRequestNodeEvidence
          state destination request nextNode
            nodeEvidence requestEvidence)
        requestEvidence := by
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (takeFirstFromSound taken).2.1
  apply
    appendRequestCommitEvidenceFacts
      state destination request nextNode response
        (reply state.network destination remaining response)
        appendHistory nodeEvidence requestEvidence evidenceFacts
        (commitBounded destination) handled requestMember
  · intro advanced
    exact
      handledAppendRequestAdvancedCommittedHistory
        state votes appendHistory canonicalHistory owners ownership
          destination request nextNode response requestMember snapshot
          (commitBounded destination) handled advanced
  · exact
      appendRequestMemberBeforeReply
        state source destination request response remaining taken

/-- Live evidence after AppendEntries receive is either unchanged or a
restriction of the selected request's pre-state evidence. -/
theorem receiveAppendRequestKnownEvidenceInherited
    (state : State TxId)
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (commitBounded : CommitIndicesBounded state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining))
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response))
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        { state with
          nodes := updateNode state.nodes destination nextNode
          network := reply state.network destination remaining response }
        appendHistory
        (appendRequestNodeEvidence
          state destination request nextNode
            nodeEvidence requestEvidence)
        requestEvidence evidence supportedPrefix) :
    Exists fun oldEvidence =>
      Exists fun oldPrefix =>
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            oldEvidence oldPrefix /\
          evidence.commitTerm = oldEvidence.commitTerm /\
          evidence.history = oldEvidence.history /\
          evidence.commitFrontier = oldEvidence.commitFrontier /\
          evidence.ackQuorum = oldEvidence.ackQuorum := by
  let post := CCFRaft.handleAppendEntriesRequestLocalPost handled
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (takeFirstFromSound taken).2.1
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, stored, prefixEq⟩
    by_cases same : node = destination
    · subst node
      have nextPositive : 0 < nextNode.commitIndex := by
        simpa [updateNode] using positive
      by_cases unchanged :
          nextNode.commitIndex =
            (state.nodes destination).commitIndex
      · have oldPositive :
            0 < (state.nodes destination).commitIndex := by
          omega
        have oldStored :
            nodeEvidence destination = some evidence := by
          simpa [
            appendRequestNodeEvidence, unchanged
          ] using stored
        exact
          ⟨evidence, (state.nodes destination).committedLog,
            Or.inl ⟨destination, oldPositive, oldStored, rfl⟩,
            rfl, rfl, rfl, rfl⟩
      · have advanced :
            (state.nodes destination).commitIndex <
              nextNode.commitIndex := by
          have monotone := post.commitIndexMonotone
          omega
        have succeeded : response.success = true :=
          post.commitAdvancedSuccessful advanced
        have withinLeaderCommit :
            nextNode.commitIndex <= request.leaderCommit := by
          rcases le_max_iff.mp post.commitUpperBound with old | learned
          · omega
          · exact learned
        have leaderCommitPositive : 0 < request.leaderCommit := by
          omega
        cases oldStored : requestEvidence request with
        | none =>
            simp [
              appendRequestNodeEvidence, unchanged, oldStored
            ] at stored
        | some oldEvidence =>
            have restrictedEq :
                oldEvidence.restrict nextNode.commitIndex = evidence := by
              exact Option.some.inj (by
                simpa [
                  appendRequestNodeEvidence, unchanged, oldStored
                ] using stored)
            subst evidence
            exact
              ⟨oldEvidence,
                (appendHistory request).take request.leaderCommit,
                Or.inr
                  ⟨destination, request, requestMember,
                    leaderCommitPositive, oldStored, rfl⟩,
                by simp [CommitEvidence.restrict],
                by simp [CommitEvidence.restrict],
                by simp [CommitEvidence.restrict],
                by simp [CommitEvidence.restrict]⟩
    · have oldPositive :
          0 < (state.nodes node).commitIndex := by
        simpa [updateNode, Function.update, same] using positive
      have oldStored :
          nodeEvidence node = some evidence := by
        simpa [
          appendRequestNodeEvidence, Function.update, same
        ] using stored
      exact
        ⟨evidence, (state.nodes node).committedLog,
          Or.inl ⟨node, oldPositive, oldStored, rfl⟩,
          rfl, rfl, rfl, rfl⟩
  · rcases requestKnown with
      ⟨queuedDestination, queuedRequest, member,
        positive, stored, prefixEq⟩
    exact
      ⟨evidence,
        (appendHistory queuedRequest).take queuedRequest.leaderCommit,
        Or.inr
          ⟨queuedDestination, queuedRequest,
            appendRequestMemberBeforeReply
              state source destination request response remaining taken
              queuedDestination queuedRequest member,
            positive, stored, rfl⟩,
        rfl, rfl, rfl, rfl⟩

/--
Every inherited evidence frontier survives handling the selected request at an
ACK-quorum member.  A same-term stale request is either compatible through its
queued history or was already fully represented before handling.
-/
theorem handledAppendRequestRetainsEvidenceFrontier
    (state : State TxId)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    {elections : ElectionHistory TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (electionQueuedFacts :
      ElectionQueuedHistoryFacts state appendHistory elections)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (nodeEvidence : NodeCommitEvidence TxId)
    (requestEvidence : RequestCommitEvidence TxId)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    (ackMember : destination ∈ evidence.ackQuorum)
    (requestMember :
      Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    evidence.history.take evidence.commitFrontier <+: nextNode.log := by
  let post := CCFRaft.handleAppendEntriesRequestLocalPost handled
  have currentPrefix :=
    prospectiveFacts.currentMember
      evidence supportedPrefix known destination ackMember
  by_cases succeeded : response.success = true
  · have requestCurrent :
        request.term = (state.nodes destination).currentTerm :=
      post.successfulCurrentTerm succeeded
    by_cases older : evidence.commitTerm < request.term
    · exact
        handledAppendRequestRetainsSharedPrefix
          state votes appendHistory canonicalHistory owners ownership
            destination request nextNode response requestMember snapshot
            handled succeeded currentPrefix
            (knownCommitEvidenceQueuedAppendContainsFrontier
              ownership electionFacts electionQueuedFacts prospectiveFacts
                known requestMember older)
    · by_cases same : evidence.commitTerm = request.term
      · rcases
            prospectiveFacts.sameTermQueuedComparable
              evidence supportedPrefix known destination request
                requestMember same with
          requestBeforeEvidence | frontierBeforeRequest
        · have valid := knownCommitEvidenceValid evidenceFacts known
          by_cases frontierWithin :
              evidence.commitFrontier <=
                (appendHistory request).length
          · have frontierBeforeRequest :
                evidence.history.take evidence.commitFrontier <+:
                  appendHistory request := by
              rw [List.prefix_iff_eq_take]
              have frontierLength :
                  (evidence.history.take evidence.commitFrontier).length =
                    evidence.commitFrontier := by
                simp [valid.1]
              calc
                evidence.history.take evidence.commitFrontier =
                    (appendHistory request).take
                      evidence.commitFrontier :=
                  (CCFRaft.takeEqOfPrefix
                    requestBeforeEvidence frontierWithin).symm
                _ =
                    (appendHistory request).take
                      (evidence.history.take
                        evidence.commitFrontier).length := by
                  rw [frontierLength]
            exact
              handledAppendRequestRetainsSharedPrefix
                state votes appendHistory canonicalHistory owners ownership
                  destination request nextNode response requestMember snapshot
                  handled succeeded currentPrefix frontierBeforeRequest
          · have requestBeforeFrontier :
                appendHistory request <+:
                  evidence.history.take evidence.commitFrontier := by
              rw [List.prefix_take_iff]
              exact ⟨requestBeforeEvidence, by omega⟩
            have requestBeforeNode :=
              requestBeforeFrontier.trans currentPrefix
            have already :
                alreadyDone (state.nodes destination) request :=
              appendRequestAlreadyDoneOfSharedPrefix
                snapshot requestBeforeNode (prefixRefl _)
                  snapshot.1
            have unchanged :=
              successfulAlreadyDoneAppendLogUnchanged
                already handled succeeded
            simpa [unchanged] using currentPrefix
        · exact
            handledAppendRequestRetainsSharedPrefix
              state votes appendHistory canonicalHistory owners ownership
                destination request nextNode response requestMember snapshot
                handled succeeded currentPrefix frontierBeforeRequest
      · have greater : request.term < evidence.commitTerm := by omega
        have valid := knownCommitEvidenceValid evidenceFacts known
        have supportedPositive :=
          knownCommitEvidenceSupportedLengthPositive evidenceFacts known
        have frontierPositive : 0 < evidence.commitFrontier := by
          exact lt_of_lt_of_le supportedPositive valid.2.2.1
        have commitTermPositive :
            0 < evidence.commitTerm := by
          have positive :=
            prospectiveFacts.commitTermPositive
              evidence supportedPrefix known
          simpa [TERM_ONE] using positive
        rcases termAtPositiveEntry
            (show 0 < termAt evidence.history evidence.commitFrontier by
              rw [valid.2.1]
              exact commitTermPositive) with
          ⟨frontierEntry, frontierFound, frontierTerm⟩
        have prefixFound :
            entryAt?
                (evidence.history.take evidence.commitFrontier)
                evidence.commitFrontier =
              some frontierEntry := by
          rw [entryAtTake_of_le le_rfl]
          exact frontierFound
        have destinationFound :=
          CCFRaft.entryAt_of_prefix currentPrefix prefixFound
        have bounded :=
          entriesBounded destination frontierEntry
            (entryAtSomeMember destinationFound)
        have entryTerm :
            frontierEntry.term = evidence.commitTerm :=
          frontierTerm.trans valid.2.1
        rw [entryTerm, ← requestCurrent] at bounded
        omega
  · have failed : response.success = false :=
      Bool.eq_false_of_not_eq_true succeeded
    simpa [post.failedStateUnchanged failed] using currentPrefix

/-- A winning candidate cannot share a term with an active leader. -/
theorem winningCandidateTermDiffersFromLeader
    {state : State TxId}
    {history : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (termsPositive : CurrentTermsPositive state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (leaders : LeadersHaveElectionMajority state)
    (votes : VoteHistoryFacts state history)
    (snapshots :
      GrantedVoteSnapshots
        state history voteCandidateHistory voteVoterHistory)
    {candidate leader : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasEffectiveElectionMajority state candidate)
    (leaderRole : (state.nodes leader).role = .leader) :
    Not (
      (state.nodes candidate).currentTerm =
        (state.nodes leader).currentTerm) := by
  intro sameTerm
  rcases leaders leader leaderRole with bootstrap | leaderMajority
  · have candidateAbove := candidatesAbove candidate candidateRole
    rw [sameTerm, bootstrap.2] at candidateAbove
    omega
  · rcases majoritiesIntersect
      (effectiveElectionVoters state candidate)
        (state.nodes leader).votesGranted
        candidateMajority leaderMajority with
      ⟨voter, member⟩
    have candidateVote :=
      (snapshots candidate voter (Or.inl candidateRole)
        (Finset.mem_inter.mp member).1).1
    have leaderVote :=
      votes.counted leader voter (Or.inr leaderRole)
        (Finset.mem_inter.mp member).2
    rw [sameTerm] at candidateVote
    have sameCandidate :
        candidate = leader :=
      Option.some.inj (candidateVote.symm.trans leaderVote)
    subst leader
    exact Role.noConfusion (candidateRole.symm.trans leaderRole)

/-- An effective winning candidate's current term has not been claimed before. -/
theorem effectiveCandidateTermUnowned
    {state : State TxId}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {candidate : Node}
    (role : (state.nodes candidate).role = .candidate)
    (majority : hasEffectiveElectionMajority state candidate) :
    owners (state.nodes candidate).currentTerm = none := by
  cases ownerAtTerm :
      owners (state.nodes candidate).currentTerm with
  | none => rfl
  | some owner =>
      rcases
          electionHistoryOwnerProvenance
            electionFacts ownerAtTerm with
        bootstrap | elected
      · have above := candidatesAbove candidate role
        rw [bootstrap.1] at above
        omega
      · rcases
            majoritiesIntersect
              (effectiveElectionVoters state candidate)
              (historicalElectionVoters
                votes (state.nodes candidate).currentTerm owner)
              majority elected with
          ⟨voter, member⟩
        have candidateVote :=
          (snapshots candidate voter (Or.inl role)
            (Finset.mem_inter.mp member).1).1
        have ownerVote :
            votes voter (state.nodes candidate).currentTerm = some owner := by
          simpa [historicalElectionVoters] using
            (Finset.mem_inter.mp member).2
        have candidateOwner : candidate = owner :=
          Option.some.inj (candidateVote.symm.trans ownerVote)
        subst owner
        have progress :=
          ownership.ownerProgress
            (state.nodes candidate).currentTerm candidate ownerAtTerm
        exact False.elim
          (Role.noConfusion ((progress.2 rfl).symm.trans role))

/-- A prospective winning candidate's current term has not been claimed before. -/
theorem potentialCandidateTermUnowned
    {state : State TxId}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {candidate : Node}
    (role : (state.nodes candidate).role = .candidate)
    (majority : hasPotentialElectionMajority state candidate) :
    owners (state.nodes candidate).currentTerm = none := by
  cases ownerAtTerm :
      owners (state.nodes candidate).currentTerm with
  | none => rfl
  | some owner =>
      rcases
          electionHistoryOwnerProvenance
            electionFacts ownerAtTerm with
        bootstrap | elected
      · have above := candidatesAbove candidate role
        rw [bootstrap.1] at above
        omega
      · rcases
            majoritiesIntersect
              (potentialElectionVoters state candidate)
              (historicalElectionVoters
                votes (state.nodes candidate).currentTerm owner)
              majority elected with
          ⟨voter, member⟩
        have ownerVote :
            votes voter (state.nodes candidate).currentTerm = some owner := by
          simpa [historicalElectionVoters] using
            (Finset.mem_inter.mp member).2
        have candidateOwner : candidate = owner := by
          have prospective :=
            (Finset.mem_inter.mp member).1
          simp only [
            potentialElectionVoters, Finset.mem_filter,
            Finset.mem_univ, true_and
          ] at prospective
          rcases prospective with effective | eligible
          · have candidateVote :=
              (snapshots candidate voter (Or.inl role) effective).1
            exact
              Option.some.inj (candidateVote.symm.trans ownerVote)
          · have voterTerm :
                (state.nodes voter).currentTerm =
                  (state.nodes candidate).currentTerm := by
              simpa [
                currentlyEligibleElectionVoter,
                makeRequestVoteRequest
              ] using eligible.1.symm
            have currentVote :
                votes voter (state.nodes candidate).currentTerm =
                  (state.nodes voter).votedFor := by
              simpa [voterTerm] using voteFacts.current voter
            have votedForOwner :
                (state.nodes voter).votedFor = some owner :=
              currentVote.symm.trans ownerVote
            rcases eligible.2.2 with noVote | candidateVote
            · rw [noVote] at votedForOwner
              contradiction
            · exact
                Option.some.inj
                  (candidateVote.symm.trans votedForOwner)
        subst owner
        have progress :=
          ownership.ownerProgress
            (state.nodes candidate).currentTerm candidate ownerAtTerm
        exact False.elim
          (Role.noConfusion ((progress.2 rfl).symm.trans role))

/-- Term ownership derives the previous candidate-term absence support fact. -/
theorem termOwnershipCandidateTermNotInLogs
    {state : State TxId}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections) :
    CandidateTermNotInLogs state := by
  intro candidate role majority node index entry found sameTerm
  have member : entry ∈ (state.nodes node).log :=
    entryAtSomeMember found
  rcases termOwnershipLogEntryOwner ownership member with
    ⟨owner, owned⟩
  have unowned :=
    effectiveCandidateTermUnowned
      candidatesAbove snapshots ownership electionFacts role majority
  rw [sameTerm] at owned
  rw [unowned] at owned
  contradiction

/-- Term ownership also excludes a prospective candidate term from all logs. -/
theorem termOwnershipPotentialCandidateTermNotInLogs
    {state : State TxId}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {candidate : Node}
    (role : (state.nodes candidate).role = .candidate)
    (majority : hasPotentialElectionMajority state candidate) :
    forall node index entry,
      entryAt? (state.nodes node).log index = some entry ->
        Not (entry.term = (state.nodes candidate).currentTerm) := by
  intro node index entry found sameTerm
  have member : entry ∈ (state.nodes node).log :=
    entryAtSomeMember found
  rcases termOwnershipLogEntryOwner ownership member with
    ⟨owner, owned⟩
  have unowned :=
    potentialCandidateTermUnowned
      voteFacts candidatesAbove snapshots ownership electionFacts
        role majority
  rw [sameTerm] at owned
  rw [unowned] at owned
  contradiction

/-- An active leader cannot have a majority beyond its current log. -/
theorem noMajorityBeyondLeaderLog
    {state : State TxId}
    (progress : LeaderProgressBounded state)
    {leader : Node}
    (role : (state.nodes leader).role = .leader)
    {index : Nat}
    (beyond : (state.nodes leader).log.length < index) :
    Not (hasMajorityAt state leader index) := by
  intro majority
  have acknowledgingOnlyLeader :
      acknowledgingNodes state leader index = {leader} := by
    ext peer
    simp only [
      acknowledgingNodes, Finset.mem_filter,
      Finset.mem_univ, true_and, Finset.mem_singleton
    ]
    constructor
    · intro acknowledges
      rcases acknowledges with peerLeader | matchCovers
      · exact peerLeader
      · have bounded := (progress leader role peer).2
        omega
    · exact fun peerLeader => Or.inl peerLeader
  unfold hasMajorityAt at majority
  rw [acknowledgingOnlyLeader] at majority
  simp [NODE_COUNT] at majority

/-- Every processed acknowledgement quorum is also an effective quorum. -/
theorem majorityImpliesEffectiveMajority
    (state : State TxId)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat)
    (majority : hasMajorityAt state leader index) :
    hasEffectiveMajorityAt state responseHistory leader index := by
  have subset :
      acknowledgingNodes state leader index ⊆
        effectiveAckers state responseHistory leader index := by
    intro node member
    simp only [
      acknowledgingNodes, effectiveAckers,
      Finset.mem_filter, Finset.mem_univ, true_and
    ] at member ⊢
    rcases member with self | matched
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
  have cardBound := Finset.card_le_card subset
  unfold hasMajorityAt at majority
  unfold hasEffectiveMajorityAt
  omega

/-- Every processed election quorum is also an effective election quorum. -/
theorem electionMajorityImpliesEffective
    (state : State TxId)
    (candidate : Node)
    (majority : hasElectionMajority state candidate) :
    hasEffectiveElectionMajority state candidate := by
  have subset :
      (state.nodes candidate).votesGranted ⊆
        effectiveElectionVoters state candidate := by
    intro voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    exact Or.inl member
  have cardBound := Finset.card_le_card subset
  unfold hasElectionMajority at majority
  unfold hasEffectiveElectionMajority
  omega

/-- Materialised election evidence is also prospective election evidence. -/
theorem effectiveElectionVotersSubsetPotential
    (state : State TxId)
    (candidate : Node) :
    effectiveElectionVoters state candidate ⊆
      potentialElectionVoters state candidate := by
  intro voter member
  simpa [potentialElectionVoters] using Or.inl member

/-- An effective election quorum is also a prospective election quorum. -/
theorem effectiveElectionMajorityImpliesPotential
    (state : State TxId)
    (candidate : Node)
    (majority : hasEffectiveElectionMajority state candidate) :
    hasPotentialElectionMajority state candidate := by
  have cardBound :=
    Finset.card_le_card
      (effectiveElectionVotersSubsetPotential state candidate)
  unfold hasEffectiveElectionMajority at majority
  unfold hasPotentialElectionMajority
  omega

/-- A prospective quorum remains a quorum in any finite superset. -/
theorem potentialElectionMajorityOfSubset
    {state after : State TxId}
    {candidate : Node}
    (subset :
      potentialElectionVoters after candidate ⊆
        potentialElectionVoters state candidate)
    (majority : hasPotentialElectionMajority after candidate) :
    hasPotentialElectionMajority state candidate := by
  have cardBound := Finset.card_le_card subset
  unfold hasPotentialElectionMajority at majority ⊢
  omega

/-- Every materialised acknowledgement is also a potential supporter. -/
theorem effectiveAckersSubsetPotential
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat) :
    effectiveAckers state responseHistory leader index ⊆
      potentialAckers
        state appendHistory responseHistory leader index := by
  intro voter member
  simpa [potentialAckers] using Or.inl member

/-- A materialised acknowledgement quorum is also a potential quorum. -/
theorem effectiveMajorityImpliesPotential
    (state : State TxId)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (leader : Node)
    (index : Nat)
    (majority :
      hasEffectiveMajorityAt state responseHistory leader index) :
    hasPotentialMajorityAt
      state appendHistory responseHistory leader index := by
  have cardBound :=
    Finset.card_le_card
      (effectiveAckersSubsetPotential
        state appendHistory responseHistory leader index)
  unfold hasEffectiveMajorityAt at majority
  unfold hasPotentialMajorityAt
  omega

/-- Effective election evidence places every voter at or above the term voted. -/
theorem effectiveElectionVoterTermBound
    {state : State TxId}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    {candidate voter : Node}
    (active :
      (state.nodes candidate).role = .candidate \/
        (state.nodes candidate).role = .leader)
    (member : voter ∈ effectiveElectionVoters state candidate) :
    (state.nodes candidate).currentTerm <=
      (state.nodes voter).currentTerm := by
  rcases snapshots candidate voter active member with
    ⟨_, self | recorded⟩
  · subst voter
    exact le_rfl
  · exact recorded.2.2.2.1

/-- Every prospective election voter is at the candidate's current term. -/
theorem potentialElectionVoterTermBound
    {state : State TxId}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    {candidate voter : Node}
    (active :
      (state.nodes candidate).role = .candidate \/
        (state.nodes candidate).role = .leader)
    (member : voter ∈ potentialElectionVoters state candidate) :
    (state.nodes candidate).currentTerm <=
      (state.nodes voter).currentTerm := by
  simp only [
    potentialElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at member
  rcases member with effective | eligible
  · exact effectiveElectionVoterTermBound snapshots active effective
  · simpa [
      currentlyEligibleElectionVoter,
      makeRequestVoteRequest
    ] using eligible.1.le

/-- A still-acceptable queued request keeps its destination in the old term. -/
theorem queuedAppendReservePeerTerm
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {leader peer : Node}
    {index : Nat}
    (reserve :
      queuedAppendReserve state appendHistory leader peer index) :
    (state.nodes peer).currentTerm =
      (state.nodes leader).currentTerm := by
  rcases reserve with
    ⟨request, _, _, requestDestination, requestTerm,
      direct | stepped, _⟩
  · rcases direct with
      ⟨nextNode, response, handled, success, _⟩
    have localPost :=
      CCFRaft.handleAppendEntriesRequestLocalPost handled
    have peerTerm :
        request.term = (state.nodes peer).currentTerm := by
      simpa [requestDestination] using
        localPost.successfulCurrentTerm success
    exact peerTerm.symm.trans requestTerm
  · rcases stepped with
      ⟨follower, nextNode, response, returned, _, _, _⟩
    unfold returnToFollowerState? at returned
    split at returned
    · rename_i canReturn
      exact canReturn.1.symm.trans requestTerm
    · contradiction

/--
The intersection of a prospective replication quorum and a strictly
higher-term election quorum contains a materialised ACK, not merely a queued
request reserve.
-/
theorem potentialElectionIntersectionEffective
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    {leader candidate : Node}
    {index : Nat}
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory leader index)
    (candidateActive :
      (state.nodes candidate).role = .candidate \/
        (state.nodes candidate).role = .leader)
    (elected : hasEffectiveElectionMajority state candidate)
    (newer :
      (state.nodes leader).currentTerm <
        (state.nodes candidate).currentTerm) :
    Exists fun voter =>
      voter ∈ effectiveAckers state responseHistory leader index /\
        voter ∈ effectiveElectionVoters state candidate := by
  rcases
      majoritiesIntersect
        (potentialAckers
          state appendHistory responseHistory leader index)
        (effectiveElectionVoters state candidate)
        potential elected with
    ⟨voter, member⟩
  have potentialMember :
      voter ∈
        potentialAckers
          state appendHistory responseHistory leader index :=
    (Finset.mem_inter.mp member).1
  have electionMember :
      voter ∈ effectiveElectionVoters state candidate :=
    (Finset.mem_inter.mp member).2
  simp only [
    potentialAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at potentialMember
  rcases potentialMember with effective | reserve
  · exact ⟨voter, effective, electionMember⟩
  · have reserveTerm :=
      queuedAppendReservePeerTerm reserve
    have voteTerm :=
      effectiveElectionVoterTermBound
        snapshots candidateActive electionMember
    rw [reserveTerm] at voteTerm
    omega

/--
A prospective replication quorum and a higher prospective election quorum
still intersect in a materialised acknowledgement.
-/
theorem potentialElectionMajorityIntersectionEffective
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    {leader candidate : Node}
    {index : Nat}
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory leader index)
    (candidateActive :
      (state.nodes candidate).role = .candidate \/
        (state.nodes candidate).role = .leader)
    (elected : hasPotentialElectionMajority state candidate)
    (newer :
      (state.nodes leader).currentTerm <
        (state.nodes candidate).currentTerm) :
    Exists fun voter =>
      voter ∈ effectiveAckers state responseHistory leader index /\
        voter ∈ potentialElectionVoters state candidate := by
  rcases
      majoritiesIntersect
        (potentialAckers
          state appendHistory responseHistory leader index)
        (potentialElectionVoters state candidate)
        potential elected with
    ⟨voter, member⟩
  have potentialMember :
      voter ∈
        potentialAckers
          state appendHistory responseHistory leader index :=
    (Finset.mem_inter.mp member).1
  have electionMember :
      voter ∈ potentialElectionVoters state candidate :=
    (Finset.mem_inter.mp member).2
  simp only [
    potentialAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at potentialMember
  rcases potentialMember with effective | reserve
  · exact ⟨voter, effective, electionMember⟩
  · have reserveTerm :=
      queuedAppendReservePeerTerm reserve
    have voteTerm :=
      potentialElectionVoterTermBound
        snapshots candidateActive electionMember
    rw [reserveTerm] at voteTerm
    omega

/-- A prospective support quorum intersects a frozen higher-term election in an ACK. -/
theorem potentialElectionRecordIntersectionEffective
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {leader : Node}
    {index term : Nat}
    {record : ElectionRecord TxId}
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory leader index)
    (recorded : elections term = some record)
    (newer : (state.nodes leader).currentTerm < term) :
    Exists fun voter =>
      voter ∈ effectiveAckers state responseHistory leader index /\
        voter ∈ record.quorum := by
  rcases
      majoritiesIntersect
        (potentialAckers
          state appendHistory responseHistory leader index)
        record.quorum
        potential
        (electionFacts.majority term record recorded) with
    ⟨voter, member⟩
  have potentialMember :
      voter ∈
        potentialAckers
          state appendHistory responseHistory leader index :=
    (Finset.mem_inter.mp member).1
  have electionMember : voter ∈ record.quorum :=
    (Finset.mem_inter.mp member).2
  simp only [
    potentialAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at potentialMember
  rcases potentialMember with effective | reserve
  · exact ⟨voter, effective, electionMember⟩
  · have reserveTerm :=
      queuedAppendReservePeerTerm reserve
    have voteTerm :=
      electionHistoryVoterTerm
        voteFacts electionFacts recorded electionMember
    rw [reserveTerm] at voteTerm
    omega

/--
For the least higher-term election whose promotion log omits a prospective
signature frontier, quorum intersection yields a voter whose frozen voter log
contains that frontier.
-/
theorem leastBadElectionHasPrefixVoter
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (ackerHistory :
      AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index term : Nat}
    {record : ElectionRecord TxId}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (recorded : elections term = some record)
    (newer : (state.nodes source).currentTerm < term)
    (earlierSafe :
      forall earlierTerm earlierRecord,
        (state.nodes source).currentTerm < earlierTerm ->
        earlierTerm < term ->
        elections earlierTerm = some earlierRecord ->
          (state.nodes source).log.take index <+:
            earlierRecord.promotionLog) :
    Exists fun voter =>
      voter ∈ record.quorum /\
        (state.nodes source).log.take index <+:
          record.voterLog voter := by
  rcases
      potentialElectionRecordIntersectionEffective
        voteFacts electionFacts potential recorded newer with
    ⟨voter, effective, electionMember⟩
  rcases
      ackerHistory source index sourceRole currentEntry currentSignature
        term record voter recorded electionMember effective newer with
    voterPrefix | earlier
  · exact ⟨voter, electionMember, voterPrefix⟩
  · rcases earlier with
      ⟨earlierTerm, earlierRecord, above, below, earlierRecorded, bad⟩
    exact False.elim
      (bad
        (earlierSafe
          earlierTerm earlierRecord above below earlierRecorded))

/--
The least higher-term election cannot omit a prospectively quorum-supported
current-term signature frontier.
-/
theorem leastBadElectionPromotionContainsPrefix
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (ackerHistory :
      AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index term : Nat}
    {record : ElectionRecord TxId}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (recorded : elections term = some record)
    (newer : (state.nodes source).currentTerm < term)
    (earlierSafe :
      forall earlierTerm earlierRecord,
        (state.nodes source).currentTerm < earlierTerm ->
        earlierTerm < term ->
        elections earlierTerm = some earlierRecord ->
          (state.nodes source).log.take index <+:
            earlierRecord.promotionLog) :
    (state.nodes source).log.take index <+: record.promotionLog := by
  rcases
      leastBadElectionHasPrefixVoter
        voteFacts electionFacts ackerHistory sourceRole currentEntry
          currentSignature
          potential recorded newer earlierSafe with
    ⟨voter, electionMember, voterPrefix⟩
  let supportedPrefix := (state.nodes source).log.take index
  have sourceTermPositive :
      0 < (state.nodes source).currentTerm := by
    simpa [TERM_ONE] using termsPositive source
  have lookupPositive :
      0 < termAt (state.nodes source).log index := by
    rw [currentEntry]
    exact sourceTermPositive
  rcases termAtPositiveEntry lookupPositive with
    ⟨sourceEntry, sourceFound, sourceEntryTerm⟩
  have sourceEntryCurrent :
      sourceEntry.term = (state.nodes source).currentTerm :=
    sourceEntryTerm.trans currentEntry
  have sourceBound :
      index <= (state.nodes source).log.length :=
    entryAtSomeIndexBound sourceFound
  have prefixLength : supportedPrefix.length = index := by
    simp [
      supportedPrefix, List.length_take,
      Nat.min_eq_left sourceBound
    ]
  have indexPositive : 0 < index := by
    have indexNe : Not (index = 0) := by
      intro zero
      rw [zero] at sourceFound
      simp [entryAt?] at sourceFound
    exact Nat.pos_of_ne_zero indexNe
  have voterLength : index <= (record.voterLog voter).length := by
    have covered := voterPrefix.length_le
    rw [prefixLength] at covered
    exact covered
  have voterTakeEq :
      (record.voterLog voter).take index = supportedPrefix := by
    have covered := CCFRaft.prefixEqTake voterPrefix
    rw [prefixLength] at covered
    exact covered
  have voterFound :
      entryAt? (record.voterLog voter) index = some sourceEntry := by
    rw [← entryAtTake_of_le (log := record.voterLog voter) le_rfl]
    rw [voterTakeEq]
    rw [entryAtTake_of_le le_rfl]
    exact sourceFound
  have voterNonempty : Not (record.voterLog voter = []) := by
    intro empty
    rw [empty] at voterLength
    simp at voterLength
    omega
  have voterLastPositive : 0 < (record.voterLog voter).length :=
    List.length_pos_iff_ne_nil.mpr voterNonempty
  rcases
      entryAtSomeOfPositiveBound voterLastPositive le_rfl with
    ⟨voterLastEntry, voterLastFound⟩
  have sourceTermLeVoterLast :
      (state.nodes source).currentTerm <= voterLastEntry.term := by
    by_cases atEnd : index = (record.voterLog voter).length
    · rw [atEnd] at voterFound
      have sameEntry : sourceEntry = voterLastEntry :=
        Option.some.inj (voterFound.symm.trans voterLastFound)
      simpa [sameEntry] using sourceEntryCurrent.symm.le
    · have beforeEnd : index < (record.voterLog voter).length := by
        omega
      have monotone :=
        electionHistoryVoterMono
          ownership electionFacts recorded electionMember
            index (record.voterLog voter).length
            sourceEntry voterLastEntry
            beforeEnd voterFound voterLastFound
      rw [sourceEntryCurrent] at monotone
      exact monotone
  have voterLastTerm :
      termAt (record.voterLog voter) (record.voterLog voter).length =
        voterLastEntry.term := by
    simp [termAt, voterLastFound]
  have candidatePrefix :=
    electionFacts.candidatePrefix
      term record voter recorded electionMember
  have candidateCanonical :=
    electionFacts.candidateCanonical
      term record voter recorded electionMember
  have voterCanonical :=
    electionFacts.voterCanonical
      term record voter recorded electionMember
  rcases
      electionFacts.upToDate
        term record voter recorded electionMember with
    candidateNewer | candidateSame
  · have candidateNonempty :
        Not (record.candidateLog voter = []) := by
      intro empty
      simp [
        empty, maxCommittableTerm, termAt, entryAt?
      ] at candidateNewer
    have candidateLastPositive :
        0 < (record.candidateLog voter).length :=
      List.length_pos_iff_ne_nil.mpr candidateNonempty
    rcases
        entryAtSomeOfPositiveBound candidateLastPositive le_rfl with
      ⟨candidateLastEntry, candidateLastFound⟩
    have candidateLastTerm :
        termAt
            (record.candidateLog voter)
            (record.candidateLog voter).length =
          candidateLastEntry.term := by
      simp [termAt, candidateLastFound]
    have sourceTermLtCandidateLast :
        (state.nodes source).currentTerm <
          candidateLastEntry.term := by
      have candidateNewer' :
          voterLastEntry.term < candidateLastEntry.term := by
        simpa [
          maxCommittableTerm,
          electionFacts.voterCommittable
            term record voter recorded electionMember,
          candidateLastTerm, voterLastTerm
        ] using candidateNewer
      omega
    have candidateEntryInPromotion :
        candidateLastEntry ∈ record.promotionLog :=
      CCFRaft.memOfPrefix candidatePrefix
        (entryAtSomeMember candidateLastFound)
    have candidateTermBeforeElection :
        candidateLastEntry.term < term :=
      electionFacts.promotionEntriesBeforeTerm
        term record recorded candidateLastEntry
          candidateEntryInPromotion
    rcases
        candidateCanonical
          (record.candidateLog voter).length
          candidateLastEntry candidateLastFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    rcases
        ownership.canonicalEntryOwner
          candidateLastEntry.term
          (record.candidateLog voter).length
          candidateLastEntry candidateCanonicalFound with
      ⟨candidateOwner, candidateOwned⟩
    rcases
        electionFacts.ownerRecorded
          candidateLastEntry.term candidateOwner candidateOwned with
      bootstrap | candidateElection
    · rw [bootstrap.1] at sourceTermLtCandidateLast
      have sourcePositive := termsPositive source
      omega
    · rcases candidateElection with
        ⟨earlierRecord, earlierRecorded, _⟩
      have prefixInEarlier :=
        earlierSafe
          candidateLastEntry.term earlierRecord
            sourceTermLtCandidateLast
            candidateTermBeforeElection earlierRecorded
      have prefixInCanonical :
          supportedPrefix <+:
            canonicalHistory candidateLastEntry.term :=
        prefixInEarlier.trans
          (electionFacts.promotionCanonical
            candidateLastEntry.term earlierRecord earlierRecorded)
      have canonicalTakeEq :
          (canonicalHistory candidateLastEntry.term).take index =
            supportedPrefix := by
        have covered := CCFRaft.prefixEqTake prefixInCanonical
        simpa [prefixLength] using covered
      have canonicalSourceFound :
          entryAt?
              (canonicalHistory candidateLastEntry.term)
              index =
            some sourceEntry := by
        rw [← entryAtTake_of_le
          (log := canonicalHistory candidateLastEntry.term) le_rfl]
        rw [canonicalTakeEq]
        rw [entryAtTake_of_le le_rfl]
        exact sourceFound
      have indexLeCandidateLength :
          index <= (record.candidateLog voter).length := by
        by_contra outside
        have order :
            (record.candidateLog voter).length < index := by omega
        have monotone :=
          ownership.canonicalMonoLog
            candidateLastEntry.term
              (record.candidateLog voter).length index
              candidateLastEntry sourceEntry
              order candidateCanonicalFound canonicalSourceFound
        rw [sourceEntryCurrent] at monotone
        omega
      have prefixInCandidate :
          supportedPrefix <+: record.candidateLog voter := by
        have candidateEq :
            record.candidateLog voter =
              (canonicalHistory candidateLastEntry.term).take
                (record.candidateLog voter).length := by
          simpa using candidateAgreed
        calc
          supportedPrefix =
              (canonicalHistory candidateLastEntry.term).take index :=
            canonicalTakeEq.symm
          _ <+:
              (canonicalHistory candidateLastEntry.term).take
                (record.candidateLog voter).length := by
            rw [List.prefix_take_iff]
            exact
              ⟨List.take_prefix index _,
                Nat.le_trans (List.length_take_le _ _)
                  indexLeCandidateLength⟩
          _ = record.candidateLog voter := candidateEq.symm
      exact prefixInCandidate.trans candidatePrefix
  · have voterCandidatePrefix :
        record.voterLog voter <+: record.candidateLog voter :=
      canonicalHistoriesPrefixOfSameLastTerm
        canonicalHistory voterCanonical candidateCanonical
          voterNonempty
          (by
            have voterCommittable :=
              electionFacts.voterCommittable
                term record voter recorded electionMember
            have candidateIndex := candidateSame.2
            simp only at candidateIndex
            rw [voterCommittable] at candidateIndex
            exact candidateIndex)
          (by
            simpa [
              maxCommittableTerm,
              electionFacts.voterCommittable
                term record voter recorded electionMember
            ] using candidateSame.1.symm)
    exact voterPrefix.trans (voterCandidatePrefix.trans candidatePrefix)

/-- Every higher frozen election record contains a prospective signature frontier. -/
theorem potentialPrefixInElectionRecords
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (ackerHistory :
      AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index) :
    forall term record,
      elections term = some record ->
      (state.nodes source).currentTerm < term ->
        (state.nodes source).log.take index <+:
          record.promotionLog := by
  intro term
  induction term using Nat.strong_induction_on with
  | h term inductionHypothesis =>
      intro record recorded newer
      apply
        leastBadElectionPromotionContainsPrefix
          termsPositive voteFacts ownership electionFacts ackerHistory
            sourceRole currentEntry currentSignature potential recorded newer
      intro earlierTerm earlierRecord above below earlierRecorded
      exact
        inductionHypothesis earlierTerm below
          earlierRecord earlierRecorded above

/-- Every higher active leader contains a prospective current-term signature frontier. -/
theorem potentialPrefixInHigherLeader
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (ackerHistory :
      AckerElectionHistory state responseHistory elections)
    {source leader : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (leaderRole : (state.nodes leader).role = .leader)
    (newer :
      (state.nodes source).currentTerm <
        (state.nodes leader).currentTerm) :
    (state.nodes source).log.take index <+:
      (state.nodes leader).log := by
  have owned :=
    ownership.activeLeader leader leaderRole
  rcases
      electionFacts.ownerRecorded
        (state.nodes leader).currentTerm leader owned with
    bootstrap | recorded
  · rw [bootstrap.1] at newer
    have positive := termsPositive source
    omega
  · rcases recorded with
      ⟨record, recordStored, recordLeader⟩
    have promotionPrefix :=
      potentialPrefixInElectionRecords
        termsPositive voteFacts ownership electionFacts ackerHistory
          sourceRole currentEntry currentSignature potential
          (state.nodes leader).currentTerm record
          recordStored newer
    have canonicalPrefix :=
      promotionPrefix.trans
        (electionFacts.promotionCanonical
          (state.nodes leader).currentTerm record recordStored)
    rw [ownership.activeLeaderHistory leader leaderRole] at canonicalPrefix
    exact canonicalPrefix

/--
An up-to-date candidate snapshot contains a prospective prefix once every
strictly intermediate elected term is known to contain it.
-/
theorem candidateSnapshotContainsProspectivePrefix
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    {source : Node}
    {index targetTerm : Nat}
    {candidateLog voterLog promotionLog : List (Entry TxId)}
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (voterPrefix :
      (state.nodes source).log.take index <+: voterLog)
    (candidatePrefix : candidateLog <+: promotionLog)
    (candidateCanonical :
      HistoryCanonical canonicalHistory candidateLog)
    (voterCanonical :
      HistoryCanonical canonicalHistory voterLog)
    (voterMono : MonoHistory voterLog)
    (candidateEntriesBeforeTerm :
      forall entry,
        entry ∈ candidateLog ->
          entry.term < targetTerm)
    (upToDate :
      voteLogUpToDate
        { (state.nodes source) with log := voterLog }
        { term := targetTerm
          lastCommittableTerm := maxCommittableTerm candidateLog
          lastCommittableIndex := maxCommittableIndex candidateLog
          source
          destination := source })
    (earlierSafe :
      forall earlierTerm earlierRecord,
        (state.nodes source).currentTerm < earlierTerm ->
        earlierTerm < targetTerm ->
        elections earlierTerm = some earlierRecord ->
          (state.nodes source).log.take index <+:
            earlierRecord.promotionLog) :
    (state.nodes source).log.take index <+: promotionLog := by
  let supportedPrefix := (state.nodes source).log.take index
  have sourceTermPositive :
      0 < (state.nodes source).currentTerm := by
    simpa [TERM_ONE] using termsPositive source
  have lookupPositive :
      0 < termAt (state.nodes source).log index := by
    rw [currentEntry]
    exact sourceTermPositive
  rcases termAtPositiveEntry lookupPositive with
    ⟨sourceEntry, sourceFound, sourceEntryTerm⟩
  have sourceEntryCurrent :
      sourceEntry.term = (state.nodes source).currentTerm :=
    sourceEntryTerm.trans currentEntry
  have sourceBound :
      index <= (state.nodes source).log.length :=
    entryAtSomeIndexBound sourceFound
  have prefixLength : supportedPrefix.length = index := by
    simp [
      supportedPrefix, List.length_take,
      Nat.min_eq_left sourceBound
    ]
  have voterLength : index <= voterLog.length := by
    have covered := voterPrefix.length_le
    rw [prefixLength] at covered
    exact covered
  have voterTakeEq : voterLog.take index = supportedPrefix := by
    have covered := CCFRaft.prefixEqTake voterPrefix
    rw [prefixLength] at covered
    exact covered
  have voterFound :
      entryAt? voterLog index = some sourceEntry := by
    rw [← entryAtTake_of_le (log := voterLog) le_rfl]
    rw [voterTakeEq]
    rw [entryAtTake_of_le le_rfl]
    exact sourceFound
  have supportedSignature :
      isSignatureAt supportedPrefix index = true := by
    exact isSignatureAt_take_of_le le_rfl currentSignature
  have voterSignature :
      isSignatureAt voterLog index = true :=
    isSignatureAt_of_prefix voterPrefix supportedSignature
  have voterFrontierBound :
      index <= maxCommittableIndex voterLog :=
    signatureIndex_le_maxCommittableIndex voterSignature
  have voterFrontierPositive :
      0 < maxCommittableIndex voterLog := by
    have indexPositive : 0 < index := by
      apply Nat.pos_of_ne_zero
      intro indexZero
      rw [indexZero] at sourceFound
      simp [entryAt?] at sourceFound
    omega
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature voterFrontierPositive) with
    ⟨voterLastEntry, voterLastFound, _⟩
  have sourceTermLeVoterLast :
      (state.nodes source).currentTerm <= voterLastEntry.term := by
    by_cases atEnd : index = maxCommittableIndex voterLog
    · rw [atEnd] at voterFound
      have sameEntry : sourceEntry = voterLastEntry :=
        Option.some.inj (voterFound.symm.trans voterLastFound)
      simpa [sameEntry] using sourceEntryCurrent.symm.le
    · have beforeEnd : index < maxCommittableIndex voterLog := by omega
      have monotone :=
        voterMono index (maxCommittableIndex voterLog)
          sourceEntry voterLastEntry
          beforeEnd voterFound voterLastFound
      rw [sourceEntryCurrent] at monotone
      exact monotone
  have voterLastTerm :
      maxCommittableTerm voterLog = voterLastEntry.term := by
    simp [maxCommittableTerm, termAt, voterLastFound]
  rcases upToDate with candidateNewer | candidateSame
  · have candidateTermPositive :
        0 < maxCommittableTerm candidateLog := by
      have voterTermPositive :
          0 < maxCommittableTerm voterLog := by
        rw [voterLastTerm]
        exact sourceTermPositive.trans_le sourceTermLeVoterLast
      exact voterTermPositive.trans candidateNewer
    have candidateFrontierPositive :
        0 < maxCommittableIndex candidateLog := by
      apply Nat.pos_of_ne_zero
      intro frontierZero
      unfold maxCommittableTerm at candidateTermPositive
      rw [frontierZero] at candidateTermPositive
      simp [termAt, entryAt?] at candidateTermPositive
    rcases
        isSignatureAtTrue
          (maxCommittableIndexPositiveIsSignature
            candidateFrontierPositive) with
      ⟨candidateLastEntry, candidateLastFound, _⟩
    have candidateLastTerm :
        maxCommittableTerm candidateLog =
          candidateLastEntry.term := by
      simp [maxCommittableTerm, termAt, candidateLastFound]
    have candidateNewer' :
        voterLastEntry.term < candidateLastEntry.term := by
      simpa [candidateLastTerm, voterLastTerm] using candidateNewer
    have sourceTermLtCandidateLast :
        (state.nodes source).currentTerm <
          candidateLastEntry.term := by
      omega
    have candidateTermBeforeElection :
        candidateLastEntry.term < targetTerm :=
      candidateEntriesBeforeTerm candidateLastEntry
        (entryAtSomeMember candidateLastFound)
    rcases
        candidateCanonical (maxCommittableIndex candidateLog)
          candidateLastEntry candidateLastFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    rcases
        ownership.canonicalEntryOwner
          candidateLastEntry.term (maxCommittableIndex candidateLog)
          candidateLastEntry candidateCanonicalFound with
      ⟨candidateOwner, candidateOwned⟩
    rcases
        electionFacts.ownerRecorded
          candidateLastEntry.term candidateOwner candidateOwned with
      bootstrap | candidateElection
    · rw [bootstrap.1] at sourceTermLtCandidateLast
      have sourcePositive := termsPositive source
      omega
    · rcases candidateElection with
        ⟨earlierRecord, earlierRecorded, _⟩
      have prefixInEarlier :=
        earlierSafe
          candidateLastEntry.term earlierRecord
            sourceTermLtCandidateLast
            candidateTermBeforeElection earlierRecorded
      have prefixInCanonical :
          supportedPrefix <+:
            canonicalHistory candidateLastEntry.term :=
        prefixInEarlier.trans
          (electionFacts.promotionCanonical
            candidateLastEntry.term earlierRecord earlierRecorded)
      have canonicalTakeEq :
          (canonicalHistory candidateLastEntry.term).take index =
            supportedPrefix := by
        have covered := CCFRaft.prefixEqTake prefixInCanonical
        rw [prefixLength] at covered
        exact covered
      have canonicalSourceFound :
          entryAt?
              (canonicalHistory candidateLastEntry.term)
              index =
            some sourceEntry := by
        rw [← entryAtTake_of_le
          (log := canonicalHistory candidateLastEntry.term) le_rfl]
        rw [canonicalTakeEq]
        rw [entryAtTake_of_le le_rfl]
        exact sourceFound
      have indexLeCandidateFrontier :
          index <= maxCommittableIndex candidateLog := by
        by_contra outside
        have order : maxCommittableIndex candidateLog < index := by omega
        have monotone :=
          ownership.canonicalMonoLog
            candidateLastEntry.term
              (maxCommittableIndex candidateLog) index
              candidateLastEntry sourceEntry
              order candidateCanonicalFound canonicalSourceFound
        rw [sourceEntryCurrent] at monotone
        omega
      have prefixInCandidate : supportedPrefix <+: candidateLog := by
        calc
          supportedPrefix =
              (canonicalHistory candidateLastEntry.term).take index :=
            canonicalTakeEq.symm
          _ <+:
              (canonicalHistory candidateLastEntry.term).take
                (maxCommittableIndex candidateLog) := by
            rw [List.prefix_take_iff]
            exact
              ⟨List.take_prefix index _,
                Nat.le_trans (List.length_take_le _ _)
                  indexLeCandidateFrontier⟩
          _ = candidateLog.take (maxCommittableIndex candidateLog) :=
            candidateAgreed.symm
          _ <+: candidateLog :=
            List.take_prefix _ _
      exact prefixInCandidate.trans candidatePrefix
  · have candidateFrontierPositive :
        0 < maxCommittableIndex candidateLog := by
      exact lt_of_lt_of_le voterFrontierPositive candidateSame.2
    rcases
        isSignatureAtTrue
          (maxCommittableIndexPositiveIsSignature
            candidateFrontierPositive) with
      ⟨candidateLastEntry, candidateLastFound, _⟩
    have candidateLastTerm :
        maxCommittableTerm candidateLog =
          candidateLastEntry.term := by
      simp [maxCommittableTerm, termAt, candidateLastFound]
    have sameTerm :
        voterLastEntry.term = candidateLastEntry.term := by
      rw [← voterLastTerm, ← candidateLastTerm]
      exact candidateSame.1.symm
    rcases
        voterCanonical (maxCommittableIndex voterLog)
          voterLastEntry voterLastFound with
      ⟨_, voterAgreed⟩
    rcases
        candidateCanonical (maxCommittableIndex candidateLog)
          candidateLastEntry candidateLastFound with
      ⟨_, candidateAgreed⟩
    have supportedInVoterFrontier :
        supportedPrefix <+:
          voterLog.take (maxCommittableIndex voterLog) := by
      rw [List.prefix_iff_eq_take]
      calc
        supportedPrefix = voterLog.take index := voterTakeEq.symm
        _ =
            (voterLog.take (maxCommittableIndex voterLog)).take
              supportedPrefix.length := by
          simp [List.take_take, prefixLength,
            Nat.min_eq_left voterFrontierBound]
    have voterInCandidateFrontier :
        voterLog.take (maxCommittableIndex voterLog) <+:
          candidateLog.take (maxCommittableIndex candidateLog) := by
      rw [voterAgreed]
      rw [sameTerm, candidateAgreed]
      rw [List.prefix_take_iff]
      exact
        ⟨List.take_prefix _ _,
          (List.length_take_le
            (maxCommittableIndex voterLog)
            (canonicalHistory candidateLastEntry.term)).trans
            candidateSame.2⟩
    exact
      supportedInVoterFrontier.trans
        (voterInCandidateFrontier.trans
          ((List.take_prefix _ _).trans candidatePrefix))

/-- Every higher prospective winning candidate contains a prospective prefix. -/
theorem potentialPrefixInHigherCandidate
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots :
      GrantedVoteCanonicalSnapshots
        state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (voteHistory :
      AckerVoteHistory
        state votes responseHistory voteVoterHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections)
    {source candidate : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority :
      hasPotentialElectionMajority state candidate)
    (newer :
      (state.nodes source).currentTerm <
        (state.nodes candidate).currentTerm) :
    (state.nodes source).log.take index <+:
      (state.nodes candidate).log := by
  have candidateTermUnowned :
      owners (state.nodes candidate).currentTerm = none :=
    potentialCandidateTermUnowned
      voteFacts candidatesAbove snapshots ownership electionFacts
        candidateRole candidateMajority
  have candidateTermNotInLogs :=
    termOwnershipPotentialCandidateTermNotInLogs
      voteFacts candidatesAbove snapshots ownership electionFacts
        candidateRole candidateMajority
  rcases
      potentialElectionMajorityIntersectionEffective
        snapshots potential (Or.inl candidateRole)
          candidateMajority newer with
    ⟨voter, effective, electionMember⟩
  have earlierSafe :
      forall earlierTerm earlierRecord,
        (state.nodes source).currentTerm < earlierTerm ->
        earlierTerm < (state.nodes candidate).currentTerm ->
        elections earlierTerm = some earlierRecord ->
          (state.nodes source).log.take index <+:
            earlierRecord.promotionLog := by
    intro earlierTerm earlierRecord above _ recorded
    exact
      potentialPrefixInElectionRecords
        termsPositive voteFacts ownership electionFacts electedHistory
          sourceRole currentEntry currentSignature potential
          earlierTerm earlierRecord recorded above
  have badImpossible :
      forall bound,
        bound <= (state.nodes candidate).currentTerm ->
        EarlierBadElection state elections source index bound ->
          False := by
    intro bound bounded bad
    rcases bad with
      ⟨badTerm, badRecord, above, badBound, recorded, missing⟩
    have badBelow :
        badTerm < (state.nodes candidate).currentTerm := by
      have notSame :
          Not (badTerm = (state.nodes candidate).currentTerm) := by
        intro same
        subst badTerm
        have owned :=
          electionFacts.recordOwned
            (state.nodes candidate).currentTerm badRecord recorded
        rw [candidateTermUnowned] at owned
        contradiction
      omega
    exact
      missing
        (earlierSafe badTerm badRecord above badBelow recorded)
  by_cases voterEq : voter = candidate
  · subst voter
    rcases
        currentHistory source index sourceRole currentEntry currentSignature
          candidate effective with
      retained | bad
    · exact retained
    · exact False.elim
        (badImpossible
          (state.nodes candidate).currentTerm le_rfl bad)
  · simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at electionMember
    rcases electionMember with materialised | eligible
    · have snapshot :=
        snapshots candidate voter
          (Or.inl candidateRole) materialised
      have recordedVote := snapshot.1
      rcases
          voteHistory source index sourceRole currentEntry currentSignature
            voter (state.nodes candidate).currentTerm candidate
            effective recordedVote voterEq newer with
        voterPrefix | bad
      · rcases snapshot.2 with self | voteSnapshot
        · exact False.elim (voterEq self)
        · rcases
            canonicalSnapshots candidate voter
              (Or.inl candidateRole) materialised with
          self | canonicalSnapshot
          · exact False.elim (voterEq self)
          · let response :=
              grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate
            have candidateEntriesBefore :
                forall entry,
                  entry ∈ voteCandidateHistory response ->
                    entry.term <
                      (state.nodes candidate).currentTerm := by
              intro entry member
              have currentMember :
                  entry ∈ (state.nodes candidate).log :=
                CCFRaft.memOfPrefix voteSnapshot.1 member
              have bounded := entriesBounded candidate entry currentMember
              have different :
                  Not (
                    entry.term =
                      (state.nodes candidate).currentTerm) := by
                intro same
                rcases memberEntryAt currentMember with
                  ⟨entryIndex, found⟩
                exact
                  candidateTermNotInLogs
                    candidate entryIndex entry found same
              omega
            apply
              candidateSnapshotContainsProspectivePrefix
                termsPositive ownership electionFacts
                  currentEntry currentSignature voterPrefix voteSnapshot.1
                  canonicalSnapshot.1
                  canonicalSnapshot.2.2.1
                  canonicalSnapshot.2.2.2
                  candidateEntriesBefore
            · simpa [
                response, voteLogUpToDate, maxCommittableTerm,
                voteSnapshot.2.1, voteSnapshot.2.2.1
              ] using voteSnapshot.2.2.2.2
            · exact earlierSafe
      · exact False.elim
          (badImpossible
            (state.nodes candidate).currentTerm le_rfl bad)
    · have voterPrefix :
          (state.nodes source).log.take index <+:
            (state.nodes voter).log := by
        rcases
            currentHistory source index sourceRole currentEntry
              currentSignature
              voter effective with
          retained | bad
        · exact retained
        · exact False.elim
            (badImpossible
              (state.nodes candidate).currentTerm
                le_rfl
                (by
                  have voterTerm :
                      (state.nodes voter).currentTerm =
                        (state.nodes candidate).currentTerm := by
                    simpa [
                      currentlyEligibleElectionVoter,
                      makeRequestVoteRequest
                    ] using eligible.1.symm
                  simpa [voterTerm] using bad))
      have candidateEntriesBefore :
          forall entry,
            entry ∈ (state.nodes candidate).log ->
              entry.term < (state.nodes candidate).currentTerm := by
        intro entry member
        have bounded := entriesBounded candidate entry member
        have different :
            Not (entry.term = (state.nodes candidate).currentTerm) := by
          intro same
          rcases memberEntryAt member with ⟨entryIndex, found⟩
          exact
            candidateTermNotInLogs
              candidate entryIndex entry found same
        omega
      apply
        candidateSnapshotContainsProspectivePrefix
          termsPositive ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
            candidateEntriesBefore
      · simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes candidate) (committedSignature candidate),
          voteLogUpToDate
        ] using eligible.2.1
      · exact earlierSafe

/--
Prospective per-ACK evidence covers a candidate with a potential election
majority.
-/
theorem prospectiveKnownPotentialWinnerCompleteness
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority :
      hasPotentialElectionMajority state candidate)
    (newer :
      evidence.commitTerm <
        (state.nodes candidate).currentTerm) :
    supportedPrefix <+: (state.nodes candidate).log := by
  have candidateTermNotInLogs :=
    termOwnershipPotentialCandidateTermNotInLogs
      voteFacts candidatesAbove snapshots ownership electionFacts
        candidateRole candidateMajority
  have candidateEntriesBefore :
      forall entry,
        entry ∈ (state.nodes candidate).log ->
          entry.term < (state.nodes candidate).currentTerm := by
    intro entry member
    have bounded := entriesBounded candidate entry member
    have different :
        Not (entry.term = (state.nodes candidate).currentTerm) := by
      intro same
      rcases memberEntryAt member with ⟨index, found⟩
      exact
        candidateTermNotInLogs
          candidate index entry found same
    omega
  have valid := knownCommitEvidenceValid evidenceFacts known
  rcases
      majoritiesIntersect
        evidence.ackQuorum
        (potentialElectionVoters state candidate)
        valid.2.2.2.2.1 candidateMajority with
    ⟨member, memberIn⟩
  have parts :
      member ∈ evidence.ackQuorum /\
        member ∈ potentialElectionVoters state candidate := by
    simpa using memberIn
  have relaxed :
      member ∈ relaxedElectionVoters state candidate := by
    simp only [
      potentialElectionVoters, relaxedElectionVoters,
      Finset.mem_filter, Finset.mem_univ, true_and
    ] at parts ⊢
    rcases parts.2 with effective | eligible
    · exact Or.inl effective
    · right
      have termsEqual :
          (state.nodes member).currentTerm =
            (state.nodes candidate).currentTerm := by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest
        ] using eligible.1.symm
      exact
        ⟨Nat.le_of_eq termsEqual,
          by simpa [
            currentlyEligibleElectionVoter,
            makeRequestVoteRequest,
            voteLogUpToDate
          ] using eligible.2.1⟩
  exact
    (validEvidenceSupportedPrefixFrontier valid).trans
      (prospectiveFacts.relaxedSupporterCarriesFrontier
        evidence supportedPrefix known candidate member
          candidateRole newer candidateEntriesBefore
          parts.1 relaxed)

/--
Valid commit evidence and prospective current-member coverage place every
committed prefix in every strict quorum.
-/
theorem commitEvidenceCurrentMembersQuorumLog
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    {elections : ElectionHistory TxId}
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections) :
    QuorumLog state := by
  intro node quorum majority
  by_cases zero : (state.nodes node).commitIndex = 0
  · rcases majorityNonempty quorum majority with ⟨witness, member⟩
    exact
      ⟨witness, member,
        by simp [NodeState.committedLog, zero]⟩
  · have positive : 0 < (state.nodes node).commitIndex :=
      Nat.pos_of_ne_zero zero
    rcases evidenceFacts.nodePositive node positive with
      ⟨evidence, stored, valid, _, _⟩
    have known :
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
            evidence (state.nodes node).committedLog :=
      Or.inl ⟨node, positive, stored, rfl⟩
    rcases
        majoritiesIntersect
          evidence.ackQuorum quorum
          valid.2.2.2.2.1 majority with
      ⟨witness, member⟩
    have parts :
        witness ∈ evidence.ackQuorum /\
          witness ∈ quorum := by
      simpa using member
    exact
      ⟨witness, parts.2,
        (validEvidenceSupportedPrefixFrontier valid).trans
          (prospectiveFacts.currentMember
            evidence (state.nodes node).committedLog known
              witness parts.1)⟩

/--
Known commit evidence makes every lower-term committed prefix part of an
active leader's log.
-/
theorem knownCommitEvidenceLeaderCompleteness
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections) :
    LeaderCompleteness state := by
  intro leader leaderRole node _different newer
  by_cases zero : (state.nodes node).commitIndex = 0
  · simp [NodeState.committedLog, zero]
  · have positive : 0 < (state.nodes node).commitIndex :=
      Nat.pos_of_ne_zero zero
    rcases evidenceFacts.nodePositive node positive with
      ⟨evidence, stored, valid, _supportedLength, termBound⟩
    have known :
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
            evidence (state.nodes node).committedLog :=
      Or.inl ⟨node, positive, stored, rfl⟩
    rcases
        majorityNonempty evidence.ackQuorum valid.2.2.2.2.1 with
      ⟨member, ackMember⟩
    exact
      (validEvidenceSupportedPrefixFrontier valid).trans
        (knownCommitEvidenceActiveLeaderContainsFrontier
          ownership electionFacts evidenceFacts prospectiveFacts
            known leaderRole (by omega) ackMember)

/--
Prospective commit closure makes every lower-term committed prefix part of a
candidate's log as soon as its effective election quorum is complete.
-/
theorem prospectiveCommitEvidenceWinningCandidateCompleteness
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections) :
    WinningCandidateCompleteness state := by
  intro candidate candidateRole candidateMajority
      node _different newer
  by_cases zero : (state.nodes node).commitIndex = 0
  · simp [NodeState.committedLog, zero]
  · have positive : 0 < (state.nodes node).commitIndex :=
      Nat.pos_of_ne_zero zero
    rcases evidenceFacts.nodePositive node positive with
      ⟨evidence, stored, _valid, _supportedLength, termBound⟩
    have known :
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
            evidence (state.nodes node).committedLog :=
      Or.inl ⟨node, positive, stored, rfl⟩
    apply
      prospectiveKnownPotentialWinnerCompleteness
        entriesBounded candidatesAbove voteFacts snapshots ownership
          electionFacts
          evidenceFacts prospectiveFacts known candidateRole
          (effectiveElectionMajorityImpliesPotential
            state candidate candidateMajority)
    omega

/--
An active leader's canonical history and canonical entry agreement imply that
its log dominates every occurrence of an entry from its current term.
-/
theorem activeLeaderHistoryLeaderTermDominance
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners) :
    LeaderTermDominance state := by
  intro leader leaderRole node index entry found sameTerm
  rcases ownership.logEntryAgreement node index entry found with
    ⟨canonicalFound, agreed⟩
  have leaderHistory :=
    ownership.activeLeaderHistory leader leaderRole
  constructor
  · have bound := entryAtSomeIndexBound canonicalFound
    rw [sameTerm, leaderHistory] at bound
    exact bound
  · calc
      (state.nodes node).log.take index =
          (canonicalHistory entry.term).take index :=
        agreed
      _ =
          (canonicalHistory
            (state.nodes leader).currentTerm).take index := by
        rw [sameTerm]
      _ = (state.nodes leader).log.take index := by
        rw [leaderHistory]

/-- The retained canonical witness derives state-local log matching. -/
theorem invariantFactsLogMatchingFromCanonicalHistories
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    LogMatching state := by
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, _elections, _nodeEvidence,
      _requestEvidence, ownership, _⟩
  exact canonicalHistoriesLogMatching ownership

/-- The retained canonical histories derive state-local log monotonicity. -/
theorem invariantFactsMonoLogFromCanonicalHistories
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    MonoLog state := by
  rcases facts.historicalSafetyEvidence with
    ⟨_owners, _canonicalHistory, _elections, _nodeEvidence,
      _requestEvidence, ownership, _⟩
  exact canonicalHistoriesMonoLog ownership

/-- Persistent self-votes derive the post-bootstrap candidate-term bound. -/
theorem invariantFactsCandidatesAboveBootstrap
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    CandidatesAboveBootstrap state :=
  candidatesSelfVoteAboveBootstrap
    facts.currentTermsPositive facts.candidatesSelfVote facts.voteHistory

/-- The retained commit witnesses derive quorum coverage. -/
theorem invariantFactsQuorumLogFromCommitEvidence
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    QuorumLog state := by
  rcases facts.historicalSafetyEvidence with
    ⟨_owners, _canonicalHistory, elections, nodeEvidence,
      requestEvidence, _ownership, _electionFacts,
      _voteCanonicalFacts, _ackerCurrentFacts, _ackerVoteFacts,
      _ackerElectionFacts, _electionQueuedFacts,
      evidenceFacts, prospectiveFacts⟩
  exact
    commitEvidenceCurrentMembersQuorumLog
      (elections := elections) evidenceFacts prospectiveFacts

/-- The retained known commit witnesses derive leader completeness. -/
theorem invariantFactsLeaderCompletenessFromCommitEvidence
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    LeaderCompleteness state := by
  rcases facts.historicalSafetyEvidence with
    ⟨_owners, _canonicalHistory, _elections, _nodeEvidence,
      _requestEvidence, ownership, electionFacts,
      _voteCanonicalFacts, _ackerCurrentFacts, _ackerVoteFacts,
      _ackerElectionFacts, _electionQueuedFacts,
      evidenceFacts, prospectiveFacts⟩
  exact
    knownCommitEvidenceLeaderCompleteness
      ownership electionFacts evidenceFacts prospectiveFacts

/-- The retained prospective commit witnesses derive candidate completeness. -/
theorem invariantFactsWinningCandidateCompletenessFromCommitEvidence
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    WinningCandidateCompleteness state := by
  rcases facts.historicalSafetyEvidence with
    ⟨_owners, _canonicalHistory, _elections, _nodeEvidence,
      _requestEvidence, ownership, electionFacts,
      _voteCanonicalFacts, _ackerCurrentFacts, _ackerVoteFacts,
      _ackerElectionFacts, _electionQueuedFacts,
      evidenceFacts, prospectiveFacts⟩
  exact
    prospectiveCommitEvidenceWinningCandidateCompleteness
      facts.entriesDoNotExceedCurrentTerm
      (invariantFactsCandidatesAboveBootstrap facts) facts.voteHistory
      facts.grantedVoteSnapshots ownership electionFacts
        evidenceFacts prospectiveFacts

/-- The retained active canonical histories derive leader-term dominance. -/
theorem invariantFactsLeaderTermDominanceFromCanonicalHistories
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {voteRequestHistory : RequestVoteRequest -> List (Entry TxId)}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    (facts :
      InvariantFacts
        state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory) :
    LeaderTermDominance state := by
  rcases facts.historicalSafetyEvidence with
    ⟨_owners, _canonicalHistory, _elections, _nodeEvidence,
      _requestEvidence, ownership, _⟩
  exact activeLeaderHistoryLeaderTermDominance ownership

/--
Future voter closure is derived from the member's current canonical log and
the same frozen election history used by term ownership.
-/
theorem prospectiveCommitFutureMemberCore
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (commitTermPositive :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          TERM_ONE <= evidence.commitTerm)
    (electionClosure :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          forall term record,
            elections term = some record ->
            evidence.commitTerm < term ->
              evidence.history.take evidence.commitFrontier <+:
                record.promotionLog)
    (currentMember :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          forall member,
            member ∈ evidence.ackQuorum ->
              evidence.history.take evidence.commitFrontier <+:
                (state.nodes member).log)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate member : Node}
    {targetTerm : Nat}
    (ackMember : member ∈ evidence.ackQuorum)
    (future :
      member ∈ futureElectionVoters state candidate targetTerm) :
    evidence.history.take evidence.commitFrontier <+:
      (state.nodes candidate).log := by
  let evidencePrefix :=
    evidence.history.take evidence.commitFrontier
  have valid := knownCommitEvidenceValid evidenceFacts known
  have supportedPositive :=
    knownCommitEvidenceSupportedLengthPositive evidenceFacts known
  have frontierPositive : 0 < evidence.commitFrontier := by
    have supportedBound := valid.2.2.1
    omega
  have prefixLength :
      evidencePrefix.length = evidence.commitFrontier := by
    simp only [evidencePrefix, List.length_take]
    rw [Nat.min_eq_left valid.1]
  rcases
      entryAtSomeOfPositiveBound frontierPositive valid.1 with
    ⟨frontierEntry, historyFound⟩
  have frontierEntryTerm :
      frontierEntry.term = evidence.commitTerm := by
    simpa [termAt, historyFound] using valid.2.1
  have prefixFound :
      entryAt? evidencePrefix evidence.commitFrontier =
        some frontierEntry := by
    rw [entryAtTake_of_le le_rfl]
    exact historyFound
  have memberCovered :=
    currentMember
      evidence supportedPrefix known member ackMember
  have memberFound :
      entryAt? (state.nodes member).log evidence.commitFrontier =
        some frontierEntry :=
    CCFRaft.entryAt_of_prefix memberCovered prefixFound
  rcases
      ownership.logEntryAgreement
        member evidence.commitFrontier frontierEntry memberFound with
    ⟨canonicalCommitFound, memberAgreed⟩
  have prefixCanonical :
      evidencePrefix =
        (canonicalHistory evidence.commitTerm).take
          evidence.commitFrontier := by
    calc
      evidencePrefix =
          (state.nodes member).log.take evidence.commitFrontier := by
        have covered := CCFRaft.prefixEqTake memberCovered
        rw [prefixLength] at covered
        exact covered.symm
      _ =
          (canonicalHistory frontierEntry.term).take
            evidence.commitFrontier :=
        memberAgreed
      _ =
          (canonicalHistory evidence.commitTerm).take
            evidence.commitFrontier := by rw [frontierEntryTerm]
  have prefixLastTerm :
      termAt evidencePrefix evidencePrefix.length =
        evidence.commitTerm := by
    rw [prefixLength]
    simpa [termAt, prefixFound] using frontierEntryTerm
  have evidenceSignature :
      isSignatureAt evidence.history evidence.commitFrontier = true :=
    valid.2.2.2.2.2.2
  have prefixSignature :
      isSignatureAt evidencePrefix evidence.commitFrontier = true := by
    exact isSignatureAt_take_of_le le_rfl evidenceSignature
  have memberSignature :
      isSignatureAt
        (state.nodes member).log evidence.commitFrontier = true :=
    isSignatureAt_of_prefix memberCovered prefixSignature
  have memberFrontierBound :
      evidence.commitFrontier <=
        maxCommittableIndex (state.nodes member).log :=
    signatureIndex_le_maxCommittableIndex memberSignature
  have memberCommittablePositive :
      0 < maxCommittableIndex (state.nodes member).log := by
    omega
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature
          memberCommittablePositive) with
    ⟨memberEntry, memberEntryFound, _⟩
  have memberEntryTerm :
      maxCommittableTerm (state.nodes member).log =
        memberEntry.term := by
    simp [maxCommittableTerm, termAt, memberEntryFound]
  have memberLastTerm :
      evidence.commitTerm <=
        maxCommittableTerm (state.nodes member).log := by
    have entryOrder :
        frontierEntry.term <= memberEntry.term := by
      by_cases sameIndex :
          evidence.commitFrontier =
            maxCommittableIndex (state.nodes member).log
      · rw [sameIndex] at memberFound
        exact
          (congrArg Entry.term
            (Option.some.inj
              (memberFound.symm.trans memberEntryFound))).le
      · exact
          (canonicalHistoriesMonoLog ownership) member
            evidence.commitFrontier
            (maxCommittableIndex (state.nodes member).log)
            frontierEntry memberEntry
            (lt_of_le_of_ne memberFrontierBound sameIndex)
            memberFound memberEntryFound
    calc
      evidence.commitTerm = frontierEntry.term := frontierEntryTerm.symm
      _ <= memberEntry.term := entryOrder
      _ = maxCommittableTerm (state.nodes member).log :=
        memberEntryTerm.symm
  simp only [
    futureElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at future
  rcases future with self | supporter
  · subst member
    exact memberCovered
  · rcases supporter with ⟨_, upToDate⟩
    have commitPositive :=
      commitTermPositive
        evidence supportedPrefix known
    have candidateLastIndex :
        lastCommittableIndex (state.nodes candidate) =
          maxCommittableIndex (state.nodes candidate).log :=
      lastCommittableIndex_eq_maxCommittableIndex
        (state.nodes candidate) (committedSignature candidate)
    have candidateLastTermEq :
        lastCommittableTerm (state.nodes candidate) =
          maxCommittableTerm (state.nodes candidate).log :=
      lastCommittableTerm_eq_maxCommittableTerm
        (state.nodes candidate) (committedSignature candidate)
    unfold voteLogUpToDate at upToDate
    simp only [makeRequestVoteRequest] at upToDate
    rw [candidateLastIndex, candidateLastTermEq] at upToDate
    have candidateLastTerm :
        evidence.commitTerm <=
          maxCommittableTerm (state.nodes candidate).log := by
      rcases upToDate with newer | same
      · omega
      · omega
    have candidateTermPositive :
        0 < maxCommittableTerm (state.nodes candidate).log := by
      have commitTermPositive :
          0 < evidence.commitTerm := by
        simpa [TERM_ONE] using commitPositive
      omega
    have candidateIndexPositive :
        0 < maxCommittableIndex (state.nodes candidate).log := by
      apply Nat.pos_of_ne_zero
      intro zero
      simp [
        maxCommittableTerm, zero, termAt, entryAt?
      ] at candidateTermPositive
    rcases
        isSignatureAtTrue
          (maxCommittableIndexPositiveIsSignature
            candidateIndexPositive) with
      ⟨candidateEntry, candidateFound, _⟩
    have candidateEntryLast :
        candidateEntry.term =
          maxCommittableTerm (state.nodes candidate).log := by
      simp [maxCommittableTerm, termAt, candidateFound]
    rcases
        ownership.logEntryAgreement
          candidate (maxCommittableIndex (state.nodes candidate).log)
            candidateEntry candidateFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    by_cases sameCommit :
        candidateEntry.term = evidence.commitTerm
    · have candidateLengthBound :
          evidence.commitFrontier <=
            maxCommittableIndex (state.nodes candidate).log := by
        rcases upToDate with newer | same
        · rw [← candidateEntryLast, sameCommit] at newer
          omega
        · have memberLength := memberFrontierBound
          omega
      rw [List.prefix_iff_eq_take]
      calc
        evidencePrefix =
            (canonicalHistory evidence.commitTerm).take
              evidence.commitFrontier :=
          prefixCanonical
        _ =
            ((canonicalHistory candidateEntry.term).take
              (maxCommittableIndex
                (state.nodes candidate).log)).take
                evidence.commitFrontier := by
          rw [sameCommit]
          simp [List.take_take, Nat.min_eq_left candidateLengthBound]
        _ =
            ((state.nodes candidate).log.take
              (maxCommittableIndex
                (state.nodes candidate).log)).take
              evidence.commitFrontier := by
          rw [← candidateAgreed]
        _ =
            (state.nodes candidate).log.take
              evidence.commitFrontier := by
          simp [List.take_take, Nat.min_eq_left candidateLengthBound]
        _ =
            (state.nodes candidate).log.take evidencePrefix.length := by
          rw [prefixLength]
    · have commitStrict :
          evidence.commitTerm < candidateEntry.term := by
        rw [candidateEntryLast] at sameCommit
        omega
      rcases
          ownership.canonicalEntryOwner
            candidateEntry.term
              (maxCommittableIndex (state.nodes candidate).log)
              candidateEntry candidateCanonicalFound with
        ⟨owner, owned⟩
      rcases
          electionFacts.ownerRecorded
            candidateEntry.term owner owned with
        bootstrap | recorded
      · rw [bootstrap.1] at commitStrict
        omega
      · rcases recorded with
          ⟨record, recordStored, _⟩
        have closure :=
          electionClosure
            evidence supportedPrefix known
              candidateEntry.term record recordStored commitStrict
        have prefixInCanonical :
            evidencePrefix <+:
              canonicalHistory candidateEntry.term :=
          closure.trans
            (electionFacts.promotionCanonical
              candidateEntry.term record recordStored)
        have canonicalPrefixFound :
            entryAt?
                (canonicalHistory candidateEntry.term)
                evidence.commitFrontier =
              some frontierEntry :=
          CCFRaft.entryAt_of_prefix prefixInCanonical prefixFound
        have lengthStrict :
            evidence.commitFrontier <
              maxCommittableIndex (state.nodes candidate).log := by
          by_contra notStrict
          have reverse :
              maxCommittableIndex (state.nodes candidate).log <=
                evidence.commitFrontier := by omega
          by_cases equal :
              maxCommittableIndex (state.nodes candidate).log =
                evidence.commitFrontier
          · rw [equal] at candidateCanonicalFound
            have entryEq :
                candidateEntry = frontierEntry :=
              Option.some.inj
                (candidateCanonicalFound.symm.trans canonicalPrefixFound)
            rw [entryEq, frontierEntryTerm] at commitStrict
            omega
          · have order :
              maxCommittableIndex (state.nodes candidate).log <
                  evidence.commitFrontier := by omega
            have termOrder :=
              ownership.canonicalMonoLog candidateEntry.term
              (maxCommittableIndex (state.nodes candidate).log)
                evidence.commitFrontier
                candidateEntry frontierEntry order
                candidateCanonicalFound canonicalPrefixFound
            rw [frontierEntryTerm] at termOrder
            omega
        rw [List.prefix_iff_eq_take]
        calc
          evidencePrefix =
              (canonicalHistory candidateEntry.term).take
                evidence.commitFrontier :=
            by
              have covered := CCFRaft.prefixEqTake prefixInCanonical
              simpa [prefixLength] using covered.symm
          _ =
              ((canonicalHistory candidateEntry.term).take
                (maxCommittableIndex
                  (state.nodes candidate).log)).take
                  evidence.commitFrontier := by
            simp [
              List.take_take,
              Nat.min_eq_left lengthStrict.le
            ]
          _ =
              ((state.nodes candidate).log.take
                (maxCommittableIndex
                  (state.nodes candidate).log)).take
                evidence.commitFrontier := by
            rw [← candidateAgreed]
          _ =
              (state.nodes candidate).log.take
                evidence.commitFrontier := by
            simp [
              List.take_take,
              Nat.min_eq_left lengthStrict.le
            ]
          _ =
              (state.nodes candidate).log.take evidencePrefix.length := by
            rw [prefixLength]

/--
Future voter closure specialized to the fields stored in prospective commit
evidence.
-/
theorem prospectiveCommitFutureMember
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    {nodeEvidence : NodeCommitEvidence TxId}
    {requestEvidence : RequestCommitEvidence TxId}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (evidenceFacts :
      CommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts :
      ProspectiveCommitEvidenceFacts
        state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence TxId}
    {supportedPrefix : List (Entry TxId)}
    (known :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate member : Node}
    {targetTerm : Nat}
    (_candidateBefore :
      (state.nodes candidate).currentTerm < targetTerm)
    (ackMember : member ∈ evidence.ackQuorum)
    (future :
      member ∈ futureElectionVoters state candidate targetTerm) :
    evidence.history.take evidence.commitFrontier <+:
      (state.nodes candidate).log :=
  prospectiveCommitFutureMemberCore
    ownership committedSignature electionFacts evidenceFacts
      prospectiveFacts.commitTermPositive
      prospectiveFacts.electionClosure
      prospectiveFacts.currentMember
      known ackMember future

/-- Under a support quorum, every materialised ACKer's current log contains the prefix. -/
theorem effectiveAckerContainsPotentialPrefix
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections)
    {source voter : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (effective :
      voter ∈ effectiveAckers state responseHistory source index) :
    (state.nodes source).log.take index <+:
      (state.nodes voter).log := by
  rcases
      currentHistory source index sourceRole currentEntry currentSignature
        voter effective with
    retained | bad
  · exact retained
  · rcases bad with
      ⟨badTerm, badRecord, above, _, recorded, missing⟩
    exact False.elim
      (missing
        (potentialPrefixInElectionRecords
          termsPositive voteFacts ownership electionFacts electedHistory
            sourceRole currentEntry currentSignature potential
            badTerm badRecord recorded above))

/--
One materialised ACKer which is either an existing voter or currently regards
the candidate log as up to date transfers the acknowledged prefix.
-/
theorem effectiveAckerRelaxedCandidateContainsPotentialPrefix
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots :
      GrantedVoteCanonicalSnapshots
        state canonicalHistory voteCandidateHistory voteVoterHistory)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (voteHistory :
      AckerVoteHistory
        state votes responseHistory voteVoterHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections)
    {source candidate voter : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (candidateRole : (state.nodes candidate).role = .candidate)
    (newer :
      (state.nodes source).currentTerm <
        (state.nodes candidate).currentTerm)
    (candidateEntriesBefore :
      forall entry,
        entry ∈ (state.nodes candidate).log ->
          entry.term < (state.nodes candidate).currentTerm)
    (effective :
      voter ∈ effectiveAckers state responseHistory source index)
    (relaxed : voter ∈ relaxedElectionVoters state candidate) :
    (state.nodes source).log.take index <+:
      (state.nodes candidate).log := by
  have earlierSafe :
      forall earlierTerm earlierRecord,
        (state.nodes source).currentTerm < earlierTerm ->
        earlierTerm < (state.nodes candidate).currentTerm ->
        elections earlierTerm = some earlierRecord ->
          (state.nodes source).log.take index <+:
            earlierRecord.promotionLog := by
    intro earlierTerm earlierRecord above _ recorded
    exact
      potentialPrefixInElectionRecords
        termsPositive voteFacts ownership electionFacts electedHistory
          sourceRole currentEntry currentSignature potential
          earlierTerm earlierRecord recorded above
  by_cases voterEq : voter = candidate
  · subst voter
    exact
      effectiveAckerContainsPotentialPrefix
        termsPositive voteFacts ownership electionFacts
          currentHistory electedHistory
          sourceRole currentEntry currentSignature potential effective
  · simp only [
      relaxedElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at relaxed
    rcases relaxed with materialised | upToDate
    · have snapshot :=
        snapshots candidate voter
          (Or.inl candidateRole) materialised
      have recordedVote := snapshot.1
      have voterPrefix :
          (state.nodes source).log.take index <+:
            voteVoterHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate) := by
        rcases
            voteHistory source index sourceRole currentEntry currentSignature
              voter (state.nodes candidate).currentTerm candidate
              effective recordedVote voterEq newer with
          retained | bad
        · exact retained
        · rcases bad with
            ⟨badTerm, badRecord, above, _, recorded, missing⟩
          exact False.elim
            (missing
              (potentialPrefixInElectionRecords
                termsPositive voteFacts ownership electionFacts electedHistory
                  sourceRole currentEntry currentSignature potential
                  badTerm badRecord recorded above))
      rcases snapshot.2 with self | voteSnapshot
      · exact False.elim (voterEq self)
      · rcases
          canonicalSnapshots candidate voter
            (Or.inl candidateRole) materialised with
        self | canonicalSnapshot
        · exact False.elim (voterEq self)
        · let response :=
            grantedVoteKey
              voter (state.nodes candidate).currentTerm candidate
          apply
            candidateSnapshotContainsProspectivePrefix
              termsPositive ownership electionFacts
                currentEntry currentSignature voterPrefix voteSnapshot.1
                canonicalSnapshot.1
                canonicalSnapshot.2.2.1
                canonicalSnapshot.2.2.2
                (fun entry member =>
                  candidateEntriesBefore entry
                    (CCFRaft.memOfPrefix voteSnapshot.1 member))
          · simpa [
              response, voteLogUpToDate, maxCommittableTerm,
              voteSnapshot.2.1, voteSnapshot.2.2.1
            ] using voteSnapshot.2.2.2.2
          · exact earlierSafe
    · have voterPrefix :=
        effectiveAckerContainsPotentialPrefix
          termsPositive voteFacts ownership electionFacts
            currentHistory electedHistory
            sourceRole currentEntry currentSignature potential effective
      apply
        candidateSnapshotContainsProspectivePrefix
          termsPositive ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
            candidateEntriesBefore
      · simpa [
          relaxedElectionVoters,
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes candidate) (committedSignature candidate),
          voteLogUpToDate
        ] using upToDate.2
      · exact earlierSafe

/--
One materialised ACKer whose current log would support a strictly later
election transfers the acknowledged prefix to that unchanged candidate log.
-/
theorem effectiveAckerFutureCandidateContainsPotentialPrefix
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections)
    {source candidate voter : Node}
    {index targetTerm : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (state.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        state appendHistory responseHistory source index)
    (sourceBefore :
      (state.nodes source).currentTerm < targetTerm)
    (candidateBefore :
      (state.nodes candidate).currentTerm < targetTerm)
    (effective :
      voter ∈ effectiveAckers state responseHistory source index)
    (future : voter ∈ futureElectionVoters state candidate targetTerm) :
    (state.nodes source).log.take index <+:
      (state.nodes candidate).log := by
  have voterPrefix :=
    effectiveAckerContainsPotentialPrefix
      termsPositive voteFacts ownership electionFacts
        currentHistory electedHistory
        sourceRole currentEntry currentSignature potential effective
  by_cases voterEq : voter = candidate
  · subst voter
    exact voterPrefix
  · simp only [
      futureElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at future
    rcases future with self | supporter
    · exact False.elim (voterEq self)
    · have earlierSafe :
          forall earlierTerm earlierRecord,
            (state.nodes source).currentTerm < earlierTerm ->
            earlierTerm < targetTerm ->
            elections earlierTerm = some earlierRecord ->
              (state.nodes source).log.take index <+:
                earlierRecord.promotionLog := by
        intro earlierTerm earlierRecord above _ recorded
        exact
          potentialPrefixInElectionRecords
            termsPositive voteFacts ownership electionFacts electedHistory
              sourceRole currentEntry currentSignature potential
              earlierTerm earlierRecord recorded above
      apply
        candidateSnapshotContainsProspectivePrefix
          termsPositive ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
            (targetTerm := targetTerm)
            (candidateEntriesBeforeTerm := fun entry member => by
              have bounded := entriesBounded candidate entry member
              omega)
      · simpa [
          futureElectionVoters,
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes candidate) (committedSignature candidate),
          voteLogUpToDate
        ] using supporter.2
      · exact earlierSafe

/-- Temporal quorum evidence derives compatibility with every committed log. -/
theorem derivePotentialCommitSafe
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (quorumLog : QuorumLog state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections) :
    PotentialCommitSafe state responseHistory := by
  intro source index role current signature majority committed
  have potential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory source index majority
  have committedMajority := committedHoldersMajority quorumLog committed
  rcases
      majoritiesIntersect
        (effectiveAckers state responseHistory source index)
        (committedHolders state committed)
        majority committedMajority with
    ⟨voter, member⟩
  have sourcePrefix :=
    effectiveAckerContainsPotentialPrefix
      termsPositive voteFacts ownership electionFacts
        currentHistory electedHistory
        role current signature potential
        (Finset.mem_inter.mp member).1
  have committedPrefix :
      (state.nodes committed).committedLog <+:
        (state.nodes voter).log := by
    simpa [committedHolders] using
      (Finset.mem_inter.mp member).2
  exact CCFRaft.prefixesComparable sourcePrefix committedPrefix

/-- Temporal quorum evidence derives higher-winner containment. -/
theorem derivePotentialCommitElectionSafe
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots :
      GrantedVoteSnapshots
        state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots :
      GrantedVoteCanonicalSnapshots
        state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (voteHistory :
      AckerVoteHistory
        state votes responseHistory voteVoterHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections) :
    PotentialCommitElectionSafe state responseHistory := by
  intro source index role current signature majority winner active newer
  have potential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory source index majority
  rcases active with leader | candidate
  · exact
      potentialPrefixInHigherLeader
        termsPositive voteFacts ownership electionFacts electedHistory
          role current signature potential leader newer
  · exact
      potentialPrefixInHigherCandidate
        termsPositive committedSignature candidatesAbove entriesBounded
          voteFacts snapshots canonicalSnapshots
          ownership electionFacts currentHistory voteHistory electedHistory
          role current signature potential candidate.1
            (effectiveElectionMajorityImpliesPotential
              state winner candidate.2)
            newer

/-- Temporal quorum evidence represents a potential prefix in every quorum. -/
theorem derivePotentialCommitQuorumLog
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections) :
    PotentialCommitQuorumLog state responseHistory := by
  intro source index role current signature majority quorum quorumMajority
  have potential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory source index majority
  rcases
      majoritiesIntersect
        (effectiveAckers state responseHistory source index)
        quorum majority quorumMajority with
    ⟨voter, member⟩
  exact
    ⟨voter, (Finset.mem_inter.mp member).2,
      effectiveAckerContainsPotentialPrefix
        termsPositive voteFacts ownership electionFacts
          currentHistory electedHistory
          role current signature potential
          (Finset.mem_inter.mp member).1⟩

/-- Temporal quorum evidence makes any two potential prefixes comparable. -/
theorem derivePotentialCommitsComparable
    {state : State TxId}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    {votes : VoteHistory}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    {elections : ElectionHistory TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (currentHistory :
      AckerCurrentHistory state responseHistory elections)
    (electedHistory :
      AckerElectionHistory state responseHistory elections) :
    PotentialCommitsComparable state responseHistory := by
  intro left leftIndex leftRole leftCurrent leftSignature leftMajority
      right rightIndex rightRole rightCurrent rightSignature rightMajority
  have leftPotential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory left leftIndex leftMajority
  have rightPotential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory right rightIndex rightMajority
  rcases
      majoritiesIntersect
        (effectiveAckers state responseHistory left leftIndex)
        (effectiveAckers state responseHistory right rightIndex)
        leftMajority rightMajority with
    ⟨voter, member⟩
  have leftPrefix :=
    effectiveAckerContainsPotentialPrefix
      termsPositive voteFacts ownership electionFacts
        currentHistory electedHistory
        leftRole leftCurrent leftSignature leftPotential
        (Finset.mem_inter.mp member).1
  have rightPrefix :=
    effectiveAckerContainsPotentialPrefix
      termsPositive voteFacts ownership electionFacts
        currentHistory electedHistory
        rightRole rightCurrent rightSignature rightPotential
        (Finset.mem_inter.mp member).2
  exact CCFRaft.prefixesComparable leftPrefix rightPrefix

/-- A successful selected request is exactly the reserve its reply materialises. -/
theorem successfulAppendRequestIsReserve
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {nextNode : NodeState TxId}
    {response : AppendEntriesResponse}
    (member :
      Message.appendEntriesRequest request ∈
        state.network destination)
    (requestDestination : request.destination = destination)
    (sourceRole :
      (state.nodes request.source).role = .leader)
    (requestTerm :
      request.term =
        (state.nodes request.source).currentTerm)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response))
    (success : response.success = true) :
    queuedAppendReserve
      state appendHistory request.source destination
        response.lastLogIndex := by
  refine
    ⟨request, member, rfl, requestDestination, requestTerm,
      Or.inl
        ⟨nextNode, response, handled, success, le_rfl⟩,
      ?_⟩
  exact
    ownership.queuedActiveSourceHistory
      destination request member requestTerm sourceRole

/-- Frame an immutable election history across monotone local changes. -/
theorem electionHistoryFrame
    (state after : State TxId)
    (votes afterVotes : VoteHistory)
    (canonicalHistory afterCanonicalHistory :
      Nat -> List (Entry TxId))
    (owners : TermOwners)
    (elections : ElectionHistory TxId)
    (facts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (votesPreserved :
      forall term record voter,
        elections term = some record ->
        voter ∈ record.quorum ->
          afterVotes voter term = votes voter term)
    (canonicalMonotone :
      forall term,
        canonicalHistory term <+: afterCanonicalHistory term)
    (canonicalFrame :
      forall history,
        HistoryCanonical canonicalHistory history ->
          HistoryCanonical afterCanonicalHistory history) :
    ElectionHistoryFacts
      after afterVotes afterCanonicalHistory owners elections := by
  constructor
  · exact facts.recordOwned
  · exact facts.ownerRecorded
  · exact facts.postBootstrap
  · exact facts.majority
  · intro term record voter recorded member
    rw [votesPreserved term record voter recorded member]
    exact facts.voted term record voter recorded member
  · intro term record recorded
    exact
      (facts.promotionCanonical term record recorded).trans
        (canonicalMonotone term)
  · exact facts.promotionCommittable
  · exact facts.promotionEntriesBeforeTerm
  · exact facts.candidatePrefix
  · intro term record voter recorded member
    exact
      canonicalFrame _
        (facts.candidateCanonical term record voter recorded member)
  · exact facts.candidateCommittable
  · intro term record voter recorded member
    exact
      canonicalFrame _
        (facts.voterCanonical term record voter recorded member)
  · exact facts.voterCommittable
  · intro term record voter recorded member
    simpa [voteLogUpToDate] using
      facts.upToDate term record voter recorded member

/-- A current node log is canonical under term ownership. -/
theorem nodeLogCanonical
    {state : State TxId}
    {votes : VoteHistory}
    {appendHistory : AppendEntriesRequest TxId -> List (Entry TxId)}
    {canonicalHistory : Nat -> List (Entry TxId)}
    {owners : TermOwners}
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (node : Node) :
    HistoryCanonical canonicalHistory (state.nodes node).log := by
  intro index entry found
  exact ownership.logEntryAgreement node index entry found

/-- Frame active vote snapshots across role/evidence restriction and canonical extension. -/
theorem grantedVoteCanonicalFrame
    (state after : State TxId)
    (canonicalHistory afterCanonicalHistory :
      Nat -> List (Entry TxId))
    (voteCandidateHistory voteVoterHistory :
      RequestVoteResponse -> List (Entry TxId))
    (facts :
      GrantedVoteCanonicalSnapshots
        state canonicalHistory
          voteCandidateHistory voteVoterHistory)
    (termEq :
      forall candidate,
        ((after.nodes candidate).role = .candidate \/
          (after.nodes candidate).role = .leader) ->
        (after.nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm)
    (activeBack :
      forall candidate,
        ((after.nodes candidate).role = .candidate \/
          (after.nodes candidate).role = .leader) ->
        ((state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader))
    (memberBack :
      forall candidate voter,
        ((after.nodes candidate).role = .candidate \/
          (after.nodes candidate).role = .leader) ->
        voter ∈ effectiveElectionVoters after candidate ->
          voter ∈ effectiveElectionVoters state candidate)
    (canonicalFrame :
      forall history,
        HistoryCanonical canonicalHistory history ->
          HistoryCanonical afterCanonicalHistory history) :
    GrantedVoteCanonicalSnapshots
      after afterCanonicalHistory
        voteCandidateHistory voteVoterHistory := by
  intro candidate voter active member
  rcases
      facts candidate voter
        (activeBack candidate active)
        (memberBack candidate voter active member) with
    self | snapshots
  · exact Or.inl self
  · right
    simpa [termEq candidate active] using
      And.intro
        (canonicalFrame _ snapshots.1)
        (And.intro snapshots.2.1
          (And.intro
            (canonicalFrame _ snapshots.2.2.1)
            snapshots.2.2.2))

/-- Frame all ACK/election temporal relations when node logs are unchanged. -/
theorem ackerTemporalFrameSameLogs
    (state after : State TxId)
    (votes afterVotes : VoteHistory)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId))
    (elections : ElectionHistory TxId)
    (currentFacts :
      AckerCurrentHistory state responseHistory elections)
    (voteFacts :
      AckerVoteHistory
        state votes responseHistory voteVoterHistory elections)
    (electionFacts :
      AckerElectionHistory state responseHistory elections)
    (roleBack :
      forall source,
        (after.nodes source).role = .leader ->
          (state.nodes source).role = .leader)
    (sourceTermEq :
      forall source,
        (after.nodes source).role = .leader ->
          (after.nodes source).currentTerm =
            (state.nodes source).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (effectiveBack :
      forall source index voter,
        (after.nodes source).role = .leader ->
        termAt (after.nodes source).log index =
            (after.nodes source).currentTerm ->
        voter ∈ effectiveAckers after responseHistory source index ->
          voter ∈ effectiveAckers state responseHistory source index)
    (termMonotone :
      forall node,
        (state.nodes node).currentTerm <=
          (after.nodes node).currentTerm)
    (voteBack :
      forall voter voteTerm candidate,
        afterVotes voter voteTerm = some candidate ->
        Not (voter = candidate) ->
          votes voter voteTerm = some candidate) :
    AckerCurrentHistory after responseHistory elections /\
      AckerVoteHistory
        after afterVotes responseHistory voteVoterHistory elections /\
      AckerElectionHistory after responseHistory elections := by
  have prefixEq :
      forall source index,
        (after.nodes source).log.take index =
          (state.nodes source).log.take index := by
    intro source index
    rw [logEq]
  constructor
  · intro source index role current signature voter effective
    have oldRole := roleBack source role
    have oldTerm :
        (after.nodes source).currentTerm =
          (state.nodes source).currentTerm :=
      sourceTermEq source role
    have oldCurrent :
        termAt (state.nodes source).log index =
          (state.nodes source).currentTerm := by
      simpa [logEq, oldTerm] using current
    have oldSignature :
        isSignatureAt (state.nodes source).log index = true := by
      simpa [logEq] using signature
    rcases
        currentFacts source index oldRole oldCurrent oldSignature voter
          (effectiveBack source index voter role current effective) with
      retained | bad
    · exact Or.inl (by simpa [logEq, prefixEq] using retained)
    · right
      rcases bad with
        ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
      exact
        ⟨badTerm, badRecord,
          by simpa [oldTerm] using above,
          Nat.le_trans bounded (termMonotone voter),
          recorded,
          by simpa [prefixEq] using missing⟩
  · constructor
    · intro source index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole := roleBack source role
      have oldTerm :
          (after.nodes source).currentTerm =
            (state.nodes source).currentTerm :=
        sourceTermEq source role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logEq, oldTerm] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logEq] using signature
      have oldEffective :=
        effectiveBack source index voter role current effective
      have oldVoted := voteBack voter voteTerm candidate voted different
      have oldNewer :
          (state.nodes source).currentTerm < voteTerm := by
        simpa [oldTerm] using newer
      rcases
          voteFacts source index oldRole oldCurrent oldSignature
            voter voteTerm candidate oldEffective oldVoted different oldNewer with
        retained | bad
      · exact Or.inl (by simpa [prefixEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [oldTerm] using above,
            bounded, recorded,
            by simpa [prefixEq] using missing⟩
    · intro source index role current signature term record voter
        recorded member effective newer
      have oldRole := roleBack source role
      have oldTerm :
          (after.nodes source).currentTerm =
            (state.nodes source).currentTerm :=
        sourceTermEq source role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logEq, oldTerm] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logEq] using signature
      have oldEffective :=
        effectiveBack source index voter role current effective
      have oldNewer :
          (state.nodes source).currentTerm < term := by
        simpa [oldTerm] using newer
      rcases
          electionFacts source index oldRole oldCurrent oldSignature
            term record voter recorded member oldEffective oldNewer with
        retained | bad
      · exact Or.inl (by simpa [prefixEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [oldTerm] using above,
            below, badRecorded,
            by simpa [prefixEq] using missing⟩

/--
An active leader has no effective quorum beyond its log: processed cursors are
bounded, while queued ACKs carry a bounded history prefix of that same log.
-/
theorem effectiveAckersBeyondLeaderLog
    {state : State TxId}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    (progress : LeaderProgressBounded state)
    (responseSafe :
      forall destination response,
        Message.appendEntriesResponse response ∈ state.network destination ->
          SuccessfulResponseSnapshot state (responseHistory response) response)
    {leader : Node}
    (role : (state.nodes leader).role = .leader)
    {index : Nat}
    (beyond : (state.nodes leader).log.length < index) :
    effectiveAckers state responseHistory leader index = {leader} := by
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter,
    Finset.mem_univ, true_and, Finset.mem_singleton
  ]
  constructor
  · intro acknowledges
    rcases acknowledges with self | matched | queued
    · exact self
    · have bounded := (progress leader role peer).2
      omega
    · rcases queued with
        ⟨response, member, success, _, _, _, _, covered⟩
      have responseBound := (responseSafe leader response member success).1
      have historyBound := covered.length_le
      omega
  · exact fun self => Or.inl self

/--
An active leader has no effective quorum beyond its log: processed cursors are
bounded, while queued ACKs carry a bounded history prefix of that same log.
-/
theorem noEffectiveMajorityBeyondLeaderLog
    {state : State TxId}
    {responseHistory : AppendEntriesResponse -> List (Entry TxId)}
    (progress : LeaderProgressBounded state)
    (responseSafe :
      forall destination response,
        Message.appendEntriesResponse response ∈ state.network destination ->
          SuccessfulResponseSnapshot state (responseHistory response) response)
    {leader : Node}
    (role : (state.nodes leader).role = .leader)
    {index : Nat}
    (beyond : (state.nodes leader).log.length < index) :
    Not (hasEffectiveMajorityAt state responseHistory leader index) := by
  intro majority
  have acknowledgingOnlyLeader :=
    effectiveAckersBeyondLeaderLog
      progress responseSafe role beyond
  unfold hasEffectiveMajorityAt at majority
  rw [acknowledgingOnlyLeader] at majority
  simp [NODE_COUNT] at majority

/-- Enqueue-with-deduplication never removes an existing queued message. -/
theorem memEnqueueNoDupOfMem
    (network : Node -> List (Message TxId))
    (newMessage message : Message TxId)
    (destination : Node)
    (member : message ∈ network destination) :
    message ∈ enqueueNoDup network newMessage destination := by
  unfold enqueueNoDup
  by_cases duplicate : newMessage ∈ network newMessage.destination
  · simpa [duplicate] using member
  · simp only [duplicate, ↓reduceIte]
    by_cases destinationEq : destination = newMessage.destination
    · subst destination
      simp [updateQueue, member]
    · simpa [updateQueue, Function.update, destinationEq] using member

/-- Enqueue-with-deduplication contains the message being enqueued. -/
theorem memEnqueueNoDupSelf
    (network : Node -> List (Message TxId))
    (message : Message TxId) :
    message ∈ enqueueNoDup network message message.destination := by
  unfold enqueueNoDup
  by_cases duplicate : message ∈ network message.destination
  · simpa [duplicate] using duplicate
  · simp [duplicate, updateQueue]

/-- Removing the first message from one source removes no other value. -/
theorem memSelectedOrRemaining
    {source : Node}
    {queue remaining : List (Message TxId)}
    {selected message : Message TxId}
    (taken :
      takeFirstFrom source queue = some (selected, remaining))
    (member : message ∈ queue) :
    message = selected \/ message ∈ remaining := by
  induction queue generalizing selected remaining with
  | nil =>
      simp [takeFirstFrom] at taken
  | cons head tail inductionHypothesis =>
      unfold takeFirstFrom at taken
      split at taken
      · simp at taken
        rcases taken with ⟨selectedEq, remainingEq⟩
        subst selected
        subst remaining
        simpa using member
      · split at taken
        · contradiction
        · rename_i selectedTail tailRemaining tailTaken
          simp at taken
          rcases taken with ⟨selectedEq, remainingEq⟩
          subst selected
          subst remaining
          simp at member
          rcases member with headEq | tailMember
          · exact Or.inr (by simp [headEq])
          · rcases inductionHypothesis tailTaken tailMember with
              selectedEq | remainingMember
            · exact Or.inl selectedEq
            · exact Or.inr (by simp [remainingMember])

/-! ## Core safety projections -/

/-- The explicit invariant implies the two core public safety properties. -/
theorem systemInductiveInvariantSafety
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    ConsensusSafety state := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  exact
    { committedLogsPrefix :=
        quorumLogCommittedLogsPrefix
          (invariantFactsQuorumLogFromCommitEvidence facts)
      committedFrontierIsSignature :=
        facts.committedFrontierIsSignature
      electionSafety :=
        voteHistoryElectionSafety
          facts.currentTermsPositive
          facts.leadersHaveElectionMajority
          facts.voteHistory }

/-- Log matching remains a separately exported supporting theorem. -/
theorem systemInductiveInvariantLogMatching
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    LogMatching state := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  exact invariantFactsLogMatchingFromCanonicalHistories facts

/-- Log-term monotonicity remains a separately exported supporting theorem. -/
theorem systemInductiveInvariantMonoLog
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    MonoLog state := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  exact invariantFactsMonoLogFromCanonicalHistories facts

/-- TLA-style state-local leader completeness is a separate export. -/
theorem systemInductiveInvariantLeaderCompleteness
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    LeaderCompleteness state := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  exact invariantFactsLeaderCompletenessFromCommitEvidence facts

/-- Every positive committed frontier in the invariant points to a signature. -/
theorem systemInductiveInvariantCommittedFrontierIsSignature
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    CommittedFrontierIsSignature state :=
  (systemInductiveInvariantSafety invariant).committedFrontierIsSignature

/-! ## Initial state -/

/-- Empty initial commits and network queues need no commit evidence. -/
theorem initialCommitEvidenceFacts
    (appendHistory :
      AppendEntriesRequest TxId -> List (Entry TxId)) :
    Exists fun nodeEvidence : NodeCommitEvidence TxId =>
      Exists fun requestEvidence : RequestCommitEvidence TxId =>
        CommitEvidenceFacts
          (initialState : State TxId)
          appendHistory nodeEvidence requestEvidence := by
  let nodeEvidence : NodeCommitEvidence TxId :=
    fun _ => none
  let requestEvidence : RequestCommitEvidence TxId :=
    fun _ => none
  refine ⟨nodeEvidence, requestEvidence, ?_⟩
  constructor
  · simp [nodeEvidence]
  · intro node positive
    simp [initialState, initialNodeState] at positive
  · intro destination request member
    simp [initialState] at member
  · intro destination request member
    simp [initialState] at member

/-- The proof-only maps are empty in the deterministic initial state. -/
theorem initialSystemInductiveInvariant :
    SystemInductiveInvariant (initialState : State TxId) := by
  let votes : VoteHistory := fun _ _ => none
  let appendHistory : AppendEntriesRequest TxId -> List (Entry TxId) :=
    fun _ => []
  let responseHistory : AppendEntriesResponse -> List (Entry TxId) :=
    fun _ => []
  let voteRequestHistory : RequestVoteRequest -> List (Entry TxId) :=
    fun _ => []
  let voteCandidateHistory : RequestVoteResponse -> List (Entry TxId) :=
    fun _ => []
  let voteVoterHistory : RequestVoteResponse -> List (Entry TxId) :=
    fun _ => []
  refine
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · simp [CommitIndicesBounded, initialState, initialNodeState]
  · intro node positive
    simp [initialState, initialNodeState] at positive
  · simp [
      CurrentTermsPositive, initialState, initialNodeState, TERM_ONE
    ]
  · simp [
      EntriesDoNotExceedCurrentTerm,
      initialState, initialNodeState
    ]
  · intro node candidate
    by_cases nodeInitial : node = INITIAL_LEADER <;>
      simp [
        initialState, initialNodeState, nodeInitial
      ] at candidate
  · intro node leader
    left
    simpa [initialState, initialNodeState] using leader
  · intro leader role peer
    simp [initialState, initialNodeState]
  · constructor
    · intro voter
      rfl
    · intro voter
      rfl
    · intro voter term future
      rfl
    · intro candidate voter active member
      simp [initialState, initialNodeState] at member
  · constructor
    · simp [initialState]
    · simp [initialState]
    · simp [initialState]
    · simp [initialState]
    · simp [initialState]
  · let owners : TermOwners :=
      fun term => if term = TERM_ONE then some INITIAL_LEADER else none
    let canonicalHistory : Nat -> List (Entry TxId) :=
      fun _ => []
    let elections : ElectionHistory TxId :=
      fun _ => none
    rcases initialCommitEvidenceFacts appendHistory with
      ⟨nodeEvidence, requestEvidence, evidenceFacts⟩
    have noKnown :
        forall evidence supportedPrefix,
          KnownCommitEvidence
              initialState appendHistory nodeEvidence requestEvidence
              evidence supportedPrefix ->
            False := by
      intro evidence supportedPrefix known
      rcases known with nodeKnown | requestKnown
      · rcases nodeKnown with ⟨node, positive, _, _⟩
        simp [initialState, initialNodeState] at positive
      · rcases requestKnown with
          ⟨destination, request, member, _⟩
        simp [initialState] at member
    have prospectiveFacts :
        ProspectiveCommitEvidenceFacts
          initialState appendHistory nodeEvidence requestEvidence elections := by
      constructor
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
    refine
      ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    constructor
    · simp [owners]
    · intro leader role
      by_cases leaderInitial : leader = INITIAL_LEADER
      · subst leader
        simp [owners, initialState, initialNodeState]
      · simp [
          initialState, initialNodeState, leaderInitial
        ] at role
    · intro node index entry found
      simp [initialState, initialNodeState, entryAt?] at found
    · intro destination request member
      simp [initialState] at member
    · intro leader role
      simp [
        canonicalHistory, initialState, initialNodeState
      ]
    · intro term index entry found
      simp [canonicalHistory, entryAt?] at found
    · intro term earlier later earlierEntry laterEntry order earlierFound
        laterFound
      simp [MonoHistory, canonicalHistory, entryAt?] at earlierFound
    · intro term owner owned
      simp [owners] at owned
      rcases owned with ⟨termEq, ownerEq⟩
      subst term
      subst owner
      simp [initialState, initialNodeState]
    · intro destination request member
      simp [initialState] at member
    · intro destination request member
      simp [initialState] at member
    · constructor
      · simp [elections]
      · intro term owner owned
        simp [owners] at owned
        exact Or.inl ⟨owned.1, owned.2.symm⟩
      all_goals simp [elections]
    · intro candidate voter active member
      simp [
        effectiveElectionVoters, queuedGrantedVote,
        initialState, initialNodeState
      ] at member
    · intro source index role current
      have impossible :
          termAt ([] : List (Entry TxId)) index = TERM_ONE := by
        simpa [initialState, initialNodeState] using current
      simp [termAt, entryAt?, TERM_ONE] at impossible
    · intro source index role current
      have impossible :
          termAt ([] : List (Entry TxId)) index = TERM_ONE := by
        simpa [initialState, initialNodeState] using current
      simp [termAt, entryAt?, TERM_ONE] at impossible
    · intro source index role current
      have impossible :
          termAt ([] : List (Entry TxId)) index = TERM_ONE := by
        simpa [initialState, initialNodeState] using current
      simp [termAt, entryAt?, TERM_ONE] at impossible
    · intro destination request member
      simp [initialState] at member
    · exact evidenceFacts
    · exact prospectiveFacts
  · intro candidate voter active member
    simp [
      effectiveElectionVoters, queuedGrantedVote,
      initialState, initialNodeState
    ] at member
  · let ackHistory : ProcessedAckHistory TxId :=
      fun _ _ => none
    refine ⟨ackHistory, ?_⟩
    constructor
    · simp [ackHistory]
    · intro leader role peer positive
      simp [initialState, initialNodeState] at positive
/-! ## Client append -/

/-- Proof-local action shape shared by transaction and signature appends. -/
inductive LeaderAppendProofAction (TxId : Type) where
  | clientRequest (node : Node) (content : EntryContent TxId)

/-- Append one current-term entry while applying the action-specific client set. -/
def leaderAppendState
    (state : State TxId)
    (node : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    State TxId :=
  let entry : Entry TxId :=
    { term := (state.nodes node).currentTerm
      content }
  { state with
    nodes :=
      updateNode state.nodes node
        { state.nodes node with
          log := (state.nodes node).log ++ [entry] }
    submittedTxIds }

@[simp]
theorem leaderAppendState_nodes_same
    (state : State TxId)
    (node : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    (leaderAppendState state node content submittedTxIds).nodes node =
      { state.nodes node with
        log :=
          (state.nodes node).log ++
            [{ term := (state.nodes node).currentTerm
               content }] } := by
  simp [leaderAppendState]

@[simp]
theorem leaderAppendState_nodes_of_ne
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId)
    (different : Not (candidate = node)) :
    (leaderAppendState state node content submittedTxIds).nodes candidate =
      state.nodes candidate := by
  simp [leaderAppendState, updateNode, Function.update, different]

@[simp]
theorem leaderAppendState_network
    (state : State TxId)
    (node : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    (leaderAppendState state node content submittedTxIds).network =
      state.network := by
  rfl

@[simp]
theorem leaderAppendState_role
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).role =
      (state.nodes candidate).role := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

@[simp]
theorem leaderAppendState_currentTerm
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).currentTerm =
      (state.nodes candidate).currentTerm := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

@[simp]
theorem leaderAppendState_commitIndex
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).commitIndex =
      (state.nodes candidate).commitIndex := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

@[simp]
theorem leaderAppendState_sentIndex
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).sentIndex =
      (state.nodes candidate).sentIndex := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

@[simp]
theorem leaderAppendState_matchIndex
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).matchIndex =
      (state.nodes candidate).matchIndex := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

@[simp]
theorem leaderAppendState_votedFor
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).votedFor =
      (state.nodes candidate).votedFor := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

@[simp]
theorem leaderAppendState_votesGranted
    (state : State TxId)
    (node candidate : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId) :
    ((leaderAppendState state node content submittedTxIds).nodes candidate).votesGranted =
      (state.nodes candidate).votesGranted := by
  by_cases same : candidate = node
  · subst candidate
    simp
  · simp [leaderAppendState_nodes_of_ne state node candidate
      content submittedTxIds same]

/-- A leader append does not change any node's committed prefix. -/
theorem leaderAppendCommittedLogUnchanged
    (state : State TxId)
    (node : Node)
    (content : EntryContent TxId)
    (submittedTxIds : Finset TxId)
    (bounded : CommitIndicesBounded state) :
    forall candidate,
      ((leaderAppendState state node content submittedTxIds).nodes
        candidate).committedLog =
        (state.nodes candidate).committedLog := by
  intro candidate
  by_cases candidateEq : candidate = node
  · subst candidate
    simp only [
      leaderAppendState, updateNode_same,
      NodeState.committedLog
    ]
    rw [List.take_append_of_le_length (bounded node)]
  · simp [
    leaderAppendState, updateNode, Function.update,
      candidateEq
    ]

/-- Appending any current-term leader entry preserves the arbitrary-term facts. -/
theorem leaderAppendPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (txId : EntryContent TxId)
    (submittedTxIds : Finset TxId)
    (invariant : SystemInductiveInvariant state)
    (leaderRole : (state.nodes node).role = .leader) :
    SystemInductiveInvariant
      (leaderAppendState state node txId submittedTxIds) := by
  let next :
      State TxId -> LeaderAppendProofAction TxId -> State TxId :=
    fun _ _ => leaderAppendState state node txId submittedTxIds
  let enabled :
      (state.nodes node).role = .leader /\ True :=
    ⟨leaderRole, trivial⟩
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  have monoLog := invariantFactsMonoLogFromCanonicalHistories facts
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  have oldCandidateTermNot :
      CandidateTermNotInLogs state :=
    termOwnershipCandidateTermNotInLogs
      candidatesAboveBootstrap facts.grantedVoteSnapshots
        ownership electionFacts
  let entry : Entry TxId :=
    { term := (state.nodes node).currentTerm
      content := txId }
  let newCanonicalHistory : Nat -> List (Entry TxId) :=
    Function.update canonicalHistory entry.term
      ((state.nodes node).log ++ [entry])
  have committedEq :=
    leaderAppendCommittedLogUnchanged
      state node txId submittedTxIds facts.commitIndicesBounded
  have oldElectionSafety :
      ElectionSafety state :=
    voteHistoryElectionSafety
      facts.currentTermsPositive
      facts.leadersHaveElectionMajority
      facts.voteHistory
  have roleEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).role =
          (state.nodes candidate).role := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have currentTermEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have commitIndexEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have sentEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have matchEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have votedForEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have votesGrantedEq :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases candidateEq : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, candidateEq
      ]
  have effectiveElectionVotersEq :
        forall candidate,
          effectiveElectionVoters
              (next state (.clientRequest node txId)) candidate =
            effectiveElectionVoters state candidate := by
      intro candidate
      ext voter
      simp only [
        effectiveElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      constructor
      · rintro (processed | queued)
        · exact Or.inl (by simpa [votesGrantedEq] using processed)
        · right
          rcases queued with
            ⟨response, member, granted, responseTerm,
              responseSource, responseDestination⟩
          exact
            ⟨response, by simpa [next, CCFRaft.next] using member,
              granted, by simpa [currentTermEq] using responseTerm,
              responseSource, responseDestination⟩
      · rintro (processed | queued)
        · exact Or.inl (by simpa [votesGrantedEq] using processed)
        · right
          rcases queued with
            ⟨response, member, granted, responseTerm,
              responseSource, responseDestination⟩
          exact
            ⟨response, by simpa [next, CCFRaft.next] using member,
              granted, by simpa [currentTermEq] using responseTerm,
              responseSource, responseDestination⟩
  have effectiveElectionMajorityEq :
        forall candidate,
          hasEffectiveElectionMajority
              (next state (.clientRequest node txId)) candidate ↔
            hasEffectiveElectionMajority state candidate := by
      intro candidate
      simp only [
        hasEffectiveElectionMajority,
        effectiveElectionVotersEq
      ]
  have logEqNode :
      ((leaderAppendState state node txId submittedTxIds).nodes node).log =
        (state.nodes node).log ++ [entry] := by
    simp [entry]
  have logEqOther :
      forall candidate,
        Not (candidate = node) ->
        ((leaderAppendState state node txId submittedTxIds).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    intro candidateNe
    simp [leaderAppendState_nodes_of_ne
      state node candidate txId submittedTxIds candidateNe]
  have monoAfterNode :
      MonoHistory
        ((leaderAppendState state node txId submittedTxIds).nodes node).log := by
    intro earlier later earlierEntry laterEntry order earlierFound laterFound
    rw [logEqNode] at earlierFound laterFound
    have laterClassified :=
      entryAtAppendSingleton laterFound
    rcases laterClassified with laterOld | laterNew
    · have earlierClassified :=
        entryAtAppendSingleton earlierFound
      rcases earlierClassified with earlierOld | earlierNew
      · exact
          monoLog node earlier later earlierEntry laterEntry
            order earlierOld.2 laterOld.2
      · omega
    · have earlierClassified :=
        entryAtAppendSingleton earlierFound
      rcases earlierClassified with earlierOld | earlierNew
      · have member := CCFRaft.entryAt_mem earlierOld.2
        have bounded :=
          facts.entriesDoNotExceedCurrentTerm node earlierEntry member
        simpa [laterNew.2, entry] using bounded
      · omega
  have potentialElectionVotersSubset :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).role =
            .candidate ->
          potentialElectionVoters
              (next state (.clientRequest node txId)) candidate ⊆
            potentialElectionVoters state candidate := by
    intro candidate role voter member
    have candidateNe : Not (candidate = node) := by
      intro same
      subst candidate
      have oldRole :
          (state.nodes node).role = .candidate := by
        simpa [roleEq] using role
      exact Role.noConfusion (oldRole.symm.trans enabled.1)
    simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at member ⊢
    rcases member with effective | eligible
    · exact Or.inl (by simpa [effectiveElectionVotersEq] using effective)
    · right
      unfold currentlyEligibleElectionVoter at eligible ⊢
      have requestEq :
          makeRequestVoteRequest
              (next state (.clientRequest node txId)) candidate voter =
            makeRequestVoteRequest state candidate voter := by
        simp [
          makeRequestVoteRequest, next, CCFRaft.next,
          updateNode, Function.update, candidateNe
        ]
      have termAccepted :
          (makeRequestVoteRequest state candidate voter).term =
            (state.nodes voter).currentTerm := by
        simpa [requestEq, currentTermEq] using eligible.1
      have upToDateAfter :
          voteLogUpToDate
            ((next state (.clientRequest node txId)).nodes voter)
            (makeRequestVoteRequest state candidate voter) := by
        simpa [requestEq] using eligible.2.1
      change
        voteLogUpToDate
          ((leaderAppendState state node txId submittedTxIds).nodes voter)
          (makeRequestVoteRequest state candidate voter)
        at upToDateAfter
      refine ⟨termAccepted, ?_, by simpa [votedForEq] using eligible.2.2⟩
      by_cases voterEq : voter = node
      · subst voter
        exact
          voteLogUpToDateOfVoterPrefix
            (List.prefix_append (state.nodes node).log [entry])
            (by simpa [logEqNode] using monoAfterNode)
            (state.nodes node)
            ((next state (.clientRequest node txId)).nodes node)
            (makeRequestVoteRequest state candidate node)
            rfl logEqNode upToDateAfter
      · simpa [logEqOther voter voterEq, voteLogUpToDate] using
          upToDateAfter
  have potentialElectionMajorityBack :
      forall candidate,
        ((next state (.clientRequest node txId)).nodes candidate).role =
            .candidate ->
          hasPotentialElectionMajority
              (next state (.clientRequest node txId)) candidate ->
            hasPotentialElectionMajority state candidate := by
    intro candidate role majority
    exact
      potentialElectionMajorityOfSubset
        (potentialElectionVotersSubset candidate role) majority
  have preserveCanonicalAgreement :
      forall (history : List (Entry TxId)) index value,
        entryAt? (canonicalHistory value.term) index = some value /\
          history.take index =
            (canonicalHistory value.term).take index ->
        entryAt? (newCanonicalHistory value.term) index = some value /\
          history.take index =
            (newCanonicalHistory value.term).take index := by
    intro history index value agreement
    by_cases sameTerm : value.term = entry.term
    · have oldCanonical :
          canonicalHistory value.term = (state.nodes node).log := by
        rw [sameTerm]
        exact ownership.activeLeaderHistory node enabled.1
      have oldFound :
          entryAt? (state.nodes node).log index = some value := by
        simpa [oldCanonical] using agreement.1
      have oldPrefixNew :
          (state.nodes node).log <+:
            (state.nodes node).log ++ [entry] :=
        List.prefix_append _ _
      have newFound :=
        CCFRaft.entryAt_of_prefix oldPrefixNew oldFound
      have takesEqual :=
        CCFRaft.takeEqOfPrefix oldPrefixNew
          (entryAtSomeIndexBound oldFound)
      constructor
      · simpa [
          newCanonicalHistory, Function.update, sameTerm
        ] using newFound
      · calc
          history.take index =
              (canonicalHistory value.term).take index :=
            agreement.2
          _ = (state.nodes node).log.take index := by rw [oldCanonical]
          _ =
              ((state.nodes node).log ++ [entry]).take index :=
            takesEqual
          _ = (newCanonicalHistory value.term).take index := by
            simp [
              newCanonicalHistory, Function.update, sameTerm
            ]
    · simpa [
        newCanonicalHistory, Function.update, sameTerm
      ] using agreement
  have effectiveAckersSubset :
      forall leader index,
        (state.nodes leader).role = .leader ->
        effectiveAckers
            (next state (.clientRequest node txId))
            responseHistory leader index ⊆
          effectiveAckers state responseHistory leader index := by
    intro leader index leaderRole peer member
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at member ⊢
    rcases member with self | matched | queued
    · exact Or.inl self
    · right
      left
      rw [matchEq] at matched
      exact matched
    · right
      right
      rcases queued with
        ⟨response, responseMember, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      have oldMember :
          Message.appendEntriesResponse response ∈
            state.network leader := by
        simpa [next, CCFRaft.next] using responseMember
      have snapshot :=
        facts.networkHistory.appendResponse leader response oldMember
      have oldTerm :
          response.term = (state.nodes leader).currentTerm := by
        rw [currentTermEq] at responseTerm
        exact responseTerm
      have oldTermAtDestination :
          response.term =
            (state.nodes response.destination).currentTerm := by
        simpa [responseDestination] using oldTerm
      have oldCovered :=
        ((snapshot success).2.2 oldTermAtDestination).2
      rw [responseDestination] at oldCovered
      exact
        ⟨response, oldMember, success, oldTerm,
          responseSource, responseDestination, lastIndex, oldCovered⟩
  have effectiveMajorityOld :
      forall leader index,
        (state.nodes leader).role = .leader ->
        hasEffectiveMajorityAt
            (next state (.clientRequest node txId))
            responseHistory leader index ->
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index role majority
    have cardBound :=
      Finset.card_le_card (effectiveAckersSubset leader index role)
    unfold hasEffectiveMajorityAt at majority ⊢
    omega
  have beyondIndexSelf :
      forall index voter,
        (state.nodes node).log.length < index ->
        voter ∈
            effectiveAckers
              (next state (.clientRequest node txId))
              responseHistory node index ->
          voter = node := by
    intro index voter beyond member
    have oldMember :=
      effectiveAckersSubset node index enabled.1 member
    have onlySelf :=
      effectiveAckersBeyondLeaderLog
        facts.leaderProgressBounded
        facts.networkHistory.appendResponse
        enabled.1 beyond
    rw [onlySelf] at oldMember
    simpa using oldMember
  have signatureBackNode :
      forall index,
        index <= (state.nodes node).log.length ->
        isSignatureAt
            ((next state (.clientRequest node txId)).nodes node).log index =
          true ->
        isSignatureAt (state.nodes node).log index = true := by
    intro index within signature
    rw [logEqNode] at signature
    rcases isSignatureAtTrue signature with
      ⟨foundEntry, found, foundSignature⟩
    rcases entryAtAppendSingleton found with old | appended
    · simp [isSignatureAt, old.2, foundSignature]
    · omega
  refine
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro candidate
    rw [commitIndexEq]
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [logEqNode, List.length_append]
      simp only [List.length_singleton]
      have bounded := facts.commitIndicesBounded node
      omega
    · rw [logEqOther candidate candidateEq]
      exact facts.commitIndicesBounded candidate
  · intro candidate positive
    have oldPositive :
        0 < (state.nodes candidate).commitIndex := by
      simpa [commitIndexEq] using positive
    have oldSignature :=
      facts.committedFrontierIsSignature candidate oldPositive
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [commitIndexEq, logEqNode]
      exact
        isSignatureAt_of_prefix
          (List.prefix_append (state.nodes node).log [entry])
          oldSignature
    · rw [
        commitIndexEq,
        logEqOther candidate candidateEq
      ]
      exact oldSignature
  · intro candidate
    rw [currentTermEq]
    exact facts.currentTermsPositive candidate
  · intro candidate value member
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [logEqNode] at member
      simp at member
      rcases member with oldMember | newMember
      · rw [currentTermEq]
        exact facts.entriesDoNotExceedCurrentTerm node value oldMember
      · subst value
        simp [entry, currentTermEq]
    · have oldMember :
          value ∈ (state.nodes candidate).log := by
        rw [logEqOther candidate candidateEq] at member
        exact member
      simpa [currentTermEq] using
        facts.entriesDoNotExceedCurrentTerm candidate value oldMember
  · intro candidate role
    rw [roleEq] at role
    have oldSelf := facts.candidatesSelfVote candidate role
    rw [votedForEq, votesGrantedEq]
    exact oldSelf
  · intro leader role
    rw [roleEq] at role
    have oldMajority := facts.leadersHaveElectionMajority leader role
    rw [currentTermEq]
    rcases oldMajority with bootstrap | elected
    · exact Or.inl bootstrap
    · right
      unfold hasElectionMajority at elected ⊢
      rw [votesGrantedEq]
      exact elected
  · intro leader role peer
    rw [roleEq] at role
    have oldProgress := facts.leaderProgressBounded leader role peer
    rw [sentEq, matchEq]
    by_cases leaderEq : leader = node
    · subst leader
      rw [logEqNode, List.length_append]
      simp only [List.length_singleton]
      omega
    · rw [logEqOther leader leaderEq]
      exact oldProgress
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [votedForEq]
      rw [currentTermEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      rw [currentTermEq] at future
      exact future
    · intro candidate voter active member
      rw [currentTermEq]
      apply facts.voteHistory.counted candidate voter
      · rw [roleEq] at active
        exact active
      · rw [votesGrantedEq] at member
        exact member
  · constructor
    · intro destination message member
      exact facts.networkHistory.addressed destination message
        (by simpa [next, CCFRaft.next] using member)
    · intro destination request member
      have old :=
        facts.networkHistory.appendRequest destination request
          (by simpa [next, CCFRaft.next] using member)
      exact
        ⟨old.1, old.2.1, old.2.2.1,
          by
            unfold RequestCommitStillPresent at old ⊢
            exact old.2.2.2.trans
              (by
                simpa [committedEq] using
                  (prefixRefl
                    (state.nodes request.source).committedLog))⟩
    · intro destination response member
      have oldMember :
          Message.appendEntriesResponse response ∈
            state.network destination := by
        simpa [next, CCFRaft.next] using member
      have old :=
        facts.networkHistory.appendResponse destination response oldMember
      intro success
      rcases old success with ⟨bounded, termBound, stable⟩
      refine
        ⟨bounded, by simpa [currentTermEq] using termBound, ?_⟩
      intro sameTerm
      have oldTerm :
          response.term =
            (state.nodes response.destination).currentTerm := by
        rw [currentTermEq] at sameTerm
        exact sameTerm
      rcases stable oldTerm with ⟨oldRole, covered⟩
      constructor
      · rw [roleEq]
        exact oldRole
      by_cases destinationEq : response.destination = node
      · rw [destinationEq] at covered ⊢
        rw [logEqNode]
        exact covered.trans (List.prefix_append _ _)
      · rw [logEqOther response.destination destinationEq]
        exact covered
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request
            (by simpa [next, CCFRaft.next] using member) with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine
        ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap,
          by simpa [currentTermEq] using termBound, ?_⟩
      intro sameTerm active
      have oldSameTerm :
          request.term =
            (state.nodes request.source).currentTerm := by
        simpa [currentTermEq] using sameTerm
      have oldActive :
          (state.nodes request.source).role = .candidate \/
            (state.nodes request.source).role = .leader := by
        simpa [roleEq] using active
      have oldPrefix := activePrefix oldSameTerm oldActive
      by_cases sourceEq : request.source = node
      · have oldPrefixNode :
            voteRequestHistory request <+: (state.nodes node).log := by
          simpa [sourceEq] using oldPrefix
        rw [sourceEq, logEqNode]
        exact oldPrefixNode.trans (List.prefix_append _ _)
      · rw [logEqOther request.source sourceEq]
        exact oldPrefix
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse destination response
            (by simpa [next, CCFRaft.next] using member) granted with
        ⟨termBound, recorded, upToDate⟩
      exact
        ⟨by simpa [currentTermEq] using termBound,
          recorded,
          by simpa [voteLogUpToDate] using upToDate⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (next state (.clientRequest node txId))
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
      state (next state (.clientRequest node txId))
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitIndexEq committedEq
    · intro candidate
      exact Nat.le_of_eq (currentTermEq candidate).symm
    · intro destination request member
      simpa [next, CCFRaft.next] using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (next state (.clientRequest node txId))
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (next state (.clientRequest node txId))
        appendHistory appendHistory
        nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (next state (.clientRequest node txId))
            appendHistory
            nodeEvidence requestEvidence
            commitIndexEq committedEq
            (fun destination request member => by
              simpa [next, CCFRaft.next] using member)
            known
    · intro member
      by_cases same : member = node
      · subst member
        rw [logEqNode]
        exact List.prefix_append _ _
      · rw [logEqOther member same]
    · intro evidence supportedPrefix destination request known queued sameTerm
      left
      exact
        ⟨by simpa [next, CCFRaft.next] using queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        have oldRole :
            (state.nodes node).role = .candidate := by
          simpa [roleEq] using role
        exact Role.noConfusion (oldRole.symm.trans enabled.1)
      left
      refine
        ⟨by simpa [roleEq] using role,
          by simpa [currentTermEq] using newer,
          ?_, ?_, ?_⟩
      · intro entry entryMember
        have afterMember :
            entry ∈
              ((next state (.clientRequest node txId)).nodes candidate).log := by
          rw [logEqOther candidate candidateNe]
          exact entryMember
        have afterBound := entriesBefore entry afterMember
        simpa [currentTermEq] using afterBound
      · simp only [
          relaxedElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ] at relaxed ⊢
        rcases relaxed with effective | upToDate
        · exact Or.inl
            (by simpa [effectiveElectionVotersEq] using effective)
        · right
          refine
            ⟨by simpa [currentTermEq] using upToDate.1, ?_⟩
          by_cases memberEq : member = node
          · subst member
            apply
              voteLogUpToDateOfVoterPrefix
                (List.prefix_append (state.nodes node).log [entry])
                (by simpa [logEqNode] using monoAfterNode)
                (state.nodes node)
                ((next state (.clientRequest node txId)).nodes node)
                (makeRequestVoteRequest state candidate candidate)
                rfl logEqNode
            simpa [
              makeRequestVoteRequest, next, CCFRaft.next,
              updateNode, Function.update, candidateNe
            ] using upToDate.2
          · simpa [
              makeRequestVoteRequest, next, CCFRaft.next,
              updateNode, Function.update,
              candidateNe, memberEq,
              voteLogUpToDate
            ] using upToDate.2
      · rw [logEqOther candidate candidateNe]
  · refine
      ⟨owners, newCanonicalHistory, elections,
        nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      rw [currentTermEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro candidate index value found
      by_cases candidateEq : candidate = node
      · subst candidate
        have classified :=
          entryAtAppendSingleton
            (by simpa [logEqNode] using found)
        rcases classified with old | new
        · have preserved :=
            preserveCanonicalAgreement
              (state.nodes node).log index value
                (ownership.logEntryAgreement node index value old.2)
          have takesEqual :=
            CCFRaft.takeEqOfPrefix
              (List.prefix_append (state.nodes node).log [entry]) old.1
          exact
            ⟨preserved.1,
              by
                rw [logEqNode]
                exact takesEqual.symm.trans preserved.2⟩
        · rcases new with ⟨indexEq, valueEq⟩
          subst index
          subst value
          constructor
          · simpa [
              newCanonicalHistory, Function.update, entry,
              logEqNode
            ] using found
          · simp [
              newCanonicalHistory, Function.update, entry,
              logEqNode
            ]
      · have oldFound :
            entryAt? (state.nodes candidate).log index = some value := by
          rw [logEqOther candidate candidateEq] at found
          exact found
        rcases
            preserveCanonicalAgreement
              (state.nodes candidate).log index value
                (ownership.logEntryAgreement
                  candidate index value oldFound) with
          ⟨canonicalFound, agreed⟩
        exact
          ⟨canonicalFound,
            by
              rw [logEqOther candidate candidateEq]
              exact agreed⟩
    · intro destination request member index value found
      exact
        preserveCanonicalAgreement
          (appendHistory request) index value
            (ownership.queuedHistoryEntryAgreement
              destination request
                (by simpa [next, CCFRaft.next] using member)
                index value found)
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        rw [currentTermEq node, logEqNode]
        simp [newCanonicalHistory, entry]
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleEq] using role
        have termNe :
            Not (
              (state.nodes leader).currentTerm = entry.term) := by
          intro sameTerm
          have sameLeaderTerm :
              (state.nodes node).currentTerm =
                (state.nodes leader).currentTerm := by
            simpa [entry] using sameTerm.symm
          exact leaderEq
            (oldElectionSafety
              node leader enabled.1 oldRole sameLeaderTerm).symm
        have oldHistory :=
          ownership.activeLeaderHistory leader oldRole
        simpa [
          currentTermEq, logEqOther leader leaderEq,
          newCanonicalHistory, Function.update, termNe
        ] using oldHistory
    · intro term index value found
      by_cases termEq : term = entry.term
      · subst term
        have classified :=
          entryAtAppendSingleton
            (by simpa [
              newCanonicalHistory, Function.update
            ] using found)
        rcases classified with old | new
        · exact
            termOwnershipLogEntryOwner ownership
              (entryAtSomeMember old.2)
        · rcases new with ⟨_, valueEq⟩
          subst value
          exact
            ⟨node, ownership.activeLeader node enabled.1⟩
      · exact
          ownership.canonicalEntryOwner term index value
            (by simpa [
              newCanonicalHistory, Function.update, termEq
            ] using found)
    · intro term
      by_cases termEq : term = entry.term
      · subst term
        intro earlier later earlierEntry laterEntry order
            earlierFound laterFound
        have earlierInExtended :
            entryAt? ((state.nodes node).log ++ [entry]) earlier =
              some earlierEntry := by
          simpa [
            newCanonicalHistory, Function.update
          ] using earlierFound
        have laterInExtended :
            entryAt? ((state.nodes node).log ++ [entry]) later =
              some laterEntry := by
          simpa [
            newCanonicalHistory, Function.update
          ] using laterFound
        rcases entryAtAppendSingleton laterInExtended with old | new
        · have earlierWithin :
              earlier <= (state.nodes node).log.length := by
            omega
          have earlierOld :
              entryAt? (state.nodes node).log earlier =
                some earlierEntry := by
            rw [← entryAtAppend_of_le_length earlierWithin]
            exact earlierInExtended
          exact
            monoLog
              node earlier later earlierEntry laterEntry
                order earlierOld old.2
        · rcases new with ⟨laterEq, laterEntryEq⟩
          subst later
          subst laterEntry
          have earlierWithin :
              earlier <= (state.nodes node).log.length := by omega
          have earlierOld :
              entryAt? (state.nodes node).log earlier =
                some earlierEntry := by
            rw [← entryAtAppend_of_le_length earlierWithin]
            exact earlierInExtended
          exact
            facts.entriesDoNotExceedCurrentTerm
              node earlierEntry (entryAtSomeMember earlierOld)
      · simpa [
          newCanonicalHistory, Function.update, termEq
        ] using ownership.canonicalMonoLog term
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      constructor
      · simpa [currentTermEq] using bound
      · intro same
        have oldSame :
            term = (state.nodes owner).currentTerm := by
          simpa [currentTermEq] using same
        simpa [roleEq] using oldLeader oldSame
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa [next, CCFRaft.next] using member)
    · intro destination request member sameTerm leaderRole
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [next, CCFRaft.next] using member
      have oldSameTerm :
          request.term =
            (state.nodes request.source).currentTerm := by
        simpa [currentTermEq] using sameTerm
      have oldLeaderRole :
          (state.nodes request.source).role = .leader := by
        simpa [roleEq] using leaderRole
      have oldPrefix :=
        ownership.queuedActiveSourceHistory
          destination request oldMember oldSameTerm oldLeaderRole
      by_cases sourceEq : request.source = node
      · rw [sourceEq] at oldPrefix ⊢
        rw [logEqNode]
        exact oldPrefix.trans (List.prefix_append _ _)
      · rw [logEqOther request.source sourceEq]
        exact oldPrefix
    · apply
        electionHistoryFrame
          state (next state (.clientRequest node txId))
            votes votes canonicalHistory newCanonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        by_cases termEq : term = entry.term
        · subst term
          rw [ownership.activeLeaderHistory node enabled.1]
          simp [newCanonicalHistory, entry]
        · simpa [
            newCanonicalHistory, Function.update, termEq
          ] using prefixRefl (canonicalHistory term)
      · intro history canonical index value found
        exact
          preserveCanonicalAgreement history index value
            (canonical index value found)
    · apply
        grantedVoteCanonicalFrame
          state (next state (.clientRequest node txId))
            canonicalHistory newCanonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => currentTermEq candidate)
      · intro candidate active
        simpa [roleEq] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical index value found
        exact
          preserveCanonicalAgreement history index value
            (canonical index value found)
    · intro source index role current signature voter effective
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleEq] using role
      by_cases sourceEq : source = node
      · subst source
        by_cases oldIndex : index <= (state.nodes node).log.length
        · have oldCurrent :
              termAt (state.nodes node).log index =
                (state.nodes node).currentTerm := by
            rw [logEqNode] at current
            simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using
              current
          rcases
              ackerCurrentFacts node index oldRole oldCurrent
                (signatureBackNode index oldIndex signature) voter
                (effectiveAckersSubset node index oldRole effective) with
            retained | bad
          · left
            rw [logEqNode]
            have sourceTake :
                ((state.nodes node).log ++ [entry]).take index =
                  (state.nodes node).log.take index := by
              rw [List.take_append_of_le_length oldIndex]
            rw [sourceTake]
            by_cases voterEq : voter = node
            · subst voter
              simpa [logEqNode] using
                retained.trans (List.prefix_append _ _)
            · simpa [logEqOther voter voterEq] using retained
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
            exact
              ⟨badTerm, badRecord,
                by simpa [currentTermEq] using above,
                by simpa [currentTermEq] using bounded,
                recorded,
                by
                  rw [logEqNode]
                  simpa [
                    List.take_append_of_le_length oldIndex
                  ] using missing⟩
        · have voterEq : voter = node :=
            beyondIndexSelf index voter (by omega) effective
          subst voter
          exact Or.inl (List.take_prefix index _)
      · have oldCurrent :
            termAt (state.nodes source).log index =
              (state.nodes source).currentTerm := by
          simpa [
            logEqOther source sourceEq, currentTermEq
          ] using current
        rcases
            ackerCurrentFacts source index oldRole oldCurrent
              (by simpa [logEqOther source sourceEq] using signature) voter
              (effectiveAckersSubset source index oldRole effective) with
          retained | bad
        · left
          rw [logEqOther source sourceEq]
          by_cases voterEq : voter = node
          · subst voter
            rw [logEqNode]
            exact retained.trans (List.prefix_append _ _)
          · simpa [logEqOther voter voterEq] using retained
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact
            ⟨badTerm, badRecord,
              by simpa [currentTermEq] using above,
              by simpa [currentTermEq] using bounded,
              recorded,
              by simpa [logEqOther source sourceEq] using missing⟩
    · intro source index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleEq] using role
      by_cases sourceEq : source = node
      · subst source
        by_cases oldIndex : index <= (state.nodes node).log.length
        · have oldCurrent :
              termAt (state.nodes node).log index =
                (state.nodes node).currentTerm := by
            rw [logEqNode] at current
            simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using
              current
          rcases
              ackerVoteFacts node index oldRole oldCurrent
                (signatureBackNode index oldIndex signature)
                voter voteTerm candidate
                (effectiveAckersSubset node index oldRole effective)
                voted different (by simpa [currentTermEq] using newer) with
            retained | bad
          · exact Or.inl (by
              rw [logEqNode]
              simpa [
                List.take_append_of_le_length oldIndex
              ] using retained)
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
            exact
              ⟨badTerm, badRecord,
                by simpa [currentTermEq] using above,
                bounded, recorded,
                by
                  rw [logEqNode]
                  simpa [
                    List.take_append_of_le_length oldIndex
                  ] using missing⟩
        · have voterEq : voter = node :=
            beyondIndexSelf index voter (by omega) effective
          subst voter
          have future :
              votes node voteTerm = none :=
            facts.voteHistory.future node voteTerm
              (by simpa [currentTermEq] using newer)
          rw [future] at voted
          contradiction
      · have oldCurrent :
            termAt (state.nodes source).log index =
              (state.nodes source).currentTerm := by
          simpa [
            logEqOther source sourceEq, currentTermEq
          ] using current
        rcases
            ackerVoteFacts source index oldRole oldCurrent
              (by simpa [logEqOther source sourceEq] using signature)
              voter voteTerm candidate
              (effectiveAckersSubset source index oldRole effective)
              voted different (by simpa [currentTermEq] using newer) with
          retained | bad
        · exact Or.inl
            (by simpa [logEqOther source sourceEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact
            ⟨badTerm, badRecord,
              by simpa [currentTermEq] using above,
              bounded, recorded,
              by simpa [logEqOther source sourceEq] using missing⟩
    · intro source index role current signature term record voter
        recorded member effective newer
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleEq] using role
      by_cases sourceEq : source = node
      · subst source
        by_cases oldIndex : index <= (state.nodes node).log.length
        · have oldCurrent :
              termAt (state.nodes node).log index =
                (state.nodes node).currentTerm := by
            rw [logEqNode] at current
            simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using
              current
          rcases
              ackerElectionFacts node index oldRole oldCurrent
                (signatureBackNode index oldIndex signature)
                term record voter recorded member
                (effectiveAckersSubset node index oldRole effective)
                (by simpa [currentTermEq] using newer) with
            retained | bad
          · exact Or.inl (by
              rw [logEqNode]
              simpa [
                List.take_append_of_le_length oldIndex
              ] using retained)
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
            exact
              ⟨badTerm, badRecord,
                by simpa [currentTermEq] using above,
                below, badRecorded,
                by
                  rw [logEqNode]
                  simpa [
                    List.take_append_of_le_length oldIndex
                  ] using missing⟩
        · have voterEq : voter = node :=
            beyondIndexSelf index voter (by omega) effective
          subst voter
          have voterTerm :=
            electionHistoryVoterTerm
              facts.voteHistory electionFacts recorded member
          rw [currentTermEq] at newer
          omega
      · have oldCurrent :
            termAt (state.nodes source).log index =
              (state.nodes source).currentTerm := by
          simpa [
            logEqOther source sourceEq, currentTermEq
          ] using current
        rcases
            ackerElectionFacts source index oldRole oldCurrent
              (by simpa [logEqOther source sourceEq] using signature)
              term record voter recorded member
              (effectiveAckersSubset source index oldRole effective)
              (by simpa [currentTermEq] using newer) with
          retained | bad
        · exact Or.inl
            (by simpa [logEqOther source sourceEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
          exact
            ⟨badTerm, badRecord,
              by simpa [currentTermEq] using above,
              below, badRecorded,
              by simpa [logEqOther source sourceEq] using missing⟩
    · intro destination request queued record recorded
      exact
        electionQueuedFacts destination request
          (by simpa [next, CCFRaft.next] using queued)
          record recorded
  · intro candidate voter active member
    rw [currentTermEq candidate, currentTermEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    rcases
        facts.grantedVoteSnapshots candidate voter active oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · rcases snapshot with ⟨candidatePrefix, voterTerm, upToDate⟩
      refine ⟨recorded, Or.inr ⟨?_, voterTerm, upToDate⟩⟩
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [logEqNode]
        exact candidatePrefix.trans (List.prefix_append _ _)
      · simpa [logEqOther candidate candidateEq] using candidatePrefix
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      apply ackFacts.zero leader oldRole peer
      simpa [matchEq] using zero
    · intro leader role peer positive
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      have oldPositive :
          0 < (state.nodes leader).matchIndex peer := by
        simpa [matchEq] using positive
      rcases ackFacts.positive leader oldRole peer oldPositive with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      refine
        ⟨snapshot, stored,
          by simpa [currentTermEq] using snapshotTerm,
          by simpa [matchEq] using snapshotIndex,
          historyBound, ?_⟩
      by_cases leaderEq : leader = node
      · subst leader
        have matchBound :=
          (facts.leaderProgressBounded node enabled.1 peer).2
        have indexBound :
            snapshot.index <= (state.nodes node).log.length := by
          rw [snapshotIndex]
          exact matchBound
        rw [logEqNode]
        rw [List.take_append_of_le_length indexBound]
        exact agreed
      · simpa [logEqOther leader leaderEq] using agreed

/-! ## Executable leader append actions -/

/-- A client transaction append preserves the arbitrary-term invariant. -/
theorem clientRequestPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (txId : TxId)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.clientRequest node txId)) :
    SystemInductiveInvariant (next state (.clientRequest node txId)) := by
  simpa [leaderAppendState, next, CCFRaft.next] using
    leaderAppendPreservesSystemInductiveInvariant
      state node (.transaction txId)
        (insert txId state.submittedTxIds) invariant enabled.1

/-- Appending a current-term signature preserves the arbitrary-term invariant. -/
theorem signCommittableMessagesPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.signCommittableMessages node)) :
    SystemInductiveInvariant
      (next state (.signCommittableMessages node)) := by
  simpa [leaderAppendState, next, CCFRaft.next] using
    leaderAppendPreservesSystemInductiveInvariant
      state node .signature state.submittedTxIds invariant enabled.1

/-! ## RequestVote send -/

/-- Sending a vote request changes only the network and its proof snapshot. -/
theorem requestVotePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    SystemInductiveInvariant
      (next state (.requestVote source destination)) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  let request := makeRequestVoteRequest state source destination
  let voteRequestSnapshot :=
    (state.nodes source).log.take
      (maxCommittableIndex (state.nodes source).log)
  let newVoteRequestHistory :=
    Function.update voteRequestHistory request voteRequestSnapshot
  have sourceLastIndex :
      lastCommittableIndex (state.nodes source) =
        maxCommittableIndex (state.nodes source).log :=
    lastCommittableIndex_eq_maxCommittableIndex
      (state.nodes source)
      (facts.committedFrontierIsSignature source)
  have sourceLastTerm :
      lastCommittableTerm (state.nodes source) =
        maxCommittableTerm (state.nodes source).log :=
    lastCommittableTerm_eq_maxCommittableTerm
      (state.nodes source)
      (facts.committedFrontierIsSignature source)
  have snapshotLength :
      voteRequestSnapshot.length =
        maxCommittableIndex (state.nodes source).log := by
    simp [
      voteRequestSnapshot,
      Nat.min_eq_left
        (maxCommittableIndexBounded (state.nodes source).log)
    ]
  have snapshotTerm :
      termAt voteRequestSnapshot voteRequestSnapshot.length =
        maxCommittableTerm (state.nodes source).log := by
    rw [snapshotLength]
    exact
      (termAtTakeOfLe
        (log := (state.nodes source).log)
        (index := maxCommittableIndex (state.nodes source).log)
        (count := maxCommittableIndex (state.nodes source).log)
        le_rfl).trans rfl
  have snapshotCommittable :
      maxCommittableIndex voteRequestSnapshot =
        voteRequestSnapshot.length := by
    rw [snapshotLength]
    exact maxCommittableIndexTakeMax (state.nodes source).log
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers
            (next state (.requestVote source destination))
            responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by
          simpa [next, CCFRaft.next] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        have oldMember :
            Message.appendEntriesResponse response ∈
              state.network leader := by
          rcases
              memEnqueueNoDup
                state.network (.requestVoteRequest request)
                  (.appendEntriesResponse response) leader
                  (by simpa [next, CCFRaft.next, request] using member) with
            old | new
          · exact old
          · simp at new
        exact
          ⟨response, oldMember, success,
            by simpa [next, CCFRaft.next] using term,
            sourceEq, destinationEq, lastIndex,
            by simpa [next, CCFRaft.next] using covered⟩
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by
          simpa [next, CCFRaft.next] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        refine
          ⟨response, ?_, success,
            by simpa [next, CCFRaft.next] using term,
            sourceEq, destinationEq, lastIndex,
            by simpa [next, CCFRaft.next] using covered⟩
        simpa [next, CCFRaft.next, request] using
          memEnqueueNoDupOfMem
            state.network (.requestVoteRequest request)
              (.appendEntriesResponse response) leader member
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt
            (next state (.requestVote source destination))
            responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    simp only [hasEffectiveMajorityAt, effectiveAckersEq]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (next state (.requestVote source destination)) candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (processed | queued)
      · exact Or.inl (by simpa [next, CCFRaft.next] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        have oldMember :
            Message.requestVoteResponse response ∈
              state.network candidate := by
          rcases
              memEnqueueNoDup
                state.network (.requestVoteRequest request)
                  (.requestVoteResponse response) candidate
                  (by simpa [next, CCFRaft.next, request] using member) with
            old | new
          · exact old
          · simp at new
        exact
          ⟨response, oldMember, granted,
            by simpa [next, CCFRaft.next] using responseTerm,
            responseSource, responseDestination⟩
    · rintro (processed | queued)
      · exact Or.inl (by simpa [next, CCFRaft.next] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        refine
          ⟨response, ?_, granted,
            by simpa [next, CCFRaft.next] using responseTerm,
            responseSource, responseDestination⟩
        simpa [next, CCFRaft.next, request] using
          memEnqueueNoDupOfMem
            state.network (.requestVoteRequest request)
              (.requestVoteResponse response) candidate member
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority
            (next state (.requestVote source destination)) candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (next state (.requestVote source destination)) candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (effective | eligible)
      · exact Or.inl (by
          rw [effectiveElectionVotersEq] at effective
          exact effective)
      · right
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          next, CCFRaft.next,
          voteLogUpToDate
        ] using eligible
    · rintro (effective | eligible)
      · exact Or.inl (by
          rw [effectiveElectionVotersEq]
          exact effective)
      · right
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          next, CCFRaft.next,
          voteLogUpToDate
        ] using eligible
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority
            (next state (.requestVote source destination)) candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq
    ]
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (next state (.requestVote source destination))
        votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by
          simpa [next, CCFRaft.next] using role)
        (fun leader _ => by simp [next, CCFRaft.next])
        (fun leader => by simp [next, CCFRaft.next])
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun node => Nat.le_of_eq (by simp [next, CCFRaft.next]))
        (fun _ _ _ voted _ => voted)
  refine
    ⟨votes, appendHistory, responseHistory,
      newVoteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · simpa [next, CCFRaft.next] using facts.commitIndicesBounded
  · simpa [next, CCFRaft.next] using
      facts.committedFrontierIsSignature
  · simpa [next, CCFRaft.next] using facts.currentTermsPositive
  · simpa [next, CCFRaft.next] using facts.entriesDoNotExceedCurrentTerm
  · simpa [next, CCFRaft.next] using facts.candidatesSelfVote
  · simpa [next, CCFRaft.next] using facts.leadersHaveElectionMajority
  · simpa [next, CCFRaft.next] using facts.leaderProgressBounded
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [next, CCFRaft.next] using facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      simpa [next, CCFRaft.next] using future
    · intro candidate voter active member
      apply facts.voteHistory.counted candidate voter
      · simpa [next, CCFRaft.next] using active
      · simpa [next, CCFRaft.next] using member
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteRequest request)
              message queuedDestination
              (by simpa [next, CCFRaft.next, request] using member) with
        old | new
      · exact facts.networkHistory.addressed queuedDestination message old
      · rcases new with ⟨destinationEq, messageEq⟩
        subst message
        simpa [request, makeRequestVoteRequest] using destinationEq.symm
    · intro queuedDestination queuedRequest member
      have old :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest) queuedDestination
                (by simpa [next, CCFRaft.next, request] using member) with
          old | new
        · exact old
        · simp at new
      simpa [next, CCFRaft.next] using
        facts.networkHistory.appendRequest
          queuedDestination queuedRequest old
    · intro queuedDestination response member
      have old :
          Message.appendEntriesResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesResponse response) queuedDestination
                (by simpa [next, CCFRaft.next, request] using member) with
          old | new
        · exact old
        · simp at new
      exact
        facts.networkHistory.appendResponse
          queuedDestination response old
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteRequest request)
              (.requestVoteRequest queuedRequest) queuedDestination
              (by simpa [next, CCFRaft.next, request] using member) with
        old | new
      · have oldFacts :=
          facts.networkHistory.voteRequest
            queuedDestination queuedRequest old
        by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          refine
            ⟨by simpa [
                newVoteRequestHistory, Function.update,
                request, makeRequestVoteRequest,
                sourceLastIndex, snapshotLength
              ],
              by simpa [
                newVoteRequestHistory, Function.update,
                request, makeRequestVoteRequest,
                sourceLastTerm, snapshotTerm
              ],
              by simpa [
                newVoteRequestHistory, Function.update
              ] using snapshotCommittable,
              candidatesAboveBootstrap source enabled.1,
              by simp [request, makeRequestVoteRequest, next, CCFRaft.next],
              ?_⟩
          intro _ _
          simpa [
            newVoteRequestHistory, Function.update
          ] using List.take_prefix
            (maxCommittableIndex (state.nodes source).log)
            (state.nodes source).log
        · simpa [
            newVoteRequestHistory, Function.update, sameRequest
          ] using oldFacts
      · rcases new with ⟨destinationEq, messageEq⟩
        simp only [Message.requestVoteRequest.injEq] at messageEq
        subst queuedRequest
        refine
          ⟨by simpa [
              newVoteRequestHistory, Function.update,
              request, makeRequestVoteRequest,
              sourceLastIndex, snapshotLength
            ],
            by simpa [
              newVoteRequestHistory, Function.update,
              request, makeRequestVoteRequest,
              sourceLastTerm, snapshotTerm
            ],
            by simpa [
              newVoteRequestHistory, Function.update
            ] using snapshotCommittable,
            candidatesAboveBootstrap source enabled.1,
            by simp [request, makeRequestVoteRequest, next, CCFRaft.next],
            ?_⟩
        intro _ _
        simpa [
          newVoteRequestHistory, Function.update
        ] using List.take_prefix
          (maxCommittableIndex (state.nodes source).log)
          (state.nodes source).log
    · intro queuedDestination response member granted
      have old :
          Message.requestVoteResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.requestVoteResponse response) queuedDestination
                (by simpa [next, CCFRaft.next, request] using member) with
          old | new
        · exact old
        · simp at new
      rcases
          facts.networkHistory.voteResponse
            queuedDestination response old granted with
        ⟨termBound, recorded, upToDate⟩
      exact
        ⟨by simpa [next, CCFRaft.next] using termBound,
          recorded,
          by simpa [voteLogUpToDate] using upToDate⟩
  have evidenceAfter :
        CommitEvidenceFacts
          (next state (.requestVote source destination))
          appendHistory nodeEvidence requestEvidence := by
      apply
        commitEvidenceFrame
        state (next state (.requestVote source destination))
          appendHistory nodeEvidence requestEvidence evidenceFacts
      · intro node
        simp [next, CCFRaft.next]
      · intro node
        simp [next, CCFRaft.next, NodeState.committedLog]
      · intro node
        simp [next, CCFRaft.next]
      · intro queuedDestination queuedRequest member
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [next, CCFRaft.next] using member) with
          old | new
        · exact old
        · simp at new
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (next state (.requestVote source destination))
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (next state (.requestVote source destination))
        appendHistory appendHistory
        nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (next state (.requestVote source destination))
            appendHistory
            nodeEvidence requestEvidence
            (fun node => by simp [next, CCFRaft.next])
            (fun node => by
              simp [next, CCFRaft.next, NodeState.committedLog])
            (fun queuedDestination queuedRequest member => by
              rcases
                  memEnqueueNoDup
                    state.network (.requestVoteRequest request)
                      (.appendEntriesRequest queuedRequest)
                      queuedDestination
                      (by simpa [next, CCFRaft.next] using member) with
                old | new
              · exact old
              · simp at new)
            known
    · intro member
      simp [next, CCFRaft.next]
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      rcases
          memEnqueueNoDup
            state.network (.requestVoteRequest request)
              (.appendEntriesRequest queuedRequest)
              queuedDestination
              (by simpa [next, CCFRaft.next] using queued) with
        old | new
      · exact Or.inl ⟨old, rfl⟩
      · simp at new
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      left
      refine
        ⟨by simpa [next, CCFRaft.next] using role,
          by simpa [next, CCFRaft.next] using newer,
          ?_, ?_,
          by simpa [next, CCFRaft.next] using
            prefixRefl (state.nodes candidate).log⟩
      · intro entry entryMember
        simpa [next, CCFRaft.next] using
          entriesBefore entry
            (by simpa [next, CCFRaft.next] using entryMember)
      · simp only [
          relaxedElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ] at relaxed ⊢
        rcases relaxed with effective | upToDate
        · rw [effectiveElectionVotersEq] at effective
          exact Or.inl effective
        · exact Or.inr (by
            simpa [
              makeRequestVoteRequest,
              next, CCFRaft.next,
              voteLogUpToDate
            ] using upToDate)
  · refine
      ⟨owners, canonicalHistory, elections,
        nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      exact
        ownership.activeLeader leader
          (by simpa [next, CCFRaft.next] using role)
    · intro node index entry found
      exact
        ownership.logEntryAgreement node index entry
          (by simpa [next, CCFRaft.next] using found)
    · intro queuedDestination queuedRequest member index entry found
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [next, CCFRaft.next] using member) with
          old | new
        · exact old
        · simp at new
      exact
        ownership.queuedHistoryEntryAgreement
          queuedDestination queuedRequest oldMember index entry found
    · intro leader role
      exact
        ownership.activeLeaderHistory leader
          (by simpa [next, CCFRaft.next] using role)
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      simpa [next, CCFRaft.next] using
        ownership.ownerProgress term owner owned
    · intro queuedDestination queuedRequest member
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [next, CCFRaft.next] using member) with
          old | new
        · exact old
        · simp at new
      exact
        ownership.queuedAppendMetadata
          queuedDestination queuedRequest oldMember
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [next, CCFRaft.next] using member) with
          old | new
        · exact old
        · simp at new
      exact
        ownership.queuedActiveSourceHistory
          queuedDestination queuedRequest oldMember
            (by simpa [next, CCFRaft.next] using sameTerm)
            (by simpa [next, CCFRaft.next] using leaderRole)
    · apply
        electionHistoryFrame
          state (next state (.requestVote source destination))
            votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    · apply
        grantedVoteCanonicalFrame
          state (next state (.requestVote source destination))
            canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => by simp [next, CCFRaft.next])
      · intro candidate active
        simpa [next, CCFRaft.next] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical
        exact canonical
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro queuedDestination queuedRequest queued record recorded
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [next, CCFRaft.next] using queued) with
          old | new
        · exact old
        · simp at new
      exact
        electionQueuedFacts
          queuedDestination queuedRequest oldMember record recorded
  · intro candidate voter active member
    have oldActive :
        (state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader := by
      simpa [next, CCFRaft.next] using active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [next, CCFRaft.next] using
      facts.grantedVoteSnapshots
        candidate voter oldActive oldMember
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      exact
        ackFacts.zero leader
          (by simpa [next, CCFRaft.next] using role)
          peer (by simpa [next, CCFRaft.next] using zero)
    · intro leader role peer positive
      rcases
          ackFacts.positive leader
            (by simpa [next, CCFRaft.next] using role)
            peer (by simpa [next, CCFRaft.next] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact
        ⟨snapshot, stored,
          by simpa [next, CCFRaft.next] using snapshotTerm,
          by simpa [next, CCFRaft.next] using snapshotIndex,
          historyBound,
          by simpa [next, CCFRaft.next] using agreed⟩
/-! ## AppendEntries send -/

/-- A request built by an enabled arbitrary-term leader snapshots its log. -/
theorem madeAppendRequestSupport
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (commitBounded : CommitIndicesBounded state)
    (progress : LeaderProgressBounded state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    let request :=
      makeAppendEntriesRequest state source destination batchEnd
    RequestSnapshots (state.nodes source).log request /\
      request.leaderCommit <= (state.nodes source).log.length /\
      (request.entries = [] ->
        request.leaderCommit <= request.prevLogIndex) /\
      RequestCommitStillPresent state (state.nodes source).log request := by
  rcases enabled with ⟨leaderRole, different, batchEndEq⟩
  let previousIndex := (state.nodes source).sentIndex destination
  have previousBound :
      previousIndex <= (state.nodes source).log.length :=
    (progress source leaderRole destination).1
  have endWithin :
      batchEnd <= (state.nodes source).log.length := by
    rw [batchEndEq]
    exact Nat.min_le_right _ _
  have previousBeforeEnd : previousIndex <= batchEnd := by
    by_cases before : previousIndex < (state.nodes source).log.length
    · dsimp [previousIndex] at before ⊢
      rw [batchEndEq, Nat.min_eq_left (by omega)]
      omega
    · have equal : previousIndex = (state.nodes source).log.length := by
        omega
      dsimp [previousIndex] at equal ⊢
      rw [batchEndEq, equal]
      omega
  have entriesLength :
      (messageEntries
        (state.nodes source).log previousIndex batchEnd).length =
          batchEnd - previousIndex :=
    messageEntriesLength
      (state.nodes source).log previousBeforeEnd endWithin
  dsimp [previousIndex] at *
  refine ⟨?_, ?_, ?_, ?_⟩
  · unfold RequestSnapshots
    simp only [makeAppendEntriesRequest]
    refine ⟨?_, by simp, ?_⟩
    · rw [entriesLength]
      omega
    · rw [entriesLength]
      have sumEq :
          (state.nodes source).sentIndex destination +
              (batchEnd - (state.nodes source).sentIndex destination) =
            batchEnd := by
        omega
      simpa [messageEntries, sumEq] using
        (List.take_add
          (l := (state.nodes source).log)
          (i := (state.nodes source).sentIndex destination)
          (j :=
            batchEnd -
              (state.nodes source).sentIndex destination))
  · simpa [makeAppendEntriesRequest] using commitBounded source
  · intro emptyEntries
    have noEntries :
        batchEnd - previousIndex = 0 := by
      rw [← entriesLength]
      simpa [makeAppendEntriesRequest] using
        congrArg List.length emptyEntries
    have previousEqLength :
        previousIndex = (state.nodes source).log.length := by
      by_cases before : previousIndex < (state.nodes source).log.length
      · have endEq : batchEnd = previousIndex + 1 := by
          rw [batchEndEq, Nat.min_eq_left (by omega)]
        omega
      · omega
    change
      (state.nodes source).sentIndex destination =
        (state.nodes source).log.length at previousEqLength
    simpa [
      makeAppendEntriesRequest, previousEqLength
    ] using commitBounded source
  · unfold RequestCommitStillPresent
    simp only [makeAppendEntriesRequest]
    exact prefixRefl _

/-- Sending AppendEntries updates one cursor and enqueues one snapshot. -/
theorem appendEntriesPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    SystemInductiveInvariant
      (next state (.appendEntries source destination batchEnd)) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let request := makeAppendEntriesRequest state source destination batchEnd
  let newAppendHistory :=
    Function.update appendHistory request (state.nodes source).log
  let newRequestEvidence : RequestCommitEvidence TxId :=
    Function.update
      requestEvidence request (nodeEvidence source)
  have requestSupport :=
    madeAppendRequestSupport
      state source destination batchEnd
        facts.commitIndicesBounded facts.leaderProgressBounded enabled
  have roleEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).role =
          (state.nodes node).role := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have currentTermEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have logEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).log =
          (state.nodes node).log := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have commitIndexEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have lastIndexEq :
      forall node,
        lastCommittableIndex
            ((next state
              (.appendEntries source destination batchEnd)).nodes node) =
          lastCommittableIndex (state.nodes node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitIndexEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm
            ((next state
              (.appendEntries source destination batchEnd)).nodes node) =
          lastCommittableTerm (state.nodes node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitIndexEq node)
  have votedForEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).votedFor =
          (state.nodes node).votedFor := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have votesGrantedEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have matchEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, nodeEq
      ]
  have committedEq :
      forall node,
        ((next state (.appendEntries source destination batchEnd)).nodes node).committedLog =
          (state.nodes node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitIndexEq, logEq]
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers
            (next state (.appendEntries source destination batchEnd))
            responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        have oldMember :
            Message.appendEntriesResponse response ∈
              state.network leader := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesResponse response) leader
                  (by simpa [next, CCFRaft.next, request] using member) with
            old | new
          · exact old
          · simp at new
        exact
          ⟨response, oldMember, success,
            by simpa [currentTermEq] using term,
            sourceEq, destinationEq, lastIndex,
            by simpa [logEq] using covered⟩
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        refine
          ⟨response, ?_, success,
            by simpa [currentTermEq] using term,
            sourceEq, destinationEq, lastIndex,
            by simpa [logEq] using covered⟩
        simpa [next, CCFRaft.next, request] using
          memEnqueueNoDupOfMem
            state.network (.appendEntriesRequest request)
              (.appendEntriesResponse response) leader member
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt
            (next state (.appendEntries source destination batchEnd))
            responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    simp only [hasEffectiveMajorityAt, effectiveAckersEq]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (next state (.appendEntries source destination batchEnd))
            candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (processed | queued)
      · exact Or.inl (by simpa [votesGrantedEq] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        have oldMember :
            Message.requestVoteResponse response ∈
              state.network candidate := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.requestVoteResponse response) candidate
                  (by simpa [next, CCFRaft.next, request] using member) with
            old | new
          · exact old
          · simp at new
        exact
          ⟨response, oldMember, granted,
            by simpa [currentTermEq] using responseTerm,
            responseSource, responseDestination⟩
    · rintro (processed | queued)
      · exact Or.inl (by simpa [votesGrantedEq] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        refine
          ⟨response, ?_, granted,
            by simpa [currentTermEq] using responseTerm,
            responseSource, responseDestination⟩
        simpa [next, CCFRaft.next, request] using
          memEnqueueNoDupOfMem
            state.network (.appendEntriesRequest request)
              (.requestVoteResponse response) candidate member
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority
            (next state (.appendEntries source destination batchEnd))
            candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (next state (.appendEntries source destination batchEnd))
            candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (effective | eligible)
      · exact Or.inl (by
          rw [effectiveElectionVotersEq] at effective
          exact effective)
      · right
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          currentTermEq, logEq, commitIndexEq, votedForEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitIndexEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitIndexEq candidate),
          voteLogUpToDate
        ] using eligible
    · rintro (effective | eligible)
      · exact Or.inl (by
          rw [effectiveElectionVotersEq]
          exact effective)
      · right
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          currentTermEq, logEq, commitIndexEq, votedForEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitIndexEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitIndexEq candidate),
          voteLogUpToDate
        ] using eligible
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority
            (next state (.appendEntries source destination batchEnd))
            candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq
    ]
  have requestSupportAfter :
      RequestSnapshots (state.nodes source).log request /\
        request.leaderCommit <= (state.nodes source).log.length /\
        (request.entries = [] ->
          request.leaderCommit <= request.prevLogIndex) /\
        RequestCommitStillPresent
          (next state (.appendEntries source destination batchEnd))
          (state.nodes source).log request := by
    refine ⟨requestSupport.1, requestSupport.2.1,
      requestSupport.2.2.1, ?_⟩
    unfold RequestCommitStillPresent at requestSupport ⊢
    rw [committedEq]
    exact requestSupport.2.2.2
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (next state (.appendEntries source destination batchEnd))
        votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by simpa [roleEq] using role)
        (fun leader _ => currentTermEq leader)
        logEq
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun node => Nat.le_of_eq (currentTermEq node).symm)
        (fun _ _ _ voted _ => voted)
  refine
    ⟨votes, newAppendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro node
    rw [commitIndexEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node positive
    rw [commitIndexEq, logEq]
    apply facts.committedFrontierIsSignature node
    simpa [commitIndexEq] using positive
  · intro node
    rw [currentTermEq]
    exact facts.currentTermsPositive node
  · intro node entry member
    rw [logEq] at member
    rw [currentTermEq]
    exact facts.entriesDoNotExceedCurrentTerm node entry member
  · intro node role
    rw [roleEq] at role
    rw [votedForEq, votesGrantedEq]
    exact facts.candidatesSelfVote node role
  · intro node role
    rw [roleEq] at role
    rw [currentTermEq]
    rcases facts.leadersHaveElectionMajority node role with bootstrap | majority
    · exact Or.inl bootstrap
    · right
      unfold hasElectionMajority at majority ⊢
      rw [votesGrantedEq]
      exact majority
  · intro leader role peer
    have oldRole :
        (state.nodes leader).role = .leader := by
      by_cases leaderEq : leader = source <;>
        simpa [
          next, CCFRaft.next, updateNode,
          Function.update, leaderEq
        ] using role
    have oldProgress := facts.leaderProgressBounded leader oldRole peer
    by_cases leaderEq : leader = source
    · subst leader
      constructor
      · by_cases peerEq : peer = destination
        · subst peer
          simp [
            next, CCFRaft.next, updateIndex,
            Function.update
          ]
          rw [enabled.2.2]
          exact Nat.min_le_right _ _
        · simpa [
            next, CCFRaft.next, updateIndex,
            Function.update, peerEq
          ] using oldProgress.1
      · simpa [next, CCFRaft.next] using oldProgress.2
    · simpa [
        next, CCFRaft.next, updateNode,
        Function.update, leaderEq
      ] using oldProgress
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [currentTermEq, votedForEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      rw [currentTermEq] at future
      exact future
    · intro candidate voter active member
      rw [currentTermEq]
      apply facts.voteHistory.counted candidate voter
      · rw [roleEq] at active
        exact active
      · rw [votesGrantedEq] at member
        exact member
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueueNoDup
            state.network (.appendEntriesRequest request)
              message queuedDestination
              (by simpa [next, CCFRaft.next, request] using member) with
        old | new
      · exact facts.networkHistory.addressed queuedDestination message old
      · rcases new with ⟨destinationEq, messageEq⟩
        subst message
        simpa [request, makeAppendEntriesRequest] using destinationEq.symm
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueueNoDup
            state.network (.appendEntriesRequest request)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [next, CCFRaft.next, request] using member) with
        old | new
      · by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          simpa [
            newAppendHistory, Function.update, request
          ] using requestSupportAfter
        · have oldFacts :=
            facts.networkHistory.appendRequest
              queuedDestination queuedRequest old
          have historyEq :
              newAppendHistory queuedRequest =
                appendHistory queuedRequest := by
            simp [newAppendHistory, Function.update, sameRequest]
          rw [historyEq]
          refine
            ⟨oldFacts.1, oldFacts.2.1, oldFacts.2.2.1, ?_⟩
          unfold RequestCommitStillPresent at oldFacts ⊢
          rw [committedEq]
          exact oldFacts.2.2.2
      · rcases new with ⟨destinationEq, messageEq⟩
        simp only [Message.appendEntriesRequest.injEq] at messageEq
        subst queuedRequest
        simpa [
          newAppendHistory, Function.update, request
        ] using requestSupportAfter
    · intro queuedDestination response member
      have old :
          Message.appendEntriesResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.appendEntriesRequest request)
                (.appendEntriesResponse response) queuedDestination
                (by simpa [next, CCFRaft.next, request] using member) with
          old | new
        · exact old
        · simp at new
      intro success
      rcases
          facts.networkHistory.appendResponse queuedDestination response old
            success with
        ⟨lengthBound, termBound, supported⟩
      refine
        ⟨lengthBound, by simpa [currentTermEq] using termBound, ?_⟩
      intro sameTerm
      rcases
          supported (by simpa [currentTermEq] using sameTerm) with
        ⟨leaderRole, covered⟩
      constructor
      · simpa [roleEq] using leaderRole
      · simpa [logEq] using covered
    · intro queuedDestination voteRequest member
      have old :
          Message.requestVoteRequest voteRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.appendEntriesRequest request)
                (.requestVoteRequest voteRequest) queuedDestination
                (by simpa [next, CCFRaft.next, request] using member) with
          old | new
        · exact old
        · simp at new
      rcases
          facts.networkHistory.voteRequest
            queuedDestination voteRequest old with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      exact
        ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap,
          by simpa [currentTermEq] using termBound,
          fun sameTerm active =>
            by
              have oldSameTerm :
                  voteRequest.term =
                    (state.nodes voteRequest.source).currentTerm := by
                simpa [currentTermEq] using sameTerm
              have oldActive :
                  (state.nodes voteRequest.source).role = .candidate \/
                    (state.nodes voteRequest.source).role = .leader := by
                simpa [roleEq] using active
              simpa [logEq] using
                activePrefix oldSameTerm oldActive⟩
    · intro queuedDestination response member granted
      have old :
          Message.requestVoteResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueueNoDup
              state.network (.appendEntriesRequest request)
                (.requestVoteResponse response) queuedDestination
                (by simpa [next, CCFRaft.next, request] using member) with
          old | new
        · exact old
        · simp at new
      rcases
          facts.networkHistory.voteResponse
            queuedDestination response old granted with
        ⟨termBound, recorded, upToDate⟩
      exact
        ⟨by simpa [currentTermEq] using termBound,
          recorded,
          by simpa [voteLogUpToDate] using upToDate⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (next state (.appendEntries source destination batchEnd))
        newAppendHistory nodeEvidence newRequestEvidence := by
    constructor
    · intro node zero
      apply evidenceFacts.nodeZero node
      rw [commitIndexEq] at zero
      exact zero
    · intro node positive
      have oldPositive :
          0 < (state.nodes node).commitIndex := by
        rw [commitIndexEq] at positive
        exact positive
      rcases evidenceFacts.nodePositive node oldPositive with
        ⟨evidence, stored, valid, lengthEq, termBound⟩
      exact
        ⟨evidence, stored,
          by simpa [committedEq] using valid,
          by simpa [commitIndexEq] using lengthEq,
          by simpa [currentTermEq] using termBound⟩
    · intro queuedDestination queuedRequest member zero
      by_cases sameRequest : queuedRequest = request
      · subst queuedRequest
        have sourceZero :
            (state.nodes source).commitIndex = 0 := by
          simpa [request, makeAppendEntriesRequest] using zero
        have none := evidenceFacts.nodeZero source sourceZero
        simpa [
          newRequestEvidence, Function.update
        ] using none
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using member) with
            old | new
          · exact old
          · simp at new
            exact False.elim (sameRequest new.2)
        have oldNone :=
          evidenceFacts.requestZero
            queuedDestination queuedRequest oldMember zero
        simpa [
          newRequestEvidence, Function.update, sameRequest
        ] using oldNone
    · intro queuedDestination queuedRequest member positive
      by_cases sameRequest : queuedRequest = request
      · subst queuedRequest
        have sourcePositive :
            0 < (state.nodes source).commitIndex := by
          simpa [request, makeAppendEntriesRequest] using positive
        rcases
            evidenceFacts.nodePositive source sourcePositive with
          ⟨evidence, stored, valid, lengthEq, termBound⟩
        refine
          ⟨evidence,
            by simpa [
              newRequestEvidence, Function.update
            ] using stored,
            ?_, ?_, ?_⟩
        · simpa [
            newAppendHistory, Function.update,
            request, makeAppendEntriesRequest,
            NodeState.committedLog
          ] using valid
        · simpa [request, makeAppendEntriesRequest] using lengthEq
        · simpa [request, makeAppendEntriesRequest] using termBound
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using member) with
            old | new
          · exact old
          · simp at new
            exact False.elim (sameRequest new.2)
        rcases
            evidenceFacts.requestPositive
              queuedDestination queuedRequest oldMember positive with
          ⟨evidence, stored, valid, lengthEq, termBound⟩
        exact
          ⟨evidence,
            by simpa [
              newRequestEvidence, Function.update, sameRequest
            ] using stored,
            by simpa [
              newAppendHistory, Function.update, sameRequest
            ] using valid,
            lengthEq, termBound⟩
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (next state (.appendEntries source destination batchEnd))
        newAppendHistory nodeEvidence newRequestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (next state (.appendEntries source destination batchEnd))
          appendHistory newAppendHistory
          nodeEvidence nodeEvidence
          requestEvidence newRequestEvidence elections prospectiveFacts
    · intro evidence supportedPrefix known
      rcases known with nodeKnown | requestKnown
      · rcases nodeKnown with
          ⟨node, positive, stored, prefixEq⟩
        exact Or.inl
          ⟨node,
            by simpa [commitIndexEq] using positive,
            stored,
            by simpa [committedEq] using prefixEq⟩
      · rcases requestKnown with
          ⟨queuedDestination, queuedRequest, member,
            positive, stored, prefixEq⟩
        by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          have sourcePositive :
              0 < (state.nodes source).commitIndex := by
            simpa [request, makeAppendEntriesRequest] using positive
          have sourceStored :
              nodeEvidence source = some evidence := by
            simpa [
              newRequestEvidence, Function.update
            ] using stored
          exact Or.inl
            ⟨source, sourcePositive, sourceStored,
              by simpa [
                newAppendHistory, Function.update,
                request, makeAppendEntriesRequest,
                NodeState.committedLog
              ] using prefixEq⟩
        · have oldMember :
              Message.appendEntriesRequest queuedRequest ∈
                state.network queuedDestination := by
            rcases
                memEnqueueNoDup
                  state.network (.appendEntriesRequest request)
                    (.appendEntriesRequest queuedRequest)
                    queuedDestination
                    (by simpa [next, CCFRaft.next] using member) with
              old | new
            · exact old
            · simp at new
              exact False.elim (sameRequest new.2)
          exact Or.inr
            ⟨queuedDestination, queuedRequest, oldMember,
              positive,
              by simpa [
                newRequestEvidence, Function.update, sameRequest
              ] using stored,
              by simpa [
                newAppendHistory, Function.update, sameRequest
              ] using prefixEq⟩
    · intro member
      simpa [logEq] using prefixRefl (state.nodes member).log
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      by_cases sameRequest : queuedRequest = request
      · subst queuedRequest
        right
        right
        have oldKnown :
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
                evidence supportedPrefix := by
          rcases known with nodeKnown | requestKnown
          · rcases nodeKnown with
              ⟨node, positive, stored, prefixEq⟩
            exact Or.inl
              ⟨node,
                by simpa [commitIndexEq] using positive,
                stored,
                by simpa [committedEq] using prefixEq⟩
          · rcases requestKnown with
              ⟨knownDestination, knownRequest, queuedMember,
                positive, stored, prefixEq⟩
            by_cases knownRequestEq : knownRequest = request
            · subst knownRequest
              have sourcePositive :
                  0 < (state.nodes source).commitIndex := by
                simpa [request, makeAppendEntriesRequest] using positive
              have sourceStored :
                  nodeEvidence source = some evidence := by
                simpa [
                  newRequestEvidence, Function.update
                ] using stored
              exact Or.inl
                ⟨source, sourcePositive, sourceStored,
                  by simpa [
                    newAppendHistory, Function.update,
                    request, makeAppendEntriesRequest,
                    NodeState.committedLog
                  ] using prefixEq⟩
            · have oldMember :
                  Message.appendEntriesRequest knownRequest ∈
                    state.network knownDestination := by
                rcases
                    memEnqueueNoDup
                      state.network (.appendEntriesRequest request)
                        (.appendEntriesRequest knownRequest)
                        knownDestination
                        (by simpa [next, CCFRaft.next] using
                          queuedMember) with
                  old | new
                · exact old
                · simp at new
                  exact False.elim (knownRequestEq new.2)
              exact Or.inr
                ⟨knownDestination, knownRequest, oldMember,
                  positive,
                  by simpa [
                    newRequestEvidence, Function.update,
                    knownRequestEq
                  ] using stored,
                  by simpa [
                    newAppendHistory, Function.update,
                    knownRequestEq
                  ] using prefixEq⟩
        rcases
            knownCommitEvidenceValid evidenceFacts oldKnown with
          ⟨_, _, _, _, ackMajority, _⟩
        rcases majorityNonempty evidence.ackQuorum ackMajority with
          ⟨member, ackMember⟩
        have leaderCovered :=
          knownCommitEvidenceActiveLeaderContainsFrontier
            ownership electionFacts evidenceFacts prospectiveFacts
              oldKnown enabled.1
              (by
                simpa [
                  request, makeAppendEntriesRequest
                ] using Nat.le_of_eq sameTerm)
              ackMember
        simpa [
          newAppendHistory, Function.update,
          request, makeAppendEntriesRequest
        ] using leaderCovered
      · left
        have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using queued) with
            old | new
          · exact old
          · simp at new
            exact False.elim (sameRequest new.2)
        exact
          ⟨oldMember,
            by simp [
              newAppendHistory, Function.update, sameRequest
            ]⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      left
      refine
        ⟨by simpa [roleEq] using role,
          by simpa [currentTermEq] using newer,
          ?_, ?_,
          by simpa [logEq] using
            prefixRefl (state.nodes candidate).log⟩
      · intro entry entryMember
        simpa [currentTermEq] using
          entriesBefore entry (by simpa [logEq] using entryMember)
      · simp only [
          relaxedElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ] at relaxed ⊢
        rcases relaxed with effective | upToDate
        · rw [effectiveElectionVotersEq] at effective
          exact Or.inl effective
        · exact Or.inr (by
            simpa [
              makeRequestVoteRequest,
              currentTermEq, logEq,
              lastIndexEq, lastTermEq,
              voteLogUpToDate
            ] using upToDate)
  · refine
      ⟨owners, canonicalHistory, elections,
        nodeEvidence, newRequestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      rw [currentTermEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro node index entry found
      rcases
          ownership.logEntryAgreement node index entry
            (by simpa [logEq] using found) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro queuedDestination queuedRequest member index entry found
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have sourceFound :
            entryAt? (state.nodes source).log index = some entry := by
          simpa [
            newAppendHistory, Function.update
          ] using found
        rcases
            ownership.logEntryAgreement source index entry sourceFound with
          ⟨canonicalFound, agreed⟩
        exact
          ⟨canonicalFound,
            by simpa [
              newAppendHistory, Function.update
            ] using agreed⟩
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        have oldFound :
            entryAt? (appendHistory queuedRequest) index = some entry := by
          simpa [
            newAppendHistory, Function.update, requestEq
          ] using found
        rcases
            ownership.queuedHistoryEntryAgreement
              queuedDestination queuedRequest oldMember index entry oldFound with
          ⟨canonicalFound, agreed⟩
        exact
          ⟨canonicalFound,
            by simpa [
              newAppendHistory, Function.update, requestEq
            ] using agreed⟩
    · intro leader role
      rw [currentTermEq]
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      simpa [logEq] using
        ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      constructor
      · simpa [currentTermEq] using bound
      · intro same
        have oldSame :
            term = (state.nodes owner).currentTerm := by
          simpa [currentTermEq] using same
        simpa [roleEq] using oldLeader oldSame
    · intro queuedDestination queuedRequest member
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        refine ⟨?_, ?_⟩
        · simpa [request, makeAppendEntriesRequest] using
            ownership.activeLeader source enabled.1
        · intro entry entryMember
          have sourceMember :
              entry ∈ (state.nodes source).log := by
            simpa [
              newAppendHistory, Function.update
            ] using entryMember
          simpa [request, makeAppendEntriesRequest] using
            facts.entriesDoNotExceedCurrentTerm
              source entry sourceMember
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        rcases
            ownership.queuedAppendMetadata
              queuedDestination queuedRequest oldMember with
          ⟨owned, bounded⟩
        exact
          ⟨owned,
            by simpa [
              newAppendHistory, Function.update, requestEq
            ] using bounded⟩
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have requestSource : request.source = source := by
          simp [request, makeAppendEntriesRequest]
        have historyEq :
            newAppendHistory request = (state.nodes source).log := by
          simp [newAppendHistory]
        rw [historyEq, requestSource, logEq]
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        have oldPrefix :=
          ownership.queuedActiveSourceHistory
            queuedDestination queuedRequest oldMember
              (by simpa [currentTermEq] using sameTerm)
              (by simpa [roleEq] using leaderRole)
        simpa [
          newAppendHistory, Function.update, requestEq, logEq
        ] using oldPrefix
    · apply
        electionHistoryFrame
          state (next state (.appendEntries source destination batchEnd))
            votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    · apply
        grantedVoteCanonicalFrame
          state (next state (.appendEntries source destination batchEnd))
            canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => currentTermEq candidate)
      · intro candidate active
        simpa [roleEq] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical
        exact canonical
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro queuedDestination queuedRequest queued record recorded
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have promotionPrefix :=
          electionFacts.promotionCanonical
            request.term record recorded
        have activeHistory :=
          ownership.activeLeaderHistory source enabled.1
        simpa [
          newAppendHistory, Function.update,
          request, makeAppendEntriesRequest,
          activeHistory
        ] using promotionPrefix
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueueNoDup
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [next, CCFRaft.next] using queued) with
            old | new
          · exact old
          · simp at new
            exact False.elim (requestEq new.2)
        simpa [
          newAppendHistory, Function.update, requestEq
        ] using
          electionQueuedFacts
            queuedDestination queuedRequest oldMember record recorded
  · intro candidate voter active member
    rw [currentTermEq candidate, currentTermEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [logEq] using
      facts.grantedVoteSnapshots
        candidate voter active oldMember
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      exact
        ackFacts.zero leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      rcases
          ackFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact
        ⟨snapshot, stored,
          by simpa [currentTermEq] using snapshotTerm,
          by simpa [matchEq] using snapshotIndex,
          historyBound,
          by simpa [logEq] using agreed⟩
/-! ## Election timeout -/

/-- One self-vote is not a strict majority of the fixed five-node cluster. -/
theorem singletonNotElectionMajority (node : Node) :
    Not ((({node} : Finset Node).card * 2) > NODE_COUNT) := by
  simp [NODE_COUNT]

/-- Starting a successor election preserves the arbitrary-term invariant. -/
theorem timeoutPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.timeout node)) :
    SystemInductiveInvariant (next state (.timeout node)) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let newTerm := (state.nodes node).currentTerm + 1
  let newVotes : VoteHistory :=
    Function.update votes node
      (Function.update (votes node) newTerm (some node))
  have oldNotLeader :
      Not ((state.nodes node).role = .leader) := by
    rcases enabled with follower | candidate
    · exact fun leader => Role.noConfusion (follower.symm.trans leader)
    · exact fun leader => Role.noConfusion (candidate.symm.trans leader)
  have roleNode :
      ((next state (.timeout node)).nodes node).role = .candidate := by
    simp [next, CCFRaft.next]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.timeout node)).nodes candidate).role =
          (state.nodes candidate).role := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have termNode :
      ((next state (.timeout node)).nodes node).currentTerm = newTerm := by
    simp [next, CCFRaft.next, newTerm]
  have termOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.timeout node)).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have logEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have commitEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((next state (.timeout node)).nodes candidate) =
          lastCommittableIndex (state.nodes candidate) := by
    intro candidate
    exact lastCommittableIndexFrame (logEq candidate) (commitEq candidate)
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((next state (.timeout node)).nodes candidate) =
          lastCommittableTerm (state.nodes candidate) := by
    intro candidate
    exact lastCommittableTermFrame (logEq candidate) (commitEq candidate)
  have committedEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).committedLog =
          (state.nodes candidate).committedLog := by
    intro candidate
    simp [NodeState.committedLog, commitEq, logEq]
  have sentEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have matchEq :
      forall candidate,
        ((next state (.timeout node)).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have votedNode :
      ((next state (.timeout node)).nodes node).votedFor = some node := by
    simp [next, CCFRaft.next]
  have votesNode :
      ((next state (.timeout node)).nodes node).votesGranted = {node} := by
    simp [next, CCFRaft.next]
  have votedOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.timeout node)).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have votesOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.timeout node)).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have effectiveAckersEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            effectiveAckers
                (next state (.timeout node))
                responseHistory leader index =
              effectiveAckers state responseHistory leader index := by
    intro leader leaderNe index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact
          ⟨response, by simpa [next, CCFRaft.next] using member,
            success, by simpa [termOther leader leaderNe] using term,
            sourceEq, destinationEq, lastIndex,
            by simpa [logEq] using covered⟩
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact
          ⟨response, by simpa [next, CCFRaft.next] using member,
            success, by simpa [termOther leader leaderNe] using term,
            sourceEq, destinationEq, lastIndex,
            by simpa [logEq] using covered⟩
  have effectiveMajorityEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            hasEffectiveMajorityAt
                (next state (.timeout node))
                responseHistory leader index ↔
              hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader leaderNe index
    simp only [hasEffectiveMajorityAt, effectiveAckersEq leader leaderNe index]
  have effectiveElectionVotersNode :
      effectiveElectionVoters
          (next state (.timeout node)) node =
        {node} := by
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and, Finset.mem_singleton
    ]
    constructor
    · rintro (processed | queued)
      · simpa [votesNode] using processed
      · rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        have oldMember :
            Message.requestVoteResponse response ∈
              state.network node := by
          simpa [next, CCFRaft.next] using member
        have oldBound :=
          (facts.networkHistory.voteResponse
            node response oldMember granted).1
        rw [responseDestination] at oldBound
        rw [termNode] at responseTerm
        simp [newTerm] at responseTerm
        omega
    · intro same
      exact Or.inl (by simpa [votesNode] using same)
  have noEffectiveElectionMajorityNode :
      Not
        (hasEffectiveElectionMajority
          (next state (.timeout node)) node) := by
    intro majority
    unfold hasEffectiveElectionMajority at majority
    rw [effectiveElectionVotersNode] at majority
    exact singletonNotElectionMajority node majority
  have effectiveElectionVotersOtherEq :
      forall candidate,
        Not (candidate = node) ->
          effectiveElectionVoters
              (next state (.timeout node)) candidate =
            effectiveElectionVoters state candidate := by
    intro candidate candidateNe
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (processed | queued)
      · exact Or.inl (by simpa [votesOther candidate candidateNe] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨response, by simpa [next, CCFRaft.next] using member,
            granted,
            by simpa [termOther candidate candidateNe] using responseTerm,
            responseSource, responseDestination⟩
    · rintro (processed | queued)
      · exact Or.inl (by simpa [votesOther candidate candidateNe] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨response, by simpa [next, CCFRaft.next] using member,
            granted,
            by simpa [termOther candidate candidateNe] using responseTerm,
            responseSource, responseDestination⟩
  have effectiveElectionMajorityOtherEq :
      forall candidate,
        Not (candidate = node) ->
          (hasEffectiveElectionMajority
              (next state (.timeout node)) candidate ↔
            hasEffectiveElectionMajority state candidate) := by
    intro candidate
    intro candidateNe
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersOtherEq candidate candidateNe
    ]
  have newTermAboveBootstrap : TERM_ONE < newTerm := by
    have positive := facts.currentTermsPositive node
    simp [newTerm]
    omega
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (next state (.timeout node))
        votes newVotes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by
          have leaderNe : Not (leader = node) := by
            intro same
            subst leader
            exact Role.noConfusion (role.symm.trans roleNode)
          simpa [roleOther leader leaderNe] using role)
        (fun leader role => by
          have leaderNe : Not (leader = node) := by
            intro same
            subst leader
            exact Role.noConfusion (role.symm.trans roleNode)
          exact termOther leader leaderNe)
        logEq
        (fun leader index voter role current member => by
          have leaderNe : Not (leader = node) := by
            intro same
            subst leader
            exact Role.noConfusion (role.symm.trans roleNode)
          rw [effectiveAckersEq leader leaderNe index] at member
          exact member)
        (fun candidate => by
          by_cases candidateEq : candidate = node
          · subst candidate
            rw [termNode]
            simp [newTerm]
          · exact Nat.le_of_eq (termOther candidate candidateEq).symm)
        (fun voter voteTerm candidate voted different => by
          by_cases voterEq : voter = node
          · subst voter
            by_cases voteTermEq : voteTerm = newTerm
            · subst voteTerm
              have chosen : some node = some candidate := by
                simpa [newVotes] using voted
              exact False.elim
                (different (Option.some.inj chosen))
            · simpa [
                newVotes, Function.update, voteTermEq
              ] using voted
          · simpa [
              newVotes, Function.update, voterEq
            ] using voted)
  refine
    ⟨newVotes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro candidate
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded candidate
  · intro candidate positive
    rw [commitEq, logEq]
    apply facts.committedFrontierIsSignature candidate
    simpa [commitEq] using positive
  · intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [termNode]
      exact Nat.le_of_lt newTermAboveBootstrap
    · rw [termOther candidate same]
      exact facts.currentTermsPositive candidate
  · intro candidate entry member
    rw [logEq] at member
    by_cases same : candidate = node
    · subst candidate
      rw [termNode]
      have oldBound :=
        facts.entriesDoNotExceedCurrentTerm node entry member
      simp [newTerm]
      omega
    · rw [termOther candidate same]
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · intro candidate role
    by_cases same : candidate = node
    · subst candidate
      exact ⟨votedNode, by simp [votesNode]⟩
    · have oldRole : (state.nodes candidate).role = .candidate := by
        rw [roleOther candidate same] at role
        exact role
      rw [votedOther candidate same, votesOther candidate same]
      exact facts.candidatesSelfVote candidate oldRole
  · intro leader role
    have leaderNe : Not (leader = node) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleNode)
    rw [roleOther leader leaderNe] at role
    have old := facts.leadersHaveElectionMajority leader role
    rw [termOther leader leaderNe]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · right
      unfold hasElectionMajority at majority ⊢
      rw [votesOther leader leaderNe]
      exact majority
  · intro leader role peer
    have leaderNe : Not (leader = node) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleNode)
    rw [roleOther leader leaderNe] at role
    have old := facts.leaderProgressBounded leader role peer
    rw [sentEq, matchEq, logEq]
    exact old
  · constructor
    · intro voter
      by_cases voterEq : voter = node
      · subst voter
        have termNe : Not (TERM_ONE = newTerm) :=
          ne_of_lt newTermAboveBootstrap
        simp [
          newVotes, Function.update, newTerm,
          termNe, facts.voteHistory.bootstrapEmpty node
        ]
      · simp [
          newVotes, Function.update, voterEq,
          facts.voteHistory.bootstrapEmpty voter
        ]
    · intro voter
      by_cases voterEq : voter = node
      · subst voter
        rw [termNode, votedNode]
        simp [newVotes, Function.update]
      · rw [termOther voter voterEq, votedOther voter voterEq]
        simpa [newVotes, Function.update, voterEq] using
          facts.voteHistory.current voter
    · intro voter term future
      by_cases voterEq : voter = node
      · subst voter
        rw [termNode] at future
        have termNe : Not (term = newTerm) := by omega
        simp [
          newVotes, Function.update, termNe,
          facts.voteHistory.future node term (by
            simp [newTerm] at future ⊢
            omega)
        ]
      · rw [termOther voter voterEq] at future
        simpa [newVotes, Function.update, voterEq] using
          facts.voteHistory.future voter term future
    · intro candidate voter active member
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [votesNode] at member
        simp at member
        subst voter
        rw [termNode]
        simp [newVotes, Function.update]
      · have oldActive :
            (state.nodes candidate).role = .candidate \/
              (state.nodes candidate).role = .leader := by
          rw [roleOther candidate candidateEq] at active
          exact active
        rw [votesOther candidate candidateEq] at member
        have oldCounted :=
          facts.voteHistory.counted candidate voter oldActive member
        rw [termOther candidate candidateEq]
        by_cases voterEq : voter = node
        · subst voter
          have termNe :
              Not ((state.nodes candidate).currentTerm = newTerm) := by
            intro sameTerm
            have empty :=
              facts.voteHistory.future
                node (state.nodes candidate).currentTerm
                (by
                  simp [newTerm] at sameTerm ⊢
                  omega)
            rw [oldCounted] at empty
            contradiction
          simpa [newVotes, Function.update, termNe] using oldCounted
        · simpa [newVotes, Function.update, voterEq] using oldCounted
  · constructor
    · exact facts.networkHistory.addressed
    · intro destination request member
      have old := facts.networkHistory.appendRequest destination request member
      refine ⟨old.1, old.2.1, old.2.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      rw [committedEq]
      exact old.2.2.2
    · intro destination response member success
      have oldMember :
          Message.appendEntriesResponse response ∈
            state.network destination := by
        simpa [next, CCFRaft.next] using member
      have responseDestination :
          response.destination = destination := by
        simpa using
          facts.networkHistory.addressed
            destination (.appendEntriesResponse response) oldMember
      subst destination
      rcases
          facts.networkHistory.appendResponse response.destination response
            oldMember success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, ?_, ?_⟩
      · by_cases destinationEq : response.destination = node
        · rw [destinationEq, termNode]
          rw [destinationEq] at termBound
          simp [newTerm]
          omega
        · simpa [termOther response.destination destinationEq] using termBound
      intro sameTerm
      by_cases destinationEq : response.destination = node
      · have impossibleOldTerm :
            response.term >
              (state.nodes response.destination).currentTerm := by
          rw [destinationEq, termNode] at sameTerm
          rw [destinationEq]
          simp [newTerm] at sameTerm ⊢
          omega
        exact False.elim (Nat.not_lt_of_ge termBound impossibleOldTerm)
      · have oldTerm :
            response.term =
              (state.nodes response.destination).currentTerm := by
          simpa [termOther response.destination destinationEq] using sameTerm
        rcases supported oldTerm with ⟨oldLeader, covered⟩
        constructor
        · simpa [roleOther response.destination destinationEq] using oldLeader
        · simpa [logEq] using covered
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request member with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap, ?_, ?_⟩
      · by_cases sourceEq : request.source = node
        · have oldBound :
              request.term <= (state.nodes node).currentTerm := by
            simpa [sourceEq] using termBound
          rw [sourceEq, termNode]
          simp [newTerm]
          omega
        · simpa [termOther request.source sourceEq] using termBound
      · intro sameTerm active
        by_cases sourceEq : request.source = node
        · have oldBound :
              request.term <= (state.nodes node).currentTerm := by
            simpa [sourceEq] using termBound
          have newSame :
              request.term = newTerm := by
            simpa [sourceEq, termNode] using sameTerm
          simp [newTerm] at newSame
          omega
        · have oldPrefix :=
            activePrefix
              (by simpa [termOther request.source sourceEq] using sameTerm)
              (by simpa [roleOther request.source sourceEq] using active)
          simpa [logEq] using oldPrefix
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse
            destination response member granted with
        ⟨oldBound, oldVote, upToDate⟩
      refine ⟨?_, ?_, upToDate⟩
      · by_cases responseDestinationEq :
            response.destination = node
        · rw [responseDestinationEq, termNode]
          rw [responseDestinationEq] at oldBound
          simp [newTerm]
          omega
        · simpa [
            termOther response.destination responseDestinationEq
          ] using oldBound
      · by_cases sourceEq : response.source = node
        · rw [sourceEq] at oldVote ⊢
          by_cases termEq : response.term = newTerm
          · have empty :=
              facts.voteHistory.future node response.term (by
                simp [newTerm] at termEq ⊢
                omega)
            rw [oldVote] at empty
            contradiction
          · simpa [newVotes, Function.update, termEq] using oldVote
        · simpa [newVotes, Function.update, sourceEq] using oldVote
  have evidenceAfter :
      CommitEvidenceFacts
        (next state (.timeout node))
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
      state (next state (.timeout node))
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitEq committedEq
    · intro candidate
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [termNode]
        simp [newTerm]
      · exact Nat.le_of_eq (termOther candidate candidateEq).symm
    · intro destination request member
      simpa [next, CCFRaft.next] using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (next state (.timeout node))
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (next state (.timeout node))
          appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
            elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (next state (.timeout node))
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [next, CCFRaft.next] using member)
            known
    · intro member
      simpa [logEq] using prefixRefl (state.nodes member).log
    · intro evidence supportedPrefix destination request known queued sameTerm
      left
      exact
        ⟨by simpa [next, CCFRaft.next] using queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      by_cases candidateEq : candidate = node
      · subst candidate
        right
        have oldKnown :=
          knownCommitEvidenceFrameBack
            state (next state (.timeout node))
              appendHistory nodeEvidence requestEvidence
              commitEq committedEq
              (fun destination request member => by
                simpa [next, CCFRaft.next] using member)
              known
        have futureMember :
            member ∈ futureElectionVoters state node newTerm := by
          simp only [
            relaxedElectionVoters, futureElectionVoters,
            Finset.mem_filter, Finset.mem_univ, true_and
          ] at relaxed ⊢
          rcases relaxed with effective | supporter
          · have voterEq : member = node := by
              have voterIn : member ∈ ({node} : Finset Node) := by
                simpa [effectiveElectionVotersNode] using effective
              simpa using voterIn
            exact Or.inl voterEq
          · by_cases memberEq : member = node
            · exact Or.inl memberEq
            · right
              exact
                ⟨by simpa [termOther member memberEq, termNode] using
                    supporter.1,
                  by simpa [
                    makeRequestVoteRequest,
                    logEq, lastIndexEq, lastTermEq,
                    voteLogUpToDate
                  ] using supporter.2⟩
        have oldCandidateBefore :
            (state.nodes node).currentTerm < newTerm := by
          simp [newTerm]
        have covered :=
          prospectiveCommitFutureMember
            ownership facts.committedFrontierIsSignature
              electionFacts evidenceFacts prospectiveFacts
              oldKnown oldCandidateBefore ackMember futureMember
        simpa [logEq] using covered
      · left
        refine
          ⟨by simpa [roleOther candidate candidateEq] using role,
            by simpa [termOther candidate candidateEq] using newer,
            ?_, ?_, ?_⟩
        · intro entry entryMember
          simpa [termOther candidate candidateEq] using
            entriesBefore entry (by simpa [logEq] using entryMember)
        · simp only [
            relaxedElectionVoters, Finset.mem_filter,
            Finset.mem_univ, true_and
          ] at relaxed ⊢
          rcases relaxed with effective | supporter
          · rw [effectiveElectionVotersOtherEq candidate candidateEq] at effective
            exact Or.inl effective
          · right
            refine
              ⟨?_, by simpa [
                makeRequestVoteRequest,
                termOther candidate candidateEq,
                logEq, lastIndexEq, lastTermEq,
                voteLogUpToDate
              ] using supporter.2⟩
            by_cases memberEq : member = node
            · have afterBound := supporter.1
              rw [memberEq, termNode,
                termOther candidate candidateEq] at afterBound
              simp [newTerm] at afterBound
              rw [memberEq]
              omega
            · simpa [termOther member memberEq,
                termOther candidate candidateEq] using supporter.1
        · simpa [logEq] using prefixRefl (state.nodes candidate).log
  · refine
      ⟨owners, canonicalHistory, elections,
        nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [termOther leader leaderNe]
      exact ownership.activeLeader leader
        (by simpa [roleOther leader leaderNe] using role)
    · intro owner index entry found
      rcases
          ownership.logEntryAgreement owner index entry
            (by simpa [logEq] using found) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro destination request member index entry found
      exact
        ownership.queuedHistoryEntryAgreement
          destination request
            (by simpa [next, CCFRaft.next] using member)
            index entry found
    · intro leader role
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [termOther leader leaderNe]
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleOther leader leaderNe] using role
      simpa [logEq] using
        ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      by_cases ownerEq : owner = node
      · subst owner
        constructor
        · rw [termNode]
          simp [newTerm]
          omega
        · intro same
          rw [termNode] at same
          simp [newTerm] at same
          omega
      · constructor
        · simpa [termOther owner ownerEq] using bound
        · intro same
          have oldSame :
              term = (state.nodes owner).currentTerm := by
            simpa [termOther owner ownerEq] using same
          simpa [roleOther owner ownerEq] using oldLeader oldSame
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa [next, CCFRaft.next] using member)
    · intro destination request member sameTerm leaderRole
      by_cases sourceEq : request.source = node
      · have afterLeader :
            ((next state (.timeout node)).nodes node).role = .leader := by
          simpa [sourceEq] using leaderRole
        exact False.elim
          (Role.noConfusion (afterLeader.symm.trans roleNode))
      · have oldMember :
            Message.appendEntriesRequest request ∈
              state.network destination := by
          simpa [next, CCFRaft.next] using member
        have oldPrefix :=
          ownership.queuedActiveSourceHistory
            destination request oldMember
              (by simpa [termOther request.source sourceEq] using sameTerm)
              (by simpa [roleOther request.source sourceEq] using leaderRole)
        simpa [logEq] using oldPrefix
    · apply
        electionHistoryFrame
          state (next state (.timeout node))
            votes newVotes canonicalHistory canonicalHistory
            owners elections electionFacts
      · intro term record voter recorded member
        by_cases voterEq : voter = node
        · subst voter
          by_cases termEq : term = newTerm
          · subst term
            have bound :=
              electionHistoryVoterTerm
                facts.voteHistory electionFacts recorded member
            simp [newTerm] at bound
          · simp [newVotes, Function.update, termEq]
        · simp [newVotes, Function.update, voterEq]
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    · intro candidate voter active member
      by_cases candidateEq : candidate = node
      · subst candidate
        left
        have voterIn : voter ∈ ({node} : Finset Node) := by
          simpa [effectiveElectionVotersNode] using member
        simpa using voterIn
      · have oldActive :
            (state.nodes candidate).role = .candidate \/
              (state.nodes candidate).role = .leader := by
          rw [roleOther candidate candidateEq] at active
          exact active
        have oldMember :
            voter ∈ effectiveElectionVoters state candidate := by
          rw [effectiveElectionVotersOtherEq candidate candidateEq] at member
          exact member
        simpa [termOther candidate candidateEq] using
          voteCanonicalFacts candidate voter oldActive oldMember
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro queuedDestination request member record recorded
      exact
        electionQueuedFacts
          queuedDestination request
            (by simpa [next, CCFRaft.next] using member)
            record recorded
  · intro candidate voter active member
    by_cases candidateEq : candidate = node
    · subst candidate
      have voterEq : voter = node := by
        have : voter ∈ ({node} : Finset Node) := by
          simpa [effectiveElectionVotersNode] using member
        simpa using this
      subst voter
      refine ⟨?_, Or.inl rfl⟩
      simp [newVotes, Function.update, termNode, newTerm]
    · have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        rw [roleOther candidate candidateEq] at active
        exact active
      rw [termOther candidate candidateEq]
      have oldMember :
          voter ∈ effectiveElectionVoters state candidate := by
        rw [effectiveElectionVotersOtherEq candidate candidateEq] at member
        exact member
      rcases
          facts.grantedVoteSnapshots
            candidate voter oldActive oldMember with
        ⟨recorded, self | snapshot⟩
      all_goals
        have newRecorded :
            newVotes voter (state.nodes candidate).currentTerm =
              some candidate := by
          by_cases voterEq : voter = node
          · rw [voterEq] at recorded ⊢
            have termNe :
                Not ((state.nodes candidate).currentTerm = newTerm) := by
              intro sameTerm
              have futureEmpty :=
                facts.voteHistory.future
                  node (state.nodes candidate).currentTerm
                  (by simp [newTerm] at sameTerm ⊢; omega)
              rw [recorded] at futureEmpty
              contradiction
            simpa [newVotes, Function.update, termNe] using recorded
          · simpa [newVotes, Function.update, voterEq] using recorded
      · refine ⟨?_, Or.inl self⟩
        exact newRecorded
      · rcases snapshot with
          ⟨candidatePrefix, candidateCommittable, voterCommittable,
            voterBound, upToDate⟩
        refine ⟨?_, Or.inr ⟨?_, ?_, ?_, ?_, ?_⟩⟩
        · exact newRecorded
        · simpa [logEq] using candidatePrefix
        · exact candidateCommittable
        · exact voterCommittable
        · by_cases voterEq : voter = node
          · subst voter
            rw [termNode]
            exact Nat.le_trans voterBound (by simp [newTerm])
          · simpa [termOther voter voterEq] using voterBound
        · simpa [voteLogUpToDate] using upToDate
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      exact
        ackFacts.zero leader
          (by simpa [roleOther leader leaderNe] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rcases
          ackFacts.positive leader
            (by simpa [roleOther leader leaderNe] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact
        ⟨snapshot, stored,
          by simpa [termOther leader leaderNe] using snapshotTerm,
          by simpa [matchEq] using snapshotIndex,
          historyBound,
          by simpa [logEq] using agreed⟩
/-! ## Newer-term observation -/

/-- Observing a queued newer term steps down without changing log history. -/
theorem updateTermPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.updateTerm source destination)) :
    SystemInductiveInvariant
      (next state (.updateTerm source destination)) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  unfold Enabled at enabled
  cases found : newerMessage? state source destination with
  | none =>
      simp [found] at enabled
  | some selected =>
    have newer := (newerMessageSound found).choose_spec.2
    have roleDestination :
        ((next state (.updateTerm source destination)).nodes destination).role =
          .follower := by
      simp [next, CCFRaft.next, found]
    have termDestination :
        ((next state (.updateTerm source destination)).nodes destination).currentTerm =
          selected.term := by
      simp [next, CCFRaft.next, found]
    have votedDestination :
        ((next state (.updateTerm source destination)).nodes destination).votedFor =
          none := by
      simp [next, CCFRaft.next, found]
    have roleOther :
        forall node,
          Not (node = destination) ->
          ((next state (.updateTerm source destination)).nodes node).role =
            (state.nodes node).role := by
      intro node different
      simp [
        next, CCFRaft.next, found, updateNode,
        Function.update, different
      ]
    have termOther :
        forall node,
          Not (node = destination) ->
          ((next state (.updateTerm source destination)).nodes node).currentTerm =
            (state.nodes node).currentTerm := by
      intro node different
      simp [
        next, CCFRaft.next, found, updateNode,
        Function.update, different
      ]
    have votedOther :
        forall node,
          Not (node = destination) ->
          ((next state (.updateTerm source destination)).nodes node).votedFor =
            (state.nodes node).votedFor := by
      intro node different
      simp [
        next, CCFRaft.next, found, updateNode,
        Function.update, different
      ]
    have logEq :
        forall node,
          ((next state (.updateTerm source destination)).nodes node).log =
            (state.nodes node).log := by
      intro node
      by_cases same : node = destination <;>
        simp [
          next, CCFRaft.next, found, updateNode,
          Function.update, same
        ]
    have commitEq :
        forall node,
          ((next state (.updateTerm source destination)).nodes node).commitIndex =
            (state.nodes node).commitIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [
          next, CCFRaft.next, found, updateNode,
          Function.update, same
        ]
    have lastIndexEq :
        forall node,
          lastCommittableIndex
              ((next state (.updateTerm source destination)).nodes node) =
            lastCommittableIndex (state.nodes node) := by
      intro node
      exact lastCommittableIndexFrame (logEq node) (commitEq node)
    have lastTermEq :
        forall node,
          lastCommittableTerm
              ((next state (.updateTerm source destination)).nodes node) =
            lastCommittableTerm (state.nodes node) := by
      intro node
      exact lastCommittableTermFrame (logEq node) (commitEq node)
    have committedEq :
        forall node,
          ((next state (.updateTerm source destination)).nodes node).committedLog =
            (state.nodes node).committedLog := by
      intro node
      simp [NodeState.committedLog, commitEq, logEq]
    have sentEq :
        forall node,
          ((next state (.updateTerm source destination)).nodes node).sentIndex =
            (state.nodes node).sentIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [
          next, CCFRaft.next, found, updateNode,
          Function.update, same
        ]
    have matchEq :
        forall node,
          ((next state (.updateTerm source destination)).nodes node).matchIndex =
            (state.nodes node).matchIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [
          next, CCFRaft.next, found, updateNode,
          Function.update, same
        ]
    have votesEq :
        forall node,
          ((next state (.updateTerm source destination)).nodes node).votesGranted =
            (state.nodes node).votesGranted := by
      intro node
      by_cases same : node = destination <;>
        simp [
          next, CCFRaft.next, found, updateNode,
          Function.update, same
        ]
    have networkEq :
        (next state (.updateTerm source destination)).network =
          state.network := by
      simp [next, CCFRaft.next, found]
    have effectiveAckersEq :
        forall leader,
          Not (leader = destination) ->
            forall index,
              effectiveAckers
                  (next state (.updateTerm source destination))
                  responseHistory leader index =
                effectiveAckers state responseHistory leader index := by
      intro leader leaderNe index
      ext peer
      simp only [
        effectiveAckers, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      constructor
      · rintro (self | matched | queued)
        · exact Or.inl self
        · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
        · right
          right
          rcases queued with
            ⟨response, member, success, term, sourceEq,
              destinationEq, lastIndex, covered⟩
          exact
            ⟨response, by simpa [networkEq] using member,
              success, by simpa [termOther leader leaderNe] using term,
              sourceEq, destinationEq, lastIndex,
              by simpa [logEq] using covered⟩
      · rintro (self | matched | queued)
        · exact Or.inl self
        · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
        · right
          right
          rcases queued with
            ⟨response, member, success, term, sourceEq,
              destinationEq, lastIndex, covered⟩
          exact
            ⟨response, by simpa [networkEq] using member,
              success, by simpa [termOther leader leaderNe] using term,
              sourceEq, destinationEq, lastIndex,
              by simpa [logEq] using covered⟩
    have effectiveMajorityEq :
        forall leader,
          Not (leader = destination) ->
            forall index,
              hasEffectiveMajorityAt
                  (next state (.updateTerm source destination))
                  responseHistory leader index ↔
                hasEffectiveMajorityAt state responseHistory leader index := by
      intro leader leaderNe index
      simp only [
        hasEffectiveMajorityAt,
        effectiveAckersEq leader leaderNe index
      ]
    have effectiveElectionVotersEq :
        forall candidate,
          Not (candidate = destination) ->
            effectiveElectionVoters
                (next state (.updateTerm source destination)) candidate =
              effectiveElectionVoters state candidate := by
      intro candidate candidateNe
      ext voter
      simp only [
        effectiveElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      constructor
      · rintro (processed | queued)
        · exact Or.inl (by simpa [votesEq] using processed)
        · right
          rcases queued with
            ⟨response, member, granted, responseTerm,
              responseSource, responseDestination⟩
          exact
            ⟨response, by simpa [networkEq] using member,
              granted,
              by simpa [termOther candidate candidateNe] using responseTerm,
              responseSource, responseDestination⟩
      · rintro (processed | queued)
        · exact Or.inl (by simpa [votesEq] using processed)
        · right
          rcases queued with
            ⟨response, member, granted, responseTerm,
              responseSource, responseDestination⟩
          exact
            ⟨response, by simpa [networkEq] using member,
              granted,
              by simpa [termOther candidate candidateNe] using responseTerm,
              responseSource, responseDestination⟩
    have effectiveElectionMajorityEq :
        forall candidate,
          Not (candidate = destination) ->
            (hasEffectiveElectionMajority
                (next state (.updateTerm source destination)) candidate ↔
              hasEffectiveElectionMajority state candidate) := by
      intro candidate candidateNe
      simp only [
        hasEffectiveElectionMajority,
        effectiveElectionVotersEq candidate candidateNe
      ]
    have temporalFacts :=
      ackerTemporalFrameSameLogs
        state (next state (.updateTerm source destination))
          votes votes responseHistory voteVoterHistory elections
          ackerCurrentFacts ackerVoteFacts ackerElectionFacts
          (fun leader role => by
            have leaderNe : Not (leader = destination) := by
              intro same
              subst leader
              exact Role.noConfusion
                (role.symm.trans roleDestination)
            simpa [roleOther leader leaderNe] using role)
          (fun leader role => by
            have leaderNe : Not (leader = destination) := by
              intro same
              subst leader
              exact Role.noConfusion
                (role.symm.trans roleDestination)
            exact termOther leader leaderNe)
          logEq
          (fun leader index voter role _ member => by
            have leaderNe : Not (leader = destination) := by
              intro same
              subst leader
              exact Role.noConfusion
                (role.symm.trans roleDestination)
            rw [effectiveAckersEq leader leaderNe index] at member
            exact member)
          (fun node => by
            by_cases nodeEq : node = destination
            · subst node
              rw [termDestination]
              exact newer.le
            · exact Nat.le_of_eq (termOther node nodeEq).symm)
          (fun _ _ _ voted _ => voted)
    refine
      ⟨votes, appendHistory, responseHistory,
        voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
    constructor
    · intro node
      rw [commitEq, logEq]
      exact facts.commitIndicesBounded node
    · intro node positive
      rw [commitEq, logEq]
      apply facts.committedFrontierIsSignature node
      simpa [commitEq] using positive
    · intro node
      by_cases same : node = destination
      · subst node
        rw [termDestination]
        exact Nat.le_trans (facts.currentTermsPositive destination) newer.le
      · rw [termOther node same]
        exact facts.currentTermsPositive node
    · intro node entry member
      rw [logEq] at member
      by_cases same : node = destination
      · subst node
        rw [termDestination]
        exact
          Nat.le_trans
            (facts.entriesDoNotExceedCurrentTerm destination entry member)
            newer.le
      · rw [termOther node same]
        exact facts.entriesDoNotExceedCurrentTerm node entry member
    · intro node role
      have nodeNe : Not (node = destination) := by
        intro same
        subst node
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [roleOther node nodeNe] at role
      rw [votedOther node nodeNe, votesEq]
      exact facts.candidatesSelfVote node role
    · intro node role
      have nodeNe : Not (node = destination) := by
        intro same
        subst node
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [roleOther node nodeNe] at role
      have old := facts.leadersHaveElectionMajority node role
      rw [termOther node nodeNe]
      rcases old with bootstrap | majority
      · exact Or.inl bootstrap
      · right
        unfold hasElectionMajority at majority ⊢
        rw [votesEq]
        exact majority
    · intro leader role peer
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [roleOther leader leaderNe] at role
      have old := facts.leaderProgressBounded leader role peer
      rw [sentEq, matchEq, logEq]
      exact old
    · constructor
      · exact facts.voteHistory.bootstrapEmpty
      · intro voter
        by_cases voterEq : voter = destination
        · subst voter
          rw [termDestination, votedDestination]
          exact facts.voteHistory.future destination selected.term newer
        · rw [termOther voter voterEq, votedOther voter voterEq]
          exact facts.voteHistory.current voter
      · intro voter term future
        by_cases voterEq : voter = destination
        · subst voter
          rw [termDestination] at future
          exact
            facts.voteHistory.future destination term
              (Nat.lt_trans newer future)
        · rw [termOther voter voterEq] at future
          exact facts.voteHistory.future voter term future
      · intro candidate voter active member
        have candidateNe : Not (candidate = destination) := by
          intro same
          subst candidate
          rcases active with candidateRole | leaderRole
          · exact Role.noConfusion (candidateRole.symm.trans roleDestination)
          · exact Role.noConfusion (leaderRole.symm.trans roleDestination)
        rw [roleOther candidate candidateNe] at active
        rw [votesEq] at member
        rw [termOther candidate candidateNe]
        exact facts.voteHistory.counted candidate voter active member
    · constructor
      · intro queuedDestination message member
        rw [networkEq] at member
        exact
          facts.networkHistory.addressed
            queuedDestination message member
      · intro queuedDestination request member
        rw [networkEq] at member
        have old :=
          facts.networkHistory.appendRequest
            queuedDestination request member
        refine ⟨old.1, old.2.1, old.2.2.1, ?_⟩
        unfold RequestCommitStillPresent at old ⊢
        rw [committedEq]
        exact old.2.2.2
      · intro queuedDestination response member success
        rw [networkEq] at member
        have responseDestination :
            response.destination = queuedDestination := by
          simpa using
            facts.networkHistory.addressed
              queuedDestination (.appendEntriesResponse response) member
        subst queuedDestination
        rcases
            facts.networkHistory.appendResponse
              response.destination response member success with
          ⟨lengthBound, termBound, supported⟩
        refine ⟨lengthBound, ?_, ?_⟩
        · by_cases destinationEq : response.destination = destination
          · rw [destinationEq, termDestination]
            exact Nat.le_trans (by simpa [destinationEq] using termBound) newer.le
          · simpa [termOther response.destination destinationEq] using termBound
        intro sameTerm
        by_cases destinationEq : response.destination = destination
        · have impossibleOldTerm :
              response.term >
                (state.nodes response.destination).currentTerm := by
            rw [destinationEq, termDestination] at sameTerm
            rw [destinationEq]
            omega
          exact False.elim (Nat.not_lt_of_ge termBound impossibleOldTerm)
        · have oldTerm :
              response.term =
                (state.nodes response.destination).currentTerm := by
            simpa [termOther response.destination destinationEq] using sameTerm
          rcases supported oldTerm with ⟨oldLeader, covered⟩
          constructor
          · simpa [roleOther response.destination destinationEq] using oldLeader
          · simpa [logEq] using covered
      · intro queuedDestination request member
        rw [networkEq] at member
        rcases
            facts.networkHistory.voteRequest
              queuedDestination request member with
          ⟨lastIndex, lastTerm, maxIndex,
            aboveBootstrap, termBound, activePrefix⟩
        refine ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap, ?_, ?_⟩
        · by_cases sourceEq : request.source = destination
          · have oldBound :
                request.term <=
                  (state.nodes destination).currentTerm := by
              simpa [sourceEq] using termBound
            rw [sourceEq, termDestination]
            exact Nat.le_trans oldBound newer.le
          · simpa [termOther request.source sourceEq] using termBound
        · intro sameTerm active
          by_cases sourceEq : request.source = destination
          · have oldBound :
                request.term <=
                  (state.nodes destination).currentTerm := by
              simpa [sourceEq] using termBound
            have newSame :
                request.term = selected.term := by
              simpa [sourceEq, termDestination] using sameTerm
            omega
          · have oldPrefix :=
              activePrefix
                (by simpa [termOther request.source sourceEq] using sameTerm)
                (by simpa [roleOther request.source sourceEq] using active)
            simpa [logEq] using oldPrefix
      · intro queuedDestination response member granted
        rw [networkEq] at member
        rcases
            facts.networkHistory.voteResponse
              queuedDestination response member granted with
          ⟨oldBound, oldVote, upToDate⟩
        refine ⟨?_, oldVote, ?_⟩
        · by_cases responseDestinationEq :
              response.destination = destination
          · rw [responseDestinationEq, termDestination]
            exact
              Nat.le_trans
                (by simpa [responseDestinationEq] using oldBound)
                newer.le
          · simpa [
              termOther response.destination responseDestinationEq
            ] using oldBound
        · simpa [voteLogUpToDate] using upToDate
    have evidenceAfter :
        CommitEvidenceFacts
          (next state (.updateTerm source destination))
          appendHistory nodeEvidence requestEvidence := by
      apply
        commitEvidenceFrame
          state (next state (.updateTerm source destination))
          appendHistory nodeEvidence requestEvidence evidenceFacts
          commitEq committedEq
      · intro node
        by_cases nodeEq : node = destination
        · subst node
          rw [termDestination]
          exact newer.le
        · exact Nat.le_of_eq (termOther node nodeEq).symm
      · intro queuedDestination request member
        simpa [next, CCFRaft.next, found] using member
    have prospectiveAfter :
        ProspectiveCommitEvidenceFacts
          (next state (.updateTerm source destination))
          appendHistory nodeEvidence requestEvidence elections := by
      apply
        prospectiveCommitEvidenceFrame
          state (next state (.updateTerm source destination))
            appendHistory appendHistory
            nodeEvidence nodeEvidence requestEvidence requestEvidence
              elections prospectiveFacts
      · intro evidence supportedPrefix known
        exact
          knownCommitEvidenceFrameBack
            state (next state (.updateTerm source destination))
              appendHistory nodeEvidence requestEvidence
              commitEq committedEq
              (fun queuedDestination request member => by
                simpa [next, CCFRaft.next, found] using member)
              known
      · intro member
        simpa [logEq] using prefixRefl (state.nodes member).log
      · intro evidence supportedPrefix queuedDestination request
          known queued sameTerm
        left
        exact
          ⟨by simpa [next, CCFRaft.next, found] using queued, rfl⟩
      · intro evidence supportedPrefix candidate member known role
          newerEvidence entriesBefore ackMember relaxed
        have candidateNe : Not (candidate = destination) := by
          intro same
          subst candidate
          exact Role.noConfusion (role.symm.trans roleDestination)
        left
        refine
          ⟨by simpa [roleOther candidate candidateNe] using role,
            by simpa [termOther candidate candidateNe] using newerEvidence,
            ?_, ?_, ?_⟩
        · intro entry entryMember
          simpa [termOther candidate candidateNe] using
            entriesBefore entry (by simpa [logEq] using entryMember)
        · simp only [
            relaxedElectionVoters, Finset.mem_filter,
            Finset.mem_univ, true_and
          ] at relaxed ⊢
          rcases relaxed with effective | supporter
          · rw [effectiveElectionVotersEq candidate candidateNe] at effective
            exact Or.inl effective
          · right
            refine ⟨?_, by simpa [
              makeRequestVoteRequest,
              (termOther candidate candidateNe),
              logEq, lastIndexEq, lastTermEq,
              voteLogUpToDate
            ] using supporter.2⟩
            by_cases memberEq : member = destination
            · have oldTermLe :
                  (state.nodes destination).currentTerm <=
                    ((next state
                      (.updateTerm source destination)).nodes
                        destination).currentTerm := by
                rw [termDestination]
                exact newer.le
              have afterBound := supporter.1
              rw [memberEq, termOther candidate candidateNe] at afterBound
              rw [memberEq]
              omega
            · simpa [termOther member memberEq,
                termOther candidate candidateNe] using supporter.1
        · simpa [logEq] using prefixRefl (state.nodes candidate).log
    · refine
        ⟨owners, canonicalHistory, elections,
          nodeEvidence, requestEvidence,
          ?_, ?_, ?_, ?_, ?_, ?_, ?_,
          evidenceAfter, prospectiveAfter⟩
      constructor
      · exact ownership.bootstrap
      · intro leader role
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        rw [termOther leader leaderNe]
        exact ownership.activeLeader leader
          (by simpa [roleOther leader leaderNe] using role)
      · intro node index entry foundEntry
        rcases
            ownership.logEntryAgreement node index entry
              (by simpa [logEq] using foundEntry) with
          ⟨canonicalFound, agreed⟩
        exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
      · intro queuedDestination request member index entry foundEntry
        exact
          ownership.queuedHistoryEntryAgreement
            queuedDestination request
              (by simpa [next, CCFRaft.next, found] using member)
              index entry foundEntry
      · intro leader role
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        rw [termOther leader leaderNe]
        have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderNe] using role
        simpa [logEq] using
          ownership.activeLeaderHistory leader oldRole
      · exact ownership.canonicalEntryOwner
      · exact ownership.canonicalMonoLog
      · intro term owner owned
        rcases ownership.ownerProgress term owner owned with
          ⟨bound, oldLeader⟩
        by_cases ownerEq : owner = destination
        · subst owner
          constructor
          · rw [termDestination]
            omega
          · intro same
            rw [termDestination] at same
            omega
        · constructor
          · simpa [termOther owner ownerEq] using bound
          · intro same
            have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termOther owner ownerEq] using same
            simpa [roleOther owner ownerEq] using oldLeader oldSame
      · intro queuedDestination request member
        exact
          ownership.queuedAppendMetadata queuedDestination request
            (by simpa [next, CCFRaft.next, found] using member)
      · intro queuedDestination request member sameTerm leaderRole
        by_cases sourceEq : request.source = destination
        · have afterLeader :
              ((next state (.updateTerm source destination)).nodes
                destination).role = .leader := by
            simpa [sourceEq] using leaderRole
          exact False.elim
            (Role.noConfusion (afterLeader.symm.trans roleDestination))
        · have oldMember :
              Message.appendEntriesRequest request ∈
                state.network queuedDestination := by
            simpa [next, CCFRaft.next, found] using member
          have oldPrefix :=
            ownership.queuedActiveSourceHistory
              queuedDestination request oldMember
                (by simpa [termOther request.source sourceEq] using sameTerm)
                (by simpa [roleOther request.source sourceEq] using leaderRole)
          simpa [logEq] using oldPrefix
      · apply
          electionHistoryFrame
            state (next state (.updateTerm source destination))
              votes votes canonicalHistory canonicalHistory
              owners elections electionFacts
        · intros
          rfl
        · intro term
          exact prefixRefl (canonicalHistory term)
        · intro history canonical
          exact canonical
      · apply
          grantedVoteCanonicalFrame
            state (next state (.updateTerm source destination))
              canonicalHistory canonicalHistory
              voteCandidateHistory voteVoterHistory voteCanonicalFacts
              (fun candidate active => by
                have candidateNe : Not (candidate = destination) := by
                  intro same
                  subst candidate
                  rcases active with candidateRole | leaderRole
                  · exact Role.noConfusion
                      (candidateRole.symm.trans roleDestination)
                  · exact Role.noConfusion
                      (leaderRole.symm.trans roleDestination)
                exact termOther candidate candidateNe)
        · intro candidate active
          have candidateNe : Not (candidate = destination) := by
            intro same
            subst candidate
            rcases active with candidateRole | leaderRole
            · exact Role.noConfusion
                (candidateRole.symm.trans roleDestination)
            · exact Role.noConfusion
                (leaderRole.symm.trans roleDestination)
          rw [roleOther candidate candidateNe] at active
          exact active
        · intro candidate voter active member
          have candidateNe : Not (candidate = destination) := by
            intro same
            subst candidate
            rcases active with candidateRole | leaderRole
            · exact Role.noConfusion
                (candidateRole.symm.trans roleDestination)
            · exact Role.noConfusion
                (leaderRole.symm.trans roleDestination)
          rw [effectiveElectionVotersEq candidate candidateNe] at member
          exact member
        · intro history canonical
          exact canonical
      · exact temporalFacts.1
      · exact temporalFacts.2.1
      · exact temporalFacts.2.2
      · intro queuedDestination request member record recorded
        have oldMember := member
        rw [networkEq] at oldMember
        exact
          electionQueuedFacts
            queuedDestination request oldMember record recorded
    · intro candidate voter active member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateRole | leaderRole
        · exact Role.noConfusion (candidateRole.symm.trans roleDestination)
        · exact Role.noConfusion (leaderRole.symm.trans roleDestination)
      rw [termOther candidate candidateNe]
      have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        rw [roleOther candidate candidateNe] at active
        exact active
      have oldMember :
          voter ∈ effectiveElectionVoters state candidate := by
        rw [effectiveElectionVotersEq candidate candidateNe] at member
        exact member
      rcases
          facts.grantedVoteSnapshots
            candidate voter oldActive oldMember with
        ⟨recorded, self | snapshot⟩
      · exact ⟨recorded, Or.inl self⟩
      · rcases snapshot with
          ⟨candidatePrefix, candidateCommittable, voterCommittable,
            voterBound, upToDate⟩
        refine
          ⟨recorded,
            Or.inr
              ⟨?_, candidateCommittable, voterCommittable, ?_, ?_⟩⟩
        · simpa [logEq] using candidatePrefix
        · by_cases voterEq : voter = destination
          · subst voter
            rw [termDestination]
            exact Nat.le_trans voterBound newer.le
          · simpa [termOther voter voterEq] using voterBound
        · simpa [voteLogUpToDate] using upToDate
    · refine ⟨ackHistory, ?_⟩
      constructor
      · intro leader role peer zero
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        exact
          ackFacts.zero leader
            (by simpa [roleOther leader leaderNe] using role)
            peer (by simpa [matchEq] using zero)
      · intro leader role peer positive
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        rcases
            ackFacts.positive leader
              (by simpa [roleOther leader leaderNe] using role)
              peer (by simpa [matchEq] using positive) with
          ⟨snapshot, stored, snapshotTerm, snapshotIndex,
            historyBound, agreed⟩
        exact
          ⟨snapshot, stored,
            by simpa [termOther leader leaderNe] using snapshotTerm,
            by simpa [matchEq] using snapshotIndex,
            historyBound,
            by simpa [logEq] using agreed⟩
/-! ## Leader promotion -/

/-- Promoting a winning candidate preserves all arbitrary-term support facts. -/
theorem becomeLeaderPreservesSystemInductiveInvariant
    (state : State TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.becomeLeader node)) :
    SystemInductiveInvariant (next state (.becomeLeader node)) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  have monoLog := invariantFactsMonoLogFromCanonicalHistories facts
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  have oldRole : (state.nodes node).role = .candidate := enabled.1
  have oldMajority : hasElectionMajority state node := enabled.2
  have oldEffectiveMajority :
      hasEffectiveElectionMajority state node :=
    electionMajorityImpliesEffective state node oldMajority
  have oldPotentialMajority :
      hasPotentialElectionMajority state node :=
    effectiveElectionMajorityImpliesPotential
      state node oldEffectiveMajority
  have oldTermUnowned :
      owners (state.nodes node).currentTerm = none :=
    effectiveCandidateTermUnowned
      candidatesAboveBootstrap facts.grantedVoteSnapshots
        ownership electionFacts
        oldRole oldEffectiveMajority
  have oldCandidateTermNot :
      CandidateTermNotInLogs state :=
    termOwnershipCandidateTermNotInLogs
      candidatesAboveBootstrap facts.grantedVoteSnapshots
        ownership electionFacts
  let promotionLog :=
    (state.nodes node).log.take
      (maxCommittableIndex (state.nodes node).log)
  have promotionPrefix :
      promotionLog <+: (state.nodes node).log :=
    List.take_prefix _ _
  have promotionLength :
      promotionLog.length =
        maxCommittableIndex (state.nodes node).log := by
    simp [
      promotionLog,
      Nat.min_eq_left
        (maxCommittableIndexBounded (state.nodes node).log)
    ]
  have promotionCommittable :
      maxCommittableIndex promotionLog = promotionLog.length := by
    rw [promotionLength]
    exact maxCommittableIndexTakeMax (state.nodes node).log
  let newOwners : TermOwners :=
    Function.update owners (state.nodes node).currentTerm (some node)
  let newCanonicalHistory : Nat -> List (Entry TxId) :=
    Function.update canonicalHistory
      (state.nodes node).currentTerm promotionLog
  let electionRecord : ElectionRecord TxId :=
    { leader := node
      quorum := (state.nodes node).votesGranted
      promotionLog
      candidateLog := fun voter =>
        if voter = node then
          promotionLog
        else
          voteCandidateHistory
            (grantedVoteKey
              voter (state.nodes node).currentTerm node)
      voterLog := fun voter =>
        if voter = node then
          promotionLog
        else
          voteVoterHistory
            (grantedVoteKey
              voter (state.nodes node).currentTerm node) }
  let newElections : ElectionHistory TxId :=
    Function.update elections
      (state.nodes node).currentTerm (some electionRecord)
  have canonicalFrameToNew :
      forall history,
        HistoryCanonical canonicalHistory history ->
          HistoryCanonical newCanonicalHistory history := by
    intro history canonical index entry found
    rcases canonical index entry found with
      ⟨canonicalFound, agreed⟩
    have entryTermNe :
        Not (entry.term = (state.nodes node).currentTerm) := by
      intro same
      rcases
          ownership.canonicalEntryOwner
            entry.term index entry canonicalFound with
        ⟨owner, owned⟩
      rw [same, oldTermUnowned] at owned
      contradiction
    exact
      ⟨by simpa [
          newCanonicalHistory, Function.update, entryTermNe
        ] using canonicalFound,
        by simpa [
          newCanonicalHistory, Function.update, entryTermNe
        ] using agreed⟩
  have recordedTermNeNew :
      forall term record,
        elections term = some record ->
          Not (term = (state.nodes node).currentTerm) := by
    intro term record recorded same
    subst term
    have owned :=
      electionFacts.recordOwned
        (state.nodes node).currentTerm record recorded
    rw [oldTermUnowned] at owned
    contradiction
  let newAckHistory : ProcessedAckHistory TxId :=
    Function.update ackHistory node (fun _ => none)
  have roleNode :
      ((next state (.becomeLeader node)).nodes node).role = .leader := by
    simp [next, CCFRaft.next]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.becomeLeader node)).nodes candidate).role =
          (state.nodes candidate).role := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have logNode :
      ((next state (.becomeLeader node)).nodes node).log =
        promotionLog := by
    simp [next, CCFRaft.next, promotionLog]
  have logOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.becomeLeader node)).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have termEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have commitEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have committedEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).committedLog =
          (state.nodes candidate).committedLog := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      have commitBound :=
        commitIndex_le_maxCommittableIndex
          (state.nodes node)
          (facts.committedFrontierIsSignature node)
      simp [
        NodeState.committedLog, commitEq, logNode,
        promotionLog, List.take_take,
        Nat.min_eq_left commitBound
      ]
    · simp [
        NodeState.committedLog, commitEq,
        logOther candidate same
      ]
  have maxCommittableIndexEq :
      forall candidate,
        maxCommittableIndex
            ((next state (.becomeLeader node)).nodes candidate).log =
          maxCommittableIndex (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [logNode, promotionCommittable, promotionLength]
    · rw [logOther candidate same]
  have maxCommittableTermEq :
      forall candidate,
        maxCommittableTerm
            ((next state (.becomeLeader node)).nodes candidate).log =
          maxCommittableTerm (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      unfold maxCommittableTerm
      rw [maxCommittableIndexEq, logNode]
      exact termAtTakeOfLe le_rfl
    · rw [logOther candidate same]
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((next state (.becomeLeader node)).nodes candidate) =
          lastCommittableIndex (state.nodes candidate) := by
    intro candidate
    simp [
      lastCommittableIndex, commitEq,
      maxCommittableIndexEq
    ]
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((next state (.becomeLeader node)).nodes candidate) =
          lastCommittableTerm (state.nodes candidate) := by
    intro candidate
    unfold lastCommittableTerm
    rw [lastIndexEq]
    by_cases same : candidate = node
    · subst candidate
      rw [logNode]
      rw [lastCommittableIndex_eq_maxCommittableIndex
        (state.nodes node)
        (facts.committedFrontierIsSignature node)]
      exact termAtTakeOfLe le_rfl
    · rw [logOther candidate same]
  have votedEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have votesEq :
      forall candidate,
        ((next state (.becomeLeader node)).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, same
      ]
  have sentNode :
      ((next state (.becomeLeader node)).nodes node).sentIndex =
        fun _ => promotionLog.length := by
    simp [next, CCFRaft.next, promotionLog]
  have matchNode :
      ((next state (.becomeLeader node)).nodes node).matchIndex =
        fun _ => 0 := by
    simp [next, CCFRaft.next]
  have sentOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.becomeLeader node)).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have matchOther :
      forall candidate,
        Not (candidate = node) ->
        ((next state (.becomeLeader node)).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate different
    simp [
      next, CCFRaft.next, updateNode,
      Function.update, different
    ]
  have networkEq :
      (next state (.becomeLeader node)).network = state.network := by
    simp [next, CCFRaft.next]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (next state (.becomeLeader node)) candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (processed | queued)
      · exact Or.inl (by simpa [votesEq] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            granted, by simpa [termEq] using responseTerm,
            responseSource, responseDestination⟩
    · rintro (processed | queued)
      · exact Or.inl (by simpa [votesEq] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            granted, by simpa [termEq] using responseTerm,
            responseSource, responseDestination⟩
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority
            (next state (.becomeLeader node)) candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (next state (.becomeLeader node)) candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (effective | eligible)
    · exact Or.inl (by
        rw [effectiveElectionVotersEq] at effective
        exact effective)
    · exact Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, maxCommittableIndexEq, maxCommittableTermEq,
          lastIndexEq, lastTermEq, votedEq, voteLogUpToDate
        ] using eligible)
    · exact Or.inl (by
        rw [effectiveElectionVotersEq]
        exact effective)
    · exact Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, maxCommittableIndexEq, maxCommittableTermEq,
          lastIndexEq, lastTermEq, votedEq, voteLogUpToDate
        ] using eligible)
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority
            (next state (.becomeLeader node)) candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq
    ]
  have effectiveAckersOtherEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            effectiveAckers
                (next state (.becomeLeader node))
                responseHistory leader index =
              effectiveAckers state responseHistory leader index := by
    intro leader leaderNe index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr
          (Or.inl (by simpa [matchOther leader leaderNe] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, responseTerm, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            success, by simpa [termEq] using responseTerm,
            sourceEq, destinationEq, lastIndex,
            by simpa [logOther leader leaderNe] using covered⟩
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr
          (Or.inl (by simpa [matchOther leader leaderNe] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, responseTerm, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            success, by simpa [termEq] using responseTerm,
            sourceEq, destinationEq, lastIndex,
            by simpa [logOther leader leaderNe] using covered⟩
  have effectiveMajorityOtherEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            hasEffectiveMajorityAt
                (next state (.becomeLeader node))
                responseHistory leader index ↔
              hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader leaderNe index
    simp only [
      hasEffectiveMajorityAt,
      effectiveAckersOtherEq leader leaderNe index
    ]
  have noNewLeaderPotential :
      forall index,
        termAt
            ((next state (.becomeLeader node)).nodes node).log index =
          ((next state (.becomeLeader node)).nodes node).currentTerm ->
        Not
          (hasEffectiveMajorityAt
            (next state (.becomeLeader node))
            responseHistory node index) := by
    intro index current
    have indexPositive : 0 < index := by
      by_contra notPositive
      have indexZero : index = 0 := Nat.eq_zero_of_not_pos notPositive
      subst index
      have positive := facts.currentTermsPositive node
      rw [termEq] at current
      simp [termAt, entryAt?, TERM_ONE] at current positive
      omega
    have onlySelf :
        effectiveAckers
            (next state (.becomeLeader node))
            responseHistory node index =
          {node} := by
      ext peer
      simp only [
        effectiveAckers, Finset.mem_filter,
        Finset.mem_univ, true_and, Finset.mem_singleton
      ]
      constructor
      · rintro (self | matched | queued)
        · exact self
        · rw [matchNode] at matched
          simp at matched
          omega
        · rcases queued with
            ⟨response, member, success, responseTerm, _,
              responseDestination, _, _⟩
          have oldMember :
              Message.appendEntriesResponse response ∈
                state.network node := by
            simpa [networkEq] using member
          have sameOldTerm :
              response.term =
                (state.nodes response.destination).currentTerm := by
            rw [responseDestination]
            simpa [termEq] using responseTerm
          have oldLeader :=
            ((facts.networkHistory.appendResponse
              node response oldMember success).2.2 sameOldTerm).1
          rw [responseDestination] at oldLeader
          exact False.elim (Role.noConfusion (oldRole.symm.trans oldLeader))
      · exact fun self => Or.inl self
    intro majority
    unfold hasEffectiveMajorityAt at majority
    rw [onlySelf] at majority
    exact singletonNotElectionMajority node majority
  have noNewLeaderCurrentTerm :
      forall index,
        Not (
          termAt
              ((next state (.becomeLeader node)).nodes node).log index =
            ((next state (.becomeLeader node)).nodes node).currentTerm) := by
    intro index current
    have positive :
        0 <
          termAt
            ((next state (.becomeLeader node)).nodes node).log index := by
      rw [current, termEq]
      simpa [TERM_ONE] using facts.currentTermsPositive node
    rcases termAtPositiveEntry positive with
      ⟨foundEntry, found, foundTerm⟩
    have oldFound :
        entryAt? (state.nodes node).log index = some foundEntry := by
      rw [logNode] at found
      exact CCFRaft.entryAt_of_prefix promotionPrefix found
    exact
      oldCandidateTermNot
        node oldRole oldEffectiveMajority node index foundEntry
          oldFound
          (by simpa [termEq] using foundTerm.trans current)
  have preserveEarlierBad :
      forall source index bound,
        Not (source = node) ->
        EarlierBadElection state elections source index bound ->
          EarlierBadElection
            (next state (.becomeLeader node))
              newElections source index bound := by
    intro source index bound sourceNe bad
    rcases bad with
      ⟨badTerm, badRecord, above, bounded, badRecorded, missing⟩
    have badTermNe :=
      recordedTermNeNew badTerm badRecord badRecorded
    exact
      ⟨badTerm, badRecord,
        by simpa [termEq] using above,
        bounded,
        by simpa [
          newElections, Function.update, badTermNe
        ] using badRecorded,
        by simpa [logOther source sourceNe] using missing⟩
  refine
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [commitEq, logNode, promotionLength]
      exact
        commitIndex_le_maxCommittableIndex
          (state.nodes node)
          (facts.committedFrontierIsSignature node)
    · rw [commitEq, logOther candidate same]
      exact facts.commitIndicesBounded candidate
  · intro candidate positive
    have oldPositive :
        0 < (state.nodes candidate).commitIndex := by
      simpa [commitEq] using positive
    have oldSignature :=
      facts.committedFrontierIsSignature candidate oldPositive
    by_cases same : candidate = node
    · subst candidate
      rw [commitEq, logNode]
      exact
        isSignatureAt_take_of_le
          (commitIndex_le_maxCommittableIndex
            (state.nodes node)
            (facts.committedFrontierIsSignature node))
          oldSignature
    · rw [commitEq, logOther candidate same]
      exact oldSignature
  · intro candidate
    rw [termEq]
    exact facts.currentTermsPositive candidate
  · intro candidate entry member
    rw [termEq]
    by_cases same : candidate = node
    · subst candidate
      rw [logNode] at member
      exact
        facts.entriesDoNotExceedCurrentTerm node entry
          (CCFRaft.memOfPrefix promotionPrefix member)
    · rw [logOther candidate same] at member
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · intro candidate role
    have candidateNe : Not (candidate = node) := by
      intro same
      subst candidate
      exact Role.noConfusion (role.symm.trans roleNode)
    rw [roleOther candidate candidateNe] at role
    rw [votedEq, votesEq]
    exact facts.candidatesSelfVote candidate role
  · intro leader role
    by_cases leaderEq : leader = node
    · subst leader
      right
      unfold hasElectionMajority at oldMajority ⊢
      rw [votesEq]
      exact oldMajority
    · rw [roleOther leader leaderEq] at role
      have old := facts.leadersHaveElectionMajority leader role
      rw [termEq]
      rcases old with bootstrap | majority
      · exact Or.inl bootstrap
      · right
        unfold hasElectionMajority at majority ⊢
        rw [votesEq]
        exact majority
  · intro leader role peer
    by_cases leaderEq : leader = node
    · subst leader
      rw [sentNode, matchNode, logNode]
      simp
    · rw [roleOther leader leaderEq] at role
      have old := facts.leaderProgressBounded leader role peer
      rw [
        sentOther leader leaderEq, matchOther leader leaderEq,
        logOther leader leaderEq
      ]
      exact old
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [termEq, votedEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      rw [termEq] at future
      exact facts.voteHistory.future voter term future
    · intro candidate voter active member
      rw [termEq]
      rw [votesEq] at member
      by_cases candidateEq : candidate = node
      · subst candidate
        exact
          facts.voteHistory.counted
            node voter (Or.inl oldRole) member
      · rw [roleOther candidate candidateEq] at active
        exact facts.voteHistory.counted candidate voter active member
  · constructor
    · intro destination message member
      rw [networkEq] at member
      exact facts.networkHistory.addressed destination message member
    · intro destination request member
      rw [networkEq] at member
      have old := facts.networkHistory.appendRequest destination request member
      refine ⟨old.1, old.2.1, old.2.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      rw [committedEq]
      exact old.2.2.2
    · intro destination response member success
      rw [networkEq] at member
      have responseDestination :
          response.destination = destination := by
        simpa using
          facts.networkHistory.addressed
            destination (.appendEntriesResponse response) member
      subst destination
      rcases
          facts.networkHistory.appendResponse
            response.destination response member success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, by simpa [termEq] using termBound, ?_⟩
      intro sameTerm
      have oldSameTerm :
          response.term =
            (state.nodes response.destination).currentTerm := by
        simpa [termEq] using sameTerm
      rcases supported oldSameTerm with ⟨oldLeader, covered⟩
      by_cases destinationEq : response.destination = node
      · rw [destinationEq, oldRole] at oldLeader
        contradiction
      · constructor
        · simpa [roleOther response.destination destinationEq] using oldLeader
        · simpa [logOther response.destination destinationEq] using covered
    · intro destination request member
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteRequest destination request member with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine
        ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap,
          by simpa [termEq] using termBound, ?_⟩
      intro sameTerm active
      have oldPrefix := activePrefix
        (by simpa [termEq] using sameTerm)
        (by
          by_cases sourceEq : request.source = node
          · rw [sourceEq]
            exact Or.inl oldRole
          · simpa [roleOther request.source sourceEq] using active)
      by_cases sourceEq : request.source = node
      · rw [sourceEq] at oldPrefix ⊢
        rw [logNode]
        exact
          committablePrefixOfMaxTake oldPrefix maxIndex
      · simpa [logOther request.source sourceEq] using oldPrefix
    · intro destination response member granted
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteResponse destination response member granted with
        ⟨termBound, vote, candidateCommittable,
          voterCommittable, upToDate⟩
      exact
        ⟨by simpa [termEq] using termBound,
          vote, candidateCommittable, voterCommittable,
          by simpa [voteLogUpToDate] using upToDate⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (next state (.becomeLeader node))
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state (next state (.becomeLeader node))
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitEq committedEq
    · intro candidate
      exact Nat.le_of_eq (termEq candidate).symm
    · intro destination request member
      simpa [networkEq] using member
  have knownBack :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            (next state (.becomeLeader node))
            appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix := by
    intro evidence supportedPrefix known
    exact
      knownCommitEvidenceFrameBack
        state (next state (.becomeLeader node))
          appendHistory nodeEvidence requestEvidence
          commitEq committedEq
          (fun destination request member => by
            simpa [networkEq] using member)
          known
  have newPromotionCovered :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            (next state (.becomeLeader node))
            appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
        evidence.commitTerm < (state.nodes node).currentTerm ->
          evidence.history.take evidence.commitFrontier <+:
            promotionLog := by
    intro evidence supportedPrefix known strict
    have oldKnown := knownBack evidence supportedPrefix known
    rcases knownCommitEvidenceValid evidenceFacts oldKnown with
      ⟨frontierBound, frontierTerm, supportedBound,
        supportedEq, ackMajority, memberAgreement, frontierSignature⟩
    rcases
        majoritiesIntersect
          evidence.ackQuorum
          (effectiveElectionVoters state node)
          ackMajority oldEffectiveMajority with
      ⟨witness, witnessMember⟩
    have witnessParts :
        witness ∈ evidence.ackQuorum /\
          witness ∈ effectiveElectionVoters state node := by
      simpa using witnessMember
    have candidateEntriesBefore :
        forall entry,
          entry ∈ (state.nodes node).log ->
            entry.term < (state.nodes node).currentTerm := by
      intro entry entryMember
      have bounded :=
        facts.entriesDoNotExceedCurrentTerm node entry entryMember
      have different :
          Not (entry.term = (state.nodes node).currentTerm) := by
        intro same
        rcases memberEntryAt entryMember with ⟨index, found⟩
        exact
          oldCandidateTermNot
            node oldRole oldEffectiveMajority
              node index entry found same
      omega
    have covered :=
      prospectiveFacts.relaxedSupporterCarriesFrontier
        evidence supportedPrefix oldKnown node witness
          oldRole strict candidateEntriesBefore
          witnessParts.1 (by
            simp only [
              relaxedElectionVoters, Finset.mem_filter,
              Finset.mem_univ, true_and
            ]
            exact Or.inl witnessParts.2)
    apply signatureEndedPrefixOfMaxTake covered
    have prefixLength :
        (evidence.history.take evidence.commitFrontier).length =
          evidence.commitFrontier := by
      simp [Nat.min_eq_left frontierBound]
    rw [prefixLength]
    exact isSignatureAt_take_of_le le_rfl frontierSignature
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (next state (.becomeLeader node))
        appendHistory nodeEvidence requestEvidence newElections := by
    constructor
    · intro evidence supportedPrefix known
      exact
        prospectiveFacts.commitTermPositive
          evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
    · intro evidence supportedPrefix known term record recorded newer
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have recordEq : electionRecord = record :=
          Option.some.inj (by
            simpa [newElections] using recorded)
        subst record
        simpa [electionRecord] using
          newPromotionCovered evidence supportedPrefix known newer
      · have oldRecorded :
            elections term = some record := by
          simpa [
            newElections, Function.update, termEqNode
          ] using recorded
        exact
          prospectiveFacts.electionClosure
            evidence supportedPrefix
              (knownBack evidence supportedPrefix known)
              term record oldRecorded newer
    · intro evidence supportedPrefix known member ackMember
      by_cases memberEq : member = node
      · subst member
        have oldKnown := knownBack evidence supportedPrefix known
        have oldCovered :=
          prospectiveFacts.currentMember
            evidence supportedPrefix oldKnown node ackMember
        have valid := knownCommitEvidenceValid evidenceFacts oldKnown
        have frontierPositive : 0 < evidence.commitFrontier := by
          have supportedPositive :=
            knownCommitEvidenceSupportedLengthPositive evidenceFacts oldKnown
          exact supportedPositive.trans_le valid.2.2.1
        rcases
            entryAtSomeOfPositiveBound frontierPositive valid.1 with
          ⟨frontierEntry, historyFound⟩
        have prefixFound :
            entryAt?
                (evidence.history.take evidence.commitFrontier)
                evidence.commitFrontier =
              some frontierEntry := by
          rw [entryAtTake_of_le le_rfl]
          exact historyFound
        have nodeFound :
            entryAt? (state.nodes node).log evidence.commitFrontier =
              some frontierEntry :=
          CCFRaft.entryAt_of_prefix oldCovered prefixFound
        have frontierTerm :
            frontierEntry.term = evidence.commitTerm := by
          simpa [termAt, historyFound] using valid.2.1
        have termBound :=
          facts.entriesDoNotExceedCurrentTerm node frontierEntry
            (CCFRaft.entryAt_mem nodeFound)
        have termNe :
            Not (
              frontierEntry.term =
                (state.nodes node).currentTerm) :=
          oldCandidateTermNot
            node oldRole oldEffectiveMajority node
              evidence.commitFrontier frontierEntry nodeFound
        have strict :
            evidence.commitTerm < (state.nodes node).currentTerm := by
          rw [← frontierTerm]
          omega
        simpa [logNode] using
          newPromotionCovered evidence supportedPrefix known strict
      · simpa [logOther member memberEq] using
          prospectiveFacts.currentMember
            evidence supportedPrefix
              (knownBack evidence supportedPrefix known)
              member ackMember
    · intro evidence supportedPrefix known destination request
        queued sameTerm
      exact
        prospectiveFacts.sameTermQueuedComparable
          evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            destination request
            (by simpa [networkEq] using queued)
            sameTerm
    · intro evidence supportedPrefix known candidate member role newer
        entriesBefore ackMember relaxed
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleNode)
      simpa [
        roleOther candidate candidateNe,
        termEq, logOther candidate candidateNe,
        maxCommittableIndexEq, maxCommittableTermEq,
        lastIndexEq, lastTermEq, votedEq,
        effectiveElectionVotersEq,
        relaxedElectionVoters,
        makeRequestVoteRequest,
        voteLogUpToDate
      ] using
        prospectiveFacts.relaxedSupporterCarriesFrontier
          evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            candidate member
            (by simpa [roleOther candidate candidateNe] using role)
            (by simpa [termEq] using newer)
            (by
              intro entry entryMember
              simpa [termEq] using
                entriesBefore entry
                  (by simpa [logOther candidate candidateNe] using entryMember))
            ackMember
            (by simpa [
              relaxedElectionVoters,
              makeRequestVoteRequest,
              termEq, logOther candidate candidateNe,
              maxCommittableIndexEq, maxCommittableTermEq,
              lastIndexEq, lastTermEq, votedEq,
              effectiveElectionVotersEq,
              voteLogUpToDate
            ] using relaxed)
  · refine
      ⟨newOwners, newCanonicalHistory, newElections,
        nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · have above := candidatesAboveBootstrap node oldRole
      have termNe :
          Not (TERM_ONE = (state.nodes node).currentTerm) := by
        omega
      simpa [
        newOwners, Function.update, termNe
      ] using ownership.bootstrap
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        simp [newOwners, termEq]
      · have oldLeader :
            (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have differentTerm :
            Not (
              (state.nodes leader).currentTerm =
                (state.nodes node).currentTerm) :=
          fun same =>
            winningCandidateTermDiffersFromLeader
              facts.currentTermsPositive candidatesAboveBootstrap
                facts.leadersHaveElectionMajority facts.voteHistory
                facts.grantedVoteSnapshots oldRole oldEffectiveMajority
                oldLeader same.symm
        have oldOwned := ownership.activeLeader leader oldLeader
        simpa [
          newOwners, Function.update, termEq,
          differentTerm
        ] using oldOwned
    · intro owner index entry found
      have oldFound :
          entryAt? (state.nodes owner).log index = some entry := by
        by_cases ownerEq : owner = node
        · subst owner
          rw [logNode] at found
          exact CCFRaft.entryAt_of_prefix promotionPrefix found
        · simpa [logOther owner ownerEq] using found
      have termNe :
          Not (entry.term = (state.nodes node).currentTerm) :=
        oldCandidateTermNot
          node oldRole oldEffectiveMajority owner index entry oldFound
      rcases
          ownership.logEntryAgreement owner index entry oldFound with
        ⟨canonicalFound, agreed⟩
      exact
        ⟨by simpa [
            newCanonicalHistory, Function.update, termNe
          ] using canonicalFound,
          by
            by_cases ownerEq : owner = node
            · subst owner
              have promotionFound :
                  entryAt? promotionLog index = some entry := by
                simpa [logNode] using found
              rw [logNode]
              calc
                promotionLog.take index =
                    (state.nodes node).log.take index :=
                  CCFRaft.takeEqOfPrefix promotionPrefix
                    (entryAtSomeIndexBound promotionFound)
                _ =
                    (newCanonicalHistory entry.term).take index := by
                  simpa [
                    newCanonicalHistory, Function.update, termNe
                  ] using agreed
            · simpa [
                logOther owner ownerEq,
                newCanonicalHistory, Function.update, termNe
              ] using agreed⟩
    · intro destination request member index entry found
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [networkEq] using member
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request oldMember index entry found with
        ⟨canonicalFound, agreed⟩
      have termNe :
          Not (entry.term = (state.nodes node).currentTerm) := by
        intro same
        rcases
            ownership.canonicalEntryOwner
              entry.term index entry canonicalFound with
          ⟨termOwner, owned⟩
        rw [same, oldTermUnowned] at owned
        contradiction
      exact
        ⟨by simpa [
            newCanonicalHistory, Function.update, termNe
          ] using canonicalFound,
          by simpa [
            newCanonicalHistory, Function.update, termNe
          ] using agreed⟩
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        simp [
          newCanonicalHistory, Function.update, termEq, logNode
        ]
      · have oldLeader :
            (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have differentTerm :
            Not (
              (state.nodes leader).currentTerm =
                (state.nodes node).currentTerm) :=
          fun same =>
            winningCandidateTermDiffersFromLeader
              facts.currentTermsPositive candidatesAboveBootstrap
                facts.leadersHaveElectionMajority facts.voteHistory
                facts.grantedVoteSnapshots oldRole oldEffectiveMajority
                oldLeader same.symm
        have oldHistory :=
          ownership.activeLeaderHistory leader oldLeader
        simpa [
          newCanonicalHistory, Function.update, differentTerm,
          termEq, logOther leader leaderEq
        ] using oldHistory
    · intro term index entry found
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have candidateFound :
            entryAt? (state.nodes node).log index = some entry := by
          have promotionFound :
              entryAt? promotionLog index = some entry := by
            simpa [
              newCanonicalHistory, Function.update
            ] using found
          exact CCFRaft.entryAt_of_prefix promotionPrefix promotionFound
        have entryTermNe :
            Not (entry.term = (state.nodes node).currentTerm) :=
          oldCandidateTermNot
            node oldRole oldEffectiveMajority node index entry candidateFound
        rcases
            termOwnershipLogEntryOwner ownership
              (entryAtSomeMember candidateFound) with
          ⟨termOwner, owned⟩
        exact
          ⟨termOwner, by
            simpa [
              newOwners, Function.update, entryTermNe
            ] using owned⟩
      · have oldFound :
            entryAt? (canonicalHistory term) index = some entry := by
          simpa [
            newCanonicalHistory, Function.update, termEqNode
          ] using found
        rcases
            ownership.canonicalEntryOwner term index entry oldFound with
          ⟨termOwner, owned⟩
        have entryTermNe :
            Not (entry.term = (state.nodes node).currentTerm) := by
          intro same
          rw [same, oldTermUnowned] at owned
          contradiction
        exact
          ⟨termOwner, by
            simpa [
              newOwners, Function.update, entryTermNe
            ] using owned⟩
    · intro term
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        simpa [
          newCanonicalHistory, Function.update
        ] using
          monoHistoryOfPrefix
            ((canonicalHistoriesMonoLog ownership) node)
            promotionPrefix
      · simpa [
          newCanonicalHistory, Function.update, termEqNode
        ] using ownership.canonicalMonoLog term
    · intro term owner owned
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have ownerEq : owner = node := by
          have nodeEqOwner : node = owner := by
            simpa [newOwners] using owned
          exact nodeEqOwner.symm
        subst owner
        exact
          ⟨by simp [termEq],
            by intro _
               exact roleNode⟩
      · have oldOwned : owners term = some owner := by
          simpa [
            newOwners, Function.update, termEqNode
          ] using owned
        rcases ownership.ownerProgress term owner oldOwned with
          ⟨bound, oldLeader⟩
        constructor
        · simpa [termEq] using bound
        · intro same
          by_cases ownerEq : owner = node
          · subst owner
            exact roleNode
          · have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using same
            simpa [roleOther owner ownerEq] using oldLeader oldSame
    · intro destination request member
      rcases
          ownership.queuedAppendMetadata destination request
            (by simpa [networkEq] using member) with
        ⟨owned, bounded⟩
      refine ⟨?_, bounded⟩
      by_cases requestTermEq :
          request.term = (state.nodes node).currentTerm
      · rw [requestTermEq, oldTermUnowned] at owned
        contradiction
      · simpa [
          newOwners, Function.update, requestTermEq
        ] using owned
    · intro destination request member sameTerm leaderRole
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [networkEq] using member
      by_cases sourceEq : request.source = node
      · have requestSourceEq : request.source = node := sourceEq
        rcases
            ownership.queuedAppendMetadata
              destination request oldMember with
          ⟨owned, _⟩
        have progress :=
          ownership.ownerProgress request.term node
            (by simpa [requestSourceEq] using owned)
        have oldSame :
            request.term = (state.nodes node).currentTerm := by
          simpa [termEq, requestSourceEq] using sameTerm
        exact False.elim
          (Role.noConfusion ((progress.2 oldSame).symm.trans oldRole))
      · have oldPrefix :=
          ownership.queuedActiveSourceHistory
            destination request oldMember
              (by simpa [termEq] using sameTerm)
              (by simpa [roleOther request.source sourceEq] using leaderRole)
        simpa [logOther request.source sourceEq] using oldPrefix
    · constructor
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          simp [newOwners, electionRecord]
        · have oldRecorded :
              elections term = some record := by
            simpa [
              newElections, Function.update, termEqNode
            ] using recorded
          simpa [
            newOwners, Function.update, termEqNode
          ] using electionFacts.recordOwned term record oldRecorded
      · intro term owner owned
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have ownerEq : node = owner :=
            Option.some.inj (by
              simpa [newOwners] using owned)
          subst owner
          right
          exact
            ⟨electionRecord,
              by simp [newElections],
              by simp [electionRecord]⟩
        · have oldOwned : owners term = some owner := by
            simpa [
              newOwners, Function.update, termEqNode
            ] using owned
          rcases
              electionFacts.ownerRecorded term owner oldOwned with
            bootstrap | recorded
          · exact Or.inl bootstrap
          · right
            rcases recorded with
              ⟨record, oldRecorded, recordLeader⟩
            exact
              ⟨record,
                by simpa [
                  newElections, Function.update, termEqNode
                ] using oldRecorded,
                recordLeader⟩
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          exact candidatesAboveBootstrap node oldRole
        · exact
            electionFacts.postBootstrap term record
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          simpa [electionRecord] using oldMajority
        · exact
            electionFacts.majority term record
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          exact
            facts.voteHistory.counted node voter
              (Or.inl oldRole)
              (by simpa [electionRecord] using member)
        · exact
            electionFacts.voted term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          simp [
            electionRecord, newCanonicalHistory
          ]
        · have oldRecorded :
              elections term = some record := by
            simpa [
              newElections, Function.update, termEqNode
            ] using recorded
          simpa [
            newCanonicalHistory, Function.update, termEqNode
          ] using
            electionFacts.promotionCanonical
              term record oldRecorded
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          simpa [electionRecord] using promotionCommittable
        · exact
            electionFacts.promotionCommittable term record
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
      · intro term record recorded entry member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          have oldMember :
              entry ∈ (state.nodes node).log :=
            CCFRaft.memOfPrefix promotionPrefix
              (by simpa [electionRecord] using member)
          have bounded :=
            facts.entriesDoNotExceedCurrentTerm
              node entry oldMember
          have different :
              Not (entry.term = (state.nodes node).currentTerm) := by
            intro same
            rcases
                termOwnershipLogEntryOwner ownership
                  oldMember with
              ⟨owner, owned⟩
            rw [same, oldTermUnowned] at owned
            contradiction
          omega
        · exact
            electionFacts.promotionEntriesBeforeTerm
              term record
                (by simpa [
                  newElections, Function.update, termEqNode
                ] using recorded)
                entry member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simp [electionRecord]
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter, Finset.mem_univ, true_and
              ]
              exact Or.inl (by simpa [electionRecord] using member)
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using
                committablePrefixOfMaxTake
                  snapshot.1 snapshot.2.1
        · exact
            electionFacts.candidatePrefix term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord] using
              canonicalFrameToNew
                promotionLog
                (historyCanonicalOfPrefix
                  (nodeLogCanonical ownership node)
                  promotionPrefix)
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter, Finset.mem_univ, true_and
              ]
              exact Or.inl (by simpa [electionRecord] using member)
            rcases
                voteCanonicalFacts
                  node voter (Or.inl oldRole) effectiveMember with
              self | snapshots
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using
                canonicalFrameToNew _ snapshots.1
        · exact
            canonicalFrameToNew _
              (electionFacts.candidateCanonical
                term record voter
                  (by simpa [
                    newElections, Function.update, termEqNode
                  ] using recorded)
                  member)
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord] using promotionCommittable
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter, Finset.mem_univ, true_and
              ]
              exact Or.inl (by simpa [electionRecord] using member)
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using snapshot.2.1
        · exact
            electionFacts.candidateCommittable term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord] using
              canonicalFrameToNew
                promotionLog
                (historyCanonicalOfPrefix
                  (nodeLogCanonical ownership node)
                  promotionPrefix)
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter, Finset.mem_univ, true_and
              ]
              exact Or.inl (by simpa [electionRecord] using member)
            rcases
                voteCanonicalFacts
                  node voter (Or.inl oldRole) effectiveMember with
              self | snapshots
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using
                canonicalFrameToNew _ snapshots.2.2.1
        · exact
            canonicalFrameToNew _
              (electionFacts.voterCanonical
                term record voter
                  (by simpa [
                    newElections, Function.update, termEqNode
                  ] using recorded)
                  member)
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord] using promotionCommittable
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter, Finset.mem_univ, true_and
              ]
              exact Or.inl (by simpa [electionRecord] using member)
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using snapshot.2.2.1
        · exact
            electionFacts.voterCommittable term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            right
            constructor
            · simp [
                electionRecord, maxCommittableTerm,
                promotionCommittable
              ]
            · simpa [electionRecord, promotionCommittable]
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter, Finset.mem_univ, true_and
              ]
              exact Or.inl (by simpa [electionRecord] using member)
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [
                electionRecord, voterEq, voteLogUpToDate
              ] using snapshot.2.2.2.2
        · exact
            electionFacts.upToDate term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
    · apply
        grantedVoteCanonicalFrame
          state (next state (.becomeLeader node))
            canonicalHistory newCanonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => termEq candidate)
      · intro candidate active
        by_cases candidateEq : candidate = node
        · subst candidate
          exact Or.inl oldRole
        · rw [roleOther candidate candidateEq] at active
          exact active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical index entry found
        rcases canonical index entry found with
          ⟨canonicalFound, agreed⟩
        have entryTermNe :
            Not (entry.term = (state.nodes node).currentTerm) := by
          intro same
          rcases
              ownership.canonicalEntryOwner
                entry.term index entry canonicalFound with
            ⟨owner, owned⟩
          rw [same, oldTermUnowned] at owned
          contradiction
        exact
          ⟨by simpa [
              newCanonicalHistory, Function.update, entryTermNe
            ] using canonicalFound,
            by simpa [
              newCanonicalHistory, Function.update, entryTermNe
            ] using agreed⟩
    · intro source index role current signature voter effective
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          voter ∈ effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      rcases
          ackerCurrentFacts source index oldRole oldCurrent oldSignature
            voter oldEffective with
        retained | bad
      · left
        by_cases voterEq : voter = node
        · subst voter
          simpa [logOther source sourceNe, logNode] using
            (signatureEndedPrefixOfMaxTake
              retained (signatureAtTakeLength oldSignature))
        · simpa [
            logOther source sourceNe,
            logOther voter voterEq
          ] using retained
      · exact Or.inr (by
          simpa [termEq] using
            preserveEarlierBad
              source index (state.nodes voter).currentTerm sourceNe bad)
    · intro source index role current signature
        voter voteTerm candidate effective voted different newer
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          voter ∈ effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      rcases
          ackerVoteFacts source index oldRole oldCurrent oldSignature
            voter voteTerm candidate oldEffective voted different
              (by simpa [termEq] using newer) with
        retained | bad
      · exact Or.inl
          (by simpa [logOther source sourceNe] using retained)
      · exact Or.inr
          (preserveEarlierBad source index voteTerm sourceNe bad)
    · intro source index role current signature term record voter
        recorded member effective newer
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          voter ∈ effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have recordEq : electionRecord = record :=
          Option.some.inj (by
            simpa [newElections] using recorded)
        subst record
        by_cases voterEq : voter = node
        · subst voter
          rcases
              ackerCurrentFacts source index oldRole oldCurrent
                oldSignature node oldEffective with
            retained | bad
          · exact Or.inl
              (by simpa [
                electionRecord, logOther source sourceNe
              ] using
                (signatureEndedPrefixOfMaxTake
                  retained (signatureAtTakeLength oldSignature)))
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded,
                badRecorded, missing⟩
            have badTermNe :=
              recordedTermNeNew badTerm badRecord badRecorded
            exact
              ⟨badTerm, badRecord,
                by simpa [termEq] using above,
                by omega,
                by simpa [
                  newElections, Function.update, badTermNe
                ] using badRecorded,
                by simpa [logOther source sourceNe] using missing⟩
        · have voterInVotes :
              voter ∈ (state.nodes node).votesGranted := by
            simpa [electionRecord] using member
          have voterVoted :
              votes voter (state.nodes node).currentTerm = some node :=
            facts.voteHistory.counted
              node voter (Or.inl enabled.1) voterInVotes
          rcases
              ackerVoteFacts source index oldRole oldCurrent
                oldSignature
                voter (state.nodes node).currentTerm node
                oldEffective voterVoted voterEq
                (by simpa [termEq] using newer) with
            retained | bad
          · exact Or.inl
              (by simpa [
                electionRecord, voterEq,
                logOther source sourceNe
              ] using retained)
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded,
                badRecorded, missing⟩
            have badTermNe :=
              recordedTermNeNew badTerm badRecord badRecorded
            exact
              ⟨badTerm, badRecord,
                by simpa [termEq] using above,
                by omega,
                by simpa [
                  newElections, Function.update, badTermNe
                ] using badRecorded,
                by simpa [logOther source sourceNe] using missing⟩
      · have oldRecorded :
            elections term = some record := by
          simpa [
            newElections, Function.update, termEqNode
          ] using recorded
        rcases
            ackerElectionFacts source index oldRole oldCurrent
              oldSignature term record voter oldRecorded member oldEffective
                (by simpa [termEq] using newer) with
          retained | bad
        · exact Or.inl
            (by simpa [logOther source sourceNe] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, below,
              badRecorded, missing⟩
          have badTermNe :=
            recordedTermNeNew badTerm badRecord badRecorded
          exact
            ⟨badTerm, badRecord,
              by simpa [termEq] using above,
              below,
              by simpa [
                newElections, Function.update, badTermNe
              ] using badRecorded,
              by simpa [logOther source sourceNe] using missing⟩
    · intro destination request member record recorded
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [networkEq] using member
      by_cases termEqNode :
          request.term = (state.nodes node).currentTerm
      · have owned :=
          (ownership.queuedAppendMetadata
            destination request oldMember).1
        rw [termEqNode, oldTermUnowned] at owned
        contradiction
      · have oldRecorded :
            elections request.term = some record := by
          simpa [
            newElections, Function.update, termEqNode
          ] using recorded
        exact
          electionQueuedFacts
            destination request oldMember record oldRecorded
  · intro candidate voter active member
    rw [termEq candidate, termEq voter]
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    have oldActive :
        (state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader := by
      by_cases candidateEq : candidate = node
      · subst candidate
        exact Or.inl oldRole
      · rw [roleOther candidate candidateEq] at active
        exact active
    rcases
        facts.grantedVoteSnapshots
          candidate voter oldActive oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · refine ⟨recorded, Or.inr ⟨?_, snapshot.2.1,
        snapshot.2.2.1, ?_, ?_⟩⟩
      · by_cases candidateEq : candidate = node
        · subst candidate
          rw [logNode]
          exact
            committablePrefixOfMaxTake snapshot.1 snapshot.2.1
        · simpa [logOther candidate candidateEq] using snapshot.1
      · simpa [termEq] using snapshot.2.2.2.1
      · simpa [voteLogUpToDate, maxCommittableIndexEq,
          maxCommittableTermEq] using snapshot.2.2.2.2
  · refine ⟨newAckHistory, ?_⟩
    constructor
    · intro leader role peer zero
      by_cases leaderEq : leader = node
      · subst leader
        simp [newAckHistory]
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have oldZero :
            (state.nodes leader).matchIndex peer = 0 := by
          simpa [matchOther leader leaderEq] using zero
        simpa [newAckHistory, Function.update, leaderEq] using
          ackFacts.zero leader oldRole peer oldZero
    · intro leader role peer positive
      by_cases leaderEq : leader = node
      · subst leader
        rw [matchNode] at positive
        simp at positive
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have oldPositive :
            0 < (state.nodes leader).matchIndex peer := by
          simpa [matchOther leader leaderEq] using positive
        rcases
            ackFacts.positive leader oldRole peer oldPositive with
          ⟨snapshot, stored, snapshotTerm, snapshotIndex,
            historyBound, agreed⟩
        exact
          ⟨snapshot,
            by simpa [
              newAckHistory, Function.update, leaderEq
            ] using stored,
            by simpa [termEq] using snapshotTerm,
            by simpa [matchOther leader leaderEq] using snapshotIndex,
            historyBound,
            by simpa [logOther leader leaderEq] using agreed⟩
/-! ## Commit advancement -/

/-- Advancing a current-term quorum frontier preserves all safety evidence. -/
theorem advanceCommitPreservesSystemInductiveInvariant
      (state : State TxId)
      (node : Node)
      (invariant : SystemInductiveInvariant state)
      (enabled : Enabled state (.advanceCommitIndex node)) :
      SystemInductiveInvariant
        (next state (.advanceCommitIndex node)) := by
  rcases invariant with
      ⟨votes, appendHistory, responseHistory,
        voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  have potentialCommitElectionSafe :
      PotentialCommitElectionSafe state responseHistory :=
    derivePotentialCommitElectionSafe
      facts.currentTermsPositive
      facts.committedFrontierIsSignature
      candidatesAboveBootstrap
      facts.entriesDoNotExceedCurrentTerm
      facts.voteHistory
      facts.grantedVoteSnapshots
      voteCanonicalFacts ownership electionFacts
      ackerCurrentFacts ackerVoteFacts ackerElectionFacts
  have potentialCommitQuorumLog :
      PotentialCommitQuorumLog state responseHistory :=
    derivePotentialCommitQuorumLog
      facts.currentTermsPositive facts.voteHistory ownership electionFacts
      ackerCurrentFacts ackerElectionFacts
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let frontier := highestCommittableIndex state node
  have leaderRole : (state.nodes node).role = .leader := enabled.1
  have advances : (state.nodes node).commitIndex < frontier := enabled.2
  have frontierBound :
        frontier <= (state.nodes node).log.length :=
      highestCommittableIndexBounded state node
  have frontierValid :
        termAt (state.nodes node).log frontier =
            (state.nodes node).currentTerm /\
          hasMajorityAt state node frontier :=
      highestCommittableIndexValid state node advances
  have frontierSignature :
      isSignatureAt (state.nodes node).log frontier = true :=
    highestCommittableIndexIsSignature state node advances
  let memberHistory : Node -> List (Entry TxId) :=
    fun member =>
      if member = node then
        (state.nodes node).log
      else
        match ackHistory node member with
        | some snapshot => snapshot.history
        | none => []
  let evidence : CommitEvidence TxId :=
    { commitTerm := (state.nodes node).currentTerm
      committer := node
      history := (state.nodes node).log
      commitFrontier := frontier
      supportedLength := frontier
      ackQuorum := acknowledgingNodes state node frontier
      memberHistory }
  let newNodeEvidence : NodeCommitEvidence TxId :=
    Function.update nodeEvidence node (some evidence)
  have roleEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).role =
            (state.nodes candidate).role := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have termEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).currentTerm =
            (state.nodes candidate).currentTerm := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have logEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).log =
            (state.nodes candidate).log := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have sentEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).sentIndex =
            (state.nodes candidate).sentIndex := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have matchEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).matchIndex =
            (state.nodes candidate).matchIndex := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have votedEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).votedFor =
            (state.nodes candidate).votedFor := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have votesEq :
        forall candidate,
          ((next state (.advanceCommitIndex node)).nodes candidate).votesGranted =
            (state.nodes candidate).votesGranted := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          next, CCFRaft.next, updateNode,
          Function.update, frontier, same
        ]
  have commitNode :
        ((next state (.advanceCommitIndex node)).nodes node).commitIndex =
          frontier := by
      simp [next, CCFRaft.next, frontier]
  have commitOther :
        forall candidate,
          Not (candidate = node) ->
          ((next state (.advanceCommitIndex node)).nodes candidate).commitIndex =
            (state.nodes candidate).commitIndex := by
      intro candidate different
      simp [
        next, CCFRaft.next, updateNode,
        Function.update, frontier, different
      ]
  have committedSignatureAfter :
      CommittedFrontierIsSignature
        (next state (.advanceCommitIndex node)) := by
    intro candidate positive
    by_cases same : candidate = node
    · subst candidate
      rw [commitNode, logEq]
      exact frontierSignature
    · rw [commitOther candidate same, logEq]
      apply facts.committedFrontierIsSignature candidate
      simpa [commitOther candidate same] using positive
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((next state (.advanceCommitIndex node)).nodes candidate) =
          lastCommittableIndex (state.nodes candidate) := by
    intro candidate
    rw [
      lastCommittableIndex_eq_maxCommittableIndex
        ((next state (.advanceCommitIndex node)).nodes candidate)
        (committedSignatureAfter candidate),
      lastCommittableIndex_eq_maxCommittableIndex
        (state.nodes candidate)
        (facts.committedFrontierIsSignature candidate),
      logEq
    ]
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((next state (.advanceCommitIndex node)).nodes candidate) =
          lastCommittableTerm (state.nodes candidate) := by
    intro candidate
    rw [
      lastCommittableTerm_eq_maxCommittableTerm
        ((next state (.advanceCommitIndex node)).nodes candidate)
        (committedSignatureAfter candidate),
      lastCommittableTerm_eq_maxCommittableTerm
        (state.nodes candidate)
        (facts.committedFrontierIsSignature candidate),
      logEq
    ]
  have committedNode :
        ((next state (.advanceCommitIndex node)).nodes node).committedLog =
          (state.nodes node).log.take frontier := by
      simp [NodeState.committedLog, commitNode, logEq]
  have committedOther :
        forall candidate,
          Not (candidate = node) ->
          ((next state (.advanceCommitIndex node)).nodes candidate).committedLog =
            (state.nodes candidate).committedLog := by
      intro candidate different
      simp [NodeState.committedLog, commitOther candidate different, logEq]
  have committedMonotonic :
        forall candidate,
          (state.nodes candidate).committedLog <+:
            ((next state (.advanceCommitIndex node)).nodes candidate).committedLog := by
      intro candidate
      by_cases same : candidate = node
      · subst candidate
        rw [committedNode]
        have oldLe :
            (state.nodes node).commitIndex <= frontier :=
          Nat.le_of_lt advances
        have taken :=
          List.take_prefix
            (state.nodes node).commitIndex
            ((state.nodes node).log.take frontier)
        simpa [
          NodeState.committedLog,
          List.take_take, Nat.min_eq_left oldLe
        ] using taken
      · rw [committedOther candidate same]
  have networkEq :
        (next state (.advanceCommitIndex node)).network = state.network := by
      simp [next, CCFRaft.next, frontier]
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers
            (next state (.advanceCommitIndex node))
            responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, responseTerm, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            success, by simpa [termEq] using responseTerm,
            sourceEq, destinationEq, lastIndex,
            by simpa [logEq] using covered⟩
    · rintro (self | matched | queued)
      · exact Or.inl self
      · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
      · right
        right
        rcases queued with
          ⟨response, member, success, responseTerm, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            success, by simpa [termEq] using responseTerm,
            sourceEq, destinationEq, lastIndex,
            by simpa [logEq] using covered⟩
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt
            (next state (.advanceCommitIndex node))
            responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    simp only [hasEffectiveMajorityAt, effectiveAckersEq]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (next state (.advanceCommitIndex node)) candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (processed | queued)
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨response, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨response, by simpa [networkEq] using member,
          granted, by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨response, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨response, by simpa [networkEq] using member,
          granted, by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority
            (next state (.advanceCommitIndex node)) candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (next state (.advanceCommitIndex node)) candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (effective | eligible)
    · exact Or.inl (by
        rw [effectiveElectionVotersEq] at effective
        exact effective)
    · exact Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedEq, voteLogUpToDate
        ] using eligible)
    · exact Or.inl (by
        rw [effectiveElectionVotersEq]
        exact effective)
    · exact Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedEq, voteLogUpToDate
        ] using eligible)
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority
            (next state (.advanceCommitIndex node)) candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq
    ]
  have frontierEffective :
      hasEffectiveMajorityAt state responseHistory node frontier :=
    majorityImpliesEffectiveMajority
      state responseHistory node frontier frontierValid.2
  have frontierPotential :
      hasPotentialMajorityAt
        state appendHistory responseHistory node frontier :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory node frontier frontierEffective
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (next state (.advanceCommitIndex node))
        votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by simpa [roleEq] using role)
        (fun leader _ => termEq leader)
        logEq
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun candidate => Nat.le_of_eq (termEq candidate).symm)
        (fun _ _ _ voted _ => voted)
  have evidenceValid :
      evidence.Valid ((state.nodes node).log.take frontier) := by
    refine
      ⟨frontierBound, frontierValid.1, le_rfl,
        by simp [evidence], ?_, ?_, by simpa [evidence]⟩
    · simpa [evidence, hasMajorityAt] using frontierValid.2
    · intro member memberIn
      have acknowledges :
          member = node \/
            (state.nodes node).matchIndex member >= frontier := by
        simpa [evidence, acknowledgingNodes] using memberIn
      by_cases self : member = node
      · subst member
        exact
          ⟨by simpa [evidence, memberHistory] using frontierBound,
            by simp [evidence, memberHistory]⟩
      · have matched :
            (state.nodes node).matchIndex member >= frontier :=
          acknowledges.resolve_left self
        have matchPositive :
            0 < (state.nodes node).matchIndex member := by
          have frontierPositive : 0 < frontier := by omega
          omega
        rcases
            ackFacts.positive node leaderRole member matchPositive with
          ⟨snapshot, stored, snapshotTerm, snapshotIndex,
            snapshotBound, agreed⟩
        have frontierHistoryBound :
            frontier <= snapshot.history.length := by
          rw [snapshotIndex] at snapshotBound
          omega
        constructor
        · simpa [evidence, memberHistory, self, stored] using
            frontierHistoryBound
        · simp only [evidence]
          have restricted :
              snapshot.history.take frontier =
                (state.nodes node).log.take frontier := by
            calc
              snapshot.history.take frontier =
                  (snapshot.history.take snapshot.index).take frontier := by
                    rw [List.take_take, Nat.min_eq_left]
                    rw [snapshotIndex]
                    omega
              _ = ((state.nodes node).log.take snapshot.index).take frontier := by
                    rw [agreed]
              _ = (state.nodes node).log.take frontier := by
                    rw [List.take_take, Nat.min_eq_left]
                    rw [snapshotIndex]
                    omega
          simpa [memberHistory, self, stored] using restricted
  have knownNewOrOld :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (next state (.advanceCommitIndex node))
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
          (knownEvidence = evidence /\
            supportedPrefix =
              ((next state (.advanceCommitIndex node)).nodes node).committedLog) \/
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
              knownEvidence supportedPrefix := by
    intro knownEvidence supportedPrefix known
    rcases known with nodeKnown | requestKnown
    · rcases nodeKnown with
        ⟨committed, positive, stored, prefixEq⟩
      by_cases same : committed = node
      · subst committed
        left
        exact
          ⟨Option.some.inj
              (by simpa [newNodeEvidence] using stored.symm),
            prefixEq⟩
      · right
        exact Or.inl
          ⟨committed,
            by simpa [commitOther committed same] using positive,
            by simpa [
              newNodeEvidence, Function.update, same
            ] using stored,
            by simpa [committedOther committed same] using prefixEq⟩
    · right
      rcases requestKnown with
        ⟨destination, request, member, positive, stored, prefixEq⟩
      exact Or.inr
        ⟨destination, request,
          by simpa [networkEq] using member,
          positive, stored, prefixEq⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (next state (.advanceCommitIndex node))
        appendHistory newNodeEvidence requestEvidence := by
    constructor
    · intro candidate zero
      by_cases same : candidate = node
      · subst candidate
        rw [commitNode] at zero
        omega
      · have oldZero :
            (state.nodes candidate).commitIndex = 0 := by
          simpa [commitOther candidate same] using zero
        have none := evidenceFacts.nodeZero candidate oldZero
        simpa [
          newNodeEvidence, Function.update, same
        ] using none
    · intro candidate positive
      by_cases same : candidate = node
      · subst candidate
        refine
          ⟨evidence,
            by simp [newNodeEvidence],
            by simpa [committedNode] using evidenceValid,
            by simpa [evidence, commitNode],
            by simp [evidence, termEq]⟩
      · have oldPositive :
            0 < (state.nodes candidate).commitIndex := by
          simpa [commitOther candidate same] using positive
        rcases evidenceFacts.nodePositive candidate oldPositive with
          ⟨oldEvidence, stored, valid, lengthEq, termBound⟩
        exact
          ⟨oldEvidence,
            by simpa [
              newNodeEvidence, Function.update, same
            ] using stored,
            by simpa [committedOther candidate same] using valid,
            by simpa [commitOther candidate same] using lengthEq,
            by simpa [termEq] using termBound⟩
    · intro destination request member zero
      exact
        evidenceFacts.requestZero destination request
          (by simpa [next, CCFRaft.next] using member) zero
    · intro destination request member positive
      exact
        evidenceFacts.requestPositive destination request
          (by simpa [next, CCFRaft.next] using member) positive
  have evidenceMemberEffective :
      forall member,
        member ∈ evidence.ackQuorum ->
          member ∈
            effectiveAckers state responseHistory node frontier := by
    intro member memberIn
    simp only [
      evidence, acknowledgingNodes, effectiveAckers,
      Finset.mem_filter, Finset.mem_univ, true_and
    ] at memberIn ⊢
    rcases memberIn with self | matched
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (next state (.advanceCommitIndex node))
        appendHistory newNodeEvidence requestEvidence elections := by
    constructor
    · intro knownEvidence supportedPrefix known
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        simpa [evidence] using facts.currentTermsPositive node
      · exact
          prospectiveFacts.commitTermPositive
            knownEvidence supportedPrefix old
    · intro knownEvidence supportedPrefix known term record recorded newer
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        simpa [evidence] using
          potentialPrefixInElectionRecords
            facts.currentTermsPositive facts.voteHistory
              ownership electionFacts
              ackerElectionFacts leaderRole frontierValid.1
              frontierSignature
              frontierPotential term record recorded
              (by simpa [evidence] using newer)
      · exact
          prospectiveFacts.electionClosure
            knownEvidence supportedPrefix old
              term record recorded newer
    · intro knownEvidence supportedPrefix known member ackMember
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        simpa [evidence, logEq] using
          effectiveAckerContainsPotentialPrefix
            facts.currentTermsPositive facts.voteHistory
              ownership electionFacts
              ackerCurrentFacts ackerElectionFacts
              leaderRole frontierValid.1 frontierSignature frontierPotential
              (evidenceMemberEffective member ackMember)
      · simpa [logEq] using
          prospectiveFacts.currentMember
            knownEvidence supportedPrefix old member ackMember
    · intro knownEvidence supportedPrefix known destination request
        queued sameTerm
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        have oldQueued :
            Message.appendEntriesRequest request ∈
              state.network destination := by
          simpa [networkEq] using queued
        have requestOwned :=
          (ownership.queuedAppendMetadata
            destination request oldQueued).1
        have nodeOwned := ownership.activeLeader node leaderRole
        have requestTerm :
            request.term = (state.nodes node).currentTerm := by
          simpa [evidence] using sameTerm.symm
        rw [requestTerm] at requestOwned
        have sourceEq : request.source = node :=
          Option.some.inj (requestOwned.symm.trans nodeOwned)
        left
        have sourceHistory :=
          ownership.queuedActiveSourceHistory
            destination request oldQueued
              (by simpa [sourceEq] using requestTerm)
              (by simpa [sourceEq] using leaderRole)
        simpa [evidence, sourceEq] using sourceHistory
      · exact
          prospectiveFacts.sameTermQueuedComparable
            knownEvidence supportedPrefix old
              destination request
              (by simpa [networkEq] using queued)
              sameTerm
    · intro knownEvidence supportedPrefix known candidate member
        role newer entriesBefore ackMember relaxed
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        have oldRole :
            (state.nodes candidate).role = .candidate := by
          simpa [roleEq] using role
        have oldNewer :
            (state.nodes node).currentTerm <
              (state.nodes candidate).currentTerm := by
          simpa [evidence, termEq] using newer
        have oldEntriesBefore :
            forall entry,
              entry ∈ (state.nodes candidate).log ->
                entry.term < (state.nodes candidate).currentTerm := by
          intro entry member
          simpa [termEq] using
            entriesBefore entry (by simpa [logEq] using member)
        have oldRelaxed :
            member ∈ relaxedElectionVoters state candidate := by
          simpa [
            relaxedElectionVoters,
            makeRequestVoteRequest,
            termEq, logEq, lastIndexEq, lastTermEq,
            effectiveElectionVotersEq,
            voteLogUpToDate
          ] using relaxed
        simpa [evidence, logEq] using
          effectiveAckerRelaxedCandidateContainsPotentialPrefix
            facts.currentTermsPositive facts.committedFrontierIsSignature
              facts.voteHistory
              ownership electionFacts
              facts.grantedVoteSnapshots voteCanonicalFacts
              ackerCurrentFacts ackerVoteFacts ackerElectionFacts
              leaderRole frontierValid.1 frontierSignature frontierPotential
              oldRole oldNewer oldEntriesBefore
              (evidenceMemberEffective member ackMember)
              oldRelaxed
      · have oldRole :
            (state.nodes candidate).role = .candidate := by
          simpa [roleEq] using role
        have oldNewer :
            knownEvidence.commitTerm <
              (state.nodes candidate).currentTerm := by
          simpa [termEq] using newer
        have oldEntriesBefore :
            forall entry,
              entry ∈ (state.nodes candidate).log ->
                entry.term < (state.nodes candidate).currentTerm := by
          intro entry member
          simpa [termEq] using
            entriesBefore entry (by simpa [logEq] using member)
        have oldRelaxed :
            member ∈ relaxedElectionVoters state candidate := by
          simpa [
            relaxedElectionVoters,
            makeRequestVoteRequest,
            termEq, logEq, lastIndexEq, lastTermEq,
            effectiveElectionVotersEq,
            voteLogUpToDate
          ] using relaxed
        simpa [logEq] using
          prospectiveFacts.relaxedSupporterCarriesFrontier
            knownEvidence supportedPrefix old candidate member
              oldRole oldNewer oldEntriesBefore ackMember oldRelaxed
  refine
      ⟨votes, appendHistory, responseHistory,
        voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [commitNode, logEq]
      exact frontierBound
    · rw [commitOther candidate same, logEq]
      exact facts.commitIndicesBounded candidate
  · exact committedSignatureAfter
  · intro candidate
    rw [termEq]
    exact facts.currentTermsPositive candidate
  · intro candidate entry member
    rw [logEq] at member
    rw [termEq]
    exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · intro candidate role
    rw [roleEq] at role
    rw [votedEq, votesEq]
    exact facts.candidatesSelfVote candidate role
  · intro leader role
    rw [roleEq] at role
    have old := facts.leadersHaveElectionMajority leader role
    rw [termEq]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · right
      unfold hasElectionMajority at majority ⊢
      rw [votesEq]
      exact majority
  · intro leader role peer
    rw [roleEq] at role
    have old := facts.leaderProgressBounded leader role peer
    rw [sentEq, matchEq, logEq]
    exact old
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [termEq, votedEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      rw [termEq] at future
      exact facts.voteHistory.future voter term future
    · intro candidate voter active member
      rw [termEq]
      rw [roleEq] at active
      rw [votesEq] at member
      exact facts.voteHistory.counted candidate voter active member
  · constructor
    · intro destination message member
      rw [networkEq] at member
      exact facts.networkHistory.addressed destination message member
    · intro destination request member
      rw [networkEq] at member
      have old := facts.networkHistory.appendRequest destination request member
      refine ⟨old.1, old.2.1, old.2.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      exact old.2.2.2.trans (committedMonotonic request.source)
    · intro destination response member
      rw [networkEq] at member
      simpa [
        SuccessfulResponseSnapshot, termEq, roleEq, logEq
      ] using
        facts.networkHistory.appendResponse destination response member
    · intro destination request member
      rw [networkEq] at member
      simpa [termEq, roleEq, logEq] using
        facts.networkHistory.voteRequest destination request member
    · intro destination response member granted
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteResponse destination response member granted with
        ⟨termBound, vote, upToDate⟩
      exact
        ⟨by simpa [termEq] using termBound,
          vote, by simpa [voteLogUpToDate] using upToDate⟩
  · refine
      ⟨owners, canonicalHistory, elections,
        newNodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      rw [termEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro owner index entry found
      rcases
          ownership.logEntryAgreement owner index entry
            (by simpa [logEq] using found) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro destination request member index entry found
      exact
        ownership.queuedHistoryEntryAgreement
          destination request
            (by simpa [next, CCFRaft.next] using member)
            index entry found
    · intro leader role
      rw [termEq]
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      simpa [logEq] using
        ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      exact
        ⟨by simpa [termEq] using bound,
          by
            intro same
            have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using same
            simpa [roleEq] using oldLeader oldSame⟩
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa [networkEq] using member)
    · intro destination request member sameTerm leaderRole
      simpa [logEq] using
        ownership.queuedActiveSourceHistory destination request
          (by simpa [networkEq] using member)
          (by simpa [termEq] using sameTerm)
          (by simpa [roleEq] using leaderRole)
    · apply
        electionHistoryFrame
          state (next state (.advanceCommitIndex node))
            votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    · apply
        grantedVoteCanonicalFrame
          state (next state (.advanceCommitIndex node))
            canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => termEq candidate)
      · intro candidate active
        simpa [roleEq] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical
        exact canonical
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · exact electionQueuedFacts
  · intro candidate voter active member
    rw [termEq candidate, termEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [logEq] using
      facts.grantedVoteSnapshots
        candidate voter active oldMember
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      exact
        ackFacts.zero leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      rcases
          ackFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact
        ⟨snapshot, stored,
          by simpa [termEq] using snapshotTerm,
          by simpa [matchEq] using snapshotIndex,
          historyBound,
          by simpa [logEq] using agreed⟩
/-! ## Message receive -/

/--
A same-term candidate may step down before consuming AppendEntries.  This
changes only its role, so every leader/election obligation either reuses the
old fact or excludes the node which just became a follower.
-/
theorem returnToFollowerPreservesSystemInductiveInvariant
    (state : State TxId)
    (destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (invariant : SystemInductiveInvariant state)
    (stepped :
      returnToFollowerState? (state.nodes destination) request =
        some nextNode) :
    SystemInductiveInvariant
      { state with nodes := updateNode state.nodes destination nextNode } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  unfold returnToFollowerState? at stepped
  split at stepped
  · rename_i canReturn
    simp at stepped
    subst nextNode
    let after : State TxId :=
      { state with
        nodes :=
          updateNode state.nodes destination
            { state.nodes destination with
              role := .follower
              isNewFollower := true } }
    have candidateRole :
        (state.nodes destination).role = .candidate :=
      canReturn.2
    have roleDestination :
        (after.nodes destination).role = .follower := by
      simp [after, updateNode]
    have roleOther :
        forall node,
          Not (node = destination) ->
            (after.nodes node).role = (state.nodes node).role := by
      intro node different
      simp [after, updateNode, Function.update, different]
    have termEq :
        forall node,
          (after.nodes node).currentTerm =
            (state.nodes node).currentTerm := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have logEq :
        forall node,
          (after.nodes node).log = (state.nodes node).log := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have commitEq :
        forall node,
          (after.nodes node).commitIndex =
            (state.nodes node).commitIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have lastIndexEq :
        forall node,
          lastCommittableIndex (after.nodes node) =
            lastCommittableIndex (state.nodes node) := by
      intro node
      exact lastCommittableIndexFrame (logEq node) (commitEq node)
    have lastTermEq :
        forall node,
          lastCommittableTerm (after.nodes node) =
            lastCommittableTerm (state.nodes node) := by
      intro node
      exact lastCommittableTermFrame (logEq node) (commitEq node)
    have committedEq :
        forall node,
          (after.nodes node).committedLog =
            (state.nodes node).committedLog := by
      intro node
      simp [NodeState.committedLog, commitEq, logEq]
    have votedEq :
        forall node,
          (after.nodes node).votedFor =
            (state.nodes node).votedFor := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have votesEq :
        forall node,
          (after.nodes node).votesGranted =
            (state.nodes node).votesGranted := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have sentEq :
        forall node,
          (after.nodes node).sentIndex =
            (state.nodes node).sentIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have matchEq :
        forall node,
          (after.nodes node).matchIndex =
            (state.nodes node).matchIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have networkEq : after.network = state.network := by
      rfl
    have effectiveAckersEq :
        forall leader index,
          effectiveAckers after responseHistory leader index =
            effectiveAckers state responseHistory leader index := by
      intro leader index
      ext peer
      simp only [
        effectiveAckers, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      constructor
      · rintro (self | matched | queued)
        · exact Or.inl self
        · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
        · right
          right
          rcases queued with
            ⟨response, member, success, responseTerm, sourceEq,
              destinationEq, lastIndex, covered⟩
          exact
            ⟨response, by simpa [networkEq] using member,
              success, by simpa [termEq] using responseTerm,
              sourceEq, destinationEq, lastIndex,
              by simpa [logEq] using covered⟩
      · rintro (self | matched | queued)
        · exact Or.inl self
        · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
        · right
          right
          rcases queued with
            ⟨response, member, success, responseTerm, sourceEq,
              destinationEq, lastIndex, covered⟩
          exact
            ⟨response, by simpa [networkEq] using member,
              success, by simpa [termEq] using responseTerm,
              sourceEq, destinationEq, lastIndex,
              by simpa [logEq] using covered⟩
    have effectiveMajorityEq :
        forall leader index,
          hasEffectiveMajorityAt after responseHistory leader index ↔
            hasEffectiveMajorityAt state responseHistory leader index := by
      intro leader index
      simp only [hasEffectiveMajorityAt, effectiveAckersEq]
    have effectiveElectionVotersEq :
        forall candidate,
          effectiveElectionVoters after candidate =
            effectiveElectionVoters state candidate := by
      intro candidate
      ext voter
      simp only [
        effectiveElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      constructor <;> rintro (processed | queued)
      · exact Or.inl (by simpa [votesEq] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            granted, by simpa [termEq] using responseTerm,
            responseSource, responseDestination⟩
      · exact Or.inl (by simpa [votesEq] using processed)
      · right
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨response, by simpa [networkEq] using member,
            granted, by simpa [termEq] using responseTerm,
            responseSource, responseDestination⟩
    have effectiveElectionMajorityEq :
        forall candidate,
          hasEffectiveElectionMajority after candidate ↔
            hasEffectiveElectionMajority state candidate := by
      intro candidate
      simp only [
        hasEffectiveElectionMajority,
        effectiveElectionVotersEq
      ]
    have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters after candidate =
          potentialElectionVoters state candidate := by
      intro candidate
      ext voter
      simp only [
      potentialElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
      ]
      constructor <;> rintro (effective | eligible)
      · exact Or.inl (by
        rw [effectiveElectionVotersEq] at effective
        exact effective)
      · exact Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedEq, voteLogUpToDate
        ] using eligible)
      · exact Or.inl (by
        rw [effectiveElectionVotersEq]
        exact effective)
      · exact Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedEq, voteLogUpToDate
        ] using eligible)
    have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority after candidate ↔
          hasPotentialElectionMajority state candidate := by
      intro candidate
      simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq
      ]
    have temporalFacts :=
      ackerTemporalFrameSameLogs
        state after votes votes responseHistory voteVoterHistory elections
          ackerCurrentFacts ackerVoteFacts ackerElectionFacts
          (fun leader role => by
            have leaderNe : Not (leader = destination) := by
              intro same
              subst leader
              exact Role.noConfusion
                (role.symm.trans roleDestination)
            simpa [roleOther leader leaderNe] using role)
          (fun leader _ => termEq leader)
          logEq
          (fun leader index voter _ _ member => by
            rw [effectiveAckersEq] at member
            exact member)
          (fun node => Nat.le_of_eq (termEq node).symm)
          (fun _ _ _ voted _ => voted)
    change SystemInductiveInvariant after
    refine
      ⟨votes, appendHistory, responseHistory,
        voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
    constructor
    · intro node
      rw [commitEq, logEq]
      exact facts.commitIndicesBounded node
    · intro node positive
      rw [commitEq, logEq]
      apply facts.committedFrontierIsSignature node
      simpa [commitEq] using positive
    · intro node
      rw [termEq]
      exact facts.currentTermsPositive node
    · intro node entry member
      rw [logEq] at member
      rw [termEq]
      exact facts.entriesDoNotExceedCurrentTerm node entry member
    · intro node role
      have nodeNe : Not (node = destination) := by
        intro same
        subst node
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [roleOther node nodeNe] at role
      rw [votedEq, votesEq]
      exact facts.candidatesSelfVote node role
    · intro leader role
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [roleOther leader leaderNe] at role
      rcases facts.leadersHaveElectionMajority leader role with
        bootstrap | majority
      · exact Or.inl ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
      · right
        unfold hasElectionMajority at majority ⊢
        simpa [votesEq] using majority
    · intro leader role peer
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [roleOther leader leaderNe] at role
      simpa [sentEq, matchEq, logEq] using
        facts.leaderProgressBounded leader role peer
    · constructor
      · exact facts.voteHistory.bootstrapEmpty
      · intro voter
        simpa [termEq, votedEq] using facts.voteHistory.current voter
      · intro voter term future
        rw [termEq] at future
        exact facts.voteHistory.future voter term future
      · intro candidate voter active member
        have candidateNe : Not (candidate = destination) := by
          intro same
          subst candidate
          rcases active with candidateActive | leaderActive
          · exact
              Role.noConfusion
                (candidateActive.symm.trans roleDestination)
          · exact
              Role.noConfusion
                (leaderActive.symm.trans roleDestination)
        rw [roleOther candidate candidateNe] at active
        rw [votesEq] at member
        rw [termEq]
        exact facts.voteHistory.counted candidate voter active member
    · constructor
      · intro queuedDestination message member
        rw [networkEq] at member
        exact facts.networkHistory.addressed queuedDestination message member
      · intro queuedDestination queuedRequest member
        rw [networkEq] at member
        rcases
            facts.networkHistory.appendRequest
              queuedDestination queuedRequest member with
          ⟨snapshot, commitBound, emptyBound, present⟩
        exact
          ⟨snapshot, commitBound, emptyBound,
            by simpa [RequestCommitStillPresent, committedEq] using present⟩
      · intro queuedDestination response member success
        rw [networkEq] at member
        have responseDestination :
            response.destination = queuedDestination := by
          simpa using
            facts.networkHistory.addressed
              queuedDestination (.appendEntriesResponse response) member
        subst queuedDestination
        rcases
            facts.networkHistory.appendResponse
              response.destination response member success with
          ⟨lengthBound, termBound, supported⟩
        refine ⟨lengthBound, by simpa [termEq] using termBound, ?_⟩
        intro sameTerm
        have oldSameTerm :
            response.term =
              (state.nodes response.destination).currentTerm := by
          simpa [termEq] using sameTerm
        rcases supported oldSameTerm with ⟨oldLeader, covered⟩
        by_cases destinationEq : response.destination = destination
        · rw [destinationEq, candidateRole] at oldLeader
          contradiction
        · constructor
          · simpa [roleOther response.destination destinationEq] using oldLeader
          · simpa [logEq] using covered
      · intro queuedDestination voteRequest member
        rw [networkEq] at member
        rcases
            facts.networkHistory.voteRequest
              queuedDestination voteRequest member with
          ⟨lastIndex, lastTerm, maxIndex,
            aboveBootstrap, termBound, activePrefix⟩
        refine
          ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap,
            by simpa [termEq] using termBound, ?_⟩
        intro sameTerm active
        by_cases sourceEq : voteRequest.source = destination
        · rw [sourceEq] at active
          rcases active with candidate | leader
          · exact False.elim
              (Role.noConfusion (candidate.symm.trans roleDestination))
          · exact False.elim
              (Role.noConfusion (leader.symm.trans roleDestination))
        · have oldPrefix :=
            activePrefix
              (by simpa [termEq] using sameTerm)
              (by simpa [roleOther voteRequest.source sourceEq] using active)
          simpa [logEq] using oldPrefix
      · intro queuedDestination response member granted
        rw [networkEq] at member
        rcases
            facts.networkHistory.voteResponse
              queuedDestination response member granted with
          ⟨termBound, recorded, candidateCommittable,
            voterCommittable, upToDate⟩
        exact
          ⟨by simpa [termEq] using termBound,
            recorded, candidateCommittable, voterCommittable,
            by simpa [voteLogUpToDate] using upToDate⟩
    have evidenceAfter :
        CommitEvidenceFacts
          after appendHistory nodeEvidence requestEvidence := by
      apply
        commitEvidenceFrame
          state after appendHistory
            nodeEvidence requestEvidence evidenceFacts
            commitEq committedEq
      · intro node
        exact Nat.le_of_eq (termEq node).symm
      · intro queuedDestination queuedRequest member
        simpa [networkEq] using member
    have prospectiveAfter :
        ProspectiveCommitEvidenceFacts
          after appendHistory nodeEvidence requestEvidence elections := by
      apply
        prospectiveCommitEvidenceFrame
          state after appendHistory appendHistory
            nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
      · intro evidence supportedPrefix known
        exact
          knownCommitEvidenceFrameBack
            state after appendHistory nodeEvidence requestEvidence
              commitEq committedEq
              (fun queuedDestination queuedRequest member => by
                simpa [networkEq] using member)
              known
      · intro member
        simpa [logEq] using prefixRefl (state.nodes member).log
      · intro evidence supportedPrefix queuedDestination queuedRequest
          known queued sameTerm
        left
        exact ⟨by simpa [networkEq] using queued, rfl⟩
      · intro evidence supportedPrefix candidate member known role newer
          entriesBefore ackMember relaxed
        have candidateNe : Not (candidate = destination) := by
          intro same
          subst candidate
          exact Role.noConfusion (role.symm.trans roleDestination)
        left
        exact
          ⟨by simpa [roleOther candidate candidateNe] using role,
            by simpa [termEq] using newer,
            by
              intro entry entryMember
              simpa [termEq] using
                entriesBefore entry (by simpa [logEq] using entryMember),
            by simpa [
              relaxedElectionVoters,
              makeRequestVoteRequest,
              termEq, logEq, lastIndexEq, lastTermEq,
              effectiveElectionVotersEq,
              voteLogUpToDate
            ] using relaxed,
            by simpa [logEq] using
              prefixRefl (state.nodes candidate).log⟩
    · refine
        ⟨owners, canonicalHistory, elections,
          nodeEvidence, requestEvidence,
          ?_, ?_, ?_, ?_, ?_, ?_, ?_,
          evidenceAfter, prospectiveAfter⟩
      constructor
      · exact ownership.bootstrap
      · intro leader role
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        rw [termEq]
        exact ownership.activeLeader leader
          (by simpa [roleOther leader leaderNe] using role)
      · intro node index entry found
        rcases
            ownership.logEntryAgreement node index entry
              (by simpa [logEq] using found) with
          ⟨canonicalFound, agreed⟩
        exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
      · intro queuedDestination queuedRequest member index entry found
        exact
          ownership.queuedHistoryEntryAgreement
            queuedDestination queuedRequest
              (by simpa [networkEq] using member)
              index entry found
      · intro leader role
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        rw [termEq]
        have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderNe] using role
        simpa [logEq] using
          ownership.activeLeaderHistory leader oldRole
      · exact ownership.canonicalEntryOwner
      · exact ownership.canonicalMonoLog
      · intro term owner owned
        rcases ownership.ownerProgress term owner owned with
          ⟨bound, oldLeader⟩
        constructor
        · simpa [termEq] using bound
        · intro same
          by_cases ownerEq : owner = destination
          · subst owner
            have oldSame :
                term = (state.nodes destination).currentTerm := by
              simpa [termEq] using same
            have oldLeaderRole := oldLeader oldSame
            exact False.elim
              (Role.noConfusion
                (oldLeaderRole.symm.trans candidateRole))
          · have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using same
            simpa [roleOther owner ownerEq] using oldLeader oldSame
      · intro queuedDestination queuedRequest member
        exact
          ownership.queuedAppendMetadata queuedDestination queuedRequest
          (by simpa [networkEq] using member)
      · intro queuedDestination queuedRequest member sameTerm leaderRole
        by_cases sourceEq : queuedRequest.source = destination
        · have afterLeader :
              (after.nodes destination).role = .leader := by
            simpa [sourceEq] using leaderRole
          exact False.elim
            (Role.noConfusion (afterLeader.symm.trans roleDestination))
        · exact
            by
              simpa [logEq] using
                ownership.queuedActiveSourceHistory
                  queuedDestination queuedRequest
                    (by simpa [networkEq] using member)
                    (by simpa [termEq] using sameTerm)
                    (by simpa [roleOther queuedRequest.source sourceEq] using
                      leaderRole)
      · apply
          electionHistoryFrame
            state after votes votes canonicalHistory canonicalHistory
              owners elections electionFacts
        · intros
          rfl
        · intro term
          exact prefixRefl (canonicalHistory term)
        · intro history canonical
          exact canonical
      · apply
          grantedVoteCanonicalFrame
            state after canonicalHistory canonicalHistory
              voteCandidateHistory voteVoterHistory voteCanonicalFacts
              (fun candidate _ => termEq candidate)
        · intro candidate active
          have candidateNe : Not (candidate = destination) := by
            intro same
            subst candidate
            rcases active with candidateRole | leaderRole
            · exact Role.noConfusion
                (candidateRole.symm.trans roleDestination)
            · exact Role.noConfusion
                (leaderRole.symm.trans roleDestination)
          rw [roleOther candidate candidateNe] at active
          exact active
        · intro candidate voter _ member
          rw [effectiveElectionVotersEq] at member
          exact member
        · intro history canonical
          exact canonical
      · exact temporalFacts.1
      · exact temporalFacts.2.1
      · exact temporalFacts.2.2
      · exact electionQueuedFacts
    · intro candidate voter active member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateActive | leaderActive
        · exact Role.noConfusion (candidateActive.symm.trans roleDestination)
        · exact Role.noConfusion (leaderActive.symm.trans roleDestination)
      rw [termEq candidate, termEq voter]
      have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        rw [roleOther candidate candidateNe] at active
        exact active
      have oldMember :
          voter ∈ effectiveElectionVoters state candidate := by
        rw [effectiveElectionVotersEq] at member
        exact member
      simpa [logEq] using
        facts.grantedVoteSnapshots
          candidate voter oldActive oldMember
    · refine ⟨ackHistory, ?_⟩
      constructor
      · intro leader role peer zero
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        exact
          ackFacts.zero leader
            (by simpa [roleOther leader leaderNe] using role)
            peer (by simpa [matchEq] using zero)
      · intro leader role peer positive
        have leaderNe : Not (leader = destination) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleDestination)
        rcases
            ackFacts.positive leader
              (by simpa [roleOther leader leaderNe] using role)
              peer (by simpa [matchEq] using positive) with
          ⟨snapshot, stored, snapshotTerm, snapshotIndex,
            historyBound, agreed⟩
        exact
          ⟨snapshot, stored,
            by simpa [termEq] using snapshotTerm,
            by simpa [matchEq] using snapshotIndex,
            historyBound,
            by simpa [logEq] using agreed⟩
  · contradiction

/-- Dequeuing a non-vote message leaves latent election voters unchanged. -/
theorem effectiveElectionVotersAfterAppendResponse
    (state after : State TxId)
    (destination : Node)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom response.source (state.network destination) =
        some (.appendEntriesResponse response, remaining))
    (networkEq :
      after.network = updateQueue state.network destination remaining)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (votesEq :
      forall node,
        (after.nodes node).votesGranted =
          (state.nodes node).votesGranted) :
    forall candidate,
      effectiveElectionVoters after candidate =
        effectiveElectionVoters state candidate := by
  intro candidate
  have remainingOld := (takeFirstFromSound taken).2.2
  ext voter
  simp only [
    effectiveElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ]
  constructor
  · rintro (processed | queued)
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨voteResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      have oldMember :
          Message.requestVoteResponse voteResponse ∈
            state.network candidate := by
        rw [networkEq] at member
        by_cases candidateEq : candidate = destination
        · have voteDestination :
              voteResponse.destination = destination :=
            responseDestination.trans candidateEq
          subst candidate
          have remainingMember :
              Message.requestVoteResponse voteResponse ∈ remaining := by
            simpa [
              updateQueue, Function.update, voteDestination
            ] using member
          simpa [voteDestination] using remainingOld _ remainingMember
        · simpa [updateQueue, Function.update, candidateEq] using member
      exact
        ⟨voteResponse, oldMember, granted,
          by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
  · rintro (processed | queued)
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨voteResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      refine
        ⟨voteResponse, ?_, granted,
          by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
      rw [networkEq]
      by_cases candidateEq : candidate = destination
      · have voteDestination :
            voteResponse.destination = destination :=
          responseDestination.trans candidateEq
        subst candidate
        have oldMember :
            Message.requestVoteResponse voteResponse ∈
              state.network destination := by
          simpa [voteDestination] using member
        rcases memSelectedOrRemaining taken oldMember with
          selectedEq | remainingMember
        · simp at selectedEq
        · simpa [
            updateQueue, Function.update, voteDestination
          ] using remainingMember
      · simpa [updateQueue, Function.update, candidateEq] using member

/-- Frame changes preserving leader role, term, log, and match retain ACK history. -/
theorem processedAckHistoryFrame
    (state after : State TxId)
    (history : ProcessedAckHistory TxId)
    (facts : ProcessedAckHistoryFacts state history)
    (roleEq :
      forall node, (after.nodes node).role = (state.nodes node).role)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (matchEq :
      forall leader peer,
        (after.nodes leader).matchIndex peer =
          (state.nodes leader).matchIndex peer) :
    ProcessedAckHistoryFacts after history := by
  constructor
  · intro leader role peer zero
    exact
      facts.zero leader
        (by simpa [roleEq] using role)
        peer (by simpa [matchEq] using zero)
  · intro leader role peer positive
    rcases
        facts.positive leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using positive) with
      ⟨snapshot, stored, snapshotTerm, snapshotIndex,
        historyBound, agreed⟩
    exact
      ⟨snapshot, stored,
        by simpa [termEq] using snapshotTerm,
        by simpa [matchEq] using snapshotIndex,
        historyBound,
        by simpa [logEq] using agreed⟩

/--
Removing a queued response while changing only replication cursors preserves
the invariant once effective-ACK evidence is shown unchanged.
-/
theorem responseDequeuePreservesSystemInductiveInvariant
    (state after : State TxId)
    (invariant : SystemInductiveInvariant state)
    (roleEq :
      forall node, (after.nodes node).role = (state.nodes node).role)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (commitEq :
      forall node,
        (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (candidatesSelfVoteAfter : CandidatesSelfVote after)
    (leadersHaveElectionMajorityAfter : LeadersHaveElectionMajority after)
    (voteHistoryAfter :
      forall
        (votes : VoteHistory)
        (appendHistory :
          AppendEntriesRequest TxId -> List (Entry TxId))
        (responseHistory : AppendEntriesResponse -> List (Entry TxId))
        (voteRequestHistory :
          RequestVoteRequest -> List (Entry TxId))
        (voteCandidateHistory voteVoterHistory :
          RequestVoteResponse -> List (Entry TxId)),
        InvariantFacts
            state votes appendHistory responseHistory
              voteRequestHistory voteCandidateHistory voteVoterHistory ->
          VoteHistoryFacts after votes)
    (processedAckHistoryAfter :
      forall
        (votes : VoteHistory)
        (appendHistory :
          AppendEntriesRequest TxId -> List (Entry TxId))
        (responseHistory : AppendEntriesResponse -> List (Entry TxId))
        (voteRequestHistory :
          RequestVoteRequest -> List (Entry TxId))
        (voteCandidateHistory voteVoterHistory :
          RequestVoteResponse -> List (Entry TxId)),
        InvariantFacts
            state votes appendHistory responseHistory
              voteRequestHistory voteCandidateHistory voteVoterHistory ->
          Exists fun history => ProcessedAckHistoryFacts after history)
    (networkSubset :
      forall destination message,
        message ∈ after.network destination ->
          message ∈ state.network destination)
    (progressAfter : LeaderProgressBounded after)
    (effectiveAckersEq :
      forall
        (votes : VoteHistory)
        (appendHistory :
          AppendEntriesRequest TxId -> List (Entry TxId))
        (responseHistory : AppendEntriesResponse -> List (Entry TxId))
        (voteRequestHistory :
          RequestVoteRequest -> List (Entry TxId))
        (voteCandidateHistory voteVoterHistory :
          RequestVoteResponse -> List (Entry TxId)),
        InvariantFacts
            state votes appendHistory responseHistory
              voteRequestHistory voteCandidateHistory voteVoterHistory ->
          forall leader index,
            effectiveAckers after responseHistory leader index =
              effectiveAckers state responseHistory leader index)
    (effectiveElectionMajorityBack :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
        hasEffectiveElectionMajority after candidate ->
          hasEffectiveElectionMajority state candidate)
    (effectiveElectionMemberBack :
      forall candidate voter,
        ((after.nodes candidate).role = .candidate \/
          (after.nodes candidate).role = .leader) ->
        voter ∈ effectiveElectionVoters after candidate ->
          voter ∈ effectiveElectionVoters state candidate) :
    SystemInductiveInvariant after := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  have committedEq :
      forall node,
        (after.nodes node).committedLog =
          (state.nodes node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitEq, logEq]
  have lastIndexEq :
      forall node,
        lastCommittableIndex (after.nodes node) =
          lastCommittableIndex (state.nodes node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm (after.nodes node) =
          lastCommittableTerm (state.nodes node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitEq node)
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt after responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    simp only [
      hasEffectiveMajorityAt,
        effectiveAckersEq
          votes appendHistory responseHistory voteRequestHistory
            voteCandidateHistory voteVoterHistory facts leader index
    ]
  refine
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro node
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node positive
    rw [commitEq, logEq]
    apply facts.committedFrontierIsSignature node
    simpa [commitEq] using positive
  · intro node
    rw [termEq]
    exact facts.currentTermsPositive node
  · intro node entry member
    rw [logEq] at member
    rw [termEq]
    exact facts.entriesDoNotExceedCurrentTerm node entry member
  · exact candidatesSelfVoteAfter
  · exact leadersHaveElectionMajorityAfter
  · exact progressAfter
  · exact
      voteHistoryAfter
        votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory facts
  · constructor
    · intro destination message member
      exact
        facts.networkHistory.addressed
          destination message (networkSubset destination message member)
    · intro destination request member
      rcases
          facts.networkHistory.appendRequest
            destination request
              (networkSubset destination (.appendEntriesRequest request) member) with
        ⟨snapshot, commitBound, emptyBound, present⟩
      exact
        ⟨snapshot, commitBound, emptyBound,
          by simpa [RequestCommitStillPresent, committedEq] using present⟩
    · intro destination response member success
      have oldMember :=
        networkSubset destination (.appendEntriesResponse response) member
      rcases
          facts.networkHistory.appendResponse destination response oldMember
            success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, by simpa [termEq] using termBound, ?_⟩
      intro sameTerm
      rcases
          supported (by simpa [termEq] using sameTerm) with
        ⟨leaderRole, covered⟩
      exact
        ⟨by simpa [roleEq] using leaderRole,
          by simpa [logEq] using covered⟩
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request
            (networkSubset destination (.requestVoteRequest request) member) with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      exact
        ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap,
          by simpa [termEq] using termBound,
          fun sameTerm active =>
            by
              have oldSameTerm :
                  request.term =
                    (state.nodes request.source).currentTerm := by
                simpa [termEq] using sameTerm
              have oldActive :
                  (state.nodes request.source).role = .candidate \/
                    (state.nodes request.source).role = .leader := by
                simpa [roleEq] using active
              simpa [logEq] using
                activePrefix oldSameTerm oldActive⟩
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse destination response
            (networkSubset destination (.requestVoteResponse response) member)
            granted with
        ⟨termBound, recorded, upToDate⟩
      exact
        ⟨by simpa [termEq] using termBound,
          recorded, by simpa [voteLogUpToDate] using upToDate⟩
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state after appendHistory
          nodeEvidence requestEvidence evidenceFacts
          commitEq committedEq
    · intro node
      exact Nat.le_of_eq (termEq node).symm
    · intro destination request member
      exact
        networkSubset destination (.appendEntriesRequest request) member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state after appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state after appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member =>
              networkSubset
                destination (.appendEntriesRequest request) member)
            known
    · intro member
      simpa [logEq] using prefixRefl (state.nodes member).log
    · intro evidence supportedPrefix destination request known
        queued sameTerm
      left
      exact
        ⟨networkSubset
            destination (.appendEntriesRequest request) queued,
          rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have oldRole :
          (state.nodes candidate).role = .candidate := by
        simpa [roleEq] using role
      have oldRelaxed :
          member ∈ relaxedElectionVoters state candidate := by
        simp only [
          relaxedElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ] at relaxed ⊢
        rcases relaxed with effective | eligible
        · exact Or.inl
            (effectiveElectionMemberBack
              candidate member (Or.inl role) effective)
        · exact Or.inr (by
            simpa [
              makeRequestVoteRequest,
              termEq, logEq, lastIndexEq, lastTermEq,
              voteLogUpToDate
            ] using eligible)
      left
      exact
        ⟨oldRole,
          by simpa [termEq] using newer,
          by
            intro entry entryMember
            simpa [termEq] using
              entriesBefore entry (by simpa [logEq] using entryMember),
          oldRelaxed,
          by simpa [logEq] using
            prefixRefl (state.nodes candidate).log⟩
  · have temporalFacts :=
      ackerTemporalFrameSameLogs
        state after votes votes responseHistory voteVoterHistory elections
          ackerCurrentFacts ackerVoteFacts ackerElectionFacts
          (fun leader role => by simpa [roleEq] using role)
          (fun leader _ => termEq leader)
          logEq
          (fun leader index voter _ _ member => by
            rw [
              effectiveAckersEq
                votes appendHistory responseHistory voteRequestHistory
                  voteCandidateHistory voteVoterHistory facts
            ] at member
            exact member)
          (fun node => Nat.le_of_eq (termEq node).symm)
          (fun _ _ _ voted _ => voted)
    refine
      ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      rw [termEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro node index entry found
      rcases
          ownership.logEntryAgreement node index entry
            (by simpa [logEq] using found) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro destination request member index entry found
      exact
        ownership.queuedHistoryEntryAgreement
          destination request
            (networkSubset destination (.appendEntriesRequest request) member)
            index entry found
    · intro leader role
      rw [termEq]
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      simpa [logEq] using
        ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      exact
        ⟨by simpa [termEq] using bound,
          by
            intro same
            have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using same
            simpa [roleEq] using oldLeader oldSame⟩
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (networkSubset destination (.appendEntriesRequest request) member)
    · intro destination request member sameTerm leaderRole
      simpa [logEq] using
        ownership.queuedActiveSourceHistory destination request
          (networkSubset destination (.appendEntriesRequest request) member)
          (by simpa [termEq] using sameTerm)
          (by simpa [roleEq] using leaderRole)
    · apply
        electionHistoryFrame
          state after votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    · apply
        grantedVoteCanonicalFrame
          state after canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => termEq candidate)
      · intro candidate active
        simpa [roleEq] using active
      · intro candidate voter active member
        exact
          effectiveElectionMemberBack candidate voter active member
      · intro history canonical
        exact canonical
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro destination request member record recorded
      exact
        electionQueuedFacts
          destination request (networkSubset _ _ member) record recorded
  · intro candidate voter active member
    have afterActive := active
    rw [termEq candidate, termEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate :=
      effectiveElectionMemberBack candidate voter afterActive member
    simpa [logEq] using
      facts.grantedVoteSnapshots
        candidate voter active oldMember
  · exact
      processedAckHistoryAfter
        votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory facts
/-- Dequeuing an ACK which is not effective leaves effective evidence intact. -/
theorem effectiveAckersAfterInactiveResponse
    (state after : State TxId)
    (destination : Node)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom response.source (state.network destination) =
        some (.appendEntriesResponse response, remaining))
    (networkEq :
      after.network = updateQueue state.network destination remaining)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (matchEq :
      forall leader peer,
        (after.nodes leader).matchIndex peer =
          (state.nodes leader).matchIndex peer)
    (inactive :
      Not
        (response.success = true /\
          response.term = (state.nodes destination).currentTerm)) :
    forall
      (responseHistory : AppendEntriesResponse -> List (Entry TxId))
      leader index,
      effectiveAckers after responseHistory leader index =
        effectiveAckers state responseHistory leader index := by
  intro responseHistory leader index
  have remainingOld := (takeFirstFromSound taken).2.2
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ]
  constructor
  · rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
      have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network leader := by
        rw [networkEq] at member
        by_cases leaderEq : leader = destination
        · have queuedDestination :
              queuedResponse.destination = destination :=
            responseDestination.trans leaderEq
          subst leader
          have remainingMember :
              Message.appendEntriesResponse queuedResponse ∈ remaining := by
            simpa [
              updateQueue, Function.update, queuedDestination
            ] using member
          simpa [queuedDestination] using
            remainingOld _ remainingMember
        · simpa [updateQueue, Function.update, leaderEq] using member
      exact
        ⟨queuedResponse, oldMember, success,
          by simpa [termEq] using responseTerm,
          sourceEq, responseDestination, lastIndex,
          by simpa [logEq] using covered⟩
  · rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
      have afterMember :
          Message.appendEntriesResponse queuedResponse ∈
            after.network leader := by
        rw [networkEq]
        by_cases leaderEq : leader = destination
        · have queuedDestination :
              queuedResponse.destination = destination :=
            responseDestination.trans leaderEq
          subst leader
          have oldMember :
              Message.appendEntriesResponse queuedResponse ∈
                state.network destination := by
            simpa [queuedDestination] using member
          rcases
              memSelectedOrRemaining taken oldMember with
            selectedEq | remainingMember
          · simp only [Message.appendEntriesResponse.injEq] at selectedEq
            subst queuedResponse
            exact False.elim
              (inactive
                ⟨success,
                  by simpa [queuedDestination] using responseTerm⟩)
          · simpa [
              updateQueue, Function.update, queuedDestination
            ] using remainingMember
        · simpa [updateQueue, Function.update, leaderEq] using member
      exact
        ⟨queuedResponse, afterMember, success,
          by simpa [termEq] using responseTerm,
          sourceEq, responseDestination, lastIndex,
          by simpa [logEq] using covered⟩

/--
Processing a successful same-term ACK transfers its evidence from the queue to
the destination leader's monotone `matchIndex`.
-/
theorem effectiveAckersAfterSuccessfulResponse
    (state after : State TxId)
    (destination : Node)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom response.source (state.network destination) =
        some (.appendEntriesResponse response, remaining))
    (responseDestination : response.destination = destination)
    (success : response.success = true)
    (sameTerm :
      response.term = (state.nodes destination).currentTerm)
    (responseHistory :
      AppendEntriesResponse -> List (Entry TxId))
    (covered :
      responseHistory response <+: (state.nodes destination).log)
    (networkEq :
      after.network = updateQueue state.network destination remaining)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (matchDestination :
      forall peer,
        (after.nodes destination).matchIndex peer =
          updateIndex
            (state.nodes destination).matchIndex
            response.source
            (max
              ((state.nodes destination).matchIndex response.source)
              response.lastLogIndex)
            peer)
    (matchOther :
      forall leader,
        Not (leader = destination) ->
          forall peer,
            (after.nodes leader).matchIndex peer =
              (state.nodes leader).matchIndex peer) :
    forall leader index,
      effectiveAckers after responseHistory leader index =
        effectiveAckers state responseHistory leader index := by
  intro leader index
  have selectedMember :
      Message.appendEntriesResponse response ∈
        state.network destination :=
    (takeFirstFromSound taken).2.1
  have remainingOld := (takeFirstFromSound taken).2.2
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ]
  constructor
  · rintro (self | matched | queued)
    · exact Or.inl self
    · by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same] at matched
          by_cases oldCovers :
              index <=
                (state.nodes destination).matchIndex response.source
          · exact Or.inr (Or.inl oldCovers)
          · right
            right
            refine
              ⟨response, selectedMember, success, sameTerm,
                rfl, responseDestination, ?_, covered⟩
            omega
        · right
          left
          simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ] using matched
      · exact Or.inr
          (Or.inl (by simpa [matchOther leader leaderEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, queuedSuccess, responseTerm, sourceEq,
          queuedDestination, lastIndex, queuedCovered⟩
      have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network leader := by
        rw [networkEq] at member
        by_cases leaderEq : leader = destination
        · have queuedDestinationEq :
              queuedResponse.destination = destination :=
            queuedDestination.trans leaderEq
          subst leader
          have remainingMember :
              Message.appendEntriesResponse queuedResponse ∈ remaining := by
            simpa [
              updateQueue, Function.update, queuedDestinationEq
            ] using member
          simpa [queuedDestinationEq] using
            remainingOld _ remainingMember
        · simpa [updateQueue, Function.update, leaderEq] using member
      exact
        ⟨queuedResponse, oldMember, queuedSuccess,
          by simpa [termEq] using responseTerm,
          sourceEq, queuedDestination, lastIndex,
          by simpa [logEq] using queuedCovered⟩
  · rintro (self | matched | queued)
    · exact Or.inl self
    · right
      left
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same]
          omega
        · simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ] using matched
      · simpa [matchOther leader leaderEq] using matched
    · rcases queued with
        ⟨queuedResponse, member, queuedSuccess, responseTerm, sourceEq,
          queuedDestination, lastIndex, queuedCovered⟩
      by_cases leaderEq : leader = destination
      · have queuedDestinationEq :
            queuedResponse.destination = destination :=
          queuedDestination.trans leaderEq
        subst leader
        have oldMember :
            Message.appendEntriesResponse queuedResponse ∈
              state.network destination := by
          simpa [queuedDestinationEq] using member
        rcases memSelectedOrRemaining taken oldMember with
          selectedEq | remainingMember
        · simp only [Message.appendEntriesResponse.injEq] at selectedEq
          rw [selectedEq] at sourceEq
          have peerEq : peer = response.source := sourceEq.symm
          subst peer
          subst queuedResponse
          right
          left
          rw [responseDestination, matchDestination, updateIndex_same]
          omega
        · right
          right
          refine
            ⟨queuedResponse, ?_, queuedSuccess,
              by simpa [termEq] using responseTerm,
              sourceEq, rfl, lastIndex,
              by simpa [logEq] using queuedCovered⟩
          rw [networkEq]
          simpa [
            updateQueue, Function.update, queuedDestinationEq
          ] using remainingMember
      · right
        right
        refine
          ⟨queuedResponse, ?_, queuedSuccess,
            by simpa [termEq] using responseTerm,
            sourceEq, queuedDestination, lastIndex,
            by simpa [logEq] using queuedCovered⟩
        rw [networkEq]
        simpa [updateQueue, Function.update, leaderEq] using member

/-- A successful ACK transfers its immutable history into processed evidence. -/
theorem processedAckHistoryAfterSuccessfulResponse
    (state after : State TxId)
    (destination : Node)
    (response : AppendEntriesResponse)
    (history : ProcessedAckHistory TxId)
    (historyFacts : ProcessedAckHistoryFacts state history)
    (responseHistory : List (Entry TxId))
    (responseBound : response.lastLogIndex <= responseHistory.length)
    (responseCovered :
      responseHistory <+: (state.nodes destination).log)
    (successful :
      response.term = (state.nodes destination).currentTerm /\
        (state.nodes destination).role = .leader)
    (roleEq :
      forall node, (after.nodes node).role = (state.nodes node).role)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (matchDestination :
      forall peer,
        (after.nodes destination).matchIndex peer =
          updateIndex
            (state.nodes destination).matchIndex
            response.source
            (max
              ((state.nodes destination).matchIndex response.source)
              response.lastLogIndex)
            peer)
    (matchOther :
      forall leader,
        Not (leader = destination) ->
          forall peer,
            (after.nodes leader).matchIndex peer =
              (state.nodes leader).matchIndex peer) :
    Exists fun nextHistory =>
      ProcessedAckHistoryFacts after nextHistory := by
  by_cases raised :
      (state.nodes destination).matchIndex response.source <
        response.lastLogIndex
  · let snapshot : ProcessedAckSnapshot TxId :=
      { term := response.term
        index := response.lastLogIndex
        history := responseHistory }
    let nextHistory : ProcessedAckHistory TxId :=
      Function.update history destination
        (Function.update
          (history destination) response.source (some snapshot))
    refine ⟨nextHistory, ?_⟩
    constructor
    · intro leader role peer zero
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same] at zero
          omega
        · have oldZero :
              (state.nodes destination).matchIndex peer = 0 := by
            simpa [
              matchDestination, updateIndex,
              Function.update, peerEq
            ] using zero
          simpa [
            nextHistory, Function.update, peerEq
          ] using
            historyFacts.zero
              destination successful.2 peer oldZero
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleEq] using role
        have oldZero :
            (state.nodes leader).matchIndex peer = 0 := by
          simpa [matchOther leader leaderEq] using zero
        simpa [
          nextHistory, Function.update, leaderEq
        ] using historyFacts.zero leader oldRole peer oldZero
    · intro leader role peer positive
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          refine ⟨snapshot, ?_, ?_, ?_, ?_, ?_⟩
          · simp [nextHistory, snapshot]
          · simp only [snapshot]
            rw [termEq]
            exact successful.1
          · simp [
              snapshot, matchDestination, updateIndex_same,
              max_eq_right raised.le
            ]
          · simpa [snapshot] using responseBound
          · have equalTake :=
              takeEqOfPrefix responseCovered responseBound
            simp only [snapshot]
            rw [logEq]
            exact equalTake
        · have oldPositive :
              0 < (state.nodes destination).matchIndex peer := by
            simpa [
              matchDestination, updateIndex,
              Function.update, peerEq
            ] using positive
          rcases
              historyFacts.positive
                destination successful.2 peer oldPositive with
            ⟨oldSnapshot, stored, snapshotTerm, snapshotIndex,
              historyBound, agreed⟩
          exact
            ⟨oldSnapshot,
              by simpa [
                nextHistory, Function.update, peerEq
              ] using stored,
              by simpa [termEq] using snapshotTerm,
              by simpa [
                matchDestination, updateIndex,
                Function.update, peerEq
              ] using snapshotIndex,
              historyBound,
              by simpa [logEq] using agreed⟩
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleEq] using role
        have oldPositive :
            0 < (state.nodes leader).matchIndex peer := by
          simpa [matchOther leader leaderEq] using positive
        rcases
            historyFacts.positive leader oldRole peer oldPositive with
          ⟨oldSnapshot, stored, snapshotTerm, snapshotIndex,
            historyBound, agreed⟩
        exact
          ⟨oldSnapshot,
            by simpa [
              nextHistory, Function.update, leaderEq
            ] using stored,
            by simpa [termEq] using snapshotTerm,
            by simpa [matchOther leader leaderEq] using snapshotIndex,
            historyBound,
            by simpa [logEq] using agreed⟩
  · refine ⟨history, ?_⟩
    have matchEq :
        forall leader peer,
          (after.nodes leader).matchIndex peer =
            (state.nodes leader).matchIndex peer := by
      intro leader peer
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same]
          omega
        · simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ]
      · exact matchOther leader leaderEq peer
    constructor
    · intro leader role peer zero
      exact
        historyFacts.zero leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      rcases
          historyFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact
        ⟨snapshot, stored,
          by simpa [termEq] using snapshotTerm,
          by simpa [matchEq] using snapshotIndex,
          historyBound,
          by simpa [logEq] using agreed⟩

/-- Receiving an AppendEntries response preserves all delayed-ACK evidence. -/
theorem receiveAppendEntriesResponsePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (nextNode : NodeState TxId)
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesResponse response, remaining))
    (responseDestination : response.destination = destination)
    (handled :
      handleAppendEntriesResponse? (state.nodes destination) response =
        some nextNode) :
    SystemInductiveInvariant
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := updateQueue state.network destination remaining } := by
  have responseSource : response.source = source :=
    (takeFirstFromSound taken).1
  have takenByResponseSource :
      takeFirstFrom response.source (state.network destination) =
        some (.appendEntriesResponse response, remaining) := by
    simpa [responseSource] using taken
  have selectedMember :
      Message.appendEntriesResponse response ∈
        state.network destination :=
    (takeFirstFromSound taken).2.1
  have remainingOld := (takeFirstFromSound taken).2.2
  have updateQueueSubset :
      forall queuedDestination message,
        message ∈
            updateQueue state.network destination remaining
              queuedDestination ->
          message ∈ state.network queuedDestination := by
    intro queuedDestination message member
    by_cases destinationEq : queuedDestination = destination
    · subst queuedDestination
      exact remainingOld message
        (by simpa [updateQueue, Function.update] using member)
    · simpa [updateQueue, Function.update, destinationEq] using member
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have packed :
      SystemInductiveInvariant state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  unfold handleAppendEntriesResponse? at handled
  split at handled
  · rename_i successful
    simp at handled
    subst nextNode
    let after : State TxId :=
      { state with
        nodes :=
          updateNode state.nodes destination
            { state.nodes destination with
              matchIndex :=
                updateIndex
                  (state.nodes destination).matchIndex
                  response.source
                  (max
                    ((state.nodes destination).matchIndex response.source)
                    response.lastLogIndex) }
        network := updateQueue state.network destination remaining }
    have roleEq :
        forall node, (after.nodes node).role = (state.nodes node).role := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have termEq :
        forall node,
          (after.nodes node).currentTerm =
            (state.nodes node).currentTerm := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have logEq :
        forall node, (after.nodes node).log = (state.nodes node).log := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have commitEq :
        forall node,
          (after.nodes node).commitIndex =
            (state.nodes node).commitIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have votedEq :
        forall node,
          (after.nodes node).votedFor =
            (state.nodes node).votedFor := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have votesEq :
        forall node,
          (after.nodes node).votesGranted =
            (state.nodes node).votesGranted := by
      intro node
      by_cases same : node = destination <;>
        simp [after, updateNode, Function.update, same]
    have matchDestination :
        forall peer,
          (after.nodes destination).matchIndex peer =
            updateIndex
              (state.nodes destination).matchIndex
              response.source
              (max
                ((state.nodes destination).matchIndex response.source)
                response.lastLogIndex)
              peer := by
      intro peer
      simp [after, updateNode]
    have matchOther :
        forall leader,
          Not (leader = destination) ->
            forall peer,
              (after.nodes leader).matchIndex peer =
                (state.nodes leader).matchIndex peer := by
      intro leader different peer
      simp [after, updateNode, Function.update, different]
    have responseSnapshot :=
      facts.networkHistory.appendResponse
        destination response selectedMember successful.1
    have snapshotSameTerm :
        response.term =
          (state.nodes response.destination).currentTerm := by
      simpa [responseDestination] using successful.2.1
    have responseCovered :
        responseHistory response <+:
          (state.nodes destination).log := by
      have covered := (responseSnapshot.2.2 snapshotSameTerm).2
      simpa [responseDestination] using covered
    have progressAfter : LeaderProgressBounded after := by
      intro leader leaderRole peer
      rw [roleEq] at leaderRole
      have old := facts.leaderProgressBounded leader leaderRole peer
      by_cases leaderEq : leader = destination
      · subst leader
        constructor
        · simpa [after, updateNode] using old.1
        · by_cases peerEq : peer = response.source
          · subst peer
            rw [matchDestination, updateIndex_same]
            rw [logEq]
            exact
              max_le old.2
                (Nat.le_trans responseSnapshot.1 responseCovered.length_le)
          · simpa [
              matchDestination, updateIndex,
              Function.update, peerEq, logEq
            ] using old.2
      · simpa [
          after, updateNode, Function.update, leaderEq
        ] using old
    change SystemInductiveInvariant after
    apply
      responseDequeuePreservesSystemInductiveInvariant
        state after packed roleEq termEq logEq commitEq
    · intro node role
      rw [roleEq] at role
      simpa [votedEq, votesEq] using
        facts.candidatesSelfVote node role
    · intro leader role
      rw [roleEq] at role
      rcases facts.leadersHaveElectionMajority leader role with
        bootstrap | majority
      · exact Or.inl
          ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
      · right
        simpa [hasElectionMajority, votesEq] using majority
    · intro _ _ _ _ _ _ actualFacts
      constructor
      · exact actualFacts.voteHistory.bootstrapEmpty
      · intro voter
        simpa [termEq, votedEq] using
          actualFacts.voteHistory.current voter
      · intro voter term future
        rw [termEq] at future
        exact actualFacts.voteHistory.future voter term future
      · intro candidate voter active member
        rw [roleEq] at active
        rw [votesEq] at member
        rw [termEq]
        exact
          actualFacts.voteHistory.counted
            candidate voter active member
    · intro _ _ actualResponseHistory _ _ _ actualFacts
      rcases actualFacts.processedAckHistory with
        ⟨actualAckHistory, actualAckFacts⟩
      have actualSnapshot :=
        actualFacts.networkHistory.appendResponse
          destination response selectedMember successful.1
      have actualCovered :
          actualResponseHistory response <+:
            (state.nodes destination).log := by
        have covered :=
          (actualSnapshot.2.2 snapshotSameTerm).2
        simpa [responseDestination] using covered
      exact
        processedAckHistoryAfterSuccessfulResponse
          state after destination response
            actualAckHistory actualAckFacts
            (actualResponseHistory response)
            actualSnapshot.1 actualCovered
            ⟨successful.2.1,
              by simpa [responseDestination] using successful.2.2⟩
            roleEq termEq logEq matchDestination matchOther
    · intro queuedDestination message member
      exact updateQueueSubset queuedDestination message (by simpa [after] using member)
    · exact progressAfter
    · intro _ _ actualResponseHistory _ _ _ actualFacts leader index
      have actualSnapshot :=
        actualFacts.networkHistory.appendResponse
          destination response selectedMember successful.1
      have actualCovered :
          actualResponseHistory response <+:
            (state.nodes destination).log := by
        have covered :=
          (actualSnapshot.2.2 snapshotSameTerm).2
        simpa [responseDestination] using covered
      apply
        effectiveAckersAfterSuccessfulResponse
          state after destination response remaining
            takenByResponseSource responseDestination successful.1
            successful.2.1
            actualResponseHistory actualCovered
      · rfl
      · exact termEq
      · exact logEq
      · exact matchDestination
      · exact matchOther
    · intro candidate role majority
      unfold hasEffectiveElectionMajority at majority ⊢
      rw [
        effectiveElectionVotersAfterAppendResponse
          state after destination response remaining
            takenByResponseSource rfl termEq votesEq
      ] at majority
      exact majority
    · intro candidate voter active member
      rw [
        effectiveElectionVotersAfterAppendResponse
          state after destination response remaining
            takenByResponseSource rfl termEq votesEq
      ] at member
      exact member
  · split at handled
    · rename_i failed
      simp at handled
      subst nextNode
      let after : State TxId :=
        { state with
          nodes :=
            updateNode state.nodes destination
              { state.nodes destination with
                sentIndex :=
                  updateIndex
                    (state.nodes destination).sentIndex
                    response.source
                    (max
                      (min
                        (findHighestPossibleMatch
                          (state.nodes destination).log
                          response.lastLogIndex response.term)
                        ((state.nodes destination).sentIndex response.source))
                      ((state.nodes destination).matchIndex response.source)) }
          network := updateQueue state.network destination remaining }
      have roleEq :
          forall node, (after.nodes node).role = (state.nodes node).role := by
        intro node
        by_cases same : node = destination <;>
          simp [after, updateNode, Function.update, same]
      have termEq :
          forall node,
            (after.nodes node).currentTerm =
              (state.nodes node).currentTerm := by
        intro node
        by_cases same : node = destination <;>
          simp [after, updateNode, Function.update, same]
      have logEq :
          forall node, (after.nodes node).log = (state.nodes node).log := by
        intro node
        by_cases same : node = destination <;>
          simp [after, updateNode, Function.update, same]
      have commitEq :
          forall node,
            (after.nodes node).commitIndex =
              (state.nodes node).commitIndex := by
        intro node
        by_cases same : node = destination <;>
          simp [after, updateNode, Function.update, same]
      have votedEq :
          forall node,
            (after.nodes node).votedFor =
              (state.nodes node).votedFor := by
        intro node
        by_cases same : node = destination <;>
          simp [after, updateNode, Function.update, same]
      have votesEq :
          forall node,
            (after.nodes node).votesGranted =
              (state.nodes node).votesGranted := by
        intro node
        by_cases same : node = destination <;>
          simp [after, updateNode, Function.update, same]
      have matchEq :
          forall leader peer,
            (after.nodes leader).matchIndex peer =
              (state.nodes leader).matchIndex peer := by
        intro leader peer
        by_cases same : leader = destination <;>
          simp [after, updateNode, Function.update, same]
      have progressAfter : LeaderProgressBounded after := by
        intro leader leaderRole peer
        rw [roleEq] at leaderRole
        have old := facts.leaderProgressBounded leader leaderRole peer
        by_cases leaderEq : leader = destination
        · subst leader
          constructor
          · by_cases peerEq : peer = response.source
            · subst peer
              simp [after, updateNode, updateIndex_same]
              exact ⟨Or.inr old.1, old.2⟩
            · simpa [
                after, updateNode, updateIndex,
                Function.update, peerEq
              ] using old.1
          · simpa [matchEq, logEq] using old.2
        · simpa [
            after, updateNode, Function.update, leaderEq
          ] using old
      change SystemInductiveInvariant after
      apply
        responseDequeuePreservesSystemInductiveInvariant
          state after packed roleEq termEq logEq commitEq
      · intro node role
        rw [roleEq] at role
        simpa [votedEq, votesEq] using
          facts.candidatesSelfVote node role
      · intro leader role
        rw [roleEq] at role
        rcases facts.leadersHaveElectionMajority leader role with
          bootstrap | majority
        · exact Or.inl
            ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
        · right
          simpa [hasElectionMajority, votesEq] using majority
      · intro _ _ _ _ _ _ actualFacts
        constructor
        · exact actualFacts.voteHistory.bootstrapEmpty
        · intro voter
          simpa [termEq, votedEq] using
            actualFacts.voteHistory.current voter
        · intro voter term future
          rw [termEq] at future
          exact actualFacts.voteHistory.future voter term future
        · intro candidate voter active member
          rw [roleEq] at active
          rw [votesEq] at member
          rw [termEq]
          exact
            actualFacts.voteHistory.counted
              candidate voter active member
      · intro _ _ _ _ _ _ actualFacts
        rcases actualFacts.processedAckHistory with
          ⟨actualAckHistory, actualAckFacts⟩
        exact
          ⟨actualAckHistory,
            processedAckHistoryFrame
              state after actualAckHistory actualAckFacts
                roleEq termEq logEq
                matchEq⟩
      · intro queuedDestination message member
        exact
          updateQueueSubset queuedDestination message
            (by simpa [after] using member)
      · exact progressAfter
      · intro _ _ actualResponseHistory _ _ _ _ leader index
        apply
          effectiveAckersAfterInactiveResponse
            state after destination response remaining
              takenByResponseSource
        · rfl
        · exact termEq
        · exact logEq
        · exact matchEq
        · intro active
          simp [failed] at active
      · intro candidate role majority
        unfold hasEffectiveElectionMajority at majority ⊢
        rw [
          effectiveElectionVotersAfterAppendResponse
            state after destination response remaining
              takenByResponseSource rfl termEq votesEq
        ] at majority
        exact majority
      · intro candidate voter active member
        rw [
          effectiveElectionVotersAfterAppendResponse
            state after destination response remaining
              takenByResponseSource rfl termEq votesEq
        ] at member
        exact member
    · split at handled
      · rename_i notLeader
        simp at handled
        subst nextNode
        have updatedNodesEq :
            updateNode state.nodes destination (state.nodes destination) =
              state.nodes := by
          funext node
          by_cases same : node = destination <;>
            simp [updateNode, Function.update, same]
        rw [updatedNodesEq]
        let after : State TxId :=
          { state with
            network := updateQueue state.network destination remaining }
        have fieldEq :
            forall node, after.nodes node = state.nodes node := by
          intro node
          rfl
        have progressAfter : LeaderProgressBounded after := by
          simpa [after] using facts.leaderProgressBounded
        change SystemInductiveInvariant after
        apply
          responseDequeuePreservesSystemInductiveInvariant
            state after packed
              (fun node => by simp [after])
              (fun node => by simp [after])
              (fun node => by simp [after])
              (fun node => by simp [after])
        · simpa [after] using facts.candidatesSelfVote
        · simpa [after] using facts.leadersHaveElectionMajority
        · intro _ _ _ _ _ _ actualFacts
          constructor
          · exact actualFacts.voteHistory.bootstrapEmpty
          · exact actualFacts.voteHistory.current
          · exact actualFacts.voteHistory.future
          · exact actualFacts.voteHistory.counted
        · intro _ _ _ _ _ _ actualFacts
          rcases actualFacts.processedAckHistory with
            ⟨actualAckHistory, actualAckFacts⟩
          exact
            ⟨actualAckHistory,
              processedAckHistoryFrame
                state after actualAckHistory actualAckFacts
                  (fun _ => rfl) (fun _ => rfl)
                  (fun _ => rfl) (fun _ _ => rfl)⟩
        · intro queuedDestination message member
          exact
            updateQueueSubset queuedDestination message
              (by simpa [after] using member)
        · exact progressAfter
        · intro _ _ actualResponseHistory _ _ _ actualFacts leader index
          have inactive :
              Not
                (response.success = true /\
                  response.term =
                    (state.nodes destination).currentTerm) := by
            rintro ⟨responseSuccess, responseTerm⟩
            have snapshot :=
              actualFacts.networkHistory.appendResponse
                destination response selectedMember responseSuccess
            have sameAtResponseDestination :
                response.term =
                  (state.nodes response.destination).currentTerm := by
              simpa [responseDestination] using responseTerm
            have responseLeader :=
              (snapshot.2.2 sameAtResponseDestination).1
            rw [responseDestination] at responseLeader
            have roleNotLeader :
                Not ((state.nodes destination).role = .leader) := by
              simpa using notLeader
            exact roleNotLeader responseLeader
          apply
            effectiveAckersAfterInactiveResponse
              state after destination response remaining
                takenByResponseSource
          · rfl
          · intro node
            rfl
          · intro node
            rfl
          · intro leader peer
            rfl
          · exact inactive
        · intro candidate role majority
          unfold hasEffectiveElectionMajority at majority ⊢
          rw [
            effectiveElectionVotersAfterAppendResponse
              state after destination response remaining
                takenByResponseSource rfl
                (fun node => rfl) (fun node => rfl)
          ] at majority
          exact majority
        · intro candidate voter active member
          rw [
            effectiveElectionVotersAfterAppendResponse
              state after destination response remaining
                takenByResponseSource rfl
                (fun node => rfl) (fun node => rfl)
          ] at member
          exact member
      · split at handled
        · rename_i stale
          simp at handled
          subst nextNode
          have updatedNodesEq :
              updateNode state.nodes destination (state.nodes destination) =
                state.nodes := by
            funext node
            by_cases same : node = destination <;>
              simp [updateNode, Function.update, same]
          rw [updatedNodesEq]
          let after : State TxId :=
            { state with
              network := updateQueue state.network destination remaining }
          have progressAfter : LeaderProgressBounded after := by
            simpa [after] using facts.leaderProgressBounded
          change SystemInductiveInvariant after
          apply
            responseDequeuePreservesSystemInductiveInvariant
              state after packed
                (fun node => by simp [after])
                (fun node => by simp [after])
                (fun node => by simp [after])
                (fun node => by simp [after])
          · simpa [after] using facts.candidatesSelfVote
          · simpa [after] using facts.leadersHaveElectionMajority
          · intro _ _ _ _ _ _ actualFacts
            constructor
            · exact actualFacts.voteHistory.bootstrapEmpty
            · exact actualFacts.voteHistory.current
            · exact actualFacts.voteHistory.future
            · exact actualFacts.voteHistory.counted
          · intro _ _ _ _ _ _ actualFacts
            rcases actualFacts.processedAckHistory with
              ⟨actualAckHistory, actualAckFacts⟩
            exact
              ⟨actualAckHistory,
                processedAckHistoryFrame
                  state after actualAckHistory actualAckFacts
                    (fun _ => rfl) (fun _ => rfl)
                    (fun _ => rfl) (fun _ _ => rfl)⟩
          · intro queuedDestination message member
            exact
              updateQueueSubset queuedDestination message
                (by simpa [after] using member)
          · exact progressAfter
          · intro _ _ actualResponseHistory _ _ _ _ leader index
            apply
              effectiveAckersAfterInactiveResponse
                state after destination response remaining
                  takenByResponseSource
            · rfl
            · intro node
              rfl
            · intro node
              rfl
            · intro leader peer
              rfl
            · rintro ⟨_, sameTerm⟩
              omega
          · intro candidate role majority
            unfold hasEffectiveElectionMajority at majority ⊢
            rw [
              effectiveElectionVotersAfterAppendResponse
                state after destination response remaining
                  takenByResponseSource rfl
                  (fun node => rfl) (fun node => rfl)
            ] at majority
            exact majority
          · intro candidate voter active member
            rw [
              effectiveElectionVotersAfterAppendResponse
                state after destination response remaining
                  takenByResponseSource rfl
                  (fun node => rfl) (fun node => rfl)
            ] at member
            exact member
        · contradiction

/-- Dequeuing a vote response leaves latent replication acknowledgements unchanged. -/
theorem effectiveAckersAfterVoteResponse
    (state after : State TxId)
    (destination : Node)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
        takeFirstFrom response.source (state.network destination) =
          some (.requestVoteResponse response, remaining))
    (networkEq :
        after.network = updateQueue state.network destination remaining)
    (termEq :
        forall node,
          (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq :
        forall node, (after.nodes node).log = (state.nodes node).log)
    (matchEq :
        forall leader peer,
          (after.nodes leader).matchIndex peer =
            (state.nodes leader).matchIndex peer) :
    forall
        (responseHistory : AppendEntriesResponse -> List (Entry TxId))
        leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
  intro responseHistory leader index
  have remainingOld := (takeFirstFromSound taken).2.2
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ]
  constructor <;> rintro (self | matched | queued)
  · exact Or.inl self
  · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
  · right
    right
    rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
    have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network leader := by
        rw [networkEq] at member
        by_cases leaderEq : leader = destination
        · have queuedDestination :
              queuedResponse.destination = destination :=
            responseDestination.trans leaderEq
          subst leader
          have remainingMember :
              Message.appendEntriesResponse queuedResponse ∈ remaining := by
            simpa [
              updateQueue, Function.update, queuedDestination
            ] using member
          simpa [queuedDestination] using
            remainingOld _ remainingMember
        · simpa [updateQueue, Function.update, leaderEq] using member
    exact
        ⟨queuedResponse, oldMember, success,
          by simpa [termEq] using responseTerm,
          sourceEq, responseDestination, lastIndex,
          by simpa [logEq] using covered⟩
  · exact Or.inl self
  · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
  · right
    right
    rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
    refine
        ⟨queuedResponse, ?_, success,
          by simpa [termEq] using responseTerm,
          sourceEq, responseDestination, lastIndex,
          by simpa [logEq] using covered⟩
    rw [networkEq]
    by_cases leaderEq : leader = destination
    · have queuedDestination :
          queuedResponse.destination = destination :=
        responseDestination.trans leaderEq
      subst leader
      have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network destination := by
        simpa [queuedDestination] using member
      rcases memSelectedOrRemaining taken oldMember with
        selectedEq | remainingMember
      · simp at selectedEq
      · simpa [
          updateQueue, Function.update, queuedDestination
        ] using remainingMember
    · simpa [updateQueue, Function.update, leaderEq] using member

/--
Processing a vote response never creates new effective election evidence:
a newly recorded vote was already represented by the selected queued grant.
-/
theorem effectiveElectionVotersAfterVoteResponseSubset
    (state after : State TxId)
    (destination : Node)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom response.source (state.network destination) =
        some (.requestVoteResponse response, remaining))
    (responseDestination : response.destination = destination)
    (networkEq :
      after.network = updateQueue state.network destination remaining)
    (termEq :
      forall node,
        (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (votesDestination :
      (after.nodes destination).votesGranted =
          (state.nodes destination).votesGranted \/
        (response.voteGranted = true /\
          response.term = (state.nodes destination).currentTerm /\
          (after.nodes destination).votesGranted =
            insert
              response.source
              (state.nodes destination).votesGranted))
    (votesOther :
      forall candidate,
        Not (candidate = destination) ->
          (after.nodes candidate).votesGranted =
            (state.nodes candidate).votesGranted) :
    forall candidate,
      effectiveElectionVoters after candidate ⊆
        effectiveElectionVoters state candidate := by
  intro candidate voter member
  have selectedMember :
      Message.requestVoteResponse response ∈
        state.network destination :=
    (takeFirstFromSound taken).2.1
  have remainingOld := (takeFirstFromSound taken).2.2
  simp only [
    effectiveElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at member ⊢
  rcases member with processed | queued
  · by_cases candidateEq : candidate = destination
    · subst candidate
      rcases votesDestination with unchanged | inserted
      · exact Or.inl (by simpa [unchanged] using processed)
      · have sourceOrOld :
            voter = response.source \/
              voter ∈ (state.nodes destination).votesGranted := by
          simpa [inserted.2.2] using processed
        rcases sourceOrOld with sourceEq | old
        · subst voter
          exact Or.inr
            ⟨response, selectedMember, inserted.1, inserted.2.1,
              rfl, responseDestination⟩
        · exact Or.inl old
    · exact Or.inl
        (by simpa [votesOther candidate candidateEq] using processed)
  · right
    rcases queued with
      ⟨queuedResponse, queuedMember, granted, responseTerm,
        responseSource, queuedDestination⟩
    have oldMember :
        Message.requestVoteResponse queuedResponse ∈
          state.network candidate := by
      rw [networkEq] at queuedMember
      by_cases candidateEq : candidate = destination
      · have queuedDestinationEq :
            queuedResponse.destination = destination :=
          queuedDestination.trans candidateEq
        subst candidate
        have remainingMember :
            Message.requestVoteResponse queuedResponse ∈ remaining := by
          simpa [
            updateQueue, Function.update, queuedDestinationEq
          ] using queuedMember
        simpa [queuedDestinationEq] using
          remainingOld _ remainingMember
      · simpa [
          updateQueue, Function.update, candidateEq
        ] using queuedMember
    exact
      ⟨queuedResponse, oldMember, granted,
        by simpa [termEq] using responseTerm,
        responseSource, queuedDestination⟩

/-- The exact vote-set alternatives of the RequestVote response handler. -/
theorem handleRequestVoteResponseVoteUpdate
    {before after : NodeState TxId}
    {response : RequestVoteResponse}
    (handled :
      handleRequestVoteResponse? before response = some after) :
    after.votesGranted = before.votesGranted \/
      (response.voteGranted = true /\
        response.term = before.currentTerm /\
        before.role = .candidate /\
        after.votesGranted =
          insert response.source before.votesGranted) := by
  unfold handleRequestVoteResponse? at handled
  split at handled
  · simp at handled
    subst after
    exact Or.inl rfl
  · split at handled
    · simp at handled
      subst after
      exact Or.inl rfl
    · rename_i candidateRole
      split at handled
      · rename_i currentTerm
        split at handled
        · rename_i granted
          simp at handled
          subst after
          exact
            Or.inr
              ⟨granted, currentTerm, by simpa using candidateRole, rfl⟩
        · simp at handled
          subst after
          exact Or.inl rfl
      · contradiction

/-- Receiving a RequestVote response transfers latent vote evidence to runtime state. -/
theorem receiveRequestVoteResponsePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (nextNode : NodeState TxId)
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteResponse response, remaining))
    (responseDestination : response.destination = destination)
    (handled :
      handleRequestVoteResponse? (state.nodes destination) response =
        some nextNode) :
    SystemInductiveInvariant
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := updateQueue state.network destination remaining } := by
  have responseSource : response.source = source :=
    (takeFirstFromSound taken).1
  have takenByResponseSource :
      takeFirstFrom response.source (state.network destination) =
        some (.requestVoteResponse response, remaining) := by
    simpa [responseSource] using taken
  have selectedMember :
      Message.requestVoteResponse response ∈
        state.network destination :=
    (takeFirstFromSound taken).2.1
  have remainingOld := (takeFirstFromSound taken).2.2
  have updateQueueSubset :
      forall queuedDestination message,
        message ∈
            updateQueue state.network destination remaining
              queuedDestination ->
          message ∈ state.network queuedDestination := by
    intro queuedDestination message member
    by_cases destinationEq : queuedDestination = destination
    · subst queuedDestination
      exact remainingOld message
        (by simpa [updateQueue, Function.update] using member)
    · simpa [updateQueue, Function.update, destinationEq] using member
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have packed :
      SystemInductiveInvariant state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have post := handleRequestVoteResponsePreserves handled
  have voteUpdate := handleRequestVoteResponseVoteUpdate handled
  let after : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network := updateQueue state.network destination remaining }
  have roleEq :
      forall node, (after.nodes node).role = (state.nodes node).role := by
    intro node
    by_cases same : node = destination <;>
      simp [after, updateNode, Function.update, same, post.roleUnchanged]
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination <;>
      simp [
        after, updateNode, Function.update, same,
        post.currentTermUnchanged
      ]
  have logEq :
      forall node, (after.nodes node).log = (state.nodes node).log := by
    intro node
    by_cases same : node = destination <;>
      simp [after, updateNode, Function.update, same, post.logUnchanged]
  have commitEq :
      forall node,
        (after.nodes node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        after, updateNode, Function.update, same,
        post.commitIndexUnchanged
      ]
  have votedEq :
      forall node,
        (after.nodes node).votedFor =
          (state.nodes node).votedFor := by
    intro node
    by_cases same : node = destination <;>
      simp [
        after, updateNode, Function.update, same,
        post.votedForUnchanged
      ]
  have sentEq :
      forall node,
        (after.nodes node).sentIndex =
          (state.nodes node).sentIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        after, updateNode, Function.update, same,
        post.sentIndexUnchanged
      ]
  have matchEq :
      forall node,
        (after.nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        after, updateNode, Function.update, same,
        post.matchIndexUnchanged
      ]
  have votesDestination :
      (after.nodes destination).votesGranted =
          (state.nodes destination).votesGranted \/
        (response.voteGranted = true /\
          response.term = (state.nodes destination).currentTerm /\
          (after.nodes destination).votesGranted =
            insert
              response.source
              (state.nodes destination).votesGranted) := by
    rcases voteUpdate with unchanged | inserted
    · exact Or.inl (by simpa [after, updateNode] using unchanged)
    · exact Or.inr
        ⟨inserted.1, inserted.2.1,
          by simpa [after, updateNode] using inserted.2.2.2⟩
  have votesOther :
      forall candidate,
        Not (candidate = destination) ->
          (after.nodes candidate).votesGranted =
            (state.nodes candidate).votesGranted := by
    intro candidate different
    simp [after, updateNode, Function.update, different]
  have votesMonotone :
      forall candidate,
        (state.nodes candidate).votesGranted ⊆
          (after.nodes candidate).votesGranted := by
    intro candidate voter member
    by_cases candidateEq : candidate = destination
    · subst candidate
      rcases votesDestination with unchanged | inserted
      · simpa [unchanged] using member
      · rw [inserted.2.2]
        exact Finset.mem_insert_of_mem member
    · simpa [votesOther candidate candidateEq] using member
  have effectiveSubset :
      forall candidate,
        effectiveElectionVoters after candidate ⊆
          effectiveElectionVoters state candidate :=
    effectiveElectionVotersAfterVoteResponseSubset
      state after destination response remaining takenByResponseSource
        responseDestination rfl termEq votesDestination votesOther
  have candidatesSelfVoteAfter : CandidatesSelfVote after := by
    intro candidate role
    have oldRole : (state.nodes candidate).role = .candidate := by
      simpa [roleEq] using role
    rcases facts.candidatesSelfVote candidate oldRole with
      ⟨selfVote, selfCounted⟩
    exact
      ⟨by simpa [votedEq] using selfVote,
        votesMonotone candidate selfCounted⟩
  have leadersHaveElectionMajorityAfter :
      LeadersHaveElectionMajority after := by
    intro leader role
    have oldRole : (state.nodes leader).role = .leader := by
      simpa [roleEq] using role
    rcases facts.leadersHaveElectionMajority leader oldRole with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · right
      unfold hasElectionMajority at majority ⊢
      have cardBound :=
        Finset.card_le_card (votesMonotone leader)
      omega
  have voteHistoryAfter :
      forall
        (actualVotes : VoteHistory)
        (actualAppendHistory :
          AppendEntriesRequest TxId -> List (Entry TxId))
        (actualResponseHistory :
          AppendEntriesResponse -> List (Entry TxId))
        (actualVoteRequestHistory :
          RequestVoteRequest -> List (Entry TxId))
        (actualVoteCandidateHistory actualVoteVoterHistory :
          RequestVoteResponse -> List (Entry TxId)),
        InvariantFacts
            state actualVotes actualAppendHistory actualResponseHistory
              actualVoteRequestHistory actualVoteCandidateHistory
              actualVoteVoterHistory ->
          VoteHistoryFacts after actualVotes := by
    intro actualVotes _ _ _ _ _ actualFacts
    constructor
    · exact actualFacts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [termEq, votedEq] using
        actualFacts.voteHistory.current voter
    · intro voter term future
      rw [termEq] at future
      exact actualFacts.voteHistory.future voter term future
    · intro candidate voter active member
      rw [termEq]
      have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        simpa [roleEq] using active
      by_cases candidateEq : candidate = destination
      · subst candidate
        rcases votesDestination with unchanged | inserted
        · exact
            actualFacts.voteHistory.counted destination voter oldActive
              (by simpa [unchanged] using member)
        · have sourceOrOld :
              voter = response.source \/
                voter ∈ (state.nodes destination).votesGranted := by
            simpa [inserted.2.2] using member
          rcases sourceOrOld with sourceEq | old
          · subst voter
            rcases
                actualFacts.networkHistory.voteResponse
                  destination response selectedMember inserted.1 with
              ⟨_, recorded, _⟩
            simpa [inserted.2.1, responseDestination] using recorded
          · exact
              actualFacts.voteHistory.counted
                destination voter oldActive old
      · exact
          actualFacts.voteHistory.counted candidate voter oldActive
            (by simpa [votesOther candidate candidateEq] using member)
  have progressAfter : LeaderProgressBounded after := by
    intro leader role peer
    have oldRole : (state.nodes leader).role = .leader := by
      simpa [roleEq] using role
    simpa [sentEq, matchEq, logEq] using
      facts.leaderProgressBounded leader oldRole peer
  change SystemInductiveInvariant after
  apply
    responseDequeuePreservesSystemInductiveInvariant
      state after packed roleEq termEq logEq commitEq
        candidatesSelfVoteAfter leadersHaveElectionMajorityAfter
  · exact voteHistoryAfter
  · intro _ _ _ _ _ _ actualFacts
    rcases actualFacts.processedAckHistory with
      ⟨actualAckHistory, actualAckFacts⟩
    exact
      ⟨actualAckHistory,
        processedAckHistoryFrame
          state after actualAckHistory actualAckFacts
            roleEq termEq logEq
            (fun leader peer => congrFun (matchEq leader) peer)⟩
  · intro queuedDestination message member
    exact
      updateQueueSubset queuedDestination message
        (by simpa [after] using member)
  · exact progressAfter
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact
      effectiveAckersAfterVoteResponse
        state after destination response remaining
          takenByResponseSource rfl termEq logEq
          (fun leader peer => congrFun (matchEq leader) peer)
          actualResponseHistory leader index
  · intro candidate role majority
    unfold hasEffectiveElectionMajority at majority ⊢
    have cardBound :=
      Finset.card_le_card (effectiveSubset candidate)
    omega
  · exact fun candidate voter _ member =>
      effectiveSubset candidate member

/-! ## Request receives -/

/-- Append requests are unaffected by consuming a vote request and replying. -/
theorem appendRequestMemAfterVoteRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.requestVoteRequest request, remaining)) :
    forall queuedDestination queuedRequest,
      Message.appendEntriesRequest queuedRequest ∈
          enqueueNoDup
            (updateQueue network destination remaining)
            (.requestVoteResponse response)
            queuedDestination ↔
        Message.appendEntriesRequest queuedRequest ∈
          network queuedDestination := by
  intro queuedDestination queuedRequest
  constructor
  · intro member
    rcases
        memEnqueueNoDup
          (updateQueue network destination remaining)
          (.requestVoteResponse response)
          (.appendEntriesRequest queuedRequest)
          queuedDestination member with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        have retained :
            Message.appendEntriesRequest queuedRequest ∈ remaining := by
          simpa [updateQueue] using old
        exact (takeFirstFromSound taken).2.2 _ retained
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

/-- Append responses are unaffected by consuming a vote request and replying. -/
theorem appendResponseMemAfterVoteRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.requestVoteRequest request, remaining)) :
    forall queuedDestination queuedResponse,
      Message.appendEntriesResponse queuedResponse ∈
          enqueueNoDup
            (updateQueue network destination remaining)
            (.requestVoteResponse response)
            queuedDestination ↔
        Message.appendEntriesResponse queuedResponse ∈
          network queuedDestination := by
  intro queuedDestination queuedResponse
  constructor
  · intro member
    rcases
        memEnqueueNoDup
          (updateQueue network destination remaining)
          (.requestVoteResponse response)
          (.appendEntriesResponse queuedResponse)
          queuedDestination member with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        have retained :
            Message.appendEntriesResponse queuedResponse ∈ remaining := by
          simpa [updateQueue] using old
        exact (takeFirstFromSound taken).2.2 _ retained
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

/-- A remaining vote request existed before the selected request was consumed. -/
theorem voteRequestMemBackAfterVoteRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.requestVoteRequest request, remaining)) :
    forall queuedDestination queuedRequest,
      Message.requestVoteRequest queuedRequest ∈
          enqueueNoDup
            (updateQueue network destination remaining)
            (.requestVoteResponse response)
            queuedDestination ->
        Message.requestVoteRequest queuedRequest ∈
          network queuedDestination := by
  intro queuedDestination queuedRequest member
  rcases
      memEnqueueNoDup
        (updateQueue network destination remaining)
        (.requestVoteResponse response)
        (.requestVoteRequest queuedRequest)
        queuedDestination member with
    old | new
  · by_cases same : queuedDestination = destination
    · subst queuedDestination
      have retained :
          Message.requestVoteRequest queuedRequest ∈ remaining := by
        simpa [updateQueue] using old
      exact (takeFirstFromSound taken).2.2 _ retained
    · simpa [updateQueue, Function.update, same] using old
  · simp at new

/-- A queued vote response is old or is the response just produced. -/
theorem voteResponseMemAfterVoteRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : RequestVoteRequest)
    (response queuedResponse : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.requestVoteRequest request, remaining))
    (queuedDestination : Node)
    (member :
      Message.requestVoteResponse queuedResponse ∈
        enqueueNoDup
          (updateQueue network destination remaining)
          (.requestVoteResponse response)
          queuedDestination) :
    Message.requestVoteResponse queuedResponse ∈
        network queuedDestination \/
      (queuedDestination = response.destination /\
        queuedResponse = response) := by
  rcases
      memEnqueueNoDup
        (updateQueue network destination remaining)
        (.requestVoteResponse response)
        (.requestVoteResponse queuedResponse)
        queuedDestination member with
    old | new
  · left
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      have retained :
          Message.requestVoteResponse queuedResponse ∈ remaining := by
        simpa [updateQueue] using old
      exact (takeFirstFromSound taken).2.2 _ retained
    · simpa [updateQueue, Function.update, same] using old
  · simp only [Message.requestVoteResponse.injEq] at new
    exact Or.inr ⟨new.1, new.2⟩

/-- Every old vote response remains queued after consuming a vote request. -/
theorem oldVoteResponseMemAfterVoteRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : RequestVoteRequest)
    (response queuedResponse : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.requestVoteRequest request, remaining))
    (queuedDestination : Node)
    (member :
      Message.requestVoteResponse queuedResponse ∈
        network queuedDestination) :
    Message.requestVoteResponse queuedResponse ∈
      enqueueNoDup
        (updateQueue network destination remaining)
        (.requestVoteResponse response)
        queuedDestination := by
  apply memEnqueueNoDupOfMem
  by_cases same : queuedDestination = destination
  · subst queuedDestination
    rcases memSelectedOrRemaining taken member with selected | retained
    · simp at selected
    · simpa [updateQueue] using retained
  · simpa [updateQueue, Function.update, same] using member

/-- Vote requests are unaffected by consuming an AppendEntries request. -/
theorem voteRequestMemAfterAppendRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.appendEntriesRequest request, remaining)) :
    forall queuedDestination queuedRequest,
      Message.requestVoteRequest queuedRequest ∈
          reply network destination remaining response queuedDestination ↔
        Message.requestVoteRequest queuedRequest ∈
          network queuedDestination := by
  intro queuedDestination queuedRequest
  constructor
  · intro member
    rcases
        memEnqueueNoDup
          (updateQueue network destination remaining)
          (.appendEntriesResponse response)
          (.requestVoteRequest queuedRequest)
          queuedDestination (by simpa [reply] using member) with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        exact (takeFirstFromSound taken).2.2 _
          (by simpa [updateQueue] using old)
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    rw [reply]
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

/-- Vote responses are unaffected by consuming an AppendEntries request. -/
theorem voteResponseMemAfterAppendRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.appendEntriesRequest request, remaining)) :
    forall queuedDestination queuedResponse,
      Message.requestVoteResponse queuedResponse ∈
          reply network destination remaining response queuedDestination ↔
        Message.requestVoteResponse queuedResponse ∈
          network queuedDestination := by
  intro queuedDestination queuedResponse
  constructor
  · intro member
    rcases
        memEnqueueNoDup
          (updateQueue network destination remaining)
          (.appendEntriesResponse response)
          (.requestVoteResponse queuedResponse)
          queuedDestination (by simpa [reply] using member) with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        exact (takeFirstFromSound taken).2.2 _
          (by simpa [updateQueue] using old)
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    rw [reply]
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

/-- A queued AppendEntries response is old or is the response just produced. -/
theorem appendResponseMemAfterAppendRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (response queuedResponse : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.appendEntriesRequest request, remaining))
    (queuedDestination : Node)
    (member :
      Message.appendEntriesResponse queuedResponse ∈
        reply network destination remaining response queuedDestination) :
    Message.appendEntriesResponse queuedResponse ∈
        network queuedDestination \/
      (queuedDestination = response.destination /\
        queuedResponse = response) := by
  rcases
      memEnqueueNoDup
        (updateQueue network destination remaining)
        (.appendEntriesResponse response)
        (.appendEntriesResponse queuedResponse)
        queuedDestination (by simpa [reply] using member) with
    old | new
  · left
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      exact (takeFirstFromSound taken).2.2 _
        (by simpa [updateQueue] using old)
    · simpa [updateQueue, Function.update, same] using old
  · simp only [Message.appendEntriesResponse.injEq] at new
    exact Or.inr new

/-- Every old AppendEntries response remains queued after request handling. -/
theorem oldAppendResponseMemAfterAppendRequestReceive
    (network : Node -> List (Message TxId))
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (response queuedResponse : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (network destination) =
        some (.appendEntriesRequest request, remaining))
    (queuedDestination : Node)
    (member :
      Message.appendEntriesResponse queuedResponse ∈
        network queuedDestination) :
    Message.appendEntriesResponse queuedResponse ∈
      reply network destination remaining response queuedDestination := by
  rw [reply]
  apply memEnqueueNoDupOfMem
  by_cases same : queuedDestination = destination
  · subst queuedDestination
    rcases memSelectedOrRemaining taken member with selected | retained
    · simp at selected
    · simpa [updateQueue] using retained
  · simpa [updateQueue, Function.update, same] using member

/-- Post-receive ACK evidence is old evidence or the selected request's newly
materialised destination ACK. -/
theorem effectiveAckerAfterAppendRequestReceive
    (state after : State TxId)
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (newHistory : List (Entry TxId))
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining))
    (producedSource : response.source = destination)
    (producedDestination : response.destination = request.source)
    (producedTerm :
      response.success = true ->
        response.term = (state.nodes destination).currentTerm)
    (successfulRequestTerm :
      response.success = true ->
        request.term = (state.nodes destination).currentTerm)
    (networkEq :
      after.network =
        reply state.network destination remaining response)
    (termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm)
    (matchEq :
      forall leader peer,
        (after.nodes leader).matchIndex peer =
          (state.nodes leader).matchIndex peer)
    (leaderLogEq :
      forall leader,
        (after.nodes leader).role = .leader ->
          (after.nodes leader).log = (state.nodes leader).log) :
    forall leader index,
      (after.nodes leader).role = .leader ->
      forall voter,
        voter ∈
            effectiveAckers after
              (Function.update responseHistory response
                newHistory)
              leader index ->
          voter ∈ effectiveAckers state responseHistory leader index \/
            (response.success = true /\
              leader = request.source /\
              voter = destination /\
              index <= response.lastLogIndex /\
              request.term =
                (state.nodes request.source).currentTerm) := by
  intro leader index role voter member
  simp only [
    effectiveAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at member ⊢
  rcases member with self | matched | queued
  · exact Or.inl (Or.inl self)
  · exact Or.inl
      (Or.inr (Or.inl (by simpa [matchEq] using matched)))
  · rcases queued with
      ⟨queuedResponse, queuedMember, success, responseTerm,
        responseSource, responseDestination, covered, historyCovered⟩
    have memberCases :=
      appendResponseMemAfterAppendRequestReceive
        state.network source destination request response queuedResponse
          remaining taken leader
          (by simpa [networkEq] using queuedMember)
    by_cases sameResponse : queuedResponse = response
    · subst queuedResponse
      right
      have leaderSource : leader = request.source := by
        rw [producedDestination] at responseDestination
        exact responseDestination.symm
      exact
        ⟨success,
          leaderSource,
          by rw [producedSource] at responseSource
             exact responseSource.symm,
          covered,
          by
            have responseRequestTerm :=
              (producedTerm success).symm.trans
                (by simpa [termEq] using responseTerm)
            exact
              (successfulRequestTerm success).trans
                (by simpa [leaderSource] using responseRequestTerm)⟩
    · rcases memberCases with oldMember | new
      · left
        right
        right
        refine
          ⟨queuedResponse, oldMember, success,
            by simpa [termEq] using responseTerm,
            responseSource, responseDestination, covered, ?_⟩
        simpa [
          Function.update, sameResponse,
          leaderLogEq leader role
        ] using historyCovered
      · exact False.elim (sameResponse new.2)

/-- Reserve materialisation preserves all temporal ACK histories. -/
theorem appendRequestAckerTemporalFacts
    (state : State TxId)
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Message TxId))
    (votes : VoteHistory)
    (appendHistory : AppendEntriesRequest TxId -> List (Entry TxId))
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId))
    (canonicalHistory : Nat -> List (Entry TxId))
    (owners : TermOwners)
    (elections : ElectionHistory TxId)
    (termsPositive : CurrentTermsPositive state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership :
      TermOwnershipFacts
        state votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        state votes canonicalHistory owners elections)
    (electionQueued :
      ElectionQueuedHistoryFacts state appendHistory elections)
    (currentFacts :
      AckerCurrentHistory state responseHistory elections)
    (ackerVoteFacts :
      AckerVoteHistory
        state votes responseHistory voteVoterHistory elections)
    (ackerElectionFacts :
      AckerElectionHistory state responseHistory elections)
    (requestDestination : request.destination = destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (notStepped :
      returnToFollowerState? (state.nodes destination) request = none)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining))
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    let after : State TxId :=
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := reply state.network destination remaining response }
    let newResponseHistory :=
      Function.update responseHistory response (appendHistory request)
    AckerCurrentHistory after newResponseHistory elections /\
      AckerVoteHistory
        after votes newResponseHistory voteVoterHistory elections /\
      AckerElectionHistory after newResponseHistory elections := by
  let post := CCFRaft.handleAppendEntriesRequestLocalPost handled
  let after : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network := reply state.network destination remaining response }
  let newResponseHistory :=
    Function.update responseHistory response (appendHistory request)
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (takeFirstFromSound taken).2.1
  have roleEq :
      forall node,
        (after.nodes node).role = (state.nodes node).role := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.roleUnchanged
    · simp [after, updateNode, Function.update, same]
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.currentTermUnchanged
    · simp [after, updateNode, Function.update, same]
  have matchEq :
      forall leader peer,
        (after.nodes leader).matchIndex peer =
          (state.nodes leader).matchIndex peer := by
    intro leader peer
    by_cases same : leader = destination
    · subst leader
      simpa [after, updateNode] using
        congrFun post.matchIndexUnchanged peer
    · simp [after, updateNode, Function.update, same]
  have activeNodeEq :
      forall node,
        ((state.nodes node).role = .candidate \/
          (state.nodes node).role = .leader) ->
          after.nodes node = state.nodes node := by
    intro node active
    by_cases same : node = destination
    · subst node
      have unchanged :=
        handleAppendEntriesRequestActiveUnchanged
          notStepped handled active
      simp [after, updateNode, unchanged]
    · simp [after, updateNode, Function.update, same]
  have leaderLogEq :
      forall leader,
        (after.nodes leader).role = .leader ->
          (after.nodes leader).log = (state.nodes leader).log := by
    intro leader role
    have oldRole : (state.nodes leader).role = .leader := by
      simpa [roleEq] using role
    exact congrArg NodeState.log
      (activeNodeEq leader (Or.inr oldRole))
  have effectiveCases :
      forall leader index,
        (after.nodes leader).role = .leader ->
        forall voter,
          voter ∈ effectiveAckers after newResponseHistory leader index ->
            voter ∈ effectiveAckers state responseHistory leader index \/
              (response.success = true /\
                leader = request.source /\
                voter = destination /\
                index <= response.lastLogIndex /\
                request.term =
                  (state.nodes request.source).currentTerm) := by
    intro leader index role voter member
    exact
      effectiveAckerAfterAppendRequestReceive
        state after source destination request response remaining
          responseHistory (appendHistory request) taken
          (by simpa [requestDestination] using post.responseSource)
          post.responseDestination
          post.successfulResponseTerm post.successfulCurrentTerm
          rfl termEq matchEq leaderLogEq
          leader index role voter
          (by simpa [newResponseHistory] using member)
  have sourceStateEq :
      forall leader,
        (after.nodes leader).role = .leader ->
          after.nodes leader = state.nodes leader := by
    intro leader role
    have oldRole : (state.nodes leader).role = .leader := by
      simpa [roleEq] using role
    exact activeNodeEq leader (Or.inr oldRole)
  change
    AckerCurrentHistory after newResponseHistory elections /\
      AckerVoteHistory
        after votes newResponseHistory voteVoterHistory elections /\
      AckerElectionHistory after newResponseHistory elections
  constructor
  · intro leader index role current signature voter effective
    have oldRole : (state.nodes leader).role = .leader := by
      simpa [roleEq] using role
    have leaderEq := sourceStateEq leader role
    have oldCurrent :
        termAt (state.nodes leader).log index =
          (state.nodes leader).currentTerm := by
      simpa [leaderEq] using current
    have oldSignature :
        isSignatureAt (state.nodes leader).log index = true := by
      simpa [leaderEq] using signature
    rcases effectiveCases leader index role voter effective with
      oldEffective | materialised
    · rcases
          currentFacts leader index oldRole oldCurrent oldSignature
            voter oldEffective with
        retained | bad
      · by_cases voterEq : voter = destination
        · subst voter
          by_cases succeeded : response.success = true
          · have destinationTerm :
                request.term =
                  (state.nodes destination).currentTerm :=
              post.successfulCurrentTerm succeeded
            have leaderTermLe :
                (state.nodes leader).currentTerm <= request.term := by
              have currentPositive :
                  0 < termAt (state.nodes leader).log index := by
                rw [oldCurrent]
                exact termsPositive leader
              rcases termAtPositiveEntry currentPositive with
                ⟨entry, found, entryTerm⟩
              have foundInPrefix :
                  entryAt?
                      ((state.nodes leader).log.take index)
                      index =
                    some entry := by
                rw [entryAtTake_of_le (le_refl index)]
                exact found
              have destinationFound :=
                CCFRaft.entryAt_of_prefix retained foundInPrefix
              have bounded :=
                entriesBounded destination entry
                  (entryAtSomeMember destinationFound)
              simpa [entryTerm, oldCurrent, destinationTerm] using bounded
            by_cases sameTerm :
                (state.nodes leader).currentTerm = request.term
            · have requestOwner :=
                (ownership.queuedAppendMetadata
                  destination request requestMember).1
              have leaderOwner := ownership.activeLeader leader oldRole
              rw [sameTerm] at leaderOwner
              have sameLeader :
                  leader = request.source :=
                Option.some.inj (leaderOwner.symm.trans requestOwner)
              subst leader
              have requestHistory :=
                ownership.queuedActiveSourceHistory
                  destination request requestMember
                    (by simpa [sameTerm])
                    oldRole
              let leaderPrefix :=
                (state.nodes request.source).log.take index
              have prefixLength :
                  leaderPrefix.length = index := by
                have currentPositive :
                    0 < termAt
                      (state.nodes request.source).log index := by
                  rw [oldCurrent]
                  exact termsPositive request.source
                rcases termAtPositiveEntry currentPositive with
                  ⟨entry, found, _⟩
                simp [
                  leaderPrefix, List.length_take,
                  entryAtSomeIndexBound found
                ]
              by_cases coveredByHistory :
                  leaderPrefix.length <=
                    (appendHistory request).length
              · have shared :
                    leaderPrefix <+: appendHistory request := by
                  rw [List.prefix_iff_eq_take]
                  calc
                    leaderPrefix =
                        (state.nodes request.source).log.take
                          leaderPrefix.length := by
                      simpa [leaderPrefix, prefixLength]
                    _ =
                        (appendHistory request).take leaderPrefix.length :=
                      (CCFRaft.takeEqOfPrefix
                        requestHistory coveredByHistory).symm
                have retainedNext :=
                  handledAppendRequestRetainsSharedPrefix
                    state votes appendHistory canonicalHistory owners
                      ownership destination request nextNode response
                      requestMember snapshot handled succeeded retained shared
                exact Or.inl
                  (by
                    rw [sourceStateEq request.source role]
                    simpa [after, updateNode, leaderPrefix] using retainedNext)
              · have historyInPrefix :
                    appendHistory request <+: leaderPrefix := by
                  rw [List.prefix_iff_eq_take]
                  have historyBound :
                      (appendHistory request).length <=
                        leaderPrefix.length := by omega
                  calc
                    appendHistory request =
                        (state.nodes request.source).log.take
                          (appendHistory request).length :=
                      (CCFRaft.prefixEqTake requestHistory).symm
                    _ =
                        leaderPrefix.take (appendHistory request).length := by
                      simp [
                        leaderPrefix, List.take_take,
                        Nat.min_eq_left
                          (by simpa [prefixLength] using historyBound)
                      ]
                have historyBefore :
                    appendHistory request <+:
                      (state.nodes destination).log :=
                  historyInPrefix.trans retained
                have already :
                    alreadyDone (state.nodes destination) request :=
                  appendRequestAlreadyDoneOfSharedPrefix
                    snapshot historyBefore (prefixRefl _)
                      snapshot.1
                have unchanged :=
                  successfulAlreadyDoneAppendLogUnchanged
                    already handled succeeded
                exact Or.inl
                  (by
                    rw [sourceStateEq request.source role]
                    simpa [after, updateNode, unchanged] using retained)
            · have strict :
                  (state.nodes leader).currentTerm < request.term := by
                omega
              rcases
                  electionFacts.ownerRecorded
                    request.term request.source
                      ((ownership.queuedAppendMetadata
                        destination request requestMember).1) with
                bootstrap | recorded
              · have positive := termsPositive leader
                rw [bootstrap.1] at strict
                omega
              · rcases recorded with
                  ⟨record, recordStored, _⟩
                by_cases inPromotion :
                    (state.nodes leader).log.take index <+:
                      record.promotionLog
                · have shared :=
                    inPromotion.trans
                      (electionQueued
                        destination request requestMember
                          record recordStored)
                  have retainedNext :=
                    handledAppendRequestRetainsSharedPrefix
                      state votes appendHistory canonicalHistory owners
                        ownership destination request nextNode response
                        requestMember snapshot handled succeeded retained shared
                  exact Or.inl
                    (by
                      rw [leaderEq]
                      simpa [after, updateNode] using retainedNext)
                · right
                  exact
                    ⟨request.term, record,
                      by simpa [leaderEq] using strict,
                      by simpa [termEq, destinationTerm],
                      recordStored, by simpa [leaderEq] using inPromotion⟩
          · have failed : response.success = false :=
              Bool.eq_false_of_not_eq_true succeeded
            have unchanged := post.failedStateUnchanged failed
            exact Or.inl
              (by
                rw [leaderEq]
                simpa [after, updateNode, unchanged] using retained)
        · exact Or.inl
            (by
              rw [leaderEq]
              simpa [
                after, updateNode, Function.update, voterEq
              ] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [leaderEq] using above,
            by simpa [termEq] using bounded,
            recorded,
            by simpa [leaderEq] using missing⟩
    · rcases materialised with
        ⟨succeeded, leaderSource, voterDestination,
          acknowledged, requestTerm⟩
      subst leader
      subst voter
      have acknowledgedPrefix :=
        handledAppendRequestAcknowledgesSourcePrefix
          state votes appendHistory canonicalHistory owners ownership
            destination request nextNode response requestMember snapshot
            handled succeeded
            (by simpa [roleEq] using role)
            requestTerm acknowledged
      exact Or.inl
        (by
          rw [sourceStateEq request.source role]
          simpa [after, updateNode] using acknowledgedPrefix)
  · constructor
    · intro leader index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      have leaderEq := sourceStateEq leader role
      have oldCurrent :
          termAt (state.nodes leader).log index =
            (state.nodes leader).currentTerm := by
        simpa [leaderEq] using current
      have oldSignature :
          isSignatureAt (state.nodes leader).log index = true := by
        simpa [leaderEq] using signature
      rcases effectiveCases leader index role voter effective with
        oldEffective | materialised
      · rcases
            ackerVoteFacts leader index oldRole oldCurrent oldSignature
              voter voteTerm candidate oldEffective voted different
                (by simpa [leaderEq] using newer) with
          retained | bad
        · exact Or.inl (by simpa [leaderEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact
            ⟨badTerm, badRecord,
              by simpa [leaderEq] using above,
              bounded, recorded,
              by simpa [leaderEq] using missing⟩
      · rcases materialised with
          ⟨succeeded, leaderSource, voterDestination,
            _, requestTerm⟩
        subst leader
        subst voter
        have destinationTerm :
            request.term =
              (state.nodes destination).currentTerm :=
          post.successfulCurrentTerm succeeded
        have future :
            votes destination voteTerm = none :=
          voteFacts.future destination voteTerm
            (by
              have sourceNewer :
                  (state.nodes request.source).currentTerm < voteTerm := by
                simpa [leaderEq] using newer
              rw [← destinationTerm, requestTerm]
              exact sourceNewer)
        rw [future] at voted
        contradiction
    · intro leader index role current signature
        term record voter recorded voterMember effective newer
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      have leaderEq := sourceStateEq leader role
      have oldCurrent :
          termAt (state.nodes leader).log index =
            (state.nodes leader).currentTerm := by
        simpa [leaderEq] using current
      have oldSignature :
          isSignatureAt (state.nodes leader).log index = true := by
        simpa [leaderEq] using signature
      rcases effectiveCases leader index role voter effective with
        oldEffective | materialised
      · rcases
            ackerElectionFacts leader index oldRole oldCurrent oldSignature
              term record voter recorded voterMember oldEffective
                (by simpa [leaderEq] using newer) with
          retained | bad
        · exact Or.inl (by simpa [leaderEq] using retained)
        · exact Or.inr (by simpa [leaderEq] using bad)
      · rcases materialised with
          ⟨succeeded, leaderSource, voterDestination,
            _, requestTerm⟩
        subst leader
        subst voter
        have destinationTerm :
            request.term =
              (state.nodes destination).currentTerm :=
          post.successfulCurrentTerm succeeded
        have voterTerm :=
          electionHistoryVoterTerm
            voteFacts electionFacts recorded voterMember
        have sourceNewer :
            request.term < term := by
          simpa [leaderEq, requestTerm] using newer
        rw [destinationTerm] at sourceNewer
        omega

/-- Vote-request processing does not change replication acknowledgement sets. -/
theorem effectiveAckersAfterVoteRequestReceive
    (state after : State TxId)
    (source destination : Node)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteRequest request, remaining))
    (networkEq :
      after.network =
        enqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response))
    (termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (matchEq :
      forall leader peer,
        (after.nodes leader).matchIndex peer =
          (state.nodes leader).matchIndex peer) :
    forall responseHistory leader index,
      effectiveAckers after responseHistory leader index =
        effectiveAckers state responseHistory leader index := by
  intro responseHistory leader index
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter,
    Finset.mem_univ, true_and
  ]
  constructor <;> rintro (self | matched | queued)
  · exact Or.inl self
  · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
  · right
    right
    rcases queued with
      ⟨queuedResponse, member, success, responseTerm,
        responseSource, responseDestination, lastIndex, covered⟩
    exact
      ⟨queuedResponse,
        (appendResponseMemAfterVoteRequestReceive
          state.network source destination request response remaining
            taken leader queuedResponse).mp
          (by simpa [networkEq] using member),
        success,
        by simpa [termEq] using responseTerm,
        responseSource, responseDestination, lastIndex,
        by simpa [logEq] using covered⟩
  · exact Or.inl self
  · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
  · right
    right
    rcases queued with
      ⟨queuedResponse, member, success, responseTerm,
        responseSource, responseDestination, lastIndex, covered⟩
    exact
      ⟨queuedResponse,
        by
          rw [networkEq]
          exact
            (appendResponseMemAfterVoteRequestReceive
              state.network source destination request response remaining
                taken leader queuedResponse).mpr member,
        success,
        by simpa [termEq] using responseTerm,
        responseSource, responseDestination, lastIndex,
        by simpa [logEq] using covered⟩

/-- Existing effective election voters survive vote-request processing. -/
theorem effectiveElectionVotersBeforeSubsetAfterVoteRequestReceive
    (state after : State TxId)
    (source destination : Node)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteRequest request, remaining))
    (networkEq :
      after.network =
        enqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response))
    (votesEq :
      forall candidate,
        (after.nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted)
    (termEq :
      forall candidate,
        (after.nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm) :
    forall candidate,
      effectiveElectionVoters state candidate ⊆
        effectiveElectionVoters after candidate := by
  intro candidate voter member
  simp only [
    effectiveElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at member ⊢
  rcases member with processed | queued
  · exact Or.inl (by simpa [votesEq] using processed)
  · right
    rcases queued with
      ⟨queuedResponse, queuedMember, granted, responseTerm,
        responseSource, responseDestination⟩
    exact
      ⟨queuedResponse,
        by
          rw [networkEq]
          exact
            oldVoteResponseMemAfterVoteRequestReceive
              state.network source destination request response
                queuedResponse remaining taken candidate queuedMember,
        granted, by simpa [termEq] using responseTerm,
        responseSource, responseDestination⟩

/-- Arbitrary-term local facts for one handled RequestVote request. -/
structure VoteRequestLocalPost
    (before after : NodeState TxId)
    (request : RequestVoteRequest)
    (response : RequestVoteResponse) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  votedForUpdate :
    after.votedFor = before.votedFor \/
      (before.votedFor = none /\
        after.votedFor = some request.source)
  responseTerm : response.term = before.currentTerm
  responseSource : response.source = request.destination
  responseDestination : response.destination = request.source
  granted :
    response.voteGranted = true ->
      request.term = before.currentTerm /\
        voteLogUpToDate before request /\
        (before.votedFor = none \/
          before.votedFor = some request.source) /\
        after.votedFor = some request.source
  grantedState :
    response.voteGranted = true ->
      after = { before with votedFor := some request.source }
  rejectedState :
    response.voteGranted = false ->
      after = before

/-- The RequestVote handler changes only the persistent vote and reply. -/
theorem handleRequestVoteRequestLocalPost
    {before after : NodeState TxId}
    {request : RequestVoteRequest}
    {response : RequestVoteResponse}
    (handled :
      handleRequestVoteRequest? before request =
        some (after, response)) :
    VoteRequestLocalPost before after request response := by
  unfold handleRequestVoteRequest? at handled
  split at handled
  · rename_i current
    let grant : Bool :=
      decide (
        request.term = before.currentTerm /\
          voteLogUpToDate before request /\
          (before.votedFor = none \/
            before.votedFor = some request.source))
    by_cases granted : grant = true
    · have grantFacts :
          request.term = before.currentTerm /\
            voteLogUpToDate before request /\
            (before.votedFor = none \/
              before.votedFor = some request.source) := by
        simpa [grant, Bool.decide_eq_true] using granted
      have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rcases grantFacts.2.2 with noVote | sameVote
        · exact Or.inr ⟨noVote, by simp [grantFacts]⟩
        · exact Or.inl (by simp [grantFacts, sameVote])
      · rfl
      · rfl
      · rfl
      · intro _
        exact
          ⟨grantFacts.1, grantFacts.2.1,
            grantFacts.2.2, by simp [grantFacts]⟩
      · intro _
        rfl
      · intro rejected
        contradiction
    · have notGranted :
          Not (
            request.term = before.currentTerm /\
              voteLogUpToDate before request /\
              (before.votedFor = none \/
                before.votedFor = some request.source)) := by
        intro facts
        apply granted
        simp [grant, facts]
      have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · exact Or.inl rfl
      · rfl
      · rfl
      · rfl
      · intro success
        simp [notGranted] at success
      · intro success
        contradiction
      · intro _
        rfl
  · contradiction

/--
A granted response can only add a voter which was already in the candidate's
pre-state prospective quorum.
-/
theorem effectiveElectionVotersAfterGrantedRequestSubsetPotential
    (state : State TxId)
    (source destination : Node)
    (request : RequestVoteRequest)
    (nextNode : NodeState TxId)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteRequest request, remaining))
    (handled :
      handleRequestVoteRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    let after : State TxId :=
      { state with
        nodes := updateNode state.nodes destination nextNode
        network :=
          enqueueNoDup
            (updateQueue state.network destination remaining)
            (.requestVoteResponse response) }
    forall candidate,
      (after.nodes candidate).role = .candidate ->
      effectiveElectionVoters after candidate ⊆
        potentialElectionVoters state candidate := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have monoLog := invariantFactsMonoLogFromCanonicalHistories facts
  let after : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response) }
  let post := handleRequestVoteRequestLocalPost handled
  have selectedMember :
      Message.requestVoteRequest request ∈ state.network destination :=
    (takeFirstFromSound taken).2.1
  have requestDestination : request.destination = destination := by
    simpa using
      facts.networkHistory.addressed
        destination (.requestVoteRequest request) selectedMember
  have roleEq :
      forall node,
        (after.nodes node).role = (state.nodes node).role := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.roleUnchanged
    · simp [after, updateNode, Function.update, same]
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.currentTermUnchanged
    · simp [after, updateNode, Function.update, same]
  have votesEq :
      forall node,
        (after.nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.votesGrantedUnchanged
    · simp [after, updateNode, Function.update, same]
  dsimp only
  intro candidate candidateRole voter member
  simp only [
    effectiveElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ] at member
  simp only [
    potentialElectionVoters, Finset.mem_filter,
    Finset.mem_univ, true_and
  ]
  rcases member with processed | queued
  · apply Or.inl
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    rw [votesEq candidate] at processed
    exact Or.inl processed
  · rcases queued with
      ⟨queuedResponse, queuedMember, granted, queuedTerm,
        queuedSource, queuedDestination⟩
    rcases
        memEnqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response)
          (.requestVoteResponse queuedResponse)
          candidate
          (by simpa [after] using queuedMember) with
      old | new
    · have oldMember :
          Message.requestVoteResponse queuedResponse ∈
            state.network candidate := by
        by_cases candidateEq : candidate = destination
        · have oldAtCandidate :
              Message.requestVoteResponse queuedResponse ∈
                updateQueue state.network destination remaining candidate :=
            old
          rw [candidateEq] at oldAtCandidate
          have remainingMember :
              Message.requestVoteResponse queuedResponse ∈ remaining := by
            simpa [updateQueue] using oldAtCandidate
          simpa [candidateEq] using
            (takeFirstFromSound taken).2.2
              (.requestVoteResponse queuedResponse) remainingMember
        · simpa [
            updateQueue, Function.update, candidateEq
          ] using old
      apply Or.inl
      simp only [
        effectiveElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      rw [termEq candidate] at queuedTerm
      exact Or.inr
        ⟨queuedResponse, oldMember, granted,
          queuedTerm,
          queuedSource, queuedDestination⟩
    · rcases new with ⟨candidateEq, responseEq⟩
      simp only [Message.requestVoteResponse.injEq] at responseEq
      subst queuedResponse
      have responseGranted : response.voteGranted = true := granted
      have grantFacts := post.granted responseGranted
      have candidateEqSource : candidate = request.source := by
        exact candidateEq.trans post.responseDestination
      have voterEqDestination : voter = destination := by
        rw [post.responseSource, requestDestination] at queuedSource
        exact queuedSource.symm
      have sourceRole :
          (state.nodes request.source).role = .candidate := by
        rw [roleEq candidate] at candidateRole
        have oldCandidateRole :
            (state.nodes candidate).role = .candidate := by
          exact candidateRole
        simpa [candidateEqSource] using oldCandidateRole
      rcases
          facts.networkHistory.voteRequest
            destination request selectedMember with
        ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap,
          sourceTermBound, activePrefix⟩
      have sourceTerm :
          request.term =
            (state.nodes request.source).currentTerm := by
        calc
          request.term = (state.nodes destination).currentTerm :=
            grantFacts.1
          _ = response.term := post.responseTerm.symm
          _ = (after.nodes candidate).currentTerm := queuedTerm
          _ = (state.nodes candidate).currentTerm := termEq candidate
          _ = (state.nodes request.source).currentTerm := by
            rw [candidateEqSource]
      have candidatePrefix :
          voteRequestHistory request <+:
            (state.nodes request.source).log :=
        activePrefix sourceTerm (Or.inl sourceRole)
      have canonicalUpToDate :
          voteLogUpToDate
            (state.nodes destination)
            (makeRequestVoteRequest
              state request.source destination) := by
        simpa [
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes request.source)
            (facts.committedFrontierIsSignature request.source),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes request.source)
            (facts.committedFrontierIsSignature request.source),
          sourceTerm, grantFacts.1
        ] using
          (voteLogUpToDateOfCandidatePrefix
            (state.nodes destination) request.source destination
              candidatePrefix
              (monoLog request.source)
              (by simpa [
                voteLogUpToDate, maxCommittableTerm,
                lastIndex, lastTerm, maxIndex
              ] using grantFacts.2.1))
      have candidateVoterTerm :
          (state.nodes request.source).currentTerm =
            (state.nodes destination).currentTerm :=
        sourceTerm.symm.trans grantFacts.1
      apply Or.inr
      unfold currentlyEligibleElectionVoter
      simpa [
        makeRequestVoteRequest,
        candidateEqSource, voterEqDestination
      ] using
        And.intro candidateVoterTerm
          (And.intro canonicalUpToDate grantFacts.2.2.1)

/-- A post-grant effective quorum was already a pre-state prospective quorum. -/
theorem effectiveElectionMajorityAfterGrantedRequestWasPotential
    (state : State TxId)
    (source destination : Node)
    (request : RequestVoteRequest)
    (nextNode : NodeState TxId)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteRequest request, remaining))
    (handled :
      handleRequestVoteRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    let after : State TxId :=
      { state with
        nodes := updateNode state.nodes destination nextNode
        network :=
          enqueueNoDup
            (updateQueue state.network destination remaining)
            (.requestVoteResponse response) }
    forall candidate,
      (after.nodes candidate).role = .candidate ->
      hasEffectiveElectionMajority after candidate ->
        hasPotentialElectionMajority state candidate := by
  dsimp only
  intro candidate role majority
  have subset :=
    effectiveElectionVotersAfterGrantedRequestSubsetPotential
      state source destination request nextNode response remaining
        invariant taken handled candidate role
  have cardBound := Finset.card_le_card subset
  unfold hasEffectiveElectionMajority at majority
  unfold hasPotentialElectionMajority
  omega

/-- Granting a vote freezes every prior ACK-retention fact at vote time. -/
theorem ackerVoteHistoryAfterGrantedRequest
    (state after : State TxId)
    (votes : VoteHistory)
    (responseHistory : AppendEntriesResponse -> List (Entry TxId))
    (voteVoterHistory : RequestVoteResponse -> List (Entry TxId))
    (elections : ElectionHistory TxId)
    (destination : Node)
    (request : RequestVoteRequest)
    (currentFacts :
      AckerCurrentHistory state responseHistory elections)
    (voteFacts :
      AckerVoteHistory
        state votes responseHistory voteVoterHistory elections)
    (requestTerm :
      request.term = (state.nodes destination).currentTerm)
    (roleEq :
      forall node, (after.nodes node).role = (state.nodes node).role)
    (termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm)
    (logEq :
      forall node, (after.nodes node).log = (state.nodes node).log)
    (effectiveEq :
      forall source index,
        effectiveAckers after responseHistory source index =
          effectiveAckers state responseHistory source index) :
    let key :=
      grantedVoteKey destination request.term request.source
    let newVotes : VoteHistory :=
      Function.update votes destination
        (Function.update
          (votes destination) request.term (some request.source))
    let newVoterHistory :=
      Function.update voteVoterHistory key
        ((state.nodes destination).log.take
          (maxCommittableIndex (state.nodes destination).log))
    AckerVoteHistory
      after newVotes responseHistory newVoterHistory elections := by
  dsimp
  intro source index role current signature
      voter voteTerm candidate effective voted different newer
  have oldRole : (state.nodes source).role = .leader := by
    simpa [roleEq] using role
  have oldCurrent :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm := by
    simpa [logEq, termEq] using current
  have oldSignature :
      isSignatureAt (state.nodes source).log index = true := by
    simpa [logEq] using signature
  have oldEffective :
      voter ∈ effectiveAckers state responseHistory source index := by
    rw [effectiveEq] at effective
    exact effective
  by_cases voterEq : voter = destination
  · subst voter
    by_cases voteTermEq : voteTerm = request.term
    · subst voteTerm
      have candidateEq : candidate = request.source := by
        have chosen :
            some request.source = some candidate := by
          simpa [Function.update] using voted
        exact (Option.some.inj chosen).symm
      subst candidate
      rcases
          currentFacts source index oldRole oldCurrent oldSignature
            destination oldEffective with
        retained | bad
      · left
        simpa [Function.update, logEq] using
          (signatureEndedPrefixOfMaxTake
            retained (signatureAtTakeLength oldSignature))
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [termEq] using above,
            by simpa [requestTerm] using bounded,
            recorded,
            by simpa [logEq] using missing⟩
    · have oldVoted :
          votes destination voteTerm = some candidate := by
        simpa [Function.update, voteTermEq] using voted
      rcases
          voteFacts source index oldRole oldCurrent oldSignature
            destination voteTerm candidate oldEffective oldVoted
              different (by simpa [termEq] using newer) with
        retained | bad
      · left
        have keyNe :
            Not (
              grantedVoteKey destination voteTerm candidate =
                grantedVoteKey
                  destination request.term request.source) := by
          intro same
          have sameTerm :
              voteTerm = request.term :=
            congrArg RequestVoteResponse.term same
          exact voteTermEq sameTerm
        simpa [Function.update, keyNe, logEq] using retained
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [termEq] using above,
            bounded, recorded,
            by simpa [logEq] using missing⟩
  · have oldVoted :
        votes voter voteTerm = some candidate := by
      simpa [Function.update, voterEq] using voted
    rcases
        voteFacts source index oldRole oldCurrent oldSignature
          voter voteTerm candidate oldEffective oldVoted
            different (by simpa [termEq] using newer) with
      retained | bad
    · left
      have keyNe :
          Not (
            grantedVoteKey voter voteTerm candidate =
              grantedVoteKey
                destination request.term request.source) := by
        intro same
        have sameVoter :
            voter = destination :=
          congrArg RequestVoteResponse.source same
        exact voterEq sameVoter
      simpa [Function.update, keyNe, logEq] using retained
    · right
      rcases bad with
        ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
      exact
        ⟨badTerm, badRecord,
          by simpa [termEq] using above,
          bounded, recorded,
          by simpa [logEq] using missing⟩

/-- Enqueuing a rejected vote response is inert for all safety evidence. -/
theorem enqueueRejectedVoteResponsePreservesSystemInductiveInvariant
    (state : State TxId)
    (response : RequestVoteResponse)
    (invariant : SystemInductiveInvariant state)
    (rejected : response.voteGranted = false) :
    SystemInductiveInvariant
      { state with
        network :=
          enqueueNoDup state.network (.requestVoteResponse response) } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let after : State TxId :=
    { state with
      network :=
        enqueueNoDup state.network (.requestVoteResponse response) }
  have appendRequestEq :
      forall destination request,
        Message.appendEntriesRequest request ∈ after.network destination ↔
          Message.appendEntriesRequest request ∈
            state.network destination := by
    intro destination request
    constructor
    · intro member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.appendEntriesRequest request) destination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after] using
        memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
            (.appendEntriesRequest request) destination member
  have appendResponseEq :
      forall destination queuedResponse,
        Message.appendEntriesResponse queuedResponse ∈
            after.network destination ↔
          Message.appendEntriesResponse queuedResponse ∈
            state.network destination := by
    intro destination queuedResponse
    constructor
    · intro member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.appendEntriesResponse queuedResponse) destination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after] using
        memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
            (.appendEntriesResponse queuedResponse) destination member
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact
        ⟨queuedResponse,
          (appendResponseEq leader queuedResponse).mp member,
          success, responseTerm, responseSource,
          responseDestination, lastIndex, covered⟩
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact
        ⟨queuedResponse,
          (appendResponseEq leader queuedResponse).mpr member,
          success, responseTerm, responseSource,
          responseDestination, lastIndex, covered⟩
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor
    · rintro (processed | queued)
      · exact Or.inl processed
      · right
        rcases queued with
          ⟨queuedResponse, member, granted, responseTerm,
            responseSource, responseDestination⟩
        rcases
            memEnqueueNoDup
              state.network (.requestVoteResponse response)
                (.requestVoteResponse queuedResponse) candidate
                (by simpa [after] using member) with
          old | new
        · exact
            ⟨queuedResponse, old, granted, responseTerm,
              responseSource, responseDestination⟩
        · simp only [Message.requestVoteResponse.injEq] at new
          have same : queuedResponse = response := new.2
          subst queuedResponse
          rw [rejected] at granted
          contradiction
    · rintro (processed | queued)
      · exact Or.inl processed
      · right
        rcases queued with
          ⟨queuedResponse, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact
          ⟨queuedResponse,
            by simpa [after] using
              memEnqueueNoDupOfMem
                state.network (.requestVoteResponse response)
                  (.requestVoteResponse queuedResponse)
                  candidate member,
            granted, responseTerm,
            responseSource, responseDestination⟩
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt after responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    simp only [hasEffectiveMajorityAt, effectiveAckersEq]
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority after candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority, effectiveElectionVotersEq
    ]
  refine
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · exact facts.commitIndicesBounded
  · exact facts.committedFrontierIsSignature
  · exact facts.currentTermsPositive
  · exact facts.entriesDoNotExceedCurrentTerm
  · exact facts.candidatesSelfVote
  · exact facts.leadersHaveElectionMajority
  · exact facts.leaderProgressBounded
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · exact facts.voteHistory.current
    · exact facts.voteHistory.future
    · exact facts.voteHistory.counted
  · constructor
    · intro destination message member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              message destination
              (by simpa [after] using member) with
        old | new
      · exact facts.networkHistory.addressed destination message old
      · exact
          (congrArg Message.destination new.2).trans new.1.symm
    · intro destination request member
      exact
        facts.networkHistory.appendRequest
          destination request (appendRequestEq destination request |>.mp member)
    · intro destination queuedResponse member
      exact
        facts.networkHistory.appendResponse
          destination queuedResponse
            ((appendResponseEq destination queuedResponse).mp member)
    · intro destination request member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.requestVoteRequest request) destination
              (by simpa [after] using member) with
        old | new
      · exact facts.networkHistory.voteRequest destination request old
      · simp at new
    · intro destination queuedResponse member granted
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) destination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.networkHistory.voteResponse
            destination queuedResponse old granted
      · simp only [Message.requestVoteResponse.injEq] at new
        have same : queuedResponse = response := new.2
        rw [same, rejected] at granted
        contradiction
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state after appendHistory nodeEvidence requestEvidence
          evidenceFacts
          (fun _ => rfl) (fun _ => rfl)
    · intro node
      exact le_rfl
    · intro destination request member
      exact (appendRequestEq destination request).mp member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state after appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state after appendHistory nodeEvidence requestEvidence
            (fun _ => rfl) (fun _ => rfl)
            (fun destination request member =>
              (appendRequestEq destination request).mp member)
            known
    · intro member
      exact prefixRefl (state.nodes member).log
    · intro evidence supportedPrefix destination request known
        queued sameTerm
      exact Or.inl
        ⟨(appendRequestEq destination request).mp queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have oldRelaxed :
          member ∈ relaxedElectionVoters state candidate := by
        simp only [
          relaxedElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ] at relaxed ⊢
        rcases relaxed with effective | eligible
        · exact Or.inl
            (by rw [effectiveElectionVotersEq] at effective; exact effective)
        · exact Or.inr eligible
      exact Or.inl
        ⟨role, newer, entriesBefore,
          oldRelaxed,
          prefixRefl (state.nodes candidate).log⟩
  · refine
      ⟨owners, canonicalHistory, elections,
        nodeEvidence, requestEvidence,
        ?_, ?_, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    · constructor
      · exact ownership.bootstrap
      · exact ownership.activeLeader
      · exact ownership.logEntryAgreement
      · intro destination request member index entry found
        exact
          ownership.queuedHistoryEntryAgreement
            destination request
              ((appendRequestEq destination request).mp member)
              index entry found
      · exact ownership.activeLeaderHistory
      · exact ownership.canonicalEntryOwner
      · exact ownership.canonicalMonoLog
      · exact ownership.ownerProgress
      · intro destination request member
        exact
          ownership.queuedAppendMetadata
            destination request
              ((appendRequestEq destination request).mp member)
      · intro destination request member sameTerm leaderRole
        exact
          ownership.queuedActiveSourceHistory
            destination request
              ((appendRequestEq destination request).mp member)
              sameTerm leaderRole
    · exact
        electionHistoryFrame
          state after votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
            (fun _ _ _ _ _ => rfl)
            (fun term => prefixRefl (canonicalHistory term))
            (fun _ canonical => canonical)
    · intro candidate voter active member
      exact
        voteCanonicalFacts candidate voter active
          (by rw [effectiveElectionVotersEq] at member; exact member)
    · intro source index role current signature voter effective
      exact
        ackerCurrentFacts source index role current signature voter
          (by rw [effectiveAckersEq] at effective; exact effective)
    · intro source index role current signature voter voteTerm candidate
        effective voted different newer
      exact
        ackerVoteFacts source index role current signature
          voter voteTerm candidate
          (by rw [effectiveAckersEq] at effective; exact effective)
          voted different newer
    · intro source index role current signature term record voter recorded member
        effective newer
      exact
        ackerElectionFacts source index role current signature term record voter
          recorded member
          (by rw [effectiveAckersEq] at effective; exact effective)
          newer
    · intro destination request member record recorded
      exact
        electionQueuedFacts destination request
          ((appendRequestEq destination request).mp member)
          record recorded
  · intro candidate voter active member
    exact
      facts.grantedVoteSnapshots candidate voter active
        (by rw [effectiveElectionVotersEq] at member; exact member)
  · exact
      ⟨ackHistory,
        processedAckHistoryFrame
          state after ackHistory ackFacts
            (fun _ => rfl) (fun _ => rfl)
            (fun _ => rfl) (fun _ _ => rfl)⟩
/-- Enqueuing a granted vote response materialises prospective election evidence. -/
theorem enqueueGrantedVoteResponsePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (request : RequestVoteRequest)
    (nextNode : NodeState TxId)
    (response : RequestVoteResponse)
    (remaining : List (Message TxId))
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteRequest request, remaining))
    (handled :
      handleRequestVoteRequest? (state.nodes destination) request =
        some (nextNode, response))
    (granted : response.voteGranted = true) :
    SystemInductiveInvariant
      { state with
        nodes := updateNode state.nodes destination nextNode
        network :=
          enqueueNoDup state.network (.requestVoteResponse response) } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  have monoLog := invariantFactsMonoLogFromCanonicalHistories facts
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  let post := handleRequestVoteRequestLocalPost handled
  have grantFacts := post.granted granted
  have selectedMember :
      Message.requestVoteRequest request ∈ state.network destination :=
    (takeFirstFromSound taken).2.1
  have requestSource : request.source = source :=
    (takeFirstFromSound taken).1
  have requestFacts :=
    facts.networkHistory.voteRequest destination request selectedMember
  have requestDestination : request.destination = destination := by
    simpa using
      facts.networkHistory.addressed
        destination (.requestVoteRequest request) selectedMember
  have responseKey :
      response =
        grantedVoteKey destination request.term request.source := by
    cases response
    simp only [grantedVoteKey, RequestVoteResponse.mk.injEq]
    exact
      ⟨post.responseTerm.trans grantFacts.1.symm,
        granted,
        post.responseSource.trans requestDestination,
        post.responseDestination⟩
  let newVotes : VoteHistory :=
    Function.update votes destination
      (Function.update
        (votes destination) request.term (some request.source))
  let newCandidateHistory :=
    Function.update voteCandidateHistory response
      (voteRequestHistory request)
  let newVoterHistory :=
    Function.update voteVoterHistory response
      ((state.nodes destination).log.take
        (maxCommittableIndex (state.nodes destination).log))
  have voterSnapshotCommittable :
      maxCommittableIndex
          ((state.nodes destination).log.take
            (maxCommittableIndex (state.nodes destination).log)) =
        ((state.nodes destination).log.take
          (maxCommittableIndex (state.nodes destination).log)).length := by
    rw [maxCommittableIndexTakeMax]
    simp [
      Nat.min_eq_left
        (maxCommittableIndexBounded (state.nodes destination).log)
    ]
  let after : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueueNoDup state.network (.requestVoteResponse response) }
  have roleEq :
      forall node,
        (after.nodes node).role = (state.nodes node).role := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.roleUnchanged
    · simp [after, updateNode, Function.update, same]
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.currentTermUnchanged
    · simp [after, updateNode, Function.update, same]
  have logEq :
      forall node,
        (after.nodes node).log = (state.nodes node).log := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.logUnchanged
    · simp [after, updateNode, Function.update, same]
  have commitEq :
      forall node,
        (after.nodes node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.commitIndexUnchanged
    · simp [after, updateNode, Function.update, same]
  have lastIndexEq :
      forall node,
        lastCommittableIndex (after.nodes node) =
          lastCommittableIndex (state.nodes node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm (after.nodes node) =
          lastCommittableTerm (state.nodes node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitEq node)
  have sentEq :
      forall node,
        (after.nodes node).sentIndex =
          (state.nodes node).sentIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.sentIndexUnchanged
    · simp [after, updateNode, Function.update, same]
  have matchEq :
      forall node,
        (after.nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.matchIndexUnchanged
    · simp [after, updateNode, Function.update, same]
  have votesGrantedEq :
      forall node,
        (after.nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.votesGrantedUnchanged
    · simp [after, updateNode, Function.update, same]
  have votedForDestination :
      (after.nodes destination).votedFor =
        some request.source := by
    simpa [after, updateNode] using grantFacts.2.2.2
  have votedForOther :
      forall node,
        Not (node = destination) ->
          (after.nodes node).votedFor =
            (state.nodes node).votedFor := by
    intro node different
    simp [after, updateNode, Function.update, different]
  have committedEq :
      forall node,
        (after.nodes node).committedLog =
          (state.nodes node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitEq, logEq]
  have appendRequestEq :
      forall queuedDestination queuedRequest,
        Message.appendEntriesRequest queuedRequest ∈
            after.network queuedDestination ↔
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
    intro queuedDestination queuedRequest
    constructor
    · intro member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after] using
        memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
            (.appendEntriesRequest queuedRequest)
            queuedDestination member
  have appendResponseEq :
      forall queuedDestination queuedResponse,
        Message.appendEntriesResponse queuedResponse ∈
            after.network queuedDestination ↔
          Message.appendEntriesResponse queuedResponse ∈
            state.network queuedDestination := by
    intro queuedDestination queuedResponse
    constructor
    · intro member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.appendEntriesResponse queuedResponse) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after] using
        memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
            (.appendEntriesResponse queuedResponse)
            queuedDestination member
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact
        ⟨queuedResponse,
          (appendResponseEq leader queuedResponse).mp member,
          success, by simpa [termEq] using responseTerm,
          responseSource, responseDestination, lastIndex,
          by simpa [logEq] using covered⟩
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact
        ⟨queuedResponse,
          (appendResponseEq leader queuedResponse).mpr member,
          success, by simpa [termEq] using responseTerm,
          responseSource, responseDestination, lastIndex,
          by simpa [logEq] using covered⟩
  have oldEffectiveSubset :
      forall candidate,
        effectiveElectionVoters state candidate ⊆
          effectiveElectionVoters after candidate := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at member ⊢
    rcases member with processed | queued
    · exact Or.inl (by simpa [votesGrantedEq] using processed)
    · right
      rcases queued with
        ⟨queuedResponse, queuedMember, queuedGranted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨queuedResponse,
          by simpa [after] using
            memEnqueueNoDupOfMem
              state.network (.requestVoteResponse response)
                (.requestVoteResponse queuedResponse)
                candidate queuedMember,
          queuedGranted, by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
  have newEffectiveClassify :
      forall candidate voter,
        voter ∈ effectiveElectionVoters after candidate ->
          voter ∈ effectiveElectionVoters state candidate \/
            (candidate = request.source /\
              voter = destination /\
              (state.nodes candidate).currentTerm = request.term) := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ] at member
    rcases member with processed | queued
    · left
      simp only [
        effectiveElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      exact Or.inl (by simpa [votesGrantedEq] using processed)
    · rcases queued with
        ⟨queuedResponse, queuedMember, queuedGranted, responseTerm,
          responseSource, responseDestination⟩
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) candidate
              (by simpa [after] using queuedMember) with
        old | new
      · left
        simp only [
          effectiveElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ]
        exact Or.inr
          ⟨queuedResponse, old, queuedGranted,
            by simpa [termEq] using responseTerm,
            responseSource, responseDestination⟩
      · simp only [Message.requestVoteResponse.injEq] at new
        have sameResponse : queuedResponse = response := new.2
        subst queuedResponse
        right
        have candidateEq :
            candidate = request.source := by
          exact new.1.trans post.responseDestination
        have voterEq : voter = destination := by
          simpa [post.responseSource, requestDestination] using
            responseSource.symm
        exact
          ⟨candidateEq, voterEq,
            by
              rw [candidateEq]
              have candidateResponse :
                  response.term =
                    (state.nodes request.source).currentTerm := by
                simpa [termEq, candidateEq] using responseTerm
              exact
                candidateResponse.symm.trans
                  (post.responseTerm.trans grantFacts.1.symm)⟩
  have effectiveSubsetPotential :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
        effectiveElectionVoters after candidate ⊆
          potentialElectionVoters state candidate := by
    intro candidate candidateRole voter member
    rcases newEffectiveClassify candidate voter member with old | new
    · exact
        effectiveElectionVotersSubsetPotential
          state candidate old
    · rcases new with ⟨candidateEq, voterEq, candidateTerm⟩
      subst candidate
      subst voter
      simp only [
        potentialElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ]
      right
      unfold currentlyEligibleElectionVoter
      have sourceRole :
          (state.nodes request.source).role = .candidate := by
        simpa [roleEq] using candidateRole
      have sourceCurrent :
          request.term =
            (state.nodes request.source).currentTerm :=
        candidateTerm.symm
      have candidatePrefix :
          voteRequestHistory request <+:
            (state.nodes request.source).log :=
        requestFacts.2.2.2.2.2
          sourceCurrent (Or.inl sourceRole)
      have canonicalUpToDate :
          voteLogUpToDate
            (state.nodes destination)
            (makeRequestVoteRequest
              state request.source destination) := by
        simpa [
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes request.source)
            (facts.committedFrontierIsSignature request.source),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes request.source)
            (facts.committedFrontierIsSignature request.source),
          sourceCurrent, grantFacts.1
        ] using
          (voteLogUpToDateOfCandidatePrefix
            (state.nodes destination) request.source destination
              candidatePrefix
              (monoLog request.source)
              (by simpa [
                voteLogUpToDate, maxCommittableTerm,
                requestFacts.1, requestFacts.2.1,
                requestFacts.2.2.1
              ] using grantFacts.2.1))
      exact
        ⟨by simpa [makeRequestVoteRequest] using
            sourceCurrent.symm.trans grantFacts.1,
          canonicalUpToDate,
          grantFacts.2.2.1⟩
  have potentialMajorityBack :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
        hasEffectiveElectionMajority after candidate ->
          hasPotentialElectionMajority state candidate := by
    intro candidate role majority
    have cardBound :=
      Finset.card_le_card (effectiveSubsetPotential candidate role)
    unfold hasEffectiveElectionMajority at majority
    unfold hasPotentialElectionMajority
    omega
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt after responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    simp only [hasEffectiveMajorityAt, effectiveAckersEq]
  have votesPreserved :
      forall term record voter,
        elections term = some record ->
        voter ∈ record.quorum ->
          newVotes voter term = votes voter term := by
    intro term record voter recorded member
    by_cases voterEq : voter = destination
    · subst voter
      by_cases termEqRequest : term = request.term
      · subst term
        have oldVote :=
          electionFacts.voted
            request.term record destination recorded member
        have currentVote :=
          facts.voteHistory.current destination
        rw [← grantFacts.1] at currentVote
        rcases grantFacts.2.2.1 with noVote | sameVote
        · rw [currentVote, noVote] at oldVote
          contradiction
        · have candidateEq :
              record.leader = request.source := by
            rw [currentVote, sameVote] at oldVote
            exact (Option.some.inj oldVote).symm
          simpa [
            newVotes, Function.update,
            oldVote, candidateEq
          ]
      · simp [newVotes, Function.update, termEqRequest]
    · simp [newVotes, Function.update, voterEq]
  have newElectionFacts :
      ElectionHistoryFacts
        after newVotes canonicalHistory owners elections :=
    electionHistoryFrame
      state after votes newVotes canonicalHistory canonicalHistory
        owners elections electionFacts votesPreserved
        (fun term => prefixRefl (canonicalHistory term))
        (fun _ canonical => canonical)
  have voteHistoryAfter : VoteHistoryFacts after newVotes := by
    constructor
    · intro voter
      by_cases voterEq : voter = destination
      · subst voter
        have requestAbove : TERM_ONE < request.term :=
          requestFacts.2.2.2.1
        simpa [
          newVotes, Function.update,
          requestAbove.ne
        ] using facts.voteHistory.bootstrapEmpty destination
      · simpa [newVotes, Function.update, voterEq] using
          facts.voteHistory.bootstrapEmpty voter
    · intro voter
      by_cases voterEq : voter = destination
      · subst voter
        simpa [
          newVotes, Function.update,
          termEq, grantFacts.1, votedForDestination
        ]
      · simpa [
          newVotes, Function.update, voterEq,
          termEq, votedForOther voter voterEq
        ] using facts.voteHistory.current voter
    · intro voter term future
      by_cases voterEq : voter = destination
      · subst voter
        have termNe : Not (term = request.term) := by
          intro same
          subst term
          rw [termEq, grantFacts.1] at future
          omega
        simpa [newVotes, Function.update, termNe] using
          facts.voteHistory.future destination term
            (by simpa [termEq] using future)
      · simpa [newVotes, Function.update, voterEq] using
          facts.voteHistory.future voter term
            (by simpa [termEq] using future)
    · intro candidate voter active member
      have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        simpa [roleEq] using active
      have oldMember :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [votesGrantedEq] using member
      have oldCounted :=
        facts.voteHistory.counted
          candidate voter oldActive oldMember
      by_cases voterEq : voter = destination
      · subst voter
        by_cases termEqRequest :
            (state.nodes candidate).currentTerm = request.term
        · have currentVote :=
            facts.voteHistory.current destination
          rw [← grantFacts.1, ← termEqRequest] at currentVote
          rcases grantFacts.2.2.1 with noVote | sameVote
          · rw [currentVote, noVote] at oldCounted
            contradiction
          · have candidateEq : candidate = request.source := by
              rw [currentVote, sameVote] at oldCounted
              exact (Option.some.inj oldCounted).symm
            rw [termEq, termEqRequest, candidateEq]
            simp [newVotes]
        · simpa [
            newVotes, Function.update,
            termEq, termEqRequest
          ] using oldCounted
      · simpa [
          newVotes, Function.update,
          voterEq, termEq
        ] using oldCounted
  have responseTermRequest : response.term = request.term :=
    post.responseTerm.trans grantFacts.1.symm
  have recordedVotePreserved :
      forall voter term candidate,
        votes voter term = some candidate ->
          newVotes voter term = some candidate := by
    intro voter term candidate voted
    by_cases voterEq : voter = destination
    · subst voter
      by_cases termRequest : term = request.term
      · subst term
        have currentVote := facts.voteHistory.current destination
        rw [← grantFacts.1] at currentVote
        rcases grantFacts.2.2.1 with noVote | sameVote
        · rw [currentVote, noVote] at voted
          contradiction
        · have candidateEq : candidate = request.source := by
            rw [currentVote, sameVote] at voted
            exact (Option.some.inj voted).symm
          simp [newVotes, candidateEq]
      · simpa [
          newVotes, Function.update, termRequest
        ] using voted
    · simpa [
        newVotes, Function.update, voterEq
      ] using voted
  have responseTermBound :
      response.term <=
        (after.nodes response.destination).currentTerm := by
    rw [post.responseDestination, termEq]
    exact responseTermRequest.trans_le requestFacts.2.2.2.2.1
  have oldGrantedVotePreserved :
      forall queuedDestination queuedResponse,
        Message.requestVoteResponse queuedResponse ∈
            state.network queuedDestination ->
        queuedResponse.voteGranted = true ->
          newVotes queuedResponse.source queuedResponse.term =
            some queuedResponse.destination := by
    intro queuedDestination queuedResponse member queuedGranted
    rcases
        facts.networkHistory.voteResponse
          queuedDestination queuedResponse member queuedGranted with
      ⟨_, voted, _⟩
    by_cases sourceEq : queuedResponse.source = destination
    · by_cases termRequest : queuedResponse.term = request.term
      · have currentVote := facts.voteHistory.current destination
        have relevantCurrent :
            votes queuedResponse.source queuedResponse.term =
              (state.nodes destination).votedFor := by
          simpa [sourceEq, termRequest, grantFacts.1] using currentVote
        rcases grantFacts.2.2.1 with noVote | sameVote
        · rw [relevantCurrent, noVote] at voted
          contradiction
        · have candidateEq :
              queuedResponse.destination = request.source := by
            rw [relevantCurrent, sameVote] at voted
            exact (Option.some.inj voted).symm
          simp [
            newVotes, Function.update,
            sourceEq, termRequest, candidateEq
          ]
      · simpa [
          newVotes, Function.update,
          sourceEq, termRequest
        ] using voted
    · simpa [
        newVotes, Function.update, sourceEq
      ] using voted
  change SystemInductiveInvariant after
  refine
    ⟨newVotes, appendHistory, responseHistory,
      voteRequestHistory, newCandidateHistory, newVoterHistory, ?_⟩
  constructor
  · intro node
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node positive
    rw [commitEq, logEq]
    apply facts.committedFrontierIsSignature node
    simpa [commitEq] using positive
  · intro node
    rw [termEq]
    exact facts.currentTermsPositive node
  · intro node entry member
    rw [termEq]
    apply
      facts.entriesDoNotExceedCurrentTerm node entry
    simpa [logEq] using member
  · intro candidate role
    have oldRole : (state.nodes candidate).role = .candidate := by
      simpa [roleEq] using role
    have old := facts.candidatesSelfVote candidate oldRole
    exact
      ⟨by
          by_cases same : candidate = destination
          · subst candidate
            have candidateVote :
                (state.nodes destination).votedFor = some destination :=
              old.1
            rcases grantFacts.2.2.1 with noVote | sameVote
            · rw [candidateVote] at noVote
              contradiction
            · rw [candidateVote] at sameVote
              have sourceEq :
                  request.source = destination :=
                Option.some.inj sameVote.symm
              simpa [votedForDestination, sourceEq]
          · simpa [votedForOther candidate same] using old.1,
        by simpa [votesGrantedEq] using old.2⟩
  · intro leader role
    rcases
        facts.leadersHaveElectionMajority leader
          (by simpa [roleEq] using role) with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [hasElectionMajority, votesGrantedEq] using majority)
  · intro leader role peer
    simpa [sentEq, matchEq, logEq] using
      facts.leaderProgressBounded leader
        (by simpa [roleEq] using role) peer
  · exact voteHistoryAfter
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              message queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.networkHistory.addressed
            queuedDestination message old
      · exact
          (congrArg Message.destination new.2).trans new.1.symm
    · intro queuedDestination queuedRequest member
      have old :=
        facts.networkHistory.appendRequest
          queuedDestination queuedRequest
            ((appendRequestEq queuedDestination queuedRequest).mp member)
      refine ⟨old.1, old.2.1, old.2.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      simpa [committedEq] using old.2.2.2
    · intro queuedDestination queuedResponse member
      have old :=
        facts.networkHistory.appendResponse
          queuedDestination queuedResponse
            ((appendResponseEq queuedDestination queuedResponse).mp member)
      intro success
      rcases old success with ⟨bound, termBound, active⟩
      exact
        ⟨bound, by simpa [termEq] using termBound,
          by
            intro sameTerm
            rcases active (by simpa [termEq] using sameTerm) with
              ⟨role, covered⟩
            exact
              ⟨by simpa [roleEq] using role,
                by simpa [logEq] using covered⟩⟩
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.requestVoteRequest queuedRequest) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          (by
            simpa [termEq, roleEq, logEq] using
              (facts.networkHistory.voteRequest
                queuedDestination queuedRequest old))
      · simp at new
    · intro queuedDestination queuedResponse member queuedGranted
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) queuedDestination
              (by simpa [after] using member) with
        old | new
      · rcases
          facts.networkHistory.voteResponse
            queuedDestination queuedResponse old queuedGranted with
          ⟨termBound, voted, candidateCommittable,
            voterCommittable, upToDate⟩
        have keyNeOrEq :
            queuedResponse = response \/
              Not (queuedResponse = response) := Classical.em _
        rcases keyNeOrEq with same | different
        · subst queuedResponse
          exact
            ⟨responseTermBound,
              by simp [newVotes, responseKey, grantedVoteKey],
              by simpa [
                newCandidateHistory, Function.update
              ] using requestFacts.2.2.1,
              by simpa [
                newVoterHistory, Function.update
              ] using voterSnapshotCommittable,
              by simpa [
                newCandidateHistory, newVoterHistory,
                maxCommittableIndexTakeMax,
                maxCommittableTermTakeMax,
                requestFacts.2.2.1,
                requestFacts.1, requestFacts.2.1,
                post.responseTerm, post.responseSource,
                post.responseDestination,
                requestDestination, voteLogUpToDate
              ] using grantFacts.2.1⟩
        · exact
            ⟨by simpa [termEq] using termBound,
              oldGrantedVotePreserved
                queuedDestination queuedResponse old queuedGranted,
              by simpa [
                newCandidateHistory, Function.update, different
              ] using candidateCommittable,
              by simpa [
                newVoterHistory, Function.update, different
              ] using voterCommittable,
              by simpa [
                newCandidateHistory, newVoterHistory,
                Function.update, different, logEq,
                voteLogUpToDate
              ] using upToDate⟩
      · simp only [Message.requestVoteResponse.injEq] at new
        have same : queuedResponse = response := new.2
        subst queuedResponse
        exact
          ⟨responseTermBound,
            by simp [newVotes, responseKey, grantedVoteKey],
            by simpa [
              newCandidateHistory, Function.update
            ] using requestFacts.2.2.1,
            by simpa [
              newVoterHistory, Function.update
            ] using voterSnapshotCommittable,
            by simpa [
              newCandidateHistory, newVoterHistory,
              maxCommittableIndexTakeMax,
              maxCommittableTermTakeMax,
              requestFacts.2.2.1,
              requestFacts.1, requestFacts.2.1,
              post.responseTerm, post.responseSource,
              post.responseDestination,
              requestDestination, voteLogUpToDate
            ] using grantFacts.2.1⟩
  have knownBack :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix := by
    intro evidence supportedPrefix known
    rcases known with nodeKnown | requestKnown
    · left
      rcases nodeKnown with ⟨node, positive, stored, prefixEq⟩
      exact
        ⟨node, by simpa [commitEq] using positive, stored,
          by simpa [committedEq] using prefixEq⟩
    · right
      rcases requestKnown with
        ⟨queuedDestination, queuedRequest, member,
          positive, stored, prefixEq⟩
      exact
        ⟨queuedDestination, queuedRequest,
          (appendRequestEq queuedDestination queuedRequest).mp member,
          positive, stored, prefixEq⟩
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    constructor
    · intro node zero
      exact evidenceFacts.nodeZero node
        (by simpa [commitEq] using zero)
    · intro node positive
      rcases evidenceFacts.nodePositive node
        (by simpa [commitEq] using positive) with
        ⟨evidence, stored, valid, supportedLength, termBound⟩
      exact
        ⟨evidence, stored,
          by simpa [committedEq] using valid,
          by simpa [commitEq] using supportedLength,
          by simpa [termEq] using termBound⟩
    · intro queuedDestination queuedRequest member zero
      exact evidenceFacts.requestZero
        queuedDestination queuedRequest
          ((appendRequestEq queuedDestination queuedRequest).mp member)
          zero
    · intro queuedDestination queuedRequest member positive
      exact evidenceFacts.requestPositive
        queuedDestination queuedRequest
          ((appendRequestEq queuedDestination queuedRequest).mp member)
          positive
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state after appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts knownBack
    · intro member
      simpa [logEq] using prefixRefl (state.nodes member).log
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      left
      exact
        ⟨(appendRequestEq queuedDestination queuedRequest).mp queued,
          rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have oldRole :
          (state.nodes candidate).role = .candidate := by
        simpa [roleEq] using role
      have oldRelaxed :
          member ∈ relaxedElectionVoters state candidate := by
        simp only [
          relaxedElectionVoters, Finset.mem_filter,
          Finset.mem_univ, true_and
        ] at relaxed ⊢
        rcases relaxed with effective | eligible
        · rcases newEffectiveClassify candidate member effective with
            old | new
          · exact Or.inl old
          · rcases new with ⟨candidateEq, memberEq, candidateTerm⟩
            right
            subst candidate
            subst member
            have sourceRole :
                (state.nodes request.source).role = .candidate := oldRole
            have candidatePrefix :
                voteRequestHistory request <+:
                  (state.nodes request.source).log :=
              requestFacts.2.2.2.2.2
                candidateTerm.symm (Or.inl sourceRole)
            have canonicalUpToDate :
                voteLogUpToDate
                  (state.nodes destination)
                  (makeRequestVoteRequest
                    state request.source request.source) := by
              simpa [
                makeRequestVoteRequest,
                lastCommittableIndex_eq_maxCommittableIndex
                  (state.nodes request.source)
                  (facts.committedFrontierIsSignature request.source),
                lastCommittableTerm_eq_maxCommittableTerm
                  (state.nodes request.source)
                  (facts.committedFrontierIsSignature request.source),
                candidateTerm, grantFacts.1
              ] using
                (voteLogUpToDateOfCandidatePrefix
                  (state.nodes destination)
                    request.source request.source
                    candidatePrefix
                    (monoLog request.source)
                    (by simpa [
                      voteLogUpToDate, maxCommittableTerm,
                      requestFacts.1, requestFacts.2.1,
                      requestFacts.2.2.1
                    ] using grantFacts.2.1))
            exact
              ⟨by simpa [candidateTerm, grantFacts.1],
                canonicalUpToDate⟩
        · exact Or.inr (by simpa [
            makeRequestVoteRequest,
            termEq, logEq, lastIndexEq, lastTermEq,
            voteLogUpToDate
          ] using eligible)
      left
      exact
        ⟨oldRole,
          by simpa [termEq] using newer,
          by
            intro entry entryMember
            simpa [termEq] using
              entriesBefore entry (by simpa [logEq] using entryMember),
          oldRelaxed,
          by simpa [logEq] using
            prefixRefl (state.nodes candidate).log⟩
  · refine
      ⟨owners, canonicalHistory, elections,
        nodeEvidence, requestEvidence,
        ?_, newElectionFacts, ?_, ?_, ?_, ?_, ?_,
        evidenceAfter, prospectiveAfter⟩
    · constructor
      · exact ownership.bootstrap
      · intro leader role
        rw [termEq]
        exact ownership.activeLeader leader
          (by simpa [roleEq] using role)
      · intro node index entry found
        rcases ownership.logEntryAgreement node index entry
          (by simpa [logEq] using found) with
          ⟨canonical, agreed⟩
        exact ⟨canonical, by simpa [logEq] using agreed⟩
      · intro queuedDestination queuedRequest member index entry found
        exact
          ownership.queuedHistoryEntryAgreement
            queuedDestination queuedRequest
              ((appendRequestEq queuedDestination queuedRequest).mp member)
              index entry found
      · intro leader role
        rw [termEq]
        simpa [logEq] using
          ownership.activeLeaderHistory leader
            (by simpa [roleEq] using role)
      · exact ownership.canonicalEntryOwner
      · exact ownership.canonicalMonoLog
      · intro term owner owned
        rcases ownership.ownerProgress term owner owned with
          ⟨bound, oldLeader⟩
        exact
          ⟨by simpa [termEq] using bound,
            by
              intro same
              have oldSame :
                  term = (state.nodes owner).currentTerm := by
                simpa [termEq] using same
              simpa [roleEq] using oldLeader oldSame⟩
      · intro queuedDestination queuedRequest member
        exact
          ownership.queuedAppendMetadata
            queuedDestination queuedRequest
              ((appendRequestEq queuedDestination queuedRequest).mp member)
      · intro queuedDestination queuedRequest member sameTerm leaderRole
        simpa [logEq] using
          ownership.queuedActiveSourceHistory
            queuedDestination queuedRequest
              ((appendRequestEq queuedDestination queuedRequest).mp member)
              (by simpa [termEq] using sameTerm)
              (by simpa [roleEq] using leaderRole)
    · intro candidate voter active member
      rw [termEq candidate]
      rcases newEffectiveClassify candidate voter member with old | new
      · rcases voteCanonicalFacts candidate voter
          (by simpa [roleEq] using active) old with
          self | snapshots
        · exact Or.inl self
        · by_cases keyEq :
            grantedVoteKey voter
                (state.nodes candidate).currentTerm candidate =
              response
          · right
            have voterEq :
                voter = destination := by
              exact
                (congrArg RequestVoteResponse.source keyEq).trans
                  (post.responseSource.trans requestDestination)
            have candidateEq :
                candidate = request.source := by
              exact
                (congrArg RequestVoteResponse.destination keyEq).trans
                  post.responseDestination
            have candidateTerm :
                (state.nodes candidate).currentTerm = request.term := by
              exact
                (congrArg RequestVoteResponse.term keyEq).trans
                  responseTermRequest
            subst voter
            subst candidate
            have sourceRole :
                (state.nodes request.source).role = .candidate \/
                  (state.nodes request.source).role = .leader := by
              simpa [roleEq] using active
            have candidatePrefix :
                voteRequestHistory request <+:
                  (state.nodes request.source).log :=
              requestFacts.2.2.2.2.2 candidateTerm.symm sourceRole
            exact
              ⟨by simpa [
                  newCandidateHistory, keyEq
                ] using
                  historyCanonicalOfPrefix
                    (nodeLogCanonical ownership request.source)
                    candidatePrefix,
                by simpa [
                  newCandidateHistory, keyEq
                ] using
                  monoHistoryOfPrefix
                    ((canonicalHistoriesMonoLog ownership) request.source)
                    candidatePrefix,
                by simpa [
                  newVoterHistory, keyEq
                ] using
                  historyCanonicalOfPrefix
                    (nodeLogCanonical ownership destination)
                    (List.take_prefix
                      (maxCommittableIndex
                        (state.nodes destination).log)
                      (state.nodes destination).log),
                by simpa [
                  newVoterHistory, keyEq
                ] using
                  monoHistoryOfPrefix
                    ((canonicalHistoriesMonoLog ownership) destination)
                    (List.take_prefix
                      (maxCommittableIndex
                        (state.nodes destination).log)
                      (state.nodes destination).log)⟩
          · right
            simpa [
              newCandidateHistory, newVoterHistory,
              Function.update, keyEq
            ] using snapshots
      · rcases new with ⟨candidateEq, voterEq, candidateTerm⟩
        subst candidate
        subst voter
        have sourceRole :
            (state.nodes request.source).role = .candidate \/
              (state.nodes request.source).role = .leader := by
          simpa [roleEq] using active
        have candidatePrefix :
            voteRequestHistory request <+:
              (state.nodes request.source).log :=
          requestFacts.2.2.2.2.2 candidateTerm.symm sourceRole
        right
        refine
          ⟨by simpa [
              newCandidateHistory, termEq,
              candidateTerm, responseKey
            ] using
              historyCanonicalOfPrefix
                (nodeLogCanonical ownership request.source)
                candidatePrefix,
            by simpa [
              newCandidateHistory, termEq,
              candidateTerm, responseKey
            ] using
              monoHistoryOfPrefix
                ((canonicalHistoriesMonoLog ownership) request.source)
                candidatePrefix,
            ?_, ?_⟩
        · simpa [
            newVoterHistory, termEq,
            candidateTerm, responseKey
          ] using
            historyCanonicalOfPrefix
              (nodeLogCanonical ownership destination)
              (List.take_prefix
                (maxCommittableIndex (state.nodes destination).log)
                (state.nodes destination).log)
        · simpa [
            newVoterHistory, termEq,
            candidateTerm, responseKey
          ] using
            monoHistoryOfPrefix
              ((canonicalHistoriesMonoLog ownership) destination)
              (List.take_prefix
                (maxCommittableIndex (state.nodes destination).log)
                (state.nodes destination).log)
    · intro sourceNode index role current signature voter effective
      rcases
          ackerCurrentFacts sourceNode index
            (by simpa [roleEq] using role)
            (by simpa [logEq, termEq] using current)
            (by simpa [logEq] using signature)
            voter
            (by rw [effectiveAckersEq] at effective; exact effective) with
        retained | bad
      · exact Or.inl (by simpa [logEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [termEq] using above,
            by simpa [termEq] using bounded,
            recorded,
            by simpa [logEq] using missing⟩
    · simpa [newVoterHistory, responseKey] using
        ackerVoteHistoryAfterGrantedRequest
          state after votes responseHistory voteVoterHistory
            elections destination request
            ackerCurrentFacts ackerVoteFacts grantFacts.1
            roleEq termEq logEq effectiveAckersEq
    · intro sourceNode index role current signature term record voter recorded member
        effective newer
      rcases
          ackerElectionFacts sourceNode index
            (by simpa [roleEq] using role)
            (by simpa [logEq, termEq] using current)
            (by simpa [logEq] using signature)
            term record voter recorded member
            (by rw [effectiveAckersEq] at effective; exact effective)
            (by simpa [termEq] using newer) with
        retained | bad
      · exact Or.inl (by simpa [logEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
        exact
          ⟨badTerm, badRecord,
            by simpa [termEq] using above,
            below, badRecorded,
            by simpa [logEq] using missing⟩
    · intro queuedDestination queuedRequest member record recorded
      exact
        electionQueuedFacts queuedDestination queuedRequest
          ((appendRequestEq queuedDestination queuedRequest).mp member)
          record recorded
  · intro candidate voter active member
    rw [termEq candidate]
    rcases newEffectiveClassify candidate voter member with old | new
    · rcases
        facts.grantedVoteSnapshots candidate voter
          (by simpa [roleEq] using active) old with
        ⟨voted, self | snapshot⟩
      · exact
          ⟨recordedVotePreserved
              voter (state.nodes candidate).currentTerm candidate voted,
            Or.inl self⟩
      · have keyNeOrEq :
            grantedVoteKey voter
                (state.nodes candidate).currentTerm candidate =
              response \/
              Not (
                grantedVoteKey voter
                    (state.nodes candidate).currentTerm candidate =
                  response) := Classical.em _
        rcases keyNeOrEq with keyEq | keyNe
        · have voterEq :
              voter = destination := by
            exact
              (congrArg RequestVoteResponse.source keyEq).trans
                (post.responseSource.trans requestDestination)
          have candidateEq :
              candidate = request.source := by
            exact
              (congrArg RequestVoteResponse.destination keyEq).trans
                post.responseDestination
          have candidateTerm :
              (state.nodes candidate).currentTerm = request.term := by
            exact
              (congrArg RequestVoteResponse.term keyEq).trans
                responseTermRequest
          have sourceRole :
              (state.nodes request.source).role = .candidate \/
                (state.nodes request.source).role = .leader := by
            simpa [candidateEq, roleEq] using active
          have candidatePrefix :
              voteRequestHistory request <+:
                (state.nodes request.source).log :=
            requestFacts.2.2.2.2.2
              (by simpa [candidateEq] using candidateTerm.symm)
              sourceRole
          have candidateHistoryEq :
              newCandidateHistory
                  (grantedVoteKey voter
                    (state.nodes candidate).currentTerm candidate) =
                voteRequestHistory request := by
            simp [newCandidateHistory, keyEq]
          have voterHistoryEq :
              newVoterHistory
                  (grantedVoteKey voter
                    (state.nodes candidate).currentTerm candidate) =
                (state.nodes destination).log.take
                  (maxCommittableIndex
                    (state.nodes destination).log) := by
            simp [newVoterHistory, keyEq]
          exact
            ⟨recordedVotePreserved
                voter (state.nodes candidate).currentTerm candidate voted,
              Or.inr
                ⟨by
                    rw [candidateHistoryEq]
                    simpa [candidateEq, logEq] using candidatePrefix,
                  by simpa [candidateHistoryEq] using
                    requestFacts.2.2.1,
                  by simpa [voterHistoryEq] using
                    voterSnapshotCommittable,
                  by
                    simp [
                      grantedVoteKey,
                      voterEq, termEq,
                      candidateTerm, grantFacts.1
                    ],
                  by
                    rw [candidateHistoryEq, voterHistoryEq]
                    simpa [
                      maxCommittableIndexTakeMax,
                      maxCommittableTermTakeMax,
                      requestFacts.2.2.1,
                      candidateEq, voterEq,
                      requestFacts.1, requestFacts.2.1,
                      voteLogUpToDate
                    ] using grantFacts.2.1⟩⟩
        · exact
            ⟨recordedVotePreserved
                voter (state.nodes candidate).currentTerm candidate voted,
              Or.inr
                ⟨by simpa [
                    newCandidateHistory, keyNe,
                    logEq
                  ] using snapshot.1,
                  by simpa [
                    newCandidateHistory, keyNe
                  ] using snapshot.2.1,
                  by simpa [
                    newVoterHistory, keyNe
                  ] using snapshot.2.2.1,
                  by simpa [termEq] using snapshot.2.2.2.1,
                  by simpa [
                    newCandidateHistory, newVoterHistory,
                    keyNe, voteLogUpToDate
                  ] using snapshot.2.2.2.2⟩⟩
    · rcases new with ⟨candidateEq, voterEq, candidateTerm⟩
      subst candidate
      subst voter
      have sourceRole :
          (state.nodes request.source).role = .candidate \/
            (state.nodes request.source).role = .leader := by
        simpa [roleEq] using active
      have candidatePrefix :
          voteRequestHistory request <+:
            (state.nodes request.source).log :=
        requestFacts.2.2.2.2.2 candidateTerm.symm sourceRole
      have keyEq :
          grantedVoteKey destination
              (state.nodes request.source).currentTerm request.source =
            response := by
        simpa [candidateTerm] using responseKey.symm
      have candidateHistoryEq :
          newCandidateHistory
              (grantedVoteKey destination
                (state.nodes request.source).currentTerm request.source) =
            voteRequestHistory request := by
        simp [newCandidateHistory, keyEq]
      have voterHistoryEq :
          newVoterHistory
              (grantedVoteKey destination
                (state.nodes request.source).currentTerm request.source) =
            (state.nodes destination).log.take
              (maxCommittableIndex
                (state.nodes destination).log) := by
        simp [newVoterHistory, keyEq]
      exact
        ⟨by simp [newVotes, candidateTerm],
          Or.inr
            ⟨by
                rw [candidateHistoryEq]
                simpa [logEq] using candidatePrefix,
              by simpa [candidateHistoryEq] using requestFacts.2.2.1,
              by simpa [voterHistoryEq] using voterSnapshotCommittable,
              by
                simp [
                  grantedVoteKey,
                  termEq, candidateTerm, grantFacts.1
                ],
              by
                rw [candidateHistoryEq, voterHistoryEq]
                simpa [
                  maxCommittableIndexTakeMax,
                  maxCommittableTermTakeMax,
                  requestFacts.2.2.1,
                  requestFacts.1, requestFacts.2.1,
                  voteLogUpToDate
                ] using grantFacts.2.1⟩⟩
  · exact
      ⟨ackHistory,
        processedAckHistoryFrame
          state after ackHistory ackFacts
            roleEq termEq logEq
            (fun leader peer => congrFun (matchEq leader) peer)⟩
/-- Receiving an AppendEntries request preserves the full arbitrary-term invariant. -/
theorem receiveAppendEntriesRequestPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (request : AppendEntriesRequest TxId)
    (remaining : List (Message TxId))
    (nextNode : NodeState TxId)
    (response : AppendEntriesResponse)
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining))
    (notStepped :
      returnToFollowerState? (state.nodes destination) request = none)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    SystemInductiveInvariant
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := reply state.network destination remaining response } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafetyEvidence with
    ⟨owners, canonicalHistory, elections, nodeEvidence, requestEvidence,
      ownership, electionFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, ackerElectionFacts,
      electionQueuedFacts, evidenceFacts, prospectiveFacts⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let post := CCFRaft.handleAppendEntriesRequestLocalPost handled
  let after : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network := reply state.network destination remaining response }
  let newResponseHistory :=
    Function.update responseHistory response (appendHistory request)
  let newNodeEvidence :=
    appendRequestNodeEvidence
      state destination request nextNode nodeEvidence requestEvidence
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (takeFirstFromSound taken).2.1
  have requestDestination : request.destination = destination := by
    simpa using
      facts.networkHistory.addressed
        destination (.appendEntriesRequest request) requestMember
  have roleEq :
      forall node,
        (after.nodes node).role = (state.nodes node).role := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.roleUnchanged
    · simp [after, updateNode, Function.update, same]
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.currentTermUnchanged
    · simp [after, updateNode, Function.update, same]
  have votedEq :
      forall node,
        (after.nodes node).votedFor = (state.nodes node).votedFor := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.votedForUnchanged
    · simp [after, updateNode, Function.update, same]
  have votesEq :
      forall node,
        (after.nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.votesGrantedUnchanged
    · simp [after, updateNode, Function.update, same]
  have sentEq :
      forall node,
        (after.nodes node).sentIndex = (state.nodes node).sentIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.sentIndexUnchanged
    · simp [after, updateNode, Function.update, same]
  have matchEq :
      forall node,
        (after.nodes node).matchIndex = (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.matchIndexUnchanged
    · simp [after, updateNode, Function.update, same]
  have activeNodeEq :
      forall node,
        ((after.nodes node).role = .candidate \/
          (after.nodes node).role = .leader) ->
          after.nodes node = state.nodes node := by
    intro node active
    have oldActive :
        (state.nodes node).role = .candidate \/
          (state.nodes node).role = .leader := by
      simpa [roleEq] using active
    by_cases same : node = destination
    · subst node
      have unchanged :=
        handleAppendEntriesRequestActiveUnchanged
          notStepped handled oldActive
      simp [after, updateNode, unchanged]
    · simp [after, updateNode, Function.update, same]
  have committedSignatureAfter :
      CommittedFrontierIsSignature after := by
    intro node positive
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using
        post.commitIndexSignature
          (facts.committedFrontierIsSignature destination)
          (by simpa [after, updateNode] using positive)
    · simpa [after, updateNode, Function.update, same] using
        facts.committedFrontierIsSignature node
          (by simpa [after, updateNode, Function.update, same] using positive)
  have committedMonotone :
      forall node,
        (state.nodes node).committedLog <+:
          (after.nodes node).committedLog := by
    intro node
    by_cases same : node = destination
    · subst node
      rw [show after.nodes destination = nextNode by
        simp [after, updateNode]]
      change
        (state.nodes destination).committedLog <+:
          nextNode.committedLog
      unfold NodeState.committedLog
      rw [List.prefix_take_iff]
      exact
        ⟨post.previousCommittedPrefix,
          by
            simp only [List.length_take]
            calc
              min
                    (state.nodes destination).commitIndex
                    (state.nodes destination).log.length =
                  (state.nodes destination).commitIndex :=
                Nat.min_eq_left
                  (facts.commitIndicesBounded destination)
              _ <= nextNode.commitIndex :=
                post.commitIndexMonotone⟩
    · have unchanged : after.nodes node = state.nodes node := by
        simp [after, updateNode, Function.update, same]
      rw [unchanged]
  have appendRequestBack :
      forall queuedDestination queuedRequest,
        Message.appendEntriesRequest queuedRequest ∈
            after.network queuedDestination ->
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
    intro queuedDestination queuedRequest member
    exact
      appendRequestMemberBeforeReply
        state source destination request response remaining taken
          queuedDestination queuedRequest
          (by simpa [after] using member)
  have voteRequestEq :
      forall queuedDestination queuedRequest,
        Message.requestVoteRequest queuedRequest ∈
            after.network queuedDestination ↔
          Message.requestVoteRequest queuedRequest ∈
            state.network queuedDestination := by
    intro queuedDestination queuedRequest
    simpa [after] using
      voteRequestMemAfterAppendRequestReceive
        state.network source destination request response remaining taken
          queuedDestination queuedRequest
  have voteResponseEq :
      forall queuedDestination queuedResponse,
        Message.requestVoteResponse queuedResponse ∈
            after.network queuedDestination ↔
          Message.requestVoteResponse queuedResponse ∈
            state.network queuedDestination := by
    intro queuedDestination queuedResponse
    simpa [after] using
      voteResponseMemAfterAppendRequestReceive
        state.network source destination request response remaining taken
          queuedDestination queuedResponse
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (processed | queued)
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨queuedResponse,
          (voteResponseEq candidate queuedResponse).mp member,
          granted, by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨queuedResponse,
          (voteResponseEq candidate queuedResponse).mpr member,
          granted, by simpa [termEq] using responseTerm,
          responseSource, responseDestination⟩
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority after candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority, effectiveElectionVotersEq
    ]
  have ownershipAfter :
      TermOwnershipFacts
        after votes appendHistory canonicalHistory owners := by
    constructor
    · exact ownership.bootstrap
    · intro leader role
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      have unchanged := activeNodeEq leader (Or.inr role)
      rw [unchanged]
      exact ownership.activeLeader leader oldRole
    · intro node index entry found
      by_cases same : node = destination
      · subst node
        simpa [after, updateNode] using
          (handledAppendRequestCanonicalAgreement
            state votes appendHistory canonicalHistory owners ownership
              destination request nextNode response requestMember
              (facts.networkHistory.appendRequest
                destination request requestMember).1 handled
              index entry (by simpa [after, updateNode] using found))
      · simpa [after, updateNode, Function.update, same] using
          (ownership.logEntryAgreement node index entry
            (by simpa [after, updateNode, Function.update, same] using found))
    · intro queuedDestination queuedRequest member index entry found
      exact ownership.queuedHistoryEntryAgreement
        queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest member)
          index entry found
    · intro leader role
      have unchanged := activeNodeEq leader (Or.inr role)
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleEq] using role
      rw [unchanged]
      exact ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bounded, leader⟩
      exact
        ⟨by simpa [termEq] using bounded,
          by
            intro current
            have oldCurrent :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using current
            simpa [roleEq] using leader oldCurrent⟩
    · intro queuedDestination queuedRequest member
      exact ownership.queuedAppendMetadata
        queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest member)
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      have oldMember :=
        appendRequestBack queuedDestination queuedRequest member
      have oldRole : (state.nodes queuedRequest.source).role = .leader := by
        simpa [roleEq] using leaderRole
      have unchanged :=
        activeNodeEq queuedRequest.source (Or.inr leaderRole)
      rw [unchanged]
      exact ownership.queuedActiveSourceHistory
        queuedDestination queuedRequest oldMember
          (by simpa [termEq] using sameTerm) oldRole
  have electionFactsAfter :
      ElectionHistoryFacts
        after votes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state after votes votes canonicalHistory canonicalHistory
          owners elections electionFacts
    · intros
      rfl
    · intro term
      exact prefixRefl _
    · intro history canonical
      exact canonical
  have voteCanonicalAfter :
      GrantedVoteCanonicalSnapshots
        after canonicalHistory voteCandidateHistory voteVoterHistory := by
    apply
      grantedVoteCanonicalFrame
        state after canonicalHistory canonicalHistory
          voteCandidateHistory voteVoterHistory voteCanonicalFacts
    · intro candidate active
      exact termEq candidate
    · intro candidate active
      simpa [roleEq] using active
    · intro candidate voter active member
      rw [effectiveElectionVotersEq] at member
      exact member
    · intro history canonical
      exact canonical
  have temporalFacts :=
    appendRequestAckerTemporalFacts
      state source destination request nextNode response remaining
        votes appendHistory responseHistory voteVoterHistory
        canonicalHistory owners elections
        facts.currentTermsPositive facts.entriesDoNotExceedCurrentTerm
        facts.voteHistory ownership electionFacts electionQueuedFacts
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        requestDestination
        (facts.networkHistory.appendRequest
          destination request requestMember).1
        notStepped taken handled
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory newNodeEvidence requestEvidence := by
    apply
      receiveAppendRequestCommitEvidenceFacts
        state source destination request nextNode response remaining
          votes appendHistory canonicalHistory owners ownership
          nodeEvidence requestEvidence evidenceFacts
          (facts.networkHistory.appendRequest
            destination request requestMember).1
          facts.commitIndicesBounded taken handled
  have knownInherited :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          Exists fun oldEvidence =>
            Exists fun oldPrefix =>
              KnownCommitEvidence
                  state appendHistory nodeEvidence requestEvidence
                    oldEvidence oldPrefix /\
                evidence.commitTerm = oldEvidence.commitTerm /\
                evidence.history = oldEvidence.history /\
                evidence.commitFrontier = oldEvidence.commitFrontier /\
                evidence.ackQuorum = oldEvidence.ackQuorum := by
    intro evidence supportedPrefix known
    exact
      receiveAppendRequestKnownEvidenceInherited
        state source destination request nextNode response remaining
          appendHistory nodeEvidence requestEvidence
          facts.commitIndicesBounded taken handled known
  have termPositiveAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          TERM_ONE <= evidence.commitTerm := by
    intro evidence supportedPrefix known
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown, termSame, _, _, _⟩
    rw [termSame]
    exact prospectiveFacts.commitTermPositive
      oldEvidence oldPrefix oldKnown
  have electionClosureAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          forall term record,
            elections term = some record ->
            evidence.commitTerm < term ->
              evidence.history.take evidence.commitFrontier <+:
                record.promotionLog := by
    intro evidence supportedPrefix known term record recorded newer
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown,
        termSame, historySame, frontierSame, _⟩
    simpa [termSame, historySame, frontierSame] using
      prospectiveFacts.electionClosure
        oldEvidence oldPrefix oldKnown term record recorded
          (by simpa [termSame] using newer)
  have currentMemberAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          forall member,
            member ∈ evidence.ackQuorum ->
              evidence.history.take evidence.commitFrontier <+:
                (after.nodes member).log := by
    intro evidence supportedPrefix known member ackMember
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown,
        _, historySame, frontierSame, quorumSame⟩
    have oldAck : member ∈ oldEvidence.ackQuorum := by
      simpa [quorumSame] using ackMember
    by_cases same : member = destination
    · subst member
      have retained :=
        handledAppendRequestRetainsEvidenceFrontier
          state destination request nextNode response
            votes appendHistory canonicalHistory owners ownership
            electionFacts electionQueuedFacts
            facts.entriesDoNotExceedCurrentTerm
            nodeEvidence requestEvidence evidenceFacts prospectiveFacts
            oldKnown oldAck requestMember
            (facts.networkHistory.appendRequest
              destination request requestMember).1 handled
      simpa [after, updateNode, historySame, frontierSame] using retained
    · have old :=
        prospectiveFacts.currentMember
          oldEvidence oldPrefix oldKnown member oldAck
      simpa [
        after, updateNode, Function.update, same,
        historySame, frontierSame
      ] using old
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        after appendHistory newNodeEvidence requestEvidence elections := by
    constructor
    · exact termPositiveAfter
    · exact electionClosureAfter
    · exact currentMemberAfter
    · intro evidence supportedPrefix known
        queuedDestination queuedRequest queued sameTerm
      rcases knownInherited evidence supportedPrefix known with
        ⟨oldEvidence, oldPrefix, oldKnown,
          termSame, historySame, frontierSame, _⟩
      simpa [historySame, frontierSame] using
        prospectiveFacts.sameTermQueuedComparable
          oldEvidence oldPrefix oldKnown
            queuedDestination queuedRequest
            (appendRequestBack queuedDestination queuedRequest queued)
            (by simpa [termSame] using sameTerm)
    · intro evidence supportedPrefix known candidate member role newer
        entriesBefore ackMember relaxed
      rcases knownInherited evidence supportedPrefix known with
        ⟨oldEvidence, oldPrefix, oldKnown,
          termSame, historySame, frontierSame, quorumSame⟩
      have candidateUnchanged := activeNodeEq candidate (Or.inl role)
      have oldRole : (state.nodes candidate).role = .candidate := by
        simpa [roleEq] using role
      have oldNewer :
          oldEvidence.commitTerm <
            (state.nodes candidate).currentTerm := by
        simpa [termSame, termEq] using newer
      have oldEntriesBefore :
          forall entry,
            entry ∈ (state.nodes candidate).log ->
              entry.term < (state.nodes candidate).currentTerm := by
        intro entry member
        simpa [candidateUnchanged] using
          entriesBefore entry (by simpa [candidateUnchanged] using member)
      have oldAck : member ∈ oldEvidence.ackQuorum := by
        simpa [quorumSame] using ackMember
      simp only [
        relaxedElectionVoters, Finset.mem_filter,
        Finset.mem_univ, true_and
      ] at relaxed
      rcases relaxed with effective | supporter
      · have oldRelaxed :
            member ∈ relaxedElectionVoters state candidate := by
          simp only [
            relaxedElectionVoters, Finset.mem_filter,
            Finset.mem_univ, true_and
          ]
          exact Or.inl
            (by rw [effectiveElectionVotersEq] at effective; exact effective)
        simpa [candidateUnchanged, historySame, frontierSame] using
          prospectiveFacts.relaxedSupporterCarriesFrontier
            oldEvidence oldPrefix oldKnown candidate member
              oldRole oldNewer oldEntriesBefore oldAck oldRelaxed
      · by_cases memberEq : member = destination
        · subst member
          have future :
              destination ∈
                futureElectionVoters
                  after candidate (after.nodes candidate).currentTerm := by
            simp only [
              futureElectionVoters, Finset.mem_filter,
              Finset.mem_univ, true_and
            ]
            exact Or.inr supporter
          exact
            prospectiveCommitFutureMemberCore
              ownershipAfter committedSignatureAfter
                electionFactsAfter evidenceAfter
                termPositiveAfter electionClosureAfter currentMemberAfter
                known ackMember future
        · have oldRelaxed :
              member ∈ relaxedElectionVoters state candidate := by
            simp only [
              relaxedElectionVoters, Finset.mem_filter,
              Finset.mem_univ, true_and
            ]
            right
            have memberUnchanged :
                after.nodes member = state.nodes member := by
              simp [after, updateNode, Function.update, memberEq]
            simp only [makeRequestVoteRequest] at supporter ⊢
            rw [memberUnchanged, candidateUnchanged] at supporter
            exact supporter
          simpa [candidateUnchanged, historySame, frontierSame] using
            prospectiveFacts.relaxedSupporterCarriesFrontier
              oldEvidence oldPrefix oldKnown candidate member
                oldRole oldNewer oldEntriesBefore oldAck oldRelaxed
  have quorumAfter : QuorumLog after := by
    intro node quorum majority
    by_cases empty : (after.nodes node).commitIndex = 0
    · have nonempty : 0 < quorum.card := by
        have countPositive : 0 < NODE_COUNT := by simp [NODE_COUNT]
        omega
      rcases Finset.card_pos.mp nonempty with ⟨witness, member⟩
      exact
        ⟨witness, member,
          by simp [NodeState.committedLog, empty]⟩
    · have positive : 0 < (after.nodes node).commitIndex := by omega
      rcases evidenceAfter.nodePositive node positive with
        ⟨evidence, stored, valid, supportedLength, _⟩
      have known :
          KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence (after.nodes node).committedLog :=
        Or.inl ⟨node, positive, stored, rfl⟩
      rcases
          majoritiesIntersect evidence.ackQuorum quorum
            valid.2.2.2.2.1 majority with
        ⟨witness, member⟩
      have parts :
          witness ∈ evidence.ackQuorum /\ witness ∈ quorum := by
        simpa using member
      exact
        ⟨witness, parts.2,
          (validEvidenceSupportedPrefixFrontier valid).trans
            (currentMemberAfter
              evidence (after.nodes node).committedLog known
                witness parts.1)⟩
  have snapshotsAfter :
      GrantedVoteSnapshots
        after votes voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    have unchanged := activeNodeEq candidate active
    have oldActive :
        (state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader := by
      simpa [roleEq] using active
    have oldMember : voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [unchanged, termEq] using
      facts.grantedVoteSnapshots candidate voter oldActive oldMember
  have entriesBoundedAfter : EntriesDoNotExceedCurrentTerm after := by
    intro node entry member
    by_cases same : node = destination
    · subst node
      by_cases succeeded : response.success = true
      · rcases post.logShape with unchanged | truncated | extended
        · exact
            (by
              have oldMember :
                  entry ∈ (state.nodes destination).log := by
                simpa [after, updateNode, unchanged] using member
              simpa [termEq] using
                facts.entriesDoNotExceedCurrentTerm
                  destination entry oldMember)
        · have oldMember :
              entry ∈ (state.nodes destination).log := by
            exact
              CCFRaft.memOfPrefix
                (List.take_prefix request.prevLogIndex _)
                (by simpa [after, updateNode, truncated] using member)
          simpa [termEq] using
            facts.entriesDoNotExceedCurrentTerm
              destination entry oldMember
        · have nextMember :
              entry ∈
                (state.nodes destination).log.take request.prevLogIndex ++
                  request.entries := by
            simpa [after, updateNode, extended] using member
          rcases List.mem_append.mp nextMember with old | learned
          · have oldMember :
                entry ∈ (state.nodes destination).log :=
              CCFRaft.memOfPrefix
                (List.take_prefix request.prevLogIndex _) old
            simpa [termEq] using
              facts.entriesDoNotExceedCurrentTerm
                destination entry oldMember
          · have historyMember : entry ∈ appendHistory request := by
              exact
                CCFRaft.memOfPrefix
                  (List.take_prefix
                    (request.prevLogIndex + request.entries.length) _)
                  (by
                    rw [
                      (facts.networkHistory.appendRequest
                        destination request requestMember).1.2.2
                    ]
                    exact List.mem_append_right _ learned)
            have bounded :=
              (ownership.queuedAppendMetadata
                destination request requestMember).2
                entry historyMember
            simpa [
              termEq, post.successfulCurrentTerm succeeded
            ] using bounded
      · have failed : response.success = false :=
          Bool.eq_false_of_not_eq_true succeeded
        have unchanged := post.failedStateUnchanged failed
        simpa [after, updateNode, unchanged, termEq] using
          facts.entriesDoNotExceedCurrentTerm
            destination entry
              (by simpa [after, updateNode, unchanged] using member)
    · simpa [after, updateNode, Function.update, same, termEq] using
        facts.entriesDoNotExceedCurrentTerm node entry
          (by simpa [after, updateNode, Function.update, same] using member)
  have processedAckAfter :
      ProcessedAckHistoryFacts after ackHistory := by
    constructor
    · intro leader role peer zero
      have unchanged := activeNodeEq leader (Or.inr role)
      exact ackFacts.zero leader
        (by simpa [roleEq] using role)
        peer (by simpa [unchanged] using zero)
    · intro leader role peer positive
      have unchanged := activeNodeEq leader (Or.inr role)
      rcases
          ackFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [unchanged] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact
        ⟨snapshot, stored,
          by simpa [unchanged] using snapshotTerm,
          by simpa [unchanged] using snapshotIndex,
          historyBound, by simpa [unchanged] using agreed⟩
  refine
    ⟨votes, appendHistory, newResponseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, ?_⟩
  constructor
  · intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using
        post.commitIndexBounded (facts.commitIndicesBounded destination)
    · simpa [after, updateNode, Function.update, same] using
        facts.commitIndicesBounded node
  · exact committedSignatureAfter
  · intro node
    rw [termEq]
    exact facts.currentTermsPositive node
  · exact entriesBoundedAfter
  · intro candidate role
    have unchanged := activeNodeEq candidate (Or.inl role)
    have oldRole : (state.nodes candidate).role = .candidate := by
      rw [roleEq] at role
      exact role
    rw [unchanged]
    exact facts.candidatesSelfVote candidate oldRole
  · intro leader role
    have unchanged := activeNodeEq leader (Or.inr role)
    have oldRole : (state.nodes leader).role = .leader := by
      rw [roleEq] at role
      exact role
    rcases facts.leadersHaveElectionMajority leader oldRole with
      bootstrap | majority
    · left
      exact
        ⟨bootstrap.1, by rw [termEq]; exact bootstrap.2⟩
    · right
      unfold hasElectionMajority at majority ⊢
      rw [votesEq]
      exact majority
  · intro leader role peer
    have unchanged := activeNodeEq leader (Or.inr role)
    have oldRole : (state.nodes leader).role = .leader := by
      rw [roleEq] at role
      exact role
    rw [unchanged]
    exact facts.leaderProgressBounded leader oldRole peer
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [termEq, votedEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      exact facts.voteHistory.future voter term
        (by rw [termEq] at future; exact future)
    · intro candidate voter active member
      have unchanged := activeNodeEq candidate active
      have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        rw [roleEq] at active
        exact active
      have oldMember :
          voter ∈ (state.nodes candidate).votesGranted := by
        rw [← unchanged]
        exact member
      rw [unchanged]
      exact facts.voteHistory.counted candidate voter oldActive oldMember
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueueNoDup
            (updateQueue state.network destination remaining)
            (.appendEntriesResponse response)
            message queuedDestination
            (by simpa [after, reply] using member) with
        old | new
      · have oldMember : message ∈ state.network queuedDestination := by
          by_cases same : queuedDestination = destination
          · subst queuedDestination
            exact (takeFirstFromSound taken).2.2 message
              (by simpa [updateQueue] using old)
          · simpa [updateQueue, Function.update, same] using old
        exact facts.networkHistory.addressed
          queuedDestination message oldMember
      · rw [new.2]
        exact new.1.symm
    · intro queuedDestination queuedRequest member
      rcases
          facts.networkHistory.appendRequest
            queuedDestination queuedRequest
              (appendRequestBack queuedDestination queuedRequest member) with
        ⟨snapshot, commitBound, emptyBound, present⟩
      exact
        ⟨snapshot, commitBound, emptyBound,
          present.trans (committedMonotone queuedRequest.source)⟩
    · intro queuedDestination queuedResponse member success
      rcases
          appendResponseMemAfterAppendRequestReceive
            state.network source destination request response queuedResponse
              remaining taken queuedDestination
              (by simpa [after] using member) with
        old | produced
      · by_cases same : queuedResponse = response
        · subst queuedResponse
          have responseLength :
              response.lastLogIndex <= (appendHistory request).length := by
            rw [post.successfulIndexExact success]
            exact
              (facts.networkHistory.appendRequest
                destination request requestMember).1.1
          have responseTerm :
              response.term <=
                (after.nodes response.destination).currentTerm := by
            rw [post.responseDestination]
            have owned :=
              (ownership.queuedAppendMetadata
                destination request requestMember).1
            have progressed := (ownership.ownerProgress
              request.term request.source owned).1
            rw [termEq]
            simpa [
              post.successfulResponseTerm success,
              post.successfulCurrentTerm success
            ] using progressed
          refine ⟨by simpa [newResponseHistory] using responseLength,
            responseTerm, ?_⟩
          intro sameTerm
          rw [termEq] at sameTerm
          have requestTerm :
              request.term =
                (state.nodes request.source).currentTerm := by
            simpa [
              post.responseDestination,
              post.successfulResponseTerm success,
              post.successfulCurrentTerm success,
            ] using sameTerm
          have sourceRole :=
            (ownership.ownerProgress request.term request.source
              (ownership.queuedAppendMetadata
                destination request requestMember).1).2 requestTerm
          have unchanged :=
            activeNodeEq request.source
              (Or.inr (by simpa [roleEq] using sourceRole))
          constructor
          · rw [post.responseDestination, unchanged]
            exact sourceRole
          · rw [post.responseDestination, unchanged]
            simpa [newResponseHistory] using
              ownership.queuedActiveSourceHistory
                destination request requestMember requestTerm sourceRole
        · rcases
              facts.networkHistory.appendResponse
                queuedDestination queuedResponse old success with
            ⟨lengthBound, termBound, supported⟩
          exact
            ⟨by simpa [newResponseHistory, Function.update, same] using
                lengthBound,
              by rw [termEq]; exact termBound,
              fun sameTerm => by
                have oldSame := sameTerm
                rw [termEq] at oldSame
                rcases supported oldSame with
                  ⟨role, covered⟩
                have afterRole :
                    (after.nodes queuedResponse.destination).role =
                      .leader := by
                  rw [roleEq]
                  exact role
                have unchanged :=
                  activeNodeEq queuedResponse.destination
                    (Or.inr afterRole)
                constructor
                · rw [unchanged]
                  exact role
                · rw [unchanged]
                  simpa [
                    newResponseHistory, Function.update, same
                  ] using covered⟩
      · rcases produced with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        have responseLength :
            response.lastLogIndex <= (appendHistory request).length := by
          rw [post.successfulIndexExact success]
          exact
            (facts.networkHistory.appendRequest
              destination request requestMember).1.1
        have responseTerm :
            response.term <=
              (after.nodes response.destination).currentTerm := by
          rw [post.responseDestination]
          have progressed :=
            (ownership.ownerProgress request.term request.source
              (ownership.queuedAppendMetadata
                destination request requestMember).1).1
          rw [termEq]
          simpa [
            post.successfulResponseTerm success,
            post.successfulCurrentTerm success
          ] using progressed
        refine
          ⟨by simpa [newResponseHistory] using responseLength,
            responseTerm, ?_⟩
        intro sameTerm
        rw [termEq] at sameTerm
        have requestTerm :
            request.term =
              (state.nodes request.source).currentTerm := by
          simpa [
            post.responseDestination,
            post.successfulResponseTerm success,
            post.successfulCurrentTerm success,
          ] using sameTerm
        have sourceRole :=
          (ownership.ownerProgress request.term request.source
            (ownership.queuedAppendMetadata
              destination request requestMember).1).2 requestTerm
        have unchanged :=
          activeNodeEq request.source
            (Or.inr (by simpa [roleEq] using sourceRole))
        constructor
        · rw [post.responseDestination, unchanged]
          exact sourceRole
        · rw [post.responseDestination, unchanged]
          simpa [newResponseHistory] using
            ownership.queuedActiveSourceHistory
              destination request requestMember requestTerm sourceRole
    · intro queuedDestination queuedRequest member
      rcases
          facts.networkHistory.voteRequest
            queuedDestination queuedRequest
              ((voteRequestEq queuedDestination queuedRequest).mp member) with
        ⟨lastIndex, lastTerm, maxIndex, above, bounded, activePrefix⟩
      exact
        ⟨lastIndex, lastTerm, maxIndex, above,
          by rw [termEq]; exact bounded,
          fun sameTerm active => by
            have unchanged := activeNodeEq queuedRequest.source active
            have oldSame := sameTerm
            rw [termEq] at oldSame
            have oldActive := active
            rw [roleEq] at oldActive
            rw [unchanged]
            exact activePrefix oldSame oldActive⟩
    · intro queuedDestination queuedResponse member granted
      rcases
          facts.networkHistory.voteResponse
            queuedDestination queuedResponse
              ((voteResponseEq queuedDestination queuedResponse).mp member)
              granted with
        ⟨bounded, recorded, candidateCommittable,
          voterCommittable, upToDate⟩
      exact
        ⟨by rw [termEq]; exact bounded,
          recorded, candidateCommittable, voterCommittable,
          by simpa [voteLogUpToDate] using upToDate⟩
  · exact
      ⟨owners, canonicalHistory, elections,
        newNodeEvidence, requestEvidence,
        ownershipAfter, electionFactsAfter, voteCanonicalAfter,
        temporalFacts.1, temporalFacts.2.1, temporalFacts.2.2,
        fun queuedDestination queuedRequest member record recorded =>
          electionQueuedFacts queuedDestination queuedRequest
            (appendRequestBack queuedDestination queuedRequest member)
            record recorded,
        evidenceAfter, prospectiveAfter⟩
  · exact snapshotsAfter
  · exact ⟨ackHistory, processedAckAfter⟩

/-- Receiving a RequestVote request preserves the full arbitrary-term invariant. -/
theorem receiveRequestVoteRequestPreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (request : RequestVoteRequest)
    (remaining : List (Message TxId))
    (nextNode : NodeState TxId)
    (response : RequestVoteResponse)
    (invariant : SystemInductiveInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteRequest request, remaining))
    (handled :
      handleRequestVoteRequest? (state.nodes destination) request =
        some (nextNode, response)) :
    SystemInductiveInvariant
      { state with
        nodes := updateNode state.nodes destination nextNode
        network :=
          enqueueNoDup
            (updateQueue state.network destination remaining)
            (.requestVoteResponse response) } := by
  let post := handleRequestVoteRequestLocalPost handled
  let enqueued : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueueNoDup state.network (.requestVoteResponse response) }
  let after : State TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response) }
  have enqueuedInvariant : SystemInductiveInvariant enqueued := by
    by_cases granted : response.voteGranted = true
    · simpa [enqueued] using
        enqueueGrantedVoteResponsePreservesSystemInductiveInvariant
          state source destination request nextNode response remaining
            invariant taken handled granted
    · have rejected : response.voteGranted = false := by
        exact Bool.eq_false_of_not_eq_true granted
      have nextEq := post.rejectedState rejected
      have nodesEq :
          updateNode state.nodes destination nextNode = state.nodes := by
        rw [nextEq]
        funext node
        by_cases same : node = destination <;>
          simp [updateNode, Function.update, same]
      simpa [enqueued, nodesEq] using
        enqueueRejectedVoteResponsePreservesSystemInductiveInvariant
          state response invariant rejected
  have roleEq :
      forall node,
        (after.nodes node).role = (enqueued.nodes node).role := by
    intro node
    rfl
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (enqueued.nodes node).currentTerm := by
    intro node
    rfl
  have logEq :
      forall node,
        (after.nodes node).log = (enqueued.nodes node).log := by
    intro node
    rfl
  have commitEq :
      forall node,
        (after.nodes node).commitIndex =
          (enqueued.nodes node).commitIndex := by
    intro node
    rfl
  have networkSubset :
      forall queuedDestination message,
        message ∈ after.network queuedDestination ->
          message ∈ enqueued.network queuedDestination := by
    intro queuedDestination message member
    rcases
        memEnqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response)
          message queuedDestination
          (by simpa [after] using member) with
      old | new
    · have oldMember :
          message ∈ state.network queuedDestination := by
        by_cases same : queuedDestination = destination
        · subst queuedDestination
          have retained : message ∈ remaining := by
            simpa [updateQueue] using old
          exact (takeFirstFromSound taken).2.2 message retained
        · simpa [updateQueue, Function.update, same] using old
      simpa [enqueued] using
        memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
            message queuedDestination oldMember
    · rcases new with ⟨destinationEq, messageEq⟩
      subst queuedDestination
      subst message
      simpa [enqueued] using
        memEnqueueNoDupSelf
          state.network (.requestVoteResponse response)
  have voteResponseEq :
      forall queuedDestination queuedResponse,
        Message.requestVoteResponse queuedResponse ∈
            after.network queuedDestination ↔
          Message.requestVoteResponse queuedResponse ∈
            enqueued.network queuedDestination := by
    intro queuedDestination queuedResponse
    constructor
    · intro member
      rcases
          voteResponseMemAfterVoteRequestReceive
            state.network source destination request response
              queuedResponse remaining taken queuedDestination
              (by simpa [after] using member) with
        old | new
      · simpa [enqueued] using
          memEnqueueNoDupOfMem
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse)
              queuedDestination old
      · rcases new with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        simpa [enqueued] using
          memEnqueueNoDupSelf
            state.network (.requestVoteResponse response)
    · intro member
      rcases
          memEnqueueNoDup
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse)
              queuedDestination
              (by simpa [enqueued] using member) with
        old | new
      · simpa [after] using
          oldVoteResponseMemAfterVoteRequestReceive
            state.network source destination request response
              queuedResponse remaining taken queuedDestination old
      · simp only [Message.requestVoteResponse.injEq] at new
        rcases new with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        simpa [after] using
          memEnqueueNoDupSelf
            (updateQueue state.network destination remaining)
            (.requestVoteResponse response)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters enqueued candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (processed | queued)
    · exact Or.inl processed
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨queuedResponse,
          (voteResponseEq candidate queuedResponse).mp member,
          granted, responseTerm, responseSource, responseDestination⟩
    · exact Or.inl processed
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact
        ⟨queuedResponse,
          (voteResponseEq candidate queuedResponse).mpr member,
          granted, responseTerm, responseSource, responseDestination⟩
  have effectiveAckersEq :
      forall
        (responseHistory : AppendEntriesResponse -> List (Entry TxId))
        leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers enqueued responseHistory leader index := by
    intro responseHistory leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter,
      Finset.mem_univ, true_and
    ]
    constructor <;> rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact
        ⟨queuedResponse,
          networkSubset leader (.appendEntriesResponse queuedResponse) member,
          success, responseTerm, responseSource,
          responseDestination, lastIndex, covered⟩
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network leader := by
        rcases
            memEnqueueNoDup
              state.network (.requestVoteResponse response)
                (.appendEntriesResponse queuedResponse)
                leader (by simpa [enqueued] using member) with
          old | new
        · exact old
        · simp at new
      have afterMember :
          Message.appendEntriesResponse queuedResponse ∈
            after.network leader := by
        rw [show
          after.network =
            enqueueNoDup
              (updateQueue state.network destination remaining)
              (.requestVoteResponse response) by rfl]
        exact
          (appendResponseMemAfterVoteRequestReceive
            state.network source destination request response remaining
              taken leader queuedResponse).mpr oldMember
      exact
        ⟨queuedResponse, afterMember, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
  change SystemInductiveInvariant after
  apply
    responseDequeuePreservesSystemInductiveInvariant
      enqueued after enqueuedInvariant roleEq termEq logEq commitEq
  · intro candidate role
    rcases enqueuedInvariant with
      ⟨_, _, _, _, _, _, enqueuedFacts⟩
    exact enqueuedFacts.candidatesSelfVote candidate role
  · intro leader role
    rcases enqueuedInvariant with
      ⟨_, _, _, _, _, _, enqueuedFacts⟩
    exact enqueuedFacts.leadersHaveElectionMajority leader role
  · intro _ _ _ _ _ _ actualFacts
    constructor
    · exact actualFacts.voteHistory.bootstrapEmpty
    · exact actualFacts.voteHistory.current
    · exact actualFacts.voteHistory.future
    · exact actualFacts.voteHistory.counted
  · intro _ _ _ _ _ _ actualFacts
    rcases actualFacts.processedAckHistory with
      ⟨history, historyFacts⟩
    exact
      ⟨history,
        processedAckHistoryFrame
          enqueued after history historyFacts
            roleEq termEq logEq (fun _ _ => rfl)⟩
  · exact networkSubset
  · rcases enqueuedInvariant with
      ⟨_, _, _, _, _, _, enqueuedFacts⟩
    exact enqueuedFacts.leaderProgressBounded
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact effectiveAckersEq actualResponseHistory leader index
  · intro candidate role majority
    unfold hasEffectiveElectionMajority at majority ⊢
    rw [effectiveElectionVotersEq] at majority
    exact majority
  · intro candidate voter active member
    rw [effectiveElectionVotersEq] at member
    exact member

/-- Every successful receive dispatch preserves the full arbitrary-term invariant. -/
theorem handleReceivePreservesSystemInductiveInvariant
    (state resultingState : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (received :
      handleReceive? state source destination = some resultingState) :
    SystemInductiveInvariant resultingState := by
  unfold handleReceive? at received
  split at received
  · contradiction
  · rename_i message remaining taken
    split at received
    · contradiction
    · rename_i destinationMatches
      split at received
      · rename_i request
        split at received
        · rename_i nextNode stepped
          have resultEq := Option.some.inj received
          rw [← resultEq]
          exact
            returnToFollowerPreservesSystemInductiveInvariant
              state destination request nextNode invariant stepped
        · rename_i notStepped
          split at received
          · contradiction
          · rename_i nextNode response handled
            have resultEq := Option.some.inj received
            rw [← resultEq]
            exact
              receiveAppendEntriesRequestPreservesSystemInductiveInvariant
                state source destination request remaining nextNode response
                  invariant taken notStepped handled
      · rename_i response
        split at received
        · contradiction
        · rename_i nextNode handled
          have resultEq := Option.some.inj received
          rw [← resultEq]
          exact
            receiveAppendEntriesResponsePreservesSystemInductiveInvariant
              state source destination response remaining nextNode
                invariant taken (by simpa using destinationMatches) handled
      · rename_i request
        split at received
        · contradiction
        · rename_i nextNode response handled
          have resultEq := Option.some.inj received
          rw [← resultEq]
          exact
            receiveRequestVoteRequestPreservesSystemInductiveInvariant
              state source destination request remaining nextNode response
                invariant taken handled
      · rename_i response
        split at received
        · contradiction
        · rename_i nextNode handled
          have resultEq := Option.some.inj received
          rw [← resultEq]
          exact
            receiveRequestVoteResponsePreservesSystemInductiveInvariant
              state source destination response remaining nextNode
                invariant taken (by simpa using destinationMatches) handled

/-- Processing any enabled queued message preserves the arbitrary-term invariant. -/
theorem receivePreservesSystemInductiveInvariant
    (state : State TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    SystemInductiveInvariant
      (next state (.receive source destination)) := by
  unfold Enabled at enabled
  cases received :
      handleReceive? state source destination with
  | none =>
      simp [received] at enabled
  | some resultingState =>
      have nextEq :
          next state (.receive source destination) =
            resultingState := by
        simp [next, CCFRaft.next, received]
      rw [nextEq]
      exact
        handleReceivePreservesSystemInductiveInvariant
          state resultingState source destination invariant received

/-- Every enabled arbitrary-term action preserves the supporting invariant. -/
theorem systemInductiveInvariantPreserved
    (state : State TxId)
    (action : Action TxId)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state action) :
    SystemInductiveInvariant (next state action) := by
  cases action with
  | clientRequest node txId =>
      exact
        clientRequestPreservesSystemInductiveInvariant
          state node txId invariant enabled
  | signCommittableMessages node =>
      exact
        signCommittableMessagesPreservesSystemInductiveInvariant
          state node invariant enabled
  | appendEntries source destination batchEnd =>
      exact
        appendEntriesPreservesSystemInductiveInvariant
          state source destination batchEnd invariant enabled
  | receive source destination =>
      exact
        receivePreservesSystemInductiveInvariant
          state source destination invariant enabled
  | advanceCommitIndex node =>
      exact
        advanceCommitPreservesSystemInductiveInvariant
          state node invariant enabled
  | timeout node =>
      exact
        timeoutPreservesSystemInductiveInvariant
          state node invariant enabled
  | requestVote source destination =>
      exact
        requestVotePreservesSystemInductiveInvariant
          state source destination invariant enabled
  | updateTerm source destination =>
      exact
        updateTermPreservesSystemInductiveInvariant
          state source destination invariant enabled
  | becomeLeader node =>
      exact
        becomeLeaderPreservesSystemInductiveInvariant
          state node invariant enabled

/-! ## Reachable safety exports -/

/-- The arbitrary-term invariant holds in every reachable state. -/
theorem reachableSystemInductiveInvariant
    {state : State TxId}
    (reachable : Reachable state) :
    SystemInductiveInvariant state :=
  ExecutableTransitionSystem.reachableInvariant
    (system (TxId := TxId))
    initialSystemInductiveInvariant
    systemInductiveInvariantPreserved
    reachable

/-- Reachable committed logs are pairwise prefix-comparable. -/
theorem reachableCommittedLogsPrefix
    {state : State TxId}
    (reachable : Reachable state) :
    CommittedLogsPrefix state :=
  (systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)).committedLogsPrefix

/-- Every positive committed frontier in a reachable state is a signature. -/
theorem reachableCommittedFrontierIsSignature
    {state : State TxId}
    (reachable : Reachable state) :
    CommittedFrontierIsSignature state :=
  systemInductiveInvariantCommittedFrontierIsSignature
    (reachableSystemInductiveInvariant reachable)

/-- Every reachable state satisfies Raft log matching. -/
theorem reachableLogMatching
    {state : State TxId}
    (reachable : Reachable state) :
    LogMatching state :=
  systemInductiveInvariantLogMatching
    (reachableSystemInductiveInvariant reachable)

/-- Entry terms are monotonic within every reachable node log. -/
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
  (systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)).electionSafety

/-- Every higher-term reachable leader contains lower-term committed logs. -/
theorem reachableLeaderCompleteness
    {state : State TxId}
    (reachable : Reachable state) :
    LeaderCompleteness state :=
  systemInductiveInvariantLeaderCompleteness
    (reachableSystemInductiveInvariant reachable)

/-- Bundle the core reachable consensus-safety properties. -/
theorem reachableConsensusSafety
    {state : State TxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)

end CCFRaft
