-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Slice25Properties
import CCFRaft.Proofs

set_option autoImplicit false

/-!
# Slice 2.5 inductive proof

The pre-election cases reuse the slice-two proofs.  Promotion freezes the
winning term-two quorum and introduces two proof-only histories.  The
post-election cases then show that every protocol handler keeps node logs on
one of those histories and keeps every committed prefix inside the unique
term-two leader history.
-/

namespace CCFRaft.Slice25

variable {TxId : Type}
variable [DecidableEq TxId]

/-! ## Request snapshot projections -/

/-- The complete request slice fits in the history it snapshots. -/
theorem requestSnapshotEndBound
    {history : List (Entry TxId)}
    {request : AppendEntriesRequest TxId}
    (snapshot : RequestSnapshots history request) :
    request.prevLogIndex + request.entries.length <= history.length :=
  snapshot.1

/-- The previous index bound follows from the complete slice bound. -/
theorem requestSnapshotPreviousBound
    {history : List (Entry TxId)}
    {request : AppendEntriesRequest TxId}
    (snapshot : RequestSnapshots history request) :
    request.prevLogIndex <= history.length := by
  have endBound := requestSnapshotEndBound snapshot
  omega

/-- The request records the history term at its previous index. -/
theorem requestSnapshotPreviousTerm
    {history : List (Entry TxId)}
    {request : AppendEntriesRequest TxId}
    (snapshot : RequestSnapshots history request) :
    request.prevLogTerm = termAt history request.prevLogIndex :=
  snapshot.2.1

/-- The request entries are exactly the advertised history slice. -/
theorem requestSnapshotEntries
    {history : List (Entry TxId)}
    {request : AppendEntriesRequest TxId}
    (snapshot : RequestSnapshots history request) :
    history.take (request.prevLogIndex + request.entries.length) =
      history.take request.prevLogIndex ++ request.entries :=
  snapshot.2.2

/-- Membership is preserved when moving from a prefix to its containing list. -/
theorem mem_of_prefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {value : Alpha}
    (member : value ∈ left) :
    value ∈ right :=
  CCFRaft.memOfPrefix isPrefix member

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

/-- A list covered by an all-one history contains only term-one entries. -/
theorem coveredByTermOne
    {history log : List (Entry TxId)}
    (terms : EntriesHaveTerm TERM_ONE history)
    (covered : log <+: history) :
    EntriesHaveTerm TERM_ONE log := by
  intro entry member
  exact terms entry (mem_of_prefix covered member)

/-- Entries in the right suffix of `base ++ suffix` are in term two. -/
theorem appendedHistoryTermOneIndexBound
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? (base ++ suffix) index = some entry)
    (termOne : entry.term = TERM_ONE) :
    index <= base.length := by
  have positive : 0 < index := by
    by_contra notPositive
    have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at found
  by_contra notBounded
  have suffixIndex : base.length <= index - 1 := by omega
  unfold entryAt? at found
  simp only [positive.ne', ↓reduceIte] at found
  rw [List.getElem?_append_right suffixIndex] at found
  rw [List.getElem?_eq_some_iff] at found
  rcases found with ⟨within, value⟩
  have member : entry ∈ suffix := by
    rw [← value]
    exact List.getElem_mem within
  have termTwo := suffixTerms entry member
  rw [termOne, TERM_ONE] at termTwo
  omega

/-- An entry at an index inside the inherited base is a term-one entry. -/
theorem appendedHistoryWithinBaseTermOne
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (basePrefix : base <+: oldLog)
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? (base ++ suffix) index = some entry)
    (within : index <= base.length) :
    entry.term = TERM_ONE := by
  have positive : 0 < index := by
    by_contra notPositive
    have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at found
  unfold entryAt? at found
  simp only [positive.ne', ↓reduceIte] at found
  rw [List.getElem?_append_left (by omega)] at found
  rw [List.getElem?_eq_some_iff] at found
  rcases found with ⟨bounded, value⟩
  apply oldTerms entry
  apply mem_of_prefix basePrefix
  rw [← value]
  exact List.getElem_mem bounded

/-- An entry after the inherited base belongs to the term-two suffix. -/
theorem appendedHistoryAfterBaseTermTwo
    {base suffix : List (Entry TxId)}
    (suffixTerms : EntriesHaveTerm 2 suffix)
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? (base ++ suffix) index = some entry)
    (after : base.length < index) :
    entry.term = 2 := by
  have positive : 0 < index := by omega
  unfold entryAt? at found
  simp only [positive.ne', ↓reduceIte] at found
  rw [List.getElem?_append_right (by omega)] at found
  rw [List.getElem?_eq_some_iff] at found
  rcases found with ⟨bounded, value⟩
  apply suffixTerms entry
  rw [← value]
  exact List.getElem_mem bounded

/-- The two proof histories agree through every term-one entry of the new log. -/
theorem oldNewTakeEqualAtTermOne
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    {index : Nat}
    {entry : Entry TxId}
    (found : entryAt? (base ++ suffix) index = some entry)
    (termOne : entry.term = TERM_ONE) :
    oldLog.take index = (base ++ suffix).take index := by
  have within :=
    appendedHistoryTermOneIndexBound
      oldTerms suffixTerms basePrefix found termOne
  calc
    oldLog.take index = base.take index :=
      (CCFRaft.takeEqOfPrefix basePrefix within).symm
    _ = (base ++ suffix).take index := by
      rw [List.take_append_of_le_length within]

/-- Prefixes of the two proof histories satisfy Raft log matching. -/
theorem coveredLogsLogMatching
    {state : State TxId}
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    (covered :
      forall node,
        (state.nodes node).log <+: oldLog \/
          (state.nodes node).log <+: base ++ suffix) :
    LogMatching state := by
  intro left right index leftEntry rightEntry leftFound rightFound sameTerm
  have leftBound := CCFRaft.entryAtSomeIndexBound leftFound
  have rightBound := CCFRaft.entryAtSomeIndexBound rightFound
  rcases covered left with leftOld | leftNew <;>
    rcases covered right with rightOld | rightNew
  · calc
      (state.nodes left).log.take index = oldLog.take index :=
        CCFRaft.takeEqOfPrefix leftOld leftBound
      _ = (state.nodes right).log.take index :=
        (CCFRaft.takeEqOfPrefix rightOld rightBound).symm
  · have leftTerm : leftEntry.term = TERM_ONE :=
      oldTerms leftEntry (mem_of_prefix leftOld (entryAt_mem leftFound))
    have rightTerm : rightEntry.term = TERM_ONE :=
      sameTerm.symm.trans leftTerm
    calc
      (state.nodes left).log.take index = oldLog.take index :=
        CCFRaft.takeEqOfPrefix leftOld leftBound
      _ = (base ++ suffix).take index :=
        oldNewTakeEqualAtTermOne
          oldTerms suffixTerms basePrefix
            (entryAt_of_prefix rightNew rightFound) rightTerm
      _ = (state.nodes right).log.take index :=
        (CCFRaft.takeEqOfPrefix rightNew rightBound).symm
  · have rightTerm : rightEntry.term = TERM_ONE :=
      oldTerms rightEntry (mem_of_prefix rightOld (entryAt_mem rightFound))
    have leftTerm : leftEntry.term = TERM_ONE := sameTerm.trans rightTerm
    calc
      (state.nodes left).log.take index = (base ++ suffix).take index :=
        CCFRaft.takeEqOfPrefix leftNew leftBound
      _ = oldLog.take index :=
        (oldNewTakeEqualAtTermOne
          oldTerms suffixTerms basePrefix
            (entryAt_of_prefix leftNew leftFound) leftTerm).symm
      _ = (state.nodes right).log.take index :=
        (CCFRaft.takeEqOfPrefix rightOld rightBound).symm
  · calc
      (state.nodes left).log.take index = (base ++ suffix).take index :=
        CCFRaft.takeEqOfPrefix leftNew leftBound
      _ = (state.nodes right).log.take index :=
        (CCFRaft.takeEqOfPrefix rightNew rightBound).symm

/-- Two arbitrary prefixes of the proof histories agree through matching entries. -/
theorem coveredHistoriesTakeEqual
    {oldLog base suffix left right : List (Entry TxId)}
    {index : Nat}
    {leftEntry rightEntry : Entry TxId}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    (leftCovered : left <+: oldLog \/ left <+: base ++ suffix)
    (rightCovered : right <+: oldLog \/ right <+: base ++ suffix)
    (leftFound : entryAt? left index = some leftEntry)
    (rightFound : entryAt? right index = some rightEntry)
    (sameTerm : leftEntry.term = rightEntry.term) :
    left.take index = right.take index := by
  have leftBound := CCFRaft.entryAtSomeIndexBound leftFound
  have rightBound := CCFRaft.entryAtSomeIndexBound rightFound
  rcases leftCovered with leftOld | leftNew <;>
    rcases rightCovered with rightOld | rightNew
  · calc
      left.take index = oldLog.take index :=
        CCFRaft.takeEqOfPrefix leftOld leftBound
      _ = right.take index :=
        (CCFRaft.takeEqOfPrefix rightOld rightBound).symm
  · have leftTerm : leftEntry.term = TERM_ONE :=
      oldTerms leftEntry (mem_of_prefix leftOld (entryAt_mem leftFound))
    have rightTerm : rightEntry.term = TERM_ONE :=
      sameTerm.symm.trans leftTerm
    calc
      left.take index = oldLog.take index :=
        CCFRaft.takeEqOfPrefix leftOld leftBound
      _ = (base ++ suffix).take index :=
        oldNewTakeEqualAtTermOne
          oldTerms suffixTerms basePrefix
            (entryAt_of_prefix rightNew rightFound) rightTerm
      _ = right.take index :=
        (CCFRaft.takeEqOfPrefix rightNew rightBound).symm
  · have rightTerm : rightEntry.term = TERM_ONE :=
      oldTerms rightEntry (mem_of_prefix rightOld (entryAt_mem rightFound))
    have leftTerm : leftEntry.term = TERM_ONE := sameTerm.trans rightTerm
    calc
      left.take index = (base ++ suffix).take index :=
        CCFRaft.takeEqOfPrefix leftNew leftBound
      _ = oldLog.take index :=
        (oldNewTakeEqualAtTermOne
          oldTerms suffixTerms basePrefix
            (entryAt_of_prefix leftNew leftFound) leftTerm).symm
      _ = right.take index :=
        (CCFRaft.takeEqOfPrefix rightOld rightBound).symm
  · calc
      left.take index = (base ++ suffix).take index :=
        CCFRaft.takeEqOfPrefix leftNew leftBound
      _ = right.take index :=
        (CCFRaft.takeEqOfPrefix rightNew rightBound).symm

/-- Matching `termAt` values give the same prefix for two covered histories. -/
theorem coveredHistoriesTakeEqualAtTerm
    {oldLog base suffix left right : List (Entry TxId)}
    {index : Nat}
    (positive : 0 < index)
    (leftBound : index <= left.length)
    (rightBound : index <= right.length)
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    (leftCovered : left <+: oldLog \/ left <+: base ++ suffix)
    (rightCovered : right <+: oldLog \/ right <+: base ++ suffix)
    (sameTerm : termAt left index = termAt right index) :
    left.take index = right.take index := by
  let leftEntry := left[index - 1]
  let rightEntry := right[index - 1]
  have leftIndex : index - 1 < left.length := by omega
  have rightIndex : index - 1 < right.length := by omega
  have leftFound :
      entryAt? left index = some leftEntry := by
    simp [entryAt?, positive.ne', leftEntry,
      List.getElem?_eq_getElem leftIndex]
  have rightFound :
      entryAt? right index = some rightEntry := by
    simp [entryAt?, positive.ne', rightEntry,
      List.getElem?_eq_getElem rightIndex]
  apply coveredHistoriesTakeEqual
      oldTerms suffixTerms basePrefix leftCovered rightCovered
      leftFound rightFound
  simpa [termAt, leftFound, rightFound] using sameTerm

/-- Every covered log has a term-one prefix followed by a term-two suffix. -/
theorem coveredLogsMono
    {state : State TxId}
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    (covered :
      forall node,
        (state.nodes node).log <+: oldLog \/
          (state.nodes node).log <+: base ++ suffix) :
    MonoLog state := by
  intro node earlier later earlierEntry laterEntry order earlierFound laterFound
  rcases covered node with oldCovered | newCovered
  · have earlierTerm :=
      oldTerms earlierEntry
        (mem_of_prefix oldCovered (entryAt_mem earlierFound))
    have laterTerm :=
      oldTerms laterEntry
        (mem_of_prefix oldCovered (entryAt_mem laterFound))
    omega
  · have earlierHistoryFound :
        entryAt? (base ++ suffix) earlier = some earlierEntry :=
      entryAt_of_prefix newCovered earlierFound
    have laterHistoryFound :
        entryAt? (base ++ suffix) later = some laterEntry :=
      entryAt_of_prefix newCovered laterFound
    by_cases earlierWithin : earlier <= base.length
    · have earlierTerm :=
        appendedHistoryWithinBaseTermOne
          oldTerms basePrefix earlierHistoryFound earlierWithin
      by_cases laterWithin : later <= base.length
      · have laterTerm :=
          appendedHistoryWithinBaseTermOne
            oldTerms basePrefix laterHistoryFound laterWithin
        omega
      · have laterTerm :=
          appendedHistoryAfterBaseTermTwo
            suffixTerms laterHistoryFound (by omega)
        rw [earlierTerm, laterTerm, TERM_ONE]
        omega
    · have earlierTerm :=
        appendedHistoryAfterBaseTermTwo
          suffixTerms earlierHistoryFound (by omega)
      have laterTerm :=
        appendedHistoryAfterBaseTermTwo
          suffixTerms laterHistoryFound (by omega)
      rw [earlierTerm, laterTerm]

/-! ## Derived cross-term facts -/

/-- The elected leader owns the canonical history in term two. -/
theorem CrossTermFacts.newLeaderOwnsHistory
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix) :
    (state.nodes newLeader).currentTerm = 2 /\
      (state.nodes newLeader).log = base ++ suffix := by
  rcases facts.leadersOwnHistories newLeader facts.newLeaderRole with
    old | new
  · exact False.elim (facts.leadersDistinct old.1.symm)
  · exact new.2

/-- An active term-one leader is node zero and owns the old history. -/
theorem CrossTermFacts.termOneLeaderOwnsHistory
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    {node : Node}
    (role : (state.nodes node).role = .leader)
    (termOne : (state.nodes node).currentTerm = TERM_ONE) :
    node = INITIAL_LEADER /\ (state.nodes node).log = oldLog := by
  rcases facts.leadersOwnHistories node role with old | new
  · exact ⟨old.1, old.2.2⟩
  · have impossible : TERM_ONE = 2 :=
      termOne.symm.trans new.2.1
    simp [TERM_ONE] at impossible

/-- An active term-two leader is the elected leader and owns the canonical history. -/
theorem CrossTermFacts.termTwoLeaderOwnsHistory
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    {node : Node}
    (role : (state.nodes node).role = .leader)
    (termTwo : (state.nodes node).currentTerm = 2) :
    node = newLeader /\ (state.nodes node).log = base ++ suffix := by
  rcases facts.leadersOwnHistories node role with old | new
  · have impossible : TERM_ONE = 2 :=
      old.2.1.symm.trans termTwo
    simp [TERM_ONE] at impossible
  · exact ⟨new.1, new.2.2⟩

/-- Derived compatibility projection for the canonical leader log. -/
theorem CrossTermFacts.newLeaderLog
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix) :
    (state.nodes newLeader).log = base ++ suffix :=
  facts.newLeaderOwnsHistory.2

/-- Derived compatibility projection for the elected leader's term. -/
theorem CrossTermFacts.newLeaderTerm
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix) :
    (state.nodes newLeader).currentTerm = 2 :=
  facts.newLeaderOwnsHistory.1

/-- Derived compatibility projection for the active term-one leader history. -/
theorem CrossTermFacts.oldLeaderOwnsHistory
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (role : (state.nodes INITIAL_LEADER).role = .leader)
    (termOne :
      (state.nodes INITIAL_LEADER).currentTerm = TERM_ONE) :
    (state.nodes INITIAL_LEADER).log = oldLog :=
  (facts.termOneLeaderOwnsHistory role termOne).2

/-- Derived uniqueness of the active term-one leader. -/
theorem CrossTermFacts.termOneLeaderUnique
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (node : Node)
    (role : (state.nodes node).role = .leader)
    (termOne : (state.nodes node).currentTerm = TERM_ONE) :
    node = INITIAL_LEADER :=
  (facts.termOneLeaderOwnsHistory role termOne).1

/-- Derived uniqueness of the active term-two leader. -/
theorem CrossTermFacts.termTwoLeaderUnique
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (node : Node)
    (role : (state.nodes node).role = .leader)
    (termTwo : (state.nodes node).currentTerm = 2) :
    node = newLeader :=
  (facts.termTwoLeaderOwnsHistory role termTwo).1

/-- A frozen election voter still records its choice of the elected leader. -/
theorem CrossTermFacts.electionVoterChoosesLeader
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    {voter : Node}
    (member : voter ∈ (state.nodes newLeader).votesGranted) :
    (state.nodes voter).votedFor = some newLeader :=
  facts.votesGrantedSound newLeader voter member

/-- Election-voter choice is derived from general vote soundness. -/
theorem CrossTermFacts.electionVotersChooseLeader
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (voter : Node)
    (member : voter ∈ (state.nodes newLeader).votesGranted) :
    (state.nodes voter).votedFor = some newLeader :=
  facts.electionVoterChoosesLeader member

/-- The elected leader's send cursor is bounded by the canonical history. -/
theorem CrossTermFacts.newSentIndicesBounded
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (peer : Node) :
    (state.nodes newLeader).sentIndex peer <= (base ++ suffix).length := by
  rw [← facts.newLeaderLog]
  exact
    (facts.leaderProgressBounded
      newLeader facts.newLeaderRole peer).1

/-- The elected leader's match cursor is bounded by the canonical history. -/
theorem CrossTermFacts.newMatchIndicesBounded
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (peer : Node) :
    (state.nodes newLeader).matchIndex peer <= (base ++ suffix).length := by
  rw [← facts.newLeaderLog]
  exact
    (facts.leaderProgressBounded
      newLeader facts.newLeaderRole peer).2

/-- Active leaders have both replication cursors inside their current log. -/
theorem CrossTermFacts.activeLeaderProgress
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    {leader : Node}
    (role : (state.nodes leader).role = .leader)
    (peer : Node) :
    (state.nodes leader).sentIndex peer <=
        (state.nodes leader).log.length /\
      (state.nodes leader).matchIndex peer <=
        (state.nodes leader).log.length :=
  facts.leaderProgressBounded leader role peer

/--
While node zero is still the active term-one leader, any majority it could
commit intersects the frozen election quorum at a voter whose old match index
is inside the inherited base.
-/
theorem activeInitialLeaderMajorityCovered
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix)
    (role : (state.nodes INITIAL_LEADER).role = .leader)
    (termOne :
      (state.nodes INITIAL_LEADER).currentTerm = TERM_ONE)
    {index : Nat}
    (majority : hasMajorityAt state INITIAL_LEADER index) :
    index <= base.length := by
  have intersection :=
    CCFRaft.fiveNodeMajoritiesIntersect
      (acknowledgingNodes state INITIAL_LEADER index)
      (state.nodes newLeader).votesGranted
      majority facts.electionMajority
  rcases intersection with ⟨voter, both⟩
  have acknowledges := (Finset.mem_inter.mp both).1
  have elected := (Finset.mem_inter.mp both).2
  simp only [
    acknowledgingNodes, Finset.mem_filter, Finset.mem_univ, true_and
  ] at acknowledges
  rcases acknowledges with voterLeader | matchCovers
  · subst voter
    have chosen := facts.electionVoterChoosesLeader elected
    have enteredTermTwo :=
      facts.votedForTermTwo INITIAL_LEADER newLeader chosen
    rw [termOne, TERM_ONE] at enteredTermTwo
    omega
  · exact le_trans matchCovers
      (facts.oldElectionMatchBound voter elected)

/-- The leader-history ownership clause directly implies election safety. -/
theorem crossTermElectionSafety
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts : CrossTermFacts state newLeader oldLog base suffix) :
    ElectionSafety state := by
  intro left right leftRole rightRole sameTerm
  rcases facts.leadersOwnHistories left leftRole with leftOld | leftNew <;>
    rcases facts.leadersOwnHistories right rightRole with rightOld | rightNew
  · exact leftOld.1.trans rightOld.1.symm
  · rw [leftOld.2.1, rightNew.2.1, TERM_ONE] at sameTerm
    omega
  · rw [leftNew.2.1, rightOld.2.1, TERM_ONE] at sameTerm
    omega
  · exact leftNew.1.trans rightNew.1.symm

/-- The pre-election invariant implies every requested public property. -/
theorem preElectionSafety
    {state : State TxId}
    (invariant : PreElectionInvariant state) :
    ConsensusSafety state where
  committedLogsPrefix :=
    CCFRaft.systemInductiveInvariantCommittedLogsPrefix invariant.sliceTwo
  electionSafety :=
    CCFRaft.systemInductiveInvariantElectionSafety invariant.sliceTwo

/-- The post-election histories imply every requested public property. -/
theorem crossTermSafety
    {state : State TxId}
    (invariant : CrossTermInvariant state) :
    ConsensusSafety state := by
  rcases invariant with
    ⟨newLeader, oldLog, base, suffix, facts⟩
  constructor
  · intro left right
    exact CCFRaft.prefixesComparable
      (facts.committedLogsCovered left)
      (facts.committedLogsCovered right)
  · exact crossTermElectionSafety facts

/-- The packaged invariant implies Raft log matching. -/
theorem systemInductiveInvariantLogMatching
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    LogMatching state := by
  cases invariant with
  | pre pre =>
      exact CCFRaft.systemInductiveInvariantLogMatching pre.sliceTwo
  | crossTerm cross =>
      rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
      exact coveredLogsLogMatching
        facts.oldEntriesTermOne facts.suffixEntriesTermTwo
        facts.basePrefixOld facts.logsCovered

/-- The packaged invariant implies monotonic terms in each log. -/
theorem systemInductiveInvariantMonoLog
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    MonoLog state := by
  cases invariant with
  | pre pre =>
      exact CCFRaft.systemInductiveInvariantMonoLog pre.sliceTwo
  | crossTerm cross =>
      rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
      exact coveredLogsMono
        facts.oldEntriesTermOne facts.suffixEntriesTermTwo
        facts.basePrefixOld facts.logsCovered

/-- The packaged invariant implies CCF-style term-two leader completeness. -/
theorem systemInductiveInvariantLeaderCompleteness
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    LeaderCompleteness state := by
  cases invariant with
  | pre pre =>
      intro leader role termTwo
      exact False.elim (pre.noTermTwoLeader leader role termTwo)
  | crossTerm cross =>
      rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
      intro leader role termTwo
      have owns := facts.termTwoLeaderOwnsHistory role termTwo
      rw [owns.2]
      exact facts.committedLogsCovered INITIAL_LEADER

/-- The packaged invariant implies the public consensus-safety bundle. -/
theorem systemInductiveInvariantSafety
    {state : State TxId}
    (invariant : SystemInductiveInvariant state) :
    ConsensusSafety state := by
  cases invariant with
  | pre pre => exact preElectionSafety pre
  | crossTerm cross => exact crossTermSafety cross

/-! ## Initial state and pre-election reuse -/

/-- Slice 2.5 uses the same deterministic updates as slice two. -/
theorem next_eq_sliceTwo
    (state : State TxId)
    (action : Action TxId) :
    next state action = CCFRaft.next state action := by
  cases action with
  | clientRequest _ _ => rfl
  | appendEntries _ _ _ => rfl
  | receive _ _ => rfl
  | advanceCommitIndex _ => rfl
  | timeout _ => rfl
  | requestVote _ _ => rfl
  | updateTerm source destination =>
      cases found : newerMessage? state source destination with
      | none => simp [next, CCFRaft.next, found]
      | some selected => simp [next, CCFRaft.next, found]
  | becomeLeader _ => rfl

/-- In the absence of a term-two leader, the wider guards imply slice-two guards. -/
theorem enabled_sliceTwo_of_pre
    {state : State TxId}
    (pre : PreElectionInvariant state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    CCFRaft.Enabled state action := by
  cases action with
  | clientRequest node txId =>
      rcases enabled with ⟨role, fresh⟩
      have termOne :
          (state.nodes node).currentTerm = TERM_ONE := by
        rcases pre.sliceTwo.currentTermsValid node with one | two
        · exact one
        · exact False.elim (pre.noTermTwoLeader node role two)
      exact ⟨role, termOne, fresh⟩
  | appendEntries source destination batchEnd =>
      rcases enabled with ⟨role, different, batch⟩
      have termOne :
          (state.nodes source).currentTerm = TERM_ONE := by
        rcases pre.sliceTwo.currentTermsValid source with one | two
        · exact one
        · exact False.elim (pre.noTermTwoLeader source role two)
      exact ⟨role, termOne, different, batch⟩
  | receive source destination =>
      exact enabled
  | advanceCommitIndex node =>
      rcases enabled with ⟨role, advances⟩
      have termOne :
          (state.nodes node).currentTerm = TERM_ONE := by
        rcases pre.sliceTwo.currentTermsValid node with one | two
        · exact one
        · exact False.elim (pre.noTermTwoLeader node role two)
      exact ⟨role, termOne, advances⟩
  | timeout node =>
      exact enabled
  | requestVote source destination =>
      exact enabled
  | updateTerm source destination =>
      exact enabled
  | becomeLeader node =>
      exact enabled

/-- The empty initial state satisfies the documented pre-election invariant. -/
theorem initialSystemInductiveInvariant :
    SystemInductiveInvariant (initialState : State TxId) := by
  apply SystemInductiveInvariant.pre
  constructor
  · intro node role termTwo
    have termOne :
        ((initialState : State TxId).nodes node).currentTerm =
          TERM_ONE := by
      simp [initialState, initialNodeState]
    rw [termOne, TERM_ONE] at termTwo
    omega
  · exact CCFRaft.initialSystemInductiveInvariant
  · intro node
    simp [
      PreFollowerCommitsCovered,
      initialState,
      initialNodeState,
      NodeState.committedLog
    ]
  · simp [PreQueuedCommitBounded, initialState]

/-! ## Generic local-handler facts -/

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

/-- Removing a selected message preserves pre-election commit-snapshot bounds. -/
theorem preQueuedBoundAfterRemove
    {state : State TxId}
    {source destination : Node}
    {selected : Message TxId}
    {remaining : List (Message TxId)}
    (bounded : PreQueuedCommitBounded state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (selected, remaining)) :
    PreQueuedCommitBounded
      { state with
        network := updateQueue state.network destination remaining } := by
  have sound := CCFRaft.takeFirstFromSound taken
  intro queue message member
  by_cases queueEq : queue = destination
  · subst queue
    have oldMember :
        message ∈ state.network destination := by
      simpa [updateQueue] using sound.2.2 message (by
        simpa [updateQueue] using member)
    exact bounded destination message oldMember
  · have oldMember :
        message ∈ state.network queue := by
      simpa [updateQueue, Function.update, queueEq] using member
    exact bounded queue message oldMember

/-- Enqueuing a non-AppendEntries-request preserves pre-election bounds. -/
theorem preQueuedBoundAfterNonRequestEnqueue
    {state : State TxId}
    (bounded : PreQueuedCommitBounded state)
    (newMessage : Message TxId)
    (notRequest :
      match newMessage with
      | .appendEntriesRequest _ => False
      | _ => True) :
    PreQueuedCommitBounded
      { state with network := enqueueNoDup state.network newMessage } := by
  intro destination message member
  have cases :=
    CCFRaft.memEnqueueNoDup
      state.network newMessage message destination (by simpa using member)
  rcases cases with oldMember | ⟨_, messageEq⟩
  · exact bounded destination message oldMember
  · subst message
    cases newMessage <;> simp_all

/-- Prefix coverage and bounded commits compare the underlying indices. -/
theorem commitIndex_le_of_committedPrefix
    {left right : NodeState TxId}
    (leftBound : left.commitIndex <= left.log.length)
    (rightBound : right.commitIndex <= right.log.length)
    (isPrefix : left.committedLog <+: right.committedLog) :
    left.commitIndex <= right.commitIndex := by
  have lengths := isPrefix.length_le
  simpa [
    NodeState.committedLog,
    List.length_take,
    Nat.min_eq_left leftBound,
    Nat.min_eq_left rightBound
  ] using lengths

/-- A bounded prefix of a covered log is covered by a longer bounded prefix. -/
theorem committedPrefixOfCoveredLog
    {small large : NodeState TxId}
    (logPrefix : small.log <+: large.log)
    (smallBound : small.commitIndex <= small.log.length)
    (largeBound : large.commitIndex <= large.log.length)
    (commitLe : small.commitIndex <= large.commitIndex) :
    small.committedLog <+: large.committedLog := by
  have equality :=
    CCFRaft.takeEqOfPrefix logPrefix smallBound
  simp only [NodeState.committedLog]
  rw [equality, List.prefix_iff_eq_take]
  have smallLarge :
      small.commitIndex <= large.log.length :=
    commitLe.trans largeBound
  have smallBoth :
      small.commitIndex <= min large.log.length large.commitIndex :=
    Nat.le_min.mpr ⟨smallLarge, commitLe⟩
  simp [
    List.take_take,
    Nat.min_eq_left smallLarge,
    Nat.min_eq_left smallBoth
  ]
  exact ⟨commitLe, smallLarge⟩

/-! ## Crossing the election boundary -/

/-- A RequestMatchesLeader snapshot is a snapshot of node zero's old history. -/
theorem requestMatchesOldHistory
    {state : State TxId}
    {request : AppendEntriesRequest TxId}
    (safe : RequestMatchesLeader state request) :
    RequestSnapshots (state.nodes INITIAL_LEADER).log request := by
  exact
    ⟨safe.2.2.2.2.1, safe.2.2.2.2.2.1,
      safe.2.2.2.2.2.2⟩

/-- Promotion of the first term-two leader establishes the cross-term phase. -/
theorem becomeLeaderStartsCrossTerm
    (state : State TxId)
    (node : Node)
    (pre : PreElectionInvariant state)
    (enabled : Enabled state (.becomeLeader node)) :
    CrossTermInvariant (next state (.becomeLeader node)) := by
  let after := next state (.becomeLeader node)
  have sliceEnabled :
      CCFRaft.Enabled state (.becomeLeader node) :=
    enabled_sliceTwo_of_pre pre enabled
  have afterCore :
      CCFRaft.SystemInductiveInvariant after := by
    dsimp [after]
    rw [next_eq_sliceTwo]
    exact
      CCFRaft.becomeLeaderPreservesSystemInductiveInvariant
        state node pre.sliceTwo sliceEnabled
  have nodeNeLeader : Not (node = INITIAL_LEADER) := by
    intro nodeEq
    subst node
    exact pre.sliceTwo.initialNodeNotCandidate enabled.1
  have oldLeaderCommitPrefix :
      (after.nodes INITIAL_LEADER).committedLog <+:
        (after.nodes node).log :=
    CCFRaft.systemInductiveInvariantTermTwoLeaderCompleteness
      afterCore node
        (by simp [after, next])
        (by simp [after, next, enabled.2.1])
  refine
    ⟨node, (state.nodes INITIAL_LEADER).log,
      (state.nodes node).log, [], ?_⟩
  constructor
  · exact pre.sliceTwo.termsAreOne INITIAL_LEADER
  · simp [EntriesHaveTerm]
  · exact pre.sliceTwo.logsPrefixLeader node
  · intro candidate
    left
    by_cases candidateEq : candidate = node
    · subst candidate
      simpa [after, next] using pre.sliceTwo.logsPrefixLeader node
    · simpa [after, next, updateNode, Function.update, candidateEq] using
        pre.sliceTwo.logsPrefixLeader candidate
  · simpa [after] using afterCore.commitIndicesBounded
  · simpa [after] using afterCore.currentTermsValid
  · intro candidate entry member
    have termOne : entry.term = TERM_ONE :=
      afterCore.termsAreOne candidate entry (by simpa [after] using member)
    rcases afterCore.currentTermsValid candidate with currentOne | currentTwo
    · have currentOne' :
          ((next state (.becomeLeader node)).nodes candidate).currentTerm =
            TERM_ONE := by
        simpa [after] using currentOne
      rw [termOne, currentOne']
    · have currentTwo' :
          ((next state (.becomeLeader node)).nodes candidate).currentTerm =
            2 := by
        simpa [after] using currentTwo
      rw [termOne, currentTwo', TERM_ONE]
      omega
  · exact Ne.symm nodeNeLeader
  · simp [after, next]
  · intro candidate role
    have candidateRole : (after.nodes candidate).role = .leader := by
      simpa [after] using role
    rcases afterCore.currentTermsValid candidate with termOne | termTwo
    · have candidateEq :=
        afterCore.termOneLeaderIsInitial candidate candidateRole termOne
      left
      refine ⟨candidateEq, by simpa [after] using termOne, ?_⟩
      subst candidate
      simp [after, next, updateNode, Function.update, Ne.symm nodeNeLeader]
    · have nodeRole : (after.nodes node).role = .leader := by
        simp [after, next]
      have nodeTerm : (after.nodes node).currentTerm = 2 := by
        simpa [after, next] using enabled.2.1
      have candidateEq :=
        CCFRaft.systemInductiveInvariantElectionSafety afterCore
          candidate node candidateRole nodeRole (termTwo.trans nodeTerm.symm)
      right
      refine ⟨candidateEq, by simpa [after] using termTwo, ?_⟩
      subst candidate
      simp [after, next]
  · simpa [after, next, hasElectionMajority] using enabled.2.2
  · simpa [after] using afterCore.candidatesSelfVote
  · simpa [after] using afterCore.votedForTermTwo
  · intro candidate voter voterIn
    have sound :=
      afterCore.votesGrantedSound candidate voter
        (by simpa [after] using voterIn)
    simpa [after] using sound.2.1
  · intro destination message member
    have oldMember :
        message ∈ state.network destination := by
      simpa [after, next] using member
    have requestSafe :=
      pre.sliceTwo.queuedRequestsMatchLeader
        destination message oldMember
    have voteSafe :=
      pre.sliceTwo.queuedVoteMessagesSafe
        destination message oldMember
    constructor
    · exact requestSafe.1
    · cases message with
      | appendEntriesRequest request =>
          have oldCommitBound :=
            pre.queuedCommitBounded destination
              (.appendEntriesRequest request) oldMember
          have advertisedPrefix :
              (state.nodes INITIAL_LEADER).log.take request.leaderCommit <+:
                (state.nodes node).log := by
            have requestCommitPrefix :
                (state.nodes INITIAL_LEADER).log.take request.leaderCommit <+:
                  (state.nodes INITIAL_LEADER).committedLog := by
              rw [NodeState.committedLog]
              have taken :=
                List.take_prefix request.leaderCommit
                  ((state.nodes INITIAL_LEADER).log.take
                    (state.nodes INITIAL_LEADER).commitIndex)
              simpa [
                List.take_take,
                Nat.min_eq_left oldCommitBound.1
              ] using taken
            have beforeAfterLeaderCommit :
                (state.nodes INITIAL_LEADER).committedLog =
                  (after.nodes INITIAL_LEADER).committedLog := by
              simp [
                after, next, updateNode, Function.update,
                Ne.symm nodeNeLeader, NodeState.committedLog
              ]
            have beforeAfterNewLog :
                (state.nodes node).log =
                  (after.nodes node).log := by
              simp [after, next]
            calc
              (state.nodes INITIAL_LEADER).log.take request.leaderCommit <+:
                  (state.nodes INITIAL_LEADER).committedLog :=
                requestCommitPrefix
              _ = (after.nodes INITIAL_LEADER).committedLog :=
                beforeAfterLeaderCommit
              _ <+: (after.nodes node).log :=
                oldLeaderCommitPrefix
              _ = (state.nodes node).log :=
                beforeAfterNewLog.symm
          have oldSafe := requestSafe.2
          have sourceNeDestination :
              Not (request.source = request.destination) := by
            intro sourceDestination
            apply oldSafe.2.1
            exact sourceDestination.symm.trans oldSafe.1
          refine
            ⟨sourceNeDestination, Or.inl
              ⟨oldSafe.2.2.1,
                oldSafe.1,
                requestMatchesOldHistory oldSafe,
                oldCommitBound.1.trans
                  (pre.sliceTwo.commitIndicesBounded INITIAL_LEADER)⟩,
              by
                simp [
                  oldSafe.2.2.1,
                  advertisedPrefix,
                  TERM_ONE],
              oldCommitBound.2⟩
      | appendEntriesResponse response =>
          rcases requestSafe.2 with
            ⟨responseDestination, responseSource, responseTerm,
              responseBound, responsePrefix⟩
          refine
            ⟨by
                intro sourceDestination
                apply responseSource
                exact sourceDestination.trans responseDestination,
              Or.inl responseDestination,
              by simpa using responseTerm,
              ?_⟩
          intro success
          left
          refine
            ⟨responseDestination, responseBound, ?_⟩
          intro voterIn
          have oldVoterIn :
              response.source ∈
                (state.nodes node).votesGranted := by
            simpa [after, next] using voterIn
          have voterPrefix :=
            (pre.sliceTwo.votesGrantedSound
              node response.source oldVoterIn).2.2
          have responseWithinVoter :
              response.lastLogIndex <=
                (state.nodes response.source).log.length := by
            have equalLengths :=
              congrArg List.length (responsePrefix success)
            simp [
              List.length_take,
              Nat.min_eq_left responseBound
            ] at equalLengths
            omega
          exact
            le_trans responseWithinVoter voterPrefix.length_le
      | requestVoteRequest request =>
          refine ⟨voteSafe.1, voteSafe.2.1, ?_, ?_⟩
          · by_cases sourceEq : request.source = node
            · have sourceTerm := voteSafe.2.2.1
              rw [sourceEq] at sourceTerm
              rw [sourceEq]
              simpa [next] using sourceTerm
            · simpa [
                after, next, updateNode, Function.update, sourceEq
              ] using voteSafe.2.2.1
          · by_cases sourceEq : request.source = node
            · have sourceVote := voteSafe.2.2.2.1
              rw [sourceEq] at sourceVote
              rw [sourceEq]
              simpa [next] using sourceVote
            · simpa [
                after, next, updateNode, Function.update, sourceEq
              ] using voteSafe.2.2.2.1
      | requestVoteResponse response =>
          refine
            ⟨voteSafe.1, voteSafe.2.1, ?_⟩
          intro granted
          have chosen := (voteSafe.2.2.2.2 granted).1
          by_cases sourceEq : response.source = node
          · rw [sourceEq] at chosen ⊢
            simpa [after, next] using chosen
          · simpa [
              after, next, updateNode, Function.update, sourceEq
            ] using chosen
  · intro leader role peer
    have leaderRole : (after.nodes leader).role = .leader := by
      simpa [after] using role
    rcases afterCore.currentTermsValid leader with termOne | termTwo
    · have leaderEq :=
        afterCore.termOneLeaderIsInitial leader leaderRole termOne
      subst leader
      constructor
      · simpa [
          after, next, updateNode, Function.update, Ne.symm nodeNeLeader
        ] using pre.sliceTwo.sentIndicesBounded peer
      · simpa [
          after, next, updateNode, Function.update, Ne.symm nodeNeLeader
        ] using pre.sliceTwo.matchIndicesBounded peer
    · have nodeRole : (after.nodes node).role = .leader := by
        simp [after, next]
      have nodeTerm : (after.nodes node).currentTerm = 2 := by
        simpa [after, next] using enabled.2.1
      have leaderEq :=
        CCFRaft.systemInductiveInvariantElectionSafety afterCore
          leader node leaderRole nodeRole (termTwo.trans nodeTerm.symm)
      subst leader
      simp [after, next]
  · intro voter voterIn
    have oldVoterIn :
        voter ∈ (state.nodes node).votesGranted := by
      simpa [after, next] using voterIn
    have voterPrefix :=
      (pre.sliceTwo.votesGrantedSound node voter oldVoterIn).2.2
    have matchEquality := pre.sliceTwo.matchIndexDescribesPrefix voter
    have matchBound := pre.sliceTwo.matchIndicesBounded voter
    have matchWithinVoter :
        (state.nodes INITIAL_LEADER).matchIndex voter <=
          (state.nodes voter).log.length := by
      have equalLengths := congrArg List.length matchEquality
      simp [
        List.length_take,
        Nat.min_eq_left matchBound
      ] at equalLengths
      omega
    simpa [
      after, next, updateNode, Function.update, Ne.symm nodeNeLeader
    ] using
      le_trans matchWithinVoter voterPrefix.length_le
  · intro candidate
    have beforePrefix := pre.followerCommitsCovered candidate
    have candidateUnchanged :
        (after.nodes candidate).committedLog =
          (state.nodes candidate).committedLog := by
      by_cases candidateEq : candidate = node
      · subst candidate
        simp [after, next, NodeState.committedLog]
      · simp [
          after, next, updateNode, Function.update, candidateEq,
          NodeState.committedLog
        ]
    have leaderUnchanged :
        (after.nodes INITIAL_LEADER).committedLog =
          (state.nodes INITIAL_LEADER).committedLog := by
      simp [
        after, next, updateNode, Function.update,
        Ne.symm nodeNeLeader, NodeState.committedLog
      ]
    simpa [after] using (show
      (after.nodes candidate).committedLog <+:
          (state.nodes node).log from by
      calc
      ((next state (.becomeLeader node)).nodes candidate).committedLog =
          (state.nodes candidate).committedLog := by
        simpa [after] using candidateUnchanged
      _ <+: (state.nodes INITIAL_LEADER).committedLog := beforePrefix
      _ = (after.nodes INITIAL_LEADER).committedLog := leaderUnchanged.symm
      _ <+: (after.nodes node).log := oldLeaderCommitPrefix
      _ = (state.nodes node).log := by
        simp [after, next])
  · intro candidate belowBase
    simp [after, next] at belowBase
  · intro destination message member
    cases message with
    | appendEntriesRequest request =>
        have safe :=
          (pre.sliceTwo.queuedRequestsMatchLeader
            destination (.appendEntriesRequest request)
              (by simpa [after, next] using member)).2
        intro termTwo
        rw [safe.2.2.1, TERM_ONE] at termTwo
        omega
    | appendEntriesResponse _ => trivial
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial
  · intro destination message member
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse response =>
        have safe :=
          (pre.sliceTwo.queuedRequestsMatchLeader
            destination (.appendEntriesResponse response)
              (by simpa [after, next] using member)).2
        intro responseDestination
        exact False.elim
          (nodeNeLeader (safe.1.symm.trans responseDestination).symm)
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial

/-! ## Preservation before promotion -/

/-- Updating one node without changing its role or term cannot create a leader. -/
theorem noTermTwoLeaderAfterLocalUpdate
    {state : State TxId}
    {destination : Node}
    {nextNode : NodeState TxId}
    (noneBefore :
      forall node,
        (state.nodes node).role = .leader ->
          Not ((state.nodes node).currentTerm = 2))
    (roleEq : nextNode.role = (state.nodes destination).role)
    (termEq :
      nextNode.currentTerm = (state.nodes destination).currentTerm) :
    forall node,
      (updateNode state.nodes destination nextNode node).role = .leader ->
        Not (
          (updateNode state.nodes destination nextNode node).currentTerm = 2) := by
  intro node role termTwo
  by_cases nodeEq : node = destination
  · subst node
    apply noneBefore destination
    · simpa [roleEq] using role
    · simpa [termEq] using termTwo
  · apply noneBefore node
    · simpa [updateNode, Function.update, nodeEq] using role
    · simpa [updateNode, Function.update, nodeEq] using termTwo

/-- A local update preserving log and commit also preserves pre-election coverage. -/
theorem preCoverageAfterUnchangedLocal
    {state : State TxId}
    {destination : Node}
    {nextNode : NodeState TxId}
    (covered : PreFollowerCommitsCovered state)
    (logEq : nextNode.log = (state.nodes destination).log)
    (commitEq :
      nextNode.commitIndex = (state.nodes destination).commitIndex) :
    PreFollowerCommitsCovered
      { state with nodes := updateNode state.nodes destination nextNode } := by
  intro node
  by_cases destinationLeader : destination = INITIAL_LEADER
  · subst destination
    by_cases nodeLeader : node = INITIAL_LEADER
    · subst node
      exact CCFRaft.prefixRefl _
    · simpa [
        NodeState.committedLog,
        updateNode,
        Function.update,
        nodeLeader,
        logEq,
        commitEq
      ] using covered node
  · by_cases nodeDestination : node = destination
    · subst node
      simpa [
        NodeState.committedLog,
        updateNode,
        Function.update,
        destinationLeader,
        Ne.symm destinationLeader,
        logEq,
        commitEq
      ] using covered destination
    · simpa [
        NodeState.committedLog,
        updateNode,
        Function.update,
        destinationLeader,
        Ne.symm destinationLeader,
        nodeDestination
      ] using covered node

/-- Receiving any enabled pre-election message preserves the pre phase. -/
theorem receivePreservesPreElectionInvariant
    (state : State TxId)
    (source destination : Node)
    (pre : PreElectionInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    PreElectionInvariant (next state (.receive source destination)) := by
  have sliceEnabled :
      CCFRaft.Enabled state (.receive source destination) :=
    enabled_sliceTwo_of_pre pre enabled
  have afterCore :
      CCFRaft.SystemInductiveInvariant
        (next state (.receive source destination)) := by
    rw [next_eq_sliceTwo]
    exact
      CCFRaft.receivePreservesSystemInductiveInvariant
        state source destination pre.sliceTwo sliceEnabled
  cases receiveResult :
      handleReceive? state source destination with
  | none =>
      simp [Enabled, receiveResult] at enabled
  | some resultingState =>
      have nextEq :
          next state (.receive source destination) = resultingState := by
        simp [next, receiveResult]
      rw [nextEq] at afterCore ⊢
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
            · rename_i nextNode stepped
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq] at afterCore ⊢
              unfold returnToFollowerState? at stepped
              split at stepped
              · rename_i canReturn
                simp at stepped
                subst nextNode
                have destinationNeLeader :
                    Not (destination = INITIAL_LEADER) := by
                  intro destinationEq
                  apply pre.sliceTwo.initialNodeNotCandidate
                  rw [← destinationEq]
                  exact canReturn.2
                constructor
                · intro node role termTwo
                  by_cases nodeEq : node = destination
                  · subst node
                    simp [updateNode] at role
                  · apply pre.noTermTwoLeader node
                    · simpa [
                        updateNode, Function.update, nodeEq
                      ] using role
                    · simpa [
                        updateNode, Function.update, nodeEq
                      ] using termTwo
                · simpa using afterCore
                · exact
                    preCoverageAfterUnchangedLocal
                      pre.followerCommitsCovered rfl rfl
                · intro queue message member
                  have bounded :=
                    pre.queuedCommitBounded queue message
                      (by simpa using member)
                  simpa [
                    updateNode, Function.update,
                    Ne.symm destinationNeLeader
                  ] using bounded
              · contradiction
            · split at receiveResult
              · contradiction
              · rename_i nextNode response handled
                have resultEq := Option.some.inj receiveResult
                rw [← resultEq] at afterCore ⊢
                have selectedSound := CCFRaft.takeFirstFromSound taken
                have queuedSafe :=
                  pre.sliceTwo.queuedRequestsMatchLeader
                    destination (.appendEntriesRequest request)
                      selectedSound.2.1
                have requestSafe : RequestMatchesLeader state request :=
                  queuedSafe.2
                have requestDestination :
                    request.destination = destination := queuedSafe.1
                have destinationNeLeader :
                    Not (destination = INITIAL_LEADER) := by
                  intro destinationEq
                  apply requestSafe.2.1
                  rw [requestDestination, destinationEq]
                have fullPost :=
                  CCFRaft.handleAppendEntriesRequestPreserves
                    pre.sliceTwo requestDestination requestSafe handled
                have localPost :=
                  handleAppendEntriesRequestLocalPost handled
                constructor
                · exact
                    noTermTwoLeaderAfterLocalUpdate
                      pre.noTermTwoLeader
                      localPost.roleUnchanged
                      localPost.currentTermUnchanged
                · simpa using afterCore
                · intro candidate
                  by_cases candidateEq : candidate = destination
                  · subst candidate
                    have beforeCommitLe :
                        (state.nodes destination).commitIndex <=
                          (state.nodes INITIAL_LEADER).commitIndex :=
                      commitIndex_le_of_committedPrefix
                        (pre.sliceTwo.commitIndicesBounded destination)
                        (pre.sliceTwo.commitIndicesBounded INITIAL_LEADER)
                        (pre.followerCommitsCovered destination)
                    have requestCommitLe :
                        request.leaderCommit <=
                          (state.nodes INITIAL_LEADER).commitIndex :=
                      (pre.queuedCommitBounded destination
                        (.appendEntriesRequest request)
                          selectedSound.2.1).1
                    have afterCommitLe :
                        nextNode.commitIndex <=
                          (state.nodes INITIAL_LEADER).commitIndex :=
                      localPost.commitUpperBound.trans
                        (max_le beforeCommitLe requestCommitLe)
                    simpa [
                      updateNode, Function.update,
                      Ne.symm destinationNeLeader
                    ] using
                      committedPrefixOfCoveredLog
                        fullPost.logPrefixLeader
                        fullPost.commitBounded
                        (pre.sliceTwo.commitIndicesBounded INITIAL_LEADER)
                        afterCommitLe
                  · simpa [
                      updateNode, Function.update,
                    candidateEq, destinationNeLeader,
                    Ne.symm destinationNeLeader
                  ] using pre.followerCommitsCovered candidate
                · have removed :=
                    preQueuedBoundAfterRemove
                      pre.queuedCommitBounded taken
                  have queueBound :=
                    preQueuedBoundAfterNonRequestEnqueue
                      removed (.appendEntriesResponse response) (by trivial)
                  intro queue message member
                  have bounded :=
                    queueBound queue message (by
                      simpa [reply] using member)
                  simpa [
                    updateNode, Function.update,
                    Ne.symm destinationNeLeader
                  ] using bounded
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i nextNode handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq] at afterCore ⊢
              have selectedSound := CCFRaft.takeFirstFromSound taken
              have queuedSafe :=
                pre.sliceTwo.queuedRequestsMatchLeader
                  destination (.appendEntriesResponse response)
                    selectedSound.2.1
              have responseSafe : ResponseMatchesLeader state response :=
                queuedSafe.2
              have destinationEq : destination = INITIAL_LEADER :=
                queuedSafe.1.symm.trans responseSafe.1
              subst destination
              have fullPost :=
                CCFRaft.handleAppendEntriesResponsePreserves
                  pre.sliceTwo responseSafe
                    (by simpa [responseSafe.1] using handled)
              constructor
              · exact
                  noTermTwoLeaderAfterLocalUpdate
                    pre.noTermTwoLeader
                    fullPost.roleUnchanged
                    fullPost.currentTermUnchanged
              · simpa using afterCore
              · exact
                  preCoverageAfterUnchangedLocal
                    pre.followerCommitsCovered
                    fullPost.logUnchanged
                    fullPost.commitIndexUnchanged
              · exact
                  (by
                    have queueBound :=
                      preQueuedBoundAfterRemove
                        pre.queuedCommitBounded taken
                    intro queue message member
                    have bounded := queueBound queue message member
                    simpa [
                      updateNode, Function.update,
                      fullPost.commitIndexUnchanged
                    ] using bounded)
          · rename_i request
            split at receiveResult
            · contradiction
            · rename_i nextNode response handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq] at afterCore ⊢
              have selectedSound := CCFRaft.takeFirstFromSound taken
              have voteSafe :=
                pre.sliceTwo.queuedVoteMessagesSafe
                  destination (.requestVoteRequest request)
                    selectedSound.2.1
              have queuedSafe :=
                pre.sliceTwo.queuedRequestsMatchLeader
                  destination (.requestVoteRequest request)
                    selectedSound.2.1
              have fullPost :=
                CCFRaft.handleRequestVoteRequestPreserves
                  pre.sliceTwo queuedSafe.1 voteSafe handled
              constructor
              · exact
                  noTermTwoLeaderAfterLocalUpdate
                    pre.noTermTwoLeader
                    fullPost.roleUnchanged
                    fullPost.currentTermUnchanged
              · simpa using afterCore
              · exact
                  preCoverageAfterUnchangedLocal
                    pre.followerCommitsCovered
                    fullPost.logUnchanged
                    fullPost.commitIndexUnchanged
              · have removed :=
                  preQueuedBoundAfterRemove
                    pre.queuedCommitBounded taken
                have queueBound :=
                  preQueuedBoundAfterNonRequestEnqueue
                    removed (.requestVoteResponse response) (by trivial)
                intro queue message member
                have bounded := queueBound queue message member
                by_cases destinationLeader : destination = INITIAL_LEADER
                · subst destination
                  simpa [
                    updateNode, fullPost.commitIndexUnchanged
                  ] using bounded
                · simpa [
                    updateNode, Function.update,
                    Ne.symm destinationLeader
                  ] using bounded
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i nextNode handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq] at afterCore ⊢
              have fullPost :=
                CCFRaft.handleRequestVoteResponsePreserves handled
              constructor
              · exact
                  noTermTwoLeaderAfterLocalUpdate
                    pre.noTermTwoLeader
                    fullPost.roleUnchanged
                    fullPost.currentTermUnchanged
              · simpa using afterCore
              · exact
                  preCoverageAfterUnchangedLocal
                    pre.followerCommitsCovered
                    fullPost.logUnchanged
                    fullPost.commitIndexUnchanged
              · exact
                  (by
                    have queueBound :=
                      preQueuedBoundAfterRemove
                        pre.queuedCommitBounded taken
                    intro queue message member
                    have bounded := queueBound queue message member
                    by_cases destinationLeader : destination = INITIAL_LEADER
                    · subst destination
                      simpa [
                        updateNode, fullPost.commitIndexUnchanged
                      ] using bounded
                    · simpa [
                        updateNode, Function.update,
                        Ne.symm destinationLeader
                      ] using bounded)

/-- Every enabled pre-election action either stays pre-election or promotes. -/
theorem preElectionInvariantPreserved
    (state : State TxId)
    (action : Action TxId)
    (pre : PreElectionInvariant state)
    (enabled : Enabled state action) :
    SystemInductiveInvariant (next state action) := by
  have sliceEnabled : CCFRaft.Enabled state action :=
    enabled_sliceTwo_of_pre pre enabled
  have afterCore :
      CCFRaft.SystemInductiveInvariant (next state action) := by
    rw [next_eq_sliceTwo]
    exact
      CCFRaft.nextPreservesSystemInductiveInvariant
        state action pre.sliceTwo sliceEnabled
  cases action with
  | clientRequest node txId =>
      apply SystemInductiveInvariant.pre
      have nodeEq : node = INITIAL_LEADER :=
        CCFRaft.termOneLeaderImpliesInitialLeader
          pre.sliceTwo sliceEnabled.1 sliceEnabled.2.1
      subst node
      constructor
      · intro candidate role termTwo
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          apply pre.noTermTwoLeader INITIAL_LEADER
          · simpa [next] using role
          · simpa [next] using termTwo
        · apply pre.noTermTwoLeader candidate
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using role
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using termTwo
      · exact afterCore
      · intro candidate
        have leaderBound := pre.sliceTwo.commitIndicesBounded INITIAL_LEADER
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          exact CCFRaft.prefixRefl _
        · have before := pre.followerCommitsCovered candidate
          simpa [
            next, NodeState.committedLog,
            updateNode, Function.update, candidateEq,
            List.take_append_of_le_length leaderBound
          ] using before
      · intro destination message member
        have oldMember : message ∈ state.network destination := by
          simpa [next] using member
        simpa [next] using
          pre.queuedCommitBounded destination message oldMember
  | appendEntries source destination batchEnd =>
      apply SystemInductiveInvariant.pre
      have sourceEq : source = INITIAL_LEADER :=
        CCFRaft.termOneLeaderImpliesInitialLeader
          pre.sliceTwo sliceEnabled.1 sliceEnabled.2.1
      subst source
      constructor
      · intro candidate role termTwo
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          apply pre.noTermTwoLeader INITIAL_LEADER
          · simpa [next] using role
          · simpa [next] using termTwo
        · apply pre.noTermTwoLeader candidate
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using role
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using termTwo
      · exact afterCore
      · intro candidate
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          exact CCFRaft.prefixRefl _
        · simpa [
            next, NodeState.committedLog,
            updateNode, Function.update, candidateEq
          ] using pre.followerCommitsCovered candidate
      · intro queue message member
        have cases :=
          CCFRaft.memEnqueueNoDup
            state.network
            (.appendEntriesRequest
              (makeAppendEntriesRequest
                state INITIAL_LEADER destination batchEnd))
            message queue (by simpa [next] using member)
        rcases cases with oldMember | ⟨queueEq, messageEq⟩
        · simpa [next] using
            pre.queuedCommitBounded queue message oldMember
        · subst message
          constructor
          · simp [next, makeAppendEntriesRequest]
          · intro entriesEmpty
            simp only [makeAppendEntriesRequest] at entriesEmpty ⊢
            have sentBound :=
              pre.sliceTwo.sentIndicesBounded destination
            have commitBound :=
              pre.sliceTwo.commitIndicesBounded INITIAL_LEADER
            by_cases sentAtEnd :
                (state.nodes INITIAL_LEADER).sentIndex destination =
                  (state.nodes INITIAL_LEADER).log.length
            · simpa [sentAtEnd] using commitBound
            · have sentLt :
                  (state.nodes INITIAL_LEADER).sentIndex destination <
                    (state.nodes INITIAL_LEADER).log.length := by
                omega
              have batchEq :
                  batchEnd =
                    (state.nodes INITIAL_LEADER).sentIndex destination + 1 := by
                rw [enabled.2.2]
                omega
              have lengths := congrArg List.length entriesEmpty
              simp [
                makeAppendEntriesRequest, messageEntries, batchEq,
                List.length_take, List.length_drop
              ] at lengths
              omega
  | receive source destination =>
      exact
        SystemInductiveInvariant.pre
          (receivePreservesPreElectionInvariant
            state source destination pre enabled)
  | advanceCommitIndex node =>
      apply SystemInductiveInvariant.pre
      have nodeEq : node = INITIAL_LEADER :=
        CCFRaft.termOneLeaderImpliesInitialLeader
          pre.sliceTwo sliceEnabled.1 sliceEnabled.2.1
      subst node
      have leaderMonotonic :
          (state.nodes INITIAL_LEADER).committedLog <+:
            ((next state (.advanceCommitIndex INITIAL_LEADER)).nodes INITIAL_LEADER).committedLog :=
        CCFRaft.nextCommittedLogMonotonicity
          state (.advanceCommitIndex INITIAL_LEADER)
            pre.sliceTwo sliceEnabled INITIAL_LEADER
      constructor
      · intro candidate role termTwo
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          apply pre.noTermTwoLeader INITIAL_LEADER
          · simpa [next] using role
          · simpa [next] using termTwo
        · apply pre.noTermTwoLeader candidate
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using role
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using termTwo
      · exact afterCore
      · intro candidate
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          exact CCFRaft.prefixRefl _
        · have before := pre.followerCommitsCovered candidate
          have candidateUnchanged :
              ((next state
                (.advanceCommitIndex INITIAL_LEADER)).nodes candidate).committedLog =
                (state.nodes candidate).committedLog := by
            simp [
              next, NodeState.committedLog,
              updateNode, Function.update, candidateEq
            ]
          rw [candidateUnchanged]
          exact before.trans leaderMonotonic
      · intro destination message member
        have oldMember : message ∈ state.network destination := by
          simpa [next] using member
        have oldBound :=
          pre.queuedCommitBounded destination message oldMember
        cases message with
        | appendEntriesRequest request =>
            exact
              ⟨oldBound.1.trans (Nat.le_of_lt sliceEnabled.2.2),
                oldBound.2⟩
        | appendEntriesResponse _ => trivial
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
  | timeout node =>
      apply SystemInductiveInvariant.pre
      have nodeNeLeader : Not (node = INITIAL_LEADER) := by
        intro nodeEq
        subst node
        have leaderRole :=
          pre.sliceTwo.initialNodeTermOneIsLeader enabled.2
        exact Role.noConfusion (enabled.1.symm.trans leaderRole)
      constructor
      · intro candidate role termTwo
        by_cases candidateEq : candidate = node
        · subst candidate
          simp [next] at role
        · apply pre.noTermTwoLeader candidate
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using role
          · simpa [
              next, updateNode, Function.update, candidateEq
            ] using termTwo
      · exact afterCore
      · intro candidate
        by_cases candidateEq : candidate = node
        · subst candidate
          simpa [
            next, NodeState.committedLog,
            updateNode, Function.update,
            nodeNeLeader, Ne.symm nodeNeLeader
          ] using pre.followerCommitsCovered node
        · simpa [
            next, NodeState.committedLog,
            updateNode, Function.update,
            candidateEq, nodeNeLeader, Ne.symm nodeNeLeader
          ] using pre.followerCommitsCovered candidate
      · intro destination message member
        have oldMember : message ∈ state.network destination := by
          simpa [next] using member
        have bounded :=
          pre.queuedCommitBounded destination message oldMember
        simpa [
          next, updateNode, Function.update, Ne.symm nodeNeLeader
        ] using bounded
  | requestVote source destination =>
      apply SystemInductiveInvariant.pre
      constructor
      · intro candidate role termTwo
        apply pre.noTermTwoLeader candidate
        · simpa [next] using role
        · simpa [next] using termTwo
      · exact afterCore
      · intro candidate
        simpa [next, NodeState.committedLog] using
          pre.followerCommitsCovered candidate
      · exact
          preQueuedBoundAfterNonRequestEnqueue
            pre.queuedCommitBounded
            (.requestVoteRequest
              (makeRequestVoteRequest state source destination))
            (by trivial)
  | updateTerm source destination =>
      apply SystemInductiveInvariant.pre
      constructor
      · intro candidate role termTwo
        cases found : newerMessage? state source destination with
        | none =>
            exact pre.noTermTwoLeader candidate
              (by simpa [next, found] using role)
              (by simpa [next, found] using termTwo)
        | some selected =>
            by_cases candidateEq : candidate = destination
            · subst candidate
              simp [next, found] at role
            · apply pre.noTermTwoLeader candidate
              · simpa [
                  next, found, updateNode, Function.update, candidateEq
                ] using role
              · simpa [
                  next, found, updateNode, Function.update, candidateEq
                ] using termTwo
      · exact afterCore
      · cases found : newerMessage? state source destination with
        | none =>
            simpa [next, found] using pre.followerCommitsCovered
        | some selected =>
            intro candidate
            by_cases destinationLeader : destination = INITIAL_LEADER
            · subst destination
              by_cases candidateLeader : candidate = INITIAL_LEADER
              · subst candidate
                exact CCFRaft.prefixRefl _
              · simpa [
                  next, found, NodeState.committedLog,
                  updateNode, Function.update, candidateLeader
                ] using pre.followerCommitsCovered candidate
            · by_cases candidateEq : candidate = destination
              · subst candidate
                simpa [
                  next, found, NodeState.committedLog,
                  updateNode, Function.update,
                  destinationLeader, Ne.symm destinationLeader
                ] using pre.followerCommitsCovered destination
              · simpa [
                  next, found, NodeState.committedLog,
                  updateNode, Function.update,
                  candidateEq, destinationLeader,
                  Ne.symm destinationLeader
                ] using pre.followerCommitsCovered candidate
      · intro queue message member
        cases found : newerMessage? state source destination with
        | none =>
            have oldMember : message ∈ state.network queue := by
              simpa [next, found] using member
            have bounded :=
              pre.queuedCommitBounded queue message oldMember
            simpa [next, found] using bounded
        | some selected =>
            have oldMember : message ∈ state.network queue := by
              simpa [next, found] using member
            have bounded :=
              pre.queuedCommitBounded queue message oldMember
            by_cases destinationLeader : destination = INITIAL_LEADER
            · subst destination
              simpa [
                next, found, updateNode, Function.update
              ] using bounded
            · simpa [
                next, found, updateNode, Function.update,
                Ne.symm destinationLeader
              ] using bounded
  | becomeLeader node =>
      exact
        SystemInductiveInvariant.crossTerm
          (becomeLeaderStartsCrossTerm state node pre enabled)

/-! ## Cross-term phase helpers -/

/-- The two represented leaders are distinct. -/
theorem crossTermLeadersDistinct
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix) :
    Not (INITIAL_LEADER = newLeader) :=
  facts.leadersDistinct

/-- Every current leader is one of the two history owners. -/
theorem crossTermLeaderCases
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    {node : Node}
    (role : (state.nodes node).role = .leader) :
    (node = INITIAL_LEADER /\
        (state.nodes node).currentTerm = TERM_ONE) \/
      (node = newLeader /\
        (state.nodes node).currentTerm = 2) := by
  rcases facts.leadersOwnHistories node role with old | new
  · exact Or.inl ⟨old.1, old.2.1⟩
  · exact Or.inr ⟨new.1, new.2.1⟩

/-- The frozen winning quorum prevents any other candidate majority. -/
theorem crossTermCandidateLacksMajority
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    {candidate : Node}
    (candidateRole : (state.nodes candidate).role = .candidate) :
    Not (hasElectionMajority state candidate) := by
  intro candidateMajority
  have intersection :=
    CCFRaft.fiveNodeMajoritiesIntersect
      (state.nodes candidate).votesGranted
      (state.nodes newLeader).votesGranted
      candidateMajority
      facts.electionMajority
  rcases intersection with ⟨voter, both⟩
  have candidateVote :=
    facts.votesGrantedSound candidate voter
      (Finset.mem_inter.mp both).1
  have leaderVote :=
    facts.electionVotersChooseLeader voter
      (Finset.mem_inter.mp both).2
  have candidateEq := Option.some.inj (candidateVote.symm.trans leaderVote)
  subst candidate
  exact Role.noConfusion (candidateRole.symm.trans facts.newLeaderRole)

/-- A term-one node cannot extend into the term-two suffix. -/
theorem currentTermOneLogPrefixOld
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    {node : Node}
    (current : (state.nodes node).currentTerm = TERM_ONE) :
    (state.nodes node).log <+: oldLog := by
  rcases facts.logsCovered node with old | new
  · exact old
  · have lengthWithin :
        (state.nodes node).log.length <= base.length := by
      by_contra beyond
      have indexBound :
          base.length + 1 <= (state.nodes node).log.length := by omega
      have elementBound :
          base.length < (state.nodes node).log.length := by omega
      let entry := (state.nodes node).log[base.length]
      have found :
          entryAt? (state.nodes node).log (base.length + 1) =
            some entry := by
        simp [
          entryAt?, entry,
          List.getElem?_eq_getElem elementBound]
      have foundNew :=
        entryAt_of_prefix new found
      have termTwo :
          entry.term = 2 :=
        appendedHistoryAfterBaseTermTwo
          facts.suffixEntriesTermTwo foundNew (by omega)
      have termBound :=
        facts.entriesDoNotExceedCurrentTerm node entry
          (entryAt_mem found)
      rw [current, termTwo, TERM_ONE] at termBound
      omega
    have baseNew : base <+: base ++ suffix :=
      List.prefix_append _ _
    have logTake :=
      CCFRaft.takeEqOfPrefix new (le_refl _)
    have baseTake :=
      CCFRaft.takeEqOfPrefix baseNew lengthWithin
    have logPrefixBase :
        (state.nodes node).log <+: base := by
      rw [List.prefix_iff_eq_take]
      simpa using logTake.trans baseTake.symm
    exact logPrefixBase.trans facts.basePrefixOld

/-- A covered log shorter than the base is already canonical. -/
theorem coveredLogWithinBasePrefixNew
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    {node : Node}
    (within : (state.nodes node).log.length <= base.length) :
    (state.nodes node).log <+: base ++ suffix := by
  rcases facts.logsCovered node with old | new
  · have baseTake :=
      CCFRaft.takeEqOfPrefix facts.basePrefixOld within
    have oldTake :=
      CCFRaft.takeEqOfPrefix old (le_refl _)
    have baseNewTake :=
      CCFRaft.takeEqOfPrefix
        (List.prefix_append base suffix) within
    rw [List.prefix_iff_eq_take]
    simpa using oldTake.trans (baseTake.symm.trans baseNewTake)
  · exact new

/-- Every represented entry inside the inherited base has term one. -/
theorem termAtCoveredWithinBase
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    {node : Node}
    {index : Nat}
    (positive : 0 < index)
    (logBound : index <= (state.nodes node).log.length)
    (baseBound : index <= base.length) :
    termAt (state.nodes node).log index = TERM_ONE := by
  rcases facts.logsCovered node with old | new
  · exact CCFRaft.termAtEqTermOne positive logBound
      (coveredByTermOne facts.oldEntriesTermOne old)
  · let entry := (state.nodes node).log[index - 1]
    have elementBound :
        index - 1 < (state.nodes node).log.length := by omega
    have found :
        entryAt? (state.nodes node).log index = some entry := by
      simp [
        entryAt?, positive.ne', entry,
        List.getElem?_eq_getElem elementBound]
    have foundNew := entryAt_of_prefix new found
    have termOne :=
      appendedHistoryWithinBaseTermOne
        facts.oldEntriesTermOne facts.basePrefixOld foundNew baseBound
    simpa [termAt, found] using termOne

/-- The canonical history reports term one at every nonzero base index. -/
theorem termAtNewWithinBase
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (basePrefix : base <+: oldLog)
    {index : Nat}
    (positive : 0 < index)
    (within : index <= base.length) :
    termAt (base ++ suffix) index = TERM_ONE := by
  have elementBound : index - 1 < (base ++ suffix).length := by
    simp
    omega
  let entry := (base ++ suffix)[index - 1]
  have found :
      entryAt? (base ++ suffix) index = some entry := by
    simp [
      entryAt?, positive.ne', entry,
      List.getElem?_eq_getElem elementBound]
  have termOne :=
    appendedHistoryWithinBaseTermOne
      oldTerms basePrefix found within
  simpa [termAt, found] using termOne

/-- The canonical history reports term two after the inherited base. -/
theorem termAtNewAfterBase
    {base suffix : List (Entry TxId)}
    (suffixTerms : EntriesHaveTerm 2 suffix)
    {index : Nat}
    (afterBase : base.length < index)
    (within : index <= (base ++ suffix).length) :
    termAt (base ++ suffix) index = 2 := by
  have positive : 0 < index := by omega
  have elementBound : index - 1 < (base ++ suffix).length := by omega
  let entry := (base ++ suffix)[index - 1]
  have found :
      entryAt? (base ++ suffix) index = some entry := by
    simp [
      entryAt?, positive.ne', entry,
      List.getElem?_eq_getElem elementBound]
  have termTwo :=
    appendedHistoryAfterBaseTermTwo suffixTerms found afterBase
  simpa [termAt, found] using termTwo

/-- A nonempty request beyond the base has term-two entries, not old terms. -/
theorem nonemptyNewRequestNotRepresentedByOld
    {oldLog base suffix log : List (Entry TxId)}
    {request : AppendEntriesRequest TxId}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (logOld : log <+: oldLog)
    (snapshot : RequestSnapshots (base ++ suffix) request)
    (afterBase : base.length <= request.prevLogIndex)
    (nonempty : Not (request.entries = []))
    (represented :
      ((log.drop request.prevLogIndex).take
          request.entries.length).map Entry.term =
        request.entries.map Entry.term) :
    False := by
  have split :=
    List.take_add
      (l := base ++ suffix)
      (i := request.prevLogIndex)
      (j := request.entries.length)
  have entriesEq :
      ((base ++ suffix).drop request.prevLogIndex).take
          request.entries.length =
        request.entries := by
    apply (List.append_right_inj
      ((base ++ suffix).take request.prevLogIndex)).mp
    exact split.symm.trans (requestSnapshotEntries snapshot)
  obtain ⟨entry, entryMember⟩ :=
    List.exists_mem_of_ne_nil request.entries nonempty
  have entryInCanonicalSlice :
      entry ∈
        ((base ++ suffix).drop request.prevLogIndex).take
          request.entries.length := by
    rw [entriesEq]
    exact entryMember
  have entryInCanonicalDrop :
      entry ∈ (base ++ suffix).drop request.prevLogIndex :=
    List.mem_of_mem_take entryInCanonicalSlice
  rw [List.drop_append] at entryInCanonicalDrop
  have baseDropEmpty :
      base.drop request.prevLogIndex = [] :=
    List.drop_eq_nil_of_le afterBase
  rw [baseDropEmpty] at entryInCanonicalDrop
  simp only [List.nil_append] at entryInCanonicalDrop
  have termTwo :
      entry.term = 2 :=
    suffixTerms entry (List.mem_of_mem_drop entryInCanonicalDrop)
  have requestTermMember :
      entry.term ∈ request.entries.map Entry.term :=
    List.mem_map.mpr ⟨entry, entryMember, rfl⟩
  rw [← represented] at requestTermMember
  rcases List.mem_map.mp requestTermMember with
    ⟨oldEntry, oldEntryMember, oldTermEq⟩
  have oldEntryInLog :
      oldEntry ∈ log :=
    List.mem_of_mem_drop (List.mem_of_mem_take oldEntryMember)
  have termOne :
      oldEntry.term = TERM_ONE :=
    oldTerms oldEntry (mem_of_prefix logOld oldEntryInLog)
  rw [termOne, termTwo, TERM_ONE] at oldTermEq
  omega

/-- A nonzero in-range entry of a covered log has one of the modeled terms. -/
theorem termAtValidOfCoveredLog
    {log oldLog base suffix : List (Entry TxId)}
    {index : Nat}
    (positive : 0 < index)
    (bounded : index <= log.length)
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    (covered : log <+: oldLog \/ log <+: base ++ suffix) :
    termAt log index = TERM_ONE \/ termAt log index = 2 := by
  unfold termAt entryAt?
  simp only [positive.ne', ↓reduceIte]
  rw [List.getElem?_eq_getElem (by omega)]
  simp only [Option.map_some, Option.getD_some]
  rcases covered with old | new
  · exact Or.inl
      (oldTerms _
        (mem_of_prefix old (List.getElem_mem (by omega))))
  · have member :
        log[index - 1] ∈ base ++ suffix :=
      mem_of_prefix new (List.getElem_mem (by omega))
    rcases List.mem_append.mp member with inBase | inSuffix
    · exact Or.inl
        (oldTerms _ (mem_of_prefix basePrefix inBase))
    · exact Or.inr (suffixTerms _ inSuffix)

/-- Failure responses generated from covered state carry a modeled term. -/
theorem failureResponseTermValid
    {state : State TxId}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (suffixTerms : EntriesHaveTerm 2 suffix)
    (basePrefix : base <+: oldLog)
    (covered :
      (state.nodes destination).log <+: oldLog \/
        (state.nodes destination).log <+: base ++ suffix)
    (current :
      (state.nodes destination).currentTerm = TERM_ONE \/
        (state.nodes destination).currentTerm = 2) :
    (failureResponse (state.nodes destination) request).term = TERM_ONE \/
      (failureResponse (state.nodes destination) request).term = 2 := by
  by_cases stale :
      request.term < (state.nodes destination).currentTerm
  · simpa [failureResponse, stale] using current
  · let previousTerm :=
      if request.prevLogIndex = 0 then
        0
      else if request.prevLogIndex >
          (state.nodes destination).log.length then
        0
      else
        termAt
          (state.nodes destination).log
          (state.nodes destination).log.length
    by_cases previousTermZero : previousTerm = 0
    · simpa [failureResponse, stale, previousTerm, previousTermZero] using
        current
    · let matchIndex :=
        findHighestPossibleMatch
          (state.nodes destination).log
          request.prevLogIndex request.prevLogTerm
      by_cases matchIndexZero : matchIndex = 0
      · simp [
          failureResponse, stale, previousTerm, previousTermZero,
          matchIndex, matchIndexZero]
      · have valid :
          termAt (state.nodes destination).log matchIndex = TERM_ONE \/
            termAt (state.nodes destination).log matchIndex = 2 := by
          apply termAtValidOfCoveredLog
          · omega
          · exact CCFRaft.findHighestPossibleMatchBoundedByLog
              (state.nodes destination).log
              request.prevLogIndex request.prevLogTerm
          · exact oldTerms
          · exact suffixTerms
          · exact basePrefix
          · exact covered
        simpa [
          failureResponse, stale, previousTerm, previousTermZero,
          matchIndex, matchIndexZero] using valid

/-- Every eligible searched index is below the NACK's highest match. -/
theorem findHighestPossibleMatchIncludes
    (log : List (Entry TxId))
    (index term candidate : Nat)
    (positive : 0 < candidate)
    (within : candidate <= min index log.length)
    (termBound : termAt log candidate <= term) :
    candidate <= findHighestPossibleMatch log index term := by
  unfold findHighestPossibleMatch
  let values := List.range (min index log.length + 1)
  let choose :=
    fun best current =>
      if current > 0 /\ termAt log current <= term then
        max best current
      else
        best
  have candidateMember : candidate ∈ values := by
    simp [values]
    omega
  have foldMonotonic :
      forall (candidates : List Nat) (best : Nat),
        best <= candidates.foldl choose best := by
    intro candidates
    induction candidates with
    | nil =>
        intro best
        exact le_refl _
    | cons head tail inductionHypothesis =>
        intro best
        apply le_trans ?_ (inductionHypothesis _)
        simp only [choose]
        split
        · exact Nat.le_max_left _ _
        · exact le_refl _
  have foldIncludes :
      forall (candidates : List Nat) (best : Nat),
        candidate ∈ candidates ->
          candidate <= candidates.foldl choose best := by
    intro candidates
    induction candidates with
    | nil =>
        intro best member
        simp at member
    | cons head tail inductionHypothesis =>
        intro best member
        simp only [List.mem_cons] at member
        rcases member with same | later
        · subst head
          have chosen :
              choose best candidate = max best candidate := by
            simp [choose, positive, termBound]
          rw [List.foldl_cons, chosen]
          exact (Nat.le_max_right _ _).trans (foldMonotonic _ _)
        · rw [List.foldl_cons]
          exact inductionHypothesis _ later
  change values.foldl choose 0 >= candidate
  exact foldIncludes values 0 candidateMember

/-- On the canonical log, a search below the base had a below-base input. -/
theorem canonicalSearchInsideBaseImpliesIndexInside
    {oldLog base suffix : List (Entry TxId)}
    (oldTerms : EntriesHaveTerm TERM_ONE oldLog)
    (basePrefix : base <+: oldLog)
    {index term : Nat}
    (termValid : term = TERM_ONE \/ term = 2)
    (searchInside :
      findHighestPossibleMatch (base ++ suffix) index term < base.length) :
    index < base.length := by
  by_contra notInside
  have baseWithinIndex : base.length <= index := by omega
  by_cases baseEmpty : base.length = 0
  · omega
  have basePositive : 0 < base.length := by omega
  have baseWithinNew : base.length <= (base ++ suffix).length := by simp
  have baseTerm :
      termAt (base ++ suffix) base.length = TERM_ONE :=
    termAtNewWithinBase
      oldTerms basePrefix basePositive (le_refl _)
  have termBound :
      termAt (base ++ suffix) base.length <= term := by
    rw [baseTerm]
    rcases termValid with one | two
    · rw [one]
    · rw [two, TERM_ONE]
      omega
  have included :=
    findHighestPossibleMatchIncludes
      (base ++ suffix) index term base.length basePositive
      (by simp [baseWithinIndex, baseWithinNew]) termBound
  omega

/-- Old request snapshots remain exact when their history is extended. -/
theorem requestSnapshotsAfterAppend
    {history : List (Entry TxId)}
    {entry : Entry TxId}
    {request : AppendEntriesRequest TxId}
    (snapshot : RequestSnapshots history request) :
    RequestSnapshots (history ++ [entry]) request := by
  rcases snapshot with
    ⟨endBound, previousTerm, entries⟩
  have previousBound :
      request.prevLogIndex <= history.length := by omega
  refine ⟨by simp; omega, ?_, ?_⟩
  · exact previousTerm.trans
      (CCFRaft.termAtAppendOfBound history entry previousBound).symm
  · rw [
      List.take_append_of_le_length endBound,
      List.take_append_of_le_length previousBound
    ]
    exact entries

/-- Queued messages remain safe when the old proof history is extended. -/
theorem networkSafeAfterOldAppend
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (entry : Entry TxId) :
    CrossTermNetworkSafe
      { state with
        nodes :=
          updateNode state.nodes INITIAL_LEADER
            { state.nodes INITIAL_LEADER with log := oldLog ++ [entry] } }
      INITIAL_LEADER newLeader (oldLog ++ [entry]) (base ++ suffix) base
      (state.nodes newLeader).votesGranted := by
  intro destination message member
  have oldSafe := facts.networkSafe destination message (by simpa using member)
  constructor
  · exact oldSafe.1
  · cases message with
    | appendEntriesRequest request =>
        rcases oldSafe.2 with
          ⟨different, history, advertised, emptyBound⟩
        rcases history with old | new
        · refine
            ⟨different,
              Or.inl
                ⟨old.1, old.2.1,
                  requestSnapshotsAfterAppend old.2.2.1,
                  by
                    simpa using Nat.le.step old.2.2.2⟩, ?_, emptyBound⟩
          simpa [
            old.1,
            List.take_append_of_le_length old.2.2.2
          ] using advertised
        · refine ⟨different, Or.inr new, ?_, emptyBound⟩
          intro termOne
          rw [new.1, TERM_ONE] at termOne
          omega
    | appendEntriesResponse response =>
        rcases oldSafe.2 with
          ⟨different, destinationLeader, term, success⟩
        refine ⟨different, destinationLeader, term, ?_⟩
        intro succeeded
        rcases success succeeded with old | new
        · left
          exact
            ⟨old.1, by simpa using Nat.le.step old.2.1, by
              simpa [facts.leadersDistinct] using old.2.2⟩
        · exact Or.inr new
    | requestVoteRequest request =>
        rcases oldSafe.2 with
          ⟨term, different, sourceTerm, sourceVote⟩
        refine ⟨term, different, ?_, ?_⟩
        · by_cases sourceEq : request.source = INITIAL_LEADER
          · rw [sourceEq] at sourceTerm ⊢
            simpa using sourceTerm
          · simpa [updateNode, Function.update, sourceEq] using sourceTerm
        · by_cases sourceEq : request.source = INITIAL_LEADER
          · rw [sourceEq] at sourceVote ⊢
            simpa using sourceVote
          · simpa [updateNode, Function.update, sourceEq] using sourceVote
    | requestVoteResponse response =>
        rcases oldSafe.2 with ⟨term, different, granted⟩
        refine ⟨term, different, ?_⟩
        intro success
        have vote := granted success
        by_cases sourceEq : response.source = INITIAL_LEADER
        · rw [sourceEq] at vote ⊢
          simpa using vote
        · simpa [updateNode, Function.update, sourceEq] using vote

/-- Queued messages remain safe when the term-two history is extended. -/
theorem networkSafeAfterNewAppend
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (entry : Entry TxId) :
    CrossTermNetworkSafe
      { state with
        nodes :=
          updateNode state.nodes newLeader
            { state.nodes newLeader with
              log := base ++ suffix ++ [entry] } }
      INITIAL_LEADER newLeader oldLog (base ++ suffix ++ [entry]) base
      (state.nodes newLeader).votesGranted := by
  intro destination message member
  have oldSafe := facts.networkSafe destination message (by simpa using member)
  constructor
  · exact oldSafe.1
  · cases message with
    | appendEntriesRequest request =>
        rcases oldSafe.2 with
          ⟨different, history, advertised, emptyBound⟩
        rcases history with old | new
        · refine ⟨different, Or.inl old, ?_, emptyBound⟩
          have advertised' :
              oldLog.take request.leaderCommit <+: base ++ suffix := by
            simpa [old.1] using advertised
          have extended :=
            advertised'.trans (List.prefix_append (base ++ suffix) [entry])
          simpa [old.1] using extended
        · refine
            ⟨different,
              Or.inr
                ⟨new.1, new.2.1,
                  requestSnapshotsAfterAppend new.2.2.1,
                  by
                    simpa [List.append_assoc] using
                      Nat.le.step new.2.2.2⟩, ?_, emptyBound⟩
          simpa [new.1, TERM_ONE, List.append_assoc] using
            (List.take_prefix request.leaderCommit
              (base ++ suffix ++ [entry]))
    | appendEntriesResponse response =>
        rcases oldSafe.2 with
          ⟨different, destinationLeader, term, success⟩
        refine ⟨different, destinationLeader, term, ?_⟩
        intro succeeded
        rcases success succeeded with old | new
        · exact Or.inl old
        · right
          exact
            ⟨new.1, by
              simpa [List.append_assoc] using Nat.le.step new.2⟩
    | requestVoteRequest request =>
        rcases oldSafe.2 with
          ⟨term, different, sourceTerm, sourceVote⟩
        refine ⟨term, different, ?_, ?_⟩
        · by_cases sourceEq : request.source = newLeader
          · rw [sourceEq] at sourceTerm ⊢
            simpa using sourceTerm
          · simpa [updateNode, Function.update, sourceEq] using sourceTerm
        · by_cases sourceEq : request.source = newLeader
          · rw [sourceEq] at sourceVote ⊢
            simpa using sourceVote
          · simpa [updateNode, Function.update, sourceEq] using sourceVote
    | requestVoteResponse response =>
        rcases oldSafe.2 with ⟨term, different, granted⟩
        refine ⟨term, different, ?_⟩
        intro success
        have vote := granted success
        by_cases sourceEq : response.source = newLeader
        · rw [sourceEq] at vote ⊢
          simpa using vote
        · simpa [updateNode, Function.update, sourceEq] using vote

/-! ## Cross-term action preservation -/

/-- A client append by either represented leader preserves both histories. -/
theorem clientRequestPreservesCrossTermInvariant
    (state : State TxId)
    (node : Node)
    (txId : TxId)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state (.clientRequest node txId)) :
    CrossTermInvariant (next state (.clientRequest node txId)) := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  let entry : Entry TxId :=
    { term := (state.nodes node).currentTerm, txId }
  rcases crossTermLeaderCases facts enabled.1 with old | new
  · rcases old with ⟨nodeEq, nodeTerm⟩
    subst node
    have oldLogEq :
        (state.nodes INITIAL_LEADER).log = oldLog :=
      facts.oldLeaderOwnsHistory enabled.1 nodeTerm
    refine
      ⟨newLeader, oldLog ++ [entry], base, suffix, ?_⟩
    constructor
    · intro value member
      simp at member
      rcases member with oldMember | newMember
      · exact facts.oldEntriesTermOne value oldMember
      · subst value
        exact nodeTerm
    · exact facts.suffixEntriesTermTwo
    · exact facts.basePrefixOld.trans (List.prefix_append _ _)
    · intro candidate
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        left
        simp [next, oldLogEq, entry]
      · rcases facts.logsCovered candidate with oldCovered | newCovered
        · left
          simpa [
            next, updateNode, Function.update, candidateEq
          ] using oldCovered.trans (List.prefix_append _ _)
        · right
          simpa [
            next, updateNode, Function.update, candidateEq
          ] using newCovered
    · intro candidate
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        simpa [next, oldLogEq] using
          Nat.le.step (facts.commitIndicesBounded INITIAL_LEADER)
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using facts.commitIndicesBounded candidate
    · intro candidate
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        simpa [next] using facts.currentTermsValid INITIAL_LEADER
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using facts.currentTermsValid candidate
    · intro candidate value member
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        simp [next, oldLogEq] at member
        rcases member with oldMember | newMember
        · have oldSafe :=
            facts.entriesDoNotExceedCurrentTerm
              INITIAL_LEADER value (by simpa [oldLogEq] using oldMember)
          simpa [next] using oldSafe
        · subst value
          simpa [entry, next] using
            Nat.le_refl (state.nodes INITIAL_LEADER).currentTerm
      · have oldSafe :=
          facts.entriesDoNotExceedCurrentTerm candidate value
            (by simpa [
                next, updateNode, Function.update, candidateEq
              ] using member)
        simpa [
          next, updateNode, Function.update, candidateEq
        ] using oldSafe
    · exact facts.leadersDistinct
    · simpa [
        next, updateNode, Function.update,
        Ne.symm facts.leadersDistinct
      ] using facts.newLeaderRole
    · intro candidate role
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        left
        exact
          ⟨rfl, by simpa [next] using nodeTerm,
            by simp [next, oldLogEq, entry]⟩
      · have beforeRole :
            (state.nodes candidate).role = .leader := by
          simpa [
            next, updateNode, Function.update, candidateEq
          ] using role
        rcases facts.leadersOwnHistories candidate beforeRole with
          oldOwner | newOwner
        · exact False.elim (candidateEq oldOwner.1)
        · right
          exact
            ⟨newOwner.1,
              by simpa [
                next, updateNode, Function.update, candidateEq
              ] using newOwner.2.1,
              by simpa [
                next, updateNode, Function.update, candidateEq
              ] using newOwner.2.2⟩
    · simpa [
        next, hasElectionMajority, updateNode, Function.update,
        Ne.symm facts.leadersDistinct
      ] using facts.electionMajority
    · intro candidate candidateRole
      have oldRole :
          (state.nodes candidate).role = .candidate := by
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          simpa [next] using candidateRole
        · simpa [
            next, updateNode, Function.update, candidateEq
          ] using candidateRole
      have self := facts.candidatesSelfVote candidate oldRole
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        simpa [next] using self
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using self
    · intro voter candidate voted
      have oldVote :
          (state.nodes voter).votedFor = some candidate := by
        by_cases voterEq : voter = INITIAL_LEADER
        · subst voter
          simpa [next] using voted
        · simpa [
            next, updateNode, Function.update, voterEq
          ] using voted
      have termTwo := facts.votedForTermTwo voter candidate oldVote
      by_cases voterEq : voter = INITIAL_LEADER
      · subst voter
        simpa [next] using termTwo
      · simpa [
          next, updateNode, Function.update, voterEq
        ] using termTwo
    · intro candidate voter voterIn
      have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          simpa [next] using voterIn
        · simpa [
            next, updateNode, Function.update, candidateEq
          ] using voterIn
      have chosen := facts.votesGrantedSound candidate voter oldIn
      by_cases voterEq : voter = INITIAL_LEADER
      · subst voter
        simpa [next] using chosen
      · simpa [
          next, updateNode, Function.update, voterEq
        ] using chosen
    · simpa [
        next, oldLogEq, entry,
        updateNode, Function.update,
        Ne.symm facts.leadersDistinct
      ] using
        networkSafeAfterOldAppend facts entry
    · intro leader role peer
      by_cases leaderEq : leader = INITIAL_LEADER
      · subst leader
        have oldProgress := facts.activeLeaderProgress enabled.1 peer
        constructor
        · simpa [next, oldLogEq] using Nat.le.step oldProgress.1
        · simpa [next, oldLogEq] using Nat.le.step oldProgress.2
      · have beforeRole :
            (state.nodes leader).role = .leader := by
          simpa [next, updateNode, Function.update, leaderEq] using role
        simpa [next, updateNode, Function.update, leaderEq] using
          facts.activeLeaderProgress beforeRole peer
    · intro voter voterIn
      have oldIn :
          voter ∈ (state.nodes newLeader).votesGranted := by
        simpa [
          next, updateNode, Function.update,
          Ne.symm facts.leadersDistinct
        ] using voterIn
      have bound := facts.oldElectionMatchBound voter oldIn
      simpa [next] using bound
    · intro candidate
      have covered := facts.committedLogsCovered candidate
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        have commitBoundOld :
            (state.nodes INITIAL_LEADER).commitIndex <= oldLog.length := by
          simpa [oldLogEq] using facts.commitIndicesBounded INITIAL_LEADER
        simpa [
          next, oldLogEq, NodeState.committedLog,
          List.take_append_of_le_length
            commitBoundOld,
          updateNode, Function.update,
          Ne.symm facts.leadersDistinct
        ] using covered
      · simpa [
          next, updateNode, Function.update,
          candidateEq, Ne.symm facts.leadersDistinct
        ] using covered
    · intro candidate belowBase
      have oldBelow :
          (state.nodes newLeader).sentIndex candidate < base.length := by
        simpa [
          next, updateNode, Function.update,
          Ne.symm facts.leadersDistinct
        ] using belowBase
      have safe := facts.newCatchupLogs candidate oldBelow
      by_cases candidateEq : candidate = INITIAL_LEADER
      · subst candidate
        rw [nodeTerm, TERM_ONE] at safe
        omega
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using safe
    · intro destination message member
      have oldMember : message ∈ state.network destination := by
        simpa [next] using member
      cases message with
      | appendEntriesRequest request =>
          have safe :=
            facts.queuedRequestTargetsSafe
              destination (.appendEntriesRequest request) oldMember
          intro termTwo previousInside
          have oldSafe := safe termTwo previousInside
          by_cases targetEq : request.destination = INITIAL_LEADER
          · rw [targetEq, nodeTerm, TERM_ONE] at oldSafe
            omega
          · simpa [
              next, updateNode, Function.update, targetEq
            ] using oldSafe
      | appendEntriesResponse _ => trivial
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
    · intro destination message member
      have oldMember : message ∈ state.network destination := by
        simpa [next] using member
      cases message with
      | appendEntriesRequest _ => trivial
      | appendEntriesResponse response =>
          have safe :=
            facts.queuedResponseCatchupSafe
              destination (.appendEntriesResponse response) oldMember
          intro responseDestination responseInside
          have oldSafe := safe responseDestination responseInside
          by_cases sourceEq : response.source = INITIAL_LEADER
          · rw [sourceEq, nodeTerm, TERM_ONE] at oldSafe
            omega
          · simpa [
              next, updateNode, Function.update, sourceEq
            ] using oldSafe
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
  · rcases new with ⟨nodeEq, nodeTerm⟩
    subst node
    have newLogEq :
        (state.nodes newLeader).log = base ++ suffix :=
      facts.newLeaderLog
    refine
      ⟨newLeader, oldLog, base, suffix ++ [entry], ?_⟩
    constructor
    · exact facts.oldEntriesTermOne
    · intro value member
      simp at member
      rcases member with oldMember | newMember
      · exact facts.suffixEntriesTermTwo value oldMember
      · subst value
        exact nodeTerm
    · exact facts.basePrefixOld
    · intro candidate
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        right
        simp [next, newLogEq, List.append_assoc, entry]
      · rcases facts.logsCovered candidate with oldCovered | newCovered
        · left
          simpa [
            next, updateNode, Function.update, candidateEq
          ] using oldCovered
        · right
          simpa [
            next, updateNode, Function.update, candidateEq,
            List.append_assoc
          ] using newCovered.trans (List.prefix_append _ _)
    · intro candidate
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        simpa [next, newLogEq, List.append_assoc] using
          Nat.le.step (facts.commitIndicesBounded newLeader)
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using facts.commitIndicesBounded candidate
    · intro candidate
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        simpa [next] using facts.currentTermsValid newLeader
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using facts.currentTermsValid candidate
    · intro candidate value member
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        have appendedMember :
            value ∈ (base ++ suffix) ++ [entry] := by
          simpa [next, newLogEq] using member
        rw [List.mem_append] at appendedMember
        rcases appendedMember with oldMember | newMember
        · have oldSafe :=
            facts.entriesDoNotExceedCurrentTerm
              newLeader value (by simpa [newLogEq] using oldMember)
          simpa [next] using oldSafe
        · simp at newMember
          subst value
          simpa [entry, next] using
            Nat.le_refl (state.nodes newLeader).currentTerm
      · have oldSafe :=
          facts.entriesDoNotExceedCurrentTerm candidate value
            (by simpa [
                next, updateNode, Function.update, candidateEq
              ] using member)
        simpa [
          next, updateNode, Function.update, candidateEq
        ] using oldSafe
    · exact facts.leadersDistinct
    · simpa [next] using facts.newLeaderRole
    · intro candidate role
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        right
        exact
          ⟨rfl, by simpa [next] using nodeTerm,
            by simp [next, newLogEq, List.append_assoc, entry]⟩
      · have beforeRole :
            (state.nodes candidate).role = .leader := by
          simpa [
            next, updateNode, Function.update, candidateEq
          ] using role
        rcases facts.leadersOwnHistories candidate beforeRole with
          oldOwner | newOwner
        · left
          exact
            ⟨oldOwner.1,
              by simpa [
                next, updateNode, Function.update, candidateEq
              ] using oldOwner.2.1,
              by simpa [
                next, updateNode, Function.update, candidateEq
              ] using oldOwner.2.2⟩
        · exact False.elim (candidateEq newOwner.1)
    · simpa [next, hasElectionMajority] using facts.electionMajority
    · intro candidate candidateRole
      have oldRole :
          (state.nodes candidate).role = .candidate := by
        by_cases candidateEq : candidate = newLeader
        · subst candidate
          simpa [next] using candidateRole
        · simpa [
            next, updateNode, Function.update, candidateEq
          ] using candidateRole
      have self := facts.candidatesSelfVote candidate oldRole
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        simpa [next] using self
      · simpa [
          next, updateNode, Function.update, candidateEq
        ] using self
    · intro voter candidate voted
      have oldVote :
          (state.nodes voter).votedFor = some candidate := by
        by_cases voterEq : voter = newLeader
        · subst voter
          simpa [next] using voted
        · simpa [
            next, updateNode, Function.update, voterEq
          ] using voted
      have termTwo := facts.votedForTermTwo voter candidate oldVote
      by_cases voterEq : voter = newLeader
      · subst voter
        simpa [next] using termTwo
      · simpa [
          next, updateNode, Function.update, voterEq
        ] using termTwo
    · intro candidate voter voterIn
      have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        by_cases candidateEq : candidate = newLeader
        · subst candidate
          simpa [next] using voterIn
        · simpa [
            next, updateNode, Function.update, candidateEq
          ] using voterIn
      have chosen := facts.votesGrantedSound candidate voter oldIn
      by_cases voterEq : voter = newLeader
      · subst voter
        simpa [next] using chosen
      · simpa [
          next, updateNode, Function.update, voterEq
        ] using chosen
    · simpa [next, newLogEq, entry, List.append_assoc] using
        networkSafeAfterNewAppend facts entry
    · intro leader role peer
      by_cases leaderEq : leader = newLeader
      · subst leader
        have oldProgress := facts.activeLeaderProgress enabled.1 peer
        constructor
        · simpa [next, newLogEq, List.append_assoc] using
            Nat.le.step oldProgress.1
        · simpa [next, newLogEq, List.append_assoc] using
            Nat.le.step oldProgress.2
      · have beforeRole :
            (state.nodes leader).role = .leader := by
          simpa [next, updateNode, Function.update, leaderEq] using role
        simpa [next, updateNode, Function.update, leaderEq] using
          facts.activeLeaderProgress beforeRole peer
    · intro voter voterIn
      have oldIn :
          voter ∈ (state.nodes newLeader).votesGranted := by
        simpa [next] using voterIn
      simpa [
        next, updateNode, Function.update, facts.leadersDistinct
      ] using facts.oldElectionMatchBound voter oldIn
    · intro candidate
      have covered := facts.committedLogsCovered candidate
      by_cases candidateEq : candidate = newLeader
      · subst candidate
        simpa [next, newLogEq, List.append_assoc] using
          (List.take_prefix
            (state.nodes newLeader).commitIndex
            ((state.nodes newLeader).log ++ [entry]))
      · have extended :=
          covered.trans
            (List.prefix_append (base ++ suffix) [entry])
        simpa [
          next, updateNode, Function.update, candidateEq,
          newLogEq, entry, List.append_assoc
        ] using extended
    · intro candidate belowBase
      have oldBelow :
          (state.nodes newLeader).sentIndex candidate < base.length := by
        simpa [next] using belowBase
      have safe := facts.newCatchupLogs candidate oldBelow
      constructor
      · by_cases candidateEq : candidate = newLeader
        · subst candidate
          simpa [next] using safe.1
        · simpa [
            next, updateNode, Function.update, candidateEq
          ] using safe.1
      · by_cases candidateEq : candidate = newLeader
        · subst candidate
          simp [next, newLogEq, entry, List.append_assoc]
        · have extended :=
            safe.2.trans
              (List.prefix_append (base ++ suffix) [entry])
          simpa [
            next, updateNode, Function.update, candidateEq,
            List.append_assoc
          ] using extended
    · intro destination message member
      have oldMember : message ∈ state.network destination := by
        simpa [next] using member
      cases message with
      | appendEntriesRequest request =>
          have safe :=
            facts.queuedRequestTargetsSafe
              destination (.appendEntriesRequest request) oldMember
          intro termTwo previousInside
          have oldSafe := safe termTwo previousInside
          constructor
          · by_cases targetEq : request.destination = newLeader
            · simpa [targetEq, next] using oldSafe.1
            · simpa [
                next, updateNode, Function.update, targetEq
              ] using oldSafe.1
          · by_cases targetEq : request.destination = newLeader
            · rw [targetEq]
              simp [next, newLogEq, entry, List.append_assoc]
            · have extended :=
                oldSafe.2.trans
                  (List.prefix_append (base ++ suffix) [entry])
              simpa [
                next, updateNode, Function.update, targetEq,
                List.append_assoc
              ] using extended
      | appendEntriesResponse _ => trivial
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
    · intro destination message member
      have oldMember : message ∈ state.network destination := by
        simpa [next] using member
      cases message with
      | appendEntriesRequest _ => trivial
      | appendEntriesResponse response =>
          have safe :=
            facts.queuedResponseCatchupSafe
              destination (.appendEntriesResponse response) oldMember
          intro responseDestination responseInside
          have oldSafe := safe responseDestination responseInside
          constructor
          · by_cases sourceEq : response.source = newLeader
            · simpa [sourceEq, next] using oldSafe.1
            · simpa [
                next, updateNode, Function.update, sourceEq
              ] using oldSafe.1
          · by_cases sourceEq : response.source = newLeader
            · rw [sourceEq]
              simp [next, newLogEq, entry, List.append_assoc]
            · have extended :=
                oldSafe.2.trans
                  (List.prefix_append (base ++ suffix) [entry])
              simpa [
                next, updateNode, Function.update, sourceEq,
                List.append_assoc
              ] using extended
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial

/-- An enabled one-entry send is an exact snapshot of its source history. -/
theorem makeAppendEntriesRequestSnapshots
    {state : State TxId}
    {source destination : Node}
    {batchEnd : Nat}
    {history : List (Entry TxId)}
    (logEq : (state.nodes source).log = history)
    (sentBound :
      (state.nodes source).sentIndex destination <= history.length)
    (batchEq :
      batchEnd =
        min
          ((state.nodes source).sentIndex destination + 1)
          (state.nodes source).log.length) :
    RequestSnapshots history
      (makeAppendEntriesRequest state source destination batchEnd) := by
  let previous := (state.nodes source).sentIndex destination
  have previousBeforeEnd : previous <= batchEnd := by
    rw [batchEq, logEq]
    simp [previous]
    omega
  have endWithin : batchEnd <= history.length := by
    rw [batchEq, logEq]
    exact min_le_right _ _
  have entriesLength :
      (messageEntries history previous batchEnd).length =
        batchEnd - previous :=
    CCFRaft.messageEntriesLength
      history previousBeforeEnd endWithin
  refine ⟨?_, ?_, ?_⟩
  · simp only [makeAppendEntriesRequest, logEq]
    rw [entriesLength]
    omega
  · simp [makeAppendEntriesRequest, logEq]
  · simp only [makeAppendEntriesRequest, logEq]
    change
      history.take
          (previous +
            (messageEntries history previous batchEnd).length) =
        history.take previous ++
          messageEntries history previous batchEnd
    rw [entriesLength]
    have sumEq : previous + (batchEnd - previous) = batchEnd := by
      omega
    simpa [messageEntries, sumEq] using
      (List.take_add
        (l := history)
        (i := previous)
        (j := batchEnd - previous))

/-- An empty enabled send can advertise no commit beyond its previous index. -/
theorem makeAppendEntriesRequestEmptyCommitBound
    {state : State TxId}
    {source destination : Node}
    {batchEnd : Nat}
    (sentBound :
      (state.nodes source).sentIndex destination <=
        (state.nodes source).log.length)
    (commitBound :
      (state.nodes source).commitIndex <=
        (state.nodes source).log.length)
    (batchEq :
      batchEnd =
        min
          ((state.nodes source).sentIndex destination + 1)
          (state.nodes source).log.length) :
    (makeAppendEntriesRequest state source destination batchEnd).entries = [] ->
      (makeAppendEntriesRequest state source destination batchEnd).leaderCommit <=
        (makeAppendEntriesRequest state source destination batchEnd).prevLogIndex := by
  intro entriesEmpty
  simp only [makeAppendEntriesRequest] at entriesEmpty ⊢
  by_cases sentAtEnd :
      (state.nodes source).sentIndex destination =
        (state.nodes source).log.length
  · simpa [sentAtEnd] using commitBound
  · have sentLt :
        (state.nodes source).sentIndex destination <
          (state.nodes source).log.length := by
      omega
    have endEq :
        batchEnd = (state.nodes source).sentIndex destination + 1 := by
      rw [batchEq]
      omega
    have lengths := congrArg List.length entriesEmpty
    simp [
      messageEntries, endEq, List.length_take, List.length_drop
    ] at lengths
    omega

/-- Sending changes only the source's `sentIndex` table. -/
structure AppendSendNodePost
    (before after : State TxId) : Prop where
  role : forall node, (after.nodes node).role = (before.nodes node).role
  currentTerm :
    forall node,
      (after.nodes node).currentTerm = (before.nodes node).currentTerm
  log : forall node, (after.nodes node).log = (before.nodes node).log
  commitIndex :
    forall node,
      (after.nodes node).commitIndex = (before.nodes node).commitIndex
  matchIndex :
    forall node,
      (after.nodes node).matchIndex = (before.nodes node).matchIndex
  votedFor :
    forall node,
      (after.nodes node).votedFor = (before.nodes node).votedFor
  votesGranted :
    forall node,
      (after.nodes node).votesGranted = (before.nodes node).votesGranted

/-- Local-state frame for an AppendEntries send. -/
theorem appendEntriesNodePost
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat) :
    AppendSendNodePost
      state (next state (.appendEntries source destination batchEnd)) := by
  constructor <;> intro node <;>
    by_cases nodeEq : node = source <;>
    simp [next, updateNode, Function.update, nodeEq]

/-- Sending from either current leader preserves the cross-term invariant. -/
theorem appendEntriesPreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    CrossTermInvariant
      (next state (.appendEntries source destination batchEnd)) := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  have post :=
    appendEntriesNodePost state source destination batchEnd
  rcases crossTermLeaderCases facts enabled.1 with old | new
  · rcases old with ⟨sourceEq, sourceTerm⟩
    subst source
    have oldLogEq :=
      facts.oldLeaderOwnsHistory enabled.1 sourceTerm
    let request :=
      makeAppendEntriesRequest state INITIAL_LEADER destination batchEnd
    have snapshot :
        RequestSnapshots oldLog request :=
      makeAppendEntriesRequestSnapshots
        oldLogEq
        (by simpa [oldLogEq] using
          (facts.activeLeaderProgress enabled.1 destination).1)
        enabled.2.2
    have commitBound :
        (state.nodes INITIAL_LEADER).commitIndex <= oldLog.length := by
      simpa [oldLogEq] using facts.commitIndicesBounded INITIAL_LEADER
    have advertised :
        oldLog.take (state.nodes INITIAL_LEADER).commitIndex <+:
          base ++ suffix := by
      have covered := facts.committedLogsCovered INITIAL_LEADER
      simpa [
        NodeState.committedLog, oldLogEq
      ] using covered
    have requestSafe :
        CrossTermRequestSafe
          INITIAL_LEADER newLeader oldLog (base ++ suffix) request := by
      refine
        ⟨enabled.2.1, Or.inl
          ⟨sourceTerm, rfl, snapshot, commitBound⟩, ?_, ?_⟩
      · intro _
        simpa [request, makeAppendEntriesRequest, sourceTerm] using advertised
      · exact makeAppendEntriesRequestEmptyCommitBound
          (by simpa [oldLogEq] using
            (facts.activeLeaderProgress enabled.1 destination).1)
          (facts.commitIndicesBounded INITIAL_LEADER)
          enabled.2.2
    refine ⟨newLeader, oldLog, base, suffix, ?_⟩
    constructor
    · exact facts.oldEntriesTermOne
    · exact facts.suffixEntriesTermTwo
    · exact facts.basePrefixOld
    · intro candidate
      rw [post.log candidate]
      exact facts.logsCovered candidate
    · intro candidate
      rw [post.commitIndex candidate, post.log candidate]
      exact facts.commitIndicesBounded candidate
    · intro candidate
      rw [post.currentTerm candidate]
      exact facts.currentTermsValid candidate
    · intro candidate entry member
      rw [post.log candidate] at member
      rw [post.currentTerm candidate]
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
    · exact facts.leadersDistinct
    · rw [post.role newLeader]
      exact facts.newLeaderRole
    · intro leader role
      rw [post.currentTerm leader, post.log leader]
      exact facts.leadersOwnHistories leader
        (by rwa [post.role leader] at role)
    · simpa [hasElectionMajority, post.votesGranted newLeader] using
        facts.electionMajority
    · intro candidate role
      rw [post.role candidate] at role
      rcases facts.candidatesSelfVote candidate role with
        ⟨term, vote, granted⟩
      rw [post.currentTerm candidate, post.votedFor candidate,
        post.votesGranted candidate]
      exact ⟨term, vote, granted⟩
    · intro voter candidate voted
      rw [post.votedFor voter] at voted
      rw [post.currentTerm voter]
      exact facts.votedForTermTwo voter candidate voted
    · intro candidate voter voterIn
      rw [post.votesGranted candidate] at voterIn
      rw [post.votedFor voter]
      exact facts.votesGrantedSound candidate voter voterIn
    · intro queue message member
      have cases :=
        CCFRaft.memEnqueueNoDup
          state.network (.appendEntriesRequest request)
          message queue (by simpa [next, request] using member)
      rcases cases with oldMember | ⟨queueEq, messageEq⟩
      · have oldSafe := facts.networkSafe queue message oldMember
        constructor
        · exact oldSafe.1
        · cases message with
          | appendEntriesRequest oldRequest => exact oldSafe.2
          | appendEntriesResponse response =>
              simpa [
                next, updateNode, Function.update,
                Ne.symm facts.leadersDistinct
              ] using oldSafe.2
          | requestVoteRequest voteRequest =>
              rcases oldSafe.2 with ⟨term, different, current, vote⟩
              refine ⟨term, different, ?_, ?_⟩
              · rw [post.currentTerm voteRequest.source]
                exact current
              · rw [post.votedFor voteRequest.source]
                exact vote
          | requestVoteResponse voteResponse =>
              rcases oldSafe.2 with ⟨term, different, granted⟩
              refine ⟨term, different, ?_⟩
              intro success
              rw [post.votedFor voteResponse.source]
              exact granted success
      · subst message
        exact ⟨queueEq.symm, requestSafe⟩
    · intro leader role peer
      have beforeRole :
          (state.nodes leader).role = .leader := by
        rwa [post.role leader] at role
      constructor
      · by_cases leaderEq : leader = INITIAL_LEADER
        · subst leader
          by_cases peerEq : peer = destination
          · subst peer
            simp only [next, updateNode_same, updateIndex_same]
            rw [enabled.2.2, oldLogEq]
            exact min_le_right _ _
          · simpa [
              next, updateNode, Function.update,
              updateIndex, peerEq
            ] using
              (facts.activeLeaderProgress beforeRole peer).1
        · simpa [
            next, updateNode, Function.update, leaderEq
          ] using (facts.activeLeaderProgress beforeRole peer).1
      · rw [post.matchIndex leader, post.log leader]
        exact (facts.activeLeaderProgress beforeRole peer).2
    · intro voter voterIn
      rw [post.votesGranted newLeader] at voterIn
      rw [post.matchIndex INITIAL_LEADER]
      exact facts.oldElectionMatchBound voter voterIn
    · intro candidate
      simp only [NodeState.committedLog]
      rw [post.log candidate, post.commitIndex candidate]
      exact facts.committedLogsCovered candidate
    · intro candidate belowBase
      have oldBelow :
          (state.nodes newLeader).sentIndex candidate < base.length := by
        simpa [
          next, updateNode, Function.update,
          Ne.symm facts.leadersDistinct
        ] using belowBase
      have safe := facts.newCatchupLogs candidate oldBelow
      simpa [post.currentTerm candidate, post.log candidate] using safe
    · intro queue message member
      have cases :=
        CCFRaft.memEnqueueNoDup
          state.network (.appendEntriesRequest request)
          message queue (by simpa [next] using member)
      rcases cases with oldMember | ⟨queueEq, messageEq⟩
      · cases message with
        | appendEntriesRequest oldRequest =>
            have safe :=
              facts.queuedRequestTargetsSafe
                queue (.appendEntriesRequest oldRequest) oldMember
            intro termTwo previousInside
            have oldSafe := safe termTwo previousInside
            constructor
            · rw [post.currentTerm oldRequest.destination]
              exact oldSafe.1
            · rw [post.log oldRequest.destination]
              exact oldSafe.2
        | appendEntriesResponse _ => trivial
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
      · subst message
        intro termTwo
        simp [
          request, makeAppendEntriesRequest,
          sourceTerm, TERM_ONE
        ] at termTwo
    · intro queue message member
      have cases :=
        CCFRaft.memEnqueueNoDup
          state.network (.appendEntriesRequest request)
          message queue (by simpa [next] using member)
      rcases cases with oldMember | ⟨queueEq, messageEq⟩
      · cases message with
        | appendEntriesRequest _ => trivial
        | appendEntriesResponse oldResponse =>
            have safe :=
              facts.queuedResponseCatchupSafe
                queue (.appendEntriesResponse oldResponse) oldMember
            intro responseDestination responseInside
            have oldSafe := safe responseDestination responseInside
            constructor
            · rw [post.currentTerm oldResponse.source]
              exact oldSafe.1
            · rw [post.log oldResponse.source]
              exact oldSafe.2
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
      · subst message
        trivial
  · rcases new with ⟨sourceEq, sourceTerm⟩
    subst source
    have newLogEq := facts.newLeaderLog
    let request :=
      makeAppendEntriesRequest state newLeader destination batchEnd
    have snapshot :
        RequestSnapshots (base ++ suffix) request :=
      makeAppendEntriesRequestSnapshots
        newLogEq
        (by simpa [newLogEq] using
          (facts.activeLeaderProgress enabled.1 destination).1)
        enabled.2.2
    have commitBound :
        (state.nodes newLeader).commitIndex <=
          (base ++ suffix).length := by
      simpa [newLogEq] using facts.commitIndicesBounded newLeader
    have requestSafe :
        CrossTermRequestSafe
          INITIAL_LEADER newLeader oldLog (base ++ suffix) request := by
      refine
        ⟨enabled.2.1, Or.inr
          ⟨sourceTerm, rfl, snapshot, commitBound⟩, ?_, ?_⟩
      · intro requestTerm
        have termOne :
            (state.nodes newLeader).currentTerm = TERM_ONE := by
          simpa [request, makeAppendEntriesRequest] using requestTerm
        rw [sourceTerm] at termOne
        norm_num [TERM_ONE] at termOne
      · exact makeAppendEntriesRequestEmptyCommitBound
          (by
            simpa [newLogEq] using
              (facts.activeLeaderProgress enabled.1 destination).1)
          (facts.commitIndicesBounded newLeader)
          enabled.2.2
    refine ⟨newLeader, oldLog, base, suffix, ?_⟩
    constructor
    · exact facts.oldEntriesTermOne
    · exact facts.suffixEntriesTermTwo
    · exact facts.basePrefixOld
    · intro candidate
      rw [post.log candidate]
      exact facts.logsCovered candidate
    · intro candidate
      rw [post.commitIndex candidate, post.log candidate]
      exact facts.commitIndicesBounded candidate
    · intro candidate
      rw [post.currentTerm candidate]
      exact facts.currentTermsValid candidate
    · intro candidate entry member
      rw [post.log candidate] at member
      rw [post.currentTerm candidate]
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
    · exact facts.leadersDistinct
    · rw [post.role newLeader]
      exact facts.newLeaderRole
    · intro leader role
      rw [post.currentTerm leader, post.log leader]
      exact facts.leadersOwnHistories leader
        (by rwa [post.role leader] at role)
    · simpa [hasElectionMajority, post.votesGranted newLeader] using
        facts.electionMajority
    · intro candidate role
      rw [post.role candidate] at role
      rcases facts.candidatesSelfVote candidate role with
        ⟨term, vote, granted⟩
      rw [post.currentTerm candidate, post.votedFor candidate,
        post.votesGranted candidate]
      exact ⟨term, vote, granted⟩
    · intro voter candidate voted
      rw [post.votedFor voter] at voted
      rw [post.currentTerm voter]
      exact facts.votedForTermTwo voter candidate voted
    · intro candidate voter voterIn
      rw [post.votesGranted candidate] at voterIn
      rw [post.votedFor voter]
      exact facts.votesGrantedSound candidate voter voterIn
    · intro queue message member
      have cases :=
        CCFRaft.memEnqueueNoDup
          state.network (.appendEntriesRequest request)
          message queue (by simpa [next, request] using member)
      rcases cases with oldMember | ⟨queueEq, messageEq⟩
      · have oldSafe := facts.networkSafe queue message oldMember
        constructor
        · exact oldSafe.1
        · cases message with
          | appendEntriesRequest oldRequest => exact oldSafe.2
          | appendEntriesResponse response =>
              simpa [next] using oldSafe.2
          | requestVoteRequest voteRequest =>
              rcases oldSafe.2 with ⟨term, different, current, vote⟩
              refine ⟨term, different, ?_, ?_⟩
              · rw [post.currentTerm voteRequest.source]
                exact current
              · rw [post.votedFor voteRequest.source]
                exact vote
          | requestVoteResponse voteResponse =>
              rcases oldSafe.2 with ⟨term, different, granted⟩
              refine ⟨term, different, ?_⟩
              intro success
              rw [post.votedFor voteResponse.source]
              exact granted success
      · subst message
        exact ⟨queueEq.symm, requestSafe⟩
    · intro leader role peer
      have beforeRole :
          (state.nodes leader).role = .leader := by
        rwa [post.role leader] at role
      constructor
      · by_cases leaderEq : leader = newLeader
        · subst leader
          by_cases peerEq : peer = destination
          · subst peer
            simp only [next, updateNode_same, updateIndex_same]
            rw [enabled.2.2, newLogEq]
            exact min_le_right _ _
          · simpa [
              next, updateNode, Function.update,
              updateIndex, peerEq
            ] using
              (facts.activeLeaderProgress beforeRole peer).1
        · simpa [
            next, updateNode, Function.update, leaderEq
          ] using (facts.activeLeaderProgress beforeRole peer).1
      · rw [post.matchIndex leader, post.log leader]
        exact (facts.activeLeaderProgress beforeRole peer).2
    · intro voter voterIn
      rw [post.votesGranted newLeader] at voterIn
      rw [post.matchIndex INITIAL_LEADER]
      exact facts.oldElectionMatchBound voter voterIn
    · intro candidate
      simp only [NodeState.committedLog]
      rw [post.log candidate, post.commitIndex candidate]
      exact facts.committedLogsCovered candidate
    · intro candidate belowBase
      have oldBelow :
          (state.nodes newLeader).sentIndex candidate < base.length := by
        by_cases candidateEq : candidate = destination
        · subst candidate
          have sentBound :=
            (facts.activeLeaderProgress enabled.1 destination).1
          have baseWithin :
              base.length <= (state.nodes newLeader).log.length := by
            rw [newLogEq]
            simp
          simp [next, updateNode_same, updateIndex_same] at belowBase
          rw [enabled.2.2] at belowBase
          omega
        · simpa [
            next, updateNode, Function.update,
            updateIndex, candidateEq
          ] using belowBase
      have safe := facts.newCatchupLogs candidate oldBelow
      simpa [post.currentTerm candidate, post.log candidate] using safe
    · intro queue message member
      have cases :=
        CCFRaft.memEnqueueNoDup
          state.network (.appendEntriesRequest request)
          message queue (by simpa [next] using member)
      rcases cases with oldMember | ⟨queueEq, messageEq⟩
      · cases message with
        | appendEntriesRequest oldRequest =>
            have safe :=
              facts.queuedRequestTargetsSafe
                queue (.appendEntriesRequest oldRequest) oldMember
            intro termTwo previousInside
            have oldSafe := safe termTwo previousInside
            constructor
            · rw [post.currentTerm oldRequest.destination]
              exact oldSafe.1
            · rw [post.log oldRequest.destination]
              exact oldSafe.2
        | appendEntriesResponse _ => trivial
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
      · subst message
        intro requestTerm previousInside
        have oldSafe :=
          facts.newCatchupLogs destination (by
            simpa [request, makeAppendEntriesRequest] using previousInside)
        have requestDestination : request.destination = destination := by
          simp [request, makeAppendEntriesRequest]
        constructor
        · rw [requestDestination, post.currentTerm destination]
          exact oldSafe.1
        · rw [requestDestination, post.log destination]
          exact oldSafe.2
    · intro queue message member
      have cases :=
        CCFRaft.memEnqueueNoDup
          state.network (.appendEntriesRequest request)
          message queue (by simpa [next] using member)
      rcases cases with oldMember | ⟨queueEq, messageEq⟩
      · cases message with
        | appendEntriesRequest _ => trivial
        | appendEntriesResponse oldResponse =>
            have safe :=
              facts.queuedResponseCatchupSafe
                queue (.appendEntriesResponse oldResponse) oldMember
            intro responseDestination responseInside
            have oldSafe := safe responseDestination responseInside
            constructor
            · rw [post.currentTerm oldResponse.source]
              exact oldSafe.1
            · rw [post.log oldResponse.source]
              exact oldSafe.2
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
      · subst message
        trivial

/-- Advancing commit changes no log, role, term, or replication evidence. -/
structure CommitAdvanceNodePost
    (before after : State TxId) : Prop where
  role : forall node, (after.nodes node).role = (before.nodes node).role
  currentTerm :
    forall node,
      (after.nodes node).currentTerm = (before.nodes node).currentTerm
  log : forall node, (after.nodes node).log = (before.nodes node).log
  sentIndex :
    forall node,
      (after.nodes node).sentIndex = (before.nodes node).sentIndex
  matchIndex :
    forall node,
      (after.nodes node).matchIndex = (before.nodes node).matchIndex
  votedFor :
    forall node,
      (after.nodes node).votedFor = (before.nodes node).votedFor
  votesGranted :
    forall node,
      (after.nodes node).votesGranted = (before.nodes node).votesGranted

/-- Local-state frame for commit advancement. -/
theorem advanceCommitNodePost
    (state : State TxId)
    (node : Node) :
    CommitAdvanceNodePost
      state (next state (.advanceCommitIndex node)) := by
  constructor <;> intro candidate <;>
    by_cases candidateEq : candidate = node <;>
    simp [next, updateNode, Function.update, candidateEq]

/-- Advancing either leader's current-term frontier preserves the invariant. -/
theorem advanceCommitPreservesCrossTermInvariant
    (state : State TxId)
    (node : Node)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state (.advanceCommitIndex node)) :
    CrossTermInvariant (next state (.advanceCommitIndex node)) := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  have post := advanceCommitNodePost state node
  have highestBound :=
    CCFRaft.highestCommittableIndexBounded state node
  have highestValid :=
    CCFRaft.highestCommittableIndexValid state node enabled.2
  have nodeCommitCovered :
      ((next state (.advanceCommitIndex node)).nodes node).committedLog <+:
        base ++ suffix := by
    rcases crossTermLeaderCases facts enabled.1 with old | new
    · rcases old with ⟨nodeEq, nodeTerm⟩
      subst node
      have oldLogEq :=
        facts.oldLeaderOwnsHistory enabled.1 nodeTerm
      have oldBound :
          highestCommittableIndex state INITIAL_LEADER <= oldLog.length := by
        simpa [oldLogEq] using highestBound
      have baseBound :
          highestCommittableIndex state INITIAL_LEADER <= base.length :=
        activeInitialLeaderMajorityCovered
          facts enabled.1 nodeTerm highestValid.2
      have oldTakeBase :
          oldLog.take (highestCommittableIndex state INITIAL_LEADER) =
            base.take (highestCommittableIndex state INITIAL_LEADER) :=
        (CCFRaft.takeEqOfPrefix facts.basePrefixOld baseBound).symm
      have newTakeBase :
          (base ++ suffix).take
              (highestCommittableIndex state INITIAL_LEADER) =
            base.take (highestCommittableIndex state INITIAL_LEADER) :=
        List.take_append_of_le_length baseBound
      have historyPrefix :
          oldLog.take (highestCommittableIndex state INITIAL_LEADER) <+:
            base ++ suffix := by
        rw [oldTakeBase, ← newTakeBase]
        exact List.take_prefix _ _
      simpa [
        next, oldLogEq,
        NodeState.committedLog
      ] using historyPrefix
    · rcases new with ⟨nodeEq, _⟩
      subst node
      simpa [next, facts.newLeaderLog, NodeState.committedLog] using
        (List.take_prefix
          (highestCommittableIndex state newLeader)
          (state.nodes newLeader).log)
  have afterCommitBounded :
      CommitIndicesBounded
        (next state (.advanceCommitIndex node)) := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simpa [next] using highestBound
    · simpa [
        next, updateNode, Function.update, candidateEq
      ] using facts.commitIndicesBounded candidate
  have afterCommittedCovered :
      forall candidate,
        ((next state (.advanceCommitIndex node)).nodes candidate).committedLog <+:
          base ++ suffix := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      exact nodeCommitCovered
    · have covered := facts.committedLogsCovered candidate
      simp only [NodeState.committedLog]
      rw [post.log candidate]
      simpa [
        next, updateNode, Function.update, candidateEq
      ] using covered
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  constructor
  · exact facts.oldEntriesTermOne
  · exact facts.suffixEntriesTermTwo
  · exact facts.basePrefixOld
  · intro candidate
    rw [post.log candidate]
    exact facts.logsCovered candidate
  · exact afterCommitBounded
  · intro candidate
    rw [post.currentTerm candidate]
    exact facts.currentTermsValid candidate
  · intro candidate entry member
    rw [post.log candidate] at member
    rw [post.currentTerm candidate]
    exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · exact facts.leadersDistinct
  · rw [post.role newLeader]
    exact facts.newLeaderRole
  · intro leader role
    rw [post.currentTerm leader, post.log leader]
    exact facts.leadersOwnHistories leader
      (by rwa [post.role leader] at role)
  · simpa [hasElectionMajority, post.votesGranted newLeader] using
      facts.electionMajority
  · intro candidate role
    rw [post.role candidate] at role
    rcases facts.candidatesSelfVote candidate role with
      ⟨term, vote, granted⟩
    rw [post.currentTerm candidate, post.votedFor candidate,
      post.votesGranted candidate]
    exact ⟨term, vote, granted⟩
  · intro voter candidate voted
    rw [post.votedFor voter] at voted
    rw [post.currentTerm voter]
    exact facts.votedForTermTwo voter candidate voted
  · intro candidate voter voterIn
    rw [post.votesGranted candidate] at voterIn
    rw [post.votedFor voter]
    exact facts.votesGrantedSound candidate voter voterIn
  · intro destination message member
    have oldSafe := facts.networkSafe destination message (by
      simpa [next] using member)
    constructor
    · exact oldSafe.1
    · cases message with
      | appendEntriesRequest request => exact oldSafe.2
      | appendEntriesResponse response =>
          rw [post.votesGranted newLeader]
          exact oldSafe.2
      | requestVoteRequest request =>
          rcases oldSafe.2 with ⟨term, different, current, vote⟩
          refine ⟨term, different, ?_, ?_⟩
          · rw [post.currentTerm request.source]
            exact current
          · rw [post.votedFor request.source]
            exact vote
      | requestVoteResponse response =>
          rcases oldSafe.2 with ⟨term, different, granted⟩
          refine ⟨term, different, ?_⟩
          intro success
          rw [post.votedFor response.source]
          exact granted success
  · intro leader role peer
    have beforeRole :
        (state.nodes leader).role = .leader := by
      rwa [post.role leader] at role
    rw [post.sentIndex leader, post.matchIndex leader, post.log leader]
    exact facts.activeLeaderProgress beforeRole peer
  · intro voter voterIn
    rw [post.votesGranted newLeader] at voterIn
    rw [post.matchIndex INITIAL_LEADER]
    exact facts.oldElectionMatchBound voter voterIn
  · exact afterCommittedCovered
  · intro candidate belowBase
    rw [post.sentIndex newLeader] at belowBase
    have safe := facts.newCatchupLogs candidate belowBase
    constructor
    · rw [post.currentTerm candidate]
      exact safe.1
    · rw [post.log candidate]
      exact safe.2
  · intro destination message member
    have oldMember : message ∈ state.network destination := by
      simpa [next] using member
    cases message with
    | appendEntriesRequest request =>
        have safe :=
          facts.queuedRequestTargetsSafe
            destination (.appendEntriesRequest request) oldMember
        intro termTwo previousInside
        have oldSafe := safe termTwo previousInside
        constructor
        · rw [post.currentTerm request.destination]
          exact oldSafe.1
        · rw [post.log request.destination]
          exact oldSafe.2
    | appendEntriesResponse _ => trivial
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial
  · intro destination message member
    have oldMember : message ∈ state.network destination := by
      simpa [next] using member
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse response =>
        have safe :=
          facts.queuedResponseCatchupSafe
            destination (.appendEntriesResponse response) oldMember
        intro responseDestination responseInside
        have oldSafe := safe responseDestination responseInside
        constructor
        · rw [post.currentTerm response.source]
          exact oldSafe.1
        · rw [post.log response.source]
          exact oldSafe.2
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial

/-- Sending RequestVote changes only the network and preserves the histories. -/
theorem requestVotePreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state (.requestVote source destination)) :
    CrossTermInvariant (next state (.requestVote source destination)) := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  let request := makeRequestVoteRequest state source destination
  have selfVote := facts.candidatesSelfVote source enabled.1
  have requestSafe : CrossTermVoteRequestSafe state request :=
    ⟨enabled.2.1, enabled.2.2, enabled.2.1, selfVote.2.1⟩
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  refine
    { facts with
      networkSafe := ?_
      queuedRequestTargetsSafe := ?_
      queuedResponseCatchupSafe := ?_ }
  · intro queue message member
    have cases :=
      CCFRaft.memEnqueueNoDup
        state.network (.requestVoteRequest request)
        message queue (by simpa [next, request] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · simpa [next] using facts.networkSafe queue message oldMember
    · subst message
      exact ⟨queueEq.symm, requestSafe⟩
  · intro queue message member
    have cases :=
      CCFRaft.memEnqueueNoDup
        state.network (.requestVoteRequest request)
        message queue (by simpa [next, request] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · simpa [next] using
        facts.queuedRequestTargetsSafe queue message oldMember
    · subst message
      trivial
  · intro queue message member
    have cases :=
      CCFRaft.memEnqueueNoDup
        state.network (.requestVoteRequest request)
        message queue (by simpa [next, request] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · simpa [next] using
        facts.queuedResponseCatchupSafe queue message oldMember
    · subst message
      trivial

/-- Starting another term-two candidacy cannot disturb the elected leader. -/
theorem timeoutPreservesCrossTermInvariant
    (state : State TxId)
    (node : Node)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state (.timeout node)) :
    CrossTermInvariant (next state (.timeout node)) := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  have nodeNeNew : Not (node = newLeader) := by
    intro nodeEq
    subst node
    exact Role.noConfusion (enabled.1.symm.trans facts.newLeaderRole)
  have nodeNotElectionVoter :
      node ∉ (state.nodes newLeader).votesGranted := by
    intro voterIn
    have chosen := facts.electionVotersChooseLeader node voterIn
    have termTwo := facts.votedForTermTwo node newLeader chosen
    rw [enabled.2, TERM_ONE] at termTwo
    omega
  have oldMatchEq :
      ((next state (.timeout node)).nodes INITIAL_LEADER).matchIndex =
        (state.nodes INITIAL_LEADER).matchIndex := by
    by_cases oldEq : INITIAL_LEADER = node <;>
      simp [next, updateNode, Function.update, oldEq]
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  constructor
  · exact facts.oldEntriesTermOne
  · exact facts.suffixEntriesTermTwo
  · exact facts.basePrefixOld
  · intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simpa [next] using facts.logsCovered node
    · simpa [
        next, updateNode, Function.update, candidateEq
      ] using facts.logsCovered candidate
  · intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simpa [next] using facts.commitIndicesBounded node
    · simpa [
        next, updateNode, Function.update, candidateEq
      ] using facts.commitIndicesBounded candidate
  · intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      exact Or.inr (by simp [next, enabled.2, TERM_ONE])
    · simpa [
        next, updateNode, Function.update, candidateEq
      ] using facts.currentTermsValid candidate
  · intro candidate entry member
    by_cases candidateEq : candidate = node
    · subst candidate
      have oldSafe :=
        facts.entriesDoNotExceedCurrentTerm node entry
          (by simpa [next] using member)
      have oldSafeOne : entry.term <= TERM_ONE := by
        simpa [enabled.2] using oldSafe
      have oldSafeOne' : entry.term <= 1 := by
        simpa [TERM_ONE] using oldSafeOne
      have safeTwo : entry.term <= 2 := by omega
      simpa [next, enabled.2, TERM_ONE] using
        safeTwo
    · have oldMember :
          entry ∈ (state.nodes candidate).log := by
        simpa [
          next, updateNode, Function.update, candidateEq
        ] using member
      have oldSafe :=
        facts.entriesDoNotExceedCurrentTerm candidate entry oldMember
      simpa [
        next, updateNode, Function.update, candidateEq
      ] using oldSafe
  · exact facts.leadersDistinct
  · simpa [
      next, updateNode, Function.update, Ne.symm nodeNeNew
    ] using facts.newLeaderRole
  · intro leader role
    by_cases leaderEq : leader = node
    · subst leader
      simp [next] at role
    · have beforeRole :
          (state.nodes leader).role = .leader := by
        simpa [
          next, updateNode, Function.update, leaderEq
        ] using role
      simpa [
        next, updateNode, Function.update, leaderEq
      ] using facts.leadersOwnHistories leader beforeRole
  · simpa [
      next, hasElectionMajority, updateNode, Function.update,
      Ne.symm nodeNeNew
    ] using facts.electionMajority
  · intro candidate role
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next, enabled.2, TERM_ONE]
    · have oldRole :
          (state.nodes candidate).role = .candidate := by
        simpa [
          next, updateNode, Function.update, candidateEq
        ] using role
      have self := facts.candidatesSelfVote candidate oldRole
      simpa [
        next, updateNode, Function.update, candidateEq
      ] using self
  · intro voter candidate voted
    by_cases voterEq : voter = node
    · subst voter
      simp [next] at voted
      subst candidate
      simp [next, enabled.2, TERM_ONE]
    · have oldVote :
          (state.nodes voter).votedFor = some candidate := by
        simpa [
          next, updateNode, Function.update, voterEq
        ] using voted
      have termTwo := facts.votedForTermTwo voter candidate oldVote
      simpa [
        next, updateNode, Function.update, voterEq
      ] using termTwo
  · intro candidate voter voterIn
    by_cases candidateEq : candidate = node
    · subst candidate
      simp [next] at voterIn
      subst voter
      simp [next]
    · have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [
          next, updateNode, Function.update, candidateEq
        ] using voterIn
      have chosen := facts.votesGrantedSound candidate voter oldIn
      by_cases voterEq : voter = node
      · subst voter
        have termTwo := facts.votedForTermTwo node candidate chosen
        rw [enabled.2, TERM_ONE] at termTwo
        omega
      · simpa [
          next, updateNode, Function.update, voterEq
        ] using chosen
  · intro destination message member
    have oldSafe := facts.networkSafe destination message (by
      simpa [next] using member)
    constructor
    · exact oldSafe.1
    · cases message with
      | appendEntriesRequest request => exact oldSafe.2
      | appendEntriesResponse response =>
          simpa [
            next, updateNode, Function.update, Ne.symm nodeNeNew
          ] using oldSafe.2
      | requestVoteRequest request =>
          rcases oldSafe.2 with ⟨term, different, current, vote⟩
          by_cases sourceEq : request.source = node
          · rw [sourceEq] at current
            rw [enabled.2] at current
            simp [TERM_ONE] at current
          · refine ⟨term, different, ?_, ?_⟩
            · simpa [
                next, updateNode, Function.update, sourceEq
              ] using current
            · simpa [
                next, updateNode, Function.update, sourceEq
              ] using vote
      | requestVoteResponse response =>
          rcases oldSafe.2 with ⟨term, different, granted⟩
          refine ⟨term, different, ?_⟩
          intro success
          have chosen := granted success
          by_cases sourceEq : response.source = node
          · rw [sourceEq] at chosen
            have termTwo :=
              facts.votedForTermTwo node response.destination chosen
            rw [enabled.2, TERM_ONE] at termTwo
            omega
          · simpa [
              next, updateNode, Function.update, sourceEq
            ] using chosen
  · intro leader role peer
    by_cases leaderEq : leader = node
    · subst leader
      simp [next] at role
    · have beforeRole :
          (state.nodes leader).role = .leader := by
        simpa [
          next, updateNode, Function.update, leaderEq
        ] using role
      simpa [
        next, updateNode, Function.update, leaderEq
      ] using facts.activeLeaderProgress beforeRole peer
  · intro voter voterIn
    have oldIn :
        voter ∈ (state.nodes newLeader).votesGranted := by
      simpa [
        next, updateNode, Function.update, Ne.symm nodeNeNew
      ] using voterIn
    rw [oldMatchEq]
    exact facts.oldElectionMatchBound voter oldIn
  · intro candidate
    have covered := facts.committedLogsCovered candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simpa [
        next, NodeState.committedLog,
        updateNode, Function.update, Ne.symm nodeNeNew
      ] using covered
    · simpa [
        next, NodeState.committedLog,
        updateNode, Function.update,
        candidateEq, Ne.symm nodeNeNew
      ] using covered
  · intro candidate belowBase
    have oldBelow :
        (state.nodes newLeader).sentIndex candidate < base.length := by
      simpa [
        next, updateNode, Function.update, Ne.symm nodeNeNew
      ] using belowBase
    have safe := facts.newCatchupLogs candidate oldBelow
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [enabled.2, TERM_ONE] at safe
      omega
    · simpa [
        next, updateNode, Function.update, candidateEq
      ] using safe
  · intro destination message member
    have oldMember : message ∈ state.network destination := by
      simpa [next] using member
    cases message with
    | appendEntriesRequest request =>
        have safe :=
          facts.queuedRequestTargetsSafe
            destination (.appendEntriesRequest request) oldMember
        intro termTwo previousInside
        have oldSafe := safe termTwo previousInside
        by_cases targetEq : request.destination = node
        · rw [targetEq, enabled.2, TERM_ONE] at oldSafe
          omega
        · simpa [
            next, updateNode, Function.update, targetEq
          ] using oldSafe
    | appendEntriesResponse _ => trivial
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial
  · intro destination message member
    have oldMember : message ∈ state.network destination := by
      simpa [next] using member
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse response =>
        have safe :=
          facts.queuedResponseCatchupSafe
            destination (.appendEntriesResponse response) oldMember
        intro responseDestination responseInside
        have oldSafe := safe responseDestination responseInside
        by_cases sourceEq : response.source = node
        · rw [sourceEq, enabled.2, TERM_ONE] at oldSafe
          omega
        · simpa [
            next, updateNode, Function.update, sourceEq
          ] using oldSafe
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial

/-- Observing a newer queued term can only move a term-one node to term two. -/
theorem updateTermPreservesCrossTermInvariant
      (state : State TxId)
      (source destination : Node)
      (cross : CrossTermInvariant state)
      (enabled : Enabled state (.updateTerm source destination)) :
      CrossTermInvariant (next state (.updateTerm source destination)) := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  cases found : newerMessage? state source destination with
  | none =>
        simp [Enabled, found] at enabled
  | some selected =>
        have selectedSound := CCFRaft.newerMessageSound found
        rcases selectedSound with ⟨remaining, taken, newer⟩
        have takenSound := CCFRaft.takeFirstFromSound taken
        have selectedNetworkSafe :=
          facts.networkSafe destination selected takenSound.2.1
        have selectedTermValid :
            selected.term = TERM_ONE \/ selected.term = 2 := by
          cases selected with
          | appendEntriesRequest request =>
              rcases selectedNetworkSafe.2.2.1 with old | new
              · exact Or.inl old.1
              · exact Or.inr new.1
          | appendEntriesResponse response =>
              exact selectedNetworkSafe.2.2.2.1
          | requestVoteRequest request =>
              exact Or.inr selectedNetworkSafe.2.1
          | requestVoteResponse response =>
              exact Or.inr selectedNetworkSafe.2.1
        have destinationTermOne :
            (state.nodes destination).currentTerm = TERM_ONE := by
          rcases facts.currentTermsValid destination with currentOne | currentTwo
          · exact currentOne
          · rcases selectedTermValid with selectedOne | selectedTwo
            · rw [currentTwo, selectedOne, TERM_ONE] at newer
              omega
            · rw [currentTwo, selectedTwo] at newer
              omega
        have selectedTermTwo : selected.term = 2 := by
          rcases selectedTermValid with selectedOne | selectedTwo
          · rw [destinationTermOne, selectedOne] at newer
            omega
          · exact selectedTwo
        have destinationNeNew : Not (destination = newLeader) := by
          intro destinationEq
          subst destination
          rw [facts.newLeaderTerm, selectedTermTwo] at newer
          omega
        have destinationNotElectionVoter :
            destination ∉ (state.nodes newLeader).votesGranted := by
          intro voterIn
          have chosen :=
            facts.electionVotersChooseLeader destination voterIn
          have termTwo :=
            facts.votedForTermTwo destination newLeader chosen
          rw [destinationTermOne, TERM_ONE] at termTwo
          omega
        have oldMatchEq :
            ((next state (.updateTerm source destination)).nodes
                INITIAL_LEADER).matchIndex =
              (state.nodes INITIAL_LEADER).matchIndex := by
          by_cases oldEq : INITIAL_LEADER = destination <;>
            simp [next, found, updateNode, Function.update, oldEq]
        refine ⟨newLeader, oldLog, base, suffix, ?_⟩
        constructor
        · exact facts.oldEntriesTermOne
        · exact facts.suffixEntriesTermTwo
        · exact facts.basePrefixOld
        · intro candidate
          by_cases candidateEq : candidate = destination
          · subst candidate
            simpa [next, found] using facts.logsCovered destination
          · simpa [
              next, found, updateNode, Function.update, candidateEq
            ] using facts.logsCovered candidate
        · intro candidate
          by_cases candidateEq : candidate = destination
          · subst candidate
            simpa [next, found] using
              facts.commitIndicesBounded destination
          · simpa [
              next, found, updateNode, Function.update, candidateEq
            ] using facts.commitIndicesBounded candidate
        · intro candidate
          by_cases candidateEq : candidate = destination
          · subst candidate
            exact Or.inr (by simp [next, found, selectedTermTwo])
          · simpa [
              next, found, updateNode, Function.update, candidateEq
            ] using facts.currentTermsValid candidate
        · intro candidate entry member
          by_cases candidateEq : candidate = destination
          · subst candidate
            have oldSafe :=
              facts.entriesDoNotExceedCurrentTerm destination entry
                (by simpa [next, found] using member)
            have oldSafeOne : entry.term <= TERM_ONE := by
              simpa [destinationTermOne] using oldSafe
            have oldSafeOne' : entry.term <= 1 := by
              simpa [TERM_ONE] using oldSafeOne
            have safeTwo : entry.term <= 2 := by omega
            simpa [next, found, selectedTermTwo] using safeTwo
          · have oldMember :
                entry ∈ (state.nodes candidate).log := by
              simpa [
                next, found, updateNode, Function.update, candidateEq
              ] using member
            have oldSafe :=
              facts.entriesDoNotExceedCurrentTerm candidate entry oldMember
            simpa [
              next, found, updateNode, Function.update, candidateEq
            ] using oldSafe
        · exact facts.leadersDistinct
        · simpa [
            next, found, updateNode, Function.update,
            Ne.symm destinationNeNew
          ] using facts.newLeaderRole
        · intro leader role
          by_cases leaderEq : leader = destination
          · subst leader
            simp [next, found] at role
          · have beforeRole :
                (state.nodes leader).role = .leader := by
              simpa [
                next, found, updateNode, Function.update, leaderEq
              ] using role
            simpa [
              next, found, updateNode, Function.update, leaderEq
            ] using facts.leadersOwnHistories leader beforeRole
        · simpa [
            next, found, hasElectionMajority,
            updateNode, Function.update,
            Ne.symm destinationNeNew
          ] using facts.electionMajority
        · intro candidate role
          by_cases candidateEq : candidate = destination
          · subst candidate
            simp [next, found] at role
          · have oldRole :
                (state.nodes candidate).role = .candidate := by
              simpa [
                next, found, updateNode, Function.update, candidateEq
              ] using role
            have self := facts.candidatesSelfVote candidate oldRole
            simpa [
              next, found, updateNode, Function.update, candidateEq
            ] using self
        · intro voter candidate voted
          by_cases voterEq : voter = destination
          · subst voter
            simp [next, found] at voted
          · have oldVote :
                (state.nodes voter).votedFor = some candidate := by
              simpa [
                next, found, updateNode, Function.update, voterEq
              ] using voted
            have termTwo := facts.votedForTermTwo voter candidate oldVote
            simpa [
              next, found, updateNode, Function.update, voterEq
            ] using termTwo
        · intro candidate voter voterIn
          have oldIn :
              voter ∈ (state.nodes candidate).votesGranted := by
            by_cases candidateEq : candidate = destination
            · subst candidate
              simpa [next, found] using voterIn
            · simpa [
                next, found, updateNode, Function.update, candidateEq
              ] using voterIn
          have chosen := facts.votesGrantedSound candidate voter oldIn
          by_cases voterEq : voter = destination
          · subst voter
            have termTwo :=
              facts.votedForTermTwo destination candidate chosen
            rw [destinationTermOne, TERM_ONE] at termTwo
            omega
          · simpa [
              next, found, updateNode, Function.update, voterEq
            ] using chosen
        · intro queue message member
          have oldSafe := facts.networkSafe queue message (by
            simpa [next, found] using member)
          constructor
          · exact oldSafe.1
          · cases message with
            | appendEntriesRequest request => exact oldSafe.2
            | appendEntriesResponse response =>
                simpa [
                  next, found, updateNode, Function.update,
                  Ne.symm destinationNeNew
                ] using oldSafe.2
            | requestVoteRequest request =>
                rcases oldSafe.2 with ⟨term, different, current, vote⟩
                by_cases sourceEq : request.source = destination
                · rw [sourceEq] at current
                  rw [destinationTermOne] at current
                  simp [TERM_ONE] at current
                · refine ⟨term, different, ?_, ?_⟩
                  · simpa [
                      next, found, updateNode, Function.update, sourceEq
                    ] using current
                  · simpa [
                      next, found, updateNode, Function.update, sourceEq
                    ] using vote
            | requestVoteResponse response =>
                rcases oldSafe.2 with ⟨term, different, granted⟩
                refine ⟨term, different, ?_⟩
                intro success
                have chosen := granted success
                by_cases sourceEq : response.source = destination
                · rw [sourceEq] at chosen
                  have termTwo :=
                    facts.votedForTermTwo
                      destination response.destination chosen
                  rw [destinationTermOne, TERM_ONE] at termTwo
                  omega
                · simpa [
                    next, found, updateNode, Function.update, sourceEq
                  ] using chosen
        · intro leader role peer
          by_cases leaderEq : leader = destination
          · subst leader
            simp [next, found] at role
          · have beforeRole :
                (state.nodes leader).role = .leader := by
              simpa [
                next, found, updateNode, Function.update, leaderEq
              ] using role
            simpa [
              next, found, updateNode, Function.update, leaderEq
            ] using facts.activeLeaderProgress beforeRole peer
        · intro voter voterIn
          have oldIn :
              voter ∈ (state.nodes newLeader).votesGranted := by
            simpa [
              next, found, updateNode, Function.update,
              Ne.symm destinationNeNew
            ] using voterIn
          rw [oldMatchEq]
          exact facts.oldElectionMatchBound voter oldIn
        · intro candidate
          have covered := facts.committedLogsCovered candidate
          by_cases candidateEq : candidate = destination
          · subst candidate
            simpa [
              next, found, NodeState.committedLog,
              updateNode, Function.update, Ne.symm destinationNeNew
            ] using covered
          · simpa [
              next, found, NodeState.committedLog,
              updateNode, Function.update,
              candidateEq, Ne.symm destinationNeNew
            ] using covered
        · intro candidate belowBase
          have oldBelow :
              (state.nodes newLeader).sentIndex candidate < base.length := by
            simpa [
              next, found, updateNode, Function.update,
              Ne.symm destinationNeNew
            ] using belowBase
          have safe := facts.newCatchupLogs candidate oldBelow
          by_cases candidateEq : candidate = destination
          · subst candidate
            rw [destinationTermOne, TERM_ONE] at safe
            omega
          · simpa [
              next, found, updateNode, Function.update, candidateEq
            ] using safe
        · intro queue message member
          have oldMember : message ∈ state.network queue := by
            simpa [next, found] using member
          cases message with
          | appendEntriesRequest request =>
              have safe :=
                facts.queuedRequestTargetsSafe
                  queue (.appendEntriesRequest request) oldMember
              intro termTwo previousInside
              have oldSafe := safe termTwo previousInside
              by_cases targetEq : request.destination = destination
              · rw [targetEq, destinationTermOne, TERM_ONE] at oldSafe
                omega
              · simpa [
                  next, found, updateNode, Function.update, targetEq
                ] using oldSafe
          | appendEntriesResponse _ => trivial
          | requestVoteRequest _ => trivial
          | requestVoteResponse _ => trivial
        · intro queue message member
          have oldMember : message ∈ state.network queue := by
            simpa [next, found] using member
          cases message with
          | appendEntriesRequest _ => trivial
          | appendEntriesResponse response =>
              have safe :=
                facts.queuedResponseCatchupSafe
                  queue (.appendEntriesResponse response) oldMember
              intro responseDestination responseInside
              have oldSafe := safe responseDestination responseInside
              by_cases sourceEq : response.source = destination
              · rw [sourceEq, destinationTermOne, TERM_ONE] at oldSafe
                omega
              · simpa [
                  next, found, updateNode, Function.update, sourceEq
                ] using oldSafe
          | requestVoteRequest _ => trivial
          | requestVoteResponse _ => trivial

/-- A changed destination log follows the selected request history. -/
theorem handledAppendRequestChangedLogPrefix
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    {history : List (Entry TxId)}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (historyChoice :
      history = oldLog \/ history = base ++ suffix)
    (snapshot : RequestSnapshots history request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response))
    (unchanged : Not (after.log = (state.nodes destination).log))
    (previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length)
    (previousMatches :
      request.prevLogIndex = 0 \/
        termAt (state.nodes destination).log request.prevLogIndex =
          request.prevLogTerm) :
    after.log <+: history := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  have historyCovered :
      (history <+: oldLog \/ history <+: base ++ suffix) := by
    rcases historyChoice with old | new
    · subst history
      exact Or.inl (prefixRefl _)
    · subst history
      exact Or.inr (prefixRefl _)
  have previousTake :
      (state.nodes destination).log.take request.prevLogIndex =
        history.take request.prevLogIndex := by
    rcases previousMatches with zero | matching
    · simp [zero]
    · by_cases zero : request.prevLogIndex = 0
      · simp [zero]
      · apply coveredHistoriesTakeEqualAtTerm
        · omega
        · exact previousBound
        · exact requestSnapshotPreviousBound snapshot
        · exact facts.oldEntriesTermOne
        · exact facts.suffixEntriesTermTwo
        · exact facts.basePrefixOld
        · exact facts.logsCovered destination
        · exact historyCovered
        · exact matching.trans (requestSnapshotPreviousTerm snapshot)
  have requestPrefix :
      history.take request.prevLogIndex ++ request.entries <+:
        history := by
    rw [← requestSnapshotEntries snapshot]
    exact List.take_prefix _ _
  rcases localPost.logShape with same | truncated | extended
  · exact False.elim (unchanged same)
  · rw [truncated, previousTake]
    exact List.take_prefix _ _
  · rw [extended, previousTake]
    exact requestPrefix

/-- A changed destination log follows one of the two proof histories. -/
theorem handledAppendRequestChangedLogCovered
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response))
    (unchanged : Not (after.log = (state.nodes destination).log))
    (previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length)
    (previousMatches :
      request.prevLogIndex = 0 \/
        termAt (state.nodes destination).log request.prevLogIndex =
          request.prevLogTerm) :
    (after.log <+: oldLog \/ after.log <+: base ++ suffix) := by
  rcases safe.2.1 with old | new
  · exact Or.inl
      (handledAppendRequestChangedLogPrefix
        facts (Or.inl rfl) old.2.2.1 handled
          unchanged previousBound previousMatches)
  · exact Or.inr
      (handledAppendRequestChangedLogPrefix
        facts (Or.inr rfl) new.2.2.1 handled
          unchanged previousBound previousMatches)

/-- A handled safe request leaves the destination log on one proof history. -/
theorem handledAppendRequestLogCovered
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    (after.log <+: oldLog \/ after.log <+: base ++ suffix) := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  rcases localPost.logUnchangedOrPreviousBound with unchanged | previousBound
  · simpa [unchanged] using facts.logsCovered destination
  · rcases localPost.logUnchangedOrPreviousMatches with unchanged | previousMatches
    · simpa [unchanged] using facts.logsCovered destination
    · by_cases same : after.log = (state.nodes destination).log
      · simpa [same] using facts.logsCovered destination
      · exact handledAppendRequestChangedLogCovered
          facts safe handled same previousBound previousMatches

/-- Applying a safe queued request preserves the canonical committed prefix. -/
theorem handledAppendRequestCommittedCovered
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (targetSafe :
      CrossTermRequestTargetSafe
        state (base ++ suffix) base request)
    (requestDestination : request.destination = destination)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    after.committedLog <+: base ++ suffix := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  have beforeBound := facts.commitIndicesBounded destination
  have afterBound :
      after.commitIndex <= after.log.length :=
    localPost.commitIndexBounded beforeBound
  have beforeCommittedSafe := facts.committedLogsCovered destination
  by_cases noAdvance :
      after.commitIndex <= (state.nodes destination).commitIndex
  · have withinOld :
        after.commitIndex <=
          (state.nodes destination).committedLog.length := by
      simpa [
        NodeState.committedLog, List.length_take,
        Nat.min_eq_left beforeBound
      ] using noAdvance
    have equality :=
      CCFRaft.takeEqOfPrefix
        localPost.previousCommittedPrefix withinOld
    unfold NodeState.committedLog
    rw [← equality]
    exact (List.take_prefix _ _).trans beforeCommittedSafe
  · have advanced :
        (state.nodes destination).commitIndex < after.commitIndex := by
      omega
    have succeeded : response.success = true :=
      localPost.commitAdvancedSuccessful advanced
    have learnedBound :
        after.commitIndex <= request.leaderCommit := by
      rcases (le_max_iff.mp localPost.commitUpperBound) with old | learned
      · omega
      · exact learned
    have currentRequest :
        request.term = (state.nodes destination).currentTerm :=
      localPost.successfulCurrentTerm succeeded
    have prefixThroughLeaderCommit
        {history : List (Entry TxId)}
        (logPrefix : after.log <+: history) :
        after.committedLog <+: history.take request.leaderCommit := by
      have equality :=
        CCFRaft.takeEqOfPrefix logPrefix afterBound
      unfold NodeState.committedLog
      rw [equality, List.prefix_take_iff]
      constructor
      · exact List.take_prefix _ _
      · simp only [List.length_take]
        omega
    rcases safe.2.1 with old | new
    · have destinationTermOne :
          (state.nodes destination).currentTerm = TERM_ONE := by
        exact currentRequest.symm.trans old.1
      have afterLogOld : after.log <+: oldLog := by
        by_cases same : after.log = (state.nodes destination).log
        · rw [same]
          exact currentTermOneLogPrefixOld facts destinationTermOne
        · exact handledAppendRequestChangedLogPrefix
            facts (Or.inl rfl) old.2.2.1 handled same
              (localPost.logUnchangedOrPreviousBound.resolve_left same)
              (localPost.logUnchangedOrPreviousMatches.resolve_left same)
      have learnedPrefix :=
        prefixThroughLeaderCommit afterLogOld
      exact learnedPrefix.trans (by
        simpa [old.1] using safe.2.2.1 old.1)
    · have afterPrefixNewOrThrough :
          after.committedLog <+: base ++ suffix := by
        by_cases same : after.log = (state.nodes destination).log
        · by_cases previousInside :
              request.prevLogIndex < base.length
          · have target := targetSafe new.1 previousInside
            have afterLogNew : after.log <+: base ++ suffix := by
              simpa [same, requestDestination] using target.2
            exact
              (prefixThroughLeaderCommit afterLogNew).trans
                (List.take_prefix _ _)
          · have afterBase :
                base.length <= request.prevLogIndex := by omega
            by_cases empty : request.entries = []
            · have leaderWithinPrevious :
                  request.leaderCommit <= request.prevLogIndex :=
                safe.2.2.2 empty
              have previousTake :
                  (state.nodes destination).log.take request.prevLogIndex =
                    (base ++ suffix).take request.prevLogIndex := by
                rcases localPost.successfulLogOk succeeded with zero | present
                · simp [zero]
                · apply coveredHistoriesTakeEqualAtTerm
                  · omega
                  · exact present.1
                  · exact requestSnapshotPreviousBound new.2.2.1
                  · exact facts.oldEntriesTermOne
                  · exact facts.suffixEntriesTermTwo
                  · exact facts.basePrefixOld
                  · exact facts.logsCovered destination
                  · exact Or.inr (prefixRefl _)
                  · exact present.2.trans
                      (requestSnapshotPreviousTerm new.2.2.1)
              unfold NodeState.committedLog
              rw [same]
              have toPrevious :
                  (state.nodes destination).log.take after.commitIndex <+:
                    (state.nodes destination).log.take
                      request.prevLogIndex := by
                rw [List.prefix_take_iff]
                constructor
                · exact List.take_prefix _ _
                · simp only [List.length_take]
                  omega
              exact toPrevious.trans <|
                previousTake ▸ List.take_prefix request.prevLogIndex
                  (base ++ suffix)
            · have beforeLogNew :
                  (state.nodes destination).log <+: base ++ suffix := by
                rcases facts.logsCovered destination with oldCovered | newCovered
                · exact False.elim
                    (nonemptyNewRequestNotRepresentedByOld
                      facts.oldEntriesTermOne
                      facts.suffixEntriesTermTwo
                      oldCovered new.2.2.1 afterBase empty
                      (localPost.successfulUnchangedEntryTerms
                        succeeded same))
                · exact newCovered
              have afterLogNew : after.log <+: base ++ suffix := by
                simpa [same] using beforeLogNew
              exact
                (prefixThroughLeaderCommit afterLogNew).trans
                  (List.take_prefix _ _)
        · have afterLogNew :=
            handledAppendRequestChangedLogPrefix
              facts (Or.inr rfl) new.2.2.1 handled same
                (localPost.logUnchangedOrPreviousBound.resolve_left same)
                (localPost.logUnchangedOrPreviousMatches.resolve_left same)
          exact
            (prefixThroughLeaderCommit afterLogNew).trans
              (List.take_prefix _ _)
      exact afterPrefixNewOrThrough

/-- A generated AppendEntries response carries safe routing and index data. -/
theorem handledAppendRequestResponseSafe
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (requestDestination : request.destination = destination)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    CrossTermResponseSafe
      INITIAL_LEADER newLeader oldLog (base ++ suffix) base
        (state.nodes newLeader).votesGranted response := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro same
    apply safe.1
    rw [localPost.responseSource, localPost.responseDestination] at same
    exact same.symm
  · rcases safe.2.1 with old | new
    · exact Or.inl (by
        rw [localPost.responseDestination]
        exact old.2.1)
    · exact Or.inr (by
        rw [localPost.responseDestination]
        exact new.2.1)
  · by_cases succeeded : response.success = true
    · have responseTerm := localPost.successfulResponseTerm succeeded
      have requestCurrent := localPost.successfulCurrentTerm succeeded
      rw [responseTerm, ← requestCurrent]
      rcases safe.2.1 with old | new
      · exact Or.inl old.1
      · exact Or.inr new.1
    · have failed : response.success = false := by
        exact Bool.eq_false_of_not_eq_true succeeded
      rw [localPost.failedResponse failed]
      exact failureResponseTermValid
        facts.oldEntriesTermOne
        facts.suffixEntriesTermTwo
        facts.basePrefixOld
        (facts.logsCovered destination)
        (facts.currentTermsValid destination)
  · intro succeeded
    have indexBound := localPost.successfulIndexBound succeeded
    rcases safe.2.1 with old | new
    · left
      refine
        ⟨by
            rw [localPost.responseDestination]
            exact old.2.1,
          indexBound.trans
            (requestSnapshotEndBound old.2.2.1), ?_⟩
      intro voterIn
      have sourceCurrentTwo :
          (state.nodes response.source).currentTerm = 2 := by
        have chosen :=
          facts.electionVotersChooseLeader response.source voterIn
        exact facts.votedForTermTwo response.source newLeader chosen
      have responseSource : response.source = destination := by
        rw [localPost.responseSource, requestDestination]
      have requestCurrent := localPost.successfulCurrentTerm succeeded
      rw [responseSource] at sourceCurrentTwo
      rw [old.1, sourceCurrentTwo] at requestCurrent
      simp [TERM_ONE] at requestCurrent
    · exact Or.inr
        ⟨by
            rw [localPost.responseDestination]
            exact new.2.1,
          indexBound.trans
            (requestSnapshotEndBound new.2.2.1)⟩

/-- A generated response which can lower catch-up remains canonical. -/
theorem handledAppendRequestResponseCatchupSafe
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (targetSafe :
      CrossTermRequestTargetSafe
        state (base ++ suffix) base request)
    (requestDestination : request.destination = destination)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    CrossTermResponseCatchupSafe
      { state with
        nodes := updateNode state.nodes destination after }
      newLeader (base ++ suffix) base response := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  intro responseDestination lastInside
  have requestSource : request.source = newLeader := by
    rw [localPost.responseDestination] at responseDestination
    exact responseDestination
  have requestNew :
      request.term = 2 /\
        request.source = newLeader /\
        RequestSnapshots (base ++ suffix) request /\
        request.leaderCommit <= (base ++ suffix).length := by
    rcases safe.2.1 with old | new
    · exact False.elim
        (facts.leadersDistinct (old.2.1.symm.trans requestSource))
    · exact new
  have responseSource : response.source = destination := by
    rw [localPost.responseSource, requestDestination]
  by_cases succeeded : response.success = true
  · have indexExact := localPost.successfulIndexExact succeeded
    have previousInside : request.prevLogIndex < base.length := by
      omega
    have target := targetSafe requestNew.1 previousInside
    have afterCurrent :
        after.currentTerm = 2 := by
      rw [localPost.currentTermUnchanged]
      simpa [requestDestination] using target.1
    have afterLog : after.log <+: base ++ suffix := by
      by_cases same : after.log = (state.nodes destination).log
      · simpa [same, requestDestination] using target.2
      · exact handledAppendRequestChangedLogPrefix
          facts (Or.inr rfl) requestNew.2.2.1 handled same
            (localPost.logUnchangedOrPreviousBound.resolve_left same)
            (localPost.logUnchangedOrPreviousMatches.resolve_left same)
    rw [responseSource]
    simp [updateNode, afterCurrent, afterLog]
  · have failed : response.success = false :=
      Bool.eq_false_of_not_eq_true succeeded
    have unchanged := localPost.failedStateUnchanged failed
    have requestCurrentLe :=
      localPost.failedRequestNotNewer failed
    have destinationCurrentTwo :
        (state.nodes destination).currentTerm = 2 := by
      rcases facts.currentTermsValid destination with one | two
      · rw [requestNew.1, one, TERM_ONE] at requestCurrentLe
        omega
      · exact two
    have beforeLogNew :
        (state.nodes destination).log <+: base ++ suffix := by
      by_cases previousInside :
          request.prevLogIndex < base.length
      · simpa [requestDestination] using
          (targetSafe requestNew.1 previousInside).2
      · have afterBase :
            base.length <= request.prevLogIndex := by omega
        have logShort :
            (state.nodes destination).log.length < base.length := by
          by_contra notShort
          have baseWithinLog :
              base.length <= (state.nodes destination).log.length := by omega
          have failureInside :
              (failureResponse
                (state.nodes destination) request).lastLogIndex <
                  base.length := by
            rw [← localPost.failedResponse failed]
            exact lastInside
          by_cases previousZero : request.prevLogIndex = 0
          · omega
          have previousPositive : 0 < request.prevLogIndex := by omega
          by_cases previousPast :
              request.prevLogIndex >
                (state.nodes destination).log.length
          · simp [
              failureResponse, requestNew.1, destinationCurrentTwo,
              previousZero, previousPast
            ] at failureInside
            omega
          have previousBound :
              request.prevLogIndex <=
                (state.nodes destination).log.length := by omega
          have logNonempty :
              Not ((state.nodes destination).log = []) := by
            exact List.ne_nil_of_length_pos (by omega)
          have lastTermValid :=
            termAtValidOfCoveredLog
              (List.length_pos_iff_ne_nil.mpr logNonempty)
              (le_refl _)
              facts.oldEntriesTermOne
              facts.suffixEntriesTermTwo
              facts.basePrefixOld
              (facts.logsCovered destination)
          have lastTermNonzero :
              Not (
                termAt
                  (state.nodes destination).log
                  (state.nodes destination).log.length = 0) := by
            rcases lastTermValid with one | two
            · rw [one, TERM_ONE]
              omega
            · omega
          by_cases previousAtBase :
              request.prevLogIndex = base.length
          · have localTerm :
                termAt (state.nodes destination).log
                  request.prevLogIndex = TERM_ONE := by
              apply termAtCoveredWithinBase facts
              · exact previousPositive
              · exact previousBound
              · omega
            have requestTerm :
                request.prevLogTerm = TERM_ONE := by
              rw [requestSnapshotPreviousTerm requestNew.2.2.1]
              exact termAtNewWithinBase
                facts.oldEntriesTermOne facts.basePrefixOld
                previousPositive (by omega)
            have logOk : logOk (state.nodes destination) request :=
              Or.inr
                ⟨previousBound, localTerm.trans requestTerm.symm⟩
            exact
              (localPost.failedSameTermNotLogOk failed
                (requestNew.1.trans destinationCurrentTwo.symm)) logOk
          · have previousAfterBase :
                base.length < request.prevLogIndex := by omega
            have requestedPreviousTerm :
                request.prevLogTerm = 2 := by
              rw [requestSnapshotPreviousTerm requestNew.2.2.1]
              exact termAtNewAfterBase
                facts.suffixEntriesTermTwo previousAfterBase
                (requestSnapshotPreviousBound requestNew.2.2.1)
            have localPreviousTermValid :=
              termAtValidOfCoveredLog
                previousPositive previousBound
                facts.oldEntriesTermOne
                facts.suffixEntriesTermTwo
                facts.basePrefixOld
                (facts.logsCovered destination)
            have localPreviousTermBound :
                termAt (state.nodes destination).log
                    request.prevLogIndex <= request.prevLogTerm := by
              rw [requestedPreviousTerm]
              rcases localPreviousTermValid with one | two
              · rw [one, TERM_ONE]
                omega
              · rw [two]
            have included :=
              findHighestPossibleMatchIncludes
                (state.nodes destination).log
                request.prevLogIndex request.prevLogTerm
                request.prevLogIndex previousPositive
                (by simp [previousBound])
                localPreviousTermBound
            have failureLast :
                (failureResponse
                  (state.nodes destination) request).lastLogIndex =
                    findHighestPossibleMatch
                      (state.nodes destination).log
                      request.prevLogIndex request.prevLogTerm := by
              simp [
                failureResponse, requestNew.1, destinationCurrentTwo,
                previousZero, previousPast, lastTermNonzero
              ]
            rw [failureLast] at failureInside
            omega
        exact coveredLogWithinBasePrefixNew facts (by omega)
    rw [responseSource, unchanged]
    simp [
      updateNode, destinationCurrentTwo, beforeLogNew
    ]

/-- A request handler cannot move a canonical term-two follower off history. -/
theorem handledAppendRequestPreservesCanonical
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (currentTwo :
      (state.nodes destination).currentTerm = 2)
    (logCanonical :
      (state.nodes destination).log <+: base ++ suffix)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    after.currentTerm = 2 /\ after.log <+: base ++ suffix := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  constructor
  · rw [localPost.currentTermUnchanged]
    exact currentTwo
  · by_cases same : after.log = (state.nodes destination).log
    · simpa [same] using logCanonical
    · have requestCurrent :=
        localPost.logUnchangedOrCurrentTerm.resolve_left same
      rcases safe.2.1 with old | new
      · rw [old.1, currentTwo] at requestCurrent
        simp [TERM_ONE] at requestCurrent
      · exact handledAppendRequestChangedLogPrefix
          facts (Or.inr rfl) new.2.2.1 handled same
            (localPost.logUnchangedOrPreviousBound.resolve_left same)
            (localPost.logUnchangedOrPreviousMatches.resolve_left same)

/-- Every entry after request handling remains within the local current term. -/
theorem handledAppendRequestEntriesWithinCurrent
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermRequestSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) request)
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    forall entry,
      entry ∈ after.log ->
        entry.term <= after.currentTerm := by
  have localPost := handleAppendEntriesRequestLocalPost handled
  intro entry member
  by_cases same : after.log = (state.nodes destination).log
  · have oldMember :
        entry ∈ (state.nodes destination).log := by
      simpa [same] using member
    rw [localPost.currentTermUnchanged]
    exact facts.entriesDoNotExceedCurrentTerm destination entry oldMember
  · have requestCurrent :=
      localPost.logUnchangedOrCurrentTerm.resolve_left same
    rcases safe.2.1 with old | new
    · have logOld :=
        handledAppendRequestChangedLogPrefix
          facts (Or.inl rfl) old.2.2.1 handled same
            (localPost.logUnchangedOrPreviousBound.resolve_left same)
            (localPost.logUnchangedOrPreviousMatches.resolve_left same)
      have termOne :=
        facts.oldEntriesTermOne entry (mem_of_prefix logOld member)
      rw [localPost.currentTermUnchanged, ← requestCurrent, old.1, termOne]
    · have logNew :=
        handledAppendRequestChangedLogPrefix
          facts (Or.inr rfl) new.2.2.1 handled same
            (localPost.logUnchangedOrPreviousBound.resolve_left same)
            (localPost.logUnchangedOrPreviousMatches.resolve_left same)
      have historyMember : entry ∈ base ++ suffix :=
        mem_of_prefix logNew member
      rw [localPost.currentTermUnchanged, ← requestCurrent, new.1]
      rcases List.mem_append.mp historyMember with inBase | inSuffix
      · have termOne :=
          facts.oldEntriesTermOne entry
            (mem_of_prefix facts.basePrefixOld inBase)
        rw [termOne, TERM_ONE]
        omega
      · rw [facts.suffixEntriesTermTwo entry inSuffix]

/-- Receiving an AppendEntries request preserves the cross-term invariant. -/
theorem receiveAppendRequestPreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    {remaining : List (Message TxId)}
    {request : AppendEntriesRequest TxId}
    {after : NodeState TxId}
    {response : AppendEntriesResponse}
    (cross : CrossTermInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesRequest request, remaining))
    (handled :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (after, response)) :
    CrossTermInvariant
      { state with
        nodes := updateNode state.nodes destination after
        network :=
          enqueueNoDup
            (updateQueue state.network destination remaining)
            (.appendEntriesResponse response) } := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  let afterState : State TxId :=
    { state with
      nodes := updateNode state.nodes destination after
      network :=
        enqueueNoDup
          (updateQueue state.network destination remaining)
          (.appendEntriesResponse response) }
  have takenSound := CCFRaft.takeFirstFromSound taken
  have selectedSafe :=
    facts.networkSafe destination (.appendEntriesRequest request)
      takenSound.2.1
  have requestDestination : request.destination = destination :=
    selectedSafe.1
  have requestSafe := selectedSafe.2
  have requestTargetSafe :=
    facts.queuedRequestTargetsSafe
      destination (.appendEntriesRequest request) takenSound.2.1
  have localPost := handleAppendEntriesRequestLocalPost handled
  have newLeaderNodeEq :
      afterState.nodes newLeader = state.nodes newLeader := by
    by_cases destinationEq : destination = newLeader
    · have handled' :
          handleAppendEntriesRequest?
              (state.nodes newLeader) request =
            some (after, response) := by
        simpa [destinationEq] using handled
      have unchanged :=
        handleAppendEntriesRequestLeaderUnchanged
          facts.newLeaderRole handled'
      simp [afterState, destinationEq, unchanged]
    · simp [
        afterState, updateNode, Function.update,
        Ne.symm destinationEq]
  have oldMatchEq :
      (afterState.nodes INITIAL_LEADER).matchIndex =
        (state.nodes INITIAL_LEADER).matchIndex := by
    by_cases destinationEq : destination = INITIAL_LEADER
    · simpa [
        afterState, destinationEq, localPost.matchIndexUnchanged]
    · simp [
        afterState, updateNode, Function.update,
        Ne.symm destinationEq]
  have oldNetworkMember :
      forall queue message,
        message ∈
            updateQueue state.network destination remaining queue ->
          message ∈ state.network queue := by
    intro queue message member
    by_cases queueEq : queue = destination
    · subst queue
      apply takenSound.2.2 message
      simpa [updateQueue] using member
    · simpa [updateQueue, Function.update, queueEq] using member
  have preserveCanonical :
      (state.nodes destination).currentTerm = 2 ->
      (state.nodes destination).log <+: base ++ suffix ->
        after.currentTerm = 2 /\ after.log <+: base ++ suffix :=
    fun current log =>
      handledAppendRequestPreservesCanonical
        facts requestSafe current log handled
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  constructor
  · exact facts.oldEntriesTermOne
  · exact facts.suffixEntriesTermTwo
  · exact facts.basePrefixOld
  · intro node
    by_cases nodeEq : node = destination
    · subst node
      simpa [afterState] using
        handledAppendRequestLogCovered facts requestSafe handled
    · simpa [
        afterState, updateNode, Function.update, nodeEq
      ] using facts.logsCovered node
  · intro node
    by_cases nodeEq : node = destination
    · subst node
      simpa [afterState] using
        localPost.commitIndexBounded
          (facts.commitIndicesBounded destination)
    · simpa [
        afterState, updateNode, Function.update, nodeEq
      ] using facts.commitIndicesBounded node
  · intro node
    by_cases nodeEq : node = destination
    · subst node
      rw [show afterState.nodes destination = after by
        simp [afterState]]
      rw [localPost.currentTermUnchanged]
      exact facts.currentTermsValid destination
    · simpa [
        afterState, updateNode, Function.update, nodeEq
      ] using facts.currentTermsValid node
  · intro node entry member
    by_cases nodeEq : node = destination
    · subst node
      simpa [afterState] using
        (handledAppendRequestEntriesWithinCurrent
          facts requestSafe handled entry (by
            simpa [afterState] using member))
    · have oldMember :
          entry ∈ (state.nodes node).log := by
        simpa [
          afterState, updateNode, Function.update, nodeEq
        ] using member
      simpa [
        afterState, updateNode, Function.update, nodeEq
      ] using facts.entriesDoNotExceedCurrentTerm node entry oldMember
  · exact facts.leadersDistinct
  · rw [newLeaderNodeEq]
    exact facts.newLeaderRole
  · intro node role
    by_cases nodeEq : node = destination
    · subst node
      have beforeRole :
          (state.nodes destination).role = .leader := by
        simpa [afterState, localPost.roleUnchanged] using role
      have unchanged :=
        handleAppendEntriesRequestLeaderUnchanged beforeRole handled
      simpa [afterState, unchanged] using
        facts.leadersOwnHistories destination beforeRole
    · have beforeRole :
          (state.nodes node).role = .leader := by
        simpa [
          afterState, updateNode, Function.update, nodeEq
        ] using role
      simpa [
          afterState, updateNode, Function.update, nodeEq
        ] using facts.leadersOwnHistories node beforeRole
  · change hasElectionMajority afterState newLeader
    unfold hasElectionMajority
    rw [newLeaderNodeEq]
    exact facts.electionMajority
  · intro node role
    have beforeRole :
        (state.nodes node).role = .candidate := by
      by_cases nodeEq : node = destination
      · subst node
        simpa [afterState, localPost.roleUnchanged] using role
      · simpa [
          afterState, updateNode, Function.update, nodeEq
        ] using role
    have self := facts.candidatesSelfVote node beforeRole
    by_cases nodeEq : node = destination
    · subst node
      simpa [
        afterState, localPost.currentTermUnchanged,
        localPost.votedForUnchanged,
        localPost.votesGrantedUnchanged
      ] using self
    · simpa [
        afterState, updateNode, Function.update, nodeEq
      ] using self
  · intro voter candidate voted
    have oldVote :
        (state.nodes voter).votedFor = some candidate := by
      by_cases voterEq : voter = destination
      · subst voter
        simpa [afterState, localPost.votedForUnchanged] using voted
      · simpa [
          afterState, updateNode, Function.update, voterEq
        ] using voted
    have termTwo := facts.votedForTermTwo voter candidate oldVote
    by_cases voterEq : voter = destination
    · subst voter
      simpa [afterState, localPost.currentTermUnchanged] using termTwo
    · simpa [
        afterState, updateNode, Function.update, voterEq
      ] using termTwo
  · intro candidate voter voterIn
    have oldIn :
        voter ∈ (state.nodes candidate).votesGranted := by
      by_cases candidateEq : candidate = destination
      · subst candidate
        simpa [afterState, localPost.votesGrantedUnchanged] using voterIn
      · simpa [
          afterState, updateNode, Function.update, candidateEq
        ] using voterIn
    have chosen := facts.votesGrantedSound candidate voter oldIn
    by_cases voterEq : voter = destination
    · subst voter
      simpa [afterState, localPost.votedForUnchanged] using chosen
    · simpa [
        afterState, updateNode, Function.update, voterEq
      ] using chosen
  · intro queue message member
    have cases :=
      CCFRaft.memEnqueueNoDup
        (updateQueue state.network destination remaining)
        (.appendEntriesResponse response)
        message queue (by simpa [afterState] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · have oldSafe :=
        facts.networkSafe queue message
          (oldNetworkMember queue message oldMember)
      constructor
      · exact oldSafe.1
      · cases message with
        | appendEntriesRequest oldRequest => exact oldSafe.2
        | appendEntriesResponse oldResponse =>
            rw [newLeaderNodeEq]
            exact oldSafe.2
        | requestVoteRequest voteRequest =>
            rcases oldSafe.2 with ⟨term, different, current, vote⟩
            refine ⟨term, different, ?_, ?_⟩
            · by_cases sourceEq : voteRequest.source = destination
              · simpa [
                  afterState, sourceEq, localPost.currentTermUnchanged
                ] using current
              · simpa [
                  afterState, updateNode, Function.update, sourceEq
                ] using current
            · by_cases sourceEq : voteRequest.source = destination
              · simpa [
                  afterState, sourceEq, localPost.votedForUnchanged
                ] using vote
              · simpa [
                  afterState, updateNode, Function.update, sourceEq
                ] using vote
        | requestVoteResponse voteResponse =>
            rcases oldSafe.2 with ⟨term, different, granted⟩
            refine ⟨term, different, ?_⟩
            intro success
            have oldVote := granted success
            by_cases sourceEq : voteResponse.source = destination
            · simpa [
                afterState, sourceEq, localPost.votedForUnchanged
              ] using oldVote
            · simpa [
                afterState, updateNode, Function.update, sourceEq
              ] using oldVote
    · subst message
      refine ⟨queueEq.symm, ?_⟩
      rw [newLeaderNodeEq]
      exact handledAppendRequestResponseSafe
        facts requestSafe requestDestination handled
  · intro leader role peer
    by_cases leaderEq : leader = destination
    · subst leader
      have beforeRole :
          (state.nodes destination).role = .leader := by
        simpa [afterState, localPost.roleUnchanged] using role
      have unchanged :=
        handleAppendEntriesRequestLeaderUnchanged beforeRole handled
      simpa [afterState, unchanged] using
        facts.activeLeaderProgress beforeRole peer
    · have beforeRole :
          (state.nodes leader).role = .leader := by
        simpa [
          afterState, updateNode, Function.update, leaderEq
        ] using role
      simpa [
        afterState, updateNode, Function.update, leaderEq
      ] using facts.activeLeaderProgress beforeRole peer
  · intro voter voterIn
    have oldIn :
        voter ∈ (state.nodes newLeader).votesGranted := by
      rw [newLeaderNodeEq] at voterIn
      exact voterIn
    rw [oldMatchEq]
    exact facts.oldElectionMatchBound voter oldIn
  · intro node
    by_cases nodeEq : node = destination
    · subst node
      have targetCommit :=
        handledAppendRequestCommittedCovered
          facts requestSafe requestTargetSafe requestDestination handled
      rw [show afterState.nodes destination = after by simp [afterState]]
      exact targetCommit
    · have oldCommit := facts.committedLogsCovered node
      rw [show afterState.nodes node = state.nodes node by
        simp [afterState, updateNode, Function.update, nodeEq]]
      exact oldCommit
  · intro node belowBase
    have oldBelow :
        (state.nodes newLeader).sentIndex node < base.length := by
      rw [newLeaderNodeEq] at belowBase
      exact belowBase
    have oldSafe := facts.newCatchupLogs node oldBelow
    by_cases nodeEq : node = destination
    · subst node
      have preserved := preserveCanonical oldSafe.1 oldSafe.2
      simpa [afterState] using preserved
    · simpa [
        afterState, updateNode, Function.update, nodeEq
      ] using oldSafe
  · intro queue message member
    have cases :=
      CCFRaft.memEnqueueNoDup
        (updateQueue state.network destination remaining)
        (.appendEntriesResponse response)
        message queue (by simpa [afterState] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · have original :=
        oldNetworkMember queue message oldMember
      cases message with
      | appendEntriesRequest oldRequest =>
          have oldSafe :=
            facts.queuedRequestTargetsSafe
              queue (.appendEntriesRequest oldRequest) original
          intro termTwo previousInside
          have target := oldSafe termTwo previousInside
          by_cases targetEq : oldRequest.destination = destination
          · have preserved := preserveCanonical
              (by simpa [targetEq] using target.1)
              (by simpa [targetEq] using target.2)
            simpa [afterState, targetEq] using preserved
          · simpa [
              afterState, updateNode, Function.update, targetEq
            ] using target
      | appendEntriesResponse _ => trivial
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
    · subst message
      trivial
  · intro queue message member
    have cases :=
      CCFRaft.memEnqueueNoDup
        (updateQueue state.network destination remaining)
        (.appendEntriesResponse response)
        message queue (by simpa [afterState] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · have original :=
        oldNetworkMember queue message oldMember
      cases message with
      | appendEntriesRequest _ => trivial
      | appendEntriesResponse oldResponse =>
          have oldSafe :=
            facts.queuedResponseCatchupSafe
              queue (.appendEntriesResponse oldResponse) original
          intro responseDestination responseInside
          have source := oldSafe responseDestination responseInside
          by_cases sourceEq : oldResponse.source = destination
          · have preserved := preserveCanonical
              (by simpa [sourceEq] using source.1)
              (by simpa [sourceEq] using source.2)
            simpa [afterState, sourceEq] using preserved
          · simpa [
              afterState, updateNode, Function.update, sourceEq
            ] using source
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
    · subst message
      simpa [afterState] using
        handledAppendRequestResponseCatchupSafe
          facts requestSafe requestTargetSafe requestDestination handled

/-- Cross-term frame and replication facts after handling one ACK or NACK. -/
structure CrossResponseLocalPost
    (state : State TxId)
    (newLeader : Node)
    (oldLog base suffix : List (Entry TxId))
    (destination : Node)
    (after : NodeState TxId) : Prop where
  roleUnchanged :
    after.role = (state.nodes destination).role
  currentTermUnchanged :
    after.currentTerm = (state.nodes destination).currentTerm
  logUnchanged :
    after.log = (state.nodes destination).log
  commitIndexUnchanged :
    after.commitIndex = (state.nodes destination).commitIndex
  votedForUnchanged :
    after.votedFor = (state.nodes destination).votedFor
  votesGrantedUnchanged :
    after.votesGranted = (state.nodes destination).votesGranted
  leaderProgressBounded :
    LeaderProgressBounded
      { state with nodes := updateNode state.nodes destination after }
  oldElectionMatchBound :
    forall voter,
      voter ∈ (state.nodes newLeader).votesGranted ->
        (updateNode state.nodes destination after INITIAL_LEADER).matchIndex voter <=
          base.length
  newCatchupLogs :
    forall node,
      (updateNode state.nodes destination after newLeader).sentIndex node <
          base.length ->
        (state.nodes node).currentTerm = 2 /\
          (state.nodes node).log <+: base ++ suffix

/-- The response handler preserves all cross-term replication evidence. -/
theorem handleAppendEntriesResponseCrossPost
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {response : AppendEntriesResponse}
    {after : NodeState TxId}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (safe :
      CrossTermResponseSafe
        INITIAL_LEADER newLeader oldLog (base ++ suffix) base
          (state.nodes newLeader).votesGranted response)
    (catchupSafe :
      CrossTermResponseCatchupSafe
        state newLeader (base ++ suffix) base response)
    (responseDestination : response.destination = destination)
    (handled :
      handleAppendEntriesResponse? (state.nodes destination) response =
        some after) :
    CrossResponseLocalPost
      state newLeader oldLog base suffix destination after := by
  have destinationLeader :
      destination = INITIAL_LEADER \/ destination = newLeader := by
    have addressed := safe.2.1
    rcases addressed with old | new
    · exact Or.inl (responseDestination.symm.trans old)
    · exact Or.inr (responseDestination.symm.trans new)
  have responseAddress := responseDestination
  clear responseDestination
  have updateNodeSelf :
      updateNode state.nodes destination (state.nodes destination) =
        state.nodes := by
    funext node
    by_cases nodeEq : node = destination
    · subst node
      simp
    · exact updateNode_of_ne state.nodes destination node
        (state.nodes destination) nodeEq
  unfold handleAppendEntriesResponse? at handled
  split at handled
  · rename_i succeeded
    have afterEq := Option.some.inj handled
    subst after
    rcases destinationLeader with destinationOld | destinationNew
    · cases destinationOld
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · intro leader role peer
        by_cases leaderEq : leader = INITIAL_LEADER
        · subst leader
          have beforeRole :
              (state.nodes INITIAL_LEADER).role = .leader := by
            simpa using role
          have beforeProgress :=
            facts.activeLeaderProgress beforeRole peer
          constructor
          · simpa using beforeProgress.1
          · by_cases peerEq : peer = response.source
            · subst peer
              simp [updateIndex]
              have responseBound :=
                (safe.2.2.2 succeeded.1).resolve_right (by
                  intro new
                  exact facts.leadersDistinct
                    ((responseAddress.symm).trans new.1))
              have oldOwner :=
                facts.leadersOwnHistories INITIAL_LEADER beforeRole
              rcases oldOwner with oldOwner | newOwner
              · exact
                  ⟨beforeProgress.2,
                    by simpa [oldOwner.2.2] using responseBound.2.1⟩
              · exact False.elim (facts.leadersDistinct newOwner.1)
            · simpa [updateIndex, Function.update, peerEq] using
                beforeProgress.2
        · have beforeRole :
              (state.nodes leader).role = .leader := by
            simpa [
              updateNode, Function.update, leaderEq
            ] using role
          simpa [
            updateNode, Function.update, leaderEq
          ] using facts.activeLeaderProgress beforeRole peer
      · intro voter voterIn
        by_cases voterEq : voter = response.source
        · subst voter
          simp [updateIndex]
          have responseBound :=
            (safe.2.2.2 succeeded.1).resolve_right (by
              intro new
              exact facts.leadersDistinct
                ((responseAddress.symm).trans new.1))
          exact
            ⟨facts.oldElectionMatchBound response.source voterIn,
              responseBound.2.2 voterIn⟩
        · simpa [updateIndex, Function.update, voterEq] using
            facts.oldElectionMatchBound voter voterIn
      · intro node belowBase
        have oldBelow :
            (state.nodes newLeader).sentIndex node < base.length := by
          simpa [Ne.symm facts.leadersDistinct] using belowBase
        exact facts.newCatchupLogs node oldBelow
    · cases destinationNew
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · intro leader role peer
        by_cases leaderEq : leader = newLeader
        · subst leader
          have beforeRole :
              (state.nodes newLeader).role = .leader := by
            simpa using role
          have beforeProgress :=
            facts.activeLeaderProgress beforeRole peer
          constructor
          · simpa using beforeProgress.1
          · by_cases peerEq : peer = response.source
            · subst peer
              simp [updateIndex]
              have responseBound :=
                (safe.2.2.2 succeeded.1).resolve_left (by
                  intro old
                  exact facts.leadersDistinct
                    ((old.1.symm).trans responseAddress))
              exact
                ⟨beforeProgress.2,
                  by simpa [facts.newLeaderLog] using responseBound.2⟩
            · simpa [updateIndex, Function.update, peerEq] using
                beforeProgress.2
        · have beforeRole :
              (state.nodes leader).role = .leader := by
            simpa [
              updateNode, Function.update, leaderEq
            ] using role
          simpa [
            updateNode, Function.update, leaderEq
          ] using facts.activeLeaderProgress beforeRole peer
      · intro voter voterIn
        simpa [facts.leadersDistinct] using
          facts.oldElectionMatchBound voter voterIn
      · intro node belowBase
        exact facts.newCatchupLogs node (by simpa using belowBase)
  · split at handled
    · rename_i failed
      have afterEq := Option.some.inj handled
      subst after
      let possible :=
        findHighestPossibleMatch
          (state.nodes destination).log
          response.lastLogIndex response.term
      rcases destinationLeader with destinationOld | destinationNew
      · cases destinationOld
        constructor
        · rfl
        · rfl
        · rfl
        · rfl
        · rfl
        · rfl
        · intro leader role peer
          by_cases leaderEq : leader = INITIAL_LEADER
          · subst leader
            have beforeRole :
                (state.nodes INITIAL_LEADER).role = .leader := by
              simpa using role
            have beforeProgress :=
              facts.activeLeaderProgress beforeRole peer
            constructor
            · by_cases peerEq : peer = response.source
              · subst peer
                have bounded :=
                  le_trans
                    (min_le_right
                      (findHighestPossibleMatch
                        (state.nodes INITIAL_LEADER).log
                        response.lastLogIndex response.term)
                      ((state.nodes INITIAL_LEADER).sentIndex
                        response.source))
                    beforeProgress.1
                have updatedBound :=
                  max_le bounded beforeProgress.2
                simpa [updateIndex] using updatedBound
              · simpa [updateIndex, Function.update, peerEq] using
                  beforeProgress.1
            · simpa using beforeProgress.2
          · have beforeRole :
                (state.nodes leader).role = .leader := by
              simpa [
                updateNode, Function.update, leaderEq
              ] using role
            simpa [
              updateNode, Function.update, leaderEq
            ] using facts.activeLeaderProgress beforeRole peer
        · intro voter voterIn
          simpa using facts.oldElectionMatchBound voter voterIn
        · intro node belowBase
          have oldBelow :
              (state.nodes newLeader).sentIndex node < base.length := by
            simpa [Ne.symm facts.leadersDistinct] using belowBase
          exact facts.newCatchupLogs node oldBelow
      · cases destinationNew
        constructor
        · rfl
        · rfl
        · rfl
        · rfl
        · rfl
        · rfl
        · intro leader role peer
          by_cases leaderEq : leader = newLeader
          · subst leader
            have beforeRole :
                (state.nodes newLeader).role = .leader := by
              simpa using role
            have beforeProgress :=
              facts.activeLeaderProgress beforeRole peer
            constructor
            · by_cases peerEq : peer = response.source
              · subst peer
                have bounded :=
                  le_trans
                    (min_le_right
                      (findHighestPossibleMatch
                        (state.nodes newLeader).log
                        response.lastLogIndex response.term)
                      ((state.nodes newLeader).sentIndex
                        response.source))
                    beforeProgress.1
                have updatedBound :=
                  max_le bounded beforeProgress.2
                simpa [updateIndex] using updatedBound
              · simpa [updateIndex, Function.update, peerEq] using
                  beforeProgress.1
            · simpa using beforeProgress.2
          · have beforeRole :
                (state.nodes leader).role = .leader := by
              simpa [
                updateNode, Function.update, leaderEq
              ] using role
            simpa [
              updateNode, Function.update, leaderEq
            ] using facts.activeLeaderProgress beforeRole peer
        · intro voter voterIn
          simpa [facts.leadersDistinct] using
            facts.oldElectionMatchBound voter voterIn
        · intro node belowBase
          by_cases nodeEq : node = response.source
          · subst node
            have minInside :
                min possible
                    ((state.nodes newLeader).sentIndex response.source) <
                  base.length := by
              simp [updateIndex] at belowBase
              omega
            rcases min_lt_iff.mp minInside with
              possibleInside | oldInside
            · have lastInside :
                  response.lastLogIndex < base.length :=
                canonicalSearchInsideBaseImpliesIndexInside
                  facts.oldEntriesTermOne facts.basePrefixOld
                  safe.2.2.1 (by
                    simpa [possible, facts.newLeaderLog] using possibleInside)
              exact catchupSafe responseAddress lastInside
            · exact facts.newCatchupLogs response.source oldInside
          · have oldInside :
                (state.nodes newLeader).sentIndex node < base.length := by
              simpa [
                updateIndex, Function.update, nodeEq
              ] using belowBase
            exact facts.newCatchupLogs node oldInside
    · split at handled
      · have afterEq := Option.some.inj handled
        subst after
        exact
          ⟨rfl, rfl, rfl, rfl, rfl, rfl,
            (by simpa [updateNodeSelf] using facts.leaderProgressBounded),
            (by simpa [updateNodeSelf] using facts.oldElectionMatchBound),
            (by simpa [updateNodeSelf] using facts.newCatchupLogs)⟩
      · split at handled
        · have afterEq := Option.some.inj handled
          subst after
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl,
              (by simpa [updateNodeSelf] using facts.leaderProgressBounded),
              (by simpa [updateNodeSelf] using facts.oldElectionMatchBound),
              (by simpa [updateNodeSelf] using facts.newCatchupLogs)⟩
        · contradiction

/-- Receiving an AppendEntries response preserves the cross-term invariant. -/
theorem receiveAppendResponsePreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    {remaining : List (Message TxId)}
    {response : AppendEntriesResponse}
    {after : NodeState TxId}
    (cross : CrossTermInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.appendEntriesResponse response, remaining))
    (handled :
      handleAppendEntriesResponse? (state.nodes destination) response =
        some after) :
    CrossTermInvariant
      { state with
        nodes := updateNode state.nodes destination after
        network := updateQueue state.network destination remaining } := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  let afterState : State TxId :=
    { state with
      nodes := updateNode state.nodes destination after
      network := updateQueue state.network destination remaining }
  have takenSound := CCFRaft.takeFirstFromSound taken
  have selectedSafe :=
    facts.networkSafe destination (.appendEntriesResponse response)
      takenSound.2.1
  have responseDestination : response.destination = destination :=
    selectedSafe.1
  have responseSafe := selectedSafe.2
  have selectedCatchupSafe :=
    facts.queuedResponseCatchupSafe
      destination (.appendEntriesResponse response) takenSound.2.1
  have post :=
    handleAppendEntriesResponseCrossPost
      facts responseSafe selectedCatchupSafe responseDestination handled
  have roleEq :
      forall node,
        (updateNode state.nodes destination after node).role =
          (state.nodes node).role := by
    intro node
    by_cases nodeEq : node = destination
    · subst node; simpa using post.roleUnchanged
    · simp [updateNode, Function.update, nodeEq]
  have currentTermEq :
      forall node,
        (updateNode state.nodes destination after node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases nodeEq : node = destination
    · subst node; simpa using post.currentTermUnchanged
    · simp [updateNode, Function.update, nodeEq]
  have logEq :
      forall node,
        (updateNode state.nodes destination after node).log =
          (state.nodes node).log := by
    intro node
    by_cases nodeEq : node = destination
    · subst node; simpa using post.logUnchanged
    · simp [updateNode, Function.update, nodeEq]
  have commitEq :
      forall node,
        (updateNode state.nodes destination after node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases nodeEq : node = destination
    · subst node; simpa using post.commitIndexUnchanged
    · simp [updateNode, Function.update, nodeEq]
  have votedForEq :
      forall node,
        (updateNode state.nodes destination after node).votedFor =
          (state.nodes node).votedFor := by
    intro node
    by_cases nodeEq : node = destination
    · subst node
      simpa using post.votedForUnchanged
    · simp [updateNode, Function.update, nodeEq]
  have votesGrantedEq :
      forall node,
        (updateNode state.nodes destination after node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases nodeEq : node = destination
    · subst node
      simpa using post.votesGrantedUnchanged
    · simp [updateNode, Function.update, nodeEq]
  have oldNetworkMember :
      forall queue message,
        message ∈ afterState.network queue ->
          message ∈ state.network queue := by
    intro queue message member
    by_cases queueEq : queue = destination
    · subst queue
      apply takenSound.2.2 message
      simpa [afterState, updateQueue] using member
    · simpa [
        afterState, updateQueue, Function.update, queueEq
      ] using member
  have newVotesAfterEq :
      (afterState.nodes newLeader).votesGranted =
        (state.nodes newLeader).votesGranted := by
    simpa [afterState] using votesGrantedEq newLeader
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  constructor
  · exact facts.oldEntriesTermOne
  · exact facts.suffixEntriesTermTwo
  · exact facts.basePrefixOld
  · simpa only [logEq] using facts.logsCovered
  · simpa only [CommitIndicesBounded, commitEq, logEq] using
      facts.commitIndicesBounded
  · simpa only [CurrentTermsValid, currentTermEq] using
      facts.currentTermsValid
  · intro node entry member
    exact facts.entriesDoNotExceedCurrentTerm node entry
      (by simpa only [logEq] using member) |>.trans_eq
        (currentTermEq node).symm
  · exact facts.leadersDistinct
  · simpa only [roleEq] using facts.newLeaderRole
  · intro node role
    have beforeRole :
        (state.nodes node).role = .leader := by
      simpa only [roleEq] using role
    simpa only [currentTermEq, logEq] using
      facts.leadersOwnHistories node beforeRole
  · simpa only [hasElectionMajority, votesGrantedEq] using
      facts.electionMajority
  · intro node candidate
    have oldCandidate :
        (state.nodes node).role = .candidate := by
      simpa only [roleEq] using candidate
    simpa only [currentTermEq, votedForEq, votesGrantedEq] using
      facts.candidatesSelfVote node oldCandidate
  · intro voter candidate voted
    have oldVote :
        (state.nodes voter).votedFor = some candidate := by
      simpa only [votedForEq] using voted
    simpa only [currentTermEq] using
      facts.votedForTermTwo voter candidate oldVote
  · intro candidate voter voterIn
    have oldIn :
        voter ∈ (state.nodes candidate).votesGranted := by
      simpa only [votesGrantedEq] using voterIn
    simpa only [votedForEq] using
      facts.votesGrantedSound candidate voter oldIn
  · intro queue message member
    have oldSafe :=
      facts.networkSafe queue message
        (oldNetworkMember queue message (by simpa [afterState] using member))
    constructor
    · exact oldSafe.1
    · cases message with
      | appendEntriesRequest _ => exact oldSafe.2
      | appendEntriesResponse _ =>
          simpa only [votesGrantedEq] using oldSafe.2
      | requestVoteRequest _ =>
          simpa only [
            CrossTermVoteRequestSafe, currentTermEq, votedForEq
          ] using oldSafe.2
      | requestVoteResponse _ =>
          simpa only [
            CrossTermVoteResponseSafe, votedForEq
          ] using oldSafe.2
  · simpa [afterState] using post.leaderProgressBounded
  · intro voter voterIn
    apply post.oldElectionMatchBound voter
    simpa only [votesGrantedEq] using voterIn
  · intro node
    simpa only [NodeState.committedLog, commitEq, logEq] using
      facts.committedLogsCovered node
  · intro node belowBase
    have oldSafe := post.newCatchupLogs node
      (by simpa [afterState] using belowBase)
    simpa only [currentTermEq, logEq] using oldSafe
  · intro queue message member
    have original :=
      oldNetworkMember queue message (by simpa [afterState] using member)
    cases message with
    | appendEntriesRequest request =>
        have oldSafe :=
          facts.queuedRequestTargetsSafe
            queue (.appendEntriesRequest request) original
        intro termTwo previousInside
        simpa only [currentTermEq, logEq] using
          oldSafe termTwo previousInside
    | appendEntriesResponse _ => trivial
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial
  · intro queue message member
    have original :=
      oldNetworkMember queue message (by simpa [afterState] using member)
    cases message with
    | appendEntriesRequest _ => trivial
    | appendEntriesResponse response =>
        have oldSafe :=
          facts.queuedResponseCatchupSafe
            queue (.appendEntriesResponse response) original
        intro responseDestination responseInside
        simpa only [currentTermEq, logEq] using
          oldSafe responseDestination responseInside
    | requestVoteRequest _ => trivial
    | requestVoteResponse _ => trivial

/-- Frame and vote facts after processing one term-two vote request. -/
structure CrossVoteRequestLocalPost
    (state : State TxId)
    (destination : Node)
    (request : RequestVoteRequest)
    (after : NodeState TxId)
    (response : RequestVoteResponse) : Prop where
  roleUnchanged :
    after.role = (state.nodes destination).role
  currentTermUnchanged :
    after.currentTerm = (state.nodes destination).currentTerm
  currentTermTwo : after.currentTerm = 2
  logUnchanged :
    after.log = (state.nodes destination).log
  commitIndexUnchanged :
    after.commitIndex = (state.nodes destination).commitIndex
  sentIndexUnchanged :
    after.sentIndex = (state.nodes destination).sentIndex
  matchIndexUnchanged :
    after.matchIndex = (state.nodes destination).matchIndex
  votesGrantedUnchanged :
    after.votesGranted = (state.nodes destination).votesGranted
  votedForUpdate :
    after.votedFor = (state.nodes destination).votedFor \/
      ((state.nodes destination).votedFor = none /\
        after.votedFor = some request.source)
  responseSafe :
    CrossTermVoteResponseSafe
      { state with nodes := updateNode state.nodes destination after }
      response

/-- A safe term-two vote request changes only the persistent local vote. -/
theorem handleVoteRequestCrossPost
    {state : State TxId}
    {newLeader : Node}
    {oldLog base suffix : List (Entry TxId)}
    {destination : Node}
    {request : RequestVoteRequest}
    {after : NodeState TxId}
    {response : RequestVoteResponse}
    (facts :
      CrossTermFacts state newLeader oldLog base suffix)
    (requestDestination : request.destination = destination)
    (requestSafe : CrossTermVoteRequestSafe state request)
    (handled :
      handleRequestVoteRequest? (state.nodes destination) request =
        some (after, response)) :
    CrossVoteRequestLocalPost
      state destination request after response := by
  unfold handleRequestVoteRequest? at handled
  split at handled
  · rename_i requestNotNewer
    let grant : Bool :=
      decide (
        request.term = (state.nodes destination).currentTerm /\
          voteLogUpToDate (state.nodes destination) request /\
          ((state.nodes destination).votedFor = none \/
            (state.nodes destination).votedFor = some request.source))
    have destinationTermTwo :
        (state.nodes destination).currentTerm = 2 := by
      rcases facts.currentTermsValid destination with termOne | termTwo
      · rw [requestSafe.1, termOne, TERM_ONE] at requestNotNewer
        omega
      · exact termTwo
    have sourceNeDestination :
        Not (request.source = destination) := by
      intro same
      apply requestSafe.2.1
      rw [requestDestination, same]
    have destinationNeSource : Not (destination = request.source) :=
      Ne.symm sourceNeDestination
    have requestDestinationNeSource :
        Not (request.destination = request.source) := by
      rw [requestDestination]
      exact destinationNeSource
    by_cases granted : grant = true
    · have grantFacts :
          request.term = (state.nodes destination).currentTerm /\
            voteLogUpToDate (state.nodes destination) request /\
            ((state.nodes destination).votedFor = none \/
              (state.nodes destination).votedFor = some request.source) := by
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
          ⟨destinationTermTwo, requestDestinationNeSource, ?_⟩
        intro _
        rw [requestDestination]
        simp [updateNode]
    · have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      have notGrantFacts :
          Not (
            request.term = (state.nodes destination).currentTerm /\
              voteLogUpToDate (state.nodes destination) request /\
              ((state.nodes destination).votedFor = none \/
                (state.nodes destination).votedFor =
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
          CrossTermVoteResponseSafe, notGrantFacts,
          destinationTermTwo, requestDestinationNeSource
        ]
  · simp at handled

/-- Receiving a RequestVote request preserves the cross-term invariant. -/
theorem receiveVoteRequestPreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    {remaining : List (Message TxId)}
    {request : RequestVoteRequest}
    {after : NodeState TxId}
    {response : RequestVoteResponse}
    (cross : CrossTermInvariant state)
    (taken :
        takeFirstFrom source (state.network destination) =
          some (.requestVoteRequest request, remaining))
    (handled :
        handleRequestVoteRequest? (state.nodes destination) request =
          some (after, response)) :
    CrossTermInvariant
        { state with
          nodes := updateNode state.nodes destination after
          network :=
            enqueueNoDup
              (updateQueue state.network destination remaining)
              (.requestVoteResponse response) } := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  let afterState : State TxId :=
    { state with
        nodes := updateNode state.nodes destination after
        network :=
          enqueueNoDup
            (updateQueue state.network destination remaining)
            (.requestVoteResponse response) }
  have takenSound := CCFRaft.takeFirstFromSound taken
  have selectedSafe :=
    facts.networkSafe destination (.requestVoteRequest request)
        takenSound.2.1
  have requestDestination : request.destination = destination :=
    selectedSafe.1
  have requestSafe := selectedSafe.2
  have post :=
    handleVoteRequestCrossPost
        facts requestDestination requestSafe handled
  have roleEq :
        forall node,
          (updateNode state.nodes destination after node).role =
            (state.nodes node).role := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.roleUnchanged]
  have currentTermEq :
        forall node,
          (updateNode state.nodes destination after node).currentTerm =
            (state.nodes node).currentTerm := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.currentTermUnchanged]
  have logEq :
        forall node,
          (updateNode state.nodes destination after node).log =
            (state.nodes node).log := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.logUnchanged]
  have commitEq :
        forall node,
          (updateNode state.nodes destination after node).commitIndex =
            (state.nodes node).commitIndex := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.commitIndexUnchanged]
  have sentEq :
        forall node,
          (updateNode state.nodes destination after node).sentIndex =
            (state.nodes node).sentIndex := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.sentIndexUnchanged]
  have matchEq :
        forall node,
          (updateNode state.nodes destination after node).matchIndex =
            (state.nodes node).matchIndex := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.matchIndexUnchanged]
  have votesGrantedEq :
        forall node,
          (updateNode state.nodes destination after node).votesGranted =
            (state.nodes node).votesGranted := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.votesGrantedUnchanged]
  have oldSomePreserved :
        forall candidate,
          (state.nodes destination).votedFor = some candidate ->
            after.votedFor = some candidate := by
    intro candidate oldVote
    rcases post.votedForUpdate with unchanged | changed
    · exact unchanged.trans oldVote
    · exact False.elim (by simpa [changed.1] using oldVote)
  have globalSomePreserved :
        forall voter candidate,
          (state.nodes voter).votedFor = some candidate ->
            (updateNode state.nodes destination after voter).votedFor =
              some candidate := by
    intro voter candidate oldVote
    exact if voterEq : voter = destination then by
      subst voter
      simpa using oldSomePreserved candidate oldVote
    else by
      simpa [updateNode, Function.update, voterEq] using oldVote
  have oldNetworkMember :
        forall queue message,
          message ∈ updateQueue state.network destination remaining queue ->
            message ∈ state.network queue := by
    intro queue message member
    exact if queueEq : queue = destination then by
      subst queue
      apply takenSound.2.2 message
      simpa [updateQueue] using member
    else by
      simpa [updateQueue, Function.update, queueEq] using member
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  constructor
  · exact facts.oldEntriesTermOne
  · exact facts.suffixEntriesTermTwo
  · exact facts.basePrefixOld
  · simpa only [logEq] using facts.logsCovered
  · simpa only [CommitIndicesBounded, commitEq, logEq] using
        facts.commitIndicesBounded
  · simpa only [CurrentTermsValid, currentTermEq] using
        facts.currentTermsValid
  · intro node entry member
    rw [currentTermEq node]
    exact facts.entriesDoNotExceedCurrentTerm node entry
        (by simpa only [logEq] using member)
  · exact facts.leadersDistinct
  · simpa only [roleEq] using facts.newLeaderRole
  · intro node role
    have beforeRole :
        (state.nodes node).role = .leader := by
      simpa only [roleEq] using role
    simpa only [currentTermEq, logEq] using
      facts.leadersOwnHistories node beforeRole
  · simpa only [hasElectionMajority, votesGrantedEq] using
      facts.electionMajority
  · intro node candidate
    have oldCandidate :
          (state.nodes node).role = .candidate := by
        simpa only [roleEq] using candidate
    have oldSelf := facts.candidatesSelfVote node oldCandidate
    exact
        ⟨by simpa only [currentTermEq] using oldSelf.1,
          globalSomePreserved node node oldSelf.2.1,
          by simpa only [votesGrantedEq] using oldSelf.2.2⟩
  · intro voter candidate voted
    exact if voterEq : voter = destination then by
      subst voter
      simpa using post.currentTermTwo
    else by
      have oldVote :
          (state.nodes voter).votedFor = some candidate := by
        simpa [updateNode, Function.update, voterEq] using voted
      rw [currentTermEq voter]
      exact facts.votedForTermTwo voter candidate oldVote
  · intro candidate voter voterIn
    have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa only [votesGrantedEq] using voterIn
    exact globalSomePreserved voter candidate
        (facts.votesGrantedSound candidate voter oldIn)
  · intro queue message member
    have cases :=
        CCFRaft.memEnqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response)
          message queue (by simpa [afterState] using member)
    rcases cases with oldMember | ⟨queueEq, messageEq⟩
    · exact
        let oldSafe :=
          facts.networkSafe queue message
            (oldNetworkMember queue message oldMember)
        ⟨oldSafe.1, by
          cases message with
          | appendEntriesRequest _ => exact oldSafe.2
          | appendEntriesResponse _ =>
              simpa only [votesGrantedEq] using oldSafe.2
          | requestVoteRequest queued =>
              rcases oldSafe.2 with ⟨term, different, current, vote⟩
              exact
                ⟨term, different,
                  by simpa only [currentTermEq] using current,
                  globalSomePreserved queued.source queued.source vote⟩
          | requestVoteResponse queued =>
              rcases oldSafe.2 with ⟨term, different, granted⟩
              exact
                ⟨term, different, fun success =>
                  globalSomePreserved
                    queued.source queued.destination (granted success)⟩⟩
    · exact
        ⟨by simpa [messageEq] using queueEq.symm,
          by simpa [messageEq, afterState] using post.responseSafe⟩
  · intro leader role peer
    have beforeRole :
        (state.nodes leader).role = .leader := by
      simpa only [roleEq] using role
    simpa only [sentEq, matchEq, logEq] using
      facts.activeLeaderProgress beforeRole peer
  · intro voter voterIn
    have oldIn :
        voter ∈ (state.nodes newLeader).votesGranted := by
      simpa only [votesGrantedEq] using voterIn
    simpa only [matchEq] using
      facts.oldElectionMatchBound voter oldIn
  · intro node
    simpa only [NodeState.committedLog, commitEq, logEq] using
        facts.committedLogsCovered node
  · intro node belowBase
    have oldBelow :
          (state.nodes newLeader).sentIndex node < base.length := by
        simpa only [sentEq] using belowBase
    simpa only [currentTermEq, logEq] using
        facts.newCatchupLogs node oldBelow
  · intro queue message member
    have cases :=
        CCFRaft.memEnqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response)
          message queue (by simpa [afterState] using member)
    rcases cases with oldMember | ⟨_, messageEq⟩
    · exact
        let original := oldNetworkMember queue message oldMember
        by
          cases message with
        | appendEntriesRequest queued =>
            have oldSafe :=
              facts.queuedRequestTargetsSafe
                queue (.appendEntriesRequest queued) original
            intro termTwo previousInside
            simpa only [currentTermEq, logEq] using
              oldSafe termTwo previousInside
        | appendEntriesResponse _ => trivial
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
    · simpa [messageEq]
  · intro queue message member
    have cases :=
        CCFRaft.memEnqueueNoDup
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response)
          message queue (by simpa [afterState] using member)
    rcases cases with oldMember | ⟨_, messageEq⟩
    · exact
        let original := oldNetworkMember queue message oldMember
        by
          cases message with
        | appendEntriesRequest _ => trivial
        | appendEntriesResponse queued =>
            have oldSafe :=
              facts.queuedResponseCatchupSafe
                queue (.appendEntriesResponse queued) original
            intro responseDestination responseInside
            simpa only [currentTermEq, logEq] using
              oldSafe responseDestination responseInside
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
    · simpa [messageEq]

/-- Receiving a RequestVote response preserves the cross-term invariant. -/
theorem receiveVoteResponsePreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    {remaining : List (Message TxId)}
    {response : RequestVoteResponse}
    {after : NodeState TxId}
    (cross : CrossTermInvariant state)
    (taken :
      takeFirstFrom source (state.network destination) =
        some (.requestVoteResponse response, remaining))
    (handled :
      handleRequestVoteResponse? (state.nodes destination) response =
        some after) :
    CrossTermInvariant
      { state with
        nodes := updateNode state.nodes destination after
        network := updateQueue state.network destination remaining } := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  let afterState : State TxId :=
    { state with
      nodes := updateNode state.nodes destination after
      network := updateQueue state.network destination remaining }
  have takenSound := CCFRaft.takeFirstFromSound taken
  have selectedSafe :=
    facts.networkSafe destination (.requestVoteResponse response)
      takenSound.2.1
  have responseDestination : response.destination = destination :=
    selectedSafe.1
  have responseSafe := selectedSafe.2
  have post := CCFRaft.handleRequestVoteResponsePreserves handled
  have roleEq :
      forall node,
        (updateNode state.nodes destination after node).role =
          (state.nodes node).role := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.roleUnchanged]
  have currentTermEq :
      forall node,
        (updateNode state.nodes destination after node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.currentTermUnchanged]
  have logEq :
      forall node,
        (updateNode state.nodes destination after node).log =
          (state.nodes node).log := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.logUnchanged]
  have commitEq :
      forall node,
        (updateNode state.nodes destination after node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.commitIndexUnchanged]
  have sentEq :
      forall node,
        (updateNode state.nodes destination after node).sentIndex =
          (state.nodes node).sentIndex := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.sentIndexUnchanged]
  have matchEq :
      forall node,
        (updateNode state.nodes destination after node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.matchIndexUnchanged]
  have votedForEq :
      forall node,
        (updateNode state.nodes destination after node).votedFor =
          (state.nodes node).votedFor := by
    intro node
    by_cases nodeEq : node = destination <;>
      simp_all [updateNode, Function.update, post.votedForUnchanged]
  have newLeaderVotesEq :
      (updateNode state.nodes destination after newLeader).votesGranted =
        (state.nodes newLeader).votesGranted := by
    by_cases destinationEq : destination = newLeader
    · rw [destinationEq, updateNode_same]
      rcases post.votesUpdate with unchanged | inserted
      · simpa [destinationEq] using unchanged
      · have candidateRole :
            (state.nodes newLeader).role = .candidate := by
          simpa [destinationEq] using inserted.2.1
        rw [facts.newLeaderRole] at candidateRole
        contradiction
    · simp [updateNode, Function.update, Ne.symm destinationEq]
  have oldVoteMemberPreserved :
      forall candidate voter,
        voter ∈ (state.nodes candidate).votesGranted ->
          voter ∈
            (updateNode state.nodes destination after candidate).votesGranted := by
    intro candidate voter oldIn
    exact if candidateEq : candidate = destination then by
      subst candidate
      rcases post.votesUpdate with unchanged | inserted
      · simpa [updateNode, unchanged] using oldIn
      · simpa [updateNode, inserted.2.2] using
          Finset.mem_insert_of_mem oldIn
    else by
      simpa [updateNode, Function.update, candidateEq] using oldIn
  have oldNetworkMember :
      forall queue message,
        message ∈ afterState.network queue ->
          message ∈ state.network queue := by
    intro queue message member
    exact if queueEq : queue = destination then by
      subst queue
      apply takenSound.2.2 message
      simpa [afterState, updateQueue] using member
    else by
      simpa [
        afterState, updateQueue, Function.update, queueEq
      ] using member
  refine ⟨newLeader, oldLog, base, suffix, ?_⟩
  constructor
  · exact facts.oldEntriesTermOne
  · exact facts.suffixEntriesTermTwo
  · exact facts.basePrefixOld
  · simpa only [logEq] using facts.logsCovered
  · simpa only [CommitIndicesBounded, commitEq, logEq] using
      facts.commitIndicesBounded
  · simpa only [CurrentTermsValid, currentTermEq] using
      facts.currentTermsValid
  · intro node entry member
    rw [currentTermEq node]
    exact facts.entriesDoNotExceedCurrentTerm node entry
      (by simpa only [logEq] using member)
  · exact facts.leadersDistinct
  · simpa only [roleEq] using facts.newLeaderRole
  · intro node role
    have beforeRole :
        (state.nodes node).role = .leader := by
      simpa only [roleEq] using role
    simpa only [currentTermEq, logEq] using
      facts.leadersOwnHistories node beforeRole
  · simpa only [hasElectionMajority, newLeaderVotesEq] using
      facts.electionMajority
  · intro node candidate
    have oldCandidate :
        (state.nodes node).role = .candidate := by
      simpa only [roleEq] using candidate
    have oldSelf := facts.candidatesSelfVote node oldCandidate
    exact
      ⟨by simpa only [currentTermEq] using oldSelf.1,
        by simpa only [votedForEq] using oldSelf.2.1,
        oldVoteMemberPreserved node node oldSelf.2.2⟩
  · simpa only [VotedForTermTwo, votedForEq, currentTermEq] using
      facts.votedForTermTwo
  · intro candidate voter voterIn
    exact if candidateEq : candidate = destination then by
      subst candidate
      rcases post.votesUpdate with unchanged | inserted
      · have oldIn :
            voter ∈ (state.nodes destination).votesGranted := by
          simpa [updateNode, unchanged] using voterIn
        simpa only [votedForEq] using
          facts.votesGrantedSound destination voter oldIn
      · have member :
            voter = response.source \/
              voter ∈ (state.nodes destination).votesGranted := by
          simpa [updateNode, inserted.2.2] using voterIn
        rcases member with newVoter | oldVoter
        · subst voter
          have chosen := responseSafe.2.2 inserted.1
          rw [responseDestination] at chosen
          simpa only [votedForEq] using chosen
        · simpa only [votedForEq] using
            facts.votesGrantedSound destination voter oldVoter
    else by
      have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [updateNode, Function.update, candidateEq] using voterIn
      simpa only [votedForEq] using
        facts.votesGrantedSound candidate voter oldIn
  · intro queue message member
    have oldSafe :=
      facts.networkSafe queue message
        (oldNetworkMember queue message (by simpa [afterState] using member))
    exact
      ⟨oldSafe.1, by
        cases message with
        | appendEntriesRequest _ => exact oldSafe.2
        | appendEntriesResponse _ =>
            simpa only [newLeaderVotesEq] using oldSafe.2
        | requestVoteRequest _ =>
            simpa only [
              CrossTermVoteRequestSafe, currentTermEq, votedForEq
            ] using oldSafe.2
        | requestVoteResponse _ =>
            simpa only [
              CrossTermVoteResponseSafe, votedForEq
            ] using oldSafe.2⟩
  · intro leader role peer
    have beforeRole :
        (state.nodes leader).role = .leader := by
      simpa only [roleEq] using role
    simpa only [sentEq, matchEq, logEq] using
      facts.activeLeaderProgress beforeRole peer
  · intro voter voterIn
    have oldIn :
        voter ∈ (state.nodes newLeader).votesGranted := by
      simpa only [newLeaderVotesEq] using voterIn
    simpa only [matchEq] using
      facts.oldElectionMatchBound voter oldIn
  · intro node
    simpa only [NodeState.committedLog, commitEq, logEq] using
      facts.committedLogsCovered node
  · intro node belowBase
    have oldBelow :
        (state.nodes newLeader).sentIndex node < base.length := by
      simpa only [sentEq] using belowBase
    simpa only [currentTermEq, logEq] using
      facts.newCatchupLogs node oldBelow
  · intro queue message member
    have original :=
      oldNetworkMember queue message (by simpa [afterState] using member)
    exact by
      cases message with
      | appendEntriesRequest request =>
          have oldSafe :=
            facts.queuedRequestTargetsSafe
              queue (.appendEntriesRequest request) original
          intro termTwo previousInside
          simpa only [currentTermEq, logEq] using
            oldSafe termTwo previousInside
      | appendEntriesResponse _ => trivial
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial
  · intro queue message member
    have original :=
      oldNetworkMember queue message (by simpa [afterState] using member)
    exact by
      cases message with
      | appendEntriesRequest _ => trivial
      | appendEntriesResponse response =>
          have oldSafe :=
            facts.queuedResponseCatchupSafe
              queue (.appendEntriesResponse response) original
          intro responseDestination responseInside
          simpa only [currentTermEq, logEq] using
            oldSafe responseDestination responseInside
      | requestVoteRequest _ => trivial
      | requestVoteResponse _ => trivial

/--
A same-term AppendEntries retry changes only a candidate's role.  The queued
request remains in place, so all message snapshots and replication histories
remain valid.
-/
theorem returnToFollowerPreservesCrossTermInvariant
    (state : State TxId)
    (destination : Node)
    {request : AppendEntriesRequest TxId}
    {nextNode : NodeState TxId}
    (cross : CrossTermInvariant state)
    (stepped :
      returnToFollowerState? (state.nodes destination) request =
        some nextNode) :
    CrossTermInvariant
      { state with nodes := updateNode state.nodes destination nextNode } := by
  rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
  unfold returnToFollowerState? at stepped
  split at stepped
  · rename_i canReturn
    simp at stepped
    subst nextNode
    have destinationCandidate :
        (state.nodes destination).role = .candidate :=
      canReturn.2
    have destinationNeNewLeader :
        Not (destination = newLeader) := by
      intro destinationEq
      rw [destinationEq, facts.newLeaderRole] at destinationCandidate
      contradiction
    have leaderBack :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).role = .leader ->
            (state.nodes node).role = .leader := by
      intro node role
      by_cases nodeEq : node = destination
      · subst node
        simp [updateNode] at role
      · simpa [updateNode, Function.update, nodeEq] using role
    have candidateBack :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).role = .candidate ->
            (state.nodes node).role = .candidate := by
      intro node role
      by_cases nodeEq : node = destination
      · subst node
        simp [updateNode] at role
      · simpa [updateNode, Function.update, nodeEq] using role
    have currentTermEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).currentTerm =
            (state.nodes node).currentTerm := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    have logEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).log =
            (state.nodes node).log := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    have commitEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).commitIndex =
            (state.nodes node).commitIndex := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    have sentEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).sentIndex =
            (state.nodes node).sentIndex := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    have matchEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).matchIndex =
            (state.nodes node).matchIndex := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    have votedForEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).votedFor =
            (state.nodes node).votedFor := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    have votesGrantedEq :
        forall node,
          (updateNode state.nodes destination
              { state.nodes destination with
                role := .follower
                isNewFollower := true } node).votesGranted =
            (state.nodes node).votesGranted := by
      intro node
      by_cases nodeEq : node = destination <;>
        simp_all [updateNode, Function.update]
    refine ⟨newLeader, oldLog, base, suffix, ?_⟩
    constructor
    · exact facts.oldEntriesTermOne
    · exact facts.suffixEntriesTermTwo
    · exact facts.basePrefixOld
    · simpa only [logEq] using facts.logsCovered
    · simpa only [CommitIndicesBounded, commitEq, logEq] using
        facts.commitIndicesBounded
    · simpa only [CurrentTermsValid, currentTermEq] using
        facts.currentTermsValid
    · intro node entry member
      rw [currentTermEq node]
      exact facts.entriesDoNotExceedCurrentTerm node entry
        (by simpa only [logEq] using member)
    · exact facts.leadersDistinct
    · simpa [
        updateNode, Function.update,
        Ne.symm destinationNeNewLeader
      ] using facts.newLeaderRole
    · intro node role
      have beforeRole := leaderBack node role
      simpa only [currentTermEq, logEq] using
        facts.leadersOwnHistories node beforeRole
    · simpa only [hasElectionMajority, votesGrantedEq] using
        facts.electionMajority
    · intro node candidate
      have oldCandidate := candidateBack node candidate
      simpa only [currentTermEq, votedForEq, votesGrantedEq] using
        facts.candidatesSelfVote node oldCandidate
    · simpa only [VotedForTermTwo, votedForEq, currentTermEq] using
        facts.votedForTermTwo
    · intro candidate voter voterIn
      have oldIn :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa only [votesGrantedEq] using voterIn
      simpa only [votedForEq] using
        facts.votesGrantedSound candidate voter oldIn
    · intro queue message member
      have oldSafe :=
        facts.networkSafe queue message (by simpa using member)
      exact
        ⟨oldSafe.1, by
          cases message with
          | appendEntriesRequest _ => exact oldSafe.2
          | appendEntriesResponse _ =>
              simpa only [votesGrantedEq] using oldSafe.2
          | requestVoteRequest _ =>
              simpa only [
                CrossTermVoteRequestSafe, currentTermEq, votedForEq
              ] using oldSafe.2
          | requestVoteResponse _ =>
              simpa only [
                CrossTermVoteResponseSafe, votedForEq
              ] using oldSafe.2⟩
    · intro leader role peer
      have beforeRole := leaderBack leader role
      simpa only [sentEq, matchEq, logEq] using
        facts.activeLeaderProgress beforeRole peer
    · intro voter voterIn
      have oldIn :
          voter ∈ (state.nodes newLeader).votesGranted := by
        simpa only [votesGrantedEq] using voterIn
      simpa only [matchEq] using
        facts.oldElectionMatchBound voter oldIn
    · intro node
      simpa only [NodeState.committedLog, commitEq, logEq] using
        facts.committedLogsCovered node
    · intro node belowBase
      have oldBelow :
          (state.nodes newLeader).sentIndex node < base.length := by
        simpa only [sentEq] using belowBase
      simpa only [currentTermEq, logEq] using
        facts.newCatchupLogs node oldBelow
    · intro queue message member
      have oldSafe :=
        facts.queuedRequestTargetsSafe queue message
          (by simpa using member)
      exact by
        cases message with
        | appendEntriesRequest queued =>
            intro termTwo previousInside
            simpa only [currentTermEq, logEq] using
              oldSafe termTwo previousInside
        | appendEntriesResponse _ => trivial
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
    · intro queue message member
      have oldSafe :=
        facts.queuedResponseCatchupSafe queue message
          (by simpa using member)
      exact by
        cases message with
        | appendEntriesRequest _ => trivial
        | appendEntriesResponse queued =>
            intro responseDestination responseInside
            simpa only [currentTermEq, logEq] using
              oldSafe responseDestination responseInside
        | requestVoteRequest _ => trivial
        | requestVoteResponse _ => trivial
  · contradiction

/-- Processing any enabled queued message preserves the cross-term phase. -/
theorem receivePreservesCrossTermInvariant
    (state : State TxId)
    (source destination : Node)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state (.receive source destination)) :
    CrossTermInvariant (next state (.receive source destination)) := by
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
        · split at receiveResult
          · rename_i request
            split at receiveResult
            · rename_i after stepped
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              exact
                returnToFollowerPreservesCrossTermInvariant
                  state destination cross stepped
            · split at receiveResult
              · contradiction
              · rename_i after response handled
                have resultEq := Option.some.inj receiveResult
                rw [← resultEq]
                exact
                  receiveAppendRequestPreservesCrossTermInvariant
                    state source destination cross taken handled
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i after handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              exact
                receiveAppendResponsePreservesCrossTermInvariant
                  state source destination cross taken handled
          · rename_i request
            split at receiveResult
            · contradiction
            · rename_i after response handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              exact
                receiveVoteRequestPreservesCrossTermInvariant
                  state source destination cross taken handled
          · rename_i response
            split at receiveResult
            · contradiction
            · rename_i after handled
              have resultEq := Option.some.inj receiveResult
              rw [← resultEq]
              exact
                receiveVoteResponsePreservesCrossTermInvariant
                  state source destination cross taken handled

/-- Every enabled action preserves the post-election phase. -/
theorem crossTermInvariantPreserved
    (state : State TxId)
    (action : Action TxId)
    (cross : CrossTermInvariant state)
    (enabled : Enabled state action) :
    SystemInductiveInvariant (next state action) := by
  cases action with
  | clientRequest node txId =>
      exact SystemInductiveInvariant.crossTerm
        (clientRequestPreservesCrossTermInvariant
          state node txId cross enabled)
  | appendEntries source destination batchEnd =>
      exact SystemInductiveInvariant.crossTerm
        (appendEntriesPreservesCrossTermInvariant
          state source destination batchEnd cross enabled)
  | receive source destination =>
      exact SystemInductiveInvariant.crossTerm
        (receivePreservesCrossTermInvariant
          state source destination cross enabled)
  | advanceCommitIndex node =>
      exact SystemInductiveInvariant.crossTerm
        (advanceCommitPreservesCrossTermInvariant
          state node cross enabled)
  | timeout node =>
      exact SystemInductiveInvariant.crossTerm
        (timeoutPreservesCrossTermInvariant
          state node cross enabled)
  | requestVote source destination =>
      exact SystemInductiveInvariant.crossTerm
        (requestVotePreservesCrossTermInvariant
          state source destination cross enabled)
  | updateTerm source destination =>
      exact SystemInductiveInvariant.crossTerm
        (updateTermPreservesCrossTermInvariant
          state source destination cross enabled)
  | becomeLeader node =>
      rcases cross with ⟨newLeader, oldLog, base, suffix, facts⟩
      exact False.elim
        (crossTermCandidateLacksMajority facts enabled.1 enabled.2.2)

/-- The documented two-phase invariant is inductive for slice 2.5. -/
theorem systemInductiveInvariantPreserved
    (state : State TxId)
    (action : Action TxId)
    (invariant : SystemInductiveInvariant state)
    (enabled : Enabled state action) :
    SystemInductiveInvariant (next state action) := by
  cases invariant with
  | pre pre =>
      exact preElectionInvariantPreserved state action pre enabled
  | crossTerm cross =>
      exact crossTermInvariantPreserved state action cross enabled

/-! ## Reachable safety exports -/

/-- The supporting two-phase invariant holds in every reachable state. -/
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

/-- Every reachable state satisfies Raft log matching. -/
theorem reachableLogMatching
    {state : State TxId}
    (reachable : Reachable state) :
    LogMatching state :=
  systemInductiveInvariantLogMatching
    (reachableSystemInductiveInvariant reachable)

/-- Terms are monotonic within each reachable node log. -/
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

/-- Every reachable term-two leader contains node zero's committed prefix. -/
theorem reachableLeaderCompleteness
    {state : State TxId}
    (reachable : Reachable state) :
    LeaderCompleteness state :=
  systemInductiveInvariantLeaderCompleteness
    (reachableSystemInductiveInvariant reachable)

/-- Bundle all exported consensus-safety properties for reachable states. -/
theorem reachableConsensusSafety
    {state : State TxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  systemInductiveInvariantSafety
    (reachableSystemInductiveInvariant reachable)

end CCFRaft.Slice25
