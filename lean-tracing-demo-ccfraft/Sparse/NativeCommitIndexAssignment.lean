-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitIndexEncoding
import Sparse.NativeMaxMatchAssignment
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem replication_majority_term_bounded {context : List Ty} {width : PNat}
    (configuration : Term context (.bits width))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (candidate : Term context .int) (limit : Nat)
    (configurationBounded :
      configuration.symbols.all (fun symbol => symbol.2 < limit) = true)
    (matchIndexBounded :
      matchIndex.symbols.all (fun symbol => symbol.2 < limit) = true)
    (candidateBounded :
      candidate.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (replicationMajorityTerm configuration matchIndex source candidate).symbols.all
      (fun symbol => symbol.2 < limit) = true := by
  apply configuration_majority_term_bounded
  · exact configurationBounded
  · intro peer
    simp [Term.symbols, matchIndexBounded, candidateBounded]

theorem all_active_term_bounded {context : List Ty} {width : PNat}
    (length current : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (bootstrapPredicate : Term context .bool)
    (physicalPredicate : Term (.int :: context) .bool) (limit : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < limit) = true)
    (currentBounded :
      current.symbols.all (fun symbol => symbol.2 < limit) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < limit) = true)
    (bootstrapBounded :
      bootstrapPredicate.symbols.all (fun symbol => symbol.2 < limit) = true)
    (physicalBounded :
      physicalPredicate.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (allActiveTerm width length current entries bootstrapPredicate
      physicalPredicate).symbols.all (fun symbol => symbol.2 < limit) = true := by
  simp [allActiveTerm, all, boundedForall, implies, lt, isConfiguration,
    selectedLogEntry, Term.symbols, Term.weaken_symbols, lengthBounded,
    currentBounded, entriesBounded, bootstrapBounded, physicalBounded]

theorem majority_at_term_bounded {context : List Ty} {width : PNat}
    (bootstrap : BitVec width) (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (current candidate : Term context .int) (limit : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < limit) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < limit) = true)
    (matchIndexBounded :
      matchIndex.symbols.all (fun symbol => symbol.2 < limit) = true)
    (currentBounded :
      current.symbols.all (fun symbol => symbol.2 < limit) = true)
    (candidateBounded :
      candidate.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (majorityAtTerm width bootstrap length entries matchIndex source current
      candidate).symbols.all (fun symbol => symbol.2 < limit) = true := by
  have bootstrapBounded :
      ((.bits bootstrap : Term context (.bits width)).symbols.all
        (fun symbol => symbol.2 < limit)) = true := by
    simp [Term.symbols]
  have bootstrapMajority :=
    replication_majority_term_bounded (.bits bootstrap) matchIndex source candidate
      limit bootstrapBounded matchIndexBounded candidateBounded
  have physicalConfigurationBounded :
      (members (.snd (selectedLogEntry entries))).symbols.all
        (fun symbol => symbol.2 < limit) = true := by
    simpa [members, selectedLogEntry, Term.symbols, Term.weaken_symbols] using
      entriesBounded
  have physicalMajority :=
    replication_majority_term_bounded
      (members (.snd (selectedLogEntry entries))) (matchIndex.weaken .int) source
      (candidate.weaken .int) limit physicalConfigurationBounded
      (by simpa only [Term.weaken_symbols] using matchIndexBounded)
      (by simpa only [Term.weaken_symbols] using candidateBounded)
  have physicalBounded :
      (implies
        (.le (.add (.bound .here) (.integer 1)) (candidate.weaken .int))
        (replicationMajorityTerm (members (.snd (selectedLogEntry entries)))
          (matchIndex.weaken .int) source (candidate.weaken .int))).symbols.all
          (fun symbol => symbol.2 < limit) = true := by
    simp [implies, Term.symbols, Term.weaken_symbols, candidateBounded,
      physicalMajority]
  exact all_active_term_bounded length current entries
    (replicationMajorityTerm (.bits bootstrap) matchIndex source candidate)
    (implies (.le (.add (.bound .here) (.integer 1)) (candidate.weaken .int))
      (replicationMajorityTerm (members (.snd (selectedLogEntry entries)))
        (matchIndex.weaken .int) source (candidate.weaken .int)))
    limit lengthBounded currentBounded entriesBounded bootstrapMajority
    physicalBounded

theorem commit_eligible_predicate_bounded {context : List Ty} {width : PNat}
    (bootstrap : BitVec width) (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (commit currentTerm current : Term context .int)
    (limit : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < limit) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < limit) = true)
    (matchIndexBounded :
      matchIndex.symbols.all (fun symbol => symbol.2 < limit) = true)
    (commitBounded :
      commit.symbols.all (fun symbol => symbol.2 < limit) = true)
    (currentTermBounded :
      currentTerm.symbols.all (fun symbol => symbol.2 < limit) = true)
    (currentBounded :
      current.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (commitEligiblePredicate width bootstrap length entries matchIndex source
      commit currentTerm current).symbols.all
        (fun symbol => symbol.2 < limit) = true := by
  have majorityBounded :=
    majority_at_term_bounded bootstrap (length.weaken .int) (entries.weaken .int)
      (matchIndex.weaken .int) source (current.weaken .int)
      (.add (.bound .here) (.integer 1)) limit
      (by simpa only [Term.weaken_symbols] using lengthBounded)
      (by simpa only [Term.weaken_symbols] using entriesBounded)
      (by simpa only [Term.weaken_symbols] using matchIndexBounded)
      (by simpa only [Term.weaken_symbols] using currentBounded)
      (by simp [Term.symbols])
  simp [commitEligiblePredicate, all, lt, isSignature, normalizedEntryTerm,
    intMaxTerm, normalizedContentTerm, selectedLogEntry, Term.symbols,
    Term.weaken_symbols, commitBounded, entriesBounded, currentTermBounded,
    majorityBounded]

theorem highest_commit_index_assignment {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (bootstrap : BitVec width) (source : Fin width)
    (old : NodeRowTerms width)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (oldRep : old.Rep assignment row) (oldBounded : old.Bounded before.next)
    (current : Expr .int) (currentNat best : Nat)
    (currentBounded :
      current.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameCurrent :
      current.eval assignment Locals.empty = (currentNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (summary : NativeArrayCommitIndex.CommitIndex row source currentNat best) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds before.assertions.toList extended /\
      (.free .int before.next : Expr .int).eval extended Locals.empty =
        (best : Int) /\
      (highestCommitIndexTerm width bootstrap old.logLength old.logEntries
        old.matchIndex source old.commit old.currentTerm current
        (.free .int before.next)).eval extended Locals.empty = true := by
  let eligible :=
    commitEligiblePredicate width bootstrap old.logLength old.logEntries old.matchIndex
      source old.commit old.currentTerm current
  have eligibleBounded :
      eligible.symbols.all (fun symbol => symbol.2 < before.next) = true := by
    exact commit_eligible_predicate_bounded bootstrap old.logLength old.logEntries
      old.matchIndex source old.commit old.currentTerm current before.next
      oldBounded.logLength oldBounded.logEntries oldBounded.matchIndex
      oldBounded.commit oldBounded.currentTerm currentBounded
  have sameEligible : forall position, position < row.log.length ->
      (eligible.eval assignment (Locals.empty.cons (position : Int)) = true <->
        NativeArrayCommitIndex.Eligible row source currentNat position) := by
    intro position live
    exact commit_eligible_predicate_correct assignment Locals.empty bootstrap
      old.logLength old.logEntries old.matchIndex source old.commit old.currentTerm
      current row currentNat position sameBootstrap oldRep.logLength oldRep.logEntries
      oldRep.matchIndex oldRep.commit oldRep.currentTerm sameCurrent live
  obtain ⟨extended, agreement, extendedHolds, sameSelected, accepted⟩ :=
    max_match_assignment before assignment holds old.logLength old.logLength eligible
      row.log.length row.log.length best
      (NativeArrayCommitIndex.Eligible row source currentNat)
      oldBounded.logLength oldBounded.logLength eligibleBounded oldRep.logLength
      oldRep.logLength (by simpa only [Nat.min_self] using sameEligible) summary
  exact ⟨extended, agreement, extendedHolds, sameSelected, by
    simpa [highestCommitIndexTerm, eligible] using accepted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
