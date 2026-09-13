-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeBecomeLeader
import Sparse.NativeArrayBecomeLeader
import Sparse.NativeMembershipRowEncoding
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem become_leader_row_terms_rep {width : PNat}
    (assignment : Assignment) (old : NodeRowTerms width)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (latest : Expr .int) (latestNat : Nat)
    (oldRep : old.Rep assignment row)
    (sameLatest :
      latest.eval assignment Locals.empty = (latestNat : Int)) :
    (becomeLeaderRowTerms old latest).Rep assignment
      (NativeArrayBecomeLeader.prepareRow row latestNat) := by
  let output := NativeArrayBecomeLeader.prepareRow row latestNat
  let length := logRangeMinTerm old.logLength latest
  have sameLength :
      length.eval assignment Locals.empty = (output.log.length : Int) := by
    simp [length, output, log_range_min_term_eval, oldRep.logLength, sameLatest,
      NativeArrayBecomeLeader.prepareRow, NativeArrayLogWrite.take, Nat.cast_min,
      min_comm]
  have allAdded :
      ((.bits (-1) : Expr (.bits width)).eval assignment Locals.empty) =
        encodeBits (Finset.univ : Finset (Fin width)) := by
    apply BitVec.eq_of_getLsbD_eq
    intro index within
    change (-1 : BitVec width).getLsbD index =
      (encodeBits Finset.univ).getLsbD index
    have allOnes :
        (-1 : BitVec width) = BitVec.allOnes width :=
      BitVec.neg_one_eq_allOnes
    rw [allOnes]
    rw [BitVec.getLsbD_allOnes]
    simpa [within] using
      (encode_bits_bit (Finset.univ : Finset (Fin width))
        ⟨index, within⟩).symm
  refine { oldRep with
    role := ?_
    logLength := ?_
    logEntries := ?_
    sentIndex := ?_
    matchIndex := ?_ }
  · rfl
  · simpa [becomeLeaderRowTerms, output, length] using sameLength
  · intro index live
    apply oldRep.logEntries index
    exact lt_of_lt_of_le live (by
      simp [NativeArrayBecomeLeader.prepareRow, NativeArrayLogWrite.take])
  · intro peer
    change
      (membershipSentIndexTerm old.sentIndex (.bits (-1)) length).eval
          assignment Locals.empty peer.val =
        (output.sentIndex peer : Int)
    rw [membership_sent_index_term_correct assignment old.sentIndex (.bits (-1))
      length Finset.univ output.log.length allAdded sameLength peer]
    simp [output, NativeArrayBecomeLeader.prepareRow]
  · intro peer
    rfl

theorem become_leader_row_terms_bounded {width : PNat}
    (old : NodeRowTerms width) (latest : Expr .int) (limit : Nat)
    (oldBounded : old.Bounded limit)
    (latestBounded :
      latest.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (becomeLeaderRowTerms old latest).Bounded limit := by
  have lengthBounded :
      (logRangeMinTerm old.logLength latest).symbols.all
          (fun symbol => symbol.2 < limit) = true := by
    simp [logRangeMinTerm, Term.symbols, oldBounded.logLength, latestBounded]
  have sentIndexBounded :
      (membershipSentIndexTerm (width := width) old.sentIndex (.bits (-1))
        (logRangeMinTerm old.logLength latest)).symbols.all
          (fun symbol => symbol.2 < limit) = true := by
    have foldBounded :
      forall (peers : List (Fin width))
        (result : Expr (.array .int .int)),
        result.symbols.all (fun symbol => symbol.2 < limit) = true ->
        (peers.foldl (fun result peer =>
          .store result (.integer peer.val)
            (.ite (.bit (.bits (-1)) peer)
              (logRangeMinTerm old.logLength latest)
              (.select old.sentIndex (.integer peer.val)))) result).symbols.all
            (fun symbol => symbol.2 < limit) = true := by
      intro peers
      induction peers with
      | nil =>
        intro result resultBounded
        exact resultBounded
      | cons peer peers ih =>
        intro result resultBounded
        simp only [List.foldl_cons]
        apply ih
        simp [Term.symbols, resultBounded, lengthBounded,
          oldBounded.sentIndex]
    exact foldBounded (List.finRange width) old.sentIndex oldBounded.sentIndex
  exact { oldBounded with
    role := by simp [becomeLeaderRowTerms, Term.symbols]
    logLength := by simpa [becomeLeaderRowTerms] using lengthBounded
    sentIndex := by simpa [becomeLeaderRowTerms] using sentIndexBounded
    matchIndex := by simp [becomeLeaderRowTerms, Term.symbols] }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
