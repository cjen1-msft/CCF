-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScript
import Sparse.NativeOptional
import Sparse.NativeNatSet
import Sparse.NativeRenaming
import Sparse.NativeLogValue
import Sparse.NativePacketHeader
import Sparse.NativePacketDomain
import Sparse.NativeQueueLengths
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeSmt

structure Case where
  name : String
  formula : Term [] .bool
  expected : Bool
  correct : forall assignment, formula.eval assignment Locals.empty = expected

private def stored : Case :=
  { name := "array-store"
    formula := .equal (.select (.store (.free (.array .int .int) 0) (.integer 7) (.integer 9)) (.integer 7)) (.integer 9)
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def wrongStore : Case :=
  { name := "wrong-store"
    formula := .equal (.select (.store (.free (.array .int .int) 0) (.integer 7) (.integer 9)) (.integer 7)) (.integer 8)
    expected := false
    correct := by intro assignment; simp [Term.eval] }

private def nestedArray : Case :=
  { name := "nested-array"
    formula := .equal
      (.select (.select
        (.store (.free (.array .int (.array .int .int)) 0) (.integer 2)
          (.store (.free (.array .int .int) 1) (.integer 3) (.integer 11))) (.integer 2)) (.integer 3))
      (.integer 11)
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def constantArray : Case :=
  { name := "constant-array-by-constraint"
    formula := .or
      (.not (.forall_ .int
        (.equal (.select (.free (.array .int .int) 0) (.bound .here)) (.free .int 0))))
      (.equal (.select (.free (.array .int .int) 0) (.integer 100)) (.free .int 0))
    expected := true
    correct := by
      intro assignment
      by_cases all : forall index : Int,
        assignment (.array .int .int) 0 index = assignment .int 0
      · simp [Term.eval, Locals.cons, all]
      · simp [Term.eval, Locals.cons, all] }

private def pair : Case :=
  { name := "pair"
    formula := .equal (.fst (.pair (.integer (-3)) (.boolean true))) (.integer (-3))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def sum : Case :=
  { name := "sum-match"
    formula := .equal
      (.cases (.inl (.integer 7) : Term [] (.sum .int .bool))
        (.add (.bound .here) (.integer 1)) (.integer 99))
      (.integer 8)
    expected := true
    correct := by intro assignment; simp [Term.eval, Locals.cons] }

private def capture : Case :=
  { name := "match-does-not-capture"
    formula := .forall_ .int
      (.equal
        (.cases (.inr (.boolean false) : Term [.int] (.sum .unit .bool))
          (.integer 99) (.bound (.there .here)))
        (.bound .here))
    expected := true
    correct := by intro assignment; simp [Term.eval, Locals.cons] }

private def nestedQuantifiers : Case :=
  { name := "nested-quantifiers"
    formula := .forall_ .int (.not (.forall_ .int
      (.not (.equal (.bound .here) (.add (.bound (.there .here)) (.integer 1))))))
    expected := true
    correct := by intro assignment; simp [Term.eval, Locals.cons] }

private def weakenedQuantifier : Case :=
  let body : Term [.int] .bool :=
    .forall_ .int (.not (.equal (.bound .here)
      (.add (.bound (.there .here)) (.integer 1))))
  { name := "weakened-quantifier"
    formula := .forall_ .int (.forall_ .bool (.not (body.weaken .bool)))
    expected := true
    correct := by
      intro assignment
      simp [body, Term.weaken, Term.rename, Renaming.underBinder, Term.eval, Locals.cons] }

private def weakenedMatch : Case :=
  let value : Term [.int] .int :=
    .cases (.inl (.integer 7) : Term [.int] (.sum .int .bool))
      (.add (.bound .here) (.bound (.there .here))) (.integer 0)
  { name := "weakened-match"
    formula := .forall_ .int (.forall_ .bool
      (.equal (value.weaken .bool) (.add (.integer 7) (.bound (.there .here)))))
    expected := true
    correct := by
      intro assignment
      simp [value, Term.weaken, Term.rename, Renaming.underBinder, Term.eval, Locals.cons] }

private def weakenedFree : Case :=
  let value : Term [] .int := .select (.free (.array .int .int) 42) (.integer 7)
  { name := "weakened-free-symbol"
    formula := .forall_ .bool (.equal (value.weaken .bool)
      (.select (.free (.array .int .int) 42) (.integer 7)))
    expected := true
    correct := by
      intro assignment
      simp [value, Term.weaken, Term.rename, Term.eval] }

private def wideBits : Case :=
  { name := "twenty-one-bits"
    formula := .bit (.bits (width := ⟨21, by decide⟩) (BitVec.ofNat 21 (2 ^ 20))) ⟨20, by decide⟩
    expected := true
    correct := by intro assignment; simp only [Term.eval]; decide +kernel }

private def widerBits : Case :=
  { name := "one-hundred-thirty-bits"
    formula := .bit (.bits (width := ⟨130, by decide⟩) (BitVec.ofNat 130 (2 ^ 129))) ⟨129, by decide⟩
    expected := true
    correct := by intro assignment; simp only [Term.eval]; decide +kernel }

private def bitsOperations : Case :=
  { name := "bits-operations"
    formula := .equal
      (.bitsAnd (.bitsOr (.bits (width := ⟨21, by decide⟩) 3) (.bits 4)) (.bitsNot (.bits 1)))
      (.bits 6)
    expected := true
    correct := by intro assignment; simp only [Term.eval, decide_eq_true_eq]; decide +kernel }

private def unitAndSecond : Case :=
  { name := "unit-and-second"
    formula := .and (.equal .unit .unit)
      (.snd (.pair (.integer 3) (.boolean true)))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def typedSymbols : Case :=
  { name := "symbol-sort-disambiguation"
    formula := .and (.equal (.free .bool 0) (.free .bool 0))
      (.equal (.free .int 0) (.free .int 0))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def overwrittenStore : Case :=
  { name := "extensional-store-overwrite"
    formula := .equal
      (.store (.store (.free (.array .int .int) 0) (.integer 3) (.integer 8)) (.integer 3) (.integer 9))
      (.store (.free (.array .int .int) 0) (.integer 3) (.integer 9))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def assertedCondition : Case :=
  { name := "assertion-before-specialization"
    formula := .and (.free .bool 0)
      (.equal (.ite (.free .bool 0) (.integer 8) (.integer 12)) (.integer 12))
    expected := false
    correct := by
      intro assignment
      cases observed : assignment .bool 0 <;> simp [Term.eval, observed] }

private def arithmetic : Case :=
  { name := "negative-integer-arithmetic"
    formula := .le (.sub (.integer (-3)) (.integer 2)) (.integer (-5))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def optionalNatural (name : String) (value : Option Int) : Case :=
  { name
    formula := NativeEncode.optionalNatDomain (NativeEncode.optionalTerm id value)
    expected := match value with | none => true | some index => decide (0 <= index)
    correct := by
      intro assignment
      cases value <;>
        simp [NativeEncode.optionalNatDomain, NativeEncode.optionalTerm, Term.eval, Locals.cons] }

private def optionalIdentity (name : String) (width : PNat) (value : Option Int) : Case :=
  { name
    formula := NativeEncode.optionalNodeDomain width (NativeEncode.optionalTerm id value)
    expected := match value with | none => true | some node => decide (0 <= node /\ node < width.val)
    correct := by
      intro assignment
      apply Bool.eq_iff_iff.mpr
      cases value <;>
        simp [NativeEncode.optionalNodeDomain, NativeEncode.optionalTerm, Term.eval, Locals.cons] }

private def natSetOutside (name : String) (index : Term [] .int) : Case :=
  { name
    formula := .and (NativeEncode.natSetDomain 0 1)
      (.and (.or (NativeEncode.lt index (.integer 0)) (.le (.free .int 1) index))
        (NativeEncode.natSetMember 0 index))
    expected := false
    correct := by
      intro assignment
      apply Bool.eq_false_iff.mpr
      intro held
      simp only [Term.eval, Bool.and_eq_true] at held
      obtain ⟨domain, outside, present⟩ := held
      have valid := (NativeEncode.nat_set_domain_correct assignment 0 1).mp domain
      have outside' : index.eval assignment Locals.empty < 0 \/
          assignment .int 1 <= index.eval assignment Locals.empty := by
        simpa [NativeEncode.lt, Term.eval] using outside
      simp [NativeEncode.natSetMember, Term.eval, valid.2 _ outside'] at present }

private def natSetNegativeLimit : Case :=
  { name := "nat-set-negative-limit"
    formula := .and (NativeEncode.natSetDomain 0 1)
      (NativeEncode.lt (.free .int 1) (.integer 0))
    expected := false
    correct := by
      intro assignment
      apply Bool.eq_false_iff.mpr
      intro held
      simp only [Term.eval, Bool.and_eq_true] at held
      obtain ⟨domain, negative⟩ := held
      have nonnegative := ((NativeEncode.nat_set_domain_correct assignment 0 1).mp domain).1
      simp [NativeEncode.lt, Term.eval] at negative
      exact (not_lt_of_ge nonnegative) negative }

private def natSetEmpty : Case :=
  { name := "nat-set-empty-prefix"
    formula := NativeEncode.implies
      (.and (NativeEncode.natSetDomain 0 1) (.equal (.free .int 1) (.integer 0)))
      (.forall_ .int (.not (NativeEncode.natSetMember 0 (.bound .here))))
    expected := true
    correct := by
      intro assignment
      rw [NativeEncode.implies_eval]
      intro held
      simp only [Term.eval, Bool.and_eq_true, decide_eq_true_eq] at held
      obtain ⟨domain, zero⟩ := held
      have valid := (NativeEncode.nat_set_domain_correct assignment 0 1).mp domain
      simp only [Term.eval, decide_eq_true_eq]
      intro index
      have outside : index < 0 \/ assignment .int 1 <= index := by
        rw [zero]
        exact lt_or_ge (index : Int) 0
      simp [NativeEncode.natSetMember, Term.eval, Locals.cons, valid.2 index outside] }

private def logOutside (name : String) (index : Term [] .int) : Case :=
  let value : Term [] (NativeEncode.logTy 2) := .free (NativeEncode.logTy 2) 0
  { name
    formula := .and (NativeEncode.logDomain value)
      (.and (.or (NativeEncode.lt index (.integer 0)) (.le (.fst value) index))
        (.not (.equal (.select (.snd value) index) (NativeEncode.entryTerm (NativeEncode.defaultLogEntry 2)))))
    expected := false
    correct := by
      intro assignment
      apply Bool.eq_false_iff.mpr
      intro held
      simp only [Term.eval, Bool.and_eq_true] at held
      obtain ⟨domain, outside, different⟩ := held
      have valid := (NativeEncode.log_domain_correct value assignment Locals.empty).mp domain
      have outside' : index.eval assignment Locals.empty < 0 \/
          (value.eval assignment Locals.empty).1 <= index.eval assignment Locals.empty := by
        simpa [NativeEncode.lt, Term.eval] using outside
      simp [NativeEncode.entry_term_eval, valid.tail _ outside'] at different }

private def logNegativeLength : Case :=
  let value : Term [] (NativeEncode.logTy 2) := .free (NativeEncode.logTy 2) 0
  { name := "log-value-negative-length"
    formula := .and (NativeEncode.logDomain value) (NativeEncode.lt (.fst value) (.integer 0))
    expected := false
    correct := by
      intro assignment
      apply Bool.eq_false_iff.mpr
      intro held
      simp only [Term.eval, Bool.and_eq_true] at held
      obtain ⟨domain, negative⟩ := held
      have valid := (NativeEncode.log_domain_correct value assignment Locals.empty).mp domain
      simp [NativeEncode.lt, Term.eval] at negative
      exact (not_lt_of_ge valid.length) negative }

private def logEmpty : Case :=
  let value : Term [] (NativeEncode.logTy 2) := .free (NativeEncode.logTy 2) 0
  { name := "log-value-empty-tail"
    formula := NativeEncode.implies
      (.and (NativeEncode.logDomain value) (.equal (.fst value) (.integer 0)))
      (.forall_ .int (.equal (.select (.snd (value.weaken .int)) (.bound .here))
        (NativeEncode.entryTerm (NativeEncode.defaultLogEntry 2))))
    expected := true
    correct := by
      intro assignment
      rw [NativeEncode.implies_eval]
      intro held
      simp only [Term.eval, Bool.and_eq_true, decide_eq_true_eq] at held
      obtain ⟨domain, zero⟩ := held
      have valid := (NativeEncode.log_domain_correct value assignment Locals.empty).mp domain
      simp only [Term.eval, decide_eq_true_eq]
      intro index
      have outside : index < 0 \/ (value.eval assignment Locals.empty).1 <= index := by
        rw [zero]
        exact lt_or_ge (index : Int) 0
      simpa only [Term.weaken_eval, Locals.cons, NativeEncode.entry_term_eval] using valid.tail index outside }

private def packetHeader (name : String) (width : PNat) (term source destination : Int) : Case :=
  let value : Term [] NativeEncode.packetHeaderTy :=
    .pair (.integer term) (.pair (.integer source) (.integer destination))
  { name
    formula := NativeEncode.packetHeaderDomain width value
    expected := decide (0 <= term /\ 0 <= source /\ source < width.val /\
      0 <= destination /\ destination < width.val)
    correct := by
      intro assignment
      apply Bool.eq_iff_iff.mpr
      simpa [NativeEncode.PacketHeaderValid, NativeEncode.nodeValue?, value, Term.eval, and_assoc] using
        NativeEncode.packet_header_domain_correct width value assignment Locals.empty }

private def packetPayloadCase (name : String) (value : Term [] (NativeEncode.packetPayloadTy 2))
    (expected : Bool)
    (correct : forall assignment, NativeEncode.PacketPayloadValid (value.eval assignment Locals.empty) <->
      expected = true) : Case :=
  { name
    formula := NativeEncode.packetPayloadDomain value
    expected
    correct := by
      intro assignment
      apply Bool.eq_iff_iff.mpr
      exact (NativeEncode.packet_payload_domain_correct value assignment Locals.empty).trans (correct assignment) }

private def appendPacketDomain : Case :=
  let entries : Term [] (NativeEncode.logTy 2) := .free (NativeEncode.logTy 2) 0
  { name := "append-packet-log-domain"
    formula := .equal
      (NativeEncode.packetPayloadDomain (width := 2)
        (.inl (.pair (.integer 1000000) (.pair (.integer 7) (.pair (.integer 0) entries)))))
      (NativeEncode.logDomain entries)
    expected := true
    correct := by
      intro assignment
      simp only [Term.eval, decide_eq_true_eq]
      apply Bool.eq_iff_iff.mpr
      rw [NativeEncode.packet_payload_domain_correct, NativeEncode.log_domain_correct]
      simp [NativeEncode.PacketPayloadValid, Term.eval] }

private def packetKindsDistinct : Case :=
  let vote : Term [] (NativeEncode.packetPayloadTy 2) := .inr (.inr (.inl (.pair (.integer 0) (.integer 0))))
  let preVote : Term [] (NativeEncode.packetPayloadTy 2) :=
    .inr (.inr (.inr (.inr (.inl (.pair (.integer 0) (.integer 0))))))
  { name := "vote-and-pre-vote-packet-tags"
    formula := .not (.equal vote preVote)
    expected := true
    correct := by
      intro assignment
      simp [vote, preVote, Term.eval]
      intro same
      cases Sum.inr.inj (Sum.inr.inj same) }

private def packetSource : Case :=
  { name := "packet-source-header"
    formula := .equal (NativeEncode.packetSource (width := 2)
      (.pair (.pair (.integer 9) (.pair (.integer 1) (.integer 0)))
        (.free (NativeEncode.packetPayloadTy 2) 0))) (.integer 1)
    expected := true
    correct := by intro assignment; simp [NativeEncode.packetSource, Term.eval] }

private def packetCases : List Case := [
  packetPayloadCase "append-response-payload" (.inr (.inl (.pair (.boolean false) (.integer 0)))) true
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "vote-request-payload" (.inr (.inr (.inl (.pair (.integer (10 ^ 30)) (.integer 0))))) true
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "vote-response-payload" (.inr (.inr (.inr (.inl (.boolean false))))) true
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "pre-vote-request-payload"
    (.inr (.inr (.inr (.inr (.inl (.pair (.integer 0) (.integer (10 ^ 30)))))))) true
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "pre-vote-response-payload" (.inr (.inr (.inr (.inr (.inr (.inl (.boolean true))))))) true
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "propose-vote-payload" (.inr (.inr (.inr (.inr (.inr (.inr .unit)))))) true
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "append-response-negative-index" (.inr (.inl (.pair (.boolean true) (.integer (-1))))) false
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "vote-request-negative-index" (.inr (.inr (.inl (.pair (.integer 0) (.integer (-1)))))) false
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "pre-vote-request-negative-term"
    (.inr (.inr (.inr (.inr (.inl (.pair (.integer (-1)) (.integer 0))))))) false
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "append-request-negative-index"
    (.inl (.pair (.integer (-1)) (.pair (.integer 0) (.pair (.integer 0) (.free (NativeEncode.logTy 2) 0))))) false
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  packetPayloadCase "append-request-negative-commit"
    (.inl (.pair (.integer 0) (.pair (.integer 0) (.pair (.integer (-1)) (.free (NativeEncode.logTy 2) 0))))) false
    (by intro assignment; simp [NativeEncode.PacketPayloadValid, Term.eval]),
  appendPacketDomain, packetKindsDistinct, packetSource]

private def queueNegativeLength (name : String) (destination source : Int) : Case :=
  { name
    formula := NativeEncode.lt
      (NativeEncode.queueLengthTerm 0 (.integer destination) (.integer source))
      (.integer 0)
    expected := false
    correct := by
      intro assignment
      simp [NativeEncode.lt, Term.eval, NativeEncode.queue_length_correct] }

private def queueLengthLiteral (name : String) (value : Int) : Case :=
  { name
    formula := NativeEncode.implies
      (.equal (.select (.select (.free (.array .int (.array .int .int)) 0) (.integer 0)) (.integer 0))
        (.integer value))
      (.equal (NativeEncode.queueLengthTerm 0 (.integer 0) (.integer 0)) (.integer value.toNat))
    expected := true
    correct := by
      intro assignment
      rw [NativeEncode.implies_eval]
      intro cell
      simp only [Term.eval, decide_eq_true_eq] at cell
      simp [Term.eval, NativeEncode.queue_length_correct, cell] }

def cases : List Case := [
  stored, wrongStore, nestedArray, constantArray, pair, sum, capture, nestedQuantifiers,
  wideBits, widerBits, bitsOperations, unitAndSecond, typedSymbols, overwrittenStore,
  assertedCondition, arithmetic, weakenedQuantifier, weakenedMatch, weakenedFree,
  optionalNatural "optional-index-none" none,
  optionalNatural "optional-index-zero" (some 0),
  optionalNatural "optional-index-large" (some (10 ^ 30)),
  optionalNatural "optional-index-negative" (some (-1)),
  optionalIdentity "optional-node-none" ⟨21, by decide⟩ none,
  optionalIdentity "optional-node-zero" ⟨21, by decide⟩ (some 0),
  optionalIdentity "optional-node-last" ⟨21, by decide⟩ (some 20),
  optionalIdentity "optional-node-past-end" ⟨21, by decide⟩ (some 21),
  optionalIdentity "optional-node-negative" ⟨21, by decide⟩ (some (-1)),
  natSetOutside "nat-set-negative-cell" (.integer (-1)),
  natSetOutside "nat-set-zero-cell" (.integer 0),
  natSetOutside "nat-set-large-cell" (.integer (10 ^ 30)),
  natSetOutside "nat-set-tail-cell" (.free .int 1),
  natSetNegativeLimit, natSetEmpty,
  logOutside "log-value-negative-cell" (.integer (-1)),
  logOutside "log-value-zero-cell" (.integer 0),
  logOutside "log-value-large-cell" (.integer (10 ^ 30)),
  logOutside "log-value-tail-cell" (.fst (.free (NativeEncode.logTy 2) 0)),
  logNegativeLength, logEmpty,
  packetHeader "packet-header-first" 21 0 0 0,
  packetHeader "packet-header-last-large-term" 21 (10 ^ 30) 20 20,
  packetHeader "packet-header-single-node" 1 0 0 0,
  packetHeader "packet-header-negative-term" 21 (-1) 0 0,
  packetHeader "packet-header-negative-source" 21 0 (-1) 0,
  packetHeader "packet-header-source-past-end" 21 0 21 0,
  packetHeader "packet-header-negative-destination" 21 0 0 (-1),
  packetHeader "packet-header-destination-past-end" 21 0 0 21,
  queueNegativeLength "queue-negative-single-node" 0 0,
  queueNegativeLength "queue-negative-last-source" 0 20,
  queueNegativeLength "queue-negative-last-destination" 20 0,
  queueNegativeLength "queue-negative-last-self" 20 20,
  queueNegativeLength "queue-normalized-negative-source" 0 (-1),
  queueNegativeLength "queue-normalized-negative-destination" (-1) 0,
  queueLengthLiteral "queue-decode-negative" (-1),
  queueLengthLiteral "queue-decode-large-negative" (-(10 ^ 30)),
  queueLengthLiteral "queue-decode-zero" 0,
  queueLengthLiteral "queue-decode-positive" 1,
  queueLengthLiteral "queue-decode-large-positive" (10 ^ 30)] ++ packetCases

end CCFRaft.NativeSmt

run_cmd do
  for axiomName in (<- Lean.collectAxioms ``CCFRaft.NativeSmt.cases) do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "unexpected fixture axiom: {axiomName}"

def main : IO Unit := do
  let fixtures := CCFRaft.NativeSmt.cases.map fun fixture =>
    Lean.Json.mkObj [("name", Lean.toJson fixture.name),
      ("expected", Lean.toJson (if fixture.expected then "sat" else "unsat")),
      ("script", Lean.toJson (CCFRaft.NativeSmt.renderScript [fixture.formula]))]
  IO.println (Lean.toJson fixtures).compress
