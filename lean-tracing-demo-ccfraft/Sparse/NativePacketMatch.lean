-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketDomain
import Sparse.NativeLogMatch

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendPayloadMatches {context : List Ty} {width : PNat}
    (value : Term context (appendPayloadTy width)) (expected : AppendEntriesRequest (Fin width) Nat) :
    Term context .bool :=
  all [.equal (.fst value) (.integer expected.prevLogIndex),
    .equal (.fst (.snd value)) (.integer expected.prevLogTerm),
    .equal (.fst (.snd (.snd value))) (.integer expected.leaderCommit),
    logMatches (.snd (.snd (.snd value))) expected.entries]

def packetPayloadMatches {context : List Ty} {width : PNat}
    (value : Term context (packetPayloadTy width)) : Message (Fin width) Nat -> Term context .bool
  | .appendEntriesRequest request =>
    .cases value (appendPayloadMatches (.bound .here) request) (.boolean false)
  | .appendEntriesResponse response =>
    .equal value (.inr (.inl (.pair (.boolean response.success) (.integer response.lastLogIndex))))
  | .requestVoteRequest request =>
    .equal value (.inr (.inr (.inl (.pair (.integer request.lastCommittableTerm)
      (.integer request.lastCommittableIndex)))))
  | .requestVoteResponse response =>
    .equal value (.inr (.inr (.inr (.inl (.boolean response.voteGranted)))))
  | .requestPreVote request =>
    .equal value (.inr (.inr (.inr (.inr (.inl (.pair (.integer request.lastCommittableTerm)
      (.integer request.lastCommittableIndex)))))))
  | .requestPreVoteResponse response =>
    .equal value (.inr (.inr (.inr (.inr (.inr (.inl (.boolean response.voteGranted)))))))
  | .proposeVoteRequest _ => .equal value (.inr (.inr (.inr (.inr (.inr (.inr .unit))))))

def packetMatches {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (expected : Message (Fin width) Nat) : Term context .bool :=
  .and (.equal (.fst value) (packetHeaderTerm (expected.term, expected.source, expected.destination)))
    (packetPayloadMatches (.snd value) expected)

theorem append_payload_matches_correct {context : List Ty} {width : PNat}
    (value : Term context (appendPayloadTy width)) (expected : AppendEntriesRequest (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (valid : LogValueValid (value.eval assignment locals).2.2.2) :
    (appendPayloadMatches value expected).eval assignment locals = true <->
      value.eval assignment locals =
        ((expected.prevLogIndex : Int), (expected.prevLogTerm : Int),
          (expected.leaderCommit : Int), logValue expected.entries) := by
  simp only [appendPayloadMatches, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, decide_eq_true_eq, and_true]
  rw [log_matches_correct (.snd (.snd (.snd value))) expected.entries assignment locals valid]
  simp only [Term.eval]
  rw [<- model_log_eq_iff _ _ valid]
  constructor
  · rintro ⟨previous, previousTerm, commit, entries⟩
    exact Prod.ext previous (Prod.ext previousTerm (Prod.ext commit entries))
  · intro same
    exact ⟨congrArg Prod.fst same, congrArg (fun payload => payload.2.1) same,
      congrArg (fun payload => payload.2.2.1) same, congrArg (fun payload => payload.2.2.2) same⟩

theorem packet_payload_matches_correct {context : List Ty} {width : PNat}
    (value : Term context (packetPayloadTy width)) (expected : Message (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (valid : PacketPayloadValid (value.eval assignment locals)) :
    (packetPayloadMatches value expected).eval assignment locals = true <->
      value.eval assignment locals = packetPayloadValue expected := by
  cases expected
  case appendEntriesRequest request =>
    cases observed : value.eval assignment locals with
    | inl payload =>
      rw [observed] at valid
      simp only [packetPayloadMatches, Term.eval, observed, packetPayloadValue]
      rw [Sum.inl.injEq]
      simpa only [Term.eval, Locals.cons] using
        append_payload_matches_correct (Term.bound .here) request assignment (locals.cons payload) valid.2.2.2
    | inr other =>
      simp [packetPayloadMatches, Term.eval, observed, packetPayloadValue]
  all_goals simp [packetPayloadMatches, packetPayloadValue, Term.eval]

theorem packet_matches_correct {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (expected : Message (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (valid : PacketValueValid (value.eval assignment locals)) :
    (packetMatches value expected).eval assignment locals = true <->
      modelPacket (value.eval assignment locals) valid = expected := by
  rw [<- model_packet_eq_iff _ _ valid]
  simp only [packetMatches, Term.eval, Bool.and_eq_true, decide_eq_true_eq, packet_header_term_eval]
  rw [packet_payload_matches_correct (.snd value) expected assignment locals valid.payload]
  simp only [packetValue, Term.eval]
  exact (@Prod.ext_iff _ _ (value.eval assignment locals)
    (packetHeaderValue (expected.term, expected.source, expected.destination), packetPayloadValue expected)).symm

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
