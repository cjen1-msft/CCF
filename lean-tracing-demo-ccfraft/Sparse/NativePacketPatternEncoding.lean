-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPatternTerm

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem optional_pattern_term_correct {α : Type} [DecidableEq α]
    {context : List Ty} {sort : Ty}
    (literal : α -> Term context sort) (encode : α -> sort.denote)
    (assignment : Assignment) (locals : Locals context)
    (literalEval :
      forall value, (literal value).eval assignment locals = encode value)
    (encodeInjective : Function.Injective encode)
    (expected : Option α) (actual : Term context sort) (observed : α)
    (actualEval : actual.eval assignment locals = encode observed) :
    (optionalPatternTerm literal expected actual).eval assignment locals =
      NativePacketPattern.matchesOptional expected observed := by
  cases expected with
  | none =>
    rfl
  | some value =>
    simp only [optionalPatternTerm, Term.eval, NativePacketPattern.matchesOptional,
      Option.all_some, decide_eq_decide]
    rw [actualEval, literalEval]
    simp only [encodeInjective.eq_iff]

private theorem nat_encode_injective : Function.Injective (fun value : Nat => (value : Int)) := by
  intro left right same
  exact Int.ofNat_inj.mp same

private theorem fin_encode_injective {width : PNat} :
    Function.Injective (fun value : Fin width => (value.val : Int)) := by
  intro left right same
  apply Fin.ext
  exact Int.ofNat_inj.mp same

private theorem log_value_injective {width : PNat} :
    Function.Injective (logValue (width := width)) := by
  intro left right same
  simpa only [model_log_value] using congrArg modelLog same

@[simp] theorem optional_nat_pattern_term_correct {context : List Ty}
    (expected : Option Nat) (actual : Term context .int) (observed : Nat)
    (assignment : Assignment) (locals : Locals context)
    (actualEval : actual.eval assignment locals = (observed : Int)) :
    (optionalPatternTerm (fun value : Nat => .integer value) expected actual).eval
        assignment locals =
      NativePacketPattern.matchesOptional expected observed := by
  exact optional_pattern_term_correct (fun value : Nat => .integer value)
    (fun value : Nat => (value : Int)) assignment locals (fun _ => rfl)
    nat_encode_injective expected actual observed actualEval

@[simp] theorem optional_node_pattern_term_correct {context : List Ty} {width : PNat}
    (expected : Option (Fin width)) (actual : Term context .int)
    (observed : Fin width) (assignment : Assignment) (locals : Locals context)
    (actualEval : actual.eval assignment locals = (observed.val : Int)) :
    (optionalPatternTerm (fun value => .integer value.val) expected actual).eval
        assignment locals =
      NativePacketPattern.matchesOptional expected observed := by
  exact optional_pattern_term_correct (fun value => .integer value.val)
    (fun value : Fin width => (value.val : Int)) assignment locals (fun _ => rfl)
    fin_encode_injective expected actual observed actualEval

@[simp] theorem optional_bool_pattern_term_correct {context : List Ty}
    (expected : Option Bool) (actual : Term context .bool) (observed : Bool)
    (assignment : Assignment) (locals : Locals context)
    (actualEval : actual.eval assignment locals = observed) :
    (optionalPatternTerm Term.boolean expected actual).eval assignment locals =
      NativePacketPattern.matchesOptional expected observed := by
  exact optional_pattern_term_correct Term.boolean id assignment locals (fun _ => rfl)
    Function.injective_id expected actual observed actualEval

@[simp] theorem optional_log_pattern_term_correct {context : List Ty} {width : PNat}
    (expected : Option (List (Entry (Fin width) Nat)))
    (actual : Term context (logTy width))
    (observed : List (Entry (Fin width) Nat))
    (assignment : Assignment) (locals : Locals context)
    (actualEval : actual.eval assignment locals = logValue observed) :
    (optionalPatternTerm logTerm expected actual).eval assignment locals =
      NativePacketPattern.matchesOptional expected observed := by
  exact optional_pattern_term_correct logTerm logValue assignment locals
    (fun value => log_term_eval value assignment locals) log_value_injective
    expected actual observed actualEval

theorem packet_header_pattern_term_correct {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Header (Fin width))
    (actual : Term context packetHeaderTy)
    (assignment : Assignment) (locals : Locals context)
    (message : Message (Fin width) Nat)
    (actualEval :
      actual.eval assignment locals =
        packetHeaderValue (message.term, message.source, message.destination)) :
    (packetHeaderPatternTerm expected actual).eval assignment locals =
      expected.matches message := by
  rcases expected with ⟨term, source, destination⟩
  cases term <;> cases source <;> cases destination <;>
    simp [packetHeaderPatternTerm, optionalPatternTerm, all, Term.eval, actualEval,
      packetHeaderValue,
      NativePacketPattern.Header.matches, NativePacketPattern.matchesOptional,
      Fin.val_inj, Bool.and_assoc]

theorem packet_payload_pattern_term_eval_congr {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Payload (Fin width) Nat)
    (left right : Term context (packetPayloadTy width))
    (assignment : Assignment) (locals : Locals context)
    (same : left.eval assignment locals = right.eval assignment locals) :
    (packetPayloadPatternTerm expected left).eval assignment locals =
      (packetPayloadPatternTerm expected right).eval assignment locals := by
  cases expected <;> simp [packetPayloadPatternTerm, Term.eval, same]

private theorem packet_payload_pattern_term_canonical {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Payload (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (message : Message (Fin width) Nat) :
    (packetPayloadPatternTerm expected (packetPayloadTerm message)).eval
        assignment locals =
      expected.matches message := by
  cases expected with
  | appendEntriesRequest previous previousTerm commit length entries =>
    cases message
    case appendEntriesRequest request =>
      let payload : (appendPayloadTy width).denote :=
        (request.prevLogIndex, request.prevLogTerm, request.leaderCommit,
          logValue request.entries)
      simp only [packetPayloadPatternTerm, packetPayloadTerm, all, List.foldr,
        Term.eval, log_term_eval]
      rw [optional_nat_pattern_term_correct previous (.fst (.bound .here))
          request.prevLogIndex assignment (locals.cons payload),
        optional_nat_pattern_term_correct previousTerm (.fst (.snd (.bound .here)))
          request.prevLogTerm assignment (locals.cons payload),
        optional_nat_pattern_term_correct commit (.fst (.snd (.snd (.bound .here))))
          request.leaderCommit assignment (locals.cons payload),
        optional_nat_pattern_term_correct length
          (.fst (.snd (.snd (.snd (.bound .here))))) request.entries.length
          assignment (locals.cons payload),
        optional_log_pattern_term_correct entries
          (.snd (.snd (.snd (.bound .here)))) request.entries assignment
          (locals.cons payload)]
      · simp [NativePacketPattern.Payload.matches, Bool.and_assoc]
      · simp [payload, Term.eval, Locals.cons, logTy, logValue]
      · simp [payload, Term.eval, Locals.cons, logTy, logValue]
      · simp [payload, Term.eval, Locals.cons, logTy, logValue]
      · simp [payload, Term.eval, Locals.cons, logTy, logValue]
      · simp [payload, Term.eval, Locals.cons, logTy]
    all_goals
      simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm, all,
        Term.eval, NativePacketPattern.Payload.matches]
  | appendEntriesResponse success lastIndex =>
    cases message
    case appendEntriesResponse response =>
      cases success <;> cases lastIndex <;>
        simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
          Term.eval, Locals.cons, NativePacketPattern.Payload.matches,
          NativePacketPattern.matchesOptional]
    all_goals
      simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
        Term.eval, Locals.cons, NativePacketPattern.Payload.matches]
  | requestVoteRequest lastTerm lastIndex =>
    cases message
    case requestVoteRequest request =>
      cases lastTerm <;> cases lastIndex <;>
        simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
          Term.eval, Locals.cons, NativePacketPattern.Payload.matches,
          NativePacketPattern.matchesOptional]
    all_goals
      simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
        Term.eval, Locals.cons, NativePacketPattern.Payload.matches]
  | requestVoteResponse granted =>
    cases message
    case requestVoteResponse response =>
      cases granted <;>
        simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
          Term.eval, Locals.cons, NativePacketPattern.Payload.matches,
          NativePacketPattern.matchesOptional]
    all_goals
      simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
        Term.eval, Locals.cons, NativePacketPattern.Payload.matches]
  | requestPreVote lastTerm lastIndex =>
    cases message
    case requestPreVote request =>
      cases lastTerm <;> cases lastIndex <;>
        simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
          Term.eval, Locals.cons, NativePacketPattern.Payload.matches,
          NativePacketPattern.matchesOptional]
    all_goals
      simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
        Term.eval, Locals.cons, NativePacketPattern.Payload.matches]
  | requestPreVoteResponse granted =>
    cases message
    case requestPreVoteResponse response =>
      cases granted <;>
        simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
          Term.eval, Locals.cons, NativePacketPattern.Payload.matches,
          NativePacketPattern.matchesOptional]
    all_goals
      simp [packetPayloadPatternTerm, packetPayloadTerm, optionalPatternTerm,
        Term.eval, Locals.cons, NativePacketPattern.Payload.matches]
  | proposeVoteRequest =>
    cases message <;>
      simp [packetPayloadPatternTerm, packetPayloadTerm, Term.eval, Locals.cons,
        NativePacketPattern.Payload.matches]

theorem packet_payload_pattern_term_correct {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Payload (Fin width) Nat)
    (actual : Term context (packetPayloadTy width))
    (assignment : Assignment) (locals : Locals context)
    (message : Message (Fin width) Nat)
    (actualEval :
      actual.eval assignment locals = packetPayloadValue message) :
    (packetPayloadPatternTerm expected actual).eval assignment locals =
      expected.matches message := by
  calc
    _ = (packetPayloadPatternTerm expected (packetPayloadTerm message)).eval
        assignment locals := packet_payload_pattern_term_eval_congr expected actual
          (packetPayloadTerm message) assignment locals
          (actualEval.trans (packet_payload_term_eval message assignment locals).symm)
    _ = _ := packet_payload_pattern_term_canonical expected assignment locals message

theorem packet_pattern_term_correct {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Pattern (Fin width) Nat)
    (actual : Term context (packetTy width))
    (assignment : Assignment) (locals : Locals context)
    (message : Message (Fin width) Nat)
    (actualEval : actual.eval assignment locals = packetValue message) :
    (packetPatternTerm expected actual).eval assignment locals =
      expected.matches message := by
  have headerEval :
      (Term.fst actual).eval assignment locals =
        packetHeaderValue (message.term, message.source, message.destination) := by
    simpa [Term.eval, packetValue] using congrArg Prod.fst actualEval
  have payloadEval :
      (Term.snd actual).eval assignment locals = packetPayloadValue message := by
    simpa [Term.eval, packetValue] using congrArg Prod.snd actualEval
  simp [packetPatternTerm, NativePacketPattern.Pattern.matches, Term.eval,
    packet_header_pattern_term_correct expected.header (.fst actual)
      assignment locals message headerEval,
    packet_payload_pattern_term_correct expected.payload (.snd actual)
      assignment locals message payloadEval]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
