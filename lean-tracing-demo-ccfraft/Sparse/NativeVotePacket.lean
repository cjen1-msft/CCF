-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSignatureEncoding
import Sparse.NativeNodeEncoding
import Sparse.NativePacketTerm

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def intMaxTerm {context : List Ty} (left right : Term context .int) : Term context .int :=
  .ite (.le left right) right left

theorem int_max_term_eval {context : List Ty} (left right : Term context .int)
    (assignment : Assignment) (locals : Locals context) :
    (intMaxTerm left right).eval assignment locals =
      max (left.eval assignment locals) (right.eval assignment locals) := by
  simp [intMaxTerm, Term.eval, max_def]

theorem int_max_zero_eval {context : List Ty} (value : Term context .int)
    (assignment : Assignment) (locals : Locals context) :
    (intMaxTerm (.integer 0) value).eval assignment locals =
      ((value.eval assignment locals).toNat : Int) := by
  rw [int_max_term_eval]
  change max 0 (value.eval assignment locals) = _
  by_cases nonnegative : (0 : Int) <= value.eval assignment locals
  · simp [max_eq_right nonnegative, Int.toNat_of_nonneg nonnegative]
  · have nonpositive := le_of_lt (lt_of_not_ge nonnegative)
    simp [max_eq_left nonpositive, Int.toNat_of_nonpos nonpositive]

def logTermAt {context : List Ty} (width : PNat) (node : Nat)
    (index : Term context .int) : Term context .int :=
  .ite (all [.le (.integer 1) index, .le index (length node)])
    (intMaxTerm (.integer 0) (.fst (entryAt width node (.sub index (.integer 1)))))
    (.integer 0)

theorem log_term_at_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width)
    (position : Term context .int) (index : Nat)
    (same : position.eval assignment locals = (index : Int)) :
    (logTermAt width node.val position).eval assignment locals =
      (NativeArrayVote.termAt (NativeArrayCheckQuorum.get arrays node).log index : Int) := by
  have lengthAt := (rep.configuration_log node).length_at locals
  simp only [logTermAt, all, List.foldr_cons, List.foldr_nil, Term.eval,
    same, lengthAt, Bool.and_true, Bool.and_eq_true, decide_eq_true_eq]
  by_cases positive : 0 < index
  · by_cases within : index <= (NativeArrayCheckQuorum.get arrays node).log.length
    · have natural : (index : Int) - 1 = ((index - 1 : Nat) : Int) := by omega
      have entry := congrArg Entry.term (rep.entries node (index - 1) (by omega))
      have readTerm := int_max_zero_eval
        (.fst (entryAt width node.val (.sub position (.integer 1)))) assignment locals
      simp only [Term.eval, entryAt, same, natural] at readTerm
      dsimp only [modelEntry, entryAt, Term.eval, entryTy] at entry
      simp only [show (1 : Int) <= index by omega,
        show (index : Int) <= (NativeArrayCheckQuorum.get arrays node).log.length by omega,
        and_self, if_true, NativeArrayVote.termAt, positive, within]
      simpa only [Term.eval, entryAt, entryTy, same, natural, entry] using readTerm
    · simp [NativeArrayVote.termAt, within,
        show ¬ (index : Int) <= (NativeArrayCheckQuorum.get arrays node).log.length by omega]
  · have zero : index = 0 := by omega
    simp [NativeArrayVote.termAt, zero]

def lastCommittableIndexTerm {context : List Ty} (node : Nat)
    (signature : Term context .int) : Term context .int :=
  intMaxTerm (commit node) signature

theorem last_committable_index_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed signature : Nat)
    (rep : ConfigurationLogRep assignment node log committed)
    (position : Term context .int) (same : position.eval assignment locals = (signature : Int)) :
    (lastCommittableIndexTerm node position).eval assignment locals = (max committed signature : Nat) := by
  simp only [lastCommittableIndexTerm, int_max_term_eval, rep.commit_at, same]
  by_cases lower : committed <= signature
  · rw [max_eq_right lower]
    exact max_eq_right (Int.ofNat_le.mpr lower)
  · rw [max_eq_left (Nat.le_of_not_ge lower)]
    exact max_eq_left (Int.ofNat_le.mpr (Nat.le_of_not_ge lower))

def votePacketTerm {context : List Ty} {width : PNat} (columns : Columns) (preVote : Bool)
    (source destination : Fin width) (signature : Term context .int) : Term context (packetTy width) :=
  let index := lastCommittableIndexTerm source.val signature
  let snapshot := .pair (logTermAt width source.val index) index
  let header := .pair (read columns.currentTerm source.val (.integer 0))
    (.pair (.integer source.val) (.integer destination.val))
  .pair header
    (if preVote then .inr (.inr (.inr (.inr (.inl snapshot))))
      else .inr (.inr (.inl snapshot)))

theorem vote_packet_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (preVote : Bool) (source destination : Fin width)
    (position : Term context .int) (signature : Nat)
    (same : position.eval assignment locals = (signature : Int)) :
    (votePacketTerm columns preVote source destination position).eval assignment locals =
      packetValue (NativeArrayVote.packet (NativeArrayCheckQuorum.get arrays source)
        preVote source destination signature) := by
  have index := last_committable_index_eval assignment locals source.val _ _ signature
    (rep.configuration_log source) position same
  have term := log_term_at_correct assignment locals columns arrays rep source
    (lastCommittableIndexTerm source.val position) _ index
  have current : (read columns.currentTerm source.val (.integer 0) : Term context .int).eval assignment locals =
      ((NativeArrayCheckQuorum.get arrays source).currentTerm : Int) := by
    simpa only [read, allocated, Term.eval] using rep.currentTerm source
  cases preVote <;>
    simp [votePacketTerm, NativeArrayVote.packet, NativeArrayVote.request, packetValue,
      packetHeaderValue, packetPayloadValue, Term.eval, index, term, current,
      Message.term, Message.source, Message.destination]

theorem vote_packet_term_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (state : State (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (model : NativeArrayCheckQuorum.Rep arrays state)
    (preVote : Bool) (source destination : Fin width) (position : Expr .int)
    (latest : (signatureIndexTerm width source.val position).eval assignment Locals.empty = true) :
    (votePacketTerm columns preVote source destination position).eval assignment Locals.empty =
      packetValue (if preVote then .requestPreVote (makeRequestPreVote state source destination)
        else .requestVoteRequest (makeRequestVoteRequest state source destination)) := by
  obtain ⟨signature, same, latest⟩ := (signature_index_term_witness assignment Locals.empty
    source.val _ _ (rep.configuration_log source) position).mp latest
  rw [vote_packet_term_eval assignment Locals.empty columns arrays rep preVote source destination
    position signature same, NativeArrayVote.packet_correct arrays state model preVote source destination signature latest]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
