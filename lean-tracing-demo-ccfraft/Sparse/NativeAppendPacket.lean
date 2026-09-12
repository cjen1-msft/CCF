-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEntryNormalize
import Sparse.NativeArrayAppend

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def singletonLogTerm {context : List Ty} {width : PNat} (entry : Term context (entryTy width)) :
    Term context (logTy width) :=
  .pair (.integer 1) (.store (.defaultValue _) (.integer 0) entry)

theorem singleton_log_term_correct {context : List Ty} {width : PNat}
    (entry : Term context (entryTy width)) (expected : Entry (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (same : entry.eval assignment locals = entryValue expected) :
    (singletonLogTerm entry).eval assignment locals = logValue [expected] := by
  have ground := log_term_eval (context := context) [expected] assignment locals
  simpa only [singletonLogTerm, logTerm, logCellsTerm, List.length_cons, List.length_nil,
    List.getElem?_cons_zero, Option.getD_some, Term.eval, entry_term_eval, same] using ground

def appendLogTerm {context : List Ty} (width : PNat) (node : Nat) (previous : Term context .int) :
    Term context (logTy width) :=
  .ite (lt previous (length node))
    (singletonLogTerm (normalizedEntryTerm (entryAt width node previous)))
    (logTerm [])

theorem append_log_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width)
    (previous : Expr .int) (index : Nat) (same : previous.eval assignment Locals.empty = (index : Int)) :
    (appendLogTerm width node.val previous).eval assignment Locals.empty =
      logValue (NativeArrayAppend.batchEntries (NativeArrayCheckQuorum.get arrays node).log index) := by
  have lengthAt := (rep.configuration_log node).length
  by_cases live : index < (NativeArrayCheckQuorum.get arrays node).log.length
  · have entry := rep.entries node index live
    have normalized := normalized_entry_term_correct (entryAt width node.val previous) assignment Locals.empty
    simp only [entryAt, Term.eval, same] at normalized entry
    rw [entry] at normalized
    have singleton := singleton_log_term_correct (normalizedEntryTerm (entryAt width node.val previous))
      ((NativeArrayCheckQuorum.get arrays node).log.entries index) assignment Locals.empty normalized
    simpa only [appendLogTerm, lt, Term.eval, same, lengthAt, Int.ofNat_le,
      decide_eq_false (Nat.not_le.mpr live), Bool.not_false, if_true,
      NativeArrayAppend.batchEntries, if_pos live] using singleton
  · simp [appendLogTerm, lt, Term.eval, same, lengthAt, live,
      NativeArrayAppend.batchEntries, log_term_eval]

def appendPacketTerm {width : PNat} (columns : Columns) (source destination : Fin width) :
    Expr (packetTy width) :=
  let previous := peerIndex columns.sentIndex source.val (.integer destination.val)
  .pair (.pair (read columns.currentTerm source.val (.integer 0))
    (.pair (.integer source.val) (.integer destination.val)))
    (.inl (.pair previous (.pair (logTermAt width source.val previous)
      (.pair (commit source.val) (appendLogTerm width source.val previous)))))

theorem append_packet_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (source destination : Fin width) :
    (appendPacketTerm columns source destination).eval assignment Locals.empty =
      packetValue (.appendEntriesRequest (NativeArrayAppend.request
        (NativeArrayCheckQuorum.get arrays source) source destination)) := by
  have previous := rep.sentIndex source destination
  have term := log_term_at_correct assignment Locals.empty columns arrays rep source
    (peerIndex columns.sentIndex source.val (.integer destination.val)) _ previous
  have entries := append_log_term_correct assignment columns arrays rep source
    (peerIndex columns.sentIndex source.val (.integer destination.val)) _ previous
  simp only [appendPacketTerm, Term.eval, previous, term, entries, rep.currentTerm, rep.commit,
    packetValue, packetHeaderValue, packetPayloadValue, NativeArrayAppend.request,
    Message.term, Message.source, Message.destination]

theorem append_packet_term_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (state : State (Fin width) Nat) (rep : NodeColumnsRep assignment columns arrays)
    (model : NativeArrayCheckQuorum.Rep arrays state) (source destination : Fin width) (batchEnd : Nat)
    (frontier : batchEnd = min ((NativeArrayCheckQuorum.get arrays source).sentIndex destination + 1)
      (NativeArrayCheckQuorum.get arrays source).log.length) :
    (appendPacketTerm columns source destination).eval assignment Locals.empty =
      packetValue (.appendEntriesRequest (makeAppendEntriesRequest state source destination batchEnd)) := by
  rw [append_packet_term_correct assignment columns arrays rep source destination,
    NativeArrayAppend.request_correct arrays state model source destination batchEnd frontier]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
