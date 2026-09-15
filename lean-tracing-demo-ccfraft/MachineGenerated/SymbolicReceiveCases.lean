-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveState

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

def messageCasesRaw {b : Ty} (message : Expr messageCodec.ty)
    (appendRequest : Expr appendRequestCodec.ty → Expr b)
    (appendResponse : Expr appendResponseCodec.ty → Expr b)
    (voteRequest : Expr voteRequestCodec.ty → Expr b)
    (voteResponse : Expr voteResponseCodec.ty → Expr b)
    (preVoteRequest : Expr preVoteRequestCodec.ty → Expr b)
    (preVoteResponse : Expr preVoteResponseCodec.ty → Expr b)
    (proposal : Expr proposeCodec.ty → Expr b) : Expr b :=
  matchSum message appendRequest fun rest =>
    matchSum rest appendResponse fun rest =>
      matchSum rest voteRequest fun rest =>
        matchSum rest voteResponse fun rest =>
          matchSum rest preVoteRequest fun rest =>
            matchSum rest preVoteResponse proposal

theorem messageCasesRaw_correct {B : Type} {b : Ty} (decode : b.Value → B)
    (ρ : Assignment) (message : Expr messageCodec.ty) (P : Message Node Nat → Prop)
    (f : Message Node Nat → B)
    (appendRequest : Expr appendRequestCodec.ty → Expr b)
    (appendResponse : Expr appendResponseCodec.ty → Expr b)
    (voteRequest : Expr voteRequestCodec.ty → Expr b)
    (voteResponse : Expr voteResponseCodec.ty → Expr b)
    (preVoteRequest : Expr preVoteRequestCodec.ty → Expr b)
    (preVoteResponse : Expr preVoteResponseCodec.ty → Expr b)
    (proposal : Expr proposeCodec.ty → Expr b)
    (h0 : ∀ r, P (.appendEntriesRequest (appendRequestCodec.decode ρ r)) →
      decode ((appendRequest r).eval ρ) = f (.appendEntriesRequest (appendRequestCodec.decode ρ r)))
    (h1 : ∀ r, P (.appendEntriesResponse (appendResponseCodec.decode ρ r)) →
      decode ((appendResponse r).eval ρ) = f (.appendEntriesResponse (appendResponseCodec.decode ρ r)))
    (h2 : ∀ r, P (.requestVoteRequest (voteRequestCodec.decode ρ r)) →
      decode ((voteRequest r).eval ρ) = f (.requestVoteRequest (voteRequestCodec.decode ρ r)))
    (h3 : ∀ r, P (.requestVoteResponse (voteResponseCodec.decode ρ r)) →
      decode ((voteResponse r).eval ρ) = f (.requestVoteResponse (voteResponseCodec.decode ρ r)))
    (h4 : ∀ r, P (.requestPreVote (preVoteRequestCodec.decode ρ r)) →
      decode ((preVoteRequest r).eval ρ) = f (.requestPreVote (preVoteRequestCodec.decode ρ r)))
    (h5 : ∀ r, P (.requestPreVoteResponse (preVoteResponseCodec.decode ρ r)) →
      decode ((preVoteResponse r).eval ρ) = f (.requestPreVoteResponse (preVoteResponseCodec.decode ρ r)))
    (h6 : ∀ r, P (.proposeVoteRequest (proposeCodec.decode ρ r)) →
      decode ((proposal r).eval ρ) = f (.proposeVoteRequest (proposeCodec.decode ρ r)))
    (bound : P (messageCodec.decode ρ message)) :
    decode ((messageCasesRaw message appendRequest appendResponse voteRequest voteResponse
      preVoteRequest preVoteResponse proposal).eval ρ) = f (messageCodec.decode ρ message) := by
  let t1 := message.rightD (defaultExpr _)
  let t2 := t1.rightD (defaultExpr _)
  let t3 := t2.rightD (defaultExpr _)
  let t4 := t3.rightD (defaultExpr _)
  let t5 := t4.rightD (defaultExpr _)
  let t6 := t5.rightD (defaultExpr _)
  generalize hm : message.eval ρ = value
  rcases value with r | (r | (r | (r | (r | (r | r)))))
  · have h := h0 (message.leftD (defaultExpr _)) (by
      simpa [Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h
  · have h := h1 (t1.leftD (defaultExpr _)) (by
      simpa [t1, Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [t1, messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h
  · have h := h2 (t2.leftD (defaultExpr _)) (by
      simpa [t2, t1, Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [t2, t1, messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h
  · have h := h3 (t3.leftD (defaultExpr _)) (by
      simpa [t3, t2, t1, Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [t3, t2, t1, messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h
  · have h := h4 (t4.leftD (defaultExpr _)) (by
      simpa [t4, t3, t2, t1, Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [t4, t3, t2, t1, messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h
  · have h := h5 (t5.leftD (defaultExpr _)) (by
      simpa [t5, t4, t3, t2, t1, Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [t5, t4, t3, t2, t1, messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h
  · have h := h6 t6 (by
      simpa [t6, t5, t4, t3, t2, t1, Codec.decode, Codec.transport, Codec.sum, Expr.normalize_correct, Expr.eval, hm] using bound)
    simpa [t6, t5, t4, t3, t2, t1, messageCasesRaw, compactCase, matchSum, Expr.normalize_correct, Expr.eval, Codec.decode, Codec.transport, Codec.sum, hm] using h

def messageCases {b : Ty} (message : Expr messageCodec.ty)
    (a : Expr appendRequestCodec.ty → Expr b) (b' : Expr appendResponseCodec.ty → Expr b)
    (c : Expr voteRequestCodec.ty → Expr b) (d : Expr voteResponseCodec.ty → Expr b)
    (e : Expr preVoteRequestCodec.ty → Expr b) (f : Expr preVoteResponseCodec.ty → Expr b)
    (g : Expr proposeCodec.ty → Expr b) : Expr b :=
  match compact (compact message) with
  | .inl r => a r
  | .inr r => messageCasesRaw (.inr r) (fun _ => defaultExpr b) b' c d e f g
  | value => messageCasesRaw value a b' c d e f g

theorem messageCases_correct {B : Type} {b : Ty} (decode : b.Value → B)
    (ρ : Assignment) (message : Expr messageCodec.ty) (P : Message Node Nat → Prop)
    (f : Message Node Nat → B)
    (a : Expr appendRequestCodec.ty → Expr b) (b' : Expr appendResponseCodec.ty → Expr b)
    (c : Expr voteRequestCodec.ty → Expr b) (d : Expr voteResponseCodec.ty → Expr b)
    (e : Expr preVoteRequestCodec.ty → Expr b) (f' : Expr preVoteResponseCodec.ty → Expr b)
    (g : Expr proposeCodec.ty → Expr b)
    (h0 : ∀ r, P (.appendEntriesRequest (appendRequestCodec.decode ρ r)) →
      decode ((a r).eval ρ) = f (.appendEntriesRequest (appendRequestCodec.decode ρ r)))
    (h1 : ∀ r, P (.appendEntriesResponse (appendResponseCodec.decode ρ r)) →
      decode ((b' r).eval ρ) = f (.appendEntriesResponse (appendResponseCodec.decode ρ r)))
    (h2 : ∀ r, P (.requestVoteRequest (voteRequestCodec.decode ρ r)) →
      decode ((c r).eval ρ) = f (.requestVoteRequest (voteRequestCodec.decode ρ r)))
    (h3 : ∀ r, P (.requestVoteResponse (voteResponseCodec.decode ρ r)) →
      decode ((d r).eval ρ) = f (.requestVoteResponse (voteResponseCodec.decode ρ r)))
    (h4 : ∀ r, P (.requestPreVote (preVoteRequestCodec.decode ρ r)) →
      decode ((e r).eval ρ) = f (.requestPreVote (preVoteRequestCodec.decode ρ r)))
    (h5 : ∀ r, P (.requestPreVoteResponse (preVoteResponseCodec.decode ρ r)) →
      decode ((f' r).eval ρ) = f (.requestPreVoteResponse (preVoteResponseCodec.decode ρ r)))
    (h6 : ∀ r, P (.proposeVoteRequest (proposeCodec.decode ρ r)) →
      decode ((g r).eval ρ) = f (.proposeVoteRequest (proposeCodec.decode ρ r)))
    (bound : P (messageCodec.decode ρ message)) :
    decode ((messageCases message a b' c d e f' g).eval ρ) = f (messageCodec.decode ρ message) := by
  have original : messageCodec.decode ρ (compact (compact message)) = messageCodec.decode ρ message := by
    simp only [decode_compact]
  unfold messageCases
  split
  · rename_i r h
    have same : messageCodec.decode ρ message = .appendEntriesRequest (appendRequestCodec.decode ρ r) := by
      rw [← original, h]; rfl
    rw [same] at bound ⊢
    exact h0 r bound
  · rename_i rest h
    have same : messageCodec.decode ρ message = messageCodec.decode ρ (.inr rest) := by
      rw [← original, h]
    rw [same] at bound ⊢
    let other := fun m : Message Node Nat =>
      match m with | .appendEntriesRequest _ => False | _ => True
    have notAppend : other (messageCodec.decode ρ (.inr rest)) := by
      generalize hr : rest.eval ρ = value
      rcases value with r | (r | (r | (r | (r | r)))) <;>
        simp [other, Codec.decode, Codec.transport, Codec.sum, Expr.eval, hr]
    exact messageCasesRaw_correct decode ρ (.inr rest) (fun m => P m ∧ other m) f
      (fun _ => defaultExpr b) b' c d e f' g
      (fun _ h => False.elim h.2) (fun r h => h1 r h.1) (fun r h => h2 r h.1)
      (fun r h => h3 r h.1) (fun r h => h4 r h.1) (fun r h => h5 r h.1)
      (fun r h => h6 r h.1) ⟨bound, notAppend⟩
  · have h := messageCasesRaw_correct decode ρ (compact (compact message)) P f
      a b' c d e f' g h0 h1 h2 h3 h4 h5 h6 (by simpa only [original] using bound)
    simpa only [original] using h

end CCFRaft.SymbolicReceive
