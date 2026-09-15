-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveHandlers

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

structure Append where
  term : Expr .nat
  previousIndex : Expr .nat
  previousTerm : Expr .nat
  entries : Expr logCodec.ty
  leaderCommit : Expr .nat
  source : Expr nodeCodec.ty
  destination : Expr nodeCodec.ty

def Append.unpack (value : Expr appendRequestCodec.ty) : Append :=
  ⟨value.fst, value.snd.fst, value.snd.snd.fst, value.snd.snd.snd.fst,
    value.snd.snd.snd.snd.fst, value.snd.snd.snd.snd.snd.fst,
    value.snd.snd.snd.snd.snd.snd⟩

def Append.eval (ρ : Assignment) (request : Append) : AppendEntriesRequest Node Nat :=
  ⟨request.term.eval ρ, request.previousIndex.eval ρ, request.previousTerm.eval ρ,
    logCodec.decode ρ request.entries, request.leaderCommit.eval ρ,
    nodeCodec.decode ρ request.source, nodeCodec.decode ρ request.destination⟩

@[simp] theorem Append.unpack_correct (ρ : Assignment) (value : Expr appendRequestCodec.ty) :
    (Append.unpack value).eval ρ = appendRequestCodec.decode ρ value := rfl

@[simp] theorem log_length (ρ : Assignment) (log : Expr logCodec.ty) :
    log.length.eval ρ = (logCodec.decode ρ log).length := by
  simp [Codec.decode, Codec.list, Expr.eval]

@[simp] theorem log_take (ρ : Assignment) (n : Expr .nat) (log : Expr logCodec.ty) :
    logCodec.decode ρ (.take n log) = (logCodec.decode ρ log).take (n.eval ρ) := by
  simp [Codec.decode, Codec.list, Expr.eval, List.map_take]

@[simp] theorem log_drop (ρ : Assignment) (n : Expr .nat) (log : Expr logCodec.ty) :
    logCodec.decode ρ (.drop n log) = (logCodec.decode ρ log).drop (n.eval ρ) := by
  simp [Codec.decode, Codec.list, Expr.eval, List.map_drop]

@[simp] theorem log_append (ρ : Assignment) (a b : Expr logCodec.ty) :
    logCodec.decode ρ (.append a b) = logCodec.decode ρ a ++ logCodec.decode ρ b := by
  simp [Codec.decode, Codec.list, Expr.eval]

def terms (capacity : Nat) (log : Expr logCodec.ty) : Expr (.seq .nat) :=
  Container.map capacity Expr.fst log

theorem terms_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (terms capacity log).eval ρ = (logCodec.decode ρ log).map Entry.term := by
  have h := Container.map_correct ρ capacity Expr.fst Prod.fst (fun _ => rfl) log
    (by simpa [Codec.decode, Codec.list] using bound)
  simpa [terms, Codec.decode, Codec.list, List.map_map, Function.comp_def] using h

def logConsistent (state : Local) (request : Append) : Expr .bool :=
  (Expr.eq request.previousIndex (.nat 0)).or
    ((request.previousIndex.le state.log.length).and
      (.eq (termAt state.log request.previousIndex) request.previousTerm))

theorem logConsistent_correct (ρ : Assignment) (state : Local) (request : Append) :
    (logConsistent state request).eval ρ = true ↔ logOk (state.eval ρ) (request.eval ρ) := by
  simp only [logConsistent, eval_or, eval_and, eval_le, Bool.or_eq_true,
    Bool.and_eq_true, Expr.eval, termAt_correct, decide_eq_true_eq]
  simp only [logOk, Local.eval, Append.eval]
  rw [show (state.log.eval ρ : List entryCodec.ty.Value).length =
    (logCodec.decode ρ state.log).length from log_length ρ state.log]

def alreadyApplied (capacity : Nat) (state : Local) (request : Append) : Expr .bool :=
  (Expr.eq request.entries.length (.nat 0)).or
    (((Expr.add request.previousIndex request.entries.length).le state.log.length).and
      (.eq (terms capacity (.take request.entries.length (.drop request.previousIndex state.log)))
        (terms capacity request.entries)))

theorem alreadyApplied_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    (alreadyApplied capacity state request).eval ρ = true ↔
      alreadyDone (state.eval ρ) (request.eval ρ) := by
  have sliceBound : (logCodec.decode ρ
      (.take request.entries.length (.drop request.previousIndex state.log))).length ≤ capacity := by
    simp only [log_take, log_drop, List.length_take, List.length_drop]
    exact le_trans (Nat.min_le_right _ _) (le_trans (Nat.sub_le _ _) stateBound)
  simp only [alreadyApplied, eval_or, eval_and, eval_le, Bool.or_eq_true,
    Bool.and_eq_true, equal_decide Codec.nat, Codec.decode, Codec.nat, Equiv.refl_apply]
  simp only [Expr.eval, terms_correct ρ capacity _ sliceBound,
    terms_correct ρ capacity request.entries requestBound, decide_eq_true_eq, log_take, log_drop,
    ← log_length]
  simp [alreadyDone, Local.eval, Append.eval, ← List.length_eq_zero_iff,
    ← log_length, Expr.eval]

def extension (state : Local) (request : Append) : Expr .bool :=
  (Expr.not (.eq request.entries.length (.nat 0))).and
    ((request.previousIndex.le state.log.length).and
      ((Expr.lt state.log.length (.add request.previousIndex request.entries.length)).and
        (logPrefixEqual (.sub state.log.length request.previousIndex)
          (.drop request.previousIndex state.log) request.entries)))

theorem extension_correct (ρ : Assignment) (state : Local) (request : Append) :
    (extension state request).eval ρ = true ↔ noConflictExtension (state.eval ρ) (request.eval ρ) := by
  simp only [extension, eval_and, eval_not, Bool.and_eq_true, Bool.not_eq_true,
    eval_le, logPrefixEqual_correct, log_drop]
  simp only [Expr.eval, decide_eq_true_eq, decide_eq_false_iff_not]
  simp [noConflictExtension, Local.eval, Append.eval, ← List.length_eq_zero_iff,
    ← log_length, Expr.eval]
  intro _ _ _
  simpa only [log_drop, Expr.eval] using
    logPrefixEqual_correct ρ (.sub state.log.length request.previousIndex)
      (.drop request.previousIndex state.log) request.entries

def termConflict (capacity : Nat) (state : Local) (request : Append) : Expr .bool :=
  let overlap := minimum request.entries.length (.sub state.log.length request.previousIndex)
  (Expr.not (.eq request.entries.length (.nat 0))).and
    (.not (.eq (terms capacity (.take overlap (.drop request.previousIndex state.log)))
      (terms capacity (.take overlap request.entries))))

theorem termConflict_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    (termConflict capacity state request).eval ρ = true ↔
      hasTermConflict (state.eval ρ) (request.eval ρ) := by
  have leftBound (n : Expr .nat) :
      (logCodec.decode ρ (.take n (.drop request.previousIndex state.log))).length ≤ capacity := by
    simp only [log_take, log_drop, List.length_take, List.length_drop]
    exact le_trans (Nat.min_le_right _ _) (le_trans (Nat.sub_le _ _) stateBound)
  have rightBound (n : Expr .nat) : (logCodec.decode ρ (.take n request.entries)).length ≤ capacity := by
    simp only [log_take, List.length_take]
    exact le_trans (Nat.min_le_right _ _) requestBound
  simp only [termConflict, eval_and, eval_not, Bool.and_eq_true, Bool.not_eq_true]
  simp only [Expr.eval, terms_correct ρ capacity _ (leftBound _),
    terms_correct ρ capacity _ (rightBound _), minimum_correct, log_take, log_drop,
    decide_eq_false_iff_not]
  simp [hasTermConflict, overlapLength, Local.eval, Append.eval,
    ← List.length_eq_zero_iff, ← log_length, Expr.eval]

def committed (capacity : Nat) (state : Local) (request : Append) (log : Expr logCodec.ty) :
    Expr .nat :=
  maximum state.commitIndex
    (maxCommittable capacity (.take
      (minimum request.leaderCommit (.add request.previousIndex request.entries.length)) log))

theorem committed_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (committed capacity state request log).eval ρ =
      committedFromLeader (state.eval ρ) (request.eval ρ) (logCodec.decode ρ log) := by
  have takeBound (n : Expr .nat) : (logCodec.decode ρ (.take n log)).length ≤ capacity := by
    simp only [log_take, List.length_take]
    exact le_trans (Nat.min_le_right _ _) bound
  simp only [committed, maximum_correct, maxCommittable_correct ρ capacity _ (takeBound _),
    log_take, minimum_correct]
  simp only [committedFromLeader, maxCommittableIndexUpTo, Local.eval, Append.eval]
  rw [show (Expr.add request.previousIndex request.entries.length).eval ρ =
    request.previousIndex.eval ρ + (logCodec.decode ρ request.entries).length from
      congrArg (request.previousIndex.eval ρ + ·) (log_length ρ request.entries)]

def ack (state : Local) (request : Append) (index : Expr .nat) : Expr appendResponseCodec.ty :=
  .pair state.currentTerm (.pair (.bool true) (.pair index (.pair request.destination request.source)))

@[simp] theorem ack_correct (ρ : Assignment) (state : Local) (request : Append) (index : Expr .nat) :
    appendResponseCodec.decode ρ (ack state request index) =
      successResponse (state.eval ρ) (request.eval ρ) (index.eval ρ) := rfl

def applied (capacity : Nat) (state : Local) (request : Append) :
    Expr (nodeStateCodec.prod appendResponseCodec).option.ty :=
  let updated := { state with commitIndex := committed (capacity * 2) state request state.log }
  .ite (alreadyApplied capacity state request)
    (.inr (.pair updated.pack (ack updated request (.add request.previousIndex request.entries.length))))
    (.inl .unit)

theorem applied_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    (nodeStateCodec.prod appendResponseCodec).option.decode ρ (applied capacity state request) =
      appendEntriesAlreadyDone? (state.eval ρ) (request.eval ρ) := by
  simp only [applied, decode_choose, alreadyApplied_correct ρ capacity state request stateBound requestBound,
    decode_some, decode_none, decode_pair, Local.pack_correct, ack_correct]
  have wide : (logCodec.decode ρ state.log).length ≤ capacity * 2 :=
    le_trans stateBound (by omega)
  simp only [Local.eval, committed_correct ρ (capacity * 2) state request state.log wide]
  simp only [appendEntriesAlreadyDone?, Local.eval, Append.eval, Expr.eval]
  simp only [← log_length, Expr.eval]

def extended (capacity : Nat) (state : Local) (request : Append) :
    Expr (nodeStateCodec.prod appendResponseCodec).option.ty :=
  let log := Expr.append (.take request.previousIndex state.log) request.entries
  let updated := { state with log := log, commitIndex := committed (capacity * 2) state request log }
  .ite (extension state request)
    (.inr (.pair updated.pack (ack updated request log.length))) (.inl .unit)

theorem extended_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    (nodeStateCodec.prod appendResponseCodec).option.decode ρ (extended capacity state request) =
      noConflictAppendEntriesRequest? (state.eval ρ) (request.eval ρ) := by
  have wide : (logCodec.decode ρ (.append (.take request.previousIndex state.log) request.entries)).length ≤
      capacity * 2 := by
    simp only [log_append, log_take, List.length_append, List.length_take]
    exact le_trans (Nat.add_le_add (le_trans (Nat.min_le_right _ _) stateBound) requestBound) (by omega)
  simp only [extended, decode_choose, extension_correct ρ state request, decode_some, decode_none,
    decode_pair, Local.pack_correct, ack_correct, log_length]
  simp only [Local.eval, committed_correct ρ (capacity * 2) state request _ wide, log_append, log_take]
  rfl

def truncated (state : Local) (request : Append) : Local :=
  { state with log := .take request.previousIndex state.log, isNewFollower := .bool false }

def conflict (capacity : Nat) (state : Local) (request : Append) : Expr nodeStateCodec.option.ty :=
  .ite ((termConflict capacity state request).and state.isNewFollower)
    (.inr (truncated state request).pack) (.inl .unit)

theorem conflict_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    nodeStateCodec.option.decode ρ (conflict capacity state request) =
      conflictAppendEntriesRequest? (state.eval ρ) (request.eval ρ) := by
  simp only [conflict, decode_choose, eval_and, Bool.and_eq_true,
    termConflict_correct ρ capacity state request stateBound requestBound,
    decode_some, decode_none, Local.pack_correct]
  simp only [truncated, Local.eval, log_take, Expr.eval]
  rfl

def optionOr {A : Type} (c : Codec A) (first second : Expr c.option.ty) : Expr c.option.ty :=
  .ite (Expr.testLeft first) second first

theorem optionOr_correct {A : Type} (c : Codec A) (ρ : Assignment)
    (first second : Expr c.option.ty) :
    c.option.decode ρ (optionOr c first second) =
      match c.option.decode ρ first with
      | some value => some value
      | none => c.option.decode ρ second := by
  cases h : first.eval ρ <;>
    simp [optionOr, Codec.decode, Codec.option, Expr.testLeft_correct, Expr.eval, h]

def nackPacket (request : Append) (term index : Expr .nat) : Expr appendResponseCodec.ty :=
  .pair term (.pair (.bool false) (.pair index (.pair request.destination request.source)))

@[simp] theorem nackPacket_correct (ρ : Assignment) (request : Append) (term index : Expr .nat) :
    appendResponseCodec.decode ρ (nackPacket request term index) =
      { term := term.eval ρ, success := false, lastLogIndex := index.eval ρ,
        source := (request.eval ρ).destination, destination := (request.eval ρ).source } := rfl

def failure (capacity : Nat) (state : Local) (request : Append) : Expr appendResponseCodec.ty :=
  let plain := nackPacket request state.currentTerm state.log.length
  let previousTerm := Expr.ite (.eq request.previousIndex (.nat 0)) (.nat 0)
    (.ite (.lt state.log.length request.previousIndex) (.nat 0) (termAt state.log state.log.length))
  let index := highestMatch capacity state.log request.previousIndex request.previousTerm
  .ite (.lt request.term state.currentTerm) plain <|
  .ite (.eq previousTerm (.nat 0)) plain <|
    nackPacket request (.ite (.eq index (.nat 0)) (.nat TERM_ONE) (termAt state.log index)) index

theorem failure_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    appendResponseCodec.decode ρ (failure capacity state request) =
      failureResponse (state.eval ρ) (request.eval ρ) := by
  simp only [failure, decode_choose, nackPacket_correct, Expr.eval, termAt_correct,
    highestMatch_correct ρ capacity state.log _ _ bound, decide_eq_true_eq]
  simp only [failureResponse, Local.eval, Append.eval, ← log_length, Expr.eval]

def rejectGuard (state : Local) (request : Append) : Expr .bool :=
  (Expr.lt request.term state.currentTerm).or
    ((Expr.eq request.term state.currentTerm).and
      ((Expr.eq state.role (roleCodec.literal .follower)).and (logConsistent state request).not))

theorem rejectGuard_correct (ρ : Assignment) (state : Local) (request : Append) :
    (rejectGuard state request).eval ρ = true ↔
      (request.eval ρ).term < (state.eval ρ).currentTerm ∨
        ((request.eval ρ).term = (state.eval ρ).currentTerm ∧
          (state.eval ρ).role = .follower ∧ ¬logOk (state.eval ρ) (request.eval ρ)) := by
  have consistent : (logConsistent state request).eval ρ =
      decide (logOk (state.eval ρ) (request.eval ρ)) :=
    Bool.eq_iff_iff.mpr (by
      simpa only [decide_eq_true_eq] using logConsistent_correct ρ state request)
  simp only [rejectGuard, eval_or, eval_and, eval_not, consistent, Bool.or_eq_true,
    Bool.and_eq_true, equal_decide roleCodec, Codec.decode_literal]
  simp only [Expr.eval, decide_eq_true_eq, Bool.not_eq_true, decide_eq_false_iff_not]
  simp [Local.eval, Append.eval]

def rejected (capacity : Nat) (state : Local) (request : Append) :
    Expr (nodeStateCodec.prod appendResponseCodec).option.ty :=
  .ite (rejectGuard state request) (.inr (.pair state.pack (failure capacity state request)))
    (.inl .unit)

theorem rejected_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (nodeStateCodec.prod appendResponseCodec).option.decode ρ (rejected capacity state request) =
      rejectAppendEntriesRequest? (state.eval ρ) (request.eval ρ) := by
  simp only [rejected, decode_choose, rejectGuard_correct ρ state request, decode_some, decode_none,
    decode_pair, Local.pack_correct, failure_correct ρ capacity state request bound]
  rfl

def acceptGuard (state : Local) (request : Append) : Expr .bool :=
  (Expr.eq request.term state.currentTerm).and
    ((Expr.eq state.role (roleCodec.literal .follower)).and
      ((logConsistent state request).and (state.commitIndex.le request.previousIndex)))

theorem acceptGuard_correct (ρ : Assignment) (state : Local) (request : Append) :
    (acceptGuard state request).eval ρ = true ↔
      (request.eval ρ).term = (state.eval ρ).currentTerm ∧
        (state.eval ρ).role = .follower ∧ logOk (state.eval ρ) (request.eval ρ) ∧
          (state.eval ρ).commitIndex ≤ (request.eval ρ).prevLogIndex := by
  simp only [acceptGuard, eval_and, Bool.and_eq_true, equal_decide roleCodec,
    Codec.decode_literal, logConsistent_correct ρ state request, eval_le, decide_eq_true_eq]
  simp only [Expr.eval, decide_eq_true_eq]
  rfl

def accepted (capacity : Nat) (state : Local) (request : Append) :
    Expr (nodeStateCodec.prod appendResponseCodec).option.ty :=
  let result := nodeStateCodec.prod appendResponseCodec
  let retry := optionOr result (applied capacity (truncated state request) request)
    (extended capacity (truncated state request) request)
  .ite (acceptGuard state request)
    (optionOr result (applied capacity state request)
      (optionOr result (extended capacity state request)
        (.ite ((termConflict capacity state request).and state.isNewFollower) retry (.inl .unit))))
    (.inl .unit)

theorem accepted_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    (nodeStateCodec.prod appendResponseCodec).option.decode ρ (accepted capacity state request) =
      acceptAppendEntriesRequest? (state.eval ρ) (request.eval ρ) := by
  have truncatedBound : (logCodec.decode ρ (truncated state request).log).length ≤ capacity := by
    simp only [truncated, log_take, List.length_take]
    exact le_trans (Nat.min_le_right _ _) stateBound
  simp only [accepted, decode_choose, acceptGuard_correct ρ state request, decode_none,
    optionOr_correct, applied_correct ρ capacity state request stateBound requestBound,
    extended_correct ρ capacity state request stateBound requestBound,
    applied_correct ρ capacity (truncated state request) request truncatedBound requestBound,
    extended_correct ρ capacity (truncated state request) request truncatedBound requestBound,
    eval_and, Bool.and_eq_true, termConflict_correct ρ capacity state request stateBound requestBound]
  unfold acceptAppendEntriesRequest?
  by_cases guard :
      (request.eval ρ).term = (state.eval ρ).currentTerm ∧
        (state.eval ρ).role = .follower ∧ logOk (state.eval ρ) (request.eval ρ) ∧
          (state.eval ρ).commitIndex ≤ (request.eval ρ).prevLogIndex
  all_goals simp only [guard, and_self, ↓reduceIte]
  · cases first : appendEntriesAlreadyDone? (state.eval ρ) (request.eval ρ) with
    | some value => rfl
    | none =>
      cases second : noConflictAppendEntriesRequest? (state.eval ρ) (request.eval ρ) with
      | some value => rfl
      | none =>
        simp only [conflictAppendEntriesRequest?]
        have same : (truncated state request).eval ρ =
            { state.eval ρ with
              log := (state.eval ρ).log.take (request.eval ρ).prevLogIndex
              isNewFollower := false } := by
          simp only [truncated, Local.eval, log_take, Expr.eval]
          rfl
        rw [same]
        by_cases hc : hasTermConflict (state.eval ρ) (request.eval ρ) ∧ state.isNewFollower.eval ρ = true
        · simp only [show hasTermConflict (state.eval ρ) (request.eval ρ) ∧
            (state.eval ρ).isNewFollower = true from hc, hc, and_self, ↓reduceIte]
          rw [← same]
          cases appendEntriesAlreadyDone? ((truncated state request).eval ρ) (request.eval ρ) <;> rfl
        · simp only [show ¬(hasTermConflict (state.eval ρ) (request.eval ρ) ∧
            (state.eval ρ).isNewFollower = true) from hc, hc, and_self, ↓reduceIte]

def appendRequest (capacity : Nat) (state : Local) (request : Append) :
    Expr (nodeStateCodec.prod appendResponseCodec).option.ty :=
  optionOr (nodeStateCodec.prod appendResponseCodec)
    (rejected capacity state request) (accepted capacity state request)

theorem appendRequest_correct (ρ : Assignment) (capacity : Nat) (state : Local) (request : Append)
    (stateBound : (logCodec.decode ρ state.log).length ≤ capacity)
    (requestBound : (logCodec.decode ρ request.entries).length ≤ capacity) :
    (nodeStateCodec.prod appendResponseCodec).option.decode ρ (appendRequest capacity state request) =
      handleAppendEntriesRequest? (state.eval ρ) (request.eval ρ) := by
  simp only [appendRequest, optionOr_correct, rejected_correct ρ capacity state request stateBound,
    accepted_correct ρ capacity state request stateBound requestBound]
  unfold handleAppendEntriesRequest?
  cases rejectAppendEntriesRequest? (state.eval ρ) (request.eval ρ) <;> rfl

end CCFRaft.SymbolicReceive
