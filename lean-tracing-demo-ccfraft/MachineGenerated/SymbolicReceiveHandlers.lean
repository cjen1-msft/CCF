-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveData

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

theorem eval_not (ρ : Assignment) (x : Expr .bool) :
    (Expr.not x).eval ρ = !(x.eval ρ) := rfl

theorem eval_and (ρ : Assignment) (x y : Expr .bool) :
    (Expr.and x y).eval ρ = (x.eval ρ && y.eval ρ) := rfl

theorem nodeInsert_correct (ρ : Assignment) (bits : Expr nodeSetCodec.ty)
    (node : Expr nodeCodec.ty) :
    nodeSetCodec.decode ρ (setInsert bits (finValue node)) =
      insert (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ bits) := by
  ext i
  simp only [setInsert_correct, finValue_correct, Finset.mem_insert]
  change ((nodeCodec.decode ρ node).val = i.val ∨ _) ↔ _
  simp only [Fin.val_inj, eq_comm]

@[simp] theorem decode_some {A : Type} (c : Codec A) (ρ : Assignment) (x : Expr c.ty) :
    c.option.decode ρ (.inr x) = some (c.decode ρ x) := rfl

@[simp] theorem decode_none {A : Type} (c : Codec A) (ρ : Assignment) :
    c.option.decode ρ (.inl .unit) = none := rfl

@[simp] theorem decode_pair {A B : Type} (a : Codec A) (b : Codec B)
    (ρ : Assignment) (x : Expr a.ty) (y : Expr b.ty) :
    (a.prod b).decode ρ (.pair x y) = (a.decode ρ x, b.decode ρ y) := rfl

theorem equal_decide {A : Type} [DecidableEq A] (c : Codec A)
    (ρ : Assignment) (x y : Expr c.ty) :
    (Expr.eq x y).eval ρ = decide (c.decode ρ x = c.decode ρ y) := by
  apply Bool.eq_iff_iff.mpr
  simp only [c.equal_correct, decide_eq_true_eq]

def returnToFollower (state : Local) (request : Expr appendRequestCodec.ty) :
    Expr nodeStateCodec.option.ty :=
  .ite ((Expr.eq request.fst state.currentTerm).and
    ((Expr.eq state.role (roleCodec.literal .candidate)).or
      (.eq state.role (roleCodec.literal .preVoteCandidate))))
    (.inr { state with role := roleCodec.literal .follower, isNewFollower := .bool true }.pack)
    (.inl .unit)

theorem returnToFollower_correct (ρ : Assignment) (state : Local)
    (request : Expr appendRequestCodec.ty) :
    nodeStateCodec.option.decode ρ (returnToFollower state request) =
      returnToFollowerState? (state.eval ρ) (appendRequestCodec.decode ρ request) := by
  simp only [returnToFollower, decode_choose, eval_and, Bool.and_eq_true, eval_or,
    Bool.or_eq_true, roleCodec.equal_correct, Codec.decode_literal, decide_eq_true_eq,
    decode_some, decode_none, Local.pack_correct]
  simp only [Expr.eval, decide_eq_true_eq]
  rfl

def voteResponse (state : Local) (response : Expr voteResponseCodec.ty) :
    Expr nodeStateCodec.option.ty :=
  .ite (.lt response.fst state.currentTerm) (.inr state.pack) <|
  .ite (.not (.eq state.role (roleCodec.literal .candidate))) (.inr state.pack) <|
  .ite (.eq response.fst state.currentTerm)
    (.ite response.snd.fst
      (.inr { state with votesGranted := setInsert state.votesGranted (finValue response.snd.snd.fst) }.pack)
      (.inr state.pack))
    (.inl .unit)

theorem voteResponse_correct (ρ : Assignment) (state : Local)
    (response : Expr voteResponseCodec.ty) :
    nodeStateCodec.option.decode ρ (voteResponse state response) =
      handleRequestVoteResponse? (state.eval ρ) (voteResponseCodec.decode ρ response) := by
  simp only [voteResponse, decode_choose, decode_some, decode_none, Local.pack_correct,
    eval_not, equal_decide roleCodec, Codec.decode_literal]
  simp only [Local.eval, nodeInsert_correct]
  simp [handleRequestVoteResponse?,
    Codec.decode, Codec.transport, Codec.prod, Codec.nat, Codec.bool, Bool.not_eq_true, Expr.eval]

def preVoteResponse (state : Local) (response : Expr preVoteResponseCodec.ty) :
    Expr nodeStateCodec.option.ty :=
  .ite (.lt response.fst state.currentTerm) (.inr state.pack) <|
  .ite (.not (.eq state.role (roleCodec.literal .preVoteCandidate))) (.inr state.pack) <|
  .ite (.eq response.fst state.currentTerm)
    (.ite response.snd.fst
      (.inr { state with preVotesGranted := setInsert state.preVotesGranted (finValue response.snd.snd.fst) }.pack)
      (.inr state.pack))
    (.inl .unit)

theorem preVoteResponse_correct (ρ : Assignment) (state : Local)
    (response : Expr preVoteResponseCodec.ty) :
    nodeStateCodec.option.decode ρ (preVoteResponse state response) =
      handleRequestPreVoteResponse? (state.eval ρ) (preVoteResponseCodec.decode ρ response) := by
  simp only [preVoteResponse, decode_choose, decode_some, decode_none, Local.pack_correct,
    eval_not, equal_decide roleCodec, Codec.decode_literal]
  simp only [Local.eval, nodeInsert_correct]
  simp [handleRequestPreVoteResponse?,
    Codec.decode, Codec.transport, Codec.prod, Codec.nat, Codec.bool, Bool.not_eq_true, Expr.eval]

def highestMatch (capacity : Nat) (log : Expr logCodec.ty) (index term : Expr .nat) :
    Expr .nat :=
  rangeFold (capacity + 1) (.add (minimum index log.length) (.nat 1))
    (fun best candidate =>
      .ite ((Expr.lt (.nat 0) candidate).and ((termAt log candidate).le term))
        (maximum best candidate) best) (.nat 0)

theorem highestMatch_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (index term : Expr .nat) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (highestMatch capacity log index term).eval ρ =
      findHighestPossibleMatch (logCodec.decode ρ log) (index.eval ρ) (term.eval ρ) := by
  have h := rangeFold_correct Codec.nat ρ (capacity + 1)
    (.add (minimum index log.length) (.nat 1))
    (fun best candidate =>
      .ite ((Expr.lt (.nat 0) candidate).and ((termAt log candidate).le term))
        (maximum best candidate) best) (.nat 0)
    (fun best candidate =>
      if candidate > 0 ∧ CCFRaft.termAt (logCodec.decode ρ log) candidate ≤ term.eval ρ then
        max best candidate else best) (by
      intro best candidate
      change (Expr.ite _ _ _).eval ρ = _
      simp only [Expr.eval, eval_le, termAt_correct, maximum_correct,
        Bool.and_eq_true, decide_eq_true_eq]
      rfl) (by
      simp only [Expr.eval, minimum_correct]
      have length : (log.eval ρ : List entryCodec.ty.Value).length ≤ capacity := by
        simpa [Codec.decode, Codec.list] using bound
      exact Nat.add_le_add_right (le_trans (Nat.min_le_right _ _) length) 1)
  simpa [highestMatch, findHighestPossibleMatch, Codec.decode, Codec.nat,
    Codec.list, Expr.eval] using h

theorem indicesStore_correct (ρ : Assignment) (indices : Expr (nodeTableCodec Codec.nat).ty)
    (node : Expr nodeCodec.ty) (value : Expr .nat) :
    ((nodeTableCodec Codec.nat).decode ρ (tableStore indices (finValue node) value)).get =
      updateIndex ((nodeTableCodec Codec.nat).decode ρ indices).get
        (nodeCodec.decode ρ node) (value.eval ρ) := by
  funext n
  rw [nodeTableStore_correct]
  simp [updateIndex, Function.update_apply, eq_comm, Codec.decode, Codec.nat]

theorem indicesSelect_correct (ρ : Assignment) (indices : Expr (nodeTableCodec Codec.nat).ty)
    (node : Expr nodeCodec.ty) :
    (tableSelect indices node).eval ρ =
      ((nodeTableCodec Codec.nat).decode ρ indices).get (nodeCodec.decode ρ node) :=
  nodeTableSelect_correct Codec.nat ρ indices node

def appendResponse (capacity : Nat) (state : Local) (response : Expr appendResponseCodec.ty) :
    Expr nodeStateCodec.option.ty :=
  let source := response.snd.snd.snd.fst
  let index := response.snd.snd.fst
  let matched := tableSelect state.matchIndex source
  let possible := highestMatch capacity state.log index response.fst
  let ack : Local :=
    { state with
      matchIndex := tableStore state.matchIndex (finValue source) (maximum matched index) }
  let nack : Local :=
    { state with
      sentIndex := tableStore state.sentIndex (finValue source)
        (maximum (minimum possible (tableSelect state.sentIndex source)) matched) }
  .ite (response.snd.fst.and ((Expr.eq response.fst state.currentTerm).and
      (.eq state.role (roleCodec.literal .leader)))) (.inr ack.pack) <|
  .ite response.snd.fst.not (.inr nack.pack) <|
  .ite (.not (.eq state.role (roleCodec.literal .leader))) (.inr state.pack) <|
  .ite (.lt response.fst state.currentTerm) (.inr state.pack) (.inl .unit)

theorem appendResponse_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (response : Expr appendResponseCodec.ty)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    nodeStateCodec.option.decode ρ (appendResponse capacity state response) =
      handleAppendEntriesResponse? (state.eval ρ) (appendResponseCodec.decode ρ response) := by
  simp only [appendResponse, decode_choose, decode_some, decode_none, Local.pack_correct,
    eval_and, eval_not, equal_decide roleCodec, Codec.decode_literal]
  simp only [Local.eval, indicesStore_correct, maximum_correct, minimum_correct,
    indicesSelect_correct, highestMatch_correct ρ capacity state.log _ _ bound]
  simp [handleAppendEntriesResponse?, Codec.decode, Codec.transport, Codec.prod,
    Codec.nat, Codec.bool, Expr.eval]

def voteLogFresh (capacity : Nat) (state : Local) (request : Expr voteRequestCodec.ty) :
    Expr .bool :=
  let index := maxCommittable capacity state.log
  let term := termAt state.log index
  (Expr.lt term request.snd.fst).or
    ((Expr.eq request.snd.fst term).and (index.le request.snd.snd.fst))

theorem voteLogFresh_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (request : Expr voteRequestCodec.ty)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (voteLogFresh capacity state request).eval ρ = true ↔
      voteLogUpToDate (state.eval ρ) (voteRequestCodec.decode ρ request) := by
  simp only [voteLogFresh, eval_or, Expr.eval, eval_le, termAt_correct,
    maxCommittable_correct ρ capacity state.log bound,
    Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
  rfl

def voteGrant (capacity : Nat) (state : Local) (request : Expr voteRequestCodec.ty) :
    Expr .bool :=
  (Expr.eq request.fst state.currentTerm).and
    ((voteLogFresh capacity state request).and
      ((Expr.eq state.votedFor (.inl .unit)).or
        (.eq state.votedFor (.inr request.snd.snd.snd.fst))))

theorem voteGrant_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (request : Expr voteRequestCodec.ty)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (voteGrant capacity state request).eval ρ =
      decide (let r := voteRequestCodec.decode ρ request
        r.term = (state.eval ρ).currentTerm ∧ voteLogUpToDate (state.eval ρ) r ∧
          ((state.eval ρ).votedFor = none ∨ (state.eval ρ).votedFor = some r.source)) := by
  apply Bool.eq_iff_iff.mpr
  simp only [voteGrant, eval_and, Bool.and_eq_true, eval_or, Bool.or_eq_true,
    nodeCodec.option.equal_correct, decode_none, decode_some, voteLogFresh_correct ρ capacity state request bound,
    decide_eq_true_eq]
  simp only [Expr.eval, decide_eq_true_eq]
  rfl

def voteRequest (capacity : Nat) (state : Local) (request : Expr voteRequestCodec.ty) :
    Expr (nodeStateCodec.prod voteResponseCodec).option.ty :=
  let grant := voteGrant capacity state request
  let next := Expr.ite grant
    { state with votedFor := .inr request.snd.snd.snd.fst }.pack state.pack
  .ite (request.fst.le state.currentTerm)
    (.inr (.pair next (.pair state.currentTerm
      (.pair grant (.pair request.snd.snd.snd.snd request.snd.snd.snd.fst)))))
    (.inl .unit)

theorem voteRequest_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (request : Expr voteRequestCodec.ty)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (nodeStateCodec.prod voteResponseCodec).option.decode ρ
        (voteRequest capacity state request) =
      handleRequestVoteRequest? (state.eval ρ) (voteRequestCodec.decode ρ request) := by
  simp only [voteRequest, decode_choose, decode_some, decode_none, decode_pair,
    Local.pack_correct, eval_le, voteGrant_correct ρ capacity state request bound]
  have response (g : Expr .bool) :
      voteResponseCodec.decode ρ (.pair state.currentTerm
        (.pair g (.pair request.snd.snd.snd.snd request.snd.snd.snd.fst))) =
      { term := (state.eval ρ).currentTerm, voteGranted := g.eval ρ,
        source := (voteRequestCodec.decode ρ request).destination,
        destination := (voteRequestCodec.decode ρ request).source } := rfl
  rw [response, voteGrant_correct ρ capacity state request bound]
  simp only [handleRequestVoteRequest?, decide_eq_true_eq]
  rfl

def preVoteRequest (capacity : Nat) (state : Local) (request : Expr preVoteRequestCodec.ty) :
    Expr (nodeStateCodec.prod preVoteResponseCodec).option.ty :=
  let grant := (Expr.eq request.fst state.currentTerm).and
    (voteLogFresh capacity state request)
  .ite (request.fst.le state.currentTerm)
    (.inr (.pair state.pack (.pair state.currentTerm
      (.pair grant (.pair request.snd.snd.snd.snd request.snd.snd.snd.fst)))))
    (.inl .unit)

theorem preVoteRequest_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (request : Expr preVoteRequestCodec.ty)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (nodeStateCodec.prod preVoteResponseCodec).option.decode ρ
        (preVoteRequest capacity state request) =
      handleRequestPreVote? (state.eval ρ) (preVoteRequestCodec.decode ρ request) := by
  have grant :
      ((Expr.eq request.fst state.currentTerm).and (voteLogFresh capacity state request)).eval ρ =
        decide ((preVoteRequestCodec.decode ρ request).term = (state.eval ρ).currentTerm ∧
          voteLogUpToDate (state.eval ρ) (preVoteRequestCodec.decode ρ request).toRequestVoteRequest) := by
    apply Bool.eq_iff_iff.mpr
    simp only [eval_and, Bool.and_eq_true, voteLogFresh_correct ρ capacity state request bound,
      Expr.eval, decide_eq_true_eq]
    rfl
  simp only [preVoteRequest, decode_choose, decode_some, decode_none, decode_pair,
    Local.pack_correct, eval_le]
  have response (g : Expr .bool) :
      preVoteResponseCodec.decode ρ (.pair state.currentTerm
        (.pair g (.pair request.snd.snd.snd.snd request.snd.snd.snd.fst))) =
      { term := (state.eval ρ).currentTerm, voteGranted := g.eval ρ,
        source := (preVoteRequestCodec.decode ρ request).destination,
        destination := (preVoteRequestCodec.decode ρ request).source } := rfl
  rw [response, grant]
  simp only [handleRequestPreVote?, decide_eq_true_eq]
  rfl

end CCFRaft.SymbolicReceive
