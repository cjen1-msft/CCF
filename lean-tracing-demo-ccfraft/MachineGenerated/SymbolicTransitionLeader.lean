-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionElectionStart
import MachineGenerated.SymbolicTransitionAllocation
import MachineGenerated.SymbolicReceiveData
import MachineGenerated.SymbolicTransitionNormalize

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def truncateLocal (capacity : Nat) (value : Expr localCodec.ty) : Expr localCodec.ty :=
  let fields := SymbolicReceive.Local.unpack value
  { fields with log := takeCompact (maxCommittableExpr capacity fields.log) fields.log }.pack

theorem truncateLocal_correct (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    BoundedState.decodeLocal (localCodec.decode ρ (truncateLocal capacity value)) =
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      { before with log := before.log.take (maxCommittableIndex before.log) } := by
  have unpack := SymbolicReceive.Local.unpack_correct ρ value
  have logeq := congrArg NodeState.log unpack
  change logCodec.decode ρ (SymbolicReceive.Local.unpack value).log =
    (BoundedState.decodeLocal (localCodec.decode ρ value)).log at logeq
  have hb : (logCodec.decode ρ (SymbolicReceive.Local.unpack value).log).length ≤ capacity := by
    rw [show logCodec.decode ρ (SymbolicReceive.Local.unpack value).log = _ from logeq]
    exact bound
  have take (log : Expr logCodec.ty) (n : Expr .nat) :
      logCodec.decode ρ (takeCompact n log) = (logCodec.decode ρ log).take (n.eval ρ) := by
    simp [Codec.decode, Codec.list, takeCompact_correct, List.map_take]
  change SymbolicReceive.nodeStateCodec.decode ρ _ = _
  simp only [truncateLocal, SymbolicReceive.Local.pack_correct]
  change { (SymbolicReceive.Local.unpack value).eval ρ with
    log := logCodec.decode ρ (takeCompact (maxCommittableExpr capacity (SymbolicReceive.Local.unpack value).log)
      (SymbolicReceive.Local.unpack value).log) } = _
  simp only [take, maxCommittableExpr_correct ρ capacity _ hb, logeq, unpack]
  rfl

theorem truncateLocal_log_bound (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (localCodec.decode ρ (truncateLocal capacity value)).log.length ≤ capacity := by
  change (BoundedState.decodeLocal (localCodec.decode ρ (truncateLocal capacity value))).log.length ≤ _
  rw [truncateLocal_correct ρ capacity value bound]
  simpa only [List.length_take] using (Nat.min_le_right _ _).trans bound

def leaderFields (value : Expr localCodec.ty) : Expr localCodec.ty :=
  let fields := SymbolicReceive.Local.unpack value
  { fields with
    role := roleCodec.literal .leader
    sentIndex := tableExpr (fun _ : Node => fields.log.length),
    matchIndex := tableExpr (fun _ : Node => .nat 0) }.pack

theorem leaderFields_correct (ρ : Assignment) (value : Expr localCodec.ty) :
    BoundedState.decodeLocal (localCodec.decode ρ (leaderFields value)) =
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      { before with role := .leader, sentIndex := fun _ => before.log.length, matchIndex := fun _ => 0 } := by
  have unpack := SymbolicReceive.Local.unpack_correct ρ value
  have logeq := congrArg NodeState.log unpack
  have sent :
      ((nodeTableCodec Codec.nat).decode ρ
        (tableExpr fun _ : Node => (SymbolicReceive.Local.unpack value).log.length)).get =
        fun _ => (BoundedState.decodeLocal (localCodec.decode ρ value)).log.length := by
    funext peer
    rw [nodeTableExpr_correct]
    change ((SymbolicReceive.Local.unpack value).log.eval ρ).length = _
    have := congrArg List.length logeq
    simpa [SymbolicReceive.Local.eval, Codec.decode, Codec.list] using this
  have matched :
      ((nodeTableCodec Codec.nat).decode ρ (tableExpr fun _ : Node => Expr.nat 0)).get =
        fun _ => 0 := by
    funext peer
    rw [nodeTableExpr_correct]
    rfl
  change SymbolicReceive.nodeStateCodec.decode ρ _ = _
  simp only [leaderFields, SymbolicReceive.Local.pack_correct]
  change { (SymbolicReceive.Local.unpack value).eval ρ with
    role := roleCodec.decode ρ (roleCodec.literal .leader),
    sentIndex := ((nodeTableCodec Codec.nat).decode ρ
      (tableExpr fun _ : Node => (SymbolicReceive.Local.unpack value).log.length)).get,
    matchIndex := ((nodeTableCodec Codec.nat).decode ρ (tableExpr fun _ : Node => Expr.nat 0)).get } = _
  rw [Codec.decode_literal, sent, matched, unpack]
  rfl

def leaderLocal (capacity : Nat) (node : Expr nodeCodec.ty) (value : Expr localCodec.ty) :
    Expr localCodec.ty :=
  SymbolicReceive.compact
    (refreshRetirementExpr capacity node (leaderFields (truncateLocal capacity value).normalizeMemo).normalizeMemo)

theorem leaderLocal_correct (ρ : Assignment) (capacity : Nat)
    (node : Expr nodeCodec.ty) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    BoundedState.decodeLocal (localCodec.decode ρ (leaderLocal capacity node value)) =
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      let log := before.log.take (maxCommittableIndex before.log)
      refreshRetirementState (nodeCodec.decode ρ node)
        { before with role := .leader, log, sentIndex := fun _ => log.length, matchIndex := fun _ => 0 } := by
  have hb : (localCodec.decode ρ (leaderFields (truncateLocal capacity value).normalizeMemo).normalizeMemo).log.length ≤ capacity := by
    change (BoundedState.decodeLocal (localCodec.decode ρ
      (leaderFields (truncateLocal capacity value).normalizeMemo).normalizeMemo)).log.length ≤ _
    rw [decode_normalizeMemo, leaderFields_correct, decode_normalizeMemo]
    exact truncateLocal_log_bound ρ capacity value bound
  rw [leaderLocal, SymbolicReceive.decode_compact, refreshRetirementExpr_correct ρ capacity node _ hb,
    decode_normalizeMemo, leaderFields_correct, decode_normalizeMemo, truncateLocal_correct ρ capacity value bound]

theorem leaderLocal_log_bound (ρ : Assignment) (capacity : Nat)
    (node : Expr nodeCodec.ty) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (localCodec.decode ρ (leaderLocal capacity node value)).log.length ≤ capacity := by
  change (BoundedState.decodeLocal (localCodec.decode ρ (leaderLocal capacity node value))).log.length ≤ _
  rw [leaderLocal_correct ρ capacity node value bound]
  change ((localCodec.decode ρ value).log.take
    (maxCommittableIndex (localCodec.decode ρ value).log)).length ≤ capacity
  simpa only [List.length_take] using (Nat.min_le_right _ _).trans bound

def leaderEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  .and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .candidate))
      (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
        (.and (configurationMajorities bounds.logCapacity value.snd.snd.snd.snd.snd.snd.snd.snd.fst value)
          (.not (.eq (localMembership
            (refreshRetirementExpr bounds.logCapacity node (truncateLocal bounds.logCapacity value).normalizeMemo))
            (membershipCodec.literal .retiredCommitted))))))

theorem leaderEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (leaderEnabled bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.becomeLeader (nodeCodec.decode ρ node)) := by
  let value := readLocal bounds.transactionCount state node
  have hb := readLocal_log_bound bounds ρ state node within
  have ht : (localCodec.decode ρ (truncateLocal bounds.logCapacity value).normalizeMemo).log.length ≤ bounds.logCapacity := by
    rw [decode_normalizeMemo]
    exact truncateLocal_log_bound ρ bounds.logCapacity value hb
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state node)
  have member := congrArg NodeState.membershipState (readLocal_correct bounds ρ state node)
  have votes := congrArg NodeState.votesGranted (readLocal_correct bounds ρ state node)
  change roleCodec.decode ρ value.fst = _ at role
  change membershipCodec.decode ρ (localMembership value) = _ at member
  change nodeSetCodec.decode ρ value.snd.snd.snd.snd.snd.snd.snd.snd.fst = _ at votes
  have refreshed := congrArg NodeState.membershipState
    (refreshRetirementExpr_correct ρ bounds.logCapacity node (truncateLocal bounds.logCapacity value).normalizeMemo ht)
  rw [decode_normalizeMemo, truncateLocal_correct ρ bounds.logCapacity value hb] at refreshed
  change membershipCodec.decode ρ (localMembership
    (refreshRetirementExpr bounds.logCapacity node (truncateLocal bounds.logCapacity value).normalizeMemo)) = _ at refreshed
  change (Expr.and (allocated bounds.transactionCount state node)
    (.and (.eq value.fst (roleCodec.literal .candidate))
      (.and (.not (.eq (localMembership value) (membershipCodec.literal .retiredCommitted)))
        (.and (configurationMajorities bounds.logCapacity value.snd.snd.snd.snd.snd.snd.snd.snd.fst value)
          (.not (.eq (localMembership
            (refreshRetirementExpr bounds.logCapacity node (truncateLocal bounds.logCapacity value).normalizeMemo))
            (membershipCodec.literal .retiredCommitted))))))).eval ρ = true ↔ _
  simp only [boolAnd_true ρ, boolNot_true ρ, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ value.fst (roleCodec.literal .candidate),
    membershipCodec.equal_correct ρ (localMembership value) (membershipCodec.literal .retiredCommitted),
    membershipCodec.equal_correct ρ (localMembership
      (refreshRetirementExpr bounds.logCapacity node (truncateLocal bounds.logCapacity value).normalizeMemo))
      (membershipCodec.literal .retiredCommitted),
    Codec.decode_literal, role, member, refreshed,
    configurationMajorities_correct ρ bounds.logCapacity _ value hb, votes]
  simp only [value, readLocal_correct]
  rfl

def leaderNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  let value := (leaderLocal bounds.logCapacity node (readLocal bounds.transactionCount state node)).normalizeMemo
  (refreshCompletedExpr bounds bounds.logCapacity
    (writeLocal bounds.transactionCount state node value).normalizeMemo node value).normalizeMemo

theorem leaderNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    evalEntry bounds ρ (leaderNext bounds state node) =
      next (evalEntry bounds ρ state) (.becomeLeader (nodeCodec.decode ρ node)) := by
  have hb := readLocal_log_bound bounds ρ state node within
  have hl : (localCodec.decode ρ
      (leaderLocal bounds.logCapacity node (readLocal bounds.transactionCount state node)).normalizeMemo).log.length ≤
      bounds.logCapacity := by
    rw [decode_normalizeMemo]
    exact leaderLocal_log_bound ρ bounds.logCapacity node _ hb
  rw [leaderNext, evalEntry_normalizeMemo, refreshCompletedExpr_correct bounds ρ bounds.logCapacity _ node _ hl,
    evalEntry_normalizeMemo, writeLocal_correct]
  simp only [decode_normalizeMemo, leaderLocal_correct ρ bounds.logCapacity node _ hb, readLocal_correct]
  rfl

def leaderAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  .and (leaderEnabled bounds state node) (stateWithin bounds (leaderNext bounds state node))

theorem leaderAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (leaderAccepted bounds state node).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.becomeLeader (nodeCodec.decode ρ node)) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ state) (.becomeLeader (nodeCodec.decode ρ node))) := by
  simp only [leaderAccepted, boolAnd_true ρ, leaderEnabled_correct bounds ρ state node within,
    stateWithin_correct bounds ρ, leaderNext_correct bounds ρ state node within]

end CCFRaft.SymbolicTransition
