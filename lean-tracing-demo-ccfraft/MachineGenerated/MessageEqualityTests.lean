-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.MessageEquality

namespace CCFRaft.MessageEquality.Tests

open TraceSmt TransactionMapping

private def node0 : Node := ⟨0, by decide⟩
private def node1 : Node := ⟨1, by decide⟩
private def node2 : Node := ⟨2, by decide⟩

private def packet (transaction : NatTerm 2) (destination : Node := node1) :
    Message Node (NatTerm 2) :=
  .appendEntriesRequest
    { term := 1, prevLogIndex := 0, prevLogTerm := 0,
      entries := [{ term := 1, content := .transaction transaction }],
      leaderCommit := 0, source := node0, destination }

private def first : NatTerm 2 := .unknown 0
private def second : NatTerm 2 := .unknown 1

example : (messageEqual (packet first) (packet second)).Holds (fun _ => 0) := by
  rw [messageEqual_correct]
  decide

example : ¬ (messageEqual (packet first) (packet second)).Holds (fun i => i.val) := by
  rw [messageEqual_correct]
  decide

example : ¬ (messageEqual (packet first) (packet first node2)).Holds (fun _ => 0) := by
  rw [messageEqual_correct]
  decide

example : ¬ (contentEqual (.reconfiguration {node0, node1})
    (.retiredCommitted {node0, node1}) : Expr 0).Holds Fin.elim0 := by
  rw [contentEqual_correct]
  decide

example : ¬ (listEqual entryEqual [] [{ term := 1, content := .signature }] :
    Expr 0).Holds Fin.elim0 := by
  simp [listEqual, Expr.Holds]

example : (entryEqual
    { term := 1, content := .transaction (.named 1 0 "accepted" first) }
    { term := 1, content := .transaction second }).Holds (fun _ => 0) := by
  rw [entryEqual_correct]
  decide

#guard (messageEqual (packet first) (packet second)).toSmt ==
  "(and true (and (and true (= unknown_0 unknown_1)) true))"

#guard (messageEqual (packet first) (packet first node2)).toSmt ==
  "(and false (and (and true (= unknown_0 unknown_0)) true))"

-- Syntactic packet inequality does not survive transaction evaluation.
#guard packet first ≠ packet second
#guard mapMessage (NatTerm.eval (fun _ => 0)) (packet first) =
  mapMessage (NatTerm.eval (fun _ => 0)) (packet second)

end CCFRaft.MessageEquality.Tests
