-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Equality
import TransactionMapping

set_option autoImplicit false

namespace CCFRaft.MessageEquality

open TraceSmt TransactionMapping

def contentEqual {holes : Nat} :
    EntryContent Node (NatTerm holes) ->
    EntryContent Node (NatTerm holes) -> Expr holes
  | .transaction left, .transaction right => .equal left right
  | .signature, .signature => .boolean true
  | .reconfiguration left, .reconfiguration right => .boolean (decide (left = right))
  | .retiredCommitted left, .retiredCommitted right => .boolean (decide (left = right))
  | _, _ => .boolean false

def entryEqual {holes : Nat}
    (left right : Entry Node (NatTerm holes)) : Expr holes :=
  .and (.boolean (decide (left.term = right.term)))
    (contentEqual left.content right.content)

private def requestHeader {holes : Nat}
    (request : AppendEntriesRequest Node (NatTerm holes)) : Message Node Unit :=
  mapMessage (fun (_ : NatTerm holes) => ())
    (.appendEntriesRequest { request with entries := [] })

def messageEqual {holes : Nat} :
    Message Node (NatTerm holes) -> Message Node (NatTerm holes) -> Expr holes
  | .appendEntriesRequest left, .appendEntriesRequest right =>
      .and (.boolean (decide (requestHeader left = requestHeader right)))
        (listEqual entryEqual left.entries right.entries)
  | left, right => .boolean (decide (left = right))

theorem contentEqual_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (left right : EntryContent Node (NatTerm holes)) :
    (contentEqual left right).Holds assignment ↔
      mapEntryContent (NatTerm.eval assignment) left =
        mapEntryContent (NatTerm.eval assignment) right := by
  cases left <;> cases right <;>
    simp [contentEqual, Expr.Holds, mapEntryContent]

theorem entryEqual_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (left right : Entry Node (NatTerm holes)) :
    (entryEqual left right).Holds assignment ↔
      mapEntry (NatTerm.eval assignment) left =
        mapEntry (NatTerm.eval assignment) right := by
  cases left
  cases right
  simp [entryEqual, Expr.Holds, contentEqual_correct, mapEntry]

theorem messageEqual_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (left right : Message Node (NatTerm holes)) :
    (messageEqual left right).Holds assignment ↔
      mapMessage (NatTerm.eval assignment) left =
        mapMessage (NatTerm.eval assignment) right := by
  cases left <;> cases right <;>
    simp [messageEqual, Expr.Holds, mapMessage]
  case appendEntriesRequest.appendEntriesRequest left right =>
    cases left
    cases right
    simp [requestHeader, mapMessage,
      listEqual_correct assignment _ _ (entryEqual_correct assignment),
      and_assoc, and_comm]

end CCFRaft.MessageEquality
