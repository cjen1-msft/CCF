-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendFrontierTerm {width : PNat} (columns : Columns)
    (source destination : Fin width) : Expr .int :=
  let successor := Term.add (peerIndex columns columns.sentIndex source.val (.integer destination.val)) (.integer 1)
  .ite (.le successor (length columns source.val)) successor (length columns source.val)

def appendLeadingGuards {width : PNat} (columns : Columns)
    (source destination : Fin width) (batchEnd : Nat) : List (Expr .bool) :=
  [allocated columns source.val, allocated columns destination.val,
    .equal (read columns columns.role source.val (.integer 0)) (.integer (roleCode .leader)),
    .boolean (decide (source ≠ destination)),
    .equal (.integer batchEnd) (appendFrontierTerm columns source destination),
    .or (.not (.equal (read columns columns.membershipState source.val (.integer 0))
      (.integer (membershipCode .retiredCommitted))))
      (lt (peerIndex columns columns.sentIndex source.val (.integer destination.val)) (.integer batchEnd))]

def appendScanGuards {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (source destination : Fin width) (base : Nat) : List (Expr .bool) :=
  [currentCandidate width columns source.val base, noLaterConfiguration width columns source.val base,
    .or (activeMemberTerm width bootstrap columns source.val destination
      (.free .int base) (.free .int (base + 1)))
      (.bit (.select (.free (.array .int (.bits width)) columns.retirementCompleted)
        (.integer source.val)) destination)]

def appendGuards {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (source destination : Fin width) (batchEnd base : Nat) : List (Expr .bool) :=
  appendLeadingGuards columns source destination batchEnd ++
    appendScanGuards columns bootstrap source destination base

end CCFRaft.NativeEncode
