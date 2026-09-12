-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCampaignMember
import Sparse.NativeVotePacket

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def campaignLeadingGuards {width : PNat} (columns : Columns) (preVote : Bool)
    (node : Fin width) : List (Expr .bool) :=
  [allocated columns node.val,
    .or (.equal (read columns columns.role node.val (.integer 0)) (.integer (roleCode .follower)))
      (.or (.equal (read columns columns.role node.val (.integer 0)) (.integer (roleCode .preVoteCandidate)))
        (.equal (read columns columns.role node.val (.integer 0)) (.integer (roleCode .candidate)))),
    .not (.equal (read columns columns.membershipState node.val (.integer 0)) (.integer (membershipCode .retiredCommitted))),
    .equal (.select (.free (.array .int .bool) columns.preVoteStatus) (.integer node.val))
      (.boolean (preVoteBit (if preVote then .enabled else .capable)))]

def campaignScanGuards {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (node : Fin width) (base : Nat) : List (Expr .bool) :=
  [currentCandidate width columns node.val base,
    noLaterConfiguration width columns node.val base,
    signatureIndexTerm width columns node.val (.free .int (base + 1)),
    .or (campaignMemberTerm width bootstrap columns node
      (.free .int base) (.free .int (base + 1))
      (.free .int (base + 2)))
      (.bit (.select (.free (.array .int (.bits width)) columns.retirementCompleted) (.integer node.val)) node)]

def campaignGuards {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (preVote : Bool) (node : Fin width) (base : Nat) : List (Expr .bool) :=
  campaignLeadingGuards columns preVote node ++ campaignScanGuards columns bootstrap node base

end CCFRaft.NativeEncode
