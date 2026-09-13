-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipRowTerms
import Sparse.NativeRetirementTail
import Sparse.NativeVotingMajority

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def becomeLeaderRowTerms {width : PNat} (old : NodeRowTerms width)
    (latest : Expr .int) : NodeRowTerms width :=
  let length := logRangeMinTerm old.logLength latest
  { old with
    role := .integer (roleCode .leader)
    logLength := length
    sentIndex := membershipSentIndexTerm (width := width) old.sentIndex (.bits (-1)) length
    matchIndex := .defaultValue _ }

def becomeLeaderGuards {width : PNat} (bootstrap : BitVec width) (columns : Columns)
    (source : Fin width) (current membership : Expr .int) : List (Expr .bool) :=
  let old := nodeRowSnapshot columns source
  [allocated columns source.val,
    .equal old.role (.integer (roleCode .candidate)),
    .not (.equal old.membershipState (.integer (membershipCode .retiredCommitted))),
    votingMajorityTerm width bootstrap old.logLength current old.logEntries old.votesGranted,
    .not (.equal membership (.integer (membershipCode .retiredCommitted)))]

def becomeLeader {width : PNat} (source : Fin width) : EncodeM width Unit := do
  let before <- get
  let old := nodeRowSnapshot before.toColumns source
  let latest <- fresh
  assertion (boundedSignatureTerm width old.logLength old.logEntries
    old.logLength (.free .int latest))
  let current <- fresh
  assertion (currentConfigurationIndexTerm width old.logLength old.logEntries
    old.commit (.free .int current))
  retirementTail before.bootstrap source (becomeLeaderRowTerms old (.free .int latest))
    old.commit (becomeLeaderGuards before.bootstrap before.toColumns source (.free .int current))

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
