module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.GenModel
public import MidTrace.Model.InitInvariant

@[expose] public section

/-!
# Necessary, not sufficient, conditions on a cut

`SafetyInvariant.lean`: `CommitFrontier`, `Terms`, `Sorted`, `Active`, `Candidate`,
`LeaderLogs` and `RootedLogs` give the local log, term, campaign and genesis clauses.
The self vote is installed by `becomeCandidate` and only extended during candidacy;
`initialNodeState` and `primaryState` set primary knowledge, and clearing it leaves the role.
`Properties.election_safety` and `committed_logs_prefix` give the two pairwise clauses;
`constrain` states the latter against one shared unknown log, in `O(n)` folds.
Packet bounds project `Messages`, `MessageTerms`, `TermMono`, `Candidate`, `AEOk` and
`Sorted`. The primary sends empty heartbeats or a term-uniform `sendEntries` batch;
broadcasts and nominations exclude self, and a reply reverses a non-self envelope.

There is no prefix witness: we omit historical votes/grants, past leadership and
canonical logs, election/commit backing, acknowledgements, persistence, completeness,
and message provenance. An empty bootstrap means the genesis membership is unknown.
-/

namespace Consensus.MidTrace.InitInvariant

open CCF (Finset)
open Model.Node (NodeID)
open Gen

def constrainNode (c : Ctx) (bootstrap : Finset NodeID) (self : Nat) (s : SNode)
    : GM Unit := do
  let ck t clause := require t s!"node {self}: {clause}"
  let log := s.log
  ck (← andL [← le s.ci log.len, ← orL [← eqK s.ci 0, ← isSignatureAt log s.ci]])
    "commit_frontier"
  ck (← log.all fun e => le e[E_TERM]! s.ct) "terms_bounded"
  ck
    (← foldAll (.int 1) (← addK log.len (-1))
        fun k => do
          le (← log.getF (← addK k (-1)) E_TERM) (← log.getF k E_TERM))
    "terms_sorted"
  let idle ← andL [← eqK s.role ROLE_FOLLOWER, ← eqK s.ct 0, ← log.isEmpty]
  ck (← orL [← eqK s.role ROLE_NONE, idle, ← le (.int Model.BOOTSTRAP_TERM) s.ct])
    "active_term"
  ck
    (← impliesT (← eqK s.role ROLE_CANDIDATE)
        (← andL
            [
              ← le (.int 3) s.ct,
              ← eqK s.vf self,
              s.votes[self]!,
              ← log.all (fun e => lt e[E_TERM]! s.ct)
            ]))
    "candidate_invariants"
  ck (← impliesT (← eqK s.role ROLE_PRIMARY) (← andL [← lt (.int 0) log.len, s.pk]))
    "leader_invariants"
  let root ← log.get (.int 0)
  let known ←
    if bootstrap.Nonempty then
      andL
        [
          ← eqK root[E_REQ]! 0,
          ← SSet.eqS (root.extract E_CFG_START (E_RC_START c.n)) (c.bitsOf bootstrap)
        ]
    else
      pure (.bool true)
  ck
    (← impliesT (← lt (.int 0) log.len)
        (← andL
            [
              ← eqK root[E_TERM]! Model.BOOTSTRAP_TERM,
              ← notT root[E_SIG]!,
              root[E_HAS_CFG]!,
              ← notT (← SSet.nonempty (root.extract (E_RC_START c.n) root.size)),
              known
            ]))
    "rooted_logs"

def constrainMessage (src dst : Nat) (atCut : Nat → SNode) (present : Tm) (m : SMsg)
    : GM Unit := do
  let term := m[M_TERM]!
  let tag := m[M_TAG]!
  let ck t := do
    require (← impliesT present t) s!"message_invariants: {src} -> {dst}"
  ck (← andL [.bool (src != dst), ← le term (atCut src).ct])
  let entries := msgEntries m
  let firstTerm ← entries.getF (.int 0) E_TERM
  let prevTerm := m[M_PREV_TERM]!
  ck
    (← impliesT (← eqK tag TAG_AE)
        (← andL
            [
              ← le (.int 2) term,
              ← le prevTerm term,
              ← impliesT (← eqK m[M_PREV]! 0) (← eqK prevTerm 0),
              ← entries.all
                  (fun e => do
                    andL
                      [
                        ← le prevTerm e[E_TERM]!,
                        ← le e[E_TERM]! term,
                        ← eqT e[E_TERM]! firstTerm
                      ])
            ]))
  ck (← impliesT (← andL [← eqK tag TAG_AER, m[M_SUCCESS]!]) (← le (.int 2) term))
  ck
    (← impliesT (← eqK tag TAG_RV) (← andL [← le (.int 3) term, ← lt m[M_LC_TERM]! term]))
  ck
    (← impliesT (← eqK tag TAG_RPV)
        (← andL [← le (.int 2) term, ← le m[M_LC_TERM]! term]))
  ck
    (← impliesT (← andL [← eqK tag TAG_RVR, m[M_GRANTED]!])
        (← andL [← le (.int 3) term, ← le term (atCut dst).ct]))
  ck (← impliesT (← eqK tag TAG_PROPOSE) (← le (.int 2) term))

def constrain (c : Ctx) (bootstrap : Finset NodeID) (nodes : Array SNode) : GM Unit := do
  -- Committed logs are pairwise comparable iff each agrees with one shared log (the
  -- longest) up to its commit index. Its length is never read.
  let canon ← if 1 < c.n then some <$> declareLog c (.int 0) else pure none
  for i in c.nodes do
    let a := nodes[i]!
    constrainNode c bootstrap i a
    for j in [i + 1:c.n] do
      let b := nodes[j]!
      require
        (← notT
            (← andL
                [← eqK a.role ROLE_PRIMARY, ← eqK b.role ROLE_PRIMARY, ← eqT a.ct b.ct]))
        s!"nodes {i}, {j}: election_safety"
    if let some canon := canon then
      let hi ← addK a.ci (-1)
      require
        (← foldAll (.int 0) hi fun k => do SSet.eqS (← a.log.get k) (← canon.get k))
        s!"node {i}: committed_logs_comparable"

end Consensus.MidTrace.InitInvariant
