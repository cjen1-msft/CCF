module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import MidTrace.Tests.Validation

public import MidTrace.Tests.Validation

@[expose] public section

namespace Consensus.MidTrace.Tests.ModelSteps

open Gen Model.Node
open Validation (node message)

private def sameLog (a b : SList) : GM Tm := do
  andL
    [
      ← eqT a.len b.len,
      ← foldAll (.int 0) (← addK a.len (-1)) fun k => do SSet.eqS (← a.get k) (← b.get k)
    ]

private def fields (s : SNode) : Array Tm :=
  #[s.role, s.ct, s.ci, s.nf, s.vf, s.pk, s.rci] ++ s.sent ++ s.mi ++ s.votes ++ s.pv

/-- Compare enabledness, the entire resulting node, and the ordered sends with `Node.step`.
Inactive symbolic branches may leave sends in the IR, but must not emit a packet. -/
private def compareStep (name : String) (c : Ctx) (self : Nat) (before : NodeState)
    (event : Event)
    : Except String Unit := do
  let expected :=
    ((Model.Node.step (CCF.Capabilities.record self) self before event).run {})
  let build : GM Unit := do
    let s ← node c before
    let action ←
      match event with
      | .internal input => pure (act c self s input)
      | .receive src m => pure (Gen.receive c self src s (← message c m))
    let (after, eff) ← action.run {}
    let some (model, outputs) := expected | require (← notT eff.ok) "disabled"; return
    require eff.ok "enabled"
    let want ← node c model
    require (← SSet.eqS (fields after) (fields want)) "state"
    require (← sameLog after.log want.log) "log"
    let mut count : Tm := .int 0
    for (pc, dst, m) in eff.sends do
      let mut matchesPacket := #[]
      for (e, idx) in outputs.outgoing.zipIdx do
        if dst == e.target then
          let want ← message c e.payload
          matchesPacket :=
            matchesPacket.push
              (← andL
                  [
                    ← eqK count idx,
                    ← SSet.eqS (m.extract 0 M_ENT_OFF) (want.extract 0 M_ENT_OFF),
                    ← sameLog (msgEntries m) (msgEntries want)
                  ])
      require (← impliesT pc (← orL matchesPacket.toList)) "packet"
      count ← addT count (← boolInt pc)
    require (← eqK count outputs.outgoing.length) "packet count"
  let (_, enc) := lower (build.run {}).2 {}
  if let some (_, reason) := enc.unsupported then throw s!"{name}: {reason}"
  if let some (_, reason) := enc.falsified then throw s!"{name}: {reason}"
  if enc.out.any (·.startsWith "(assert") then
    throw s!"{name}: expected literal results"

private def scenarios : Except String Unit := do
  let members : CCF.Finset Nat := {0, 1, 2}
  let cfg (ids : CCF.Finset Nat) (rc : CCF.Finset Nat := ∅) : Entry :=
    ⟨2, .transaction 19 { configuration := some ids, retirementConfirmations := rc }⟩
  let sig : Entry := ⟨2, .signature⟩
  let primary := Model.initialNodeState members 0
  let leader := { primary with log := primary.log ++ [cfg {0}, sig, sig] }
  let ack (index : Nat) : Event := .receive 1 (.appendEntriesResponse ⟨2, true, index⟩)
  compareStep "later signature uses newly committed configuration" ⟨3⟩ 0 leader (ack 3)
  compareStep "ignore unknown peer before observing response term" ⟨3⟩ 0
    (Model.initialNodeState {0} 0) (.receive 2 (.appendEntriesResponse ⟨9, false, 0⟩))
  let follower :=
    { (Model.initialNodeState members 1) with log := primary.log, primaryKnown := true }
  let ae (entries : List Entry) : Event :=
    .receive 0 (.appendEntriesRequest ⟨2, 1, 2, entries, 5⟩)
  compareStep "first confirming commit precedes removal" ⟨3⟩ 1 follower
    (ae [cfg members {1}, sig, cfg {0}, sig])
  compareStep "removal before first confirming commit" ⟨3⟩ 1 follower
    (ae [cfg {0} {1}, sig, cfg {2}, sig])
  let candidate :=
    {
      follower with
        role := .candidate,
        log := primary.log ++ [cfg {1}, ⟨1, .signature⟩],
        votesGranted := {1},
        preVotesGranted := {2},
        votedFor := some 1
    }
  compareStep "same-term reset and first overlapping conflict" ⟨3⟩ 1 candidate
    (ae [cfg {2}, sig])
  let signed := { follower with log := primary.log ++ [sig], commitIndex := 2 }
  compareStep "every election timeout starts with pre-vote" ⟨3⟩ 1 signed
    (.internal (.timeout .election))
  compareStep "pre-vote quorum starts candidacy" ⟨3⟩ 1
    { signed with role := .preVoteCandidate, preVotesGranted := {1} }
    (.receive 2 (.requestPreVoteResponse ⟨2, true⟩))
  compareStep "regular vote quorum becomes primary and sends heartbeats" ⟨3⟩ 1
    {
      signed with
        role := .candidate, currentTerm := 3, votedFor := some 1, votesGranted := {1}
    }
    (.receive 2 (.requestVoteResponse ⟨3, true⟩))
  compareStep "snapshot initialization adopts last signed term" ⟨3⟩ 1
    (Model.initialNodeState {0} 1) (.internal (.initAsBackup signed.log))
  let configured := { primary with log := [cfg {0, 1}, cfg {0}, sig], commitIndex := 3 }
  let combined := (cfg {0, 2} {1}).content
  compareStep "pre-append heartbeat, combined metadata and per-entry flushes" ⟨3⟩ 0
    configured (.internal (.append [⟨combined, [(2, 4)]⟩, ⟨.signature, [(2, 5)]⟩]))
  compareStep "cannot rejoin a removed identity" ⟨3⟩ 0 configured
    (.internal (.append [⟨(cfg {0, 1}).content, []⟩]))
  let retiring :=
    {
      primary with
        log :=
          [
            cfg {0, 1, 2, 3},
            cfg {2, 3},
            sig,
            ⟨2, .transaction 1 { retirementConfirmations := {1} }⟩,
            ⟨2, .transaction 2 { retirementConfirmations := {0} }⟩,
            sig
          ],
        commitIndex := 3,
        matchIndex := fun i => if i == 1 then 10 else 6
    }
  compareStep "nominate by precommit rank excluding confirmed peers" ⟨4⟩ 0 retiring
    (.receive 3 (.appendEntriesResponse ⟨2, true, 6⟩))
  -- Timeouts and nominations.
  compareStep "check quorum demotes a primary with peers" ⟨3⟩ 0 primary
    (.internal (.timeout .checkQuorum))
  compareStep "check quorum is disabled without peers" ⟨3⟩ 0
    (Model.initialNodeState {0} 0) (.internal (.timeout .checkQuorum))
  compareStep "check quorum is disabled on a follower" ⟨3⟩ 1 signed
    (.internal (.timeout .checkQuorum))
  compareStep "nominate the most replicated peer" ⟨3⟩ 0
    { primary with matchIndex := fun i => if i == 2 then 1 else 0 }
    (.internal .nominateSuccessor)
  compareStep "nominate is disabled on a follower" ⟨3⟩ 1 signed
    (.internal .nominateSuccessor)
  -- Vote proposals and requests.
  compareStep "vote proposal in the current term starts candidacy" ⟨3⟩ 1 signed
    (.receive 0 (.proposeRequestVoteRequest 2))
  compareStep "vote proposal in another term is ignored" ⟨3⟩ 1 signed
    (.receive 0 (.proposeRequestVoteRequest 3))
  let unled := { signed with primaryKnown := false }
  compareStep "grant a vote" ⟨3⟩ 1 unled (.receive 2 (.requestVoteRequest ⟨2, 2, 2⟩))
  compareStep "grant a vote in a newer term" ⟨3⟩ 1
    { signed with votedFor := some 0 } (.receive 2 (.requestVoteRequest ⟨3, 2, 2⟩))
  compareStep "reject a vote while the primary is known" ⟨3⟩ 1 signed
    (.receive 2 (.requestVoteRequest ⟨2, 2, 2⟩))
  compareStep "reject a vote after voting for another" ⟨3⟩ 1
    { unled with votedFor := some 0 } (.receive 2 (.requestVoteRequest ⟨2, 2, 2⟩))
  compareStep "repeat a vote for the same candidate" ⟨3⟩ 1
    { unled with votedFor := some 2 } (.receive 2 (.requestVoteRequest ⟨2, 2, 2⟩))
  compareStep "reject a vote for a stale log" ⟨3⟩ 1 unled
    (.receive 2 (.requestVoteRequest ⟨2, 2, 1⟩))
  compareStep "grant a pre-vote while the primary is known" ⟨3⟩ 1 signed
    (.receive 2 (.requestPreVoteRequest ⟨2, 2, 2⟩))
  compareStep "reject a pre-vote for a stale log" ⟨3⟩ 1 signed
    (.receive 2 (.requestPreVoteRequest ⟨2, 1, 1⟩))
  -- AppendEntries rejections and ignored requests.
  let diverged :=
    {
      signed with
        currentTerm := 3, log := signed.log ++ [⟨3, .signature⟩, ⟨3, .signature⟩]
    }
  compareStep "NACK with the highest possible match" ⟨3⟩ 1 diverged
    (.receive 0 (.appendEntriesRequest ⟨4, 4, 2, [], 0⟩))
  compareStep "NACK past the end of the log" ⟨3⟩ 1 signed
    (.receive 0 (.appendEntriesRequest ⟨2, 5, 2, [], 0⟩))
  compareStep "NACK a stale term" ⟨3⟩ 1 diverged
    (.receive 0 (.appendEntriesRequest ⟨2, 2, 2, [], 0⟩))
  compareStep "ignore a request below the commit index" ⟨3⟩ 1 signed
    (.receive 0 (.appendEntriesRequest ⟨2, 1, 2, [sig], 2⟩))
  compareStep "ignore a conflict unless a new follower" ⟨3⟩ 1 diverged
    (.receive 0 (.appendEntriesRequest ⟨3, 2, 2, [sig], 0⟩))
  compareStep "a new follower truncates a conflict" ⟨3⟩ 1
    { diverged with isNewFollower := true }
    (.receive 0 (.appendEntriesRequest ⟨3, 2, 2, [sig], 0⟩))
  -- AppendEntries NACKs roll back the sent index, but not below the match index.
  let sending :=
    { primary with log := primary.log ++ [sig, sig], sentIndex := fun _ => 3 }
  compareStep "NACK rolls back the sent index" ⟨3⟩ 0 sending
    (.receive 1 (.appendEntriesResponse ⟨2, false, 1⟩))
  compareStep "NACK keeps the sent index at the match index" ⟨3⟩ 0
    { sending with matchIndex := fun i => if i == 1 then 2 else 0 }
    (.receive 1 (.appendEntriesResponse ⟨2, false, 1⟩))
  compareStep "send entries to a lagging peer" ⟨3⟩ 0
    { sending with sentIndex := fun _ => 1 } (.internal (.sendEntries 1 3))

#eval IO.ofExcept scenarios

end Consensus.MidTrace.Tests.ModelSteps
