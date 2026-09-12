-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCampaign
import Sparse.NativeCampaignGuardEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def campaignNodes {width : PNat} (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (preVote : Bool) (node : Fin width) : NativeArrayCheckQuorum.Arrays (Fin width) Nat :=
  let row := NativeArrayCheckQuorum.get arrays node
  Function.update arrays node (some (if preVote then { row with
    role := .preVoteCandidate, preVotesGranted := {node} } else { row with
    role := .candidate, currentTerm := row.currentTerm + 1, votedFor := some node,
    votesGranted := {node}, preVotesGranted := ∅ }))

theorem get_campaign {width : PNat} (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (preVote : Bool) (node peer : Fin width) :
    NativeArrayCheckQuorum.get (campaignNodes arrays preVote node) peer =
      if peer = node then
        if preVote then { NativeArrayCheckQuorum.get arrays node with
          role := .preVoteCandidate, preVotesGranted := {node} }
        else { NativeArrayCheckQuorum.get arrays node with
          role := .candidate, currentTerm := (NativeArrayCheckQuorum.get arrays node).currentTerm + 1,
          votedFor := some node, votesGranted := {node}, preVotesGranted := ∅ }
      else NativeArrayCheckQuorum.get arrays peer := by
  by_cases same : peer = node
  · subst peer
    cases preVote <;> simp [campaignNodes, NativeArrayCheckQuorum.get]
  · simp [campaignNodes, NativeArrayCheckQuorum.get, same]

def campaignColumns (before : Columns) (base : Nat) : Columns :=
  { before with
    role := base, currentTerm := base + 1, votedFor := base + 2,
    votesGranted := base + 3, preVotesGranted := base + 4 }

def campaignWriteClauses {width : PNat} (before : Columns) (preVote : Bool)
    (node : Fin width) (base : Nat) : List (Expr .bool) :=
  [.equal (.free (.array .int .int) base)
      (.store (.free (.array .int .int) before.role) (.integer node.val)
        (.integer (roleCode (if preVote then .preVoteCandidate else .candidate)))),
    .equal (.free (.array .int .int) (base + 1))
      (.store (.free (.array .int .int) before.currentTerm) (.integer node.val) (campaignTerm before preVote node.val)),
    .equal (.free (.array .int optionalIntTy) (base + 2))
      (.store (.free (.array .int optionalIntTy) before.votedFor) (.integer node.val) (campaignVotedFor before preVote node.val)),
    .equal (.free (.array .int (.bits width)) (base + 3))
      (.store (.free (.array .int (.bits width)) before.votesGranted) (.integer node.val) (campaignVotesGranted before preVote node)),
    .equal (.free (.array .int (.bits width)) (base + 4))
      (.store (.free (.array .int (.bits width)) before.preVotesGranted) (.integer node.val) (campaignPreVotesGranted preVote node))]

theorem node_columns_campaign {width : PNat} (assignment : Assignment)
    (before : Columns) (base : Nat) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (preVote : Bool) (node : Fin width)
    (rep : NodeColumnsRep assignment before arrays) (present : (arrays node).isSome = true)
    (bindings : Holds (campaignWriteClauses before preVote node base) assignment) :
    NodeColumnsRep assignment (campaignColumns before base) (campaignNodes arrays preVote node) := by
  simp only [Holds, campaignWriteClauses, List.mem_cons, List.not_mem_nil,
    forall_eq_or_imp, false_implies, implies_true, and_true] at bindings
  obtain ⟨roleBinding, termBinding, votedBinding, votesBinding, preVotesBinding⟩ := bindings
  have allocatedNode : (allocated node.val : Expr .bool).eval assignment Locals.empty = true :=
    (rep.allocated node).trans present
  dsimp only [campaignColumns]
  constructor
  · intro peer
    by_cases same : peer = node
    · subst peer
      simpa [campaignNodes] using allocatedNode
    · simpa [campaignNodes, same] using rep.allocated peer
  · intro peer
    rw [stored_read_correct assignment before.role base node.val peer.val
      (.integer 0) (.integer (roleCode (if preVote then .preVoteCandidate else .candidate)))
      allocatedNode roleBinding, get_campaign]
    by_cases same : peer = node
    · subst peer
      cases preVote <;> simp [Term.eval]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.role peer
  · intro peer
    have previous := rep.newFollower peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer
    rw [stored_read_correct assignment before.currentTerm (base + 1) node.val peer.val
      (.integer 0) (campaignTerm before preVote node.val) allocatedNode termBinding, get_campaign]
    by_cases same : peer = node
    · subst peer
      cases preVote <;> simp [campaignTerm, Term.eval, rep.currentTerm]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.currentTerm peer
  · intro peer
    have previous := rep.commit peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer
    have previous := rep.length peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer index within
    rw [get_campaign] at within ⊢
    by_cases same : peer = node
    · subst peer
      cases preVote <;> simpa using rep.entries node index (by simpa using within)
    · simpa [same] using rep.entries peer index (by simpa [same] using within)
  · intro peer
    have previous := rep.retirementIndex peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer
    have previous := rep.retirementCommittableIndex peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer
    have previous := rep.retiredCommittedIndex peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer
    rw [stored_read_correct assignment before.votedFor (base + 2) node.val peer.val
      (.inl .unit) (campaignVotedFor before preVote node.val) allocatedNode votedBinding, get_campaign]
    by_cases same : peer = node
    · subst peer
      cases preVote <;> simp [campaignVotedFor, Term.eval, optionalValue, rep.votedFor]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.votedFor peer
  · intro peer
    rw [stored_read_correct assignment before.votesGranted (base + 3) node.val peer.val
      (.bits 0) (campaignVotesGranted before preVote node) allocatedNode votesBinding, get_campaign]
    by_cases same : peer = node
    · subst peer
      cases preVote
      · simp [campaignVotesGranted, Term.eval]
      · simpa only [campaignVotesGranted, Bool.true_eq, ite_true] using rep.votesGranted node
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.votesGranted peer
  · intro peer
    rw [stored_read_correct assignment before.preVotesGranted (base + 4) node.val peer.val
      (.bits 0) (campaignPreVotesGranted preVote node) allocatedNode preVotesBinding, get_campaign]
    by_cases same : peer = node
    · subst peer
      cases preVote <;> simp [campaignPreVotesGranted, Term.eval]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.preVotesGranted peer
  · intro peer
    have previous := rep.membershipState peer
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer target
    have previous := rep.sentIndex peer target
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all
  · intro peer target
    have previous := rep.matchIndex peer target
    rw [get_campaign]
    by_cases same : peer = node <;> cases preVote <;> simp_all

structure CampaignWriteResult {width : PNat} (before after : Encoding width)
    (preVote : Bool) (node : Fin width) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = campaignColumns before.toColumns before.next
  next : after.next = before.next + 5
  clauses : after.assertions.toList = before.assertions.toList ++
    campaignWriteClauses before.toColumns preVote node before.next

theorem campaign_writes_success {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width)
    (run : (campaignWrites preVote node).run before = .ok ((), after)) :
    CampaignWriteResult before after preVote node := by
  simp only [campaignWrites, get_bind_run] at run
  obtain ⟨roleId, first, role, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨termId, second, term, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨votedId, third, voted, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨votesId, fourth, votes, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨preVotesId, fifth, preVotes, run⟩ := (bind_run _ _ _ _ _).mp run
  change Except.ok ((), { fifth with
    role := roleId, currentTerm := termId, votedFor := votedId,
    votesGranted := votesId, preVotesGranted := preVotesId }) = .ok ((), after) at run
  have final := congrArg Prod.snd (Except.ok.inj run)
  dsimp only at final
  rw [<- final]
  obtain ⟨roleIdEq, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
    define_success _ before first roleId role
  obtain ⟨termIdEq, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
    define_success _ first second termId term
  obtain ⟨votedIdEq, thirdNext, thirdBootstrap, thirdColumns, thirdClauses⟩ :=
    define_success _ second third votedId voted
  obtain ⟨votesIdEq, fourthNext, fourthBootstrap, fourthColumns, fourthClauses⟩ :=
    define_success _ third fourth votesId votes
  obtain ⟨preVotesIdEq, fifthNext, fifthBootstrap, fifthColumns, fifthClauses⟩ :=
    define_success _ fourth fifth preVotesId preVotes
  have termIndex : termId = before.next + 1 := by rw [termIdEq, firstNext]
  have votedIndex : votedId = before.next + 2 := by rw [votedIdEq, secondNext, firstNext]
  have votesIndex : votesId = before.next + 3 := by rw [votesIdEq, thirdNext, secondNext, firstNext]
  have preVotesIndex : preVotesId = before.next + 4 := by
    rw [preVotesIdEq, fourthNext, thirdNext, secondNext, firstNext]
  constructor
  · exact fifthBootstrap.trans (fourthBootstrap.trans (thirdBootstrap.trans
      (secondBootstrap.trans firstBootstrap)))
  · simp only [fifthColumns, fourthColumns, thirdColumns, secondColumns, firstColumns,
      campaignColumns, roleIdEq, termIndex, votedIndex, votesIndex, preVotesIndex]
  · dsimp only
    rw [fifthNext, fourthNext, thirdNext, secondNext, firstNext]
  · dsimp only
    rw [fifthClauses, Array.toList_push, fourthClauses, Array.toList_push, thirdClauses,
      Array.toList_push, secondClauses, Array.toList_push, firstClauses, Array.toList_push,
      roleIdEq, termIndex, votedIndex, votesIndex, preVotesIndex]
    simp [campaignWriteClauses, List.append_assoc]

theorem campaign_writes_holds {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width)
    (run : (campaignWrites preVote node).run before = .ok ((), after)) (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (campaignWriteClauses before.toColumns preVote node before.next) assignment := by
  rw [(campaign_writes_success preVote node before after run).clauses]
  simp [Holds, or_imp, forall_and]

theorem campaign_writes_references {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width)
    (run : (campaignWrites preVote node).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  have shape := campaign_writes_success preVote node before after run
  cases valid
  constructor <;> simp only [shape.columns, campaignColumns, shape.next] <;> omega

theorem campaign_writes_frame {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width)
    (run : (campaignWrites preVote node).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (present : (frame.nodes node).isSome = true) :
    FrameColumnsRep assignment after.toColumns (frame.campaign preVote node) := by
  have bindings := ((campaign_writes_holds preVote node before after run assignment).mp holds).2
  have nodes := node_columns_campaign assignment before.toColumns before.next frame.nodes preVote node rep.nodes present bindings
  have shape := campaign_writes_success preVote node before after run
  constructor
  · simpa only [shape.columns, NativeArrayVote.Frame.campaign, campaignNodes] using nodes
  · simpa only [shape.columns, campaignColumns, NativeArrayVote.Frame.campaign] using rep.hasJoined
  · intro peer
    simpa only [shape.columns, campaignColumns, NativeArrayVote.Frame.campaign] using rep.preVoteStatus peer
  · intro peer
    simpa only [shape.columns, campaignColumns, NativeArrayVote.Frame.campaign] using rep.retirementCompleted peer
  · intro txId
    simpa only [shape.columns, campaignColumns, NativeArrayVote.Frame.campaign] using rep.submittedTxIds txId
  · intro destination source
    simpa only [shape.columns, campaignColumns, NativeArrayVote.Frame.campaign, queueRow] using rep.queues destination source

theorem campaign_writes_complete {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width)
    (run : (campaignWrites preVote node).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (present : (frame.nodes node).isSome = true) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns (frame.campaign preVote node) := by
  have originalRun := run
  simp only [campaignWrites, get_bind_run] at run
  obtain ⟨roleId, first, role, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨termId, second, term, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨votedId, third, voted, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨votesId, fourth, votes, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨preVotesId, fifth, preVotes, run⟩ := (bind_run _ _ _ _ _).mp run
  change Except.ok ((), { fifth with
    role := roleId, currentTerm := termId, votedFor := votedId,
    votesGranted := votesId, preVotesGranted := preVotesId }) = .ok ((), after) at run
  have final := congrArg Prod.snd (Except.ok.inj run)
  dsimp only at final
  obtain ⟨firstAssignment, firstAgreement, firstHolds⟩ :=
    define_extension _ before first roleId role assignment holds
  obtain ⟨secondAssignment, secondAgreement, secondHolds⟩ :=
    define_extension _ first second termId term firstAssignment firstHolds
  obtain ⟨thirdAssignment, thirdAgreement, thirdHolds⟩ :=
    define_extension _ second third votedId voted secondAssignment secondHolds
  obtain ⟨fourthAssignment, fourthAgreement, fourthHolds⟩ :=
    define_extension _ third fourth votesId votes thirdAssignment thirdHolds
  obtain ⟨extended, fifthAgreement, fifthHolds⟩ :=
    define_extension _ fourth fifth preVotesId preVotes fourthAssignment fourthHolds
  have firstNext := (define_success _ before first roleId role).2.1
  have secondNext := (define_success _ first second termId term).2.1
  have thirdNext := (define_success _ second third votedId voted).2.1
  have fourthNext := (define_success _ third fourth votesId votes).2.1
  have agreement : assignment.AgreesBelow before.next extended :=
    firstAgreement.trans ((secondAgreement.restrict (by omega)).trans
      ((thirdAgreement.restrict (by omega)).trans
        ((fourthAgreement.restrict (by omega)).trans (fifthAgreement.restrict (by omega)))))
  have finalHolds : Holds after.assertions.toList extended := by
    rw [<- final]
    exact fifthHolds
  exact ⟨extended, agreement, finalHolds, campaign_writes_frame preVote node before after originalRun
    extended finalHolds frame (rep.agrees_below before assignment extended frame valid agreement) present⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
