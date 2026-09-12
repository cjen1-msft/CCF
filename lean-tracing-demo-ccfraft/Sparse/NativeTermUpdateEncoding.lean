-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeTermUpdate
import Sparse.NativeTermGuardEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def termUpdatedNodes {width : PNat} (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (node : Fin width) (term : Nat) : NativeArrayCheckQuorum.Arrays (Fin width) Nat :=
  Function.update arrays node (some
    { NativeArrayCheckQuorum.get arrays node with
      role := .follower, currentTerm := term, isNewFollower := true,
      votedFor := none, preVotesGranted := ∅ })

theorem get_term_updated {width : PNat} (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (node peer : Fin width) (term : Nat) :
    NativeArrayCheckQuorum.get (termUpdatedNodes arrays node term) peer =
      if peer = node then
        { NativeArrayCheckQuorum.get arrays node with
          role := .follower, currentTerm := term, isNewFollower := true,
          votedFor := none, preVotesGranted := ∅ }
      else NativeArrayCheckQuorum.get arrays peer := by
  by_cases same : peer = node
  · subst peer
    simp [termUpdatedNodes, NativeArrayCheckQuorum.get]
  · simp [termUpdatedNodes, NativeArrayCheckQuorum.get, same]

def termUpdatedColumns (before : Columns) (base : Nat) : Columns :=
  { before with
    role := base, currentTerm := base + 1, newFollower := base + 2,
    votedFor := base + 3, preVotesGranted := base + 4 }

def termWriteClauses {width : PNat} (before : Columns) (node : Fin width)
    (term : Expr .int) (base : Nat) : List (Expr .bool) :=
  [.equal (.free (.array .int .int) base) (stepDownRole before.role node.val),
    .equal (.free (.array .int .int) (base + 1))
      (.store (.free (.array .int .int) before.currentTerm) (.integer node.val) term),
    .equal (.free (.array .int .bool) (base + 2)) (stepDownFollower before.newFollower node.val),
    .equal (.free (.array .int optionalIntTy) (base + 3))
      (.store (.free (.array .int optionalIntTy) before.votedFor) (.integer node.val) (.inl .unit)),
    .equal (.free (.array .int (.bits width)) (base + 4))
      (.store (.free (.array .int (.bits width)) before.preVotesGranted) (.integer node.val) (.bits 0))]

theorem node_columns_term_updated {width : PNat} (assignment : Assignment)
    (before : Columns) (base : Nat) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (node : Fin width) (term : Expr .int) (expected : Nat)
    (rep : NodeColumnsRep assignment before arrays)
    (present : (arrays node).isSome = true)
    (sameTerm : term.eval assignment Locals.empty = (expected : Int))
    (bindings : Holds (termWriteClauses before node term base) assignment) :
    NodeColumnsRep assignment (termUpdatedColumns before base) (termUpdatedNodes arrays node expected) := by
  simp only [Holds, termWriteClauses, List.mem_cons, List.not_mem_nil,
    forall_eq_or_imp, false_implies, implies_true, and_true] at bindings
  obtain ⟨roleBinding, termBinding, followerBinding, votedBinding, preVotesBinding⟩ := bindings
  have allocatedNode : (allocated before node.val : Expr .bool).eval assignment Locals.empty = true :=
    (rep.allocated node).trans present
  constructor
  · intro peer
    by_cases same : peer = node
    · subst peer
      simpa [termUpdatedNodes] using allocatedNode
    · simpa [termUpdatedNodes, same] using rep.allocated peer
  · intro peer
    change (read (termUpdatedColumns before base) base peer.val (.integer 0)).eval
      assignment Locals.empty = _
    rw [stored_read_correct assignment (termUpdatedColumns before base)
      before.role base node.val peer.val
      (.integer 0) (.integer 1) allocatedNode roleBinding, get_term_updated]
    by_cases same : peer = node
    · subst peer
      simp [Term.eval, roleCode]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.role peer
  · intro peer
    change (read (termUpdatedColumns before base) (base + 2) peer.val (.boolean true)).eval
      assignment Locals.empty = _
    rw [stored_read_correct assignment (termUpdatedColumns before base)
      before.newFollower (base + 2) node.val peer.val
      (.boolean true) (.boolean true) allocatedNode followerBinding, get_term_updated]
    by_cases same : peer = node
    · subst peer
      simp [Term.eval]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.newFollower peer
  · intro peer
    change (read (termUpdatedColumns before base) (base + 1) peer.val (.integer 0)).eval
      assignment Locals.empty = _
    rw [stored_read_correct assignment (termUpdatedColumns before base)
      before.currentTerm (base + 1) node.val peer.val
      (.integer 0) term allocatedNode termBinding, get_term_updated]
    by_cases same : peer = node
    · subst peer
      simp [sameTerm]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.currentTerm peer
  · intro peer
    have previous := rep.commit peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, NativeEncode.commit, read, NativeEncode.allocated]
  · intro peer
    have previous := rep.length peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, NativeEncode.length, read, NativeEncode.allocated]
  · intro peer index within
    rw [get_term_updated] at within ⊢
    by_cases same : peer = node
    · subst peer
      simpa [termUpdatedColumns, entryAt] using rep.entries node index (by simpa using within)
    · simpa [termUpdatedColumns, entryAt, same] using
        rep.entries peer index (by simpa [same] using within)
  · intro peer
    have previous := rep.retirementIndex peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, read, NativeEncode.allocated]
  · intro peer
    have previous := rep.retirementCommittableIndex peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, read, NativeEncode.allocated]
  · intro peer
    have previous := rep.retiredCommittedIndex peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, read, NativeEncode.allocated]
  · intro peer
    change (read (termUpdatedColumns before base) (base + 3) peer.val (.inl .unit)).eval
      assignment Locals.empty = _
    rw [stored_read_correct assignment (termUpdatedColumns before base)
      before.votedFor (base + 3) node.val peer.val
      (.inl .unit) (.inl .unit) allocatedNode votedBinding, get_term_updated]
    by_cases same : peer = node
    · subst peer
      simp [Term.eval, optionalValue]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.votedFor peer
  · intro peer
    have previous := rep.votesGranted peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, read, NativeEncode.allocated]
  · intro peer
    change (read (termUpdatedColumns before base) (base + 4) peer.val (.bits 0)).eval
      assignment Locals.empty = _
    rw [stored_read_correct assignment (termUpdatedColumns before base)
      before.preVotesGranted (base + 4) node.val peer.val
      (.bits 0) (.bits 0) allocatedNode preVotesBinding, get_term_updated]
    by_cases same : peer = node
    · subst peer
      simp [Term.eval]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.preVotesGranted peer
  · intro peer
    have previous := rep.membershipState peer
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, read, NativeEncode.allocated]
  · intro peer target
    have previous := rep.sentIndex peer target
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, peerIndex, NativeEncode.allocated]
  · intro peer target
    have previous := rep.matchIndex peer target
    rw [get_term_updated]
    by_cases same : peer = node <;>
      simp_all [termUpdatedColumns, peerIndex, NativeEncode.allocated]

structure TermUpdateResult {width : PNat} (before after : Encoding width)
    (source destination : Fin width) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = termUpdatedColumns before.toColumns before.next
  next : after.next = before.next + 5
  clauses : after.assertions.toList = before.assertions.toList ++
    termUpdateGuards before.toColumns source destination ++
    termWriteClauses before.toColumns destination
      (.fst (.fst (queueHeadPacketTerm before.toColumns source destination))) before.next

theorem term_update_success {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (updateTerm source destination).run before = .ok ((), after)) :
    TermUpdateResult before after source destination := by
  simp only [updateTerm, get_bind_run] at run
  obtain ⟨guardValue, guarded, guards, run⟩ := (bind_run _ _ _ _ _).mp run
  cases guardValue
  obtain ⟨roleId, first, role, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨termId, second, term, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨followerId, third, follower, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨votedId, fourth, voted, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨preVotesId, fifth, preVotes, run⟩ := (bind_run _ _ _ _ _).mp run
  change Except.ok ((), { fifth with
    role := roleId, currentTerm := termId, newFollower := followerId,
    votedFor := votedId, preVotesGranted := preVotesId }) = .ok ((), after) at run
  have final := congrArg Prod.snd (Except.ok.inj run)
  dsimp only at final
  rw [<- final]
  obtain ⟨guardFrame, guardClauses⟩ := assert_all_success _ before guarded guards
  obtain ⟨roleIdEq, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
    define_success _ guarded first roleId role
  obtain ⟨termIdEq, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
    define_success _ first second termId term
  obtain ⟨followerIdEq, thirdNext, thirdBootstrap, thirdColumns, thirdClauses⟩ :=
    define_success _ second third followerId follower
  obtain ⟨votedIdEq, fourthNext, fourthBootstrap, fourthColumns, fourthClauses⟩ :=
    define_success _ third fourth votedId voted
  obtain ⟨preVotesIdEq, fifthNext, fifthBootstrap, fifthColumns, fifthClauses⟩ :=
    define_success _ fourth fifth preVotesId preVotes
  have roleIndex : roleId = before.next := roleIdEq.trans guardFrame.next
  have termIndex : termId = before.next + 1 := by rw [termIdEq, firstNext, guardFrame.next]
  have followerIndex : followerId = before.next + 2 := by rw [followerIdEq, secondNext, firstNext, guardFrame.next]
  have votedIndex : votedId = before.next + 3 := by rw [votedIdEq, thirdNext, secondNext, firstNext, guardFrame.next]
  have preVotesIndex : preVotesId = before.next + 4 := by
    rw [preVotesIdEq, fourthNext, thirdNext, secondNext, firstNext, guardFrame.next]
  constructor
  · exact fifthBootstrap.trans (fourthBootstrap.trans (thirdBootstrap.trans
      (secondBootstrap.trans (firstBootstrap.trans guardFrame.bootstrap))))
  · simp only [fifthColumns, fourthColumns, thirdColumns, secondColumns, firstColumns, guardFrame.columns,
      termUpdatedColumns, roleIndex, termIndex, followerIndex, votedIndex, preVotesIndex]
  · dsimp only
    rw [fifthNext, fourthNext, thirdNext, secondNext, firstNext, guardFrame.next]
  · dsimp only
    rw [fifthClauses, Array.toList_push, fourthClauses, Array.toList_push, thirdClauses,
      Array.toList_push, secondClauses, Array.toList_push, firstClauses, Array.toList_push,
      guardClauses, roleIndex, termIndex, followerIndex, votedIndex, preVotesIndex]
    simp [termWriteClauses, List.append_assoc]

theorem term_update_holds {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (updateTerm source destination).run before = .ok ((), after)) (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (termUpdateGuards before.toColumns source destination) assignment /\
        Holds (termWriteClauses before.toColumns destination
          (.fst (.fst (queueHeadPacketTerm before.toColumns source destination))) before.next) assignment := by
  rw [(term_update_success source destination before after run).clauses]
  simp [Holds, or_imp, forall_and]

theorem term_update_references {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (updateTerm source destination).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  have shape := term_update_success source destination before after run
  cases valid
  constructor <;> simp only [shape.columns, termUpdatedColumns, shape.next] <;> omega

theorem newer_message_head {width : PNat} (frame : NativeArrayVote.Frame (Fin width) Nat)
    (source destination : Fin width) (packet : Message (Fin width) Nat)
    (selected : NativeArrayVote.newerMessage? frame source destination = some packet) :
    0 < (frame.queues destination source).length /\
      (frame.queues destination source).cells (frame.queues destination source).head = packet := by
  by_cases nonempty : 0 < (frame.queues destination source).length
  · refine ⟨nonempty, ?_⟩
    simp only [NativeArrayVote.newerMessage?, NativeArrayQueue.Queue.peek, if_pos nonempty,
      Bind.bind, Option.bind] at selected
    split at selected
    · exact Option.some.inj selected
    · cases selected
  · simp [NativeArrayVote.newerMessage?, NativeArrayQueue.Queue.peek, nonempty] at selected

theorem term_update_frame_success {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (updateTerm source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    (frame.nodes destination).isSome = true /\
      (NativeArrayVote.newerMessage? frame source destination).isSome = true /\
      FrameColumnsRep assignment after.toColumns (frame.updateTerm source destination) := by
  obtain ⟨_, guards, bindings⟩ := (term_update_holds source destination before after run assignment).mp holds
  obtain ⟨present, available⟩ :=
    (term_update_guards_correct assignment before.toColumns frame rep source destination).mp guards
  refine ⟨present, available, ?_⟩
  cases selected : NativeArrayVote.newerMessage? frame source destination with
  | none => simp [selected] at available
  | some packet =>
    obtain ⟨nonempty, head⟩ := newer_message_head frame source destination packet selected
    have samePacket := queue_head_packet_term_correct assignment before.toColumns frame rep source destination nonempty
    rw [head] at samePacket
    have sameTerm : (Term.fst (.fst (queueHeadPacketTerm before.toColumns source destination))).eval
        assignment Locals.empty = (packet.term : Int) := by
      simp only [Term.eval, samePacket, packetValue, packetHeaderValue]
    have nodes := node_columns_term_updated assignment before.toColumns before.next frame.nodes destination
      (.fst (.fst (queueHeadPacketTerm before.toColumns source destination))) packet.term
      rep.nodes present sameTerm bindings
    have shape := term_update_success source destination before after run
    simp only [NativeArrayVote.Frame.updateTerm, selected]
    constructor
    · simpa only [shape.columns, termUpdatedNodes] using nodes
    · simpa only [shape.columns, termUpdatedColumns] using rep.hasJoined
    · intro node
      simpa only [shape.columns, termUpdatedColumns] using rep.preVoteStatus node
    · intro node
      simpa only [shape.columns, termUpdatedColumns] using rep.retirementCompleted node
    · intro txId
      simpa only [shape.columns, termUpdatedColumns] using rep.submittedTxIds txId
    · intro dest src
      simpa only [shape.columns, termUpdatedColumns, queueRow] using rep.queues dest src

theorem term_update_complete {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (run : (updateTerm source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (present : (frame.nodes destination).isSome = true)
    (available : (NativeArrayVote.newerMessage? frame source destination).isSome = true) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns (frame.updateTerm source destination) := by
  have originalRun := run
  simp only [updateTerm, get_bind_run] at run
  obtain ⟨guardValue, guarded, guards, run⟩ := (bind_run _ _ _ _ _).mp run
  cases guardValue
  obtain ⟨roleId, first, role, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨termId, second, term, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨followerId, third, follower, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨votedId, fourth, voted, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨preVotesId, fifth, preVotes, run⟩ := (bind_run _ _ _ _ _).mp run
  change Except.ok ((), { fifth with
    role := roleId, currentTerm := termId, newFollower := followerId,
    votedFor := votedId, preVotesGranted := preVotesId }) = .ok ((), after) at run
  have final := congrArg Prod.snd (Except.ok.inj run)
  dsimp only at final
  have guardHolds := (term_update_guards_correct assignment before.toColumns frame rep
    source destination).mpr ⟨present, available⟩
  have guardedHolds := (assert_all_holds _ before guarded guards assignment).mpr ⟨holds, guardHolds⟩
  obtain ⟨firstAssignment, firstAgreement, firstHolds⟩ :=
    define_extension _ guarded first roleId role assignment guardedHolds
  obtain ⟨secondAssignment, secondAgreement, secondHolds⟩ :=
    define_extension _ first second termId term firstAssignment firstHolds
  obtain ⟨thirdAssignment, thirdAgreement, thirdHolds⟩ :=
    define_extension _ second third followerId follower secondAssignment secondHolds
  obtain ⟨fourthAssignment, fourthAgreement, fourthHolds⟩ :=
    define_extension _ third fourth votedId voted thirdAssignment thirdHolds
  obtain ⟨extended, fifthAgreement, fifthHolds⟩ :=
    define_extension _ fourth fifth preVotesId preVotes fourthAssignment fourthHolds
  have guardNext := (assert_all_success _ before guarded guards).1.next
  have firstNext := (define_success _ guarded first roleId role).2.1
  have secondNext := (define_success _ first second termId term).2.1
  have thirdNext := (define_success _ second third followerId follower).2.1
  have agreement : assignment.AgreesBelow before.next extended :=
    (firstAgreement.restrict (by omega)).trans
      ((secondAgreement.restrict (by omega)).trans
        ((thirdAgreement.restrict (by omega)).trans
          ((fourthAgreement.restrict (by omega)).trans (fifthAgreement.restrict (by
            have fourthNext := (define_success _ third fourth votedId voted).2.1
            omega)))))
  have finalHolds : Holds after.assertions.toList extended := by
    rw [<- final]
    exact fifthHolds
  exact ⟨extended, agreement, finalHolds,
    (term_update_frame_success source destination before after originalRun extended finalHolds
      frame (rep.agrees_below before assignment extended frame valid agreement)).2.2⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
