-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem native_log_length_eq_of_decode_eq {N T : Type}
    (left right : NativeArrayCheckQuorum.Log N T)
    (same : left.decode = right.decode) :
    left.length = right.length := by
  have lengths := congrArg List.length same
  simpa [NativeArrayCheckQuorum.Log.decode] using lengths

theorem native_log_entry_eq_of_decode_eq {N T : Type}
    (left right : NativeArrayCheckQuorum.Log N T)
    (same : left.decode = right.decode) (index : Nat) (live : index < left.length) :
    left.entries index = right.entries index := by
  have sameLength := native_log_length_eq_of_decode_eq left right same
  have rightLive : index < right.length := by rw [<- sameLength]; exact live
  have selected := congrArg (fun entries => entries[index]?) same
  simpa [NativeArrayCheckQuorum.Log.decode, live, rightLive] using selected

theorem NodeRowTerms.Rep.of_model_eq {width : PNat}
    (assignment : Assignment) (values : NodeRowTerms width)
    (row other : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rep : values.Rep assignment row) (same : row.toModel = other.toModel) :
    values.Rep assignment other := by
  have sameRole : row.role = other.role := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.role same
  have sameFollower : row.isNewFollower = other.isNewFollower := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.isNewFollower same
  have sameCommit : row.commit = other.commit := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.commitIndex same
  have sameTerm : row.currentTerm = other.currentTerm := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.currentTerm same
  have sameLog : row.log.decode = other.log.decode := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.log same
  have sameRetirement : row.retirementIndex = other.retirementIndex := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.retirementIndex same
  have sameCommittable :
      row.retirementCommittableIndex = other.retirementCommittableIndex := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.retirementCommittableIndex same
  have sameRetired : row.retiredCommittedIndex = other.retiredCommittedIndex := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.retiredCommittedIndex same
  have sameVoted : row.votedFor = other.votedFor := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.votedFor same
  have sameVotes : row.votesGranted = other.votesGranted := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.votesGranted same
  have samePreVotes : row.preVotesGranted = other.preVotesGranted := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.preVotesGranted same
  have sameMembership : row.membershipState = other.membershipState := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.membershipState same
  have sameSent : row.sentIndex = other.sentIndex := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.sentIndex same
  have sameMatch : row.matchIndex = other.matchIndex := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.matchIndex same
  have sameLength := native_log_length_eq_of_decode_eq row.log other.log sameLog
  constructor
  · exact rep.role.trans (congrArg roleCode sameRole)
  · exact rep.newFollower.trans sameFollower
  · exact rep.logLength.trans (congrArg Int.ofNat sameLength)
  · exact rep.commit.trans (congrArg Int.ofNat sameCommit)
  · exact rep.currentTerm.trans (congrArg Int.ofNat sameTerm)
  · intro index live
    have rowLive : index < row.log.length := by rw [sameLength]; exact live
    exact (rep.logEntries index rowLive).trans
      (native_log_entry_eq_of_decode_eq row.log other.log sameLog index rowLive)
  · exact rep.retirementIndex.trans (congrArg (optionalValue Nat.cast) sameRetirement)
  · exact rep.retirementCommittableIndex.trans
      (congrArg (optionalValue Nat.cast) sameCommittable)
  · exact rep.retiredCommittedIndex.trans
      (congrArg (optionalValue Nat.cast) sameRetired)
  · exact rep.votedFor.trans
      (congrArg (optionalValue fun peer : Fin width => (peer.val : Int)) sameVoted)
  · exact rep.votesGranted.trans (congrArg encodeBits sameVotes)
  · exact rep.preVotesGranted.trans (congrArg encodeBits samePreVotes)
  · exact rep.membershipState.trans (congrArg membershipCode sameMembership)
  · intro peer
    exact (rep.sentIndex peer).trans
      (congrArg (fun sent => (sent peer : Int)) sameSent)
  · intro peer
    exact (rep.matchIndex peer).trans
      (congrArg (fun matched => (matched peer : Int)) sameMatch)

theorem NodeColumnsRep.of_model_eq {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays other : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (sameAllocation : forall node, (arrays node).isSome = (other node).isSome)
    (sameRows : forall node,
      (NativeArrayCheckQuorum.get arrays node).toModel =
        (NativeArrayCheckQuorum.get other node).toModel) :
    NodeColumnsRep assignment columns other := by
  have rows (node : Fin width) :
      (nodeRowSnapshot columns node).Rep assignment
        (NativeArrayCheckQuorum.get other node) :=
    NodeRowTerms.Rep.of_model_eq assignment (nodeRowSnapshot columns node)
      (NativeArrayCheckQuorum.get arrays node) (NativeArrayCheckQuorum.get other node)
      (node_row_snapshot_rep assignment columns arrays rep node) (sameRows node)
  refine
    { allocated := fun node => (rep.allocated node).trans (sameAllocation node)
      role := fun node => (rows node).role
      newFollower := fun node => (rows node).newFollower
      currentTerm := fun node => (rows node).currentTerm
      commit := fun node => (rows node).commit
      length := fun node => (rows node).logLength
      entries := ?_
      retirementIndex := fun node => (rows node).retirementIndex
      retirementCommittableIndex := fun node => (rows node).retirementCommittableIndex
      retiredCommittedIndex := fun node => (rows node).retiredCommittedIndex
      votedFor := fun node => (rows node).votedFor
      votesGranted := fun node => (rows node).votesGranted
      preVotesGranted := fun node => (rows node).preVotesGranted
      membershipState := fun node => (rows node).membershipState
      sentIndex := ?_
      matchIndex := ?_ }
  · intro node index live
    simpa only [nodeRowSnapshot, entryAt, Term.eval] using (rows node).logEntries index live
  · intro node peer
    by_cases present :
        (NativeEncode.allocated columns node.val : Expr .bool).eval assignment Locals.empty = true
    · simpa [nodeRowSnapshot, peerIndex, read, Term.eval, present] using (rows node).sentIndex peer
    · simpa [nodeRowSnapshot, peerIndex, read, Term.eval, present] using (rows node).sentIndex peer
  · intro node peer
    by_cases present :
        (NativeEncode.allocated columns node.val : Expr .bool).eval assignment Locals.empty = true
    · simpa [nodeRowSnapshot, peerIndex, read, Term.eval, present] using (rows node).matchIndex peer
    · simpa [nodeRowSnapshot, peerIndex, read, Term.eval, present] using (rows node).matchIndex peer

theorem FrameColumnsRep.of_model_rep {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (frame other : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (frameModel : frame.Rep state) (otherModel : other.Rep state) :
    FrameColumnsRep assignment columns other := by
  have sameGlobals : frame.globals = other.globals :=
    frameModel.globals.trans otherModel.globals.symm
  have sameQueues :
      NativeArrayQueue.decodeNetwork frame.queues = NativeArrayQueue.decodeNetwork other.queues :=
    frameModel.queues.trans otherModel.queues.symm
  constructor
  · apply NodeColumnsRep.of_model_eq assignment columns frame.nodes other.nodes rep.nodes
    · intro node
      apply Bool.eq_iff_iff.mpr
      exact (NativeArrayCheckQuorum.allocated_rep frame.nodes state frameModel.nodes node).trans
        (NativeArrayCheckQuorum.allocated_rep other.nodes state otherModel.nodes node).symm
    · intro node
      exact (NativeArrayCheckQuorum.get_rep frame.nodes state frameModel.nodes node).trans
        (NativeArrayCheckQuorum.get_rep other.nodes state otherModel.nodes node).symm
  · simpa only [<- sameGlobals] using rep.hasJoined
  · simpa only [<- sameGlobals] using rep.preVoteStatus
  · simpa only [<- sameGlobals] using rep.retirementCompleted
  · simpa only [<- sameGlobals] using rep.submittedTxIds
  · intro destination source
    exact (rep.queues destination source).trans
      (congrFun (congrFun sameQueues destination) source)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
