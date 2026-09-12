-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveWrites
import Sparse.NativeQueuePopEncoding
import Sparse.NativeQueueStoreEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def voteReceiveNodes {width : PNat}
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (destination : Fin width)
    (request : RequestVoteRequest (Fin width)) (signature : Nat) :
    NativeArrayCheckQuorum.Arrays (Fin width) Nat :=
  Function.update arrays destination
    (some (NativeArrayVoteReceive.nextRow
      (NativeArrayCheckQuorum.get arrays destination) request signature))

theorem get_vote_receive_nodes {width : PNat}
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (destination peer : Fin width)
    (request : RequestVoteRequest (Fin width)) (signature : Nat) :
    NativeArrayCheckQuorum.get (voteReceiveNodes arrays destination request signature) peer =
      if peer = destination then
        NativeArrayVoteReceive.nextRow
          (NativeArrayCheckQuorum.get arrays destination) request signature
      else NativeArrayCheckQuorum.get arrays peer := by
  by_cases same : peer = destination
  · subst peer
    simp [voteReceiveNodes, NativeArrayCheckQuorum.get]
  · simp [voteReceiveNodes, NativeArrayCheckQuorum.get, same]

def voteReceiveColumns (before : Columns) (votedFor : Nat) : Columns :=
  { before with votedFor }

def voteReceiveWriteClauses {width : PNat} (before : Columns)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (signature : Expr .int) (id : Nat) : List (Expr .bool) :=
  [.equal (.free (.array .int optionalIntTy) id)
    (voteReceiveVotedFor before source destination packet signature)]

theorem node_columns_vote_received {width : PNat} (assignment : Assignment)
    (before : Columns) (votedFor : Nat)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (request : RequestVoteRequest (Fin width))
    (signatureTerm : Expr .int) (signature : Nat)
    (rep : NodeColumnsRep assignment before arrays)
    (present : (arrays destination).isSome = true)
    (sameSource : request.source = source)
    (samePacket : packet.eval assignment Locals.empty =
      packetValue (.requestVoteRequest request))
    (sameSignature : signatureTerm.eval assignment Locals.empty = (signature : Int))
    (binding : assignment (.array .int optionalIntTy) votedFor =
      (voteReceiveVotedFor before source destination packet signatureTerm).eval
        assignment Locals.empty) :
    NodeColumnsRep assignment (voteReceiveColumns before votedFor)
      (voteReceiveNodes arrays destination request signature) := by
  have granted := vote_grant_term_correct assignment before arrays rep destination packet request
    samePacket signatureTerm signature sameSignature
  have allocatedDestination :
      (allocated before destination.val : Expr .bool).eval assignment Locals.empty = true :=
    (rep.allocated destination).trans present
  have allocatedValue :
      assignment (.array .int .bool) before.allocated destination.val = true := by
    simpa [NativeEncode.allocated, Term.eval] using allocatedDestination
  constructor
  · intro peer
    by_cases same : peer = destination
    · subst peer
      simpa [voteReceiveNodes, present] using rep.allocated destination
    · simpa [voteReceiveNodes, same] using rep.allocated peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.role destination
    · simpa [same] using rep.role peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.newFollower destination
    · simpa [same] using rep.newFollower peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.currentTerm destination
    · simpa [same] using rep.currentTerm peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.commit destination
    · simpa [same] using rep.commit peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.length destination
    · simpa [same] using rep.length peer
  · intro peer index within
    rw [get_vote_receive_nodes] at within ⊢
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using
          rep.entries destination index (by simpa [NativeArrayVoteReceive.nextRow, grant] using within)
    · simpa [same] using rep.entries peer index (by simpa [same] using within)
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.retirementIndex destination
    · simpa [same] using rep.retirementIndex peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using
          rep.retirementCommittableIndex destination
    · simpa [same] using rep.retirementCommittableIndex peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using
          rep.retiredCommittedIndex destination
    · simpa [same] using rep.retiredCommittedIndex peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      simp only [voteReceiveColumns, read, NativeEncode.allocated, Term.eval,
        allocatedValue, if_true, binding,
        voteReceiveVotedFor, granted]
      have oldValue :
          assignment (.array .int optionalIntTy) before.votedFor destination.val =
            optionalValue (fun peer : Fin width => (peer.val : Int))
              (NativeArrayCheckQuorum.get arrays destination).votedFor := by
        simpa [read, Term.eval, allocatedDestination] using rep.votedFor destination
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature
      · simpa [grant, NativeArrayVoteReceive.nextRow] using oldValue
      · simp [grant, NativeArrayVoteReceive.nextRow, sameSource, optionalValue]
    · have different : (peer.val : Int) ≠ (destination.val : Int) := by
        intro equal
        exact same (Fin.ext (by exact_mod_cast equal))
      have sameValue :
          assignment (.array .int optionalIntTy) votedFor peer.val =
            assignment (.array .int optionalIntTy) before.votedFor peer.val := by
        rw [binding]
        simp only [voteReceiveVotedFor, Term.eval, granted]
        cases grant : NativeArrayVoteReceive.grant
            (NativeArrayCheckQuorum.get arrays destination) request signature <;>
          simp [different]
      simpa only [voteReceiveColumns, read, NativeEncode.allocated, Term.eval, sameValue, same]
        using rep.votedFor peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.votesGranted destination
    · simpa [same] using rep.votesGranted peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.preVotesGranted destination
    · simpa [same] using rep.preVotesGranted peer
  · intro peer
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.membershipState destination
    · simpa [same] using rep.membershipState peer
  · intro peer target
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.sentIndex destination target
    · simpa [same] using rep.sentIndex peer target
  · intro peer target
    rw [get_vote_receive_nodes]
    by_cases same : peer = destination
    · subst peer
      cases grant : NativeArrayVoteReceive.grant
          (NativeArrayCheckQuorum.get arrays destination) request signature <;>
        simpa [NativeArrayVoteReceive.nextRow, grant] using rep.matchIndex destination target
    · simpa [same] using rep.matchIndex peer target

structure VoteReceiveWritePrefix {width : PNat} (before voted : Encoding width)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (signature : Expr .int) : Prop where
  bootstrap : voted.bootstrap = before.bootstrap
  columns : voted.toColumns = voteReceiveColumns before.toColumns before.next
  next : voted.next = before.next + 1
  clauses : voted.assertions.toList = before.assertions.toList ++
    voteReceiveWriteClauses before.toColumns source destination packet signature before.next
  definition : exists defined : Encoding width,
    (define (voteReceiveVotedFor before.toColumns source destination packet signature)).run before =
      .ok (before.next, defined) /\
    voted = { defined with votedFor := before.next }
  packetSymbols : forall symbol, symbol ∈ packet.symbols -> symbol.2 < before.next
  signatureSymbols : forall symbol, symbol ∈ signature.symbols -> symbol.2 < before.next

theorem vote_receive_writes_steps {width : PNat} (source destination : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int)
    (before after : Encoding width)
    (run : (voteReceiveWrites source destination packet signature).run before = .ok ((), after)) :
    exists voted popped : Encoding width,
      VoteReceiveWritePrefix before voted source destination packet signature /\
      (popQueue destination source).run voted = .ok ((), popped) /\
      (pushQueue source destination
        (voteResponseTerm before.toColumns destination packet signature)).run popped =
          .ok ((), after) := by
  simp only [voteReceiveWrites, get_bind_run] at run
  split at run
  · rename_i known
    obtain ⟨votedFor, defined, definition, run⟩ := (bind_run _ _ _ _ _).mp run
    change (do
      popQueue destination source
      pushQueue source destination
        (voteResponseTerm before.toColumns destination packet signature)).run
      { defined with votedFor } = .ok ((), after) at run
    obtain ⟨unused, popped, poppedRun, pushedRun⟩ := (bind_run _ _ _ _ _).mp run
    cases unused
    obtain ⟨votedForId, definedNext, definedBootstrap, definedColumns, definedClauses⟩ :=
      define_success _ before defined votedFor definition
    let voted : Encoding width := { defined with votedFor }
    refine ⟨voted, popped, ?_, poppedRun, pushedRun⟩
    have accepted :
        packet.symbols.all (fun symbol => symbol.2 < before.next) = true /\
          signature.symbols.all (fun symbol => symbol.2 < before.next) = true := by
      simpa only [Bool.and_eq_true] using known
    constructor
    · exact definedBootstrap
    · simp [voted, voteReceiveColumns, definedColumns, votedForId]
    · simpa [voted] using definedNext
    · rw [show voted.assertions = defined.assertions by rfl, definedClauses, Array.toList_push,
        votedForId]
      simp [voteReceiveWriteClauses]
    · exact ⟨defined, by simpa only [votedForId] using definition, by simp [voted, votedForId]⟩
    · intro symbol member
      simpa only [decide_eq_true_eq] using List.all_eq_true.mp accepted.1 symbol member
    · intro symbol member
      simpa only [decide_eq_true_eq] using List.all_eq_true.mp accepted.2 symbol member
  · cases run

theorem VoteReceiveWritePrefix.references {width : PNat} {before voted : Encoding width}
    {source destination : Fin width} {packet : Expr (packetTy width)} {signature : Expr .int}
    (shape : VoteReceiveWritePrefix before voted source destination packet signature)
    (valid : ReferencesValid before) : ReferencesValid voted := by
  cases valid
  constructor <;> simp only [shape.columns, voteReceiveColumns, shape.next] <;> omega

theorem VoteReceiveWritePrefix.holds {width : PNat} {before voted : Encoding width}
    {source destination : Fin width} {packet : Expr (packetTy width)} {signature : Expr .int}
    (shape : VoteReceiveWritePrefix before voted source destination packet signature)
    (assignment : Assignment) :
    Holds voted.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        assignment (.array .int optionalIntTy) before.next =
          (voteReceiveVotedFor before.toColumns source destination packet signature).eval
            assignment Locals.empty := by
  rw [shape.clauses]
  simp [Holds, voteReceiveWriteClauses, Term.eval, or_imp, forall_and]

theorem vote_receive_write_frame {width : PNat}
    (source destination : Fin width) (packet : Expr (packetTy width))
    (request : RequestVoteRequest (Fin width)) (signatureTerm : Expr .int) (signature : Nat)
    (before voted : Encoding width)
    (shape : VoteReceiveWritePrefix before voted source destination packet signatureTerm)
    (assignment : Assignment) (holds : Holds voted.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (present : (frame.nodes destination).isSome = true)
    (sameSource : request.source = source)
    (samePacket : packet.eval assignment Locals.empty =
      packetValue (.requestVoteRequest request))
    (sameSignature : signatureTerm.eval assignment Locals.empty = (signature : Int)) :
    FrameColumnsRep assignment voted.toColumns
      { frame with nodes := voteReceiveNodes frame.nodes destination request signature } := by
  have binding := (shape.holds assignment).mp holds |>.2
  have nodes := node_columns_vote_received assignment before.toColumns before.next frame.nodes
    source destination packet request signatureTerm signature rep.nodes present sameSource
    samePacket sameSignature binding
  constructor
  · simpa only [shape.columns, voteReceiveColumns] using nodes
  · simpa only [shape.columns, voteReceiveColumns] using rep.hasJoined
  · intro node
    simpa only [shape.columns, voteReceiveColumns] using rep.preVoteStatus node
  · intro node
    simpa only [shape.columns, voteReceiveColumns] using rep.retirementCompleted node
  · intro txId
    simpa only [shape.columns, voteReceiveColumns] using rep.submittedTxIds txId
  · intro readDestination readSource
    simpa only [shape.columns, voteReceiveColumns, queueRow] using
      rep.queues readDestination readSource

theorem vote_receive_writes_references {width : PNat} (source destination : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int)
    (before after : Encoding width)
    (run : (voteReceiveWrites source destination packet signature).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨voted, popped, shape, popRun, pushRun⟩ :=
    vote_receive_writes_steps source destination packet signature before after run
  have votedValid := shape.references valid
  exact push_queue_references source destination _ popped after pushRun
    (pop_queue_references destination source voted popped popRun votedValid)

theorem vote_receive_writes_holds_before {width : PNat} (source destination : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int)
    (before after : Encoding width)
    (run : (voteReceiveWrites source destination packet signature).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨voted, popped, shape, popRun, pushRun⟩ :=
    vote_receive_writes_steps source destination packet signature before after run
  obtain ⟨poppedHolds, _, _⟩ :=
    (push_queue_holds source destination _ popped after pushRun assignment).mp holds
  obtain ⟨votedHolds, _, _⟩ :=
    (pop_queue_holds destination source voted popped popRun assignment).mp poppedHolds
  exact ((shape.holds assignment).mp votedHolds).1

theorem vote_receive_writes_frame_success {width : PNat}
    (source destination : Fin width) (packet : Expr (packetTy width))
    (request : RequestVoteRequest (Fin width)) (signatureTerm : Expr .int) (signature : Nat)
    (before after : Encoding width)
    (run : (voteReceiveWrites source destination packet signatureTerm).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (present : (frame.nodes destination).isSome = true)
    (sameSource : request.source = source) (sameDestination : request.destination = destination)
    (samePacket : packet.eval assignment Locals.empty =
      packetValue (.requestVoteRequest request))
    (sameSignature : signatureTerm.eval assignment Locals.empty = (signature : Int)) :
    FrameColumnsRep assignment after.toColumns
      (NativeArrayVoteReceive.receive frame destination request signature) := by
  obtain ⟨voted, popped, shape, popRun, pushRun⟩ :=
    vote_receive_writes_steps source destination packet signatureTerm before after run
  obtain ⟨poppedHolds, _, _⟩ :=
    (push_queue_holds source destination _ popped after pushRun assignment).mp holds
  obtain ⟨votedHolds, _, _⟩ :=
    (pop_queue_holds destination source voted popped popRun assignment).mp poppedHolds
  have votedRep := vote_receive_write_frame source destination packet request signatureTerm signature
    before voted shape assignment votedHolds frame rep present sameSource samePacket sameSignature
  let votedFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := voteReceiveNodes frame.nodes destination request signature }
  have poppedRep := pop_queue_frame_success source destination voted popped popRun assignment
    poppedHolds votedFrame (by simpa [votedFrame] using votedRep)
  let response := NativeArrayVoteReceive.response
    (NativeArrayCheckQuorum.get frame.nodes destination) request signature
  have sameResponse := vote_response_term_correct assignment before.toColumns frame.nodes rep.nodes
    destination packet request samePacket signatureTerm signature sameSignature
  have responseSource : response.source = destination := by
    change request.destination = destination
    exact sameDestination
  have responseDestination : response.destination = source := by
    change request.source = source
    exact sameSource
  have responseRun :
      (pushQueue response.destination response.source
        (voteResponseTerm before.toColumns destination packet signatureTerm)).run popped =
          .ok ((), after) := by
    rw [responseDestination, responseSource]
    exact pushRun
  have pushedRep := push_queue_frame_success _ (.requestVoteResponse response) popped after
    responseRun
    assignment holds
    { votedFrame with queues := NativeArrayQueue.popSource votedFrame.queues destination source }
    poppedRep sameResponse
  simpa [NativeArrayVoteReceive.receive, votedFrame, voteReceiveNodes, response, sameSource] using pushedRep

theorem vote_receive_writes_complete {width : PNat}
    (source destination : Fin width) (packet : Expr (packetTy width))
    (request : RequestVoteRequest (Fin width)) (signatureTerm : Expr .int) (signature : Nat)
    (before after : Encoding width)
    (run : (voteReceiveWrites source destination packet signatureTerm).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (present : (frame.nodes destination).isSome = true)
    (sameSource : request.source = source) (sameDestination : request.destination = destination)
    (samePacket : packet.eval assignment Locals.empty =
      packetValue (.requestVoteRequest request))
    (sameSignature : signatureTerm.eval assignment Locals.empty = (signature : Int)) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        (NativeArrayVoteReceive.receive frame destination request signature) := by
  obtain ⟨voted, popped, shape, popRun, pushRun⟩ :=
    vote_receive_writes_steps source destination packet signatureTerm before after run
  obtain ⟨defined, definition, votedEqual⟩ := shape.definition
  subst voted
  obtain ⟨first, firstAgreement, firstHolds⟩ :=
    define_extension _ before defined before.next definition assignment holds
  have votedHolds :
      Holds ({ defined with votedFor := before.next } : Encoding width).assertions.toList first :=
    firstHolds
  have firstRep := rep.agrees_below before assignment first frame valid firstAgreement
  have firstPacket : packet.eval first Locals.empty = packetValue (.requestVoteRequest request) :=
    (packet.eval_agrees_below assignment first Locals.empty before.next shape.packetSymbols
      firstAgreement).symm.trans samePacket
  have firstSignature : signatureTerm.eval first Locals.empty = (signature : Int) :=
    (signatureTerm.eval_agrees_below assignment first Locals.empty before.next
      shape.signatureSymbols firstAgreement).symm.trans sameSignature
  have votedRep := vote_receive_write_frame source destination packet request signatureTerm signature
    before { defined with votedFor := before.next } shape first votedHolds frame firstRep present
    sameSource firstPacket firstSignature
  let votedFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := voteReceiveNodes frame.nodes destination request signature }
  obtain ⟨afterPop, popAgreement, popHolds, popRep⟩ :=
    pop_queue_complete source destination { defined with votedFor := before.next } popped popRun
      first votedHolds votedFrame (by simpa [votedFrame] using votedRep)
      (shape.references valid)
  have firstToPop : first.AgreesBelow before.next afterPop :=
    popAgreement.restrict (by rw [shape.next]; omega)
  have totalToPop := firstAgreement.trans firstToPop
  have popPacket : packet.eval afterPop Locals.empty =
      packetValue (.requestVoteRequest request) :=
    (packet.eval_agrees_below assignment afterPop Locals.empty before.next shape.packetSymbols
      totalToPop).symm.trans samePacket
  have popSignature : signatureTerm.eval afterPop Locals.empty = (signature : Int) :=
    (signatureTerm.eval_agrees_below assignment afterPop Locals.empty before.next
      shape.signatureSymbols totalToPop).symm.trans sameSignature
  have originalRep := rep.agrees_below before assignment afterPop frame valid totalToPop
  let response := NativeArrayVoteReceive.response
    (NativeArrayCheckQuorum.get frame.nodes destination) request signature
  have sameResponse := vote_response_term_correct afterPop before.toColumns frame.nodes
    originalRep.nodes destination packet request popPacket signatureTerm signature popSignature
  have responseSource : response.source = destination := by
    change request.destination = destination
    exact sameDestination
  have responseDestination : response.destination = source := by
    change request.source = source
    exact sameSource
  have responseRun :
      (pushQueue response.destination response.source
        (voteResponseTerm before.toColumns destination packet signatureTerm)).run popped =
          .ok ((), after) := by
    rw [responseDestination, responseSource]
    exact pushRun
  obtain ⟨extended, pushAgreement, finalHolds, finalRep⟩ :=
    push_queue_complete _ (.requestVoteResponse response) popped after
      responseRun
      afterPop popHolds
      { votedFrame with queues := NativeArrayQueue.popSource votedFrame.queues destination source }
      popRep (pop_queue_references destination source
        { defined with votedFor := before.next } popped popRun (shape.references valid))
      sameResponse
  have agreement : assignment.AgreesBelow before.next extended :=
    totalToPop.trans (pushAgreement.restrict (by
      have popNext :=
        (pop_queue_success destination source { defined with votedFor := before.next } popped popRun).next
      rw [popNext, shape.next]
      omega))
  refine ⟨extended, agreement, finalHolds, ?_⟩
  simpa [NativeArrayVoteReceive.receive, votedFrame, voteReceiveNodes, response, sameSource] using finalRep

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
