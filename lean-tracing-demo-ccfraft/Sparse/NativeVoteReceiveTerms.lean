-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVotePacket
import Sparse.NativeArrayVoteReceive

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def isVoteRequestTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) : Term context .bool :=
  .cases (.snd packet) (.boolean false)
    (.cases (.bound .here) (.boolean false)
      (.cases (.bound .here) (.boolean true) (.boolean false)))

def voteRequestSnapshotTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) : Term context (.pair .int .int) :=
  .cases (.snd packet) (.pair (.integer 0) (.integer 0))
    (.cases (.bound .here) (.pair (.integer 0) (.integer 0))
      (.cases (.bound .here) (.bound .here) (.pair (.integer 0) (.integer 0))))

def voteFreshTerm {context : List Ty} {width : PNat} (columns : Columns)
    (node : Fin width) (packet : Term context (packetTy width))
    (signature : Term context .int) : Term context .bool :=
  let snapshot := voteRequestSnapshotTerm packet
  let localTerm := logTermAt width columns node.val signature
  .or (lt localTerm (.fst snapshot))
    (.and (.equal (.fst snapshot) localTerm) (.le signature (.snd snapshot)))

def voteGrantTerm {width : PNat} (columns : Columns) (node : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int) : Expr .bool :=
  let voted : Expr optionalIntTy := read columns columns.votedFor node.val (.inl .unit)
  all [.equal (.fst (.fst packet)) (read columns columns.currentTerm node.val (.integer 0)),
    voteFreshTerm columns node packet signature,
    .or (.equal voted (.inl .unit)) (.equal voted (.inr (.fst (.snd (.fst packet)))))]

def voteResponseTerm {width : PNat} (columns : Columns) (node : Fin width)
    (packet : Expr (packetTy width)) (signature : Expr .int) : Expr (packetTy width) :=
  .pair (.pair (read columns columns.currentTerm node.val (.integer 0))
    (.pair (.snd (.snd (.fst packet))) (.fst (.snd (.fst packet)))))
    (.inr (.inr (.inr (.inl (voteGrantTerm columns node packet signature)))))

theorem is_vote_request_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment) (locals : Locals context)
    (message : Message (Fin width) Nat) (same : packet.eval assignment locals = packetValue message) :
    (isVoteRequestTerm packet).eval assignment locals = true <->
      exists request, message = .requestVoteRequest request := by
  cases message <;> simp [isVoteRequestTerm, Term.eval, same, packetValue, packetPayloadValue, Locals.cons]

theorem vote_request_snapshot_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment) (locals : Locals context)
    (request : RequestVoteRequest (Fin width))
    (same : packet.eval assignment locals = packetValue (.requestVoteRequest request)) :
    (voteRequestSnapshotTerm packet).eval assignment locals =
      ((request.lastCommittableTerm : Int), (request.lastCommittableIndex : Int)) := by
  simp [voteRequestSnapshotTerm, Term.eval, same, packetValue, packetPayloadValue, Locals.cons]

theorem vote_fresh_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width)
    (packet : Expr (packetTy width)) (request : RequestVoteRequest (Fin width))
    (samePacket : packet.eval assignment Locals.empty = packetValue (.requestVoteRequest request))
    (position : Expr .int) (signature : Nat)
    (sameSignature : position.eval assignment Locals.empty = (signature : Int)) :
    (voteFreshTerm columns node packet position).eval assignment Locals.empty = true <->
      NativeArrayVoteReceive.logUpToDate (NativeArrayCheckQuorum.get arrays node) request signature := by
  have snapshot := vote_request_snapshot_correct packet assignment Locals.empty request samePacket
  have term := log_term_at_correct assignment Locals.empty columns arrays rep node position signature sameSignature
  simp only [voteFreshTerm, lt, Term.eval, snapshot, term, sameSignature,
    Bool.or_eq_true, Bool.and_eq_true, Bool.not_eq_true', decide_eq_false_iff_not,
    decide_eq_true_eq, Int.ofNat_le, Int.ofNat_inj, not_le, NativeArrayVoteReceive.logUpToDate]

theorem vote_grant_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width)
    (packet : Expr (packetTy width)) (request : RequestVoteRequest (Fin width))
    (samePacket : packet.eval assignment Locals.empty = packetValue (.requestVoteRequest request))
    (position : Expr .int) (signature : Nat)
    (sameSignature : position.eval assignment Locals.empty = (signature : Int)) :
    (voteGrantTerm columns node packet position).eval assignment Locals.empty =
      NativeArrayVoteReceive.grant (NativeArrayCheckQuorum.get arrays node) request signature := by
  have fresh := vote_fresh_term_correct assignment columns arrays rep node packet request samePacket
    position signature sameSignature
  apply Bool.eq_iff_iff.mpr
  simp only [voteGrantTerm, all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq, and_true, fresh, rep.currentTerm, rep.votedFor,
    samePacket, packetValue, packetHeaderValue, Message.term, Message.source,
    Message.destination, NativeArrayVoteReceive.grant, Int.ofNat_inj]
  cases chosen : (NativeArrayCheckQuorum.get arrays node).votedFor with
  | none => simp [optionalValue]
  | some peer =>
    simp only [optionalValue, reduceCtorEq, false_or, Option.some.injEq]
    apply and_congr Iff.rfl
    apply and_congr Iff.rfl
    change (Sum.inr (peer.val : Int) : Unit ⊕ Int) = Sum.inr (request.source.val : Int) <->
      peer = request.source
    simp [Fin.ext_iff]

theorem vote_response_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width)
    (packet : Expr (packetTy width)) (request : RequestVoteRequest (Fin width))
    (samePacket : packet.eval assignment Locals.empty = packetValue (.requestVoteRequest request))
    (position : Expr .int) (signature : Nat)
    (sameSignature : position.eval assignment Locals.empty = (signature : Int)) :
    (voteResponseTerm columns node packet position).eval assignment Locals.empty =
      packetValue (.requestVoteResponse (NativeArrayVoteReceive.response
        (NativeArrayCheckQuorum.get arrays node) request signature)) := by
  have granted := vote_grant_term_correct assignment columns arrays rep node packet request samePacket
    position signature sameSignature
  simp only [voteResponseTerm, Term.eval, granted, rep.currentTerm, samePacket,
    packetValue, packetHeaderValue, packetPayloadValue, NativeArrayVoteReceive.response,
    Message.term, Message.source, Message.destination]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
