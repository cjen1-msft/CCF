module

public import CCFRaft.Liveness.Model.Packets

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasTime (time)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasNetwork W]

/-- From `start` on, every message sent on the selected links is delivered. Not a
premise of `Properties.commit_liveness`; it implies `FairLoss`. -/
def Reliable (trace : Trace W Event) (participants : Finset NodeID) (start : Nat) : Prop :=
  forall sent packet,
    trace.SentAt sent packet
    -> start <= sent
    -> packet.envelope.source ∈ participants
    -> packet.envelope.target ∈ participants
    -> exists index step,
        sent < index
        /\ trace.stepAt index = some step
        /\ step.action = .deliver packet

/-- Traffic classes ignore changing batch ends and commit advertisements.
Index-specific classes prevent unrelated heartbeats or old acknowledgements
from satisfying fairness while a particular log position is starved.
Each class covers a minimum term and every newer one. With exact terms, a node
that keeps moving to newer terms sends finitely many messages of each class, so
the network could drop all of its rejections and hide the newer terms forever.
`exact` is the textbook fair-loss class of one wire message. Without it the
network could always drop a rejection's lower hint while delivering a newer-term
rejection with the same index, so the primary would never backtrack. -/
inductive Traffic where
  | appendRequest (term : Nat)
  | replication (term index : Nat)
  | response (term : Nat) (success : Bool) (minimumIndex : Nat)
  | exact (message : Message)

/-- Protocol-relevant attempts, plus equality of entire wire messages. -/
def Traffic.Matches : Traffic -> Message -> Prop
  | .exact message, payload => payload = message
  | .appendRequest term, .appendEntriesRequest request => term <= request.term
  | .replication term index, .appendEntriesRequest request =>
      term <= request.term
      /\ request.prevLogIndex < index
      /\ index <= request.prevLogIndex + request.entries.length
  | .response term success minimumIndex, .appendEntriesResponse reply =>
      term <= reply.term /\ reply.success = success /\ minimumIndex <= reply.lastLogIndex
  | _, _ => False

/-- The source keeps sending this kind of message on the directed link. -/
def InfinitelySent (trace : Trace W Event) (source target : NodeID) (traffic : Traffic) : Prop :=
  forall cutoff,
    exists sent packet,
      trace.SentAt sent packet
      /\ cutoff <= sent
      /\ packet.envelope.source = source
      /\ packet.envelope.target = target
      /\ traffic.Matches packet.envelope.payload

/-- Messages of this kind sent in the execution keep arriving on the directed link. -/
def InfinitelyDelivered (trace : Trace W Event) (source target : NodeID) (traffic : Traffic)
    : Prop :=
  forall cutoff,
    exists index step packet,
      cutoff <= index
      /\ trace.stepAt index = some step
      /\ step.action = .deliver packet
      /\ packet.envelope.source = source
      /\ packet.envelope.target = target
      /\ traffic.Matches packet.envelope.payload

/-- Separately imposed fair-loss links between the participants, which may include
the whole working quorum: the network cannot drop every message of a `Traffic`
kind from some point on while its sender keeps sending that kind.
Any finite number of consecutive attempts may be dropped, in both directions,
and there is no bound on the number of omissions or on successful-delivery latency.
Needed: if the network drops every message, nothing more can commit.
Finite executions have no infinitely repeated traffic, so this condition is
vacuous for them; it does not require every outstanding packet to be delivered. -/
def FairLoss (trace : Trace W Event) (participants : Finset NodeID) : Prop :=
  forall source target traffic,
    source ∈ participants
    -> target ∈ participants
    -> InfinitelySent trace source target traffic
    -> InfinitelyDelivered trace source target traffic

end CCFRaft.Liveness
