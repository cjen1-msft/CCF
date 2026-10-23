module

public import CCFRaft.Liveness.Model.Protocol

@[expose] public section

namespace CCFRaft.Liveness

open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending issued)

/-- The outstanding packets that remain after an event: all but the one it
consumes, erased by send identity, so equal envelopes remain distinct occurrences. -/
def Event.remaining (event : Event) (pending : List Packet) : List Packet :=
  match event.consumedPacket with
  | some packet => pending.eraseP packet.sameIdentity
  | none => pending

/-- A step's outputs as packets, numbered on from `first`, all sent at `sentAt`. -/
def Packet.batch (emitted : List Model.Envelope) (first : Nat) (sentAt : Real)
    : List Packet :=
  (emitted.zipIdx first).map fun (envelope, id) => { id, envelope, sentAt }

/-- Constrain the packet ledger, without changing protocol, time or availability.
The ledger starts empty with no packets issued; consumption precedes registration
of this step's outputs.
Each output receives the next sequence number and the before-time of its sending step.
The supplied system checks that a protocol action producing outputs is enabled. -/
def deliveryModel {W : Type} [HasProtocol W Model.State] [HasTime W] [HasNetwork W]
    (system : CCF.TransitionSystem Model.State Model.Action)
    : Model W Event where
  init world := pending world = [] /\ issued world = 0
  next step :=
    (match step.action.consumedPacket with
      | some packet => packet ∈ pending step.before
      | none => True)
    /\ exists emitted,
        (match step.action.action with
          | some action => do
              let _ <- system.step (proto step.before) action
              outgoing (proto step.before) action
          | none => some [])
          = some emitted
        /\ issued step.after = issued step.before + emitted.length
        /\ pending step.after
            = step.action.remaining (pending step.before)
              ++ Packet.batch emitted (issued step.before) (time step.before)

/-- A separate deadline constraint on outstanding packets to live targets.
It permits loss: dropping a packet removes the obligation, unlike `Timely`.
No deadline state or delivery bound is built into `deliveryModel`. -/
def boundedDelayModel {W : Type} [HasTime W] [HasLive W] [HasNetwork W] (maxDelay : Real)
    : Model W Event where
  init world :=
    forall packet,
      packet ∈ pending world
      -> packet.envelope.target ∈ live world
      -> time world <= packet.sentAt + maxDelay
  next step :=
    forall packet,
      packet ∈ pending step.after
      -> packet.envelope.target ∈ live step.after
      -> time step.after <= packet.sentAt + maxDelay

end CCFRaft.Liveness
