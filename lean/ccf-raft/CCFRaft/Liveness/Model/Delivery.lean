module

public import CCFRaft.Liveness.Model.Protocol

@[expose] public section

namespace CCFRaft.Liveness

open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending issued)

/-- Constrain the packet ledger, without changing protocol, time or availability.
The ledger starts empty with no packets issued; consumption precedes registration
of this step's outputs.
Each output receives the next sequence number and the after-time of its sending step.
Consumption erases by send identity, so equal envelopes remain distinct occurrences.
The supplied system checks that a protocol action producing outputs is enabled. -/
def deliveryModel {W : Type} [HasProtocol W Model.State] [HasTime W] [HasNetwork W]
    (system : CCF.TransitionSystem Model.State Model.Action) : Model W Event where
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
        | none => some []) = some emitted
      /\ issued step.after = issued step.before + emitted.length
      /\ pending step.after =
        (match step.action.consumedPacket with
          | some packet => (pending step.before).eraseP packet.sameIdentity
          | none => pending step.before) ++
        (emitted.zipIdx (issued step.before)).map (fun (envelope, id) =>
          { id, envelope, sentAt := time step.after })

/-- A separate deadline constraint on outstanding packets to live targets.
It permits loss: dropping a packet removes the obligation, unlike `Timely`.
No deadline state or delivery bound is built into `deliveryModel`. -/
def boundedDelayModel {W : Type} [HasTime W] [HasLive W] [HasNetwork W]
    (maxDelay : Real) : Model W Event where
  init world :=
    forall packet, packet ∈ pending world
      -> packet.envelope.target ∈ live world
      -> time world <= packet.sentAt + maxDelay
  next step :=
    forall packet, packet ∈ pending step.after
      -> packet.envelope.target ∈ live step.after
      -> time step.after <= packet.sentAt + maxDelay

end CCFRaft.Liveness
