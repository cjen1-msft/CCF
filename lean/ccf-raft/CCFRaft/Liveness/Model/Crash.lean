module

public import CCFRaft.Liveness.Model.Event

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

/-- Crash-stop availability after an event. -/
def Event.liveAfter (event : Event) (live : Finset NodeID) : Finset NodeID :=
  match event with
  | .crash node => live.erase node
  | _ => live

/-- Actors must be live, and crashes permanently remove them.
The initial live set is unrestricted. -/
def crashSystem : CCF.TransitionSystem (Finset NodeID) Event where
  init _ := True
  step live event :=
    match event.actor with
    | some node =>
        if node ∈ live then
          some (match event with
            | .crash _ => live.erase node
            | _ => live)
        else none
    | none => some (event.liveAfter live)

end CCFRaft.Liveness
