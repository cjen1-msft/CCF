module

public import CCFRaft.Proofs.Leadership.ConfiguredWindow

@[expose] public section

/-!
# A committed configuration persists in a good window

NOT IMPORTED BY `Properties`. A placeholder for D's propagation of
`ConfigurationCommitted` through a good window: commit indices only grow and the
committed prefix of a log is kept. To be replaced by D's lemma.
-/

namespace CCFRaft.Proofs.Duel

open Model.Node
open CCFRaft.Liveness
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}

/-- `ConfigurationCommitted` at the start of a good period holds at every recorded
state of it. -/
theorem ConfigurationCommitted.window
    (admissible
      : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)
    {start : Nat} {duration : Real} {participants : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    (initial
      : forall first,
          trace.stateAt start = some first
          -> ConfigurationCommitted participants (proto first))
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> ConfigurationCommitted participants (proto point) := by
  sorry

end CCFRaft.Proofs.Duel
