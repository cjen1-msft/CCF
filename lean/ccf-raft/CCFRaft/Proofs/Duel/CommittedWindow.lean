module

public import CCFRaft.Proofs.Leadership.ConfiguredWindow
public import CCFRaft.Proofs.Leadership.InitEligible

@[expose] public section

/-!
# A committed configuration persists in a good window

`ConfigurationCommitted` through a good window: the committed prefix of a log only
grows (`Leadership.committed_later`).
-/

namespace CCFRaft.Proofs.Duel

open Model.Node
open CCFRaft.Liveness
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Proofs.Safety

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}

set_option linter.unusedVariables false in
/-- `ConfigurationCommitted` at the start of a good period holds at every recorded
state of it. -/
theorem ConfigurationCommitted.window
    (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
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
  intro index point within found node local_ mem member
  have nodeFound :=
    Direct.nodeState_of_mem (Direct.keys_nodup (admissible.reachable found)) mem
  exact Leadership.committed_iff.mpr
    (Leadership.committed_later admissible
      (fun first state firstFound stateFound =>
        Leadership.committed_iff.mp
          (initial first firstFound node state (Concrete.mem_of_nodeState stateFound) member))
      within.1 found nodeFound)

end CCFRaft.Proofs.Duel
