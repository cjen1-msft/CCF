module

public import CCFRaft.Proofs.Duel.SplitDefs

@[expose] public section

/-!
# The leaderless round: the frozen invariant

NOT IMPORTED BY `Properties`. Once every participant has adopted `term + 1`, and as
long as no participant is primary of `term + 1`, the round is `Frozen`, the
participants' logs and configurations stay put, and a participant's timer is reset
only by its own timeouts.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Duel.Racing (Keeps)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

section Frozen

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup originFound noElection

/-- A leaderless round is frozen from one delay after its start. -/
theorem RoundSetup.frozen {index : Nat} {point : W}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (late : time origin + maxDelay < time point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    : Frozen trace participants c term index point := by
  sorry

/-- A leaderless round keeps every participant's log, commit index and retirement
from one delay after its start. -/
theorem RoundSetup.frozen_keeps {index later : Nat} {point laterPoint : W}
    (capped : Capped trace participants c term later) (le : index <= later)
    (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint)
    (late : time origin + maxDelay < time point)
    (timeLe
      : time laterPoint <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants) {state laterState : NodeState}
    (stateFound : nodeState (proto point) node = some state)
    (laterStateFound : nodeState (proto laterPoint) node = some laterState)
    : Keeps state laterState := by
  sorry

/-- From two delays after the start of a leaderless round, only a participant's own
timeouts reset its timer, until the step that ends the round. -/
theorem RoundSetup.reset_late {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (capped : Capped trace participants c term (index + 1))
    (stepped : trace.stepAt index = some step)
    (late : time origin + 2 * maxDelay < time step.before)
    (timeLe
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants) (reset : ElectionReset step node)
    : TermTimeout trace term index node := by
  sorry

end Frozen

end CCFRaft.Proofs.Duel.Round
