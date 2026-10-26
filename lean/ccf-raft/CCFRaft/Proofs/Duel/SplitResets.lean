module

public import CCFRaft.Proofs.Duel.SplitFrozen

@[expose] public section

/-!
# The leaderless round: resets without timeouts

NOT IMPORTED BY `Properties`. A participant that does not time out in `term + 1` is
reset into `term + 1` at most twice in the round: when it adopts `term + 1`, and
when it grants its one vote of `term + 1`. A candidate of `term + 1` asks each
participant once, and a delivery consumes its packet.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-- A participant without a timeout in `term + 1` before `index` has been reset into
`term + 1` at most twice. -/
theorem RoundSetup.resets_le_two
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    {index : Nat} {point : W} (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants)
    (quiet
      : forall earlier,
          c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier node))
    : priorResets trace c index node term <= 2 := by
  sorry

end CCFRaft.Proofs.Duel.Round
