module

public import CCFRaft.Proofs.Duel.SplitFrozen

@[expose] public section

/-!
# The leaderless round: progress

NOT IMPORTED BY `Properties`. In a leaderless round a participant that can gather a
pre-vote quorum and times out raises the next round within two delays: its requests
arrive within one delay, every participant its log covers grants, and the grants
arrive within another. A participant with a longest log can gather one, and its
timer fires within an election timeout of its last reset, so a leaderless round ends
within a round length plus the overshoot.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

section Progress

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup originFound noElection

/-- A participant that can gather a pre-vote quorum and times out in `term + 1` ends
the round within two delays. -/
theorem RoundSetup.poll {timeoutIndex : Nat} {node : NodeID} {timeoutPoint : W}
    (member : node ∈ participants) (timedOut : TermTimeout trace term timeoutIndex node)
    (timeoutCapped : Capped trace participants c term timeoutIndex)
    (timeoutFound : trace.stateAt timeoutIndex = some timeoutPoint)
    (hopeful : Not (Racing.Hopeless participants timeoutPoint node))
    (timeLe
      : time timeoutPoint + 2 * maxDelay
        <= time origin + roundLength electionTimeout maxDelay + jump)
    {index : Nat} {point : W} (le : timeoutIndex <= index)
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    : time point <= time timeoutPoint + 2 * maxDelay := by
  sorry

/-- A leaderless round ends within a round length plus the overshoot of its steps. -/
theorem RoundSetup.progress {slack : Real} (slackNonnegative : 0 <= slack)
    (slackLe : slack <= jump) {index : Nat} {point : W}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (overshoot
      : forall earlier step node,
          node ∈ participants
          -> c <= earlier
          -> earlier < index
          -> trace.stepAt earlier = some step
          -> NoOvershoot (some slack) step node)
    : time point <= time origin + roundLength electionTimeout maxDelay + slack := by
  sorry

end Progress

end CCFRaft.Proofs.Duel.Round
