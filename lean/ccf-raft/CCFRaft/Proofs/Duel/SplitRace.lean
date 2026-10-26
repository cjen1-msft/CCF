module

public import CCFRaft.Proofs.Duel.SplitResets
public import CCFRaft.Proofs.Duel.SplitProgress

@[expose] public section

/-!
# The leaderless round: the race

NOT IMPORTED BY `Properties`. A raise of a leaderless round needs a pre-vote quorum,
so some participant that can gather one timed out first. With no overshoot its
timeout is at its deadline, and with a margin every other such participant's
deadline is more than four delays later: each was last reset at most its second
time in the round, and only by adoption, a vote, or its own timeouts. That is a
`Racing.Race`.
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

/-- The step that ends a leaderless round without overshoot and with a margin is
preceded by a race of `term + 1`. -/
theorem RoundSetup.race_found
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    {next : Nat} {nextPoint : W} (capped : Capped trace participants c term next)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + roundLength electionTimeout maxDelay)
    (raise
      : exists step node state,
          trace.stepAt next = some step
          /\ node ∈ participants
          /\ nodeState (proto step.after) node = some state
          /\ term + 1 < state.currentTerm)
    (overshoot
      : forall index step node,
          node ∈ participants
          -> c <= index
          -> index < next
          -> trace.stepAt index = some step
          -> NoOvershoot (some 0) step node)
    (margin : RoundMargin trace participants c term (4 * maxDelay))
    : exists first winner step,
        c <= first
        /\ first <= next
        /\ trace.stepAt first = some step
        /\ Racing.Race trace electionTimeout maxDelay participants first winner
            (term + 1) := by
  sorry

end CCFRaft.Proofs.Duel.Round
