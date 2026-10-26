module

public import CCFRaft.Proofs.Duel.Round
public import CCFRaft.Proofs.Duel.Elected

@[expose] public section

/-!
# The duel round

NOT IMPORTED BY `Properties`. Public statement (i): one duel round reaches an
anchored start or the next round, and with a margin an anchored start.
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

/-! ## The round -/

/-- (i) One duel round. From a round start at `c`, the run reaches an anchored start,
or the next round start, within a round length plus the overshoot. The next round
start is the first step after `c` that moves a participant past `term + 1`. If no
step of the round overshoots, the next round starts within a round length; if the
round also keeps a margin of `4 * maxDelay`, it reaches an anchored start within a
round length and four delays. -/
theorem duel_round
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    : HandoffBy trace participants c (roundLength electionTimeout maxDelay + jump)
        (electionTimeout / 2 - 4 * maxDelay)
      \/ exists next origin point,
          c < next
          /\ trace.stateAt c = some origin
          /\ trace.stateAt next = some point
          /\ Capped trace participants c term next
          /\ time point <= time origin + roundLength electionTimeout maxDelay + jump
          /\ RoundStart trace participants next (term + 1)
          /\ ((forall index step node,
                node ∈ participants
                -> c <= index
                -> index < next
                -> trace.stepAt index = some step
                -> NoOvershoot (some 0) step node)
              -> time point <= time origin + roundLength electionTimeout maxDelay
                  /\ (RoundMargin trace participants c term (4 * maxDelay)
                      -> HandoffBy trace participants c
                          (roundLength electionTimeout maxDelay + 4 * maxDelay)
                          (electionTimeout / 2 - 4 * maxDelay))) := by
  sorry

end CCFRaft.Proofs.Duel.Round
