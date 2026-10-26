module

public import CCFRaft.Proofs.Duel.Elected
public import CCFRaft.Proofs.Duel.Round

@[expose] public section

/-!
# The elected case with a short window

NOT IMPORTED BY `Properties`. The elected case of a duel round when the window is
known to cover only the round's first four delays: a primary of `term + 1` by
`time c + 4 * maxDelay` hands off by then. The round's caps and packet bounds are
derived within that horizon.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {E d jump : Real} {start : Nat} {duration : Real}
  {participants members : Finset NodeID} {c term : Nat}

/-- A primary of `term + 1` within four delays of the round start hands off by then,
with the window known to cover only those four delays. -/
theorem RoundBase.handoff_within
    (setup : RoundBase nodes trace E d jump start duration participants members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    (inside
      : forall index point,
          c <= index
          -> trace.stateAt index = some point
          -> time point <= time origin + 4 * d
          -> Within trace start duration index)
    {index : Nat} {point : W} {leader : NodeID} {state : NodeState} (indexLe : c <= index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + 4 * d) (member : leader ∈ participants)
    (leaderFound : nodeState (proto point) leader = some state)
    (primary : state.role = .primary) (termEq : state.currentTerm = term + 1)
    : HandoffBy trace participants c (4 * d) (E / 2 - 4 * d) := by
  have window : Inside trace start duration c origin (4 * d) := inside
  have := setup.nonnegative
  have := setup.ratio
  have short : RoundShort nodes trace E d jump start duration participants members c term :=
    { toRoundBase := setup
      inside := fun other otherFound => by
        rw [originFound, Option.some.injEq] at otherFound
        subst other
        exact window }
  have capped
      : forall index point,
          c <= index
          -> trace.stateAt index = some point
          -> time point <= time origin + 4 * d
          -> Capped trace participants c term index :=
    fun index point le found bounded =>
      (setup.capped_from originFound window (by linarith) index point le found
        (by linarith) bounded).1
  obtain ⟨elected, electedPoint, electedState, first, _, electedFound, electedEarly,
      electedLeader, electedPrimary, electedTerm⟩ :=
    setup.elected_from originFound window (by linarith) member index point state
      (capped index point indexLe found timeLe) found timeLe leaderFound primary termEq
  exact short.handoff_settle originFound
    (fun index point packet le found bounded queued source target payload =>
      (setup.packets (capped index point le found bounded) originFound
        (window.mono (by linarith)) found queued source target).2.2.2.2.2
        payload)
    capped first electedFound electedEarly member electedLeader electedPrimary electedTerm

end CCFRaft.Proofs.Duel.Round
