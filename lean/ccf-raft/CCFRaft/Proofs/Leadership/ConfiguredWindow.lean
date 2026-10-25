module

public import CCFRaft.Proofs.Leadership.AnchorWindow

@[expose] public section

/-!
# Configurations stay fixed in a good window

`Configured.step` over a good period: participants receive only from
participants, and nobody appends a configuration, so a predicate on every
configuration participants can count votes in, holding at the start, holds at
every recorded state of the window. In particular a fixed membership
(`Membership`) and an anchor blocking every countable quorum (`Blocks`) persist.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- A predicate on every configuration participants can count votes in, holding
at the start of a good period, holds at every recorded state of it. -/
theorem Configured.window {P : Finset NodeID -> Prop} {start : Nat} {duration : Real}
    {participants : Finset NodeID} (good : GoodPeriod trace start duration participants)
    (initial
      : forall first,
          trace.stateAt start = some first -> Configured P participants (proto first))
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> Configured P participants (proto point) := by
  intro index
  induction index with
  | zero =>
      intro point within found
      have atStart : start = 0 := Nat.le_zero.mp within.1
      subst atStart
      exact initial point found
  | succ index ih =>
      intro point within recorded
      by_cases atStart : index + 1 = start
      · rw [atStart] at recorded
        exact initial point recorded
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp recorded
      have afterStart : start <= index := by have := within.1; omega
      have indexWithin :=
        within_of_le admissible within recorded afterStart (Nat.le_succ index)
      have now := ih step.before indexWithin (admissible.before stepped)
      rcases selected : step.action.action with _ | action
      · rw [admissible.stutter stepped selected]
        exact now
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
      have isolated
          : c.actor ∈ participants
            -> forall source message,
                c.event = .receive source message -> source ∈ participants := by
        intro actorIn source message eventEq
        cases action with
        | «local» node input =>
            obtain ⟨_, eventEq'⟩ := acts
            cases eventEq'.symm.trans eventEq
        | deliver envelope =>
            obtain ⟨actorEq, eventEq'⟩ := acts
            obtain ⟨sourceEq, _⟩ := Model.Node.Event.receive.inj (eventEq'.symm.trans eventEq)
            rw [← sourceEq]
            exact good.isolated index step envelope indexWithin stepped
              (delivered_of_action selected) (actorEq ▸ actorIn)
      exact Configured.step c isolated
        (fun contents eventEq =>
          good.noReconfiguration index step c.actor contents indexWithin stepped
            (anchor_local_of_internal selected acts eventEq))
        now

/-- A fixed membership at the start of a good period holds throughout it. -/
theorem Membership.window {start : Nat} {duration : Real}
    {participants members : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    (initial
      : forall first,
          trace.stateAt start = some first
          -> Membership participants members (proto first))
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> Membership participants members (proto point) :=
  Configured.window admissible good initial

end CCFRaft.Proofs.Leadership
