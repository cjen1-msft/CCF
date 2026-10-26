module

public import CCFRaft.Proofs.Duel.Resolve
public import CCFRaft.Proofs.Leadership.Init

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The duel's setup from a configured good period

`Setup.initialPhase` is not an assumption: `Leadership.init_of_incumbent` derives
it from a good period whose participants have committed configurations and roles
at its start.
-/

namespace CCFRaft.Proofs.Duel.Resolve

open CCFRaft.Liveness
open CCF.MultiNodeTransitionSystem (nodeState)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Leadership (initRaiseLength init_of_incumbent Low)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-- The duel's setup, with its initial phase from INIT. -/
theorem setup_of_init [Config.InitialConfiguration] {nodes : List NodeID}
    {trace : Trace W Liveness.Event}
    {electionTimeout maxDelay jump fresh bound duration : Real} {overshoots start : Nat}
    {participants members : Finset NodeID}
    (admissible
      : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
    (firing
      : forall node,
          node ∈ participants
          -> Scheduled trace (some 0) (fun point => TimeoutDue point node)
              (fun step => step.action = .local node (.timeout .election)))
    (overshoot
      : exists bad : Finset Nat,
          bad.card <= overshoots
          /\ forall index step node,
              node ∈ participants
              -> Within trace start duration index
              -> trace.stepAt index = some step
              -> NoOvershoot (some (if index ∈ bad then jump else 0)) step node)
    (nonnegative : 0 <= maxDelay) (jumpNonnegative : 0 <= jump)
    (ratio : 4 * maxDelay < electionTimeout / 2)
    (long : initRaiseLength electionTimeout maxDelay jump + bound <= duration)
    (boundNonnegative : 0 <= bound)
    (period : GoodPeriod trace start duration participants)
    (matching : Window.Matching trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (membership
      : forall point,
          trace.stateAt start = some point
          -> Membership participants members (proto point))
    (subset : participants ⊆ members)
    (configured
      : forall point,
          trace.stateAt start = some point
          -> ConfigurationCommitted participants (proto point))
    (roled
      : forall first node state,
          trace.stateAt start = some first
          -> node ∈ participants
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
    (nonempty : participants.Nonempty)
    (present : forall node, node ∈ participants -> node ∈ nodes)
    (incumbent
      : forall index point leader state term,
          Within trace start (initRaiseLength electionTimeout maxDelay jump) index
          -> Low trace participants index term
          -> trace.stateAt index = some point
          -> leader ∈ participants
          -> nodeState (proto point) leader = some state
          -> state.currentTerm = term
          -> state.role = .primary
          -> HandoffBy trace participants index bound fresh
              \/ exists c after,
                  index <= c
                  /\ trace.stateAt c = some after
                  /\ time after <= time point + bound
                  /\ RoundStart trace participants c term)
    : Setup nodes trace (initRaiseLength electionTimeout maxDelay jump + bound)
        electionTimeout maxDelay jump fresh overshoots start duration participants
        members where
  admissible := admissible
  delay := delay
  timers := timers
  diverges := diverges
  firing := firing
  overshoot := overshoot
  nonnegative := nonnegative
  jumpNonnegative := jumpNonnegative
  ratio := ratio
  initialPhase := by
    obtain ⟨bad, _, holds⟩ := overshoot
    exact init_of_incumbent admissible delay timers diverges firing
      (fun index step node member within stepped =>
        noOvershoot_mono (by split_ifs <;> linarith)
          (holds index step node member within stepped))
      nonnegative jumpNonnegative (by linarith) (by linarith) boundNonnegative period
      active membership subset configured roled nonempty present incumbent
  period := period
  matching := matching
  active := active
  membership := membership
  subset := subset
  configured := configured

/-- The window covers the initial phase. -/
theorem initial_le_window {initial electionTimeout maxDelay jump : Real}
    {overshoots rounds : Nat} (nonnegative : 0 <= maxDelay) (jumpNonnegative : 0 <= jump)
    (ratio : 4 * maxDelay < electionTimeout / 2)
    : initial <= window initial electionTimeout maxDelay jump overshoots rounds := by
  unfold window Round.roundLength
  have : 0 <= ((overshoots : Real) + 1) * rounds * (electionTimeout + 4 * maxDelay) := by
    have : 0 <= electionTimeout + 4 * maxDelay := by linarith
    positivity
  have : 0 <= ((overshoots : Real) + 1) * jump := by positivity
  linarith

end CCFRaft.Proofs.Duel.Resolve
