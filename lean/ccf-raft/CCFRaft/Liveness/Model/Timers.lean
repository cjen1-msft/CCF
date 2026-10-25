module

public import CCFRaft.Liveness.Model.Scheduling

@[expose] public section

/-!
# Election timers with explicit deadlines

`ElectionScheduling` constrains timeouts only through the recorded resets. To
reason about the random draw itself, the world carries each node's pending
deadline: a reset draws it, and a node times out only once it has passed.
`Liveness.TimerDraws` pins the draws to a sample of a product measure.
-/

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

/-- Each node's pending election deadline, drawn when its timer is reset. -/
class HasTimers (W : Type) where
  deadline : W -> NodeID -> Real

open HasTimers (deadline)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W]

/-- Idealized real-time deadlines: a reset draws between half and all of
`electionTimeout` after its before-time; nothing else changes the deadline.
A node times out only once its deadline has passed. This implies
`ElectionScheduling (some (electionTimeout / 2))`
(`Proofs.Liveness.electionScheduling_of_timerModel`).
This is not yet a refinement of CCF's elapsed-tick counter: the conservative
lower-bound interpretation in `Bounds.electionTimeout` alone does not establish
the upper bound or the distribution of real-time deadlines. -/
def timerModel (electionTimeout : Real) : Model W Event where
  init _ := True
  next step :=
    forall node,
      (ElectionReset step node
        -> time step.before + electionTimeout / 2 <= deadline step.after node
            /\ deadline step.after node <= time step.before + electionTimeout)
      /\ (Not (ElectionReset step node)
          -> deadline step.after node = deadline step.before node)
      /\ (step.action = .local node (.timeout .election)
          -> deadline step.before node <= time step.before)

/-- A live node whose deadline has passed and which may start an election.
`startElection` runs only under `canStartElection`
(`Proofs.Leadership.startElection_guard`), so a node that cannot time out is
never due: only a halted clock could discharge its obligation. -/
def TimeoutDue (point : W) (node : NodeID) : Prop :=
  node ∈ live point
  /\ deadline point node <= time point
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
      /\ canStartElection state node

/-- A step that starts before the deadline of a live node that may start an
election ends at most `bound` past that deadline: the node is not paused for
longer than `bound` past its timeout. `none` allows any overshoot. -/
def NoOvershoot (bound : Option Real) (step : CCF.Execution.Step W Event) (node : NodeID)
    : Prop :=
  match bound with
  | none => True
  | some bound =>
      node ∈ live step.before
      -> (exists state,
            CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node = some state
            /\ canStartElection state node)
      -> time step.before < deadline step.before node
      -> time step.after <= deadline step.before node + bound

/-- A node whose deadline has passed times out, within the optional bound, and
no step carries the clock more than the bound past its deadline.
CCF checks on each `periodic` tick; `some 0` fires at the deadline itself, and
the tick is accounted for in `Bounds.electionTimeout`.
Needed (`NoOvershoot`): `Scheduled` counts only from the first recorded point at
which a node is due, so one idle step past every pending deadline would make
every node time out at once, whatever the draws. -/
def Trace.TimeoutScheduling (trace : Trace W Event) (bound : Option Real) : Prop :=
  forall node,
    Scheduled trace bound (fun point => TimeoutDue point node)
      (fun step => step.action = .local node (.timeout .election))
    /\ forall index step, trace.stepAt index = some step -> NoOvershoot bound step node

/-- The clock is unbounded along the recording: the execution neither stops nor
stalls. Needed: nothing else obliges a cluster without a primary to keep going. -/
def TimeDiverges (trace : Trace W Event) : Prop :=
  forall bound : Real,
    exists index point, trace.stateAt index = some point /\ bound <= time point

end CCFRaft.Liveness
