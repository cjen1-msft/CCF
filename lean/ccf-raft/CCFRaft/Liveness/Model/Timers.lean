module

public import CCFRaft.Liveness.Model.Scheduling

@[expose] public section

/-!
# Election timers with explicit deadlines

`ElectionScheduling` constrains timeouts only through the recorded resets. To
reason about the random draw itself, the world carries each node's pending
deadline: a reset draws it, and a node times out only once it has passed.
In the duel, `Liveness.run` takes the `j`-th participant reset's draw from a
sample (`Liveness.Sample`) of independent draws.
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

Risk: this is a precondition about CCF's host driver, not a refinement of it.
CCF keeps no real-time deadline. `restart_election_timeout` (`raft.h`) sets
`timeout_elapsed` to a whole number of milliseconds drawn uniformly from
`[0, election_timeout / 2]`. `periodic` runs every `tick_interval` on the node's
own job-board clock, adds the time since its last run, and starts an election
once `timeout_elapsed >= election_timeout`, if the node is `ticking` and its
retirement is not committed. The differences:
- Ticks. A timeout fires at a tick, so up to a tick after the ideal deadline,
  and later still if ticks run late under load. The first tick after a reset
  also counts the time before the reset, so a timeout can also fire up to a
  tick early. `Bounds.electionTimeout` absorbs the early side. The late side is
  unbounded in CCF but capped at `electionTimeout` here.
- Clocks. Deadlines here are on the one global `time`, whereas each CCF node
  measures elapsed time on its own clock, so drift moves real deadlines.
- Gating. CCF never times out before `start_ticking`, which runs the first time
  the node appends a signature while it is in its latest configuration, and
  stays on. `canStartElection` instead checks membership of a signed active
  configuration at each timeout. The two are close but not the same, and the
  difference is not modelled.
- Resets. Becoming primary zeroes `timeout_elapsed`, which then counts towards
  the heartbeat `request_timeout`, not an election. Here a primary keeps a stale
  deadline, which is harmless: a primary cannot time out, and in both every way
  out of primary either draws afresh (`become_follower`, on a later term or a
  failed quorum check) or commits the node's retirement, after which it never
  times out. `start_ticking` also zeroes it, without a draw, so until its next
  reset a newly ticking node is due after the full `election_timeout`: the top
  of the range, not a uniform draw.
Why the risk is accepted: the properties are about the protocol, not the
driver. Outside the duel only the lower end is used, through
`ElectionScheduling`, which CCF meets once `Bounds.electionTimeout` allows for
ticks and drift. Only the duel uses the upper end and the draw distribution, so
only the duel is exposed to late ticks, drift and the `start_ticking` reset.
Per-node clocks are future work (`README.md`). -/
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
