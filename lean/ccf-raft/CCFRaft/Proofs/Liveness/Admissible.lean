module

public import CCFRaft.Proofs.Liveness.Trace
public import CCFRaft.Liveness.Assumptions

@[expose] public section

/-!
# Admissible executions

The executions the liveness theorems quantify over: coherent recordings valid for
the protocol, timing, crash and delivery models. Each fact here is read off one
recorded step, or carried along the recording by induction.
-/

namespace CCFRaft.Liveness.Trace

open Model.Node
open HasProtocol (proto)

variable {W A : Type} [HasProtocol W Model.State]

/-- A node's protocol state at a recorded index; `none` past the end of a finite
recording, or when the node has no state. -/
def nodeAt (trace : Trace W A) (index : Nat) (node : NodeID) : Option NodeState :=
  (trace.stateAt index).bind
    fun point =>
      CCF.MultiNodeTransitionSystem.nodeState (proto point) node

theorem nodeAt_of_stateAt {trace : Trace W A} {index : Nat} {point : W}
    (found : trace.stateAt index = some point) (node : NodeID)
    : trace.nodeAt index node
      = CCF.MultiNodeTransitionSystem.nodeState (proto point) node := by
  simp [nodeAt, found]

theorem nodeAt_eq_some {trace : Trace W A} {index : Nat} {node : NodeID}
    {state : NodeState}
    : trace.nodeAt index node = some state
      <-> exists point,
            trace.stateAt index = some point
            /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) node
                = some state := by
  simp [nodeAt, Option.bind_eq_some_iff]

theorem stateAt_of_nodeAt {trace : Trace W A} {index : Nat} {node : NodeID}
    {state : NodeState} (found : trace.nodeAt index node = some state)
    : exists point, trace.stateAt index = some point :=
  let ⟨point, found, _⟩ := nodeAt_eq_some.mp found
  ⟨point, found⟩

/-- A node's state after a recorded step. -/
theorem nodeAt_succ {trace : Trace W A} {index : Nat} {step : CCF.Execution.Step W A}
    (stepped : trace.stepAt index = some step) (node : NodeID)
    : trace.nodeAt (index + 1) node
      = CCF.MultiNodeTransitionSystem.nodeState (proto step.after) node :=
  nodeAt_of_stateAt (stateAt_succ_of_stepAt stepped) node

end CCFRaft.Liveness.Trace

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- The recorded executions of `system` that the liveness theorems consider. -/
structure Admissible (system : CCF.TransitionSystem Model.State Model.Action)
    (trace : Trace W Liveness.Event)
    : Prop where
  coherent : trace.Coherent
  protocol : trace.Valid (protocolModel system)
  timing : trace.Valid timingModel
  crash : trace.Valid crashModel
  delivery : trace.Valid (deliveryModel system)

namespace Admissible

variable {system : CCF.TransitionSystem Model.State Model.Action}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible system trace)

include admissible

theorem before {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : trace.stateAt index = some step.before :=
  admissible.coherent.before stepped

/-- A recorded protocol action is an enabled step of the system. -/
theorem step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {action : Model.Action} (stepped : trace.stepAt index = some step)
    (selected : step.action.action = some action)
    : system.step (proto step.before) action = some (proto step.after) := by
  have next := admissible.protocol.next stepped
  simp only [protocolModel, selected] at next
  exact next

/-- Environment-only events leave the protocol state unchanged. -/
theorem stutter {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (selected : step.action.action = none)
    : proto step.after = proto step.before := by
  have next := admissible.protocol.next stepped
  simp only [protocolModel, selected] at next
  exact next

/-- Environment events do not introduce new protocol states. -/
theorem reachable {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : system.Reachable (proto point) :=
  admissible.protocol.invariant admissible.coherent
    (invariant := fun point => system.Reachable (proto point))
    (fun _ init => .initial init)
    (fun step next held => by
      cases selected : step.action.action with
      | none =>
          simp only [protocolModel, selected] at next
          rw [next]
          exact held
      | some action =>
          simp only [protocolModel, selected] at next
          exact .step held next)
    found

/-- A node's state before a recorded step. -/
theorem nodeAt_before {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (node : NodeID)
    : trace.nodeAt index node
      = CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node :=
  Trace.nodeAt_of_stateAt (admissible.before stepped) node

theorem reachable_before {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : system.Reachable (proto step.before) :=
  admissible.reachable (admissible.before stepped)

/-- Time never runs backwards along the recording. -/
theorem time_le {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : time first <= time last :=
  admissible.coherent.chain (relation := fun first last => time first <= time last)
    (fun _ => le_rfl) (fun _ _ _ => le_trans)
    (fun _ _ stepped => admissible.timing.next stepped) le firstFound lastFound

/-- The actor of a recorded step is live before it. -/
theorem actor_live {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {node : NodeID} (stepped : trace.stepAt index = some step)
    (actor : step.action.actor = some node)
    : node ∈ live step.before := by
  have next := admissible.crash.next stepped
  simp only [crashModel, crashSystem, actor] at next
  by_contra absent
  simp [absent] at next

/-- A step only removes live nodes, by crashing them. -/
theorem live_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : live step.after ⊆ live step.before := by
  have next := admissible.crash.next stepped
  obtain ⟨before, event, after⟩ := step
  simp only [crashModel, crashSystem] at next
  cases event with
  | crash node =>
      simp only [Liveness.Event.actor] at next
      split_ifs at next with present
      · simp only [Option.some.injEq] at next
        rw [← next]
        exact Finset.erase_subset _ _
  | _ =>
      simp only [Liveness.Event.actor, Liveness.Event.liveAfter] at next
      first
      | (split_ifs at next with present; simp_all)
      | simp_all

/-- Crash-stop: a node live at a recorded state was live at every earlier one. -/
theorem live_anti {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : live last ⊆ live first :=
  admissible.coherent.chain (relation := fun first last => live last ⊆ live first)
    (fun _ => Finset.Subset.refl _) (fun _ _ _ first second => second.trans first)
    (fun _ _ stepped => admissible.live_step stepped) le firstFound lastFound

end Admissible

end CCFRaft.Proofs.Liveness

namespace CCFRaft.Liveness.StableLeader

open Model.Node
open HasProtocol (proto)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasLive W]
  {trace : Trace W Liveness.Event}
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)

include stable

/-- The primary at a recorded state from `start`. -/
theorem leads {index : Nat} {point : W} (le : start <= index)
    (found : trace.stateAt index = some point)
    : Membership.mem (live point) leader
      /\ exists state,
          CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
          /\ state.role = .primary
          /\ state.currentTerm = term
          /\ Not (state.isRetiredCommitted leader) := by
  obtain ⟨point', state, found', alive, nodeFound, primary, current, notRetired⟩ :=
    stable.2 index point le found
  rw [found, Option.some.injEq] at found'
  subst found'
  exact ⟨alive, state, nodeFound, primary, current, notRetired⟩

theorem live {index : Nat} {point : W} (le : start <= index)
    (found : trace.stateAt index = some point)
    : Membership.mem (live point) leader :=
  (stable.leads le found).1

/-- The primary has a state at every recorded index from `start`. -/
theorem found {index : Nat} {point : W} (le : start <= index)
    (found : trace.stateAt index = some point)
    : exists state, trace.nodeAt index leader = some state := by
  obtain ⟨_, state, nodeFound, _⟩ := stable.leads le found
  exact ⟨state, by rw [Trace.nodeAt_of_stateAt found, nodeFound]⟩

/-- The primary's state from `start` is primary in `term`, and not retired. -/
theorem state {index : Nat} {state : NodeState} (le : start <= index)
    (found : trace.nodeAt index leader = some state)
    : state.role = .primary
      /\ state.currentTerm = term
      /\ Not (state.isRetiredCommitted leader) := by
  obtain ⟨point, pointFound, nodeFound⟩ := Trace.nodeAt_eq_some.mp found
  obtain ⟨_, state', nodeFound', primary, current, notRetired⟩ := stable.leads le pointFound
  rw [nodeFound, Option.some.injEq] at nodeFound'
  subst nodeFound'
  exact ⟨primary, current, notRetired⟩

theorem primary {index : Nat} {state : NodeState} (le : start <= index)
    (found : trace.nodeAt index leader = some state)
    : state.role = .primary :=
  (stable.state le found).1

theorem current {index : Nat} {state : NodeState} (le : start <= index)
    (found : trace.nodeAt index leader = some state)
    : state.currentTerm = term :=
  (stable.state le found).2.1

theorem notRetired {index : Nat} {state : NodeState} (le : start <= index)
    (found : trace.nodeAt index leader = some state)
    : Not (state.isRetiredCommitted leader) :=
  (stable.state le found).2.2

/-- The primary stays primary of `term` from any later recorded index. -/
theorem later {later : Nat} (le : start <= later)
    (found : exists point, trace.stateAt later = some point)
    : StableLeader trace later leader term :=
  ⟨
    found,
    fun index point after indexFound => stable.2 index point (le.trans after) indexFound
  ⟩

end CCFRaft.Liveness.StableLeader
