module

public import CCFRaft.Proofs.Duel.Adaptive
public import CCFRaft.Proofs.Duel.Attempts
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

/-!
# Relevant draws of a policy run

NOT IMPORTED BY `Properties`. The draws of `Adaptive.run` that `Attempts` counts.

Rounds are cut at raises: steps that lift the highest term among the participants.
Counting from the first round start at or after `start`, round `k` runs from the
`k + 1`-th raise up to the next one. A draw is
relevant to round `k` when a participant's reset in round `k` into the round's term
consumes it, and the participant has reset into that term at most once before in
the round. Its centres are the other participants' deadlines, less the reset time.

Whether a draw is relevant, and its centres, depend only on the steps before the
reset that consumes it and on that step's skeleton, which the policy fixes from the
earlier draws: so both are measurable in the draws before it.
-/

namespace CCFRaft.Proofs.Duel.Adaptive

open CCFRaft.Liveness MeasureTheory Set
open CCFRaft.Proofs.Duel.Rounds (revealed)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-! ## Rounds of a trace -/

/-- The highest term among the participants. -/
def maxTerm (participants : Finset NodeID) (point : W) : Nat :=
  participants.sup fun node => ((nodeState (proto point) node).map (·.currentTerm)).getD 0

/-- Step `index` lifts the highest participant term. -/
def Raises (trace : Trace W Liveness.Event) (participants : Finset NodeID) (index : Nat)
    : Prop :=
  exists step,
    trace.stepAt index = some step
    /\ maxTerm participants step.before < maxTerm participants step.after

/-- `first` is the first round start at or after `start`. -/
def FirstRound (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (start first : Nat)
    : Prop :=
  start <= first
  /\ (exists term, RoundStart trace participants first term)
  /\ forall index,
      start <= index
      -> index < first
      -> Not (exists term, RoundStart trace participants index term)

open Classical in
/-- Step `index` is in round `k` from `start`: counting from the first round start at
or after `start`, it is at or after the `k + 1`-th raise, and before the next. -/
def InRound (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (start k index : Nat)
    : Prop :=
  exists first,
    FirstRound trace participants start first
    /\ first <= index
    /\ ((Finset.Icc first index).filter (Raises trace participants)).card = k + 1

open Classical in
/-- The participant resets among the steps before `index`: the index of the draw
a participant reset at `index` consumes. -/
noncomputable def drawsBefore (trace : Trace W Liveness.Event)
    (participants : Finset NodeID) (index : Nat)
    : Nat :=
  ((Finset.range index).filter
    fun earlier =>
      exists step node,
        trace.stepAt earlier = some step
        /\ node ∈ participants
        /\ ElectionReset step node).card

/-- Step `index` resets `node` into the highest participant term. -/
def TopReset (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (index : Nat) (node : NodeID)
    : Prop :=
  exists step state,
    trace.stepAt index = some step
    /\ ElectionReset step node
    /\ nodeState (proto step.after) node = some state
    /\ state.currentTerm = maxTerm participants step.after

open Classical in
/-- The resets of `node` into the top term in round `k` before `index`. -/
noncomputable def roundResets (trace : Trace W Liveness.Event)
    (participants : Finset NodeID) (start k index : Nat) (node : NodeID)
    : Nat :=
  ((Finset.Ico start index).filter
    fun earlier =>
      InRound trace participants start k earlier
      /\ TopReset trace participants earlier node).card

/-- Step `index` is a relevant reset of `node` in round `k`: a participant's first
or second reset into the round's term. -/
def RelevantReset (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (start k index : Nat) (node : NodeID)
    : Prop :=
  InRound trace participants start k index
  /\ node ∈ participants
  /\ TopReset trace participants index node
  /\ roundResets trace participants start k index node < 2

/-- The `position`-th other participant's deadline, less the time, before `step`.
The other participants are those other than the step's actor, in increasing order. -/
noncomputable def centre (participants : Finset NodeID) (step : DuelStep) (position : Nat)
    : Real :=
  let node := step.action.actor.getD 0
  match ((participants.erase node).sort (· <= ·))[position]? with
  | some other => deadline step.before other - time step.before
  | none => 0

/-! ## Relevant draws of a run -/

variable (participants : Finset NodeID) (policy : Policy) (start : Nat)

/-- Draw `j` is relevant to round `k`: a relevant reset consumes it. -/
def Relevant (k j : Nat) (sample : Sample) : Prop :=
  exists index node,
    RelevantReset (run participants policy sample) participants start k index node
    /\ drawsBefore (run participants policy sample) participants index = j

open Classical in
/-- The centres of draw `j` in round `k`: the other participants' deadlines, less the
time, before the reset consuming it. -/
noncomputable def centres (k j : Nat) (sample : Sample)
    (position : Fin (participants.card - 1))
    : Real :=
  if found
      : exists index,
      exists node,
        RelevantReset (run participants policy sample) participants start k index node
        /\ drawsBefore (run participants policy sample) participants index = j then
    ((run participants policy sample).stepAt (Nat.find found)).elim 0
      fun step => centre participants step position
  else
    0

/-! ## The `Attempts` fields -/

variable {participants policy start}

theorem relevant_measurable (borel : Borel participants policy) (k j : Nat)
    : MeasurableSet[revealed j]
        {sample | Relevant participants policy start k j sample} := by
  sorry

theorem centres_measurable (borel : Borel participants policy) (k j : Nat)
    (position : Fin (participants.card - 1))
    : Measurable[revealed j]
        fun sample => centres participants policy start k j sample position := by
  sorry

theorem relevant_ordered {k k' j j' : Nat} {sample : Sample} (lt : k < k')
    (relevant : Relevant participants policy start k j sample)
    (relevant' : Relevant participants policy start k' j' sample)
    : j < j' := by
  sorry

theorem relevant_bounded (k : Nat) (sample : Sample)
    : exists draws : Finset Nat,
        draws.card <= 2 * participants.card
        /\ forall j, Relevant participants policy start k j sample -> j ∈ draws := by
  sorry

/-! ## Draws and deadlines -/

/-- A participant reset of the run draws its deadline from the sample. -/
theorem run_deadline {sample : Sample} {index : Nat} {step : DuelStep} {node : NodeID}
    (stepAt : (run participants policy sample).stepAt index = some step)
    (member : node ∈ participants) (reset : ElectionReset step node)
    : deadline step.after node
      = time step.before
        + sample (drawsBefore (run participants policy sample) participants index) := by
  sorry

/-- Each other participant's deadline before a relevant reset is one of the centres
of the draw it consumes. -/
theorem centre_of_relevant {sample : Sample} {k index : Nat} {node other : NodeID}
    {step : DuelStep}
    (relevant
      : RelevantReset (run participants policy sample) participants start k index node)
    (stepAt : (run participants policy sample).stepAt index = some step)
    (otherIn : other ∈ participants) (ne : other ≠ node)
    : exists position,
        centres participants policy start k
          (drawsBefore (run participants policy sample) participants index) sample
          position
        = deadline step.before other - time step.before := by
  sorry

end CCFRaft.Proofs.Duel.Adaptive
