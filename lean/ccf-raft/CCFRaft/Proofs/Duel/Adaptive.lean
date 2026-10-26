module

public import CCFRaft.Proofs.Duel.Support
public import CCFRaft.Liveness.Model.WitnessWorld
public import Mathlib.Probability.ProductMeasure

@[expose] public section

/-!
# Duelling leaders against a scheduling policy

NOT IMPORTED BY `Properties`. The policy model of the duel; the statement is in
`Duel.Resolve`.

CCF's `restart_election_timeout` (`raft.h`) draws a fresh uniform offset at every
reset. Here a sample is one offset per participant reset, consumed in trace order
from index 0. CCF's `start_ticking` sets a full election timeout without a draw at
node start; that is out of scope, so the initial deadlines are the policy's. It also
matters mid-run: a node joining a configuration starts ticking in
`execute_append_entries_sync` (`raft.h`), after the draw in `recv_append_entries`,
so CCF gives it exactly `E` where the model draws.

A `Policy` chooses the next event and every other nondeterministic part of the next
world from the recorded prefix; `run` builds the recording, overwriting the deadline
of each participant reset with `time + sample j`. The policy sees earlier draws
only through the deadlines in the prefix, so the `j`-th draw is independent of the
prefix before the `j`-th reset by construction; no non-anticipation premise.

`Borel` is the standard measurable-scheduler assumption. It is a premise, not a
lemma: an arbitrary policy may branch on a non-measurable set of past deadlines,
and then neither the event nor any bound on its measure is meaningful. Any
policy that decides by Borel tests on the reals it sees satisfies it.
-/

namespace CCFRaft.Proofs.Duel.Adaptive

open CCFRaft.Liveness MeasureTheory Set
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)

/-! ## Samples -/

/-- The offset drawn by the `j`-th participant reset. -/
abbrev Sample := Nat -> Real

/-- Independent uniform offsets, one per reset. -/
noncomputable def sampleMeasure (E : Real) : Measure Sample :=
  Measure.infinitePi fun _ => uniform E

/-! ## The concrete world and the policy -/

/-- `World` with each node's pending election deadline. -/
structure DuelWorld extends World Model.State where
  deadlines : NodeID -> Real

instance : HasProtocol DuelWorld Model.State where
  proto world := world.proto

instance : HasTime DuelWorld where
  time world := world.time

instance : HasLive DuelWorld where
  live world := world.live

instance : HasNetwork DuelWorld where
  pending world := world.pending
  issued world := world.issued

instance : HasTimers DuelWorld where
  deadline world := world.deadlines

/-- A recorded step of the duel. -/
abbrev DuelStep := CCF.Execution.Step DuelWorld Liveness.Event

/-- A scheduler: the initial world, and from the steps so far and the current world
the next event and proposed next world (or `none` to stop). It never sees the
sample, only the deadlines earlier draws produced. -/
structure Policy where
  initial : DuelWorld
  next : List DuelStep -> DuelWorld -> Option (Liveness.Event × DuelWorld)

open Classical in
/-- The number of participant resets among `history`: the next draw's index. -/
noncomputable def drawIndex (participants : Finset NodeID) (history : List DuelStep)
    : Nat :=
  history.countP
    fun step => decide (exists node, node ∈ participants /\ ElectionReset step node)

open Classical in
/-- The proposed step, with each participant reset drawing the next offset. A step
resets at most its actor, and the deadline does not affect `ElectionReset`. -/
noncomputable def stamp (participants : Finset NodeID) (sample : Sample)
    (history : List DuelStep) (before : DuelWorld) (event : Liveness.Event)
    (proposed : DuelWorld)
    : DuelStep :=
  let raw : DuelStep := { before, action := event, after := proposed }
  {
    raw with
      after :=
        {
          proposed with
            deadlines :=
              fun node =>
                if node ∈ participants /\ ElectionReset raw node then
                  before.time + sample (drawIndex participants history)
                else
                  proposed.deadlines node
        }
  }

/-- The recording `policy` produces against `sample`. -/
noncomputable def run (participants : Finset NodeID) (policy : Policy) (sample : Sample)
    : Trace DuelWorld Liveness.Event where
  initial := policy.initial
  steps :=
    Stream'.Seq.corec
      (fun (state : List DuelStep × DuelWorld) =>
        (policy.next state.1 state.2).map
          fun choice =>
            let step := stamp participants sample state.1 state.2 choice.1 choice.2
            (step, (state.1 ++ [step], step.after)))
      ([], policy.initial)

/-! ## Measurability -/

/-- A step with every real-valued field zeroed: its discrete skeleton. -/
def blank (step : Option DuelStep) : Option DuelStep :=
  let clear (world : DuelWorld) : DuelWorld :=
    {
      world with
        time := 0
        deadlines := fun _ => 0
        pending := world.pending.map fun packet => { packet with sentAt := 0 }
    }
  step.map
    fun step =>
      {
        before := clear step.before
        action :=
          match step.action with
          | .deliver packet => .deliver { packet with sentAt := 0 }
          | .drop packet => .drop { packet with sentAt := 0 }
          | other => other
        after := clear step.after
      }

/-- The real-valued fields of a step, by code `Nat.pair tag position`. -/
def reals (step : Option DuelStep) : Nat -> Real :=
  fun code =>
    match step with
    | none => 0
    | some step =>
        let sentAt (packets : List Packet) (position : Nat) :=
          (packets[position]?.map (·.sentAt)).getD 0
        match code.unpair with
        | (0, _) => step.before.time
        | (1, _) => step.after.time
        | (2, node) => step.before.deadlines node
        | (3, node) => step.after.deadlines node
        | (4, position) => sentAt step.before.pending position
        | (5, position) => sentAt step.after.pending position
        | (6, _) => (step.action.consumedPacket.map (·.sentAt)).getD 0
        | _ => 0

set_option warn.classDefReducibility false in
/-- Discrete on the skeleton, Borel on the real fields. -/
def stepSpace : MeasurableSpace (Option DuelStep) :=
  MeasurableSpace.comap blank ⊤ ⊔ MeasurableSpace.comap reals MeasurableSpace.pi

/-- The standard measurable-scheduler assumption: the recorded steps depend
measurably on the sample. Any policy that decides by Borel tests on the reals it
sees satisfies it. Needed: otherwise the policy can branch on a non-measurable set
of past deadlines, and then neither the event nor a bound on its measure means
anything. -/
def Borel (participants : Finset NodeID) (policy : Policy) : Prop :=
  forall index,
    Measurable[MeasurableSpace.pi, stepSpace]
      fun sample => (run participants policy sample).stepAt index

end CCFRaft.Proofs.Duel.Adaptive
