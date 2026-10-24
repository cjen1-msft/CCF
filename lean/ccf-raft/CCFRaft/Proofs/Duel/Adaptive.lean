module

public import CCFRaft.Proofs.Duel.Support
public import Mathlib.Probability.ProductMeasure
public import Mathlib.Probability.Process.Filtration

@[expose] public section

/-!
# Draft: duelling leaders against a non-anticipating adversary

DRAFT FOR REVIEW, NOT IMPORTED BY `Properties`; every proof is `sorry`.

CCF draws a fresh offset at every `restart_election_timeout`. Here a sample is
one offset per participant reset after `start`, in the order the resets happen,
and the adversary chooses the execution up to a reset from the offsets already
drawn (`NonAnticipating`), so it cannot re-roll a draw it has not seen.

(a) `Sample`, `sampleMeasure`, `revealed`, `ResetDraws`, `NonAnticipating`.
(b) `race_commits`: a race whose fresh draws have a margin among its electable
    competitors forces a live signed primary within `roundLength`;
    `races_exist`: without a commit, the good period holds `rounds` races whose
    draw indices are chosen adaptively.
(c) `adaptive_settle`: margins in adaptively chosen fresh blocks of draws have at
    least the settling probability; it uses only (a).
-/

namespace CCFRaft.Proofs.Duel.Adaptive

open CCFRaft.Liveness MeasureTheory Set
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

/-! ## (a) Per-reset draws and the non-anticipating adversary -/

/-- The offset of the `j`-th participant reset after `start`. -/
abbrev Sample := Nat → Real

/-- Independent uniform offsets, one per reset. -/
noncomputable def sampleMeasure (E : Real) : Measure Sample :=
  Measure.infinitePi fun _ => uniform E

/-- The draws revealed by the `j`-th reset: offsets `0` to `j`. -/
noncomputable def revealed
    : Filtration Nat (MeasurableSpace.pi : MeasurableSpace Sample) :=
  Filtration.natural (fun j (sample : Sample) => sample j)
    fun j => (measurable_pi_apply j).stronglyMeasurable

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W]
  [HasNetwork W]

/-- Step `index` resets participant `node` at or after `start`. -/
def ParticipantReset (trace : Trace W Liveness.Event) (start : Nat)
    (participants : Finset NodeID) (reset : Nat ×ₗ NodeID)
    : Prop :=
  start <= (ofLex reset).1
  /\ (ofLex reset).2 ∈ participants
  /\ exists step,
      trace.stepAt (ofLex reset).1 = some step /\ ElectionReset step (ofLex reset).2

/-- `reset` is the `count`-th participant reset after `start`, ordered by index,
then by node within one step. -/
def NthReset (trace : Trace W Liveness.Event) (start : Nat) (participants : Finset NodeID)
    (count : Nat) (reset : Nat ×ₗ NodeID)
    : Prop :=
  ParticipantReset trace start participants reset
  /\ Set.ncard
        {earlier | ParticipantReset trace start participants earlier /\ earlier < reset}
      = count

/-- The `j`-th participant reset after `start` draws offset `sample j`. Replaces
`TimerDraws`: every reset draws, as `restart_election_timeout` does. -/
def ResetDraws (trace : Trace W Liveness.Event) (start : Nat)
    (participants : Finset NodeID) (sample : Sample)
    : Prop :=
  forall j reset step,
    NthReset trace start participants j reset
    -> trace.stepAt (ofLex reset).1 = some step
    -> deadline step.after (ofLex reset).2 = time step.before + sample j

/-- The recording up to the `j`-th reset, and that reset's position, depend only
on the offsets drawn before it. -/
def NonAnticipating (family : Sample → Trace W Liveness.Event) (start : Nat)
    (participants : Finset NodeID)
    : Prop :=
  forall sample other j reset,
    (forall l, l < j → sample l = other l)
    -> NthReset (family sample) start participants j reset
    -> NthReset (family other) start participants j reset
        /\ (family sample).initial = (family other).initial
        /\ (forall l,
              l < (ofLex reset).1 → (family sample).stepAt l = (family other).stepAt l)
        /\ ((family sample).stepAt (ofLex reset).1).map (·.before)
            = ((family other).stepAt (ofLex reset).1).map (·.before)

/-! ## (c) Adaptive blocks of fresh draws -/

/-- Some draw of `block` undercuts every other draw of it by more than `margin`. -/
def BlockMargin (sample : Sample) (block : Finset Nat) (margin : Real) : Prop :=
  exists a, a ∈ block /\ forall b, b ∈ block → b ≠ a → sample a + margin < sample b

/-- `rounds` blocks of at most `competitors` draw indices, each chosen from the
draws before it, each later than the previous. -/
structure AdaptiveBlocks (competitors rounds : Nat) where
  block : Fin rounds → Sample → Finset Nat
  size
    : forall r sample, 0 < (block r sample).card /\ (block r sample).card <= competitors
  ordered
    : forall r r' sample a b, r < r' → a ∈ block r sample → b ∈ block r' sample → a < b
  predictable
    : forall r sample other,
        (forall l, (forall a, a ∈ block r sample → l < a) → sample l = other l)
        -> block r sample = block r other

/-- Margins in adaptively chosen fresh blocks: the conditional probability of a
margin in each block, given everything before it, is at least
`marginProbability`, so all `rounds` fail with probability at most
`(1 - marginProbability) ^ rounds`. -/
theorem adaptive_settle {competitors rounds : Nat} {margin E : Real}
    (hn : 0 < competitors) (hm : 0 <= margin) (hmE : margin < E / 2)
    (blocks : AdaptiveBlocks competitors rounds)
    : ENNReal.ofReal (settleProbability competitors rounds margin E)
      <= sampleMeasure E
          {sample | exists r, BlockMargin sample (blocks.block r sample) margin} := by
  sorry

/-! ## (b) The deterministic race -/

/-- A participant's log is up to date for a quorum of participants: its
`voteLogUpToDate` request would pass at each of them, so it can win pre-votes and
votes. -/
def Electable (point : W) (participants : Finset NodeID) (node : NodeID) : Prop :=
  exists state,
    CCF.MultiNodeTransitionSystem.nodeState (proto point) node = some state
    /\ hasQuorum state.activeConfigurations
        {voter ∈ participants |
          exists voterState,
            CCF.MultiNodeTransitionSystem.nodeState (proto point) voter = some voterState
            /\ Model.Node.voteLogUpToDate voterState
                (Model.Node.makeRequestVoteRequest state)
        }

/-- At `point`, `leader` is a live primary with a committed signature of its term:
`SignedPrimary` plus liveness. -/
def LiveSignedPrimary (point : W) (leader : NodeID) (term : Nat) : Prop :=
  leader ∈ live point /\ SignedPrimary point leader term

/-- A race from index `first`: the electable participants at `first` each reset
once, in `block`, within `maxDelay` of `first`, with no participant packet left
from before `first`. Those resets' offsets decide who times out first. -/
structure Race (trace : Trace W Liveness.Event) (start : Nat)
    (participants : Finset NodeID) (maxDelay : Real) (first : Nat) (block : Finset Nat)
    : Prop where
  bound
    : forall point,
        trace.stateAt first = some point
        → block.card
          = Set.ncard {node | node ∈ participants /\ Electable point participants node}
  fresh
    : forall j,
        j ∈ block
        → exists reset point later,
            NthReset trace start participants j reset
            /\ trace.stateAt first = some point
            /\ trace.stateAt (ofLex reset).1 = some later
            /\ first <= (ofLex reset).1
            /\ time later <= time point + maxDelay
            /\ Electable point participants (ofLex reset).2
  quiet
    : forall point packet,
        trace.stateAt first = some point
        -> packet ∈ HasNetwork.pending point
        -> packet.envelope.target ∈ participants
        -> False

/-- The admissible premises of `duelling_leaders_resolve` for one recording. -/
def Admissible (system : CCF.TransitionSystem Model.State Model.Action) (bounds : Bounds)
    (maxDelay : Real) (start : Nat) (duration : Real) (participants : Finset NodeID)
    (trace : Trace W Liveness.Event)
    : Prop :=
  trace.Coherent
  /\ trace.Valid (protocolModel system)
  /\ trace.Valid timingModel
  /\ trace.Valid crashModel
  /\ trace.Valid (deliveryModel system)
  /\ trace.Valid (boundedDelayModel maxDelay)
  /\ trace.Valid (timerModel bounds.electionTimeout)
  /\ TimeDiverges trace
  /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
  /\ trace.SignatureScheduling (some bounds.signatureInterval)
  /\ trace.TimeoutScheduling (some 0)
  /\ GoodPeriod trace start duration participants

/-- (b) A race with a margin among its fresh draws ends the duel within
`roundLength`: the winner's pre-vote, vote and first AppendEntries land before
any rival times out, then it signs and replicates the signature. -/
theorem race_commits {config : Finset NodeID} {nodes : List NodeID} {bounds : Bounds}
    {maxDelay duration : Real} {start first : Nat} {participants : Finset NodeID}
    {trace : Trace W Liveness.Event} {sample : Sample} {block : Finset Nat}
    (admissible
      : Admissible (Model.transitionSystem config nodes) bounds maxDelay start duration
          participants trace)
    (draws : ResetDraws trace start participants sample)
    (race : Race trace start participants maxDelay first block)
    (margin : BlockMargin sample block (duelMargin bounds maxDelay))
    : exists index point leader term,
        Within trace first (roundLength bounds maxDelay) index
        /\ trace.stateAt index = some point
        /\ LiveSignedPrimary point leader term := by
  sorry

/-- (b) Until the duel ends, each `roundLength` of the good period starts a race,
and a non-anticipating adversary's races form adaptive blocks. The main open
risk: resets must line up into races across participants. -/
theorem races_exist {config : Finset NodeID} {nodes : List NodeID} {bounds : Bounds}
    {maxDelay : Real} {start rounds : Nat} {participants : Finset NodeID}
    {family : Sample → Trace W Liveness.Event}
    (admissible
      : forall sample,
          Admissible (Model.transitionSystem config nodes) bounds maxDelay start
            (rounds * roundLength bounds maxDelay) participants (family sample)
          /\ ResetDraws (family sample) start participants sample)
    (nonAnticipating : NonAnticipating family start participants)
    : exists blocks : AdaptiveBlocks participants.card rounds,
        forall sample r,
          (exists first,
            Race (family sample) start participants maxDelay first (blocks.block r sample)
            /\ forall point,
                (family sample).stateAt first = some point
                → exists origin,
                    (family sample).stateAt start = some origin
                    /\ time point + roundLength bounds maxDelay
                        <= time origin + rounds * roundLength bounds maxDelay)
          \/ exists index point leader term,
              Within (family sample) start (rounds * roundLength bounds maxDelay) index
              /\ (family sample).stateAt index = some point
              /\ LiveSignedPrimary point leader term := by
  sorry

end CCFRaft.Proofs.Duel.Adaptive
