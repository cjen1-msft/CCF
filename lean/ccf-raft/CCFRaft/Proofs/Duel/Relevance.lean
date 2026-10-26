module

public import CCFRaft.Proofs.Duel.Adaptive
public import CCFRaft.Proofs.Duel.Attempts
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

/-!
# Relevant draws of a policy run

NOT IMPORTED BY `Properties`. The draws of `Liveness.run` that `Attempts` counts.

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

/-! ## Unfolding the run -/

/-- The corecursion state after `n` steps, if the corecursion has not stopped. -/
private def iterState {A B : Type} (f : B -> Option (A × B)) (b : B) : Nat -> Option B
  | 0 => some b
  | n + 1 => (iterState f b n).bind fun state => (f state).map Prod.snd

private theorem iterState_succ' {A B : Type} (f : B -> Option (A × B)) (n : Nat) (b : B)
    : iterState f b (n + 1) = (f b).bind fun pair => iterState f pair.2 n := by
  induction n generalizing b with
  | zero => rcases h : f b <;> simp [iterState, h]
  | succ n ih =>
      rw [iterState, ih]
      cases f b with
      | none => rfl
      | some pair => rfl

private theorem get?_corec {A B : Type} (f : B -> Option (A × B)) (b : B) (n : Nat)
    : (Stream'.Seq.corec f b).get? n
      = (iterState f b n).bind fun state => (f state).map Prod.fst := by
  induction n generalizing b with
  | zero =>
      rcases h : f b with _ | ⟨x, s⟩
      · simp [Stream'.Seq.corec_nil f b h, iterState, h]
      · simp [Stream'.Seq.corec_cons h, iterState, h]
  | succ n ih =>
      rw [iterState_succ']
      rcases h : f b with _ | ⟨x, s⟩
      · simp [Stream'.Seq.corec_nil f b h]
      · simp [Stream'.Seq.corec_cons h, ih]

/-- One step of the run's corecursion. -/
private noncomputable def advance (participants : Finset NodeID) (policy : Policy)
    (sample : Sample) (state : List DuelStep × DuelWorld)
    : Option (DuelStep × (List DuelStep × DuelWorld)) :=
  (policy.next state.1 state.2).map
    fun choice =>
      let step := stamp participants sample state.1 state.2 choice.1 choice.2
      (step, (state.1 ++ [step], step.after))

/-- The recorded prefix and current world after `n` steps of the run. -/
private noncomputable def history (participants : Finset NodeID) (policy : Policy)
    (sample : Sample) (n : Nat)
    : Option (List DuelStep × DuelWorld) :=
  iterState (advance participants policy sample) ([], policy.initial) n

private theorem stepAt_run (participants : Finset NodeID) (policy : Policy)
    (sample : Sample) (n : Nat)
    : (run participants policy sample).stepAt n
      = (history participants policy sample n).bind
          fun state =>
            (policy.next state.1 state.2).map
              fun choice =>
                stamp participants sample state.1 state.2 choice.1 choice.2 := by
  have steps
      : (run participants policy sample).steps
        = Stream'.Seq.corec (advance participants policy sample) ([], policy.initial) :=
    rfl
  rw [Trace.stepAt, steps, get?_corec]
  simp only [history, advance, Option.map_map, Function.comp_def]

private theorem history_succ (participants : Finset NodeID) (policy : Policy)
    (sample : Sample) (n : Nat)
    : history participants policy sample (n + 1)
      = (history participants policy sample n).bind
          fun state =>
            (policy.next state.1 state.2).map
              fun choice =>
                let step := stamp participants sample state.1 state.2 choice.1 choice.2
                (state.1 ++ [step], step.after) := by
  simp only [history, iterState, advance]
  rcases iterState _ _ n with _ | state <;> simp [Option.map_map, Function.comp_def]

open Classical in
private theorem drawsBefore_succ (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) (n : Nat)
    : drawsBefore trace participants (n + 1)
      = drawsBefore trace participants n
        + if exists step node,
              trace.stepAt n = some step
              /\ node ∈ participants
              /\ ElectionReset step node then
            1
          else
            0 := by
  simp only [drawsBefore, Finset.range_add_one, Finset.filter_insert]
  split_ifs with reset
  · rw [Finset.card_insert_of_notMem (by simp)]
  · rfl

open Classical in
private theorem drawsBefore_mono (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) {m n : Nat} (le : m <= n)
    : drawsBefore trace participants m <= drawsBefore trace participants n := by
  unfold drawsBefore
  exact Finset.card_le_card (Finset.filter_subset_filter _ (Finset.range_subset_range.mpr le))

private theorem stepAt_run_eq {participants : Finset NodeID} {policy : Policy}
    {sample : Sample} {n : Nat} {step : DuelStep}
    (stepAt : (run participants policy sample).stepAt n = some step)
    : exists state choice,
        history participants policy sample n = some state
        /\ policy.next state.1 state.2 = some choice
        /\ step = stamp participants sample state.1 state.2 choice.1 choice.2 := by
  rw [stepAt_run] at stepAt
  simp only [Option.bind_eq_some_iff, Option.map_eq_some_iff] at stepAt
  obtain ⟨state, found, choice, next, rfl⟩ := stepAt
  exact ⟨state, choice, found, next, rfl⟩

private theorem drawIndex_history {participants : Finset NodeID} {policy : Policy}
    {sample : Sample} {n : Nat} {state : List DuelStep × DuelWorld}
    (found : history participants policy sample n = some state)
    : drawIndex participants state.1
      = drawsBefore (run participants policy sample) participants n := by
  induction n generalizing state with
  | zero =>
      simp only [history, iterState, Option.some.injEq] at found
      subst found
      simp [drawIndex, drawsBefore]
  | succ n ih =>
      rw [history_succ] at found
      simp only [Option.bind_eq_some_iff, Option.map_eq_some_iff] at found
      obtain ⟨previous, previousFound, choice, next, rfl⟩ := found
      have stepAt : (run participants policy sample).stepAt n
          = some (stamp participants sample previous.1 previous.2 choice.1 choice.2) := by
        rw [stepAt_run, previousFound]
        simp [next]
      rw [drawsBefore_succ, stepAt, <- ih previousFound]
      simp only [drawIndex, List.countP_append, List.countP_singleton]
      split_ifs <;> simp_all
      grind

/-! ## Skeleton predicates -/

/-- The skeleton of a recorded step, as `blank` computes it. -/
private def blankStep (step : DuelStep) : DuelStep :=
  ((blank (some step)).getD step)

private theorem blank_some (step : DuelStep)
    : blank (some step) = some (blankStep step) :=
  rfl

/-- A predicate of a step option that holds of some step. -/
private def AtomE (R : DuelStep -> Prop) (x : Option DuelStep) : Prop :=
  exists step, x = some step /\ R step

/-- A predicate of a step option that holds of every step. -/
private def AtomA (R : DuelStep -> Prop) (x : Option DuelStep) : Prop :=
  forall step, x = some step -> R step

/-- `R` reads only the skeleton of a step. -/
private def Skeletal (R : DuelStep -> Prop) : Prop :=
  forall step, R (blankStep step) <-> R step

private theorem atomE_blank {R : DuelStep -> Prop} (skeletal : Skeletal R)
    (x : Option DuelStep)
    : AtomE R (blank x) <-> AtomE R x := by
  cases x with
  | none => exact Iff.rfl
  | some step => simp [AtomE, blank_some, skeletal step]

private theorem atomA_blank {R : DuelStep -> Prop} (skeletal : Skeletal R)
    (x : Option DuelStep)
    : AtomA R (blank x) <-> AtomA R x := by
  cases x with
  | none => exact Iff.rfl
  | some step => simp [AtomA, blank_some, skeletal step]

private theorem atomE_congr {R : DuelStep -> Prop} (skeletal : Skeletal R)
    {x y : Option DuelStep} (same : blank x = blank y)
    : AtomE R x <-> AtomE R y := by
  rw [<- atomE_blank skeletal x, same, atomE_blank skeletal y]

private theorem atomA_congr {R : DuelStep -> Prop} (skeletal : Skeletal R)
    {x y : Option DuelStep} (same : blank x = blank y)
    : AtomA R x <-> AtomA R y := by
  rw [<- atomA_blank skeletal x, same, atomA_blank skeletal y]

private theorem electionReset_blankStep (step : DuelStep) (node : NodeID)
    : ElectionReset (blankStep step) node <-> ElectionReset step node := by
  obtain ⟨before, action, after⟩ := step
  cases action <;> exact Iff.rfl

private theorem actor_blankStep (step : DuelStep)
    : (blankStep step).action.actor = step.action.actor := by
  obtain ⟨before, action, after⟩ := step
  cases action <;> rfl

/-- The step lifts the highest participant term. -/
private def raisesStep (participants : Finset NodeID) (step : DuelStep) : Prop :=
  maxTerm participants step.before < maxTerm participants step.after

/-- The step resets a participant. -/
private def resetStep (participants : Finset NodeID) (step : DuelStep) : Prop :=
  exists node, node ∈ participants /\ ElectionReset step node

/-- The step resets `node` into the highest participant term. -/
private def topStep (participants : Finset NodeID) (node : NodeID) (step : DuelStep)
    : Prop :=
  ElectionReset step node
  /\ exists state : NodeState,
      nodeState (proto step.after) node = some state
      /\ state.currentTerm = maxTerm participants step.after

/-- No participant is past `term` in `point`, nor any packet between participants. -/
private def lowWorld (participants : Finset NodeID) (term : Nat) (point : DuelWorld)
    : Prop :=
  (forall node state,
    node ∈ participants
    -> nodeState (proto point) node = some state
    -> state.currentTerm <= term)
  /\ forall packet,
      packet ∈ HasNetwork.pending point
      -> packet.envelope.source ∈ participants
      -> packet.envelope.target ∈ participants
      -> packet.envelope.payload.term <= term

/-- The step moves a participant past `term`. -/
private def raiseStep (participants : Finset NodeID) (term : Nat) (step : DuelStep)
    : Prop :=
  exists node state,
    node ∈ participants
    /\ nodeState (proto step.after) node = some state
    /\ term < (state : NodeState).currentTerm

private theorem raisesStep_skeletal (participants : Finset NodeID)
    : Skeletal (raisesStep participants) :=
  fun _ => Iff.rfl

private theorem resetStep_skeletal (participants : Finset NodeID)
    : Skeletal (resetStep participants) := by
  intro step
  simp only [resetStep, electionReset_blankStep]

private theorem topStep_skeletal (participants : Finset NodeID) (node : NodeID)
    : Skeletal (topStep participants node) := by
  intro step
  simp only [topStep, electionReset_blankStep]
  exact Iff.rfl

private theorem lowAfter_skeletal (participants : Finset NodeID) (term : Nat)
    : Skeletal fun step => lowWorld participants term step.after := by
  intro step
  refine and_congr Iff.rfl ?_
  show (forall packet, packet ∈ step.after.pending.map _ -> _) <-> _
  simp only [List.mem_map, forall_exists_index, and_imp, forall_apply_eq_imp_iff₂]
  exact Iff.rfl

private theorem raiseStep_skeletal (participants : Finset NodeID) (term : Nat)
    : Skeletal (raiseStep participants term) :=
  fun _ => Iff.rfl

private theorem raises_iff (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) (index : Nat)
    : Raises trace participants index
      <-> AtomE (raisesStep participants) (trace.stepAt index) :=
  Iff.rfl

private theorem reset_iff (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) (index : Nat)
    : (exists step node,
        trace.stepAt index = some step /\ node ∈ participants /\ ElectionReset step node)
      <-> AtomE (resetStep participants) (trace.stepAt index) := by
  simp only [AtomE, resetStep]
  grind

private theorem topReset_iff (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) (index : Nat) (node : NodeID)
    : TopReset trace participants index node
      <-> AtomE (topStep participants node) (trace.stepAt index) := by
  simp only [TopReset, AtomE, topStep]
  grind

private theorem roundStart_iff (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) (c term : Nat)
    : RoundStart trace participants c term
      <-> (forall point, trace.stateAt c = some point -> lowWorld participants term point)
          /\ AtomE (raiseStep participants term) (trace.stepAt c) := by
  constructor
  · rintro ⟨low, messages, raise⟩
    refine ⟨fun point found => ⟨fun node state member current => ?_, ?_⟩, ?_⟩
    · exact low point node state found member current
    · exact fun packet => messages point packet found
    · obtain ⟨step, node, state, found, member, current, lt⟩ := raise
      exact ⟨step, found, node, state, member, current, lt⟩
  · rintro ⟨low, step, found, node, state, member, current, lt⟩
    exact ⟨fun point node state found' member current =>
        (low point found').1 node state member current,
      fun point packet found' => (low point found').2 packet,
      ⟨step, node, state, found, member, current, lt⟩⟩

private theorem stateAt_low_iff (trace : Trace DuelWorld Liveness.Event)
    (participants : Finset NodeID) (n term : Nat)
    : (forall point,
        trace.stateAt (n + 1) = some point -> lowWorld participants term point)
      <-> AtomA (fun step => lowWorld participants term step.after) (trace.stepAt n) := by
  simp only [Trace.stateAt, AtomA, Option.map_eq_some_iff]
  grind

/-! ## Agreement of traces up to an index -/

/-- Two traces with the same initial world and the same skeletons before `n`. -/
private def Agree (trace trace' : Trace DuelWorld Liveness.Event) (n : Nat) : Prop :=
  trace.initial = trace'.initial
  /\ forall index, index < n -> blank (trace.stepAt index) = blank (trace'.stepAt index)

private theorem Agree.mono {trace trace' : Trace DuelWorld Liveness.Event} {m n : Nat}
    (agree : Agree trace trace' n) (le : m <= n)
    : Agree trace trace' m :=
  ⟨agree.1, fun index lt => agree.2 index (by omega)⟩

section AgreeLemmas

open Classical

variable {trace trace' : Trace DuelWorld Liveness.Event} {participants : Finset NodeID}

private theorem raises_agree {index : Nat} (agree : Agree trace trace' (index + 1))
    : Raises trace participants index <-> Raises trace' participants index := by
  rw [raises_iff, raises_iff]
  exact atomE_congr (raisesStep_skeletal participants) (agree.2 index (by omega))

private theorem roundStart_agree {c term : Nat} (agree : Agree trace trace' (c + 1))
    : RoundStart trace participants c term <-> RoundStart trace' participants c term := by
  rw [roundStart_iff, roundStart_iff]
  refine and_congr ?_
    (atomE_congr (raiseStep_skeletal participants term) (agree.2 c (by omega)))
  cases c with
  | zero => simp only [Trace.stateAt, agree.1]
  | succ n =>
      rw [stateAt_low_iff, stateAt_low_iff]
      exact atomA_congr (lowAfter_skeletal participants term) (agree.2 n (by omega))

private theorem firstRound_agree {start first : Nat}
    (agree : Agree trace trace' (first + 1))
    : FirstRound trace participants start first
      <-> FirstRound trace' participants start first := by
  unfold FirstRound
  refine and_congr Iff.rfl
    (and_congr (exists_congr fun _ => roundStart_agree agree) ?_)
  exact forall_congr'
    fun index =>
      imp_congr_right
        fun _ =>
          imp_congr_right
            fun lt =>
              not_congr (exists_congr fun _ => roundStart_agree (agree.mono (by omega)))

private theorem inRound_agree {start k index : Nat}
    (agree : Agree trace trace' (index + 1))
    : InRound trace participants start k index
      <-> InRound trace' participants start k index := by
  have key
      : forall first,
          first <= index
          -> (FirstRound trace participants start first
                <-> FirstRound trace' participants start first)
            /\ ((Finset.Icc first index).filter (Raises trace participants)).card
              = ((Finset.Icc first index).filter (Raises trace' participants)).card := by
    intro first le
    refine ⟨firstRound_agree (agree.mono (by omega)), ?_⟩
    congr 1
    exact Finset.filter_congr fun earlier member =>
      raises_agree (agree.mono (by simp at member; omega))
  unfold InRound
  refine exists_congr fun first => ?_
  constructor
  · rintro ⟨found, le, card⟩
    exact ⟨(key first le).1.mp found, le, (key first le).2 ▸ card⟩
  · rintro ⟨found, le, card⟩
    exact ⟨(key first le).1.mpr found, le, (key first le).2.symm ▸ card⟩

private theorem topReset_agree {index : Nat} {node : NodeID}
    (agree : Agree trace trace' (index + 1))
    : TopReset trace participants index node
      <-> TopReset trace' participants index node := by
  rw [topReset_iff, topReset_iff]
  exact atomE_congr (topStep_skeletal participants node) (agree.2 index (by omega))

private theorem drawsBefore_agree {n : Nat} (agree : Agree trace trace' n)
    : drawsBefore trace participants n = drawsBefore trace' participants n := by
  unfold drawsBefore
  congr 1
  refine Finset.filter_congr fun earlier member => ?_
  rw [reset_iff, reset_iff]
  exact atomE_congr (resetStep_skeletal participants)
    (agree.2 earlier (by simpa using member))

private theorem roundResets_agree {start k index : Nat} {node : NodeID}
    (agree : Agree trace trace' index)
    : roundResets trace participants start k index node
      = roundResets trace' participants start k index node := by
  unfold roundResets
  congr 1
  refine Finset.filter_congr fun earlier member => ?_
  have lt : earlier < index := by simp at member; omega
  exact and_congr (inRound_agree (agree.mono lt)) (topReset_agree (agree.mono lt))

private theorem relevantReset_agree {start k index : Nat} {node : NodeID}
    (agree : Agree trace trace' (index + 1))
    : RelevantReset trace participants start k index node
      <-> RelevantReset trace' participants start k index node := by
  unfold RelevantReset
  rw [inRound_agree agree, topReset_agree agree, roundResets_agree (agree.mono (by omega))]

end AgreeLemmas

/-! ## Runs on samples that agree before a draw -/

open Classical in
private theorem stamp_congr {participants : Finset NodeID} {sample sample' : Sample}
    {history : List DuelStep} {before : DuelWorld} {event : Liveness.Event}
    {proposed : DuelWorld}
    (same
      : (exists node,
          node ∈ participants
          /\ ElectionReset (stamp participants sample history before event proposed) node)
        -> sample (drawIndex participants history)
            = sample' (drawIndex participants history))
    : stamp participants sample history before event proposed
      = stamp participants sample' history before event proposed := by
  by_cases reset
      : exists node,
          node ∈ participants
          /\ ElectionReset (stamp participants sample history before event proposed) node
  · simp only [stamp, same reset]
  · have none
        : forall node,
            Not (node ∈ participants
              /\ ElectionReset
                ({ before, action := event, after := proposed } : DuelStep) node) :=
      fun node member => reset ⟨node, member⟩
    simp only [stamp, none, ite_false]

private theorem history_agree {participants : Finset NodeID} {policy : Policy}
    {sample sample' : Sample} {j : Nat} (agree : forall i, i < j -> sample i = sample' i)
    (n : Nat) (le : drawsBefore (run participants policy sample) participants n <= j)
    : history participants policy sample n = history participants policy sample' n := by
  induction n with
  | zero => rfl
  | succ n ih =>
      have le' := (drawsBefore_mono _ participants (Nat.le_succ n)).trans le
      rw [history_succ, history_succ, <- ih le']
      rcases found : history participants policy sample n with _ | state
      · rfl
      · simp only [Option.bind_some]
        rcases next : policy.next state.1 state.2 with _ | choice
        · rfl
        · simp only [Option.map_some]
          rw [stamp_congr]
          intro reset
          apply agree
          have stepAt : (run participants policy sample).stepAt n
              = some (stamp participants sample state.1 state.2 choice.1 choice.2) := by
            rw [stepAt_run, found]
            simp [next]
          rw [drawsBefore_succ, stepAt] at le
          split_ifs at le with counted
          · rw [drawIndex_history found]
            omega
          · obtain ⟨node, member, electionReset⟩ := reset
            exact absurd ⟨_, node, rfl, member, electionReset⟩ counted

/-- The parts of a step that do not depend on the draw it consumes. -/
private def strip (step : DuelStep) : DuelWorld × Liveness.Event × World Model.State :=
  (step.before, step.action, step.after.toWorld)

private theorem run_strip {participants : Finset NodeID} {policy : Policy}
    {sample sample' : Sample} {j : Nat} (agree : forall i, i < j -> sample i = sample' i)
    {n : Nat} (le : drawsBefore (run participants policy sample) participants n <= j)
    : ((run participants policy sample).stepAt n).map strip
      = ((run participants policy sample').stepAt n).map strip := by
  rw [stepAt_run, stepAt_run, <- history_agree agree n le]
  rcases history participants policy sample n with _ | state
  · rfl
  · simp only [Option.bind_some]
    rcases policy.next state.1 state.2 with _ | choice
    · rfl
    · rfl

private theorem blank_of_strip {x y : Option DuelStep} (same : x.map strip = y.map strip)
    : blank x = blank y := by
  rcases x with _ | ⟨before, action, ⟨world, deadlines⟩⟩ <;>
    rcases y with _ | ⟨before', action', ⟨world', deadlines'⟩⟩ <;>
    simp [strip] at same
  · rfl
  · obtain ⟨rfl, rfl, rfl⟩ := same
    rfl

private theorem run_agree {participants : Finset NodeID} {policy : Policy}
    {sample sample' : Sample} {j : Nat} (agree : forall i, i < j -> sample i = sample' i)
    {n : Nat} (le : drawsBefore (run participants policy sample) participants n <= j)
    : Agree (run participants policy sample) (run participants policy sample') (n + 1) :=
  ⟨
    rfl,
    fun _ lt =>
      blank_of_strip
        (run_strip agree ((drawsBefore_mono _ participants (by omega)).trans le))
  ⟩

private theorem relevantAt_agree {participants : Finset NodeID} {policy : Policy}
    {start k j index : Nat} {sample sample' : Sample}
    (agree : forall i, i < j -> sample i = sample' i)
    (relevant
      : exists node,
          RelevantReset (run participants policy sample) participants start k index node
          /\ drawsBefore (run participants policy sample) participants index = j)
    : exists node,
        RelevantReset (run participants policy sample') participants start k index node
        /\ drawsBefore (run participants policy sample') participants index = j := by
  obtain ⟨node, relevantReset, rfl⟩ := relevant
  have same := run_agree agree (le_refl _)
  exact ⟨
    node,
    (relevantReset_agree same).mp relevantReset,
    (drawsBefore_agree (same.mono (by omega))).symm
  ⟩

private theorem relevant_agree {participants : Finset NodeID} {policy : Policy}
    {start k j : Nat} {sample sample' : Sample}
    (agree : forall i, i < j -> sample i = sample' i)
    (relevant : Relevant participants policy start k j sample)
    : Relevant participants policy start k j sample' := by
  obtain ⟨index, relevant⟩ := relevant
  exact ⟨index, relevantAt_agree agree relevant⟩

private theorem centre_congr {participants : Finset NodeID} {position : Nat}
    {x y : Option DuelStep} (same : x.map strip = y.map strip)
    : x.elim 0 (fun step => centre participants step position)
      = y.elim 0 (fun step => centre participants step position) := by
  rcases x with _ | ⟨before, action, ⟨world, deadlines⟩⟩ <;>
    rcases y with _ | ⟨before', action', ⟨world', deadlines'⟩⟩ <;>
    simp [strip] at same
  · rfl
  · obtain ⟨rfl, rfl, rfl⟩ := same
    rfl

open Classical in
private theorem centres_agree {participants : Finset NodeID} {policy : Policy}
    {start k j : Nat} {sample sample' : Sample}
    (agree : forall i, i < j -> sample i = sample' i)
    (position : Fin (participants.card - 1))
    : centres participants policy start k j sample position
      = centres participants policy start k j sample' position := by
  have iff
      : forall index,
          (exists node,
            RelevantReset (run participants policy sample) participants start k index node
            /\ drawsBefore (run participants policy sample) participants index = j)
          <-> exists node,
            RelevantReset (run participants policy sample') participants start k index node
            /\ drawsBefore (run participants policy sample') participants index = j :=
    fun _ => ⟨relevantAt_agree agree, relevantAt_agree fun i lt => (agree i lt).symm⟩
  unfold centres
  by_cases found
      : exists index node,
          RelevantReset (run participants policy sample) participants start k index node
          /\ drawsBefore (run participants policy sample) participants index = j
  · have found' := (exists_congr iff).mp found
    rw [dite_eq_left found, dite_eq_left found']
    have find : Nat.find found = Nat.find found' :=
      le_antisymm (Nat.find_min' found ((iff _).mpr (Nat.find_spec found')))
        (Nat.find_min' found' ((iff _).mp (Nat.find_spec found)))
    obtain ⟨node, _, draws⟩ := Nat.find_spec found
    have same := run_strip (policy := policy) agree (le_of_eq draws)
    rw [<- find]
    exact centre_congr same
  · have found' := fun h => found ((exists_congr iff).mpr h)
    rw [dite_eq_right found, dite_eq_right found']

/-! ## Measurability in the sample -/

section Measurability

open Classical

variable {participants : Finset NodeID} {policy : Policy}

private theorem blank_measurable : Measurable[stepSpace, ⊤] blank :=
  Measurable.of_comap_le le_sup_left

private theorem reals_measurable (code : Nat)
    : Measurable[stepSpace] fun step => reals step code :=
  have reals : Measurable[stepSpace, MeasurableSpace.pi] reals :=
    Measurable.of_comap_le le_sup_right
  (measurable_pi_apply code).comp reals

private theorem atomE_stepSpace {R : DuelStep -> Prop} (skeletal : Skeletal R)
    : Measurable[stepSpace] (AtomE R) := by
  have top : Measurable[⊤] (AtomE R) := fun _ _ => MeasurableSpace.measurableSet_top
  have eq : AtomE R = AtomE R ∘ blank := funext fun x => propext (atomE_blank skeletal x).symm
  rw [eq]
  exact top.comp blank_measurable

private theorem atomA_stepSpace {R : DuelStep -> Prop} (skeletal : Skeletal R)
    : Measurable[stepSpace] (AtomA R) := by
  have top : Measurable[⊤] (AtomA R) := fun _ _ => MeasurableSpace.measurableSet_top
  have eq : AtomA R = AtomA R ∘ blank := funext fun x => propext (atomA_blank skeletal x).symm
  rw [eq]
  exact top.comp blank_measurable

private theorem atomE_measurable (borel : Borel participants policy)
    {R : DuelStep -> Prop} (skeletal : Skeletal R) (index : Nat)
    : Measurable fun sample => AtomE R ((run participants policy sample).stepAt index) :=
  (atomE_stepSpace skeletal).comp (borel index)

private theorem atomA_measurable (borel : Borel participants policy)
    {R : DuelStep -> Prop} (skeletal : Skeletal R) (index : Nat)
    : Measurable fun sample => AtomA R ((run participants policy sample).stepAt index) :=
  (atomA_stepSpace skeletal).comp (borel index)

private theorem card_filter_measurable (indices : Finset Nat) {p : Nat -> Sample -> Prop}
    [forall sample, DecidablePred fun index => p index sample]
    (measurable : forall index, Measurable (p index))
    : Measurable fun sample => (indices.filter fun index => p index sample).card := by
  simp only [Finset.card_filter]
  exact Finset.measurable_sum indices fun index _ =>
    Measurable.ite (measurable index).setOf measurable_const measurable_const

private theorem nat_measurable {f : Sample -> Nat} (measurable : Measurable f)
    (g : Nat -> Prop)
    : Measurable fun sample => g (f sample) :=
  (measurable_from_nat (f := g)).comp measurable

variable (borel : Borel participants policy)
include borel

private theorem raises_measurable (index : Nat)
    : Measurable
        fun sample =>
          Raises (run participants policy sample) participants index :=
  atomE_measurable borel (raisesStep_skeletal participants) index

private theorem roundStart_measurable (c term : Nat)
    : Measurable
        fun sample =>
          RoundStart (run participants policy sample) participants c term := by
  simp only [roundStart_iff]
  refine Measurable.and ?_
    (atomE_measurable borel (raiseStep_skeletal participants term) c)
  cases c with
  | zero =>
      have initial
          : forall sample : Sample,
              (run participants policy sample).stateAt 0 = some policy.initial :=
        fun _ => rfl
      simp only [initial]
      exact measurable_const
  | succ n =>
      simp only [stateAt_low_iff]
      exact atomA_measurable borel (lowAfter_skeletal participants term) n

private theorem firstRound_measurable (start first : Nat)
    : Measurable
        fun sample =>
          FirstRound (run participants policy sample) participants start first := by
  unfold FirstRound
  refine measurable_const.and
    ((Measurable.exists fun term => roundStart_measurable borel first term).and ?_)
  exact Measurable.forall fun index =>
    measurable_const.imp (measurable_const.imp
      (Measurable.exists fun term => roundStart_measurable borel index term).not)

private theorem inRound_measurable (start k index : Nat)
    : Measurable
        fun sample =>
          InRound (run participants policy sample) participants start k index := by
  unfold InRound
  exact Measurable.exists fun first =>
    (firstRound_measurable borel start first).and (measurable_const.and
      (nat_measurable (card_filter_measurable _ fun earlier =>
        raises_measurable borel earlier) (fun n => n = k + 1)))

private theorem topReset_measurable (index : Nat) (node : NodeID)
    : Measurable
        fun sample =>
          TopReset (run participants policy sample) participants index node := by
  simp only [topReset_iff]
  exact atomE_measurable borel (topStep_skeletal participants node) index

private theorem drawsBefore_measurable (index : Nat)
    : Measurable
        fun sample =>
          drawsBefore (run participants policy sample) participants index := by
  unfold drawsBefore
  refine card_filter_measurable _ fun earlier => ?_
  simp only [reset_iff]
  exact atomE_measurable borel (resetStep_skeletal participants) earlier

private theorem relevantReset_measurable (start k index : Nat) (node : NodeID)
    : Measurable
        fun sample =>
          RelevantReset (run participants policy sample) participants start k index
            node := by
  unfold RelevantReset roundResets
  exact (inRound_measurable borel start k index).and (measurable_const.and
    ((topReset_measurable borel index node).and
      (nat_measurable (card_filter_measurable _ fun earlier =>
        (inRound_measurable borel start k earlier).and
          (topReset_measurable borel earlier node)) (fun n => n < 2))))

private theorem relevantAt_measurable (start k j index : Nat)
    : Measurable
        fun sample =>
          exists node,
            RelevantReset (run participants policy sample) participants start k index node
            /\ drawsBefore (run participants policy sample) participants index = j :=
  Measurable.exists
    fun node =>
      (relevantReset_measurable borel start k index node).and
        (nat_measurable (drawsBefore_measurable borel index) (fun n => n = j))

end Measurability

/-- The draws before `j`, and zero after. -/
private def trunc (j : Nat) (sample : Sample) : Sample :=
  fun i => if i < j then sample i else 0

private theorem trunc_measurable (j : Nat) : Measurable[revealed j] (trunc j) := by
  have eq
      : trunc j
        = (fun (point : Finset.range j -> Real) (i : Nat) =>
            if lt : i < j then point ⟨i, Finset.mem_range.mpr lt⟩ else 0)
          ∘ Rounds.front j := by
    funext sample i
    by_cases lt : i < j <;> simp [trunc, Rounds.front, lt]
  rw [eq]
  refine Measurable.comp (Measurable.of_eval fun i => ?_)
    (comap_measurable (Rounds.front j))
  by_cases lt : i < j
  · simp only [lt, dite_true]
    exact measurable_pi_apply _
  · simp only [lt, dite_false]
    exact measurable_const

private theorem trunc_agree (j : Nat) (sample : Sample)
    : forall i, i < j -> sample i = trunc j sample i :=
  fun i lt => by simp [trunc, lt]

/-! ## Centres as measurable functions -/

/-- The `position`-th other participant of the step's actor is `other`. -/
private def otherAt (participants : Finset NodeID) (position : Nat) (other : NodeID)
    (step : DuelStep)
    : Prop :=
  ((participants.erase (step.action.actor.getD 0)).sort (· <= ·))[position]? = some other

private theorem otherAt_skeletal (participants : Finset NodeID) (position : Nat)
    (other : NodeID)
    : Skeletal (otherAt participants position other) := by
  intro step
  simp only [otherAt, actor_blankStep]

open Classical in
private theorem centre_sum (participants : Finset NodeID) (position : Nat)
    (x : Option DuelStep)
    : x.elim 0 (fun step => centre participants step position)
      = ∑ other ∈ participants,
          if AtomE (otherAt participants position other) x then
            reals x (Nat.pair 2 other) - reals x (Nat.pair 0 0)
          else
            0 := by
  rcases x with _ | step
  · simp [AtomE]
  · simp only [Option.elim, centre]
    rcases found
        : ((participants.erase (step.action.actor.getD 0)).sort (· <= ·))[position]?
      with _ | other
    · simp [AtomE, otherAt, found]
    · have member : other ∈ participants := by
        have := List.mem_of_getElem? found
        simp only [Finset.mem_sort, Finset.mem_erase] at this
        exact this.2
      simp [AtomE, otherAt, found, member, reals, Nat.unpair_pair]
      rfl

open Classical in
private theorem centres_pi {participants : Finset NodeID} {policy : Policy} {start : Nat}
    (borel : Borel participants policy) (k j : Nat)
    (position : Fin (participants.card - 1))
    : Measurable fun sample => centres participants policy start k j sample position := by
  have measurable
      : forall index,
          Measurable fun sample =>
            ((run participants policy sample).stepAt index).elim 0
              fun step => centre participants step position := by
    intro index
    simp only [centre_sum]
    exact Finset.measurable_sum _ fun other _ =>
      Measurable.ite
        (atomE_measurable borel (otherAt_skeletal participants position other) index).setOf
        (((reals_measurable (Nat.pair 2 other)).comp (borel index)).sub
          ((reals_measurable (Nat.pair 0 0)).comp (borel index)))
        measurable_const
  have total
      : forall sample : Sample,
          exists index,
            (exists node,
              RelevantReset (run participants policy sample) participants start k index node
              /\ drawsBefore (run participants policy sample) participants index = j)
            \/ Not (exists index node,
              RelevantReset (run participants policy sample) participants start k index node
              /\ drawsBefore (run participants policy sample) participants index = j) := by
    intro sample
    by_cases found
        : exists index node,
            RelevantReset (run participants policy sample) participants start k index node
            /\ drawsBefore (run participants policy sample) participants index = j
    · obtain ⟨index, relevant⟩ := found
      exact ⟨index, Or.inl relevant⟩
    · exact ⟨0, Or.inr found⟩
  have eq
      : (fun sample => centres participants policy start k j sample position)
        = fun sample =>
          if exists index node,
              RelevantReset (run participants policy sample) participants start k index node
              /\ drawsBefore (run participants policy sample) participants index = j then
            ((run participants policy sample).stepAt (Nat.find (total sample))).elim 0
              fun step => centre participants step position
          else
            0 := by
    funext sample
    unfold centres
    by_cases found
        : exists index node,
            RelevantReset (run participants policy sample) participants start k index node
            /\ drawsBefore (run participants policy sample) participants index = j
    · rw [dite_eq_left found, ite_eq_left found]
      have find : Nat.find found = Nat.find (total sample) :=
        le_antisymm
          (Nat.find_min' found ((Nat.find_spec (total sample)).resolve_right (not_not.mpr found)))
          (Nat.find_min' (total sample) (Or.inl (Nat.find_spec found)))
      rw [find]
    · rw [dite_eq_right found, ite_eq_right found]
  rw [eq]
  refine Measurable.ite
    (Measurable.exists fun index => relevantAt_measurable borel start k j index).setOf
    (Measurable.find (p := fun index sample =>
        (exists node,
          RelevantReset (run participants policy sample) participants start k index node
          /\ drawsBefore (run participants policy sample) participants index = j)
        \/ Not (exists index node,
          RelevantReset (run participants policy sample) participants start k index node
          /\ drawsBefore (run participants policy sample) participants index = j))
      measurable (fun index => ?_) total)
    measurable_const
  exact ((relevantAt_measurable borel start k j index).or
          (Measurable.exists
            fun index => relevantAt_measurable borel start k j index).not).setOf

/-! ## Order and counting of relevant resets -/

section Counting

variable {trace : Trace DuelWorld Liveness.Event} {participants : Finset NodeID}

private theorem firstRound_unique {start first first' : Nat}
    (found : FirstRound trace participants start first)
    (found' : FirstRound trace participants start first')
    : first = first' := by
  obtain ⟨le, start_, minimal⟩ := found
  obtain ⟨le', start', minimal'⟩ := found'
  rcases lt_trichotomy first first' with lt | eq | lt
  · exact absurd start_ (minimal' first le lt)
  · exact eq
  · exact absurd start' (minimal first' le' lt)

private theorem drawsBefore_lt {index index' : Nat} (lt : index < index')
    (reset
      : exists step node,
          trace.stepAt index = some step
          /\ node ∈ participants
          /\ ElectionReset step node)
    : drawsBefore trace participants index < drawsBefore trace participants index' := by
  have succ : drawsBefore trace participants (index + 1)
      = drawsBefore trace participants index + 1 := by
    rw [drawsBefore_succ]
    split_ifs
    rfl
  have := drawsBefore_mono trace participants (show index + 1 <= index' by omega)
  omega

private theorem reset_of_topReset {index : Nat} {node : NodeID}
    (top : TopReset trace participants index node) (member : node ∈ participants)
    : exists step node,
        trace.stepAt index = some step
        /\ node ∈ participants
        /\ ElectionReset step node := by
  obtain ⟨step, _, found, reset, _⟩ := top
  exact ⟨step, node, found, member, reset⟩

open Classical in
private theorem inRound_lt {start k k' index index' : Nat} (lt : k < k')
    (inRound : InRound trace participants start k index)
    (inRound' : InRound trace participants start k' index')
    : index < index' := by
  obtain ⟨first, found, _, card⟩ := inRound
  obtain ⟨first', found', _, card'⟩ := inRound'
  cases firstRound_unique found found'
  by_contra not
  have le := Finset.card_le_card (Finset.filter_subset_filter (Raises trace participants)
    (Finset.Icc_subset_Icc_right (a := first) (Nat.le_of_not_lt not)))
  omega

open Classical in
private theorem relevantReset_three {start k a b c : Nat} {node : NodeID}
    (relevantA : RelevantReset trace participants start k a node)
    (relevantB : RelevantReset trace participants start k b node)
    (relevantC : RelevantReset trace participants start k c node)
    (ab : a < b) (bc : b < c)
    : False := by
  have ⟨⟨first, ⟨startLe, _⟩, firstLe, _⟩, _, topA, _⟩ := relevantA
  have subset
      : ({a, b} : Finset Nat)
        ⊆ (Finset.Ico start c).filter fun earlier =>
            InRound trace participants start k earlier
            /\ TopReset trace participants earlier node := by
    intro earlier member
    simp only [Finset.mem_insert, Finset.mem_singleton] at member
    rcases member with rfl | rfl
    · simp only [Finset.mem_filter, Finset.mem_Ico]
      exact ⟨⟨by omega, by omega⟩, relevantA.1, topA⟩
    · simp only [Finset.mem_filter, Finset.mem_Ico]
      exact ⟨⟨by have ⟨⟨_, ⟨_, _⟩, _, _⟩, _⟩ := relevantB; omega, bc⟩,
        relevantB.1, relevantB.2.2.1⟩
  have two := Finset.card_le_card subset
  rw [Finset.card_pair (by omega)] at two
  exact absurd relevantC.2.2.2 (by unfold roundResets; omega)

private theorem at_most_two (S : Nat -> Prop)
    (three : forall a b c, S a -> S b -> S c -> a < b -> b < c -> False)
    : exists T : Finset Nat, T.card <= 2 /\ forall index, S index -> index ∈ T := by
  classical
  by_cases first : exists index, S index
  · by_cases second : exists index, S index /\ Nat.find first < index
    · refine ⟨{Nat.find first, Nat.find second}, Finset.card_le_two, fun c member => ?_⟩
      simp only [Finset.mem_insert, Finset.mem_singleton]
      by_contra different
      push Not at different
      have lt : Nat.find first < c :=
        lt_of_le_of_ne (Nat.find_min' first member) (Ne.symm different.1)
      have lt' : Nat.find second < c :=
        lt_of_le_of_ne (Nat.find_min' second ⟨member, lt⟩) (Ne.symm different.2)
      obtain ⟨found, lt''⟩ := Nat.find_spec second
      exact three _ _ _ (Nat.find_spec first) found member lt'' lt'
    · refine ⟨{Nat.find first}, by simp, fun c member => ?_⟩
      simp only [Finset.mem_singleton]
      by_contra different
      exact second ⟨c, member, lt_of_le_of_ne (Nat.find_min' first member) (Ne.symm different)⟩
  · exact ⟨∅, by simp, fun index found => (first ⟨index, found⟩).elim⟩

end Counting

private theorem actor_of_reset {step : DuelStep} {node : NodeID}
    (reset : ElectionReset step node)
    : step.action.actor = some node := by
  obtain ⟨before, action, after⟩ := step
  cases action with
  | «local» actor input =>
      cases input <;> simp_all [ElectionReset, Event.actor]
  | deliver packet => simp_all [ElectionReset, Event.actor]
  | drop packet => simp [ElectionReset] at reset
  | crash actor => simp [ElectionReset] at reset
  | idle => simp [ElectionReset] at reset

/-! ## The `Attempts` fields -/

variable {participants policy start}

theorem relevant_measurable (borel : Borel participants policy) (k j : Nat)
    : MeasurableSet[revealed j]
        {sample | Relevant participants policy start k j sample} := by
  have eq
      : {sample | Relevant participants policy start k j sample}
        = trunc j ⁻¹' {sample | Relevant participants policy start k j sample} := by
    ext sample
    exact ⟨relevant_agree (trunc_agree j sample),
      relevant_agree fun i lt => (trunc_agree j sample i lt).symm⟩
  rw [eq]
  exact (Measurable.exists fun index => relevantAt_measurable borel start k j index).setOf
    |>.preimage (trunc_measurable j)

theorem centres_measurable (borel : Borel participants policy) (k j : Nat)
    (position : Fin (participants.card - 1))
    : Measurable[revealed j]
        fun sample => centres participants policy start k j sample position := by
  have eq
      : (fun sample => centres participants policy start k j sample position)
        = (fun sample => centres participants policy start k j sample position) ∘ trunc j :=
    funext fun sample => centres_agree (trunc_agree j sample) position
  rw [eq]
  exact (centres_pi borel k j position).comp (trunc_measurable j)

theorem relevant_ordered {k k' j j' : Nat} {sample : Sample} (lt : k < k')
    (relevant : Relevant participants policy start k j sample)
    (relevant' : Relevant participants policy start k' j' sample)
    : j < j' := by
  obtain ⟨index, node, ⟨inRound, member, top, _⟩, rfl⟩ := relevant
  obtain ⟨index', node', ⟨inRound', _, _, _⟩, rfl⟩ := relevant'
  exact drawsBefore_lt (inRound_lt lt inRound inRound') (reset_of_topReset top member)

theorem relevant_bounded (k : Nat) (sample : Sample)
    : exists draws : Finset Nat,
        draws.card <= 2 * participants.card
        /\ forall j, Relevant participants policy start k j sample -> j ∈ draws := by
  choose T bound
    using fun node =>
      at_most_two
        (fun index =>
          RelevantReset (run participants policy sample) participants start k index node)
        fun _ _ _ => relevantReset_three
  refine ⟨(participants.biUnion T).image
    (drawsBefore (run participants policy sample) participants), ?_, ?_⟩
  · calc
      _ <= (participants.biUnion T).card := Finset.card_image_le
      _ <= ∑ node ∈ participants, (T node).card := Finset.card_biUnion_le
      _ <= ∑ _node ∈ participants, 2 := Finset.sum_le_sum fun node _ => (bound node).1
      _ = 2 * participants.card := by simp [mul_comm]
  · rintro j ⟨index, node, relevant, rfl⟩
    exact Finset.mem_image_of_mem _
      (Finset.mem_biUnion.mpr ⟨node, relevant.2.1, (bound node).2 index relevant⟩)

/-! ## Draws and deadlines -/

/-- A participant reset of the run draws its deadline from the sample. -/
theorem run_deadline {sample : Sample} {index : Nat} {step : DuelStep} {node : NodeID}
    (stepAt : (run participants policy sample).stepAt index = some step)
    (member : node ∈ participants) (reset : ElectionReset step node)
    : deadline step.after node
      = time step.before
        + sample (drawsBefore (run participants policy sample) participants index) := by
  classical
  obtain ⟨state, choice, found, next, rfl⟩ := stepAt_run_eq stepAt
  rw [<- drawIndex_history found]
  show (if node ∈ participants /\ ElectionReset _ node then _ else _) = _
  split_ifs with reset'
  · rfl
  · exact absurd ⟨member, reset⟩ reset'

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
  classical
  have found
      : exists index' node',
          RelevantReset (run participants policy sample) participants start k index' node'
          /\ drawsBefore (run participants policy sample) participants index'
            = drawsBefore (run participants policy sample) participants index :=
    ⟨index, node, relevant, rfl⟩
  have find : Nat.find found = index := by
    refine le_antisymm (Nat.find_min' found ⟨node, relevant, rfl⟩) ?_
    by_contra lt
    obtain ⟨node', relevant', draws⟩ := Nat.find_spec found
    have := drawsBefore_lt (Nat.lt_of_not_le lt)
      (reset_of_topReset relevant'.2.2.1 relevant'.2.1)
    omega
  have actor : step.action.actor = some node := by
    obtain ⟨step', _, found', reset, _⟩ := relevant.2.2.1
    rw [stepAt] at found'
    cases found'
    exact actor_of_reset reset
  have member : other ∈ (participants.erase node).sort (· <= ·) := by
    simp [Finset.mem_sort, Finset.mem_erase, ne, otherIn]
  obtain ⟨position, lookup⟩ := List.mem_iff_getElem?.mp member
  have bound : position < participants.card - 1 := by
    obtain ⟨lt, _⟩ := List.getElem?_eq_some_iff.mp lookup
    rw [Finset.length_sort, Finset.card_erase_of_mem relevant.2.1] at lt
    exact lt
  refine ⟨⟨position, bound⟩, ?_⟩
  unfold centres
  rw [dite_eq_left found, find, stepAt]
  simp only [Option.elim, centre, actor, Option.getD_some, lookup]

end CCFRaft.Proofs.Duel.Adaptive
