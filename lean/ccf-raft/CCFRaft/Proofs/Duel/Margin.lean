module

public import CCFRaft.Proofs.Duel.ResolveChain

@[expose] public section

/-!
# Margins from draws

A round of the run keeps its margin (`Round.RoundMargin`) when every relevant draw of
the round keeps the margin from its centres (`margin_of_far`): each of a
participant's first two resets into the round's term is a relevant reset
(`relevantReset_of_reset`), its new deadline is the time plus its draw
(`Adaptive.run_deadline`), and every other participant's deadline, which the reset
leaves alone, is the time plus one of its centres (`Adaptive.centre_of_relevant`).
-/

namespace CCFRaft.Proofs.Duel.Resolve

open CCFRaft.Liveness
open CCFRaft.Proofs.Duel.Adaptive
open CCFRaft.Proofs.Duel.Round (RoundMargin Capped priorResets)
open CCF.MultiNodeTransitionSystem (nodeState)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A step resets at most one node. -/
theorem reset_unique {step : CCF.Execution.Step W Liveness.Event} {node other : NodeID}
    (resets : ElectionReset step node) (resets' : ElectionReset step other)
    : node = other := by
  revert resets resets'
  unfold ElectionReset
  split
  · intro resets resets'
    exact resets.symm.trans resets'
  · intro resets resets'
    exact resets.1.symm.trans resets'.1
  · intro resets
    exact resets.elim

omit [HasTime W] [HasLive W] [HasTimers W] in
/-- There is one first round start. -/
theorem firstRound_unique {trace : Trace W Liveness.Event} {participants : Finset NodeID}
    {start first first' : Nat} (isFirst : FirstRound trace participants start first)
    (isFirst' : FirstRound trace participants start first')
    : first = first' := by
  rcases Nat.lt_trichotomy first first' with lt | eq | gt
  · exact absurd isFirst.2.1 (isFirst'.2.2 first isFirst.1 lt)
  · exact eq
  · exact absurd isFirst'.2.1 (isFirst.2.2 first' isFirst'.1 gt)

section Admissible

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

omit [HasTimers W] in
/-- After a round start, the highest participant term is at least the round's. -/
theorem top_of_roundStart {participants : Finset NodeID} {c term index : Nat} {point : W}
    (round : RoundStart trace participants c term) (lt : c < index)
    (found : trace.stateAt index = some point)
    : term + 1 <= maxTerm participants point := by
  obtain ⟨raiseStep, node, state, raised, member, raisedFound, gt⟩ := round.raise
  have raisedAt : trace.nodeAt (c + 1) node = some state :=
    Trace.nodeAt_eq_some.mpr ⟨_, Trace.stateAt_succ_of_stepAt raised, raisedFound⟩
  obtain ⟨later, laterFound, grows⟩ :=
    StablePrimary.term_mono admissible (show c + 1 <= index by omega) raisedAt found
  rw [Trace.nodeAt_of_stateAt found] at laterFound
  have := le_maxTerm member laterFound
  omega

omit [HasTimers W] in
/-- A participant's reset into a capped round's term leaves the round's term on top. -/
theorem top_after_reset {participants : Finset NodeID} {c term index : Nat}
    {step : CCF.Execution.Step W Liveness.Event} {node : NodeID} {state : NodeState}
    (capped : Capped trace participants c term index)
    (stepped : trace.stepAt index = some step) (member : node ∈ participants)
    (reset : ElectionReset step node)
    (found : nodeState (proto step.after) node = some state)
    (eq : state.currentTerm = term + 1)
    : maxTerm participants step.after = term + 1 := by
  refine le_antisymm (maxTerm_le fun other state' member' found' => ?_)
    (eq ▸ le_maxTerm member found)
  by_cases same : other = node
  · subst same
    rw [found, Option.some.injEq] at found'
    subst found'
    omega
  obtain ⟨before, beforeFound, le⟩ := Racing.node_before admissible stepped found'
  have notLt : Not (before.currentTerm < state'.currentTerm) := fun lt =>
    same (reset_unique (Racing.reset_of_term_lt admissible stepped beforeFound found' lt)
      reset)
  have := capped.2 index step.before other before capped.1 le_rfl
    (admissible.before stepped) member' beforeFound
  omega

omit [HasTimers W] in
/-- Each of a participant's first two resets into a capped round's term is a relevant
reset of the round. -/
theorem relevantReset_of_reset {participants : Finset NodeID} {start k c term index : Nat}
    {step : CCF.Execution.Step W Liveness.Event} {node : NodeID} {state : NodeState}
    (roundAt : RoundAt trace participants start k c term)
    (capped : Capped trace participants c term index)
    (stepped : trace.stepAt index = some step) (member : node ∈ participants)
    (reset : ElectionReset step node)
    (found : nodeState (proto step.after) node = some state)
    (eq : state.currentTerm = term + 1) (prior : priorResets trace c index node term < 2)
    : RelevantReset trace participants start k index node := by
  classical
  obtain ⟨round, first, isFirst, firstLe, count⟩ := roundAt
  have top := top_after_reset admissible capped stepped member reset found eq
  have noRaise : Not (c < index /\ Raises trace participants index) := by
    rintro ⟨lt, step', stepped', rises⟩
    rw [stepped, Option.some.injEq] at stepped'
    subst stepped'
    have := top_of_roundStart admissible round lt (admissible.before stepped)
    omega
  have sameRaises
      : (Finset.Icc first index).filter (Raises trace participants)
        = (Finset.Icc first c).filter (Raises trace participants) := by
    ext other
    simp only [Finset.mem_filter, Finset.mem_Icc]
    constructor
    · rintro ⟨⟨lower, upper⟩, raises⟩
      refine ⟨⟨lower, ?_⟩, raises⟩
      by_contra above
      rcases Nat.lt_or_ge other index with below | atLeast
      · exact not_raises_inside admissible round capped (by omega) below raises
      · exact noRaise ⟨by omega, (show other = index by omega) ▸ raises⟩
    · rintro ⟨⟨lower, upper⟩, raises⟩
      exact ⟨⟨lower, upper.trans capped.1⟩, raises⟩
  refine ⟨⟨first, isFirst, firstLe.trans capped.1, sameRaises ▸ count⟩, member,
    ⟨step, state, stepped, reset, found, eq.trans top.symm⟩, ?_⟩
  refine lt_of_le_of_lt (Finset.card_le_card fun earlier => ?_) prior
  simp only [Finset.mem_filter, Finset.mem_Ico]
  rintro ⟨⟨_, upper⟩, ⟨first', isFirst', firstLe', count'⟩, step', state', stepped', reset',
    found', top'⟩
  rw [← firstRound_unique isFirst isFirst'] at firstLe' count'
  have cLe : c <= earlier := by
    by_contra below
    push Not at below
    have raisesC := raises_of_roundStart admissible round
    have sub
        : insert c ((Finset.Icc first earlier).filter (Raises trace participants))
          ⊆ (Finset.Icc first c).filter (Raises trace participants) := by
      intro other
      simp only [Finset.mem_insert, Finset.mem_filter, Finset.mem_Icc]
      rintro (rfl | ⟨⟨lower, upper⟩, raises⟩)
      · exact ⟨⟨firstLe, le_rfl⟩, raisesC⟩
      · exact ⟨⟨lower, by omega⟩, raises⟩
    have := Finset.card_le_card sub
    rw [Finset.card_insert_of_notMem (by simp; omega), count, count'] at this
    omega
  refine ⟨⟨cLe, upper⟩, step', state', stepped', reset', found', ?_⟩
  have high : maxTerm participants step'.after <= term + 1 :=
    maxTerm_le fun other state'' member' found'' =>
      capped.2 (earlier + 1) step'.after other state'' (by omega) (by omega)
        (Trace.stateAt_succ_of_stepAt stepped') member' found''
  have low := top_of_roundStart admissible round (show c < earlier + 1 by omega)
    (Trace.stateAt_succ_of_stepAt stepped')
  omega

end Admissible

/-- A round of the run whose relevant draws all keep `margin` from their centres keeps
its margin. -/
theorem margin_of_far [Config.InitialConfiguration] {nodes : List NodeID}
    {participants : Finset NodeID} {policy : Policy} {start : Nat} {sample : Sample}
    {electionTimeout margin : Real}
    (admissible
      : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)
          (run participants policy sample))
    (timers : (run participants policy sample).Valid (timerModel electionTimeout))
    {k c term : Nat}
    (roundAt : RoundAt (run participants policy sample) participants start k c term)
    (far
      : forall j,
          Relevant participants policy start k j sample
          -> forall position,
              margin < |sample j - centres participants policy start k j sample position|)
    : RoundMargin (run participants policy sample) participants c term margin := by
  intro index step node state capped stepped member reset found eq prior other otherIn ne
  have relevant :=
    relevantReset_of_reset admissible roundAt capped stepped member reset found eq prior
  obtain ⟨position, centreEq⟩ := centre_of_relevant relevant stepped otherIn ne
  have kept := far _ ⟨index, node, relevant, rfl⟩ position
  rw [centreEq] at kept
  rw [run_deadline stepped member reset,
    ((timers.next stepped) other).2.1 fun resets => ne (reset_unique resets reset)]
  convert kept using 2
  ring

end CCFRaft.Proofs.Duel.Resolve
