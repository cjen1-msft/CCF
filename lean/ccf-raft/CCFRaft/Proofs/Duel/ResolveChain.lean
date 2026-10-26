module

public import CCFRaft.Proofs.Duel.DuelRound
public import CCFRaft.Proofs.Duel.Relevance
public import CCFRaft.Proofs.Duel.CommittedWindow
public import CCFRaft.Proofs.Leadership.ConfiguredWindow
public import CCFRaft.Proofs.StablePrimary

@[expose] public section

/-!
# Chaining duel rounds

NOT IMPORTED BY `Properties`. The deterministic part of `Resolve`: from a round start
within the initial phase, rounds follow one another (`Round.duel_round`), each within
a round length plus any overshoot. If at most `overshoots` steps overshoot, and each
of `overshoots + 1` blocks of `rounds` rounds has a round that keeps its margin, some
such round has no overshoot and ends in an anchored start (`chain`).
-/

namespace CCFRaft.Proofs.Duel.Resolve

open CCFRaft.Liveness
open CCFRaft.Proofs.Duel.Adaptive (InRound FirstRound Raises maxTerm)
open CCFRaft.Proofs.Duel.Round (RoundMargin RoundSetup Capped roundLength)
open CCF.MultiNodeTransitionSystem (nodeState)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-- The window: the initial phase, `(overshoots + 1) * rounds` round lengths, an
overshoot per block, and four delays for the last round's handoff. -/
def window (initial electionTimeout maxDelay jump : Real) (overshoots rounds : Nat)
    : Real :=
  initial
  + (overshoots + 1) * rounds * roundLength electionTimeout maxDelay
  + (overshoots + 1) * jump
  + 4 * maxDelay

/-- Everything the duel needs of one run, over the window from `start`. -/
structure Setup [Config.InitialConfiguration] (nodes : List NodeID)
    (trace : Trace W Liveness.Event) (initial electionTimeout maxDelay jump fresh : Real)
    (overshoots start : Nat) (duration : Real) (participants members : Finset NodeID)
    : Prop where
  admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace
  delay : trace.Valid (boundedDelayModel maxDelay)
  timers : trace.Valid (timerModel electionTimeout)
  diverges : TimeDiverges trace
  firing
    : forall node,
        node ∈ participants
        -> Scheduled trace (some 0) (fun point => TimeoutDue point node)
            (fun step => step.action = .local node (.timeout .election))
  /-- At most `overshoots` steps of the window overshoot a deadline, each by at most
  `jump`. -/
  overshoot
    : exists bad : Finset Nat,
        bad.card <= overshoots
        /\ forall index step node,
            node ∈ participants
            -> Within trace start duration index
            -> trace.stepAt index = some step
            -> NoOvershoot (some (if index ∈ bad then jump else 0)) step node
  nonnegative : 0 <= maxDelay
  jumpNonnegative : 0 <= jump
  ratio : 4 * maxDelay < electionTimeout / 2
  /-- The initial phase: within `initial` of `start`, an anchored start or a round
  start (`Leadership.init` from a configured good period). -/
  initialPhase
    : HandoffBy trace participants start initial fresh
      \/ exists c term origin point,
          start <= c
          /\ trace.stateAt start = some origin
          /\ trace.stateAt c = some point
          /\ time point <= time origin + initial
          /\ RoundStart trace participants c term
  period : GoodPeriod trace start duration participants
  matching : Window.Matching trace start duration participants
  /-- As `Round.RoundSetup.active`. -/
  active : Window.AnchorActive trace start duration participants
  membership
    : forall point,
        trace.stateAt start = some point -> Membership participants members (proto point)
  subset : participants ⊆ members
  /-- As `Round.RoundSetup.configured`, at the start. -/
  configured
    : forall point,
        trace.stateAt start = some point
        -> ConfigurationCommitted participants (proto point)

/-- `c` starts round `k`, of `term + 1`, counting from the first round start at or
after `start`. -/
def RoundAt (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (start k c term : Nat)
    : Prop :=
  RoundStart trace participants c term /\ InRound trace participants start k c

/-! ## Rounds along a trace -/

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
theorem le_maxTerm {participants : Finset NodeID} {point : W} {node : NodeID}
    {state : NodeState} (member : node ∈ participants)
    (found : nodeState (proto point) node = some state)
    : state.currentTerm <= maxTerm participants point := by
  have := Finset.le_sup
    (f := fun node => ((nodeState (proto point) node).map (·.currentTerm)).getD 0) member
  simpa [maxTerm, found] using this

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
theorem maxTerm_le {participants : Finset NodeID} {point : W} {bound : Nat}
    (low
      : forall node state,
          node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.currentTerm <= bound)
    : maxTerm participants point <= bound := by
  unfold maxTerm
  apply Finset.sup_le
  intro node member
  cases found : nodeState (proto point) node with
  | none => simp
  | some state => simpa using low node state member found

omit [HasNetwork W] in
theorem noOvershoot_mono {step : CCF.Execution.Step W Liveness.Event} {node : NodeID}
    {small large : Real} (le : small <= large)
    (holds : NoOvershoot (some small) step node)
    : NoOvershoot (some large) step node := by
  intro live can early
  exact (holds live can early).trans (by linarith)

omit [HasLive W] [HasTimers W] in
/-- A handoff after `c` is a handoff after `start`, with the bound measured from it. -/
theorem HandoffBy.shift {trace : Trace W Liveness.Event} {participants : Finset NodeID}
    {start c : Nat} {bound bound' fresh : Real} {origin point : W} (le : start <= c)
    (originFound : trace.stateAt start = some origin)
    (found : trace.stateAt c = some point)
    (fits : time point + bound <= time origin + bound')
    (handoff : HandoffBy trace participants c bound fresh)
    : HandoffBy trace participants start bound' fresh := by
  obtain ⟨index, leader, term, anchor, origin', point', cLe, originFound', found', timeLe,
    anchored⟩ := handoff
  rw [found, Option.some.injEq] at originFound'
  subst originFound'
  exact ⟨
    index,
    leader,
    term,
    anchor,
    origin,
    point',
    by omega,
    originFound,
    found',
    by linarith,
    anchored
  ⟩

omit [HasLive W] [HasTimers W] in
theorem HandoffBy.mono_fresh {trace : Trace W Liveness.Event}
    {participants : Finset NodeID} {c : Nat} {bound fresh shorter : Real}
    (le : shorter <= fresh) (handoff : HandoffBy trace participants c bound fresh)
    : HandoffBy trace participants c bound shorter := by
  obtain ⟨index, leader, term, anchor, origin, point, cLe, originFound, found, timeLe,
    anchored⟩ := handoff
  exact ⟨index, leader, term, anchor, origin, point, cLe, originFound, found, timeLe,
    anchored.mono_fresh le⟩

section Admissible

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

omit [HasTimers W] in
/-- A round start raises the highest participant term. -/
theorem raises_of_roundStart {participants : Finset NodeID} {c term : Nat}
    (round : RoundStart trace participants c term)
    : Raises trace participants c := by
  obtain ⟨step, node, state, stepped, member, found, lt⟩ := round.raise
  refine ⟨step, stepped, ?_⟩
  have low : maxTerm participants step.before <= term :=
    maxTerm_le fun other state' member' found' =>
      round.low step.before other state' (admissible.before stepped) member' found'
  have := le_maxTerm member found
  omega

omit [HasTimers W] in
/-- No step strictly inside a capped round raises. -/
theorem not_raises_inside {participants : Finset NodeID} {c term next index : Nat}
    (round : RoundStart trace participants c term)
    (capped : Capped trace participants c term next) (lower : c < index)
    (upper : index < next)
    : Not (Raises trace participants index) := by
  rintro ⟨step, stepped, lt⟩
  have high : maxTerm participants step.after <= term + 1 :=
    maxTerm_le fun other state member found =>
      capped.2 (index + 1) step.after other state (by omega) (by omega)
        (Trace.stateAt_succ_of_stepAt stepped) member found
  obtain ⟨raiseStep, node, state, raised, member, found, gt⟩ := round.raise
  have raisedAt : trace.nodeAt (c + 1) node = some state :=
    Trace.nodeAt_eq_some.mpr ⟨_, Trace.stateAt_succ_of_stepAt raised, found⟩
  obtain ⟨later, laterFound, grows⟩ :=
    StablePrimary.term_mono admissible (show c + 1 <= index by omega) raisedAt
      (admissible.before stepped)
  rw [Trace.nodeAt_of_stateAt (admissible.before stepped)] at laterFound
  have := le_maxTerm member laterFound
  omega

omit [HasTimers W] in
/-- The next round start after a capped round starts the next round. -/
theorem RoundAt.next {participants : Finset NodeID} {start k c term next : Nat}
    (current : RoundAt trace participants start k c term) (lt : c < next)
    (capped : Capped trace participants c term next)
    (round : RoundStart trace participants next (term + 1))
    : RoundAt trace participants start (k + 1) next (term + 1) := by
  classical
  obtain ⟨roundC, first, isFirst, firstLe, count⟩ := current
  refine ⟨round, first, isFirst, by omega, ?_⟩
  have split
      : (Finset.Icc first next).filter (Raises trace participants)
        = insert next ((Finset.Icc first c).filter (Raises trace participants)) := by
    ext index
    simp only [Finset.mem_filter, Finset.mem_Icc, Finset.mem_insert]
    constructor
    · rintro ⟨⟨lower, upper⟩, raises⟩
      by_cases eq : index = next
      · exact Or.inl eq
      refine Or.inr ⟨⟨lower, ?_⟩, raises⟩
      by_contra above
      exact not_raises_inside admissible roundC capped (by omega) (by omega) raises
    · rintro (eq | ⟨⟨lower, upper⟩, raises⟩)
      · subst eq
        exact ⟨⟨by omega, le_rfl⟩, raises_of_roundStart admissible round⟩
      · exact ⟨⟨lower, by omega⟩, raises⟩
  rw [split, Finset.card_insert_of_notMem (by simp; omega), count]

omit [HasTimers W] in
/-- A round start at or after `start` gives the first one, which starts round zero. -/
theorem first_round {participants : Finset NodeID} {start c term : Nat} (le : start <= c)
    (round : RoundStart trace participants c term)
    : exists first term',
        first <= c /\ RoundAt trace participants start 0 first term' := by
  classical
  have found : exists index, start <= index /\ exists term, RoundStart trace participants index term :=
    ⟨c, le, term, round⟩
  obtain ⟨startLe, term', round'⟩ := Nat.find_spec found
  refine ⟨Nat.find found, term', Nat.find_min' found ⟨le, term, round⟩, round',
    Nat.find found, ⟨startLe, ⟨term', round'⟩, fun index lower upper starts =>
      Nat.find_min found upper ⟨lower, starts⟩⟩, le_rfl, ?_⟩
  rw [Finset.Icc_self, Finset.filter_true_of_mem (fun index member => by
    rw [Finset.mem_singleton] at member
    subst member
    exact raises_of_roundStart admissible round'), Finset.card_singleton]

/-- Each round start in the window, early enough for its round, meets `RoundSetup`. -/
theorem Setup.roundSetup {initial electionTimeout maxDelay jump fresh duration : Real}
    {overshoots start c term : Nat} {participants members : Finset NodeID}
    {origin point : W}
    (setup
      : Setup nodes trace initial electionTimeout maxDelay jump fresh overshoots start
          duration participants members)
    (startLe : start <= c) (originFound : trace.stateAt start = some origin)
    (found : trace.stateAt c = some point) (round : RoundStart trace participants c term)
    (fits
      : time point + roundLength electionTimeout maxDelay + jump + 4 * maxDelay
        <= time origin + duration)
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term := by
  have positive : 0 <= roundLength electionTimeout maxDelay + jump + 4 * maxDelay := by
    have := setup.ratio
    have := setup.nonnegative
    have := setup.jumpNonnegative
    unfold Round.roundLength
    linarith
  obtain ⟨bad, _, overshoot⟩ := setup.overshoot
  refine {
    admissible := setup.admissible
    delay := setup.delay
    timers := setup.timers
    diverges := setup.diverges
    firing := setup.firing
    overshoot := ?_
    nonnegative := setup.nonnegative
    jumpNonnegative := setup.jumpNonnegative
    ratio := setup.ratio
    round := round
    period := setup.period
    matching := setup.matching
    active := setup.active
    startLe := startLe
    covers := ?_
    membership := ?_
    subset := setup.subset
    configured := ?_
  }
  · intro index step node member within stepped
    refine noOvershoot_mono ?_ (overshoot index step node member within stepped)
    split_ifs
    · exact le_rfl
    · exact setup.jumpNonnegative
  · intro point' found'
    refine Leadership.Membership.window admissible setup.period setup.membership c point'
      ⟨startLe, fun origin' point'' originFound' found'' => ?_⟩ found'
    rw [originFound, Option.some.injEq] at originFound'
    rw [found, Option.some.injEq] at found''
    subst originFound' found''
    linarith
  · intro point' found'
    refine ConfigurationCommitted.window admissible setup.period setup.configured c point'
      ⟨startLe, fun origin' point'' originFound' found'' => ?_⟩ found'
    rw [originFound, Option.some.injEq] at originFound'
    rw [found, Option.some.injEq] at found''
    subst originFound' found''
    linarith
  · intro origin' point' originFound' found'
    rw [originFound, Option.some.injEq] at originFound'
    rw [found, Option.some.injEq] at found'
    subst originFound' found'
    exact fits

end Admissible

/-- One chosen round per block: `overshoots + 1` distinct rounds, all among the first
`(overshoots + 1) * rounds`. -/
theorem block_rounds (overshoots rounds : Nat) (pick : Nat -> Nat)
    (lt : forall block, block < overshoots + 1 -> pick block < rounds)
    : exists chosen : Finset Nat,
        chosen.card = overshoots + 1
        /\ (forall k, k ∈ chosen -> k < (overshoots + 1) * rounds)
        /\ forall k,
            k ∈ chosen
            -> exists block,
                block < overshoots + 1 /\ k = block * rounds + pick block := by
  have positive : 0 < rounds := (Nat.zero_le _).trans_lt (lt 0 (by omega))
  have recover
      : forall block, block < overshoots + 1 -> (block * rounds + pick block) / rounds = block :=
    fun block below => by
      rw [show block * rounds + pick block = pick block + rounds * block by ring,
        Nat.add_mul_div_left _ _ positive, Nat.div_eq_of_lt (lt block below), zero_add]
  refine ⟨(Finset.range (overshoots + 1)).image fun block => block * rounds + pick block,
    ?_, ?_, ?_⟩
  · rw [Finset.card_image_of_injOn, Finset.card_range]
    intro block below block' below' eq
    simp only [Finset.coe_range, Set.mem_Iio] at below below'
    rw [← recover block below, ← recover block' below']
    exact congrArg (· / rounds) eq
  · simp only [Finset.mem_image, Finset.mem_range]
    rintro k ⟨block, below, rfl⟩
    have := lt block below
    have : (block + 1) * rounds <= (overshoots + 1) * rounds :=
      Nat.mul_le_mul_right _ (by omega)
    nlinarith
  · simp only [Finset.mem_image, Finset.mem_range]
    rintro k ⟨block, below, rfl⟩
    exact ⟨block, below, rfl⟩

/-- If every block of rounds has a round that keeps its margin, the run reaches an
anchored start in the window. -/
theorem chain [Config.InitialConfiguration] {nodes : List NodeID}
    {trace : Trace W Liveness.Event}
    {initial electionTimeout maxDelay jump fresh : Real} {overshoots rounds start : Nat}
    {participants members : Finset NodeID}
    (setup
      : Setup nodes trace initial electionTimeout maxDelay jump fresh overshoots start
          (window initial electionTimeout maxDelay jump overshoots rounds) participants
          members)
    (freshLe : fresh <= electionTimeout / 2 - 4 * maxDelay)
    (margined
      : forall block,
          block < overshoots + 1
          -> exists k,
              k < rounds
              /\ forall c term,
                  RoundAt trace participants start (block * rounds + k) c term
                  -> RoundMargin trace participants c term (4 * maxDelay))
    : HandoffBy trace participants start
        (window initial electionTimeout maxDelay jump overshoots rounds) fresh := by
  classical
  have admissible := setup.admissible
  set R := roundLength electionTimeout maxDelay with R_def
  set total := (overshoots + 1) * rounds with total_def
  have nonnegative := setup.nonnegative
  have jumpNonnegative := setup.jumpNonnegative
  have ratio := setup.ratio
  have roundNonnegative : 0 <= R := by rw [R_def]; unfold Round.roundLength; linarith
  have windowEq
      : window initial electionTimeout maxDelay jump overshoots rounds
        = initial + ((overshoots : Real) + 1) * rounds * R + ((overshoots : Real) + 1) * jump
          + 4 * maxDelay := by
    rw [R_def]; unfold window; ring
  choose! pick pickLt pickMargin using margined
  obtain ⟨chosen, chosenCard, chosenLt, chosenBlock⟩ :=
    block_rounds overshoots rounds pick pickLt
  obtain ⟨bad, badCard, overshoot⟩ := setup.overshoot
  let badIn : Nat -> Nat := fun c => (bad.filter fun index => start <= index /\ index < c).card
  have badInLe : forall c, badIn c <= overshoots := fun c =>
    (Finset.card_filter_le _ _).trans badCard
  have badInMono : forall c c', c <= c' -> badIn c <= badIn c' := by
    intro c c' le
    apply Finset.card_le_card
    intro index
    simp only [Finset.mem_filter]
    rintro ⟨member, lower, upper⟩
    exact ⟨member, lower, by omega⟩
  have badInStep
      : forall c next index, index ∈ bad -> start <= index -> c <= index -> index < next
          -> badIn c + 1 <= badIn next := by
    intro c next index member lower cLe upper
    have notIn : index ∉ bad.filter fun index => start <= index /\ index < c := by
      simp only [Finset.mem_filter]; omega
    rw [← Finset.card_insert_of_notMem notIn]
    apply Finset.card_le_card
    intro other
    simp only [Finset.mem_insert, Finset.mem_filter]
    rintro (rfl | ⟨member', lower', upper'⟩)
    · exact ⟨member, lower, upper⟩
    · exact ⟨member', lower', by omega⟩
  rcases setup.initialPhase with handoff | ⟨c0, term0, origin, point0, startLe0, originFound,
    found0, time0, round0⟩
  · obtain ⟨index, leader, term, anchor, origin, point, le, originFound, found, timeLe,
      anchored⟩ := handoff
    refine ⟨index, leader, term, anchor, origin, point, le, originFound, found, ?_, anchored⟩
    rw [windowEq]
    have : 0 <= ((overshoots : Real) + 1) * rounds * R :=
      mul_nonneg (by positivity) roundNonnegative
    have : 0 <= ((overshoots : Real) + 1) * jump := mul_nonneg (by positivity) jumpNonnegative
    linarith
  have invariant
      : forall k, k <= total
          -> HandoffBy trace participants start
              (window initial electionTimeout maxDelay jump overshoots rounds) fresh
            \/ exists c term point,
                trace.stateAt c = some point
                /\ RoundAt trace participants start k c term
                /\ time point <= time origin + initial + k * R + badIn c * jump
                /\ (chosen.filter (· < k)).card <= badIn c := by
    intro k
    induction k with
    | zero =>
        intro _
        obtain ⟨first, term', firstLe, roundAt⟩ := first_round admissible startLe0 round0
        obtain ⟨pointFirst, foundFirst⟩ := Trace.stateAt_of_le firstLe found0
        have := admissible.time_le firstLe foundFirst found0
        have : 0 <= (badIn first : Real) * jump := mul_nonneg (by positivity) jumpNonnegative
        right
        refine ⟨first, term', pointFirst, foundFirst, roundAt, ?_, by simp⟩
        push_cast
        linarith
    | succ k ih =>
        intro kLt
        rcases ih (by omega) with done | ⟨c, term, point, found, roundAt, timeC, countC⟩
        · exact Or.inl done
        obtain ⟨first, isFirst, firstLe, _⟩ := roundAt.2
        have startLe : start <= c := isFirst.1.trans firstLe
        have kReal : (k : Real) + 1 <= ((overshoots : Real) + 1) * rounds := by
          exact_mod_cast kLt
        have badReal : (badIn c : Real) <= overshoots := by exact_mod_cast badInLe c
        have kBound := mul_le_mul_of_nonneg_right kReal roundNonnegative
        have badBound := mul_le_mul_of_nonneg_right badReal jumpNonnegative
        have fits
            : time point + R + jump + 4 * maxDelay
              <= time origin + window initial electionTimeout maxDelay jump overshoots rounds := by
          rw [windowEq]; nlinarith
        rcases Round.duel_round (setup.roundSetup admissible startLe originFound found roundAt.1
            fits) with handoff | ⟨next, origin', point', lt, cFound, nextFound, capped,
              timeNext, roundNext, clean⟩
        · exact Or.inl (HandoffBy.mono_fresh freshLe
            (HandoffBy.shift startLe originFound found (by linarith) handoff))
        rw [found, Option.some.injEq] at cFound
        subst cFound
        have roundAt' := roundAt.next admissible lt capped roundNext
        by_cases dirty : exists index, index ∈ bad /\ c <= index /\ index < next
        · obtain ⟨index, member, lower, upper⟩ := dirty
          have grows := badInStep c next index member (startLe.trans lower) lower upper
          have growsReal : (badIn c : Real) + 1 <= badIn next := by exact_mod_cast grows
          have := mul_le_mul_of_nonneg_right growsReal jumpNonnegative
          refine Or.inr ⟨next, term + 1, point', nextFound, roundAt', ?_, ?_⟩
          · push_cast; nlinarith
          · have : chosen.filter (· < k + 1) ⊆ insert k (chosen.filter (· < k)) := by
              intro other
              simp only [Finset.mem_filter, Finset.mem_insert]
              rintro ⟨member', below⟩
              rcases Nat.lt_succ_iff_lt_or_eq.mp below with below | eq
              · exact Or.inr ⟨member', below⟩
              · exact Or.inl eq
            have := (Finset.card_le_card this).trans (Finset.card_insert_le _ _)
            omega
        · have cleanSteps
              : forall index step node,
                  node ∈ participants -> c <= index -> index < next
                  -> trace.stepAt index = some step -> NoOvershoot (some 0) step node := by
            intro index step node member lower upper stepped
            have within
                : Within trace start
                    (window initial electionTimeout maxDelay jump overshoots rounds) index := by
              refine ⟨startLe.trans lower, fun first' pointIndex firstFound indexFound => ?_⟩
              rw [originFound, Option.some.injEq] at firstFound
              subst firstFound
              have := admissible.time_le upper.le indexFound nextFound
              linarith
            have := overshoot index step node member within stepped
            simpa [show index ∉ bad from fun inBad => dirty ⟨index, inBad, lower, upper⟩]
              using this
          obtain ⟨timeClean, handoffOf⟩ := clean cleanSteps
          by_cases chosenK : k ∈ chosen
          · obtain ⟨block, below, eq⟩ := chosenBlock k chosenK
            have margin := pickMargin block below c term (eq ▸ roundAt)
            exact Or.inl (HandoffBy.mono_fresh freshLe
              (HandoffBy.shift startLe originFound found (by linarith) (handoffOf margin)))
          · have mono := badInMono c next lt.le
            have monoReal : (badIn c : Real) <= badIn next := by exact_mod_cast mono
            have := mul_le_mul_of_nonneg_right monoReal jumpNonnegative
            refine Or.inr ⟨next, term + 1, point', nextFound, roundAt', ?_, ?_⟩
            · push_cast; nlinarith
            · have : chosen.filter (· < k + 1) ⊆ chosen.filter (· < k) := by
                intro index
                simp only [Finset.mem_filter]
                rintro ⟨member, below⟩
                refine ⟨member, lt_of_le_of_ne (by omega) ?_⟩
                rintro rfl
                exact chosenK member
              have := Finset.card_le_card this
              omega
  rcases invariant total le_rfl with done | ⟨c, term, point, found, roundAt, timeC, countC⟩
  · exact done
  rw [Finset.filter_true_of_mem chosenLt, chosenCard] at countC
  have := badInLe c
  omega

end CCFRaft.Proofs.Duel.Resolve
