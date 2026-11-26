module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean
public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

-- This module is the adapter for the frame deliberately kept private by the proof.
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-!
# Full generated proof coverage

There are three kinds of questions: every state class before the step, every
step class, and every state class after the step. The predicates are exactly
the indexed dispatchers `Classes.ctx` and `Classes.sig`, with the same frame
projections as in `Classes.lean`. In particular `Classes.creates` is a separate
diagnostic, not one of the indexed questions.

The shared generator closes each branch telescope separately. Where a step
predicate uses `Ctx`, its own existential closure (possibly in a disjunct
for one of its call paths, including inside a `reach_*` definition) is part
of the predicate. Some step classes do not use `Ctx` at all. We do not
require one common `Ctx` to make the step bits true, nor evaluate the step
bits at the action that happened to witness reachability. This is a specification
of the generated *closed predicates*, not of a joint execution of branch lemmas.

A reader with the initial membership, folded ghost frame and post-state can
ask the frame questions. A reader given only the two full model states gets
the unordered set of whole profiles compatible with those states, hiding
the initial configuration, ambient node list, history and action. This
preserves correlations between questions across alternative histories.
Both specifications below are classical, not executable snapshot readers.
-/

namespace ConsensusCoverage.FullProfile

open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

meta section

/-- Read the nullary constructors from the generated index itself. All uses of
this array as an enumeration are checked below, not trusted to the elaborator. -/
elab "constructors%" ty:term:max : term => do
  let t ← Lean.Elab.Term.elabTerm ty none
  let i ← Lean.getConstInfoInduct t.constName!
  Lean.Meta.mkArrayLit t (i.ctors.map (fun name => Lean.mkConst name))

end

public section

set_option maxRecDepth 8192
set_option exponentiation.threshold 259

inductive Question
  | pre (branch : Classes.StateBranch)
  | step (branch : Classes.StepBranch)
  | post (branch : Classes.StateBranch)
  deriving DecidableEq

abbrev Profile := Question → Bool

@[expose] def Profile.pre (p : Profile) (b : Classes.StateBranch) : Bool := p (.pre b)
@[expose] def Profile.step (p : Profile) (b : Classes.StepBranch) : Bool := p (.step b)
@[expose] def Profile.post (p : Profile) (b : Classes.StateBranch) : Bool := p (.post b)

/-! ## Finite universes -/

@[expose] def stateBranches : Array Classes.StateBranch := constructors% Classes.StateBranch
@[expose] def stepBranches : Array Classes.StepBranch := constructors% Classes.StepBranch

theorem stateBranch_count : stateBranches.size = 2 := rfl
theorem stepBranch_count : stepBranches.size = 255 := rfl

@[expose] def questions : Array Question :=
  (stateBranches.map Question.pre ++ stepBranches.map Question.step) ++
    stateBranches.map Question.post

@[expose] def questionCount : Nat :=
  stateBranches.size + stepBranches.size + stateBranches.size

theorem question_count : questionCount = 259 := rfl

theorem questions_size : questions.size = questionCount := by
  simp only [questions, Array.size_append, Array.size_map, questionCount]

private theorem stateSlot_lt (b : Classes.StateBranch) : b.ctorIdx < stateBranches.size := by
  cases b <;> decide

set_option maxHeartbeats 0 in
private theorem stepSlot_lt (b : Classes.StepBranch) : b.ctorIdx < stepBranches.size := by
  cases b <;> decide

private theorem state_get (b : Classes.StateBranch) :
    stateBranches[b.ctorIdx]'(stateSlot_lt b) = b := by
  cases b <;> rfl

set_option maxHeartbeats 0 in
private theorem step_get (b : Classes.StepBranch) :
    stepBranches[b.ctorIdx]'(stepSlot_lt b) = b := by
  cases b <;> rfl

def Question.slot : Question → Fin questionCount
  | .pre b => ⟨b.ctorIdx, by
      have h := stateSlot_lt b
      simp only [questionCount]
      omega⟩
  | .step b => ⟨stateBranches.size + b.ctorIdx, by
      have h := stepSlot_lt b
      simp only [questionCount]
      omega⟩
  | .post b => ⟨stateBranches.size + stepBranches.size + b.ctorIdx, by
      have h := stateSlot_lt b
      simp only [questionCount]
      omega⟩

def questionAt (i : Fin questionCount) : Question := questions[i.val]'(questions_size.symm ▸ i.isLt)

@[simp] theorem questionAt_slot (q : Question) : questionAt q.slot = q := by
  have sz (f : Classes.StateBranch → Question) :
      (stateBranches.map f).size = stateBranches.size := Array.size_map
  have stepsz : (stepBranches.map Question.step).size = stepBranches.size := Array.size_map
  cases q with
  | pre b =>
    have h := stateSlot_lt b
    simp only [questionAt, Question.slot, questions]
    rw [Array.getElem_append_left (by simp only [Array.size_append, sz, stepsz]; omega)]
    rw [Array.getElem_append_left (by simpa only [sz] using h), Array.getElem_map, state_get]
  | step b =>
    have h := stepSlot_lt b
    simp only [questionAt, Question.slot, questions]
    rw [Array.getElem_append_left (by simp only [Array.size_append, sz, stepsz]; omega)]
    rw [Array.getElem_append_right (by simp only [sz]; omega), Array.getElem_map]
    simp only [sz, Nat.add_sub_cancel_left, step_get]
  | post b =>
    simp only [questionAt, Question.slot, questions]
    rw [Array.getElem_append_right (by simp only [Array.size_append, sz, stepsz]; omega),
      Array.getElem_map]
    simp only [Array.size_append, sz, stepsz, Nat.add_sub_cancel_left, state_get]

set_option maxHeartbeats 0 in
theorem slot_questionAt : ∀ i : Fin questionCount, (questionAt i).slot = i := by
  decide +kernel

-- Keep the width of the second bit-vector symbolic; the kernel must not try
-- to compute a natural number with profileCapacity binary digits.
private opaque profileSpace : {n : Nat // n = Nat.pow 2 questionCount} :=
  ⟨Nat.pow 2 questionCount, rfl⟩

def profileCapacity : Nat := profileSpace.val

theorem profileCapacity_eq : profileCapacity = Nat.pow 2 questionCount :=
  profileSpace.property

theorem profile_capacity : profileCapacity = Nat.pow 2 259 :=
  profileCapacity_eq.trans (congrArg (Nat.pow 2) question_count)

private def encodeBits {n : Nat} (f : Fin n → Bool) : BitVec n :=
  (BitVec.ofBoolListLE (List.ofFn f)).cast List.length_ofFn

private theorem encodeBits_get {n : Nat} (f : Fin n → Bool) (i : Fin n) :
    (encodeBits f).getLsbD i.val = f i := by
  simp only [encodeBits, BitVec.getLsbD_cast, BitVec.getLsbD_ofBoolListLE, List.getD_eq_getElem?_getD]
  rw [List.getElem?_eq_getElem (by simpa only [List.length_ofFn] using i.isLt)]
  simp

def profileCode (p : Profile) : BitVec questionCount :=
  encodeBits fun i => p (questionAt i)

def profileOfCode (b : BitVec questionCount) : Profile :=
  fun q => b.getLsbD q.slot.val

@[simp] theorem profileOfCode_code (p : Profile) : profileOfCode (profileCode p) = p := by
  funext q
  simp only [profileOfCode, profileCode, encodeBits_get, questionAt_slot]

theorem profileCode_injective : Function.Injective profileCode :=
  fun _ _ h => by simpa only [profileOfCode_code] using congrArg profileOfCode h

@[simp] theorem profileCode_ofCode (b : BitVec questionCount) :
    profileCode (profileOfCode b) = b := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  let k : Fin questionCount := ⟨i, hi⟩
  change (encodeBits fun j => profileOfCode b (questionAt j)).getLsbD k.val = b.getLsbD k.val
  rw [encodeBits_get]
  simp only [profileOfCode, slot_questionAt]

abbrev Configuration := CCF.Finset NodeID
/-- The proof's actual frame, not a reconstruction from `Inv`. -/
abbrev ProofFrame := Frame

def questionHolds (cfg : Configuration) (f : ProofFrame) (after : Model.State) :
    Question → Prop :=
  letI : Config.InitialConfiguration := ⟨cfg⟩
  fun
    | .pre b => Classes.ctx f b
    | .step b => Classes.sig f after b
    | .post b => Classes.ctx (Frame.advance f after) b

noncomputable def frameProfile (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) : Profile :=
  fun q => @decide (questionHolds cfg f after q) (Classical.propDecidable _)

@[simp] theorem frameProfile_true (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (q : Question) :
    frameProfile cfg f after q = true ↔ questionHolds cfg f after q :=
  @decide_eq_true_iff _ (Classical.propDecidable _)

theorem frameProfile_pre (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (b : Classes.StateBranch) :
    (frameProfile cfg f after).pre b = true ↔ questionHolds cfg f after (.pre b) :=
  frameProfile_true cfg f after _

theorem frameProfile_step (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (b : Classes.StepBranch) :
    (frameProfile cfg f after).step b = true ↔ questionHolds cfg f after (.step b) :=
  frameProfile_true cfg f after _

theorem frameProfile_post (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (b : Classes.StateBranch) :
    (frameProfile cfg f after).post b = true ↔ questionHolds cfg f after (.post b) :=
  frameProfile_true cfg f after _

private theorem bool_eq_iff_true_iff (a b : Bool) : a = b ↔ (a = true ↔ b = true) := by
  cases a <;> cases b <;> decide

theorem frameProfile_eq_iff {cfg cfg' : Configuration} {f f' : ProofFrame}
    {after after' : Model.State} :
    frameProfile cfg f after = frameProfile cfg' f' after' ↔
      ∀ q, questionHolds cfg f after q ↔ questionHolds cfg' f' after' q := by
  simp only [← frameProfile_true]
  constructor
  · intro eq q
    rw [eq]
  · intro h
    funext q
    exact (bool_eq_iff_true_iff _ _).mpr (h q)

abbrev system (cfg : Configuration) (nodes : List NodeID) :=
  Model.transitionSystem cfg nodes

def startFrame (cfg : Configuration) (s : Model.State) : ProofFrame :=
  letI : Config.InitialConfiguration := ⟨cfg⟩
  Frame.start s

def advanceFrame (cfg : Configuration) (f : ProofFrame) (after : Model.State) : ProofFrame :=
  letI : Config.InitialConfiguration := ⟨cfg⟩
  Frame.advance f after

def current (f : ProofFrame) : Model.State := Frame.current f

@[simp] theorem current_startFrame (cfg : Configuration) (s : Model.State) :
    current (startFrame cfg s) = s := by unfold current startFrame; rfl

@[simp] theorem current_advanceFrame (cfg : Configuration) (f : ProofFrame) (s : Model.State) :
    current (advanceFrame cfg f s) = s := by unfold current advanceFrame; rfl

theorem questionHolds_pre (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (b : Classes.StateBranch) :
    questionHolds cfg f after (.pre b) ↔
      (letI : Config.InitialConfiguration := ⟨cfg⟩; Classes.ctx f b) := by
  unfold questionHolds
  exact Iff.rfl

theorem questionHolds_step (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (b : Classes.StepBranch) :
    questionHolds cfg f after (.step b) ↔
      (letI : Config.InitialConfiguration := ⟨cfg⟩; Classes.sig f after b) := by
  unfold questionHolds
  exact Iff.rfl

theorem questionHolds_post (cfg : Configuration) (f : ProofFrame)
    (after : Model.State) (b : Classes.StateBranch) :
    questionHolds cfg f after (.post b) ↔
      (letI : Config.InitialConfiguration := ⟨cfg⟩; Classes.ctx (advanceFrame cfg f after) b) := by
  unfold questionHolds advanceFrame
  exact Iff.rfl

/-- The inductive graph of folding the proof's actual frame updates over an
initialized sequence of successful model steps. `Inv` alone is not enough. -/
inductive Folded (cfg : Configuration) (nodes : List NodeID) : ProofFrame → Prop where
  | initial {s : Model.State} (init : (system cfg nodes).init s) :
      Folded cfg nodes (startFrame cfg s)
  | step {f : ProofFrame} {action : Model.Action} {after : Model.State}
      (prior : Folded cfg nodes f)
      (ran : (system cfg nodes).step (current f) action = some after) :
      Folded cfg nodes (advanceFrame cfg f after)

theorem Folded.reachable {cfg : Configuration} {nodes : List NodeID} {f : ProofFrame}
    (h : Folded cfg nodes f) : (system cfg nodes).Reachable (current f) := by
  induction h with
  | initial h => exact .initial h
  | step _ ran ih => exact .step ih ran

theorem folded_of_reachable {cfg : Configuration} {nodes : List NodeID} {s : Model.State}
    (h : (system cfg nodes).Reachable s) :
    ∃ f : ProofFrame, Folded cfg nodes f ∧ current f = s := by
  induction h using (@CCF.TransitionSystem.Reachable.rec (system cfg nodes)) with
  | initial init => exact ⟨startFrame cfg _, .initial init, rfl⟩
  | step _ ran ih =>
    obtain ⟨f, folded, rfl⟩ := ih
    exact ⟨advanceFrame cfg f _, .step folded ran, rfl⟩

theorem Folded.invariant {cfg : Configuration} {nodes : List NodeID} {f : ProofFrame}
    (h : Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    Inv f := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  change Inv f
  induction h with
  | initial init => exact inv_initial init
  | step _ ran ih =>
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    exact (Ctx.mk tr ih).inv_step

/-- Full model-state pairs for which some allowed configuration and execution
have a successful last step between the two states, including stutters. -/
def IsReachableStep (before after : Model.State) : Prop :=
  ∃ (cfg : Configuration) (nodes : List NodeID) (action : Model.Action),
    (system cfg nodes).Reachable before ∧ (system cfg nodes).step before action = some after

abbrev ReachableStep :=
  {pair : Model.State × Model.State // IsReachableStep pair.1 pair.2}

abbrev Observation := Profile → Prop

/-- Capacity of the universe of *all* sets of profiles; not a reachable row count. -/
def observationCapacity : Nat := Nat.pow 2 profileCapacity

/-- Combine with `profile_capacity` for the bound `2 ^ (2 ^ 259)`. The
exponent is left symbolic so a kernel reduction cannot expand this bound. -/
theorem observation_capacity {n : Nat} (h : profileCapacity = n) :
    observationCapacity = Nat.pow 2 n :=
  congrArg (Nat.pow 2) h

noncomputable def observationBits (o : Observation) : BitVec profileCapacity :=
  encodeBits fun i =>
    @decide (o (profileOfCode (BitVec.ofFin (i.cast profileCapacity_eq))))
      (Classical.propDecidable _)

def observationOfBits (b : BitVec profileCapacity) : Observation :=
  fun p => b.getLsbD (profileCode p).toNat = true

@[simp] theorem observationOfBits_bits (o : Observation) :
    observationOfBits (observationBits o) = o := by
  funext p
  apply propext
  let i := (profileCode p).toFin.cast profileCapacity_eq.symm
  change (encodeBits _).getLsbD i.val = true ↔ o p
  have hi : i.cast profileCapacity_eq = (profileCode p).toFin := Fin.ext rfl
  have hp : profileOfCode (BitVec.ofFin (i.cast profileCapacity_eq)) = p := by
    rw [hi, BitVec.ofFin_toFin, profileOfCode_code]
  rw [encodeBits_get, hp]
  exact @decide_eq_true_iff _ (Classical.propDecidable _)

@[simp] theorem observationBits_ofBits (b : BitVec profileCapacity) :
    observationBits (observationOfBits b) = b := by
  apply BitVec.eq_of_getLsbD_eq
  intro k hk
  let i : Fin profileCapacity := ⟨k, hk⟩
  change (encodeBits _).getLsbD i.val = b.getLsbD i.val
  rw [encodeBits_get]
  apply (bool_eq_iff_true_iff _ _).mpr
  rw [@decide_eq_true_iff _ (Classical.propDecidable _)]
  unfold observationOfBits
  rw [profileCode_ofCode]
  rfl

noncomputable def observationCode (o : Observation) : Fin observationCapacity :=
  (observationBits o).toFin

theorem observationCode_injective : Function.Injective observationCode := by
  intro o o' eq
  have bits : observationBits o = observationBits o' := BitVec.toFin_inj.mp eq
  simpa only [observationOfBits_bits] using congrArg observationOfBits bits

/-- A membership question asks for an entire row on one compatible execution,
not independent witnesses for individual coordinates in different frames. -/
@[expose] def Compatible (before after : Model.State) (p : Profile) : Prop :=
  ∃ (cfg : Configuration) (nodes : List NodeID) (f : ProofFrame) (action : Model.Action),
    Folded cfg nodes f ∧ current f = before ∧
      (system cfg nodes).step before action = some after ∧ frameProfile cfg f after = p

@[expose] def observe (before after : Model.State) : Observation := Compatible before after

instance : Membership Profile Observation where
  mem o p := o p

theorem mem_observe_iff {before after : Model.State} {p : Profile} :
    p ∈ observe before after ↔
      ∃ (cfg : Configuration) (nodes : List NodeID) (f : ProofFrame) (action : Model.Action),
        Folded cfg nodes f ∧ current f = before ∧
          (system cfg nodes).step before action = some after ∧
          ∀ q, p q = true ↔ questionHolds cfg f after q := by
  change Compatible before after p ↔ _
  simp only [Compatible]
  constructor
  · rintro ⟨cfg, nodes, f, action, folded, curr, ran, rfl⟩
    exact ⟨cfg, nodes, f, action, folded, curr, ran, frameProfile_true cfg f after⟩
  · rintro ⟨cfg, nodes, f, action, folded, curr, ran, bits⟩
    refine ⟨cfg, nodes, f, action, folded, curr, ran, ?_⟩
    funext q
    exact (bool_eq_iff_true_iff _ _).mpr ((frameProfile_true cfg f after q).trans (bits q).symm)

theorem observe_nonempty_iff {before after : Model.State} :
    (∃ p, p ∈ observe before after) ↔ IsReachableStep before after := by
  constructor
  · rintro ⟨_, cfg, nodes, f, action, folded, rfl, ran, _⟩
    exact ⟨cfg, nodes, action, folded.reachable, ran⟩
  · rintro ⟨cfg, nodes, action, reached, ran⟩
    obtain ⟨f, folded, curr⟩ := folded_of_reachable reached
    exact ⟨frameProfile cfg f after, cfg, nodes, f, action, folded, curr, ran, rfl⟩

@[expose] def classify (s : ReachableStep) : Observation := observe s.val.1 s.val.2

def Indistinguishable (s t : ReachableStep) : Prop :=
  ∀ p, p ∈ classify s ↔ p ∈ classify t

theorem classify_eq_iff {s t : ReachableStep} :
    classify s = classify t ↔ Indistinguishable s t := by
  constructor
  · intro eq p
    rw [eq]
  · exact fun h => funext fun p => propext (h p)

/-- Exactly the realized observation labels, excluding unreachable sets. -/
abbrev Realized := {o : Observation // ∃ s : ReachableStep, classify s = o}

def realized (s : ReachableStep) : Realized := ⟨classify s, s, rfl⟩

theorem realized_eq_iff {s t : ReachableStep} :
    realized s = realized t ↔ Indistinguishable s t :=
  ⟨fun h => classify_eq_iff.mp (congrArg Subtype.val h),
    fun h => Subtype.ext (classify_eq_iff.mpr h)⟩

theorem realized_surjective : ∀ r : Realized, ∃ s, realized s = r := by
  rintro ⟨_, s, rfl⟩
  exact ⟨s, rfl⟩

def stepSetoid : Setoid ReachableStep where
  r := Indistinguishable
  iseqv := ⟨fun _ => classify_eq_iff.mp rfl,
    fun h => classify_eq_iff.mp (classify_eq_iff.mpr h).symm,
    fun h h' => classify_eq_iff.mp ((classify_eq_iff.mpr h).trans (classify_eq_iff.mpr h'))⟩

abbrev CoverageQuotient := Quotient stepSetoid

def quotientObservation : CoverageQuotient → Realized :=
  Quotient.lift realized fun _ _ h => realized_eq_iff.mpr h

theorem quotientObservation_bijective :
    Function.Injective quotientObservation ∧ Function.Surjective quotientObservation := by
  constructor
  · intro l r
    induction l using Quotient.inductionOn with
    | _ s =>
      induction r using Quotient.inductionOn with
      | _ t =>
        intro same
        exact Quotient.sound (realized_eq_iff.mp same)
  · intro r
    obtain ⟨s, same⟩ := realized_surjective r
    exact ⟨Quotient.mk _ s, same⟩

noncomputable def quotientCode (q : CoverageQuotient) : Fin observationCapacity :=
  observationCode (quotientObservation q).val

theorem quotientCode_injective : Function.Injective quotientCode :=
  fun _ _ eq => quotientObservation_bijective.1
    (Subtype.ext (observationCode_injective eq))

/-- Any classifier that decodes the whole observation has at least one
distinct label for each realized observation. No finiteness assumption on
the competing classifier is needed. -/
theorem faithful_lower_bound {α : Type u} (encode : ReachableStep → α)
    (decode : α → Observation) (faithful : ∀ s, decode (encode s) = classify s) :
    ∃ inject : Realized → α, Function.Injective inject := by
  let choose (r : Realized) : ReachableStep := Classical.choose r.property
  refine ⟨fun r => encode (choose r), ?_⟩
  intro r r' eq
  apply Subtype.ext
  calc
    r.val = classify (choose r) := (Classical.choose_spec r.property).symm
    _ = decode (encode (choose r)) := (faithful _).symm
    _ = decode (encode (choose r')) := congrArg decode eq
    _ = classify (choose r') := faithful _
    _ = r'.val := Classical.choose_spec r'.property

/-- A candidate table proves the actual denominator by giving both the
exclusion theorem and a real execution witness for every distinct row. -/
structure ExactTable (rows : List Observation) : Prop where
  nodup : rows.Nodup
  complete : ∀ s : ReachableStep, classify s ∈ rows
  witnessed : ∀ o ∈ rows, ∃ s : ReachableStep, classify s = o

theorem ExactTable.mem_iff {rows : List Observation} (h : ExactTable rows) (o : Observation) :
    o ∈ rows ↔ ∃ s : ReachableStep, classify s = o := by
  exact ⟨h.witnessed o, fun ⟨s, eq⟩ => eq ▸ h.complete s⟩

theorem ExactTable.length_eq {rows rows' : List Observation}
    (h : ExactTable rows) (h' : ExactTable rows') : rows.length = rows'.length := by
  apply Nat.le_antisymm
  · exact h.nodup.length_le_of_subset fun {a} ha => (h'.mem_iff a).mpr ((h.mem_iff a).mp ha)
  · exact h'.nodup.length_le_of_subset fun {a} ha => (h.mem_iff a).mpr ((h'.mem_iff a).mp ha)

/-- The finite universe yields existence, but not a computable enumeration or
an evaluated number. To establish a particular denominator, supply an
`ExactTable` for concrete rows and prove its length. -/
theorem exists_exactTable :
    ∃ rows : List Observation, ExactTable rows ∧ rows.length ≤ observationCapacity := by
  classical
  let decode (i : Fin observationCapacity) : Option Observation :=
    if h : ∃ o : Realized, observationCode o.val = i then
      some (Classical.choose h).val
    else none
  have sound {i o} (h : decode i = some o) :
      (∃ s : ReachableStep, classify s = o) ∧ observationCode o = i := by
    unfold decode at h
    split at h
    · rename_i found
      obtain rfl := Option.some.inj h
      exact ⟨(Classical.choose found).property, Classical.choose_spec found⟩
    · contradiction
  have complete (o : Realized) : decode (observationCode o.val) = some o.val := by
    have h : ∃ r : Realized, observationCode r.val = observationCode o.val := ⟨o, rfl⟩
    unfold decode
    rw [dite_eq_left h, observationCode_injective (Classical.choose_spec h)]
  let indices := List.finRange observationCapacity
  refine ⟨indices.filterMap decode, ⟨?_, ?_, ?_⟩, ?_⟩
  · apply (List.nodup_finRange _).filterMap decode
    intro i j ne o ho o' ho' eq
    subst o'
    exact ne ((sound ho).2.symm.trans (sound ho').2)
  · intro s
    exact List.mem_filterMap.mpr ⟨_, List.mem_finRange _, complete (realized s)⟩
  · intro o mem
    obtain ⟨_, _, h⟩ := List.mem_filterMap.mp mem
    exact (sound h).1
  · simpa only [indices, List.length_finRange] using List.length_filterMap_le decode indices

theorem ExactTable.length_le_capacity {rows : List Observation} (h : ExactTable rows) :
    rows.length ≤ observationCapacity := by
  obtain ⟨_, table, bound⟩ := exists_exactTable
  rw [h.length_eq table]
  exact bound

theorem ExactTable.length_le_of_decoder {rows : List Observation} (h : ExactTable rows)
    {n : Nat} (encode : ReachableStep → Fin n) (decode : Fin n → Observation)
    (faithful : ∀ s, decode (encode s) = classify s) : rows.length ≤ n := by
  obtain ⟨embed, injective⟩ := faithful_lower_bound encode decode faithful
  let code (r : {o // o ∈ rows}) : Fin n := embed ⟨r.val, h.witnessed r.val r.property⟩
  have code_injective : Function.Injective code := by
    intro r r' eq
    exact Subtype.ext (congrArg (fun o : Realized => o.val) (injective eq))
  have attached : rows.attach.Nodup := by
    apply List.Pairwise.of_map (S := (· ≠ ·)) Subtype.val
      (fun _ _ hne eq => hne (congrArg Subtype.val eq))
    rw [List.attach_map_subtype_val]
    exact List.nodup_iff_pairwise_ne.mp h.nodup
  have distinct : (rows.attach.map code).Nodup :=
    attached.map code (fun _ _ ne eq => ne (code_injective eq))
  have bound := distinct.length_le_of_subset (l₂ := List.finRange n) fun {i} _ =>
    List.mem_finRange i
  simpa using bound

end

end ConsensusCoverage.FullProfile
