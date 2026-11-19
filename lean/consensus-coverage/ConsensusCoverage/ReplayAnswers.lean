module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionFrontier
public import ConsensusCoverage.CommitKeys
public import ConsensusCoverage.DeltaSupport
public import ConsensusCoverage.EventSupport
public import ConsensusCoverage.GuardedQuestions
public import ConsensusCoverage.ReducedQuestions
public import ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.ActionFrontier
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.Projection
import all ConsensusCoverage.StutterProfile

namespace ConsensusCoverage.ReplayAnswers

open ActionProfile FullProfile Consensus

/-- Values shared by all questions at a validated action boundary. -/
public structure Evidence where
  key : FrontierRows.Row × Bool
  tag : EventSupport.Tag
  fresh : List Model.Node.Message
  view : Option GuardedDomain.View
  freshCommit : Bool
  inert : Bool
  delta : DeltaSupport.Evidence

public def read (cfg : Configuration) (s : Model.State) (a : Model.Action)
    (t : Model.State) (past : List Model.State) : Evidence :=
  let view := GuardedDomain.ofAction cfg s t past a
  let noNew := CommitKeys.noNew (cfg.min?.getD 0) t (s :: past)
  ⟨(FrontierRows.historyLabel cfg s t past, LeaderEffect.changedPrimary s t),
    EventSupport.actionTag a, ReducedQuestions.freshPayloads s t.network,
    view, !noNew, SignedQuiet.test view s t noNew, DeltaSupport.read s a t⟩

private def direct (k : FrontierRows.Row × Bool) (freshCommit : Bool) : Classes.StepBranch → Option Bool
  | .leader_led_leader_inr => some k.1.wonPrimary
  | .leader_led_now_after_inl => some k.2
  | .leader_led_leader_inl => some (k.2 && !k.1.wonPrimary)
  | .commitChains_step_committed_inr => some freshCommit
  | _ => none

/-- `none` is an unknown coordinate, not a negative answer. -/
public def answer (e : Evidence) : Question → Option Bool
  | .pre b => some (ProofContexts.answers (e.key.1.zeroBefore, e.key.1.backedBefore) b)
  | .post b => some (ProofContexts.answers (e.key.1.zeroAfter, e.key.1.backedAfter) b)
  | .step b => (e.view.bind (GuardedQuestions.answer · b)).orElse fun _ =>
      (ReducedQuestions.readFrom? e.fresh b).orElse fun _ => (direct e.key e.freshCommit b).orElse fun _ =>
      if e.inert || decide (e.tag ∉ EventSupport.allowed b) || DeltaSupport.excluded e.delta b then some false else none

private theorem direct_sound (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : direct (ActionFrontier.project (label s))
      (read s.cfg s.before s.act s.after s.past).freshCommit b = some v) : label s (.step b) = v := by
  generalize key : ActionFrontier.project (label s) = k at h
  have won := congrArg (fun (p : FrontierRows.Row × Bool) => p.1.wonPrimary) key
  have changed := congrArg Prod.snd key
  have incumbent := ActionFrontier.incumbent_eq s
  rw [key] at incumbent
  cases b <;> first | exact won.trans (Option.some.inj h) | exact changed.trans (Option.some.inj h)
                    | exact incumbent.trans (Option.some.inj h)
                    | exact (CommitKeys.fresh_answer s).symm.trans (Option.some.inj h) | contradiction

public theorem sound (s : Step) (q : Question) {v : Bool}
    (known : answer (read s.cfg s.before s.act s.after s.past) q = some v) : label s q = v := by
  cases q with
  | pre b => exact (congrFun (pre_answers s) b).trans (Option.some.inj known)
  | post b => exact (congrFun (post_answers s) b).trans (Option.some.inj known)
  | step b =>
    change (Option.orElse (GuardedQuestions.read? s.cfg s.before s.after s.past s.act b) _) = some v at known
    cases g : GuardedQuestions.read? s.cfg s.before s.after s.past s.act b
    case some res => exact (GuardedQuestions.read?_correct s b g).trans (by simpa [g] using known)
    simp only [g, Option.orElse_none, read, ← ActionFrontier.project_eq] at known
    rw [show ReducedQuestions.readFrom? (ReducedQuestions.freshPayloads s.before s.after.network) b =
      ReducedQuestions.read? s.before s.after b from rfl] at known
    cases queue : ReducedQuestions.read? s.before s.after b with
    | some res =>
      have eq := ((ReducedQuestions.read?_correct s b res).mp queue).2
      exact eq.symm.trans (by simpa [queue] using known)
    | none =>
      simp only [queue, Option.orElse_none] at known
      cases h : direct (ActionFrontier.project (label s))
          (!CommitKeys.noNew _ s.after (s.before :: s.past)) b with
      | some res => exact (direct_sound s b h).trans (by simpa [h] using known)
      | none =>
        simp only [h, Option.orElse_none] at known
        split at known
        · rename_i excluded
          simp only [Bool.or_eq_true, decide_eq_true_eq] at excluded
          rcases excluded with (inert | tag) | delta
          · exact (congrFun (SignedQuiet.gate_sound s inert) (.step b)).trans (Option.some.inj known)
          · exact (EventSupport.label_false s b tag).trans (Option.some.inj known)
          · exact (DeltaSupport.label_false s b delta).trans (Option.some.inj known)
        · contradiction

/-- Columns the reader settles on every step, without needing a tag exclusion. -/
public def unconditional : List Classes.StepBranch :=
  GuardedQuestions.covered ++ (ReducedQuestions.covered ++ [.leader_led_leader_inr,
    .leader_led_now_after_inl, .leader_led_leader_inl, .commitChains_step_committed_inr])

public theorem unconditional_count : unconditional.Nodup ∧ unconditional.length = 34 := by decide

public theorem read_unconditional (s : Step) {b : Classes.StepBranch} (mem : b ∈ unconditional) :
    answer (read s.cfg s.before s.act s.after s.past) (.step b) = some (label s (.step b)) := by
  have enough (h : (answer (read s.cfg s.before s.act s.after s.past) (.step b)).isSome) :
      answer (read s.cfg s.before s.act s.after s.past) (.step b) = some (label s (.step b)) := by
    obtain ⟨v, eq⟩ := Option.isSome_iff_exists.mp h
    rw [sound s (.step b) eq, eq]
  apply enough
  change ((GuardedQuestions.read? s.cfg s.before s.after s.past s.act b).orElse _).isSome
  rcases List.mem_append.mp mem with guardCol | mem
  · rw [GuardedQuestions.read?_at s guardCol]
    rfl
  cases g : GuardedQuestions.read? s.cfg s.before s.after s.past s.act b
  case some => rfl
  change ((ReducedQuestions.read? s.before s.after b).orElse _).isSome
  rcases List.mem_append.mp mem with queue | leaderCol
  · rw [(ReducedQuestions.read?_correct s b _).mpr ⟨queue, (rfl : _ = label s (.step b))⟩]
    rfl
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at leaderCol
    cases h : ReducedQuestions.read? s.before s.after b with
    | some _ => rfl
    | none => rcases leaderCol with rfl | rfl | rfl | rfl <;> rfl

/-- Membership in the three-row all-false slice. One positive bit excludes
the whole row; an unknown bit is not evidence that the action belongs. -/
public def quietFrom (inert : Bool) (atQuestion : Question → Option Bool) : Option Bool :=
  if inert then some true else
  let bits := stepBranches.toList.map fun b => atQuestion (.step b)
  if some true ∈ bits then some false else if none ∈ bits then none else some true

public def quiet? (e : Evidence) : Option Bool := quietFrom e.inert (answer e)

public theorem quiet?_sound (s : Step) {v : Bool}
    (known : quiet? (read s.cfg s.before s.act s.after s.past) = some v) :
    label s ∈ ZeroRows.table ↔ v = true := by
  rw [SignedQuiet.exact, and_iff_right (show Realized (label s) from ⟨s, rfl⟩)]
  let e := read s.cfg s.before s.act s.after s.past
  change quiet? e = some v at known
  unfold quiet? quietFrom at known
  split at known
  · rename_i inert
    cases known
    exact ⟨fun _ => rfl, fun _ => congrArg Profile.step (SignedQuiet.gate_sound s inert)⟩
  dsimp only at known
  split at known
  · rename_i pos
    cases known
    obtain ⟨b, _, bit⟩ := List.mem_map.mp pos
    exact ⟨fun zero => (congrFun zero b).symm.trans (sound s (.step b) bit), Bool.noConfusion⟩
  · rename_i noPos
    split at known
    · contradiction
    · rename_i noUnknown
      cases known
      refine ⟨fun _ => rfl, fun _ => funext fun b => ?_⟩
      have mem : b ∈ stepBranches.toList := by
        rw [← step_get b]
        exact Array.getElem_mem_toList ..
      cases bit : answer e (.step b) with
      | none => exact (noUnknown (List.mem_map.mpr ⟨b, mem, bit⟩)).elim
      | some out =>
        cases out
        · exact sound s (.step b) bit
        · exact (noPos (List.mem_map.mpr ⟨b, mem, bit⟩)).elim

end ConsensusCoverage.ReplayAnswers
