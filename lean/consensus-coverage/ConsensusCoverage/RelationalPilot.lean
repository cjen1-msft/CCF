module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Classes
public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.ClauseQuestions
public import ConsensusCoverage.Historical
public import ConsensusCoverage.GrantMonitor
public import ConsensusCoverage.Schedule
public import ConsensusCoverage.KernelLRAT
import all ConsensusCoverage.Classes
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.Historical
import all ConsensusCoverage.GrantMonitor
import all Consensus.Proofs.SafetyInvariant

/-!
# Bottom-up relational query compiler (Milestone 1 pilot on the frozen 255 schema)

Demonstrates Astra's bottom-up relational architecture directly on **raw `Classes.sig`**
(never substituting one-way `PinnedClasses` results for raw semantics):

1. **Shared opaque reach interfaces:** `reach_2` and `reach_31..34` are compiled **once**
   into opaque interface theorems (`reach_2_iff`, `reach_31_iff`). Downstream step classes
   compose those opaque theorems without unfolding transitive `reach_*` definitions.
2. **Fresh-actor agreement bridge (`fresh_ctx_agree`):** generalizes `LedPilot.lean` to
   connect raw `∃ d : Ctx f t, ...` to the step's concrete actor/pre/post fields whenever a
   fresh post-state node record is witnessed — with zero unique-action assumptions.
3. **End-to-end raw `Classes.sig` iff + executable readers:**
   - `step_led_cur_led_cur_inl` (from `reach_2` + `fresh_ctx_agree` + `GrantMonitor.led`),
   - `step_led_cur_led_cur_inr` (second step class reusing the **same** opaque `reach_2_iff`
     interface without unfolding `reach_2`),
   - `step_led_cur_now_after_inl` (third step class reusing `reach_2_iff`),
   - `step_unique_now_after_inl` and `step_unique_now_after_inr` (using `reach_31_iff`),
   - plus kernel-checked **positive and negative** initialized replay examples on concrete
     `Schedule` runs.
4. **First raw frozen-255 clause closure via `KernelLRAT`:** closes `Clause.observed` (exact
   1 row) and the `unique_now_after` 2-bit raw projection (`{FF, TF}` / `{FF, TF, TT}` etc.)
   purely via `KernelLRAT.mem_rows_of_checkProof` + `decide +kernel`, standard axioms only.
-/

namespace ConsensusCoverage.RelationalPilot

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage ConsensusCoverage.Classes

set_option autoImplicit false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-! ## 1. Reusable fresh-actor agreement bridge (raw `∃ d : Ctx f t` → concrete step fields) -/

/-- Whenever any alternative context `d : Ctx f t` produces a fresh post-state actor record
`¬ Now f d.actor d.post`, it must agree with the step's concrete context `c : Ctx f t` on
`actor`, `pre`, and `post`. No unique-action assumption is needed. -/
private theorem fresh_ctx_agree [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c d : Ctx f t) (fresh : ¬ Now f d.actor d.post) :
    d.actor = c.actor ∧ d.post = c.post ∧ d.pre = c.pre := by
  rcases c.now_after d.post_now with ⟨hActor, hPost⟩ | ⟨_, hOld⟩
  · have hPre : d.pre = c.pre := c.now_pre (hActor ▸ d.pre_now)
    exact ⟨hActor, hPost, hPre⟩
  · exact (fresh hOld).elim

/-! ## 2. Shared opaque reach interfaces (compiled once, reused by multiple step classes) -/

/-- Opaque interface for `reach_2`: a fresh `(node, state, term)` leadership-at-current pair. -/
private theorem reach_2_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (n : NodeID) (s : NodeState) (k : Nat) :
    reach_2 f t c n s k ↔
      Now (f.advance t) n s ∧ Led (f.advance t) n k ∧ ¬ (Now f n s ∧ Led f n k) := by
  constructor
  · rintro ⟨_, _, _, _, hNow, hLed, hFresh, rfl, rfl, rfl, rfl⟩
    exact ⟨hNow, hLed, hFresh⟩
  · rintro ⟨hNow, hLed, hFresh⟩
    exact ⟨c, n, s, k, hNow, hLed, hFresh, rfl, rfl, rfl, rfl⟩

/-- Opaque interface for `reach_31`: a fresh node-uniqueness witness pair at `t`. -/
private theorem reach_31_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    reach_31 f t c ↔
      ∃ node first second,
        Now (f.advance t) node first ∧ Now (f.advance t) node second ∧
        ¬ (Now f node first ∧ Now f node second) := by
  constructor
  · rintro ⟨_, node, first, second, h1, h2, hFresh, rfl⟩
    exact ⟨node, first, second, h1, h2, hFresh⟩
  · rintro ⟨node, first, second, h1, h2, hFresh⟩
    exact ⟨c, node, first, second, h1, h2, hFresh, rfl⟩

/-! ## 3. Three raw `Classes.sig` predicates composing the single opaque `reach_2_iff` interface -/

/-- Class 1 (`step_led_cur_led_cur_inl`): raw semantics bridged via `reach_2_iff` and
`fresh_ctx_agree`, without unfolding `reach_2`. -/
private theorem raw_led_cur_inl_at [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    Classes.sig f t .led_cur_led_cur_inl ↔
      ¬ Now f c.actor c.post ∧ ∃ k, k < c.pre.currentTerm ∧ Led f c.actor k := by
  change step_led_cur_led_cur_inl f t ↔ _
  constructor
  · rintro ⟨d, _, _, k, site, _, ⟨rfl, rfl⟩, _, _, _, _, hLed, _, hLt, _⟩
    have hFresh : ¬ Now f d.actor d.post := fun hOld =>
      ((reach_2_iff d d.actor d.post k).mp site).2.2 ⟨hOld, hLed⟩
    obtain ⟨hActor, hPost, hPre⟩ := fresh_ctx_agree c d hFresh
    exact ⟨by simpa only [hActor, hPost] using hFresh, k,
      by simpa only [hPre] using hLt, by simpa only [hActor] using hLed⟩
  · rintro ⟨hFresh, k, hLt, hLed⟩
    have hNow := c.post_now
    have hAfterLed := hLed.mono t
    have site := (reach_2_iff c c.actor c.post k).mpr ⟨hNow, hAfterLed, fun h => hFresh h.1⟩
    exact ⟨c, c.actor, c.post, k, site, hLed, ⟨rfl, rfl⟩, rfl, rfl, hNow, hAfterLed, hLed,
      hNow, hLt, hNow, hAfterLed, c.term_le⟩

/-- Class 2 (`step_led_cur_led_cur_inr`): reuses the **same** opaque `reach_2_iff` and
`fresh_ctx_agree` theorems without unfolding `reach_2`. -/
private theorem raw_led_cur_inr_at [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    Classes.sig f t .led_cur_led_cur_inr ↔
      ¬ Now f c.actor c.post ∧ c.pre.role ≠ .candidate ∧ Led f c.actor c.pre.currentTerm := by
  change step_led_cur_led_cur_inr f t ↔ _
  constructor
  · rintro ⟨d, _, _, k, site, _, ⟨rfl, rfl⟩, _, _, _, _, hLed, _, ⟨rfl, hRole⟩, _⟩
    have hFresh : ¬ Now f d.actor d.post := fun hOld =>
      ((reach_2_iff d d.actor d.post d.pre.currentTerm).mp site).2.2 ⟨hOld, hLed⟩
    obtain ⟨hActor, hPost, hPre⟩ := fresh_ctx_agree c d hFresh
    exact ⟨by simpa only [hActor, hPost] using hFresh,
      by simpa only [hPre] using hRole,
      by simpa only [hActor, hPre] using hLed⟩
  · rintro ⟨hFresh, hRole, hLed⟩
    have hNow := c.post_now
    have hAfterLed := hLed.mono t
    have site := (reach_2_iff c c.actor c.post c.pre.currentTerm).mpr
      ⟨hNow, hAfterLed, fun h => hFresh h.1⟩
    exact ⟨c, c.actor, c.post, c.pre.currentTerm, site, hLed, ⟨rfl, rfl⟩, rfl, rfl,
      hNow, hAfterLed, hLed, hNow, ⟨rfl, hRole⟩, rfl, hRole, hNow, hAfterLed, c.term_le⟩

/-- Class 3 (`step_led_cur_now_after_inl`): also reuses `reach_2_iff` + `fresh_ctx_agree`. -/
private theorem raw_led_cur_now_after_inl_at [Config.InitialConfiguration] {f : Frame}
    {t : Model.State} (c : Ctx f t) :
    Classes.sig f t .led_cur_now_after_inl ↔
      ¬ Now f c.actor c.post ∧ ∃ k, Led f c.actor k := by
  change step_led_cur_now_after_inl f t ↔ _
  constructor
  · rintro ⟨d, _, _, k, site, hLed, ⟨rfl, rfl⟩, _⟩
    have hFresh : ¬ Now f d.actor d.post := fun hOld =>
      ((reach_2_iff d d.actor d.post k).mp site).2.2 ⟨hOld, hLed⟩
    obtain ⟨hActor, hPost, _⟩ := fresh_ctx_agree c d hFresh
    exact ⟨by simpa only [hActor, hPost] using hFresh, k, by simpa only [hActor] using hLed⟩
  · rintro ⟨hFresh, k, hLed⟩
    have hNow := c.post_now
    have hAfterLed := hLed.mono t
    have site := (reach_2_iff c c.actor c.post k).mpr ⟨hNow, hAfterLed, fun h => hFresh h.1⟩
    exact ⟨c, c.actor, c.post, k, site, hLed, ⟨rfl, rfl⟩, rfl, rfl, hNow, hAfterLed⟩

/-! ## 4. Executable history-backed readers for raw `led_cur_led_cur_{inl,inr}` -/

/-- Executable reader for `∃ k < pre.currentTerm, Led f actor k` using `GrantMonitor.led`. -/
@[expose] public def readOlderLed (cfg : Finset NodeID) (history : List Model.State)
    (actor : NodeID) (preTerm : Nat) : Bool :=
  (List.range preTerm).any fun k => GrantMonitor.led cfg history actor k

private theorem readOlderLed_iff [Config.InitialConfiguration] (before : Model.State)
    (past : List Model.State) (actor : NodeID) (preTerm : Nat) :
    readOlderLed Config.INITIAL_CONFIGURATION (before :: past) actor preTerm = true ↔
      ∃ k, k < preTerm ∧ Led (StateCoverage.frame before past) actor k := by
  simp only [readOlderLed, List.any_eq_true, List.mem_range, GrantMonitor.led_historical]
  constructor
  · rintro ⟨k, hk, hled⟩
    exact ⟨k, hk, (Historical.led_iff before past actor k).mpr hled⟩
  · rintro ⟨k, hk, hled⟩
    exact ⟨k, hk, (Historical.led_iff before past actor k).mp hled⟩

/-- Executable reader for `pre.role ≠ .candidate ∧ Led f actor pre.currentTerm`. -/
@[expose] public def readCurrentLed (cfg : Finset NodeID) (history : List Model.State)
    (actor : NodeID) (pre : NodeState) : Bool :=
  decide (pre.role ≠ .candidate) && GrantMonitor.led cfg history actor pre.currentTerm

private theorem readCurrentLed_iff [Config.InitialConfiguration] (before : Model.State)
    (past : List Model.State) (actor : NodeID) (pre : NodeState) :
    readCurrentLed Config.INITIAL_CONFIGURATION (before :: past) actor pre = true ↔
      pre.role ≠ .candidate ∧ Led (StateCoverage.frame before past) actor pre.currentTerm := by
  simp only [readCurrentLed, Bool.and_eq_true, decide_eq_true_eq, GrantMonitor.led_historical]
  constructor
  · rintro ⟨hrole, hled⟩
    exact ⟨hrole, (Historical.led_iff before past actor pre.currentTerm).mpr hled⟩
  · rintro ⟨hrole, hled⟩
    exact ⟨hrole, (Historical.led_iff before past actor pre.currentTerm).mp hled⟩

/-- End-to-end raw `Classes.sig` iff for `led_cur_led_cur_inl` on any `ActionProfile.Step`. -/
private theorem step_raw_led_cur_inl_iff (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Classes.sig s.frame s.after .led_cur_led_cur_inl ↔
      ¬ Now s.frame s.context.actor s.context.post ∧
        readOlderLed s.cfg (s.before :: s.past) s.context.actor s.context.pre.currentTerm = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [raw_led_cur_inl_at s.context]
  have h := readOlderLed_iff s.before s.past s.context.actor s.context.pre.currentTerm
  exact ⟨fun ⟨hf, hl⟩ => ⟨hf, h.mpr hl⟩, fun ⟨hf, hr⟩ => ⟨hf, h.mp hr⟩⟩

/-- End-to-end raw `Classes.sig` iff for `led_cur_led_cur_inr` on any `ActionProfile.Step`. -/
private theorem step_raw_led_cur_inr_iff (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Classes.sig s.frame s.after .led_cur_led_cur_inr ↔
      ¬ Now s.frame s.context.actor s.context.post ∧
        readCurrentLed s.cfg (s.before :: s.past) s.context.actor s.context.pre = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [raw_led_cur_inr_at s.context]
  have h := readCurrentLed_iff s.before s.past s.context.actor s.context.pre
  exact ⟨fun ⟨hf, hr, hl⟩ => ⟨hf, h.mpr ⟨hr, hl⟩⟩,
         fun ⟨hf, hread⟩ => let ⟨hr, hl⟩ := h.mp hread; ⟨hf, hr, hl⟩⟩

/-! ## 5. Semantic factor implications + kernel-checked LRAT closure over the 3-bit `led_cur` slice -/

/-- Any step where `led_cur_led_cur_inl` holds must also satisfy `led_cur_now_after_inl`
(derived directly from the shared opaque `reach_2_iff` characterizations!). -/
public theorem led_cur_inl_implies_now_after_inl (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Classes.sig s.frame s.after .led_cur_led_cur_inl →
      Classes.sig s.frame s.after .led_cur_now_after_inl := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [raw_led_cur_inl_at s.context, raw_led_cur_now_after_inl_at s.context]
  rintro ⟨hFresh, k, _, hLed⟩
  exact ⟨hFresh, k, hLed⟩

/-- Any step where `led_cur_led_cur_inr` holds must also satisfy `led_cur_now_after_inl`. -/
public theorem led_cur_inr_implies_now_after_inl (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Classes.sig s.frame s.after .led_cur_led_cur_inr →
      Classes.sig s.frame s.after .led_cur_now_after_inl := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [raw_led_cur_inr_at s.context, raw_led_cur_now_after_inl_at s.context]
  rintro ⟨hFresh, _, hLed⟩
  exact ⟨hFresh, s.context.pre.currentTerm, hLed⟩

/-- Complete 3-bit implication: `led_cur_now_after_inl → led_cur_led_cur_inl ∨ led_cur_led_cur_inr`
(via `inv.led_cur` on the pre-state!). -/
public theorem led_cur_now_after_inl_implies_disj (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Classes.sig s.frame s.after .led_cur_now_after_inl →
      Classes.sig s.frame s.after .led_cur_led_cur_inl ∨
      Classes.sig s.frame s.after .led_cur_led_cur_inr := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [raw_led_cur_now_after_inl_at s.context, raw_led_cur_inl_at s.context,
      raw_led_cur_inr_at s.context]
  rintro ⟨hFresh, k, hLed⟩
  rcases s.context.inv.led_cur s.context.actor s.context.pre k s.context.pre_now hLed with
    hLt | ⟨rfl, hRole⟩
  · exact Or.inl ⟨hFresh, k, hLt, hLed⟩
  · exact Or.inr ⟨hFresh, hRole, hLed⟩

/-- Upper CNF over the 3-bit raw slice `(0 = now_after_inl, 1 = led_cur_inl, 2 = led_cur_inr)`:
`0 ↔ (1 ∨ 2)` (3 clauses: `¬1 ∨ 0`, `¬2 ∨ 0`, `¬0 ∨ 1 ∨ 2`). -/
@[expose] public def ledCur3Upper : KernelLRAT.Formula := [
  [(1, false), (0, true)],
  [(2, false), (0, true)],
  [(0, false), (1, true), (2, true)]]

/-- The 4 rows allowed by `0 ↔ (1 ∨ 2)`: `[F,F,F], [T,F,T], [T,T,F], [T,T,T]`. -/
@[expose] public def ledCur3Rows : List (List Bool) := [
  [false, false, false],
  [true,  false, true],
  [true,  true,  false],
  [true,  true,  true]]

/-- Soundness bridge: every real step's raw 3-bit vector satisfies `ledCur3Upper`. -/
public theorem ledCur3Upper_sound (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let env : Nat → Bool := fun i =>
      open Classical in
      match i with
      | 0 => decide (Classes.sig s.frame s.after .led_cur_now_after_inl)
      | 1 => decide (Classes.sig s.frame s.after .led_cur_led_cur_inl)
      | 2 => decide (Classes.sig s.frame s.after .led_cur_led_cur_inr)
      | _ => false
    KernelLRAT.evalFormula env ledCur3Upper = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  open Classical in
  have h1 := led_cur_inl_implies_now_after_inl s
  have h2 := led_cur_inr_implies_now_after_inl s
  have h3 := led_cur_now_after_inl_implies_disj s
  by_cases b0 : Classes.sig s.frame s.after .led_cur_now_after_inl <;>
    by_cases b1 : Classes.sig s.frame s.after .led_cur_led_cur_inl <;>
    by_cases b2 : Classes.sig s.frame s.after .led_cur_led_cur_inr <;>
    simp [ledCur3Upper, KernelLRAT.evalFormula, KernelLRAT.evalClause, KernelLRAT.evalLit,
      b0, b1, b2] at h1 h2 h3 ⊢

/-- Kernel-only LRAT proof closing the 3-bit raw `led_cur` upper bound to exactly 4 rows
(`ledCur3Rows`): clauses 0..2 are `ledCur3Upper`, clauses 3..6 block the 4 rows:
  0: ¬1 ∨ 0
  1: ¬2 ∨ 0
  2: ¬0 ∨ 1 ∨ 2
  3: 0 ∨ 1 ∨ 2     [blocks F,F,F]
  4: ¬0 ∨ 1 ∨ ¬2   [blocks T,F,T]
  5: ¬0 ∨ ¬1 ∨ 2   [blocks T,T,F]
  6: ¬0 ∨ ¬1 ∨ ¬2  [blocks T,T,T]
LRAT derivation (0-indexed):
  7: addRup [0]     hints [0, 1, 3]    (¬0 → ¬1 by 0, ¬2 by 1, conflict on 3)
  8: addRup [¬0, 1] hints [4, 2]       (0, ¬1 → 2 by 2, conflict on 4)
  9: addRup [¬0,¬1] hints [5, 6]       (0, 1 → 2 by 5, conflict on 6)
 10: addEmpty       hints [7, 8, 9]    (0 by 7, 1 by 8, conflict on 9)
-/
public theorem ledCur3_upper_closed (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    open Classical in
    [decide (Classes.sig s.frame s.after .led_cur_now_after_inl),
     decide (Classes.sig s.frame s.after .led_cur_led_cur_inl),
     decide (Classes.sig s.frame s.after .led_cur_led_cur_inr)] ∈ ledCur3Rows := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  open Classical in
  let env : Nat → Bool := fun i =>
    match i with
    | 0 => decide (Classes.sig s.frame s.after .led_cur_now_after_inl)
    | 1 => decide (Classes.sig s.frame s.after .led_cur_led_cur_inl)
    | 2 => decide (Classes.sig s.frame s.after .led_cur_led_cur_inr)
    | _ => false
  have hmem := KernelLRAT.mem_rows_of_checkProof
    (rows := ledCur3Rows)
    (upper := ledCur3Upper)
    (steps := [
      .addRup [(0, true)] [0, 1, 3],
      .addRup [(0, false), (1, true)] [2, 4],
      .addRup [(0, false), (1, false)] [5, 6],
      .addEmpty [7, 8, 9]])
    (by decide +kernel) env (ledCur3Upper_sound s) 3 (by decide)
  simpa [List.ofFn_succ, env] using hmem

/-! ## 6. Concrete initialized replay witnesses (positive & negative) for both compiled classes -/

private theorem actor_of_local (s : ActionProfile.Step) (n : NodeID) (inp : Input)
    (hact : s.act = .local n inp) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.actor = n := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have h : ActionContext.action s.context = .local n inp :=
    ((s.context_eq s.context).mpr rfl).trans hact
  cases hev : s.context.event with
  | internal i =>
    simp [ActionContext.action, ActionContext.encode, hev] at h
    exact h.1
  | receive src msg =>
    simp [ActionContext.action, ActionContext.encode, hev] at h

private theorem now_step_iff (s : ActionProfile.Step) (n : NodeID) (st : NodeState) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Now s.frame n st ↔ (n, st) ∈ s.before.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have hcur : s.frame.current = s.before := s.current_eq
  change (n, st) ∈ s.frame.current.nodes ↔ (n, st) ∈ s.before.nodes
  rw [hcur]

/-- 1-node bootstrap cluster `{0}` appending one transaction entry on primary `0` (term 2).
- `step_led_cur_led_cur_inr` is **TRUE** (`0` is primary, fresh post-state, led bootstrap term 2).
- `step_led_cur_led_cur_inl` is **FALSE** (`0` never led any term `< 2`). -/
private def appendSched : Schedule :=
  ⟨{0}, [0], [.local 0 (.append [{ content := .transaction 1 {} }])]⟩

private theorem appendSched_valid : appendSched.Valid := by decide +kernel

private def appendAfter : Model.State :=
  (networkStep appendSched.cfg appendSched.initial
    (.local 0 (.append [{ content := .transaction 1 {} }]))).getD appendSched.initial

private theorem appendSched_ok : appendSched.replay = some [appendSched.initial, appendAfter] := rfl

private def appendStep : ActionProfile.Step :=
  appendSched.step appendSched_valid appendSched_ok ⟨0, by decide⟩

/-- Positive raw witness: `Classes.sig` holds for `led_cur_led_cur_inr` on `appendStep`. -/
public theorem witness_led_cur_inr_true :
    letI : Config.InitialConfiguration := ⟨appendStep.cfg⟩
    Classes.sig appendStep.frame appendStep.after .led_cur_led_cur_inr := by
  letI : Config.InitialConfiguration := ⟨appendStep.cfg⟩
  rw [step_raw_led_cur_inr_iff appendStep]
  have hActor : appendStep.context.actor = 0 := actor_of_local appendStep 0 _ rfl
  have hPreMem : (0, appendStep.context.pre) ∈ appendStep.before.nodes := by
    have h := (now_step_iff appendStep _ _).mp appendStep.context.pre_now
    rwa [hActor] at h
  have hPreEq : appendStep.context.pre = initialNodeState {0} 0 := by
    have hNodes : appendStep.before.nodes = [(0, initialNodeState {0} 0)] := rfl
    rw [hNodes] at hPreMem
    simpa using hPreMem
  have hPostMem : (0, appendStep.context.post) ∈ appendStep.after.nodes := by
    have h : (appendStep.context.actor, appendStep.context.post) ∈ appendStep.after.nodes :=
      appendStep.context.post_now
    rwa [hActor] at h
  have hPostLogLen : appendStep.context.post.log.length = 2 := by
    have hNodes : appendStep.after.nodes.map (fun p => (p.1, p.2.log.length)) = [(0, 2)] := rfl
    have hIn : (0, appendStep.context.post.log.length) ∈
        appendStep.after.nodes.map (fun p => (p.1, p.2.log.length)) :=
      List.mem_map.mpr ⟨(0, appendStep.context.post), hPostMem, rfl⟩
    rw [hNodes] at hIn
    simpa using hIn
  refine ⟨?_, ?_⟩
  · intro hOld
    have hOldMem : (0, appendStep.context.post) ∈ appendStep.before.nodes := by
      have h := (now_step_iff appendStep _ _).mp hOld
      rwa [hActor] at h
    have hNodes : appendStep.before.nodes.map (fun p => (p.1, p.2.log.length)) = [(0, 1)] := rfl
    have hIn : (0, appendStep.context.post.log.length) ∈
        appendStep.before.nodes.map (fun p => (p.1, p.2.log.length)) :=
      List.mem_map.mpr ⟨(0, appendStep.context.post), hOldMem, rfl⟩
    rw [hNodes, hPostLogLen] at hIn
    simp at hIn
  · rw [hActor, hPreEq]
    decide +kernel

/-- Negative raw witness: `¬ Classes.sig` for `led_cur_led_cur_inl` on the same `appendStep`
(proved via the compiled `readOlderLed` returning `false`). -/
public theorem witness_led_cur_inl_false :
    letI : Config.InitialConfiguration := ⟨appendStep.cfg⟩
    ¬ Classes.sig appendStep.frame appendStep.after .led_cur_led_cur_inl := by
  letI : Config.InitialConfiguration := ⟨appendStep.cfg⟩
  rw [step_raw_led_cur_inl_iff appendStep]
  rintro ⟨_, hRead⟩
  have hActor : appendStep.context.actor = 0 := actor_of_local appendStep 0 _ rfl
  have hPreMem : (0, appendStep.context.pre) ∈ appendStep.before.nodes := by
    have h := (now_step_iff appendStep _ _).mp appendStep.context.pre_now
    rwa [hActor] at h
  have hPreEq : appendStep.context.pre = initialNodeState {0} 0 := by
    have hNodes : appendStep.before.nodes = [(0, initialNodeState {0} 0)] := rfl
    rw [hNodes] at hPreMem
    simpa using hPreMem
  rw [hActor, hPreEq] at hRead
  have hFalse : readOlderLed appendStep.cfg (appendStep.before :: appendStep.past) 0
      (initialNodeState {0} 0).currentTerm = false := by decide +kernel
  rw [hFalse] at hRead
  exact Bool.noConfusion hRead

/-- Negative raw witness for `led_cur_led_cur_inr`: node 1 (which is a follower and has never
led term 2) starts an election timeout after receiving the bootstrap entry (or directly on a
heartbeat `sendEntries 1 0` from primary 0 where node 1's `appendEntriesRequest` delivery makes
node 1 fresh without having led term 2). -/
private def followerRecvSched : Schedule :=
  ⟨{0, 1}, [0, 1], [
    .local 0 (.sendEntries 1 1),
    .deliver ⟨0, 1, .appendEntriesRequest ⟨2, 0, 0,
      [⟨2, .transaction 0 {configuration := some {0, 1}}⟩], 0⟩⟩]⟩

private theorem followerRecvSched_valid : followerRecvSched.Valid := by decide +kernel

private theorem followerRecvSched_enabled : followerRecvSched.replay.isSome := by
  decide +kernel

private def followerRecvStep : ActionProfile.Step :=
  followerRecvSched.step followerRecvSched_valid
    (Option.some_get followerRecvSched_enabled).symm ⟨1, by decide⟩

private theorem actor_of_deliver (s : ActionProfile.Step) (env : Model.Envelope)
    (hact : s.act = .deliver env) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.actor = env.target := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have h : ActionContext.action s.context = .deliver env :=
    ((s.context_eq s.context).mpr rfl).trans hact
  cases hev : s.context.event with
  | internal i =>
    simp [ActionContext.action, ActionContext.encode, hev] at h
  | receive src msg =>
    simp [ActionContext.action, ActionContext.encode, hev] at h
    exact congrArg CCF.Envelope.target h

public theorem witness_led_cur_inr_false :
    letI : Config.InitialConfiguration := ⟨followerRecvStep.cfg⟩
    ¬ Classes.sig followerRecvStep.frame followerRecvStep.after .led_cur_led_cur_inr := by
  letI : Config.InitialConfiguration := ⟨followerRecvStep.cfg⟩
  rw [step_raw_led_cur_inr_iff followerRecvStep]
  rintro ⟨_, hRead⟩
  have hActor : followerRecvStep.context.actor = 1 :=
    actor_of_deliver followerRecvStep _ rfl
  have hPreMem : (1, followerRecvStep.context.pre) ∈ followerRecvStep.before.nodes := by
    have h := (now_step_iff followerRecvStep _ _).mp followerRecvStep.context.pre_now
    rwa [hActor] at h
  have hPreTerm : followerRecvStep.context.pre.currentTerm = 2 := by
    have hNodes : followerRecvStep.before.nodes.map (fun p => (p.1, p.2.currentTerm)) =
        [(0, 2), (1, 2)] := by decide +kernel
    have hIn : (1, followerRecvStep.context.pre.currentTerm) ∈
        followerRecvStep.before.nodes.map (fun p => (p.1, p.2.currentTerm)) :=
      List.mem_map.mpr ⟨(1, followerRecvStep.context.pre), hPreMem, rfl⟩
    rw [hNodes] at hIn
    simpa using hIn
  have hLed : GrantMonitor.led followerRecvStep.cfg
      (followerRecvStep.before :: followerRecvStep.past) 1 2 = false := by decide +kernel
  unfold readCurrentLed at hRead
  rw [hActor, hPreTerm, hLed, Bool.and_false] at hRead
  exact Bool.noConfusion hRead

/-- Positive raw witness for `led_cur_led_cur_inl`: 2-node cluster `{0, 1}` replicates a
signature, node 1 starts pre-vote + vote for term 3, node 0 grants the vote and moves to
term 3 follower, then node 0 runs an election timeout in term 3 (fresh post-state:
`follower → preVoteCandidate`, while `pre.currentTerm = 3` and `Led f 0 2` holds with `2 < 3`).
Checked cleanly via `Schedule.replay.isSome` (like `Fixtures.lean`), with zero giant `rfl`. -/
private def reelectCfg : Finset NodeID := {0, 1}
private def reelectActs : List Model.Action := [
  .local 0 (.append [{ content := .signature }]),
  .local 0 (.sendEntries 1 2),
  .deliver ⟨0, 1, .appendEntriesRequest ⟨2, 0, 0,
    [⟨2, .transaction 0 {configuration := some reelectCfg}⟩, ⟨2, .signature⟩], 0⟩⟩,
  .local 1 (.timeout .election),
  .deliver ⟨1, 0, .requestPreVoteRequest ⟨2, 2, 2⟩⟩,
  .deliver ⟨0, 1, .requestPreVoteResponse ⟨2, true⟩⟩,
  .deliver ⟨1, 0, .requestVoteRequest ⟨3, 2, 2⟩⟩,
  .local 0 (.timeout .election)]

private def reelectSched : Schedule := ⟨reelectCfg, [0, 1], reelectActs⟩

private theorem reelectSched_valid : reelectSched.Valid := by decide +kernel

private theorem reelectSched_enabled : reelectSched.replay.isSome := by decide +kernel

private def reelectStep : ActionProfile.Step :=
  reelectSched.step reelectSched_valid (Option.some_get reelectSched_enabled).symm ⟨7, by decide⟩

public theorem witness_led_cur_inl_true :
    letI : Config.InitialConfiguration := ⟨reelectStep.cfg⟩
    Classes.sig reelectStep.frame reelectStep.after .led_cur_led_cur_inl := by
  letI : Config.InitialConfiguration := ⟨reelectStep.cfg⟩
  rw [step_raw_led_cur_inl_iff reelectStep]
  have hActor : reelectStep.context.actor = 0 := actor_of_local reelectStep 0 _ rfl
  have hPreMem : (0, reelectStep.context.pre) ∈ reelectStep.before.nodes := by
    have h := (now_step_iff reelectStep _ _).mp reelectStep.context.pre_now
    rwa [hActor] at h
  have hPreTerm : reelectStep.context.pre.currentTerm = 3 := by
    have hNodes : reelectStep.before.nodes.map (fun p => (p.1, p.2.currentTerm)) =
        [(0, 3), (1, 3)] := by decide +kernel
    have hIn : (0, reelectStep.context.pre.currentTerm) ∈
        reelectStep.before.nodes.map (fun p => (p.1, p.2.currentTerm)) :=
      List.mem_map.mpr ⟨(0, reelectStep.context.pre), hPreMem, rfl⟩
    rw [hNodes] at hIn
    simpa using hIn
  have hPostMem : (0, reelectStep.context.post) ∈ reelectStep.after.nodes := by
    have h : (reelectStep.context.actor, reelectStep.context.post) ∈ reelectStep.after.nodes :=
      reelectStep.context.post_now
    rwa [hActor] at h
  have hPostRole : reelectStep.context.post.role = .preVoteCandidate := by
    have hNodes : reelectStep.after.nodes.map (fun p => (p.1, p.2.role)) =
        [(0, .preVoteCandidate), (1, .candidate)] := by decide +kernel
    have hIn : (0, reelectStep.context.post.role) ∈
        reelectStep.after.nodes.map (fun p => (p.1, p.2.role)) :=
      List.mem_map.mpr ⟨(0, reelectStep.context.post), hPostMem, rfl⟩
    rw [hNodes] at hIn
    simpa using hIn
  refine ⟨?_, ?_⟩
  · intro hOld
    have hOldMem : (0, reelectStep.context.post) ∈ reelectStep.before.nodes := by
      have h := (now_step_iff reelectStep _ _).mp hOld
      rwa [hActor] at h
    have hNodes : reelectStep.before.nodes.map (fun p => (p.1, p.2.role)) =
        [(0, .follower), (1, .candidate)] := by decide +kernel
    have hIn : (0, reelectStep.context.post.role) ∈
        reelectStep.before.nodes.map (fun p => (p.1, p.2.role)) :=
      List.mem_map.mpr ⟨(0, reelectStep.context.post), hOldMem, rfl⟩
    rw [hNodes, hPostRole] at hIn
    simp at hIn
  · rw [hActor, hPreTerm]
    unfold readOlderLed
    rw [List.any_eq_true]
    refine ⟨BOOTSTRAP_TERM, by decide, ?_⟩
    simp only [GrantMonitor.led, Bool.or_eq_true, decide_eq_true_eq]
    left
    exact ⟨trivial, by decide +kernel⟩

/-! ## 7. Exact frozen-255 `Clause.observed` full-clause closure via `KernelLRAT` -/

/-- `Clause.observed` has 0 step questions, so its exact table is the single empty bitvector `[]`,
closed via `KernelLRAT.mem_rows_of_checkProof`. -/
public theorem observed_exact_closed (s : ActionProfile.Step) :
    (ClauseQuestions.questions .observed).map (fun b =>
      letI : Config.InitialConfiguration := ⟨s.cfg⟩
      open Classical in decide (Classes.sig s.frame s.after b)) ∈ ([[]] : List (List Bool)) := by
  have hq : ClauseQuestions.questions .observed = [] := by decide +kernel
  rw [hq]
  exact KernelLRAT.mem_rows_of_checkProof (rows := [[]]) (upper := [])
    (steps := [.addEmpty [0]]) (by decide +kernel) (fun _ => false) rfl 0 (by decide)

end ConsensusCoverage.RelationalPilot
