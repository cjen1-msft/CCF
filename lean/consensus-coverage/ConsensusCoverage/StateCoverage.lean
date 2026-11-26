module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FullProfile
public import ConsensusCoverage.StateBasis
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.StateBasis
import all Consensus.Proofs.SafetyInvariant

/-!
# The exact state table

The state questions are read from a snapshot alone: both hold exactly when the
node list is nonempty. The history argument is kept so that the reader has the same
inputs as the proof frame, which is folded over the whole run.
-/

namespace ConsensusCoverage.StateCoverage

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public abbrev Row := Bool

/-- Membership is an input of the protocol, not a proof witness. -/
@[expose] public def read (_cfg : CCF.Finset NodeID) (s : Model.State) (_past : List Model.State) : Row :=
  !s.nodes.isEmpty

private def frame [Config.InitialConfiguration] (s : Model.State) : List Model.State → Frame
  | [] => Frame.start s
  | t :: h => (frame t h).advance s

private theorem frame_current [Config.InitialConfiguration] (s : Model.State) (h : List Model.State) :
    (frame s h).current = s := by cases h <;> rfl

/-- Snapshots in an actual initialized protocol run, with no action tags required
by the reader. A past list starts at the immediate predecessor. -/
public inductive Run (cfg : CCF.Finset NodeID) (ns : List NodeID) :
    Model.State → List Model.State → Prop where
  | initial {s} (init : (transitionSystem cfg ns).init s) : Run cfg ns s []
  | step {s h a t} (prior : Run cfg ns s h) (ran : (transitionSystem cfg ns).step s a = some t) :
      Run cfg ns t (s :: h)

private theorem run_folded {cfg ns s past} (run : Run cfg ns s past) :
    FullProfile.Folded cfg ns (@frame ⟨cfg⟩ s past) := by
  induction run with
  | initial init => exact .initial init
  | step prior step ih =>
    apply FullProfile.Folded.step ih
    rwa [show ∀ x h, FullProfile.current (@frame ⟨cfg⟩ x h) = x from
      fun x h => @frame_current ⟨cfg⟩ x h]

private theorem folded_history {cfg ns f} (folded : FullProfile.Folded cfg ns f) :
    ∃ s past, Run cfg ns s past ∧ @frame ⟨cfg⟩ s past = f := by
  induction folded with
  | initial h => exact ⟨_, [], .initial h, rfl⟩
  | step _ stepped ih =>
    obtain ⟨s, past, run, rfl⟩ := ih
    change (transitionSystem _ _).step (@frame ⟨cfg⟩ s past).current _ = _ at stepped
    rw [@frame_current ⟨cfg⟩ s past] at stepped
    exact ⟨_, s :: past, .step run stepped, rfl⟩

private theorem run_inv [Config.InitialConfiguration] {ns s h}
    (run : Run Config.INITIAL_CONFIGURATION ns s h) : Inv (frame s h) :=
  (run_folded run).invariant

/-- The proof's own state dispatcher on the frame obtained by folding this run. -/
public def Holds (cfg : CCF.Finset NodeID) (s : Model.State) (hist : List Model.State)
    (b : Classes.StateBranch) : Prop :=
  letI : Config.InitialConfiguration := ⟨cfg⟩
  Classes.ctx (frame s hist) b

public theorem read_iff {cfg ns s h} (run : Run cfg ns s h) (b : Classes.StateBranch) :
    read cfg s h = true ↔ Holds cfg s h b := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  unfold Holds
  rw [StateBasis.ctx_iff_present _ (run_inv run), StateBasis.Present, frame_current]
  cases h : s.nodes <;> simp [read, h]

/-- In both directions: the executable key loses no generated state distinction and
does not add any. The two histories need not come from the same configuration. -/
public theorem same_answers {cfg cfg' ns ns' s t h h'} (left : Run cfg ns s h) (right : Run cfg' ns' t h') :
    read cfg s h = read cfg' t h' ↔ ∀ b, Holds cfg s h b ↔ Holds cfg' t h' b := by
  constructor
  · intro eq b
    rw [← read_iff left b, ← read_iff right b, eq]
  · intro all
    exact Bool.eq_iff_iff.mpr ((read_iff left .committed_logs_comparable_committed_comparable_inl).trans
      ((all _).trans (read_iff right _).symm))

/-- A step keeps the node list nonempty: its actor is present before and after. -/
public theorem step_read {cfg ns s a t} (ran : (transitionSystem cfg ns).step s a = some t)
    (past past' : List Model.State) : read cfg s past = true ∧ read cfg t past' = true := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨tr⟩ := LocalTransition.ofStep ran
  have pre := tr.pre_mem
  have post := tr.post_mem
  constructor
  · cases h : s.nodes <;> simp_all [read]
  · cases h : t.nodes <;> simp_all [read]

public def table : List Row := [false, true]
public def activeTable : List Row := [true]

public def Occurs (r : Row) (nonempty : Bool) : Prop :=
  ∃ (cfg : CCF.Finset NodeID) (ns : List NodeID) (s : Model.State) (h : List Model.State),
    Run cfg ns s h ∧ read cfg s h = r ∧
    (nonempty = true → s.nodes ≠ [])

private abbrev single : CCF.Finset NodeID := {0}
private def initial (ns : List NodeID) : Model.State :=
  {nodes := ns.map fun n => (n, initialNodeState single n)}

private theorem init (ns : List NodeID) (nodup : ns.Nodup) :
    (transitionSystem single ns).init (initial ns) := by
  refine ⟨⟨0, by decide⟩, ?_, ?_⟩ <;> simp [initial, protocol, Function.comp_def, nodup]

private theorem cases_exact (r : Row) (active : Bool) :
    r ∈ (if active then activeTable else table) ↔ Occurs r active := by
  constructor
  · cases r
    · cases active
      · intro _
        exact ⟨single, [], initial [], [], .initial (init _ (by decide)), rfl, by decide⟩
      · simp [activeTable]
    · intro _
      exact ⟨single, [0], initial [0], [], .initial (init _ (by decide)), rfl,
        fun _ => List.cons_ne_nil _ _⟩
  · rintro ⟨cfg, ns, s, hist, run, rfl, nonempty⟩
    cases active with
    | false => cases read cfg s hist <;> decide
    | true =>
      have non := nonempty rfl
      cases h : s.nodes <;> simp_all [read, activeTable]

/-- Across the original protocol's initial configurations: two state profiles, one
on nonempty clusters. An empty node list is a valid, isolated initial state. -/
public theorem exact (r : Row) : (r ∈ table ↔ Occurs r false) ∧ (r ∈ activeTable ↔ Occurs r true) :=
  ⟨cases_exact r false, cases_exact r true⟩

public theorem counts : table.Nodup ∧ table.length = 2 ∧ activeTable.Nodup ∧ activeTable.length = 1 :=
  by decide

/-- The endpoints of a successful step from a snapshot of an initialized run. -/
public def Transition (pre post : Row) : Prop :=
  ∃ (cfg : CCF.Finset NodeID) (ns : List NodeID) (s t : Model.State) (h : List Model.State)
    (a : Model.Action), Run cfg ns s h ∧ (transitionSystem cfg ns).step s a = some t ∧
    read cfg s h = pre ∧ read cfg t (s :: h) = post

public def transitions : List (Row × Row) := [(true, true)]

private def appendSig : Model.Action := .local 0 (.append [{content := .signature}])

/-- Exactly one endpoint pair: the empty cluster has no successful step. -/
public theorem transitions_exact (pre post : Row) :
    (pre, post) ∈ transitions ↔ Transition pre post := by
  constructor
  · intro mem
    obtain ⟨rfl, rfl⟩ : pre = true ∧ post = true := by simpa [transitions] using mem
    have some : ((transitionSystem single [0]).step (initial [0]) appendSig).isSome := by
      decide +kernel
    have ran := (Option.some_get some).symm
    exact ⟨single, [0], initial [0], _, [], appendSig, .initial (init _ (by decide)), ran,
      (step_read ran [] []).1, (step_read ran [] [initial [0]]).2⟩
  · rintro ⟨cfg, ns, s, t, h, a, _, ran, rfl, rfl⟩
    obtain ⟨l, r⟩ := step_read ran h (s :: h)
    simp [transitions, l, r]

end ConsensusCoverage.StateCoverage
