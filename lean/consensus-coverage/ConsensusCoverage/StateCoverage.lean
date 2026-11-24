module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CommitMonitor
public import ConsensusCoverage.StateBasis
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateBasis
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.StateCoverage

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

public abbrev Row := Bool × Bool

/-- The two state questions are read from a snapshot and its preceding snapshots
(newest first). Membership is an input of the protocol, not a proof witness. -/
public def read (cfg : CCF.Finset NodeID) (s : Model.State) (past : List Model.State) : Row :=
  (s.nodes.any (fun n => n.2.commitIndex == 0),
   !s.nodes.isEmpty && CommitMonitor.anyCommit (cfg.min?.getD 0) (s :: past))

private def frame [Config.InitialConfiguration] (s : Model.State) : List Model.State → Frame
  | [] => Frame.start s
  | t :: h => (frame t h).advance s

private theorem frame_current [Config.InitialConfiguration] (s : Model.State) (h : List Model.State) :
    (frame s h).current = s := by cases h <;> rfl

private theorem frame_logs [Config.InitialConfiguration] (s : Model.State) (h : List Model.State) :
    (frame s h).logs = Historical.logFacts (s :: h) := by
  induction h generalizing s with
  | nil => rfl
  | cons t h ih => simp only [frame, Frame.advance, ih, frame_current, Historical.logFacts, List.head?_cons]

private theorem backed_iff [Config.InitialConfiguration] (f : Frame) (inv : Inv f) :
    StateBasis.Backing f ↔ f.current.nodes ≠ [] ∧ ∃ k p, f.logs.committed k p := by
  constructor
  · rintro ⟨n, st, k, p, mem, commit, _⟩
    exact ⟨List.ne_nil_of_mem mem, k, p, commit⟩
  · rintro ⟨nonempty, k, p, commit⟩
    obtain ⟨⟨n, st⟩, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
    obtain ⟨term, zero | ⟨e, part, old, _, sub⟩⟩ := (inv.commit_backed n st mem).1
    · exact ⟨n, st, k, p, mem, commit, by simp [NodeState.committedLog, zero]⟩
    · exact ⟨n, st, e, part, mem, old, sub⟩

private theorem read_iff [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (inv : Inv (frame s h)) :
    ((read Config.INITIAL_CONFIGURATION s h).1 = true ↔ StateBasis.Zero (frame s h)) ∧
    ((read Config.INITIAL_CONFIGURATION s h).2 = true ↔ StateBasis.Backing (frame s h)) := by
  constructor
  · simp [read, StateBasis.Zero, frame_current, List.any_eq_true, Prod.exists]
  · rw [backed_iff _ inv, frame_current, frame_logs]
    change (!s.nodes.isEmpty && CommitMonitor.anyCommit Config.INITIAL_PRIMARY (s :: h)) = true ↔ _
    simp [CommitMonitor.anyCommit_iff]

private theorem nonempty_context [Config.InitialConfiguration] {f : Frame} (inv : Inv f)
    (nonempty : f.current.nodes ≠ []) : StateBasis.Zero f ∨ StateBasis.Backing f := by
  obtain ⟨⟨n, st⟩, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
  obtain ⟨term, z | ⟨e, part, old, _, sub⟩⟩ := (inv.commit_backed n st mem).1
  · exact .inl ⟨n, st, mem, z⟩
  · exact .inr ⟨n, st, e, part, mem, old, sub⟩

/-- Snapshots in an actual initialized protocol run, with no action tags required
by the reader. A past list starts at the immediate predecessor. -/
public inductive Run (cfg : CCF.Finset NodeID) (ns : List NodeID) :
    Model.State → List Model.State → Prop where
  | initial {s} (init : (transitionSystem cfg ns).init s) : Run cfg ns s []
  | step {s h a t} (prior : Run cfg ns s h) (ran : (transitionSystem cfg ns).step s a = some t) :
      Run cfg ns t (s :: h)

private theorem run_inv [Config.InitialConfiguration] {ns s h}
    (run : Run Config.INITIAL_CONFIGURATION ns s h) : Inv (frame s h) := by
  induction run with
  | initial init => exact inv_initial init
  | @step s hist a t prior ran ih =>
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    have tr' : LocalTransition (frame s hist).current t := by rw [frame_current]; exact tr
    exact (Ctx.mk tr' ih).inv_step

/-- The proof's own state dispatcher on the frame obtained by folding this run. -/
public def Holds (cfg : CCF.Finset NodeID) (s : Model.State) (hist : List Model.State)
    (b : Classes.StateBranch) : Prop :=
  letI : Config.InitialConfiguration := ⟨cfg⟩
  Classes.ctx (frame s hist) b

/-- In both directions: the executable key loses no generated state distinction and
does not add any. The two histories need not come from the same configuration. -/
public theorem same_answers {cfg cfg' ns ns' s t h h'} (left : Run cfg ns s h) (right : Run cfg' ns' t h') :
    read cfg s h = read cfg' t h' ↔ ∀ b, Holds cfg s h b ↔ Holds cfg' t h' b := by
  have inv := @run_inv ⟨cfg⟩ _ _ _ left
  have inv' := @run_inv ⟨cfg'⟩ _ _ _ right
  obtain ⟨z, c⟩ := @read_iff ⟨cfg⟩ s h inv
  obtain ⟨z', c'⟩ := @read_iff ⟨cfg'⟩ t h' inv'
  unfold Holds
  rw [StateBasis.ctx_equiv_iff _ _ _ _
    (@Inv.commitChains ⟨cfg⟩ _ inv) (@Inv.commitChains ⟨cfg'⟩ _ inv')]
  change ((read cfg s h).1 = true ↔ _) at z
  change ((read cfg s h).2 = true ↔ _) at c
  change ((read cfg' t h').1 = true ↔ _) at z'
  change ((read cfg' t h').2 = true ↔ _) at c'
  rw [← z, ← c, ← z', ← c']
  generalize read cfg s h = a; generalize read cfg' t h' = b
  rcases a with ⟨a, a'⟩; rcases b with ⟨b, b'⟩
  cases a <;> cases a' <;> cases b <;> cases b' <;> decide

public def table : List Row := [(false, false), (true, false), (true, true), (false, true)]
public def activeTable : List Row := [(true, false), (true, true), (false, true)]

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

private def appendSig : Model.Action := .local 0 (.append [{content := .signature}])

private theorem before (ns : List NodeID) (nodup : ns.Nodup) (r : Row) (active : Bool)
    (ne : active = true → (initial ns).nodes ≠ []) (eq : read single (initial ns) [] = r) :
    Occurs r active := by
  exact ⟨single, ns, initial ns, [], .initial (init _ nodup), eq, ne⟩

private theorem after (ns : List NodeID) (nodup : ns.Nodup) (s : Model.State) (r : Row) (active : Bool)
    (ran : (transitionSystem single ns).step (initial ns) appendSig = some s)
    (ne : active = true → s.nodes ≠ []) (eq : read single s [initial ns] = r) : Occurs r active := by
  exact ⟨single, ns, s, [_], .step (.initial (init _ nodup)) ran, eq, ne⟩

private def appended (ns : List NodeID) (yes : ((transitionSystem single ns).step (initial ns) appendSig).isSome) :
    Model.State := ((transitionSystem single ns).step (initial ns) appendSig).get yes

private theorem cases_exact (r : Row) (active : Bool) :
    r ∈ (if active then activeTable else table) ↔ Occurs r active := by
  constructor
  · rcases r with ⟨z, b⟩
    cases z <;> cases b
    · cases active
      · intro _; exact before [] (by decide) _ _ (by decide) (by decide +kernel)
      · simp [activeTable]
    · intro _
      exact after [0] (by decide) (appended [0] (by decide +kernel)) _ _
        (Option.some_get _).symm (fun _ => List.cons_ne_nil _ _) (by decide +kernel)
    · intro _
      exact before [0] (by decide) _ _ (fun _ => List.cons_ne_nil _ _) (by decide +kernel)
    · intro _
      exact after [0, 1] (by decide) (appended [0, 1] (by decide +kernel)) _ _
        (Option.some_get _).symm (fun _ => List.cons_ne_nil _ _) (by decide +kernel)
  · rintro ⟨cfg, ns, s, hist, run, rfl, nonempty⟩
    letI : Config.InitialConfiguration := ⟨cfg⟩
    cases active with
    | false =>
      generalize read cfg s hist = r
      rcases r with ⟨z, b⟩; cases z <;> cases b <;> decide
    | true =>
      have inv := @run_inv ‹_› ns s hist run
      have non : (frame s hist).current.nodes ≠ [] := by rw [frame_current]; exact nonempty rfl
      have h := nonempty_context inv non
      obtain ⟨zero, backed⟩ := read_iff _ _ inv
      change ((read cfg s hist).1 = true ↔ _) at zero
      change ((read cfg s hist).2 = true ↔ _) at backed
      generalize read cfg s hist = r at *
      rcases r with ⟨z, b⟩
      cases z <;> cases b <;> simp_all [activeTable]

/-- Across the original protocol's initial configurations: four state profiles, three
on nonempty clusters. An empty node list is a valid, isolated initial state. -/
public theorem exact (r : Row) : (r ∈ table ↔ Occurs r false) ∧ (r ∈ activeTable ↔ Occurs r true) :=
  ⟨cases_exact r false, cases_exact r true⟩

public theorem counts : table.Nodup ∧ table.length = 4 ∧ activeTable.Nodup ∧ activeTable.length = 3 :=
  by decide

end ConsensusCoverage.StateCoverage
