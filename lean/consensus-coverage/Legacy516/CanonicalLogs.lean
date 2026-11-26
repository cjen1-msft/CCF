module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.CanonicalLogs

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev Key := Nat × List Entry

-- A node may have stepped down since its election; don't filter for current primaries.
private def here (bootstrap : NodeID) (s : Model.State) (past : List Model.State) : List Key :=
  (s.nodes.filter fun (n, st) =>
    st.role != .candidate &&
      ((st.currentTerm == BOOTSTRAP_TERM && n == bootstrap) ||
        CommitMonitor.elected n st.currentTerm (s :: past))).map fun (_, st) => (st.currentTerm, st.log)

private def keys (bootstrap : NodeID) : List Model.State → List Key
  | [] => []
  | s :: h => here bootstrap s h ++ keys bootstrap h

private theorem mem_here [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (k : Nat) (l : List Entry) :
    (k, l) ∈ here Config.INITIAL_PRIMARY s h ↔
      ∃ n st, Historical.CanonNow (s :: h) n st k ∧ st.log = l := by
  simp only [here, List.mem_map, List.mem_filter, Prod.exists, Bool.and_eq_true, Bool.or_eq_true,
    beq_iff_eq, bne_iff_ne, Prod.mk.injEq, CommitMonitor.elected_iff, Historical.CanonNow,
    Historical.Now, Historical.Led]
  grind

private theorem mem_keys [Config.InitialConfiguration] (h : List Model.State) (k : Nat) (l : List Entry) :
    (k, l) ∈ keys Config.INITIAL_PRIMARY h ↔ Historical.Canon h k l := by
  induction h with
  | nil => simp [keys, Historical.Canon, Historical.CanonNow, Historical.Now]
  | cons s h ih =>
    simp only [keys, List.mem_append, mem_here, ih, Historical.Canon, List.suffix_cons_iff]
    grind

/-- Did this step install a canonical `(term, log)` pair absent from the entire
earlier run? Looking only at the two endpoint snapshots does not establish absence. -/
public def fresh (bootstrap : NodeID) (t : Model.State) (history : List Model.State) : Bool :=
  let old := keys bootstrap history
  (here bootstrap t history).any fun p => !old.contains p

private theorem fresh_iff [Config.InitialConfiguration] (t : Model.State) (h : List Model.State) :
    fresh Config.INITIAL_PRIMARY t h = true ↔ ∃ k l,
      (Historical.logFacts (t :: h)).canon k l ∧ ¬ (Historical.logFacts h).canon k l := by
  simp only [fresh, List.any_eq_true, Prod.exists, Bool.not_eq_true', Bool.eq_false_iff]
  simp only [(Historical.logFacts_correct _).canon, ← mem_keys, keys, List.mem_append]
  grind

private theorem step_fresh (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    fresh (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true ↔
      ∃ k l, (s.frame.advance s.after).logs.canon k l ∧ ¬ s.frame.logs.canon k l := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change fresh Config.INITIAL_PRIMARY _ _ = true ↔ ∃ k l,
    (StateCoverage.frame s.after (s.before :: s.past)).logs.canon k l ∧
      ¬ (StateCoverage.frame s.before s.past).logs.canon k l
  rw [StateCoverage.frame_logs, StateCoverage.frame_logs]
  exact fresh_iff _ _

private def actor : Model.Action → NodeID
  | .local n _ => n
  | .deliver e => e.target

private theorem actor_eq (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    actor s.act = s.context.actor := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [← (s.context_eq s.context).mpr rfl]
  change actor (ActionContext.encode s.context.tr.actor s.context.tr.event) = s.context.tr.actor
  cases s.context.tr.event <;> rfl

/-- The nonacting-node branch also needs an entry on that node, not just
any new canonical log. -/
public def otherLog (a : Model.Action) (t : Model.State) : Bool :=
  t.nodes.any fun (n, st) => n != actor a && !st.log.isEmpty

public theorem other_answer (s : ActionProfile.Step) :
    (fresh (s.cfg.min?.getD 0) s.after (s.before :: s.past) && otherLog s.act s.after) =
      ActionProfile.label s (.step .terms_now_after_inr) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_iff_iff.mpr
  rw [ActionProfile.label_true, Bool.and_eq_true, step_fresh]
  simp only [otherLog, List.any_eq_true, Prod.exists, Bool.and_eq_true, bne_iff_ne,
    Bool.not_eq_true', List.isEmpty_eq_false_iff, actor_eq]
  change (_ ∧ _) ↔ PinnedClasses.step_terms_now_after_inr s.frame s.after s.context
  constructor
  · rintro ⟨⟨k, l, canon, freshKey⟩, n, st, now, other, nonempty⟩
    obtain ⟨entry, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
    have old := (s.context.now_after now).resolve_left fun h => other h.1
    exact ⟨s.context, rfl, ⟨s.context, rfl, k, l, canon, freshKey, rfl⟩,
      n, st, now, entry, mem, old, old⟩
  · rintro ⟨_, rfl, ⟨_, rfl, k, l, canon, freshKey, _⟩, n, st, now, entry, mem, ⟨other, _⟩, _⟩
    exact ⟨⟨k, l, canon, freshKey⟩, n, st, now, other, List.ne_nil_of_mem mem⟩

end ConsensusCoverage.CanonicalLogs
