module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionContext
public import ConsensusCoverage.PinnedClasses
public import ConsensusCoverage.ProofContexts
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ActionProfile

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety FullProfile

set_option autoImplicit false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- The inputs to replay: initial membership, preceding snapshots (newest first),
and the action actually recorded. A disabled action has no label. -/
public structure Step where
  cfg : FullProfile.Configuration
  nodes : List NodeID
  before : Model.State
  past : List Model.State
  act : Model.Action
  after : Model.State
  run : StateCoverage.Run cfg nodes before past
  ran : (transitionSystem cfg nodes).step before act = some after

public def Step.frame (s : Step) : ProofFrame := @StateCoverage.frame ⟨s.cfg⟩ s.before s.past

public theorem Step.current_eq (s : Step) : current s.frame = s.before :=
  @StateCoverage.frame_current ⟨s.cfg⟩ s.before s.past

public theorem Step.folded (s : Step) : Folded s.cfg s.nodes s.frame :=
  StateCoverage.run_folded s.run

private theorem Step.exists_context (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ c : Ctx s.frame s.after, ActionContext.action c = s.act := by
  have ran := s.ran
  rw [← s.current_eq] at ran
  obtain ⟨c, eq, _⟩ := ActionContext.exists_unique s.folded ran
  exact ⟨c, eq⟩

public noncomputable def Step.context (s : Step) : @Ctx ⟨s.cfg⟩ s.frame s.after :=
  s.exists_context.choose

public theorem Step.context_eq (s : Step) (c : @Ctx ⟨s.cfg⟩ s.frame s.after) :
    @ActionContext.action ⟨s.cfg⟩ _ _ c = s.act ↔ c = s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have recorded := s.exists_context.choose_spec
  exact ⟨fun h => ActionContext.injective (h.trans recorded.symm), fun h => h ▸ recorded⟩

/-- All step coordinates share `s.context`; the state questions at either
endpoint refer to the same initialization and history, extended by this step. -/
public def holds (s : Step) : Question → Prop
  | .pre b => StateCoverage.Holds s.cfg s.before s.past b
  | .step b => @PinnedClasses.sig ⟨s.cfg⟩ _ _ s.context b
  | .post b => StateCoverage.Holds s.cfg s.after (s.before :: s.past) b

public noncomputable def label (s : Step) : Profile :=
  open Classical in fun q => decide (holds s q)

public theorem label_true (s : Step) (q : Question) : label s q = true ↔ holds s q :=
  @decide_eq_true_iff _ (Classical.propDecidable _)

public theorem same_label {s t : Step} : label s = label t ↔ ∀ q, holds s q ↔ holds t q := by
  simp only [← label_true]
  exact ⟨fun h q => by rw [h], fun h => funext fun q => Bool.eq_iff_iff.mpr (h q)⟩

public theorem pre_answers (s : Step) :
    (label s).pre = ProofContexts.answers (StateCoverage.read s.cfg s.before s.past) :=
  funext fun b => Bool.eq_iff_iff.mpr ((label_true s (.pre b)).trans (ProofContexts.faithful s.run b).symm)

public theorem post_answers (s : Step) :
    (label s).post = ProofContexts.answers (StateCoverage.read s.cfg s.after (s.before :: s.past)) :=
  funext fun b => Bool.eq_iff_iff.mpr ((label_true s (.post b)).trans
    (ProofContexts.faithful (.step s.run s.ran) b).symm)

public def Realized (p : Profile) : Prop := ∃ s : Step, label s = p

/-- For the full recorded-action table, require witnesses as well as an upper
bound. It is a table of profiles, not sets of profiles for pairs of snapshots. -/
public structure ExactTable (rows : List Profile) : Prop where
  nodup : rows.Nodup
  mem_iff (p : Profile) : p ∈ rows ↔ Realized p

/-- Distinct, witnessed projections give a certified lower bound without
assuming the projection has already distinguished every pair of full labels. -/
public theorem projected_lower_bound {α : Type} (project : Profile → α) {keys : List α}
    (distinct : keys.Nodup) (occurs : ∀ k ∈ keys, ∃ s : Step, project (label s) = k)
    {rows : List Profile} (complete : ∀ s, label s ∈ rows) : keys.length ≤ rows.length := by
  have sub : keys ⊆ rows.map project := by
    intro k hk
    obtain ⟨s, eq⟩ := occurs k hk
    exact List.mem_map.mpr ⟨_, complete s, eq⟩
  simpa only [List.length_map] using distinct.length_le_of_subset sub

end ConsensusCoverage.ActionProfile
