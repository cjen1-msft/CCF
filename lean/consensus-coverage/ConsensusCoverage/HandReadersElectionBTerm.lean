module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBReflect
public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.HandReadersElectionBReflect
import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersElectionBReflect

namespace ConsensusCoverage.HandReadersElectionB.Term

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
set_option maxRecDepth 16384
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option Elab.async false

private theorem backing_ceiling {f : Frame} (l : List Entry) (d : Nat) (P : Nat → List Entry → Prop) :
    (∃ w, Backed f l d w ∧
      (∃ e p, Committed f e p ∧ e ≤ w ∧ l.take d <+: p) ∧
      ∃ e, (∃ p, Committed f e p ∧ e ≤ w ∧ l.take d <+: p) ∧
      ∃ p, (Committed f e p ∧ e ≤ w ∧ l.take d <+: p) ∧ Committed f e p ∧
        (e ≤ w ∧ l.take d <+: p) ∧ e ≤ w ∧ l.take d <+: p ∧ P e p) ↔
      ∃ e p, Committed f e p ∧ l.take d <+: p ∧ P e p := by
  constructor
  · rintro ⟨_,_,_,e,_,p,_,m,_,_,sub,h⟩
    exact ⟨e,p,m,sub,h⟩
  · rintro ⟨e,p,m,sub,h⟩
    have row := And.intro m (And.intro (Nat.le_refl e) sub)
    exact ⟨e,.inr ⟨e,p,row⟩,⟨e,p,row⟩,e,⟨p,row⟩,p,row,m,row.2,row.2.1,sub,h⟩

private theorem any_backing {f : Frame} (l : List Entry) (d : Nat) :
    (∃ w, Backed f l d w) ↔ d = 0 ∨ ∃ e p, Committed f e p ∧ l.take d <+: p := by
  constructor
  · rintro ⟨_,z | ⟨e,p,m,_,sub⟩⟩
    · exact .inl z
    · exact .inr ⟨e,p,m,sub⟩
  · rintro (z | ⟨e,p,m,sub⟩)
    · exact ⟨0,.inl z⟩
    · exact ⟨e,.inr ⟨e,p,m,Nat.le_refl _,sub⟩⟩

open CCF in
private theorem any_quorum (a : List Configuration) :
    (∃ vs, hasQuorum a vs) ↔ CommitMonitor.quorum a (fun _ => true) = true := by
  simp [CommitMonitor.quorum_iff]

open CCF in
private theorem common_voter (a b : List Configuration) (G P : NodeID → Prop) :
    (∃ vs, hasQuorum a vs ∧ ∃ xs, (hasQuorum b xs ∧ ∀ v ∈ xs, G v) ∧
      hasQuorum b xs ∧ (∀ v ∈ xs, G v) ∧ ∃ v, (v ∈ xs ∧ v ∈ vs) ∧ v ∈ xs ∧ v ∈ vs ∧ P v) ↔
      CommitMonitor.quorum a (fun _ => true) = true ∧
      (∃ xs, hasQuorum b xs ∧ ∀ v ∈ xs, G v) ∧ ∃ v, G v ∧ P v := by
  rw [← any_quorum]
  constructor
  · rintro ⟨vs,h,xs,q,_,_,v,_,m,_,p⟩
    exact ⟨⟨vs,h⟩,⟨xs,q⟩,v,q.2 v m,p⟩
  · rintro ⟨⟨vs,h⟩,⟨xs,q,g⟩,v,good,p⟩
    have extend {cs : List Configuration} {ys : Finset NodeID} (yes : hasQuorum cs ys) :
        hasQuorum cs (ys ∪ Finset.ofList [v]) :=
      ReadersShapes.quorum_mono (fun _ m => Finset.mem_union.mpr (.inl m)) yes
    have mem (ys : Finset NodeID) : v ∈ ys ∪ Finset.ofList [v] :=
      Finset.mem_union.mpr (.inr (Finset.mem_ofList.mpr (by simp)))
    have support (w) (m : w ∈ xs ∪ Finset.ofList [v]) : G w := by
      rcases Finset.mem_union.mp m with m | m
      · exact g w m
      · have same : w = v := by simpa using Finset.mem_ofList.mp m
        exact same ▸ good
    exact ⟨_,extend h,_,⟨extend q,support⟩,extend q,support,v,⟨mem _,mem _⟩,mem _,mem _,p⟩

private theorem selected_voter {α : Type} (a b : List Configuration)
    (H : NodeID → α → Prop) (L : α → Prop) (P : Prop) :
    (∃ vs, hasQuorum a vs ∧ ∃ xs,
      (hasQuorum b xs ∧ ∀ v ∈ xs, ∃ x, H v x ∧ L x) ∧
      hasQuorum b xs ∧ (∀ v ∈ xs, ∃ x, H v x ∧ L x) ∧
      ∃ v, (v ∈ xs ∧ v ∈ vs) ∧ v ∈ xs ∧ v ∈ vs ∧ ∃ x, (H v x ∧ L x) ∧ H v x ∧ L x ∧ P) ↔
      CommitMonitor.quorum a (fun _ => true) = true ∧
      (∃ xs, hasQuorum b xs ∧ ∀ v ∈ xs, ∃ x, H v x ∧ L x) ∧ P := by
  rw [common_voter]
  constructor
  · rintro ⟨q,r,_,_,_,_,_,_,p⟩
    exact ⟨q,r,p⟩
  · rintro ⟨q,⟨xs,r,g⟩,p⟩
    obtain ⟨v,m⟩ := HandReadersA.CampaignRows.voter_of_quorum r
    obtain ⟨x,h,l⟩ := g v m
    exact ⟨q,⟨xs,r,g⟩,v,g v m,x,⟨h,l⟩,h,l,p⟩

open Lean Elab Command in
set_option maxHeartbeats 0 in
run_cmd liftTermElabM do
  Reflect.compile `ConsensusCoverage.HandReadersElectionB.Term.Reflected
    #[``step_termAt_le_of_mem_found_some] #[``backing_ceiling,``any_backing,``selected_voter]

def exactReader : HandReadersA.Exact .termAt_le_of_mem_found_some :=
  Reflect.exact _ (@Reflected.R.step_termAt_le_of_mem_found_some)
    (fun c x ok => Reflected.R.step_termAt_le_of_mem_found_some_iff _ _ c x ok)

end ConsensusCoverage.HandReadersElectionB.Term
