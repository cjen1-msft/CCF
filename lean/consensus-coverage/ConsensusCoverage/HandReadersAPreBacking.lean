module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.PreBacking

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

inductive Case where | zero | covered | prior

def column : Case → Classes.StepBranch
  | .zero => .pre_split_pre_backed_inl
  | .covered => .pre_split_pre_backed_inr
  | .prior => .pre_split_backing_inl

def test (kind : Case) (cfg : FullProfile.Configuration) (h : List State) (pre post : NodeState) :=
  match kind with
  | .zero => pre.commitIndex == 0
  | .covered => (CommitKeys.keys (cfg.min?.getD 0) h).any fun (_,p) => decide (pre.log.take pre.commitIndex <+: p)
  | .prior => (CommitKeys.keys (cfg.min?.getD 0) h).any fun (e,p) =>
    decide (e ≤ post.currentTerm - 1 ∧ pre.log.take pre.commitIndex <+: p)

def reader (kind : Case) : Reader := fun cfg before act after past =>
  actorRead (fun _ pre _ post => decide (pre.currentTerm < post.currentTerm) &&
    test kind cfg (before :: past) pre post) cfg before act after past &&
  (actorRead (fun _ _ _ post => post.role == .candidate) cfg before act after past ||
    Election.reader cfg before act after past)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Elect := ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex
private abbrev Gate := c.pre.currentTerm < c.post.currentTerm ∧ (c.post.role = .candidate ∨ Elect c)
private abbrev Part := c.pre.log.take c.pre.commitIndex
private def Condition : Case → Prop
  | .zero => c.pre.commitIndex = 0
  | .covered => ∃ e p, Committed f e p ∧ Part c <+: p
  | .prior => ∃ e p, Committed f e p ∧ e ≤ c.post.currentTerm - 1 ∧ Part c <+: p

private abbrev Here (term : Nat) := (reach% step_pre_split_pre_backed_inl[0]) f t c c term
private abbrev ElectedSite (term : Nat) := (reach% step_pre_split_pre_backed_inl[5]) f t c c term

local macro "along " h:term : tactic => `(tactic| {
  have tail := $h
  repeat' first | exact tail | exact tail.1 | obtain ⟨_,tail⟩ := tail })

private theorem local_site {term} (h : Here c term) : Gate c ∧ term = c.post.currentTerm := by
  obtain ⟨st,origin,_,_,next,_,eq⟩ := h
  have same : st = c.post := by along origin
  subst st
  have role := origin.2.2.1
  exact ⟨⟨by omega,.inl role⟩,eq⟩

private theorem sources (gate : Gate c) : Here c c.post.currentTerm ∨ ElectedSite c c.post.currentTerm := by
  obtain ⟨higher,role | election⟩ := gate
  · exact .inl (DeepHistoryCases.campaign c role higher)
  · have root := Election.new_site c election
    obtain ⟨_,_,_,cases_,_,roles,sub,floor⟩ := c.electStep election
    exact .inr ⟨root,cases_,roles,sub,floor,election,higher,election,rfl,rfl⟩

local macro "extractSite " c:ident origin:ident : tactic => `(tactic| {
  first | exact local_site $c $origin
        | have e : Elect $c := by along $origin
          have lt : ($c).pre.currentTerm < ($c).post.currentTerm := by along $origin
          exact ⟨⟨lt,.inr e⟩,by along $origin⟩ })

private theorem necessary (kind : Case) (yes : sig c (column kind)) : Gate c ∧ Condition c kind := by
  cases kind
  all_goals
    rcases yes with h | h | h | h | h | h | h | h | h | h | h | h | h | h
    all_goals
      obtain ⟨term,origin,_,_,w,back,tail⟩ := h
      have site : Gate c ∧ term = c.post.currentTerm := by extractSite c origin
      refine ⟨site.1,?_⟩
      first
      | exact tail.1
      | obtain ⟨e,p,m,_,sub⟩ := tail.1
        exact ⟨e,p,m,sub⟩
      | have prior : ∃ e p, f.logs.committed e p ∧ e ≤ term - 1 ∧ Part c <+: p := by along tail
        rw [site.2] at prior
        exact prior

private theorem sufficient (kind : Case) (gate : Gate c) (condition : Condition c kind) :
    sig c (column kind) := by
  have backed := c.inv.commit_backed c.actor c.pre c.pre_now
  have higher := gate.1
  obtain origin | origin := sources c gate
  all_goals
    cases kind
    all_goals
      first
      | left; refine ⟨_,origin,backed.1,backed.2,?_⟩
      | iterate 5 right
        left
        refine ⟨_,origin,backed.1,backed.2,?_⟩
      first
      | exact ⟨0,.inl condition,condition,higher⟩
      | obtain ⟨e,p,m,sub⟩ := condition
        have pack := And.intro m (And.intro (Nat.le_refl e) sub)
        exact ⟨e,.inr ⟨e,p,pack⟩,⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,m,pack.2,pack.2.1,sub,higher⟩
      | obtain ⟨e,p,m,bounded,sub⟩ := condition
        have pack := And.intro m (And.intro (Nat.le_refl e) sub)
        have prior := And.intro m (And.intro bounded sub)
        exact ⟨e,.inr ⟨e,p,pack⟩,⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,m,pack.2,pack.2.1,sub,
          ⟨e,p,prior⟩,e,⟨p,prior⟩,p,prior,m,prior.2,bounded,sub,higher,m,.inl ⟨e,p,prior⟩⟩
end

def exactReader (kind : Case) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have elected := Bool.eq_iff_iff.mp (Election.exactReader.eq_label s)
    rw [label_true,holds,sig_iff] at elected
    change step_led_after_elected_after_inr _ _ c ↔ Election.reader s.cfg s.before s.act s.after s.past = true at elected
    rw [Election.iff_election] at elected
    have cut : test kind s.cfg (s.before :: s.past) c.pre c.post = true ↔ Condition c kind := by
      cases kind <;> simp only [test,Condition,beq_iff_eq,List.any_eq_true,Prod.exists,
        decide_eq_true_eq,CommitKeys.step_mem,CommitKeys.committedBefore,Part,Committed]
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,Bool.and_eq_true,Bool.or_eq_true,actorRead_at,actorRead_at]
    change sig c (column kind) ↔ _
    rw [show sig c (column kind) ↔ Gate c ∧ Condition c kind from ⟨necessary c kind,fun h => sufficient c kind h.1 h.2⟩]
    simp only [Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq,←elected,Gate]
    grind

end ConsensusCoverage.HandReadersA.PreBacking
