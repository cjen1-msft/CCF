module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.CommitMonitor
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepHistoryCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open ReadersAtoms GuardedDomain ActionProfile QueueSamplesA

set_option maxRecDepth 8192

-- Search only snapshot data. Each counted voter must have observed this
-- candidate log's signed prefix in the same term before the current step.
def oldFacts (x : XView) (l : List Entry) (k b i : Nat) : Bool :=
  let h := x.base.before :: x.base.past
  decide (2 ≤ k ∧ b ≤ i ∧ i ≤ l.length ∧ isSignatureAt l i = true ∧ termAt l i = k) &&
    canonAt x.base.bootstrap k l h &&
    CommitMonitor.quorum ((activeConfigurations l b).filter (·.index ≤ i)) fun v =>
      (observations h v).any fun o => decide (o.currentTerm = k ∧ l.take i <+: o.log)

theorem oldFacts_sound [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
    {x : XView} (ok : x.Matches c) {l k b i} (yes : oldFacts x l k b i = true) :
    CommitFacts f.logs l k b i := by
  simp only [oldFacts,Bool.and_eq_true,decide_eq_true_eq,CommitMonitor.quorum_iff,
    List.any_eq_true] at yes
  obtain ⟨⟨⟨floor,base,within,sig_,term⟩,canon⟩,xs,quorum,acks⟩ := yes
  have canonical := (X.canon_before ok k l).mpr canon
  have copy := c.inv.copyLog canonical
  refine ⟨canonical,copy.rooted,copy.sorted,floor,base,within,sig_,term,xs,quorum,?_⟩
  intro v member
  obtain ⟨o,mem,eq,sub⟩ := acks v member
  exact ⟨o.log,eq ▸ (X.seen_before ok v o.currentTerm o.log).mpr mem,sub⟩

theorem campaign [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (role : c.post.role = .candidate) (later : c.pre.currentTerm < c.post.currentTerm) :
    (reach% step_pre_split_pre_backed_inl[0]) f t c c c.post.currentTerm := by
  have camp := Summary.candidate c.sum role
  obtain ⟨floor,tc⟩ := c.campaign_three camp
  obtain ⟨eng,next,vote,self⟩ := camp.2.2.2.resolve_right
    fun h => (Nat.ne_of_lt later) h.2.1.symm
  have now := c.post_now
  have fresh : ¬ Now f c.actor c.post := fun old =>
    (Nat.ne_of_lt later) (congrArg NodeState.currentTerm (c.now_pre old)).symm
  have call : (reach% step_pre_split_pre_backed_inl[0,0]) f t c c c.post :=
    ⟨⟨now,role,fun h => fresh h.1,rfl⟩,now,role,now,role,camp.2.1,camp.2.2.1,camp.2.2.2,
      floor,tc,⟨eng,next,vote,self⟩,eng,⟨next,vote,self⟩,next,⟨vote,self⟩,now,role,camp,rfl,rfl⟩
  exact ⟨_,call,camp.2.1,camp.2.2.1,next,rfl,rfl⟩

inductive Case where | zero | nonzero | prior | later | fresh | backed | low | high | baseLe | baseGt

def column : Case → Classes.StepBranch
  | .zero => .pre_split_pre_backed_inl
  | .nonzero => .pre_split_pre_backed_inr
  | .prior => .pre_split_backing_inl
  | .later => .pre_split_backing_inr
  | .fresh => .backing_split_cert_fresh
  | .backed => .backing_split_cert_backed
  | .low => .backing_split_low_pos
  | .high => .backing_split_low_neg
  | .baseLe => .backing_split_baseLe_pos
  | .baseGt => .backing_split_baseLe_neg

private def condition (k : Case) (pre post : NodeState) (term b : Nat) : Prop :=
  match k with
  | .zero => pre.commitIndex = 0
  | .nonzero | .backed => True
  | .fresh => b = 0
  | .prior => term ≤ post.currentTerm - 1
  | .later | .baseLe => post.currentTerm - 1 < term ∧ b ≤ pre.commitIndex
  | .low => b = 0 ∧ term ≤ post.currentTerm - 1
  | .high => b = 0 ∧ ¬term ≤ post.currentTerm - 1
  | .baseGt => post.currentTerm - 1 < term ∧ ¬b ≤ pre.commitIndex

private instance (k : Case) (pre post : NodeState) (term b : Nat) : Decidable (condition k pre post term b) :=
  by cases k <;> unfold condition <;> infer_instance

private def check (s : Step) (k : Case) (term b i : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    decide (x.base.post.role = .candidate ∧ x.base.pre.currentTerm < x.base.post.currentTerm ∧
      condition k x.base.pre x.base.post term b) &&
    ((x.base.before :: x.base.past).flatMap fun a => a.nodes.map (fun p => p.2.log)).any fun l =>
      decide ((term,l.take i) ∈ x.committedBefore ∧ x.base.pre.log.take x.base.pre.commitIndex <+: l.take i) &&
        oldFacts x l term b i

local macro "backing_fields " c:term:arg origin:term:arg any_:term:arg other:term:arg
    term:term:arg part:term:arg commits:term:arg sub:term:arg : tactic =>
  `(tactic| refine ⟨($c).post.currentTerm,$origin,$any_,$other,$term,
    Or.inr ⟨$term,$part,$commits,Nat.le_refl _,$sub⟩,
    ⟨$term,$part,$commits,Nat.le_refl _,$sub⟩,$term,⟨$part,$commits,Nat.le_refl _,$sub⟩,
    $part,⟨$commits,Nat.le_refl _,$sub⟩,$commits,⟨Nat.le_refl _,$sub⟩,Nat.le_refl _,$sub,?_⟩)

theorem sound (s : Step) (k : Case) (term b i : Nat) (passed : check s k term b i = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at passed
  obtain ⟨⟨role,newer,cond⟩,l,_,⟨mem,sub⟩,facts⟩ := passed
  rw [← View.pre_eq ok.1] at newer cond sub
  rw [← View.post_eq ok.1] at role newer cond
  have call := campaign c role newer
  have f := oldFacts_sound ok facts
  have m := (X.committed_before ok term (l.take i)).mpr mem
  have all_ := c.inv.commit_backed c.actor c.pre c.pre_now
  have chain := c.inv.commitChains term (l.take i) m
  have len := List.length_take_of_le c.frontier_pre
  let bound := c.post.currentTerm-1
  have pack := And.intro m (And.intro (Nat.le_refl term) sub)
  have root : (reach% step_backing_split_cert_fresh[0]) _ _ c c.pre.log c.pre.commitIndex term (l.take i) := by
    exact ⟨_,call,all_.1,all_.2,term,Or.inr ⟨term,_,pack⟩,⟨term,_,pack⟩,⟨_,pack⟩,pack,
      m,pack.2,Nat.le_refl _,sub,newer,m,rfl,rfl⟩
  have fuller : (reach% step_backing_split_cert_backed[0]) _ _ c c.pre.log c.pre.commitIndex term bound (l.take i) := by
    exact ⟨_,call,all_.1,all_.2,term,Or.inr ⟨term,_,pack⟩,⟨term,_,pack⟩,⟨_,pack⟩,pack,
      m,pack.2,Nat.le_refl _,sub,newer,m,rfl,rfl,rfl⟩
  have baseSub := take_prefix_take l f.baseLe
  have ih := fun (p : s.frame.logs.committed term (l.take i)) (sub' : c.pre.log.take c.pre.commitIndex <+: l.take i) =>
    backing_split (bound := bound) chain p sub' c.frontier_pre
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | zero =>
    exact Or.inl ⟨_,call,all_.1,all_.2,term,Or.inl cond,cond,newer⟩
  | nonzero | prior | later =>
    left
    backing_fields c call all_.1 all_.2 term (l.take i) m sub
    first
    | exact newer
    | have orig := And.intro m (And.intro cond sub)
      exact ⟨⟨term,_,orig⟩,term,⟨_,orig⟩,_,orig,m,orig.2,cond,sub,newer,m,.inl ⟨term,_,orig⟩⟩
    | have orig := And.intro f (And.intro cond.1 (And.intro cond.2 sub))
      exact ⟨⟨l,term,b,i,orig⟩,l,⟨term,b,i,orig⟩,term,⟨b,i,orig⟩,b,⟨i,orig⟩,i,orig,
        f,orig.2,cond.1,orig.2.2,cond.2,sub,newer,m,.inr ⟨l,term,b,i,orig⟩⟩
  | fresh =>
    have zero : b = 0 := cond
    subst b
    exact Or.inl ⟨_,_,_,_,root,l,term,i,f,m,sub,sub,c.frontier_pre,len,chain,m⟩
  | low | high =>
    have zero : b = 0 := cond.1
    subst b
    exact Or.inl ⟨_,_,_,_,_,fuller,l,term,i,f,m,sub,cond.2,sub,c.frontier_pre,len,chain,m⟩
  | backed | baseLe | baseGt =>
    left
    refine ⟨_,_,_,_,_,fuller,l,term,b,i,term,l.take i,f,m,chain,Nat.le_refl _,baseSub,ih,m,sub,?_⟩
    first
    | exact ⟨sub,c.frontier_pre,len,chain,m⟩
    | exact ⟨Nat.not_le_of_gt cond.1,cond.2,sub,c.frontier_pre,len,chain,m⟩

open FrontierRows DeepSchedules in
local macro "history_at " k:term:arg sc:term:arg offset:num t:num b:num i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $offset)
    (check · $k $t $b $i) (by decide +kernel) (sound · $k $t $b $i))

open DeepSchedules in
def certificates : List Certificate :=
  [history_at .zero divergent 6 2 0 2,history_at .nonzero (threeTerms true) 18 3 0 3,
   history_at .prior divergent 6 2 0 2,history_at .later laggingBacked 24 3 2 3,
   history_at .fresh divergent 6 2 0 2,history_at .backed divergent 6 2 0 2,
   history_at .low divergent 6 2 0 2,history_at .high laggingBacked 24 3 0 3,
   history_at .baseLe laggingBacked 24 3 2 3,history_at .baseGt laggingBacked 24 3 3 4]

end ConsensusCoverage.DeepHistoryCases
