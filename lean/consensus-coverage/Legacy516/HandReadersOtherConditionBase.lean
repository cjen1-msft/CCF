module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Condition

open CCF Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def blocked (self : NodeID) (st : NodeState) (n : NodeID) (m : Message) : Prop :=
  (match m with | .appendEntriesResponse _ | .requestVoteResponse _ | .requestPreVoteResponse _ => true
                | _ => false) = true ∧ n ∉ eligiblePeers st self
instance (self st n m) : Decidable (blocked self st n m) := by unfold blocked; infer_instance

abbrev reject (z : NodeState) (r : AppendEntriesRequest) :=
  let w := AssistReplyA.prepared z r
  r.term < w.currentTerm ∨ ¬appendEntryMatchesLog w r

def inner (self : NodeID) (pre : NodeState) (m : Message) : Bool :=
  let z := observeTerm pre m
  match m with
  | .appendEntriesResponse r => decide (z.role ≠ .primary ∨ r.success = true)
  | .appendEntriesRequest r => decide (reject z r ∨ AssistConflictA.Bad z r)
  | .requestVoteResponse r => decide (z.role = .candidate ∧ r.term = z.currentTerm ∧ r.voteGranted)
  | .requestPreVoteResponse r => decide (z.role = .preVoteCandidate ∧ r.term = z.currentTerm ∧ r.voteGranted)
  | .proposeRequestVoteRequest k => decide (k = z.currentTerm ∧ canStartElection z self)
  | _ => false

abbrev firstVote (n : NodeID) (st : NodeState) := SelfQuorumCasesB.pre n st
abbrev timeQuorum (n : NodeID) (st : NodeState) :=
  hasQuorum (firstVote n st).activeConfigurations (firstVote n st).preVotesGranted

def test (pos : Bool) (self : NodeID) (st : NodeState) : Event → Bool
  | .internal (.append _) => true
  | .internal (.timeout .election) =>
    if pos then decide (timeQuorum self st) else
      decide (¬timeQuorum self st ∨ ¬Promotion.elects self (freshCandidate self (firstVote self st)))
  | .receive n m => if pos then decide (blocked self st n m) || inner self st m else decide (¬blocked self st n m)
  | _ => false

def column (pos : Bool) : Classes.StepBranch := if pos then .ite__condition_pos else .ite__condition_neg

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Fresh := ¬Now f c.actor c.post
abbrev Answer (pos : Bool) := Fresh c ∧ test pos c.actor c.pre c.event
abbrev Receive (caps : Caps) (n : NodeID) (st : NodeState) (src : NodeID) (msg : Message) :=
  (reach% step_ite__condition_pos[0,0]) f t c caps n st src msg
abbrev Local (caps : Caps) (n : NodeID) (i : Input) :=
  (reach% step_ite__condition_pos[1,0,0]) f t c caps n i
abbrev Timeout (caps : Caps) (n : NodeID) (st : NodeState) :=
  (reach% step_ite__condition_pos[1,2]) f t c caps n st

theorem receive_iff {caps n st src m} : Receive c caps n st src m ↔
    Fresh c ∧ n = c.actor ∧ st = c.pre ∧ c.event = .receive src m ∧ caps = Capabilities.record n := by
  constructor
  · rintro ⟨e,a,o,h,ev,run,fr,ran,cap⟩
    have ⟨fresh,who,pre,what⟩ := (Observe.receive_iff c).mp ⟨e,a,o,h,ev,run,fr,ran⟩
    exact ⟨fresh,who,pre,what,cap⟩
  · rintro ⟨fresh,rfl,rfl,ev,rfl⟩
    obtain ⟨e,a,o,h,eq,run,fr,ran⟩ := (Observe.receive_iff c (st := c.pre) (self := c.actor)).mpr ⟨fresh,rfl,rfl,ev⟩
    exact ⟨e,a,o,h,eq,run,fr,ran,rfl⟩

theorem local_iff {caps n i} : Local c caps n i ↔
    Fresh c ∧ n = c.actor ∧ c.event = .internal i ∧ caps = Capabilities.record n := by
  constructor
  · rintro ⟨st,e,a,o,h,ev,run,fr,ran,cap⟩
    obtain ⟨fresh,n,_,what⟩ := (Promotion.input_iff c).mp ⟨e,a,o,h,ev,run,fr,ran⟩
    exact ⟨fresh,n,what,cap⟩
  · rintro ⟨fresh,rfl,ev,rfl⟩
    obtain ⟨e,a,o,h,eq,run,fr,ran⟩ := (Promotion.input_iff c (st := c.pre) (self := c.actor)).mpr ⟨fresh,rfl,rfl,ev⟩
    exact ⟨_,e,a,o,h,eq,run,fr,ran,rfl⟩

theorem timeout_iff {caps n st} : Timeout c caps n st ↔ Fresh c ∧ n = c.actor ∧ st = c.pre ∧
    c.event = .internal (.timeout .election) ∧ caps = Capabilities.record n := by
  constructor
  · rintro ⟨_,⟨e,a,o,h,ev,run,fr,ran,cap⟩,rfl,_,_⟩
    obtain ⟨fresh,n,st,what⟩ := (Promotion.input_iff c).mp ⟨e,a,o,h,ev,run,fr,ran⟩
    exact ⟨fresh,n,st,what,cap⟩
  · rintro ⟨fresh,rfl,rfl,ev,rfl⟩
    obtain ⟨e,a,o,h,eq,run,fr,ran⟩ := (Promotion.input_iff c (st := c.pre) (self := c.actor)).mpr ⟨fresh,rfl,rfl,ev⟩
    exact ⟨_,⟨e,a,o,h,eq,run,fr,ran,rfl⟩,rfl,rfl,fr⟩
end

end ConsensusCoverage.HandReadersOther.Condition
