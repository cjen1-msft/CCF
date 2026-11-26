module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistConflictA

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA AssistReplyA AssistReplyBranchesA
set_option maxRecDepth 8192
set_option maxHeartbeats 700000

private abbrev base (z : NodeState) (r : AppendEntriesRequest) : NodeState := {prepared z r with primaryKnown := true}
private abbrev limit (r : AppendEntriesRequest) := min r.primaryCommit (r.prevLogIndex + r.entries.length)
private abbrev trim (z : NodeState) (r : AppendEntriesRequest) :=
  match conflictIndex z.log r with | some i => z.log.take (i - 1) | none => z.log
private abbrev Bad (z : NodeState) (r : AppendEntriesRequest) :=
  r.prevLogIndex < (prepared z r).commitIndex ∨
    (firstTermConflictIndex (base z r) r).isSome = true ∧ (!(prepared z r).isNewFollower) = true

private abbrev Rest (self src : NodeID) (z : NodeState) (r : AppendEntriesRequest) (a : NodeState) (sent : List Model.Envelope) :=
  (a.log = z.log ∧ a.commitIndex = z.commitIndex ∧ ∀ e ∈ sent, e.source = self ∧
    ∃ p, e.payload = .appendEntriesResponse p ∧ p.success = false) ∨
  (r.term = z.currentTerm ∧ z.commitIndex ≤ r.prevLogIndex ∧ appendEntryMatchesLog z r ∧
    a.log = acceptLog z.log r ∧ a.commitIndex = max z.commitIndex (maxCommittableIndexUpTo a.log (limit r)) ∧
    ∃ e, sent = [e] ∧ e.source = self ∧ e.target = src ∧
      e.payload = .appendEntriesResponse ⟨z.currentTerm,true,r.prevLogIndex+r.entries.length⟩)

private theorem common (self src : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    (a : NodeState) (sent : List Model.Envelope) (rest : Rest self src z r a sent)
    (term : a.currentTerm = (prepared z r).currentTerm) (voted : a.votedFor = (prepared z r).votedFor)
    (match_ : a.matchIndex = (prepared z r).matchIndex)
    (role : a.role = (prepared z r).role ∨ a.role = .none)
    (cand : a.role = .candidate → a = prepared z r) : AEReply self src z r a sent := by
  have h := fields z r
  refine ⟨term.trans h.term,voted.trans h.vote,match_.trans h.match_,?_,?_,rest⟩
  · rcases role with same | gone
    · exact h.role.elim (fun e => .inl (same.trans e)) (fun e => .inr (.inl (same.trans e)))
    · exact .inr (.inr gone)
  · intro active
    have aeq := cand active
    exact aeq.trans (h.cand (aeq ▸ active))

private theorem tail (self src : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    (same : r.term = z.currentTerm) (safe : z.commitIndex ≤ r.prevLogIndex) (accept : appendEntryMatchesLog z r)
    (v : NodeState) (vLog : v.log = trim z r) (vTerm : v.currentTerm = (prepared z r).currentTerm)
    (vCommit : v.commitIndex = (prepared z r).commitIndex) (vVote : v.votedFor = (prepared z r).votedFor)
    (vMatch : v.matchIndex = (prepared z r).matchIndex) (vRole : v.role = (prepared z r).role) :
    Sends (Notification := Notification) (AEReply self src z r)
      (match handleAppendEntiresFromPrimary self v r with
       | (a,response) => do (Capabilities.record self).send (.appendEntriesResponse response) src; pure a) := by
  have p := fields z r
  have spec := fromLeader_spec self v r
  generalize eq : handleAppendEntiresFromPrimary self v r = pair at spec ⊢
  obtain ⟨a,reply⟩ := pair
  obtain ⟨term,vote,match_,_,role,log,commit,response⟩ := spec
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq' => Sends.pure' ?_
  subst sent
  refine common self src z r _ _ (.inr ⟨same,safe,accept,?_,?_,_,rfl,rfl,rfl,?_⟩)
    (term.trans vTerm) (vote.trans vVote) (match_.trans vMatch) (vRole ▸ role) ?_
  · rw [log,vLog]; rfl
  · rw [commit,vCommit,p.commit]
  · change reply = _ at response
    rw [response,vTerm,p.term]
  · intro c
    rcases role with h | h
    · exact (p.stays same (vRole ▸ h ▸ c)).elim
    · exact (Role.noConfusion (h ▸ c : Role.none = Role.candidate))

inductive Case where | clear | conflict | retired
def column : Case → Classes.StepBranch
  | .clear => .aeReply_conflict_none
  | .conflict => .aeReply_conflict_some
  | .retired => .aeReply_role_inr

private def guard (k : Case) (self : NodeID) (z : NodeState) (r : AppendEntriesRequest) : Bool :=
  match k with
  | .clear => decide (firstTermConflictIndex (base z r) r = none)
  | .conflict => (firstTermConflictIndex (base z r) r).isSome
  | .retired => decide (firstTermConflictIndex (base z r) r = none ∧ (handleAppendEntiresFromPrimary self (base z r) r).1.role = .none)

private def check (s : Step) (k : Case) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    match x.event with
    | .receive _ (.appendEntriesRequest r) =>
      let z := observed x.base.pre r
      decide (x.base.changed = true ∧ r.term = z.currentTerm ∧ appendEntryMatchesLog z r ∧
        z.commitIndex ≤ r.prevLogIndex ∧ ¬Bad z r) && guard k x.base.actor z r
    | _ => false

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (k : Case) {self src z r} (call : (reach% step_aeReply_conflict_none[15]) f t c self src z r)
    (same : r.term = z.currentTerm) (matched : appendEntryMatchesLog z r) (safe : z.commitIndex ≤ r.prevLogIndex)
    (proceed : ¬Bad z r) (g : guard k self z r = true) : sig c (column k) := by
  let w := prepared z r
  let v := base z r
  have p := fields z r
  have lo := Nat.le_of_eq same
  have accept : ¬(r.term < w.currentTerm ∨ ¬appendEntryMatchesLog w r) := by
    intro h
    rcases h with lt | mismatch
    · exact (Nat.not_lt_of_ge (Nat.le_of_eq (p.term.trans same.symm))) lt
    · exact mismatch (by simpa only [appendEntryMatchesLog,p.log,w] using matched)
  have eq : firstTermConflictIndex v r = conflictIndex z.log r := by
    rw [firstTermConflictIndex_eq]
    change conflictIndex w.log r = _
    rw [p.log]
  cases k with
  | clear =>
    iterate 15 right
    left
    have clearEq : firstTermConflictIndex v r = none := of_decide_eq_true g
    exact ⟨self,src,z,r,call,accept,proceed,clearEq,clearEq,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,
      common self src z r,same,p.stays same,matched,safe,tail self src z r same safe matched,eq⟩
  | conflict =>
    iterate 15 right
    left
    obtain ⟨i,found⟩ := Option.isSome_iff_exists.mp (show (firstTermConflictIndex v r).isSome = true from g)
    exact ⟨self,src,z,r,call,accept,proceed,i,found,found,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,
      common self src z r,same,p.stays same,matched,safe,tail self src z r same safe matched,eq⟩
  | retired =>
    have ⟨clearEq,gone⟩ := (of_decide_eq_true g : firstTermConflictIndex v r = none ∧
      (handleAppendEntiresFromPrimary self v r).1.role = .none)
    let res := handleAppendEntiresFromPrimary self v r
    have spec := fromLeader_spec self v r
    obtain ⟨term,voted,match_,votes,role,log,commit,response⟩ := spec
    have pair : res = (res.1,{term := v.currentTerm, success := true, lastLogIndex := r.prevLogIndex + r.entries.length}) :=
      Prod.ext rfl response
    have lc := And.intro log commit
    have rlc := And.intro role lc
    have vl := And.intro votes rlc
    have ml := And.intro match_ vl
    iterate 102 right
    left
    exact ⟨self,src,z,r,call,accept,proceed,clearEq,clearEq,res.1,pair,term,⟨voted,ml⟩,voted,ml,match_,vl,votes,rlc,
      role,lc,log,commit,commit,gone,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,same,p.stays same,
      matched,safe,eq,term,voted,match_,votes,role,log,commit,response⟩

private theorem sound (s : Step) (k : Case) (yes : check s k = true) : label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some] at yes
  split at yes <;> try contradiction
  rename_i n r ev
  simp only [Bool.and_eq_true,decide_eq_true_eq] at yes
  obtain ⟨⟨fresh,same,matched,safe,proceed⟩,g⟩ := yes
  obtain ⟨call,_⟩ := seed ok fresh ev
  exact (label_true _ _).mpr ((sig_iff _ _).mpr (casesOf k call same matched safe proceed g))

open DeepSchedulesB in
local macro "at_reply " k:term:arg r:term:arg i:num : term =>
  `(checked (column $k) (DeepSchedulesB.Replay.atStep $r $i) (check · $k) (by decide +kernel) (sound · $k))

open DeepSchedulesB in
def certificates : List Certificate :=
  [at_reply .clear firstAck 1,at_reply .conflict divergent 11,at_reply .retired retireOnHeartbeat 6]

end ConsensusCoverage.AssistConflictA
