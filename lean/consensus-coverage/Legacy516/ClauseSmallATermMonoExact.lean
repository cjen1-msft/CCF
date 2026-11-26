module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallATermMono
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.ClauseSmallATermMono
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.ClauseSmallATermMonoSource
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.HandReadersASeen
import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.Historical
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallA.TermMonoExact

open ActionProfile ClauseExactTables ClauseQuestions TermMono
open HandReadersA HandReadersElectionB
open Consensus Consensus.Proofs Consensus.Proofs.Safety Consensus.Model.Node

set_option maxHeartbeats 2000000
set_option maxRecDepth 8192

open ExploredWitnesses in
private def schedule (extra : Bool) : FrontierRows.Run :=
  ⟨{0,1,2,3,4}, [0,1,2,3,4] ++ (if extra then [5] else []), [
    append 0 [{sig with flushes := [(1,2),(2,2)]}], deliver 0 1, deliver 0 2, deliver 1 0, deliver 2 0,
    append 0 [{cfg {0,1,2} with flushes := [(2,2),(3,2),(4,2)]},
      {sig with flushes := [(4,4)]}, {sig with flushes := [(1,5)]}],
    deliver 0 1, deliver 0 2, deliver 0 3, deliver 0 4, deliver 1 0, nom 0,
    deliver 0 1, deliver 1 2, deliver 1 3, deliver 2 1, deliver 3 1,
    deliver 0 4, nom 0]⟩

private noncomputable def sample (extra : Bool) : Option Step := do
  let run := schedule extra
  let steps ← JointWitnesses.recordedAt run (by cases extra <;> unfold FrontierRows.Run.valid <;> decide) []
  return (← steps.getLast?).val

private noncomputable def replay (extra : Bool) : Step :=
  (sample extra).get (by cases extra <;> decide +kernel)

private theorem bootstrap (extra : Bool) : (replay extra).cfg.min?.getD 0 = 0 :=
  by cases extra <;> decide +kernel

private def zeroPair (s : Step) : Bool × Bool :=
    (s.before.nodes.any (fun n => n.2.commitIndex == 0),
     s.after.nodes.any (fun n => n.2.commitIndex == 0))

private theorem zero_endpoints (extra : Bool) : zeroPair (replay extra) = (extra,extra) :=
  by cases extra <;> decide +kernel

private theorem actor_unchanged (extra : Bool) :
    let s := replay extra
    SeenRows.reader s.cfg s.before s.act s.after s.past = false :=
  by cases extra <;> decide +kernel

private theorem unchanged_answer (s : Step)
    (h : SeenRows.reader s.cfg s.before s.act s.after s.past = false) :
    changed s = false := (SeenRows.exactReader .old |>.eq_label s).trans h

private def fullLog : List Entry :=
  [⟨2,.transaction 0 {configuration := some {0,1,2,3,4}}⟩, ⟨2,.signature⟩,
   ⟨2,.transaction 1 {configuration := some {0,1,2}}⟩, ⟨2,.signature⟩, ⟨2,.signature⟩]

private def possibleLeader (n : NodeID) (st : NodeState) : Bool :=
  decide (st.currentTerm = Consensus.Model.BOOTSTRAP_TERM ∧ n = 0) || decide (3 ≤ st.currentTerm)

private def fastLeader (hist : List Consensus.Model.State) (n : NodeID) (st : NodeState) : Bool :=
  decide (st.role ≠ .candidate) &&
    (decide (st.currentTerm = Consensus.Model.BOOTSTRAP_TERM ∧ n = 0) ||
      (decide (3 ≤ st.currentTerm) && CommitMonitor.elected n st.currentTerm hist))

private theorem fastLeader_eq (h : List Consensus.Model.State) (n : NodeID) (st : NodeState) :
    fastLeader h n st = CommitKeys.leader 0 h n st := by
  have floor (yes : CommitMonitor.elected n st.currentTerm h = true) : 3 ≤ st.currentTerm := by
    obtain ⟨_,_,_,_,_,_,elect⟩ := (CommitMonitor.elected_iff _ _ _).mp yes
    obtain ⟨_,_,_,_,_,_,_,_,_,_,_,floor,_⟩ := elect
    exact floor
  cases won : CommitMonitor.elected n st.currentTerm h with
  | false => simp [fastLeader,CommitKeys.leader,won]
  | true => simp [fastLeader,CommitKeys.leader,won,floor won]

-- Check signatures before searching the history for a leader election.
private noncomputable def fastHere (s : Consensus.Model.State) (past : List Consensus.Model.State)
    (support : NodeState → Nat → Bool) : List CommitKeys.Key :=
  s.nodes.flatMap fun (n,st) =>
    let indices := (List.range (st.log.length+1)).filter (CommitKeys.certified s past support st)
    if !possibleLeader n st || indices.isEmpty then []
    else if fastLeader (s :: past) n st then
      indices.map (fun i => (st.currentTerm,st.log.take i))
    else []

private theorem fastHere_eq (s : Consensus.Model.State) (past : List Consensus.Model.State) (support) :
    fastHere s past support = CommitKeys.here 0 s past support := by
  let indices (st : NodeState) := (List.range (st.log.length+1)).filter (CommitKeys.certified s past support st)
  let out (p : NodeID × NodeState) := (indices p.2).map fun i => (p.2.currentTerm,p.2.log.take i)
  let lead (p : NodeID × NodeState) := CommitKeys.leader 0 (s :: past) p.1 p.2
  simp only [fastHere,fastLeader_eq]
  change (s.nodes.flatMap fun p => if !possibleLeader p.1 p.2 || (indices p.2).isEmpty then []
    else if lead p then out p else []) =
    (s.nodes.filter lead).flatMap out
  have same : (fun p => if !possibleLeader p.1 p.2 || (indices p.2).isEmpty then ([] : List CommitKeys.Key)
      else if lead p then out p else []) = (fun p => if lead p then out p else []) := by
    funext p
    cases possible : possibleLeader p.1 p.2 with
    | false =>
      have impossible := Bool.or_eq_false_iff.mp (by simpa only [possibleLeader] using possible)
      have no : lead p = false := by
        rw [show lead p = _ from (fastLeader_eq (s :: past) p.1 p.2).symm]
        simp only [fastLeader, impossible.1, impossible.2, Bool.false_and, Bool.false_or, Bool.and_false]
      simp [no]
    | true =>
      by_cases empty : (indices p.2).isEmpty = true
      · have nil := List.isEmpty_iff.mp empty
        have result : out p = [] := by dsimp [out]; rw [nil]; rfl
        simp [empty,result]
      · simp [empty]
  rw [same]
  generalize s.nodes = nodes
  induction nodes with
  | nil => rfl
  | cons p rest ih =>
    by_cases isLeader : lead p = true
    · rw [List.filter_cons, isLeader]
      simp only [List.flatMap_cons, isLeader, ↓reduceIte]
      exact congrArg (out p ++ ·) ih
    · have no := Bool.eq_false_iff.mpr isLeader
      rw [List.filter_cons, no]
      simp only [List.flatMap_cons, no, Bool.false_eq_true, ↓reduceIte, List.nil_append]
      exact ih

private theorem committable (extra : Bool) :
    let s := replay extra
    (2,fullLog) ∈ CommitKeys.here 0 s.after (s.before :: s.past) (fun _ b => b == 3) := by
  dsimp only
  rw [← fastHere_eq]
  cases extra <;> decide +kernel

private def keyAfter (n : Nat) : List CommitKeys.Key :=
  if n < 4 then [] else if n < 19 then [(2,fullLog.take 2)]
  else [(2,fullLog.take 2),(2,fullLog.take 4)]

private noncomputable def keyStep (h : List Consensus.Model.State) : Bool :=
  match h with
  | [] => true
  | s :: past =>
    let old := keyAfter past.length
    decide ((fastHere s past (CommitKeys.backed old) ++ old).eraseDups = keyAfter h.length)

private noncomputable def preHistory (extra : Bool) :=
  let s := replay extra
  s.before :: s.past

private theorem trace_count (extra : Bool) : (preHistory extra).length = 19 :=
  by cases extra <;> decide +kernel

private theorem check_transfer (h : List Consensus.Model.State) (i : Nat)
    (check : keyStep (h.drop i) = true)
    (old : CommitKeys.keys 0 (h.drop (i+1)) = keyAfter (h.drop (i+1)).length) :
    CommitKeys.keys 0 (h.drop i) = keyAfter (h.drop i).length := by
  rw [← List.drop_drop] at old
  generalize h.drop i = tail at *
  cases tail with
  | nil => rfl
  | cons s past =>
    change CommitKeys.keys 0 past = keyAfter past.length at old
    rw [CommitKeys.keys, old, ← fastHere_eq]
    exact of_decide_eq_true check

private theorem cycle (extra : Bool) (j : Fin 19) :
    keyStep ((preHistory extra).drop j.val) = true := by
  have check0 : ∀ i : Fin 19, keyStep ((preHistory false).drop i.val) = true := by decide +kernel
  have check1 : ∀ i : Fin 19, keyStep ((preHistory true).drop i.val) = true := by decide +kernel
  cases extra
  · exact check0 j
  · exact check1 j

private theorem transfer_history (h : List Consensus.Model.State) (i remaining : Nat)
    (done : CommitKeys.keys 0 (h.drop (i + remaining)) = keyAfter (h.drop (i + remaining)).length)
    (checks : ∀ j, i ≤ j → j < i+remaining → keyStep (h.drop j) = true) :
    CommitKeys.keys 0 (h.drop i) = keyAfter (h.drop i).length := by
  induction remaining generalizing i with
  | zero => exact done
  | succ m ih =>
    apply check_transfer h i (checks i (Nat.le_refl _) (by omega))
    apply ih (i+1)
    · rwa [show i+1+m = i+(m+1) from by omega]
    · intro j le upper
      exact checks j (by omega) (by omega)

private theorem old_keys (extra : Bool) :
    CommitKeys.keys 0 (preHistory extra) = [(2,fullLog.take 2),(2,fullLog.take 4)] := by
  have actual := transfer_history (preHistory extra) 0 19 (by
    rw [Nat.zero_add, List.drop_eq_nil_of_le (Nat.le_of_eq (trace_count extra))]
    rfl) (fun j _ bound => by
    exact cycle extra ⟨j,bound⟩)
  rw [List.drop_zero, trace_count] at actual
  exact actual

private theorem has_backing (s : Step) {a b : Bool}
    (zeros : zeroPair s = (a,b))
    (got : (2,fullLog.take 2) ∈ CommitKeys.keys (s.cfg.min?.getD 0) (s.before :: s.past)) :
    endpoints s = ((a,true),(b,true)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have pastKey : Committed s.frame 2 (fullLog.take 2) := (CommitKeys.step_mem s _ _).mp got
  have c := s.context
  have old : (endpoints s).1.2 = true :=
    (StateCoverage.read_iff s.before s.past c.inv).2.mpr
      ((StateCoverage.backed_iff _ c.inv).mpr ⟨List.ne_nil_of_mem c.pre_now,_,_,pastKey⟩)
  have post : (endpoints s).2.2 = true :=
    (StateCoverage.read_iff s.after (s.before :: s.past) c.inv_step).2.mpr
      ((StateCoverage.backed_iff _ c.inv_step).mpr ⟨List.ne_nil_of_mem c.post_now,_,_,.inl pastKey⟩)
  have before : (endpoints s).1.1 = a := congrArg (Prod.fst (α := Bool) (β := Bool)) zeros
  have after : (endpoints s).2.1 = b := congrArg (Prod.snd (α := Bool) (β := Bool)) zeros
  exact Prod.ext (Prod.ext before old) (Prod.ext after post)

private theorem closed_endpoints (extra : Bool) : endpoints (replay extra) = ((extra,true),(extra,true)) := by
  refine has_backing (replay extra) (zero_endpoints extra) ?_
  rw [bootstrap]
  change (2,fullLog.take 2) ∈ CommitKeys.keys 0 (preHistory extra)
  rw [old_keys]
  exact List.mem_cons_self

private theorem elected (extra : Bool) :
    let s := replay extra
    ReadersAtoms.electedExact 1 3 fullLog 2 (s.after :: s.before :: s.past) = true :=
  by cases extra <;> decide +kernel

private theorem certified_answers (s : Step) (boot : s.cfg.min?.getD 0 = 0)
    (current : (2,fullLog) ∈ CommitKeys.here 0 s.after (s.before :: s.past) (fun _ b => b == 3))
    (old : CommitKeys.keys 0 (s.before :: s.past) = [(2,fullLog.take 2),(2,fullLog.take 4)])
    (election : ReadersAtoms.electedExact 1 3 fullLog 2 (s.after :: s.before :: s.past) = true) :
    keys s = true ∧ label s (.step .leader_floor_led_inl) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let hist := s.after :: s.before :: s.past
  rw [← boot] at current
  obtain ⟨n,st,base,i,witness,log,baseEq⟩ := (CommitKeys.mem_here s.after (s.before :: s.past)
    (fun _ b => b == 3) 2 fullLog).mp current
  have eq : base = 3 := beq_iff_eq.mp baseEq
  subst base
  have folded : (s.frame.advance s.after).logs = Historical.logFacts hist :=
    StateCoverage.frame_logs s.after (s.before :: s.past)
  have backward : CommitStep (s.frame.advance s.after) n st 2 3 i := by
    change (s.frame.advance s.after).logs.commitAt Config.INITIAL_PRIMARY s.after n st 2 3 i
    rw [folded]
    refine (Historical.commitAt_iff ?_ (Historical.logFacts_correct hist).seen n st 2 3 i).mpr witness
    intro n' st' k'
    simp only [LogFacts.Ghost.canonNow, LogFacts.Ghost.led, Historical.CanonNow, Historical.Led,
      Historical.Now, (Historical.logFacts_correct hist).elected, hist]
  have oldKey := CommitKeys.step_mem s 2 (fullLog.take 4)
  have saved : (2,fullLog.take 4) ∈ CommitKeys.keys (s.cfg.min?.getD 0) (s.before :: s.past) := by
    rw [boot, old]
    exact List.mem_cons_of_mem _ List.mem_cons_self
  have agree : st.log.take 3 = fullLog.take 3 := by
    rw [log, List.take_take, Nat.min_eq_left backward.2.1]
  have backing : Backed s.frame st.log 3 2 := by
    refine .inr ⟨2,fullLog.take 4,oldKey.mp saved,by decide,?_⟩
    rw [agree]
    exact take_prefix_take _ (by decide)
  have fresh : ¬ Committed s.frame 2 (st.log.take i) := by
    rw [← log]
    intro hit
    have listed := (CommitKeys.step_mem s 2 fullLog).mpr hit
    rw [boot, old] at listed
    exact (by decide +kernel : (2,fullLog) ∉ [(2,fullLog.take 2),(2,fullLog.take 4)]) listed
  have wins : Elected (s.frame.advance s.after) 1 3 fullLog 2 := by
    change (s.frame.advance s.after).logs.elected 1 3 fullLog 2
    rw [folded, (Historical.logFacts_correct hist).elected]
    exact (ReadersAtoms.electedExact_iff 1 3 _ 2 hist).mp election
  have source := delayed_source s.context backward backing fresh wins (by decide) agree (by decide)
  have key := Keys.sufficient s.context (.inr ⟨source,n,st,backward.1.1,backward.1.2.2.1,
    backward.1.2.1.symm ▸ backward.1.2.2.2⟩)
  refine ⟨((label_true s (.step .replaceNode_keys_here_pos)).trans
    (SolvedWitnesses.sig_iff s.context .replaceNode_keys_here_pos)).mpr key, ?_⟩
  have n_is_bootstrap : n = Config.INITIAL_PRIMARY := by
    apply s.context.inv_step.election_safety n Config.INITIAL_PRIMARY 2
    · exact backward.1.2.1.symm ▸ backward.1.2.2.2
    · exact Or.inl ⟨rfl,rfl⟩
  subst n
  have floor := delayed_floor s.context backward backing fresh wins (by decide) agree
  exact ((label_true s (.step .leader_floor_led_inl)).trans
    (SolvedWitnesses.sig_iff s.context .leader_floor_led_inl)).mpr floor

private theorem replay_answers (extra : Bool) :
    keys (replay extra) = true ∧ label (replay extra) (.step .leader_floor_led_inl) = true :=
  certified_answers (replay extra) (bootstrap extra) (committable extra) (old_keys extra) (elected extra)

/-- Node 1 is elected in the new term before node 4 sees the shorter term-two
signature. The next nomination leaves node records unchanged but extends
the old-term backing to the longer signature already held by nodes 0 and 1.
The optional inactive deployment node contributes the remaining zero index. -/
private theorem checked (extra : Bool) :
    nonTrunkLabel .term_mono (replay extra) = row ((extra,true),(extra,true)) false true := by
  rw [shape, closed_endpoints, unchanged_answer (replay extra) (actor_unchanged extra),
    (replay_answers extra).1]

private theorem newest_keys (extra : Bool) :
    let s := replay extra
    (fastHere s.after (s.before :: s.past) (CommitKeys.backed [(2,fullLog.take 2),(2,fullLog.take 4)]) ++
      [(2,fullLog.take 2),(2,fullLog.take 4)]).eraseDups = [(2,fullLog.take 2),(2,fullLog.take 4),(2,fullLog)] :=
  by cases extra <;> decide +kernel

private theorem replay_commits (extra : Bool) :
    let s := replay extra
    CommitKeys.keys 0 (s.after :: s.before :: s.past) =
      [(2,fullLog.take 2),(2,fullLog.take 4),(2,fullLog)] := by
  let s := replay extra
  change CommitKeys.keys 0 (s.after :: preHistory extra) = _
  rw [CommitKeys.keys, old_keys, ← fastHere_eq]
  exact newest_keys extra

private theorem recorded_nomination (extra : Bool) :
    let s := replay extra
    EventSupport.actionTag s.act = .nominateSuccessor :=
  by cases extra <;> decide +kernel

private theorem remaining_lower (r : RestrictedProfile) (mem : r ∈ remaining) :
    ∃ s : Step, nonTrunkLabel .term_mono s = r := by
  have listed : ∀ q ∈ remaining, ∃ extra : Bool, q = row ((extra,true),(extra,true)) false true :=
    by decide +kernel
  obtain ⟨extra,rfl⟩ := listed r mem
  exact ⟨replay extra, checked extra⟩

public def rows := witnessed ++ remaining
public def patterns := TermMono.patterns ++ remainingPatterns

public theorem counts : rows.Nodup ∧ rows.length = 11 ∧ patterns.Nodup ∧ patterns.length = 3 :=
  by decide +kernel

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s : Step, nonTrunkLabel .term_mono s = r :=
  (List.mem_append.mp mem).elim (TermMono.lower r) (remaining_lower r)

public theorem exact_rows (r : RestrictedProfile) :
    r ∈ rows ↔ ∃ s : Step, nonTrunkLabel .term_mono s = r :=
  ⟨lower r, by rintro ⟨s,rfl⟩; exact upper s⟩

public theorem exact_patterns (p : List Bool) :
    p ∈ patterns ↔ ∃ s : Step, (nonTrunkLabel .term_mono s).bits = p := by
  have eq : patterns = (rows.map RestrictedProfile.bits).eraseDups := by decide +kernel
  rw [eq]
  exact ClauseSmallA.patterns_exact upper lower p

end ConsensusCoverage.ClauseSmallA.TermMonoExact
