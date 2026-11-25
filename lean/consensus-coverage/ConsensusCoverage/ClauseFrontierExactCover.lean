module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactFactors
public import ConsensusCoverage.ActionCover
import all ConsensusCoverage.ActionCover
import all ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile ClauseQuestions ClauseExactTables EventSupport
open Consensus Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Model.Node

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private def representative : Classes.StepBranch → Classes.StepBranch
  | .commitFrontier_invariant_event_internal | .commitFrontier_invariant_event_receive
  | .act_input_append | .act_input_sendEntries | .act_input_timeout | .act_input_initAsBackup
  | .appendEntry_configuration_none | .appendEntry_configuration_some | .foldlM__items_nil | .foldlM__items_cons =>
    .inv_step_frontier_now_inl
  | .maxCommittableIndexBounded_signature_neg => .maxCommittableIndexBounded_values_cons
  | .receive_message_appendEntriesRequest | .receive_message_appendEntriesResponse
  | .receive_message_requestVoteRequest | .receive_message_requestVoteResponse
  | .receive_message_requestPreVoteRequest | .receive_message_requestPreVoteResponse
  | .receive_message_proposeRequestVoteRequest =>
    .observeTerm_log_message_proposeRequestVoteRequest
  | .observeTerm_log_message_appendEntriesResponse
  | .observeTerm_commitIndex_message_proposeRequestVoteRequest
  | .observeTerm_commitIndex_message_appendEntriesResponse =>
    .observeTerm_log_message_proposeRequestVoteRequest
  | .observeTerm_commitIndex_primary_pos => .observeTerm_log_primary_pos
  | .observeTerm_commitIndex_newer_pos => .observeTerm_log_newer_pos
  | .observeTerm_commitIndex_newer_neg => .observeTerm_log_newer_neg
  | .observeTerm_commitIndex_primary_neg => .observeTerm_log_primary_neg
  | .observeTerm_commitIndex_message_other => .observeTerm_log_message_other
  | .foldl_select_max_ih_inl | .foldl_select_max_chosen_pos | .foldl_select_max_le_total_inl
  | .foldl_select_max_le_total_inr | .foldl_select_max_chosen_neg | .foldl_select_max_ih_inr =>
    .foldl_select_max_values_cons
  | q => q

private theorem internal_alias (s : Step)
    (tag : actionTag s.act ∈ allowed .commitFrontier_invariant_event_internal) :
    label s (.step .commitFrontier_invariant_event_internal) =
      label s (.step .inv_step_frontier_now_inl) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have eq : actionTag s.act = eventTag c.event :=
    (congrArg actionTag ((s.context_eq c).mpr rfl)).symm.trans (actionTag_eq c)
  rw [eq] at tag
  apply Bool.eq_iff_iff.mpr
  simp only [label_true, holds, SolvedWitnesses.sig_iff, internal_iff, changed_iff]
  change (_ ∧ ∃ i, c.event = .internal i) ↔ _
  cases ev : c.event with
  | internal i => simp
  | receive n m => cases m <;> simp [ev, eventTag, messageTag, allowed] at tag

private theorem receive_alias (s : Step)
    (tag : actionTag s.act ∈ allowed .commitFrontier_invariant_event_receive) :
    label s (.step .commitFrontier_invariant_event_receive) =
      label s (.step .inv_step_frontier_now_inl) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have eq : actionTag s.act = eventTag c.event :=
    (congrArg actionTag ((s.context_eq c).mpr rfl)).symm.trans (actionTag_eq c)
  rw [eq] at tag
  apply Bool.eq_iff_iff.mpr
  simp only [label_true, holds, SolvedWitnesses.sig_iff, received_iff, changed_iff]
  change (_ ∧ ∃ n m, c.event = .receive n m) ↔ _
  cases ev : c.event with
  | internal i => cases i <;> simp [ev, eventTag, inputTag, allowed] at tag
  | receive n m => simp

private def localDispatch : Tag → Option Classes.StepBranch
  | .append => some .act_input_append
  | .sendEntries => some .act_input_sendEntries
  | .timeout => some .act_input_timeout
  | .initAsBackup => some .act_input_initAsBackup
  | _ => none

private def remoteDispatch : Tag → Option Classes.StepBranch
  | .appendEntriesRequest => some .receive_message_appendEntriesRequest
  | .appendEntriesResponse => some .receive_message_appendEntriesResponse
  | .requestVoteRequest => some .receive_message_requestVoteRequest
  | .requestVoteResponse => some .receive_message_requestVoteResponse
  | .requestPreVoteRequest => some .receive_message_requestPreVoteRequest
  | .requestPreVoteResponse => some .receive_message_requestPreVoteResponse
  | .proposeRequestVoteRequest => some .receive_message_proposeRequestVoteRequest
  | _ => none

private theorem local_alias (s : Step) (q : Classes.StepBranch)
    (tag : localDispatch (actionTag s.act) = some q) :
    label s (.step q) = label s (.step .inv_step_frontier_now_inl) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have eq : actionTag s.act = eventTag c.event :=
    (congrArg actionTag ((s.context_eq c).mpr rfl)).symm.trans (actionTag_eq c)
  rw [eq] at tag
  apply Bool.eq_iff_iff.mpr
  simp only [label_true, holds, SolvedWitnesses.sig_iff, changed_iff]
  change SolvedWitnesses.sig c q ↔ _
  obtain ⟨a,b,d,e,_,_⟩ := local_dispatch c
  cases ev : c.event with
  | receive n m => cases m <;> simp [ev,localDispatch,eventTag,messageTag] at tag
  | internal i =>
    cases i <;> simp [localDispatch,eventTag,inputTag,ev] at tag
    all_goals subst q
    all_goals first | simpa [ev] using a
                    | simpa [ev] using b
                    | simpa [ev] using d
                    | simpa [ev] using e

private theorem remote_alias (s : Step) (q : Classes.StepBranch)
    (tag : remoteDispatch (actionTag s.act) = some q) :
    label s (.step q) = label s (.step .observeTerm_log_message_proposeRequestVoteRequest) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have eq : actionTag s.act = eventTag c.event :=
    (congrArg actionTag ((s.context_eq c).mpr rfl)).symm.trans (actionTag_eq c)
  rw [eq] at tag
  apply Bool.eq_iff_iff.mpr
  simp only [label_true, holds, SolvedWitnesses.sig_iff]
  change SolvedWitnesses.sig c q ↔ HandReadersA.Observe.Calls c
  obtain ⟨a,b,d,e,g,h,i⟩ := remote_dispatch c
  cases ev : c.event with
  | internal input => cases input <;> simp [ev,remoteDispatch,eventTag,inputTag] at tag
  | receive n msg =>
    cases msg <;> simp [remoteDispatch,eventTag,messageTag,ev] at tag
    all_goals subst q
    all_goals first | simpa [ev] using a | simpa [ev] using b | simpa [ev] using d
                    | simpa [ev] using e | simpa [ev] using g | simpa [ev] using h | simpa [ev] using i

private theorem appends_alias (s : Step)
    (tag : actionTag s.act = .append) :
    label s (.step .foldlM__items_cons) = label s (.step .inv_step_frontier_now_inl) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have eq : actionTag s.act = eventTag c.event :=
    (congrArg actionTag ((s.context_eq c).mpr rfl)).symm.trans (actionTag_eq c)
  rw [eq] at tag
  apply Bool.eq_iff_iff.mpr
  rw [label_true, label_true, holds, holds, SolvedWitnesses.sig_iff, SolvedWitnesses.sig_iff,
    changed_iff]
  change SolvedWitnesses.step_foldlM__items_cons _ _ c ↔ _
  rw [HandReadersA.Append.cons_iff]
  cases ev : c.event with
  | receive n m => cases m <;> simp [ev,eventTag,messageTag] at tag
  | internal i =>
    cases i <;> simp [eventTag,inputTag,ev] at tag
    rename_i entries
    refine ⟨fun _ h => ?_, fun _ => ⟨entries, ev⟩⟩
    have ran : (Consensus.Model.Node.step (CCF.Capabilities.record c.actor) c.actor c.pre
        (.internal (.append entries))).run {} = some (c.post,c.tr.outputs) := ev ▸ c.tr.ran
    obtain ⟨_,_,grow⟩ := LeaderEffect.appendBatch_grows c.actor c.pre entries _ _ _ ran
    exact Nat.lt_irrefl _ ((c.now_pre h) ▸ grow)

private theorem representative_eq (s : Step) (q : Classes.StepBranch)
    (supported : actionTag s.act ∈ allowed q) :
    label s (.step q) = label s (.step (representative q)) := by
  by_cases same : representative q = q
  · rw [same]
  cases q <;> try exact (same rfl).elim
  case commitFrontier_invariant_event_internal => exact internal_alias s supported
  case commitFrontier_invariant_event_receive => exact receive_alias s supported
  case maxCommittableIndexBounded_signature_neg => exact (bound_cons_eq_nonsignature s).symm
  case act_input_append | act_input_sendEntries | act_input_timeout | act_input_initAsBackup =>
    apply local_alias
    revert supported
    generalize actionTag s.act = t
    cases t <;> decide +kernel
  case receive_message_appendEntriesRequest | receive_message_appendEntriesResponse
       | receive_message_requestVoteRequest | receive_message_requestVoteResponse
       | receive_message_requestPreVoteRequest | receive_message_requestPreVoteResponse
       | receive_message_proposeRequestVoteRequest =>
    apply remote_alias
    revert supported
    generalize actionTag s.act = t
    cases t <;> decide +kernel
  case foldlM__items_nil =>
    exact (append_nil_eq s).trans (appends_alias s (by simpa [allowed] using supported))
  case appendEntry_configuration_none =>
    exact (append_eq s .none).trans (appends_alias s (by simpa [allowed] using supported))
  case appendEntry_configuration_some =>
    exact (append_eq s .some).trans (appends_alias s (by simpa [allowed] using supported))
  case foldlM__items_cons => exact appends_alias s (by simpa [allowed] using supported)
  case observeTerm_log_message_appendEntriesResponse => exact ack_observe_eq s true
  case observeTerm_commitIndex_message_proposeRequestVoteRequest => exact (observe_eq s .call).symm
  case observeTerm_commitIndex_message_appendEntriesResponse =>
    exact (ack_observe_eq s false).trans (observe_eq s .call).symm
  case observeTerm_commitIndex_primary_pos => exact (observe_eq s .primary).symm
  case observeTerm_commitIndex_primary_neg => exact (observe_eq s .backup).symm
  case observeTerm_commitIndex_newer_pos => exact (observe_eq s .higher).symm
  case observeTerm_commitIndex_newer_neg => exact (observe_eq s .stable).symm
  case observeTerm_commitIndex_message_other => exact (observe_eq s .other).symm
  case foldl_select_max_ih_inl => exact fold_eq s .kept
  case foldl_select_max_chosen_pos => exact fold_eq s .selected
  case foldl_select_max_le_total_inl => exact fold_eq s .smaller
  case foldl_select_max_le_total_inr => exact fold_eq s .larger
  case foldl_select_max_chosen_neg => exact fold_eq s .rejected
  case foldl_select_max_ih_inr => exact fold_eq s .found

private def permits (tag : Tag) (q : Classes.StepBranch) : Bool :=
  decide (tag ∈ allowed q) && (ReadersRefuted.read? q != some false)

private def derived (q : Classes.StepBranch) : Bool :=
  q == .observeTerm_log_primary_neg || q == .observeTerm_log_message_other ||
    q == .observeTerm_log_newer_neg

private abbrev observed := Classes.StepBranch.observeTerm_log_message_proposeRequestVoteRequest
private abbrev primary := Classes.StepBranch.observeTerm_log_primary_pos
private abbrev higher := Classes.StepBranch.observeTerm_log_newer_pos

private def free (tag : Tag) : List Classes.StepBranch :=
  ([observed, primary, higher] ++
    (((nonTrunk .frontier).filter (permits tag)).map representative).filter (!derived ·)).eraseDups

private def subsets {α : Type} : List α → List (List α)
  | [] => [[]]
  | a :: as => let tail := subsets as; tail ++ tail.map (a :: ·)

private theorem select_mem {α : Type} (p : α → Bool) (xs : List α) :
    xs.filter p ∈ subsets xs := by
  induction xs with
  | nil => exact List.mem_cons_self
  | cons a as ih =>
    cases h : p a
    · exact List.mem_append_left _ (by simpa only [List.filter_cons, h, Bool.false_eq_true, ite_false] using ih)
    · exact List.mem_append_right _ (List.mem_map.mpr
        ⟨_, ih, by simp only [List.filter_cons, h, ite_true]⟩)

private theorem subsets_length {α : Type} (xs : List α) :
    (subsets xs).length = 2 ^ xs.length := by
  induction xs with
  | nil => rfl
  | cons a as ih =>
    simp only [subsets, List.length_append, List.length_map, List.length_cons, ih, Nat.pow_succ,
      Nat.mul_two]

private def expand (tag : Tag) (yes : List Classes.StepBranch) (q : Classes.StepBranch) : Bool :=
  if q = .observeTerm_log_primary_neg then yes.contains observed && !yes.contains primary
  else if q = .observeTerm_log_message_other then yes.contains observed && otherMessage tag
  else if q = .observeTerm_log_newer_neg then
    yes.contains observed && compares tag (yes.contains primary) && !yes.contains higher
  else yes.contains q

private def decode (tag : Tag) (yes : List Classes.StepBranch) : List Bool :=
  (nonTrunk .frontier).map fun q => permits tag q && expand tag yes (representative q)

private noncomputable def selected (s : Step) : List Classes.StepBranch :=
  (free (actionTag s.act)).filter fun q => label s (.step q)

private theorem chosen_iff (s : Step) (q : Classes.StepBranch) :
    q ∈ selected s ↔ q ∈ free (actionTag s.act) ∧ label s (.step q) = true :=
  List.mem_filter

private theorem actual (s : Step) :
    (nonTrunkLabel .frontier s).bits = decode (actionTag s.act) (selected s) := by
  dsimp only [nonTrunkLabel, restrictedLabel, decode]
  apply List.map_congr_left
  intro q mem
  by_cases excluded : actionTag s.act ∉ allowed q
  · simp [permits, excluded, EventSupport.label_false s q excluded]
  · have included := Classical.not_not.mp excluded
    by_cases no : ReadersRefuted.read? q = some false
    · simp [permits, no, ReadersRefuted.read?_correct s no]
    · have ok : permits (actionTag s.act) q = true := by simp [permits, included, no]
      rw [representative_eq s q included, ok, Bool.true_and]
      have lookup (r) (hm : r ∈ free (actionTag s.act)) :
          (selected s).contains r = label s (.step r) := by
        apply Bool.eq_iff_iff.mpr
        rw [List.contains_iff_mem, chosen_iff]
        exact ⟨And.right, fun h => ⟨hm,h⟩⟩
      have lk (r) (hm : r ∈ [observed, primary, higher]) :=
        lookup r (List.mem_eraseDups.mpr (List.mem_append_left _ hm))
      have calls := lk observed (by decide)
      have prim := lk primary (by decide)
      have new := lk higher (by decide)
      obtain ⟨backup,other,stable⟩ := observe_shape s
      generalize hr : representative q = r
      unfold expand
      split
      next eq =>
        rw [eq,calls,prim]
        exact backup
      next n₁ =>
        split
        next eq =>
          rw [eq,calls]
          exact other
        next n₂ =>
          split
          next eq =>
            rw [eq,calls,prim,new]
            exact stable
          next n₃ =>
            have nd : !derived r = true := by simp [derived,n₁,n₂,n₃]
            refine (lookup r (List.mem_eraseDups.mpr (List.mem_append_right _
              (List.mem_filter.mpr ⟨List.mem_map.mpr ⟨q,List.mem_filter.mpr ⟨mem,ok⟩,hr⟩,nd⟩)))).symm

private abbrev foldCons := Classes.StepBranch.foldl_select_max_values_cons
private abbrev foldNil := Classes.StepBranch.foldl_select_max_values_nil
private abbrev promotesPositive := Classes.StepBranch.promotedLog_committed_pos
private abbrev promotesZero := Classes.StepBranch.promotedLog_committed_neg

private def compatible (yes : List Classes.StepBranch) : Bool :=
  (!yes.contains foldCons || yes.contains foldNil) &&
    !(yes.contains promotesPositive && yes.contains promotesZero)

private theorem chosen_compatible (s : Step) : compatible (selected s) = true := by
  have no (q : Classes.StepBranch) : (selected s).contains q = false ↔ q ∉ selected s :=
    Bool.eq_false_iff.trans (not_congr List.contains_iff_mem)
  simp only [compatible, Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', Bool.and_eq_false_iff,
    List.contains_iff_mem, no]
  constructor
  · by_cases h : foldCons ∈ selected s
    · have nil := fold_cons_imp_nil s ((chosen_iff s _).mp h).2
      have all : ∀ tag ∈ ActionCover.tags, foldNil ∈ free tag := by decide +kernel
      have mem := all _ (allTag (actionTag s.act))
      exact .inr ((chosen_iff s _).mpr ⟨mem,nil⟩)
    · exact .inl h
  · by_cases h : promotesPositive ∈ selected s
    · exact .inr fun zero => Bool.noConfusion (((chosen_iff s _).mp zero).2.symm.trans
        (promotion_excludes s true ((chosen_iff s _).mp h).2))
    · exact .inl h

/-- Symbolic cover by event tag. Duplicate patterns and unrealizable assignments
may occur; only the exclusions and aliases in the decoder are asserted. -/
@[irreducible] public def upperPatterns : List (List Bool) :=
  ActionCover.tags.flatMap fun tag => ((subsets (free tag)).filter compatible).map (decode tag)

public theorem patterns_upper (s : Step) : (nonTrunkLabel .frontier s).bits ∈ upperPatterns := by
  rw [actual, upperPatterns]
  exact List.mem_flatMap.mpr ⟨_, allTag _, List.mem_map.mpr
    ⟨_, List.mem_filter.mpr ⟨select_mem _ _, chosen_compatible s⟩, rfl⟩⟩

@[irreducible] public def upperRows : List RestrictedProfile :=
  endpointRows.flatMap fun e => upperPatterns.map fun bits => ⟨e.1,bits,e.2⟩

public theorem rows_upper (s : Step) : nonTrunkLabel .frontier s ∈ upperRows := by
  unfold upperRows
  exact List.mem_flatMap.mpr ⟨endpoints s, (endpoint_exact _).mpr ⟨s,rfl⟩,
    List.mem_map.mpr ⟨_, patterns_upper s, rfl⟩⟩

private theorem capacity (tags : List Tag) :
    (tags.flatMap fun t => ((subsets (free t)).filter compatible).map (decode t)).length ≤
      (tags.map fun t => 2 ^ (free t).length).sum := by
  induction tags with
  | nil => exact Nat.le_refl 0
  | cons t ts ih =>
    simp only [List.flatMap_cons, List.length_append, List.length_map, List.map_cons, List.sum_cons]
    have le := List.length_filter_le compatible (subsets (free t))
    rw [subsets_length] at le
    exact Nat.add_le_add le ih

private theorem rawCapacity : (ActionCover.tags.map fun tag => 2 ^ (free tag).length).sum = 204288 :=
  by decide +kernel

public theorem upper_patterns_size : upperPatterns.length ≤ 204288 := by
  unfold upperPatterns
  exact Nat.le_trans (capacity ActionCover.tags) (Nat.le_of_eq rawCapacity)

private theorem endpoint_product (bits : List (List Bool)) :
    (endpointRows.flatMap fun e => bits.map fun b => (⟨e.1,b,e.2⟩ : RestrictedProfile)).length =
      6 * bits.length := by
  simp only [List.length_flatMap, List.length_map, endpoint_rows,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  omega

public theorem upper_rows_size : upperRows.length = 6 * upperPatterns.length := by
  unfold upperRows
  exact endpoint_product upperPatterns

public theorem upper_rows_bound : upperRows.length ≤ 1225728 := by
  rw [upper_rows_size]
  exact Nat.mul_le_mul_left 6 upper_patterns_size

end ConsensusCoverage.ClauseFrontierExact
