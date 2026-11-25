module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactCover
import all ConsensusCoverage.ClauseFrontierExactCover
import all ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.ClauseFrontierExactHandler
import all ConsensusCoverage.ClauseFrontierExactMaximum
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.EventSupport

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile ClauseQuestions ClauseExactTables EventSupport
open Handler (isReceive reply)

set_option maxHeartbeats 0
set_option maxRecDepth 16384

private abbrev Q := Classes.StepBranch
private abbrev Lit := Q × Bool
private abbrev Rule := List Lit
private def pos (q : Q) : Lit := (q,true)
private def neg (q : Q) : Lit := (q,false)
private def need (a b : Q) : Rule := [neg a,pos b]
private def exclude (a b : Q) : Rule := [neg a,neg b]
private def hit (p : Q → Bool) (l : Lit) : Bool := p l.1 == l.2

/-- A clause is still possible if a literal is already satisfied or its
coordinate remains unassigned. Coordinates outside `free` are false. -/
private def possible (todo yes : List Q) (r : Rule) : Bool :=
  r.any fun l => hit yes.contains l || todo.contains l.1

private def search (rules : List Rule) (todo yes : List Q) : List (List Q) :=
  if rules.all (possible todo yes) then
    match todo with
    | [] => [yes]
    | q :: qs => search rules qs yes ++ search rules qs (yes ++ [q])
  else []

private theorem search_complete (rules : List Rule) (todo yes : List Q) (p : Q → Bool)
    (valid : rules.all (fun r => r.any (hit p)) = true)
    (sound : ∀ q ∈ yes, p q = true)
    (cover : ∀ q, p q = true → q ∈ yes ∨ q ∈ todo) :
    yes ++ todo.filter p ∈ search rules todo yes := by
  have possibleAll : rules.all (possible todo yes) = true := by
    apply List.all_eq_true.mpr
    intro r hr
    obtain ⟨l,hl,eq⟩ := List.any_eq_true.mp (List.all_eq_true.mp valid r hr)
    exact List.any_eq_true.mpr ⟨l,hl,by
      have eql := beq_iff_eq.mp eq
      by_cases h : l.1 ∈ todo
      · simp [h]
      · have exactOn : yes.contains l.1 = p l.1 :=
          Bool.eq_iff_iff.mpr ⟨fun hy => sound _ (List.contains_iff_mem.mp hy),
            fun hp => List.contains_iff_mem.mpr ((cover _ hp).resolve_right h)⟩
        apply Bool.or_eq_true_iff.mpr
        exact .inl (beq_iff_eq.mpr (exactOn.trans eql))⟩
  unfold search
  rw [ite_eq_left possibleAll]
  cases todo with
  | nil => simp
  | cons q qs =>
    cases h : p q with
    | false =>
      have hc (k) (hp : p k = true) : k ∈ yes ∨ k ∈ qs := by
        rcases cover k hp with old | m
        · exact .inl old
        · rcases List.mem_cons.mp m with rfl | mem
          · simp [h] at hp
          · exact .inr mem
      have ih := search_complete rules qs yes p valid sound hc
      simpa [List.filter_cons,h] using List.mem_append_left (search rules qs (yes ++ [q])) ih
    | true =>
      have hs (k) (mem : k ∈ yes ++ [q]) : p k = true := by
        rcases List.mem_append.mp mem with old | now
        · exact sound k old
        · simp only [List.mem_singleton] at now
          simpa [now] using h
      have hc (k) (hp : p k = true) : k ∈ yes ++ [q] ∨ k ∈ qs := by
        rcases cover k hp with old | m
        · exact .inl (List.mem_append_left _ old)
        · rcases List.mem_cons.mp m with rfl | mem
          · exact .inl (List.mem_append_right _ List.mem_cons_self)
          · exact .inr mem
      have ih := search_complete rules qs (yes ++ [q]) p valid hs hc
      simpa [List.filter_cons,h,List.append_assoc] using List.mem_append_right (search rules qs yes) ih
termination_by todo.length

private abbrev changeActor : Q := .inv_step_frontier_now_inl
private abbrev branchYes : Q := .ite__condition_pos
private abbrev branchNo : Q := .ite__condition_neg
private abbrev boundNil : Q := .maxCommittableIndexBounded_values_nil
private abbrev boundCons : Q := .maxCommittableIndexBounded_values_cons
private abbrev boundSig : Q := .maxCommittableIndexBounded_signature_pos
private abbrev elected : Q := .act_kind_election
private abbrev checkQuorum : Q := .act_kind_checkQuorum
private abbrev clear : Q := .handleAppendEntriesRequest_conflict_none
private abbrev conflict : Q := .handleAppendEntriesRequest_conflict_some
private abbrev down : Q := .handleAppendEntriesRequest_stepDown_pos
private abbrev stay : Q := .handleAppendEntriesRequest_stepDown_neg
private abbrev advances : Q := .advance_le_total_inl
private abbrev retains : Q := .advance_le_total_inr

private def sharedRules : List Rule :=
  [need primary observed, need higher observed, need observed changeActor,
    need branchYes changeActor, need branchNo changeActor, need foldNil changeActor,
    need foldCons foldNil, exclude promotesPositive promotesZero, need boundSig boundCons]

private def comparisonRules (tag : Tag) : List Rule :=
  if tag == .proposeRequestVoteRequest then [[neg higher]]
  else if tag == .appendEntriesResponse then [need higher primary] else []

private def receiveRules (tag : Tag) : List Rule :=
  if isReceive tag then
    [need observed branchNo, need branchNo observed, [neg changeActor,pos branchNo,pos branchYes]] ++
      (if reply tag then [] else [need changeActor observed]) else [[neg observed]]

private def handlerRules : Tag → List Rule
  | .append => [[pos changeActor],[pos branchYes],[pos branchNo],[pos foldCons]]
  | .timeout => [[neg changeActor,pos elected,pos checkQuorum], exclude elected checkQuorum,
      need branchYes elected, need branchNo elected]
  | .nominateSuccessor => [[neg changeActor]]
  | .initAsBackup => [[pos changeActor]]
  | .appendEntriesRequest =>
    [need clear boundNil, need clear boundCons, need conflict boundNil, need conflict boundCons,
      [neg changeActor,pos down,pos stay], need down changeActor, need stay changeActor,
      [neg changeActor,pos clear,pos conflict,pos branchYes], exclude clear conflict,
      exclude clear branchYes, exclude conflict branchYes,
      [neg clear,neg down,neg stay], [neg conflict,neg down,neg stay],
      [neg advances,pos clear,pos conflict], [neg retains,pos clear,pos conflict],
      need advances boundSig]
  | _ => []

private def rules (tag : Tag) : List Rule :=
  sharedRules ++ comparisonRules tag ++ receiveRules tag ++ handlerRules tag

private def coordinates : List Q :=
  [changeActor, branchYes, branchNo, boundNil, boundCons, boundSig, elected, checkQuorum,
    clear, conflict, down, stay, advances, retains, foldNil, foldCons, promotesPositive, promotesZero,
    observed, primary, higher]

private theorem coords (tag : Tag) :
    ∀ r ∈ rules tag, ∀ l ∈ r, l.1 ∈ coordinates := by
  cases tag <;> decide +kernel

private theorem free_or_excluded :
    ∀ tag ∈ ActionCover.tags, ∀ q ∈ coordinates, q ∈ free tag ∨ tag ∉ allowed q := by
  decide +kernel

private theorem chosen_value (s : Step) (q : Q) (h : q ∈ coordinates) :
    (selected s).contains q = label s (.step q) := by
  apply Bool.eq_iff_iff.mpr
  rw [List.contains_iff_mem, chosen_iff]
  refine ⟨And.right,fun bit => ⟨?_,bit⟩⟩
  rcases free_or_excluded _ (allTag _) _ h with mem | excluded
  · exact mem
  · exact Bool.noConfusion (bit.symm.trans (label_false s q excluded))

private def holdsRules (s : Step) (rs : List Rule) : Prop :=
  rs.all (fun r => r.any (hit (fun q => label s (.step q)))) = true

local macro "clauses" : tactic => `(tactic|
  simp only [holdsRules,need,exclude,pos,neg,hit,List.all_cons,List.all_nil,
    List.any_cons,List.any_nil,Bool.or_false,Bool.and_eq_true,Bool.or_eq_true,
    beq_iff_eq,and_true,← Bool.not_eq_true])

private theorem shared_valid (s : Step) : holdsRules s sharedRules := by
  have ⟨p,h,c⟩ := Handler.observe_requires_call s
  have ⟨y,n,_⟩ := Handler.condition_shape s
  have pf := Handler.fold_nil_shape s
  have pn := fold_cons_imp_nil s
  have px := promotion_excludes s true
  have ps := Maximum.signature_needs_scan s
  unfold sharedRules
  clauses
  simp only [Handler.bit, Handler.changed] at p h c y n pf
  change (label s (.step promotesPositive) = true → label s (.step promotesZero) = false) at px
  repeat' apply And.intro
  all_goals grind (splits := 4)

private theorem comparison_valid (s : Step) : holdsRules s (comparisonRules (actionTag s.act)) := by
  have h := (Handler.observe_requires_call s).2.1
  unfold comparisonRules
  split
  · rename_i tag
    have eq : actionTag s.act = .proposeRequestVoteRequest := beq_iff_eq.mp tag
    clauses
    intro high
    have impossible := (h high).2
    simp [eq,compares] at impossible
  · split
    · rename_i tag
      have eq : actionTag s.act = .appendEntriesResponse := beq_iff_eq.mp tag
      clauses
      by_cases high : Handler.bit s higher
      · exact .inr (by simpa [eq,compares] using (h high).2)
      · exact .inl high
    · rfl

private theorem receive_valid (s : Step) : holdsRules s (receiveRules (actionTag s.act)) := by
  unfold receiveRules
  split
  · rename_i rec
    have ⟨iffCall,atLeast,nonreply⟩ := Handler.receive_shape s rec
    simp only [holdsRules,List.all_append,Bool.and_eq_true]
    constructor
    · change holdsRules s _
      clauses
      simp only [Handler.bit,Handler.changed] at iffCall atLeast
      repeat' apply And.intro
      all_goals grind (splits := 4)
    · split
      · rfl
      · rename_i notReply
        change holdsRules s _
        clauses
        by_cases changed : Handler.changed s
        · exact .inr (nonreply ((Bool.eq_false_iff).mpr notReply) changed)
        · exact .inl changed
  · rename_i localTag
    have exclusion : ∀ t ∈ ActionCover.tags, isReceive t = false → t ∉ allowed observed := by decide +kernel
    clauses
    exact Bool.eq_false_iff.mp (label_false s observed
      (exclusion _ (allTag _) (Bool.eq_false_iff.mpr localTag)))

private theorem handler_valid (s : Step) : holdsRules s (handlerRules (actionTag s.act)) := by
  generalize tag : actionTag s.act = t
  cases t <;> try rfl
  case append =>
    unfold handlerRules
    clauses
    exact Handler.append_shape s tag
  case initAsBackup =>
    unfold handlerRules
    clauses
    exact Handler.backup_changes s tag
  case nominateSuccessor =>
    unfold handlerRules
    clauses
    exact Handler.nomination_stutters s tag
  case timeout =>
    have ⟨a,b,c⟩ := Handler.timeout_kinds s tag
    unfold handlerRules
    clauses
    simp only [Handler.changed, Handler.bit] at a b c
    repeat' apply And.intro
    all_goals grind (splits := 4)
  case appendEntriesRequest =>
    have ⟨a,b,c,d,e,f⟩ := Handler.follower_shape s tag
    have v (h : Handler.bit s clear) := Maximum.append_accept_scans s .clear (.inl rfl) h
    have w (h : Handler.bit s conflict) := Maximum.append_accept_scans s .conflict (.inr rfl) h
    have g := Maximum.advance_needs_signature s
    unfold handlerRules
    clauses
    simp only [Handler.changed, Handler.bit] at a b c d e f v w
    repeat' apply And.intro
    all_goals grind (splits := 4)

private theorem valid_labels (s : Step) : holdsRules s (rules (actionTag s.act)) := by
  have a := shared_valid s
  have b := comparison_valid s
  have c := receive_valid s
  have d := handler_valid s
  simp only [holdsRules, rules, List.all_append, Bool.and_eq_true] at *
  exact ⟨⟨⟨a,b⟩,c⟩,d⟩

private theorem selected_rules (s : Step) :
    (rules (actionTag s.act)).all (fun r => r.any (hit (selected s).contains)) = true := by
  apply List.all_eq_true.mpr
  intro r hr
  obtain ⟨l,hl,eq⟩ := List.any_eq_true.mp (List.all_eq_true.mp (valid_labels s) r hr)
  exact List.any_eq_true.mpr ⟨l,hl,by simpa only [hit, chosen_value s l.1 (coords _ r hr l hl)] using eq⟩

private def candidates (tag : Tag) : List (List Q) := search (rules tag) (free tag) []

private theorem selected_candidate (s : Step) : selected s ∈ candidates (actionTag s.act) := by
  have key : (free (actionTag s.act)).filter (selected s).contains = selected s := by
    apply List.filter_congr
    intro q h
    apply Bool.eq_iff_iff.mpr
    unfold selected
    simp only [List.contains_iff_mem, List.mem_filter, h, true_and]
  rw [← key]
  change [] ++ _ ∈ _
  exact search_complete _ _ [] _ (selected_rules s) (by simp)
    (fun q h => .inr ((chosen_iff s q).mp (List.contains_iff_mem.mp h)).1)

private def tightFor (tag : Tag) : List (List Bool) := (candidates tag).map (decode tag)

@[irreducible] public def tightPatterns : List (List Bool) := ActionCover.tags.flatMap tightFor

public theorem tight_patterns_upper (s : Step) : (nonTrunkLabel .frontier s).bits ∈ tightPatterns := by
  rw [tightPatterns,actual]
  exact List.mem_flatMap.mpr ⟨_,allTag _,List.mem_map.mpr ⟨_,selected_candidate s,rfl⟩⟩

private def fits (changed : Bool) (e : Endpoints) : Bool :=
  decide (e.1 = e.2) || changed

private def rowsFor (tag : Tag) : List RestrictedProfile :=
  (candidates tag).flatMap fun yes =>
    (endpointRows.filter (fits (yes.contains changeActor))).map fun e =>
      ⟨e.1,decode tag yes,e.2⟩

@[irreducible] public def tightRows : List RestrictedProfile := ActionCover.tags.flatMap rowsFor

public theorem tight_rows_upper (s : Step) : nonTrunkLabel .frontier s ∈ tightRows := by
  have ok : fits ((selected s).contains changeActor) (endpoints s) = true := by
    rw [chosen_value s changeActor (by decide +kernel)]
    by_cases diag : (endpoints s).1 = (endpoints s).2
    · simp [fits,diag]
    · have fresh : label s (.step changeActor) = true := by
        rw [← Bool.not_eq_false]
        exact fun h => diag (unchanged_endpoints s h)
      simp [fresh, fits]
  rw [tightRows]
  refine List.mem_flatMap.mpr ⟨_,allTag _,List.mem_flatMap.mpr ⟨_,selected_candidate s,?_⟩⟩
  exact List.mem_map.mpr ⟨endpoints s,
    List.mem_filter.mpr ⟨(endpoint_exact _).mpr ⟨s,rfl⟩,ok⟩,
    congrArg (fun bits => RestrictedProfile.mk (endpoints s).1 bits (endpoints s).2)
      (actual s).symm⟩

end ConsensusCoverage.ClauseFrontierExact
