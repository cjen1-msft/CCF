module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile ClauseQuestions

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private abbrev Certificate := (Nat × Nat) × Nat

private def stepAt (entry : Certificate) : Option Step :=
  ReadersCorpus.stepAt entry.1.1 entry.1.2

private def key (bits : List Bool) : Nat :=
  bits.foldl (fun n bit => 2*n + bit.toNat) 0

private def endKey (e : StateCoverage.Row) : Nat := 2*e.1.toNat + e.2.toNat

private def patternKey (slots : List Nat) (bits : List Bool) : Nat :=
  key (slots.map fun i => bits[i]?.getD false)

private def keyBits (slots : List Nat) (r : RestrictedProfile) : Nat :=
  patternKey slots r.bits

private def keyRow (slots : List Nat) (r : RestrictedProfile) : Nat :=
  16 * keyBits slots r + 4 * endKey r.pre + endKey r.post

private def readBits (slots : List Nat) (s : Step) : Nat :=
  let query := ReadersTotal.read s.cfg s.before s.act s.after s.past
  key (slots.map fun i => ((nonTrunk .frontier)[i]?.bind query).getD false)

private theorem readBits_eq (slots : List Nat) (s : Step) :
    readBits slots s = keyBits slots (read s) := by
  dsimp only [readBits, keyBits, patternKey]
  congr 1
  apply List.map_congr_left
  intro i _
  simp only [read, List.getElem?_map]
  cases (nonTrunk .frontier)[i]? <;> rfl

private def readRow (slots : List Nat) (s : Step) : Nat :=
  16 * readBits slots s + 4 * endKey (ClauseExactTables.endpoints s).1 +
    endKey (ClauseExactTables.endpoints s).2

private theorem readRow_eq (slots : List Nat) (s : Step) :
    readRow slots s = keyRow slots (read s) := by
  simp only [readRow, keyRow, readBits_eq]
  rfl

private def checks (readKey : Step → Nat) (entries : List Certificate) : Bool :=
  entries.all fun e => (stepAt e).any fun s => readKey s == e.2

private theorem keys_eq (readKey : Step → Nat) (entries : List Certificate)
    (h : checks readKey entries = true) :
    (entries.filterMap stepAt).map readKey = entries.map Prod.snd := by
  induction entries with
  | nil => rfl
  | cons e es ih =>
    change ((stepAt e).any (fun s => readKey s == e.2) && checks readKey es) = true at h
    simp only [Bool.and_eq_true] at h
    obtain ⟨head, tail⟩ := h
    simp only [Option.any_eq_true] at head
    obtain ⟨s, someStep, eq⟩ := head
    simp only [List.filterMap_cons, someStep, List.map_cons, beq_iff_eq.mp eq, ih tail]

private theorem checks_append (readKey : Step → Nat) (a b : List Certificate) :
    checks readKey (a ++ b) = (checks readKey a && checks readKey b) := by
  simp only [checks, List.all_append]

private theorem checks_flatten (readKey : Step → Nat) (batches : List (List Certificate)) :
    checks readKey batches.flatten = batches.all (checks readKey) := by
  induction batches with
  | nil => rfl
  | cons a as ih => simp only [List.flatten_cons, List.all_cons, checks_append, ih]

private def patternSlots : List Nat := [0,1,4,5,10,12,13,15,17,31,32,43,45,47,49,50,57,58,59,60]
private def rowSlots : List Nat := [1,4,5,10,12,13,17,31,33,43,45,47,48,49,50,57,58,59,60]

-- Sparse distinguishing keys from the corpus, not substitutes for the full
-- labels in the tables below. Chunk the replay checks to bound kernel work.
private def patternBatches : List (List Certificate) :=
  [[((0,0),786544), ((15,0),0), ((19,0),786432), ((26,0),917504), ((44,0),851968), ((20,1),557184)],
   [((21,1),557888), ((3,2),852000), ((21,2),525312), ((26,2),525408), ((52,2),525424), ((131,3),524384)],
   [((3,4),526432), ((59,4),557196), ((70,4),557192), ((165,4),550400), ((3,5),549376), ((131,5),525824)],
   [((166,5),528481), ((168,5),852066), ((73,6),542208), ((61,7),524800), ((109,7),557188), ((130,7),558724)],
   [((172,7),526400), ((80,8),557448), ((98,8),528482), ((132,8),558732), ((134,8),557120), ((35,9),528480)],
   [((69,9),557452), ((138,9),558728), ((33,10),557440), ((124,11),525888), ((176,11),557060), ((92,12),557376)],
   [((119,12),526848), ((23,17),541184), ((30,17),548864), ((74,19),557704)]]

private def rowBatches : List (List Certificate) :=
  [[((0,0),4198153), ((1,0),4198155), ((2,0),4198154), ((15,0),10), ((19,0),4194314), ((26,0),6291466)],
   [((44,0),5242890), ((0,1),4198149), ((20,1),545803), ((21,1),535562), ((25,1),15), ((26,1),545802)],
   [((34,1),4198159), ((46,1),4194317), ((66,1),4194319), ((3,2),5244426), ((21,2),50186), ((26,2),52746)],
   [((45,2),6291471), ((52,2),53007), ((55,2),5242895), ((140,2),535567), ((174,2),545807), ((30,3),5244431)],
   [((59,3),5), ((131,3),3599), ((140,3),50191), ((175,3),52751), ((3,4),85514), ((59,4),545989)],
   [((70,4),545933), ((121,4),545935), ((165,4),427023), ((3,5),394250), ((70,5),52741), ((128,5),85519)],
   [((130,5),394255), ((131,5),33807), ((166,5),19999), ((168,5),5245477), ((186,5),5242885), ((3,6),19994)],
   [((69,6),6291461), ((70,6),5244421), ((73,6),295951), ((119,6),3589), ((135,6),85509), ((141,6),5245487)],
   [((61,7),1034), ((90,7),3594), ((109,7),545871), ((130,7),562255), ((135,7),394245), ((172,7),85002)],
   [((80,8),554125), ((96,8),427013), ((98,8),20015), ((119,8),33797), ((131,8),1039), ((132,8),562373)],
   [((134,8),543749), ((135,8),20005), ((141,8),562383), ((25,9),50181), ((35,9),19978), ((69,9),554181)],
   [((84,9),52997), ((138,9),562317), ((33,10),553999), ((81,11),295941), ((110,11),53005), ((122,11),1029)],
   [((124,11),35850), ((126,11),33802), ((128,11),35855), ((176,11),541775), ((178,11),19983), ((30,12),85007)],
   [((82,12),554117), ((92,12),551941), ((119,12),66565), ((38,13),551951), ((102,14),427018), ((120,14),35845)],
   [((181,16),545925), ((23,17),263178), ((30,17),410639), ((65,17),66575), ((95,18),263183), ((74,19),529541)],
   [((84,22),410629)]]

private theorem patternChecked : checks (readBits patternSlots) patternBatches.flatten = true := by
  simp only [checks_flatten, patternBatches, List.all_cons, List.all_nil, Bool.and_eq_true, and_true]
  repeat' apply And.intro
  all_goals decide +kernel

private theorem rowChecked : checks (readRow rowSlots) rowBatches.flatten = true := by
  simp only [checks_flatten, rowBatches, List.all_cons, List.all_nil, Bool.and_eq_true, and_true]
  repeat' apply And.intro
  all_goals decide +kernel

private def patternSteps := patternBatches.flatten.filterMap stepAt
private def rowSteps := rowBatches.flatten.filterMap stepAt

public def witnessedPatterns : List (List Bool) := patternSteps.map fun s => (read s).bits
public def witnessedRows : List RestrictedProfile := rowSteps.map read

public theorem witnessed_patterns_count : witnessedPatterns.Nodup ∧ witnessedPatterns.length = 40 := by
  have keys := keys_eq _ _ patternChecked
  have distinct : (patternBatches.flatten.map Prod.snd).Nodup := by decide +kernel
  refine ⟨?_,?_⟩
  · apply List.Pairwise.of_map (R := (· ≠ ·)) (S := (· ≠ ·)) (patternKey patternSlots)
      (fun _ _ hne eq => hne (congrArg (patternKey patternSlots) eq))
    change (witnessedPatterns.map _).Nodup
    rw [witnessedPatterns, List.map_map]
    change (patternSteps.map (fun s => keyBits patternSlots (read s))).Nodup
    simpa only [patternSteps, ← readBits_eq, keys] using distinct
  · have len := congrArg List.length keys
    simpa only [witnessedPatterns, patternSteps, List.length_map] using len.trans (by decide +kernel)

public theorem witnessed_rows_count : witnessedRows.Nodup ∧ witnessedRows.length = 91 := by
  have keys := keys_eq _ _ rowChecked
  have distinct : (rowBatches.flatten.map Prod.snd).Nodup := by decide +kernel
  refine ⟨?_,?_⟩
  · apply List.Pairwise.of_map (R := (· ≠ ·)) (S := (· ≠ ·)) (keyRow rowSlots)
      (fun _ _ hne eq => hne (congrArg (keyRow rowSlots) eq))
    change (witnessedRows.map _).Nodup
    simpa only [witnessedRows, rowSteps, List.map_map, Function.comp_def, ← readRow_eq, keys] using distinct
  · have len := congrArg List.length keys
    simpa only [witnessedRows, rowSteps, List.length_map] using len.trans (by decide +kernel)

public theorem witnessed_pattern_realized {p : List Bool} (mem : p ∈ witnessedPatterns) :
    ∃ s : Step, (nonTrunkLabel .frontier s).bits = p := by
  obtain ⟨s,_,eq⟩ := List.mem_map.mp mem
  exact ⟨s,(congrArg RestrictedProfile.bits (read_eq s)).symm.trans eq⟩

public theorem witnessed_row_realized {r : RestrictedProfile} (mem : r ∈ witnessedRows) :
    ∃ s : Step, nonTrunkLabel .frontier s = r := by
  obtain ⟨s,_,eq⟩ := List.mem_map.mp mem
  exact ⟨s,(read_eq s).symm.trans eq⟩

end ConsensusCoverage.ClauseFrontierExact
