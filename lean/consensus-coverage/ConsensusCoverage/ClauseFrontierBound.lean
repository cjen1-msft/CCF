module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSampleBound
import all ConsensusCoverage.ClauseSampleBound

namespace ConsensusCoverage.ClauseFrontierBound

open ClauseQuestions ClauseSampleBound

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private instance (n : Nat) : OfNat Tree n := ⟨.leaf n⟩
private abbrev q := Tree.ask

/-- A separating tree learned from the corpus. Each internal node queries a
slot of `questions .frontier`, not a global question number. Unobserved
patterns may go to any leaf; this is a lower bound, not exhaustion. -/
private def trees : Forest
  | 5 => q 43 (q 1 (q 0 (q 75 0 17) (q 17 8 (q 40 7 6)))
    (q 11 (q 9 (q 10 4 1) 5) (q 12 3 2)))
    (q 18 (q 40 (q 16 (q 21 15 14) 18) (q 16 (q 39 13 10) 16)) (q 19 12 (q 39 11 9)))
  | 9 => 19
  | 10 => q 42 (q 2 (q 0 (q 75 20 39) (q 11 (q 9 21 24) (q 12 23 22)))
    (q 17 (q 18 (q 16 30 41) (q 19 29 28)) (q 40 26 25)))
    (q 16 (q 40 (q 18 (q 21 (q 23 27 36) 35) 34) (q 18 (q 22 33 32) 31))
      (q 51 (q 40 (q 53 38 43) 42) (q 53 37 40)))
  | 11 => q 16 (q 1 45 44) (q 39 (q 51 48 46) 47)
  | 13 => q 1 50 49
  | 15 => q 42 (q 2 (q 0 (q 75 51 72) (q 11 (q 9 (q 10 55 52) 56) (q 12 54 53)))
    (q 16 (q 17 (q 18 62 (q 19 61 60)) (q 40 58 57)) (q 81 74 78)))
    (q 16 (q 40 (q 18 (q 21 (q 23 59 69) 68) 67) (q 18 (q 22 66 65) (q 19 64 63)))
      (q 51 (q 81 (q 53 76 75) (q 87 77 79)) (q 40 (q 53 70 73) 71)))
  | _ => 80

private def picks : List (Nat × Nat) :=
  [(15,0),(26,0),(3,2),(44,0),(19,0),(2,0),(124,11),(21,2),(90,7),(102,14),
   (126,11),(3,5),(23,17),(61,7),(3,6),(3,4),(21,1),(192,4),(26,1),(0,0),
   (59,3),(69,6),(168,5),(186,5),(0,1),(120,14),(70,5),(119,6),(96,8),(81,11),
   (119,8),(135,7),(122,11),(119,12),(84,22),(135,8),(135,6),(92,12),(134,8),(34,7),
   (69,9),(132,8),(74,19),(59,4),(46,1),(110,11),(80,8),(138,9),(70,4),(1,0),
   (20,1),(25,1),(45,2),(30,3),(55,2),(66,1),(34,1),(128,11),(52,2),(131,3),
   (165,4),(73,6),(131,5),(130,5),(95,18),(131,8),(65,17),(30,17),(166,5),(128,5),
   (38,13),(140,2),(79,9),(33,10),(130,7),(174,2),(176,11),(143,5),(141,8),(121,4)]

private def leaves := picks.filterMap (lookup .frontier trees)

private theorem checked : leaves.length = 80 ∧ leaves.Nodup := by decide +kernel

public theorem frontier_bound (rows : List RestrictedProfile)
    (complete : ∀ s, clauseLabel .frontier s ∈ rows) : 80 ≤ rows.length :=
  bound _ trees picks _ checked rows complete

end ConsensusCoverage.ClauseFrontierBound
