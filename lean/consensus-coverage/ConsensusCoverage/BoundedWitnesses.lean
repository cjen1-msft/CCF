module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses

/-!
The bounded explorer suggests initialized schedules; the kernel independently
replays every action and checks the last projected key. No assumption about
the search's merge key or completeness is needed.
-/

namespace ConsensusCoverage.BoundedWitnesses

open ActionProfile FullProfile FrontierRows
open ExploredWitnesses (append deliver down elect flush nom project send sig tx)

set_option maxRecDepth 8192

local instance (r : Run) : Decidable r.valid :=
  inferInstanceAs (Decidable (r.cfg.Nonempty ∧ r.nodes.Nodup))

private def lastObserved (r : Run) (valid : r.valid) (choices : List (Nat × Nat)) :
    Option Nat := do
  let steps ← JointWitnesses.recordedAt r valid choices
  let w ← steps.getLast?
  return ExploredWitnesses.encode (← JointWitnesses.read w.val)

private structure Certificate where
  key : Nat
  checked : ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = key

private def certify (r : Run) (choices : List (Nat × Nat)) (key : Nat)
    (valid : r.valid) (multi : LeaderCoverage.MultiNode r.nodes)
    (test : lastObserved r valid choices = some key) : Certificate := by
  refine ⟨key, ?_⟩
  unfold lastObserved at test
  cases ran : JointWitnesses.recordedAt r valid choices with
  | none => simp [ran] at test
  | some steps =>
    cases last : steps.getLast? with
    | none => simp [ran, last] at test
    | some w =>
      refine ⟨w.val, w.property.symm ▸ multi, ?_⟩
      simpa [ran, last, JointWitnesses.read_eq, project] using test

local macro "multiCert " r:term:arg choices:term:arg key:term:arg : term =>
  `(certify $r $choices $key (by decide)
      ⟨0, by decide, 1, by decide, by decide⟩ (by decide +kernel))

-- BEGIN GENERATED CERTIFICATES
private def cert0 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2,
    deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0,
    deliver 0 1, append 1 [tx], send 1 0 3, deliver 1 0]⟩) [] 638339726456

private def cert1 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2,
    deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0,
    deliver 0 1, append 1 [flush 0 3], deliver 1 0]⟩) [] 638339988606

private def cert2 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, down 0,
    elect 0]⟩) [] 646460980985

private def cert3 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, nom 0,
    deliver 0 1, deliver 1 0]⟩) [] 646529138553

private def cert4 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, down 0,
    elect 0, deliver 0 1, deliver 1 0]⟩) [] 646665453433

private def cert5 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [tx, flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0,
    send 0 1 2, deliver 0 1]⟩) [] 1256815042561

private def cert6 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1,
    deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0]⟩)
  [] 1256815049849

private def cert7 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, elect 0, deliver 0 1]⟩) [(3, 1), (8, 1)] 1264902185081

private def cert8 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1,
    deliver 1 0, nom 0, deliver 0 1, deliver 1 0]⟩) [] 1265004429177

private def cert9 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, down 0, elect 0, deliver 0 1,
    deliver 1 0]⟩) [] 1265140744057

private def cert10 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 0 1, deliver 1 0, append 0 [tx]]⟩) [(3, 1), (7, 1)] 1271310548728

private def cert11 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1,
    deliver 1 0, append 0 [flush 1 3], deliver 0 1]⟩) [] 1325534748796

private def cert12 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1,
    deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1]⟩) [] 1575187902585

private def cert13 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, nom 1, deliver 1 0, deliver 0 1,
    deliver 1 0, deliver 0 1]⟩) [] 1737851387001

private def cert14 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, append 1 [flush 0 3], deliver 1 0,
    deliver 0 1]⟩) [] 1752346901241

private def cert15 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [flush 1 2], deliver 0 1, append 0 [flush 2 3],
    deliver 0 2]⟩) [] 1875290562638

private def cert16 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1,
    deliver 1 0, deliver 0 1, append 1 [flush 0 3], deliver 1 0]⟩) [(8, 1)] 1875290569854

private def cert17 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, nom 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, down 1, elect 1,
    deliver 1 0, deliver 0 1, deliver 1 0]⟩) [] 1265004428409

private def cert18 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, nom 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, append 1 [tx], send 1 0 3,
    deliver 1 0]⟩) [] 1256815017080

private def cert19 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, nom 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, append 1 [flush 0 3],
    deliver 1 0]⟩) [] 1325534755964

private def cert20 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, down 1, elect 1, deliver 1 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, append 1 [flush 0 3], deliver 1 0,
    deliver 0 1]⟩) [] 1752346902265

private def cert21 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, down 0, deliver 1 0, elect 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1,
    append 1 [flush 0 3], deliver 1 0, deliver 0 1, append 1 [tx], send 1 0 4,
    deliver 1 0]⟩) [] 1737851354232

private def cert22 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, down 0, deliver 1 0, elect 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1,
    append 1 [flush 0 3], deliver 1 0, deliver 0 1, append 1 [flush 0 4], deliver 1 0]⟩)
  [] 1737851616382

private def cert23 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0
    1, nom 0, deliver 0 1, elect 1, deliver 1 0, deliver 0 1, elect 0, deliver 0 1,
    deliver 1 0]⟩) [(8, 2), (12, 3)] 618475535481

private def cert24 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [send 0 1 0, append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0,
    elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, nom 0,
    deliver 0 1, deliver 0 1, deliver 1 0]⟩) [(2, 1), (6, 1), (8, 1), (10, 1), (12, 2),
    (14, 2)] 618475536249

private def cert25 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 2 2,
    deliver 0 2, deliver 2 0, nom 0, deliver 0 2, deliver 2 1, deliver 1 2, deliver 2 1,
    deliver 2 0]⟩) [(11, 1)] 638339758969

private def cert26 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0
    1, nom 0, deliver 0 1, elect 1, deliver 1 0, deliver 0 1, elect 1, deliver 1 0]⟩) [(8,
    2), (11, 3)] 646426901625

private def cert27 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0,
    deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, nom 0, deliver 0 1,
    elect 1, deliver 1 0]⟩) [(13, 2)] 646426902393

private def cert28 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 0 1, deliver 1 0]⟩)
    [(3, 1), (7, 1), (9, 2), (11, 2)] 1236950826873

private def cert29 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 0 1, elect 1, deliver 1 0, deliver 0 1, elect 1, deliver 1 0]⟩)
    [(3, 1), (8, 2), (11, 3)] 1264902192249

private def cert30 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], down 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 0 1, deliver 1 0, nom 0, deliver 0 1, elect 1, deliver 1 0]⟩)
    [(3, 1), (7, 1), (9, 2), (11, 3)] 1264902193017

private def cert31 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2,
    deliver 0 1, send 0 2 2, deliver 0 2]⟩) [] 1737851347016

private def cert32 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, down 0, elect 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 0 1, deliver 1 0]⟩)
    [(5, 1), (7, 1), (9, 2), (11, 2)] 1855426117497

private def cert33 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [send 0 1 1, deliver 0 1, deliver 1 0, append 0 [flush 2 2],
    deliver 0 2, deliver 2 0, nom 0, deliver 0 2, deliver 2 0, deliver 0 2, deliver 2 1]⟩)
    [(10, 2)] 1875290333185

private def cert34 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver
    0 1, deliver 1 2, deliver 2 1, deliver 1 0]⟩) [(7, 1)] 1875290340217

private def cert35 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, nom 0, deliver 0 1, elect 1,
    deliver 1 0, deliver 0 1, elect 1, deliver 1 0]⟩) [(5, 2), (8, 3)] 1883377482873

private def certificates : List Certificate :=
  [cert0, cert1, cert2, cert3, cert4, cert5, cert6, cert7, cert8, cert9, cert10, cert11,
    cert12, cert13, cert14, cert15, cert16, cert17, cert18, cert19, cert20, cert21, cert22,
    cert23, cert24, cert25, cert26, cert27, cert28, cert29, cert30, cert31, cert32, cert33,
    cert34, cert35]
-- END GENERATED CERTIFICATES

private def newKeys : List Nat := certificates.map (·.key)
private def keys : List Nat := (ExploredWitnesses.keys ++ newKeys).eraseDups
private def multiKeys : List Nat := (ExploredWitnesses.multiKeys ++ newKeys).eraseDups

private theorem new_occurs {k : Nat} (mem : k ∈ newKeys) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  obtain ⟨c, _, rfl⟩ := List.mem_map.mp mem
  exact c.checked

private theorem occurs {k : Nat} (mem : k ∈ keys) :
    ∃ s : Step, project (label s) = k := by
  rcases List.mem_append.mp (List.mem_eraseDups.mp mem) with old | new
  · exact ExploredWitnesses.occurs old
  · obtain ⟨s, _, eq⟩ := new_occurs new
    exact ⟨s, eq⟩

private theorem multi_occurs {k : Nat} (mem : k ∈ multiKeys) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  rcases List.mem_append.mp (List.mem_eraseDups.mp mem) with old | new
  · exact ExploredWitnesses.multi_occurs old
  · exact new_occurs new

private theorem count : keys.Nodup ∧ keys.length = 223 := by decide +kernel
private theorem multi_count : multiKeys.Nodup ∧ multiKeys.length = 220 := by decide +kernel

/-- Every cover of initialized recorded step labels contains at least 223 rows. -/
public theorem full_lower_bound (rows : List Profile) (complete : ∀ s, label s ∈ rows) :
    223 ≤ rows.length := by
  simpa only [count.2] using
    (projected_lower_bound project count.1 (fun _ => occurs) complete)

/-- Every cover of initialized multi-node step labels contains at least 220 rows. -/
public theorem multi_lower_bound (rows : List Profile)
    (complete : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → label s ∈ rows) :
    220 ≤ rows.length := by
  have sub : multiKeys ⊆ rows.map project := by
    intro k hk
    obtain ⟨s, multi, key⟩ := multi_occurs hk
    exact List.mem_map.mpr ⟨_, complete s multi, key⟩
  simpa only [multi_count.2, List.length_map] using multi_count.1.length_le_of_subset sub

end ConsensusCoverage.BoundedWitnesses
