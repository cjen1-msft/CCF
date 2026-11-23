module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses

/-!
# Lower bounds from mechanically discovered initialized schedules

The explorer's outputs are not trusted. Each certificate checks the full
schedule and its projected keys with `decide +kernel`. Distinct projections
give a lower bound, not an exhaustion theorem.
-/

namespace ConsensusCoverage.ExploredWitnesses

open ActionProfile FullProfile FrontierRows Consensus Consensus.Model Consensus.Model.Node

set_option maxRecDepth 8192

-- A further projection to keep the certificate literals and deduplication
-- compact. No injectivity assumption is needed for either lower bound.
private def encode (k : JointWitnesses.Key) : Nat :=
  k.2.2.foldl (fun n bit => 2 * n + bit.toNat) (k.1 * 2 + k.2.1.toNat)

private def project (p : Profile) : Nat := encode (JointWitnesses.project p)

private def observed (r : Run) (valid : r.valid) (choices : List (Nat × Nat)) :
    Option (List Nat) :=
  (JointWitnesses.recordedAt r valid choices).map fun steps =>
    steps.filterMap fun w => (JointWitnesses.read w.val).map encode

private structure Certificate where
  run : Run
  keys : List Nat
  checked : ∀ k ∈ keys, ∃ s : Step, s.nodes = run.nodes ∧ project (label s) = k
  multi : Option (PLift (LeaderCoverage.MultiNode run.nodes))

local instance (r : Run) : Decidable r.valid :=
  inferInstanceAs (Decidable (r.cfg.Nonempty ∧ r.nodes.Nodup))

private def certify (r : Run) (choices : List (Nat × Nat)) (keys : List Nat)
    (valid : r.valid) (multi : Option (PLift (LeaderCoverage.MultiNode r.nodes)))
    (checked : observed r valid choices = some keys) : Certificate := by
  refine ⟨r, keys, ?_, multi⟩
  intro k hk
  unfold observed at checked
  obtain ⟨steps, _, rfl⟩ := Option.map_eq_some_iff.mp checked
  obtain ⟨w, _, code⟩ := List.mem_filterMap.mp hk
  exact ⟨w.val, w.property, Option.some.inj ((congrArg (·.map encode) (JointWitnesses.read_eq _)).symm.trans code)⟩

private abbrev send (n peer i : Nat) : Command := .input n (.sendEntries peer i)
private abbrev deliver (a b : Nat) : Command := .deliver a b
private abbrev elect (n : Nat) : Command := .input n (.timeout .election)
private abbrev down (n : Nat) : Command := .input n (.timeout .checkQuorum)
private abbrev nom (n : Nat) : Command := .input n .nominateSuccessor
private abbrev restore (n : Nat) (entries : List Entry) : Command := .input n (.initAsBackup entries)
private abbrev backup (n : Nat) : Command := restore n []
private abbrev append (n : Nat) (entries : List AppendEntryInput) : Command := .input n (.append entries)
private abbrev sig : AppendEntryInput := {content := .signature}
private abbrev tx : AppendEntryInput := {content := .transaction 1 {}}
private abbrev cfg (ns : CCF.Finset NodeID) : AppendEntryInput :=
  {content := .transaction 1 {configuration := some ns}}
private abbrev flush (peer i : Nat) : AppendEntryInput := {sig with flushes := [(peer, i)]}
private abbrev signed : Entry := ⟨2, .signature⟩
private abbrev unsigned : Entry := ⟨2, .transaction 1 {}⟩
private abbrev bootstrap (ns : CCF.Finset NodeID) : Entry := ⟨2, .transaction 0 {configuration := some ns}⟩

local macro "multiCert " r:term:arg choices:term:arg keys:term:arg : term =>
  `(certify $r $choices $keys (by decide)
      (some ⟨⟨0, by decide, 1, by decide, by decide⟩⟩) (by decide +kernel))
local macro "soloCert " r:term:arg choices:term:arg keys:term:arg : term =>
  `(certify $r $choices $keys (by decide) none (by decide +kernel))

-- BEGIN GENERATED CERTIFICATES
-- explore.lean --depth 3 --walks 300 --length 20 --seed 20261123
private def cert0 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [tx, sig], append 0 [cfg {1}, flush 1 5, sig], deliver 0 1,
    append 0 [cfg {0, 1}, flush 1 8, sig], deliver 1 0, append 0 [tx, flush 1 10], deliver 0 1,
    down 0, elect 0, deliver 0 1, deliver 0 1, deliver 1 0, deliver 1 0, elect 0, elect 1, deliver 0 1]⟩) [(12, 1)]
  [1271310531272, 1300309949176, 1325534748748, 1918785256184, 1889785854713, 1918785256184,
    1875290562686, 1855426116345, 1883411561209, 1737851609214, 646426656768, 618475290624, 646665452409,
    646460980345, 646460973177, 646529130617]

private def cert1 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [nom 0, nom 0, append 0 [cfg {0, 1}, flush 2 3, sig], send 0 2 4,
    append 0 [cfg {0}], deliver 0 2, deliver 2 0, nom 0, nom 0, append 0 [tx, sig], nom 0, deliver 0 2,
    down 0, elect 2, elect 0, deliver 0 2, deliver 0 2, deliver 2 0]⟩) [(5, 2), (11, 2), (16, 8), (17, 8)]
  [1256294711296, 1236950581248, 1300309949128, 1300309981945, 1271310531320, 1256815009864,
    1271310564089, 1236950581248, 1236950581248, 1271310547704, 1236950581248, 1256815009912,
    1236950825721, 1264936263801, 1264936270585, 1265140736121, 1264901947392, 1265004428153]

private def cert2 : Certificate := multiCert
  (⟨{0}, [0, 1], [backup 1, append 0 [sig], append 0 [cfg {0, 1}], deliver 0 1, down 0, deliver 1 0,
    elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, append 0 [cfg {0, 1}, sig], down 0, elect 0]⟩) []
  [1236950712321, 1340030270156, 1918785239800, 1875290234881, 1855426116345, 1855425871872,
    1883411561209, 1883377238016, 1883616033657, 1883479613441, 2164663762041, 1918785240824,
    1855426117369, 1883411562233]

private def cert3 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [sig], nom 0, restore 1 [bootstrap {0}, signed], append 0 [sig], nom 0,
    append 0 [cfg {0, 1}], nom 0, deliver 0 1, send 0 1 3, deliver 1 0, down 0, deliver 0 1, deliver 1 0,
    deliver 0 1, elect 0, elect 0, deliver 0 1, deliver 0 1, elect 0]⟩) [(11, 1)]
  [1340030270156, 1855425871872, 1717987123272, 652835519230, 618475290624, 681834674936,
    637819420672, 638339514368, 647474708480, 652835273465, 618475535097, 638339514368, 618475290624,
    618475290624, 646460979961, 618475290624, 646426656768, 618475290624, 646460735488]

private def cert4 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [send 0 1 1, deliver 0 1, deliver 1 0, append 0 [cfg {0}, sig], send 0 1 2,
    send 0 1 2, down 0, deliver 0 1, deliver 1 0, elect 0, deliver 0 1, deliver 0 1, deliver 1 0,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, send 0 1 3, append 0 [cfg {0, 1}, flush 1 5]]⟩) []
  [1300309981825, 1256815009792, 1271310563969, 1271310547656, 1300309981945, 1265949999104,
    1236950825721, 1256815009792, 1236950581248, 1264936270585, 1256814804992, 1264901947392,
    1236950581248, 1265140743033, 1265004421121, 1575187905657, 1256814804992, 1265949999104, 1300309966584]

private def cert5 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [append 0 [flush 1 2], down 0, elect 0, deliver 0 1, deliver 0 1, deliver 1 0,
    backup 2, elect 1, elect 0, deliver 1 0, deliver 1 0, deliver 0 1, deliver 0 1, deliver 1 0,
    append 0 [cfg {0}, sig], deliver 0 1, append 0 [cfg {0, 2}, flush 2 6]]⟩) [(11, 1), (12, 1)]
  [1300309949128, 1236950825721, 1264936270585, 1325534748748, 1883377238016, 1855425871872,
    1855426002945, 1883411554425, 1883411316736, 1883616033657, 1883377238016, 1883479711865,
    1855425871872, 2193663196281, 1889785839352, 1883377238016, 1918785257208]

private def cert6 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [nom 0, append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, append 0 [tx, flush 1 5],
    append 0 [tx, flush 1 8], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 0 1,
    deliver 1 0, deliver 1 0, send 0 1 2, deliver 0 1, append 0 [tx, sig]]⟩) [(7, 3), (9, 1), (10, 2), (11, 3)]
  [1256294711296, 1300309949128, 1236950581248, 1300309949176, 1300309949176, 1236950825721,
    1264936270585, 1264901947392, 1265140743033, 1256814804992, 1265004322817, 1575187889273,
    1271310565113, 1300309982969, 1256814804992, 1271310532344]

private def cert7 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [append 0 [tx, sig], send 0 1 3, backup 2, down 0, deliver 0 1, elect 0, elect 1,
    deliver 1 0, elect 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 0 1, nom 1, nom 1,
    deliver 1 0]⟩) [(10, 2), (11, 2), (16, 2)]
  [1271310531272, 1300309981945, 1236950712321, 1236950825721, 1325534748748, 1883411561209,
    1883411554425, 1855425871872, 1855425871872, 1883377238016, 1883616026745, 1883479718777,
    1883377238016, 2193663193209, 1874770001920, 1855425871872, 1875290340473]

private def cert8 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [nom 0, append 0 [cfg {0, 1}, flush 1 3], deliver 0 1, elect 1, deliver 1 0,
    send 0 2 0, deliver 0 2, deliver 1 2, deliver 1 0, deliver 0 2, deliver 2 0, down 0, deliver 2 1,
    deliver 0 1, deliver 1 2, elect 1, deliver 1 0, deliver 1 0]⟩) [(6, 3), (16, 2)]
  [1256294711296, 1300309949128, 1325534748748, 1883411554425, 1889785854713, 1884425289728,
    1875290234881, 1883377238016, 1883377238016, 1855425871872, 1855425871872, 1855426116345,
    1855426109561, 1883616026745, 1883479613441, 1883411554425, 1883377482617, 1883479719033]

private def cert9 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [append 0 [cfg {0}, flush 1 3], down 0, backup 2, elect 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 0 1, deliver 1 0, elect 0, elect 1, deliver 1 0, deliver 0 1,
    elect 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 1 0, deliver 0 1]⟩) [(4, 1), (14, 1), (16, 2)]
  [1300309949128, 1236950825721, 1236950712321, 1264936270585, 1264901947392, 1265140743033,
    1256815009864, 1265004421241, 1236950581248, 1264936270969, 1264936263801, 1236950581248,
    1264901947392, 1236950581248, 1265140743289, 1265004421241, 1575187905657, 1264901947392, 1256815042681]

private def cert10 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [send 0 1 0, deliver 0 1, append 0 [cfg {0, 2}],
    append 0 [cfg {0, 1, 2}, flush 2 4, sig], send 0 1 5, nom 0, deliver 0 2, deliver 0 1]⟩) []
  [1265949999104, 1256814944257, 1271310531200, 1300309949128, 1300309981945, 1256294711296,
    1325534748748, 1875290562634]

private def cert11 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [tx, flush 1 3], send 0 2 3, send 0 1 3, append 0 [cfg {0, 2}, flush 1 5],
    down 0, deliver 0 1, elect 1, deliver 1 0, elect 1, elect 0, deliver 0 1, deliver 0 1, deliver 0 2]⟩) [(10, 2)]
  [1300309949128, 1300309981945, 1265949999104, 1300309949176, 1236950825721, 1325534748748,
    1883411554425, 1855425871872, 1855425871872, 1883411561209, 1875290300536, 1875290095616, 1875290300488]

private def cert12 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [tx, sig], append 0 [cfg {0, 1}, flush 1 5], nom 0, down 0, deliver 0 1,
    restore 1 [bootstrap {0}, unsigned, signed], deliver 0 1, deliver 0 1, deliver 1 0, elect 1,
    deliver 1 0, deliver 1 0, deliver 0 1, elect 1, elect 0, elect 1, deliver 1 0]⟩) [(4, 2), (6, 1), (8, 1)]
  [1340030270156, 1918785239800, 1874770001920, 1855426116345, 1855425871872, 1717987123272,
    638339981438, 638339514368, 618475290624, 646460973177, 618475290624, 646426656768, 646665445497,
    646460973177, 646460979961, 618475290624, 646529137529]

private def cert13 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [send 0 1 0, append 0 [cfg {0, 1, 2}, flush 2 3], backup 2, down 0, elect 0,
    deliver 0 1, deliver 1 0, deliver 0 2, deliver 0 1, deliver 2 0, deliver 1 0, deliver 0 2,
    append 0 [cfg {1, 2}, flush 1 5]]⟩) [(5, 3), (7, 5), (8, 4), (11, 3)]
  [1265949999104, 1300309949128, 1236950712321, 1236950825721, 1264936270585, 1264901947392,
    1265140743033, 1265004322817, 1265004322817, 1236950826105, 1575187889273, 1264901947392, 1300309950200]

private def cert14 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [cfg {1, 2}, sig], append 0 [cfg {1}, flush 2 5], deliver 0 2,
    append 0 [tx, flush 1 7], append 0 [cfg {0, 1}, flush 2 9], elect 2, send 0 1 9, down 0, deliver 2 0,
    deliver 2 0, deliver 0 1, deliver 0 1, deliver 2 1]⟩) [(10, 3)]
  [1271310531272, 1300309949176, 1256815009864, 1300309965560, 1300309965560, 1264936263801,
    1300309981945, 1236950825721, 1236950581248, 1264901947392, 1256814804992, 1325534748748, 1883377631235]
private def cert15 : Certificate := multiCert
  (⟨{0}, [0, 1], [backup 1, nom 0, nom 0, append 0 [sig], append 0 [cfg {0, 1}], append 0 [cfg {0}, sig],
    down 0, deliver 0 1, deliver 1 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0]⟩) []
  [1236950712321, 1236950581248, 1236950581248, 1340030270156, 1918785239800, 1889785821944,
    1855426116345, 1875290234881, 1855425871872, 1883411561209, 1883377238016, 1883616033657,
    1883479613441, 2193663179897]

private def cert16 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [cfg {0, 1}, flush 2 3], append 0 [cfg {0}, flush 1 5, sig],
    send 0 2 6, append 0 [cfg {0, 2}, flush 1 8, sig], nom 0, send 0 1 8, deliver 0 2,
    down 0, elect 0, deliver 0 1, elect 1, deliver 1 2, elect 1, deliver 0 1]⟩) [(6, 4), (13, 3)]
  [1300309949128, 1300309949176, 1300309981945, 1300309949176, 1256294711296, 1265949999104,
    1236950581248, 1236950825721, 1264936270585, 1325534748748, 1883411816571, 1883377238016,
    1883411316736, 1875290333305]

private def cert17 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [append 0 [cfg {1}, sig], down 0, backup 2, elect 0, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, send 0 1 3, down 0, deliver 0 1,
    deliver 1 0, deliver 1 0, elect 0]⟩) []
  [1271310531272, 1236950825721, 1236950712321, 1264936270585, 1264901947392, 1265140743033,
    1265004322817, 1575187889273, 1256814804992, 1265949999104, 1236950826745, 1236950581248,
    1236950581248, 1236950581248, 1264936271609]

private def cert18 : Certificate := multiCert
  (⟨{0}, [0, 1], [backup 1, nom 0, nom 0, append 0 [tx, sig], append 0 [tx, sig], nom 0,
    append 0 [cfg {0, 1}], deliver 0 1, down 0, deliver 1 0, elect 0, deliver 0 1, deliver 1 0,
    deliver 0 1, deliver 1 0, append 0 [tx, sig]]⟩) []
  [1236950712321, 1236950581248, 1236950581248, 1340030270156, 1889786084094, 1855425871872,
    1918785239800, 1875290234881, 1855426116345, 1855425871872, 1883411561209, 1883377238016,
    1883616033657, 1883479613441, 2164663762041, 1889786085118]

private def cert19 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [send 0 1 1, backup 2, send 0 1 1, append 0 [tx, sig], deliver 0 1, send 0 1 2,
    deliver 0 1, down 0, deliver 1 0, deliver 0 1, deliver 1 0, elect 0, deliver 0 1, elect 0,
    deliver 1 0, deliver 0 1, deliver 1 0, elect 0, deliver 0 1]⟩) [(4, 1), (8, 2), (18, 2)]
  [1300309981825, 1236950712321, 1265949999104, 1271310531272, 1256814804992, 1300309981945,
    1256815009792, 1236950825721, 1236950581248, 1256815009792, 1236950581248, 1264936270585,
    1264901947392, 1264936026112, 1236950581248, 1236950581248, 1265140743033, 1264936270969, 1264902184961]

private def cert20 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [tx, flush 1 3], down 0, deliver 0 1, elect 0, deliver 0 1,
    elect 1, deliver 1 0, elect 0, elect 0, deliver 0 1, deliver 1 0, deliver 1 0, deliver 1 0,
    deliver 0 1, deliver 0 1, deliver 0 1, elect 0, elect 0, deliver 0 1, deliver 1 0]⟩)
  [(6, 1), (11, 3), (13, 2)]
  [1300309949128, 1236950825721, 1325534748748, 1883411561209, 1883377238016, 1883411554425,
    1883616033657, 1883411561593, 1855425871872, 1883479711865, 1855425871872, 1855425871872,
    1883377238016, 1855425871872, 1883377238016, 1855425871872, 1883411316736, 1855425871872,
    1855425871872, 1883616033913]

private def cert21 : Certificate := multiCert (⟨{0}, [0, 1], [append 0 [cfg {0, 1}]]⟩) [] [1300309949056]

private def cert22 : Certificate := multiCert (⟨{0, 1}, [0, 1], [down 0]⟩) [] [1236950825601]

private def cert23 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [sig], append 0 [cfg {0, 1}], send 0 1 3]⟩) []
  [1340030270156, 1918785239800, 1918785272569]

private def cert24 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [sig], restore 1 [bootstrap {0}, signed], append 0 [tx]]⟩) []
  [1340030270156, 1717987123272, 652835257080]

private def cert25 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [send 0 1 1, deliver 0 1, append 0 [tx]]⟩) []
  [1300309981825, 1256815009792, 1271310547584]

private def cert26 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [send 0 1 1, deliver 0 1, append 0 [flush 1 2]]⟩) []
  [1300309981825, 1256815009792, 1300309965512]

private def cert27 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [flush 1 2], deliver 0 1, append 0 [tx]]⟩) []
  [1300309949128, 1325534748748, 1889785838328]

private def cert28 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3], deliver 0 1, append 0 [sig]]⟩) []
  [1300309949128, 1325534748748, 1889786100474]

private def cert29 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3], deliver 0 1, append 0 [flush 1 4]]⟩) []
  [1300309949128, 1325534748748, 1918785518330]

private def cert30 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, deliver 1 0]⟩) []
  [1300309949128, 1325534748748, 1889786116859]
private def cert31 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, send 0 1 3]⟩) []
  [1300309949128, 1325534748748, 1884425682947]

private def cert32 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, send 0 1 4]⟩) []
  [1300309949128, 1325534748748, 1918785534715]

private def cert33 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, down 0]⟩) []
  [1300309949128, 1325534748748, 1855426378491]

private def cert34 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, nom 0]⟩) []
  [1300309949128, 1325534748748, 1874770395139]

private def cert35 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [send 0 1 1, deliver 0 1, append 0 [cfg {0, 1, 2}]]⟩) []
  [1300309981825, 1256815009792, 1300309965440]

private def cert36 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [append 0 [cfg {0}, flush 1 3, sig], deliver 0 1, backup 2]⟩) []
  [1300309949128, 1325534748748, 1855426265091]

private def cert37 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [tx, sig], restore 1 [bootstrap {0}, unsigned, signed], append 0 [cfg {0, 1}],
    nom 0, deliver 0 1]⟩) []
  [1340030270156, 1717987123272, 681834674936, 637819420672, 638339752057]

private def cert38 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [append 0 [cfg {0, 1}, flush 1 3], send 0 2 1,
    append 0 [cfg {0, 1, 2}, flush 1 5, sig], down 0, deliver 0 1, deliver 1 0, deliver 0 2]⟩) []
  [1300309949128, 1300309981945, 1300309949176, 1236950825721, 1325534748748, 1855425871872, 1875290300416]

private def cert39 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [cfg {0, 1}, sig], nom 0, deliver 0 1, send 0 1 3, backup 1, down 0,
    elect 0, deliver 0 1]⟩) [(2, 1), (7, 2)]
  [1300309949128, 1256294711296, 1236950581248, 1300309981945, 1236950712321, 1236950825721,
    1264936270585, 1264902086657]

private def cert40 : Certificate := multiCert
  (⟨{0, 1, 2}, [0, 1, 2], [send 0 2 0, send 0 1 0, nom 0, deliver 0 2, append 0 [cfg {0, 1}, flush 2 3],
    down 0, deliver 0 1, deliver 1 0, deliver 0 2, deliver 2 0, deliver 0 2, deliver 2 0, elect 2,
    deliver 2 1, deliver 2 0, deliver 1 2]⟩) [(3, 2), (8, 1)]
  [1265949999104, 1265949999104, 1256294711296, 1236950581248, 1300309949128, 1236950825721,
    1256814944257, 1236950581248, 1256815009864, 1236950581248, 1256814804992, 1236950581248,
    1264936263801, 1264901947392, 1264901947392, 1236950818937]

private def cert41 : Certificate := multiCert
  (⟨{0}, [0, 1], [backup 1, nom 0, nom 0, nom 0, append 0 [tx], nom 0, nom 0, append 0 [tx, sig],
    nom 0, nom 0, append 0 [cfg {0, 1}], append 0 [tx, sig], append 0 [cfg {0}, flush 1 9],
    down 0, elect 0, deliver 0 1]⟩) [(15, 2)]
  [1236950712321, 1236950581248, 1236950581248, 1236950581248, 1271310531200, 1236950581248,
    1236950581248, 1340030270156, 1855425871872, 1855425871872, 1918785239800, 1889785821944,
    1918785239800, 1855426116345, 1883411561209, 1883377377281]

private def cert42 : Certificate := multiCert
  (⟨{0, 1}, [0, 1], [append 0 [cfg {1}], append 0 [sig], append 0 [cfg {0, 1}, flush 1 5, sig], nom 0,
    nom 0, deliver 0 1, append 0 [tx, flush 1 7], down 0, elect 0, deliver 0 1, deliver 0 1,
    deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, elect 1, deliver 1 0]⟩)
  [(5, 1), (9, 3), (10, 2), (11, 3)]
  [1271310531200, 1271310531272, 1300309949176, 1256294711296, 1236950581248, 1236950581248,
    1300309949176, 1236950825721, 1264936270585, 1264901947392, 1256814804992, 1236950581248,
    1325534748748, 1883616033657, 1883616026745, 1855425871872, 1883411554425, 1883479474176]

private def cert43 : Certificate := multiCert
  (⟨{0, 1}, [0, 1, 2], [backup 2, nom 0, nom 0, nom 0, deliver 0 1, append 0 [cfg {0}],
    append 0 [cfg {0, 1}, flush 1 4], append 0 [tx, flush 1 6], down 0, deliver 0 1, deliver 0 1,
    deliver 1 0, elect 0, elect 0, deliver 0 1, elect 0, deliver 0 1, deliver 1 0]⟩)
  [(9, 2), (14, 1), (16, 2), (17, 5)]
  [1236950712321, 1256294711296, 1236950581248, 1236950581248, 1236950581248, 1271310531200,
    1300309949128, 1300309949176, 1236950825721, 1325534748748, 1883616026745, 1855425871872,
    1883411561209, 1855425871872, 1875290095616, 1855425871872, 1883377238016, 1855426116473]

private def cert44 : Certificate := multiCert
  (⟨{0}, [0, 1], [append 0 [sig], backup 1, nom 0, append 0 [cfg {0, 1}], down 0, deliver 0 1,
    elect 0, deliver 1 0, deliver 0 1, elect 0, deliver 1 0, deliver 0 1, deliver 1 0, nom 0,
    append 0 [tx, sig], deliver 0 1, deliver 1 0, append 0 [tx]]⟩) [(11, 1)]
  [1340030270156, 1855426002945, 1855425871872, 1918785239800, 1855426116345, 1875290234881,
    1883411561209, 1855425871872, 1883377238016, 1883411316736, 1883616033657, 1883479613441,
    2164663762041, 1855425871872, 1889786085118, 1883377238016, 1855425871872, 1889785822968]

private def cert45 : Certificate := soloCert
  (⟨{0}, [0], [append 0 [sig], append 0 [tx]]⟩) [] [1202591316684, 652835240696]

private def cert46 : Certificate := soloCert
  (⟨{0}, [0], [append 0 [sig], append 0 [sig]]⟩) [] [1202591316684, 652835502846]

private def certificates : List Certificate :=
  [cert0, cert1, cert2, cert3, cert4, cert5, cert6, cert7, cert8, cert9, cert10, cert11, cert12, cert13,
    cert14, cert15, cert16, cert17, cert18, cert19, cert20, cert21, cert22, cert23, cert24, cert25, cert26,
    cert27, cert28, cert29, cert30, cert31, cert32, cert33, cert34, cert35, cert36, cert37, cert38, cert39,
    cert40, cert41, cert42, cert43, cert44, cert45, cert46]
-- END GENERATED CERTIFICATES

private def multiKeys : List Nat :=
  (certificates.flatMap fun c => if c.multi.isSome then c.keys else []).eraseDups

private def keys : List Nat := (certificates.flatMap (·.keys)).eraseDups

private theorem occurs {k : Nat} (mem : k ∈ keys) :
    ∃ s : Step, project (label s) = k := by
  obtain ⟨c, _, found⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp mem)
  obtain ⟨s, _, key⟩ := c.checked k found
  exact ⟨s, key⟩

private theorem multi_occurs {k : Nat} (mem : k ∈ multiKeys) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  obtain ⟨c, _, found⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp mem)
  cases multi : c.multi with
  | none => simp [multi] at found
  | some h =>
    simp only [multi, Option.isSome_some, ite_true] at found
    obtain ⟨s, nodes, key⟩ := c.checked k found
    exact ⟨s, nodes ▸ h.down, key⟩

private theorem count : keys.Nodup ∧ keys.length = 139 := by decide +kernel
private theorem multi_count : multiKeys.Nodup ∧ multiKeys.length = 136 := by decide +kernel

/-- Every list covering all initialized recorded step labels has at least 139 rows. -/
public theorem full_lower_bound (rows : List Profile) (complete : ∀ s, label s ∈ rows) :
    139 ≤ rows.length := by
  simpa only [count.2] using
    (projected_lower_bound project count.1 (fun _ => occurs) complete)

/-- Every cover of initialized steps on multi-node deployments has at least 136 rows. -/
public theorem multi_lower_bound (rows : List Profile)
    (complete : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → label s ∈ rows) :
    136 ≤ rows.length := by
  have sub : multiKeys ⊆ rows.map project := by
    intro k hk
    obtain ⟨s, multi, key⟩ := multi_occurs hk
    exact List.mem_map.mpr ⟨_, complete s multi, key⟩
  simpa only [multi_count.2, List.length_map] using multi_count.1.length_le_of_subset sub

end ConsensusCoverage.ExploredWitnesses
