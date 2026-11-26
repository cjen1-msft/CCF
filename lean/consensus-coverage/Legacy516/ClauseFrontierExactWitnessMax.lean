module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactSamples
public import ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.ClauseFrontierExactMaximum
import all ConsensusCoverage.ClauseFrontierExactSamples
import all ConsensusCoverage.HandReadersAHandler
import all ConsensusCoverage.HandReadersOtherFrontier
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-- Selected witness steps whose four bound answers can be computed without
running any of the reflected maximum-query readers. -/
public def maximumCertifiedPicks : List (Nat × Nat) :=
  [(70,4),(80,8),(132,8),(69,9),(138,9),(74,19)]

private def acceptsAndAdvances (s : Step) : Bool :=
  (HandReadersA.Handler.exactReader .clear).eval s.cfg s.before s.act s.after s.past &&
    (HandReadersOther.Frontier.exactReader true).eval s.cfg s.before s.act s.after s.past

private theorem checked :
    maximumCertifiedPicks.all (fun (i,j) => (ReadersCorpus.stepAt i j).any acceptsAndAdvances) = true ∧
      maximumCertifiedPicks.all (fun p => (patternBatches.flatten.map Prod.fst).contains p) = true := by
  decide +kernel

public def maximumBits (s : Step) : List Bool :=
  [Classes.StepBranch.maxCommittableIndexBounded_values_nil,
    .maxCommittableIndexBounded_values_cons, .maxCommittableIndexBounded_signature_pos,
    .maxCommittableIndexBounded_signature_neg].map fun q =>
    (ReadersTotal.read s.cfg s.before s.act s.after s.past q).getD false

public theorem maximum_bits_eq (s : Step) :
    maximumBits s = ((nonTrunkLabel .frontier s).bits.drop 19).take 4 := by
  have columns :
      ((nonTrunk .frontier).drop 19).take 4 =
        [.maxCommittableIndexBounded_values_nil, .maxCommittableIndexBounded_values_cons,
         .maxCommittableIndexBounded_signature_pos, .maxCommittableIndexBounded_signature_neg] := by
    decide +kernel
  rw [← read_eq s]
  simp only [read, ← List.map_drop, ← List.map_take, columns, maximumBits]

public theorem maximum_certified {i j : Nat} (h : (i,j) ∈ maximumCertifiedPicks) :
    ∃ s, ReadersCorpus.stepAt i j = some s ∧ maximumBits s = [true,true,true,true] := by
  have yes := List.all_eq_true.mp checked.1 (i,j) h
  simp only [Option.any_eq_true] at yes
  obtain ⟨s,step,reads⟩ := yes
  dsimp only [acceptsAndAdvances] at reads
  have ⟨clear, advance⟩ := Bool.and_eq_true_iff.mp reads
  have hc := (HandReadersA.Handler.exactReader .clear).eq_label s |>.trans clear
  have ha := (HandReadersOther.Frontier.exactReader true).eq_label s |>.trans advance
  have ⟨nil,cons⟩ := Maximum.append_accept_scans s .clear (.inl rfl) hc
  have sig := Maximum.advance_needs_signature s ha
  have neg := (bound_cons_eq_nonsignature s).symm.trans cons
  have readAt (q : Classes.StepBranch) (covered : q ∈ ReadersTotal.covered) :=
    ReadersTotal.read_total s covered
  refine ⟨s,step,?_⟩
  simp only [maximumBits,List.map_cons,List.map_nil,
    readAt .maxCommittableIndexBounded_values_nil (by decide +kernel),
    readAt .maxCommittableIndexBounded_values_cons (by decide +kernel),
    readAt .maxCommittableIndexBounded_signature_pos (by decide +kernel),
    readAt .maxCommittableIndexBounded_signature_neg (by decide +kernel), Option.getD_some,
    nil,cons,sig,neg]

end ConsensusCoverage.ClauseFrontierExact
