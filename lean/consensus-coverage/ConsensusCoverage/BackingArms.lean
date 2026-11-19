module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.BackingArms

open Consensus Consensus.Model Consensus.Proofs Consensus.Proofs.Safety

private theorem commitFacts [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n st k b i} (step : CommitStep (f.advance t) n st k b i) :
    CommitFacts (f.advance t).logs st.log k b i := by
  have floor : 2 ≤ k := step.1.2.2.2.elim (fun h => by rw [h.1]; decide)
    (fun ⟨l, j, elect⟩ => Nat.le_trans (by decide : 2 ≤ 3) (c.electionCerts n k l j elect).above)
  exact step.facts floor c.inv_step.rooted c.inv_step.sorted

/-- The zero-base arm for a newly committed key. -/
theorem zero_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    PinnedClasses.sig c .commitChains_step_backing_inl ↔
      ∃ n st k i, CommitStep (f.advance t) n st k 0 i ∧ ¬ Committed f k (st.log.take i) := by
  rw [SolvedWitnesses.sig_iff]
  change SolvedWitnesses.step_commitChains_step_backing_inl f t c ↔ _
  constructor
  · rintro ⟨k, p, fresh, _, n, _, st, _, _, i, _, step, _, rfl, _⟩
    exact ⟨n, st, k, i, step, fresh.2⟩
  · rintro ⟨n, st, k, i, step, fresh⟩
    have backing : Backed f st.log 0 k := .inl rfl
    have post : Committed (f.advance t) k (st.log.take i) :=
      .inr ⟨n, st, 0, i, step, rfl, backing⟩
    have h := And.intro step (And.intro (Eq.refl (st.log.take i)) backing)
    -- After the base is fixed to zero, normalization replaces `0 = 0` with `True`.
    have normalized : True ∨ ∃ e p, Committed f e p ∧ e ≤ k ∧ st.log.take 0 <+: p := .inl trivial
    have hz := And.intro step (And.intro (Eq.refl (st.log.take i)) normalized)
    have facts := commitFacts c step
    have ⟨now, le, bound, sig, term, acks⟩ := step
    exact ⟨k, st.log.take i, ⟨post, fresh⟩, ⟨n, st, 0, i, h⟩, n, ⟨st, 0, i, h⟩,
      st, ⟨0, i, h⟩, ⟨i, hz⟩, i, hz, step, hz.2, rfl, normalized,
      now, step.2, le, step.2.2, bound, step.2.2.2, sig, step.2.2.2.2, term, acks,
      le, acks, facts, post, facts.floor, facts⟩

/-- The prior-key arm for a newly committed key; the base may still be zero. -/
theorem prior_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    PinnedClasses.sig c .commitChains_step_backing_inr ↔
      ∃ n st k b i, CommitStep (f.advance t) n st k b i ∧ ¬ Committed f k (st.log.take i) ∧
        ∃ e p, Committed f e p ∧ e ≤ k ∧ st.log.take b <+: p := by
  rw [SolvedWitnesses.sig_iff]
  change SolvedWitnesses.step_commitChains_step_backing_inr f t c ↔ _
  constructor
  · rintro ⟨k, p, fresh, _, n, _, st, _, b, _, i, _, step, _, rfl, _, rest⟩
    obtain ⟨_, _, _, _, _, _, _, _, _, _, prior, _⟩ := rest
    exact ⟨n, st, k, b, i, step, fresh.2, prior⟩
  · rintro ⟨n, st, k, b, i, step, fresh, e, p, prior, leTerm, sub⟩
    have old := And.intro prior (And.intro leTerm sub)
    have earlier : ∃ e p, Committed f e p ∧ e ≤ k ∧ st.log.take b <+: p := ⟨e, p, old⟩
    have backing : Backed f st.log b k := .inr earlier
    have post : Committed (f.advance t) k (st.log.take i) :=
      .inr ⟨n, st, b, i, step, rfl, backing⟩
    have h := And.intro step (And.intro (Eq.refl (st.log.take i)) backing)
    have facts := commitFacts c step
    have ⟨now, le, bound, sig, term, acks⟩ := step
    exact ⟨k, st.log.take i, ⟨post, fresh⟩, ⟨n, st, b, i, h⟩, n, ⟨st, b, i, h⟩,
      st, ⟨b, i, h⟩, b, ⟨i, h⟩, i, h, step, h.2, rfl, backing,
      now, step.2, le, step.2.2, bound, step.2.2.2, sig, step.2.2.2.2, term, acks,
      earlier, e, ⟨p, old⟩, p, old, prior, old.2, leTerm, sub, post, facts.floor, facts⟩

end ConsensusCoverage.BackingArms
