module

public import CCFRaft.Proofs.Duel.ResolveChain
public import CCFRaft.Proofs.Duel.Relevance
public import CCFRaft.Proofs.Duel.Blocks

@[expose] public section

/-!
# Duelling leaders resolve

NOT IMPORTED BY `Properties`. Public statement (ii): against any measurable
scheduling policy, a run that starts a round reaches an anchored start within a
bounded window, except on a set of draws of small measure.

The policy sees every draw as soon as it is made (through the deadline it sets),
and may use it to schedule everything after; this is stronger than any physical
adversary. Each draw is independent of what the policy saw before it, so each
relevant draw of a round (a participant's first or second reset into the round's
term) lands within `4 * maxDelay` of another participant's deadline with probability
at most `(n - 1) * rho` given the past, where `n` is the number of participants. A
round has at most `2 * n` relevant draws, so it fails with probability at most
`q = 2 * n * (n - 1) * rho`. A round that does not fail, and none of whose steps
overshoots a deadline, ends in an anchored start (`Round.duel_round`).

At most `overshoots` steps of the window overshoot a deadline, each by at most
`jump`. Cutting the rounds into `overshoots + 1` blocks of `rounds` rounds, some
block has no overshoot, and all its rounds fail with probability at most
`q ^ rounds`; so the run fails on a set of measure at most
`(overshoots + 1) * q ^ rounds`.

Regime. For the uniform law `rho = 4 * margin / electionTimeout` with
`margin = 4 * maxDelay` (`Rounds.uniform_law`), so `q = 32 * n * (n - 1) * maxDelay /
electionTimeout`, which is below one only when `maxDelay` is small against
`electionTimeout / n ^ 2`: at CCF's default `electionTimeout = 5000ms` and `n = 5`,
only up to `maxDelay` of about 7ms. CCF's whole-millisecond law has a similar `rho`
(`Rounds.ccf_law`).
-/

namespace CCFRaft.Proofs.Duel.Resolve

open CCFRaft.Liveness MeasureTheory Set
open CCFRaft.Proofs.Duel.Adaptive
open CCFRaft.Proofs.Duel.Rounds (Law roundFailure)
open CCFRaft.Proofs.Duel.Round (HandoffBy roundLength)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCFRaft.Proofs.Liveness (Admissible)

/-- One round's failure probability with `n` participants: `2 * n` relevant draws,
each within the margin of one of `n - 1` deadlines with probability at most `rho`. -/
noncomputable def roundFailureOf (rho : Real) (participants : Finset NodeID) : Real :=
  roundFailure rho (participants.card - 1) (2 * participants.card)

/-- (ii) Duelling leaders resolve. Against a measurable policy, if every run with
draws in `[electionTimeout / 2, electionTimeout]` reaches an anchored start or a round
start within `initial` of `start`, and meets the window's premises, the runs without an anchored start in the window have
measure at most `(overshoots + 1) * q ^ rounds`. The set need not be measurable;
the bound is on its outer measure, so a measurable set of runs with an anchored
start has measure at least `1 - (overshoots + 1) * q ^ rounds`. -/
theorem duelling_leaders_resolve [Config.InitialConfiguration] {nodes : List NodeID}
    {initial electionTimeout maxDelay jump rho fresh : Real} {law : Measure Real}
    {overshoots rounds start : Nat} {participants members : Finset NodeID}
    {policy : Policy}
    (isLaw : Law electionTimeout (4 * maxDelay) rho law)
    (borel : Borel participants policy)
    (freshLe : fresh <= electionTimeout / 2 - 4 * maxDelay)
    (setup
      : forall sample : Sample,
          (forall j, sample j ∈ Icc (electionTimeout / 2) electionTimeout)
          -> Setup nodes (run participants policy sample) initial electionTimeout
              maxDelay jump fresh overshoots start
              (window initial electionTimeout maxDelay jump overshoots rounds)
              participants members)
    : Measure.infinitePi (fun _ => law)
        {sample |
          Not
            (HandoffBy (run participants policy sample) participants start
              (window initial electionTimeout maxDelay jump overshoots rounds) fresh)
        }
      <= ENNReal.ofReal
          ((overshoots + 1) * roundFailureOf rho participants ^ rounds) := by
  sorry

/-- (ii), as a lower bound on the outer measure of the runs with an anchored start. -/
theorem duelling_leaders_resolve_lower [Config.InitialConfiguration] {nodes : List NodeID}
    {initial electionTimeout maxDelay jump rho fresh : Real} {law : Measure Real}
    {overshoots rounds start : Nat} {participants members : Finset NodeID}
    {policy : Policy}
    (isLaw : Law electionTimeout (4 * maxDelay) rho law)
    (borel : Borel participants policy)
    (freshLe : fresh <= electionTimeout / 2 - 4 * maxDelay)
    (setup
      : forall sample : Sample,
          (forall j, sample j ∈ Icc (electionTimeout / 2) electionTimeout)
          -> Setup nodes (run participants policy sample) initial electionTimeout
              maxDelay jump fresh overshoots start
              (window initial electionTimeout maxDelay jump overshoots rounds)
              participants members)
    : ENNReal.ofReal (1 - (overshoots + 1) * roundFailureOf rho participants ^ rounds)
      <= Measure.infinitePi (fun _ => law)
          {sample |
            HandoffBy (run participants policy sample) participants start
              (window initial electionTimeout maxDelay jump overshoots rounds) fresh
          } := by
  sorry

end CCFRaft.Proofs.Duel.Resolve
