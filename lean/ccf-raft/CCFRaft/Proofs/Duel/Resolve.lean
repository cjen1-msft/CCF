module

public import CCFRaft.Proofs.Duel.Margin
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
open CCFRaft.Proofs.Duel.Round (roundLength)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCFRaft.Proofs.Liveness (Admissible)

/-- One round's failure probability with `n` participants: `2 * n` relevant draws,
each within the margin of one of `n - 1` deadlines with probability at most `rho`. -/
noncomputable def roundFailureOf (rho : Real) (participants : Finset NodeID) : Real :=
  roundFailure rho (participants.card - 1) (2 * participants.card)

/-- The relevant draws of the run's rounds, as `Rounds.Attempts`. -/
noncomputable def attemptsOf {margin : Real} {participants : Finset NodeID}
    {policy : Policy} (borel : Borel participants policy) (start : Nat)
    : Rounds.Attempts margin (participants.card - 1) (2 * participants.card) where
  relevant := Relevant participants policy start
  relevant_measurable := relevant_measurable borel
  centres := centres participants policy start
  centres_measurable := centres_measurable borel
  ordered _ _ _ _ _ lt relevant relevant' := relevant_ordered lt relevant relevant'
  bounded := relevant_bounded

/-- Every block having a round whose relevant draws keep the margin forces an anchored
start in the window. -/
theorem forces_handoff [Config.InitialConfiguration] {nodes : List NodeID}
    {initial electionTimeout maxDelay jump fresh : Real}
    {overshoots rounds start : Nat} {participants members : Finset NodeID}
    {policy : Policy} (borel : Borel participants policy)
    (freshLe : fresh <= electionTimeout / 2 - 4 * maxDelay)
    (setup
      : forall sample : Sample,
          (forall j, sample j ∈ Icc (electionTimeout / 2) electionTimeout)
          -> Setup nodes (run participants policy sample) initial electionTimeout
              maxDelay jump fresh overshoots start
              (window initial electionTimeout maxDelay jump overshoots rounds)
              participants members)
    : forall sample,
        (forall j, sample j ∈ Icc (electionTimeout / 2) electionTimeout)
        -> (forall b,
              b < overshoots + 1
              -> exists k,
                  k < rounds
                  /\ forall j,
                      (attemptsOf (margin := 4 * maxDelay) borel start).relevant
                        (b * rounds + k) j sample
                      -> forall i,
                          4 * maxDelay
                          < |sample j
                              - (attemptsOf (margin := 4 * maxDelay) borel start).centres
                                  (b * rounds + k) j sample i|)
        -> sample
            ∈ {sample |
                HandoffBy (run participants policy sample) participants start
                  (window initial electionTimeout maxDelay jump overshoots rounds) fresh
              } := by
  intro sample support blocks
  have setup := setup sample support
  exact chain setup freshLe fun b below => by
    obtain ⟨k, kLt, far⟩ := blocks b below
    exact ⟨k, kLt, fun c term roundAt =>
      margin_of_far setup.admissible setup.timers roundAt far⟩

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
  have bound := Rounds.blocks_bound isLaw (attemptsOf borel start)
    (forces_handoff borel freshLe setup)
  have q0 : 0 <= roundFailureOf rho participants := by
    have := isLaw.nonnegative
    simp only [roundFailureOf, roundFailure]
    positivity
  rw [ENNReal.ofReal_mul (by positivity), ENNReal.ofReal_pow q0]
  unfold roundFailureOf
  convert bound using 2
  · rfl
  · norm_cast

end CCFRaft.Proofs.Duel.Resolve
