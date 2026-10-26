module

public import CCFRaft.Proofs.Leadership.InitRaiseClear
public import CCFRaft.Proofs.Direct.CommitFrontier

@[expose] public section

set_option linter.unusedSectionVars false

/-!
A finite nonempty set of participants has a log whose pre-vote every other
participant's log permits.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A reachable node's advertised commit frontier is its latest signature. -/
theorem request_frontier {index : Nat} {point : W} {node : NodeID} {state : NodeState}
    (found : trace.stateAt index = some point)
    (stateFound : nodeState (proto point) node = some state)
    : lastCommittableTerm state = maxCommittableTerm state.log
      /\ lastCommittableIndex state = maxCommittableIndex state.log := by
  have frontier := Direct.commitFrontier_invariant.reachable (admissible.reachable found)
    node state (Concrete.mem_of_nodeState stateFound)
  have eq : lastCommittableIndex state = maxCommittableIndex state.log :=
    Nat.max_eq_right frontier.truncateToSignature
  exact ⟨congrArg (termAt state.log) eq, eq⟩

/-- Some participant's request passes every participant's log-freshness check. -/
theorem best_log {index : Nat} {point : W} {participants : Finset NodeID}
    (found : trace.stateAt index = some point) (nonempty : participants.Nonempty)
    (present
      : forall node,
          node ∈ participants -> exists state, nodeState (proto point) node = some state)
    : exists winner state,
        winner ∈ participants
        /\ nodeState (proto point) winner = some state
        /\ forall voter local_,
            voter ∈ participants
            -> nodeState (proto point) voter = some local_
            -> voteLogUpToDate local_ (makeRequestVoteRequest state) := by
  classical
  obtain ⟨first, firstIn⟩ := nonempty
  obtain ⟨defaultState, _⟩ := present first firstIn
  let states node := (nodeState (proto point) node).getD defaultState
  have statesFound : forall node, node ∈ participants
      -> nodeState (proto point) node = some (states node) := by
    intro node member
    obtain ⟨state, stateFound⟩ := present node member
    simp only [states, stateFound, Option.getD_some]
  obtain ⟨newest, newestIn, newestTerm⟩ := Finset.exists_max_image participants
    (fun node => maxCommittableTerm (states node).log) ⟨first, firstIn⟩
  let tied := participants.filter fun node =>
    maxCommittableTerm (states node).log = maxCommittableTerm (states newest).log
  have tiedNonempty : tied.Nonempty := ⟨newest, Finset.mem_filter.mpr ⟨newestIn, rfl⟩⟩
  obtain ⟨winner, winnerTied, winnerIndex⟩ := Finset.exists_max_image tied
    (fun node => maxCommittableIndex (states node).log) tiedNonempty
  obtain ⟨winnerIn, winnerTerm⟩ := Finset.mem_filter.mp winnerTied
  have winnerFound := statesFound winner winnerIn
  have frontier := request_frontier admissible found winnerFound
  refine ⟨winner, states winner, winnerIn, winnerFound, ?_⟩
  intro voter local_ voterIn voterFound
  have voterEq : states voter = local_ := by simp only [states, voterFound, Option.getD_some]
  have cap := newestTerm voter voterIn
  rw [← winnerTerm, voterEq] at cap
  simp only [voteLogUpToDate, makeRequestVoteRequest, frontier.1, frontier.2]
  rcases Nat.lt_or_eq_of_le cap with lt | eq
  · exact Or.inl lt
  · refine Or.inr ⟨eq.symm, ?_⟩
    have voterTied : voter ∈ tied := Finset.mem_filter.mpr ⟨voterIn, by
      rw [voterEq, eq, winnerTerm]⟩
    simpa only [voterEq] using winnerIndex voter voterTied

end CCFRaft.Proofs.Leadership.InitRaise
