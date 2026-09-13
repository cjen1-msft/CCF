-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeClientRequestExecution
import Sparse.NativeLeaderLogPrefix
import Sparse.NativeRetirementTailExecution
import Sparse.NativeSubmittedWriteEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem client_request_bootstrap {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  obtain ⟨prefixStates, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before
      states.prepared states.appended execution.prepareRun
  exact
    (insert_submitted_success transaction states.retired after
      execution.submittedRun).bootstrap.trans
      ((retirement_tail_bootstrap before.bootstrap source states.appended
        (nodeRowSnapshot before.toColumns source).commit
        (clientRequestGuards before.toColumns source transaction)
        states.prepared states.retired execution.tailRun).trans
        prefixResult.afterBootstrap)

theorem client_request_prior_holds {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  obtain ⟨prefixStates, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before
      states.prepared states.appended execution.prepareRun
  have retiredHolds :=
    ((insert_submitted_holds transaction states.retired after
      execution.submittedRun assignment).mp holds).1
  have preparedHolds :=
    retirement_tail_prior_holds before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired execution.tailRun assignment retiredHolds
  exact
    (leader_log_prefix_facts source (.inr (.inl transaction)) before
      states.prepared states.appended prefixStates prefixResult assignment
      preparedHolds).priorHolds

theorem client_request_references {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  obtain ⟨_, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before
      states.prepared states.appended execution.prepareRun
  have preparedValid : ReferencesValid states.prepared := by
    cases valid
    constructor <;>
      simp only [prefixResult.afterColumns, prefixResult.afterNext] <;>
      omega
  have retiredValid :=
    retirement_tail_references before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired execution.tailRun preparedValid
  exact
    insert_submitted_references transaction states.retired after
      execution.submittedRun retiredValid

theorem client_request_next {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after)) :
    after.next = before.next + 27 + 3 * width := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  obtain ⟨_, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before
      states.prepared states.appended execution.prepareRun
  have tailNext :=
    retirement_tail_next before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired execution.tailRun
  have submittedNext :=
    (insert_submitted_success transaction states.retired after
      execution.submittedRun).next
  have preparedNext := prefixResult.afterNext
  omega

theorem client_request_transaction_bounded {width : PNat}
    (source : Fin width) (transaction : Expr .int)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after)) :
    transaction.symbols.all (fun symbol => symbol.2 < before.next) = true := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  obtain ⟨prefixStates, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before
      states.prepared states.appended execution.prepareRun
  have firstRun := prefixResult.runs.entriesRun
  simp only [define, StateT.run] at firstRun
  split at firstRun
  next bounded =>
    simp only [leaderLogPrefixTerms, leaderLogEntriesTerm, Term.symbols,
      List.all_append, Bool.and_eq_true] at bounded
    exact bounded.2.2
  next =>
    contradiction

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
