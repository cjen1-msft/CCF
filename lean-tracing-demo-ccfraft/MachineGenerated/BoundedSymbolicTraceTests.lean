-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTraceEncoding

set_option autoImplicit false

namespace CCFRaft.BoundedSymbolicTrace.Tests

open Symbolic SymbolicModel

private def source : Node := ⟨2, by decide⟩
private def destination : Node := ⟨9, by decide⟩
private def bounds : BoundedState.Bounds := ⟨2, 3, 4, 2, 2⟩
private def zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩

#guard (transactionDomains bounds 1).eval
  (fun index => if index = entryWidth bounds then 1 else 999)
#guard !((transactionDomains bounds 1).eval (fun _ => 2))
#guard (transactionDomains zeroBounds 0).eval (fun _ => 999)
#guard !((transactionDomains zeroBounds 1).eval (fun _ => 0))

#guard BoundedState.check bounds (BoundedState.encode (initialState : State Node Nat))
#guard Enabled (initialState : State Node Nat) (.clientRequest INITIAL_LEADER 2)
#guard !(BoundedState.check bounds (BoundedState.encode
  (next (initialState : State Node Nat) (.clientRequest INITIAL_LEADER 2))))

#guard evaluateAction (fun _ => 1) (.clientRequest source (.unknown 0)) =
  .clientRequest source 1
#guard evaluateAction (fun _ => 1) (.clientRequest source (.unknown 0)) =
  evaluateAction (fun _ => 1) (.clientRequest source (.unknown 7))
#guard evaluateAction (fun index => index) (.clientRequest source (.unknown 7)) =
  .clientRequest source 7

private def unchangedActions : List (SymbolicAction × Action Node Nat) :=
  [(.signCommittableMessages source, .signCommittableMessages source),
   (.changeConfiguration source {source, destination}, .changeConfiguration source {source, destination}),
   (.appendRetiredCommitted source, .appendRetiredCommitted source),
   (.appendEntries source destination 3, .appendEntries source destination 3),
   (.receive source destination, .receive source destination),
   (.timeout source, .timeout source),
   (.becomePreVoteCandidate source, .becomePreVoteCandidate source),
   (.becomeCandidate source, .becomeCandidate source),
   (.advanceCommitIndex source, .advanceCommitIndex source),
   (.checkQuorum source, .checkQuorum source),
   (.updateTerm source destination, .updateTerm source destination),
   (.becomeLeader source, .becomeLeader source),
   (.requestVote source destination, .requestVote source destination),
   (.requestPreVote source destination, .requestPreVote source destination),
   (.proposeVote source destination, .proposeVote source destination),
   (.advanceCommitIndexAndProposeVote source destination,
     .advanceCommitIndexAndProposeVote source destination)]

#guard unchangedActions.all fun (symbolic, actual) =>
  evaluateAction (fun _ => 999) symbolic == actual

end CCFRaft.BoundedSymbolicTrace.Tests

run_cmd do
  for theoremName in [
      ``CCFRaft.BoundedSymbolicTrace.transactionDomains_correct,
      ``CCFRaft.SymbolicTraceEncoding.follows_correct,
      ``CCFRaft.SymbolicTraceEncoding.encode_holds_correct,
      ``CCFRaft.SymbolicTraceEncoding.verifiedEncoder,
      ``CCFRaft.SymbolicTraceEncoding.group_count] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
