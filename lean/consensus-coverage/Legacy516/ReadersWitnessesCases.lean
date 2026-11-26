module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersWitnessProof
import all ConsensusCoverage.ReadersWitnessProof
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReadersPolarBacking
import all ConsensusCoverage.ReadersPolarSummary
import all ConsensusCoverage.ReadersPolarObserve
import all ConsensusCoverage.ReadersPolarFrontier
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.CaseWitnesses

namespace ConsensusCoverage.ReadersWitnessesCases

open ReadersWitnessProof

set_option maxHeartbeats 0
set_option pp.maxSteps 1500
set_option maxRecDepth 8192
set_option Elab.async false

private def observations : Claim ReadersCorpus.caseStepAt :=
  ⟨20, 4, [
    .observeTerm_log_message_appendEntriesResponse, .observeTerm_commitIndex_message_appendEntriesResponse,
    .observeTerm_commitIndex_message_proposeRequestVoteRequest, .observeTerm_commitIndex_message_other,
    .observeTerm_log_message_proposeRequestVoteRequest, .observeTerm_log_message_other
  ], by decide +kernel⟩

private def electionLater : Claim ReadersCorpus.caseStepAt :=
  ⟨21, 5, [.elect_backed_termCase_inr], by decide +kernel⟩

private def electionEarlier : Claim ReadersCorpus.caseStepAt :=
  ⟨23, 5, [.elect_backed_termCase_inl], by decide +kernel⟩

private def preBacked : Claim ReadersCorpus.caseStepAt :=
  ⟨29, 6, [.pre_split_pre_backed_inl], by decide +kernel⟩

private def conflict : Claim ReadersCorpus.caseStepAt :=
  ⟨31, 11, [.handleAppendEntriesRequest_conflict_some], by decide +kernel⟩

public def claims : List (Claim ReadersCorpus.caseStepAt) :=
  [observations, electionLater, electionEarlier, preBacked, conflict]

public def backing : Claim ReadersCorpus.caseStepAt :=
  ⟨29, 6, [.pre_split_pre_backed_inr, .pre_split_backing_inl], by decide +kernel⟩

end ConsensusCoverage.ReadersWitnessesCases
