module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.CaseWitnessesDeep
import all ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.FrontierWitnesses

namespace ConsensusCoverage.DeepSchedulesB

open Consensus.Model Consensus.Model.Node FrontierRows

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private structure Replay where
  run : Run
  choices : List (Nat × Nat)
  valid : run.valid

public def Replay.atStep (r : Replay) (offset : Nat) : Option ActionProfile.Step := do
  let shortened := {r.run with schedule := r.run.schedule.take (offset + 1)}
  return (← (← JointWitnesses.recordedAt shortened r.valid r.choices)[offset]?).val

private def fromScript (s : DeepSchedules.Script) (h : s.run.valid) : Replay :=
  ⟨s.run, s.choices, h⟩

local macro "script! " s:term:arg : term =>
  `(fromScript $s (by unfold Run.valid; decide))

private def onTwo (commands : List Command) : Run := ⟨{0, 1}, [0, 1], commands⟩

public def firstAck : Replay := ⟨CaseWitnesses.bounded8, [], CaseWitnesses.bounded8Valid⟩
public def duplicate : Replay := ⟨CaseWitnessesDeep.duplicateAck, [], CaseWitnessesDeep.validAck⟩
public def campaign : Replay := ⟨CaseWitnesses.bounded19, [(4, 1)], CaseWitnesses.bounded19Valid⟩
public def preVote : Replay := ⟨CaseWitnesses.bounded17, [], CaseWitnesses.bounded17Valid⟩
public def copyCommit : Replay := ⟨CaseWitnesses.bounded16, [], CaseWitnesses.bounded16Valid⟩
public def soloCampaign : Replay := ⟨CaseWitnesses.bounded21, [], CaseWitnesses.bounded21Valid⟩
public def doomed : Replay := script! DeepSchedules.doomed
public def divergent : Replay := script! DeepSchedules.divergent
public def retire : Replay := script! DeepSchedules.retireOnAppend

public def batch : Replay :=
  ⟨⟨{0, 1}, [0, 1, 2, 3], [.input 0 (.append [
      {content := .signature, flushes := [(1, 2)]},
      {content := .transaction 1 {configuration := some {0, 1, 2, 3}}, flushes := [(1, 3)]}])]⟩,
    [], by unfold Run.valid; decide⟩

public def solo : Replay :=
  ⟨⟨{0}, [0], [.input 0 (.append [{content := .signature}]), .input 0 .nominateSuccessor]⟩,
    [], by unfold Run.valid; decide⟩

public def repeatPre : Replay :=
  ⟨{preVote.run with schedule := preVote.run.schedule.take 3 ++ [.input 0 (.timeout .election)]},
    [], preVote.valid⟩

public def retryCandidate : Replay :=
  ⟨{campaign.run with schedule := campaign.run.schedule.take 4 ++ [.input 1 (.timeout .election)]},
    [], campaign.valid⟩

public def stepDown : Replay :=
  ⟨onTwo [.input 0 (.append [{content := .signature, flushes := [(1, 2)]}]), .deliver 0 1,
      .input 0 (.sendEntries 1 2), .input 1 (.timeout .election), .deliver 0 1],
    [], by unfold Run.valid; decide⟩

public def reject : Replay :=
  ⟨onTwo [.input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),
      .input 0 (.append [{content := .signature, flushes := [(1, 3)]}]), .deliver 0 1],
    [(2, 1)], by unfold Run.valid; decide⟩

public def twoSigCopy : Replay :=
  ⟨onTwo [.input 0 (.append [{content := .signature}, {content := .signature, flushes := [(1, 3)]}]),
      .deliver 0 1, .deliver 1 0, .input 0 (.sendEntries 1 3), .deliver 0 1],
    [], by unfold Run.valid; decide⟩

-- Voter 0 still has the extra term-2 signature that the candidate lacks.
public def denyVote : Replay := script! ({ DeepSchedules.divergent with
  ops := DeepSchedules.divergent.ops.take 7 ++ [.msg 1 0 .requestVoteRequest] })

-- Voter 0 already granted 4 a term-3 vote when the competing term-3 request arrives.
public def staleVote : Replay := script! ({ DeepSchedules.doomed with
  ops := DeepSchedules.doomed.ops.take 20 ++ [.msg 1 0 .requestVoteRequest] })

end ConsensusCoverage.DeepSchedulesB
