-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import EncodeTrace
import ControlActionAudit
import Shared.SmtTests
import Shared.SmtOrderTests
import Shared.GuardedTests
import MachineGenerated.TraceStateJsonTests
import MachineGenerated.TraceCertificateTests
import MachineGenerated.BoundedStateProofs
import MachineGenerated.BoundedStateExamples
import MachineGenerated.TransactionMappingProofs
import MachineGenerated.LeaderWriteMappingProofs
import MachineGenerated.MessageEqualityTests
import MachineGenerated.AppendEntriesMappingProofs
import MachineGenerated.GuardedAppendEntriesTests
import MachineGenerated.ControlTraceTests
import MachineGenerated.ReceiveTraceTests

run_cmd do
  for theoremName in [
      ``CCFRaft.BoundedState.decode_encode,
      ``CCFRaft.BoundedState.decode_withinBounds_iff,
      ``CCFRaft.TransactionMapping.mapState_clientRequest,
      ``CCFRaft.TransactionMapping.enabled_mapState_clientRequest_iff,
      ``CCFRaft.TransactionMapping.mapState_signCommittableMessages,
      ``CCFRaft.TransactionMapping.enabled_mapState_signCommittableMessages_iff,
      ``CCFRaft.TransactionMapping.mapState_changeConfiguration,
      ``CCFRaft.TransactionMapping.enabled_mapState_changeConfiguration_iff,
      ``CCFRaft.TransactionMapping.mapState_appendRetiredCommitted,
      ``CCFRaft.TransactionMapping.enabled_mapState_appendRetiredCommitted_iff,
      ``CCFRaft.MessageEquality.messageEqual_correct,
      ``CCFRaft.TransactionMapping.enabled_mapState_appendEntries_iff,
      ``CCFRaft.TransactionMapping.mapState_appendEntries,
      ``TraceSmt.Guarded.test_holds,
      ``TraceSmt.Guarded.eval_enqueueNoDup_map,
      ``CCFRaft.GuardedAppendEntries.step_correct,
      ``CCFRaft.GuardedReceive.step_correct,
      ``CCFRaft.GuardedReceive.step_enabledExpr_correct,
      ``CCFRaft.TraceEncoding.receiveGroup_correct,
      ``CCFRaft.TraceEncoding.receiveFrames_correct,
      ``CCFRaft.TraceEncoding.receiveFrames_state,
      ``CCFRaft.TraceEncoding.responseMatchValue_actual,
      ``CCFRaft.TraceEncoding.responseSentValue_actual,
      ``CCFRaft.ReceiveTraceValues.conditionalClamp_correct,
      ``CCFRaft.TraceEncoding.trackedReceiveStep_eval,
      ``CCFRaft.TraceEncoding.appendLogLengthValue_actual,
      ``CCFRaft.TraceEncoding.appendLogTerm_copied,
      ``CCFRaft.TraceEncoding.indexedLogTerm_correct,
      ``CCFRaft.TraceEncoding.appendStepdownValue_role_actual,
      ``CCFRaft.TraceEncoding.rememberUnappliedAppend_correct,
      ``CCFRaft.TraceEncoding.receiveConsumptionAmount_correct,
      ``CCFRaft.ReceiveTraceQueue.reconcile_correct,
      ``CCFRaft.TraceEncoding.receiveCommitShape,
      ``CCFRaft.TraceEncoding.receiveConfigurationSnapshots_correct,
      ``CCFRaft.TraceEncoding.receiveQueueValue_correct,
      ``CCFRaft.TraceEncoding.appendReplyValues_actual,
      ``CCFRaft.ReceiveTraceBranching.step_eval,
      ``CCFRaft.TraceEncoding.nextControlTracking_correct,
      ``CCFRaft.TraceEncoding.roleGuard_correct,
      ``CCFRaft.TraceEncoding.actionGuard_correct,
      ``CCFRaft.TraceEncoding.structuralClientExpr_correct,
      ``CCFRaft.TraceEncoding.latestConfigurationValue_correct,
      ``CCFRaft.TraceEncoding.currentConfigurationIndexValue_correct,
      ``CCFRaft.TraceEncoding.highestCommittableValue_correct,
      ``CCFRaft.TraceEncoding.refreshCompletedTracking_correct,
      ``CCFRaft.TraceEncoding.controlQueueLengths_correct,
      ``CCFRaft.TraceEncoding.appendQueueLength_correct,
      ``CCFRaft.TraceEncoding.configurationRankLeExpr_correct,
      ``CCFRaft.ControlTraceConfigurations.truncate_correct,
      ``CCFRaft.ControlTraceConfigurations.truncatePure_correct,
      ``CCFRaft.ControlTraceRetirement.retiredExpr_correct,
      ``CCFRaft.ControlTraceRetirement.completedValue_correct,
      ``CCFRaft.ControlTracePackets.equalExpr_correct,
      ``CCFRaft.ControlTracePackets.appendEqualExpr_correct,
      ``CCFRaft.TraceEncoding.rememberPacketTerm_correct,
      ``CCFRaft.TraceEncoding.controlLogLengths_correct,
      ``CCFRaft.TraceEncoding.controlSentIndices_correct,
      ``CCFRaft.TraceEncoding.controlCommitIndices_correct,
      ``CCFRaft.TraceEncoding.controlFrame_correct,
      ``CCFRaft.TraceEncoding.encode_holds_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
