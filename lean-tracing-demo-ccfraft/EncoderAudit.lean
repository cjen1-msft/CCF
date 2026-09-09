-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import EncodeTrace
import Shared.SmtTests
import Shared.SmtOrderTests
import MachineGenerated.TraceStateJsonTests
import MachineGenerated.TraceCertificateTests
import MachineGenerated.BoundedStateProofs
import MachineGenerated.BoundedStateExamples
import MachineGenerated.TransactionMappingProofs
import MachineGenerated.LeaderWriteMappingProofs
import MachineGenerated.MessageEqualityTests

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
      ``CCFRaft.MessageEquality.messageEqual_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
