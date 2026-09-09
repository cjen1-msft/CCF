-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceCertificate
import MachineGenerated.TraceStateJsonTests

set_option autoImplicit false

namespace CCFRaft.TraceCertificateTests

open Lean

def certificate (version : String) (entry bounds : Json) : Json :=
  Json.mkObj
    [("schema_version", toJson version),
     ("entry", entry),
     ("bounds", bounds),
     ("unknowns", toJson ["tx"]),
     ("steps", toJson ([] : List Json))]

def bounds : Json := Json.mkObj
  [("transaction_count", toJson (2 : Nat)),
   ("term_count", toJson (9 : Nat)),
   ("index_count", toJson (20 : Nat)),
   ("log_capacity", toJson (2 : Nat)),
   ("queue_capacity", toJson (7 : Nat))]

def legacyBounds : Json := Json.mkObj
  [("transaction_count", toJson (2 : Nat)), ("log_capacity", toJson (2 : Nat))]

def action (name : String) (extra : List (String × Json) := []) : Json :=
  Json.mkObj ([("kind", toJson "action"), ("action", toJson name),
    ("node", toJson (0 : Nat))] ++ extra)

def writes (version : String) (actions : List Json) (limits : Json := bounds) : Json :=
  Json.mkObj
    [("schema_version", toJson version), ("entry", toJson "bootstrap"),
     ("bounds", limits), ("unknowns", toJson ([] : List String)),
     ("steps", toJson actions)]

#guard match TraceCertificate.decode (writes "ccfraft-trace/v1"
    [action "signCommittableMessages",
     action "changeConfiguration" [("configuration", toJson [0, 7])],
     action "appendRetiredCommitted"]) with
  | .ok input =>
      input.acceptedActions == TraceInstructions.supportedActions &&
      input.trace.map TraceInstructions.Instruction.isAction == [true, true, true]
  | .error _ => false

#guard match TraceCertificate.decode
    (writes "ccfraft-client-request/v1" [action "signCommittableMessages"] legacyBounds) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode
    (writes "ccfraft-client-request/v2" [action "signCommittableMessages"]) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode
    (writes "ccfraft-trace/v1" [action "receive"]) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode
    (writes "ccfraft-trace/v1" [action "changeConfiguration"]) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode (writes "ccfraft-trace/v1"
    [action "signCommittableMessages" [("transaction", toJson (0 : Nat))]]) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode
    (certificate "ccfraft-client-request/v2" TraceStateJsonTests.stateJson bounds) with
  | .error _ => false
  | .ok input =>
      input.entryProfile == "template" &&
      input.bounds.termCount == 9 &&
      input.bounds.indexCount == 20 &&
      input.bounds.queueCapacity == 7 &&
      input.unknowns == #["tx"] &&
      input.trace.isEmpty

#guard match TraceCertificate.decode
    (certificate "ccfraft-client-request/v1" (toJson "bootstrap") legacyBounds) with
  | .error _ => false
  | .ok input =>
      input.entryProfile == "bootstrap" &&
      input.bounds.transactionCount == 2 &&
      input.bounds.logCapacity == 2 &&
      input.bounds.termCount == 2 &&
      input.bounds.indexCount == 1 &&
      input.bounds.queueCapacity == 0

#guard match TraceCertificate.decode
    (certificate "ccfraft-client-request/v2" (toJson "bootstrap") bounds) with
  | .ok input => input.entryProfile == "bootstrap"
  | .error _ => false

#guard match TraceCertificate.decode
    (certificate "ccfraft-client-request/v2" (toJson "bootstrap") legacyBounds) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode
    (certificate "ccfraft-client-request/v2" (toJson "mid-trace") bounds) with
  | .error _ => true
  | .ok _ => false

#guard match TraceCertificate.decode
    (certificate "ccfraft-client-request/v1" TraceStateJsonTests.stateJson legacyBounds) with
  | .error _ => true
  | .ok _ => false

end CCFRaft.TraceCertificateTests
