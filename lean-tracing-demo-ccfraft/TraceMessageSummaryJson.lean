-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceMessageSummary
import TraceStateJson

set_option autoImplicit false

namespace CCFRaft.TraceMessageSummary

open Lean TraceJson

def decode (json : Json) : Except String (Summary Node) := do
  let kind <- field json "kind" >>= Json.getStr?
  if kind == "appendEntriesRequest" then
    checkKeys json ["kind", "term", "source", "destination",
      "prevLogIndex", "entriesLength", "leaderCommit"]
    pure (.appendEntriesRequest
      { term := ← field json "term" >>= Json.getNat?
        source := ← field json "source" >>= nodeValue
        destination := ← field json "destination" >>= nodeValue
        prevLogIndex := ← field json "prevLogIndex" >>= Json.getNat?
        entriesLength := ← field json "entriesLength" >>= Json.getNat?
        leaderCommit := ← field json "leaderCommit" >>= Json.getNat? })
  else
    pure (ofMessage (← TraceStateJson.message #[] json))

end CCFRaft.TraceMessageSummary
