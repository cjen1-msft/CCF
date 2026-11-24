module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import ConsensusCoverage.Classes
meta import ConsensusCoverage.EventSupport

open ConsensusCoverage

-- Compare by question name, independent of generated constructor order.
#eval do
  for b in FullProfile.stepBranches do
    IO.println s!"{reprStr b}\t{String.intercalate "," ((EventSupport.allowed b).map reprStr)}"
