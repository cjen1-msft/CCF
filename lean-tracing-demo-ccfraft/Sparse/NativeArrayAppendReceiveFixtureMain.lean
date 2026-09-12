-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendReceiveFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayAppendReceiveFixtures.cases).compress
