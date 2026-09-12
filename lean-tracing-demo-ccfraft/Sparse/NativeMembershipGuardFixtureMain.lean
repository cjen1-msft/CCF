-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipTerms
import Sparse.NativeMembershipFixtureInstructions

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeMembershipGuardFixtures

open Lean NativeSmt NativeEncode NativeMembershipFixtures

def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inr (source, configuration) =>
        let before <- get
        let columns := before.toColumns
        let old := nodeRowSnapshot columns source
        let current <- fresh
        assertion (currentConfigurationIndexTerm input.width old.logLength old.logEntries
          old.logLength (.free .int current))
        let previous := currentConfigurationMembersTerm input.width before.bootstrap
          old.logEntries (.free .int current)
        let entries <- define (membershipLogEntriesTerm columns source configuration)
        let first <- fresh
        let retirement <- fresh
        let signature <- fresh
        let retired <- fresh
        assertion (retirementRefreshConstraints input.width before.bootstrap
          (.add old.logLength (.integer 1)) (.free (.array .int (entryTy input.width)) entries)
          source (.free .int first) (.free .int retirement) (.free .int signature) (.free .int retired))
        let refreshed := retirementRefreshTerms old.commit
          (.free .int retirement) (.free .int signature) (.free .int retired)
        assertAll (membershipGuards columns source configuration previous refreshed.membershipState)
        return ()
      | .inl observation => frameInstruction observation
    throw "membership guard fixture has no changeConfiguration instruction"
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  let enabled <- (<- field item "modelEnabled").getBool?
  return Json.mkObj [("name", toJson s!"membership-guard-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if enabled then "sat" else "unsat"))]

end CCFRaft.NativeMembershipGuardFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeMembershipGuardFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
