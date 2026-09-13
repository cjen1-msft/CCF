-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSignatureTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def prepareLeaderLog {width : PNat} (source : Fin width)
    (content : Expr (contentTy width)) : EncodeM width (NodeRowTerms width) := do
  let before <- get
  let old := nodeRowSnapshot before.toColumns source
  let entries <- define (leaderLogEntriesTerm old content)
  let length <- define (.add old.logLength (.integer 1))
  return leaderLogRowTerms old (.free .int length) (.free _ entries)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
