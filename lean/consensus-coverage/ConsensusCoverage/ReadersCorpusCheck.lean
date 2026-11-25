module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.Readers
public meta import ConsensusCoverage.ReadersCorpusReplay

open ConsensusCoverage

public meta def main (args : List String) : IO Unit := ReadersCorpusReplay.run Readers.read? args
