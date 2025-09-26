// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/node/startup_config.h"
#include "common/configuration.h"

#include <string>
#include <vector>

namespace ccf::indexer
{
  struct Config
  {
    std::string ledger_dir;
    std::vector<std::string> bootstrap_nodes;
    CCFConfig::Attestation attestation;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Config);
  DECLARE_JSON_REQUIRED_FIELDS(
    Config, ledger_dir, bootstrap_nodes, attestation);
}