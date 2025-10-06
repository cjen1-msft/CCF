// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/report_data.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/openssl/key_pair.h"
#include "indexer/config.h"
#include "node/quote_endorsements_client.h"
#include "pal/quote_generation.h"

#include <stdexcept>

#define INDEXER_START generate_quote
#define INDEXER_AFTER_QUOTE_GEN read_current_public_ledger
#define INDEXER_AFTER_READ_CURRENT_PUBLIC_LEDGER fetch_endorsements
#define INDEXER_AFTER_FETCH_ENDORSEMENTS send_join_requests
#define INDEXER_AFTER_SEND_JOIN_REQUESTS poll_ledger_for_secrets
#define INDEXER_AFTER_POLL_LEDGER_FOR_SECRETS open_frontend

namespace ccf::indexer
{
  class State
  {
  private:
    void generate_quote();
    void read_current_public_ledger();
    void fetch_endorsements();
    void send_join_requests();
    void poll_ledger_for_secrets();
    void open_frontend();

    Config config;

    ccf::crypto::CurveID curve_id;

    std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> node_sign_kp;
    NodeId self;
    std::shared_ptr<ccf::crypto::RSAKeyPair> node_encrypt_kp;
    ccf::crypto::Pem self_signed_node_cert;
    std::optional<ccf::crypto::Pem> endorsed_node_cert = std::nullopt;

    std::optional<QuoteInfo> quote_info_opt = std::nullopt;
    std::optional<pal::snp::EndorsementEndpointsConfiguration>
      snp_endorsement_endpoints_config_opt = std::nullopt;

    void load_aci_endorsements_from_disk(std::function<void()> cb);

  public:
    State(Config&& config, crypto::CurveID curve_id_) :
      config(config),
      curve_id(curve_id_),
      node_sign_kp(std::make_shared<ccf::crypto::KeyPair_OpenSSL>(curve_id_)),
      self(compute_node_id_from_kp(node_sign_kp)),
      node_encrypt_kp(ccf::crypto::make_rsa_key_pair())
    {}
    void start()
    {
      INDEXER_START();
    }
  };

}