#include "indexer_state.h"

namespace ccf::indexer {
    void State::generate_quote()
    {
      pal::PlatformAttestationReportData report_data =
        ccf::crypto::Sha256Hash((node_sign_kp->public_key_der()));

      pal::generate_quote(
        report_data,
        [this](
          const QuoteInfo& qi,
          const pal::snp::EndorsementEndpointsConfiguration endpoint_config) {
          quote_info_opt = qi;
          snp_endorsement_endpoints_config_opt = endpoint_config;
          INDEXER_AFTER_QUOTE_GEN();
        },
        config.attestation.snp_endorsements_servers);
    }

    void State::load_aci_endorsements_from_disk(std::function<void()> cb)
    {
      if (!quote_info_opt.has_value())
      {
        throw std::logic_error("No quote info available");
      }
      auto& quote_info = this->quote_info_opt.value();
      try
      {
        const auto raw_data = ccf::crypto::raw_from_b64(
          config.attestation.environment.snp_endorsements.value());

        const auto j = nlohmann::json::parse(raw_data);
        const auto aci_endorsements =
          j.get<ccf::pal::snp::ACIReportEndorsements>();

        // Check that tcbm in endorsement matches reported TCB in our
        // retrieved attestation
        const auto* quote = reinterpret_cast<const ccf::pal::snp::Attestation*>(
          quote_info.quote.data());
        const auto reported_tcb = quote->reported_tcb;

        // tcbm is a single hex value, like DB18000000000004. To match
        // that with a TcbVersion, reverse the bytes.
        const auto* tcb_begin = reinterpret_cast<const uint8_t*>(&reported_tcb);
        const std::span<const uint8_t> tcb_bytes{
          tcb_begin, tcb_begin + sizeof(reported_tcb)};
        auto tcb_as_hex = fmt::format(
          "{:02x}", fmt::join(tcb_bytes.rbegin(), tcb_bytes.rend(), ""));
        ccf::nonstd::to_upper(tcb_as_hex);

        if (tcb_as_hex == aci_endorsements.tcbm)
        {
          LOG_INFO_FMT(
            "Using SNP endorsements loaded from file, endorsing TCB {}",
            tcb_as_hex);

          auto& endorsements_pem = quote_info.endorsements;
          endorsements_pem.insert(
            endorsements_pem.end(),
            aci_endorsements.vcek_cert.begin(),
            aci_endorsements.vcek_cert.end());
          endorsements_pem.insert(
            endorsements_pem.end(),
            aci_endorsements.certificate_chain.begin(),
            aci_endorsements.certificate_chain.end());

          cb();
        }
        else
        {
          LOG_FAIL_FMT(
            "SNP endorsements loaded from disk ({}) contained tcbm {}, "
            "which does not match reported TCB of current attestation "
            "{}. "
            "Falling back to fetching fresh endorsements from server.",
            config.attestation.snp_endorsements_file.value(),
            aci_endorsements.tcbm,
            tcb_as_hex);
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Error attempting to use SNP endorsements from file: {}", e.what());
      }
    }

    void State::fetch_endorsements()
    {
      if (!quote_info_opt.has_value())
      {
        throw std::logic_error("No quote info available");
      }
      auto& quote_info = this->quote_info_opt.value();
      if (!snp_endorsement_endpoints_config_opt.has_value())
      {
        throw std::logic_error("No SNP endorsement endpoints config available");
      }
      auto& endpoint_config =
        this->snp_endorsement_endpoints_config_opt.value();

      auto b64encoded_quote = ccf::crypto::b64url_from_raw(quote_info.quote);
      nlohmann::json jq;
      to_json(jq, quote_info.format);
      LOG_INFO_FMT(
        "Initial node attestation ({}): {}", jq.dump(), b64encoded_quote);
      if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
      {
        if (!((quote_info.format == QuoteFormat::oe_sgx_v1 &&
               !quote_info.endorsements.empty()) ||
              (quote_info.format != QuoteFormat::oe_sgx_v1 &&
               quote_info.endorsements.empty())))
        {
          throw std::runtime_error(
            "SGX quote generation should have already fetched endorsements");
        }
      }
      else
      {
        // Use endorsements retrieved from file, if available
        if (config.attestation.environment.snp_endorsements.has_value())
        {
          INDEXER_AFTER_FETCH_ENDORSEMENTS();
          return;
        }

        if (config.attestation.snp_endorsements_servers.empty())
        {
          throw std::runtime_error(
            "One or more SNP endorsements servers must be specified to fetch "
            "the collateral for the attestation");
        }
        // shared-ptr to extend its lifetime across the async call
        auto quote_endorsements_client =
          std::make_shared<QuoteEndorsementsClient>(
            endpoint_config, [this](std::vector<uint8_t>&& endorsements) {
              if (!quote_info_opt.has_value())
              {
                throw std::logic_error("No quote info available");
              }
              auto& quote_info = this->quote_info_opt.value();
              quote_info.endorsements = std::move(endorsements);
              INDEXER_AFTER_FETCH_ENDORSEMENTS();
              return;
            });
        quote_endorsements_client->fetch_endorsements();
      }
    }

    void State::read_current_public_ledger()
    {
      // kick off reading then
      INDEXER_AFTER_READ_CURRENT_PUBLIC_LEDGER();
    }

    void State::send_join_requests()
    {
      // Do something here
      INDEXER_AFTER_SEND_JOIN_REQUESTS();
    }

    void State::poll_ledger_for_secrets()
    {
      // Poll ledger until we see the network secrets
      INDEXER_AFTER_POLL_LEDGER_FOR_SECRETS();
    }

    void State::open_frontend()
    {
      // open frontend for client requests
    }

}