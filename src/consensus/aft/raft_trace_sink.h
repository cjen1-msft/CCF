// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace aft
{
  // Process-wide destination for raft_trace msgpack events, exported to a
  // Fluentd tcp (in_forward) listener.
  //
  // Configured exactly once at startup - by cchost's run.cpp for real nodes,
  // by raft_driver's main() for the scenario-driven test harness - before any
  // raft_trace event can fire. This mirrors ccf::logger::config, which is a
  // similar global, configured the same way, once, before use.
  //
  // Step 0 (this change): send() only counts (and occasionally logs) drops.
  // No socket is ever opened. This exists so that call sites, and the
  // msgpack-encoding work that produces the bytes passed to send(), can be
  // exercised end-to-end (e.g. via raft_driver) ahead of step 1.
  // Step 1 (follow-up): send() opens a thread_local, non-blocking TCP
  // connection to the configured endpoint and writes to it, only counting a
  // drop when the write does not fully complete.
  class RaftTraceSink
  {
  public:
    struct Endpoint
    {
      std::string host;
      std::string port;
    };

    static void configure(std::optional<Endpoint> endpoint)
    {
      target() = std::move(endpoint);
    }

    static bool is_configured()
    {
      return target().has_value();
    }

    // Takes a fully-encoded Fluentd Forward Protocol entry
    // ([tag, time, record], see raft_trace_msgpack.h) and either sends it or
    // drops it.
    static void send(std::span<const uint8_t> entry)
    {
      (void)entry;

      // Step 0 stub: every event is a drop, regardless of configuration.
      record_drop();
    }

    static uint64_t drop_count()
    {
      return drops().load(std::memory_order_relaxed);
    }

  private:
    static std::optional<Endpoint>& target()
    {
      static std::optional<Endpoint> the_target;
      return the_target;
    }

    static std::atomic<uint64_t>& drops()
    {
      static std::atomic<uint64_t> the_drops{0};
      return the_drops;
    }

    static void record_drop()
    {
      const auto count = drops().fetch_add(1, std::memory_order_relaxed) + 1;
      // Log on each power-of-two crossing: cheap to check (count is a power
      // of two iff count & (count - 1) == 0), and self-limiting under
      // sustained drops.
      if ((count & (count - 1)) == 0)
      {
        LOG_FAIL_FMT("RaftTraceSink has dropped {} raft_trace events", count);
      }
    }
  };
} // namespace aft
