// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/aft/raft_trace_msgpack.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#define PICOBENCH_DONT_BIND_TO_ONE_CORE
#include <iostream>
#include <picobench/picobench.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{
  constexpr size_t reserved_capacity = 2048;

  template <bool FreshBuffer>
  void serialise(
    picobench::state& benchmark,
    std::string_view name,
    size_t committable_count,
    bool retired)
  {
    aft::State state(ccf::NodeId(std::string(64, 'a')));
    state.current_view = 2;
    state.last_idx = 200'000;
    state.commit_idx = 99'999;
    state.leadership_state = ccf::kv::LeadershipState::Leader;
    for (size_t i = 0; i < committable_count; ++i)
    {
      state.committable_indices.push_back(100'001 + i);
    }
    if (retired)
    {
      state.leadership_state = ccf::kv::LeadershipState::Follower;
      state.membership_state = ccf::kv::MembershipState::Retired;
      state.retirement_phase = ccf::kv::RetirementPhase::RetiredCommitted;
      state.retirement_idx = 99'990;
      state.retirement_committable_idx = 99'995;
      state.retired_committed_idx = 99'999;
    }

    std::vector<uint8_t> out;
    out.reserve(reserved_capacity);
    aft::trace::write_msgpack(out, state);
    const auto encoded_size = out.size();
    auto expected = nlohmann::json(state);
    expected["committable_indices"] = nlohmann::json::array();
    if (!state.committable_indices.empty())
    {
      expected["committable_indices"].push_back(
        state.committable_indices.front());
      if (state.committable_indices.size() > 1)
      {
        expected["committable_indices"].push_back(
          state.committable_indices.back());
      }
    }
    if (
      encoded_size > reserved_capacity ||
      nlohmann::json::from_msgpack(out) != expected)
    {
      throw std::logic_error("Raft State benchmark encoding differs from JSON");
    }

    {
      picobench::scope scope(benchmark);
      for (int i = 0; i < benchmark.iterations(); ++i)
      {
        asm volatile("" : : "g"(&state) : "memory");
        if constexpr (FreshBuffer)
        {
          std::vector<uint8_t> fresh;
          aft::trace::write_msgpack(fresh, state);
          asm volatile("" : : "g"(fresh.data()), "g"(fresh.size()) : "memory");
        }
        else
        {
          out.clear();
          aft::trace::write_msgpack(out, state);
          asm volatile("" : : "g"(out.data()), "g"(out.size()) : "memory");
        }
      }
    }
    // Picobench's CSV reports the fastest sample. Keep all batch timings too.
    std::cout << "raft_state_sample," << name << "," << benchmark.iterations()
              << "," << benchmark.duration_ns() << "," << encoded_size << "\n";
  }

  void active_empty(picobench::state& state)
  {
    serialise<false>(state, "active_empty", 0, false);
  }

  void active_pending(picobench::state& state)
  {
    serialise<false>(state, "active_pending", 2, false);
  }

  void active_many_pending(picobench::state& state)
  {
    serialise<false>(state, "active_many_pending", 1024, false);
  }

  void retired(picobench::state& state)
  {
    serialise<false>(state, "retired", 2, true);
  }

  void fresh_buffer(picobench::state& state)
  {
    serialise<true>(state, "fresh_buffer", 2, false);
  }
}

const std::vector<int> iterations = {100'000, 1'000'000};

PICOBENCH_SUITE("Raft State MessagePack");
PICOBENCH(active_empty).iterations(iterations).baseline();
PICOBENCH(active_pending).iterations(iterations);
PICOBENCH(active_many_pending).iterations(iterations);
PICOBENCH(retired).iterations(iterations);
PICOBENCH(fresh_buffer).iterations(iterations);
