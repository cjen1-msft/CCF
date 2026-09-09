// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "consensus/aft/impl/state.h"
#include "consensus/aft/raft_trace_sink.h"
#include "consensus/aft/raft_types.h"
#include "msgpack/encode.h"
#include "msgpack/fluentd_event_time.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

namespace aft::trace
{
  constexpr std::string_view raft_trace_tag = "ccf.raft_trace";

  inline uint32_t container_size(size_t size)
  {
    if (size > std::numeric_limits<uint32_t>::max())
    {
      throw std::length_error(
        "Raft trace container exceeds MessagePack size limit");
    }
    return static_cast<uint32_t>(size);
  }

  inline void write_key(std::vector<uint8_t>& out, std::string_view key)
  {
    ccf::msgpack::write_str(out, key);
  }

  inline void write_msgpack(std::vector<uint8_t>& out, const ccf::NodeId& id)
  {
    ccf::msgpack::write_str(out, id.value());
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, ccf::kv::LeadershipState state)
  {
    static constexpr std::array<std::string_view, 5> names = {
      "None", "Leader", "Follower", "PreVoteCandidate", "Candidate"};
    ccf::msgpack::write_str(out, names.at(static_cast<uint8_t>(state)));
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, ccf::kv::MembershipState state)
  {
    static constexpr std::array<std::string_view, 2> names = {
      "Active", "Retired"};
    ccf::msgpack::write_str(out, names.at(static_cast<uint8_t>(state)));
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, ccf::kv::RetirementPhase phase)
  {
    static constexpr std::array<std::string_view, 4> names = {
      "Ordered", "Signed", "Completed", "RetiredCommitted"};
    ccf::msgpack::write_str(out, names.at(static_cast<uint8_t>(phase) - 1));
  }

  inline void write_msgpack(std::vector<uint8_t>& out, RaftMsgType message)
  {
    static constexpr std::array<std::string_view, 8> names = {
      "raft_append_entries",
      "raft_append_entries_response",
      "raft_append_entries_signed_response",
      "raft_request_vote",
      "raft_request_vote_response",
      "raft_propose_request_vote",
      "raft_request_pre_vote",
      "raft_request_pre_vote_response"};
    ccf::msgpack::write_str(out, names.at(static_cast<size_t>(message)));
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, AppendEntriesResponseType response)
  {
    static constexpr std::array<std::string_view, 2> names = {"OK", "FAIL"};
    ccf::msgpack::write_str(out, names.at(static_cast<uint8_t>(response)));
  }

  template <typename T, typename WriteValue>
  inline void write_optional(
    std::vector<uint8_t>& out,
    std::string_view key,
    const std::optional<T>& value,
    WriteValue&& write_value)
  {
    if (value.has_value())
    {
      write_key(out, key);
      write_value(out, *value);
    }
  }

  template <bool IncludeCommittableIndices = true>
  inline void write_msgpack(std::vector<uint8_t>& out, const State& state)
  {
    const auto optional_field_count =
      static_cast<uint32_t>(state.retirement_phase.has_value()) +
      static_cast<uint32_t>(state.retirement_idx.has_value()) +
      static_cast<uint32_t>(state.retirement_committable_idx.has_value()) +
      static_cast<uint32_t>(state.retired_committed_idx.has_value());
    ccf::msgpack::write_map_header(
      out, 7 + IncludeCommittableIndices + optional_field_count);

    write_key(out, "node_id");
    write_msgpack(out, state.node_id);
    write_key(out, "current_view");
    ccf::msgpack::write_uint(out, state.current_view);
    write_key(out, "last_idx");
    ccf::msgpack::write_uint(out, state.last_idx);
    write_key(out, "commit_idx");
    ccf::msgpack::write_uint(out, state.commit_idx);
    write_key(out, "leadership_state");
    write_msgpack(out, state.leadership_state);
    write_key(out, "membership_state");
    write_msgpack(out, state.membership_state);
    write_key(out, "pre_vote_enabled");
    ccf::msgpack::write_bool(out, state.pre_vote_enabled);

    write_optional(
      out,
      "retirement_phase",
      state.retirement_phase,
      [](auto& buffer, auto value) { write_msgpack(buffer, value); });
    write_optional(
      out,
      "retirement_idx",
      state.retirement_idx,
      [](auto& buffer, auto value) {
        ccf::msgpack::write_uint(buffer, value);
      });
    write_optional(
      out,
      "retirement_committable_idx",
      state.retirement_committable_idx,
      [](auto& buffer, auto value) {
        ccf::msgpack::write_uint(buffer, value);
      });
    write_optional(
      out,
      "retired_committed_idx",
      state.retired_committed_idx,
      [](auto& buffer, auto value) {
        ccf::msgpack::write_uint(buffer, value);
      });

    if constexpr (IncludeCommittableIndices)
    {
      write_key(out, "committable_indices");
      const auto& indices = state.committable_indices;
      const auto count =
        static_cast<uint32_t>(std::min<size_t>(indices.size(), 2));
      ccf::msgpack::write_array_header(out, count);
      if (count > 0)
      {
        ccf::msgpack::write_uint(out, indices.front());
      }
      if (count > 1)
      {
        ccf::msgpack::write_uint(out, indices.back());
      }
    }
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const ccf::kv::Configuration::NodeInfo& node)
  {
    ccf::msgpack::write_map_header(out, 1);
    write_key(out, "address");
    ccf::msgpack::write_str(
      out, ccf::make_net_address(node.hostname, node.port));
  }

  inline void write_configuration(
    std::vector<uint8_t>& out,
    Index idx,
    const ccf::kv::Configuration::Nodes& nodes,
    ccf::kv::ReconfigurationId rid)
  {
    ccf::msgpack::write_map_header(out, 3);
    write_key(out, "idx");
    ccf::msgpack::write_uint(out, idx);
    write_key(out, "nodes");
    ccf::msgpack::write_map_header(out, container_size(nodes.size()));
    for (const auto& [node_id, node_info] : nodes)
    {
      write_msgpack(out, node_id);
      write_msgpack(out, node_info);
    }
    write_key(out, "rid");
    ccf::msgpack::write_uint(out, rid);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const ccf::kv::Configuration& configuration)
  {
    write_configuration(
      out, configuration.idx, configuration.nodes, configuration.rid);
  }

  template <typename Configurations>
  inline void write_configurations(
    std::vector<uint8_t>& out, const Configurations& configurations)
  {
    ccf::msgpack::write_array_header(
      out, container_size(configurations.size()));
    for (const auto& configuration : configurations)
    {
      write_msgpack(out, configuration);
    }
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const AppendEntries& packet)
  {
    ccf::msgpack::write_map_header(out, 8);
    write_key(out, "msg");
    write_msgpack(out, packet.msg);
    write_key(out, "idx");
    ccf::msgpack::write_uint(out, packet.idx);
    write_key(out, "prev_idx");
    ccf::msgpack::write_uint(out, packet.prev_idx);
    write_key(out, "term");
    ccf::msgpack::write_uint(out, packet.term);
    write_key(out, "prev_term");
    ccf::msgpack::write_uint(out, packet.prev_term);
    write_key(out, "leader_commit_idx");
    ccf::msgpack::write_uint(out, packet.leader_commit_idx);
    write_key(out, "term_of_idx");
    ccf::msgpack::write_uint(out, packet.term_of_idx);
    write_key(out, "contains_new_view");
    ccf::msgpack::write_bool(out, packet.contains_new_view);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const AppendEntriesResponse& packet)
  {
    ccf::msgpack::write_map_header(out, 4);
    write_key(out, "msg");
    write_msgpack(out, packet.msg);
    write_key(out, "term");
    ccf::msgpack::write_uint(out, packet.term);
    write_key(out, "last_log_idx");
    ccf::msgpack::write_uint(out, packet.last_log_idx);
    write_key(out, "success");
    write_msgpack(out, packet.success);
  }

  template <typename VoteRequest>
  inline void write_vote_request(
    std::vector<uint8_t>& out, const VoteRequest& packet)
  {
    ccf::msgpack::write_map_header(out, 4);
    write_key(out, "msg");
    write_msgpack(out, packet.msg);
    write_key(out, "term");
    ccf::msgpack::write_uint(out, packet.term);
    write_key(out, "last_committable_idx");
    ccf::msgpack::write_uint(out, packet.last_committable_idx);
    write_key(out, "term_of_last_committable_idx");
    ccf::msgpack::write_uint(out, packet.term_of_last_committable_idx);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestVote& packet)
  {
    write_vote_request(out, packet);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestPreVote& packet)
  {
    write_vote_request(out, packet);
  }

  template <typename VoteResponse>
  inline void write_vote_response(
    std::vector<uint8_t>& out, const VoteResponse& packet)
  {
    ccf::msgpack::write_map_header(out, 3);
    write_key(out, "msg");
    write_msgpack(out, packet.msg);
    write_key(out, "term");
    ccf::msgpack::write_uint(out, packet.term);
    write_key(out, "vote_granted");
    ccf::msgpack::write_bool(out, packet.vote_granted);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestVoteResponse& packet)
  {
    write_vote_response(out, packet);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestPreVoteResponse& packet)
  {
    write_vote_response(out, packet);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const ProposeRequestVote& packet)
  {
    ccf::msgpack::write_map_header(out, 2);
    write_key(out, "msg");
    write_msgpack(out, packet.msg);
    write_key(out, "term");
    ccf::msgpack::write_uint(out, packet.term);
  }

  inline std::vector<uint8_t>& event_buffer()
  {
    thread_local auto buffer = [] {
      std::vector<uint8_t> buffer;
      buffer.reserve(2048);
      return buffer;
    }();
    return buffer;
  }

  inline uint64_t next_sequence()
  {
    static std::atomic<uint64_t> sequence = 0;
    return sequence.fetch_add(1, std::memory_order_relaxed);
  }

  template <typename WriteRecord>
  inline void emit(uint32_t field_count, WriteRecord&& write_record)
  {
    if (!RaftTraceSink::is_configured())
    {
      return;
    }
    const auto sequence = next_sequence();
    auto& buffer = event_buffer();
    buffer.clear();
    ccf::msgpack::write_array_header(buffer, 3);
    ccf::msgpack::write_str(buffer, raft_trace_tag);
    ccf::msgpack::write_fluentd_event_time(
      buffer,
      ccf::msgpack::FluentdEventTime::make(std::chrono::system_clock::now()));
    ccf::msgpack::write_map_header(buffer, 2);
    write_key(buffer, "h_ts");
    ccf::msgpack::write_uint(buffer, sequence);
    write_key(buffer, "msg");
    ccf::msgpack::write_map_header(buffer, field_count);
    write_record(buffer);
    RaftTraceSink::send(buffer);
  }

  inline void write_function_and_state(
    std::vector<uint8_t>& out, std::string_view function, const State& state)
  {
    write_key(out, "function");
    ccf::msgpack::write_str(out, function);
    write_key(out, "state");
    write_msgpack(out, state);
  }

  inline void emit_state_node(
    std::string_view function,
    const State& state,
    std::string_view node_key,
    const ccf::NodeId& node_id)
  {
    emit(3, [&](auto& out) {
      write_function_and_state(out, function, state);
      write_key(out, node_key);
      write_msgpack(out, node_id);
    });
  }

  template <typename Configurations>
  inline void emit_state_configurations(
    std::string_view function,
    const State& state,
    const Configurations& configurations)
  {
    emit(3, [&](auto& out) {
      write_function_and_state(out, function, state);
      write_key(out, "configurations");
      write_configurations(out, configurations);
    });
  }

  template <typename Packet>
  inline void emit_state_packet_node(
    std::string_view function,
    const State& state,
    const Packet& packet,
    std::string_view node_key,
    const ccf::NodeId& node_id)
  {
    emit(4, [&](auto& out) {
      write_function_and_state(out, function, state);
      write_key(out, "packet");
      write_msgpack(out, packet);
      write_key(out, node_key);
      write_msgpack(out, node_id);
    });
  }

  template <typename Packet>
  inline void emit_state_packet_node_indices(
    std::string_view function,
    const State& state,
    const Packet& packet,
    std::string_view node_key,
    const ccf::NodeId& node_id,
    Index match_idx,
    Index sent_idx)
  {
    emit(6, [&](auto& out) {
      write_function_and_state(out, function, state);
      write_key(out, "packet");
      write_msgpack(out, packet);
      write_key(out, node_key);
      write_msgpack(out, node_id);
      write_key(out, "match_idx");
      ccf::msgpack::write_uint(out, match_idx);
      write_key(out, "sent_idx");
      ccf::msgpack::write_uint(out, sent_idx);
    });
  }

  template <typename Configurations>
  inline void emit_add_configuration(
    const State& state,
    const Configurations& configurations,
    Index idx,
    const ccf::kv::Configuration::Nodes& nodes)
  {
    emit(4, [&](auto& out) {
      write_function_and_state(out, "add_configuration", state);
      write_key(out, "configurations");
      write_configurations(out, configurations);
      write_key(out, "args");
      ccf::msgpack::write_map_header(out, 1);
      write_key(out, "configuration");
      write_configuration(out, idx, nodes, idx);
    });
  }

  inline void emit_replicate(
    const State& state, Term view, Index seqno, bool globally_committable)
  {
    emit(5, [&](auto& out) {
      write_function_and_state(out, "replicate", state);
      write_key(out, "view");
      ccf::msgpack::write_uint(out, view);
      write_key(out, "seqno");
      ccf::msgpack::write_uint(out, seqno);
      write_key(out, "globally_committable");
      ccf::msgpack::write_bool(out, globally_committable);
    });
  }

  template <typename Configurations>
  inline void emit_commit(
    const State& state, const Configurations& configurations, Index idx)
  {
    emit(4, [&](auto& out) {
      write_function_and_state(out, "commit", state);
      write_key(out, "args");
      ccf::msgpack::write_map_header(out, 1);
      write_key(out, "idx");
      ccf::msgpack::write_uint(out, idx);
      write_key(out, "configurations");
      write_configurations(out, configurations);
    });
  }

  template <typename Packet>
  inline void emit_drop_pending_to(
    const State& state,
    const Packet& packet,
    const ccf::NodeId& from,
    const ccf::NodeId& to)
  {
    emit(5, [&](auto& out) {
      write_key(out, "function");
      ccf::msgpack::write_str(out, "drop_pending_to");
      write_key(out, "state");
      write_msgpack<false>(out, state);
      write_key(out, "from_node_id");
      write_msgpack(out, from);
      write_key(out, "to_node_id");
      write_msgpack(out, to);
      write_key(out, "packet");
      write_msgpack(out, packet);
    });
  }
} // namespace aft::trace
