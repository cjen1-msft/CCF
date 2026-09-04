// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Hand-rolled msgpack encoding for raft_trace events, matching the fields
// that the existing nlohmann::json-based RAFT_TRACE_JSON_OUT path already
// serialises. Deliberately not routed through nlohmann::json::to_msgpack -
// these writers go straight from the raft objects to msgpack bytes.
//
// Encoders are written to be branch-free where possible: map/array headers
// use a fixed, compile-time-known count (no two-pass count-then-patch), and
// enum-to-string lookups use array indexing rather than switch/if chains.
// The one unavoidable branch per field is optional-vs-absent (encoded as
// msgpack nil when absent), and the small few-way branch for
// committable_indices size (0, 1 or 2 entries).

#include "ccf/entity_id.h"
#include "consensus/aft/impl/state.h"
#include "consensus/aft/raft_types.h"
#include "msgpack/encode.h"
#include "msgpack/fluentd_event_time.h"

#include <array>
#include <chrono>
#include <optional>
#include <string_view>
#include <vector>

namespace aft::trace
{
  inline void write_msgpack(std::vector<uint8_t>& buf, const ccf::NodeId& id)
  {
    ccf::msgpack::write_str(buf, id.value());
  }

  inline void write_msgpack(
    std::vector<uint8_t>& buf, ccf::kv::LeadershipState s)
  {
    static constexpr std::array<std::string_view, 5> names = {
      "None", "Leader", "Follower", "PreVoteCandidate", "Candidate"};
    ccf::msgpack::write_str(buf, names.at(static_cast<uint8_t>(s)));
  }

  inline void write_msgpack(
    std::vector<uint8_t>& buf, ccf::kv::MembershipState s)
  {
    static constexpr std::array<std::string_view, 2> names = {
      "Active", "Retired"};
    ccf::msgpack::write_str(buf, names.at(static_cast<uint8_t>(s)));
  }

  inline void write_msgpack(
    std::vector<uint8_t>& buf, ccf::kv::RetirementPhase s)
  {
    // Values start at 1 (Ordered), not 0.
    static constexpr std::array<std::string_view, 4> names = {
      "Ordered", "Signed", "Completed", "RetiredCommitted"};
    ccf::msgpack::write_str(buf, names.at(static_cast<uint8_t>(s) - 1));
  }

  inline void write_msgpack(std::vector<uint8_t>& buf, aft::RaftMsgType m)
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
    ccf::msgpack::write_str(buf, names.at(static_cast<size_t>(m)));
  }

  // Writes `value` if present, else msgpack nil. `write_value` writes just
  // the value (no key), matching the shape of the other write_msgpack
  // overloads in this file.
  template <typename T, typename F>
  inline void write_msgpack_optional(
    std::vector<uint8_t>& buf, const std::optional<T>& value, F&& write_value)
  {
    if (value.has_value())
    {
      write_value(buf, *value);
    }
    else
    {
      ccf::msgpack::write_nil(buf);
    }
  }

  inline void write_msgpack(std::vector<uint8_t>& buf, const aft::State& state)
  {
    ccf::msgpack::write_map_header(buf, 12);

    ccf::msgpack::write_str(buf, "node_id");
    write_msgpack(buf, state.node_id);

    ccf::msgpack::write_str(buf, "current_view");
    ccf::msgpack::write_uint(buf, state.current_view);

    ccf::msgpack::write_str(buf, "last_idx");
    ccf::msgpack::write_uint(buf, state.last_idx);

    ccf::msgpack::write_str(buf, "commit_idx");
    ccf::msgpack::write_uint(buf, state.commit_idx);

    ccf::msgpack::write_str(buf, "leadership_state");
    write_msgpack(buf, state.leadership_state);

    ccf::msgpack::write_str(buf, "membership_state");
    write_msgpack(buf, state.membership_state);

    ccf::msgpack::write_str(buf, "pre_vote_enabled");
    ccf::msgpack::write_bool(buf, state.pre_vote_enabled);

    ccf::msgpack::write_str(buf, "retirement_phase");
    write_msgpack_optional(
      buf,
      state.retirement_phase,
      [](std::vector<uint8_t>& b, ccf::kv::RetirementPhase v) {
        write_msgpack(b, v);
      });

    ccf::msgpack::write_str(buf, "retirement_idx");
    write_msgpack_optional(
      buf, state.retirement_idx, [](std::vector<uint8_t>& b, ccf::SeqNo v) {
        ccf::msgpack::write_uint(b, v);
      });

    ccf::msgpack::write_str(buf, "retirement_committable_idx");
    write_msgpack_optional(
      buf,
      state.retirement_committable_idx,
      [](std::vector<uint8_t>& b, ccf::SeqNo v) {
        ccf::msgpack::write_uint(b, v);
      });

    ccf::msgpack::write_str(buf, "retired_committed_idx");
    write_msgpack_optional(
      buf,
      state.retired_committed_idx,
      [](std::vector<uint8_t>& b, ccf::SeqNo v) {
        ccf::msgpack::write_uint(b, v);
      });

    // Mirrors add_committable_indices_start_and_end in raft.h: front and (if
    // more than one entry) back of the deque, always as an array (empty if
    // the deque is empty) rather than nil, to match the JSON field's shape.
    ccf::msgpack::write_str(buf, "committable_indices");
    const auto& committable_indices = state.committable_indices;
    if (committable_indices.empty())
    {
      ccf::msgpack::write_array_header(buf, 0);
    }
    else if (committable_indices.size() == 1)
    {
      ccf::msgpack::write_array_header(buf, 1);
      ccf::msgpack::write_uint(buf, committable_indices.front());
    }
    else
    {
      ccf::msgpack::write_array_header(buf, 2);
      ccf::msgpack::write_uint(buf, committable_indices.front());
      ccf::msgpack::write_uint(buf, committable_indices.back());
    }
  }

  inline void write_msgpack(
    std::vector<uint8_t>& buf, const aft::AppendEntries& ae)
  {
    ccf::msgpack::write_map_header(buf, 8);

    ccf::msgpack::write_str(buf, "msg");
    write_msgpack(buf, ae.msg);

    ccf::msgpack::write_str(buf, "idx");
    ccf::msgpack::write_uint(buf, ae.idx);

    ccf::msgpack::write_str(buf, "prev_idx");
    ccf::msgpack::write_uint(buf, ae.prev_idx);

    ccf::msgpack::write_str(buf, "term");
    ccf::msgpack::write_uint(buf, ae.term);

    ccf::msgpack::write_str(buf, "prev_term");
    ccf::msgpack::write_uint(buf, ae.prev_term);

    ccf::msgpack::write_str(buf, "leader_commit_idx");
    ccf::msgpack::write_uint(buf, ae.leader_commit_idx);

    ccf::msgpack::write_str(buf, "term_of_idx");
    ccf::msgpack::write_uint(buf, ae.term_of_idx);

    ccf::msgpack::write_str(buf, "contains_new_view");
    ccf::msgpack::write_bool(buf, ae.contains_new_view);
  }

  // Fluentd Forward Protocol single entry: [tag, time, record]. write_record
  // appends just the record's msgpack bytes (typically a single
  // write_map_header + fields, as in the write_msgpack(..., State/
  // AppendEntries) overloads above).
  template <typename WriteRecord>
  inline std::vector<uint8_t> build_fluentd_entry(
    std::string_view tag, WriteRecord&& write_record)
  {
    std::vector<uint8_t> buf;
    ccf::msgpack::write_array_header(buf, 3);
    ccf::msgpack::write_str(buf, tag);
    ccf::msgpack::write_fluentd_event_time(
      buf,
      ccf::msgpack::FluentdEventTime::make(std::chrono::system_clock::now()));
    write_record(buf);
    return buf;
  }

  constexpr std::string_view raft_trace_tag = "ccf.raft_trace";

  inline std::vector<uint8_t> encode_send_append_entries(
    const aft::State& state,
    const aft::AppendEntries& packet,
    const ccf::NodeId& to_node_id,
    aft::Index match_idx,
    aft::Index sent_idx)
  {
    return build_fluentd_entry(
      raft_trace_tag, [&](std::vector<uint8_t>& buf) {
        ccf::msgpack::write_map_header(buf, 6);

        ccf::msgpack::write_str(buf, "function");
        ccf::msgpack::write_str(buf, "send_append_entries");

        ccf::msgpack::write_str(buf, "packet");
        write_msgpack(buf, packet);

        ccf::msgpack::write_str(buf, "state");
        write_msgpack(buf, state);

        ccf::msgpack::write_str(buf, "to_node_id");
        write_msgpack(buf, to_node_id);

        ccf::msgpack::write_str(buf, "match_idx");
        ccf::msgpack::write_uint(buf, match_idx);

        ccf::msgpack::write_str(buf, "sent_idx");
        ccf::msgpack::write_uint(buf, sent_idx);
      });
  }

  inline std::vector<uint8_t> encode_recv_append_entries(
    const aft::State& state,
    const aft::AppendEntries& packet,
    const ccf::NodeId& from_node_id)
  {
    return build_fluentd_entry(
      raft_trace_tag, [&](std::vector<uint8_t>& buf) {
        ccf::msgpack::write_map_header(buf, 4);

        ccf::msgpack::write_str(buf, "function");
        ccf::msgpack::write_str(buf, "recv_append_entries");

        ccf::msgpack::write_str(buf, "packet");
        write_msgpack(buf, packet);

        ccf::msgpack::write_str(buf, "state");
        write_msgpack(buf, state);

        ccf::msgpack::write_str(buf, "from_node_id");
        write_msgpack(buf, from_node_id);
      });
  }
} // namespace aft::trace
