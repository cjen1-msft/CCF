// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "common/configuration.h"
#include "consensus/aft/raft_trace_msgpack.h"

#include <deque>
#include <doctest/doctest.h>
#include <set>
#include <sys/resource.h>
#include <sys/wait.h>
#include <thread>

namespace
{
  template <typename T>
  void check_encoding(const T& value)
  {
    std::vector<uint8_t> bytes;
    aft::trace::write_msgpack(bytes, value);
    CHECK(nlohmann::json::from_msgpack(bytes) == nlohmann::json(value));
  }

  thread_local std::deque<ssize_t> send_results;
  thread_local std::vector<uint8_t> attempted;
  thread_local int send_flags = 0;
}

extern "C" ssize_t __real_send(int, const void*, size_t, int);

// Exercise short writes and EAGAIN deterministically without changing the sink.
extern "C" ssize_t __wrap_send(int fd, const void* data, size_t size, int flags)
{
  send_flags = flags;
  const auto* bytes = static_cast<const uint8_t*>(data);
  attempted.assign(bytes, bytes + size);
  if (!send_results.empty())
  {
    const auto result = send_results.front();
    send_results.pop_front();
    if (result < 0)
    {
      errno = static_cast<int>(-result);
      return -1;
    }
    size = static_cast<size_t>(result);
  }
  return __real_send(fd, data, size, flags);
}

TEST_CASE("Raft trace State matches JSON, including absent optional fields")
{
  aft::State state(ccf::NodeId("node"));
  for (unsigned mask = 0; mask < 16; ++mask)
  {
    state.retirement_phase = mask & 1 ?
      std::make_optional(ccf::kv::RetirementPhase::Ordered) :
      std::nullopt;
    state.retirement_idx =
      mask & 2 ? std::make_optional<uint64_t>(7) : std::nullopt;
    state.retirement_committable_idx =
      mask & 4 ? std::make_optional<uint64_t>(8) : std::nullopt;
    state.retired_committed_idx =
      mask & 8 ? std::make_optional<uint64_t>(9) : std::nullopt;
    for (size_t n = 0; n < 4; ++n)
    {
      state.committable_indices.clear();
      for (size_t i = 0; i < n; ++i)
      {
        state.committable_indices.push_back(i + 1);
      }
      auto expected = nlohmann::json(state);
      std::vector<uint8_t> bytes;
      aft::trace::write_msgpack<false>(bytes, state);
      CHECK(nlohmann::json::from_msgpack(bytes) == expected);
      expected["committable_indices"] = nlohmann::json::array();
      if (n != 0)
      {
        expected["committable_indices"].push_back(1);
        if (n > 1)
        {
          expected["committable_indices"].push_back(n);
        }
      }
      bytes.clear();
      aft::trace::write_msgpack(bytes, state);
      CHECK(nlohmann::json::from_msgpack(bytes) == expected);
    }
  }
  for (auto phase :
       {ccf::kv::RetirementPhase::Ordered,
        ccf::kv::RetirementPhase::Signed,
        ccf::kv::RetirementPhase::Completed,
        ccf::kv::RetirementPhase::RetiredCommitted})
  {
    check_encoding(phase);
  }
}

TEST_CASE("Raft packet and configuration encodings match JSON")
{
  aft::AppendEntries append{};
  append.idx = std::numeric_limits<uint64_t>::max();
  append.contains_new_view = true;
  check_encoding(append);
  for (auto response :
       {aft::AppendEntriesResponseType::OK,
        aft::AppendEntriesResponseType::FAIL})
  {
    check_encoding(aft::AppendEntriesResponse{
      .term = 2, .last_log_idx = 3, .success = response});
  }
  check_encoding(aft::RequestVote{
    .term = 4, .last_committable_idx = 7, .term_of_last_committable_idx = 3});
  check_encoding(aft::RequestPreVote{
    .term = 5, .last_committable_idx = 8, .term_of_last_committable_idx = 4});
  check_encoding(aft::RequestVoteResponse{.term = 5, .vote_granted = false});
  check_encoding(aft::RequestPreVoteResponse{.term = 6, .vote_granted = true});
  check_encoding(aft::ProposeRequestVote{.term = 7});
  check_encoding(ccf::kv::Configuration{
    1,
    {{ccf::NodeId("v4"), {"127.0.0.1", "123"}},
     {ccf::NodeId("v6"), {"::1", "456"}}},
    2});
  check_encoding(ccf::kv::Configuration{});
}

TEST_CASE("Fluentd configuration round trips")
{
  ccf::CCFConfig::Observability config;
  CHECK(nlohmann::json(config) == nlohmann::json::object());
  config.fluentd = {"::1", "24224"};
  CHECK(nlohmann::json(config).get<ccf::CCFConfig::Observability>() == config);
  config.fluentd->discard = true;
  CHECK(nlohmann::json(config).get<ccf::CCFConfig::Observability>() == config);
}

TEST_CASE("Per-thread TCP connections, drops, and short writes")
{
  using Sink = aft::RaftTraceSink;
  const std::vector<uint8_t> payload = {1, 2, 3, 4, 5, 6};
  CHECK_FALSE(Sink::is_configured());
  bool encoded = false;
  aft::trace::emit(0, [&](auto&) { encoded = true; });
  CHECK_FALSE(encoded);
  Sink::send(payload);
  CHECK(Sink::drop_count() == 0);
  CHECK_THROWS_AS(
    Sink::configure(Sink::Endpoint{"localhost", "1"}), std::invalid_argument);
  CHECK_THROWS_AS(
    Sink::configure(Sink::Endpoint{"127.0.0.1", "0"}), std::invalid_argument);
  CHECK_THROWS_AS(
    Sink::configure(Sink::Endpoint{"127.0.0.1", "65536"}),
    std::invalid_argument);

  const auto discard_child = fork();
  REQUIRE(discard_child >= 0);
  if (discard_child == 0)
  {
    Sink::configure(Sink::Endpoint{"127.0.0.1", "1", true});
    aft::trace::emit(1, [&](auto& out) {
      encoded = true;
      ccf::msgpack::write_str(out, "discard_test");
      ccf::msgpack::write_bool(out, true);
    });
    _exit(encoded && attempted.empty() && Sink::drop_count() == 0 ? 0 : 1);
  }
  int discard_status = 0;
  REQUIRE(waitpid(discard_child, &discard_status, 0) == discard_child);
  REQUIRE(WIFEXITED(discard_status));
  CHECK(WEXITSTATUS(discard_status) == 0);

  const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(listener >= 0);
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(
    bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ==
    0);
  REQUIRE(listen(listener, 8) == 0);
  socklen_t size = sizeof(address);
  REQUIRE(
    getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0);
  Sink::configure(
    Sink::Endpoint{"127.0.0.1", std::to_string(ntohs(address.sin_port))});
  CHECK_THROWS_AS(Sink::configure(std::nullopt), std::logic_error);

  Sink::send(payload);
  CHECK(
    (send_flags & (MSG_DONTWAIT | MSG_NOSIGNAL)) ==
    (MSG_DONTWAIT | MSG_NOSIGNAL));
  const auto connection = accept(listener, nullptr, nullptr);
  REQUIRE(connection >= 0);
  std::vector<uint8_t> received(payload.size());
  REQUIRE(recv(connection, received.data(), received.size(), MSG_WAITALL) == 6);
  CHECK(received == payload);

  send_results = {-EAGAIN};
  Sink::send(payload);
  CHECK(Sink::drop_count() == 1);
  send_results = {2};
  Sink::send(payload);
  CHECK(attempted == std::vector<uint8_t>(payload.begin() + 2, payload.end()));
  REQUIRE(recv(connection, received.data(), received.size(), MSG_WAITALL) == 6);
  CHECK(received == payload);

  // An incomplete second write must terminate, not throw into a Raft handler.
  auto child = fork();
  REQUIRE(child >= 0);
  if (child == 0)
  {
    const rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0)
    {
      _exit(2);
    }
    send_results = {1, -EAGAIN};
    Sink::send(payload);
    _exit(3);
  }
  int status = 0;
  REQUIRE(waitpid(child, &status, 0) == child);
  CHECK(WIFSIGNALED(status));
  CHECK(WTERMSIG(status) == SIGABRT);
  uint8_t partial = 0;
  REQUIRE(recv(connection, &partial, 1, MSG_WAITALL) == 1);

  send_results = {-EPIPE};
  Sink::send(payload);
  CHECK(Sink::drop_count() == 2);
  CHECK(recv(connection, &partial, 1, 0) == 0);
  CHECK(close(connection) == 0);
  Sink::send(payload);
  const auto reconnected = accept(listener, nullptr, nullptr);
  REQUIRE(reconnected >= 0);
  REQUIRE(
    recv(reconnected, received.data(), received.size(), MSG_WAITALL) == 6);
  CHECK(received == payload);
  CHECK(close(reconnected) == 0);

  const auto emit = [] {
    aft::trace::emit(1, [](auto& out) {
      ccf::msgpack::write_str(out, "function");
      ccf::msgpack::write_str(out, "thread_test");
    });
  };
  std::thread first(emit);
  std::thread second(emit);
  first.join();
  second.join();
  std::set<uint64_t> sequences;
  for (size_t i = 0; i < 2; ++i)
  {
    const auto peer = accept(listener, nullptr, nullptr);
    REQUIRE(peer >= 0);
    std::vector<uint8_t> bytes;
    std::array<uint8_t, 512> chunk;
    ssize_t count;
    while ((count = recv(peer, chunk.data(), chunk.size(), 0)) > 0)
    {
      bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + count);
    }
    CHECK(count == 0);
    const auto entry = nlohmann::json::from_msgpack(bytes);
    CHECK(entry.at(0) == "ccf.raft_trace");
    CHECK(entry.at(2).at("msg").at("function") == "thread_test");
    sequences.insert(entry.at(2).at("h_ts").get<uint64_t>());
    CHECK(close(peer) == 0);
  }
  CHECK(sequences == std::set<uint64_t>{0, 1});
  CHECK(close(listener) == 0);
  std::thread unavailable([&] { Sink::send(payload); });
  unavailable.join();
  CHECK(Sink::drop_count() == 3);
}
