// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "consensus/aft/raft_trace_sink.h"

#include <array>
#include <condition_variable>
#include <doctest/doctest.h>
#include <future>
#include <mutex>
#include <set>
#include <sys/wait.h>

namespace
{
  std::mutex gate_mutex;
  std::condition_variable gate;
  bool released = false;
  bool entered = false;
  bool force_eagain = false;
  thread_local bool fail_ring_allocation = false;
  thread_local bool forbid_allocation = false;
  std::vector<std::thread::id> send_threads;

  struct DropLogger : ccf::logger::AbstractLogger
  {
    std::vector<std::string> messages;
    std::vector<std::chrono::steady_clock::time_point> times;
    void write(const ccf::logger::LogLine& line) override
    {
      messages.push_back(line.msg);
      times.push_back(std::chrono::steady_clock::now());
    }
  };
}

extern "C" ssize_t __real_send(int, const void*, size_t, int);
extern "C" void* __real__Znwm(size_t);

extern "C" void* __wrap__Znwm(size_t size)
{
  if (forbid_allocation)
  {
    throw std::bad_alloc();
  }
  if (fail_ring_allocation && size == 1024)
  {
    fail_ring_allocation = false;
    throw std::bad_alloc();
  }
  return __real__Znwm(size);
}

extern "C" ssize_t __wrap_send(int fd, const void* data, size_t size, int flags)
{
  if (force_eagain)
  {
    errno = EAGAIN;
    std::this_thread::yield();
    return -1;
  }
  {
    std::unique_lock lock(gate_mutex);
    entered = true;
    gate.notify_all();
    gate.wait(lock, [] { return released; });
  }
  send_threads.push_back(std::this_thread::get_id());
  return __real_send(fd, data, size, flags);
}

TEST_CASE("Buffered export isolates producers and bounds shutdown")
{
  using Sink = aft::RaftTraceSink;
  const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(listener >= 0);
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(
    bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ==
    0);
  REQUIRE(listen(listener, 8) == 0);
  socklen_t address_size = sizeof(address);
  REQUIRE(
    getsockname(
      listener, reinterpret_cast<sockaddr*>(&address), &address_size) == 0);
  Sink::Endpoint endpoint{"127.0.0.1", std::to_string(ntohs(address.sin_port))};
  endpoint.buffered = true;
  endpoint.ring_buffer_size = "1KB";
  auto too_large = endpoint;
  too_large.ring_buffer_size = "128MB";
  CHECK_THROWS_AS(Sink::configure(too_large), std::invalid_argument);
  CHECK_FALSE(Sink::is_configured());

  const auto discard_child = fork();
  REQUIRE(discard_child >= 0);
  if (discard_child == 0)
  {
    endpoint.discard = true;
    Sink::configure(endpoint);
    Sink::bind_producer(0);
    const std::array<uint8_t, 8> bytes = {};
    for (size_t i = 0; i < 10; ++i)
    {
      Sink::send(bytes);
    }
    Sink::shutdown();
    _exit(
      Sink::buffered_consumed_count() == 10 && Sink::drop_count() == 0 &&
          send_threads.empty() ?
        0 :
        1);
  }
  int discard_status = 0;
  REQUIRE(waitpid(discard_child, &discard_status, 0) == discard_child);
  REQUIRE(WIFEXITED(discard_status));
  CHECK(WEXITSTATUS(discard_status) == 0);

  const auto child = fork();
  REQUIRE(child >= 0);
  if (child == 0)
  {
    force_eagain = true;
    endpoint.ring_buffer_size = "8KB";
    auto waiting_logger = std::make_unique<DropLogger>();
    auto* reports = waiting_logger.get();
    ccf::logger::config::loggers().push_back(std::move(waiting_logger));
    Sink::configure(endpoint);
    Sink::bind_producer(0);
    const std::array<uint8_t, 8> bytes = {};
    size_t queued = 0;
    for (size_t i = 0; i < 1000; ++i)
    {
      queued += Sink::enqueue(bytes);
    }
    const auto start = std::chrono::steady_clock::now();
    Sink::shutdown();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    _exit(
      elapsed < std::chrono::seconds(3) && Sink::drop_count() == 1000 &&
          Sink::buffered_consumed_count() < queued && !reports->times.empty() &&
          reports->times.front() - start < std::chrono::milliseconds(500) ?
        0 :
        1);
  }
  // Drain the child's connection from the listen backlog.
  const auto child_peer = accept(listener, nullptr, nullptr);
  REQUIRE(child_peer >= 0);
  int status = 0;
  REQUIRE(waitpid(child, &status, 0) == child);
  REQUIRE(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);
  CHECK(close(child_peer) == 0);

  fail_ring_allocation = true;
  CHECK_THROWS_AS(Sink::configure(endpoint, 3), std::bad_alloc);
  CHECK_FALSE(fail_ring_allocation);
  CHECK_FALSE(Sink::is_configured());
  auto logger = std::make_unique<DropLogger>();
  auto* captured = logger.get();
  ccf::logger::config::loggers().push_back(std::move(logger));
  Sink::configure(endpoint, 3);
  Sink::bind_producer(0);
  std::vector<uint64_t> expected;
  const auto enqueue = [&](uint64_t value) {
    bool copied = false;
    bool allocated = false;
    forbid_allocation = true;
    try
    {
      copied = Sink::enqueue(
        {reinterpret_cast<const uint8_t*>(&value), sizeof(value)});
    }
    catch (const std::bad_alloc&)
    {
      allocated = true;
    }
    forbid_allocation = false;
    CHECK_FALSE(allocated);
    if (copied)
    {
      expected.push_back(value);
    }
  };
  enqueue(0);
  {
    std::unique_lock lock(gate_mutex);
    REQUIRE(
      gate.wait_for(lock, std::chrono::seconds(2), [] { return entered; }));
  }
  const auto main_thread = std::this_thread::get_id();
  const auto before = std::chrono::steady_clock::now();
  for (uint64_t i = 1; i < 1000; ++i)
  {
    enqueue(i);
  }
  CHECK(std::chrono::steady_clock::now() - before < std::chrono::seconds(1));
  CHECK(Sink::drop_count() > 0);
  CHECK(expected.size() < 1000);
  {
    std::lock_guard lock(gate_mutex);
    released = true;
  }
  gate.notify_all();

  std::thread one([] {
    Sink::bind_producer(1);
    const uint64_t value = 1001;
    Sink::enqueue({reinterpret_cast<const uint8_t*>(&value), sizeof(value)});
  });
  std::thread two([] {
    Sink::bind_producer(2);
    const uint64_t value = 1002;
    Sink::enqueue({reinterpret_cast<const uint8_t*>(&value), sizeof(value)});
  });
  one.join();
  two.join();
  expected.push_back(1001);
  expected.push_back(1002);
  Sink::shutdown();
  CHECK(Sink::buffered_consumed_count() == expected.size());
  uint64_t threshold = 1;
  REQUIRE(!captured->messages.empty());
  for (const auto& message : captured->messages)
  {
    CHECK(message.starts_with("Dropped " + std::to_string(threshold) + " "));
    CHECK(message.find("monotonic_us") != std::string::npos);
    threshold <<= 1;
  }

  const auto peer = accept(listener, nullptr, nullptr);
  REQUIRE(peer >= 0);
  std::vector<uint64_t> received(expected.size());
  REQUIRE(
    recv(
      peer, received.data(), received.size() * sizeof(uint64_t), MSG_WAITALL) ==
    static_cast<ssize_t>(received.size() * sizeof(uint64_t)));
  uint8_t byte = 0;
  CHECK(recv(peer, &byte, 1, 0) == 0);
  std::sort(expected.begin(), expected.end());
  std::sort(received.begin(), received.end());
  CHECK(received == expected);
  REQUIRE(!send_threads.empty());
  CHECK(send_threads.front() != main_thread);
  CHECK(std::all_of(send_threads.begin(), send_threads.end(), [&](auto id) {
    return id == send_threads.front();
  }));
  pollfd pending{listener, POLLIN, 0};
  CHECK(poll(&pending, 1, 0) == 0);
  CHECK(close(peer) == 0);
  CHECK(close(listener) == 0);
}
