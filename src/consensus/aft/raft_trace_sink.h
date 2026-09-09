// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/startup_config.h"
#include "ds/internal_logger.h"
#include "ds/ring_buffer.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <poll.h>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace aft
{
  class RaftTraceSink
  {
    static_assert(std::atomic<uint64_t>::is_always_lock_free);
    static_assert(std::atomic_ref<uint64_t>::is_always_lock_free);

  public:
    using Endpoint = ccf::CCFConfig::Observability::Fluentd;

    // Configure before starting Raft or worker threads. The destination is
    // immutable for the lifetime of their thread-local connections.
    static void configure(
      std::optional<Endpoint> endpoint, size_t producer_count = 1)
    {
      if (configured())
      {
        throw std::logic_error("Raft trace exporter is already configured");
      }
      if (endpoint.has_value())
      {
        const auto address = make_address(*endpoint);
        std::unique_ptr<BufferedTransport> transport;
        if (endpoint->buffered)
        {
          if (producer_count == 0 || producer_count > 65535)
          {
            throw std::invalid_argument("Invalid number of trace producers");
          }
          const auto size = endpoint->ring_buffer_size.count_bytes();
          if (
            size < 1024 || size > 64 * 1024 * 1024 ||
            !ringbuffer::Const::is_power_of_2(size))
          {
            throw std::invalid_argument(
              "Trace ring buffer size must be a power of two between 1KB and "
              "64MB");
          }
          transport = std::make_unique<BufferedTransport>(
            address, size, endpoint->discard, producer_count);
        }
        target() = address;
        discard() = endpoint->discard;
        buffered_transport() = std::move(transport);
      }
      configured() = true;
    }

    static bool is_configured()
    {
      return target().has_value();
    }

    static bool is_buffered()
    {
      return buffered_transport() != nullptr;
    }

    // Bind once, before this thread starts emitting. Slots have one writer.
    static void bind_producer(size_t slot)
    {
      if (is_buffered())
      {
        bound_queue() = &buffered_transport()->queue_at(slot);
      }
    }

    static bool enqueue(std::span<const uint8_t> bytes)
    {
      auto& instance = buffered_transport();
      if (instance == nullptr)
      {
        return false;
      }
      auto& transport = *instance;
      auto* queue = bound_queue();
      if (queue == nullptr)
      {
        transport.unbound_drops.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      if (
        transport.stopping.load(std::memory_order_relaxed) ||
        bytes.size() > transport.max_payload_size() ||
        !queue->writer.try_write_raw(TRACE_MESSAGE, bytes))
      {
        // This counter has one writer. Reporting is exclusively consumer-side.
        queue->dropped.store(
          queue->dropped.load(std::memory_order_relaxed) + 1,
          std::memory_order_relaxed);
        return false;
      }
      ++queue->enqueued;
      return true;
    }

    static void shutdown()
    {
      if (is_buffered())
      {
        buffered_transport()->shutdown();
      }
    }

    static size_t buffered_consumed_count()
    {
      return is_buffered() ? buffered_transport()->consumed_count() : 0;
    }

    struct Lifetime
    {
      Lifetime() = default;
      Lifetime(const Lifetime&) = delete;
      Lifetime& operator=(const Lifetime&) = delete;
      ~Lifetime()
      {
        shutdown();
      }
    };

    static void send(std::span<const uint8_t> entry)
    {
      if (!is_configured())
      {
        return;
      }
      if (is_buffered())
      {
        enqueue(entry);
        return;
      }
      if (discard())
      {
        // Benchmark serialization without socket IO or drop-counter contention.
        asm volatile("" : : "g"(entry.data()), "g"(entry.size()) : "memory");
        return;
      }

      auto& connection = local_connection();
      if (!connection.is_connected() && !connection.connect(*target()))
      {
        record_drop(errno);
        return;
      }

      const auto sent = connection.send(entry);
      if (sent == static_cast<ssize_t>(entry.size()))
      {
        return;
      }

      if (sent < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          record_drop(errno);
          return;
        }

        const auto error = errno;
        connection.close();
        record_drop(error);
        return;
      }

      const auto remaining = entry.subspan(static_cast<size_t>(sent));
      const auto retry_sent = connection.send(remaining);
      if (retry_sent != static_cast<ssize_t>(remaining.size()))
      {
        connection.close();
        LOG_FATAL_FMT(
          "Partial raft_trace write: sent {} of {} bytes, then {} of {} "
          "bytes",
          sent,
          entry.size(),
          retry_sent,
          remaining.size());
        std::abort();
      }
    }

    static uint64_t drop_count()
    {
      return drops().load(std::memory_order_relaxed) +
        (is_buffered() ? buffered_transport()->producer_drops() : 0);
    }

  private:
    static constexpr ringbuffer::Message TRACE_MESSAGE =
      ccf::ds::fnv_1a<ringbuffer::Message>("raft_trace");

    static bool& discard()
    {
      static bool value = false;
      return value;
    }

    struct Address
    {
      sockaddr_storage storage = {};
      socklen_t size = 0;
    };

    static Address make_address(const Endpoint& endpoint)
    {
      unsigned int port = 0;
      const auto* end = endpoint.port.data() + endpoint.port.size();
      const auto result = std::from_chars(endpoint.port.data(), end, port);
      if (
        result.ec != std::errc{} || result.ptr != end || port == 0 ||
        port > 65535)
      {
        throw std::invalid_argument("Fluentd port must be between 1 and 65535");
      }

      Address address;
      sockaddr_in ipv4 = {};
      sockaddr_in6 ipv6 = {};
      if (inet_pton(AF_INET, endpoint.host.c_str(), &ipv4.sin_addr) == 1)
      {
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&address.storage, &ipv4, sizeof(ipv4));
        address.size = sizeof(ipv4);
      }
      else if (inet_pton(AF_INET6, endpoint.host.c_str(), &ipv6.sin6_addr) == 1)
      {
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&address.storage, &ipv6, sizeof(ipv6));
        address.size = sizeof(ipv6);
      }
      else
      {
        throw std::invalid_argument(
          "Fluentd host must be an IPv4 or IPv6 address");
      }
      return address;
    }

    static bool& configured()
    {
      static bool value = false;
      return value;
    }

    class Connection
    {
    private:
      int fd = -1;

    public:
      Connection() = default;
      Connection(const Connection&) = delete;
      Connection& operator=(const Connection&) = delete;

      ~Connection()
      {
        close();
      }

      bool is_connected() const
      {
        return fd >= 0;
      }

      bool connect(const Address& address)
      {
        fd = ::socket(address.storage.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
        {
          return false;
        }

        // Direct mode retains synchronous connection establishment.
        if (
          ::connect(
            fd,
            reinterpret_cast<const sockaddr*>(&address.storage),
            address.size) == 0)
        {
          return true;
        }
        const auto error = errno;
        close();
        errno = error;
        return false;
      }

      template <typename Cancelled, typename OnWait>
      bool connect_buffered(
        const Address& address, Cancelled&& cancelled, OnWait&& on_wait)
      {
        fd = ::socket(
          address.storage.ss_family,
          SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
          0);
        if (fd < 0)
        {
          return false;
        }
        if (
          ::connect(
            fd,
            reinterpret_cast<const sockaddr*>(&address.storage),
            address.size) == 0)
        {
          return true;
        }
        if (errno != EINPROGRESS || !wait_writable(cancelled, on_wait))
        {
          const auto error = errno;
          close();
          errno = error;
          return false;
        }
        int error = 0;
        socklen_t size = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0)
        {
          error = errno;
        }
        if (error != 0)
        {
          close();
          errno = error;
          return false;
        }
        return true;
      }

      template <typename Cancelled, typename OnWait>
      bool wait_writable(Cancelled&& cancelled, OnWait&& on_wait)
      {
        while (!cancelled())
        {
          on_wait();
          pollfd descriptor{fd, POLLOUT, 0};
          const auto result = ::poll(&descriptor, 1, 50);
          if (result > 0)
          {
            if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            {
              errno = ECONNRESET;
              return false;
            }
            return true;
          }
          if (result < 0 && errno != EINTR)
          {
            return false;
          }
        }
        errno = ECANCELED;
        return false;
      }

      ssize_t send(std::span<const uint8_t> entry)
      {
        return ::send(
          fd, entry.data(), entry.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
      }

      void close()
      {
        if (fd >= 0)
        {
          ::close(fd);
          fd = -1;
        }
      }
    };

    struct ProducerQueue
    {
      std::vector<uint64_t> storage;
      ringbuffer::Offsets offsets;
      ringbuffer::Reader reader;
      ringbuffer::Writer writer;
      alignas(ringbuffer::CACHELINE_SIZE) size_t enqueued = 0;
      alignas(ringbuffer::CACHELINE_SIZE) size_t consumed = 0;
      alignas(ringbuffer::CACHELINE_SIZE) std::atomic<uint64_t> dropped = 0;

      explicit ProducerQueue(size_t size) :
        storage(size / sizeof(uint64_t)),
        reader({reinterpret_cast<uint8_t*>(storage.data()), size, &offsets}),
        writer(reader, true)
      {}
    };

    static ProducerQueue*& bound_queue()
    {
      thread_local ProducerQueue* queue = nullptr;
      return queue;
    }

    class BufferedTransport
    {
    public:
      std::atomic<bool> stopping = false;
      std::atomic<uint64_t> unbound_drops = 0;

    private:
      Address address;
      size_t ring_size;
      bool discard_received;
      std::vector<std::unique_ptr<ProducerQueue>> queues;
      uint64_t next_drop_report = 1;
      std::chrono::steady_clock::time_point shutdown_deadline;
      Connection connection;
      size_t records_read = 0;
      std::thread consumer;

      bool expired() const
      {
        return stopping.load(std::memory_order_acquire) &&
          std::chrono::steady_clock::now() >= shutdown_deadline;
      }

      void write(std::span<const uint8_t> bytes)
      {
        if (discard_received)
        {
          asm volatile("" : : "g"(bytes.data()), "g"(bytes.size()) : "memory");
          return;
        }
        const auto cancelled = [this] { return expired(); };
        const auto on_wait = [this] { report_drops(); };
        if (expired())
        {
          record_drop(ECANCELED);
          return;
        }
        if (
          !connection.is_connected() &&
          !connection.connect_buffered(address, cancelled, on_wait))
        {
          record_drop(errno);
          return;
        }
        while (!bytes.empty())
        {
          if (cancelled())
          {
            connection.close();
            record_drop(ECANCELED);
            return;
          }
          const auto sent = connection.send(bytes);
          if (sent > 0)
          {
            bytes = bytes.subspan(static_cast<size_t>(sent));
            continue;
          }
          if (sent < 0 && errno == EINTR)
          {
            continue;
          }
          if (
            sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            connection.wait_writable(cancelled, on_wait))
          {
            continue;
          }
          const auto error = sent == 0 ? ECONNRESET : errno;
          connection.close();
          record_drop(error);
          return;
        }
      }

      void run()
      {
        for (;;)
        {
          bool progress;
          do
          {
            progress = false;
            for (auto& queue : queues)
            {
              if (expired())
              {
                abandon_pending();
                report_drops();
                connection.close();
                return;
              }
              const auto before =
                queue->offsets.head.load(std::memory_order_relaxed);
              queue->reader.read(
                64, [this, &queue](auto, const uint8_t* data, size_t size) {
                  write({data, size});
                  ++records_read;
                  ++queue->consumed;
                });
              progress |=
                before != queue->offsets.head.load(std::memory_order_relaxed);
            }
            report_drops();
          } while (progress);
          if (stopping.load(std::memory_order_acquire))
          {
            connection.close();
            return;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      }

      void abandon_pending()
      {
        // Shutdown starts only after producers have stopped, so their counters
        // are stable and no payload scan or clearing is needed.
        size_t pending = 0;
        for (const auto& queue : queues)
        {
          pending += queue->enqueued - queue->consumed;
        }
        if (pending != 0)
        {
          drops().fetch_add(pending, std::memory_order_relaxed);
        }
      }

      void report_drops()
      {
        const auto total =
          drops().load(std::memory_order_relaxed) + producer_drops();
        while (next_drop_report != 0 && total >= next_drop_report)
        {
          const auto time_us =
            std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count();
          LOG_FAIL_FMT(
            "Dropped {} raft_trace events (observed {}, monotonic_us {})",
            next_drop_report,
            total,
            time_us);
          next_drop_report <<= 1;
        }
      }

    public:
      BufferedTransport(
        Address address_,
        size_t ring_size_,
        bool discard_received_,
        size_t producer_count) :
        address(address_),
        ring_size(ring_size_),
        discard_received(discard_received_)
      {
        queues.reserve(producer_count);
        for (size_t i = 0; i < producer_count; ++i)
        {
          queues.push_back(std::make_unique<ProducerQueue>(ring_size));
        }
        consumer = std::thread([this] { run(); });
      }

      ~BufferedTransport()
      {
        shutdown();
      }

      size_t max_payload_size() const
      {
        return ringbuffer::Const::max_reservation_size(ring_size) -
          ringbuffer::Const::header_size();
      }

      size_t consumed_count() const
      {
        if (consumer.joinable())
        {
          throw std::logic_error(
            "Read buffered trace statistics after shutdown");
        }
        return records_read;
      }

      ProducerQueue& queue_at(size_t slot)
      {
        return *queues.at(slot);
      }

      uint64_t producer_drops() const
      {
        auto total = unbound_drops.load(std::memory_order_relaxed);
        for (const auto& queue : queues)
        {
          total += queue->dropped.load(std::memory_order_relaxed);
        }
        return total;
      }

      // Producers must be stopped before this bounded drain begins.
      void shutdown()
      {
        if (consumer.joinable())
        {
          shutdown_deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(2);
          stopping.store(true, std::memory_order_release);
          consumer.join();
        }
      }
    };

    static std::unique_ptr<BufferedTransport>& buffered_transport()
    {
      static std::unique_ptr<BufferedTransport> transport;
      return transport;
    }

    static std::optional<Address>& target()
    {
      static std::optional<Address> the_target;
      return the_target;
    }

    static Connection& local_connection()
    {
      thread_local Connection connection;
      return connection;
    }

    static std::atomic<uint64_t>& drops()
    {
      static std::atomic<uint64_t> the_drops{0};
      return the_drops;
    }

    static void record_drop(int error)
    {
      const auto count = drops().fetch_add(1, std::memory_order_relaxed) + 1;
      if (!is_buffered() && count != 0 && (count & (count - 1)) == 0)
      {
        const auto time_us =
          std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
        LOG_FAIL_FMT(
          "Dropped {} raft_trace events (socket error {}, monotonic_us {})",
          count,
          error,
          time_us);
      }
    }
  };
} // namespace aft
