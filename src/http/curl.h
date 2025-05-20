// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"

#include <curl/curl.h>
#include <memory>
#include <span>

#define CHECK_CURL_EASY(fn, ...) \
  do \
  { \
    const auto res = fn(__VA_ARGS__); \
    if (res != CURLE_OK) \
    { \
      throw std::runtime_error(fmt::format( \
        "Error calling " #fn ": {} ({})", res, curl_easy_strerror(res))); \
    } \
  } while (0)

#define CHECK_CURL_EASY_SETOPT(handle, info, arg) \
  CHECK_CURL_EASY(curl_easy_setopt, handle, info, arg)
#define CHECK_CURL_EASY_GETINFO(handle, info, arg) \
  CHECK_CURL_EASY(curl_easy_getinfo, handle, info, arg)

namespace ccf::curl
{

  class UniqueCURL
  {
  protected:
    std::unique_ptr<CURL, void (*)(CURL*)> p;

  public:
    UniqueCURL() : p(curl_easy_init(), [](auto x) { curl_easy_cleanup(x); })
    {
      if (!p.get())
      {
        throw std::runtime_error("Error initialising curl easy request");
      }
    }

    operator CURL*() const
    {
      return p.get();
    }
  };

  class UniqueSlist
  {
  protected:
    std::unique_ptr<curl_slist, void (*)(curl_slist*)> p;

  public:
    UniqueSlist() : p(nullptr, [](auto x) { curl_slist_free_all(x); }) {}

    void append(const char* str)
    {
      p.reset(curl_slist_append(p.release(), str));
    }

    curl_slist* get() const
    {
      return p.get();
    }
  };

  class RequestBody
  {
    // use a class as the holder of the buffer, as the curl callback requires
    // something it can update the position
    // Afaict all other ways to do this require the user to allocate the
    // relevant bit and ensure it stays live over the duration of the call
    std::span<const uint8_t> buffer_span;

  public:
    RequestBody(std::span<const uint8_t> buffer) : buffer_span(buffer) {}

    static size_t send_data(
      char* ptr, size_t size, size_t nitems, void* userdata)
    {
      auto* data = static_cast<RequestBody*>(userdata);
      auto bytes_to_copy = std::min(data->buffer_span.size(), size * nitems);
      memcpy(ptr, data->buffer_span.data(), bytes_to_copy);
      data->buffer_span = data->buffer_span.subspan(bytes_to_copy);
      return bytes_to_copy;
    }

    void attach_to_curl(CURL* curl)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_READDATA, this);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_READFUNCTION, send_data);
      CHECK_CURL_EASY_SETOPT(
        curl, CURLOPT_INFILESIZE, static_cast<curl_off_t>(buffer_span.size()));
    }
  };

  class ResponseBody
  {
  public:
    std::vector<uint8_t> buffer;

    static size_t write_response_chunk(
      char* ptr, size_t size, size_t nmemb, void* userdata)
    {
      auto* data = static_cast<ResponseBody*>(userdata);
      auto bytes_to_copy = size * nmemb;
      data->buffer.insert(
        data->buffer.end(), (uint8_t*)ptr, (uint8_t*)ptr + bytes_to_copy);
      // Should probably set a maximum response size here
      return bytes_to_copy;
    }

    void attach_to_curl(CURL* curl)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEDATA, this);
      // Called one or more times to add more data
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEFUNCTION, write_response_chunk);
    }
  };

} // namespace ccf::curl