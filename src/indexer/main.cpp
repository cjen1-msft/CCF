// Minimal standalone indexer prototype.
// For now this does NOT start a full CCF node. Instead it demonstrates
// initialising the shared libuv event loop and the Curlm (multi-curl)
// singleton used elsewhere in CCF so later components (eg. endorsement
// fetching, HTTP clients, etc.) can be integrated.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Order of includes matters: standard + nlohmann before project headers that rely on them
#include <curl/curl.h>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <uv.h>
#include <nlohmann/json.hpp>

#include "http/curl.h"

int main()
{
  using namespace std::chrono_literals;

  // 1. Global libcurl init (paired with curl_global_cleanup at end)
  curl_global_init(CURL_GLOBAL_DEFAULT);

  int rc = 0;

  {
    ccf::curl::CurlmLibuvContextSingleton curlm_ctx(uv_default_loop());
    try
    {
      std::cout << "Indexer: entering event loop" << std::endl;
      uv_run(uv_default_loop(), UV_RUN_DEFAULT);
      std::cout << "Indexer: exited event loop" << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cerr << "Indexer runtime exception: " << e.what() << std::endl;
      rc = 1;
    }
    catch (...)
    {
      std::cerr << "Indexer runtime: unknown exception" << std::endl;
      rc = 1;
    }
  }

  constexpr size_t max_close_iterations = 1000;
  size_t close_iterations = max_close_iterations;
  int loop_close_rc = 0;
  while (close_iterations > 0)
  {
    loop_close_rc = uv_loop_close(uv_default_loop());
    if (loop_close_rc != UV_EBUSY)
      break;
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    --close_iterations;
    std::this_thread::sleep_for(10ms);
  }
  if (loop_close_rc != 0)
  {
    std::cerr << "Indexer: uv_loop_close still busy after cleanup attempts" << std::endl;
    rc = rc == 0 ? 1 : rc;
  }

  // 4. Global curl cleanup
  curl_global_cleanup();

  std::cout << "Indexer: shutdown complete" << std::endl;
  return rc;
}
