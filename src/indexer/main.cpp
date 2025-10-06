// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/pal/platform.h"
#include "ccf/version.h"
#include "ds/files.h"
#include "http/curl.h"
#include "sig_term.h"

#include <CLI11/CLI11.hpp>
#include <chrono>
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <thread>
#include <uv.h>

void print_version(int64_t ignored)
{
  (void)ignored;
  LOG_INFO_FMT("CCF host: {}", ccf::ccf_version);
  LOG_INFO_FMT(
    "Platform: {}", nlohmann::json(ccf::pal::platform).get<std::string>());
  exit(0); // NOLINT(concurrency-mt-unsafe)
}

int main(int argc, char** argv)
{
  using namespace std::chrono_literals;
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
  {
    LOG_FAIL_FMT("Failed to ignore SIGPIPE");
    return 1;
  }

  CLI::App app{"Run a single ccf indexer instance"};

  app.add_flag("-v, --version", print_version, "Display the corresponding CCF version and exit");

  ccf::LoggerLevel log_level = ccf::LoggerLevel::INFO;
  std::map<std::string, ccf::LoggerLevel> log_level_options;
  for (size_t i = ccf::logger::MOST_VERBOSE;
       i < ccf::LoggerLevel::MAX_LOG_LEVEL;
       ++i)
  {
    const auto level = (ccf::LoggerLevel)i;
    log_level_options[ccf::logger::to_string(level)] = level;
  }

  app
    .add_option(
      "--log-level",
      log_level,
      "Logging level for the node (security critical)")
    ->transform(CLI::CheckedTransformer(log_level_options, CLI::ignore_case));

  std::string config_file_path;
  app
    .add_option(
      "-c,--config", config_file_path, "Path to JSON configuration file")
    ->required();

  ccf::ds::TimeString config_timeout = {"0s"};
  app.add_option(
    "--config-timeout",
    config_timeout,
    "Configuration file read timeout, for example 5s or 1min");

  try
  {
    app.parse(argc, argv);
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  ccf::logger::config::add_text_console_logger();
  ccf::logger::config::level() = log_level;

  nlohmann::json config_json;
  const auto config_timeout_end = // NOLINT(clang-analyzer-deadcode.DeadStores)
                                  // line 195
    std::chrono::high_resolution_clock::now() +
    std::chrono::microseconds(config_timeout);
  std::string config_parsing_error;
  do
  {
    std::string config_str = files::slurp_string(
      config_file_path,
      true /* return an empty string if the file does not exist */);
    try
    {
      config_json = nlohmann::json::parse(config_str);
      config_parsing_error = "";
      break;
    }
    catch (const std::exception& e)
    {
      config_parsing_error = fmt::format(
        "Error parsing configuration file {}: {}", config_file_path, e.what());
      std::this_thread::sleep_for(100ms);
    }
  } while (std::chrono::high_resolution_clock::now() < config_timeout_end);
  if (!config_parsing_error.empty())
  {
    throw std::logic_error(config_parsing_error);
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);

  int rc = 0;

  {
    ccf::curl::CurlmLibuvContextSingleton curlm_ctx(uv_default_loop());
    asynchost::Sigterm sigterm_handler;
    asynchost::Sighup sighub_handler;
    try
    {
      LOG_INFO_FMT("Indexer: entering event loop");
      uv_run(uv_default_loop(), UV_RUN_DEFAULT);
      LOG_INFO_FMT("Indexer: exited event loop");
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
    {
      break;
    }
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    --close_iterations;
    std::this_thread::sleep_for(10ms);
  }
  if (loop_close_rc != 0)
  {
    std::cerr << "Indexer: uv_loop_close still busy after cleanup attempts"
              << std::endl;
    rc = rc == 0 ? 1 : rc;
  }

  // 4. Global curl cleanup
  curl_global_cleanup();

  LOG_INFO_FMT("Indexer: shutdown complete");
  return rc;
}
