// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "host/proxy.h"
#include "host/signal.h"
#include "signal.h"

#include <chrono>
#include <cstring>
#include <uv.h>

namespace asynchost
{
  class ShutdownSignalImpl
  {
  public:
    void on_signal(int signal)
    {
      LOG_INFO_FMT(
        "{}: Shutting down enclave gracefully...", strsignal(signal));
      uv_stop(uv_default_loop());
    }
  };

  using Sigterm = proxy_ptr<Signal<SIGTERM, ShutdownSignalImpl>>;
  using Sighup = proxy_ptr<Signal<SIGHUP, ShutdownSignalImpl>>;
}
