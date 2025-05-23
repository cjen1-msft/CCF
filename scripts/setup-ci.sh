#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

H2SPEC_VERSION="v2.6.0"
PEBBLE_VERSION="v2.3.1"

# Source control
tdnf -y install  \
    git  \
    ca-certificates

# To build CCF
tdnf -y install  \
    build-essential  \
    clang  \
    cmake  \
    ninja-build  \
    which  \
    openssl-devel  \
    libuv-devel  \
    nghttp2-devel  \
    curl-devel  \
    libarrow-devel  \
    parquet-libs-devel  \
    doxygen  \
    clang-tools-extra-devel

# To run standard tests
tdnf -y install  \
    lldb  \
    expect  \
    npm  \
    jq

# Extra-dependency for CDDL schema checker
tdnf -y install rubygems
gem install cddl

# Release (extended) tests
tdnf -y install procps

# protocoltest
tdnf install -y bind-utils
curl -L --output h2spec_linux_amd64.tar.gz https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz
tar -xvf h2spec_linux_amd64.tar.gz
mkdir /opt/h2spec
mv h2spec /opt/h2spec/h2spec
rm h2spec_linux_amd64.tar.gz

# acme endorsement tests
mkdir -p /opt/pebble
curl -L --output pebble_linux-amd64 https://github.com/letsencrypt/pebble/releases/download/$PEBBLE_VERSION/pebble_linux-amd64
mv pebble_linux-amd64 /opt/pebble/pebble_linux-amd64
curl -L --output pebble-challtestsrv_linux-amd64 https://github.com/letsencrypt/pebble/releases/download/$PEBBLE_VERSION/pebble-challtestsrv_linux-amd64
mv pebble-challtestsrv_linux-amd64 /opt/pebble/pebble-challtestsrv_linux-amd64
chmod +x /opt/pebble/pebble_linux-amd64 /opt/pebble/pebble-challtestsrv_linux-amd64

# partitions test
tdnf -y install iptables
tdnf -y install strace

# For packaging
tdnf -y install rpm-build

# SymCrypt backend is pinned to 1.7.0 for the time being until
# https://github.com/microsoft/SymCrypt-OpenSSL/issues/115 is shipped.
tdnf -y remove SymCrypt-OpenSSL
tdnf -y install SymCrypt-OpenSSL-1.7.0-1.azl3
