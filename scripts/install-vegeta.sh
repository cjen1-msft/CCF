#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

VEGETA_VERSION="${VEGETA_VERSION:-12.12.0}"
VEGETA_ARCHIVE="vegeta_${VEGETA_VERSION}_linux_amd64.tar.gz"
VEGETA_URL="https://github.com/tsenart/vegeta/releases/download/v${VEGETA_VERSION}/${VEGETA_ARCHIVE}"
VEGETA_SHA256="${VEGETA_SHA256:-e7ce26c8fa4b9e1a3668aa7f82a4d77fca6a6d955f8dd5e843816115cc568450}"
VEGETA_INSTALL_DIR="${VEGETA_INSTALL_DIR:-/opt/vegeta}"
VEGETA_BIN_DIR="${VEGETA_BIN_DIR:-/usr/local/bin}"

curl -L --output "${VEGETA_ARCHIVE}" "${VEGETA_URL}"
echo "${VEGETA_SHA256}  ${VEGETA_ARCHIVE}" | sha256sum --check
tar -xvf "${VEGETA_ARCHIVE}" vegeta
mkdir -p "${VEGETA_INSTALL_DIR}" "${VEGETA_BIN_DIR}"
mv vegeta "${VEGETA_INSTALL_DIR}/vegeta"
ln -sf "${VEGETA_INSTALL_DIR}/vegeta" "${VEGETA_BIN_DIR}/vegeta"
rm "${VEGETA_ARCHIVE}"
