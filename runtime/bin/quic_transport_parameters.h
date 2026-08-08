// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_QUIC_TRANSPORT_PARAMETERS_H_
#define RUNTIME_BIN_QUIC_TRANSPORT_PARAMETERS_H_

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bin/quic_packet.h"

namespace dart {
namespace bin {

static constexpr uint64_t kQuicLocalActiveConnectionIdLimit = 64;

struct QuicTransportParameters {
  uint64_t max_idle_timeout = 5000;
  uint64_t initial_max_data = 0;
  uint64_t initial_max_stream_data_bidi_local = 0;
  uint64_t initial_max_stream_data_bidi_remote = 0;
  uint64_t initial_max_stream_data_uni = 0;
  uint64_t initial_max_streams_bidi = 0;
  uint64_t initial_max_streams_uni = 0;
  uint64_t active_connection_id_limit = 2;
  uint64_t max_datagram_frame_size = 0;
  bool has_original_destination_connection_id = false;
  bool has_initial_source_connection_id = false;
  bool has_retry_source_connection_id = false;
  std::vector<uint8_t> original_destination_connection_id;
  std::vector<uint8_t> initial_source_connection_id;
  std::vector<uint8_t> retry_source_connection_id;
  std::vector<uint8_t> stateless_reset_token;
  std::vector<uint8_t> preferred_address;
  std::vector<uint8_t> preferred_connection_id;
  std::vector<uint8_t> preferred_stateless_reset_token;
};

std::vector<uint8_t> BuildLocalQuicTransportParameters(
    const std::vector<uint8_t>& initial_source_connection_id,
    uint64_t initial_max_data = kQuicInitialMaxData,
    uint64_t initial_max_stream_data = kQuicInitialMaxStreamData);
bool ParseQuicTransportParameters(const uint8_t* data,
                                  size_t length,
                                  QuicTransportParameters* parameters);

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)

#endif  // RUNTIME_BIN_QUIC_TRANSPORT_PARAMETERS_H_
