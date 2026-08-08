// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include "bin/quic_transport_parameters.h"

#include <set>

#include "bin/quic_packet.h"

namespace dart {
namespace bin {

namespace {

void AppendIntegerParameter(std::vector<uint8_t>* out,
                            uint64_t id,
                            uint64_t value) {
  std::vector<uint8_t> encoded;
  AppendVarInt(&encoded, value);
  AppendVarInt(out, id);
  AppendVarInt(out, encoded.size());
  out->insert(out->end(), encoded.begin(), encoded.end());
}

void AppendBytesParameter(std::vector<uint8_t>* out,
                          uint64_t id,
                          const std::vector<uint8_t>& value) {
  AppendVarInt(out, id);
  AppendVarInt(out, value.size());
  out->insert(out->end(), value.begin(), value.end());
}

bool ParseInteger(const uint8_t* data,
                  size_t start,
                  size_t end,
                  uint64_t* value) {
  size_t offset = start;
  return ReadVarInt(data, end, &offset, value) && offset == end;
}

}  // namespace

std::vector<uint8_t> BuildLocalQuicTransportParameters(
    const std::vector<uint8_t>& initial_source_connection_id,
    uint64_t initial_max_data,
    uint64_t initial_max_stream_data) {
  std::vector<uint8_t> params;
  //AppendIntegerParameter(&params, 0x01, 5000);
  //AppendIntegerParameter(&params, 0x01, 0);
  //AppendIntegerParameter(&params, 0x03, kQuicMaxDatagramPayloadSize);
  //AppendIntegerParameter(&params, 0x03, 0x3FFFFFFFFFFFFFFF);
  AppendIntegerParameter(&params, 0x04, initial_max_data);
  AppendIntegerParameter(&params, 0x05, initial_max_stream_data);
  AppendIntegerParameter(&params, 0x06, initial_max_stream_data);
  AppendIntegerParameter(&params, 0x07, initial_max_stream_data);
  //AppendIntegerParameter(&params, 0x08, kQuicInitialMaxStreamsBidi);
  AppendIntegerParameter(&params, 0x09, kQuicInitialMaxStreamsUni);
  AppendIntegerParameter(&params, 0x0e, kQuicLocalActiveConnectionIdLimit);
  AppendBytesParameter(&params, 0x0f, initial_source_connection_id);
  // Disabled due to WebKit
  //AppendIntegerParameter(&params, 0x20, kQuicMaxDatagramPayloadSize);
  return params;
}

bool ParseQuicTransportParameters(const uint8_t* data,
                                  size_t length,
                                  QuicTransportParameters* parameters) {
  *parameters = QuicTransportParameters();
  std::set<uint64_t> seen;
  size_t offset = 0;
  while (offset < length) {
    uint64_t id = 0;
    uint64_t value_length = 0;
    if (!ReadVarInt(data, length, &offset, &id) ||
        !ReadVarInt(data, length, &offset, &value_length) ||
        value_length > length - offset || !seen.insert(id).second) {
      return false;
    }
    const size_t value_end = offset + static_cast<size_t>(value_length);
    uint64_t value = 0;
    switch (id) {
      case 0x01:
      case 0x04:
      case 0x05:
      case 0x06:
      case 0x07:
      case 0x08:
      case 0x09:
      case 0x0e:
      case 0x20:
        if (!ParseInteger(data, offset, value_end, &value)) return false;
        break;
      case 0x00:
        parameters->original_destination_connection_id.assign(data + offset,
                                                              data + value_end);
        parameters->has_original_destination_connection_id = true;
        offset = value_end;
        continue;
      case 0x02:
        if (value_length != kQuicTagLength) return false;
        parameters->stateless_reset_token.assign(data + offset,
                                                 data + value_end);
        offset = value_end;
        continue;
      case 0x0d: {
        constexpr size_t kFixedPrefixLength = 4 + 2 + 16 + 2 + 1;
        if (value_length < kFixedPrefixLength + 1 + kQuicTagLength) {
          return false;
        }
        const size_t connection_id_length_offset = offset + 4 + 2 + 16 + 2;
        const uint8_t connection_id_length = data[connection_id_length_offset];
        if (connection_id_length == 0 || connection_id_length > 20 ||
            value_length !=
                kFixedPrefixLength + connection_id_length + kQuicTagLength) {
          return false;
        }
        const uint16_t ipv4_port =
            (static_cast<uint16_t>(data[offset + 4]) << 8) | data[offset + 5];
        const size_t ipv6_offset = offset + 6;
        const uint16_t ipv6_port =
            (static_cast<uint16_t>(data[ipv6_offset + 16]) << 8) |
            data[ipv6_offset + 17];
        bool ipv4_unspecified = true;
        for (size_t i = 0; i < 4; i++) {
          ipv4_unspecified &= data[offset + i] == 0;
        }
        bool ipv6_unspecified = true;
        for (size_t i = 0; i < 16; i++) {
          ipv6_unspecified &= data[ipv6_offset + i] == 0;
        }
        if (ipv4_unspecified != (ipv4_port == 0) ||
            ipv6_unspecified != (ipv6_port == 0) ||
            (ipv4_unspecified && ipv6_unspecified)) {
          return false;
        }
        const size_t connection_id_offset = connection_id_length_offset + 1;
        parameters->preferred_connection_id.assign(
            data + connection_id_offset,
            data + connection_id_offset + connection_id_length);
        parameters->preferred_stateless_reset_token.assign(
            data + connection_id_offset + connection_id_length,
            data + value_end);
        parameters->preferred_address.assign(data + offset, data + value_end);
        offset = value_end;
        continue;
      }
      case 0x0f:
        parameters->initial_source_connection_id.assign(data + offset,
                                                        data + value_end);
        parameters->has_initial_source_connection_id = true;
        offset = value_end;
        continue;
      case 0x10:
        parameters->retry_source_connection_id.assign(data + offset,
                                                      data + value_end);
        parameters->has_retry_source_connection_id = true;
        offset = value_end;
        continue;
      default:
        offset = value_end;
        continue;
    }
    switch (id) {
      case 0x01:
        parameters->max_idle_timeout = value;
        break;
      case 0x04:
        parameters->initial_max_data = value;
        break;
      case 0x05:
        parameters->initial_max_stream_data_bidi_local = value;
        break;
      case 0x06:
        parameters->initial_max_stream_data_bidi_remote = value;
        break;
      case 0x07:
        parameters->initial_max_stream_data_uni = value;
        break;
      case 0x08:
        if (value > (uint64_t{1} << 60)) return false;
        parameters->initial_max_streams_bidi = value;
        break;
      case 0x09:
        if (value > (uint64_t{1} << 60)) return false;
        parameters->initial_max_streams_uni = value;
        break;
      case 0x0e:
        if (value < 2) return false;
        parameters->active_connection_id_limit = value;
        break;
      case 0x20:
        parameters->max_datagram_frame_size = value;
        break;
    }
    offset = value_end;
  }
  return true;
}

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)
