// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include "bin/quic_packet.h"

#include <cstring>

namespace dart {
namespace bin {

size_t QuicVarIntLength(uint64_t value) {
  if (value <= 63) return 1;
  if (value <= 16383) return 2;
  if (value <= 1073741823) return 4;
  return 8;
}

void AppendUint32(std::vector<uint8_t>* out, uint32_t value) {
  out->push_back(static_cast<uint8_t>(value >> 24));
  out->push_back(static_cast<uint8_t>(value >> 16));
  out->push_back(static_cast<uint8_t>(value >> 8));
  out->push_back(static_cast<uint8_t>(value));
}

void AppendVarInt(std::vector<uint8_t>* out, uint64_t value) {
  const size_t len = QuicVarIntLength(value);
  uint64_t encoded = value;
  if (len == 2) {
    encoded |= 0x4000ULL;
  } else if (len == 4) {
    encoded |= 0x80000000ULL;
  } else if (len == 8) {
    encoded |= 0xc000000000000000ULL;
  }
  for (size_t i = 0; i < len; i++) {
    const size_t shift = 8 * (len - i - 1);
    out->push_back(static_cast<uint8_t>(encoded >> shift));
  }
}

bool ReadVarInt(const uint8_t* data,
                size_t len,
                size_t* offset,
                uint64_t* value) {
  if (*offset >= len) return false;
  const uint8_t first = data[*offset];
  const size_t varint_len = 1u << (first >> 6);
  if (*offset + varint_len > len) return false;
  uint64_t out = first & 0x3f;
  for (size_t i = 1; i < varint_len; i++) {
    out = (out << 8) | data[*offset + i];
  }
  *offset += varint_len;
  *value = out;
  return true;
}

uint64_t ReadPacketNumber(const uint8_t* data, size_t len, size_t* offset) {
  uint64_t packet_number = 0;
  for (size_t i = 0; i < len; i++) {
    packet_number = (packet_number << 8) | data[*offset + i];
  }
  *offset += len;
  return packet_number;
}

uint64_t DecodePacketNumber(uint64_t largest_received,
                            bool has_largest_received,
                            uint64_t truncated,
                            size_t packet_number_len) {
  if (!has_largest_received) {
    return truncated;
  }
  const uint64_t expected = largest_received + 1;
  const uint64_t window = uint64_t{1} << (packet_number_len * 8);
  const uint64_t half_window = window / 2;
  const uint64_t mask = window - 1;
  uint64_t candidate = (expected & ~mask) | truncated;
  if (candidate <= expected && expected - candidate >= half_window &&
      candidate <= ((uint64_t{1} << 62) - window)) {
    candidate += window;
  } else if (candidate > expected + half_window && candidate >= window) {
    candidate -= window;
  }
  return candidate;
}

ssl_encryption_level_t PacketTypeToLevel(uint8_t first_byte) {
  if ((first_byte & 0x80) == 0) return ssl_encryption_application;
  switch ((first_byte & 0x30) >> 4) {
    case 0:
      return ssl_encryption_initial;
    case 1:
      return ssl_encryption_early_data;
    case 2:
      return ssl_encryption_handshake;
    default:
      return ssl_encryption_initial;
  }
}

int QuicPacketNumberSpaceIndex(ssl_encryption_level_t level) {
  return level == ssl_encryption_early_data
             ? static_cast<int>(ssl_encryption_application)
             : static_cast<int>(level);
}

uint8_t LongHeaderTypeForLevel(ssl_encryption_level_t level) {
  switch (level) {
    case ssl_encryption_initial:
      return 0x00;
    case ssl_encryption_early_data:
      return 0x10;
    case ssl_encryption_handshake:
      return 0x20;
    case ssl_encryption_application:
      return 0x00;
  }
  return 0x00;
}

static size_t CryptoFrameHeaderLength(uint64_t offset, size_t len) {
  return QuicVarIntLength(0x06) + QuicVarIntLength(offset) +
         QuicVarIntLength(len);
}

size_t ProtectedPacketHeaderLength(ssl_encryption_level_t level,
                                   size_t destination_connection_id_len,
                                   size_t source_connection_id_len,
                                   size_t plaintext_len,
                                   size_t initial_token_len) {
  if (level == ssl_encryption_application) {
    return 1 + destination_connection_id_len + kQuicPacketNumberLength;
  }
  size_t header_len =
      1 + 4 + 1 + destination_connection_id_len + 1 + source_connection_id_len;
  if (level == ssl_encryption_initial) {
    header_len += QuicVarIntLength(initial_token_len) + initial_token_len;
  }
  header_len += QuicVarIntLength(kQuicPacketNumberLength + plaintext_len +
                                 kQuicTagLength);
  header_len += kQuicPacketNumberLength;
  return header_len;
}

size_t ProtectedPacketLength(ssl_encryption_level_t level,
                             size_t destination_connection_id_len,
                             size_t source_connection_id_len,
                             size_t plaintext_len,
                             size_t initial_token_len) {
  return ProtectedPacketHeaderLength(level, destination_connection_id_len,
                                     source_connection_id_len, plaintext_len,
                                     initial_token_len) +
         plaintext_len + kQuicTagLength;
}

size_t MaxCryptoFramePayloadLength(ssl_encryption_level_t level,
                                   uint64_t crypto_offset,
                                   size_t available,
                                   size_t destination_connection_id_len,
                                   size_t source_connection_id_len,
                                   size_t initial_token_len) {
  if (available == 0) {
    return 0;
  }
  size_t candidate = available;
  while (candidate > 0) {
    const size_t payload_len =
        CryptoFrameHeaderLength(crypto_offset, candidate) + candidate;
    const size_t packet_len = ProtectedPacketLength(
        level, destination_connection_id_len, source_connection_id_len,
        payload_len, initial_token_len);
    if (packet_len <= kQuicMaxDatagramPayloadSize) {
      return candidate;
    }
    const size_t excess = packet_len - kQuicMaxDatagramPayloadSize;
    candidate -= excess < candidate ? excess : candidate;
  }
  return 0;
}

void AppendCryptoFrame(std::vector<uint8_t>* out,
                       uint64_t offset,
                       const uint8_t* data,
                       size_t len) {
  AppendVarInt(out, 0x06);
  AppendVarInt(out, offset);
  AppendVarInt(out, len);
  out->insert(out->end(), data, data + len);
}

void AppendTransportConnectionCloseFrame(std::vector<uint8_t>* out,
                                         uint64_t error_code,
                                         uint64_t frame_type,
                                         const char* reason) {
  const size_t reason_len = reason == nullptr ? 0 : strlen(reason);
  AppendVarInt(out, 0x1c);
  AppendVarInt(out, error_code);
  AppendVarInt(out, frame_type);
  AppendVarInt(out, reason_len);
  if (reason_len != 0) {
    out->insert(out->end(), reason, reason + reason_len);
  }
}

void AppendConnectionCloseFrame(std::vector<uint8_t>* out,
                                uint64_t error_code,
                                const char* reason) {
  AppendTransportConnectionCloseFrame(out, error_code, 0, reason);
}

void AppendNewConnectionIdFrame(
    std::vector<uint8_t>* out,
    uint64_t sequence,
    uint64_t retire_prior_to,
    const std::vector<uint8_t>& connection_id,
    const std::vector<uint8_t>& stateless_reset_token) {
  AppendVarInt(out, 0x18);
  AppendVarInt(out, sequence);
  AppendVarInt(out, retire_prior_to);
  out->push_back(static_cast<uint8_t>(connection_id.size()));
  out->insert(out->end(), connection_id.begin(), connection_id.end());
  out->insert(out->end(), stateless_reset_token.begin(),
              stateless_reset_token.end());
}

void AppendRetireConnectionIdFrame(std::vector<uint8_t>* out,
                                   uint64_t sequence) {
  AppendVarInt(out, 0x19);
  AppendVarInt(out, sequence);
}

void AppendPathResponseFrame(std::vector<uint8_t>* out, const uint8_t data[8]) {
  AppendVarInt(out, 0x1b);
  out->insert(out->end(), data, data + 8);
}

void AppendPathChallengeFrame(std::vector<uint8_t>* out,
                              const uint8_t data[8]) {
  AppendVarInt(out, 0x1a);
  out->insert(out->end(), data, data + 8);
}

void AppendDatagramFrame(std::vector<uint8_t>* out,
                         const uint8_t* data,
                         size_t len) {
  AppendVarInt(out, 0x31);
  AppendVarInt(out, len);
  out->insert(out->end(), data, data + len);
}

void AppendStreamFrame(std::vector<uint8_t>* out,
                       uint64_t stream_id,
                       uint64_t offset,
                       const uint8_t* data,
                       size_t len,
                       bool fin) {
  uint64_t frame_type = 0x08 | 0x02;
  if (offset != 0) {
    frame_type |= 0x04;
  }
  if (fin) {
    frame_type |= 0x01;
  }
  AppendVarInt(out, frame_type);
  AppendVarInt(out, stream_id);
  if (offset != 0) {
    AppendVarInt(out, offset);
  }
  AppendVarInt(out, len);
  if (len != 0) {
    out->insert(out->end(), data, data + len);
  }
}

void AppendResetStreamFrame(std::vector<uint8_t>* out,
                            uint64_t stream_id,
                            uint64_t error_code,
                            uint64_t final_size) {
  AppendVarInt(out, 0x04);
  AppendVarInt(out, stream_id);
  AppendVarInt(out, error_code);
  AppendVarInt(out, final_size);
}

void AppendStopSendingFrame(std::vector<uint8_t>* out,
                            uint64_t stream_id,
                            uint64_t error_code) {
  AppendVarInt(out, 0x05);
  AppendVarInt(out, stream_id);
  AppendVarInt(out, error_code);
}

void AppendMaxDataFrame(std::vector<uint8_t>* out, uint64_t maximum_data) {
  AppendVarInt(out, 0x10);
  AppendVarInt(out, maximum_data);
}

void AppendMaxStreamDataFrame(std::vector<uint8_t>* out,
                              uint64_t stream_id,
                              uint64_t maximum_stream_data) {
  AppendVarInt(out, 0x11);
  AppendVarInt(out, stream_id);
  AppendVarInt(out, maximum_stream_data);
}

void AppendDataBlockedFrame(std::vector<uint8_t>* out, uint64_t maximum_data) {
  AppendVarInt(out, 0x14);
  AppendVarInt(out, maximum_data);
}

void AppendStreamDataBlockedFrame(std::vector<uint8_t>* out,
                                  uint64_t stream_id,
                                  uint64_t maximum_stream_data) {
  AppendVarInt(out, 0x15);
  AppendVarInt(out, stream_id);
  AppendVarInt(out, maximum_stream_data);
}

void AppendStreamsBlockedFrame(std::vector<uint8_t>* out,
                               bool bidirectional,
                               uint64_t maximum_streams) {
  AppendVarInt(out, bidirectional ? 0x16 : 0x17);
  AppendVarInt(out, maximum_streams);
}

void AppendMaxStreamsFrame(std::vector<uint8_t>* out,
                           bool bidirectional,
                           uint64_t maximum_streams) {
  AppendVarInt(out, bidirectional ? 0x12 : 0x13);
  AppendVarInt(out, maximum_streams);
}

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)
