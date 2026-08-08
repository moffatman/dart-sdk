// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_QUIC_PACKET_H_
#define RUNTIME_BIN_QUIC_PACKET_H_

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include <openssl/ssl.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dart {
namespace bin {

constexpr uint32_t kQuicVersion1 = 0x00000001;
constexpr size_t kQuicTagLength = 16;
constexpr size_t kQuicPacketNumberLength = 2;
constexpr size_t kQuicMinInitialDatagramSize = 1200;
constexpr size_t kQuicMaxDatagramPayloadSize = 1200;
constexpr size_t kQuicInitialConnectionIdLength = 8;
constexpr uint64_t kQuicInitialMaxData = 16 * 1024 * 1024;
constexpr uint64_t kQuicInitialMaxStreamData = 2 * 1024 * 1024;
constexpr uint64_t kQuicNativeStreamReadBufferSize = 128 * 1024;
constexpr uint64_t kQuicInitialMaxStreamsBidi = 0;
constexpr uint64_t kQuicInitialMaxStreamsUni = 8;

size_t QuicVarIntLength(uint64_t value);

void AppendUint32(std::vector<uint8_t>* out, uint32_t value);

void AppendVarInt(std::vector<uint8_t>* out, uint64_t value);

bool ReadVarInt(const uint8_t* data,
                size_t len,
                size_t* offset,
                uint64_t* value);

uint64_t ReadPacketNumber(const uint8_t* data, size_t len, size_t* offset);

uint64_t DecodePacketNumber(uint64_t largest_received,
                            bool has_largest_received,
                            uint64_t truncated,
                            size_t packet_number_len);

ssl_encryption_level_t PacketTypeToLevel(uint8_t first_byte);
int QuicPacketNumberSpaceIndex(ssl_encryption_level_t level);

uint8_t LongHeaderTypeForLevel(ssl_encryption_level_t level);

size_t ProtectedPacketHeaderLength(ssl_encryption_level_t level,
                                   size_t destination_connection_id_len,
                                   size_t source_connection_id_len,
                                   size_t plaintext_len,
                                   size_t initial_token_len);

size_t ProtectedPacketLength(ssl_encryption_level_t level,
                             size_t destination_connection_id_len,
                             size_t source_connection_id_len,
                             size_t plaintext_len,
                             size_t initial_token_len);

size_t MaxCryptoFramePayloadLength(ssl_encryption_level_t level,
                                   uint64_t crypto_offset,
                                   size_t available,
                                   size_t destination_connection_id_len,
                                   size_t source_connection_id_len,
                                   size_t initial_token_len);

void AppendCryptoFrame(std::vector<uint8_t>* out,
                       uint64_t offset,
                       const uint8_t* data,
                       size_t len);

void AppendTransportConnectionCloseFrame(std::vector<uint8_t>* out,
                                         uint64_t error_code,
                                         uint64_t frame_type,
                                         const char* reason);

void AppendConnectionCloseFrame(std::vector<uint8_t>* out,
                                uint64_t error_code,
                                const char* reason);

void AppendNewConnectionIdFrame(
    std::vector<uint8_t>* out,
    uint64_t sequence,
    uint64_t retire_prior_to,
    const std::vector<uint8_t>& connection_id,
    const std::vector<uint8_t>& stateless_reset_token);

void AppendRetireConnectionIdFrame(std::vector<uint8_t>* out,
                                   uint64_t sequence);

void AppendPathResponseFrame(std::vector<uint8_t>* out, const uint8_t data[8]);

void AppendPathChallengeFrame(std::vector<uint8_t>* out, const uint8_t data[8]);

void AppendDatagramFrame(std::vector<uint8_t>* out,
                         const uint8_t* data,
                         size_t len);

void AppendStreamFrame(std::vector<uint8_t>* out,
                       uint64_t stream_id,
                       uint64_t offset,
                       const uint8_t* data,
                       size_t len,
                       bool fin);

void AppendResetStreamFrame(std::vector<uint8_t>* out,
                            uint64_t stream_id,
                            uint64_t error_code,
                            uint64_t final_size);

void AppendStopSendingFrame(std::vector<uint8_t>* out,
                            uint64_t stream_id,
                            uint64_t error_code);

void AppendMaxDataFrame(std::vector<uint8_t>* out, uint64_t maximum_data);

void AppendMaxStreamDataFrame(std::vector<uint8_t>* out,
                              uint64_t stream_id,
                              uint64_t maximum_stream_data);

void AppendDataBlockedFrame(std::vector<uint8_t>* out, uint64_t maximum_data);

void AppendStreamDataBlockedFrame(std::vector<uint8_t>* out,
                                  uint64_t stream_id,
                                  uint64_t maximum_stream_data);

void AppendStreamsBlockedFrame(std::vector<uint8_t>* out,
                               bool bidirectional,
                               uint64_t maximum_streams);

void AppendMaxStreamsFrame(std::vector<uint8_t>* out,
                           bool bidirectional,
                           uint64_t maximum_streams);

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)

#endif  // RUNTIME_BIN_QUIC_PACKET_H_
