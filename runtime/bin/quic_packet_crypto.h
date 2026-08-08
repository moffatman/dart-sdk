// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_QUIC_PACKET_CRYPTO_H_
#define RUNTIME_BIN_QUIC_PACKET_CRYPTO_H_

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dart {
namespace bin {

struct QuicPacketKeys {
  bool installed = false;
  uint32_t cipher_id = 0;
  std::vector<uint8_t> secret;
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> header_protection_key;
};

bool DeriveQuicPacketKeys(const uint8_t* secret,
                          size_t secret_len,
                          uint32_t cipher_id,
                          QuicPacketKeys* keys);
bool DeriveNextQuicPacketKeys(const QuicPacketKeys& current,
                              QuicPacketKeys* next);
bool DeriveInitialQuicPacketKeys(const std::vector<uint8_t>& connection_id,
                                 QuicPacketKeys* client_keys,
                                 QuicPacketKeys* server_keys);

bool SealQuicPacketPayload(const QuicPacketKeys* keys,
                           uint64_t packet_number,
                           const std::vector<uint8_t>& plaintext,
                           const std::vector<uint8_t>& aad,
                           std::vector<uint8_t>* ciphertext);
// Packet construction writes directly into an external UDP slot.  Keeping this
// pointer API avoids allocating a temporary ciphertext vector for every packet.
bool SealQuicPacketPayloadInto(const QuicPacketKeys* keys,
                               uint64_t packet_number,
                               const uint8_t* plaintext,
                               size_t plaintext_len,
                               const uint8_t* aad,
                               size_t aad_len,
                               uint8_t* ciphertext,
                               size_t ciphertext_capacity,
                               size_t* ciphertext_len);
bool OpenQuicPacketPayload(const QuicPacketKeys* keys,
                           uint64_t packet_number,
                           const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& aad,
                           std::vector<uint8_t>* plaintext);
bool ApplyQuicHeaderProtection(const QuicPacketKeys* keys,
                               size_t packet_start,
                               size_t packet_number_offset,
                               size_t packet_number_len,
                               bool long_header,
                               std::vector<uint8_t>* packet);
bool ApplyQuicHeaderProtectionInPlace(const QuicPacketKeys* keys,
                                      size_t packet_number_offset,
                                      size_t packet_number_len,
                                      bool long_header,
                                      uint8_t* packet,
                                      size_t packet_len);
bool RemoveQuicHeaderProtection(const QuicPacketKeys* keys,
                                size_t packet_start,
                                size_t packet_number_offset,
                                bool long_header,
                                std::vector<uint8_t>* packet,
                                size_t* packet_number_len);
bool ValidateQuicRetryIntegrity(
    const uint8_t* packet,
    size_t packet_len,
    const std::vector<uint8_t>& original_destination_connection_id);

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)

#endif  // RUNTIME_BIN_QUIC_PACKET_CRYPTO_H_
