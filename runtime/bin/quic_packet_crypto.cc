// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include "bin/quic_packet_crypto.h"

#include <openssl/aes.h>
#include <openssl/chacha.h>
#include <openssl/hkdf.h>
#include <openssl/ssl.h>

#include <cstring>

namespace dart {
namespace bin {

namespace {

constexpr size_t kQuicTagLength = 16;
constexpr uint8_t kQuicInitialSalt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
constexpr uint8_t kQuicRetryIntegrityKey[] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
constexpr uint8_t kQuicRetryIntegrityNonce[] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

const EVP_MD* DigestForCipher(uint32_t cipher_id) {
  return cipher_id == 0x03001302 ? EVP_sha384() : EVP_sha256();
}

const EVP_AEAD* AeadForCipher(uint32_t cipher_id) {
  switch (cipher_id) {
    case 0x03001302:  // TLS_AES_256_GCM_SHA384
      return EVP_aead_aes_256_gcm();
    case 0x03001301:  // TLS_AES_128_GCM_SHA256
      return EVP_aead_aes_128_gcm();
    case 0x03001303:  // TLS_CHACHA20_POLY1305_SHA256
      return EVP_aead_chacha20_poly1305();
    default:
      return nullptr;
  }
}

size_t KeyLengthForCipher(uint32_t cipher_id) {
  return cipher_id == 0x03001302 || cipher_id == 0x03001303 ? 32 : 16;
}

size_t HashLengthForCipher(uint32_t cipher_id) {
  return cipher_id == 0x03001302 ? 48 : 32;
}

std::vector<uint8_t> HkdfExpandLabel(const uint8_t* secret,
                                     size_t secret_len,
                                     const char* label,
                                     size_t out_len,
                                     const EVP_MD* digest) {
  std::vector<uint8_t> info;
  const char kTls13Prefix[] = "tls13 ";
  const size_t prefix_len = strlen(kTls13Prefix);
  const size_t label_len = strlen(label);
  info.push_back(static_cast<uint8_t>(out_len >> 8));
  info.push_back(static_cast<uint8_t>(out_len));
  info.push_back(static_cast<uint8_t>(prefix_len + label_len));
  info.insert(info.end(), kTls13Prefix, kTls13Prefix + prefix_len);
  info.insert(info.end(), label, label + label_len);
  info.push_back(0);

  std::vector<uint8_t> out(out_len);
  if (HKDF_expand(out.data(), out.size(), digest, secret, secret_len,
                  info.data(), info.size()) != 1) {
    return {};
  }
  return out;
}

bool MakeQuicNonce(const QuicPacketKeys* keys,
                   uint64_t packet_number,
                   uint8_t nonce[12]) {
  if (keys->iv.size() != sizeof(uint8_t[12])) return false;
  memcpy(nonce, keys->iv.data(), sizeof(uint8_t[12]));
  for (size_t i = 0; i < 8; i++) {
    nonce[sizeof(uint8_t[12]) - 1 - i] ^=
        static_cast<uint8_t>(packet_number >> (8 * i));
  }
  return true;
}

bool HeaderProtectionMask(const QuicPacketKeys* keys,
                          const uint8_t sample[16],
                          uint8_t mask[16]) {
  if (keys->cipher_id == 0x03001303) {
    if (keys->header_protection_key.size() != 32) return false;
    const uint32_t counter = static_cast<uint32_t>(sample[0]) |
                             (static_cast<uint32_t>(sample[1]) << 8) |
                             (static_cast<uint32_t>(sample[2]) << 16) |
                             (static_cast<uint32_t>(sample[3]) << 24);
    static constexpr uint8_t kZeros[5] = {};
    memset(mask, 0, 16);
    CRYPTO_chacha_20(mask, kZeros, sizeof(kZeros),
                     keys->header_protection_key.data(), sample + 4, counter);
    return true;
  }
  AES_KEY aes_key;
  if (AES_set_encrypt_key(
          keys->header_protection_key.data(),
          static_cast<unsigned>(keys->header_protection_key.size() * 8),
          &aes_key) != 0) {
    return false;
  }
  AES_encrypt(sample, mask, &aes_key);
  return true;
}

}  // namespace

bool DeriveQuicPacketKeys(const uint8_t* secret,
                          size_t secret_len,
                          uint32_t cipher_id,
                          QuicPacketKeys* keys) {
  const EVP_MD* digest = DigestForCipher(cipher_id);
  const size_t key_len = KeyLengthForCipher(cipher_id);
  keys->installed = false;
  keys->cipher_id = cipher_id;
  keys->secret.assign(secret, secret + secret_len);
  keys->key = HkdfExpandLabel(secret, secret_len, "quic key", key_len, digest);
  keys->iv = HkdfExpandLabel(secret, secret_len, "quic iv", 12, digest);
  keys->header_protection_key =
      HkdfExpandLabel(secret, secret_len, "quic hp", key_len, digest);
  keys->installed = !keys->key.empty() && keys->iv.size() == 12 &&
                    !keys->header_protection_key.empty() &&
                    AeadForCipher(cipher_id) != nullptr;
  return keys->installed;
}

bool DeriveNextQuicPacketKeys(const QuicPacketKeys& current,
                              QuicPacketKeys* next) {
  if (!current.installed || current.secret.empty()) {
    return false;
  }
  const EVP_MD* digest = DigestForCipher(current.cipher_id);
  const size_t secret_len = HashLengthForCipher(current.cipher_id);
  std::vector<uint8_t> next_secret =
      HkdfExpandLabel(current.secret.data(), current.secret.size(), "quic ku",
                      secret_len, digest);
  if (next_secret.empty()) {
    return false;
  }
  return DeriveQuicPacketKeys(next_secret.data(), next_secret.size(),
                              current.cipher_id, next);
}

bool DeriveInitialQuicPacketKeys(const std::vector<uint8_t>& connection_id,
                                 QuicPacketKeys* client_keys,
                                 QuicPacketKeys* server_keys) {
  uint8_t initial_secret[EVP_MAX_MD_SIZE];
  size_t initial_secret_len = EVP_MD_size(EVP_sha256());
  if (HKDF_extract(initial_secret, &initial_secret_len, EVP_sha256(),
                   connection_id.data(), connection_id.size(), kQuicInitialSalt,
                   sizeof(kQuicInitialSalt)) != 1) {
    return false;
  }
  const size_t secret_len = HashLengthForCipher(0x03001301);
  std::vector<uint8_t> client_initial =
      HkdfExpandLabel(initial_secret, initial_secret_len, "client in",
                      secret_len, EVP_sha256());
  std::vector<uint8_t> server_initial =
      HkdfExpandLabel(initial_secret, initial_secret_len, "server in",
                      secret_len, EVP_sha256());
  return !client_initial.empty() && !server_initial.empty() &&
         DeriveQuicPacketKeys(client_initial.data(), client_initial.size(),
                              0x03001301, client_keys) &&
         DeriveQuicPacketKeys(server_initial.data(), server_initial.size(),
                              0x03001301, server_keys);
}

bool SealQuicPacketPayload(const QuicPacketKeys* keys,
                           uint64_t packet_number,
                           const std::vector<uint8_t>& plaintext,
                           const std::vector<uint8_t>& aad,
                           std::vector<uint8_t>* ciphertext) {
  ciphertext->assign(plaintext.size() + kQuicTagLength, 0);
  size_t ciphertext_len = 0;
  if (!SealQuicPacketPayloadInto(keys, packet_number, plaintext.data(),
                                 plaintext.size(), aad.data(), aad.size(),
                                 ciphertext->data(), ciphertext->size(),
                                 &ciphertext_len)) {
    ciphertext->clear();
    return false;
  }
  ciphertext->resize(ciphertext_len);
  return true;
}

bool SealQuicPacketPayloadInto(const QuicPacketKeys* keys,
                               uint64_t packet_number,
                               const uint8_t* plaintext,
                               size_t plaintext_len,
                               const uint8_t* aad,
                               size_t aad_len,
                               uint8_t* ciphertext,
                               size_t ciphertext_capacity,
                               size_t* ciphertext_len) {
  const EVP_AEAD* aead = AeadForCipher(keys->cipher_id);
  if (!keys->installed || aead == nullptr ||
      ciphertext_capacity < plaintext_len + kQuicTagLength) {
    return false;
  }
  EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, keys->key.data(), keys->key.size(),
                                       EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (ctx == nullptr) return false;
  uint8_t nonce[12];
  if (!MakeQuicNonce(keys, packet_number, nonce)) {
    EVP_AEAD_CTX_free(ctx);
    return false;
  }
  size_t out_len = 0;
  const int ok =
      EVP_AEAD_CTX_seal(ctx, ciphertext, &out_len, ciphertext_capacity, nonce,
                        sizeof(nonce), plaintext, plaintext_len, aad, aad_len);
  EVP_AEAD_CTX_free(ctx);
  if (ok != 1) return false;
  *ciphertext_len = out_len;
  return true;
}

bool OpenQuicPacketPayload(const QuicPacketKeys* keys,
                           uint64_t packet_number,
                           const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& aad,
                           std::vector<uint8_t>* plaintext) {
  const EVP_AEAD* aead = AeadForCipher(keys->cipher_id);
  if (!keys->installed || aead == nullptr) return false;
  EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, keys->key.data(), keys->key.size(),
                                       EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (ctx == nullptr) return false;
  uint8_t nonce[12];
  if (!MakeQuicNonce(keys, packet_number, nonce)) {
    EVP_AEAD_CTX_free(ctx);
    return false;
  }
  plaintext->assign(ciphertext.size(), 0);
  size_t out_len = 0;
  const int ok = EVP_AEAD_CTX_open(
      ctx, plaintext->data(), &out_len, plaintext->size(), nonce, sizeof(nonce),
      ciphertext.data(), ciphertext.size(), aad.data(), aad.size());
  EVP_AEAD_CTX_free(ctx);
  if (ok != 1) {
    plaintext->clear();
    return false;
  }
  plaintext->resize(out_len);
  return true;
}

bool ApplyQuicHeaderProtection(const QuicPacketKeys* keys,
                               size_t packet_start,
                               size_t packet_number_offset,
                               size_t packet_number_len,
                               bool long_header,
                               std::vector<uint8_t>* packet) {
  return ApplyQuicHeaderProtectionInPlace(keys, packet_number_offset,
                                          packet_number_len, long_header,
                                          packet->data(), packet->size());
}

bool ApplyQuicHeaderProtectionInPlace(const QuicPacketKeys* keys,
                                      size_t packet_number_offset,
                                      size_t packet_number_len,
                                      bool long_header,
                                      uint8_t* packet,
                                      size_t packet_len) {
  if (packet_number_offset + 4 + 16 > packet_len) return false;
  uint8_t sample[16];
  memcpy(sample, packet + packet_number_offset + 4, sizeof(sample));
  uint8_t mask[16];
  if (!HeaderProtectionMask(keys, sample, mask)) return false;
  packet[0] ^= mask[0] & (long_header ? 0x0f : 0x1f);
  for (size_t i = 0; i < packet_number_len; i++) {
    packet[packet_number_offset + i] ^= mask[i + 1];
  }
  return true;
}

bool RemoveQuicHeaderProtection(const QuicPacketKeys* keys,
                                size_t packet_start,
                                size_t packet_number_offset,
                                bool long_header,
                                std::vector<uint8_t>* packet,
                                size_t* packet_number_len) {
  if (packet_number_offset + 4 + 16 > packet->size()) return false;
  uint8_t sample[16];
  memcpy(sample, packet->data() + packet_number_offset + 4, sizeof(sample));
  uint8_t mask[16];
  if (!HeaderProtectionMask(keys, sample, mask)) return false;
  (*packet)[packet_start] ^= mask[0] & (long_header ? 0x0f : 0x1f);
  *packet_number_len = ((*packet)[packet_start] & 0x03) + 1;
  if (packet_number_offset + *packet_number_len > packet->size()) return false;
  for (size_t i = 0; i < *packet_number_len; i++) {
    (*packet)[packet_number_offset + i] ^= mask[i + 1];
  }
  return true;
}

bool ValidateQuicRetryIntegrity(
    const uint8_t* packet,
    size_t packet_len,
    const std::vector<uint8_t>& original_destination_connection_id) {
  if (packet_len < kQuicTagLength) return false;
  std::vector<uint8_t> pseudo_packet;
  pseudo_packet.reserve(1 + original_destination_connection_id.size() +
                        packet_len - kQuicTagLength);
  pseudo_packet.push_back(
      static_cast<uint8_t>(original_destination_connection_id.size()));
  pseudo_packet.insert(pseudo_packet.end(),
                       original_destination_connection_id.begin(),
                       original_destination_connection_id.end());
  pseudo_packet.insert(pseudo_packet.end(), packet,
                       packet + packet_len - kQuicTagLength);

  EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(
      EVP_aead_aes_128_gcm(), kQuicRetryIntegrityKey,
      sizeof(kQuicRetryIntegrityKey), EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (ctx == nullptr) return false;
  uint8_t expected[kQuicTagLength];
  size_t expected_len = 0;
  const int ok = EVP_AEAD_CTX_seal(ctx, expected, &expected_len,
                                   sizeof(expected), kQuicRetryIntegrityNonce,
                                   sizeof(kQuicRetryIntegrityNonce), nullptr, 0,
                                   pseudo_packet.data(), pseudo_packet.size());
  EVP_AEAD_CTX_free(ctx);
  if (ok != 1 || expected_len != kQuicTagLength) return false;
  uint8_t difference = 0;
  const uint8_t* received = packet + packet_len - kQuicTagLength;
  for (size_t i = 0; i < kQuicTagLength; i++) {
    difference |= expected[i] ^ received[i];
  }
  return difference == 0;
}

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)
