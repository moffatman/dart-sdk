// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_QUIC_RECOVERY_H_
#define RUNTIME_BIN_QUIC_RECOVERY_H_

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include <openssl/ssl.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "platform/globals.h"

namespace dart {
namespace bin {

struct QuicSentPacket {
  uint64_t packet_number = 0;
  uint64_t key_generation = 0;
  ssl_encryption_level_t encryption_level = ssl_encryption_initial;
  int64_t sent_time_micros = 0;
  size_t bytes = 0;
  uint32_t path_id = 0;
  std::vector<uint8_t> retransmittable_payload;
};

struct QuicRecoveryResult {
  bool valid = false;
  bool current_application_key_generation_acked = false;
  std::vector<QuicSentPacket> lost_packets;
};

struct QuicRecoveryProbe {
  ssl_encryption_level_t encryption_level = ssl_encryption_initial;
  QuicSentPacket packet;
  bool has_packet = false;
};

class QuicReceivedPacketTracker {
 public:
  void Reset();
  void Add(uint64_t packet_number);
  std::vector<std::pair<uint64_t, uint64_t>> AckRanges(
      size_t maximum_ranges) const;

 private:
  static constexpr uint64_t kTrackedPacketWindow = 4096;

  std::map<uint64_t, uint64_t> ranges_;
  uint64_t largest_received_ = 0;
  bool has_largest_received_ = false;
};

class QuicRecovery {
 public:
  QuicRecovery();

  void Reset();
  void ResetInitialPacketNumberSpace();
  void RemovePacketsAtEncryptionLevel(ssl_encryption_level_t level);
  std::vector<std::vector<uint8_t>> RetransmittablePayloads(
      ssl_encryption_level_t level) const;
  void ResetPath(uint32_t path_id);
  void DiscardPacketNumberSpace(ssl_encryption_level_t level);
  bool IsPacketNumberSpaceDiscarded(ssl_encryption_level_t level) const;

  bool CanSend(size_t packet_size) const;
  void OnPacketSent(ssl_encryption_level_t level,
                    uint64_t packet_number,
                    uint64_t key_generation,
                    size_t packet_size,
                    const std::vector<uint8_t>& payload,
                    bool retransmittable,
                    uint32_t path_id,
                    int64_t now_micros);
  QuicRecoveryResult OnAckReceived(
      ssl_encryption_level_t level,
      const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges,
      uint64_t ack_delay,
      uint64_t next_packet_number,
      uint64_t application_key_generation,
      int64_t now_micros);
  std::vector<QuicSentPacket> DetectLostPackets(ssl_encryption_level_t level,
                                                int64_t now_micros);

  int64_t ProbeTimeoutMicros(ssl_encryption_level_t level) const;
  int64_t SmoothedRttMicros() const { return smoothed_rtt_micros_; }
  int64_t NextDeadlineMicros() const;
  int64_t LossTimeMicros(ssl_encryption_level_t level) const;
  bool GetProbe(int64_t now_micros, QuicRecoveryProbe* probe) const;
  void OnProbeSent();

 private:
  struct PacketNumberSpace {
    std::map<uint64_t, QuicSentPacket> sent_packets;
    bool has_largest_acked = false;
    uint64_t largest_acked = 0;
    int64_t loss_time_micros = -1;
    int64_t last_ack_eliciting_sent_time_micros = -1;
  };

  static bool PacketNumberIsAcked(
      uint64_t packet_number,
      const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges);
  void RemoveBytesInFlight(const QuicSentPacket& packet);

  PacketNumberSpace packet_number_spaces_[4];
  bool packet_number_space_discarded_[4] = {false, false, false, false};
  int64_t latest_rtt_micros_ = 0;
  int64_t min_rtt_micros_ = -1;
  int64_t smoothed_rtt_micros_ = 333000;
  int64_t rtt_variance_micros_ = 166500;
  uint64_t bytes_in_flight_ = 0;
  uint64_t congestion_window_ = 12000;
  uint64_t slow_start_threshold_ = UINT64_MAX;
  int64_t recovery_start_time_micros_ = 0;
  uint32_t pto_count_ = 0;
};

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)

#endif  // RUNTIME_BIN_QUIC_RECOVERY_H_
