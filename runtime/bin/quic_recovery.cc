// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include "bin/quic_recovery.h"

#include "bin/quic_packet.h"

#include <algorithm>
#include <iterator>
#include <limits>

namespace dart {
namespace bin {

namespace {

constexpr uint64_t kMaxDatagramSize = 1200;
constexpr uint64_t kMinimumCongestionWindow = 2 * kMaxDatagramSize;
constexpr uint64_t kMaximumCongestionWindow = 4 * MB;
constexpr uint64_t kPacketThreshold = 3;
constexpr int64_t kTimerGranularityMicros = 1000;
constexpr int64_t kDefaultMaxAckDelayMicros = 25000;
constexpr uint8_t kDefaultAckDelayExponent = 3;

}  // namespace

QuicRecovery::QuicRecovery() = default;

void QuicReceivedPacketTracker::Reset() {
  ranges_.clear();
  largest_received_ = 0;
  has_largest_received_ = false;
}

void QuicReceivedPacketTracker::Add(uint64_t packet_number) {
  if (!has_largest_received_ || packet_number > largest_received_) {
    largest_received_ = packet_number;
    has_largest_received_ = true;
  }
  const uint64_t first_tracked =
      largest_received_ >= kTrackedPacketWindow - 1
          ? largest_received_ - (kTrackedPacketWindow - 1)
          : 0;
  if (packet_number < first_tracked) return;

  auto next = ranges_.upper_bound(packet_number);
  uint64_t range_start = packet_number;
  uint64_t range_end = packet_number;
  if (next != ranges_.begin()) {
    auto previous = std::prev(next);
    if (previous->second >= packet_number) return;
    if (previous->second + 1 == packet_number) {
      range_start = previous->first;
      ranges_.erase(previous);
    }
  }
  if (next != ranges_.end() && next->first == packet_number + 1) {
    range_end = next->second;
    ranges_.erase(next);
  }
  ranges_[range_start] = range_end;

  while (!ranges_.empty() && ranges_.begin()->second < first_tracked) {
    ranges_.erase(ranges_.begin());
  }
  if (!ranges_.empty() && ranges_.begin()->first < first_tracked) {
    const uint64_t end = ranges_.begin()->second;
    ranges_.erase(ranges_.begin());
    ranges_[first_tracked] = end;
  }
}

std::vector<std::pair<uint64_t, uint64_t>> QuicReceivedPacketTracker::AckRanges(
    size_t maximum_ranges) const {
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  ranges.reserve(std::min(maximum_ranges, ranges_.size()));
  for (auto range = ranges_.rbegin();
       range != ranges_.rend() && ranges.size() < maximum_ranges; ++range) {
    ranges.emplace_back(range->first, range->second);
  }
  std::reverse(ranges.begin(), ranges.end());
  return ranges;
}

void QuicRecovery::Reset() {
  for (int i = 0; i < 4; i++) {
    packet_number_spaces_[i] = PacketNumberSpace();
    packet_number_space_discarded_[i] = false;
  }
  latest_rtt_micros_ = 0;
  min_rtt_micros_ = -1;
  smoothed_rtt_micros_ = 333000;
  rtt_variance_micros_ = 166500;
  bytes_in_flight_ = 0;
  congestion_window_ = 10 * kMaxDatagramSize;
  slow_start_threshold_ = std::numeric_limits<uint64_t>::max();
  recovery_start_time_micros_ = 0;
  pto_count_ = 0;
}

void QuicRecovery::ResetInitialPacketNumberSpace() {
  PacketNumberSpace& space = packet_number_spaces_[ssl_encryption_initial];
  for (const auto& entry : space.sent_packets) {
    RemoveBytesInFlight(entry.second);
  }
  space = PacketNumberSpace();
  congestion_window_ = 10 * kMaxDatagramSize;
  slow_start_threshold_ = std::numeric_limits<uint64_t>::max();
  recovery_start_time_micros_ = 0;
  pto_count_ = 0;
}

void QuicRecovery::RemovePacketsAtEncryptionLevel(
    ssl_encryption_level_t level) {
  PacketNumberSpace& space =
      packet_number_spaces_[QuicPacketNumberSpaceIndex(level)];
  for (auto it = space.sent_packets.begin(); it != space.sent_packets.end();) {
    if (it->second.encryption_level != level) {
      ++it;
      continue;
    }
    RemoveBytesInFlight(it->second);
    it = space.sent_packets.erase(it);
  }
}

std::vector<std::vector<uint8_t>> QuicRecovery::RetransmittablePayloads(
    ssl_encryption_level_t level) const {
  std::vector<std::vector<uint8_t>> payloads;
  const PacketNumberSpace& space =
      packet_number_spaces_[QuicPacketNumberSpaceIndex(level)];
  for (const auto& entry : space.sent_packets) {
    if (entry.second.encryption_level == level &&
        !entry.second.retransmittable_payload.empty()) {
      payloads.push_back(entry.second.retransmittable_payload);
    }
  }
  return payloads;
}

void QuicRecovery::ResetPath(uint32_t path_id) {
  congestion_window_ = 10 * kMaxDatagramSize;
  slow_start_threshold_ = std::numeric_limits<uint64_t>::max();
  bytes_in_flight_ = 0;
  latest_rtt_micros_ = 0;
  min_rtt_micros_ = -1;
  smoothed_rtt_micros_ = 333000;
  rtt_variance_micros_ = 166500;
  pto_count_ = 0;
  PacketNumberSpace& application =
      packet_number_spaces_[ssl_encryption_application];
  for (auto& entry : application.sent_packets) {
    entry.second.path_id = path_id;
  }
}

void QuicRecovery::DiscardPacketNumberSpace(ssl_encryption_level_t level) {
  const int index = QuicPacketNumberSpaceIndex(level);
  if (packet_number_space_discarded_[index]) {
    return;
  }
  packet_number_space_discarded_[index] = true;
  for (const auto& entry : packet_number_spaces_[index].sent_packets) {
    RemoveBytesInFlight(entry.second);
  }
  packet_number_spaces_[index] = PacketNumberSpace();
}

bool QuicRecovery::IsPacketNumberSpaceDiscarded(
    ssl_encryption_level_t level) const {
  return packet_number_space_discarded_[QuicPacketNumberSpaceIndex(level)];
}

bool QuicRecovery::CanSend(size_t packet_size) const {
  return packet_size <=
         congestion_window_ -
             std::min<uint64_t>(bytes_in_flight_, congestion_window_);
}

void QuicRecovery::OnPacketSent(ssl_encryption_level_t level,
                                uint64_t packet_number,
                                uint64_t key_generation,
                                size_t packet_size,
                                const std::vector<uint8_t>& payload,
                                bool retransmittable,
                                uint32_t path_id,
                                int64_t now_micros) {
  QuicSentPacket sent;
  sent.packet_number = packet_number;
  sent.key_generation = key_generation;
  sent.encryption_level = level;
  sent.sent_time_micros = now_micros;
  sent.bytes = packet_size;
  sent.path_id = path_id;
  if (retransmittable) {
    sent.retransmittable_payload = payload;
  }
  PacketNumberSpace& space =
      packet_number_spaces_[QuicPacketNumberSpaceIndex(level)];
  // TODO: This crashes sometimes
  space.sent_packets[packet_number] = std::move(sent);
  space.last_ack_eliciting_sent_time_micros = now_micros;
  bytes_in_flight_ += packet_size;
}

QuicRecoveryResult QuicRecovery::OnAckReceived(
    ssl_encryption_level_t level,
    const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges,
    uint64_t ack_delay,
    uint64_t next_packet_number,
    uint64_t application_key_generation,
    int64_t now_micros) {
  QuicRecoveryResult result;
  const int index = QuicPacketNumberSpaceIndex(level);
  if (packet_number_space_discarded_[index] || ack_ranges.empty()) {
    return result;
  }
  // AckRanges are ordered from the lowest packet-number range to the highest.
  const uint64_t largest_acked = ack_ranges.back().second;
  if (largest_acked >= next_packet_number) {
    return result;
  }
  result.valid = true;

  PacketNumberSpace& space = packet_number_spaces_[index];
  space.has_largest_acked = true;
  space.largest_acked = std::max(space.largest_acked, largest_acked);
  auto largest = space.sent_packets.find(largest_acked);
  if (largest != space.sent_packets.end()) {
    const bool first_sample = min_rtt_micros_ < 0;
    latest_rtt_micros_ =
        std::max<int64_t>(1, now_micros - largest->second.sent_time_micros);
    if (first_sample || latest_rtt_micros_ < min_rtt_micros_) {
      min_rtt_micros_ = latest_rtt_micros_;
    }
    int64_t adjusted_rtt = latest_rtt_micros_;
    if (level == ssl_encryption_application) {
      const uint64_t max_encoded_delay =
          static_cast<uint64_t>(kDefaultMaxAckDelayMicros) >>
          kDefaultAckDelayExponent;
      const int64_t decoded_ack_delay = static_cast<int64_t>(
          std::min(ack_delay, max_encoded_delay) << kDefaultAckDelayExponent);
      if (adjusted_rtt - min_rtt_micros_ > decoded_ack_delay) {
        adjusted_rtt -= decoded_ack_delay;
      }
    }
    if (first_sample) {
      smoothed_rtt_micros_ = adjusted_rtt;
      rtt_variance_micros_ = adjusted_rtt / 2;
    } else {
      const int64_t difference = smoothed_rtt_micros_ > adjusted_rtt
                                     ? smoothed_rtt_micros_ - adjusted_rtt
                                     : adjusted_rtt - smoothed_rtt_micros_;
      rtt_variance_micros_ = (3 * rtt_variance_micros_ + difference) / 4;
      smoothed_rtt_micros_ = (7 * smoothed_rtt_micros_ + adjusted_rtt) / 8;
    }
  }

  bool acked_any = false;
  for (auto it = space.sent_packets.begin(); it != space.sent_packets.end();) {
    if (!PacketNumberIsAcked(it->first, ack_ranges)) {
      ++it;
      continue;
    }
    acked_any = true;
    const QuicSentPacket& sent = it->second;
    if (level == ssl_encryption_application &&
        sent.key_generation == application_key_generation) {
      result.current_application_key_generation_acked = true;
    }
    RemoveBytesInFlight(sent);
    if (sent.sent_time_micros > recovery_start_time_micros_) {
      if (congestion_window_ < slow_start_threshold_) {
        congestion_window_ = std::min<uint64_t>(
            kMaximumCongestionWindow, congestion_window_ + sent.bytes);
      } else {
        congestion_window_ = std::min<uint64_t>(
            kMaximumCongestionWindow,
            congestion_window_ +
                std::max<uint64_t>(
                    1, kMaxDatagramSize * sent.bytes / congestion_window_));
      }
    }
    it = space.sent_packets.erase(it);
  }
  if (acked_any) {
    pto_count_ = 0;
  }
  result.lost_packets = DetectLostPackets(level, now_micros);
  return result;
}

std::vector<QuicSentPacket> QuicRecovery::DetectLostPackets(
    ssl_encryption_level_t level,
    int64_t now_micros) {
  std::vector<QuicSentPacket> lost_packets;
  const int index = QuicPacketNumberSpaceIndex(level);
  if (packet_number_space_discarded_[index]) {
    return lost_packets;
  }
  PacketNumberSpace& space = packet_number_spaces_[index];
  if (!space.has_largest_acked) {
    space.loss_time_micros = -1;
    return lost_packets;
  }
  const int64_t base_rtt =
      std::max<int64_t>(latest_rtt_micros_, smoothed_rtt_micros_);
  const int64_t loss_delay =
      std::max<int64_t>(kTimerGranularityMicros, (base_rtt * 9 + 7) / 8);
  space.loss_time_micros = -1;
  bool congestion_event = false;
  for (auto it = space.sent_packets.begin(); it != space.sent_packets.end();) {
    if (it->first > space.largest_acked) {
      ++it;
      continue;
    }
    const bool packet_threshold_lost =
        space.largest_acked - it->first >= kPacketThreshold;
    const bool time_threshold_lost =
        it->second.sent_time_micros + loss_delay <= now_micros;
    if (!packet_threshold_lost && !time_threshold_lost) {
      const int64_t candidate = it->second.sent_time_micros + loss_delay;
      if (space.loss_time_micros < 0 || candidate < space.loss_time_micros) {
        space.loss_time_micros = candidate;
      }
      ++it;
      continue;
    }

    QuicSentPacket lost = std::move(it->second);
    it = space.sent_packets.erase(it);
    RemoveBytesInFlight(lost);
    if (lost.sent_time_micros > recovery_start_time_micros_) {
      congestion_event = true;
    }
    lost_packets.push_back(std::move(lost));
  }
  if (congestion_event) {
    recovery_start_time_micros_ = now_micros;
    congestion_window_ =
        std::max<uint64_t>(kMinimumCongestionWindow, congestion_window_ / 2);
    slow_start_threshold_ = congestion_window_;
  }
  return lost_packets;
}

int64_t QuicRecovery::ProbeTimeoutMicros(ssl_encryption_level_t level) const {
  int64_t timeout =
      smoothed_rtt_micros_ +
      std::max<int64_t>(4 * rtt_variance_micros_, kTimerGranularityMicros);
  if (level == ssl_encryption_application) {
    timeout += kDefaultMaxAckDelayMicros;
  }
  const uint32_t shift = std::min<uint32_t>(pto_count_, 16);
  return timeout << shift;
}

int64_t QuicRecovery::NextDeadlineMicros() const {
  int64_t deadline = -1;
  for (int i = 0; i < 4; i++) {
    if (i == ssl_encryption_early_data || packet_number_space_discarded_[i]) {
      continue;
    }
    const PacketNumberSpace& space = packet_number_spaces_[i];
    if (space.loss_time_micros >= 0 &&
        (deadline < 0 || space.loss_time_micros < deadline)) {
      deadline = space.loss_time_micros;
    }
    if (!space.sent_packets.empty() &&
        space.last_ack_eliciting_sent_time_micros >= 0) {
      const int64_t pto =
          space.last_ack_eliciting_sent_time_micros +
          ProbeTimeoutMicros(static_cast<ssl_encryption_level_t>(i));
      if (deadline < 0 || pto < deadline) {
        deadline = pto;
      }
    }
  }
  return deadline;
}

int64_t QuicRecovery::LossTimeMicros(ssl_encryption_level_t level) const {
  return packet_number_spaces_[QuicPacketNumberSpaceIndex(level)]
      .loss_time_micros;
}

bool QuicRecovery::GetProbe(int64_t now_micros,
                            QuicRecoveryProbe* probe) const {
  int64_t deadline = -1;
  int probe_level = -1;
  const QuicSentPacket* probe_packet = nullptr;
  for (int i = 0; i < 4; i++) {
    if (i == ssl_encryption_early_data || packet_number_space_discarded_[i]) {
      continue;
    }
    const PacketNumberSpace& space = packet_number_spaces_[i];
    if (space.sent_packets.empty() ||
        space.last_ack_eliciting_sent_time_micros < 0) {
      continue;
    }
    const int64_t candidate =
        space.last_ack_eliciting_sent_time_micros +
        ProbeTimeoutMicros(static_cast<ssl_encryption_level_t>(i));
    if (deadline < 0 || candidate < deadline) {
      deadline = candidate;
      probe_level = i;
      probe_packet = &space.sent_packets.begin()->second;
    }
  }
  if (deadline < 0 || deadline > now_micros || probe_level < 0) {
    return false;
  }
  probe->encryption_level = static_cast<ssl_encryption_level_t>(probe_level);
  if (probe_packet != nullptr) {
    probe->packet = *probe_packet;
    probe->has_packet = true;
  }
  return true;
}

void QuicRecovery::OnProbeSent() {
  pto_count_++;
}

bool QuicRecovery::PacketNumberIsAcked(
    uint64_t packet_number,
    const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges) {
  for (const auto& range : ack_ranges) {
    if (packet_number >= range.first && packet_number <= range.second) {
      return true;
    }
  }
  return false;
}

void QuicRecovery::RemoveBytesInFlight(const QuicSentPacket& packet) {
  bytes_in_flight_ =
      packet.bytes > bytes_in_flight_ ? 0 : bytes_in_flight_ - packet.bytes;
}

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)
