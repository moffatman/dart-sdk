// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#include "bin/quic_stream.h"

#include <algorithm>
#include <cstring>

namespace dart {
namespace bin {

bool QuicCircularBuffer::Allocate(int size, int initial_position) {
  if (size < 2 || initial_position < 0 || initial_position >= size) {
    return false;
  }
  data_ = std::shared_ptr<uint8_t>(new uint8_t[size],
                                   std::default_delete<uint8_t[]>());
  size_ = size;
  start_ = initial_position;
  end_ = initial_position;
  return true;
}

void QuicCircularBuffer::Reset() {
  data_.reset();
  size_ = 0;
  start_ = 0;
  end_ = 0;
}

size_t QuicCircularBuffer::Distance(int from, int to) const {
  return static_cast<size_t>(from > to ? size_ + to - from : to - from);
}

size_t QuicCircularBuffer::length() const {
  return size_ == 0 ? 0 : Distance(start_, end_);
}

size_t QuicCircularBuffer::free_space() const {
  return size_ < 2 ? 0 : static_cast<size_t>(size_ - 1) - length();
}

size_t QuicCircularBuffer::contiguous_readable() const {
  if (empty()) return 0;
  return static_cast<size_t>(start_ < end_ ? end_ - start_ : size_ - start_);
}

size_t QuicCircularBuffer::contiguous_writable() const {
  if (free_space() == 0) return 0;
  if (start_ > end_) {
    return static_cast<size_t>(start_ - end_ - 1);
  }
  return static_cast<size_t>(start_ == 0 ? size_ - end_ - 1 : size_ - end_);
}

bool QuicCircularBuffer::CommitStart(int position, size_t* consumed) {
  if (!IsPositionValid(position)) return false;
  *consumed = Distance(start_, position);
  if (*consumed > length()) return false;
  start_ = position;
  return true;
}

bool QuicCircularBuffer::CommitEnd(int position, size_t* produced) {
  if (!IsPositionValid(position)) return false;
  *produced = Distance(end_, position);
  if (*produced > free_space()) return false;
  end_ = position;
  return true;
}

void QuicCircularBuffer::Consume(size_t count) {
  start_ = static_cast<int>((start_ + count) % size_);
}

void QuicCircularBuffer::Produce(size_t count) {
  end_ = static_cast<int>((end_ + count) % size_);
}

void QuicStreamManager::Reset(bool is_server) {
  is_server_ = is_server;
  next_bidirectional_stream_id_ = is_server ? 1 : 0;
  next_unidirectional_stream_id_ = is_server ? 3 : 2;
  local_max_streams_bidi_ = 100;
  local_max_streams_uni_ = 100;
  last_streams_blocked_bidi_ = std::numeric_limits<uint64_t>::max();
  last_streams_blocked_uni_ = std::numeric_limits<uint64_t>::max();
  streams_.clear();
  newly_registered_streams_.clear();
}

bool QuicStreamManager::IsLocallyInitiated(uint64_t stream_id) const {
  return (stream_id & 0x01) == (is_server_ ? 1 : 0);
}

QuicStreamState* QuicStreamManager::Find(uint64_t stream_id) {
  auto stream = streams_.find(stream_id);
  return stream == streams_.end() ? nullptr : &stream->second;
}

const QuicStreamState* QuicStreamManager::Find(uint64_t stream_id) const {
  auto stream = streams_.find(stream_id);
  return stream == streams_.end() ? nullptr : &stream->second;
}

QuicStreamState& QuicStreamManager::GetOrCreate(uint64_t stream_id) {
  return streams_[stream_id];
}

QuicStreamOpenResult QuicStreamManager::Open(bool bidirectional,
                                             uint64_t peer_stream_limit) {
  QuicStreamOpenResult result;
  uint64_t& next_stream_id = bidirectional ? next_bidirectional_stream_id_
                                           : next_unidirectional_stream_id_;
  if ((next_stream_id >> 2) >= peer_stream_limit) {
    uint64_t& last_blocked =
        bidirectional ? last_streams_blocked_bidi_ : last_streams_blocked_uni_;
    result.stream_limit = peer_stream_limit;
    result.send_streams_blocked = last_blocked != peer_stream_limit;
    last_blocked = peer_stream_limit;
    return result;
  }

  const uint64_t stream_id = next_stream_id;
  next_stream_id += 4;
  QuicStreamState& stream = streams_[stream_id];
  stream.accepted = true;
  result.stream_id = static_cast<int64_t>(stream_id);
  return result;
}

void QuicStreamManager::PeerStreamLimitIncreased(bool bidirectional) {
  (bidirectional ? last_streams_blocked_bidi_ : last_streams_blocked_uni_) =
      std::numeric_limits<uint64_t>::max();
}

bool QuicStreamManager::ValidatePeerStreamLimit(uint64_t stream_id) const {
  if (IsLocallyInitiated(stream_id)) return true;
  const uint64_t limit = IsBidirectional(stream_id) ? local_max_streams_bidi_
                                                    : local_max_streams_uni_;
  return (stream_id >> 2) < limit;
}

QuicStreamCreditResult QuicStreamManager::MaybeReturnCredit(
    uint64_t stream_id) {
  QuicStreamCreditResult result;
  QuicStreamState* stream = Find(stream_id);
  if (stream == nullptr || IsLocallyInitiated(stream_id) ||
      stream->stream_credit_returned) {
    return result;
  }
  const bool receive_closed =
      stream->fin_delivered ||
      (stream->reset_received && stream->read_error_delivered);
  const bool send_closed =
      !IsBidirectional(stream_id) || stream->fin_sent || stream->reset_sent;
  if (!receive_closed || !send_closed) return result;

  result.bidirectional = IsBidirectional(stream_id);
  uint64_t& limit =
      result.bidirectional ? local_max_streams_bidi_ : local_max_streams_uni_;
  if (limit < (uint64_t{1} << 60)) {
    limit++;
    result.send_max_streams = true;
    result.stream_limit = limit;
  }
  stream->stream_credit_returned = true;
  return result;
}

void QuicStreamManager::MarkRegistered(uint64_t stream_id) {
  newly_registered_streams_.push_back(stream_id);
}

}  // namespace bin
}  // namespace dart
