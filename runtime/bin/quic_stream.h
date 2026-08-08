// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_QUIC_STREAM_H_
#define RUNTIME_BIN_QUIC_STREAM_H_

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <vector>

namespace dart {
namespace bin {

class QuicCircularBuffer {
 public:
  bool Allocate(int size, int initial_position);
  void Reset();

  uint8_t* data() const { return data_.get(); }
  int size() const { return size_; }
  int start() const { return start_; }
  int end() const { return end_; }
  bool empty() const { return start_ == end_; }
  size_t length() const;
  size_t free_space() const;
  size_t contiguous_readable() const;
  size_t contiguous_writable() const;

  bool CommitStart(int position, size_t* consumed);
  bool CommitEnd(int position, size_t* produced);
  void Consume(size_t count);
  void Produce(size_t count);
  void ClearAtStart() { end_ = start_; }
  void ClearAtEnd() { start_ = end_; }
  std::shared_ptr<uint8_t> RetainData() const { return data_; }

 private:
  bool IsPositionValid(int position) const {
    return position >= 0 && position < size_;
  }
  size_t Distance(int from, int to) const;

  std::shared_ptr<uint8_t> data_;
  int size_ = 0;
  int start_ = 0;
  int end_ = 0;
};

struct QuicStreamState {
  uint64_t send_offset = 0;
  uint64_t send_limit = 0;
  uint64_t receive_highest_offset = 0;
  uint64_t receive_offset = 0;
  uint64_t receive_limit = 0;
  uint64_t consumed_offset = 0;
  uint64_t receive_window = 0;
  uint64_t final_size = 0;
  uint64_t last_stream_data_blocked_limit =
      std::numeric_limits<uint64_t>::max();
  bool fin_received = false;
  bool fin_sent = false;
  bool fin_delivered = false;
  bool reset_received = false;
  bool reset_sent = false;
  bool stop_sending_received = false;
  bool stop_sending_sent = false;
  bool read_abandoned = false;
  bool read_error_delivered = false;
  bool write_error_delivered = false;
  bool stream_credit_returned = false;
  bool accepted = false;
  bool application_fin_pending = false;
  uint64_t reset_error_code = 0;
  uint64_t stop_sending_error_code = 0;
  // Cursor last returned to Dart. Native packet processing may advance the
  // actual ring end before Dart sends its next filter request.
  int published_read_end = -1;
  int published_write_start = -1;
  QuicCircularBuffer application_read_buffer;
  QuicCircularBuffer application_write_buffer;
};

struct QuicStreamOpenResult {
  int64_t stream_id = -1;
  bool send_streams_blocked = false;
  uint64_t stream_limit = 0;
};

struct QuicStreamCreditResult {
  bool send_max_streams = false;
  bool bidirectional = false;
  uint64_t stream_limit = 0;
};

class QuicStreamManager {
 public:
  QuicStreamManager() { Reset(false); }

  void Reset(bool is_server);
  bool IsLocallyInitiated(uint64_t stream_id) const;
  static bool IsBidirectional(uint64_t stream_id) {
    return (stream_id & 0x02) == 0;
  }

  QuicStreamState* Find(uint64_t stream_id);
  const QuicStreamState* Find(uint64_t stream_id) const;
  QuicStreamState& GetOrCreate(uint64_t stream_id);
  std::map<uint64_t, QuicStreamState>& all() { return streams_; }
  const std::map<uint64_t, QuicStreamState>& all() const { return streams_; }

  QuicStreamOpenResult Open(bool bidirectional, uint64_t peer_stream_limit);
  void PeerStreamLimitIncreased(bool bidirectional);
  bool ValidatePeerStreamLimit(uint64_t stream_id) const;
  QuicStreamCreditResult MaybeReturnCredit(uint64_t stream_id);

  void MarkRegistered(uint64_t stream_id);
  const std::vector<uint64_t>& newly_registered() const {
    return newly_registered_streams_;
  }
  void ClearNewlyRegistered() { newly_registered_streams_.clear(); }

 private:
  bool is_server_ = false;
  uint64_t next_bidirectional_stream_id_ = 0;
  uint64_t next_unidirectional_stream_id_ = 2;
  uint64_t local_max_streams_bidi_ = 100;
  uint64_t local_max_streams_uni_ = 100;
  uint64_t last_streams_blocked_bidi_ = std::numeric_limits<uint64_t>::max();
  uint64_t last_streams_blocked_uni_ = std::numeric_limits<uint64_t>::max();
  std::map<uint64_t, QuicStreamState> streams_;
  std::vector<uint64_t> newly_registered_streams_;
};

}  // namespace bin
}  // namespace dart

#endif  // RUNTIME_BIN_QUIC_STREAM_H_
