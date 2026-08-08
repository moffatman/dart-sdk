// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_DATAGRAM_SECURE_SOCKET_FILTER_H_
#define RUNTIME_BIN_DATAGRAM_SECURE_SOCKET_FILTER_H_

#include "bin/secure_socket_filter.h"

#include <deque>
#include <limits>
#include <map>
#include <vector>

#include "bin/quic_packet.h"
#include "bin/quic_packet_crypto.h"
#include "bin/quic_recovery.h"
#include "bin/quic_stream.h"
#include "bin/quic_transport_parameters.h"
#include "bin/socket.h"

namespace dart {
namespace bin {

class QuicPumpReactor;

struct QuicCryptoSendState {
  uint64_t offset = 0;
  std::deque<std::vector<uint8_t>> chunks;
};

struct QuicCryptoReceiveState {
  uint64_t offset = 0;
  std::map<uint64_t, std::vector<uint8_t>> pending;
};

struct QuicPendingPacket {
  std::vector<uint8_t> payload;
  bool ack_eliciting = true;
  bool retransmittable = true;
  uint32_t path_id = 0;
  bool bypass_congestion = false;
  bool control = true;
};

struct QuicDatagram {
  std::vector<uint8_t> payload;
  uint32_t path_id = 0;
};

enum class QuicPacketWriteResult {
  kSent,
  kBlocked,
  kError,
};

struct QuicNativePath {
  Socket* socket = nullptr;
  RawAddr remote_address;
};

enum class QuicTerminationType : int {
  kNone = 0,
  kTransportClose = 1,
  kApplicationClose = 2,
  kIdleTimeout = 3,
  kVersionNegotiation = 4,
  kStatelessReset = 5,
};

struct QuicPeerConnectionId {
  std::vector<uint8_t> connection_id;
  std::vector<uint8_t> stateless_reset_token;
  bool retired = false;
};

struct QuicLocalConnectionId {
  std::vector<uint8_t> connection_id;
  std::vector<uint8_t> stateless_reset_token;
  bool retired = false;
};

struct QuicTerminationInfo {
  QuicTerminationType type = QuicTerminationType::kNone;
  uint64_t error_code = 0;
  int64_t frame_type = -1;
  std::vector<uint8_t> reason;
};

struct QuicFrameError {
  uint64_t error_code = 0x07;
  uint64_t frame_type = 0;
  const char* reason = "malformed QUIC frame";
};

class DatagramSSLFilter : public BaseSSLFilter {
 public:
  explicit DatagramSSLFilter(bool use_native_udp)
      : use_native_udp_(use_native_udp),
        local_receive_window_(kQuicInitialMaxData),
        local_max_data_(local_receive_window_) {}

  intptr_t ApproximateSize() const;

  void Connect(const char* hostname,
               SSLCertContext* context,
               bool is_server,
               Dart_Handle protocols_handle,
               Dart_Handle settings_handle,
               bool use_ech_grease,
               const std::vector<uint8_t>& initial_token,
               const std::vector<uint8_t>& resumption_state,
               bool enable_early_data);
  void FreeResources() override;
  void Destroy();

  void ProcessPostHandshake();
  void AttachNativeSocket(uint32_t path_id,
                          Socket* socket,
                          const RawAddr& remote_address);
  bool StartNativePump(Dart_Port notification_port);
  void StopNativePump();
  Mutex* process_mutex() override { return &process_mutex_; }

  std::vector<uint8_t> PeerQuicTransportParams();
  std::vector<uint8_t> PeerPreferredAddress();
  bool IsInEarlyData() const;
  bool EarlyDataAccepted() const;
  void HandleEarlyDataRejected() override;
  void HandleNewSession(SSL_SESSION* session) override;

  void CloseQuic(int error_code, const char* reason);
  int64_t OpenStream(bool bidirectional);
  bool TakeConnectionTermination(QuicTerminationInfo* info);
  bool IsConnectionTerminated() const { return connection_terminated_; }
  void StartPathValidation(uint32_t path_id);
  bool TakePathValidationResult(uint32_t* path_id, bool* succeeded);
  bool HasReadableStreams();
  bool TakeInternalProgress() override {
    const bool result = internal_progress_;
    internal_progress_ = false;
    return result;
  }
  bool TakeWriteReady() override {
    const bool result = write_ready_;
    write_ready_ = false;
    return result;
  }
  void ProcessTimers() override;
  int64_t NextTimeoutMillis() override;
  bool ProcessAllBuffers(int starts[kNumBuffers],
                         int ends[kNumBuffers],
                         bool in_handshake) override;
  bool PrepareStreamBuffers(const CObjectArray& request,
                            intptr_t request_offset,
                            intptr_t stream_count) override;
  bool ProcessStreamBuffers(const CObjectArray& request,
                            intptr_t request_offset,
                            intptr_t stream_count,
                            bool in_handshake,
                            CObjectArray* result,
                            intptr_t result_offset) override;
  bool FlushOutgoingDatagrams(int starts[kNumBuffers],
                              int ends[kNumBuffers]) override;
  intptr_t FilterRequestHeaderSize() const override;
  intptr_t FilterResponseHeaderSize() const override;
  bool ProcessConnectionCommands(const CObjectArray& request,
                                 CObjectArray* result) override;
  bool ProcessConnectionEvents(CObjectArray* result) override;
  CObject* ProcessQuicEvents(const CObjectArray& request) override;
  void AfterFilterRequest() override;
  intptr_t StreamWrite(int64_t stream_id,
                       const uint8_t* data,
                       intptr_t offset,
                       intptr_t len,
                       bool fin);
  bool StreamClose(int64_t stream_id);
  void StreamReset(int64_t stream_id, int64_t error_code);
  void StreamStopSending(int64_t stream_id, int64_t error_code);

 protected:
  virtual Dart_Handle InitializeBuffers(Dart_Handle dart_this) override;

 private:
  friend class QuicPumpReactor;

  static int SetReadSecret(SSL* ssl,
                           ssl_encryption_level_t level,
                           const SSL_CIPHER* cipher,
                           const uint8_t* secret,
                           size_t secret_len);
  static int SetWriteSecret(SSL* ssl,
                            ssl_encryption_level_t level,
                            const SSL_CIPHER* cipher,
                            const uint8_t* secret,
                            size_t secret_len);
  static int AddHandshakeData(SSL* ssl,
                              ssl_encryption_level_t level,
                              const uint8_t* data,
                              size_t len);
  static int FlushFlight(SSL* ssl);
  static int SendAlert(SSL* ssl, ssl_encryption_level_t level, uint8_t alert);

  static DatagramSSLFilter* FromSSL(const SSL* ssl);
  static const SSL_QUIC_METHOD* QuicMethod();

  void QueueCrypto(ssl_encryption_level_t level,
                   const uint8_t* data,
                   size_t len);
  void QueueAck(ssl_encryption_level_t level,
                uint64_t packet_number,
                uint32_t path_id);
  void EmitAck(ssl_encryption_level_t level, uint32_t path_id);
  void FlushDueAcks();
  void PacketizeCryptoFlights();
  bool QueueProtectedPacket(
      ssl_encryption_level_t level,
      const std::vector<uint8_t>& payload,
      bool ack_eliciting,
      bool retransmittable,
      bool bypass_congestion = false,
      uint32_t path_id = std::numeric_limits<uint32_t>::max(),
      bool control = true);
  void FlushPendingPackets();
  bool HasNetworkOutputSlot() const;
  bool OnAckReceived(
      ssl_encryption_level_t level,
      const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges,
      uint64_t ack_delay);
  bool RequeueLostPackets(std::vector<QuicSentPacket> lost_packets);
  void DiscardPacketNumberSpace(ssl_encryption_level_t level);
  bool DeriveNextApplicationReadKeys();
  void PromoteApplicationReadKeys();
  void RetirePreviousApplicationReadKeys();
  bool MaybeInitiateApplicationKeyUpdate();
  void StartPeerClose(QuicTerminationType type,
                      uint64_t error_code,
                      int64_t frame_type,
                      const uint8_t* reason,
                      size_t reason_len,
                      ssl_encryption_level_t level);
  void StartTransportError(ssl_encryption_level_t level,
                           uint64_t error_code,
                           uint64_t frame_type,
                           const char* reason);
  void StartIdleTimeout();
  void TerminateImmediately(QuicTerminationType type, const char* reason);
  void RefreshIdleDeadline(int64_t now_micros);
  bool HandleVersionNegotiation(const uint8_t* data, size_t len);
  bool HandleRetry(const uint8_t* data, size_t len);
  bool DetectStatelessReset(const uint8_t* data, size_t len);
  void ResetInitialStateAfterRetry(
      const std::vector<std::vector<uint8_t>>& retransmit_payloads);
  void MaybeIssueConnectionIds();
  bool SelectPeerConnectionId(uint64_t minimum_sequence);
  void BeginPathValidation(uint32_t path_id);
  void CompletePathValidation(bool succeeded);
  bool BuildProtectedPacketInto(ssl_encryption_level_t level,
                                const std::vector<uint8_t>& payload,
                                uint8_t* packet,
                                size_t packet_capacity,
                                size_t* packet_length);
  QuicPacketWriteResult WriteProtectedPacket(
      ssl_encryption_level_t level,
      const std::vector<uint8_t>& payload,
      bool ack_eliciting,
      bool retransmittable,
      uint32_t path_id);
  int ParseFrames(ssl_encryption_level_t level,
                  const uint8_t* data,
                  size_t len,
                  uint64_t local_connection_id_sequence,
                  uint32_t path_id,
                  bool* provided_crypto,
                  bool* ack_eliciting,
                  QuicFrameError* error);
  int AddCryptoData(ssl_encryption_level_t level,
                    uint64_t offset,
                    const uint8_t* data,
                    size_t len,
                    bool* provided_crypto);
  bool InstallReadSecret(ssl_encryption_level_t level,
                         const SSL_CIPHER* cipher,
                         const uint8_t* secret,
                         size_t secret_len);
  bool InstallWriteSecret(ssl_encryption_level_t level,
                          const SSL_CIPHER* cipher,
                          const uint8_t* secret,
                          size_t secret_len);
  void InstallInitialSecrets();
  int DecodeProtectedDatagram(const uint8_t* data,
                              size_t len,
                              uint32_t path_id,
                              std::vector<uint8_t>* deferred,
                              bool* provided_crypto);
  intptr_t QueueDatagramFrame(const uint8_t* data,
                              intptr_t offset,
                              intptr_t len);
  bool QueueStreamFrame(uint64_t stream_id,
                        uint64_t offset,
                        const uint8_t* data,
                        size_t len,
                        bool fin);
  bool ProcessBufferedStreamWrite(uint64_t stream_id, QuicStreamState* stream);
  bool ProcessBufferedStreamWrites();
  void QueueResetStreamFrame(uint64_t stream_id,
                             uint64_t error_code,
                             uint64_t final_size);
  void QueueStopSendingFrame(uint64_t stream_id, uint64_t error_code);
  bool AddStreamData(uint64_t frame_type,
                     uint64_t stream_id,
                     uint64_t offset,
                     const uint8_t* data,
                     size_t len,
                     bool fin,
                     QuicFrameError* error);
  bool HandleResetStream(uint64_t stream_id,
                         uint64_t error_code,
                         uint64_t final_size,
                         QuicFrameError* error);
  bool HandleStopSending(uint64_t stream_id,
                         uint64_t error_code,
                         QuicFrameError* error);
  bool ValidatePeerStreamLimit(uint64_t stream_id) const;
  void MaybeReturnStreamCredit(uint64_t stream_id);
  void ReleaseStreamBuffers(QuicStreamState* stream);
  bool RegisterStreamBuffers(uint64_t stream_id);
  int TakeStreamEvents(uint64_t stream_id,
                       QuicStreamState* stream,
                       int64_t* read_error_code,
                       int64_t* write_error_code);
  CObjectArray* NewRegisteredStreamList();
  size_t BufferedApplicationPacketBytes() const;
  bool CanBufferApplicationPacket(size_t payload_bytes) const;
  bool EnsurePeerTransportParameters();
  bool RestoreRememberedTransportParameters(const std::vector<uint8_t>& params);
  void CaptureResumptionState(SSL_SESSION* session);
  ssl_encryption_level_t ApplicationWriteLevel() const;
  void ReplayRejectedEarlyData();
  uint64_t InitialSendLimitForStream(uint64_t stream_id) const;
  uint64_t InitialReceiveLimitForStream(uint64_t stream_id) const;
  bool IsLocallyInitiatedStream(uint64_t stream_id) const;
  static bool IsBidirectionalStream(uint64_t stream_id) {
    return (stream_id & 0x02) == 0;
  }
  void MaybeIncreaseReceiveWindows(uint64_t stream_id, size_t consumed_bytes);
  bool CommitStreamReadCursor(uint64_t stream_id, int read_start);
  void InitializeStreamReceiveFlowControl(uint64_t stream_id,
                                          QuicStreamState* stream);
  void QueueMaxDataFrame(uint64_t maximum_data);
  void QueueMaxStreamDataFrame(uint64_t stream_id,
                               uint64_t maximum_stream_data);
  void QueueDataBlockedFrame(uint64_t maximum_data);
  void QueueStreamDataBlockedFrame(uint64_t stream_id,
                                   uint64_t maximum_stream_data);
  void QueueStreamsBlockedFrame(bool bidirectional, uint64_t maximum_streams);
  void QueueMaxStreamsFrame(bool bidirectional, uint64_t maximum_streams);
  bool ProcessNativeNetworkInput(size_t packet_budget);
  bool HasFullDartEvents() const;
  bool HasFastDartEvents() const;
  void WakeNativePump();
  bool in_handshake_ = false;
  const bool use_native_udp_;
  uint8_t* buffers_[kNumBuffers];
  QuicPacketKeys read_keys_[4];
  QuicPacketKeys write_keys_[4];
  QuicPacketKeys next_application_read_keys_;
  QuicPacketKeys previous_application_read_keys_;
  QuicCryptoSendState crypto_send_[4];
  QuicCryptoReceiveState crypto_receive_[4];
  QuicReceivedPacketTracker received_packet_trackers_[4];
  uint8_t ack_eliciting_since_last_ack_[4] = {0, 0, 0, 0};
  int64_t ack_deadline_micros_[4] = {-1, -1, -1, -1};
  uint64_t largest_ack_eliciting_packet_number_[4] = {0, 0, 0, 0};
  int64_t largest_ack_eliciting_packet_received_micros_[4] = {-1, -1, -1, -1};
  bool has_largest_ack_eliciting_packet_number_[4] = {false, false, false,
                                                      false};
  uint32_t pending_ack_path_id_[4] = {0, 0, 0, 0};
  std::deque<QuicPendingPacket> pending_packets_[4];
  uint64_t next_packet_number_[4] = {0, 0, 0, 0};
  uint64_t largest_received_packet_number_[4] = {0, 0, 0, 0};
  bool has_largest_received_packet_number_[4] = {false, false, false, false};
  bool handshake_confirmed_ = false;
  bool application_read_key_phase_ = false;
  bool application_write_key_phase_ = false;
  bool application_write_key_generation_acked_ = false;
  bool previous_application_read_key_phase_ = false;
  uint64_t application_write_key_generation_ = 0;
  uint64_t application_write_key_generation_start_packet_ = 0;
  int64_t previous_application_read_keys_expiry_micros_ = -1;
  std::vector<uint8_t> destination_connection_id_;
  std::vector<uint8_t> source_connection_id_;
  std::vector<uint8_t> original_destination_connection_id_;
  std::vector<uint8_t> peer_initial_source_connection_id_;
  std::vector<uint8_t> retry_source_connection_id_;
  std::vector<uint8_t> initial_token_;
  std::deque<std::vector<uint8_t>> new_tokens_;
  std::deque<std::vector<uint8_t>> resumption_states_;
  std::vector<uint8_t> last_resumption_state_;
  std::vector<std::vector<uint8_t>> early_data_payloads_;
  bool early_data_enabled_ = false;
  bool early_data_rejected_ = false;
  bool one_rtt_write_keys_installed_ = false;
  bool remembered_transport_parameters_loaded_ = false;
  QuicTransportParameters remembered_transport_parameters_;
  std::map<uint64_t, QuicPeerConnectionId> peer_connection_ids_;
  std::map<uint64_t, QuicLocalConnectionId> local_connection_ids_;
  uint64_t current_peer_connection_id_sequence_ = 0;
  uint64_t next_local_connection_id_sequence_ = 1;
  bool received_authenticated_packet_ = false;
  bool retry_processed_ = false;
  bool version_negotiation_processed_ = false;
  // Valid only while BaseSSLFilter::ProcessFilterRequest is processing this
  // filter. Outgoing packets are committed directly to this ring.
  int* network_output_starts_ = nullptr;
  int* network_output_ends_ = nullptr;
  std::deque<std::vector<uint8_t>> readable_datagrams_;
  std::deque<QuicDatagram> deferred_encrypted_datagrams_;
  uint32_t active_path_id_ = 0;
  std::map<uint32_t, QuicNativePath> native_paths_;
  bool native_udp_write_blocked_ = false;
  bool native_receive_blocked_ = false;
  bool published_native_receive_blocked_ = false;
  uint64_t native_receive_blocked_stream_id_ =
      std::numeric_limits<uint64_t>::max();
  bool path_validation_deferred_ = false;
  uint32_t deferred_path_validation_id_ = 0;
  bool path_validation_pending_ = false;
  uint32_t validating_path_id_ = 0;
  uint64_t validating_previous_peer_connection_id_sequence_ = 0;
  uint8_t path_challenge_[8] = {0};
  uint32_t path_validation_attempts_ = 0;
  int64_t path_validation_deadline_micros_ = -1;
  std::deque<std::pair<uint32_t, bool>> path_validation_results_;
  std::vector<uint8_t> peer_preferred_address_;
  bool internal_progress_ = false;
  bool handshake_crypto_progress_ = false;
  bool receive_backpressured_ = false;
  uint64_t receive_backpressured_stream_id_ =
      std::numeric_limits<uint64_t>::max();
  bool receive_reordered_ = false;
  bool write_ready_ = false;
  bool local_closing_ = false;
  bool draining_ = false;
  bool connection_terminated_ = false;
  bool termination_delivered_ = false;
  QuicTerminationInfo termination_info_;
  int64_t draining_deadline_micros_ = -1;
  int64_t closing_deadline_micros_ = -1;
  int64_t idle_deadline_micros_ = -1;
  std::vector<uint8_t> local_connection_close_payload_;
  uint64_t local_max_idle_timeout_millis_ = 0;
  uint64_t effective_idle_timeout_millis_ = 30000;
  bool peer_transport_parameters_parsed_ = false;
  QuicTransportParameters peer_transport_parameters_;
  uint64_t connection_send_offset_ = 0;
  uint64_t last_data_blocked_limit_ = std::numeric_limits<uint64_t>::max();
  const uint64_t local_receive_window_;
  uint64_t local_max_data_;
  uint64_t received_data_ = 0;
  uint64_t consumed_data_ = 0;
  QuicRecovery recovery_;
  QuicStreamManager stream_manager_;
  Mutex process_mutex_;
  Dart_Port native_pump_notification_port_ = ILLEGAL_PORT;
  bool native_pump_started_ = false;
  bool native_pump_notification_pending_ = false;

  DISALLOW_COPY_AND_ASSIGN(DatagramSSLFilter);
};

}  // namespace bin
}  // namespace dart

#endif  // RUNTIME_BIN_DATAGRAM_SECURE_SOCKET_FILTER_H_
