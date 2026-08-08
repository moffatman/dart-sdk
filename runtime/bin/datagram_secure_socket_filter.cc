// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include "bin/datagram_secure_socket_filter.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <limits>
#include <string>

#if !defined(DART_HOST_OS_WINDOWS)
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#endif

#include "bin/dartutils.h"
#include "bin/secure_socket_utils.h"
#include "bin/socket_base.h"
#include "bin/thread.h"
#include "bin/utils.h"
#include "platform/text_buffer.h"

#define RETURN_IF_ERROR(handle)                                                \
  {                                                                            \
    Dart_Handle __handle = handle;                                             \
    if (Dart_IsError((__handle))) {                                            \
      return __handle;                                                         \
    }                                                                          \
  }

namespace dart {
namespace bin {

static constexpr size_t kQuicDatagramSlotSize = 1536;
static constexpr size_t kQuicApplicationDatagramSlotCount = 1;
static constexpr size_t kQuicNativeHandshakeInputSlotCount = 1;
static constexpr size_t kQuicNetworkInputDatagramSlotCount = 64;
static constexpr size_t kQuicNetworkOutputDatagramSlotCount = 8;
static constexpr uint64_t kQuicIssuedConnectionIdTarget = 2;
static constexpr size_t kQuicDatagramSlotHeaderSize = 8;
static constexpr size_t kQuicDatagramSlotPayloadCapacity =
    kQuicDatagramSlotSize - kQuicDatagramSlotHeaderSize;

static size_t QuicDatagramSlotCountForBuffer(int index, bool use_native_udp) {
  if (use_native_udp && index == BaseSSLFilter::kReadEncrypted) {
    return kQuicNativeHandshakeInputSlotCount;
  }
  if (use_native_udp && index == BaseSSLFilter::kWriteEncrypted) {
    return 0;
  }
  if (index == BaseSSLFilter::kReadEncrypted) {
    return kQuicNetworkInputDatagramSlotCount;
  }
  if (index == BaseSSLFilter::kWriteEncrypted) {
    return kQuicNetworkOutputDatagramSlotCount;
  }
  return kQuicApplicationDatagramSlotCount;
}

class QuicDatagramSlotRing {
 public:
  QuicDatagramSlotRing(uint8_t* data,
                       int size,
                       int start,
                       int end,
                       size_t expected_slot_count)
      : data_(data),
        slot_count_(size / static_cast<int>(kQuicDatagramSlotSize)),
        cursor_limit_(2 * slot_count_),
        start_(start),
        end_(end) {
    if (expected_slot_count == 0) {
      valid_ = data != nullptr && size == 0 && start == 0 && end == 0;
      return;
    }
    valid_ = data != nullptr && size > 0 &&
             size % static_cast<int>(kQuicDatagramSlotSize) == 0 &&
             slot_count_ == static_cast<int>(expected_slot_count) &&
             start >= 0 && start < cursor_limit_ && end >= 0 &&
             end < cursor_limit_ && length() <= slot_count_;
  }

  bool valid() const { return valid_; }
  int start() const { return start_; }
  int end() const { return end_; }
  bool empty() const { return start_ == end_; }
  bool full() const { return length() == slot_count_; }

  bool Peek(const uint8_t** payload,
            size_t* payload_length,
            uint32_t* id) const {
    if (!valid_ || empty()) return false;
    const uint8_t* slot =
        data_ + (start_ % slot_count_) * kQuicDatagramSlotSize;
    *payload_length = ReadUint32(slot);
    *id = ReadUint32(slot + 4);
    if (*payload_length > kQuicDatagramSlotPayloadCapacity) return false;
    *payload = slot + kQuicDatagramSlotHeaderSize;
    return true;
  }

  void Consume() { start_ = (start_ + 1) % cursor_limit_; }

  bool Write(uint32_t id, const uint8_t* payload, size_t payload_length) {
    uint8_t* slot_payload = nullptr;
    size_t capacity = 0;
    if (!Reserve(id, &slot_payload, &capacity) || payload_length > capacity) {
      return false;
    }
    if (payload_length != 0) {
      memcpy(slot_payload, payload, payload_length);
    }
    Commit(payload_length);
    return true;
  }

  bool Reserve(uint32_t id, uint8_t** payload, size_t* capacity) {
    if (!valid_ || full() || reserved_) return false;
    uint8_t* slot = data_ + (end_ % slot_count_) * kQuicDatagramSlotSize;
    WriteUint32(slot + 4, id);
    *payload = slot + kQuicDatagramSlotHeaderSize;
    *capacity = kQuicDatagramSlotPayloadCapacity;
    reserved_ = true;
    return true;
  }

  bool Commit(size_t payload_length) {
    if (!reserved_ || payload_length > kQuicDatagramSlotPayloadCapacity) {
      return false;
    }
    uint8_t* slot = data_ + (end_ % slot_count_) * kQuicDatagramSlotSize;
    WriteUint32(slot, static_cast<uint32_t>(payload_length));
    end_ = (end_ + 1) % cursor_limit_;
    reserved_ = false;
    return true;
  }

 private:
  int length() const {
    return start_ > end_ ? cursor_limit_ + end_ - start_ : end_ - start_;
  }

  static uint32_t ReadUint32(const uint8_t* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3];
  }

  static void WriteUint32(uint8_t* bytes, uint32_t value) {
    bytes[0] = static_cast<uint8_t>(value >> 24);
    bytes[1] = static_cast<uint8_t>(value >> 16);
    bytes[2] = static_cast<uint8_t>(value >> 8);
    bytes[3] = static_cast<uint8_t>(value);
  }

  uint8_t* data_;
  int slot_count_;
  int cursor_limit_;
  int start_;
  int end_;
  bool reserved_ = false;
  bool valid_ = false;
};

static bool AppendQuicVarInt(uint8_t** cursor,
                             const uint8_t* limit,
                             uint64_t value) {
  const size_t length = QuicVarIntLength(value);
  if (static_cast<size_t>(limit - *cursor) < length) return false;
  uint64_t encoded = value;
  if (length == 2) {
    encoded |= 0x4000ULL;
  } else if (length == 4) {
    encoded |= 0x80000000ULL;
  } else if (length == 8) {
    encoded |= 0xc000000000000000ULL;
  }
  for (size_t i = 0; i < length; i++) {
    const size_t shift = 8 * (length - i - 1);
    *(*cursor)++ = static_cast<uint8_t>(encoded >> shift);
  }
  return true;
}
static constexpr size_t kQuicMaximumBufferedApplicationPacketBytes = 32 * KB;
static constexpr int64_t kQuicMaximumAckDelayMicros = 25000;
static constexpr int64_t kQuicNativeAckDelayMicros = 2000;
static constexpr uint8_t kQuicDefaultAckDelayExponent = 3;
// AES-GCM has a 2^23-packet confidentiality limit. Rotate one generation
// earlier so a stalled peer still leaves room for retransmissions and close.
static constexpr uint64_t kQuicApplicationKeyUpdatePacketLimit = uint64_t{1}
                                                                 << 22;

static bool SetQuicFrameError(QuicFrameError* error,
                              uint64_t error_code,
                              uint64_t frame_type,
                              const char* reason) {
  error->error_code = error_code;
  error->frame_type = frame_type;
  error->reason = reason;
  return false;
}
static constexpr size_t kQuicMaxStreamFrameData = 1024;
static constexpr int kQuicStreamApplicationReadBufferSize = 128 * KB;
static constexpr int kQuicStreamApplicationWriteBufferSize = 16 * KB;

static void QuicStreamBufferFinalizer(void* isolate_callback_data, void* peer) {
  delete static_cast<std::shared_ptr<uint8_t>*>(peer);
}

intptr_t DatagramSSLFilter::ApproximateSize() const {
  const size_t network_slot_count =
      use_native_udp_ ? kQuicNativeHandshakeInputSlotCount
                      : kQuicNetworkInputDatagramSlotCount +
                            kQuicNetworkOutputDatagramSlotCount;
  return sizeof(DatagramSSLFilter) +
         kQuicDatagramSlotSize *
             (2 * kQuicApplicationDatagramSlotCount + network_slot_count);
}

Dart_Handle DatagramSSLFilter::InitializeBuffers(Dart_Handle dart_this) {
  Dart_Handle buffers_string = DartUtils::NewString("buffers");
  RETURN_IF_ERROR(buffers_string);
  Dart_Handle dart_buffers_object = Dart_GetField(dart_this, buffers_string);
  RETURN_IF_ERROR(dart_buffers_object);

  Dart_Handle data_identifier = DartUtils::NewString("data");
  RETURN_IF_ERROR(data_identifier);

  for (int i = 0; i < kNumBuffers; i++) {
    const int size =
        static_cast<int>(kQuicDatagramSlotSize *
                         QuicDatagramSlotCountForBuffer(i, use_native_udp_));
    buffers_[i] = new uint8_t[std::max(size, 1)];
    ASSERT(buffers_[i] != nullptr);
    memset(buffers_[i], 0, size);
    dart_buffer_objects_[i] = nullptr;
  }

  Dart_Handle result = Dart_Null();
  for (int i = 0; i < kNumBuffers; ++i) {
    const int size =
        static_cast<int>(kQuicDatagramSlotSize *
                         QuicDatagramSlotCountForBuffer(i, use_native_udp_));
    result = Dart_ListGetAt(dart_buffers_object, i);
    if (Dart_IsError(result)) {
      break;
    }

    dart_buffer_objects_[i] = Dart_NewPersistentHandle(result);
    ASSERT(dart_buffer_objects_[i] != nullptr);

    Dart_Handle data =
        Dart_NewExternalTypedData(Dart_TypedData_kUint8, buffers_[i], size);
    if (Dart_IsError(data)) {
      return data;
    }
    result = Dart_SetField(result, data_identifier, data);
    if (Dart_IsError(result)) {
      return result;
    }
  }

  // Caller handles cleanup on an error.
  return result;
}

#if !defined(DART_HOST_OS_WINDOWS)
class QuicPumpReactor {
 public:
  static QuicPumpReactor& Instance() {
    static QuicPumpReactor* reactor = new QuicPumpReactor();
    return *reactor;
  }

  bool Register(DatagramSSLFilter* filter) {
    bool start_thread = false;
    {
      MonitorLocker ml(&monitor_);
      if (!EnsureWakePipeLocked()) return false;
      if (FindEntryLocked(filter) != entries_.end()) return false;
      filter->Retain();
      entries_.push_back(Entry{filter, true, true, 0});
      if (!thread_started_) {
        thread_started_ = true;
        start_thread = true;
      }
      SignalLocked();
    }
    if (start_thread) {
      Thread::Start("dart:io QUIC reactor", ReactorEntry,
                    reinterpret_cast<uword>(this));
    }
    return true;
  }

  void Unregister(DatagramSSLFilter* filter) {
    bool release_filter = false;
    {
      MonitorLocker ml(&monitor_);
      auto entry = FindEntryLocked(filter);
      if (entry == entries_.end()) return;
      entry->registered = false;
      entry->dirty = false;
      SignalLocked();
      while (true) {
        entry = FindEntryLocked(filter);
        if (entry == entries_.end()) return;
        if (entry->in_flight == 0) break;
        ml.Wait();
      }
      entries_.erase(entry);
      release_filter = true;
    }
    if (release_filter) filter->Release();
  }

  void Wake(DatagramSSLFilter* filter) {
    MonitorLocker ml(&monitor_);
    auto entry = FindEntryLocked(filter);
    if (entry == entries_.end() || !entry->registered) return;
    entry->dirty = true;
    SignalLocked();
  }

 private:
  struct Entry {
    DatagramSSLFilter* filter;
    bool registered;
    bool dirty;
    intptr_t in_flight;
  };

  struct Snapshot {
    DatagramSSLFilter* filter;
    bool dirty;
    bool active = false;
    std::vector<size_t> poll_indices;
  };

  QuicPumpReactor() = default;

  static void ReactorEntry(uword parameter) {
    reinterpret_cast<QuicPumpReactor*>(parameter)->Run();
  }

  bool EnsureWakePipeLocked() {
    if (wakeup_fds_[0] >= 0) return true;
    if (pipe(wakeup_fds_) != 0) return false;
    for (int fd : wakeup_fds_) {
      const int flags = fcntl(fd, F_GETFL, 0);
      if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
      }
    }
    return true;
  }

  void SignalLocked() {
    if (wakeup_fds_[1] < 0) return;
    const uint8_t value = 1;
    const ssize_t ignored = write(wakeup_fds_[1], &value, 1);
    USE(ignored);
  }

  std::vector<Entry>::iterator FindEntryLocked(DatagramSSLFilter* filter) {
    return std::find_if(
        entries_.begin(), entries_.end(),
        [filter](const Entry& entry) { return entry.filter == filter; });
  }

  void FinishSnapshots(const std::vector<Snapshot>& snapshots) {
    MonitorLocker ml(&monitor_);
    bool notify = false;
    for (const Snapshot& snapshot : snapshots) {
      auto entry = FindEntryLocked(snapshot.filter);
      if (entry == entries_.end()) continue;
      ASSERT(entry->in_flight > 0);
      entry->in_flight--;
      notify = notify || entry->in_flight == 0;
    }
    if (notify) ml.NotifyAll();
  }

  void Run() {
    while (true) {
      std::vector<Snapshot> snapshots;
      {
        MonitorLocker ml(&monitor_);
        for (Entry& entry : entries_) {
          if (!entry.registered) continue;
          entry.in_flight++;
          entry.filter->Retain();
          snapshots.push_back(Snapshot{entry.filter, entry.dirty});
          entry.dirty = false;
        }
      }

      std::vector<pollfd> poll_fds;
      poll_fds.push_back(pollfd{wakeup_fds_[0], POLLIN, 0});
      int timeout_millis = -1;
      for (Snapshot& snapshot : snapshots) {
        DatagramSSLFilter* filter = snapshot.filter;
        MutexLocker process_lock(&filter->process_mutex_);
        if (!filter->native_pump_started_) continue;
        snapshot.active = true;
        if (snapshot.dirty) timeout_millis = 0;
        std::set<intptr_t> seen_fds;
        for (const auto& path : filter->native_paths_) {
          const intptr_t fd = path.second.socket->fd();
          if (fd < 0 || !seen_fds.insert(fd).second) continue;
          snapshot.poll_indices.push_back(poll_fds.size());
          poll_fds.push_back(
              pollfd{static_cast<int>(fd),
                     static_cast<short>(
                         (filter->native_receive_blocked_ ? 0 : POLLIN) |
                         (filter->native_udp_write_blocked_ ? POLLOUT : 0)),
                     0});
        }
        const int64_t next_timeout = filter->NextTimeoutMillis();
        if (next_timeout >= 0) {
          const int connection_timeout = static_cast<int>(
              std::min<int64_t>(next_timeout, std::numeric_limits<int>::max()));
          if (timeout_millis < 0 || connection_timeout < timeout_millis) {
            timeout_millis = connection_timeout;
          }
        }
      }

      const int poll_result =
          poll(poll_fds.data(), poll_fds.size(), timeout_millis);
      const bool poll_failed = poll_result < 0 && errno != EINTR;
      if (poll_result >= 0 && (poll_fds[0].revents & POLLIN) != 0) {
        uint8_t wakeups[64];
        while (read(wakeup_fds_[0], wakeups, sizeof(wakeups)) > 0) {
        }
      }
      {
        MonitorLocker ml(&monitor_);
        for (Snapshot& snapshot : snapshots) {
          auto entry = FindEntryLocked(snapshot.filter);
          if (entry == entries_.end() || !entry->registered || !entry->dirty) {
            continue;
          }
          snapshot.dirty = true;
          entry->dirty = false;
        }
      }

      std::vector<DatagramSSLFilter*> failed_notifications;
      for (Snapshot& snapshot : snapshots) {
        DatagramSSLFilter* filter = snapshot.filter;
        Dart_Port notification_port = ILLEGAL_PORT;
        int32_t notification_type = 0;
        {
          MutexLocker process_lock(&filter->process_mutex_);
          if (!snapshot.active || !filter->native_pump_started_) continue;

          bool socket_event = false;
          bool socket_error = false;
          for (size_t poll_index : snapshot.poll_indices) {
            const short events = poll_fds[poll_index].revents;
            socket_event = socket_event || events != 0;
            if ((events & POLLOUT) != 0) {
              filter->native_udp_write_blocked_ = false;
            }
            socket_error =
                socket_error || (events & (POLLERR | POLLHUP | POLLNVAL)) != 0;
          }
          const bool timer_due = filter->NextTimeoutMillis() == 0;
          if (!poll_failed && !snapshot.dirty && !socket_event && !timer_due) {
            continue;
          }

          if (poll_failed) {
            filter->TerminateImmediately(QuicTerminationType::kTransportClose,
                                         "native UDP poll failed");
          } else if (socket_error) {
            filter->TerminateImmediately(QuicTerminationType::kTransportClose,
                                         "native UDP socket closed");
          } else {
            filter->ProcessTimers();
            filter->FlushPendingPackets();
            if (!filter->connection_terminated_ &&
                !filter->native_receive_blocked_ &&
                !filter->ProcessNativeNetworkInput(1024)) {
              filter->TerminateImmediately(QuicTerminationType::kTransportClose,
                                           "native UDP receive failed");
            }
            if (!filter->connection_terminated_) {
              if (!filter->in_handshake_) {
                filter->ProcessPostHandshake();
              }
              filter->FlushDueAcks();
              filter->FlushPendingPackets();
              if (!filter->ProcessBufferedStreamWrites()) {
                filter->TerminateImmediately(
                    QuicTerminationType::kTransportClose,
                    "native QUIC stream write failed");
              } else {
                filter->FlushPendingPackets();
              }
            }
          }

          if (!filter->native_pump_notification_pending_) {
            if (filter->HasFullDartEvents()) {
              notification_type = 1;
            } else if (filter->HasFastDartEvents()) {
              notification_type = 2;
            }
            if (notification_type != 0) {
              filter->native_pump_notification_pending_ = true;
              notification_port = filter->native_pump_notification_port_;
            }
          }
        }
        if (notification_port != ILLEGAL_PORT &&
            !DartUtils::PostInt32(notification_port, notification_type)) {
          MutexLocker process_lock(&filter->process_mutex_);
          filter->native_pump_started_ = false;
          failed_notifications.push_back(filter);
        }
      }

      FinishSnapshots(snapshots);
      for (DatagramSSLFilter* filter : failed_notifications) {
        Unregister(filter);
      }
      for (const Snapshot& snapshot : snapshots) {
        snapshot.filter->Release();
      }
    }
  }

  Monitor monitor_;
  std::vector<Entry> entries_;
  int wakeup_fds_[2] = {-1, -1};
  bool thread_started_ = false;
};
#endif

void DatagramSSLFilter::AttachNativeSocket(uint32_t path_id,
                                           Socket* socket,
                                           const RawAddr& remote_address) {
  MutexLocker process_lock(process_mutex());
  ASSERT(socket != nullptr);
  auto existing = native_paths_.find(path_id);
  if (existing != native_paths_.end()) {
    existing->second.socket->Release();
    native_paths_.erase(existing);
  }
  socket->Retain();
  native_paths_[path_id] = QuicNativePath{socket, remote_address};
  WakeNativePump();
}

bool DatagramSSLFilter::StartNativePump(Dart_Port notification_port) {
#if defined(DART_HOST_OS_WINDOWS)
  return false;
#else
  if (!use_native_udp_) {
    return false;
  }
  {
    MutexLocker process_lock(process_mutex());
    if (native_pump_started_) return true;
    native_pump_notification_port_ = notification_port;
    native_pump_notification_pending_ = false;
    native_pump_started_ = true;
  }
  if (!QuicPumpReactor::Instance().Register(this)) {
    MutexLocker process_lock(process_mutex());
    native_pump_started_ = false;
    native_pump_notification_port_ = ILLEGAL_PORT;
    return false;
  }
  return true;
#endif
}

void DatagramSSLFilter::StopNativePump() {
#if !defined(DART_HOST_OS_WINDOWS)
  if (!use_native_udp_) return;
  {
    MutexLocker process_lock(process_mutex());
    native_pump_started_ = false;
    native_pump_notification_port_ = ILLEGAL_PORT;
    native_pump_notification_pending_ = false;
  }
  QuicPumpReactor::Instance().Unregister(this);
#endif
}

void DatagramSSLFilter::WakeNativePump() {
#if !defined(DART_HOST_OS_WINDOWS)
  if (native_pump_started_) {
    QuicPumpReactor::Instance().Wake(this);
  }
#endif
}

void DatagramSSLFilter::Connect(const char* hostname,
                                SSLCertContext* context,
                                bool is_server,
                                Dart_Handle protocols_handle,
                                Dart_Handle settings_handle,
                                bool use_ech_grease,
                                const std::vector<uint8_t>& initial_token,
                                const std::vector<uint8_t>& resumption_state,
                                bool enable_early_data) {
  hostname_ = Utils::StrDup(hostname);
  is_server_ = is_server;
  stream_manager_.Reset(is_server);
  ASSERT(context != nullptr);
  ASSERT(context->context() != nullptr);
  ssl_ = SSL_new(context->context());

  SSL_set_ex_data(ssl_, filter_ssl_index, this);
  context->RegisterCallbacks(ssl_);
  SSL_set_ex_data(ssl_, ssl_cert_context_index, context);
  SSL_set_connect_state(ssl_);
  SSL_set_min_proto_version(ssl_, TLS1_3_VERSION);
  SSL_set_max_proto_version(ssl_, TLS1_3_VERSION);
  SSL_set1_groups_list(ssl_, "X25519MLKEM768:X25519:P-256:P-384:P-521");

  // QUIC-specific TLS setup. This replaces BIO setup in SSLFilter::Connect.
  SSL_set_quic_method(ssl_, QuicMethod());
  SSL_set_quic_use_legacy_codepoint(ssl_, 0);
  SSL_CTX* ssl_context = context->context();
  SSL_CTX_set_session_cache_mode(
      ssl_context,
      SSL_CTX_get_session_cache_mode(ssl_context) | SSL_SESS_CACHE_CLIENT);
  SSL_CTX_sess_set_new_cb(ssl_context, BaseSSLFilter::NewSessionCallback);
  SSL_set_enable_ech_grease(ssl_, use_ech_grease);
  SSLCertContext::SetAlps(settings_handle, ssl_);
  int status;
  // TLS SNI identifies a DNS name. IP-literal connections validate against
  // an iPAddress subjectAltName below, but must not send an SNI extension.
  if (!SocketBase::IsValidAddress(hostname_)) {
    status = SSL_set_tlsext_host_name(ssl_, hostname_);
    SecureSocketUtils::CheckStatusSSL(status, "TlsException",
                                      "Set SNI host name", ssl_);
  }
  X509_VERIFY_PARAM* certificate_checking_parameters = SSL_get0_param(ssl_);
  X509_VERIFY_PARAM_set_flags(
      certificate_checking_parameters,
      X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_TRUSTED_FIRST);
  X509_VERIFY_PARAM_set_hostflags(certificate_checking_parameters, 0);
  if (SocketBase::IsValidAddress(hostname_)) {
    status = X509_VERIFY_PARAM_set1_ip_asc(certificate_checking_parameters,
                                           hostname_);
  } else {
    status = X509_VERIFY_PARAM_set1_host(certificate_checking_parameters,
                                         hostname_, strlen(hostname_));
  }
  SecureSocketUtils::CheckStatusSSL(
      status, "TlsException", "Set hostname for certificate checking", ssl_);
  SSLCertContext::SetAlpnProtocolList(protocols_handle, ssl_, nullptr, false);
  initial_token_ = initial_token;

  if (enable_early_data && resumption_state.size() >= 12 &&
      memcmp(resumption_state.data(), "QRS1", 4) == 0) {
    const auto read_uint32 = [&](size_t offset) {
      return (static_cast<uint32_t>(resumption_state[offset]) << 24) |
             (static_cast<uint32_t>(resumption_state[offset + 1]) << 16) |
             (static_cast<uint32_t>(resumption_state[offset + 2]) << 8) |
             static_cast<uint32_t>(resumption_state[offset + 3]);
    };
    const size_t session_len = read_uint32(4);
    const size_t params_len = read_uint32(8);
    if (session_len <= resumption_state.size() - 12 &&
        params_len == resumption_state.size() - 12 - session_len) {
      SSL_SESSION* session = SSL_SESSION_from_bytes(
          resumption_state.data() + 12, session_len, context->context());
      std::vector<uint8_t> remembered_params(
          resumption_state.begin() + 12 + session_len, resumption_state.end());
      if (session != nullptr && SSL_SESSION_early_data_capable(session) &&
          RestoreRememberedTransportParameters(remembered_params) &&
          SSL_set_session(ssl_, session) == 1) {
        SSL_set_early_data_enabled(ssl_, 1);
        early_data_enabled_ = true;
      }
      SSL_SESSION_free(session);
    }
  }

  destination_connection_id_.resize(kQuicInitialConnectionIdLength);
  source_connection_id_.resize(kQuicInitialConnectionIdLength);
  if (RAND_bytes(destination_connection_id_.data(),
                 destination_connection_id_.size()) != 1 ||
      RAND_bytes(source_connection_id_.data(), source_connection_id_.size()) !=
          1) {
    Dart_PropagateError(
        Dart_NewApiError("Unable to generate QUIC connection IDs."));
  }
  original_destination_connection_id_ = destination_connection_id_;
  QuicLocalConnectionId initial_local_connection_id;
  initial_local_connection_id.connection_id = source_connection_id_;
  local_connection_ids_[0] = std::move(initial_local_connection_id);

  const std::vector<uint8_t> quic_params = BuildLocalQuicTransportParameters(
      source_connection_id_, local_max_data_, kQuicInitialMaxStreamData);
  if (SSL_set_quic_transport_params(ssl_, quic_params.data(),
                                    quic_params.size()) != 1) {
    Dart_PropagateError(
        Dart_NewApiError("Unable to set QUIC transport parameters."));
  }
  InstallInitialSecrets();
  RefreshIdleDeadline(TimerUtils::GetCurrentMonotonicMicros());
}

void DatagramSSLFilter::ProcessPostHandshake() {
  SSL_process_quic_post_handshake(ssl_);
  EnsurePeerTransportParameters();
  if (EarlyDataAccepted()) {
    early_data_payloads_.clear();
  }
}

intptr_t DatagramSSLFilter::FilterRequestHeaderSize() const {
  // Base fields, stream count, command flags, close code/reason, path id, and
  // requested bidirectional/unidirectional stream counts.
  return 18;
}

intptr_t DatagramSSLFilter::FilterResponseHeaderSize() const {
  // Base fields followed by registered streams, termination, path results,
  // tokens, resumption states, terminated, readable-event flags, and native
  // UDP backpressure and handshake CRYPTO progress state.
  return 21;
}

bool DatagramSSLFilter::RegisterStreamBuffers(uint64_t stream_id) {
  QuicStreamState* stream = stream_manager_.Find(stream_id);
  if (stream == nullptr) return false;
  QuicStreamState& state = *stream;
  if (state.application_read_buffer.data() != nullptr ||
      state.application_write_buffer.data() != nullptr) {
    return state.application_read_buffer.data() != nullptr &&
           state.application_write_buffer.data() != nullptr;
  }
  const int read_buffer_size =
      use_native_udp_ ? static_cast<int>(kQuicNativeStreamReadBufferSize + 1)
                      : kQuicStreamApplicationReadBufferSize;
  const int read_initial_position = read_buffer_size / 2;
  const int write_initial_position = kQuicStreamApplicationWriteBufferSize / 2;
  if (!state.application_read_buffer.Allocate(read_buffer_size,
                                              read_initial_position) ||
      !state.application_write_buffer.Allocate(
          kQuicStreamApplicationWriteBufferSize, write_initial_position)) {
    state.application_read_buffer.Reset();
    state.application_write_buffer.Reset();
    return false;
  }
  state.published_read_end = read_initial_position;
  state.published_write_start = write_initial_position;
  stream_manager_.MarkRegistered(stream_id);
  return true;
}

int DatagramSSLFilter::TakeStreamEvents(uint64_t stream_id,
                                        QuicStreamState* stream,
                                        int64_t* read_error_code,
                                        int64_t* write_error_code) {
  static constexpr int kFinReceived = 1;
  static constexpr int kReadErrorReceived = 2;
  static constexpr int kWriteErrorReceived = 4;

  int event_flags = 0;
  *read_error_code = -1;
  *write_error_code = -1;
  if (stream->reset_received && !stream->read_error_delivered) {
    stream->read_error_delivered = true;
    stream->fin_delivered = true;
    *read_error_code = static_cast<int64_t>(stream->reset_error_code);
    event_flags |= kReadErrorReceived;
    MaybeReturnStreamCredit(stream_id);
  } else if (stream->fin_received && !stream->fin_delivered &&
             stream->receive_offset == stream->final_size) {
    stream->fin_delivered = true;
    event_flags |= kFinReceived;
    MaybeReturnStreamCredit(stream_id);
  }
  if (stream->stop_sending_received && !stream->write_error_delivered) {
    stream->write_error_delivered = true;
    *write_error_code = static_cast<int64_t>(stream->stop_sending_error_code);
    event_flags |= kWriteErrorReceived;
    MaybeReturnStreamCredit(stream_id);
  }
  return event_flags;
}

CObjectArray* DatagramSSLFilter::NewRegisteredStreamList() {
  const uint64_t peer_initiator_bit = is_server_ ? 0 : 1;
  for (auto& entry : stream_manager_.all()) {
    QuicStreamState& stream = entry.second;
    if ((entry.first & 1) == peer_initiator_bit && !stream.accepted) {
      stream.accepted = true;
      if (!RegisterStreamBuffers(entry.first)) return nullptr;
    }
  }

  const std::vector<uint64_t>& newly_registered =
      stream_manager_.newly_registered();
  CObjectArray* streams =
      new CObjectArray(CObject::NewArray(newly_registered.size()));
  for (intptr_t i = 0; i < static_cast<intptr_t>(newly_registered.size());
       i++) {
    const uint64_t stream_id = newly_registered[i];
    QuicStreamState* stream = stream_manager_.Find(stream_id);
    if (stream == nullptr) return nullptr;
    QuicStreamState& state = *stream;
    CObjectArray* descriptor = new CObjectArray(CObject::NewArray(10));
    descriptor->SetAt(
        0,
        new CObjectInt64(CObject::NewInt64(static_cast<int64_t>(stream_id))));
    descriptor->SetAt(
        1, new CObjectExternalUint8Array(CObject::NewExternalUint8Array(
               state.application_read_buffer.size(),
               state.application_read_buffer.data(),
               new std::shared_ptr<uint8_t>(
                   state.application_read_buffer.RetainData()),
               QuicStreamBufferFinalizer)));
    descriptor->SetAt(
        2, new CObjectExternalUint8Array(CObject::NewExternalUint8Array(
               state.application_write_buffer.size(),
               state.application_write_buffer.data(),
               new std::shared_ptr<uint8_t>(
                   state.application_write_buffer.RetainData()),
               QuicStreamBufferFinalizer)));
    int64_t read_error_code = -1;
    int64_t write_error_code = -1;
    const int event_flags = TakeStreamEvents(
        stream_id, &state, &read_error_code, &write_error_code);
    descriptor->SetAt(3, new CObjectInt32(CObject::NewInt32(event_flags)));
    descriptor->SetAt(4, new CObjectInt64(CObject::NewInt64(read_error_code)));
    descriptor->SetAt(5, new CObjectInt64(CObject::NewInt64(write_error_code)));
    state.published_read_end = state.application_read_buffer.end();
    descriptor->SetAt(6, new CObjectInt32(CObject::NewInt32(
                             state.application_read_buffer.start())));
    descriptor->SetAt(7, new CObjectInt32(CObject::NewInt32(
                             state.application_read_buffer.end())));
    descriptor->SetAt(8, new CObjectInt32(CObject::NewInt32(
                             state.application_write_buffer.start())));
    descriptor->SetAt(9, new CObjectInt32(CObject::NewInt32(
                             state.application_write_buffer.end())));
    streams->SetAt(i, descriptor);
  }
  stream_manager_.ClearNewlyRegistered();
  return streams;
}

bool DatagramSSLFilter::ProcessConnectionCommands(const CObjectArray& request,
                                                  CObjectArray* result) {
  static constexpr int kCloseRequested = 1;
  static constexpr int kPathValidationRequested = 2;
  const int flags = CObjectIntptr(request[11]).Value();
  const intptr_t close_error_code = CObjectIntptr(request[12]).Value();
  CObjectUint8Array close_reason(request[13]);
  const intptr_t path_id = CObjectIntptr(request[14]).Value();
  const intptr_t open_bidirectional = CObjectIntptr(request[15]).Value();
  const intptr_t open_unidirectional = CObjectIntptr(request[16]).Value();
  const bool native_udp_write_ready = CObjectBool(request[17]).Value();
  if ((flags & ~(kCloseRequested | kPathValidationRequested)) != 0 ||
      close_error_code < 0 || path_id < -1 || path_id > UINT32_MAX ||
      open_bidirectional < 0 || open_bidirectional > 64 ||
      open_unidirectional < 0 || open_unidirectional > 64) {
    return false;
  }
  if (native_udp_write_ready) {
    native_udp_write_blocked_ = false;
  }
  if ((flags & kCloseRequested) != 0) {
    std::string reason(reinterpret_cast<const char*>(close_reason.Buffer()),
                       close_reason.Length());
    CloseQuic(close_error_code, reason.c_str());
  }
  if ((flags & kPathValidationRequested) != 0) {
    if (path_id < 0) return false;
    StartPathValidation(static_cast<uint32_t>(path_id));
  }
  for (intptr_t i = 0; i < open_bidirectional; i++) {
    const int64_t stream_id = OpenStream(true);
    if (stream_id >= 0 &&
        !RegisterStreamBuffers(static_cast<uint64_t>(stream_id))) {
      return false;
    }
  }
  for (intptr_t i = 0; i < open_unidirectional; i++) {
    const int64_t stream_id = OpenStream(false);
    if (stream_id >= 0 &&
        !RegisterStreamBuffers(static_cast<uint64_t>(stream_id))) {
      return false;
    }
  }
  return true;
}

bool DatagramSSLFilter::ProcessConnectionEvents(CObjectArray* result) {
  CObjectArray* registered_streams = NewRegisteredStreamList();
  if (registered_streams == nullptr) return false;
  const bool has_readable_events =
      registered_streams->Length() != 0 || HasReadableStreams() ||
      !new_tokens_.empty() || !resumption_states_.empty();
  result->SetAt(11, registered_streams);

  QuicTerminationInfo termination;
  if (TakeConnectionTermination(&termination)) {
    CObjectArray* value = new CObjectArray(CObject::NewArray(4));
    value->SetAt(0, new CObjectInt32(
                        CObject::NewInt32(static_cast<int>(termination.type))));
    value->SetAt(1,
                 new CObjectInt64(CObject::NewInt64(termination.error_code)));
    value->SetAt(2,
                 new CObjectInt64(CObject::NewInt64(termination.frame_type)));
    value->SetAt(3, new CObjectUint8Array(CObject::NewUint8Array(
                        termination.reason.data(), termination.reason.size())));
    result->SetAt(12, value);
  } else {
    result->SetAt(12, CObject::Null());
  }

  const intptr_t path_result_count = path_validation_results_.size();
  CObjectArray* path_results =
      new CObjectArray(CObject::NewArray(path_result_count));
  for (intptr_t i = 0; i < path_result_count; i++) {
    const auto value = path_validation_results_.front();
    path_validation_results_.pop_front();
    CObjectArray* entry = new CObjectArray(CObject::NewArray(2));
    entry->SetAt(0, new CObjectInt64(CObject::NewInt64(value.first)));
    entry->SetAt(1, new CObjectBool(CObject::Bool(value.second)));
    path_results->SetAt(i, entry);
  }
  result->SetAt(13, path_results);

  const intptr_t token_count = new_tokens_.size();
  CObjectArray* tokens = new CObjectArray(CObject::NewArray(token_count));
  for (intptr_t i = 0; i < token_count; i++) {
    std::vector<uint8_t> token = std::move(new_tokens_.front());
    new_tokens_.pop_front();
    tokens->SetAt(i, new CObjectUint8Array(
                         CObject::NewUint8Array(token.data(), token.size())));
  }
  result->SetAt(14, tokens);

  const intptr_t resumption_state_count = resumption_states_.size();
  CObjectArray* resumption_states =
      new CObjectArray(CObject::NewArray(resumption_state_count));
  for (intptr_t i = 0; i < resumption_state_count; i++) {
    std::vector<uint8_t> state = std::move(resumption_states_.front());
    resumption_states_.pop_front();
    resumption_states->SetAt(i, new CObjectUint8Array(CObject::NewUint8Array(
                                    state.data(), state.size())));
  }
  result->SetAt(15, resumption_states);
  result->SetAt(16, new CObjectBool(CObject::Bool(connection_terminated_)));
  result->SetAt(17, new CObjectBool(CObject::Bool(has_readable_events)));
  result->SetAt(18, new CObjectBool(CObject::Bool(native_udp_write_blocked_)));
  result->SetAt(19, new CObjectBool(CObject::Bool(native_receive_blocked_)));
  result->SetAt(20, new CObjectBool(CObject::Bool(handshake_crypto_progress_)));
  handshake_crypto_progress_ = false;
  return true;
}

bool DatagramSSLFilter::HasFullDartEvents() const {
  if ((in_handshake_ && internal_progress_) || !readable_datagrams_.empty() ||
      !new_tokens_.empty() || !resumption_states_.empty() ||
      !path_validation_results_.empty() || connection_terminated_ ||
      (termination_info_.type != QuicTerminationType::kNone &&
       !termination_delivered_)) {
    return true;
  }
  return false;
}

bool DatagramSSLFilter::HasFastDartEvents() const {
  if (native_receive_blocked_ != published_native_receive_blocked_ ||
      write_ready_ || !stream_manager_.newly_registered().empty()) {
    return true;
  }
  for (const auto& entry : stream_manager_.all()) {
    const QuicStreamState& stream = entry.second;
    if (stream.application_read_buffer.data() != nullptr &&
        stream.application_read_buffer.end() != stream.published_read_end) {
      return true;
    }
    if (stream.application_write_buffer.data() != nullptr &&
        stream.application_write_buffer.start() !=
            stream.published_write_start) {
      return true;
    }
    if ((stream.reset_received && !stream.read_error_delivered) ||
        (stream.stop_sending_received && !stream.write_error_delivered) ||
        (stream.fin_received && !stream.fin_delivered &&
         stream.receive_offset == stream.final_size)) {
      return true;
    }
  }
  return false;
}

CObject* DatagramSSLFilter::ProcessQuicEvents(const CObjectArray& request) {
  static constexpr intptr_t kRequestHeaderSize = 4;
  static constexpr intptr_t kResponseHeaderSize = 7;
  static constexpr intptr_t kStreamRequestSize = 8;
  static constexpr intptr_t kStreamResponseSize = 7;

  if (request.Length() < kRequestHeaderSize || !request[1]->IsIntptr() ||
      !request[2]->IsIntptr() || !request[3]->IsIntptr()) {
    return CObject::IllegalArgumentError();
  }
  const intptr_t open_bidirectional = CObjectIntptr(request[1]).Value();
  const intptr_t open_unidirectional = CObjectIntptr(request[2]).Value();
  const intptr_t stream_count = CObjectIntptr(request[3]).Value();
  if (open_bidirectional < 0 || open_bidirectional > 64 ||
      open_unidirectional < 0 || open_unidirectional > 64 || stream_count < 0 ||
      stream_count > 4096 ||
      request.Length() !=
          kRequestHeaderSize + stream_count * kStreamRequestSize) {
    return CObject::IllegalArgumentError();
  }

  int blocked_read_start_before = -1;
  if (native_receive_blocked_) {
    const QuicStreamState* blocked_stream =
        stream_manager_.Find(native_receive_blocked_stream_id_);
    if (blocked_stream != nullptr &&
        blocked_stream->application_read_buffer.data() != nullptr) {
      blocked_read_start_before =
          blocked_stream->application_read_buffer.start();
    }
  }

  for (intptr_t i = 0; i < open_bidirectional; i++) {
    const int64_t stream_id = OpenStream(true);
    if (stream_id >= 0 &&
        !RegisterStreamBuffers(static_cast<uint64_t>(stream_id))) {
      return CObject::IllegalArgumentError();
    }
  }
  for (intptr_t i = 0; i < open_unidirectional; i++) {
    const int64_t stream_id = OpenStream(false);
    if (stream_id >= 0 &&
        !RegisterStreamBuffers(static_cast<uint64_t>(stream_id))) {
      return CObject::IllegalArgumentError();
    }
  }

  CObjectArray* result = new CObjectArray(CObject::NewArray(
      kResponseHeaderSize + stream_count * kStreamResponseSize));
  if (!PrepareStreamBuffers(request, kRequestHeaderSize, stream_count) ||
      !ProcessStreamBuffers(request, kRequestHeaderSize, stream_count, false,
                            result, kResponseHeaderSize)) {
    return CObject::IllegalArgumentError();
  }

  if (native_receive_blocked_) {
    const QuicStreamState* blocked_stream =
        stream_manager_.Find(native_receive_blocked_stream_id_);
    if (blocked_stream != nullptr &&
        blocked_stream->application_read_buffer.data() != nullptr &&
        blocked_stream->application_read_buffer.start() !=
            blocked_read_start_before) {
      native_receive_blocked_ = false;
    }
  }
  if (!native_receive_blocked_) {
    native_receive_blocked_ = false;
    published_native_receive_blocked_ = false;
    native_receive_blocked_stream_id_ = std::numeric_limits<uint64_t>::max();
  }

  FlushPendingPackets();
  CObjectArray* registered_streams = NewRegisteredStreamList();
  if (registered_streams == nullptr) {
    return CObject::IllegalArgumentError();
  }

  struct StreamEvent {
    uint64_t id;
    int read_end;
    int write_start;
    int flags;
    int64_t read_error_code;
    int64_t write_error_code;
  };
  std::vector<StreamEvent> changed_streams;
  for (auto& entry : stream_manager_.all()) {
    QuicStreamState& stream = entry.second;
    if (stream.application_read_buffer.data() == nullptr) continue;
    int64_t read_error_code = -1;
    int64_t write_error_code = -1;
    const int event_flags = TakeStreamEvents(
        entry.first, &stream, &read_error_code, &write_error_code);
    if (stream.application_read_buffer.end() == stream.published_read_end &&
        stream.application_write_buffer.start() ==
            stream.published_write_start &&
        event_flags == 0) {
      continue;
    }
    changed_streams.push_back(
        StreamEvent{entry.first, stream.application_read_buffer.end(),
                    stream.application_write_buffer.start(), event_flags,
                    read_error_code, write_error_code});
    stream.published_read_end = stream.application_read_buffer.end();
    stream.published_write_start = stream.application_write_buffer.start();
  }

  CObjectArray* streams =
      new CObjectArray(CObject::NewArray(changed_streams.size()));
  for (intptr_t i = 0; i < static_cast<intptr_t>(changed_streams.size()); i++) {
    CObjectArray* stream = new CObjectArray(CObject::NewArray(6));
    stream->SetAt(0, new CObjectInt64(CObject::NewInt64(
                         static_cast<int64_t>(changed_streams[i].id))));
    stream->SetAt(
        1, new CObjectInt32(CObject::NewInt32(changed_streams[i].read_end)));
    stream->SetAt(
        2, new CObjectInt32(CObject::NewInt32(changed_streams[i].write_start)));
    stream->SetAt(
        3, new CObjectInt32(CObject::NewInt32(changed_streams[i].flags)));
    stream->SetAt(4, new CObjectInt64(CObject::NewInt64(
                         changed_streams[i].read_error_code)));
    stream->SetAt(5, new CObjectInt64(CObject::NewInt64(
                         changed_streams[i].write_error_code)));
    streams->SetAt(i, stream);
  }

  const bool full_request_required = HasFullDartEvents();
  int blocked_read_start = -1;
  if (native_receive_blocked_) {
    const QuicStreamState* blocked_stream =
        stream_manager_.Find(native_receive_blocked_stream_id_);
    if (blocked_stream != nullptr &&
        blocked_stream->application_read_buffer.data() != nullptr) {
      blocked_read_start = blocked_stream->application_read_buffer.start();
    }
  }

  result->SetAt(0, new CObjectBool(CObject::Bool(full_request_required)));
  result->SetAt(1, new CObjectBool(CObject::Bool(native_receive_blocked_)));
  result->SetAt(
      2, new CObjectInt64(CObject::NewInt64(
             native_receive_blocked_
                 ? static_cast<int64_t>(native_receive_blocked_stream_id_)
                 : -1)));
  result->SetAt(3, new CObjectInt32(CObject::NewInt32(blocked_read_start)));
  result->SetAt(4, registered_streams);
  result->SetAt(5, new CObjectBool(CObject::Bool(TakeWriteReady())));
  result->SetAt(6, streams);
  if (!full_request_required) {
    published_native_receive_blocked_ = native_receive_blocked_;
    native_pump_notification_pending_ = false;
    WakeNativePump();
  } else if (open_bidirectional != 0 || open_unidirectional != 0 ||
             stream_count != 0) {
    WakeNativePump();
  }
  return result;
}

void DatagramSSLFilter::AfterFilterRequest() {
  native_pump_notification_pending_ = false;
  native_receive_blocked_ = false;
  published_native_receive_blocked_ = false;
  native_receive_blocked_stream_id_ = std::numeric_limits<uint64_t>::max();
  WakeNativePump();
}

std::vector<uint8_t> DatagramSSLFilter::PeerQuicTransportParams() {
  const uint8_t* params = nullptr;
  size_t params_len = 0;
  SSL_get_peer_quic_transport_params(ssl_, &params, &params_len);
  if (params == nullptr || params_len == 0) return std::vector<uint8_t>();
  return std::vector<uint8_t>(params, params + params_len);
}

std::vector<uint8_t> DatagramSSLFilter::PeerPreferredAddress() {
  if (!EnsurePeerTransportParameters()) {
    return std::vector<uint8_t>();
  }
  return peer_preferred_address_;
}

bool DatagramSSLFilter::IsInEarlyData() const {
  return early_data_enabled_ && SSL_in_early_data(ssl_) == 1;
}

bool DatagramSSLFilter::EarlyDataAccepted() const {
  return early_data_enabled_ && SSL_early_data_accepted(ssl_) == 1;
}

void DatagramSSLFilter::HandleEarlyDataRejected() {
  early_data_rejected_ = true;
}

void DatagramSSLFilter::HandleNewSession(SSL_SESSION* session) {
  CaptureResumptionState(session);
}

ssl_encryption_level_t DatagramSSLFilter::ApplicationWriteLevel() const {
  return write_keys_[ssl_encryption_early_data].installed &&
                 !one_rtt_write_keys_installed_ && !early_data_rejected_
             ? ssl_encryption_early_data
             : ssl_encryption_application;
}

void DatagramSSLFilter::ReplayRejectedEarlyData() {
  recovery_.RemovePacketsAtEncryptionLevel(ssl_encryption_early_data);
  pending_packets_[ssl_encryption_early_data].clear();
  write_keys_[ssl_encryption_early_data] = QuicPacketKeys();
  std::vector<std::vector<uint8_t>> payloads = std::move(early_data_payloads_);
  early_data_payloads_.clear();
  for (const auto& payload : payloads) {
    QueueProtectedPacket(ssl_encryption_application, payload, true, true, true);
  }
  internal_progress_ = true;
}

bool DatagramSSLFilter::RestoreRememberedTransportParameters(
    const std::vector<uint8_t>& params) {
  QuicTransportParameters parsed;
  if (!ParseQuicTransportParameters(params.data(), params.size(), &parsed)) {
    return false;
  }
  remembered_transport_parameters_ = parsed;
  remembered_transport_parameters_loaded_ = true;
  peer_transport_parameters_ = std::move(parsed);
  peer_transport_parameters_parsed_ = true;
  return true;
}

void DatagramSSLFilter::CaptureResumptionState(SSL_SESSION* session) {
  if (!EnsurePeerTransportParameters()) {
    return;
  }
  if (session == nullptr || !SSL_SESSION_is_resumable(session) ||
      !SSL_SESSION_early_data_capable(session)) {
    return;
  }
  uint8_t* session_bytes = nullptr;
  size_t session_len = 0;
  if (SSL_SESSION_to_bytes(session, &session_bytes, &session_len) != 1) {
    return;
  }
  const std::vector<uint8_t> params = PeerQuicTransportParams();
  if (session_len > std::numeric_limits<uint32_t>::max() ||
      params.size() > std::numeric_limits<uint32_t>::max() ||
      session_len + params.size() + 12 > 64 * 1024) {
    OPENSSL_free(session_bytes);
    return;
  }
  std::vector<uint8_t> state;
  state.insert(state.end(), {'Q', 'R', 'S', '1'});
  AppendUint32(&state, static_cast<uint32_t>(session_len));
  AppendUint32(&state, static_cast<uint32_t>(params.size()));
  state.insert(state.end(), session_bytes, session_bytes + session_len);
  state.insert(state.end(), params.begin(), params.end());
  OPENSSL_free(session_bytes);
  if (state != last_resumption_state_) {
    last_resumption_state_ = state;
    resumption_states_.push_back(std::move(state));
    internal_progress_ = true;
  }
}

bool DatagramSSLFilter::EnsurePeerTransportParameters() {
  if (peer_transport_parameters_parsed_) {
    return true;
  }
  const uint8_t* params = nullptr;
  size_t params_len = 0;
  SSL_get_peer_quic_transport_params(ssl_, &params, &params_len);
  if (params == nullptr) {
    return false;
  }

  QuicTransportParameters parsed;
  if (!ParseQuicTransportParameters(params, params_len, &parsed) ||
      !parsed.has_original_destination_connection_id ||
      parsed.original_destination_connection_id !=
          original_destination_connection_id_ ||
      !parsed.has_initial_source_connection_id ||
      parsed.initial_source_connection_id !=
          peer_initial_source_connection_id_ ||
      retry_processed_ != parsed.has_retry_source_connection_id ||
      (retry_processed_ &&
       parsed.retry_source_connection_id != retry_source_connection_id_)) {
    return false;
  }

  if (remembered_transport_parameters_loaded_ && EarlyDataAccepted()) {
    const QuicTransportParameters& remembered =
        remembered_transport_parameters_;
    if (parsed.initial_max_data < remembered.initial_max_data ||
        parsed.initial_max_stream_data_bidi_local <
            remembered.initial_max_stream_data_bidi_local ||
        parsed.initial_max_stream_data_bidi_remote <
            remembered.initial_max_stream_data_bidi_remote ||
        parsed.initial_max_stream_data_uni <
            remembered.initial_max_stream_data_uni ||
        parsed.initial_max_streams_bidi < remembered.initial_max_streams_bidi ||
        parsed.initial_max_streams_uni < remembered.initial_max_streams_uni ||
        parsed.active_connection_id_limit <
            remembered.active_connection_id_limit ||
        parsed.max_datagram_frame_size < remembered.max_datagram_frame_size) {
      CloseQuic(0x08, "0-RTT transport parameters reduced");
      return false;
    }
  }

  peer_transport_parameters_ = std::move(parsed);
  const QuicTransportParameters& peer = peer_transport_parameters_;
  if (local_max_idle_timeout_millis_ == 0) {
    effective_idle_timeout_millis_ = peer.max_idle_timeout;
  } else if (peer.max_idle_timeout == 0) {
    effective_idle_timeout_millis_ = local_max_idle_timeout_millis_;
  } else {
    effective_idle_timeout_millis_ =
        std::min(local_max_idle_timeout_millis_, peer.max_idle_timeout);
  }
  RefreshIdleDeadline(TimerUtils::GetCurrentMonotonicMicros());

  for (auto& entry : stream_manager_.all()) {
    entry.second.send_limit = std::max(entry.second.send_limit,
                                       InitialSendLimitForStream(entry.first));
  }
  auto initial_peer_connection_id = peer_connection_ids_.find(0);
  if (initial_peer_connection_id != peer_connection_ids_.end() &&
      !peer.stateless_reset_token.empty()) {
    initial_peer_connection_id->second.stateless_reset_token =
        peer.stateless_reset_token;
  }
  if (!peer.preferred_address.empty()) {
    for (const auto& entry : peer_connection_ids_) {
      if (entry.second.connection_id == peer.preferred_connection_id) {
        return false;
      }
    }
    QuicPeerConnectionId preferred;
    preferred.connection_id = peer.preferred_connection_id;
    preferred.stateless_reset_token = peer.preferred_stateless_reset_token;
    peer_connection_ids_[1] = std::move(preferred);
    peer_preferred_address_ = peer.preferred_address;
  }
  peer_transport_parameters_parsed_ = true;
  MaybeIssueConnectionIds();
  return true;
}

bool DatagramSSLFilter::IsLocallyInitiatedStream(uint64_t stream_id) const {
  return stream_manager_.IsLocallyInitiated(stream_id);
}

uint64_t DatagramSSLFilter::InitialSendLimitForStream(
    uint64_t stream_id) const {
  if (IsBidirectionalStream(stream_id)) {
    return IsLocallyInitiatedStream(stream_id)
               ? peer_transport_parameters_.initial_max_stream_data_bidi_remote
               : peer_transport_parameters_.initial_max_stream_data_bidi_local;
  }
  return IsLocallyInitiatedStream(stream_id)
             ? peer_transport_parameters_.initial_max_stream_data_uni
             : 0;
}

uint64_t DatagramSSLFilter::InitialReceiveLimitForStream(
    uint64_t stream_id) const {
  if (IsBidirectionalStream(stream_id)) {
    return kQuicInitialMaxStreamData;
  }
  return IsLocallyInitiatedStream(stream_id) ? 0 : kQuicInitialMaxStreamData;
}

void DatagramSSLFilter::InitializeStreamReceiveFlowControl(
    uint64_t stream_id,
    QuicStreamState* stream) {
  if (stream->receive_window != 0 || (!IsBidirectionalStream(stream_id) &&
                                      IsLocallyInitiatedStream(stream_id))) {
    return;
  }
  stream->receive_window = kQuicInitialMaxStreamData;
  stream->receive_limit = InitialReceiveLimitForStream(stream_id);
}

intptr_t DatagramSSLFilter::QueueDatagramFrame(const uint8_t* data,
                                               intptr_t offset,
                                               intptr_t len) {
  if (data == nullptr || offset < 0 || len <= 0) return 0;
  if (!remembered_transport_parameters_loaded_ &&
      !EnsurePeerTransportParameters()) {
    return len;
  }
  std::vector<uint8_t> payload;
  AppendDatagramFrame(&payload, data + offset, static_cast<size_t>(len));
  if (peer_transport_parameters_.max_datagram_frame_size != 0 &&
      payload.size() <= peer_transport_parameters_.max_datagram_frame_size &&
      CanBufferApplicationPacket(payload.size())) {
    QueueProtectedPacket(ApplicationWriteLevel(), payload, true, false, false,
                         std::numeric_limits<uint32_t>::max(), false);
  }
  return len;
}

int64_t DatagramSSLFilter::OpenStream(bool bidirectional) {
  if (!remembered_transport_parameters_loaded_ &&
      !EnsurePeerTransportParameters()) {
    return -1;
  }
  const uint64_t stream_limit =
      bidirectional ? peer_transport_parameters_.initial_max_streams_bidi
                    : peer_transport_parameters_.initial_max_streams_uni;
  const QuicStreamOpenResult opened =
      stream_manager_.Open(bidirectional, stream_limit);
  if (opened.send_streams_blocked) {
    QueueStreamsBlockedFrame(bidirectional, opened.stream_limit);
  }
  if (opened.stream_id >= 0) {
    const uint64_t stream_id = static_cast<uint64_t>(opened.stream_id);
    QuicStreamState* stream = stream_manager_.Find(stream_id);
    ASSERT(stream != nullptr);
    stream->send_limit = InitialSendLimitForStream(stream_id);
    InitializeStreamReceiveFlowControl(stream_id, stream);
  }
  return opened.stream_id;
}

bool DatagramSSLFilter::TakeConnectionTermination(QuicTerminationInfo* info) {
  if (termination_info_.type == QuicTerminationType::kNone ||
      termination_delivered_) {
    return false;
  }
  *info = termination_info_;
  termination_delivered_ = true;
  return true;
}

bool DatagramSSLFilter::HasReadableStreams() {
  for (const auto& entry : stream_manager_.all()) {
    if (!entry.second.application_read_buffer.empty() ||
        (!entry.second.read_error_delivered && entry.second.reset_received) ||
        (!entry.second.write_error_delivered &&
         entry.second.stop_sending_received) ||
        (entry.second.fin_received && !entry.second.fin_delivered &&
         entry.second.receive_offset == entry.second.final_size)) {
      return true;
    }
  }
  return false;
}

intptr_t DatagramSSLFilter::StreamWrite(int64_t stream_id,
                                        const uint8_t* data,
                                        intptr_t offset,
                                        intptr_t len,
                                        bool fin) {
  if (data == nullptr || offset < 0 || len < 0) {
    return 0;
  }
  if (!remembered_transport_parameters_loaded_ &&
      !EnsurePeerTransportParameters()) {
    return 0;
  }
  const uint64_t id = static_cast<uint64_t>(stream_id);
  QuicStreamState* stream_state = stream_manager_.Find(id);
  if (stream_state == nullptr ||
      (!IsBidirectionalStream(id) && !IsLocallyInitiatedStream(id))) {
    return 0;
  }
  QuicStreamState& stream = *stream_state;
  if (stream.fin_sent || stream.reset_sent || stream.stop_sending_received) {
    return 0;
  }
  const uint64_t stream_available = stream.send_limit > stream.send_offset
                                        ? stream.send_limit - stream.send_offset
                                        : 0;
  const uint64_t connection_available =
      peer_transport_parameters_.initial_max_data > connection_send_offset_
          ? peer_transport_parameters_.initial_max_data -
                connection_send_offset_
          : 0;
  const uint64_t available =
      std::min<uint64_t>(static_cast<uint64_t>(len),
                         std::min(stream_available, connection_available));

  uint64_t queued = 0;
  while (queued < available) {
    const size_t chunk_len = static_cast<size_t>(
        std::min<uint64_t>(kQuicMaxStreamFrameData, available - queued));
    const bool chunk_fin = fin && queued + chunk_len == available &&
                           available == static_cast<uint64_t>(len);
    if (!QueueStreamFrame(id, stream.send_offset, data + offset + queued,
                          chunk_len, chunk_fin)) {
      break;
    }
    stream.send_offset += chunk_len;
    connection_send_offset_ += chunk_len;
    queued += chunk_len;
    if (chunk_fin) {
      stream.fin_sent = true;
    }
  }
  if (len == 0 && fin && !stream.fin_sent) {
    if (QueueStreamFrame(id, stream.send_offset, nullptr, 0, true)) {
      stream.fin_sent = true;
    }
  }
  if (queued < static_cast<uint64_t>(len)) {
    if (connection_send_offset_ >=
            peer_transport_parameters_.initial_max_data &&
        last_data_blocked_limit_ !=
            peer_transport_parameters_.initial_max_data) {
      QueueDataBlockedFrame(peer_transport_parameters_.initial_max_data);
      last_data_blocked_limit_ = peer_transport_parameters_.initial_max_data;
    }
    if (stream.send_offset >= stream.send_limit &&
        stream.last_stream_data_blocked_limit != stream.send_limit) {
      QueueStreamDataBlockedFrame(id, stream.send_limit);
      stream.last_stream_data_blocked_limit = stream.send_limit;
    }
  }
  return static_cast<intptr_t>(queued);
}

bool DatagramSSLFilter::StreamClose(int64_t stream_id) {
  const uint64_t id = static_cast<uint64_t>(stream_id);
  QuicStreamState* stream = stream_manager_.Find(id);
  if (stream == nullptr || stream->fin_sent || stream->reset_sent ||
      stream->stop_sending_received) {
    return stream != nullptr && (stream->fin_sent || stream->reset_sent ||
                                 stream->stop_sending_received);
  }
  if (!QueueStreamFrame(id, stream->send_offset, nullptr, 0, true)) {
    return false;
  }
  stream->fin_sent = true;
  MaybeReturnStreamCredit(id);
  return true;
}

void DatagramSSLFilter::StreamReset(int64_t stream_id, int64_t error_code) {
  if (stream_id < 0 || error_code < 0) {
    return;
  }
  const uint64_t id = static_cast<uint64_t>(stream_id);
  QuicStreamState* stream = stream_manager_.Find(id);
  if (stream == nullptr || stream->reset_sent ||
      (!IsBidirectionalStream(id) && !IsLocallyInitiatedStream(id))) {
    return;
  }
  QueueResetStreamFrame(id, static_cast<uint64_t>(error_code),
                        stream->send_offset);
  stream->reset_sent = true;
  stream->fin_sent = true;
  MaybeReturnStreamCredit(id);
}

void DatagramSSLFilter::StreamStopSending(int64_t stream_id,
                                          int64_t error_code) {
  if (stream_id < 0 || error_code < 0) {
    return;
  }
  const uint64_t id = static_cast<uint64_t>(stream_id);
  QuicStreamState* stream_state = stream_manager_.Find(id);
  if (stream_state == nullptr || stream_state->stop_sending_sent ||
      (!IsBidirectionalStream(id) && IsLocallyInitiatedStream(id))) {
    return;
  }
  QuicStreamState& stream = *stream_state;
  stream.stop_sending_sent = true;
  stream.read_abandoned = true;
  const uint64_t discarded =
      stream.receive_highest_offset - stream.consumed_offset;
  stream.receive_offset = stream.receive_highest_offset;
  MaybeIncreaseReceiveWindows(id, static_cast<size_t>(discarded));
  QueueStopSendingFrame(id, static_cast<uint64_t>(error_code));
  internal_progress_ = true;
}

bool DatagramSSLFilter::QueueStreamFrame(uint64_t stream_id,
                                         uint64_t offset,
                                         const uint8_t* data,
                                         size_t len,
                                         bool fin) {
  std::vector<uint8_t> payload;
  AppendStreamFrame(&payload, stream_id, offset, data, len, fin);
  if (len != 0 && !CanBufferApplicationPacket(payload.size())) {
    return false;
  }
  const ssl_encryption_level_t level = ApplicationWriteLevel();
  if (!QueueProtectedPacket(level, payload, true, true, false,
                            std::numeric_limits<uint32_t>::max(), false)) {
    return false;
  }
  if (level == ssl_encryption_early_data) {
    early_data_payloads_.push_back(payload);
  }
  return true;
}

bool DatagramSSLFilter::ProcessBufferedStreamWrite(uint64_t stream_id,
                                                   QuicStreamState* stream) {
  QuicCircularBuffer& write_buffer = stream->application_write_buffer;
  while (!write_buffer.empty()) {
    const size_t linear_length = write_buffer.contiguous_readable();
    const intptr_t accepted =
        StreamWrite(static_cast<int64_t>(stream_id), write_buffer.data(),
                    write_buffer.start(), linear_length, false);
    if (accepted < 0 || static_cast<size_t>(accepted) > linear_length) {
      return false;
    }
    write_buffer.Consume(static_cast<size_t>(accepted));
    if (static_cast<size_t>(accepted) != linear_length) {
      if (stream->fin_sent || stream->reset_sent ||
          stream->stop_sending_received) {
        write_buffer.ClearAtEnd();
      }
      return true;
    }
  }
  if (stream->application_fin_pending &&
      StreamClose(static_cast<int64_t>(stream_id))) {
    stream->application_fin_pending = false;
    write_ready_ = true;
  }
  return true;
}

bool DatagramSSLFilter::ProcessBufferedStreamWrites() {
  for (auto& entry : stream_manager_.all()) {
    QuicStreamState& stream = entry.second;
    if (stream.application_write_buffer.data() == nullptr) continue;
    if (!ProcessBufferedStreamWrite(entry.first, &stream)) return false;
  }
  return true;
}

void DatagramSSLFilter::QueueResetStreamFrame(uint64_t stream_id,
                                              uint64_t error_code,
                                              uint64_t final_size) {
  std::vector<uint8_t> payload;
  AppendResetStreamFrame(&payload, stream_id, error_code, final_size);
  const ssl_encryption_level_t level = ApplicationWriteLevel();
  if (level == ssl_encryption_early_data) {
    early_data_payloads_.push_back(payload);
  }
  QueueProtectedPacket(level, payload, true, true);
}

void DatagramSSLFilter::QueueStopSendingFrame(uint64_t stream_id,
                                              uint64_t error_code) {
  std::vector<uint8_t> payload;
  AppendStopSendingFrame(&payload, stream_id, error_code);
  const ssl_encryption_level_t level = ApplicationWriteLevel();
  if (level == ssl_encryption_early_data) {
    early_data_payloads_.push_back(payload);
  }
  QueueProtectedPacket(level, payload, true, true);
}

void DatagramSSLFilter::QueueMaxDataFrame(uint64_t maximum_data) {
  std::vector<uint8_t> payload;
  AppendMaxDataFrame(&payload, maximum_data);
  QueueProtectedPacket(ssl_encryption_application, payload, true, true);
}

void DatagramSSLFilter::QueueMaxStreamDataFrame(uint64_t stream_id,
                                                uint64_t maximum_stream_data) {
  std::vector<uint8_t> payload;
  AppendMaxStreamDataFrame(&payload, stream_id, maximum_stream_data);
  QueueProtectedPacket(ssl_encryption_application, payload, true, true);
}

void DatagramSSLFilter::QueueDataBlockedFrame(uint64_t maximum_data) {
  std::vector<uint8_t> payload;
  AppendDataBlockedFrame(&payload, maximum_data);
  QueueProtectedPacket(ssl_encryption_application, payload, true, true);
}

void DatagramSSLFilter::QueueStreamDataBlockedFrame(
    uint64_t stream_id,
    uint64_t maximum_stream_data) {
  std::vector<uint8_t> payload;
  AppendStreamDataBlockedFrame(&payload, stream_id, maximum_stream_data);
  QueueProtectedPacket(ssl_encryption_application, payload, true, true);
}

void DatagramSSLFilter::QueueStreamsBlockedFrame(bool bidirectional,
                                                 uint64_t maximum_streams) {
  std::vector<uint8_t> payload;
  AppendStreamsBlockedFrame(&payload, bidirectional, maximum_streams);
  QueueProtectedPacket(ssl_encryption_application, payload, true, true);
}

void DatagramSSLFilter::QueueMaxStreamsFrame(bool bidirectional,
                                             uint64_t maximum_streams) {
  std::vector<uint8_t> payload;
  AppendMaxStreamsFrame(&payload, bidirectional, maximum_streams);
  QueueProtectedPacket(ssl_encryption_application, payload, true, true);
}

bool DatagramSSLFilter::ValidatePeerStreamLimit(uint64_t stream_id) const {
  return stream_manager_.ValidatePeerStreamLimit(stream_id);
}

void DatagramSSLFilter::MaybeReturnStreamCredit(uint64_t stream_id) {
  const QuicStreamCreditResult credit =
      stream_manager_.MaybeReturnCredit(stream_id);
  if (credit.send_max_streams) {
    QueueMaxStreamsFrame(credit.bidirectional, credit.stream_limit);
  }
}

void DatagramSSLFilter::ReleaseStreamBuffers(QuicStreamState* stream) {
  stream->application_read_buffer.Reset();
  stream->application_write_buffer.Reset();
  stream->published_read_end = -1;
  stream->published_write_start = -1;
}

size_t DatagramSSLFilter::BufferedApplicationPacketBytes() const {
  size_t bytes = 0;
  for (const auto& queue : pending_packets_) {
    for (const QuicPendingPacket& packet : queue) {
      bytes += packet.payload.size();
    }
  }
  return bytes;
}

bool DatagramSSLFilter::CanBufferApplicationPacket(size_t payload_bytes) const {
  const size_t buffered = BufferedApplicationPacketBytes();
  return payload_bytes <= kQuicMaximumBufferedApplicationPacketBytes &&
         buffered <= kQuicMaximumBufferedApplicationPacketBytes - payload_bytes;
}

bool DatagramSSLFilter::HandleResetStream(uint64_t stream_id,
                                          uint64_t error_code,
                                          uint64_t final_size,
                                          QuicFrameError* error) {
  if (!ValidatePeerStreamLimit(stream_id)) {
    return SetQuicFrameError(error, 0x04, 0x04,
                             "RESET_STREAM exceeds stream limit");
  }
  if (!IsBidirectionalStream(stream_id) &&
      IsLocallyInitiatedStream(stream_id)) {
    return SetQuicFrameError(error, 0x05, 0x04,
                             "RESET_STREAM on send-only stream");
  }
  if (IsLocallyInitiatedStream(stream_id) &&
      stream_manager_.Find(stream_id) == nullptr) {
    return SetQuicFrameError(error, 0x05, 0x04,
                             "RESET_STREAM on unopened stream");
  }
  QuicStreamState& stream = stream_manager_.GetOrCreate(stream_id);
  if (stream.receive_limit == 0) {
    InitializeStreamReceiveFlowControl(stream_id, &stream);
    stream.send_limit = InitialSendLimitForStream(stream_id);
  }
  if (stream.reset_received) {
    return stream.final_size == final_size ||
           SetQuicFrameError(error, 0x06, 0x04,
                             "RESET_STREAM changes final size");
  }
  if (final_size > stream.receive_limit) {
    return SetQuicFrameError(error, 0x03, 0x04,
                             "RESET_STREAM exceeds stream flow control");
  }
  if (final_size < stream.receive_highest_offset ||
      (stream.fin_received && stream.final_size != final_size)) {
    return SetQuicFrameError(error, 0x06, 0x04,
                             "RESET_STREAM has inconsistent final size");
  }
  if (final_size > stream.receive_highest_offset) {
    const uint64_t increment = final_size - stream.receive_highest_offset;
    if (increment > local_max_data_ - received_data_) {
      return SetQuicFrameError(error, 0x03, 0x04,
                               "RESET_STREAM exceeds connection flow control");
    }
    received_data_ += increment;
    stream.receive_highest_offset = final_size;
  }

  const uint64_t discarded = final_size - stream.consumed_offset;
  consumed_data_ += discarded;
  stream.consumed_offset = final_size;
  stream.receive_offset = final_size;
  stream.final_size = final_size;
  stream.fin_received = true;
  stream.reset_received = true;
  stream.reset_error_code = error_code;
  if (stream.read_abandoned) {
    stream.read_error_delivered = true;
    stream.fin_delivered = true;
  }

  if (local_max_data_ - consumed_data_ <= local_receive_window_ / 2) {
    const uint64_t new_limit = consumed_data_ + local_receive_window_;
    if (new_limit > local_max_data_) {
      local_max_data_ = new_limit;
      QueueMaxDataFrame(new_limit);
    }
  }
  internal_progress_ = true;
  return true;
}

bool DatagramSSLFilter::HandleStopSending(uint64_t stream_id,
                                          uint64_t error_code,
                                          QuicFrameError* error) {
  if (!ValidatePeerStreamLimit(stream_id)) {
    return SetQuicFrameError(error, 0x04, 0x05,
                             "STOP_SENDING exceeds stream limit");
  }
  if (!IsBidirectionalStream(stream_id) &&
      !IsLocallyInitiatedStream(stream_id)) {
    return SetQuicFrameError(error, 0x05, 0x05,
                             "STOP_SENDING on receive-only stream");
  }
  if (IsLocallyInitiatedStream(stream_id) &&
      stream_manager_.Find(stream_id) == nullptr) {
    return SetQuicFrameError(error, 0x05, 0x05,
                             "STOP_SENDING on unopened stream");
  }
  QuicStreamState& stream = stream_manager_.GetOrCreate(stream_id);
  if (stream.send_limit == 0) {
    stream.send_limit = InitialSendLimitForStream(stream_id);
    InitializeStreamReceiveFlowControl(stream_id, &stream);
  }
  if (stream.stop_sending_received) {
    return true;
  }
  stream.stop_sending_received = true;
  stream.stop_sending_error_code = error_code;
  if (!stream.reset_sent) {
    QueueResetStreamFrame(stream_id, error_code, stream.send_offset);
    stream.reset_sent = true;
    stream.fin_sent = true;
  }
  internal_progress_ = true;
  MaybeReturnStreamCredit(stream_id);
  return true;
}

void DatagramSSLFilter::MaybeIncreaseReceiveWindows(uint64_t stream_id,
                                                    size_t consumed_bytes) {
  QuicStreamState* stream_state = stream_manager_.Find(stream_id);
  if (stream_state == nullptr || consumed_bytes == 0) {
    return;
  }
  QuicStreamState& stream = *stream_state;
  stream.consumed_offset += consumed_bytes;
  consumed_data_ += consumed_bytes;

  if (stream.receive_limit - stream.consumed_offset <=
      stream.receive_window / 2) {
    const uint64_t new_limit = stream.consumed_offset + stream.receive_window;
    if (new_limit > stream.receive_limit) {
      stream.receive_limit = new_limit;
      QueueMaxStreamDataFrame(stream_id, new_limit);
    }
  }
  if (local_max_data_ - consumed_data_ <= local_receive_window_ / 2) {
    const uint64_t new_limit = consumed_data_ + local_receive_window_;
    if (new_limit > local_max_data_) {
      local_max_data_ = new_limit;
      QueueMaxDataFrame(new_limit);
    }
  }
}

bool DatagramSSLFilter::AddStreamData(uint64_t frame_type,
                                      uint64_t stream_id,
                                      uint64_t offset,
                                      const uint8_t* data,
                                      size_t len,
                                      bool fin,
                                      QuicFrameError* error) {
  if (!ValidatePeerStreamLimit(stream_id)) {
    return SetQuicFrameError(error, 0x04, frame_type,
                             "STREAM exceeds stream limit");
  }
  if (IsLocallyInitiatedStream(stream_id) &&
      stream_manager_.Find(stream_id) == nullptr) {
    return SetQuicFrameError(error, 0x05, frame_type,
                             "STREAM on unopened stream");
  }
  QuicStreamState* stream = &stream_manager_.GetOrCreate(stream_id);
  if (stream->receive_limit == 0) {
    InitializeStreamReceiveFlowControl(stream_id, stream);
    stream->send_limit = InitialSendLimitForStream(stream_id);
  }
  if (!IsBidirectionalStream(stream_id) &&
      IsLocallyInitiatedStream(stream_id)) {
    return SetQuicFrameError(error, 0x05, frame_type,
                             "STREAM on send-only stream");
  }
  if (len > (uint64_t{1} << 62) - 1 - offset) {
    return SetQuicFrameError(error, 0x07, frame_type,
                             "STREAM offset and length exceed varint range");
  }
  const uint64_t end = offset + len;
  if (end > stream->receive_limit) {
    return SetQuicFrameError(error, 0x03, frame_type,
                             "STREAM exceeds stream flow control");
  }
  if (stream->reset_received) {
    return (end <= stream->final_size && (!fin || end == stream->final_size)) ||
           SetQuicFrameError(error, 0x06, frame_type,
                             "STREAM conflicts with reset final size");
  }
  if (fin && end < stream->receive_highest_offset) {
    return SetQuicFrameError(error, 0x06, frame_type,
                             "STREAM final size is below received data");
  }
  if (stream->fin_received && end > stream->final_size) {
    return SetQuicFrameError(error, 0x06, frame_type,
                             "STREAM exceeds final size");
  }
  if (end > stream->receive_highest_offset) {
    const uint64_t increment = end - stream->receive_highest_offset;
    if (increment > local_max_data_ - received_data_) {
      return SetQuicFrameError(error, 0x03, frame_type,
                               "STREAM exceeds connection flow control");
    }
    received_data_ += increment;
    stream->receive_highest_offset = end;
  }
  if (fin) {
    if (stream->fin_received && stream->final_size != end) {
      return SetQuicFrameError(error, 0x06, frame_type,
                               "STREAM changes final size");
    }
    stream->fin_received = true;
    stream->final_size = end;
  }
  if (stream->read_abandoned) {
    if (end > stream->consumed_offset) {
      MaybeIncreaseReceiveWindows(
          stream_id, static_cast<size_t>(end - stream->consumed_offset));
    }
    stream->receive_offset = std::max<uint64_t>(stream->receive_offset, end);
    return true;
  }
  if (end <= stream->receive_offset) {
    return true;
  }
  if (len == 0) {
    return true;
  }
  if (offset < stream->receive_offset) {
    const size_t duplicate = static_cast<size_t>(
        std::min<uint64_t>(len, stream->receive_offset - offset));
    data += duplicate;
    offset += duplicate;
    len -= duplicate;
    if (len == 0) return true;
  }
  if (offset != stream->receive_offset) {
    receive_reordered_ = true;
    return true;
  }

  if (stream->application_read_buffer.data() == nullptr &&
      !RegisterStreamBuffers(stream_id)) {
    return SetQuicFrameError(error, 0x01, frame_type,
                             "failed to allocate STREAM buffers");
  }
  QuicCircularBuffer& ring = stream->application_read_buffer;
  while (len != 0 && ring.free_space() != 0) {
    const size_t count =
        std::min({len, ring.free_space(), ring.contiguous_writable()});
    if (count == 0) break;
    memcpy(ring.data() + ring.end(), data, count);
    ring.Produce(count);
    data += count;
    offset += count;
    len -= count;
    stream->receive_offset += count;
  }
  receive_backpressured_ = len != 0;
  if (receive_backpressured_) {
    receive_backpressured_stream_id_ = stream_id;
  }
  return true;
}

void DatagramSSLFilter::CloseQuic(int error_code, const char* reason) {
  if (local_closing_ || draining_ || connection_terminated_) {
    return;
  }
  local_connection_close_payload_.clear();
  AppendConnectionCloseFrame(&local_connection_close_payload_,
                             static_cast<uint64_t>(error_code), reason);
  for (int i = 0; i < 4; i++) {
    pending_packets_[i].clear();
  }
  local_closing_ = true;
  idle_deadline_micros_ = -1;
  const int64_t now = TimerUtils::GetCurrentMonotonicMicros();
  closing_deadline_micros_ =
      now + 3 * recovery_.ProbeTimeoutMicros(ssl_encryption_application);
  QueueProtectedPacket(ssl_encryption_application,
                       local_connection_close_payload_, false, false, true);
  internal_progress_ = true;
}

void DatagramSSLFilter::StartTransportError(ssl_encryption_level_t level,
                                            uint64_t error_code,
                                            uint64_t frame_type,
                                            const char* reason) {
  if (local_closing_ || draining_ || connection_terminated_) return;
  termination_info_.type = QuicTerminationType::kTransportClose;
  termination_info_.error_code = error_code;
  termination_info_.frame_type = static_cast<int64_t>(frame_type);
  if (reason != nullptr) {
    termination_info_.reason.assign(reason, reason + strlen(reason));
  }
  local_connection_close_payload_.clear();
  AppendTransportConnectionCloseFrame(&local_connection_close_payload_,
                                      error_code, frame_type, reason);
  for (int i = 0; i < 4; i++) {
    pending_packets_[i].clear();
  }
  local_closing_ = true;
  idle_deadline_micros_ = -1;
  const int64_t now = TimerUtils::GetCurrentMonotonicMicros();
  closing_deadline_micros_ = now + 3 * recovery_.ProbeTimeoutMicros(level);
  QueueProtectedPacket(level, local_connection_close_payload_, false, false,
                       true);
  internal_progress_ = true;
}

void DatagramSSLFilter::RefreshIdleDeadline(int64_t now_micros) {
  if (effective_idle_timeout_millis_ == 0 || local_closing_ || draining_ ||
      connection_terminated_) {
    idle_deadline_micros_ = -1;
    return;
  }
  const uint64_t timeout_micros =
      effective_idle_timeout_millis_ >
              std::numeric_limits<uint64_t>::max() / 1000
          ? std::numeric_limits<uint64_t>::max()
          : effective_idle_timeout_millis_ * 1000;
  idle_deadline_micros_ =
      timeout_micros > static_cast<uint64_t>(
                           std::numeric_limits<int64_t>::max() - now_micros)
          ? std::numeric_limits<int64_t>::max()
          : now_micros + static_cast<int64_t>(timeout_micros);
}

void DatagramSSLFilter::StartPeerClose(QuicTerminationType type,
                                       uint64_t error_code,
                                       int64_t frame_type,
                                       const uint8_t* reason,
                                       size_t reason_len,
                                       ssl_encryption_level_t level) {
  if (termination_info_.type != QuicTerminationType::kNone) {
    return;
  }
  termination_info_.type = type;
  termination_info_.error_code = error_code;
  termination_info_.frame_type = frame_type;
  if (reason_len != 0) {
    termination_info_.reason.assign(reason, reason + reason_len);
  }
  draining_ = true;
  local_closing_ = false;
  idle_deadline_micros_ = -1;
  for (int i = 0; i < 4; i++) {
    pending_packets_[i].clear();
  }
  const int64_t now = TimerUtils::GetCurrentMonotonicMicros();
  draining_deadline_micros_ = now + 3 * recovery_.ProbeTimeoutMicros(level);
  internal_progress_ = true;
}

void DatagramSSLFilter::StartIdleTimeout() {
  if (termination_info_.type != QuicTerminationType::kNone) {
    return;
  }
  termination_info_.type = QuicTerminationType::kIdleTimeout;
  termination_info_.reason = {'i', 'd', 'l', 'e', ' ', 't',
                              'i', 'm', 'e', 'o', 'u', 't'};
  idle_deadline_micros_ = -1;
  connection_terminated_ = true;
  internal_progress_ = true;
}

void DatagramSSLFilter::TerminateImmediately(QuicTerminationType type,
                                             const char* reason) {
  if (termination_info_.type != QuicTerminationType::kNone) {
    return;
  }
  termination_info_.type = type;
  if (reason != nullptr) {
    termination_info_.reason.assign(reason, reason + strlen(reason));
  }
  idle_deadline_micros_ = -1;
  connection_terminated_ = true;
  for (int i = 0; i < 4; i++) {
    pending_packets_[i].clear();
  }
  internal_progress_ = true;
}

bool DatagramSSLFilter::HandleVersionNegotiation(const uint8_t* data,
                                                 size_t len) {
  if (received_authenticated_packet_ || version_negotiation_processed_ ||
      len < 7) {
    return false;
  }
  size_t offset = 5;
  const uint8_t dcid_len = data[offset++];
  if (offset + dcid_len + 1 > len) {
    return false;
  }
  const bool destination_matches =
      dcid_len == source_connection_id_.size() &&
      memcmp(data + offset, source_connection_id_.data(), dcid_len) == 0;
  offset += dcid_len;
  const uint8_t scid_len = data[offset++];
  if (offset + scid_len > len || (len - offset - scid_len) % 4 != 0 ||
      len - offset - scid_len == 0) {
    return false;
  }
  const bool source_matches =
      scid_len == original_destination_connection_id_.size() &&
      memcmp(data + offset, original_destination_connection_id_.data(),
             scid_len) == 0;
  offset += scid_len;
  if (!destination_matches || !source_matches) {
    return false;
  }
  version_negotiation_processed_ = true;
  for (; offset < len; offset += 4) {
    const uint32_t version = (static_cast<uint32_t>(data[offset]) << 24) |
                             (static_cast<uint32_t>(data[offset + 1]) << 16) |
                             (static_cast<uint32_t>(data[offset + 2]) << 8) |
                             static_cast<uint32_t>(data[offset + 3]);
    if (version == kQuicVersion1) {
      return true;
    }
  }
  TerminateImmediately(QuicTerminationType::kVersionNegotiation,
                       "server does not support QUIC v1");
  return true;
}

void DatagramSSLFilter::ResetInitialStateAfterRetry(
    const std::vector<std::vector<uint8_t>>& retransmit_payloads) {
  recovery_.ResetInitialPacketNumberSpace();
  pending_packets_[ssl_encryption_initial].clear();
  received_packet_trackers_[ssl_encryption_initial].Reset();
  ack_eliciting_since_last_ack_[ssl_encryption_initial] = 0;
  ack_deadline_micros_[ssl_encryption_initial] = -1;
  largest_ack_eliciting_packet_number_[ssl_encryption_initial] = 0;
  largest_ack_eliciting_packet_received_micros_[ssl_encryption_initial] = -1;
  has_largest_ack_eliciting_packet_number_[ssl_encryption_initial] = false;
  largest_received_packet_number_[ssl_encryption_initial] = 0;
  has_largest_received_packet_number_[ssl_encryption_initial] = false;
  read_keys_[ssl_encryption_initial] = QuicPacketKeys();
  write_keys_[ssl_encryption_initial] = QuicPacketKeys();
  InstallInitialSecrets();
  for (const auto& payload : retransmit_payloads) {
    QueueProtectedPacket(ssl_encryption_initial, payload, true, true, true);
  }
  if (write_keys_[ssl_encryption_early_data].installed) {
    for (const auto& payload : early_data_payloads_) {
      QueueProtectedPacket(ssl_encryption_early_data, payload, true, true,
                           true);
    }
  }
  internal_progress_ = true;
}

bool DatagramSSLFilter::HandleRetry(const uint8_t* data, size_t len) {
  if (retry_processed_ || received_authenticated_packet_ || len < 23 ||
      !ValidateQuicRetryIntegrity(data, len,
                                  original_destination_connection_id_)) {
    return false;
  }
  size_t offset = 5;
  const uint8_t dcid_len = data[offset++];
  if (offset + dcid_len + 1 > len) {
    return false;
  }
  if (dcid_len != source_connection_id_.size() ||
      memcmp(data + offset, source_connection_id_.data(), dcid_len) != 0) {
    return false;
  }
  offset += dcid_len;
  const uint8_t scid_len = data[offset++];
  if (scid_len == 0 || offset + scid_len + kQuicTagLength >= len) {
    return false;
  }
  std::vector<uint8_t> retry_source(data + offset, data + offset + scid_len);
  if (retry_source == original_destination_connection_id_) {
    return false;
  }
  offset += scid_len;
  std::vector<uint8_t> token(data + offset, data + len - kQuicTagLength);
  if (token.empty()) {
    return false;
  }

  std::vector<std::vector<uint8_t>> retransmit_payloads =
      recovery_.RetransmittablePayloads(ssl_encryption_initial);
  retry_processed_ = true;
  retry_source_connection_id_ = retry_source;
  destination_connection_id_ = std::move(retry_source);
  initial_token_ = std::move(token);
  ResetInitialStateAfterRetry(retransmit_payloads);
  return true;
}

bool DatagramSSLFilter::DetectStatelessReset(const uint8_t* data, size_t len) {
  if (len < 21) {
    return false;
  }
  const uint8_t* candidate = data + len - kQuicTagLength;
  for (const auto& entry : peer_connection_ids_) {
    const QuicPeerConnectionId& connection_id = entry.second;
    if (connection_id.retired ||
        connection_id.stateless_reset_token.size() != kQuicTagLength) {
      continue;
    }
    uint8_t difference = 0;
    for (size_t i = 0; i < kQuicTagLength; i++) {
      difference |= candidate[i] ^ connection_id.stateless_reset_token[i];
    }
    if (difference == 0) {
      TerminateImmediately(QuicTerminationType::kStatelessReset,
                           "stateless reset");
      return true;
    }
  }
  return false;
}

bool DatagramSSLFilter::SelectPeerConnectionId(uint64_t minimum_sequence) {
  for (auto& entry : peer_connection_ids_) {
    if (entry.first < minimum_sequence || entry.second.retired) {
      continue;
    }
    destination_connection_id_ = entry.second.connection_id;
    current_peer_connection_id_sequence_ = entry.first;
    return true;
  }
  return false;
}

void DatagramSSLFilter::StartPathValidation(uint32_t path_id) {
  if (connection_terminated_ || draining_ || local_closing_ ||
      path_id == active_path_id_) {
    path_validation_results_.emplace_back(path_id, path_id == active_path_id_);
    internal_progress_ = true;
    return;
  }
  if (!handshake_confirmed_) {
    if (path_validation_deferred_ && deferred_path_validation_id_ != path_id) {
      path_validation_results_.emplace_back(deferred_path_validation_id_,
                                            false);
    }
    path_validation_deferred_ = true;
    deferred_path_validation_id_ = path_id;
    internal_progress_ = true;
    return;
  }
  BeginPathValidation(path_id);
}

void DatagramSSLFilter::BeginPathValidation(uint32_t path_id) {
  if (path_validation_pending_) {
    if (validating_path_id_ == path_id) {
      return;
    }
    CompletePathValidation(false);
  }
  if (RAND_bytes(path_challenge_, sizeof(path_challenge_)) != 1) {
    path_validation_results_.emplace_back(path_id, false);
    internal_progress_ = true;
    return;
  }

  // A new path should use an unused peer CID when one is available. A peer
  // that only supplied one CID does not make validation itself impossible.
  validating_previous_peer_connection_id_sequence_ =
      current_peer_connection_id_sequence_;
  SelectPeerConnectionId(current_peer_connection_id_sequence_ + 1);
  path_validation_pending_ = true;
  validating_path_id_ = path_id;
  path_validation_attempts_ = 1;
  path_validation_deadline_micros_ =
      TimerUtils::GetCurrentMonotonicMicros() +
      recovery_.ProbeTimeoutMicros(ssl_encryption_application);

  std::vector<uint8_t> payload;
  AppendPathChallengeFrame(&payload, path_challenge_);
  QueueProtectedPacket(ssl_encryption_application, payload, true, false, true,
                       path_id);
  internal_progress_ = true;
}

void DatagramSSLFilter::CompletePathValidation(bool succeeded) {
  if (!path_validation_pending_) {
    return;
  }
  const uint32_t path_id = validating_path_id_;
  const uint64_t previous_connection_id_sequence =
      validating_previous_peer_connection_id_sequence_;
  const bool changed_connection_id =
      current_peer_connection_id_sequence_ != previous_connection_id_sequence;
  path_validation_pending_ = false;
  path_validation_deadline_micros_ = -1;
  path_validation_attempts_ = 0;
  if (succeeded) {
    active_path_id_ = path_id;
    // Congestion and RTT state is path-specific. Start conservatively on the
    // validated path instead of carrying estimates from the old route.
    recovery_.ResetPath(path_id);
    for (auto& pending : pending_packets_[ssl_encryption_application]) {
      pending.path_id = path_id;
    }
    if (changed_connection_id) {
      auto previous =
          peer_connection_ids_.find(previous_connection_id_sequence);
      if (previous != peer_connection_ids_.end()) {
        previous->second.retired = true;
        std::vector<uint8_t> retire;
        AppendRetireConnectionIdFrame(&retire, previous_connection_id_sequence);
        QueueProtectedPacket(ssl_encryption_application, retire, true, true,
                             false, path_id);
      }
    }
  } else if (changed_connection_id) {
    const auto previous =
        peer_connection_ids_.find(previous_connection_id_sequence);
    if (previous != peer_connection_ids_.end() && !previous->second.retired) {
      destination_connection_id_ = previous->second.connection_id;
      current_peer_connection_id_sequence_ = previous_connection_id_sequence;
    }
  }
  if (!succeeded && path_id != active_path_id_) {
    auto native_path = native_paths_.find(path_id);
    if (native_path != native_paths_.end()) {
      native_path->second.socket->Release();
      native_paths_.erase(native_path);
    }
  }
  path_validation_results_.emplace_back(path_id, succeeded);
  internal_progress_ = true;
}

bool DatagramSSLFilter::TakePathValidationResult(uint32_t* path_id,
                                                 bool* succeeded) {
  if (path_validation_results_.empty()) {
    return false;
  }
  *path_id = path_validation_results_.front().first;
  *succeeded = path_validation_results_.front().second;
  path_validation_results_.pop_front();
  return true;
}

void DatagramSSLFilter::MaybeIssueConnectionIds() {
  if (!write_keys_[ssl_encryption_application].installed) {
    return;
  }
  size_t active = 0;
  for (const auto& entry : local_connection_ids_) {
    if (!entry.second.retired) {
      active++;
    }
  }
  const uint64_t target =
      std::min(peer_transport_parameters_.active_connection_id_limit,
               kQuicIssuedConnectionIdTarget);
  while (active < target) {
    QuicLocalConnectionId connection_id;
    connection_id.connection_id.resize(kQuicInitialConnectionIdLength);
    connection_id.stateless_reset_token.resize(kQuicTagLength);
    if (RAND_bytes(connection_id.connection_id.data(),
                   connection_id.connection_id.size()) != 1 ||
        RAND_bytes(connection_id.stateless_reset_token.data(),
                   connection_id.stateless_reset_token.size()) != 1) {
      return;
    }
    const uint64_t sequence = next_local_connection_id_sequence_++;
    std::vector<uint8_t> payload;
    AppendNewConnectionIdFrame(&payload, sequence, 0,
                               connection_id.connection_id,
                               connection_id.stateless_reset_token);
    local_connection_ids_[sequence] = std::move(connection_id);
    QueueProtectedPacket(ssl_encryption_application, payload, true, true);
    active++;
  }
}

void DatagramSSLFilter::Destroy() {
  StopNativePump();
  BaseSSLFilter::Destroy();
  readable_datagrams_.clear();
  deferred_encrypted_datagrams_.clear();
  recovery_.Reset();
  for (int i = 0; i < 4; i++) {
    pending_packets_[i].clear();
  }
  stream_manager_.Reset(is_server_);
}

void DatagramSSLFilter::DiscardPacketNumberSpace(ssl_encryption_level_t level) {
  const int space_index = QuicPacketNumberSpaceIndex(level);
  if (recovery_.IsPacketNumberSpaceDiscarded(level)) {
    return;
  }
  recovery_.DiscardPacketNumberSpace(level);
  pending_packets_[level].clear();
  crypto_send_[level] = QuicCryptoSendState();
  crypto_receive_[level] = QuicCryptoReceiveState();
  received_packet_trackers_[space_index].Reset();
  ack_eliciting_since_last_ack_[space_index] = 0;
  ack_deadline_micros_[space_index] = -1;
  largest_ack_eliciting_packet_number_[space_index] = 0;
  largest_ack_eliciting_packet_received_micros_[space_index] = -1;
  has_largest_ack_eliciting_packet_number_[space_index] = false;
  read_keys_[level] = QuicPacketKeys();
  write_keys_[level] = QuicPacketKeys();
  internal_progress_ = true;
  FlushPendingPackets();
}

bool DatagramSSLFilter::DeriveNextApplicationReadKeys() {
  return DeriveNextQuicPacketKeys(read_keys_[ssl_encryption_application],
                                  &next_application_read_keys_);
}

void DatagramSSLFilter::PromoteApplicationReadKeys() {
  previous_application_read_keys_ =
      std::move(read_keys_[ssl_encryption_application]);
  previous_application_read_key_phase_ = application_read_key_phase_;
  read_keys_[ssl_encryption_application] =
      std::move(next_application_read_keys_);
  application_read_key_phase_ = !application_read_key_phase_;
  DeriveNextApplicationReadKeys();
  previous_application_read_keys_expiry_micros_ =
      TimerUtils::GetCurrentMonotonicMicros() +
      3 * recovery_.ProbeTimeoutMicros(ssl_encryption_application);
}

void DatagramSSLFilter::RetirePreviousApplicationReadKeys() {
  previous_application_read_keys_ = QuicPacketKeys();
  previous_application_read_keys_expiry_micros_ = -1;
}

bool DatagramSSLFilter::MaybeInitiateApplicationKeyUpdate() {
  const uint64_t packet_number =
      next_packet_number_[ssl_encryption_application];
  if (!handshake_confirmed_ || !application_write_key_generation_acked_ ||
      packet_number - application_write_key_generation_start_packet_ <
          kQuicApplicationKeyUpdatePacketLimit) {
    return true;
  }
  QuicPacketKeys next;
  if (!DeriveNextQuicPacketKeys(write_keys_[ssl_encryption_application],
                                &next)) {
    return false;
  }
  write_keys_[ssl_encryption_application] = std::move(next);
  application_write_key_generation_++;
  application_write_key_phase_ = !application_write_key_phase_;
  application_write_key_generation_start_packet_ = packet_number;
  application_write_key_generation_acked_ = false;
  return true;
}

int DatagramSSLFilter::SetReadSecret(SSL* ssl,
                                     ssl_encryption_level_t level,
                                     const SSL_CIPHER* cipher,
                                     const uint8_t* secret,
                                     size_t secret_len) {
  DatagramSSLFilter* filter = FromSSL(ssl);
  if (filter == nullptr) return 0;
  if (!filter->InstallReadSecret(level, cipher, secret, secret_len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

int DatagramSSLFilter::SetWriteSecret(SSL* ssl,
                                      ssl_encryption_level_t level,
                                      const SSL_CIPHER* cipher,
                                      const uint8_t* secret,
                                      size_t secret_len) {
  DatagramSSLFilter* filter = FromSSL(ssl);
  if (filter == nullptr) return 0;
  if (!filter->InstallWriteSecret(level, cipher, secret, secret_len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

int DatagramSSLFilter::AddHandshakeData(SSL* ssl,
                                        ssl_encryption_level_t level,
                                        const uint8_t* data,
                                        size_t len) {
  DatagramSSLFilter* filter = FromSSL(ssl);
  if (filter == nullptr) return 0;
  filter->QueueCrypto(level, data, len);
  return 1;
}

int DatagramSSLFilter::FlushFlight(SSL* ssl) {
  DatagramSSLFilter* filter = FromSSL(ssl);
  if (filter == nullptr) return 0;
  filter->PacketizeCryptoFlights();
  if (filter->early_data_rejected_ && filter->one_rtt_write_keys_installed_) {
    filter->ReplayRejectedEarlyData();
  }
  return 1;
}

int DatagramSSLFilter::SendAlert(SSL* ssl,
                                 ssl_encryption_level_t level,
                                 uint8_t alert) {
  DatagramSSLFilter* filter = FromSSL(ssl);
  if (filter == nullptr) return 0;
  std::vector<uint8_t> payload;
  AppendConnectionCloseFrame(&payload, 0x100 + alert, "TLS alert");
  filter->QueueProtectedPacket(level, payload, false, false, true);
  return 1;
}

DatagramSSLFilter* DatagramSSLFilter::FromSSL(const SSL* ssl) {
  return reinterpret_cast<DatagramSSLFilter*>(
      SSL_get_ex_data(ssl, filter_ssl_index));
}

const SSL_QUIC_METHOD* DatagramSSLFilter::QuicMethod() {
  static const SSL_QUIC_METHOD method = {
      DatagramSSLFilter::SetReadSecret,    DatagramSSLFilter::SetWriteSecret,
      DatagramSSLFilter::AddHandshakeData, DatagramSSLFilter::FlushFlight,
      DatagramSSLFilter::SendAlert,
  };
  return &method;
}

bool DatagramSSLFilter::BuildProtectedPacketInto(
    ssl_encryption_level_t level,
    const std::vector<uint8_t>& payload,
    uint8_t* packet,
    size_t packet_capacity,
    size_t* packet_length) {
  const int space_index = QuicPacketNumberSpaceIndex(level);
  if (recovery_.IsPacketNumberSpaceDiscarded(level)) {
    return false;
  }
  if (level == ssl_encryption_application &&
      !MaybeInitiateApplicationKeyUpdate()) {
    return false;
  }
  uint64_t* packet_number = &next_packet_number_[space_index];
  const size_t packet_number_len = kQuicPacketNumberLength;
  QuicPacketKeys* keys = &write_keys_[level];
  if (!keys->installed || packet == nullptr || packet_length == nullptr ||
      payload.size() > kQuicDatagramSlotPayloadCapacity) {
    return false;
  }

  // Header protection samples 16 bytes starting four bytes after the packet
  // number.  A tiny ACK-only packet therefore still needs four plaintext bytes.
  size_t plaintext_length = std::max(payload.size(), size_t{4});
  for (int i = 0; i < 2; i++) {
    const size_t header_length = ProtectedPacketHeaderLength(
        level, destination_connection_id_.size(), source_connection_id_.size(),
        plaintext_length, initial_token_.size());
    if (level == ssl_encryption_initial &&
        header_length + plaintext_length + kQuicTagLength <
            kQuicMinInitialDatagramSize) {
      plaintext_length =
          kQuicMinInitialDatagramSize - header_length - kQuicTagLength;
    }
  }
  const size_t header_length = ProtectedPacketHeaderLength(
      level, destination_connection_id_.size(), source_connection_id_.size(),
      plaintext_length, initial_token_.size());
  const size_t total_length = header_length + plaintext_length + kQuicTagLength;
  if (plaintext_length > kQuicDatagramSlotPayloadCapacity ||
      total_length > packet_capacity ||
      destination_connection_id_.size() > UINT8_MAX ||
      source_connection_id_.size() > UINT8_MAX) {
    return false;
  }

  uint8_t* cursor = packet;
  const uint8_t* const limit = packet + packet_capacity;
  const auto append_byte = [&](uint8_t byte) {
    if (cursor == limit) return false;
    *cursor++ = byte;
    return true;
  };
  const auto append_bytes = [&](const std::vector<uint8_t>& bytes) {
    if (static_cast<size_t>(limit - cursor) < bytes.size()) return false;
    if (!bytes.empty()) memcpy(cursor, bytes.data(), bytes.size());
    cursor += bytes.size();
    return true;
  };
  if (level == ssl_encryption_application) {
    if (!append_byte(0x40 | (application_write_key_phase_ ? 0x04 : 0) |
                     (packet_number_len - 1)) ||
        !append_bytes(destination_connection_id_)) {
      return false;
    }
  } else {
    if (!append_byte(0xc0 | LongHeaderTypeForLevel(level) |
                     (packet_number_len - 1)) ||
        static_cast<size_t>(limit - cursor) < 4) {
      return false;
    }
    *cursor++ = static_cast<uint8_t>(kQuicVersion1 >> 24);
    *cursor++ = static_cast<uint8_t>(kQuicVersion1 >> 16);
    *cursor++ = static_cast<uint8_t>(kQuicVersion1 >> 8);
    *cursor++ = static_cast<uint8_t>(kQuicVersion1);
    if (!append_byte(static_cast<uint8_t>(destination_connection_id_.size())) ||
        !append_bytes(destination_connection_id_) ||
        !append_byte(static_cast<uint8_t>(source_connection_id_.size())) ||
        !append_bytes(source_connection_id_)) {
      return false;
    }
    if (level == ssl_encryption_initial &&
        (!AppendQuicVarInt(&cursor, limit, initial_token_.size()) ||
         !append_bytes(initial_token_))) {
      return false;
    }
    if (!AppendQuicVarInt(
            &cursor, limit,
            packet_number_len + plaintext_length + kQuicTagLength)) {
      return false;
    }
  }
  const size_t packet_number_offset = cursor - packet;
  if (!append_byte(static_cast<uint8_t>(*packet_number >> 8)) ||
      !append_byte(static_cast<uint8_t>(*packet_number))) {
    return false;
  }
  if (static_cast<size_t>(cursor - packet) != header_length) return false;

  std::array<uint8_t, kQuicDatagramSlotPayloadCapacity> plaintext;
  if (!payload.empty())
    memcpy(plaintext.data(), payload.data(), payload.size());
  if (plaintext_length > payload.size()) {
    memset(plaintext.data() + payload.size(), 0,
           plaintext_length - payload.size());
  }
  size_t ciphertext_length = 0;
  if (!SealQuicPacketPayloadInto(keys, *packet_number, plaintext.data(),
                                 plaintext_length, packet, header_length,
                                 cursor, packet_capacity - header_length,
                                 &ciphertext_length) ||
      ciphertext_length != plaintext_length + kQuicTagLength ||
      !ApplyQuicHeaderProtectionInPlace(
          keys, packet_number_offset, packet_number_len,
          level != ssl_encryption_application, packet,
          header_length + ciphertext_length)) {
    return false;
  }
  *packet_length = header_length + ciphertext_length;
  return true;
}

QuicPacketWriteResult DatagramSSLFilter::WriteProtectedPacket(
    ssl_encryption_level_t level,
    const std::vector<uint8_t>& payload,
    bool ack_eliciting,
    bool retransmittable,
    uint32_t path_id) {
  const int space_index = QuicPacketNumberSpaceIndex(level);
  const uint64_t packet_number = next_packet_number_[space_index];
  size_t packet_length = 0;

  if (use_native_udp_) {
    auto path = native_paths_.find(path_id);
    if (path == native_paths_.end()) {
      path = native_paths_.find(active_path_id_);
    }
    if (path == native_paths_.end() || path->second.socket->fd() < 0) {
      return QuicPacketWriteResult::kError;
    }
    std::array<uint8_t, kQuicDatagramSlotPayloadCapacity> packet;
    if (!BuildProtectedPacketInto(level, payload, packet.data(), packet.size(),
                                  &packet_length)) {
      return QuicPacketWriteResult::kError;
    }
    const intptr_t sent = SocketBase::SendTo(
        path->second.socket->fd(), packet.data(), packet_length,
        path->second.remote_address, SocketBase::kAsync);
    if (sent == 0) {
      native_udp_write_blocked_ = true;
      return QuicPacketWriteResult::kBlocked;
    }
    if (sent < 0 || static_cast<size_t>(sent) != packet_length) {
      return QuicPacketWriteResult::kError;
    }
  } else {
    QuicDatagramSlotRing output(
        buffers_[kWriteEncrypted],
        kQuicDatagramSlotSize * kQuicNetworkOutputDatagramSlotCount,
        network_output_starts_[kWriteEncrypted],
        network_output_ends_[kWriteEncrypted],
        kQuicNetworkOutputDatagramSlotCount);
    uint8_t* packet = nullptr;
    size_t packet_capacity = 0;
    if (!output.Reserve(path_id, &packet, &packet_capacity)) {
      return QuicPacketWriteResult::kBlocked;
    }
    if (!BuildProtectedPacketInto(level, payload, packet, packet_capacity,
                                  &packet_length) ||
        !output.Commit(packet_length)) {
      return QuicPacketWriteResult::kError;
    }
    network_output_ends_[kWriteEncrypted] = output.end();
  }

  next_packet_number_[space_index]++;
  if (ack_eliciting) {
    recovery_.OnPacketSent(level, packet_number,
                           level == ssl_encryption_application
                               ? application_write_key_generation_
                               : 0,
                           packet_length, payload, retransmittable, path_id,
                           TimerUtils::GetCurrentMonotonicMicros());
  }
  return QuicPacketWriteResult::kSent;
}

bool DatagramSSLFilter::QueueProtectedPacket(
    ssl_encryption_level_t level,
    const std::vector<uint8_t>& payload,
    bool ack_eliciting,
    bool retransmittable,
    bool bypass_congestion,
    uint32_t path_id,
    bool control) {
  if (draining_ || connection_terminated_ ||
      (local_closing_ && !bypass_congestion) ||
      recovery_.IsPacketNumberSpaceDiscarded(level)) {
    return false;
  }
  const size_t estimated_size =
      level == ssl_encryption_initial
          ? kQuicMinInitialDatagramSize
          : payload.size() + destination_connection_id_.size() +
                kQuicTagLength + kQuicPacketNumberLength + 1;
  if (path_id == std::numeric_limits<uint32_t>::max()) {
    path_id = active_path_id_;
  }
  const auto queue_pending = [&]() {
    QuicPendingPacket pending{payload, ack_eliciting,     retransmittable,
                              path_id, bypass_congestion, control};
    if (control) {
      pending_packets_[level].push_front(std::move(pending));
    } else {
      pending_packets_[level].push_back(std::move(pending));
    }
  };
  if ((ack_eliciting && !bypass_congestion &&
       !recovery_.CanSend(estimated_size)) ||
      !HasNetworkOutputSlot()) {
    queue_pending();
    return true;
  }

  const QuicPacketWriteResult result = WriteProtectedPacket(
      level, payload, ack_eliciting, retransmittable, path_id);
  if (result == QuicPacketWriteResult::kBlocked) {
    queue_pending();
    return true;
  }
  return result == QuicPacketWriteResult::kSent;
}

bool DatagramSSLFilter::HasNetworkOutputSlot() const {
  if (use_native_udp_) return !native_udp_write_blocked_;
  if (network_output_starts_ == nullptr || network_output_ends_ == nullptr) {
    return false;
  }
  QuicDatagramSlotRing output(
      buffers_[kWriteEncrypted],
      kQuicDatagramSlotSize * kQuicNetworkOutputDatagramSlotCount,
      network_output_starts_[kWriteEncrypted],
      network_output_ends_[kWriteEncrypted],
      kQuicNetworkOutputDatagramSlotCount);
  return output.valid() && !output.full();
}

void DatagramSSLFilter::FlushPendingPackets() {
  for (int i = 0; i < 4; i++) {
    const auto level = static_cast<ssl_encryption_level_t>(i);
    if (recovery_.IsPacketNumberSpaceDiscarded(level)) {
      pending_packets_[i].clear();
      continue;
    }
    auto& pending = pending_packets_[i];
    while (!pending.empty()) {
      if (!HasNetworkOutputSlot()) {
        break;
      }
      const QuicPendingPacket& next = pending.front();
      const size_t estimated_size =
          level == ssl_encryption_initial
              ? kQuicMinInitialDatagramSize
              : next.payload.size() + destination_connection_id_.size() +
                    kQuicTagLength + kQuicPacketNumberLength + 1;
      if (next.ack_eliciting && !next.bypass_congestion &&
          !recovery_.CanSend(estimated_size)) {
        break;
      }
      if (use_native_udp_) {
        const QuicPendingPacket& packet = pending.front();
        const QuicPacketWriteResult result =
            WriteProtectedPacket(level, packet.payload, packet.ack_eliciting,
                                 packet.retransmittable, packet.path_id);
        if (result != QuicPacketWriteResult::kSent) break;
        pending.pop_front();
      } else {
        QuicPendingPacket packet = std::move(pending.front());
        pending.pop_front();
        QueueProtectedPacket(level, packet.payload, packet.ack_eliciting,
                             packet.retransmittable, packet.bypass_congestion,
                             packet.path_id, packet.control);
      }
    }
  }
}

bool DatagramSSLFilter::OnAckReceived(
    ssl_encryption_level_t level,
    const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges,
    uint64_t ack_delay) {
  const int space_index = QuicPacketNumberSpaceIndex(level);
  QuicRecoveryResult result = recovery_.OnAckReceived(
      level, ack_ranges, ack_delay, next_packet_number_[space_index],
      application_write_key_generation_,
      TimerUtils::GetCurrentMonotonicMicros());
  if (!result.valid) {
    return false;
  }
  if (result.current_application_key_generation_acked) {
    application_write_key_generation_acked_ = true;
  }
  RequeueLostPackets(std::move(result.lost_packets));
  FlushPendingPackets();
  return true;
}

bool DatagramSSLFilter::RequeueLostPackets(
    std::vector<QuicSentPacket> lost_packets) {
  const bool lost_any = !lost_packets.empty();
  for (QuicSentPacket& lost : lost_packets) {
    if (!lost.retransmittable_payload.empty()) {
      const ssl_encryption_level_t retransmit_level =
          lost.encryption_level == ssl_encryption_early_data
              ? ApplicationWriteLevel()
              : lost.encryption_level;
      pending_packets_[retransmit_level].push_front(QuicPendingPacket{
          std::move(lost.retransmittable_payload), true, true, lost.path_id});
    }
  }
  if (lost_any) {
    internal_progress_ = true;
  }
  return lost_any;
}

int64_t DatagramSSLFilter::NextTimeoutMillis() {
  if (connection_terminated_) {
    return -1;
  }
  const int64_t now = TimerUtils::GetCurrentMonotonicMicros();
  if (draining_) {
    const int64_t remaining = draining_deadline_micros_ - now;
    return remaining <= 0 ? 0 : (remaining + 999) / 1000;
  }
  if (local_closing_) {
    const int64_t remaining = closing_deadline_micros_ - now;
    return remaining <= 0 ? 0 : (remaining + 999) / 1000;
  }
  int64_t deadline = recovery_.NextDeadlineMicros();
  for (int i = 0; i < 4; i++) {
    if (ack_deadline_micros_[i] >= 0 &&
        (deadline < 0 || ack_deadline_micros_[i] < deadline)) {
      deadline = ack_deadline_micros_[i];
    }
  }
  if (previous_application_read_keys_expiry_micros_ >= 0 &&
      (deadline < 0 ||
       previous_application_read_keys_expiry_micros_ < deadline)) {
    deadline = previous_application_read_keys_expiry_micros_;
  }
  if (path_validation_deadline_micros_ >= 0 &&
      (deadline < 0 || path_validation_deadline_micros_ < deadline)) {
    deadline = path_validation_deadline_micros_;
  }
  if (idle_deadline_micros_ >= 0 &&
      (deadline < 0 || idle_deadline_micros_ < deadline)) {
    deadline = idle_deadline_micros_;
  }
  if (deadline < 0) {
    return -1;
  }
  const int64_t remaining = deadline - now;
  return remaining <= 0 ? 0 : (remaining + 999) / 1000;
}

void DatagramSSLFilter::ProcessTimers() {
  const int64_t now = TimerUtils::GetCurrentMonotonicMicros();
  if (connection_terminated_) {
    return;
  }
  if (draining_) {
    if (draining_deadline_micros_ >= 0 && draining_deadline_micros_ <= now) {
      connection_terminated_ = true;
      internal_progress_ = true;
    }
    return;
  }
  if (local_closing_) {
    if (closing_deadline_micros_ >= 0 && closing_deadline_micros_ <= now) {
      connection_terminated_ = true;
      internal_progress_ = true;
    }
    return;
  }
  if (idle_deadline_micros_ >= 0 && idle_deadline_micros_ <= now) {
    StartIdleTimeout();
    return;
  }
  if (previous_application_read_keys_expiry_micros_ >= 0 &&
      previous_application_read_keys_expiry_micros_ <= now) {
    RetirePreviousApplicationReadKeys();
  }
  for (int i = 0; i < 4; i++) {
    if (ack_deadline_micros_[i] >= 0 && ack_deadline_micros_[i] <= now) {
      EmitAck(static_cast<ssl_encryption_level_t>(i), pending_ack_path_id_[i]);
    }
  }
  if (path_validation_pending_ && path_validation_deadline_micros_ <= now) {
    if (path_validation_attempts_ >= 3) {
      CompletePathValidation(false);
    } else {
      path_validation_attempts_++;
      std::vector<uint8_t> payload;
      AppendPathChallengeFrame(&payload, path_challenge_);
      QueueProtectedPacket(ssl_encryption_application, payload, true, false,
                           true, validating_path_id_);
      path_validation_deadline_micros_ =
          now + recovery_.ProbeTimeoutMicros(ssl_encryption_application);
      internal_progress_ = true;
    }
    return;
  }
  bool detected_loss = false;
  for (int i = 0; i < 4; i++) {
    if (i == ssl_encryption_early_data) continue;
    const auto level = static_cast<ssl_encryption_level_t>(i);
    if (recovery_.IsPacketNumberSpaceDiscarded(level)) {
      continue;
    }
    const int64_t loss_time = recovery_.LossTimeMicros(level);
    if (loss_time >= 0 && loss_time <= now) {
      detected_loss |=
          RequeueLostPackets(recovery_.DetectLostPackets(level, now));
    }
  }
  if (detected_loss) {
    FlushPendingPackets();
    return;
  }

  QuicRecoveryProbe probe;
  if (!recovery_.GetProbe(now, &probe)) {
    return;
  }

  std::vector<uint8_t> probe_payload;
  bool retransmittable = false;
  uint32_t probe_path_id = active_path_id_;
  ssl_encryption_level_t probe_encryption_level = probe.encryption_level;
  if (probe.has_packet && !probe.packet.retransmittable_payload.empty()) {
    probe_payload = probe.packet.retransmittable_payload;
    retransmittable = true;
    probe_path_id = probe.packet.path_id;
    probe_encryption_level =
        probe.packet.encryption_level == ssl_encryption_early_data
            ? ApplicationWriteLevel()
            : probe.packet.encryption_level;
  } else {
    AppendVarInt(&probe_payload, 0x01);
  }
  QueueProtectedPacket(probe_encryption_level, probe_payload, true,
                       retransmittable, true, probe_path_id);
  recovery_.OnProbeSent();
  internal_progress_ = true;
}

int DatagramSSLFilter::AddCryptoData(ssl_encryption_level_t level,
                                     uint64_t frame_offset,
                                     const uint8_t* data,
                                     size_t len,
                                     bool* provided_crypto) {
  if (len > std::numeric_limits<uint64_t>::max() - frame_offset) {
    return 1;
  }

  QuicCryptoReceiveState* state = &crypto_receive_[level];
  uint64_t frame_end = frame_offset + len;
  if (frame_end <= state->offset) {
    return 0;
  }
  if (frame_offset < state->offset) {
    const size_t already_received =
        static_cast<size_t>(state->offset - frame_offset);
    data += already_received;
    len -= already_received;
    frame_offset = state->offset;
  }

  uint64_t merged_start = frame_offset;
  uint64_t merged_end = frame_offset + len;
  auto first = state->pending.lower_bound(merged_start);
  if (first != state->pending.begin()) {
    auto previous = std::prev(first);
    const uint64_t previous_end = previous->first + previous->second.size();
    if (previous_end >= merged_start) {
      first = previous;
    }
  }

  auto last = first;
  while (last != state->pending.end() && last->first <= merged_end) {
    merged_start = std::min(merged_start, last->first);
    merged_end = std::max(
        merged_end, last->first + static_cast<uint64_t>(last->second.size()));
    ++last;
  }

  std::vector<uint8_t> merged(static_cast<size_t>(merged_end - merged_start));
  for (auto current = first; current != last; ++current) {
    memcpy(merged.data() + (current->first - merged_start),
           current->second.data(), current->second.size());
  }
  memcpy(merged.data() + (frame_offset - merged_start), data, len);
  state->pending.erase(first, last);
  state->pending.emplace(merged_start, std::move(merged));

  while (!state->pending.empty()) {
    auto current = state->pending.begin();
    if (current->first > state->offset) {
      break;
    }
    const size_t consumed = static_cast<size_t>(state->offset - current->first);
    if (consumed >= current->second.size()) {
      state->pending.erase(current);
      continue;
    }
    const uint8_t* contiguous = current->second.data() + consumed;
    const size_t contiguous_len = current->second.size() - consumed;
    if (SSL_provide_quic_data(ssl_, level, contiguous, contiguous_len) != 1) {
      return 1;
    }
    state->offset += contiguous_len;
    state->pending.erase(current);
    *provided_crypto = true;
  }
  return 0;
}

int DatagramSSLFilter::ParseFrames(ssl_encryption_level_t level,
                                   const uint8_t* data,
                                   size_t len,
                                   uint64_t local_connection_id_sequence,
                                   uint32_t path_id,
                                   bool* provided_crypto,
                                   bool* ack_eliciting,
                                   QuicFrameError* error) {
  size_t offset = 0;
  while (offset < len) {
    const size_t frame_start = offset;
    uint64_t frame_type = 0;
    const auto fail = [&](uint64_t error_code, const char* reason) {
      SetQuicFrameError(error, error_code, frame_type, reason);
      return 1;
    };
    if (!ReadVarInt(data, len, &offset, &frame_type)) {
      return fail(0x07, "truncated frame type");
    }
    if (frame_type == 0x00) {
      continue;
    }
    if (frame_type != 0x02 && frame_type != 0x03 && frame_type != 0x1c &&
        frame_type != 0x1d) {
      *ack_eliciting = true;
    }
    if (frame_type == 0x1c || frame_type == 0x1d) {
      if (frame_type == 0x1d && level != ssl_encryption_application) {
        return fail(0x0a, "APPLICATION_CLOSE at invalid encryption level");
      }
      uint64_t error_code = 0;
      uint64_t triggering_frame_type = 0;
      uint64_t reason_len = 0;
      if (!ReadVarInt(data, len, &offset, &error_code) ||
          (frame_type == 0x1c &&
           !ReadVarInt(data, len, &offset, &triggering_frame_type)) ||
          !ReadVarInt(data, len, &offset, &reason_len) ||
          reason_len > len - offset) {
        return fail(0x07, "malformed CONNECTION_CLOSE frame");
      }
      StartPeerClose(
          frame_type == 0x1c ? QuicTerminationType::kTransportClose
                             : QuicTerminationType::kApplicationClose,
          error_code,
          frame_type == 0x1c ? static_cast<int64_t>(triggering_frame_type) : -1,
          data + offset, static_cast<size_t>(reason_len), level);
      return 0;
    }
    if (frame_type == 0x01) {
      continue;
    }
    if (frame_type == 0x06) {
      if (level == ssl_encryption_early_data) {
        return fail(0x0a, "CRYPTO frame in 0-RTT packet");
      }
      uint64_t crypto_offset = 0;
      uint64_t crypto_len = 0;
      if (!ReadVarInt(data, len, &offset, &crypto_offset)) {
        return fail(0x07, "truncated CRYPTO offset");
      }
      if (!ReadVarInt(data, len, &offset, &crypto_len)) {
        return fail(0x07, "truncated CRYPTO length");
      }
      if (offset + crypto_len > len) {
        return fail(0x07, "truncated CRYPTO data");
      }
      if (AddCryptoData(level, crypto_offset, data + offset,
                        static_cast<size_t>(crypto_len), provided_crypto)) {
        return fail(0x0d, "CRYPTO data exceeded receiver capacity");
      }
      offset += crypto_len;
      continue;
    }
    if (frame_type == 0x07) {
      if (level != ssl_encryption_application) {
        return fail(0x0a, "NEW_TOKEN at invalid encryption level");
      }
      uint64_t token_len = 0;
      if (!ReadVarInt(data, len, &offset, &token_len) || token_len == 0 ||
          token_len > len - offset) {
        return fail(0x07, "malformed NEW_TOKEN frame");
      }
      std::vector<uint8_t> token(data + offset, data + offset + token_len);
      offset += static_cast<size_t>(token_len);
      bool duplicate = false;
      for (const auto& existing : new_tokens_) {
        if (existing == token) {
          duplicate = true;
          break;
        }
      }
      if (!duplicate) {
        new_tokens_.push_back(std::move(token));
      }
      continue;
    }
    if (frame_type == 0x18) {
      if (level != ssl_encryption_application) {
        return fail(0x0a, "NEW_CONNECTION_ID at invalid encryption level");
      }
      uint64_t sequence = 0;
      uint64_t retire_prior_to = 0;
      if (!ReadVarInt(data, len, &offset, &sequence) ||
          !ReadVarInt(data, len, &offset, &retire_prior_to) ||
          retire_prior_to > sequence || offset >= len) {
        return fail(0x07, "malformed NEW_CONNECTION_ID frame");
      }
      const uint8_t connection_id_len = data[offset++];
      if (connection_id_len == 0 || connection_id_len > 20 ||
          offset + connection_id_len + kQuicTagLength > len) {
        return fail(0x07, "invalid NEW_CONNECTION_ID connection ID");
      }
      QuicPeerConnectionId received;
      received.connection_id.assign(data + offset,
                                    data + offset + connection_id_len);
      offset += connection_id_len;
      received.stateless_reset_token.assign(data + offset,
                                            data + offset + kQuicTagLength);
      offset += kQuicTagLength;

      auto existing = peer_connection_ids_.find(sequence);
      if (existing != peer_connection_ids_.end()) {
        if (existing->second.connection_id != received.connection_id ||
            existing->second.stateless_reset_token !=
                received.stateless_reset_token) {
          return fail(0x0a, "NEW_CONNECTION_ID changes an existing sequence");
        }
      } else {
        for (const auto& entry : peer_connection_ids_) {
          if (entry.second.connection_id == received.connection_id) {
            return fail(0x0a, "NEW_CONNECTION_ID reuses a connection ID");
          }
        }
        peer_connection_ids_[sequence] = std::move(received);
      }

      std::vector<uint64_t> retired_sequences;
      for (auto& entry : peer_connection_ids_) {
        if (entry.first >= retire_prior_to || entry.second.retired) {
          continue;
        }
        entry.second.retired = true;
        retired_sequences.push_back(entry.first);
      }
      const auto current =
          peer_connection_ids_.find(current_peer_connection_id_sequence_);
      if (current != peer_connection_ids_.end() && current->second.retired &&
          !SelectPeerConnectionId(retire_prior_to)) {
        return fail(
            0x0a,
            "NEW_CONNECTION_ID retired the active ID without replacement");
      }
      for (const uint64_t sequence_to_retire : retired_sequences) {
        std::vector<uint8_t> retire;
        AppendRetireConnectionIdFrame(&retire, sequence_to_retire);
        QueueProtectedPacket(ssl_encryption_application, retire, true, true);
      }
      size_t active = 0;
      for (const auto& entry : peer_connection_ids_) {
        if (!entry.second.retired) {
          active++;
        }
      }
      if (active > kQuicLocalActiveConnectionIdLimit) {
        return fail(0x09, "active_connection_id_limit exceeded");
      }
      continue;
    }
    if (frame_type == 0x19) {
      if (level != ssl_encryption_application) {
        return fail(0x0a, "RETIRE_CONNECTION_ID at invalid encryption level");
      }
      uint64_t sequence = 0;
      if (!ReadVarInt(data, len, &offset, &sequence)) {
        return fail(0x07, "truncated RETIRE_CONNECTION_ID frame");
      }
      auto connection_id = local_connection_ids_.find(sequence);
      if (connection_id == local_connection_ids_.end() ||
          sequence == local_connection_id_sequence) {
        return fail(0x0a, "invalid RETIRE_CONNECTION_ID sequence");
      }
      connection_id->second.retired = true;
      MaybeIssueConnectionIds();
      continue;
    }
    if (frame_type == 0x1a) {
      if (level != ssl_encryption_application) {
        return fail(0x0a, "PATH_CHALLENGE at invalid encryption level");
      }
      if (offset + 8 > len) {
        return fail(0x07, "truncated PATH_CHALLENGE frame");
      }
      std::vector<uint8_t> response;
      AppendPathResponseFrame(&response, data + offset);
      offset += 8;
      QueueProtectedPacket(ssl_encryption_application, response, true, false,
                           true, path_id);
      continue;
    }
    if (frame_type == 0x1b) {
      if (level != ssl_encryption_application) {
        return fail(0x0a, "PATH_RESPONSE at invalid encryption level");
      }
      if (offset + 8 > len) {
        return fail(0x07, "truncated PATH_RESPONSE frame");
      }
      if (path_validation_pending_ && path_id == validating_path_id_ &&
          memcmp(data + offset, path_challenge_, sizeof(path_challenge_)) ==
              0) {
        CompletePathValidation(true);
      }
      offset += 8;
      continue;
    }
    if ((frame_type & 0xf8) == 0x08) {
      if (level != ssl_encryption_early_data &&
          level != ssl_encryption_application) {
        return fail(0x0a, "STREAM at invalid encryption level");
      }
      uint64_t stream_id = 0;
      uint64_t stream_offset = 0;
      uint64_t stream_len = 0;
      if (!ReadVarInt(data, len, &offset, &stream_id))
        return fail(0x07, "truncated STREAM identifier");
      if ((frame_type & 0x04) != 0 &&
          !ReadVarInt(data, len, &offset, &stream_offset)) {
        return fail(0x07, "truncated STREAM offset");
      }
      if ((frame_type & 0x02) != 0) {
        if (!ReadVarInt(data, len, &offset, &stream_len))
          return fail(0x07, "truncated STREAM length");
      } else {
        stream_len = len - offset;
      }
      if (offset + stream_len > len) return fail(0x07, "truncated STREAM data");
      if (!AddStreamData(frame_type, stream_id, stream_offset, data + offset,
                         static_cast<size_t>(stream_len),
                         (frame_type & 0x01) != 0, error)) {
        return 1;
      }
      if (receive_backpressured_) return 2;
      if (receive_reordered_) return 3;
      offset += stream_len;
      continue;
    }
    if (frame_type == 0x30 || frame_type == 0x31) {
      if (level != ssl_encryption_early_data &&
          level != ssl_encryption_application) {
        return fail(0x0a, "DATAGRAM at invalid encryption level");
      }
      uint64_t datagram_len = 0;
      if (frame_type == 0x31) {
        if (!ReadVarInt(data, len, &offset, &datagram_len)) {
          return fail(0x07, "truncated DATAGRAM length");
        }
      } else {
        datagram_len = len - offset;
      }
      if (offset + datagram_len > len) {
        return fail(0x07, "truncated DATAGRAM data");
      }
      if (offset + datagram_len - frame_start > kQuicMaxDatagramPayloadSize) {
        return fail(0x0a, "DATAGRAM exceeds max_datagram_frame_size");
      }
      if (datagram_len <= kQuicDatagramSlotPayloadCapacity &&
          readable_datagrams_.size() < kQuicApplicationDatagramSlotCount) {
        readable_datagrams_.push_back(
            std::vector<uint8_t>(data + offset, data + offset + datagram_len));
      }
      offset += datagram_len;
      continue;
    }
    if (frame_type == 0x02 || frame_type == 0x03) {
      if (level == ssl_encryption_early_data) {
        return fail(0x0a, "ACK frame in 0-RTT packet");
      }
      uint64_t largest_acked = 0;
      uint64_t ack_delay = 0;
      uint64_t ack_range_count = 0;
      uint64_t first_ack_range = 0;
      if (!ReadVarInt(data, len, &offset, &largest_acked) ||
          !ReadVarInt(data, len, &offset, &ack_delay) ||
          !ReadVarInt(data, len, &offset, &ack_range_count) ||
          !ReadVarInt(data, len, &offset, &first_ack_range) ||
          first_ack_range > largest_acked) {
        return fail(0x07, "malformed ACK frame");
      }
      std::vector<std::pair<uint64_t, uint64_t>> ack_ranges;
      uint64_t smallest_acked = largest_acked - first_ack_range;
      ack_ranges.emplace_back(smallest_acked, largest_acked);
      for (uint64_t i = 0; i < ack_range_count; i++) {
        uint64_t gap = 0;
        uint64_t ack_range = 0;
        if (!ReadVarInt(data, len, &offset, &gap) ||
            !ReadVarInt(data, len, &offset, &ack_range) ||
            gap > smallest_acked || smallest_acked - gap < 2) {
          return fail(0x07, "malformed ACK range");
        }
        const uint64_t range_largest = smallest_acked - gap - 2;
        if (ack_range > range_largest) {
          return fail(0x07, "invalid ACK range");
        }
        smallest_acked = range_largest - ack_range;
        ack_ranges.emplace_back(smallest_acked, range_largest);
      }
      if (frame_type == 0x03) {
        uint64_t ignored = 0;
        for (int i = 0; i < 3; i++) {
          if (!ReadVarInt(data, len, &offset, &ignored)) {
            return fail(0x07, "truncated ACK_ECN counters");
          }
        }
      }
      if (!OnAckReceived(level, ack_ranges, ack_delay)) {
        return fail(0x0a, "ACK acknowledges an unsent packet");
      }
      continue;
    }
    if (frame_type == 0x04) {
      if (level != ssl_encryption_early_data &&
          level != ssl_encryption_application) {
        return fail(0x0a, "RESET_STREAM at invalid encryption level");
      }
      uint64_t stream_id = 0;
      uint64_t error_code = 0;
      uint64_t final_size = 0;
      if (!ReadVarInt(data, len, &offset, &stream_id) ||
          !ReadVarInt(data, len, &offset, &error_code) ||
          !ReadVarInt(data, len, &offset, &final_size)) {
        return fail(0x07, "malformed RESET_STREAM frame");
      }
      if (!HandleResetStream(stream_id, error_code, final_size, error)) {
        return 1;
      }
      continue;
    }
    if (frame_type == 0x05) {
      if (level != ssl_encryption_early_data &&
          level != ssl_encryption_application) {
        return fail(0x0a, "STOP_SENDING at invalid encryption level");
      }
      uint64_t stream_id = 0;
      uint64_t error_code = 0;
      if (!ReadVarInt(data, len, &offset, &stream_id) ||
          !ReadVarInt(data, len, &offset, &error_code)) {
        return fail(0x07, "malformed STOP_SENDING frame");
      }
      if (!HandleStopSending(stream_id, error_code, error)) {
        return 1;
      }
      continue;
    }
    if (frame_type >= 0x10 && frame_type <= 0x17 &&
        level != ssl_encryption_early_data &&
        level != ssl_encryption_application) {
      return fail(0x0a, "flow-control frame at invalid encryption level");
    }
    if (frame_type == 0x10) {
      uint64_t maximum_data = 0;
      if (!ReadVarInt(data, len, &offset, &maximum_data)) {
        return fail(0x07, "truncated MAX_DATA frame");
      }
      if (maximum_data > peer_transport_parameters_.initial_max_data) {
        peer_transport_parameters_.initial_max_data = maximum_data;
        last_data_blocked_limit_ = std::numeric_limits<uint64_t>::max();
        write_ready_ = true;
      }
      continue;
    }
    if (frame_type == 0x11) {
      uint64_t stream_id = 0;
      uint64_t maximum_stream_data = 0;
      if (!ReadVarInt(data, len, &offset, &stream_id) ||
          !ReadVarInt(data, len, &offset, &maximum_stream_data)) {
        return fail(0x07, "malformed MAX_STREAM_DATA frame");
      }
      QuicStreamState* stream = stream_manager_.Find(stream_id);
      if (stream == nullptr || (!IsBidirectionalStream(stream_id) &&
                                !IsLocallyInitiatedStream(stream_id))) {
        return fail(0x05, "MAX_STREAM_DATA on invalid stream");
      }
      if (maximum_stream_data > stream->send_limit) {
        stream->send_limit = maximum_stream_data;
        stream->last_stream_data_blocked_limit =
            std::numeric_limits<uint64_t>::max();
        write_ready_ = true;
      }
      continue;
    }
    if (frame_type == 0x12 || frame_type == 0x13) {
      uint64_t maximum_streams = 0;
      if (!ReadVarInt(data, len, &offset, &maximum_streams) ||
          maximum_streams > (uint64_t{1} << 60)) {
        return fail(0x07, "invalid MAX_STREAMS limit");
      }
      uint64_t* current =
          frame_type == 0x12
              ? &peer_transport_parameters_.initial_max_streams_bidi
              : &peer_transport_parameters_.initial_max_streams_uni;
      if (maximum_streams > *current) {
        *current = maximum_streams;
        stream_manager_.PeerStreamLimitIncreased(frame_type == 0x12);
        write_ready_ = true;
      }
      continue;
    }
    if (frame_type == 0x14 || frame_type == 0x16 || frame_type == 0x17) {
      uint64_t ignored = 0;
      if (!ReadVarInt(data, len, &offset, &ignored)) {
        return fail(0x07, "truncated blocked frame");
      }
      continue;
    }
    if (frame_type == 0x15) {
      uint64_t ignored = 0;
      if (!ReadVarInt(data, len, &offset, &ignored) ||
          !ReadVarInt(data, len, &offset, &ignored)) {
        return fail(0x07, "malformed STREAM_DATA_BLOCKED frame");
      }
      continue;
    }
    if (frame_type == 0x1e) {
      if (level != ssl_encryption_application) {
        return fail(0x0a, "HANDSHAKE_DONE at invalid encryption level");
      }
      if (!handshake_confirmed_) {
        handshake_confirmed_ = true;
        DiscardPacketNumberSpace(ssl_encryption_handshake);
        if (path_validation_deferred_) {
          const uint32_t path_id = deferred_path_validation_id_;
          path_validation_deferred_ = false;
          BeginPathValidation(path_id);
        }
      }
      continue;
    }
    return fail(0x07, "unknown QUIC frame type");
  }
  return 0;
}

bool DatagramSSLFilter::ProcessAllBuffers(int starts[kNumBuffers],
                                          int ends[kNumBuffers],
                                          bool in_handshake) {
  ProcessTimers();
  QuicDatagramSlotRing application_output(
      buffers_[kReadPlaintext], buffer_size_, starts[kReadPlaintext],
      ends[kReadPlaintext], kQuicApplicationDatagramSlotCount);
  QuicDatagramSlotRing application_input(
      buffers_[kWritePlaintext], buffer_size_, starts[kWritePlaintext],
      ends[kWritePlaintext], kQuicApplicationDatagramSlotCount);
  QuicDatagramSlotRing network_input(
      buffers_[kReadEncrypted],
      kQuicDatagramSlotSize * (use_native_udp_
                                   ? kQuicNativeHandshakeInputSlotCount
                                   : kQuicNetworkInputDatagramSlotCount),
      starts[kReadEncrypted], ends[kReadEncrypted],
      use_native_udp_ ? kQuicNativeHandshakeInputSlotCount
                      : kQuicNetworkInputDatagramSlotCount);
  QuicDatagramSlotRing network_output(
      buffers_[kWriteEncrypted],
      kQuicDatagramSlotSize *
          (use_native_udp_ ? 0 : kQuicNetworkOutputDatagramSlotCount),
      starts[kWriteEncrypted], ends[kWriteEncrypted],
      use_native_udp_ ? 0 : kQuicNetworkOutputDatagramSlotCount);
  if (!application_output.valid() || !application_input.valid() ||
      !network_input.valid() || !network_output.valid()) {
    return false;
  }
  network_output_starts_ = starts;
  network_output_ends_ = ends;
  // Commands and timers run before this method, so give already-pending work
  // the first available slots before processing another input burst.
  FlushPendingPackets();

  auto flush_readable_datagrams = [&]() {
    while (!readable_datagrams_.empty()) {
      const std::vector<uint8_t>& payload = readable_datagrams_.front();
      if (!application_output.Write(0, payload.data(), payload.size())) {
        break;
      }
      readable_datagrams_.pop_front();
    }
    return readable_datagrams_.empty();
  };

  bool pause_network_input = !flush_readable_datagrams();
  const size_t deferred_count = deferred_encrypted_datagrams_.size();
  for (size_t i = 0; i < deferred_count && !pause_network_input; i++) {
    QuicDatagram datagram = std::move(deferred_encrypted_datagrams_.front());
    deferred_encrypted_datagrams_.pop_front();
    std::vector<uint8_t> deferred;
    bool provided_crypto = false;
    const int decode_result = DecodeProtectedDatagram(
        datagram.payload.data(), datagram.payload.size(), datagram.path_id,
        &deferred, &provided_crypto);
    if (decode_result == 2) {
      deferred_encrypted_datagrams_.push_front(std::move(datagram));
      pause_network_input = true;
    } else if (decode_result != 0 && decode_result != 3) {
      return false;
    }
    if (decode_result == 0 && !deferred.empty()) {
      // Do not retry a still-undecryptable packet tail in this pass. The
      // caller first needs to drive TLS so the next encryption-level keys can
      // be installed.
      deferred_encrypted_datagrams_.push_back(
          QuicDatagram{std::move(deferred), datagram.path_id});
    }
    if (provided_crypto) {
      handshake_crypto_progress_ = true;
      internal_progress_ = true;
    }
    if (!flush_readable_datagrams()) {
      pause_network_input = true;
    }
  }

  if (!pause_network_input && !native_pump_started_ && !native_paths_.empty()) {
    std::array<uint8_t, 65536> datagram;
    for (auto entry = native_paths_.begin(); entry != native_paths_.end();
         ++entry) {
      Socket* socket = entry->second.socket;
      bool already_drained = false;
      for (auto previous = native_paths_.begin(); previous != entry;
           ++previous) {
        if (previous->second.socket == socket) {
          already_drained = true;
          break;
        }
      }
      if (already_drained) {
        continue;
      }
      while (!pause_network_input) {
        RawAddr sender;
        const intptr_t received =
            SocketBase::RecvFrom(socket->fd(), datagram.data(), datagram.size(),
                                 &sender, SocketBase::kAsync);
        if (received == 0) break;
        if (received < 0) return false;
        if (static_cast<size_t>(received) > kQuicDatagramSlotPayloadCapacity) {
          continue;
        }

        uint32_t path_id = std::numeric_limits<uint32_t>::max();
        for (const auto& candidate : native_paths_) {
          if (candidate.second.socket == socket &&
              SocketAddress::AreAddressesEqual(candidate.second.remote_address,
                                               sender) &&
              SocketAddress::GetAddrPort(candidate.second.remote_address) ==
                  SocketAddress::GetAddrPort(sender)) {
            path_id = candidate.first;
            break;
          }
        }
        if (path_id == std::numeric_limits<uint32_t>::max()) {
          continue;
        }

        std::vector<uint8_t> deferred;
        bool provided_crypto = false;
        const int decode_result = DecodeProtectedDatagram(
            datagram.data(), static_cast<size_t>(received), path_id, &deferred,
            &provided_crypto);
        if (decode_result == 2) {
          deferred_encrypted_datagrams_.push_front(
              QuicDatagram{std::vector<uint8_t>(datagram.begin(),
                                                datagram.begin() + received),
                           path_id});
          pause_network_input = true;
          internal_progress_ = true;
          break;
        }
        if (decode_result == 3) {
          // Leave the packet unacknowledged. A retransmission can be accepted
          // after the missing STREAM range arrives.
          continue;
        }
        if (decode_result != 0) return false;
        if (!deferred.empty()) {
          deferred_encrypted_datagrams_.push_back(
              QuicDatagram{std::move(deferred), path_id});
        }
        if (!flush_readable_datagrams()) {
          pause_network_input = true;
          break;
        }
        if (provided_crypto) {
          handshake_crypto_progress_ = true;
          internal_progress_ = true;
        }
      }
      if (pause_network_input) break;
    }
  }

  while (!pause_network_input) {
    const uint8_t* datagram = nullptr;
    size_t datagram_length = 0;
    uint32_t path_id = 0;
    if (!network_input.Peek(&datagram, &datagram_length, &path_id)) {
      if (!network_input.empty()) return false;
      break;
    }
    std::vector<uint8_t> deferred;
    bool provided_crypto = false;
    const int decode_result = DecodeProtectedDatagram(
        datagram, datagram_length, path_id, &deferred, &provided_crypto);
    if (decode_result == 2) {
      // Keep the UDP slot in place. Once Dart consumes plaintext, the next
      // filter request decrypts and parses this packet again.
      pause_network_input = true;
      internal_progress_ = true;
      break;
    }
    if (decode_result == 3) {
      // Leave the packet unacknowledged. A retransmission can be accepted
      // after the missing STREAM range arrives.
      network_input.Consume();
      continue;
    }
    if (decode_result != 0) {
      return false;
    }
    network_input.Consume();
    if (!deferred.empty()) {
      deferred_encrypted_datagrams_.push_back(
          QuicDatagram{std::move(deferred), path_id});
    }
    if (!flush_readable_datagrams()) {
      break;
    }
    if (provided_crypto) {
      handshake_crypto_progress_ = true;
      internal_progress_ = true;
    }
  }

  if (!in_handshake) {
    ProcessPostHandshake();
  }

  const bool can_process_application_input = !in_handshake || IsInEarlyData();
  if (can_process_application_input) {
    while (true) {
      const uint8_t* payload = nullptr;
      size_t payload_length = 0;
      uint32_t unused_id = 0;
      if (!application_input.Peek(&payload, &payload_length, &unused_id)) {
        if (!application_input.empty()) return false;
        break;
      }
      QueueDatagramFrame(payload, 0, static_cast<intptr_t>(payload_length));
      application_input.Consume();
    }
  }

  // The network ring can contain a burst of UDP datagrams.  Accumulate their
  // packet numbers first so one ACK frame covers the whole contiguous burst.
  FlushDueAcks();

  starts[kWritePlaintext] = application_input.start();
  starts[kReadEncrypted] = network_input.start();
  ends[kReadPlaintext] = application_output.end();
  return true;
}

bool DatagramSSLFilter::ProcessNativeNetworkInput(size_t packet_budget) {
  bool provided_crypto_data = false;
  const size_t deferred_count = deferred_encrypted_datagrams_.size();
  for (size_t i = 0; i < deferred_count && packet_budget != 0 &&
                     !deferred_encrypted_datagrams_.empty();
       i++) {
    QuicDatagram datagram = std::move(deferred_encrypted_datagrams_.front());
    deferred_encrypted_datagrams_.pop_front();
    std::vector<uint8_t> deferred;
    bool provided_crypto = false;
    const int decode_result = DecodeProtectedDatagram(
        datagram.payload.data(), datagram.payload.size(), datagram.path_id,
        &deferred, &provided_crypto);
    if (decode_result == 2) {
      deferred_encrypted_datagrams_.push_front(std::move(datagram));
      native_receive_blocked_ = true;
      native_receive_blocked_stream_id_ = receive_backpressured_stream_id_;
      return true;
    }
    if (decode_result != 0 && decode_result != 3) return false;
    if (decode_result == 0 && !deferred.empty()) {
      deferred_encrypted_datagrams_.push_back(
          QuicDatagram{std::move(deferred), datagram.path_id});
    }
    if (provided_crypto) provided_crypto_data = true;
    packet_budget--;
  }

  std::array<uint8_t, 65536> datagram;
  std::set<Socket*> drained_sockets;
  for (const auto& entry : native_paths_) {
    if (packet_budget == 0) break;
    Socket* socket = entry.second.socket;
    if (!drained_sockets.insert(socket).second) continue;
    while (packet_budget != 0) {
      RawAddr sender;
      const intptr_t received =
          SocketBase::RecvFrom(socket->fd(), datagram.data(), datagram.size(),
                               &sender, SocketBase::kAsync);
      if (received == 0) break;
      if (received < 0) return false;
      packet_budget--;
      if (static_cast<size_t>(received) > kQuicDatagramSlotPayloadCapacity) {
        continue;
      }

      uint32_t path_id = std::numeric_limits<uint32_t>::max();
      for (const auto& candidate : native_paths_) {
        if (candidate.second.socket == socket &&
            SocketAddress::AreAddressesEqual(candidate.second.remote_address,
                                             sender) &&
            SocketAddress::GetAddrPort(candidate.second.remote_address) ==
                SocketAddress::GetAddrPort(sender)) {
          path_id = candidate.first;
          break;
        }
      }
      if (path_id == std::numeric_limits<uint32_t>::max()) continue;

      std::vector<uint8_t> deferred;
      bool provided_crypto = false;
      const int decode_result = DecodeProtectedDatagram(
          datagram.data(), static_cast<size_t>(received), path_id, &deferred,
          &provided_crypto);
      if (decode_result == 2) {
        deferred_encrypted_datagrams_.push_front(QuicDatagram{
            std::vector<uint8_t>(datagram.begin(), datagram.begin() + received),
            path_id});
        native_receive_blocked_ = true;
        native_receive_blocked_stream_id_ = receive_backpressured_stream_id_;
        return true;
      }
      if (decode_result == 3) continue;
      if (decode_result != 0) return false;
      if (!deferred.empty()) {
        deferred_encrypted_datagrams_.push_back(
            QuicDatagram{std::move(deferred), path_id});
      }
      if (provided_crypto) provided_crypto_data = true;
    }
  }
  if (provided_crypto_data) {
    handshake_crypto_progress_ = true;
    internal_progress_ = true;
  }
  return true;
}

bool DatagramSSLFilter::FlushOutgoingDatagrams(int starts[kNumBuffers],
                                               int ends[kNumBuffers]) {
  // ProcessStreamBuffers can have produced packets after ProcessAllBuffers.
  // They use the same external ring, so this last pass only drains plaintext
  // work that became sendable during the request.
  FlushPendingPackets();
  if (!use_native_udp_ && !HasNetworkOutputSlot()) {
    for (const auto& pending : pending_packets_) {
      if (!pending.empty()) {
        // Dart will drain the shared UDP slots after this response. Continue
        // once so the newly freed slots do not strand buffered STREAM data.
        internal_progress_ = true;
        break;
      }
    }
  }
  network_output_starts_ = nullptr;
  network_output_ends_ = nullptr;
  return true;
}

bool DatagramSSLFilter::CommitStreamReadCursor(uint64_t stream_id,
                                               int read_start) {
  QuicStreamState* stream = stream_manager_.Find(stream_id);
  if (stream == nullptr || stream->application_read_buffer.data() == nullptr) {
    return false;
  }
  size_t consumed_bytes = 0;
  if (!stream->application_read_buffer.CommitStart(read_start,
                                                   &consumed_bytes)) {
    return false;
  }
  if (consumed_bytes != 0) {
    MaybeIncreaseReceiveWindows(stream_id, consumed_bytes);
  }
  return true;
}

bool DatagramSSLFilter::PrepareStreamBuffers(const CObjectArray& request,
                                             intptr_t request_offset,
                                             intptr_t stream_count) {
  static constexpr intptr_t kRequestSize = 8;

  for (intptr_t i = 0; i < stream_count; i++) {
    const intptr_t input = request_offset + i * kRequestSize;
    const intptr_t stream_id_value = CObjectIntptr(request[input]).Value();
    const int read_start = CObjectIntptr(request[input + 1]).Value();
    const int read_end = CObjectIntptr(request[input + 2]).Value();
    if (stream_id_value < 0) return false;

    const uint64_t stream_id = static_cast<uint64_t>(stream_id_value);
    QuicStreamState* stream = stream_manager_.Find(stream_id);
    if (stream == nullptr ||
        stream->application_read_buffer.data() == nullptr ||
        read_end != stream->published_read_end) {
      return false;
    }

    if (!CommitStreamReadCursor(stream_id, read_start)) return false;
  }
  return true;
}

bool DatagramSSLFilter::ProcessStreamBuffers(const CObjectArray& request,
                                             intptr_t request_offset,
                                             intptr_t stream_count,
                                             bool in_handshake,
                                             CObjectArray* result,
                                             intptr_t result_offset) {
  static constexpr intptr_t kRequestSize = 8;
  static constexpr intptr_t kResponseSize = 7;
  static constexpr int kFinRequested = 1;
  static constexpr int kResetRequested = 2;
  static constexpr int kStopSendingRequested = 4;
  static constexpr int kReleaseRequested = 8;

  const bool can_process_application_input = !in_handshake || IsInEarlyData();

  for (intptr_t i = 0; i < stream_count; i++) {
    const intptr_t input = request_offset + i * kRequestSize;
    const intptr_t output = result_offset + i * kResponseSize;
    const intptr_t stream_id_value = CObjectIntptr(request[input]).Value();
    const int read_end = CObjectIntptr(request[input + 2]).Value();
    const int write_start = CObjectIntptr(request[input + 3]).Value();
    const int write_end = CObjectIntptr(request[input + 4]).Value();
    const int command_flags = CObjectIntptr(request[input + 5]).Value();
    const intptr_t reset_error_code = CObjectIntptr(request[input + 6]).Value();
    const intptr_t stop_error_code = CObjectIntptr(request[input + 7]).Value();
    if (stream_id_value < 0 || reset_error_code < 0 || stop_error_code < 0 ||
        (command_flags & ~(kFinRequested | kResetRequested |
                           kStopSendingRequested | kReleaseRequested)) != 0) {
      return false;
    }
    const uint64_t stream_id = static_cast<uint64_t>(stream_id_value);
    QuicStreamState* stream = stream_manager_.Find(stream_id);
    if (stream == nullptr) return false;
    QuicStreamState& state = *stream;
    QuicCircularBuffer& read_buffer = state.application_read_buffer;
    QuicCircularBuffer& write_buffer = state.application_write_buffer;
    if (read_buffer.data() == nullptr || write_buffer.data() == nullptr ||
        read_end != state.published_read_end ||
        write_start != state.published_write_start) {
      return false;
    }

    size_t produced_bytes = 0;
    if (!write_buffer.CommitEnd(write_end, &produced_bytes)) return false;

    int applied_flags = 0;
    if (can_process_application_input &&
        (command_flags & kStopSendingRequested) != 0) {
      StreamStopSending(stream_id_value, stop_error_code);
      read_buffer.ClearAtStart();
      state.application_fin_pending = false;
      applied_flags |= kStopSendingRequested;
    }

    if (can_process_application_input &&
        (command_flags & kResetRequested) != 0) {
      write_buffer.ClearAtEnd();
      state.application_fin_pending = false;
      StreamReset(stream_id_value, reset_error_code);
      applied_flags |= kResetRequested;
    } else if (can_process_application_input) {
      if ((command_flags & kFinRequested) != 0) {
        state.application_fin_pending = true;
      }
      if (!ProcessBufferedStreamWrite(stream_id, &state)) return false;
      if ((command_flags & kFinRequested) != 0 && state.fin_sent) {
        applied_flags |= kFinRequested;
      }
    }

    result->SetAt(
        output,
        new CObjectInt64(CObject::NewInt64(static_cast<int64_t>(stream_id))));
    result->SetAt(output + 1,
                  new CObjectInt32(CObject::NewInt32(read_buffer.end())));
    state.published_read_end = read_buffer.end();
    result->SetAt(output + 2,
                  new CObjectInt32(CObject::NewInt32(write_buffer.start())));
    state.published_write_start = write_buffer.start();

    if ((command_flags & kReleaseRequested) != 0) {
      const bool send_closed = (!IsBidirectionalStream(stream_id) &&
                                !IsLocallyInitiatedStream(stream_id)) ||
                               state.fin_sent || state.reset_sent ||
                               state.stop_sending_received;
      const bool receive_closed =
          (!IsBidirectionalStream(stream_id) &&
           IsLocallyInitiatedStream(stream_id)) ||
          state.fin_delivered ||
          (state.reset_received && state.read_error_delivered) ||
          state.stop_sending_sent;
      if (send_closed && receive_closed && read_buffer.empty() &&
          write_buffer.empty()) {
        applied_flags |= kReleaseRequested;
        ReleaseStreamBuffers(&state);
        internal_progress_ = true;
      }
    }
    result->SetAt(output + 3,
                  new CObjectInt32(CObject::NewInt32(applied_flags)));
    int64_t read_error_code = -1;
    int64_t write_error_code = -1;
    const int event_flags = TakeStreamEvents(
        stream_id, &state, &read_error_code, &write_error_code);
    result->SetAt(output + 4, new CObjectInt32(CObject::NewInt32(event_flags)));
    result->SetAt(output + 5,
                  new CObjectInt64(CObject::NewInt64(read_error_code)));
    result->SetAt(output + 6,
                  new CObjectInt64(CObject::NewInt64(write_error_code)));
  }
  return true;
}

void DatagramSSLFilter::QueueCrypto(ssl_encryption_level_t level,
                                    const uint8_t* data,
                                    size_t len) {
  if (data == nullptr || len == 0) return;
  crypto_send_[level].chunks.push_back(std::vector<uint8_t>(data, data + len));
}

void DatagramSSLFilter::QueueAck(ssl_encryption_level_t level,
                                 uint64_t packet_number,
                                 uint32_t path_id) {
  const int space_index = QuicPacketNumberSpaceIndex(level);
  QuicReceivedPacketTracker& tracker = received_packet_trackers_[space_index];
  tracker.Add(packet_number);
  pending_ack_path_id_[space_index] = path_id;
  const int64_t now = TimerUtils::GetCurrentMonotonicMicros();
  const bool has_largest =
      has_largest_ack_eliciting_packet_number_[space_index];
  const uint64_t largest = largest_ack_eliciting_packet_number_[space_index];
  const bool reordered = has_largest && packet_number < largest;
  const bool has_gap = has_largest && packet_number > largest + 1;
  if (!has_largest || packet_number > largest) {
    largest_ack_eliciting_packet_number_[space_index] = packet_number;
    largest_ack_eliciting_packet_received_micros_[space_index] = now;
    has_largest_ack_eliciting_packet_number_[space_index] = true;
  }

  // RFC 9000 requires immediate acknowledgments during the handshake and
  // recommends them when packet reordering or loss becomes visible.
  if (level != ssl_encryption_application || reordered || has_gap) {
    EmitAck(level, path_id);
    return;
  }

  ack_eliciting_since_last_ack_[space_index]++;
  if (ack_deadline_micros_[space_index] < 0) {
    // A native UDP receive pass can return to the filter cheaply when this
    // short timer expires. Keep enough delay to coalesce adjacent kernel
    // readiness notifications without letting a one-packet tail hold up a
    // low-RTT sender for the full advertised maximum ACK delay.
    const int64_t delay = native_paths_.empty() ? kQuicMaximumAckDelayMicros
                                                : kQuicNativeAckDelayMicros;
    ack_deadline_micros_[space_index] = now + delay;
  }
}

void DatagramSSLFilter::EmitAck(ssl_encryption_level_t level,
                                uint32_t path_id) {
  const int space_index = QuicPacketNumberSpaceIndex(level);
  ack_eliciting_since_last_ack_[space_index] = 0;
  ack_deadline_micros_[space_index] = -1;
  QuicReceivedPacketTracker& tracker = received_packet_trackers_[space_index];
  static constexpr size_t kMaxAckRanges = 32;
  const std::vector<std::pair<uint64_t, uint64_t>> ranges =
      tracker.AckRanges(kMaxAckRanges);
  if (ranges.empty()) {
    return;
  }

  const auto& largest_range = ranges.back();
  std::vector<uint8_t> payload;
  AppendVarInt(&payload, 0x02);
  AppendVarInt(&payload, largest_range.second);
  uint64_t encoded_ack_delay = 0;
  if (level == ssl_encryption_application &&
      largest_ack_eliciting_packet_received_micros_[space_index] >= 0) {
    const int64_t delay_micros = std::max<int64_t>(
        0, TimerUtils::GetCurrentMonotonicMicros() -
               largest_ack_eliciting_packet_received_micros_[space_index]);
    encoded_ack_delay =
        static_cast<uint64_t>(delay_micros) >> kQuicDefaultAckDelayExponent;
  }
  AppendVarInt(&payload, encoded_ack_delay);
  AppendVarInt(&payload, ranges.size() - 1);
  AppendVarInt(&payload, largest_range.second - largest_range.first);
  for (size_t i = ranges.size() - 1; i > 0; i--) {
    const auto& higher = ranges[i];
    const auto& lower = ranges[i - 1];
    AppendVarInt(&payload, higher.first - lower.second - 2);
    AppendVarInt(&payload, lower.second - lower.first);
  }

  QueueProtectedPacket(level, payload, false, false, true, path_id);
}

void DatagramSSLFilter::FlushDueAcks() {
  const int application_space =
      QuicPacketNumberSpaceIndex(ssl_encryption_application);
  if (ack_eliciting_since_last_ack_[application_space] >= 2) {
    EmitAck(ssl_encryption_application,
            pending_ack_path_id_[application_space]);
  }
}
// TODO: Use more std move?

void DatagramSSLFilter::PacketizeCryptoFlights() {
  for (int level = 0; level < 4; level++) {
    QuicCryptoSendState* state = &crypto_send_[level];
    while (!state->chunks.empty()) {
      std::vector<uint8_t> chunk = std::move(state->chunks.front());
      state->chunks.pop_front();
      size_t chunk_offset = 0;
      while (chunk_offset < chunk.size()) {
        const ssl_encryption_level_t encryption_level =
            static_cast<ssl_encryption_level_t>(level);
        const size_t available = chunk.size() - chunk_offset;
        size_t slice_len = MaxCryptoFramePayloadLength(
            encryption_level, state->offset, available,
            destination_connection_id_.size(), source_connection_id_.size(),
            initial_token_.size());
        if (slice_len == 0) {
          return;
        }
        std::vector<uint8_t> payload;
        AppendCryptoFrame(&payload, state->offset, chunk.data() + chunk_offset,
                          slice_len);
        state->offset += slice_len;
        chunk_offset += slice_len;
        QueueProtectedPacket(encryption_level, payload, true, true);
      }
    }
  }
}

bool DatagramSSLFilter::InstallReadSecret(ssl_encryption_level_t level,
                                          const SSL_CIPHER* cipher,
                                          const uint8_t* secret,
                                          size_t secret_len) {
  QuicPacketKeys* keys = &read_keys_[level];
  if (!DeriveQuicPacketKeys(secret, secret_len, SSL_CIPHER_get_id(cipher),
                            keys)) {
    TerminateImmediately(QuicTerminationType::kTransportClose,
                         "failed to install QUIC read keys");
    termination_info_.error_code = 0x01;  // INTERNAL_ERROR
    return false;
  }
  if (level == ssl_encryption_application) {
    application_read_key_phase_ = false;
    previous_application_read_keys_ = QuicPacketKeys();
    previous_application_read_keys_expiry_micros_ = -1;
    if (!DeriveNextApplicationReadKeys()) {
      TerminateImmediately(QuicTerminationType::kTransportClose,
                           "failed to derive next QUIC read keys");
      termination_info_.error_code = 0x01;  // INTERNAL_ERROR
      return false;
    }
  }
  return true;
}

bool DatagramSSLFilter::InstallWriteSecret(ssl_encryption_level_t level,
                                           const SSL_CIPHER* cipher,
                                           const uint8_t* secret,
                                           size_t secret_len) {
  QuicPacketKeys* keys = &write_keys_[level];
  if (!DeriveQuicPacketKeys(secret, secret_len, SSL_CIPHER_get_id(cipher),
                            keys)) {
    TerminateImmediately(QuicTerminationType::kTransportClose,
                         "failed to install QUIC write keys");
    termination_info_.error_code = 0x01;  // INTERNAL_ERROR
    return false;
  }
  if (level == ssl_encryption_application) {
    one_rtt_write_keys_installed_ = true;
    application_write_key_phase_ = false;
    application_write_key_generation_ = 0;
    application_write_key_generation_start_packet_ =
        next_packet_number_[ssl_encryption_application];
    application_write_key_generation_acked_ = false;
  }
  return true;
}

void DatagramSSLFilter::InstallInitialSecrets() {
  DeriveInitialQuicPacketKeys(destination_connection_id_,
                              &write_keys_[ssl_encryption_initial],
                              &read_keys_[ssl_encryption_initial]);
}

int DatagramSSLFilter::DecodeProtectedDatagram(const uint8_t* data,
                                               size_t len,
                                               uint32_t path_id,
                                               std::vector<uint8_t>* deferred,
                                               bool* provided_crypto) {
  if (draining_ || connection_terminated_) {
    return 0;
  }
  size_t offset = 0;
  while (offset < len) {
    const size_t packet_start = offset;
    const uint8_t first = data[offset++];
    const bool long_header = (first & 0x80) != 0;
    if (long_header && packet_start + 5 <= len) {
      const uint32_t unprotected_version =
          (static_cast<uint32_t>(data[packet_start + 1]) << 24) |
          (static_cast<uint32_t>(data[packet_start + 2]) << 16) |
          (static_cast<uint32_t>(data[packet_start + 3]) << 8) |
          static_cast<uint32_t>(data[packet_start + 4]);
      if (unprotected_version == 0) {
        HandleVersionNegotiation(data + packet_start, len - packet_start);
        break;
      }
      if (unprotected_version == kQuicVersion1 && ((first & 0x30) >> 4) == 3) {
        HandleRetry(data + packet_start, len - packet_start);
        break;
      }
    }
    if ((first & 0x40) == 0) {
      DetectStatelessReset(data + packet_start, len - packet_start);
      break;
    }
    const ssl_encryption_level_t level = PacketTypeToLevel(first);
    QuicPacketKeys* keys = &read_keys_[level];
    std::vector<uint8_t> unprotected(data + packet_start, data + len);
    size_t payload_offset = 0;
    size_t payload_len = 0;
    size_t packet_end = len;
    size_t packet_number_offset = 0;
    size_t packet_number_len = 0;
    uint64_t packet_number = 0;
    uint64_t local_connection_id_sequence = 0;
    std::vector<uint8_t> peer_source_connection_id;
    std::vector<uint8_t> payload;
    bool payload_opened = false;
    bool promote_application_read_keys = false;

    if (long_header) {
      if (offset + 4 > len) {
        break;
      }
      const uint32_t version = (static_cast<uint32_t>(data[offset]) << 24) |
                               (static_cast<uint32_t>(data[offset + 1]) << 16) |
                               (static_cast<uint32_t>(data[offset + 2]) << 8) |
                               static_cast<uint32_t>(data[offset + 3]);
      if (version != kQuicVersion1) {
        break;
      }
      offset += 4;
      if (offset >= len) {
        break;
      }
      const uint8_t dcid_len = data[offset++];
      if (offset + dcid_len > len) {
        break;
      }
      offset += dcid_len;
      if (offset >= len) {
        break;
      }
      const uint8_t scid_len = data[offset++];
      if (offset + scid_len > len) {
        break;
      }
      peer_source_connection_id.assign(data + offset, data + offset + scid_len);
      offset += scid_len;
      if (level == ssl_encryption_initial) {
        uint64_t token_len = 0;
        if (!ReadVarInt(data, len, &offset, &token_len)) {
          break;
        }
        if (offset + token_len > len) {
          break;
        }
        offset += token_len;
      }
      uint64_t packet_len = 0;
      if (!ReadVarInt(data, len, &offset, &packet_len)) {
        break;
      }
      packet_number_offset = offset;
      if (packet_len > len - packet_number_offset) {
        break;
      }
      packet_end = packet_number_offset + static_cast<size_t>(packet_len);
      const int space_index = QuicPacketNumberSpaceIndex(level);
      if (recovery_.IsPacketNumberSpaceDiscarded(level)) {
        offset = packet_end;
        continue;
      }
      if (!keys->installed) {
        deferred->assign(data + packet_start, data + len);
        return 0;
      }
      if (!RemoveQuicHeaderProtection(keys, 0,
                                      packet_number_offset - packet_start, true,
                                      &unprotected, &packet_number_len)) {
        break;
      }
      if (packet_len < packet_number_len) {
        break;
      }
      size_t pn_read_offset = packet_number_offset - packet_start;
      const uint64_t truncated_packet_number = ReadPacketNumber(
          unprotected.data(), packet_number_len, &pn_read_offset);
      packet_number =
          DecodePacketNumber(largest_received_packet_number_[space_index],
                             has_largest_received_packet_number_[space_index],
                             truncated_packet_number, packet_number_len);
      payload_offset = packet_number_offset + packet_number_len;
      payload_len = static_cast<size_t>(packet_len) - packet_number_len;
    } else {
      if (!keys->installed) {
        deferred->assign(data + packet_start, data + len);
        return 0;
      }
      const size_t dcid_len = source_connection_id_.size();
      if (offset + dcid_len + 1 > len) {
        break;
      }
      bool matched_connection_id = false;
      for (const auto& entry : local_connection_ids_) {
        if (!entry.second.retired &&
            entry.second.connection_id.size() == dcid_len &&
            memcmp(data + offset, entry.second.connection_id.data(),
                   dcid_len) == 0) {
          local_connection_id_sequence = entry.first;
          matched_connection_id = true;
          break;
        }
      }
      if (!matched_connection_id) {
        DetectStatelessReset(data + packet_start, len - packet_start);
        break;
      }
      offset += dcid_len;
      packet_number_offset = offset;
      packet_end = len;
      auto try_keys = [&](QuicPacketKeys* candidate, bool candidate_phase,
                          bool promote) {
        if (!candidate->installed) {
          return false;
        }
        std::vector<uint8_t> candidate_unprotected(data + packet_start,
                                                   data + packet_end);
        size_t candidate_packet_number_len = 0;
        if (!RemoveQuicHeaderProtection(
                candidate, 0, packet_number_offset - packet_start, false,
                &candidate_unprotected, &candidate_packet_number_len)) {
          return false;
        }
        const uint8_t unprotected_first = candidate_unprotected[0];
        if ((unprotected_first & 0x18) != 0 ||
            ((unprotected_first & 0x04) != 0) != candidate_phase) {
          return false;
        }
        size_t pn_read_offset = packet_number_offset - packet_start;
        const uint64_t truncated_packet_number =
            ReadPacketNumber(candidate_unprotected.data(),
                             candidate_packet_number_len, &pn_read_offset);
        const uint64_t candidate_packet_number = DecodePacketNumber(
            largest_received_packet_number_[QuicPacketNumberSpaceIndex(level)],
            has_largest_received_packet_number_[QuicPacketNumberSpaceIndex(
                level)],
            truncated_packet_number, candidate_packet_number_len);
        const size_t candidate_payload_offset =
            packet_number_offset + candidate_packet_number_len;
        std::vector<uint8_t> aad(candidate_unprotected.begin(),
                                 candidate_unprotected.begin() +
                                     (candidate_payload_offset - packet_start));
        std::vector<uint8_t> ciphertext(data + candidate_payload_offset,
                                        data + packet_end);
        std::vector<uint8_t> candidate_payload;
        if (!OpenQuicPacketPayload(candidate, candidate_packet_number,
                                   ciphertext, aad, &candidate_payload)) {
          return false;
        }
        keys = candidate;
        unprotected = std::move(candidate_unprotected);
        packet_number_len = candidate_packet_number_len;
        packet_number = candidate_packet_number;
        payload_offset = candidate_payload_offset;
        payload_len = packet_end - payload_offset;
        payload = std::move(candidate_payload);
        payload_opened = true;
        promote_application_read_keys = promote;
        return true;
      };
      if (!try_keys(&read_keys_[ssl_encryption_application],
                    application_read_key_phase_, false) &&
          !(handshake_confirmed_ &&
            try_keys(&next_application_read_keys_, !application_read_key_phase_,
                     true)) &&
          !try_keys(&previous_application_read_keys_,
                    previous_application_read_key_phase_, false)) {
        DetectStatelessReset(data + packet_start, len - packet_start);
        break;
      }
    }

    if (packet_end > len || payload_offset < packet_start) {
      break;
    }
    if (!payload_opened) {
      std::vector<uint8_t> aad(
          unprotected.begin(),
          unprotected.begin() + (payload_offset - packet_start));
      std::vector<uint8_t> ciphertext(data + payload_offset, data + packet_end);
      if (!OpenQuicPacketPayload(keys, packet_number, ciphertext, aad,
                                 &payload)) {
        DetectStatelessReset(data + packet_start, len - packet_start);
        break;
      }
    }
    received_authenticated_packet_ = true;
    if (promote_application_read_keys) {
      PromoteApplicationReadKeys();
    }
    if (local_closing_) {
      QueueProtectedPacket(ssl_encryption_application,
                           local_connection_close_payload_, false, false, true,
                           path_id);
      break;
    }
    RefreshIdleDeadline(TimerUtils::GetCurrentMonotonicMicros());
    const int space_index = QuicPacketNumberSpaceIndex(level);
    if (!has_largest_received_packet_number_[space_index] ||
        packet_number > largest_received_packet_number_[space_index]) {
      largest_received_packet_number_[space_index] = packet_number;
      has_largest_received_packet_number_[space_index] = true;
    }
    if (long_header && !peer_source_connection_id.empty()) {
      if (peer_initial_source_connection_id_.empty()) {
        peer_initial_source_connection_id_ = peer_source_connection_id;
        QuicPeerConnectionId initial_peer_connection_id;
        initial_peer_connection_id.connection_id =
            peer_initial_source_connection_id_;
        peer_connection_ids_[0] = std::move(initial_peer_connection_id);
      }
      destination_connection_id_ = peer_source_connection_id;
    }
    bool ack_eliciting = false;
    QuicFrameError frame_error;
    if (level == ssl_encryption_application && handshake_confirmed_ &&
        path_id != active_path_id_ &&
        (!path_validation_pending_ || validating_path_id_ != path_id)) {
      BeginPathValidation(path_id);
    }
    receive_backpressured_ = false;
    receive_backpressured_stream_id_ = std::numeric_limits<uint64_t>::max();
    receive_reordered_ = false;
    int ret = ParseFrames(level, payload.data(), payload.size(),
                          local_connection_id_sequence, path_id,
                          provided_crypto, &ack_eliciting, &frame_error);
    if (ret == 2) {
      return 2;
    }
    if (ret == 3) {
      return 3;
    }
    if (ret) {
      StartTransportError(level, frame_error.error_code, frame_error.frame_type,
                          frame_error.reason);
      return 0;
    }
    if (draining_) {
      break;
    }
    if (level == ssl_encryption_handshake &&
        !recovery_.IsPacketNumberSpaceDiscarded(ssl_encryption_initial)) {
      DiscardPacketNumberSpace(ssl_encryption_initial);
    }
    if (ack_eliciting) {
      QueueAck(level, packet_number, path_id);
    }
    offset = packet_end;
    if (offset <= packet_start) {
      break;
    }
  }
  return 0;
}

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)
