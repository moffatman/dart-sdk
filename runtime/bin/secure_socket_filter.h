// Copyright (c) 2017, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#ifndef RUNTIME_BIN_SECURE_SOCKET_FILTER_H_
#define RUNTIME_BIN_SECURE_SOCKET_FILTER_H_

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include "bin/builtin.h"
#include "bin/reference_counting.h"
#include "bin/security_context.h"
#include "platform/synchronization.h"
#include "platform/utils.h"

namespace dart {
namespace bin {

/* These are defined in root_certificates.cc. */
extern const unsigned char* root_certificates_pem;
extern unsigned int root_certificates_pem_length;

class X509TrustState {
 public:
  X509TrustState(const X509* x509, bool is_trusted)
      : x509_(x509), is_trusted_(is_trusted) {}

  const X509* x509() const { return x509_; }
  bool is_trusted() const { return is_trusted_; }

 private:
  const X509* x509_;
  bool is_trusted_;

  DISALLOW_COPY_AND_ASSIGN(X509TrustState);
};

class BaseSSLFilter : public ReferenceCounted<BaseSSLFilter> {
 public:
  static void Init();
  static void Cleanup();

  // These enums must agree with those in sdk/lib/io/secure_socket.dart.
  enum BufferIndex {
    kReadPlaintext,
    kWritePlaintext,
    kReadEncrypted,
    kWriteEncrypted,
    kNumBuffers,
    kFirstEncrypted = kReadEncrypted
  };

  static constexpr int kSSLFilterNativeFieldIndex = 0;

  BaseSSLFilter()
      : callback_error(nullptr),
        handshake_complete_(nullptr),
        in_handshake_(false),
        hostname_(nullptr),
        ssl_(nullptr),
        bad_certificate_callback_(nullptr) {}
  ~BaseSSLFilter();

  char* hostname() const { return hostname_; }
  bool is_server() const { return is_server_; }
  bool is_client() const { return !is_server_; }

  Dart_Handle Init(Dart_Handle dart_this);
  void Destroy();
  virtual void FreeResources();
  void MarkAsTrusted(Dart_NativeArguments args);
  int Handshake(Dart_Port reply_port);
  void GetSelectedProtocol(Dart_NativeArguments args);
  void RegisterHandshakeCompleteCallback(Dart_Handle handshake_complete);
  void RegisterBadCertificateCallback(Dart_Handle callback);
  void RegisterKeyLogPort(Dart_Port key_log_port);
  Dart_Port key_log_port() { return key_log_port_; }
  Dart_Handle bad_certificate_callback() {
    return Dart_HandleFromPersistent(bad_certificate_callback_);
  }
  virtual int ProcessReadPlaintextBuffer(int start, int end) { return 0; }
  virtual int ProcessWritePlaintextBuffer(int start, int end) { return 0; }
  virtual int ProcessReadEncryptedBuffer(int start, int end) { return 0; }
  virtual int ProcessWriteEncryptedBuffer(int start, int end) { return 0; }
  virtual bool TakeInternalProgress() { return false; }
  virtual bool TakeWriteReady() { return false; }
  virtual void HandleEarlyDataRejected() {}
  virtual void HandleNewSession(SSL_SESSION* session) {}
  virtual void ProcessTimers() {}
  virtual int64_t NextTimeoutMillis() { return -1; }
  virtual bool ProcessAllBuffers(int starts[kNumBuffers],
                                 int ends[kNumBuffers],
                                 bool in_handshake);
  virtual bool PrepareStreamBuffers(const CObjectArray& request,
                                    intptr_t request_offset,
                                    intptr_t stream_count) {
    return stream_count == 0;
  }
  virtual bool ProcessStreamBuffers(const CObjectArray& request,
                                    intptr_t request_offset,
                                    intptr_t stream_count,
                                    bool in_handshake,
                                    CObjectArray* result,
                                    intptr_t result_offset) {
    return stream_count == 0;
  }
  virtual bool FlushOutgoingDatagrams(int starts[kNumBuffers],
                                      int ends[kNumBuffers]) {
    return true;
  }
  virtual intptr_t FilterRequestHeaderSize() const {
    return 2 + kNumBuffers * 2;
  }
  virtual intptr_t FilterResponseHeaderSize() const {
    return kNumBuffers * 2 + 3;
  }
  virtual bool ProcessConnectionCommands(const CObjectArray& request,
                                         CObjectArray* result) {
    return true;
  }
  virtual bool ProcessConnectionEvents(CObjectArray* result) { return true; }
  virtual CObject* ProcessQuicEvents(const CObjectArray& request) {
    return CObject::IllegalArgumentError();
  }
  virtual void AfterFilterRequest() {}
  Dart_Handle PeerCertificate();
  static void InitializeLibrary();
  Dart_Handle callback_error;

  static CObject* ProcessFilterRequest(const CObjectArray& request);
  static CObject* ProcessQuicEventsRequest(const CObjectArray& request);
  static int NewSessionCallback(SSL* ssl, SSL_SESSION* session);

  // The index of the external data field in _ssl that points to the SSLFilter.
  static int filter_ssl_index;
  // The index of the external data field in _ssl that points to the
  // SSLCertContext.
  static int ssl_cert_context_index;

  const X509TrustState* certificate_trust_state() {
    return certificate_trust_state_.get();
  }
  Dart_Port reply_port() const { return reply_port_; }
  static Dart_Port TrustEvaluateReplyPort();
  virtual Mutex* process_mutex() { return nullptr; }

 protected:
  static bool library_initialized_;
  Dart_PersistentHandle handshake_complete_;
  bool in_handshake_;
  char* hostname_;
  bool is_server_;
  SSL* ssl_;
  int BufferSize(BufferIndex index);
  virtual Dart_Handle InitializeBuffers(Dart_Handle dart_this) = 0;
  int buffer_size_;
  int encrypted_buffer_size_;
  Dart_PersistentHandle dart_buffer_objects_[kNumBuffers];
  static bool IsBufferEncrypted(int i) {
    return static_cast<BufferIndex>(i) >= kFirstEncrypted;
  }

 private:
  static Mutex* mutex_;  // To protect library initialization.
  static Dart_Port trust_evaluate_reply_port_;

  // Currently only one(root) certificate is evaluated via
  // TrustEvaluate mechanism.
  std::unique_ptr<X509TrustState> certificate_trust_state_;

  Dart_PersistentHandle bad_certificate_callback_;

  Dart_Port reply_port_ = ILLEGAL_PORT;
  Dart_Port key_log_port_ = ILLEGAL_PORT;
};

class SSLFilter : public BaseSSLFilter {
 public:
  static const intptr_t kApproximateSize;

  SSLFilter() : BaseSSLFilter(), socket_side_(nullptr) {}

  void Connect(const char* hostname,
               SSLCertContext* context,
               bool is_server,
               bool request_client_certificate,
               bool require_client_certificate,
               Dart_Handle protocols_handle,
               Dart_Handle settings_handle,
               bool use_new_alps_codepoint,
               bool use_ech_grease);
  void FreeResources() override;
  int ProcessReadPlaintextBuffer(int start, int end) override;
  int ProcessWritePlaintextBuffer(int start, int end) override;
  int ProcessReadEncryptedBuffer(int start, int end) override;
  int ProcessWriteEncryptedBuffer(int start, int end) override;

 protected:
  virtual Dart_Handle InitializeBuffers(Dart_Handle dart_this) override;

 private:
  static const intptr_t kInternalBIOSize;

  uint8_t* buffers_[kNumBuffers];
  BIO* socket_side_;

  DISALLOW_COPY_AND_ASSIGN(SSLFilter);
};

}  // namespace bin
}  // namespace dart

#endif  // RUNTIME_BIN_SECURE_SOCKET_FILTER_H_
