// Copyright (c) 2017, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#if !defined(DART_IO_SECURE_SOCKET_DISABLED)

#include "bin/secure_socket_filter.h"
#include "bin/datagram_secure_socket_filter.h"

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <string>

#include "bin/io_service.h"
#include "bin/lockers.h"
#include "bin/secure_socket_utils.h"
#include "bin/security_context.h"
#include "bin/socket_base.h"
#include "bin/utils.h"
#include "platform/syslog.h"
#include "platform/text_buffer.h"

// Return the error from the containing function if handle is an error handle.
#define RETURN_IF_ERROR(handle)                                                \
  {                                                                            \
    Dart_Handle __handle = handle;                                             \
    if (Dart_IsError((__handle))) {                                            \
      return __handle;                                                         \
    }                                                                          \
  }

namespace dart {
namespace bin {

class OptionalMutexLocker {
 public:
  explicit OptionalMutexLocker(Mutex* mutex) : mutex_(mutex) {
    if (mutex_ != nullptr) mutex_->Lock();
  }
  ~OptionalMutexLocker() {
    if (mutex_ != nullptr) mutex_->Unlock();
  }

 private:
  Mutex* mutex_;
};

bool BaseSSLFilter::library_initialized_ = false;
// To protect library initialization.
Mutex* BaseSSLFilter::mutex_ = nullptr;
int BaseSSLFilter::filter_ssl_index;
int BaseSSLFilter::ssl_cert_context_index;
Dart_Port BaseSSLFilter::trust_evaluate_reply_port_ = ILLEGAL_PORT;

void BaseSSLFilter::Init() {
  ASSERT(BaseSSLFilter::mutex_ == nullptr);
  BaseSSLFilter::mutex_ = new Mutex();
}

void BaseSSLFilter::Cleanup() {
  ASSERT(BaseSSLFilter::mutex_ != nullptr);
  delete BaseSSLFilter::mutex_;
  BaseSSLFilter::mutex_ = nullptr;
  trust_evaluate_reply_port_ = ILLEGAL_PORT;
}

const intptr_t SSLFilter::kInternalBIOSize = 10 * KB;
const intptr_t SSLFilter::kApproximateSize =
    sizeof(SSLFilter) + (2 * SSLFilter::kInternalBIOSize);

static BaseSSLFilter* GetFilter(Dart_NativeArguments args) {
  BaseSSLFilter* filter = nullptr;
  Dart_Handle dart_this = ThrowIfError(Dart_GetNativeArgument(args, 0));
  ASSERT(Dart_IsInstance(dart_this));
  ThrowIfError(Dart_GetNativeInstanceField(
      dart_this, BaseSSLFilter::kSSLFilterNativeFieldIndex,
      reinterpret_cast<intptr_t*>(&filter)));
  if (filter == nullptr) {
    Dart_PropagateError(Dart_NewUnhandledExceptionError(
        DartUtils::NewInternalError("No native peer")));
  }
  return filter;
}

static void DeleteFilter(void* isolate_data, void* context_pointer) {
  BaseSSLFilter* filter = reinterpret_cast<BaseSSLFilter*>(context_pointer);
  filter->Release();
}

static Dart_Handle SetSSLFilter(Dart_NativeArguments args, SSLFilter* filter) {
  ASSERT(filter != nullptr);
  Dart_Handle dart_this = Dart_GetNativeArgument(args, 0);
  RETURN_IF_ERROR(dart_this);
  ASSERT(Dart_IsInstance(dart_this));
  Dart_Handle err = Dart_SetNativeInstanceField(
      dart_this, BaseSSLFilter::kSSLFilterNativeFieldIndex,
      reinterpret_cast<intptr_t>(filter));
  RETURN_IF_ERROR(err);
  Dart_NewFinalizableHandle(dart_this, reinterpret_cast<void*>(filter),
                            SSLFilter::kApproximateSize, DeleteFilter);
  return Dart_Null();
}

static Dart_Handle SetDatagramSSLFilter(Dart_NativeArguments args,
                                        DatagramSSLFilter* filter) {
  ASSERT(filter != nullptr);
  Dart_Handle dart_this = Dart_GetNativeArgument(args, 0);
  RETURN_IF_ERROR(dart_this);
  ASSERT(Dart_IsInstance(dart_this));
  Dart_Handle err = Dart_SetNativeInstanceField(
      dart_this, BaseSSLFilter::kSSLFilterNativeFieldIndex,
      reinterpret_cast<intptr_t>(filter));
  RETURN_IF_ERROR(err);
  Dart_NewFinalizableHandle(dart_this, reinterpret_cast<void*>(filter),
                            filter->ApproximateSize(), DeleteFilter);
  return Dart_Null();
}

void FUNCTION_NAME(SecureSocket_Init)(Dart_NativeArguments args) {
  Dart_Handle dart_this = ThrowIfError(Dart_GetNativeArgument(args, 0));
  SSLFilter* filter = new SSLFilter();
  Dart_Handle err = SetSSLFilter(args, filter);
  if (Dart_IsError(err)) {
    filter->Release();
    Dart_PropagateError(err);
  }
  err = filter->Init(dart_this);
  if (Dart_IsError(err)) {
    // The finalizer was set up by SetFilter. It will delete `filter` if there
    // is an error.
    filter->Destroy();
    Dart_PropagateError(err);
  }
}

void FUNCTION_NAME(SecureSocket_Connect)(Dart_NativeArguments args) {
  Dart_Handle host_name_object = ThrowIfError(Dart_GetNativeArgument(args, 1));
  Dart_Handle context_object = ThrowIfError(Dart_GetNativeArgument(args, 2));
  bool is_server = DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 3));
  bool request_client_certificate =
      DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 4));
  bool require_client_certificate =
      DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 5));
  Dart_Handle protocols_handle = ThrowIfError(Dart_GetNativeArgument(args, 6));
  Dart_Handle settings_handle = ThrowIfError(Dart_GetNativeArgument(args, 7));
  bool use_new_alps_codepoint =
      DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 8));
  bool use_ech_grease =
      DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 9));

  const char* host_name = nullptr;
  // TODO(whesse): Is truncating a Dart string containing \0 what we want?
  ThrowIfError(Dart_StringToCString(host_name_object, &host_name));

  SSLCertContext* context = nullptr;
  if (!Dart_IsNull(context_object)) {
    ThrowIfError(Dart_GetNativeInstanceField(
        context_object, SSLCertContext::kSecurityContextNativeFieldIndex,
        reinterpret_cast<intptr_t*>(&context)));
  }

  // The protocols_handle is guaranteed to be a valid Uint8List.
  // It will have the correct length encoding of the protocols array.
  ASSERT(!Dart_IsNull(protocols_handle));
  ASSERT(!Dart_IsNull(settings_handle));
  ((SSLFilter*)GetFilter(args))
      ->Connect(host_name, context, is_server, request_client_certificate,
                require_client_certificate, protocols_handle, settings_handle,
                use_new_alps_codepoint, use_ech_grease);
}

void FUNCTION_NAME(DatagramSecureSocket_Connect)(Dart_NativeArguments args) {
  Dart_Handle host_name_object = ThrowIfError(Dart_GetNativeArgument(args, 1));
  Dart_Handle context_object = ThrowIfError(Dart_GetNativeArgument(args, 2));
  bool is_server = DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 3));
  Dart_Handle protocols_handle = ThrowIfError(Dart_GetNativeArgument(args, 4));
  Dart_Handle settings_handle = ThrowIfError(Dart_GetNativeArgument(args, 5));
  bool use_ech_grease =
      DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 6));
  Dart_Handle initial_token_handle =
      ThrowIfError(Dart_GetNativeArgument(args, 7));
  Dart_Handle resumption_state_handle =
      ThrowIfError(Dart_GetNativeArgument(args, 8));
  const bool enable_early_data =
      DartUtils::GetBooleanValue(Dart_GetNativeArgument(args, 9));

  const char* host_name = nullptr;
  // TODO(whesse): Is truncating a Dart string containing \0 what we want?
  ThrowIfError(Dart_StringToCString(host_name_object, &host_name));

  SSLCertContext* context = nullptr;
  if (!Dart_IsNull(context_object)) {
    ThrowIfError(Dart_GetNativeInstanceField(
        context_object, SSLCertContext::kSecurityContextNativeFieldIndex,
        reinterpret_cast<intptr_t*>(&context)));
  }

  // The protocols_handle is guaranteed to be a valid Uint8List.
  // It will have the correct length encoding of the protocols array.
  ASSERT(!Dart_IsNull(protocols_handle));
  ASSERT(!Dart_IsNull(settings_handle));
  ASSERT(!Dart_IsNull(initial_token_handle));
  Dart_TypedData_Type token_type;
  void* token_bytes = nullptr;
  intptr_t token_length = 0;
  ThrowIfError(Dart_TypedDataAcquireData(initial_token_handle, &token_type,
                                         &token_bytes, &token_length));
  std::vector<uint8_t> initial_token(
      static_cast<uint8_t*>(token_bytes),
      static_cast<uint8_t*>(token_bytes) + token_length);
  ThrowIfError(Dart_TypedDataReleaseData(initial_token_handle));
  ASSERT(!Dart_IsNull(resumption_state_handle));
  void* resumption_state_bytes = nullptr;
  intptr_t resumption_state_length = 0;
  ThrowIfError(Dart_TypedDataAcquireData(resumption_state_handle, &token_type,
                                         &resumption_state_bytes,
                                         &resumption_state_length));
  std::vector<uint8_t> resumption_state(
      static_cast<uint8_t*>(resumption_state_bytes),
      static_cast<uint8_t*>(resumption_state_bytes) + resumption_state_length);
  ThrowIfError(Dart_TypedDataReleaseData(resumption_state_handle));
  ((DatagramSSLFilter*)GetFilter(args))
      ->Connect(host_name, context, is_server, protocols_handle, settings_handle,
                use_ech_grease, initial_token, resumption_state, enable_early_data);
}

void FUNCTION_NAME(SecureSocket_Destroy)(Dart_NativeArguments args) {
  BaseSSLFilter* filter = GetFilter(args);
  // There are two paths that can clean up an SSLFilter object. First,
  // there is this explicit call to Destroy(), called from
  // _SecureFilter.destroy() in Dart code. After a call to destroy(), the Dart
  // code maintains the invariant that there will be no further SSLFilter
  // requests sent to the IO Service. Therefore, the internals of the SSLFilter
  // are safe to deallocate, but not the SSLFilter itself, which is already
  // set up to be cleaned up by the finalizer.
  //
  // The second path is through the finalizer, which we have to do in case
  // some mishap prevents a call to _SecureFilter.destroy().
  filter->Destroy();
}

void FUNCTION_NAME(SecureSocket_Handshake)(Dart_NativeArguments args) {
  Dart_Handle port = ThrowIfError(Dart_GetNativeArgument(args, 1));
  ASSERT(!Dart_IsNull(port));

  Dart_Port port_id;
  ThrowIfError(Dart_SendPortGetId(port, &port_id));
  BaseSSLFilter* filter = GetFilter(args);
  OptionalMutexLocker process_lock(filter->process_mutex());
  int result = filter->Handshake(port_id);
  Dart_SetReturnValue(args, Dart_NewInteger(result));
}

void FUNCTION_NAME(SecureSocket_MarkAsTrusted)(Dart_NativeArguments args) {
  GetFilter(args)->MarkAsTrusted(args);
}

void FUNCTION_NAME(SecureSocket_NewX509CertificateWrapper)(
    Dart_NativeArguments args) {
// This is to be used only in conjunction with certificate trust evaluator
// running asynchronously, which is only used on mac/ios at the moment.
#if defined(DART_HOST_OS_MACOS)
  intptr_t x509_pointer = DartUtils::GetNativeIntptrArgument(args, 0);
  X509* x509 = reinterpret_cast<X509*>(x509_pointer);
  Dart_SetReturnValue(args, X509Helper::WrappedX509Certificate(x509));
#else
  FATAL("This is to be used only on mac/ios platforms");
#endif
}

void FUNCTION_NAME(SecureSocket_GetSelectedProtocol)(
    Dart_NativeArguments args) {
  GetFilter(args)->GetSelectedProtocol(args);
}

void FUNCTION_NAME(SecureSocket_RegisterHandshakeCompleteCallback)(
    Dart_NativeArguments args) {
  Dart_Handle handshake_complete =
      ThrowIfError(Dart_GetNativeArgument(args, 1));
  if (!Dart_IsClosure(handshake_complete)) {
    Dart_ThrowException(DartUtils::NewDartArgumentError(
        "Illegal argument to RegisterHandshakeCompleteCallback"));
  }
  GetFilter(args)->RegisterHandshakeCompleteCallback(handshake_complete);
}

void FUNCTION_NAME(SecureSocket_RegisterBadCertificateCallback)(
    Dart_NativeArguments args) {
  Dart_Handle callback = ThrowIfError(Dart_GetNativeArgument(args, 1));
  if (!Dart_IsClosure(callback) && !Dart_IsNull(callback)) {
    Dart_ThrowException(DartUtils::NewDartArgumentError(
        "Illegal argument to RegisterBadCertificateCallback"));
  }
  GetFilter(args)->RegisterBadCertificateCallback(callback);
}

void FUNCTION_NAME(SecureSocket_RegisterKeyLogPort)(Dart_NativeArguments args) {
  Dart_Handle port = ThrowIfError(Dart_GetNativeArgument(args, 1));
  ASSERT(!Dart_IsNull(port));

  Dart_Port port_id;
  ThrowIfError(Dart_SendPortGetId(port, &port_id));
  GetFilter(args)->RegisterKeyLogPort(port_id);
}

void FUNCTION_NAME(SecureSocket_PeerCertificate)(Dart_NativeArguments args) {
  Dart_Handle cert = ThrowIfError(GetFilter(args)->PeerCertificate());
  Dart_SetReturnValue(args, cert);
}

void FUNCTION_NAME(SecureSocket_FilterPointer)(Dart_NativeArguments args) {
  BaseSSLFilter* filter = GetFilter(args);
  // This filter pointer is passed to the IO Service thread. The IO Service
  // thread must Release() the pointer when it is done with it.
  filter->Retain();
  intptr_t filter_pointer = reinterpret_cast<intptr_t>(filter);
  Dart_SetReturnValue(args, Dart_NewInteger(filter_pointer));
}

/**
 * Pushes data through the SSL filter, reading and writing from circular
 * buffers shared with Dart.
 *
 * The Dart _SecureFilterImpl class contains 4 ExternalByteArrays used to
 * pass encrypted and plaintext data to and from the C++ SSLFilter object.
 *
 * ProcessFilter is called with a CObject array containing the pointer to
 * the SSLFilter, encoded as an int, and the start and end positions of the
 * valid data in the four circular buffers.  The function only reads from
 * the valid data area of the input buffers, and only writes to the free
 * area of the output buffers.  The function returns the new start and end
 * positions in the buffers, but it only updates start for input buffers, and
 * end for output buffers.  Therefore, the Dart thread can simultaneously
 * write to the free space and end pointer of input buffers, and read from
 * the data space of output buffers, and modify the start pointer.
 *
 * When ProcessFilter returns, the Dart thread is responsible for combining
 * the updated pointers from Dart and C++, to make the new valid state of
 * the circular buffer.
 */
CObject* BaseSSLFilter::ProcessFilterRequest(const CObjectArray& request) {
  static constexpr intptr_t kBaseConnectionRequestSize = 2 + kNumBuffers * 2;
  static constexpr intptr_t kStreamRequestSize = 8;
  static constexpr intptr_t kStreamResponseSize = 7;
  CObjectIntptr filter_object(request[0]);
  BaseSSLFilter* filter =
      reinterpret_cast<BaseSSLFilter*>(filter_object.Value());
  RefCntReleaseScope<BaseSSLFilter> rs(filter);
  OptionalMutexLocker process_lock(filter->process_mutex());

  bool in_handshake = CObjectBool(request[1]).Value();
  int starts[kNumBuffers];
  int ends[kNumBuffers];
  for (int i = 0; i < kNumBuffers; ++i) {
    starts[i] = CObjectInt32(request[2 * i + 2]).Value();
    ends[i] = CObjectInt32(request[2 * i + 3]).Value();
  }

  intptr_t stream_count = 0;
  const intptr_t connection_request_size = filter->FilterRequestHeaderSize();
  const intptr_t connection_response_size = filter->FilterResponseHeaderSize();
  intptr_t stream_request_offset = connection_request_size;
  if (connection_request_size > kBaseConnectionRequestSize) {
    stream_count = CObjectIntptr(request[kBaseConnectionRequestSize]).Value();
  }
  const bool valid_request =
      connection_request_size >= kBaseConnectionRequestSize &&
      connection_response_size >= kNumBuffers * 2 + 3 && stream_count >= 0 &&
      request.Length() ==
          stream_request_offset + stream_count * kStreamRequestSize;

  if (valid_request) {
    CObjectArray* result = new CObjectArray(CObject::NewArray(
        connection_response_size + stream_count * kStreamResponseSize));
    if (!filter->ProcessConnectionCommands(request, result) ||
        !filter->PrepareStreamBuffers(request, stream_request_offset,
                                      stream_count) ||
        !filter->ProcessAllBuffers(starts, ends, in_handshake) ||
        !filter->ProcessStreamBuffers(request, stream_request_offset,
                                      stream_count, in_handshake, result,
                                      connection_response_size) ||
        !filter->FlushOutgoingDatagrams(starts, ends) ||
        !filter->ProcessConnectionEvents(result)) {
      // CObject allocations use Dart_ScopeAllocate and are released with the
      // current native scope. They must not be passed to operator delete.
      result = nullptr;
    }
    if (result != nullptr) {
      for (int i = 0; i < kNumBuffers; ++i) {
        result->SetAt(2 * i, new CObjectInt32(CObject::NewInt32(starts[i])));
        result->SetAt(2 * i + 1, new CObjectInt32(CObject::NewInt32(ends[i])));
      }
      const bool internal_progress = filter->TakeInternalProgress();
      result->SetAt(kNumBuffers * 2,
                    new CObjectBool(CObject::Bool(internal_progress)));
      result->SetAt(
          kNumBuffers * 2 + 1,
          new CObjectInt64(CObject::NewInt64(filter->NextTimeoutMillis())));
      result->SetAt(kNumBuffers * 2 + 2,
                    new CObjectBool(CObject::Bool(filter->TakeWriteReady())));
      filter->AfterFilterRequest();
      return result;
    }
  }
  int32_t error_code = static_cast<int32_t>(ERR_peek_error());
  TextBuffer error_string(SecureSocketUtils::SSL_ERROR_MESSAGE_BUFFER_SIZE);
  SecureSocketUtils::FetchErrorString(filter->ssl_, &error_string);
  CObjectArray* result = new CObjectArray(CObject::NewArray(2));
  result->SetAt(0, new CObjectInt32(CObject::NewInt32(error_code)));
  result->SetAt(1,
                new CObjectString(CObject::NewString(error_string.buffer())));
  return result;
}

CObject* BaseSSLFilter::ProcessQuicEventsRequest(const CObjectArray& request) {
  if (request.Length() < 2 || !request[0]->IsIntptr()) {
    return CObject::IllegalArgumentError();
  }
  CObjectIntptr filter_object(request[0]);
  BaseSSLFilter* filter =
      reinterpret_cast<BaseSSLFilter*>(filter_object.Value());
  RefCntReleaseScope<BaseSSLFilter> rs(filter);
  OptionalMutexLocker process_lock(filter->process_mutex());
  return filter->ProcessQuicEvents(request);
}

bool BaseSSLFilter::ProcessAllBuffers(int starts[kNumBuffers],
                                      int ends[kNumBuffers],
                                      bool in_handshake) {
  ProcessTimers();
  for (int i = 0; i < kNumBuffers; ++i) {
    if (in_handshake && (i == kReadPlaintext || i == kWritePlaintext)) continue;
    int start = starts[i];
    int end = ends[i];
    int size = IsBufferEncrypted(i) ? encrypted_buffer_size_ : buffer_size_;
    if (start < 0 || end < 0 || start >= size || end >= size) {
      FATAL("Out-of-bounds internal buffer access in dart:io SecureSocket");
    }
    switch (i) {
      case kReadPlaintext:
      case kWriteEncrypted:
        // Write data to the circular buffer's free space.  If the buffer
        // is full, neither if statement is executed and nothing happens.
        if (start <= end) {
          // If the free space may be split into two segments,
          // then the first is [end, size), unless start == 0.
          // Then, since the last free byte is at position start - 2,
          // the interval is [end, size - 1).
          int buffer_end = (start == 0) ? size - 1 : size;
          int bytes = (i == kReadPlaintext)
                          ? ProcessReadPlaintextBuffer(end, buffer_end)
                          : ProcessWriteEncryptedBuffer(end, buffer_end);
          if (bytes < 0) return false;
          end += bytes;
          ASSERT(end <= size);
          if (end == size) end = 0;
        }
        if (start > end + 1) {
          int bytes = (i == kReadPlaintext)
                          ? ProcessReadPlaintextBuffer(end, start - 1)
                          : ProcessWriteEncryptedBuffer(end, start - 1);
          if (bytes < 0) return false;
          end += bytes;
          ASSERT(end < start);
        }
        ends[i] = end;
        break;
      case kReadEncrypted:
      case kWritePlaintext:
        // Read/Write data from circular buffer.  If the buffer is empty,
        // neither if statement's condition is true.
        if (end < start) {
          // Data may be split into two segments.  In this case,
          // the first is [start, size).
          int bytes = (i == kReadEncrypted)
                          ? ProcessReadEncryptedBuffer(start, size)
                          : ProcessWritePlaintextBuffer(start, size);
          if (bytes < 0) return false;
          start += bytes;
          ASSERT(start <= size);
          if (start == size) start = 0;
        }
        if (start < end) {
          int bytes = (i == kReadEncrypted)
                          ? ProcessReadEncryptedBuffer(start, end)
                          : ProcessWritePlaintextBuffer(start, end);
          if (bytes < 0) return false;
          start += bytes;
          ASSERT(start <= end);
        }
        starts[i] = start;
        break;
      default:
        UNREACHABLE();
    }
  }
  return true;
}

Dart_Handle BaseSSLFilter::Init(Dart_Handle dart_this) {
  if (!BaseSSLFilter::library_initialized_) {
    BaseSSLFilter::InitializeLibrary();
  }
  ASSERT(bad_certificate_callback_ == nullptr);
  bad_certificate_callback_ = Dart_NewPersistentHandle(Dart_Null());
  ASSERT(bad_certificate_callback_ != nullptr);
  Dart_Handle secure_filter_impl_type = Dart_InstanceGetType(dart_this);
  RETURN_IF_ERROR(secure_filter_impl_type);
  Dart_Handle size_string = DartUtils::NewString("SIZE");
  RETURN_IF_ERROR(size_string);
  Dart_Handle dart_buffer_size =
      Dart_GetField(secure_filter_impl_type, size_string);
  RETURN_IF_ERROR(dart_buffer_size);

  int64_t buffer_size = 0;
  Dart_Handle err = Dart_IntegerToInt64(dart_buffer_size, &buffer_size);
  RETURN_IF_ERROR(err);

  Dart_Handle encrypted_size_string = DartUtils::NewString("ENCRYPTED_SIZE");
  RETURN_IF_ERROR(encrypted_size_string);

  Dart_Handle dart_encrypted_buffer_size =
      Dart_GetField(secure_filter_impl_type, encrypted_size_string);
  RETURN_IF_ERROR(dart_encrypted_buffer_size);

  int64_t encrypted_buffer_size = 0;
  err = Dart_IntegerToInt64(dart_encrypted_buffer_size, &encrypted_buffer_size);
  RETURN_IF_ERROR(err);

  if (buffer_size <= 0 || buffer_size > 1 * MB) {
    FATAL("Invalid buffer size in _ExternalBuffer");
  }
  if (encrypted_buffer_size <= 0 || encrypted_buffer_size > 1 * MB) {
    FATAL("Invalid encrypted buffer size in _ExternalBuffer");
  }
  buffer_size_ = static_cast<int>(buffer_size);
  encrypted_buffer_size_ = static_cast<int>(encrypted_buffer_size);
  // Caller handles cleanup on an error.
  return InitializeBuffers(dart_this);
}

Dart_Handle SSLFilter::InitializeBuffers(Dart_Handle dart_this) {
  Dart_Handle data_identifier = DartUtils::NewString("data");
  RETURN_IF_ERROR(data_identifier);
  // Create SSLFilter buffers as ExternalUint8Array objects.
  Dart_Handle buffers_string = DartUtils::NewString("buffers");
  RETURN_IF_ERROR(buffers_string);
  Dart_Handle dart_buffers_object = Dart_GetField(dart_this, buffers_string);
  RETURN_IF_ERROR(dart_buffers_object);

  for (int i = 0; i < kNumBuffers; i++) {
    int size = IsBufferEncrypted(i) ? encrypted_buffer_size_ : buffer_size_;
    buffers_[i] = new uint8_t[size];
    ASSERT(buffers_[i] != nullptr);
    memset(buffers_[i], 0, size);
    dart_buffer_objects_[i] = nullptr;
  }

  Dart_Handle result = Dart_Null();
  for (int i = 0; i < kNumBuffers; ++i) {
    int size = IsBufferEncrypted(i) ? encrypted_buffer_size_ : buffer_size_;
    result = Dart_ListGetAt(dart_buffers_object, i);
    if (Dart_IsError(result)) {
      break;
    }

    dart_buffer_objects_[i] = Dart_NewPersistentHandle(result);
    ASSERT(dart_buffer_objects_[i] != nullptr);
    Dart_Handle data =
        Dart_NewExternalTypedData(Dart_TypedData_kUint8, buffers_[i], size);
    if (Dart_IsError(data)) {
      result = data;
      break;
    }
    result = Dart_HandleFromPersistent(dart_buffer_objects_[i]);
    if (Dart_IsError(result)) {
      break;
    }
    result = Dart_SetField(result, data_identifier, data);
    if (Dart_IsError(result)) {
      break;
    }
  }

  // Caller handles cleanup on an error.
  return result;
}

void BaseSSLFilter::RegisterHandshakeCompleteCallback(Dart_Handle complete) {
  ASSERT(nullptr == handshake_complete_);
  handshake_complete_ = Dart_NewPersistentHandle(complete);

  ASSERT(handshake_complete_ != nullptr);
}

void BaseSSLFilter::RegisterBadCertificateCallback(Dart_Handle callback) {
  ASSERT(bad_certificate_callback_ != nullptr);
  Dart_DeletePersistentHandle(bad_certificate_callback_);
  bad_certificate_callback_ = Dart_NewPersistentHandle(callback);
  ASSERT(bad_certificate_callback_ != nullptr);
}

Dart_Handle BaseSSLFilter::PeerCertificate() {
  X509* ca = SSL_get_peer_certificate(ssl_);
  if (ca == nullptr) {
    return Dart_Null();
  }
  return X509Helper::WrappedX509Certificate(ca);
}

void BaseSSLFilter::RegisterKeyLogPort(Dart_Port key_log_port) {
  key_log_port_ = key_log_port;
}

void BaseSSLFilter::InitializeLibrary() {
  MutexLocker locker(mutex_);
  if (!library_initialized_) {
    SSL_library_init();
    filter_ssl_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    ASSERT(filter_ssl_index >= 0);
    ssl_cert_context_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    ASSERT(ssl_cert_context_index >= 0);
    library_initialized_ = true;
  }
}

Dart_Port BaseSSLFilter::TrustEvaluateReplyPort() {
  MutexLocker locker(mutex_);
  if (trust_evaluate_reply_port_ == ILLEGAL_PORT) {
    trust_evaluate_reply_port_ =
        Dart_NewConcurrentNativePort("SSLCertContextTrustEvaluate",
                                     SSLCertContext::GetTrustEvaluateHandler(),
                                     IOService::max_concurrency());
  }
  return trust_evaluate_reply_port_;
}

void SSLFilter::Connect(const char* hostname,
                        SSLCertContext* context,
                        bool is_server,
                        bool request_client_certificate,
                        bool require_client_certificate,
                        Dart_Handle protocols_handle,
                        Dart_Handle settings_handle,
                        bool use_new_alps_codepoint,
                        bool use_ech_grease) {
  is_server_ = is_server;
  if (in_handshake_) {
    FATAL("Connect called twice on the same _SecureFilter.");
  }

  int status;
  int error;
  BIO* ssl_side;
  status = BIO_new_bio_pair(&ssl_side, kInternalBIOSize, &socket_side_,
                            kInternalBIOSize);
  SecureSocketUtils::CheckStatusSSL(status, "TlsException", "BIO_new_bio_pair",
                                    ssl_);

  ASSERT(context != nullptr);
  ASSERT(context->context() != nullptr);
  ssl_ = SSL_new(context->context());
  SSL_set_bio(ssl_, ssl_side, ssl_side);
  SSL_set_mode(ssl_, SSL_MODE_AUTO_RETRY);  // TODO(whesse): Is this right?
  SSL_set_ex_data(ssl_, filter_ssl_index, this);
  SSL_set_enable_ech_grease(ssl_, use_ech_grease);
  SSL_set_alps_use_new_codepoint(ssl_, use_new_alps_codepoint);
  if (context->allow_tls_renegotiation()) {
    SSL_set_renegotiate_mode(ssl_, ssl_renegotiate_freely);
  }
  context->RegisterCallbacks(ssl_);
  SSL_set_ex_data(ssl_, ssl_cert_context_index, context);

  if (is_server_) {
    int certificate_mode =
        request_client_certificate ? SSL_VERIFY_PEER : SSL_VERIFY_NONE;
    if (require_client_certificate) {
      certificate_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_set_verify(ssl_, certificate_mode, nullptr);
  } else {
    SSLCertContext::SetAlpnProtocolList(protocols_handle, ssl_, nullptr, false);
    SSLCertContext::SetAlps(settings_handle, ssl_);
    // TLS SNI identifies a DNS name. IP-literal connections validate against
    // an iPAddress subjectAltName below, but must not send an SNI extension.
    if (!SocketBase::IsValidAddress(hostname)) {
      status = SSL_set_tlsext_host_name(ssl_, hostname);
      SecureSocketUtils::CheckStatusSSL(status, "TlsException",
                                        "Set SNI host name", ssl_);
    }
    // Sets the hostname in the certificate-checking object, so it is checked
    // against the certificate presented by the server.
    X509_VERIFY_PARAM* certificate_checking_parameters = SSL_get0_param(ssl_);
    hostname_ = Utils::StrDup(hostname);
    X509_VERIFY_PARAM_set_flags(
        certificate_checking_parameters,
        X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_TRUSTED_FIRST);
    X509_VERIFY_PARAM_set_hostflags(certificate_checking_parameters, 0);

    // Use different check depending on whether the hostname is an IP address
    // or a DNS name.
    if (SocketBase::IsValidAddress(hostname_)) {
      status = X509_VERIFY_PARAM_set1_ip_asc(certificate_checking_parameters,
                                             hostname_);
    } else {
      status = X509_VERIFY_PARAM_set1_host(certificate_checking_parameters,
                                           hostname_, strlen(hostname_));
    }
    SecureSocketUtils::CheckStatusSSL(
        status, "TlsException", "Set hostname for certificate checking", ssl_);
  }
  // Make the connection:
  if (is_server_) {
    status = SSL_accept(ssl_);
    if (SSL_LOG_STATUS) {
      Syslog::Print("SSL_accept status: %d\n", status);
    }
    if (status != 1) {
      // TODO(whesse): expect a needs-data error here.  Handle other errors.
      error = SSL_get_error(ssl_, status);
      if (SSL_LOG_STATUS) {
        Syslog::Print("SSL_accept error: %d\n", error);
      }
    }
  } else {
    status = SSL_connect(ssl_);
    if (SSL_LOG_STATUS) {
      Syslog::Print("SSL_connect status: %d\n", status);
    }
    if (status != 1) {
      // TODO(whesse): expect a needs-data error here.  Handle other errors.
      error = SSL_get_error(ssl_, status);
      if (SSL_LOG_STATUS) {
        Syslog::Print("SSL_connect error: %d\n", error);
      }
    }
  }
  // We don't expect certificate evaluation on first attempt,
  // we expect requests for more bytes, therefore we could get away
  // with passing illegal port.
  Handshake(ILLEGAL_PORT);
}

void BaseSSLFilter::MarkAsTrusted(Dart_NativeArguments args) {
  intptr_t certificate_pointer = DartUtils::GetNativeIntptrArgument(args, 1);
  ASSERT(certificate_pointer != 0);
  certificate_trust_state_.reset(
      new X509TrustState(reinterpret_cast<X509*>(certificate_pointer),
                         DartUtils::GetNativeBooleanArgument(args, 2)));
  if (SSL_LOG_STATUS) {
    Syslog::Print("Mark %p as %strusted certificate\n",
                  certificate_trust_state_->x509(),
                  certificate_trust_state_->is_trusted() ? "" : "not ");
  }
}

int BaseSSLFilter::Handshake(Dart_Port reply_port) {
  // Set reply port to be used by CertificateVerificationCallback
  // invoked by SSL_do_handshake: this is where results of
  // certificate evaluation will be communicated to.
  reply_port_ = reply_port;

  // Try and push handshake along.
  int status = SSL_do_handshake(ssl_);
  int error = SSL_get_error(ssl_, status);
  if (error == SSL_ERROR_EARLY_DATA_REJECTED) {
    HandleEarlyDataRejected();
    SSL_reset_early_data_reject(ssl_);
    status = SSL_do_handshake(ssl_);
    error = SSL_get_error(ssl_, status);
  }
  if (error == SSL_ERROR_WANT_CERTIFICATE_VERIFY) {
    return SSL_ERROR_WANT_CERTIFICATE_VERIFY;
  }
  if (callback_error != nullptr) {
    // The SSL_do_handshake will try performing a handshake and might call one
    // or both of:
    //   SSLCertContext::KeyLogCallback
    //   SSLCertContext::CertificateCallback
    //
    // If either of those functions fail, and this.callback_error has not
    // already been set, then they will set this.callback_error to an error
    // handle i.e. only the first error will be captured and propagated.
    Dart_PropagateError(callback_error);
  }
  if (status == 1 && SSL_in_early_data(ssl_)) {
    in_handshake_ = true;
    return SSL_ERROR_NONE;
  }
  if (SSL_want_write(ssl_) || SSL_want_read(ssl_)) {
    in_handshake_ = true;
    return error;
  }
  SecureSocketUtils::CheckStatusSSL(
      status, "HandshakeException",
      is_server_ ? "Handshake error in server" : "Handshake error in client",
      ssl_);
  // Handshake succeeded.
  if (in_handshake_) {
    // TODO(24071): Check return value of SSL_get_verify_result, this
    //    should give us the hostname check.
    int result = SSL_get_verify_result(ssl_);
    if (SSL_LOG_STATUS) {
      Syslog::Print("Handshake verification status: %d\n", result);
      X509* peer_certificate = SSL_get_peer_certificate(ssl_);
      if (peer_certificate == nullptr) {
        Syslog::Print("No peer certificate received\n");
      } else {
        X509_NAME* s_name = X509_get_subject_name(peer_certificate);
        printf("Peer certificate SN: ");
        X509_NAME_print_ex_fp(stdout, s_name, 4, 0);
        printf("\n");
      }
    }
    ThrowIfError(Dart_InvokeClosure(
        Dart_HandleFromPersistent(handshake_complete_), 0, nullptr));
    in_handshake_ = false;
  }

  return error;
}

int BaseSSLFilter::NewSessionCallback(SSL* ssl, SSL_SESSION* session) {
  auto* filter =
      reinterpret_cast<BaseSSLFilter*>(SSL_get_ex_data(ssl, filter_ssl_index));
  if (filter != nullptr) {
    filter->HandleNewSession(session);
  }
  return 0;
}

void BaseSSLFilter::GetSelectedProtocol(Dart_NativeArguments args) {
  const uint8_t* protocol;
  unsigned length;
  SSL_get0_alpn_selected(ssl_, &protocol, &length);
  if (length == 0) {
    Dart_SetReturnValue(args, Dart_Null());
  } else {
    Dart_SetReturnValue(args, Dart_NewStringFromUTF8(protocol, length));
  }
}

void BaseSSLFilter::FreeResources() {
  if (ssl_ != nullptr) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }

  if (hostname_ != nullptr) {
    free(hostname_);
    hostname_ = nullptr;
  }
}

void SSLFilter::FreeResources() {
  BaseSSLFilter::FreeResources();
  if (socket_side_ != nullptr) {
    BIO_free(socket_side_);
    socket_side_ = nullptr;
  }
  for (int i = 0; i < kNumBuffers; ++i) {
    if (buffers_[i] != nullptr) {
      delete[] buffers_[i];
      buffers_[i] = nullptr;
    }
  }
}

void DatagramSSLFilter::FreeResources() {
  StopNativePump();
  BaseSSLFilter::FreeResources();
  stream_manager_.Reset(is_server_);
  for (auto& entry : native_paths_) {
    entry.second.socket->Release();
  }
  native_paths_.clear();
  for (int i = 0; i < kNumBuffers; ++i) {
    if (buffers_[i] != nullptr) {
      delete[] buffers_[i];
      buffers_[i] = nullptr;
    }
  }
}

BaseSSLFilter::~BaseSSLFilter() {
  FreeResources();
}

void BaseSSLFilter::Destroy() {
  for (int i = 0; i < kNumBuffers; ++i) {
    if (dart_buffer_objects_[i] != nullptr) {
      Dart_DeletePersistentHandle(dart_buffer_objects_[i]);
      dart_buffer_objects_[i] = nullptr;
    }
  }
  if (handshake_complete_ != nullptr) {
    Dart_DeletePersistentHandle(handshake_complete_);
    handshake_complete_ = nullptr;
  }
  if (bad_certificate_callback_ != nullptr) {
    Dart_DeletePersistentHandle(bad_certificate_callback_);
    bad_certificate_callback_ = nullptr;
  }
  FreeResources();
}

/* Read decrypted data from the filter to the circular buffer */
int SSLFilter::ProcessReadPlaintextBuffer(int start, int end) {
  int length = end - start;
  int bytes_processed = 0;
  if (SSL_LOG_DATA) {
    Syslog::Print("Entering ProcessReadPlaintextBuffer with %d bytes\n",
                  length);
  }
  if (length > 0) {
    bytes_processed = SSL_read(
        ssl_, reinterpret_cast<char*>((buffers_[kReadPlaintext] + start)),
        length);
    if (bytes_processed < 0) {
      int error = SSL_get_error(ssl_, bytes_processed);
      if (SSL_LOG_DATA) {
        Syslog::Print("SSL_read returned error %d\n", error);
      }
      switch (error) {
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
          return -1;
        default:
          break;
      }
      bytes_processed = 0;
    }
  }
  if (SSL_LOG_DATA) {
    Syslog::Print("Leaving ProcessReadPlaintextBuffer read %d bytes\n",
                  bytes_processed);
  }
  return bytes_processed;
}

int SSLFilter::ProcessWritePlaintextBuffer(int start, int end) {
  int length = end - start;
  if (SSL_LOG_DATA) {
    Syslog::Print("Entering ProcessWritePlaintextBuffer with %d bytes\n",
                  length);
  }
  int bytes_processed =
      SSL_write(ssl_, buffers_[kWritePlaintext] + start, length);
  if (bytes_processed < 0) {
    if (SSL_LOG_DATA) {
      Syslog::Print("SSL_write returned error %d\n", bytes_processed);
    }
    return 0;
  }
  if (SSL_LOG_DATA) {
    Syslog::Print("Leaving ProcessWritePlaintextBuffer wrote %d bytes\n",
                  bytes_processed);
  }
  return bytes_processed;
}

/* Read encrypted data from the circular buffer to the filter */
int SSLFilter::ProcessReadEncryptedBuffer(int start, int end) {
  int length = end - start;
  if (SSL_LOG_DATA) {
    Syslog::Print("Entering ProcessReadEncryptedBuffer with %d bytes\n",
                  length);
  }
  int bytes_processed = 0;
  if (length > 0) {
    bytes_processed =
        BIO_write(socket_side_, buffers_[kReadEncrypted] + start, length);
    if (bytes_processed <= 0) {
      bool retry = BIO_should_retry(socket_side_) != 0;
      if (!retry) {
        if (SSL_LOG_DATA) {
          Syslog::Print("BIO_write failed in ReadEncryptedBuffer\n");
        }
      }
      bytes_processed = 0;
    }
  }
  if (SSL_LOG_DATA) {
    Syslog::Print("Leaving ProcessReadEncryptedBuffer read %d bytes\n",
                  bytes_processed);
  }
  return bytes_processed;
}

int SSLFilter::ProcessWriteEncryptedBuffer(int start, int end) {
  int length = end - start;
  int bytes_processed = 0;
  if (SSL_LOG_DATA) {
    Syslog::Print("Entering ProcessWriteEncryptedBuffer with %d bytes\n",
                  length);
  }
  if (length > 0) {
    bytes_processed =
        BIO_read(socket_side_, buffers_[kWriteEncrypted] + start, length);
    if (bytes_processed < 0) {
      if (SSL_LOG_DATA) {
        Syslog::Print("WriteEncrypted BIO_read returned error %d\n",
                      bytes_processed);
      }
      return 0;
    } else {
      if (SSL_LOG_DATA) {
        Syslog::Print("WriteEncrypted  BIO_read wrote %d bytes\n",
                      bytes_processed);
      }
    }
  }
  return bytes_processed;
}

void FUNCTION_NAME(DatagramSecureSocket_Init)(Dart_NativeArguments args) {
  Dart_Handle dart_this = ThrowIfError(Dart_GetNativeArgument(args, 0));
  const bool use_native_udp =
      DartUtils::GetBooleanValue(ThrowIfError(Dart_GetNativeArgument(args, 1)));
  DatagramSSLFilter* filter = new DatagramSSLFilter(use_native_udp);
  Dart_Handle err = SetDatagramSSLFilter(args, filter);
  if (Dart_IsError(err)) {
    filter->Release();
    Dart_PropagateError(err);
  }
  err = filter->Init(dart_this);
  if (Dart_IsError(err)) {
    // The finalizer was set up by SetFilter. It will delete `filter` if there
    // is an error.
    filter->Destroy();
    Dart_PropagateError(err);
  }
}

void FUNCTION_NAME(DatagramSecureSocket_AttachNativeSocket)(
    Dart_NativeArguments args) {
  Socket* socket = Socket::GetSocketIdNativeField(
      ThrowIfError(Dart_GetNativeArgument(args, 1)));
  if (socket == nullptr || socket->fd() < 0) {
    Dart_ThrowException(
        DartUtils::NewDartArgumentError("Cannot attach a closed UDP socket"));
  }

  RawAddr remote_address;
  SocketAddress::GetSockAddr(ThrowIfError(Dart_GetNativeArgument(args, 2)),
                             &remote_address);
  const int64_t remote_port = DartUtils::GetInt64ValueCheckRange(
      ThrowIfError(Dart_GetNativeArgument(args, 3)), 0, 65535);
  SocketAddress::SetAddrPort(&remote_address, remote_port);
  const int64_t path_id = DartUtils::GetInt64ValueCheckRange(
      ThrowIfError(Dart_GetNativeArgument(args, 4)), 0,
      std::numeric_limits<uint32_t>::max());
  ((DatagramSSLFilter*)GetFilter(args))
      ->AttachNativeSocket(static_cast<uint32_t>(path_id), socket,
                           remote_address);
}

void FUNCTION_NAME(DatagramSecureSocket_StartNativePump)(
    Dart_NativeArguments args) {
  Dart_Port notification_port = ILLEGAL_PORT;
  Dart_Handle result = Dart_SendPortGetId(
      ThrowIfError(Dart_GetNativeArgument(args, 1)), &notification_port);
  ThrowIfError(result);
  Dart_SetBooleanReturnValue(args, ((DatagramSSLFilter*)GetFilter(args))
                                       ->StartNativePump(notification_port));
}

void FUNCTION_NAME(DatagramSecureSocket_StopNativePump)(
    Dart_NativeArguments args) {
  ((DatagramSSLFilter*)GetFilter(args))->StopNativePump();
}

void FUNCTION_NAME(DatagramSecureSocket_PeerQuicTransportParams)(
    Dart_NativeArguments args) {
  std::vector<uint8_t> bytes =
      ((DatagramSSLFilter*)GetFilter(args))->PeerQuicTransportParams();

  Dart_Handle handle = Dart_NewTypedData(Dart_TypedData_kUint8, bytes.size());
  if (Dart_IsError(handle)) {
    Dart_PropagateError(handle);
  }

  Dart_TypedData_Type typ;
  void* dart_bytes;
  intptr_t length;
  Dart_Handle result =
      Dart_TypedDataAcquireData(handle, &typ, &dart_bytes, &length);
  if (Dart_IsError(result)) {
    Dart_PropagateError(result);
  }

  memcpy(dart_bytes, bytes.data(), length);

  result = Dart_TypedDataReleaseData(handle);
  if (Dart_IsError(result)) {
    Dart_PropagateError(result);
  }

  Dart_SetReturnValue(args, handle);
}

void FUNCTION_NAME(DatagramSecureSocket_PeerPreferredAddress)(
    Dart_NativeArguments args) {
  std::vector<uint8_t> bytes =
      ((DatagramSSLFilter*)GetFilter(args))->PeerPreferredAddress();
  if (bytes.empty()) {
    Dart_SetReturnValue(args, Dart_Null());
    return;
  }
  Dart_Handle handle =
      ThrowIfError(Dart_NewTypedData(Dart_TypedData_kUint8, bytes.size()));
  Dart_TypedData_Type type;
  void* dart_bytes = nullptr;
  intptr_t length = 0;
  ThrowIfError(Dart_TypedDataAcquireData(handle, &type, &dart_bytes, &length));
  memcpy(dart_bytes, bytes.data(), bytes.size());
  ThrowIfError(Dart_TypedDataReleaseData(handle));
  Dart_SetReturnValue(args, handle);
}

void FUNCTION_NAME(DatagramSecureSocket_IsInEarlyData)(
    Dart_NativeArguments args) {
  Dart_SetReturnValue(
      args,
      Dart_NewBoolean(((DatagramSSLFilter*)GetFilter(args))->IsInEarlyData()));
}

void FUNCTION_NAME(DatagramSecureSocket_EarlyDataAccepted)(
    Dart_NativeArguments args) {
  Dart_SetReturnValue(
      args, Dart_NewBoolean(
                ((DatagramSSLFilter*)GetFilter(args))->EarlyDataAccepted()));
}

int BaseSSLFilter::BufferSize(BufferIndex index) {
  return index >= kFirstEncrypted ? encrypted_buffer_size_ : buffer_size_;
}

}  // namespace bin
}  // namespace dart

#endif  // !defined(DART_IO_SECURE_SOCKET_DISABLED)
