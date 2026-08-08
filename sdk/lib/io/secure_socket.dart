// Copyright (c) 2013, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

part of "dart:io";

/// A TCP socket using TLS and SSL.
///
/// See [Socket] for more information.
abstract interface class SecureSocket implements Socket {
  external factory SecureSocket._(RawSecureSocket rawSocket);

  /// Constructs a new secure client socket and connects it to the given
  /// [host] on port [port].
  ///
  /// The returned Future will complete with a
  /// [SecureSocket] that is connected and ready for subscription.
  ///
  /// The certificate provided by the server is checked
  /// using the trusted certificates set in the SecurityContext object.
  /// The default SecurityContext object contains a built-in set of trusted
  /// root certificates for well-known certificate authorities.
  ///
  /// [onBadCertificate] is an optional handler for unverifiable certificates.
  /// The handler receives the [X509Certificate], and can inspect it and
  /// decide (or let the user decide) whether to accept
  /// the connection or not.  The handler should return true
  /// to continue the [SecureSocket] connection.
  ///
  /// [keyLog] is an optional callback that will be called when new TLS keys
  /// are exchanged with the server. [keyLog] will receive one line of text in
  /// [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
  /// for each call. Writing these lines to a file will allow tools (such as
  /// [Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/TLS#tls-decryption))
  /// to decrypt content sent through this socket. This is meant to allow
  /// network-level debugging of secure sockets and should not be used in
  /// production code. For example:
  /// ```dart
  /// final log = File('keylog.txt');
  /// final socket = await SecureSocket.connect('www.example.com', 443,
  ///     keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append));
  /// ```
  ///
  /// [supportedProtocols] is an optional list of protocols (in decreasing
  /// order of preference) to use during the ALPN protocol negotiation with the
  /// server.  Example values are "http/1.1" or "h2".  The selected protocol
  /// can be obtained via [SecureSocket.selectedProtocol].
  ///
  /// The argument [timeout] is used to specify the maximum allowed time to wait
  /// for a connection to be established. If [timeout] is longer than the system
  /// level timeout duration, a timeout may occur sooner than specified in
  /// [timeout]. On timeout, a [SocketException] is thrown and all ongoing
  /// connection attempts to [host] are cancelled.
  static Future<SecureSocket> connect(
    host,
    int port, {
    SecurityContext? context,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
    Duration? timeout,
  }) {
    return RawSecureSocket.connect(
      host,
      port,
      context: context,
      onBadCertificate: onBadCertificate,
      keyLog: keyLog,
      supportedProtocols: supportedProtocols,
      protocolSettings: protocolSettings,
      useNewAlpsCodePoint: useNewAlpsCodePoint,
      useEchGrease: useEchGrease,
      timeout: timeout,
    ).then((rawSocket) => SecureSocket._(rawSocket));
  }

  /// Like [connect], but returns a [Future] that completes with a
  /// [ConnectionTask] that can be cancelled if the [SecureSocket] is no
  /// longer needed.
  static Future<ConnectionTask<SecureSocket>> startConnect(
    host,
    int port, {
    SecurityContext? context,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
  }) {
    return RawSecureSocket.startConnect(
      host,
      port,
      context: context,
      onBadCertificate: onBadCertificate,
      keyLog: keyLog,
      supportedProtocols: supportedProtocols,
      protocolSettings: protocolSettings,
      useNewAlpsCodePoint: useNewAlpsCodePoint,
      useEchGrease: useEchGrease,
    ).then((rawState) {
      Future<SecureSocket> socket = rawState.socket.then(
        (rawSocket) => SecureSocket._(rawSocket),
      );
      return ConnectionTask<SecureSocket>._(socket, rawState._onCancel);
    });
  }

  /// Initiates TLS on an existing connection.
  ///
  /// Takes an already connected [socket] and starts client side TLS
  /// handshake to make the communication secure. When the returned
  /// future completes the [SecureSocket] has completed the TLS
  /// handshake. Using this function requires that the other end of the
  /// connection is prepared for TLS handshake.
  ///
  /// If the [socket] already has a subscription, this subscription
  /// will no longer receive and events. In most cases calling
  /// [StreamSubscription.pause] on this subscription before
  /// starting TLS handshake is the right thing to do.
  ///
  /// The given [socket] is closed and may not be used anymore.
  ///
  /// If the [host] argument is passed it will be used as the host name
  /// for the TLS handshake. If [host] is not passed the host name from
  /// the [socket] will be used. The [host] can be either a [String] or
  /// an [InternetAddress].
  ///
  /// [onBadCertificate] is an optional handler for unverifiable certificates.
  /// The handler receives the [X509Certificate], and can inspect it and
  /// decide (or let the user decide) whether to accept
  /// the connection or not.  The handler should return true
  /// to continue the [SecureSocket] connection.
  ///
  /// [keyLog] is an optional callback that will be called when new TLS keys
  /// are exchanged with the server. [keyLog] will receive one line of text in
  /// [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
  /// for each call. Writing these lines to a file will allow tools (such as
  /// [Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/TLS#tls-decryption))
  /// to decrypt content sent through this socket. This is meant to allow
  /// network-level debugging of secure sockets and should not be used in
  /// production code. For example:
  /// ```dart
  /// final log = File('keylog.txt');
  /// final socket = await SecureSocket.connect('www.example.com', 443,
  ///     keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append));
  /// ```
  ///
  /// [supportedProtocols] is an optional list of protocols (in decreasing
  /// order of preference) to use during the ALPN protocol negotiation with the
  /// server.  Example values are "http/1.1" or "h2".  The selected protocol
  /// can be obtained via [SecureSocket.selectedProtocol].
  ///
  /// Calling this function will _not_ cause a DNS host lookup. If the
  /// [host] passed is a [String], the [InternetAddress] for the
  /// resulting [SecureSocket] will have the passed in [host] as its
  /// host value and the internet address of the already connected
  /// socket as its address value.
  ///
  /// See [connect] for more information on the arguments.
  static Future<SecureSocket> secure(
    Socket socket, {
    host,
    SecurityContext? context,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
  }) {
    return socket
        ._detachRaw()
        .then<RawSecureSocket>((detachedRaw) {
          return RawSecureSocket.secure(
            detachedRaw[0] as RawSocket,
            subscription: detachedRaw[1] as StreamSubscription<RawSocketEvent>?,
            host: host,
            context: context,
            onBadCertificate: onBadCertificate,
            keyLog: keyLog,
            supportedProtocols: supportedProtocols,
            protocolSettings: protocolSettings,
            useNewAlpsCodePoint: useNewAlpsCodePoint,
            useEchGrease: useEchGrease,
          );
        })
        .then<SecureSocket>((raw) => SecureSocket._(raw));
  }

  /// Initiates TLS on an existing server connection.
  ///
  /// Takes an already connected [socket] and starts server side TLS
  /// handshake to make the communication secure. When the returned
  /// future completes the [SecureSocket] has completed the TLS
  /// handshake. Using this function requires that the other end of the
  /// connection is going to start the TLS handshake.
  ///
  /// If the [socket] already has a subscription, this subscription
  /// will no longer receive and events. In most cases calling
  /// [StreamSubscription.pause] on this subscription
  /// before starting TLS handshake is the right thing to do.
  ///
  /// If some of the data of the TLS handshake has already been read
  /// from the socket this data can be passed in the [bufferedData]
  /// parameter. This data will be processed before any other data
  /// available on the socket.
  ///
  /// See [SecureServerSocket.bind] for more information on the
  /// arguments.
  static Future<SecureSocket> secureServer(
    Socket socket,
    SecurityContext? context, {
    List<int>? bufferedData,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
    List<String>? supportedProtocols,
  }) {
    return socket
        ._detachRaw()
        .then<RawSecureSocket>((detachedRaw) {
          return RawSecureSocket.secureServer(
            detachedRaw[0] as RawSocket,
            context,
            subscription: detachedRaw[1] as StreamSubscription<RawSocketEvent>?,
            bufferedData: bufferedData,
            requestClientCertificate: requestClientCertificate,
            requireClientCertificate: requireClientCertificate,
            supportedProtocols: supportedProtocols,
          );
        })
        .then<SecureSocket>((raw) => SecureSocket._(raw));
  }

  /// The peer certificate for a connected SecureSocket.
  ///
  /// If this [SecureSocket] is the server end of a secure socket connection,
  /// [peerCertificate] will return the client certificate, or `null` if no
  /// client certificate was received.  If this socket is the client end,
  /// [peerCertificate] will return the server's certificate.
  X509Certificate? get peerCertificate;

  /// The protocol which was selected during ALPN protocol negotiation.
  ///
  /// Returns `null` if one of the peers does not have support for ALPN, did not
  /// specify a list of supported ALPN protocols or there was no common
  /// protocol between client and server.
  String? get selectedProtocol;

  /// Does nothing.
  ///
  /// The original intent was to allow TLS renegotiation of existing secure
  /// connections.
  @Deprecated("Not implemented")
  void renegotiate({
    bool useSessionCache = true,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  });
}

/// `RawSecureSocket` provides a secure (SSL or TLS) network connection.
///
/// Client connections to a server are provided by calling
/// RawSecureSocket.connect.  A secure server, created with
/// [RawSecureServerSocket], also returns `RawSecureSocket` objects representing
/// the server end of a secure connection.
/// The certificate provided by the server is checked
/// using the trusted certificates set in the [SecurityContext] object.
/// The default [SecurityContext] object contains a built-in set of trusted
/// root certificates for well-known certificate authorities.
///
/// See [RawSocket] for more information.
abstract interface class RawSecureSocket implements RawSocket {
  /// Constructs a new secure client socket and connect it to the given
  /// host on the given port.
  ///
  /// The returned [Future] is completed with the
  /// [RawSecureSocket] when it is connected and ready for subscription.
  ///
  /// The certificate provided by the server is checked using the trusted
  /// certificates set in the SecurityContext object If a certificate and key are
  /// set on the client, using [SecurityContext.useCertificateChain] and
  /// [SecurityContext.usePrivateKey], and the server asks for a client
  /// certificate, then that client certificate is sent to the server.
  ///
  /// [onBadCertificate] is an optional handler for unverifiable certificates.
  /// The handler receives the [X509Certificate], and can inspect it and
  /// decide (or let the user decide) whether to accept
  /// the connection or not.  The handler should return true
  /// to continue the [RawSecureSocket] connection.
  ///
  /// [onBadCertificate] is an optional handler for unverifiable certificates.
  /// The handler receives the [X509Certificate], and can inspect it and
  /// decide (or let the user decide) whether to accept
  /// the connection or not.  The handler should return true
  /// to continue the [SecureSocket] connection.
  ///
  /// [keyLog] is an optional callback that will be called when new TLS keys
  /// are exchanged with the server. [keyLog] will receive one line of text in
  /// [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
  /// for each call. Writing these lines to a file will allow tools (such as
  /// [Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/TLS#tls-decryption))
  /// to decrypt content sent through this socket. This is meant to allow
  /// network-level debugging of secure sockets and should not be used in
  /// production code. For example:
  /// ```dart
  /// final log = File('keylog.txt');
  /// final socket = await SecureSocket.connect('www.example.com', 443,
  ///     keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append));
  /// ```
  ///
  /// [supportedProtocols] is an optional list of protocols (in decreasing
  /// order of preference) to use during the ALPN protocol negotiation with the
  /// server.  Example values are "http/1.1" or "h2".  The selected protocol
  /// can be obtained via [RawSecureSocket.selectedProtocol].
  static Future<RawSecureSocket> connect(
    host,
    int port, {
    SecurityContext? context,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
    Duration? timeout,
  }) {
    _RawSecureSocket._verifyFields(host, port, false, false);
    return RawSocket.connect(host, port, timeout: timeout).then((socket) {
      return secure(
        socket,
        context: context,
        onBadCertificate: onBadCertificate,
        keyLog: keyLog,
        supportedProtocols: supportedProtocols,
        protocolSettings: protocolSettings,
        useNewAlpsCodePoint: useNewAlpsCodePoint,
        useEchGrease: useEchGrease,
      );
    });
  }

  /// Like [connect], but returns a [Future] that completes with a
  /// [ConnectionTask] that can be cancelled if the [RawSecureSocket] is no
  /// longer needed.
  static Future<ConnectionTask<RawSecureSocket>> startConnect(
    host,
    int port, {
    SecurityContext? context,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
  }) {
    return RawSocket.startConnect(host, port).then((
      ConnectionTask<RawSocket> rawState,
    ) {
      Future<RawSecureSocket> socket = rawState.socket.then((rawSocket) {
        return secure(
          rawSocket,
          context: context,
          onBadCertificate: onBadCertificate,
          keyLog: keyLog,
          supportedProtocols: supportedProtocols,
          protocolSettings: protocolSettings,
          useEchGrease: useEchGrease,
          useNewAlpsCodePoint: useNewAlpsCodePoint,
        );
      });
      return ConnectionTask<RawSecureSocket>._(socket, rawState._onCancel);
    });
  }

  /// Initiates TLS on an existing connection.
  ///
  /// Takes an already connected [socket] and starts client side TLS
  /// handshake to make the communication secure. When the returned
  /// future completes the [RawSecureSocket] has completed the TLS
  /// handshake. Using this function requires that the other end of the
  /// connection is prepared for TLS handshake.
  ///
  /// If the [socket] already has a subscription, pass the existing
  /// subscription in the [subscription] parameter. The [secure]
  /// operation will take over the subscription by replacing the
  /// handlers with it own secure processing. The caller must not touch
  /// this subscription anymore. Passing a paused subscription is an
  /// error.
  ///
  /// If the [host] argument is passed it will be used as the host name
  /// for the TLS handshake. If [host] is not passed the host name from
  /// the [socket] will be used. The [host] can be either a [String] or
  /// an [InternetAddress].
  ///
  /// [onBadCertificate] is an optional handler for unverifiable certificates.
  /// The handler receives the [X509Certificate], and can inspect it and
  /// decide (or let the user decide) whether to accept
  /// the connection or not.  The handler should return true
  /// to continue the [SecureSocket] connection.
  ///
  /// [keyLog] is an optional callback that will be called when new TLS keys
  /// are exchanged with the server. [keyLog] will receive one line of text in
  /// [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
  /// for each call. Writing these lines to a file will allow tools (such as
  /// [Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/TLS#tls-decryption))
  /// to decrypt content sent through this socket. This is meant to allow
  /// network-level debugging of secure sockets and should not be used in
  /// production code. For example:
  /// ```dart
  /// final log = File('keylog.txt');
  /// final socket = await SecureSocket.connect('www.example.com', 443,
  ///     keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append));
  /// ```
  ///
  /// [supportedProtocols] is an optional list of protocols (in decreasing
  /// order of preference) to use during the ALPN protocol negotiation with the
  /// server.  Example values are "http/1.1" or "h2".  The selected protocol
  /// can be obtained via [SecureSocket.selectedProtocol].
  ///
  /// Calling this function will _not_ cause a DNS host lookup. If the
  /// [host] passed is a [String] the [InternetAddress] for the
  /// resulting [SecureSocket] will have this passed in [host] as its
  /// host value and the internet address of the already connected
  /// socket as its address value.
  ///
  /// See [connect] for more information on the arguments.
  static Future<RawSecureSocket> secure(
    RawSocket socket, {
    StreamSubscription<RawSocketEvent>? subscription,
    host,
    SecurityContext? context,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
  }) {
    socket.readEventsEnabled = false;
    socket.writeEventsEnabled = false;
    return _RawSecureSocket.connect(
      host != null ? host : socket.address.host,
      socket.port,
      false,
      socket,
      subscription: subscription,
      context: context,
      onBadCertificate: onBadCertificate,
      keyLog: keyLog,
      supportedProtocols: supportedProtocols,
      protocolSettings: protocolSettings,
      useNewAlpsCodePoint: useNewAlpsCodePoint,
      useEchGrease: useEchGrease,
    );
  }

  /// Initiates TLS on an existing server connection.
  ///
  /// Takes an already connected [socket] and starts server side TLS
  /// handshake to make the communication secure. When the returned
  /// future completes the [RawSecureSocket] has completed the TLS
  /// handshake. Using this function requires that the other end of the
  /// connection is going to start the TLS handshake.
  ///
  /// If the [socket] already has a subscription, pass the existing
  /// subscription in the [subscription] parameter. The [secureServer]
  /// operation will take over the subscription by replacing the
  /// handlers with it own secure processing. The caller must not touch
  /// this subscription anymore. Passing a paused subscription is an
  /// error.
  ///
  /// If some of the data of the TLS handshake has already been read
  /// from the socket this data can be passed in the [bufferedData]
  /// parameter. This data will be processed before any other data
  /// available on the socket.
  ///
  /// See [RawSecureServerSocket.bind] for more information on the
  /// arguments.
  static Future<RawSecureSocket> secureServer(
    RawSocket socket,
    SecurityContext? context, {
    StreamSubscription<RawSocketEvent>? subscription,
    List<int>? bufferedData,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
    List<String>? supportedProtocols,
  }) {
    socket.readEventsEnabled = false;
    socket.writeEventsEnabled = false;
    return _RawSecureSocket.connect(
      socket.address,
      socket.remotePort,
      true,
      socket,
      context: context,
      subscription: subscription,
      bufferedData: bufferedData,
      requestClientCertificate: requestClientCertificate,
      requireClientCertificate: requireClientCertificate,
      supportedProtocols: supportedProtocols,
    );
  }

  /// Does nothing.
  ///
  /// The original intent was to allow TLS renegotiation of existing secure
  /// connections.
  @Deprecated("Not implemented")
  void renegotiate({
    bool useSessionCache = true,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  });

  /// Get the peer certificate for a connected RawSecureSocket.  If this
  /// RawSecureSocket is the server end of a secure socket connection,
  /// [peerCertificate] will return the client certificate, or null, if no
  /// client certificate was received.  If it is the client end,
  /// [peerCertificate] will return the server's certificate.
  X509Certificate? get peerCertificate;

  /// The protocol which was selected during protocol negotiation.
  ///
  /// Returns null if one of the peers does not have support for ALPN, did not
  /// specify a list of supported ALPN protocols or there was no common
  /// protocol between client and server.
  String? get selectedProtocol;
}

/// X509Certificate represents an SSL certificate, with accessors to
/// get the fields of the certificate.
@pragma("vm:entry-point")
abstract interface class X509Certificate {
  @pragma("vm:entry-point")
  external factory X509Certificate._();

  /// The DER encoded bytes of the certificate.
  Uint8List get der;

  /// The PEM encoded String of the certificate.
  String get pem;

  /// The SHA1 hash of the certificate.
  Uint8List get sha1;

  String get subject;
  String get issuer;
  DateTime get startValidity;
  DateTime get endValidity;
}

class _FilterStatus {
  bool progress = false; // The filter read or wrote data to the buffers.
  bool needsImmediatePass = false;
  bool readEmpty = true; // The read buffers and decryption filter are empty.
  bool writeEmpty = true; // The write buffers and encryption filter are empty.
  // These are set if a buffer changes state from empty or full.
  bool readPlaintextNoLongerEmpty = false;
  bool writePlaintextNoLongerFull = false;
  bool readEncryptedNoLongerFull = false;
  bool writeEncryptedNoLongerEmpty = false;
  bool streamWriteReady = false;
  bool nativeUdpWriteBlocked = false;
  bool nativeReceiveBlocked = false;
  bool handshakeCryptoProgress = false;
  int? nativeReceiveBlockedStreamId;
  int recoveryTimeoutMillis = -1;

  _FilterStatus();

  @override
  String toString() => 'FilterStatus(${[if (progress) 'progress', if (needsImmediatePass) 'needsImmediatePass', if (readEmpty) 'readEmpty', if (writeEmpty) 'writeEmpty', if (readPlaintextNoLongerEmpty) 'readPlaintextNoLongerEmpty', if (writePlaintextNoLongerFull) 'writePlaintextNoLongerFull', if (readEncryptedNoLongerFull) 'readEncryptedNoLongerFull', if (writeEncryptedNoLongerEmpty) 'writeEncryptedNoLongerEmpty'].join(', ')}, recoveryTimeoutMillis: $recoveryTimeoutMillis)';
}

// Interface used by [RawSecureServerSocket] and [_RawSecureSocket] that exposes
// members of [_NativeSocket].
abstract interface class _RawSocketBase {
  bool get _closedReadEventSent;
  void set _owner(owner);
}

class _RawSecureSocket extends Stream<RawSocketEvent>
    implements RawSecureSocket, _RawSocketBase {
  // Status states
  static const int handshakeStatus = 201;
  static const int connectedStatus = 202;
  static const int closedStatus = 203;

  // Buffer identifiers.
  // These must agree with those in the native C++ implementation.
  static const int readPlaintextId = 0;
  static const int writePlaintextId = 1;
  static const int readEncryptedId = 2;
  static const int writeEncryptedId = 3;
  static const int bufferCount = 4;

  // Is a buffer identifier for an encrypted buffer?
  static bool _isBufferEncrypted(int identifier) =>
      identifier >= readEncryptedId;

  final RawSocket _socket;
  final Completer<_RawSecureSocket> _handshakeComplete =
      Completer<_RawSecureSocket>();
  final _controller = StreamController<RawSocketEvent>(sync: true);
  late final StreamSubscription<RawSocketEvent> _socketSubscription;
  List<int>? _bufferedData;
  int _bufferedDataIndex = 0;
  final InternetAddress address;
  final bool isServer;
  final SecurityContext context;
  final bool requestClientCertificate;
  final bool requireClientCertificate;
  final bool Function(X509Certificate certificate)? onBadCertificate;
  final void Function(String line)? keyLog;
  ReceivePort? keyLogPort;

  var _status = handshakeStatus;
  bool _writeEventsEnabled = true;
  bool _readEventsEnabled = true;
  int _pauseCount = 0;
  bool _pendingReadEvent = false;
  bool _socketClosedRead = false; // The network socket is closed for reading.
  bool _socketClosedWrite = false; // The network socket is closed for writing.
  bool _closedRead = false; // The secure socket has fired an onClosed event.
  bool _closedWrite = false; // The secure socket has been closed for writing.
  // The network socket is gone.
  Completer<RawSecureSocket> _closeCompleter = Completer<RawSecureSocket>();
  _FilterStatus _filterStatus = _FilterStatus();
  bool _connectPending = true;
  bool _filterPending = false;
  bool _filterActive = false;

  _SecureFilter? _secureFilter = _SecureFilter._();
  String? _selectedProtocol;

  static Future<_RawSecureSocket> connect(
    dynamic /*String|InternetAddress*/ host,
    int requestedPort,
    bool isServer,
    RawSocket socket, {
    SecurityContext? context,
    StreamSubscription<RawSocketEvent>? subscription,
    List<int>? bufferedData,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
    bool onBadCertificate(X509Certificate certificate)?,
    void keyLog(String line)?,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useNewAlpsCodePoint,
    bool? useEchGrease,
  }) {
    _verifyFields(
      host,
      requestedPort,
      requestClientCertificate,
      requireClientCertificate,
    );
    if (host is InternetAddress) host = host.host;
    InternetAddress address = socket.address;
    if (host != null) {
      address = InternetAddress._cloneWithNewHost(address, host);
    }
    return _RawSecureSocket(
      address,
      requestedPort,
      isServer,
      context ?? SecurityContext.defaultContext,
      socket,
      subscription,
      bufferedData,
      requestClientCertificate,
      requireClientCertificate,
      onBadCertificate,
      keyLog,
      supportedProtocols,
      protocolSettings ?? {
        // Fallback when building chance master branch
        if (Platform.isAndroid && (supportedProtocols?.contains('h2') ?? false))
          'h2': Uint8List(0)
      },
      useNewAlpsCodePoint ?? true,
      // Fallback when building with chance master
      useEchGrease ?? Platform.isAndroid
    )._handshakeComplete.future;
  }

  _RawSecureSocket(
    this.address,
    int requestedPort,
    this.isServer,
    this.context,
    this._socket,
    StreamSubscription<RawSocketEvent>? subscription,
    this._bufferedData,
    this.requestClientCertificate,
    this.requireClientCertificate,
    this.onBadCertificate,
    this.keyLog,
    List<String>? supportedProtocols,
    Map<String, Uint8List> protocolSettings,
    bool useNewAlpsCodePoint,
    bool useEchGrease,
  ) {
    _controller
      ..onListen = _onSubscriptionStateChange
      ..onPause = _onPauseStateChange
      ..onResume = _onPauseStateChange
      ..onCancel = _onSubscriptionStateChange;
    // Throw an ArgumentError if any field is invalid.  After this, all
    // errors will be reported through the future or the stream.
    final secureFilter = _secureFilter!;
    secureFilter.init();
    secureFilter.registerHandshakeCompleteCallback(
      _secureHandshakeCompleteHandler,
    );

    if (keyLog != null) {
      final port = ReceivePort();
      port.listen((line) {
        try {
          keyLog!((line as String) + '\n');
        } catch (e, s) {
          // There is no obvious place to surface exceptions from the keyLog
          // callback so write the details to stderr.
          stderr.writeln("Failure in keyLog callback:");
          stderr.writeln(s);
        }
      });
      secureFilter.registerKeyLogPort(port.sendPort);
      keyLogPort = port;
    }

    if (onBadCertificate != null) {
      secureFilter.registerBadCertificateCallback(_onBadCertificateWrapper);
    }
    _socket.readEventsEnabled = true;
    _socket.writeEventsEnabled = false;
    if (subscription == null) {
      // If a current subscription is provided use this otherwise
      // create a new one.
      _socketSubscription = _socket.listen(
        _eventDispatcher,
        onError: _reportError,
        onDone: _doneHandler,
      );
    } else {
      _socketSubscription = subscription;
      if (_socketSubscription.isPaused) {
        _socket.close();
        throw ArgumentError("Subscription passed to TLS upgrade is paused");
      }
      // If we are upgrading a socket that is already closed for read,
      // report an error as if we received readClosed during the handshake.
      if (_closedReadEventSent) {
        _eventDispatcher(RawSocketEvent.readClosed);
      }
      _socketSubscription
        ..onData(_eventDispatcher)
        ..onError(_reportError)
        ..onDone(_doneHandler);
    }
    try {
      var encodedProtocols = SecurityContext._protocolsToLengthEncoding(
        supportedProtocols,
      );
      var encodedProtocolSettings = protocolSettings.entries.map((e) => [utf8.encode(e.key), e.value]).toList();
      secureFilter.connect(
        address.host,
        context,
        isServer,
        requestClientCertificate || requireClientCertificate,
        requireClientCertificate,
        encodedProtocols,
        encodedProtocolSettings,
        useNewAlpsCodePoint,
        useEchGrease,
      );
      _secureHandshake();
    } catch (e, s) {
      _reportError(e, s);
    }
  }

  StreamSubscription<RawSocketEvent> listen(
    void onData(RawSocketEvent data)?, {
    Function? onError,
    void onDone()?,
    bool? cancelOnError,
  }) {
    _sendWriteEvent();
    return _controller.stream.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }

  static void _verifyFields(
    host,
    int requestedPort,
    bool requestClientCertificate,
    bool requireClientCertificate,
  ) {
    if (host is! String && host is! InternetAddress) {
      throw ArgumentError("host is not a String or an InternetAddress");
    }
    // TODO(40614): Remove once non-nullability is sound.
    ArgumentError.checkNotNull(requestedPort, "requestedPort");
    if (requestedPort < 0 || requestedPort > 65535) {
      throw ArgumentError("requestedPort is not in the range 0..65535");
    }
    // TODO(40614): Remove once non-nullability is sound.
    ArgumentError.checkNotNull(
      requestClientCertificate,
      "requestClientCertificate",
    );
    ArgumentError.checkNotNull(
      requireClientCertificate,
      "requireClientCertificate",
    );
  }

  int get port => _socket.port;

  InternetAddress get remoteAddress => _socket.remoteAddress;

  int get remotePort => _socket.remotePort;

  bool get _closedReadEventSent =>
      (_socket as _RawSocketBase)._closedReadEventSent;

  void set _owner(owner) {
    (_socket as _RawSocketBase)._owner = owner;
  }

  int available() {
    return _status != connectedStatus
        ? 0
        : _secureFilter!.buffers![readPlaintextId].length;
  }

  Future<RawSecureSocket> close() {
    shutdown(SocketDirection.both);
    return _closeCompleter.future;
  }

  void _completeCloseCompleter([RawSocket? dummy]) {
    if (!_closeCompleter.isCompleted) _closeCompleter.complete(this);
  }

  void _close() {
    _closedWrite = true;
    _closedRead = true;
    _socket.close().then(_completeCloseCompleter);
    _socketClosedWrite = true;
    _socketClosedRead = true;
    if (!_filterActive && _secureFilter != null) {
      _secureFilter!.destroy();
      _secureFilter = null;
    }
    keyLogPort?.close();
    if (_socketSubscription != null) {
      _socketSubscription.cancel();
    }
    _controller.close();
    _status = closedStatus;
  }

  void shutdown(SocketDirection direction) {
    if (direction == SocketDirection.send ||
        direction == SocketDirection.both) {
      _closedWrite = true;
      if (_filterStatus.writeEmpty) {
        _socket.shutdown(SocketDirection.send);
        _socketClosedWrite = true;
        if (_closedRead) {
          _close();
        }
      }
    }
    if (direction == SocketDirection.receive ||
        direction == SocketDirection.both) {
      _closedRead = true;
      _socketClosedRead = true;
      _socket.shutdown(SocketDirection.receive);
      if (_socketClosedWrite) {
        _close();
      }
    }
  }

  bool get writeEventsEnabled => _writeEventsEnabled;

  void set writeEventsEnabled(bool value) {
    _writeEventsEnabled = value;
    if (value) {
      Timer.run(() => _sendWriteEvent());
    }
  }

  bool get readEventsEnabled => _readEventsEnabled;

  void set readEventsEnabled(bool value) {
    _readEventsEnabled = value;
    _scheduleReadEvent();
  }

  Uint8List? read([int? length]) {
    if (length != null && length < 0) {
      throw ArgumentError(
        "Invalid length parameter in SecureSocket.read (length: $length)",
      );
    }
    if (_closedRead) {
      throw SocketException("Reading from a closed socket");
    }
    if (_status != connectedStatus) {
      return null;
    }
    var result = _secureFilter!.buffers![readPlaintextId].read(length);
    _scheduleFilter();
    return result;
  }

  SocketMessage? readMessage([int? count]) {
    throw UnsupportedError("Message-passing not supported by secure sockets");
  }

  static int _fixOffset(int? offset) => offset ?? 0;

  // Write the data to the socket, and schedule the filter to encrypt it.
  int write(List<int> data, [int offset = 0, int? bytes]) {
    if (bytes != null && bytes < 0) {
      throw ArgumentError(
        "Invalid bytes parameter in SecureSocket.read (bytes: $bytes)",
      );
    }
    // TODO(40614): Remove once non-nullability is sound.
    offset = _fixOffset(offset);
    if (offset < 0) {
      throw ArgumentError(
        "Invalid offset parameter in SecureSocket.read (offset: $offset)",
      );
    }
    if (_closedWrite) {
      _controller.addError(SocketException("Writing to a closed socket"));
      return 0;
    }
    if (_status != connectedStatus) return 0;
    bytes ??= data.length - offset;

    int written = _secureFilter!.buffers![writePlaintextId].write(
      data,
      offset,
      bytes,
    );
    if (written > 0) {
      _filterStatus.writeEmpty = false;
    }
    _scheduleFilter();
    return written;
  }

  int sendMessage(
    List<SocketControlMessage> controlMessages,
    List<int> data, [
    int offset = 0,
    int? count,
  ]) {
    throw UnsupportedError("Message-passing not supported by secure sockets");
  }

  X509Certificate? get peerCertificate => _secureFilter!.peerCertificate;

  String? get selectedProtocol => _selectedProtocol;

  bool _onBadCertificateWrapper(X509Certificate certificate) {
    if (onBadCertificate == null) return false;
    return onBadCertificate!(certificate);
  }

  bool setOption(SocketOption option, bool enabled) {
    return _socket.setOption(option, enabled);
  }

  Uint8List getRawOption(RawSocketOption option) {
    return _socket.getRawOption(option);
  }

  void setRawOption(RawSocketOption option) {
    _socket.setRawOption(option);
  }

  void _eventDispatcher(RawSocketEvent event) {
    try {
      if (event == RawSocketEvent.read) {
        _readHandler();
      } else if (event == RawSocketEvent.write) {
        _writeHandler();
      } else if (event == RawSocketEvent.readClosed) {
        _closeHandler();
      }
    } catch (e, stackTrace) {
      _reportError(e, stackTrace);
    }
  }

  void _readHandler() {
    _readSocket();
    _scheduleFilter();
  }

  void _writeHandler() {
    _writeSocket();
    _scheduleFilter();
  }

  void _doneHandler() {
    if (_filterStatus.readEmpty) {
      _close();
    }
  }

  void _reportError(e, [StackTrace? stackTrace]) {
    if (_status == closedStatus) {
      return;
    } else if (_connectPending) {
      // _connectPending is true until the handshake has completed, and the
      // _handshakeComplete future returned from SecureSocket.connect has
      // completed.  Before this point, we must complete it with an error.
      _handshakeComplete.completeError(e, stackTrace);
    } else {
      _controller.addError(e, stackTrace);
    }
    _close();
  }

  void _closeHandler() async {
    if (_status == connectedStatus) {
      if (_closedRead) return;
      _socketClosedRead = true;
      if (_filterStatus.readEmpty) {
        _closedRead = true;
        _controller.add(RawSocketEvent.readClosed);
        if (_socketClosedWrite) {
          _close();
        }
      } else {
        await _scheduleFilter();
      }
    } else if (_status == handshakeStatus) {
      _socketClosedRead = true;
      // The other party might have disconnected, but if there still
      // bytes available we can continue handshake.
      if (_filterStatus.readEmpty) {
        _reportError(
          HandshakeException('Connection terminated during handshake'),
          null,
        );
      }
    }
  }

  Future<void> _secureHandshake() async {
    try {
      bool needRetryHandshake = await _secureFilter!.handshake();
      if (needRetryHandshake) {
        // Some certificates have been evaluated, need to retry handshake.
        await _secureHandshake();
      } else {
        _filterStatus.writeEmpty = false;
        _readSocket();
        _writeSocket();
        await _scheduleFilter();
      }
    } catch (e, stackTrace) {
      _reportError(e, stackTrace);
    }
  }

  @Deprecated("Not implemented")
  void renegotiate({
    bool useSessionCache = true,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  }) {
    if (_status != connectedStatus) {
      throw HandshakeException("Called renegotiate on a non-connected socket");
    }
    _status = handshakeStatus;
    _filterStatus.writeEmpty = false;
    _scheduleFilter();
  }

  void _secureHandshakeCompleteHandler() {
    _status = connectedStatus;
    if (_connectPending) {
      _connectPending = false;
      try {
        _selectedProtocol = _secureFilter!.selectedProtocol();
        // We don't want user code to run synchronously in this callback.
        Timer.run(() => _handshakeComplete.complete(this));
      } catch (error, stack) {
        _handshakeComplete.completeError(error, stack);
      }
    }
  }

  void _onPauseStateChange() {
    if (_controller.isPaused) {
      _pauseCount++;
    } else {
      _pauseCount--;
      if (_pauseCount == 0) {
        _scheduleReadEvent();
        _sendWriteEvent(); // Can send event synchronously.
      }
    }

    if (!_socketClosedRead || !_socketClosedWrite) {
      if (_controller.isPaused) {
        _socketSubscription.pause();
      } else {
        _socketSubscription.resume();
      }
    }
  }

  void _onSubscriptionStateChange() {
    if (_controller.hasListener) {
      // TODO(ajohnsen): Do something here?
    }
  }

  Future<void> _scheduleFilter() {
    _filterPending = true;
    return _tryFilter();
  }

  Future<void> _tryFilter() async {
    try {
      while (true) {
        if (_status == closedStatus) {
          return;
        }
        if (!_filterPending || _filterActive) {
          return;
        }
        _filterActive = true;
        _filterPending = false;

        _filterStatus = await _pushAllFilterStages();
        _filterActive = false;
        if (_status == closedStatus) {
          _secureFilter!.destroy();
          _secureFilter = null;
          return;
        }
        _socket.readEventsEnabled = true;
        if (_filterStatus.writeEmpty && _closedWrite && !_socketClosedWrite) {
          // Checks for and handles all cases of partially closed sockets.
          shutdown(SocketDirection.send);
          if (_status == closedStatus) {
            return;
          }
        }
        if (_filterStatus.readEmpty && _socketClosedRead && !_closedRead) {
          if (_status == handshakeStatus) {
            _secureFilter!.handshake();
            if (_status == handshakeStatus) {
              throw HandshakeException(
                'Connection terminated during handshake',
              );
            }
          }
          _closeHandler();
        }
        if (_status == closedStatus) {
          return;
        }
        if (_filterStatus.progress) {
          _filterPending = true;
          if (_filterStatus.writeEncryptedNoLongerEmpty) {
            _writeSocket();
          }
          if (_filterStatus.writePlaintextNoLongerFull) {
            _sendWriteEvent();
          }
          if (_filterStatus.readEncryptedNoLongerFull) {
            _readSocket();
          }
          if (_filterStatus.readPlaintextNoLongerEmpty) {
            _scheduleReadEvent();
          }
          if (_status == handshakeStatus) {
            await _secureHandshake();
          }
        }
      }
    } catch (e, st) {
      _reportError(e, st);
    }
  }

  List<int>? _readSocketOrBufferedData(int bytes) {
    final bufferedData = _bufferedData;
    if (bufferedData != null) {
      if (bytes > bufferedData.length - _bufferedDataIndex) {
        bytes = bufferedData.length - _bufferedDataIndex;
      }
      var result = bufferedData.sublist(
        _bufferedDataIndex,
        _bufferedDataIndex + bytes,
      );
      _bufferedDataIndex += bytes;
      if (bufferedData.length == _bufferedDataIndex) {
        _bufferedData = null;
      }
      return result;
    } else if (!_socketClosedRead) {
      return _socket.read(bytes);
    } else {
      return null;
    }
  }

  void _readSocket() {
    if (_status == closedStatus) return;
    var buffer = _secureFilter!.buffers![readEncryptedId];
    if (buffer.writeFromSource(_readSocketOrBufferedData) > 0) {
      _filterStatus.readEmpty = false;
    } else {
      _socket.readEventsEnabled = false;
    }
  }

  void _writeSocket() {
    if (_socketClosedWrite) return;
    var buffer = _secureFilter!.buffers![writeEncryptedId];
    if (buffer.readToSocket(_socket)) {
      // Returns true if blocked
      _socket.writeEventsEnabled = true;
    }
  }

  // If a read event should be sent, add it to the controller.
  _scheduleReadEvent() {
    if (!_pendingReadEvent &&
        _readEventsEnabled &&
        _pauseCount == 0 &&
        _secureFilter != null &&
        !_secureFilter!.buffers![readPlaintextId].isEmpty) {
      _pendingReadEvent = true;
      Timer.run(_sendReadEvent);
    }
  }

  _sendReadEvent() {
    _pendingReadEvent = false;
    if (_status != closedStatus &&
        _readEventsEnabled &&
        _pauseCount == 0 &&
        _secureFilter != null &&
        !_secureFilter!.buffers![readPlaintextId].isEmpty) {
      _controller.add(RawSocketEvent.read);
      _scheduleReadEvent();
    }
  }

  // If a write event should be sent, add it to the controller.
  _sendWriteEvent() {
    if (!_closedWrite &&
        _writeEventsEnabled &&
        _pauseCount == 0 &&
        _secureFilter != null &&
        _secureFilter!.buffers![writePlaintextId].free > 0) {
      _writeEventsEnabled = false;
      _controller.add(RawSocketEvent.write);
    }
  }

  Future<_FilterStatus> _pushAllFilterStages() async {
    bool wasInHandshake = _status != connectedStatus;
    List args = List<dynamic>.filled(2 + bufferCount * 2, null);
    args[0] = _secureFilter!._pointer();
    args[1] = wasInHandshake;
    var bufs = _secureFilter!.buffers!;
    for (var i = 0; i < bufferCount; ++i) {
      args[2 * i + 2] = bufs[i].start;
      args[2 * i + 3] = bufs[i].end;
    }

    var response =
        (await _IOService._dispatch(_IOService.sslProcessFilter, args))
            as List<Object?>;
    if (response.length == 2) {
      if (wasInHandshake) {
        // If we're in handshake, throw a handshake error.
        _reportError(
          HandshakeException('${response[1]} error ${response[0]}'),
          null,
        );
      } else {
        // If we're connected, throw a TLS error.
        _reportError(TlsException('${response[1]} error ${response[0]}'), null);
      }
    }
    int start(int index) => response[2 * index] as int;
    int end(int index) => response[2 * index + 1] as int;

    _FilterStatus status = _FilterStatus();
    // Compute writeEmpty as "write plaintext buffer and write encrypted
    // buffer were empty when we started and are empty now".
    status.writeEmpty =
        bufs[writePlaintextId].isEmpty &&
        start(writeEncryptedId) == end(writeEncryptedId);
    // If we were in handshake when this started, _writeEmpty may be false
    // because the handshake wrote data after we checked.
    if (wasInHandshake) status.writeEmpty = false;

    // Compute readEmpty as "both read buffers were empty when we started
    // and are empty now".
    status.readEmpty =
        bufs[readEncryptedId].isEmpty &&
        start(readPlaintextId) == end(readPlaintextId);

    _ExternalBuffer buffer = bufs[writePlaintextId];
    int new_start = start(writePlaintextId);
    if (new_start != buffer.start) {
      status.progress = true;
      if (buffer.free == 0) {
        status.writePlaintextNoLongerFull = true;
      }
      buffer.start = new_start;
    }
    buffer = bufs[readEncryptedId];
    new_start = start(readEncryptedId);
    if (new_start != buffer.start) {
      status.progress = true;
      if (buffer.free == 0) {
        status.readEncryptedNoLongerFull = true;
      }
      buffer.start = new_start;
    }
    buffer = bufs[writeEncryptedId];
    int new_end = end(writeEncryptedId);
    if (new_end != buffer.end) {
      status.progress = true;
      if (buffer.length == 0) {
        status.writeEncryptedNoLongerEmpty = true;
      }
      buffer.end = new_end;
    }
    buffer = bufs[readPlaintextId];
    new_end = end(readPlaintextId);
    if (new_end != buffer.end) {
      status.progress = true;
      if (buffer.length == 0) {
        status.readPlaintextNoLongerEmpty = true;
      }
      buffer.end = new_end;
    }
    return status;
  }
}

enum QuicConnectionTerminationType {
  transportClose,
  applicationClose,
  idleTimeout,
  versionNegotiation,
  statelessReset,
}

final class QuicConnectionTermination {
  const QuicConnectionTermination({
    required this.type,
    required this.errorCode,
    required this.reason,
    this.frameType,
  });

  final QuicConnectionTerminationType type;
  final int errorCode;
  final int? frameType;
  final String reason;
}

final class QuicConnectionException implements IOException {
  const QuicConnectionException(this.termination);

  final QuicConnectionTermination termination;

  @override
  String toString() {
    final frame = termination.frameType == null ? '' : ', frame ${termination.frameType}';
    final reason = termination.reason.isEmpty ? '' : ': ${termination.reason}';
    return 'QuicConnectionException(${termination.type.name}, '
        'error ${termination.errorCode}$frame)$reason';
  }
}

/// Alternative network addresses advertised by a QUIC peer.
///
/// A peer can advertise either address family or both. QUIC validates a new
/// path before it becomes active, so callers can continue using the existing
/// path if migration to one of these endpoints fails.
final class QuicPreferredAddress {
  const QuicPreferredAddress({this.ipv4Address, this.ipv4Port, this.ipv6Address, this.ipv6Port});

  final InternetAddress? ipv4Address;
  final int? ipv4Port;
  final InternetAddress? ipv6Address;
  final int? ipv6Port;
}

/// Raw QUIC-over-UDP socket.
///
/// This mirrors [RawSecureSocket] at the datagram level. It is where the VM
/// implementation would bridge QUIC packet processing, BoringSSL's QUIC TLS
/// callbacks, timers, and stream readiness into Dart events.
abstract class RawDatagramSecureSocket implements Stream<RawSocketEvent> {
  static Future<RawDatagramSecureSocket> connect(
    host,
    int port, {
    SecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    void Function(String line)? keyLog,
    List<String>? supportedProtocols = const <String>['h3'],
    Map<String, Uint8List>? protocolSettings,
    bool? useEchGrease,
    Uint8List? initialToken,
    Uint8List? resumptionState,
    bool enableEarlyData = false,
    bool useNativeUdp = false,
    Duration? timeout,
  }) async {
    _verifyFields(host, port);
    _verifyInitialToken(initialToken);
    _verifyResumptionState(resumptionState);
    final result = Completer<RawDatagramSecureSocket>();
    final pendingAddresses = Queue<InternetAddress>();
    final activeSockets = <RawDatagramSocket>{};
    Timer? attemptTimer;
    Timer? ipv6LookupTimer;
    Timer? timeoutTimer;
    Object? firstConnectionError;
    StackTrace? firstConnectionStackTrace;
    Object? firstLookupError;
    StackTrace? firstLookupStackTrace;
    var activeAttempts = 0;
    var pendingLookups = 0;
    var finished = false;
    final tlsHost = host is InternetAddress ? host.address : host as String;
    DateTime? lastAttempt;
    var lastAttemptDelay = const Duration(milliseconds: 250);

    void closeActiveSockets([RawDatagramSocket? except]) {
      for (final socket in activeSockets.toList()) {
        if (!identical(socket, except)) socket.close();
      }
      activeSockets
        ..clear()
        ..addAll(except == null ? const [] : [except]);
    }

    void finishErrorIfExhausted() {
      if (finished || pendingLookups != 0 || pendingAddresses.isNotEmpty || activeAttempts != 0) {
        return;
      }
      finished = true;
      attemptTimer?.cancel();
      ipv6LookupTimer?.cancel();
      timeoutTimer?.cancel();
      closeActiveSockets();
      final error =
          firstConnectionError ?? firstLookupError ?? SocketException('No address found for $host');
      final stackTrace = firstConnectionError != null
          ? firstConnectionStackTrace
          : firstLookupStackTrace;
      result.completeError(error, stackTrace ?? StackTrace.current);
    }

    late void Function({bool immediate}) scheduleNext;
    late void Function() startNext;

    startNext = () {
      attemptTimer?.cancel();
      attemptTimer = null;
      if (finished || pendingAddresses.isEmpty) {
        finishErrorIfExhausted();
        return;
      }
      final address = pendingAddresses.removeFirst();
      activeAttempts++;
      lastAttempt = DateTime.now();
      lastAttemptDelay = address.isLoopback
          ? const Duration(milliseconds: 25)
          : const Duration(milliseconds: 250);
      () async {
        RawDatagramSocket? socket;
        try {
          final bindAddress = address.type == InternetAddressType.IPv6
              ? InternetAddress.anyIPv6
              : InternetAddress.anyIPv4;
          socket = await RawDatagramSocket.bind(bindAddress, 0);
          if (finished) {
            socket.close();
            return;
          }
          activeSockets.add(socket);
          final connected = await secure(
            socket,
            remoteAddress: address,
            remotePort: port,
            host: tlsHost,
            context: context,
            onBadCertificate: onBadCertificate,
            keyLog: keyLog,
            supportedProtocols: supportedProtocols,
            protocolSettings: protocolSettings,
            useEchGrease: useEchGrease,
            initialToken: initialToken,
            resumptionState: resumptionState,
            enableEarlyData: enableEarlyData,
            useNativeUdp: useNativeUdp,
          );
          if (enableEarlyData &&
              connected.isEarlyData &&
              host is String &&
              InternetAddress.tryParse(host) == null) {
            await connected.handshakeComplete;
          }
          if (finished) {
            socket.close();
            return;
          }
          finished = true;
          attemptTimer?.cancel();
          ipv6LookupTimer?.cancel();
          timeoutTimer?.cancel();
          closeActiveSockets(socket);
          result.complete(connected);
        } catch (error, stackTrace) {
          socket?.close();
          activeSockets.remove(socket);
          firstConnectionError ??= error;
          firstConnectionStackTrace ??= stackTrace;
        } finally {
          activeAttempts--;
          if (!finished) scheduleNext(immediate: true);
        }
      }();
      scheduleNext();
    };

    scheduleNext = ({bool immediate = false}) {
      if (finished) return;
      if (pendingAddresses.isEmpty) {
        finishErrorIfExhausted();
        return;
      }
      attemptTimer?.cancel();
      if (immediate || activeAttempts == 0 || lastAttempt == null) {
        startNext();
        return;
      }
      final elapsed = DateTime.now().difference(lastAttempt!);
      final remaining = lastAttemptDelay - elapsed;
      if (remaining <= Duration.zero) {
        startNext();
      } else {
        attemptTimer = Timer(remaining, startNext);
      }
    };

    void addAddresses(List<InternetAddress> addresses) {
      if (finished) return;
      for (final address in addresses) {
        if (address.type == InternetAddressType.IPv4 || address.type == InternetAddressType.IPv6) {
          pendingAddresses.add(address);
        }
      }
      scheduleNext();
    }

    void lookup(InternetAddressType type) async {
      try {
        addAddresses(await InternetAddress.lookup(host as String, type: type));
      } catch (error, stackTrace) {
        firstLookupError ??= error;
        firstLookupStackTrace ??= stackTrace;
      } finally {
        pendingLookups--;
        finishErrorIfExhausted();
      }
    }

    final resolvedHost = host is InternetAddress ? host : InternetAddress.tryParse(host as String);
    if (resolvedHost != null) {
      addAddresses([resolvedHost]);
    } else {
      pendingLookups = 2;
      lookup(InternetAddressType.IPv4);
      ipv6LookupTimer = Timer(
        const Duration(milliseconds: 10),
        () => lookup(InternetAddressType.IPv6),
      );
    }
    if (timeout != null) {
      timeoutTimer = Timer(timeout, () {
        if (finished) return;
        finished = true;
        attemptTimer?.cancel();
        ipv6LookupTimer?.cancel();
        closeActiveSockets();
        result.completeError(
          SocketException('Connection to $host:$port timed out'),
          StackTrace.current,
        );
      });
    }
    return result.future;
  }

  static Future<RawDatagramSecureSocket> secure(
    RawDatagramSocket socket, {
    required InternetAddress remoteAddress,
    required int remotePort,
    host,
    SecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    void Function(String line)? keyLog,
    List<String>? supportedProtocols = const <String>['h3'],
    Map<String, Uint8List>? protocolSettings,
    bool? useEchGrease,
    Uint8List? initialToken,
    Uint8List? resumptionState,
    bool enableEarlyData = false,
    bool useNativeUdp = false,
  }) {
    _verifyInitialToken(initialToken);
    _verifyResumptionState(resumptionState);
    socket.readEventsEnabled = true;
    socket.writeEventsEnabled = false;
    return _RawDatagramSecureSocket.connect(
      socket,
      remoteAddress: remoteAddress,
      remotePort: remotePort,
      host: host,
      context: context ?? SecurityContext.defaultContext,
      onBadCertificate: onBadCertificate,
      keyLog: keyLog,
      supportedProtocols: supportedProtocols,
      protocolSettings: protocolSettings,
      useEchGrease: useEchGrease,
      initialToken: initialToken,
      resumptionState: resumptionState,
      enableEarlyData: enableEarlyData,
      useNativeUdp: useNativeUdp,
    );
  }

  static void _verifyFields(host, int requestedPort) {
    if (host is! String && host is! InternetAddress) {
      throw ArgumentError('host is not a String or an InternetAddress');
    }
    if (requestedPort < 0 || requestedPort > 65535) {
      throw ArgumentError('requestedPort is not in the range 0..65535');
    }
  }

  static void _verifyInitialToken(Uint8List? token) {
    if (token != null && token.length > 1024) {
      throw ArgumentError.value(token, 'initialToken', 'Must not exceed 1024 bytes');
    }
  }

  static void _verifyResumptionState(Uint8List? state) {
    if (state != null && state.length > 64 * 1024) {
      throw ArgumentError.value(state, 'resumptionState', 'Must not exceed 64 KiB');
    }
  }

  InternetAddress get remoteAddress;
  int get remotePort;
  InternetAddress get address;
  int get port;

  X509Certificate? get peerCertificate;
  String? get selectedProtocol;
  Uint8List get peerQuicTransportParameters;
  QuicPreferredAddress? get peerPreferredAddress;
  Uint8List? takeNewToken();
  Uint8List? takeResumptionState();

  /// Completes after the TLS handshake finishes and reports whether 0-RTT was
  /// accepted. It reports false when early data was not attempted.
  Future<bool> get handshakeComplete;

  bool get isHandshakeComplete;
  bool get isEarlyData;
  bool? get earlyDataAccepted;
  QuicConnectionTermination? get termination;

  bool get readEventsEnabled;
  set readEventsEnabled(bool enabled);

  bool get writeEventsEnabled;
  set writeEventsEnabled(bool enabled);

  /// Sends unreliable plaintext application data in a QUIC DATAGRAM frame.
  int send(List<int> data, [int offset = 0, int? bytes]);

  /// Receives unreliable plaintext application data from QUIC DATAGRAM frames.
  Uint8List? receive();

  /// Opens a client-initiated bidirectional reliable QUIC stream.
  int openBidirectionalStream();

  /// Opens a client-initiated unidirectional reliable QUIC stream.
  int openUnidirectionalStream();

  /// Returns the ID of the next peer-initiated stream, or `-1` if none is
  /// currently available.
  ///
  /// Each stream ID is returned at most once. Stream data is read with
  /// [streamRead].
  int acceptStream();

  /// Returns whether [streamId] is a bidirectional QUIC stream.
  bool isStreamBidirectional(int streamId);

  /// Returns the number of contiguous readable bytes queued for [streamId].
  int streamAvailable(int streamId);

  /// Reads reliable plaintext data from [streamId].
  ///
  /// Returns `null` when no stream bytes are currently available. Returns an
  /// empty [Uint8List] when the peer's FIN has been received and all bytes have
  /// been read.
  Uint8List? streamRead(int streamId, [int? bytes]);

  /// Returns the peer-provided application error from RESET_STREAM for the
  /// readable direction of [streamId], if one has arrived.
  ///
  /// The error is returned at most once for each stream.
  int? streamReadErrorCode(int streamId);

  /// Returns the peer-provided application error from STOP_SENDING for the
  /// writable direction of [streamId], if one has arrived.
  ///
  /// The error is returned at most once for each stream.
  int? streamWriteErrorCode(int streamId);

  /// Writes reliable plaintext data to [streamId] as QUIC STREAM frames.
  int streamWrite(int streamId, List<int> data, [int offset = 0, int? bytes]);

  /// Sends FIN on [streamId].
  void streamClose(int streamId);

  /// Resets [streamId].
  void streamReset(int streamId, {int errorCode = 0});

  /// Requests that the peer stop sending on [streamId].
  void streamStopSending(int streamId, {int errorCode = 0});

  /// Moves this QUIC connection to a new network path.
  ///
  /// The old path remains active until the peer validates [remoteAddress] and
  /// [remotePort] with PATH_CHALLENGE and PATH_RESPONSE. Supplying [socket]
  /// also changes the local address or port. The secure socket takes ownership
  /// of a supplied socket and closes it with the connection.
  Future<void> migrate({
    RawDatagramSocket? socket,
    InternetAddress? remoteAddress,
    int? remotePort,
  });

  Future<void> close({int errorCode = 0, String reason = ''});
}

class _DatagramSocketPath {
  _DatagramSocketPath({
    required this.id,
    required this.socket,
    required this.remoteAddress,
    required this.remotePort,
  });

  final int id;
  final RawDatagramSocket socket;
  final InternetAddress remoteAddress;
  final int remotePort;
}

class _QuicApplicationStreamState {
  _QuicApplicationStreamState(
    Uint8List readData,
    Uint8List writeData, {
    required int readStart,
    required int readEnd,
    required int writeStart,
    required int writeEnd,
    required this.sendClosed,
    required this.receiveClosed,
  }) : readBuffer = _ExternalBuffer.fromData(readData, start: readStart, end: readEnd),
       writeBuffer = _ExternalBuffer.fromData(writeData, start: writeStart, end: writeEnd);

  final _ExternalBuffer readBuffer;
  final _ExternalBuffer writeBuffer;
  bool sendClosed;
  bool receiveClosed;
  bool finRequested = false;
  int? resetErrorCode;
  int? stopSendingErrorCode;
  bool releaseRequested = false;
  bool finReceived = false;
  int? readErrorCode;
  int? writeErrorCode;

  bool get canReleaseBuffers =>
      sendClosed &&
      receiveClosed &&
      readBuffer.isEmpty &&
      writeBuffer.isEmpty &&
      !finRequested &&
      resetErrorCode == null &&
      stopSendingErrorCode == null;
}

class _RawDatagramSecureSocket extends Stream<RawSocketEvent> implements RawDatagramSecureSocket {
  static const int handshakeStatus = 301;
  static const int connectedStatus = 302;
  static const int closedStatus = 303;
  static const int readPlaintextId = 0;
  static const int writePlaintextId = 1;
  static const int readEncryptedId = 2;
  static const int writeEncryptedId = 3;
  static const int bufferCount = 4;
  static const int _maximumApplicationDatagram = 1024;
  static const int _maximumNetworkDatagram = 1500;

  static bool _isBufferEncrypted(int identifier) => identifier >= readEncryptedId;

  static Future<_RawDatagramSecureSocket> connect(
    RawDatagramSocket socket, {
    required InternetAddress remoteAddress,
    required int remotePort,
    host,
    required SecurityContext context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    void Function(String line)? keyLog,
    List<String>? supportedProtocols,
    Map<String, Uint8List>? protocolSettings,
    bool? useEchGrease,
    Uint8List? initialToken,
    Uint8List? resumptionState,
    bool enableEarlyData = false,
    bool useNativeUdp = false,
  }) {
    final secureSocket = _RawDatagramSecureSocket(
      socket,
      remoteAddress: remoteAddress,
      isServer: false,
      remotePort: remotePort,
      host: host ?? remoteAddress.host,
      context: context,
      onBadCertificate: onBadCertificate,
      keyLog: keyLog,
      supportedProtocols: supportedProtocols ?? const <String>['h3'],
      protocolSettings:
          protocolSettings ??
          {
            // Fallback when building chance master branch
            if (Platform.isAndroid && (supportedProtocols?.contains('h3') ?? false))
              'h3': Uint8List(0),
          },
      // Fallback when building with chance master
      useEchGrease: useEchGrease ?? Platform.isAndroid,
      initialToken: initialToken ?? Uint8List(0),
      resumptionState: resumptionState ?? Uint8List(0),
      enableEarlyData: enableEarlyData,
      useNativeUdp: useNativeUdp,
    );
    return secureSocket._connectReady.future;
  }

  _RawDatagramSecureSocket(
    this._socket, {
    required InternetAddress remoteAddress,
    required int remotePort,
    required this.host,
    required this.isServer,
    required this.context,
    required this.onBadCertificate,
    required this.keyLog,
    List<String>? supportedProtocols,
    required Map<String, Uint8List> protocolSettings,
    required this.useEchGrease,
    required this.initialToken,
    required this.resumptionState,
    required this.enableEarlyData,
    required this.useNativeUdp,
  }) {
    _controller
      ..onListen = _onSubscriptionStateChange
      ..onPause = _onPauseStateChange
      ..onResume = _onPauseStateChange
      ..onCancel = _onSubscriptionStateChange;

    final initialPath = _DatagramSocketPath(
      id: 0,
      socket: _socket,
      remoteAddress: remoteAddress,
      remotePort: remotePort,
    );
    _paths[0] = initialPath;
    _activePath = initialPath;
    _listenToSocket(_socket);

    try {
      _secureFilter = _DatagramSecureFilter._(useNativeUdp);
      _secureFilter.init();
      if (useNativeUdp) {
        _secureFilter.attachNativeSocket(_socket, remoteAddress, remotePort, 0);
      }
      _secureFilter.registerHandshakeCompleteCallback(_handshakeCompleteHandler);
      if (onBadCertificate != null) {
        _secureFilter.registerBadCertificateCallback(_onBadCertificateWrapper);
      }
      if (keyLog != null) {
        final keyLogPort = ReceivePort();
        keyLogPort.listen((line) {
          keyLog!('${line as String}\n');
        });
        _secureFilter.registerKeyLogPort(keyLogPort.sendPort);
        _keyLogPort = keyLogPort;
      }

      var encodedProtocols = SecurityContext._protocolsToLengthEncoding(supportedProtocols);
      var encodedProtocolSettings = protocolSettings.entries
          .map((e) => [utf8.encode(e.key), e.value])
          .toList();
      _secureFilter.connect(
        host,
        context,
        isServer,
        encodedProtocols,
        encodedProtocolSettings,
        useEchGrease,
        initialToken,
        resumptionState,
        enableEarlyData,
      );
      _secureHandshake();
    } catch (error, stackTrace) {
      _reportError(error, stackTrace);
    }
  }

  final RawDatagramSocket _socket;
  final String host;
  final bool isServer;
  final SecurityContext context;
  final bool Function(X509Certificate certificate)? onBadCertificate;
  final void Function(String line)? keyLog;
  final Uint8List initialToken;
  final Uint8List resumptionState;
  final bool enableEarlyData;
  final bool useNativeUdp;
  final bool useEchGrease;

  @override
  InternetAddress get remoteAddress => _activePath.remoteAddress;

  @override
  int get remotePort => _activePath.remotePort;

  @override
  InternetAddress get address => _activePath.socket.address;

  @override
  int get port => _activePath.socket.port;

  final _controller = StreamController<RawSocketEvent>(sync: true);
  final _connectReady = Completer<_RawDatagramSecureSocket>();
  final _handshakeComplete = Completer<bool>();
  final _paths = <int, _DatagramSocketPath>{};
  final _socketSubscriptions = <RawDatagramSocket, StreamSubscription<RawSocketEvent>>{};
  final _migrationCompleters = <int, Completer<void>>{};
  late _DatagramSocketPath _activePath;
  var _nextPathId = 1;
  late final _DatagramSecureFilter _secureFilter;
  ReceivePort? _keyLogPort;
  ReceivePort? _nativePumpPort;

  var _status = handshakeStatus;
  var _handshakeFinished = false;
  var _handshakeOperationActive = false;
  var _handshakeOperationPending = false;
  var _handshakeAwaitingResult = false;
  var _earlyDataAttempted = false;
  bool? _earlyDataAccepted;
  var _readEventsEnabled = true;
  var _writeEventsEnabled = true;
  var _nativeUdpWriteReady = false;
  var _nativePumpActive = false;
  var _pendingReadEvent = false;
  var _pendingWriteEvent = false;
  var _pauseCount = 0;
  var _filterStatus = _FilterStatus();
  var _filterPending = false;
  var _nativeEventFilterPending = false;
  var _filterActive = false;
  var _streamFilterScheduled = false;
  Completer<void>? _filterIdleCompleter;
  Future<void>? _closeFuture;
  Timer? _recoveryTimer;
  var _closing = false;
  var _filterDestroyed = false;
  QuicConnectionTermination? _termination;
  Future<void>? _nativeTerminationFuture;
  Completer<void>? _nativeTerminationCompleter;
  final Queue<Uint8List> _receivedDatagrams = Queue<Uint8List>();
  final Queue<Uint8List> _newTokens = Queue<Uint8List>();
  final Queue<Uint8List> _resumptionStates = Queue<Uint8List>();
  final Queue<int> _openedBidirectionalStreams = Queue<int>();
  final Queue<int> _openedUnidirectionalStreams = Queue<int>();
  final Queue<int> _acceptedStreams = Queue<int>();
  final Map<int, _QuicApplicationStreamState> _applicationStreams =
      <int, _QuicApplicationStreamState>{};
  final Set<int> _pendingNativeReadCursors = <int>{};
  final Set<int> _pendingNativeStreamUpdates = <int>{};
  var _openBidirectionalStreamRequests = 0;
  var _openUnidirectionalStreamRequests = 0;
  int? _pathValidationRequest;
  int? _closeErrorCode;
  Uint8List _closeReason = Uint8List(0);
  var _nativeConnectionTerminated = false;
  _ExternalDatagram? _pendingNetworkWrite;

  @override
  StreamSubscription<RawSocketEvent> listen(
    void Function(RawSocketEvent event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    _sendWriteEvent();
    return _controller.stream.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }

  @override
  bool get readEventsEnabled => _readEventsEnabled;

  @override
  set readEventsEnabled(bool value) {
    _readEventsEnabled = value;
    _scheduleReadEvent();
  }

  @override
  bool get writeEventsEnabled => _writeEventsEnabled;

  @override
  set writeEventsEnabled(bool value) {
    _writeEventsEnabled = value;
    _scheduleWriteEvent();
  }

  @override
  X509Certificate? get peerCertificate => _secureFilter.peerCertificate;

  @override
  String? get selectedProtocol => _secureFilter.selectedProtocol();

  @override
  Uint8List get peerQuicTransportParameters {
    // BoringSSL call:
    //   SSL_get_peer_quic_transport_params(ssl, &ptr, &len)
    return _secureFilter.peerQuicTransportParameters();
  }

  @override
  QuicPreferredAddress? get peerPreferredAddress {
    final value = _secureFilter.peerPreferredAddress();
    if (value == null || value.length < 42) return null;

    InternetAddress? ipv4Address;
    int? ipv4Port;
    if (value.sublist(0, 4).any((byte) => byte != 0)) {
      ipv4Address = InternetAddress.fromRawAddress(
        Uint8List.sublistView(value, 0, 4),
        type: InternetAddressType.IPv4,
      );
      ipv4Port = (value[4] << 8) | value[5];
    }

    InternetAddress? ipv6Address;
    int? ipv6Port;
    if (value.sublist(6, 22).any((byte) => byte != 0)) {
      ipv6Address = InternetAddress.fromRawAddress(
        Uint8List.sublistView(value, 6, 22),
        type: InternetAddressType.IPv6,
      );
      ipv6Port = (value[22] << 8) | value[23];
    }

    return QuicPreferredAddress(
      ipv4Address: ipv4Address,
      ipv4Port: ipv4Port,
      ipv6Address: ipv6Address,
      ipv6Port: ipv6Port,
    );
  }

  @override
  Uint8List? takeNewToken() {
    return _newTokens.isEmpty ? null : _newTokens.removeFirst();
  }

  @override
  Uint8List? takeResumptionState() {
    return _resumptionStates.isEmpty ? null : _resumptionStates.removeFirst();
  }

  @override
  Future<bool> get handshakeComplete => _handshakeComplete.future;

  @override
  bool get isHandshakeComplete => _handshakeFinished;

  @override
  bool get isEarlyData => _earlyDataAttempted && !_handshakeFinished;

  @override
  bool? get earlyDataAccepted => _earlyDataAccepted;

  @override
  QuicConnectionTermination? get termination => _termination;

  @override
  int send(List<int> data, [int offset = 0, int? bytes]) {
    if (bytes != null && bytes < 0) {
      throw ArgumentError("Invalid bytes parameter in DatagramSecureSocket.send (bytes: $bytes)");
    }
    if (_status != connectedStatus || _closing || _termination != null) return 0;
    bytes ??= data.length - offset;
    if (offset < 0 || bytes < 0 || offset + bytes > data.length) {
      throw RangeError.range(offset, 0, data.length);
    }
    if (bytes > _maximumApplicationDatagram) {
      throw ArgumentError.value(
        bytes,
        'bytes',
        'QUIC DATAGRAM payload exceeds $_maximumApplicationDatagram bytes',
      );
    }
    final written = _secureFilter.buffers![writePlaintextId].writeDatagram(
      data,
      offset: offset,
      bytes: bytes,
    );
    if (written) {
      _filterStatus.writeEmpty = false;
      _scheduleFilter();
    }
    return written ? bytes : 0;
  }

  @override
  Uint8List? receive() {
    if (_status != connectedStatus || _closing || _termination != null) return null;
    final buffer = _secureFilter.buffers![readPlaintextId];
    final payload = _receivedDatagrams.isNotEmpty
        ? _receivedDatagrams.removeFirst()
        : buffer.readDatagram()?.data;
    if (payload != null) _scheduleFilter();
    return payload;
  }

  @override
  int openBidirectionalStream() {
    if (_status != connectedStatus || _closing || _termination != null) return -1;
    if (_openedBidirectionalStreams.isNotEmpty) {
      return _openedBidirectionalStreams.removeFirst();
    }
    _openBidirectionalStreamRequests++;
    if (_nativePumpActive) {
      _scheduleNativeEventFilter();
    } else {
      _scheduleFilter();
    }
    return -1;
  }

  @override
  int openUnidirectionalStream() {
    if (_status != connectedStatus || _closing || _termination != null) return -1;
    if (_openedUnidirectionalStreams.isNotEmpty) {
      return _openedUnidirectionalStreams.removeFirst();
    }
    _openUnidirectionalStreamRequests++;
    if (_nativePumpActive) {
      _scheduleNativeEventFilter();
    } else {
      _scheduleFilter();
    }
    return -1;
  }

  @override
  int acceptStream() {
    if (_status != connectedStatus || _closing || _termination != null) return -1;
    return _acceptedStreams.isEmpty ? -1 : _acceptedStreams.removeFirst();
  }

  void _registerApplicationStream(
    int streamId,
    Uint8List readData,
    Uint8List writeData,
    int eventFlags,
    int readErrorCode,
    int writeErrorCode,
    int readStart,
    int readEnd,
    int writeStart,
    int writeEnd,
  ) {
    if (_applicationStreams.containsKey(streamId)) {
      throw StateError('QUIC stream $streamId was registered more than once');
    }
    final bidirectional = isStreamBidirectional(streamId);
    final locallyInitiated = (streamId & 0x01) == (isServer ? 1 : 0);
    final state = _QuicApplicationStreamState(
      readData,
      writeData,
      readStart: readStart,
      readEnd: readEnd,
      writeStart: writeStart,
      writeEnd: writeEnd,
      sendClosed: !bidirectional && !locallyInitiated,
      receiveClosed: !bidirectional && locallyInitiated,
    );
    if ((eventFlags & 1) != 0) state.finReceived = true;
    if ((eventFlags & 2) != 0) state.readErrorCode = readErrorCode;
    if ((eventFlags & 4) != 0) state.writeErrorCode = writeErrorCode;
    _applicationStreams[streamId] = state;
    if (locallyInitiated) {
      (bidirectional ? _openedBidirectionalStreams : _openedUnidirectionalStreams).add(streamId);
    } else {
      _acceptedStreams.add(streamId);
    }
  }

  @override
  bool isStreamBidirectional(int streamId) {
    return (streamId & 0x02) == 0;
  }

  @override
  int streamAvailable(int streamId) {
    if (_status != connectedStatus || _closing || _termination != null) return 0;
    return _applicationStreams[streamId]?.readBuffer.length ?? 0;
  }

  @override
  Uint8List? streamRead(int streamId, [int? bytes]) {
    if (_status != connectedStatus || _closing || _termination != null) return null;
    if (bytes != null && bytes < 0) {
      throw ArgumentError.value(bytes, 'bytes');
    }
    final state = _applicationStreams[streamId];
    if (state == null) return null;
    final wasFull = state.readBuffer.free == 0;
    final payload = state.readBuffer.read(bytes);
    if (payload == null && state.finReceived) {
      state.finReceived = false;
      state.receiveClosed = true;
      _scheduleStreamFilter(streamId);
      return Uint8List(0);
    }
    // Native UDP readiness normally carries updated cursors on the next filter
    // pass. A deferred STREAM frame may need more room than this ring had
    // available without the ring being completely full, so explicitly publish
    // a cursor advance whenever the native receive path reports backpressure.
    if (payload != null && (wasFull || _filterStatus.nativeReceiveBlockedStreamId == streamId)) {
      if (_filterStatus.nativeReceiveBlockedStreamId == streamId) {
        _filterStatus.nativeReceiveBlocked = false;
        _filterStatus.nativeReceiveBlockedStreamId = null;
      }
      if (_nativePumpActive) {
        _pendingNativeReadCursors.add(streamId);
        _scheduleNativeEventFilter();
      } else {
        _scheduleStreamFilter(streamId);
      }
    }
    return payload;
  }

  @override
  int? streamReadErrorCode(int streamId) {
    if (_status != connectedStatus || _closing || _termination != null) return null;
    final state = _applicationStreams[streamId];
    if (state == null) return null;
    final errorCode = state.readErrorCode;
    state.readErrorCode = null;
    if (errorCode != null) {
      state.receiveClosed = true;
      _scheduleStreamFilter(streamId);
    }
    return errorCode;
  }

  @override
  int? streamWriteErrorCode(int streamId) {
    if (_status != connectedStatus || _closing || _termination != null) return null;
    final state = _applicationStreams[streamId];
    if (state == null) return null;
    final errorCode = state.writeErrorCode;
    state.writeErrorCode = null;
    if (errorCode != null) {
      state.sendClosed = true;
      _scheduleStreamFilter(streamId);
    }
    return errorCode;
  }

  @override
  int streamWrite(int streamId, List<int> data, [int offset = 0, int? bytes]) {
    if (bytes != null && bytes < 0) {
      throw ArgumentError("Invalid bytes parameter in streamWrite (bytes: $bytes)");
    }
    if (_status != connectedStatus || _closing || _termination != null) return 0;
    bytes ??= data.length - offset;
    if (offset < 0 || bytes < 0 || offset + bytes > data.length) {
      throw RangeError.range(offset, 0, data.length);
    }
    final state = _applicationStreams[streamId];
    if (state == null || state.sendClosed) return 0;
    final written = state.writeBuffer.write(data, offset, bytes);
    if (written != 0) {
      _filterStatus.writeEmpty = false;
      _scheduleStreamFilter(streamId);
    }
    return written;
  }

  @override
  void streamClose(int streamId) {
    if (_status != connectedStatus || _closing || _termination != null) return;
    final state = _applicationStreams[streamId];
    if (state == null || state.sendClosed) return;
    state.sendClosed = true;
    state.finRequested = true;
    _scheduleStreamFilter(streamId);
  }

  @override
  void streamReset(int streamId, {int errorCode = 0}) {
    if (_status != connectedStatus || _closing || _termination != null) return;
    if (errorCode < 0 || errorCode > 0x3fffffffffffffff) {
      throw RangeError.range(errorCode, 0, 0x3fffffffffffffff, 'errorCode');
    }
    final state = _applicationStreams[streamId];
    if (state == null) return;
    state.sendClosed = true;
    state.finRequested = false;
    state.resetErrorCode = errorCode;
    _scheduleStreamFilter(streamId);
  }

  @override
  void streamStopSending(int streamId, {int errorCode = 0}) {
    if (_status != connectedStatus || _closing || _termination != null) return;
    if (errorCode < 0 || errorCode > 0x3fffffffffffffff) {
      throw RangeError.range(errorCode, 0, 0x3fffffffffffffff, 'errorCode');
    }
    final state = _applicationStreams[streamId];
    if (state == null) return;
    state.readBuffer.clear();
    state.receiveClosed = true;
    state.stopSendingErrorCode = errorCode;
    _scheduleStreamFilter(streamId);
  }

  bool get _hasReadableApplicationData {
    if (_receivedDatagrams.isNotEmpty || !_secureFilter.buffers![readPlaintextId].isEmpty) {
      return true;
    }
    return _acceptedStreams.isNotEmpty ||
        _newTokens.isNotEmpty ||
        _resumptionStates.isNotEmpty ||
        _applicationStreams.values.any(
          (state) =>
              !state.readBuffer.isEmpty ||
              state.finReceived ||
              state.readErrorCode != null ||
              state.writeErrorCode != null,
        );
  }

  @override
  Future<void> migrate({
    RawDatagramSocket? socket,
    InternetAddress? remoteAddress,
    int? remotePort,
  }) async {
    if (_status != connectedStatus || _closing || _termination != null) {
      return Future<void>.error(StateError('The QUIC connection is not open.'));
    }
    remoteAddress ??= _activePath.remoteAddress;
    remotePort ??= _activePath.remotePort;
    if (remotePort < 0 || remotePort > 65535) {
      return Future<void>.error(
        ArgumentError.value(remotePort, 'remotePort', 'Must be in the range 0..65535'),
      );
    }
    socket ??= _activePath.socket;
    if (identical(socket, _activePath.socket) &&
        _sameInternetAddress(remoteAddress, _activePath.remoteAddress) &&
        remotePort == _activePath.remotePort) {
      return Future<void>.value();
    }
    if (_migrationCompleters.isNotEmpty) {
      return Future<void>.error(StateError('A QUIC path migration is already in progress.'));
    }
    if (useNativeUdp) await _waitForFilterIdle();

    socket.readEventsEnabled = true;
    socket.writeEventsEnabled = false;
    _listenToSocket(socket);
    final pathId = _nextPathId++;
    final path = _DatagramSocketPath(
      id: pathId,
      socket: socket,
      remoteAddress: remoteAddress,
      remotePort: remotePort,
    );
    _paths[pathId] = path;
    if (useNativeUdp) {
      _secureFilter.attachNativeSocket(socket, remoteAddress, remotePort, pathId);
    }
    final completer = Completer<void>();
    _migrationCompleters[pathId] = completer;
    _pathValidationRequest = pathId;
    _scheduleFilter();
    return completer.future;
  }

  @override
  Future<void> close({int errorCode = 0, String reason = ''}) {
    return _closeFuture ??= _close(errorCode, reason);
  }

  Future<void> _close(int errorCode, String reason) async {
    if (_status == closedStatus) return;
    _closing = true;
    final terminated = _nativeTerminationCompleter ??= Completer<void>();

    _secureFilter.buffers![writePlaintextId].clear();
    _closeErrorCode = errorCode;
    _closeReason = Uint8List.fromList(utf8.encode(reason));
    await _scheduleFilter();
    await _waitForFilterIdle();
    if (!useNativeUdp) _writeSocket();
    await terminated.future;
  }

  Future<void> _waitForFilterIdle() async {
    while (_filterActive) {
      final completer = _filterIdleCompleter ??= Completer<void>();
      await completer.future;
    }
  }

  void _finishFilterPass() {
    _filterActive = false;
    final completer = _filterIdleCompleter;
    _filterIdleCompleter = null;
    if (completer != null && !completer.isCompleted) {
      completer.complete();
    }
  }

  void _destroyFilter() {
    if (_filterDestroyed) return;
    _filterDestroyed = true;
    if (_nativePumpActive) {
      _secureFilter.stopNativePump();
      _nativePumpActive = false;
    }
    _nativePumpPort?.close();
    _nativePumpPort = null;
    _secureFilter.destroy();
  }

  void _listenToSocket(RawDatagramSocket socket) {
    if (_socketSubscriptions.containsKey(socket)) return;
    final subscription = socket.listen(
      (event) => _eventDispatcher(socket, event),
      onError: _reportError,
      onDone: () => _doneHandler(socket),
    );
    _socketSubscriptions[socket] = subscription;
    if (_nativePumpActive) {
      socket.readEventsEnabled = false;
      socket.writeEventsEnabled = false;
    }
  }

  void _eventDispatcher(RawDatagramSocket socket, RawSocketEvent event) {
    if (_status == closedStatus) {
      socket.readEventsEnabled = false;
      socket.writeEventsEnabled = false;
      return;
    }
    if (event == RawSocketEvent.read) {
      if (_nativePumpActive) return;
      if (useNativeUdp && _handshakeAwaitingResult) {
        socket.readEventsEnabled = false;
        return;
      }
      if (useNativeUdp) {
        socket.readEventsEnabled = false;
      } else {
        _readSocket(socket);
      }
      _scheduleFilter();
    } else if (event == RawSocketEvent.write) {
      if (_nativePumpActive) return;
      if (useNativeUdp) {
        _nativeUdpWriteReady = true;
      } else {
        _writeSocket();
      }
      _scheduleFilter();
    } else if (event == RawSocketEvent.closed || event == RawSocketEvent.readClosed) {
      _controller.add(RawSocketEvent.readClosed);
      if (identical(socket, _activePath.socket)) {
        if (!_closing) {
          _reportError(const SocketException('QUIC UDP socket closed'));
        }
        unawaited(_finishNativeTermination());
      }
    }
  }

  Future<void> _secureHandshake() async {
    if (_status == closedStatus || _filterDestroyed) return;
    if (_handshakeOperationActive) {
      _handshakeOperationPending = true;
      return;
    }
    _handshakeOperationActive = true;
    try {
      while (true) {
        _handshakeAwaitingResult = true;
        final retry = await _secureFilter!.handshake();
        _handshakeAwaitingResult = false;
        if (_status == closedStatus || _filterDestroyed) return;
        if (!retry) break;
        // Certificate verification completed; drive the same TLS handshake
        // operation again without allowing concurrent callers.
      }
      if (enableEarlyData && !_handshakeFinished && _secureFilter.isInEarlyData()) {
        _earlyDataAttempted = true;
        _status = connectedStatus;
        if (!_connectReady.isCompleted) {
          _connectReady.complete(this);
        }
      }
      _filterStatus.writeEmpty = false;
      if (!useNativeUdp) {
        _readSocket();
        _writeSocket();
      }
      await _scheduleFilter();
    } catch (e, stackTrace) {
      if (_status != closedStatus && !_filterDestroyed) {
        _reportError(e, stackTrace);
      }
    } finally {
      _handshakeAwaitingResult = false;
      _handshakeOperationActive = false;
      if (_handshakeOperationPending &&
          !_handshakeFinished &&
          _status != closedStatus &&
          !_filterDestroyed) {
        _handshakeOperationPending = false;
        scheduleMicrotask(_secureHandshake);
      } else {
        _handshakeOperationPending = false;
      }
    }
  }

  void _readSocket([RawDatagramSocket? sourceSocket]) {
    if (_status == closedStatus) return;
    final buffer = _secureFilter.buffers![readEncryptedId];
    var written = 0;
    final sockets = sourceSocket == null
        ? _socketSubscriptions.keys
        : <RawDatagramSocket>[sourceSocket];
    while (buffer.hasFreeSlot) {
      Datagram? datagram;
      RawDatagramSocket? receivingSocket;
      for (final socket in sockets) {
        datagram = socket.receive();
        if (datagram != null) {
          receivingSocket = socket;
          break;
        }
      }
      if (datagram == null || receivingSocket == null) break;
      if (datagram.data.length > _maximumNetworkDatagram) continue;
      final path = _pathForDatagram(receivingSocket, datagram);
      if (!buffer.writeDatagram(datagram.data, id: path.id)) {
        break;
      }
      written++;
    }
    if (written != 0) {
      _filterStatus.readEmpty = false;
    } else {
      if (sourceSocket != null) {
        sourceSocket.readEventsEnabled = false;
      } else {
        for (final socket in _socketSubscriptions.keys) {
          socket.readEventsEnabled = false;
        }
      }
    }
  }

  _DatagramSocketPath _pathForDatagram(RawDatagramSocket socket, Datagram datagram) {
    for (final path in _paths.values) {
      if (identical(path.socket, socket) &&
          path.remotePort == datagram.port &&
          _sameInternetAddress(path.remoteAddress, datagram.address)) {
        return path;
      }
    }
    final path = _DatagramSocketPath(
      id: _nextPathId++,
      socket: socket,
      remoteAddress: datagram.address,
      remotePort: datagram.port,
    );
    _paths[path.id] = path;
    return path;
  }

  void _writeSocket() {
    final buffer = _secureFilter.buffers![writeEncryptedId];
    while (true) {
      final datagram = _pendingNetworkWrite ?? buffer.readDatagram();
      if (datagram == null) return;
      final path = _paths[datagram.id] ?? _activePath;
      final sent = path.socket.send(datagram.data, path.remoteAddress, path.remotePort);
      if (sent <= 0) {
        _pendingNetworkWrite = datagram;
        path.socket.writeEventsEnabled = true;
        return;
      }
      _pendingNetworkWrite = null;
    }
  }

  void _markFullFilterPending() {
    _filterPending = true;
  }

  Future<void> _scheduleFilter() {
    _streamFilterScheduled = false;
    _nativeEventFilterPending = false;
    _markFullFilterPending();
    return _tryFilter();
  }

  Future<void> _scheduleNativeEventFilter() {
    _nativeEventFilterPending = true;
    return _tryFilter();
  }

  void _scheduleStreamFilter(int streamId) {
    if (_nativePumpActive) {
      _pendingNativeStreamUpdates.add(streamId);
      _scheduleNativeEventFilter();
      return;
    }
    if (_streamFilterScheduled) return;
    _streamFilterScheduled = true;
    scheduleMicrotask(() {
      if (!_streamFilterScheduled) return;
      _streamFilterScheduled = false;
      if (_status != closedStatus) {
        _scheduleFilter();
      }
    });
  }

  Future<void> _tryFilter() async {
    try {
      while (true) {
        if (_status == closedStatus) return;
        if ((!_filterPending && !_nativeEventFilterPending) || _filterActive) {
          return;
        }
        _filterActive = true;
        if (!_filterPending) {
          _nativeEventFilterPending = false;
          await _pushNativeEvents();
          _finishFilterPass();
          continue;
        }
        _filterPending = false;
        _nativeEventFilterPending = false;

        final wasInHandshake = !_handshakeFinished;
        _filterStatus = await _pushAllFilterStages(wasInHandshake);
        _finishFilterPass();
        if (useNativeUdp &&
            !_nativePumpActive &&
            (!wasInHandshake || _filterStatus.handshakeCryptoProgress)) {
          _startNativePump();
        }
        if (!_nativePumpActive) {
          _armRecoveryTimer(_filterStatus.recoveryTimeoutMillis);
        }
        if (_nativeConnectionTerminated) {
          unawaited(_finishNativeTermination());
          return;
        }
        if (useNativeUdp && wasInHandshake && !_nativePumpActive) {
          final encryptedInput = _secureFilter.buffers![readEncryptedId];
          _readSocket();
          if (!encryptedInput.isEmpty) {
            _markFullFilterPending();
          }
        }
        if (!_nativePumpActive) {
          for (final socket in _socketSubscriptions.keys) {
            socket.readEventsEnabled = true;
            if (useNativeUdp) {
              socket.writeEventsEnabled = _filterStatus.nativeUdpWriteBlocked;
            }
          }
        }

        if (_filterStatus.needsImmediatePass && !_nativePumpActive) {
          _markFullFilterPending();
        }
        if (!useNativeUdp && _filterStatus.writeEncryptedNoLongerEmpty) {
          _writeSocket();
        }
        if (!useNativeUdp && _filterStatus.readEncryptedNoLongerFull) {
          final encryptedInput = _secureFilter.buffers![readEncryptedId];
          final previousEnd = encryptedInput.end;
          _readSocket();
          if (encryptedInput.end != previousEnd) {
            _markFullFilterPending();
          }
        }
        if (_filterStatus.readPlaintextNoLongerEmpty || _hasReadableApplicationData) {
          _scheduleReadEvent();
        }
        if (_filterStatus.writePlaintextNoLongerFull || _filterStatus.streamWriteReady) {
          _sendWriteEvent();
        }
        if (_filterStatus.progress && wasInHandshake && !_handshakeFinished) {
          _secureHandshake();
        }
      }
    } catch (error, stackTrace) {
      if (_filterActive) {
        _finishFilterPass();
      }
      if (_status != closedStatus && !_filterDestroyed) {
        _reportError(error, stackTrace);
      }
    }
  }

  Future<_FilterStatus> _pushAllFilterStages(bool wasInHandshake) async {
    final buffers = _secureFilter.buffers!;
    final streams = _applicationStreams.entries.toList(growable: false);
    const streamRequestSize = 8;
    const streamResponseSize = 7;
    const connectionRequestSize = 18;
    const connectionResponseSize = 21;
    const finRequested = 1;
    const resetRequested = 2;
    const stopSendingRequested = 4;
    const releaseRequested = 8;
    const closeRequested = 1;
    const pathValidationRequested = 2;
    const finReceived = 1;
    const readErrorReceived = 2;
    const writeErrorReceived = 4;
    final requestedBidirectionalStreams = _openBidirectionalStreamRequests;
    final requestedUnidirectionalStreams = _openUnidirectionalStreamRequests;
    final requestedPathId = _pathValidationRequest;
    final requestedCloseErrorCode = _closeErrorCode;
    final requestedCloseReason = _closeReason;
    final requestedFlags = <int>[];
    final requestedResetCodes = <int?>[];
    final requestedStopCodes = <int?>[];
    final requestedWriteEnds = <int>[];
    final requestedNativeReadCursors = <int, int>{};
    final args = List<dynamic>.filled(
      connectionRequestSize + streams.length * streamRequestSize,
      null,
    );
    args[0] = _secureFilter!._pointer();
    args[1] = wasInHandshake;
    for (var i = 0; i < bufferCount; ++i) {
      args[2 * i + 2] = buffers[i].start;
      args[2 * i + 3] = buffers[i].end;
    }
    args[10] = streams.length;
    var connectionFlags = 0;
    if (requestedCloseErrorCode != null) connectionFlags |= closeRequested;
    if (requestedPathId != null) connectionFlags |= pathValidationRequested;
    args[11] = connectionFlags;
    args[12] = requestedCloseErrorCode ?? 0;
    args[13] = requestedCloseReason;
    args[14] = requestedPathId ?? -1;
    args[15] = requestedBidirectionalStreams;
    args[16] = requestedUnidirectionalStreams;
    args[17] = _nativeUdpWriteReady;
    _nativeUdpWriteReady = false;
    for (var i = 0; i < streams.length; i++) {
      final entry = streams[i];
      final state = entry.value;
      var flags = 0;
      if (state.finRequested) flags |= finRequested;
      if (state.resetErrorCode != null) flags |= resetRequested;
      if (state.stopSendingErrorCode != null) flags |= stopSendingRequested;
      if (state.canReleaseBuffers) {
        state.releaseRequested = true;
        flags |= releaseRequested;
      }
      requestedFlags.add(flags);
      requestedResetCodes.add(state.resetErrorCode);
      requestedStopCodes.add(state.stopSendingErrorCode);
      requestedWriteEnds.add(state.writeBuffer.end);
      final offset = connectionRequestSize + i * streamRequestSize;
      args[offset] = entry.key;
      args[offset + 1] = state.readBuffer.start;
      args[offset + 2] = state.readBuffer.end;
      args[offset + 3] = state.writeBuffer.start;
      args[offset + 4] = state.writeBuffer.end;
      args[offset + 5] = flags;
      args[offset + 6] = state.resetErrorCode ?? 0;
      args[offset + 7] = state.stopSendingErrorCode ?? 0;
      if (_pendingNativeReadCursors.contains(entry.key)) {
        requestedNativeReadCursors[entry.key] = state.readBuffer.start;
      }
    }
    final response =
        (await _IOService._dispatch(_IOService.sslProcessFilter, args)) as List<Object?>;
    if (response.length == 2) {
      if (wasInHandshake) {
        throw HandshakeException('${response[1]} error ${response[0]}');
      }
      throw TlsException('${response[1]} error ${response[0]}');
    }
    _openBidirectionalStreamRequests -= requestedBidirectionalStreams;
    _openUnidirectionalStreamRequests -= requestedUnidirectionalStreams;
    if (_pathValidationRequest == requestedPathId) _pathValidationRequest = null;
    if (_closeErrorCode == requestedCloseErrorCode) {
      _closeErrorCode = null;
      _closeReason = Uint8List(0);
    }
    final expectedResponseSize = connectionResponseSize + streams.length * streamResponseSize;
    if (response.length != expectedResponseSize) {
      throw StateError(
        'Invalid QUIC filter response length ${response.length}; '
        'expected $expectedResponseSize',
      );
    }

    final status = _FilterStatus();
    status.needsImmediatePass = response[bufferCount * 2] as bool;
    status.progress = status.needsImmediatePass;
    status.recoveryTimeoutMillis = response[bufferCount * 2 + 1] as int;
    status.streamWriteReady = response[bufferCount * 2 + 2] as bool;

    final registeredStreams = response[11] as List<Object?>;
    for (final value in registeredStreams) {
      final descriptor = value! as List<Object?>;
      _registerApplicationStream(
        descriptor[0] as int,
        descriptor[1] as Uint8List,
        descriptor[2] as Uint8List,
        descriptor[3] as int,
        descriptor[4] as int,
        descriptor[5] as int,
        descriptor[6] as int,
        descriptor[7] as int,
        descriptor[8] as int,
        descriptor[9] as int,
      );
    }
    if (registeredStreams.isNotEmpty) {
      status.progress = true;
      status.streamWriteReady = true;
      status.readPlaintextNoLongerEmpty = true;
    }

    void updateStart(int index) {
      final newStart = response[2 * index] as int;
      final buffer = buffers[index];
      if (newStart != buffer.start) {
        status.progress = true;
        if (index == writePlaintextId) {
          status.writePlaintextNoLongerFull = true;
        }
        if (index == readEncryptedId && buffer.free == 0) {
          status.readEncryptedNoLongerFull = true;
        }
        buffer.start = newStart;
      }
    }

    void updateEnd(int index) {
      final newEnd = response[2 * index + 1] as int;
      final buffer = buffers[index];
      if (newEnd != buffer.end) {
        status.progress = true;
        if (index == writeEncryptedId && buffer.length == 0) {
          status.writeEncryptedNoLongerEmpty = true;
        }
        if (index == readPlaintextId && buffer.length == 0) {
          status.readPlaintextNoLongerEmpty = true;
        }
        buffer.end = newEnd;
      }
    }

    updateStart(writePlaintextId);
    updateStart(readEncryptedId);
    if (useNativeUdp) updateStart(writeEncryptedId);
    updateEnd(writeEncryptedId);
    updateEnd(readPlaintextId);

    final releasedStreams = <int>[];
    for (var i = 0; i < streams.length; i++) {
      final entry = streams[i];
      final state = entry.value;
      final offset = connectionResponseSize + i * streamResponseSize;
      if (response[offset] != entry.key) {
        throw StateError('QUIC filter returned the wrong stream identifier');
      }
      final newReadEnd = response[offset + 1] as int;
      final newWriteStart = response[offset + 2] as int;
      final appliedFlags = response[offset + 3] as int;
      final eventFlags = response[offset + 4] as int;
      if (newReadEnd != state.readBuffer.end) {
        final wasEmpty = state.readBuffer.isEmpty;
        state.readBuffer.end = newReadEnd;
        status.progress = true;
        if (wasEmpty) status.readPlaintextNoLongerEmpty = true;
      }
      if (newWriteStart != state.writeBuffer.start) {
        state.writeBuffer.start = newWriteStart;
        status.progress = true;
        status.writePlaintextNoLongerFull = true;
      }
      if ((appliedFlags & finRequested) != 0 && (requestedFlags[i] & finRequested) != 0) {
        state.finRequested = false;
      }
      if ((appliedFlags & resetRequested) != 0 && state.resetErrorCode == requestedResetCodes[i]) {
        state.resetErrorCode = null;
      }
      if ((appliedFlags & stopSendingRequested) != 0 &&
          state.stopSendingErrorCode == requestedStopCodes[i]) {
        state.stopSendingErrorCode = null;
      }
      if ((appliedFlags & releaseRequested) != 0 && state.releaseRequested) {
        releasedStreams.add(entry.key);
      }
      if ((eventFlags & finReceived) != 0) {
        state.finReceived = true;
        status.readPlaintextNoLongerEmpty = true;
      }
      if ((eventFlags & readErrorReceived) != 0) {
        state.readErrorCode = response[offset + 5] as int;
        status.readPlaintextNoLongerEmpty = true;
      }
      if ((eventFlags & writeErrorReceived) != 0) {
        state.writeErrorCode = response[offset + 6] as int;
        status.readPlaintextNoLongerEmpty = true;
      }
    }

    _takeConnectionTermination(response[12] as List<Object?>?);
    _takePathValidationResults(response[13] as List<Object?>);
    for (final token in response[14] as List<Object?>) {
      _newTokens.add(token! as Uint8List);
    }
    for (final state in response[15] as List<Object?>) {
      _resumptionStates.add(state! as Uint8List);
    }
    _nativeConnectionTerminated = response[16] as bool;
    if (response[17] as bool) {
      status.readPlaintextNoLongerEmpty = true;
    }
    status.nativeUdpWriteBlocked = response[18] as bool;
    status.nativeReceiveBlocked = response[19] as bool;
    status.handshakeCryptoProgress = response[20] as bool;

    status.writeEmpty =
        buffers[writePlaintextId].isEmpty &&
        response[2 * writeEncryptedId] == response[2 * writeEncryptedId + 1] &&
        _applicationStreams.values.every(
          (state) =>
              state.writeBuffer.isEmpty &&
              !state.finRequested &&
              state.resetErrorCode == null &&
              state.stopSendingErrorCode == null,
        );
    status.readEmpty =
        buffers[readEncryptedId].isEmpty &&
        response[2 * readPlaintextId] == response[2 * readPlaintextId + 1] &&
        _applicationStreams.values.every((state) => state.readBuffer.isEmpty);
    for (final streamId in releasedStreams) {
      _applicationStreams.remove(streamId);
      _pendingNativeReadCursors.remove(streamId);
      _pendingNativeStreamUpdates.remove(streamId);
    }
    for (var i = 0; i < streams.length; i++) {
      final entry = streams[i];
      final state = _applicationStreams[entry.key];
      if (state == null) continue;
      if (!_hasPendingNativeStreamUpdate(state)) {
        _pendingNativeStreamUpdates.remove(entry.key);
      } else if (_nativePumpActive &&
          (status.streamWriteReady || state.writeBuffer.end != requestedWriteEnds[i])) {
        _nativeEventFilterPending = true;
      }
    }
    _completeNativeReadCursorRequests(requestedNativeReadCursors);
    if (wasInHandshake) status.writeEmpty = false;
    return status;
  }

  Future<void> _pushNativeEvents() async {
    const requestHeaderSize = 4;
    const responseHeaderSize = 7;
    const streamRequestSize = 8;
    const streamResponseSize = 7;
    const finRequested = 1;
    const resetRequested = 2;
    const stopSendingRequested = 4;
    const releaseRequested = 8;
    const finReceived = 1;
    const readErrorReceived = 2;
    const writeErrorReceived = 4;

    final requestedNativeReadCursors = <int, int>{};
    for (final streamId in _pendingNativeReadCursors) {
      final state = _applicationStreams[streamId];
      if (state == null) continue;
      requestedNativeReadCursors[streamId] = state.readBuffer.start;
    }

    final streamIds = <int>{..._pendingNativeStreamUpdates, ...requestedNativeReadCursors.keys};
    final streams = <MapEntry<int, _QuicApplicationStreamState>>[];
    for (final streamId in streamIds) {
      final state = _applicationStreams[streamId];
      if (state != null) streams.add(MapEntry(streamId, state));
    }
    final requestedBidirectionalStreams = _openBidirectionalStreamRequests;
    final requestedUnidirectionalStreams = _openUnidirectionalStreamRequests;
    final requestedFlags = <int>[];
    final requestedResetCodes = <int?>[];
    final requestedStopCodes = <int?>[];
    final requestedWriteEnds = <int>[];
    final args = List<Object?>.filled(requestHeaderSize + streams.length * streamRequestSize, null);
    args[0] = _secureFilter!._pointer();
    args[1] = requestedBidirectionalStreams;
    args[2] = requestedUnidirectionalStreams;
    args[3] = streams.length;
    for (var i = 0; i < streams.length; i++) {
      final entry = streams[i];
      final state = entry.value;
      var flags = 0;
      if (state.finRequested) flags |= finRequested;
      if (state.resetErrorCode != null) flags |= resetRequested;
      if (state.stopSendingErrorCode != null) flags |= stopSendingRequested;
      if (state.canReleaseBuffers) {
        state.releaseRequested = true;
        flags |= releaseRequested;
      }
      requestedFlags.add(flags);
      requestedResetCodes.add(state.resetErrorCode);
      requestedStopCodes.add(state.stopSendingErrorCode);
      requestedWriteEnds.add(state.writeBuffer.end);
      final offset = requestHeaderSize + i * streamRequestSize;
      args[offset] = entry.key;
      args[offset + 1] = state.readBuffer.start;
      args[offset + 2] = state.readBuffer.end;
      args[offset + 3] = state.writeBuffer.start;
      args[offset + 4] = state.writeBuffer.end;
      args[offset + 5] = flags;
      args[offset + 6] = state.resetErrorCode ?? 0;
      args[offset + 7] = state.stopSendingErrorCode ?? 0;
    }
    final response =
        (await _IOService._dispatch(_IOService.sslProcessQuicEvents, args)) as List<Object?>;
    final expectedResponseSize = responseHeaderSize + streams.length * streamResponseSize;
    if (response.length != expectedResponseSize) {
      throw StateError(
        'Invalid QUIC event response length ${response.length}; '
        'expected $expectedResponseSize',
      );
    }
    _openBidirectionalStreamRequests -= requestedBidirectionalStreams;
    _openUnidirectionalStreamRequests -= requestedUnidirectionalStreams;
    _completeNativeReadCursorRequests(requestedNativeReadCursors);

    var becameReadable = false;
    var becameWritable = response[5] as bool;
    final registeredStreams = response[4] as List<Object?>;
    for (final value in registeredStreams) {
      final descriptor = value! as List<Object?>;
      _registerApplicationStream(
        descriptor[0] as int,
        descriptor[1] as Uint8List,
        descriptor[2] as Uint8List,
        descriptor[3] as int,
        descriptor[4] as int,
        descriptor[5] as int,
        descriptor[6] as int,
        descriptor[7] as int,
        descriptor[8] as int,
        descriptor[9] as int,
      );
    }
    if (registeredStreams.isNotEmpty) {
      becameReadable = true;
      becameWritable = true;
    }

    _filterStatus.nativeReceiveBlocked = response[1] as bool;
    final blockedStreamId = response[2] as int;
    final blockedReadStart = response[3] as int;
    _filterStatus.nativeReceiveBlockedStreamId =
        _filterStatus.nativeReceiveBlocked && blockedStreamId >= 0 ? blockedStreamId : null;
    if (_filterStatus.nativeReceiveBlocked && blockedStreamId >= 0 && blockedReadStart >= 0) {
      final blockedState = _applicationStreams[blockedStreamId];
      if (blockedState != null && blockedState.readBuffer.start != blockedReadStart) {
        _pendingNativeReadCursors.add(blockedStreamId);
        _nativeEventFilterPending = true;
      }
    }

    final releasedStreams = <int>[];
    for (var i = 0; i < streams.length; i++) {
      final entry = streams[i];
      final state = entry.value;
      final offset = responseHeaderSize + i * streamResponseSize;
      if (response[offset] != entry.key) {
        throw StateError('QUIC event response returned the wrong stream identifier');
      }
      final newReadEnd = response[offset + 1] as int;
      final newWriteStart = response[offset + 2] as int;
      final appliedFlags = response[offset + 3] as int;
      final eventFlags = response[offset + 4] as int;
      if (newReadEnd != state.readBuffer.end) {
        if (state.readBuffer.isEmpty) becameReadable = true;
        state.readBuffer.end = newReadEnd;
      }
      if (newWriteStart != state.writeBuffer.start) {
        state.writeBuffer.start = newWriteStart;
        becameWritable = true;
      }
      if ((appliedFlags & finRequested) != 0 && (requestedFlags[i] & finRequested) != 0) {
        state.finRequested = false;
      }
      if ((appliedFlags & resetRequested) != 0 && state.resetErrorCode == requestedResetCodes[i]) {
        state.resetErrorCode = null;
      }
      if ((appliedFlags & stopSendingRequested) != 0 &&
          state.stopSendingErrorCode == requestedStopCodes[i]) {
        state.stopSendingErrorCode = null;
      }
      if ((appliedFlags & releaseRequested) != 0 && state.releaseRequested) {
        releasedStreams.add(entry.key);
      }
      if ((eventFlags & finReceived) != 0) {
        state.finReceived = true;
        becameReadable = true;
      }
      if ((eventFlags & readErrorReceived) != 0) {
        state.readErrorCode = response[offset + 5] as int;
        becameReadable = true;
      }
      if ((eventFlags & writeErrorReceived) != 0) {
        state.writeErrorCode = response[offset + 6] as int;
        becameReadable = true;
      }
    }

    for (final value in response[6] as List<Object?>) {
      final descriptor = value! as List<Object?>;
      if (descriptor.length != 6) {
        throw StateError('Invalid QUIC stream event descriptor');
      }
      final streamId = descriptor[0] as int;
      final state = _applicationStreams[streamId];
      if (state == null) {
        _markFullFilterPending();
        continue;
      }
      final newReadEnd = descriptor[1] as int;
      if (newReadEnd != state.readBuffer.end) {
        if (state.readBuffer.isEmpty) becameReadable = true;
        state.readBuffer.end = newReadEnd;
      }
      final newWriteStart = descriptor[2] as int;
      if (newWriteStart != state.writeBuffer.start) {
        state.writeBuffer.start = newWriteStart;
        becameWritable = true;
      }
      final eventFlags = descriptor[3] as int;
      if ((eventFlags & finReceived) != 0) {
        state.finReceived = true;
        becameReadable = true;
      }
      if ((eventFlags & readErrorReceived) != 0) {
        state.readErrorCode = descriptor[4] as int;
        becameReadable = true;
      }
      if ((eventFlags & writeErrorReceived) != 0) {
        state.writeErrorCode = descriptor[5] as int;
        becameReadable = true;
      }
    }

    for (final streamId in releasedStreams) {
      _applicationStreams.remove(streamId);
      _pendingNativeReadCursors.remove(streamId);
      _pendingNativeStreamUpdates.remove(streamId);
    }
    for (var i = 0; i < streams.length; i++) {
      final entry = streams[i];
      final state = _applicationStreams[entry.key];
      if (state == null) continue;
      if (!_hasPendingNativeStreamUpdate(state)) {
        _pendingNativeStreamUpdates.remove(entry.key);
      } else if (state.writeBuffer.end != requestedWriteEnds[i] || (response[5] as bool)) {
        _nativeEventFilterPending = true;
      }
    }

    _filterStatus.streamWriteReady = response[5] as bool;
    _filterStatus.writeEmpty = _applicationStreams.values.every(
      (state) => !_hasPendingNativeStreamUpdate(state),
    );
    if (response[0] as bool) {
      _markFullFilterPending();
    }
    if (becameReadable || _hasReadableApplicationData) {
      _scheduleReadEvent();
    }
    if (becameWritable) _sendWriteEvent();
  }

  bool _hasPendingNativeStreamUpdate(_QuicApplicationStreamState state) =>
      !state.writeBuffer.isEmpty ||
      state.finRequested ||
      state.resetErrorCode != null ||
      state.stopSendingErrorCode != null ||
      state.releaseRequested ||
      state.canReleaseBuffers;

  void _completeNativeReadCursorRequests(Map<int, int> requested) {
    for (final entry in requested.entries) {
      final state = _applicationStreams[entry.key];
      if (state == null || state.readBuffer.start == entry.value) {
        _pendingNativeReadCursors.remove(entry.key);
      }
    }
    _pendingNativeReadCursors.removeWhere((streamId) => !_applicationStreams.containsKey(streamId));
    if (_nativePumpActive && _pendingNativeReadCursors.isNotEmpty) {
      _nativeEventFilterPending = true;
    }
  }

  void _armRecoveryTimer(int timeoutMillis) {
    _recoveryTimer?.cancel();
    _recoveryTimer = null;
    if (_status == closedStatus || timeoutMillis < 0) {
      return;
    }
    _recoveryTimer = Timer(Duration(milliseconds: timeoutMillis < 1 ? 1 : timeoutMillis), () {
      _recoveryTimer = null;
      if (_status != closedStatus) {
        _scheduleFilter();
      }
    });
  }

  void _takeConnectionTermination(List<Object?>? values) {
    if (_termination != null) return;
    if (values == null) return;
    final type = switch (values[0] as int) {
      1 => QuicConnectionTerminationType.transportClose,
      2 => QuicConnectionTerminationType.applicationClose,
      3 => QuicConnectionTerminationType.idleTimeout,
      4 => QuicConnectionTerminationType.versionNegotiation,
      5 => QuicConnectionTerminationType.statelessReset,
      _ => throw StateError('Unknown QUIC connection termination type'),
    };
    final frameType = values[2] as int;
    final termination = QuicConnectionTermination(
      type: type,
      errorCode: values[1] as int,
      frameType: frameType < 0 ? null : frameType,
      reason: utf8.decode(values[3] as Uint8List, allowMalformed: true),
    );
    _termination = termination;
    final exception = QuicConnectionException(termination);
    final wasConnectReady = _connectReady.isCompleted;
    if (!wasConnectReady) {
      _connectReady.completeError(exception);
    }
    if (wasConnectReady && !_handshakeComplete.isCompleted) {
      _handshakeComplete.completeError(exception);
    }
    if (!_controller.isClosed) {
      _controller.addError(exception);
      _controller.add(RawSocketEvent.readClosed);
    }
  }

  void _takePathValidationResults(List<Object?> results) {
    for (final value in results) {
      final values = value! as List<Object?>;
      final pathId = values[0] as int;
      final succeeded = values[1] as bool;
      final path = _paths[pathId];
      final completer = _migrationCompleters.remove(pathId);
      if (succeeded && path != null) {
        _activePath = path;
        if (completer != null && !completer.isCompleted) {
          completer.complete();
        }
      } else {
        if (path != null && !identical(path, _activePath)) {
          _paths.remove(pathId);
          _closeSocketIfUnused(path.socket);
        }
        if (completer != null && !completer.isCompleted) {
          completer.completeError(TimeoutException('QUIC path validation failed.'));
        }
      }
    }
  }

  void _closeSocketIfUnused(RawDatagramSocket socket) {
    if (_paths.values.any((path) => identical(path.socket, socket))) return;
    final subscription = _socketSubscriptions.remove(socket);
    unawaited(subscription?.cancel());
    socket.close();
  }

  Future<void> _finishNativeTermination() {
    return _nativeTerminationFuture ??= _disposeNativeTermination();
  }

  Future<void> _disposeNativeTermination() async {
    try {
      if (_status == closedStatus) return;
      _closing = true;
      _status = closedStatus;
      _recoveryTimer?.cancel();
      _recoveryTimer = null;
      if (_nativePumpActive) {
        _secureFilter.stopNativePump();
        _nativePumpActive = false;
      }
      _nativePumpPort?.close();
      _nativePumpPort = null;
      final subscriptions = _socketSubscriptions.values.toList();
      _socketSubscriptions.clear();
      await Future.wait(subscriptions.map((subscription) => subscription.cancel()));
      final sockets = <RawDatagramSocket>{for (final path in _paths.values) path.socket};
      _paths.clear();
      for (final socket in sockets) {
        socket.close();
      }
      for (final completer in _migrationCompleters.values) {
        if (!completer.isCompleted) {
          completer.completeError(StateError('The QUIC connection closed during migration.'));
        }
      }
      _migrationCompleters.clear();
      await _waitForFilterIdle();
      _destroyFilter();
      _keyLogPort?.close();
      if (!_controller.isClosed) {
        final hasListener = _controller.hasListener;
        _controller.add(RawSocketEvent.closed);
        final closed = _controller.close();
        if (hasListener) {
          await closed;
        }
      }
    } finally {
      final completer = _nativeTerminationCompleter;
      if (completer != null && !completer.isCompleted) {
        completer.complete();
      }
    }
  }

  void _handshakeCompleteHandler() {
    if (_status == closedStatus || _filterDestroyed) return;
    _handshakeFinished = true;
    _earlyDataAccepted = _earlyDataAttempted && _secureFilter.earlyDataAccepted();
    _status = connectedStatus;
    if (!_connectReady.isCompleted) {
      _connectReady.complete(this);
    }
    if (!_handshakeComplete.isCompleted) {
      _handshakeComplete.complete(_earlyDataAccepted ?? false);
    }
    if (useNativeUdp && !_nativePumpActive) {
      scheduleMicrotask(_startNativePump);
    }
  }

  void _startNativePump() {
    if (_nativePumpActive || _status == closedStatus || _filterDestroyed) {
      return;
    }
    for (final socket in _socketSubscriptions.keys) {
      socket.readEventsEnabled = false;
      socket.writeEventsEnabled = false;
    }
    _recoveryTimer?.cancel();
    _recoveryTimer = null;
    final port = ReceivePort();
    port.listen((message) {
      if (_status != closedStatus && !_filterDestroyed) {
        if (message == 2) {
          _scheduleNativeEventFilter();
        } else {
          _scheduleFilter();
        }
      }
    });
    if (_secureFilter.startNativePump(port.sendPort)) {
      _nativePumpPort = port;
      _nativePumpActive = true;
    } else {
      port.close();
      for (final socket in _socketSubscriptions.keys) {
        socket.readEventsEnabled = true;
        socket.writeEventsEnabled = _filterStatus.nativeUdpWriteBlocked;
      }
      _armRecoveryTimer(_filterStatus.recoveryTimeoutMillis);
    }
  }

  bool _onBadCertificateWrapper(X509Certificate certificate) {
    return onBadCertificate?.call(certificate) ?? false;
  }

  void _scheduleReadEvent() {
    if (_status != connectedStatus || _closing) return;
    final hasReadablePlaintext = _hasReadableApplicationData;
    if (!_readEventsEnabled || _pendingReadEvent || _pauseCount > 0 || !hasReadablePlaintext) {
      return;
    }
    _pendingReadEvent = true;
    scheduleMicrotask(() {
      _pendingReadEvent = false;
      if (_status != connectedStatus || _closing) return;
      final hasReadablePlaintext = _hasReadableApplicationData;
      if (_readEventsEnabled && _status == connectedStatus && hasReadablePlaintext) {
        _controller.add(RawSocketEvent.read);
      }
    });
  }

  void _scheduleWriteEvent() {
    if (!_writeEventsEnabled || _pendingWriteEvent || _pauseCount > 0) return;
    _pendingWriteEvent = true;
    scheduleMicrotask(_sendWriteEvent);
  }

  void _sendWriteEvent() {
    _pendingWriteEvent = false;
    final streamWriteReady = _filterStatus.streamWriteReady;
    final hasOpenSendStream = _applicationStreams.values.any((state) => !state.sendClosed);
    final applicationWriteReady =
        !hasOpenSendStream && _secureFilter.buffers![writePlaintextId].hasFreeSlot;
    final streamBufferReady = _applicationStreams.values.any(
      (state) => !state.sendClosed && state.writeBuffer.free != 0,
    );
    if (_writeEventsEnabled &&
        _pauseCount == 0 &&
        !_closing &&
        _status != closedStatus &&
        (applicationWriteReady || streamBufferReady || streamWriteReady)) {
      _filterStatus.streamWriteReady = false;
      _controller.add(RawSocketEvent.write);
    }
  }

  void _onSubscriptionStateChange() {}

  void _onPauseStateChange() {
    if (_controller.isPaused) {
      _pauseCount++;
    } else if (_pauseCount > 0) {
      _pauseCount--;
    }
  }

  void _reportError(Object error, [StackTrace? stackTrace]) {
    if (_status == closedStatus || _filterDestroyed) return;
    final wasConnectReady = _connectReady.isCompleted;
    if (!wasConnectReady) {
      _connectReady.completeError(error, stackTrace);
    }
    if (wasConnectReady && !_handshakeComplete.isCompleted) {
      _handshakeComplete.completeError(error, stackTrace);
    }
    if (!_controller.isClosed) {
      _controller.addError(error, stackTrace);
    }
    if (_closing) {
      unawaited(_finishNativeTermination());
    }
  }

  void _doneHandler(RawDatagramSocket socket) {
    if (identical(socket, _activePath.socket)) {
      if (!_closing) {
        _reportError(const SocketException('QUIC UDP socket closed'));
      }
      unawaited(_finishNativeTermination());
    }
  }

  static bool _sameInternetAddress(InternetAddress left, InternetAddress right) {
    if (left.type != right.type) return false;
    final leftBytes = left.rawAddress;
    final rightBytes = right.rawAddress;
    if (leftBytes.length != rightBytes.length) return false;
    for (var i = 0; i < leftBytes.length; i++) {
      if (leftBytes[i] != rightBytes[i]) return false;
    }
    return true;
  }

  static Uint8List _protocolsToLengthEncoding(List<String> protocols) {
    final bytes = <int>[];
    for (final protocol in protocols) {
      final encoded = protocol.codeUnits;
      if (encoded.length > 255) {
        throw ArgumentError.value(protocol, 'protocol', 'ALPN id is too long');
      }
      bytes
        ..add(encoded.length)
        ..addAll(encoded);
    }
    return Uint8List.fromList(bytes);
  }
}

/// A circular buffer backed by an external byte array.  Accessed from
/// both C++ and Dart code in an unsynchronized way, with one reading
/// and one writing.  All updates to start and end are done by Dart code.
class _ExternalBuffer {
  // This will be an ExternalByteArray, backed by C allocated data.
  @pragma("vm:entry-point")
  List<int>? data;

  @pragma("vm:entry-point")
  int start;

  @pragma("vm:entry-point")
  int end;

  @pragma("vm:entry-point")
  int size;

  _ExternalBuffer(int size) : size = size, start = size ~/ 2, end = size ~/ 2;

  _ExternalBuffer.fromData(Uint8List bytes, {int? start, int? end})
    : data = bytes,
      size = bytes.length,
      start = start ?? bytes.length ~/ 2,
      end = end ?? bytes.length ~/ 2;

  void advanceStart(int bytes) {
    assert(start > end || start + bytes <= end);
    start += bytes;
    if (start >= size) {
      start -= size;
      assert(start <= end);
      assert(start < size);
    }
  }

  void advanceEnd(int bytes) {
    assert(start <= end || start > end + bytes);
    end += bytes;
    if (end >= size) {
      end -= size;
      assert(end < start);
      assert(end < size);
    }
  }

  bool get isEmpty => end == start;

  int get length => start > end ? size + end - start : end - start;

  int get linearLength => start > end ? size - start : end - start;

  int get free => start > end ? start - end - 1 : size + start - end - 1;

  int get linearFree {
    if (start > end) return start - end - 1;
    if (start == 0) return size - end - 1;
    return size - end;
  }

  void clear() {
    start = end;
  }

  Uint8List? read(int? bytes) {
    if (bytes == null) {
      bytes = length;
    } else {
      bytes = min(bytes, length);
    }
    if (bytes == 0) return null;
    Uint8List result = Uint8List(bytes);
    int bytesRead = 0;
    // Loop over zero, one, or two linear data ranges.
    while (bytesRead < bytes) {
      int toRead = min(bytes - bytesRead, linearLength);
      result.setRange(bytesRead, bytesRead + toRead, data!, start);
      advanceStart(toRead);
      bytesRead += toRead;
    }
    return result;
  }

  int write(List<int> inputData, int offset, int bytes) {
    if (bytes > free) {
      bytes = free;
    }
    int written = 0;
    int toWrite = min(bytes, linearFree);
    // Loop over zero, one, or two linear data ranges.
    while (toWrite > 0) {
      data!.setRange(end, end + toWrite, inputData, offset);
      advanceEnd(toWrite);
      offset += toWrite;
      written += toWrite;
      toWrite = min(bytes - written, linearFree);
    }
    return written;
  }

  int writeFromSource(List<int>? getData(int requested)) {
    int written = 0;
    int toWrite = linearFree;
    // Loop over zero, one, or two linear data ranges.
    while (toWrite > 0) {
      // Source returns at most toWrite bytes, and it returns null when empty.
      var inputData = getData(toWrite);
      if (inputData == null || inputData.length == 0) break;
      var len = inputData.length;
      data!.setRange(end, end + len, inputData);
      advanceEnd(len);
      written += len;
      toWrite = linearFree;
    }
    return written;
  }

  bool readToSocket(RawSocket socket) {
    // Loop over zero, one, or two linear data ranges.
    while (true) {
      var toWrite = linearLength;
      if (toWrite == 0) return false;
      int bytes = socket.write(data!, start, toWrite);
      advanceStart(bytes);
      if (bytes < toWrite) {
        // The socket has blocked while we have data to write.
        return true;
      }
    }
  }
}

class _ExternalDatagram {
  const _ExternalDatagram(this.id, this.data);

  final int id;
  final Uint8List data;
}

/// A bounded queue of fixed-size slots backed by an external byte array.
/// Cursors include one generation bit so every slot can be used while empty
/// and full remain distinguishable. Each slot stores a datagram length, an
/// application-defined identifier, and one complete datagram.
class _ExternalDatagramBuffer extends _ExternalBuffer {
  static const int slotSize = 1536;
  static const int applicationSlotCount = 1;
  static const int nativeHandshakeInputSlotCount = 1;
  static const int networkInputSlotCount = 64;
  static const int networkOutputSlotCount = 8;
  static const int headerSize = 8;
  static const int payloadCapacity = slotSize - headerSize;

  _ExternalDatagramBuffer(this.slotCount) : super(slotSize * slotCount) {
    if (slotCount < 0) {
      throw ArgumentError.value(slotCount, 'slotCount');
    }
    start = 0;
    end = 0;
  }

  final int slotCount;

  int get _cursorLimit => 2 * slotCount;

  @override
  bool get isEmpty => start == end;

  @override
  int get length => start > end ? _cursorLimit + end - start : end - start;

  @override
  int get free => slotCount - length;

  bool get hasFreeSlot => free != 0;

  int _readUint32(int offset) {
    return (data![offset] << 24) |
        (data![offset + 1] << 16) |
        (data![offset + 2] << 8) |
        data![offset + 3];
  }

  void _writeUint32(int offset, int value) {
    data![offset] = (value >> 24) & 0xff;
    data![offset + 1] = (value >> 16) & 0xff;
    data![offset + 2] = (value >> 8) & 0xff;
    data![offset + 3] = value & 0xff;
  }

  bool writeDatagram(List<int> input, {int id = 0, int offset = 0, int? bytes}) {
    bytes ??= input.length - offset;
    if (offset < 0 || bytes < 0 || offset + bytes > input.length) {
      throw RangeError.range(offset, 0, input.length);
    }
    if (bytes > payloadCapacity) {
      throw ArgumentError.value(bytes, 'bytes', 'Datagram exceeds slot capacity');
    }
    if (id < 0 || id > 0xffffffff) {
      throw RangeError.range(id, 0, 0xffffffff, 'id');
    }
    if (!hasFreeSlot) return false;
    final base = (end % slotCount) * slotSize;
    _writeUint32(base, bytes);
    _writeUint32(base + 4, id);
    data!.setRange(base + headerSize, base + headerSize + bytes, input, offset);
    end = (end + 1) % _cursorLimit;
    return true;
  }

  _ExternalDatagram? readDatagram() {
    if (isEmpty) return null;
    final base = (start % slotCount) * slotSize;
    final bytes = _readUint32(base);
    if (bytes > payloadCapacity) {
      throw StateError('Invalid external datagram slot length $bytes');
    }
    final id = _readUint32(base + 4);
    final payload = Uint8List.fromList(data!.sublist(base + headerSize, base + headerSize + bytes));
    start = (start + 1) % _cursorLimit;
    return _ExternalDatagram(id, payload);
  }
}

abstract class _BaseSecureFilter<BufferType> {
  void destroy();
  Future<bool> handshake();
  String? selectedProtocol();
  void rehandshake();
  void init();
  X509Certificate? get peerCertificate;
  int processBuffer(int bufferIndex);
  void registerBadCertificateCallback(bool Function(X509Certificate) callback);
  void registerHandshakeCompleteCallback(Function handshakeCompleteHandler);
  void registerKeyLogPort(SendPort port);

  // This call may cause a reference counted pointer in the native
  // implementation to be retained. It should only be called when the resulting
  // value is passed to the IO service through a call to dispatch().
  int _pointer();

  List<BufferType>? get buffers;
}

abstract class _SecureFilter extends _BaseSecureFilter<_ExternalBuffer> {
  external factory _SecureFilter._();

  void connect(
    String hostName,
    SecurityContext context,
    bool isServer,
    bool requestClientCertificate,
    bool requireClientCertificate,
    Uint8List protocols,
    List<List<Uint8List>> protocolSettings,
    bool useNewAlpsCodePoint,
    bool useEchGrease,
  );
}

abstract class _DatagramSecureFilter extends _BaseSecureFilter<_ExternalDatagramBuffer> {
  external factory _DatagramSecureFilter._(bool useNativeUdp);

  void attachNativeSocket(
    RawDatagramSocket socket,
    InternetAddress remoteAddress,
    int remotePort,
    int pathId,
  );

  bool startNativePump(SendPort notificationPort);

  void stopNativePump();

  void connect(
    String hostName,
    SecurityContext context,
    bool isServer,
    Uint8List protocols,
    List<List<Uint8List>> protocolSettings,
    bool useEchGrease,
    Uint8List initialToken,
    Uint8List resumptionState,
    bool enableEarlyData,
  );

  Uint8List peerQuicTransportParameters();

  Uint8List? peerPreferredAddress();

  bool isInEarlyData();

  bool earlyDataAccepted();
}

/// A secure networking exception caused by a failure in the
/// TLS/SSL protocol.
@pragma("vm:entry-point")
class TlsException implements IOException {
  final String type;
  final String message;
  final OSError? osError;

  @pragma("vm:entry-point")
  const TlsException([String message = "", OSError? osError])
    : this._("TlsException", message, osError);

  const TlsException._(this.type, this.message, this.osError);

  String toString() {
    StringBuffer sb = StringBuffer();
    sb.write(type);
    if (message.isNotEmpty) {
      sb.write(": $message");
      if (osError != null) {
        sb.write(" ($osError)");
      }
    } else if (osError != null) {
      sb.write(": $osError");
    }
    return sb.toString();
  }
}

/// An exception that happens in the handshake phase of establishing
/// a secure network connection.
@pragma("vm:entry-point")
class HandshakeException extends TlsException {
  @pragma("vm:entry-point")
  const HandshakeException([String message = "", OSError? osError])
    : super._("HandshakeException", message, osError);
}

/// An exception that happens in the handshake phase of establishing
/// a secure network connection, when looking up or verifying a
/// certificate.
class CertificateException extends TlsException {
  @pragma("vm:entry-point")
  const CertificateException([String message = "", OSError? osError])
    : super._("CertificateException", message, osError);
}
