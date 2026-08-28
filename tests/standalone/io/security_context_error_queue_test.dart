// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

// OtherResources=localhost.crt

import 'dart:io';
import 'dart:typed_data';

import 'package:expect/expect.dart';

String getFilename(String path) => Platform.script.resolve(path).toFilePath();

void main() {
  final certificate = File(getFilename('localhost.crt')).readAsBytesSync();

  final verifyAlgorithmsContext = SecurityContext();

  Expect.throwsArgumentError(
    () => verifyAlgorithmsContext.setVerifyAlgorithms(
      Uint16List.fromList([0x1234]),
    ),
  );

  // A rejected preference list must not leave its BoringSSL error behind for
  // the next operation on the same thread.
  verifyAlgorithmsContext.useCertificateChainBytes(certificate);

  final ciphersContext = SecurityContext();
  Expect.throwsArgumentError(
    () => ciphersContext.setCiphers('not-a-cipher'),
  );
  ciphersContext.useCertificateChainBytes(certificate);
}
