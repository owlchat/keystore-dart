import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import 'extensions.dart';
import 'ffi.dart' as ffi;

class OwlchatKeyStore {
  OwlchatKeyStore() : _raw = _load();

  final ffi.RawKeyStore _raw;
  Pointer<Void> _ks = nullptr;

  KeysContainer create() {
    _ks = _raw.keystore_new();
    return KeysContainer(
      secretKey: secretKey,
      publicKey: publicKey,
      seed: seed,
    );
  }

  KeysContainer init(SecretKey secretKey) {
    final sk = secretKey.expose().asFixed32ArrayPtr();
    _ks = _raw.keystore_init(sk);
    secretKey.zeroize();
    return KeysContainer(
      secretKey: secretKey,
      publicKey: publicKey,
      seed: seed,
    );
  }

  KeysContainer restore(String paperKey) {
    final pk = Utf8.toUtf8(paperKey);
    _ks = _raw.keystore_restore(pk.cast());
    return KeysContainer(
      secretKey: secretKey,
      publicKey: publicKey,
      seed: seed,
    );
  }

  String backup(KeyStoreSeed? seed) {
    Pointer<ffi.Fixed32Array> arr = nullptr;
    if (seed != null) {
      arr = seed.expose().asFixed32ArrayPtr();
      seed.zeroize();
    }
    final ptr = _raw.keystore_backup(_ks, arr);
    final paperKey = Utf8.fromUtf8(ptr.cast());
    _raw.keystore_string_free(ptr);
    return paperKey;
  }

  SharedSecret diffieHellman(PublicKey thierPublic) {
    final arr = _emptyFixed32Array();
    final pk = thierPublic.expose().asFixed32ArrayPtr();
    final status = _raw.keystore_dh(_ks, pk, arr);
    return SharedSecret(arr.asUint8List());
  }

  Uint8List encrypt(Uint8List data, SharedSecret? sharedSecret) {
    Pointer<ffi.Fixed32Array> secret = nullptr;
    if (sharedSecret != null) {
      secret = sharedSecret.expose().asFixed32ArrayPtr();
    }
    final input = data.asSharedBufferPtr();
    final status = _raw.keystore_encrypt(_ks, input, secret);
    final out = input.asUint8List();
    return out;
  }

  Uint8List decrypt(Uint8List data, SharedSecret? sharedSecret) {
    Pointer<ffi.Fixed32Array> secret = nullptr;
    if (sharedSecret != null) {
      secret = sharedSecret.expose().asFixed32ArrayPtr();
    }
    final input = data.asSharedBufferPtr();
    final status = _raw.keystore_decrypt(_ks, input, secret);
    final out = input.asUint8List();
    return out;
  }

  SecretKey get secretKey {
    final secretKeyArray = _emptyFixed32Array();
    final status = _raw.keystore_secret_key(_ks, secretKeyArray);
    final secretKey = secretKeyArray.asUint8List();
    return SecretKey(secretKey);
  }

  PublicKey get publicKey {
    final publicKeyArray = _emptyFixed32Array();
    final status = _raw.keystore_public_key(_ks, publicKeyArray);
    final publicKey = publicKeyArray.asUint8List();
    return PublicKey(publicKey);
  }

  KeyStoreSeed? get seed {
    final seedArray = _emptyFixed32Array();
    final status = _raw.keystore_seed(_ks, seedArray);
    final seed = seedArray.asUint8List();
    return KeyStoreSeed(seed);
  }

  void dispose() {
    _raw.keystore_free(_ks);
  }
}

class KeysContainer {
  KeysContainer({
    required this.publicKey,
    required this.secretKey,
    this.seed,
  });

  final PublicKey publicKey;
  final SecretKey secretKey;
  final KeyStoreSeed? seed;
}

abstract class Key {
  const Key(Uint8List key) : _inner = key;

  final Uint8List _inner;

  String asBase64() {
    return base64.encode(_inner);
  }

  void zeroize() {
    _inner.setAll(0, List.filled(32, 0));
  }

  Uint8List expose() {
    return _inner;
  }
}

class PublicKey extends Key {
  const PublicKey(Uint8List key) : super(key);
  factory PublicKey.fromBase64(String b64) {
    final bytes = base64.decode(b64);
    return PublicKey(bytes);
  }
}

class SecretKey extends Key {
  const SecretKey(Uint8List key) : super(key);
  factory SecretKey.fromBase64(String b64) {
    final bytes = base64.decode(b64);
    return SecretKey(bytes);
  }
}

class SharedSecret extends Key {
  const SharedSecret(Uint8List key) : super(key);
  factory SharedSecret.fromBase64(String b64) {
    final bytes = base64.decode(b64);
    return SharedSecret(bytes);
  }
}

class KeyStoreSeed extends Key {
  const KeyStoreSeed(Uint8List key) : super(key);

  factory KeyStoreSeed.fromBase64(String b64) {
    final bytes = base64.decode(b64);
    return KeyStoreSeed(bytes);
  }
}

ffi.RawKeyStore _load() {
  if (Platform.isAndroid) {
    return ffi.RawKeyStore(DynamicLibrary.open('libkeystore.so'));
  } else if (Platform.isIOS) {
    return ffi.RawKeyStore(DynamicLibrary.executable());
  } else if (Platform.isWindows) {
    return ffi.RawKeyStore(DynamicLibrary.open('target/keystore.dll'));
  } else if (Platform.isLinux) {
    return ffi.RawKeyStore(DynamicLibrary.open('target/libkeystore.so'));
  } else if (Platform.isMacOS) {
    return ffi.RawKeyStore(DynamicLibrary.open('target/libkeystore.dylib'));
  } else {
    throw UnsupportedError('The Current Platform is not supported.');
  }
}

Pointer<ffi.Fixed32Array> _emptyFixed32Array() {
  final ptr = allocate<Uint8>(count: 32)
    ..asTypedList(32).setAll(0, List.filled(32, 0));

  final buf = allocate<ffi.Fixed32Array>();
  buf.ref.buf = ptr;
  return buf;
}
