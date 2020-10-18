library owlchat_keystore;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart';

import 'extensions.dart';
import 'ffi.dart' as ffi;

/// Owlchat Keystore Bining.
///
/// Holds the [DynamicLibrary] and the Current `KeyStore`.
class OwlchatKeyStore {
  /// Loads `KeyStore`'s [DynamicLibrary] depending on the current [Platform]
  ///
  /// Maybe throws [UnsupportedError] if the current [Platform]
  /// is not supported.
  OwlchatKeyStore();

  final ffi.RawKeyStore _raw = _load();
  Pointer<Void> _ks = nullptr;

  /// Create a new `KeyStore`.
  ///
  /// the returned [KeysContainer] will contain [PublicKey], [SecretKey]
  /// and `[KeyStoreSeed]`.
  /// `SecretKey` and `KeyStoreSeed` should be stored in some secure place.
  KeysContainer create() {
    _ks = _raw?.keystore_new();
    if (_ks == nullptr) {
      throw StateError('Failed to create KeyStore (got null)');
    }
    return KeysContainer(
      secretKey: secretKey,
      publicKey: publicKey,
      seed: seed,
    );
  }

  /// Initialize a previously created [OwlchatKeyStore] with a [SecretKey].
  ///
  /// the returned [KeysContainer] will contain [PublicKey], [SecretKey]
  /// and the `[KeyStoreSeed]` will be `null`.
  KeysContainer init(SecretKey secretKey) {
    final sk = secretKey.expose().asFixed32ArrayPtr();
    _ks = _raw?.keystore_init(sk);
    if (_ks == nullptr) {
      throw StateError('Failed to init KeyStore (got null)');
    }
    return KeysContainer(
      secretKey: secretKey,
      publicKey: publicKey,
      seed: seed,
    );
  }

  // ignore: comment_references
  /// Restores `KeyStore` using a [Mnemonic] paper key.
  ///
  /// the returned [KeysContainer] will contain [PublicKey], [SecretKey]
  /// and `[KeyStoreSeed]`.
  /// `SecretKey` and `KeyStoreSeed` should be stored in some secure place.
  KeysContainer restore(String paperKey) {
    final pk = Utf8.toUtf8(paperKey);
    _ks = _raw?.keystore_restore(pk.cast());
    if (_ks == nullptr) {
      throw StateError('Failed to restore KeyStore (got null)');
    }
    return KeysContainer(
      secretKey: secretKey,
      publicKey: publicKey,
      seed: seed,
    );
  }

  /// Backup the current `KeyStore`.
  ///
  /// this will first try to create the backup and return
  /// a [`Mnemonic`] paper key, if the current `KeyStore` has no seed.
  /// it will read from the provided one, if both are null;
  /// it will throw an Error.
  String backup({KeyStoreSeed seed}) {
    Pointer<ffi.Fixed32Array> arr = nullptr;
    if (seed != null) {
      arr = seed.expose().asFixed32ArrayPtr();
    }
    final ptr = _raw?.keystore_backup(_ks, arr);
    if (ptr == nullptr) {
      throw StateError('Failed to create backup (got null)');
    }
    final paperKey = Utf8.fromUtf8(ptr.cast());
    _raw?.keystore_string_free(ptr);
    return paperKey;
  }

  /// Perform a Diffie-Hellman key agreement to produce a [SharedSecret].
  SharedSecret diffieHellman(PublicKey thierPublic) {
    final arr = _emptyFixed32Array();
    final pk = thierPublic.expose().asFixed32ArrayPtr();
    final status = _raw?.keystore_dh(_ks, pk, arr);
    _assertOk(status);
    final sharedSecret = SharedSecret(arr.asUint8List());
    return sharedSecret;
  }

  /// Encrypt the provided data using the current `KeyStore`'s [SecretKey]
  /// else uses [SharedSecret] if provided.
  Uint8List encrypt(Uint8List data, {SharedSecret sharedSecret}) {
    Pointer<ffi.Fixed32Array> secret = nullptr;
    if (sharedSecret != null) {
      secret = sharedSecret.expose().asFixed32ArrayPtr();
    }
    final input = data.asSharedBufferPtr();
    final status = _raw?.keystore_encrypt(_ks, input, secret);
    _assertOk(status);
    final out = input.asUint8List();
    return out;
  }

  /// Decrypt the provided data using the current `KeyStore`'s [SecretKey]
  /// else uses [SharedSecret] if provided.
  Uint8List decrypt(Uint8List data, {SharedSecret sharedSecret}) {
    Pointer<ffi.Fixed32Array> secret = nullptr;
    if (sharedSecret != null) {
      secret = sharedSecret.expose().asFixed32ArrayPtr();
    }
    final input = data.asSharedBufferPtrExact();
    final status = _raw?.keystore_decrypt(_ks, input, secret);
    _assertOk(status);
    final out = input.asUint8List();
    return out;
  }

  /// Current `KeyStore`'s [SecretKey]
  SecretKey get secretKey {
    final secretKeyArray = _emptyFixed32Array();
    final status = _raw?.keystore_secret_key(_ks, secretKeyArray);
    _assertOk(status);
    final secretKey = secretKeyArray.asUint8List();
    return SecretKey(secretKey);
  }

  /// Current `KeyStore`'s [PublicKey]
  PublicKey get publicKey {
    final publicKeyArray = _emptyFixed32Array();
    final status = _raw?.keystore_public_key(_ks, publicKeyArray);
    _assertOk(status);
    final publicKey = publicKeyArray.asUint8List();
    return PublicKey(publicKey);
  }

  /// Current `KeyStore`'s `Seed`.
  ///
  /// ### Note
  /// The [KeyStoreSeed] will be `null` in the case this `KeyStore`
  /// is Inialized with `SecretKey`
  KeyStoreSeed get seed {
    final seedArray = _emptyFixed32Array();
    final status = _raw?.keystore_seed(_ks, seedArray);
    if (status == ffi.OperationStatus.KeyStoreHasNoSeed) {
      return null;
    } else {
      final seed = seedArray.asUint8List();
      return KeyStoreSeed(seed);
    }
  }

  /// Clean the Current `KeyStore`.
  ///
  /// ### Note
  /// this dose not unload the [DynamicLibrary], and the
  /// current [OwlchatKeyStore] could be reused.
  /// to clear everything call `dispose`.
  void clean() {
    _raw?.keystore_free(_ks);
    _ks = nullptr;
  }

  Uint8List calculateSha256Hash(String path) {
    final hash = _emptyFixed32Array();
    final status = _raw?.keystore_sha256_hash(path.toPointer().cast(), hash);
    _assertOk(status);
    return hash.asUint8List();
  }
}

/// A [KeysContainer] is a simple class that holds
/// [PublicKey], [SecretKey] and [KeyStoreSeed] if available.
class KeysContainer {
  KeysContainer({
    @required this.publicKey,
    @required this.secretKey,
    this.seed,
  });

  /// The Current `KeyStore`'s `PublicKey`.
  final PublicKey publicKey;

  /// The Current `KeyStore`'s `SecretKey`.
  final SecretKey secretKey;

  /// The Current `KeyStore`'s `Seed`.
  ///
  /// ### Note
  /// The Seed will be `null` in the case this `KeyStore`
  /// is Inialized with `SecretKey`.
  final KeyStoreSeed seed;
}

/// A [Key] is an abstract class that shares functinality between
/// [PublicKey], [SecretKey], [SharedSecret] and [KeyStoreSeed].
abstract class Key {
  const Key(Uint8List key) : _inner = key;

  final Uint8List _inner;

  /// Convert The Key into base64 encoded string.
  String asBase64() {
    return base64.encode(_inner);
  }

  /// Expose the underlaying bytes.
  Uint8List expose() {
    return _inner;
  }

  @override
  int get hashCode => _inner.hashCode;

  @override
  bool operator ==(Object other) {
    if (other is Key) {
      return _inner == other._inner;
    } else {
      return false;
    }
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

/// Loads the KeyStore [DynamicLibrary] depending on the [Platform]
/// and creates new `RawKeyStore`.
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

/// Creates a New Empty `Fixed32Array` so `FFI` can Write into it.
Pointer<ffi.Fixed32Array> _emptyFixed32Array() {
  final ptr = allocate<Uint8>(count: 32)
    ..asTypedList(32).setAll(0, List.filled(32, 0));

  final buf = allocate<ffi.Fixed32Array>();
  buf.ref.buf = ptr;
  return buf;
}

void _assertOk(int status) {
  if (status != ffi.OperationStatus.OK) {
    throw StateError(_operationStatusCodeToErrorMessage(status));
  }
}

String _operationStatusCodeToErrorMessage(int status) {
  switch (status) {
    case ffi.OperationStatus.AeadError:
      return 'AEAD Error (status: $status).';
    case ffi.OperationStatus.BadFixed32ArrayProvided:
      return 'Bad Fixed32 Array Provided it maybe null? (status: $status)';
    case ffi.OperationStatus.BadSharedBufferProvided:
      return 'Bad SharedBuffer Provided it maybe null? (status: $status)';
    case ffi.OperationStatus.Bip39Error:
      return 'Bip39 Error, maybe bad PaperKey Provided (status: $status)';
    case ffi.OperationStatus.KeyStoreHasNoSeed:
      return 'The Current KeyStore has no seed, and you provided None '
          'Please Provide seed to create a backup paper key (status: $status)';
    case ffi.OperationStatus.KeyStoreNotInialized:
      return 'KeyStore not inialized yet. call one of (create, init, restore)'
          ' methods to Inialize the KeyStore (status: $status)';
    case ffi.OperationStatus.Utf8Error:
      return 'Bad Utf8 String Provided (status: $status)';
    case ffi.OperationStatus.IOError:
      return 'IO Error, perhaps bad file path provided (status: $status)';
    default:
      return 'Unknonw Status Code: $status';
  }
}
