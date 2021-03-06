// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
import 'dart:ffi' as ffi;

/// Owlchat KeyStore Binding
class RawKeyStore {
  /// Holds the Dynamic library.
  final ffi.DynamicLibrary _dylib;

  /// The symbols are looked up in [dynamicLibrary].
  RawKeyStore(ffi.DynamicLibrary dynamicLibrary) : _dylib = dynamicLibrary;

  /// Create a [`Mnemonic`] Backup from the provided seed (or the keystore seed if exist).
  ///
  /// the caller should call [`keystore_string_free`] after being done with it.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  /// - if `seed` is empty, it will try to use the `KeyStore` seed if available.
  ///
  /// otherwise it will return null.
  ffi.Pointer<ffi.Int8> keystore_backup(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<Fixed32Array> seed,
  ) {
    return (_keystore_backup ??=
        _dylib.lookupFunction<_c_keystore_backup, _dart_keystore_backup>(
            'keystore_backup'))(
      ks,
      seed,
    );
  }

  _dart_keystore_backup? _keystore_backup;

  /// Calculate the signature of the message using the given `KeyStore`.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  /// - `message` is not null pointer and valid bytes buffer.
  int keystore_calculate_signature(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<SharedBuffer> message,
    ffi.Pointer<Fixed64Array> out,
  ) {
    return (_keystore_calculate_signature ??= _dylib.lookupFunction<
        _c_keystore_calculate_signature,
        _dart_keystore_calculate_signature>('keystore_calculate_signature'))(
      ks,
      message,
      out,
    );
  }

  _dart_keystore_calculate_signature? _keystore_calculate_signature;

  /// Decrypt the Given data using `KeyStore` owned `SecretKey`
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  /// - if `shared_secret` is null, it will use the `KeyStore` secret key.
  int keystore_decrypt(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<SharedBuffer> data,
    ffi.Pointer<Fixed32Array> shared_secret,
  ) {
    return (_keystore_decrypt ??=
        _dylib.lookupFunction<_c_keystore_decrypt, _dart_keystore_decrypt>(
            'keystore_decrypt'))(
      ks,
      data,
      shared_secret,
    );
  }

  _dart_keystore_decrypt? _keystore_decrypt;

  /// Perform a Diffie-Hellman key agreement to produce a `SharedSecret`.
  ///
  /// see [`KeyStore::dh`] for full docs.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  int keystore_dh(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<Fixed32Array> their_public,
    ffi.Pointer<Fixed32Array> out,
  ) {
    return (_keystore_dh ??= _dylib
        .lookupFunction<_c_keystore_dh, _dart_keystore_dh>('keystore_dh'))(
      ks,
      their_public,
      out,
    );
  }

  _dart_keystore_dh? _keystore_dh;

  /// Encrypt the Given data using `KeyStore` owned `SecretKey`
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  /// - if `shared_secret` is null, it will use the `KeyStore` secret key.
  int keystore_encrypt(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<SharedBuffer> data,
    ffi.Pointer<Fixed32Array> shared_secret,
  ) {
    return (_keystore_encrypt ??=
        _dylib.lookupFunction<_c_keystore_encrypt, _dart_keystore_encrypt>(
            'keystore_encrypt'))(
      ks,
      data,
      shared_secret,
    );
  }

  _dart_keystore_encrypt? _keystore_encrypt;

  /// Free (Drop) the created KeyStore.
  /// ### Safety
  /// this assumes that the given pointer is not null.
  void keystore_free(
    ffi.Pointer<ffi.Void> ks,
  ) {
    return (_keystore_free ??=
        _dylib.lookupFunction<_c_keystore_free, _dart_keystore_free>(
            'keystore_free'))(
      ks,
    );
  }

  _dart_keystore_free? _keystore_free;

  /// Init the `KeyStore` with existing SecretKey Bytes.
  ///
  /// See [`KeyStore::init`] for full docs.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `secret_key` is not null
  /// otherwise it will return null.
  ffi.Pointer<ffi.Void> keystore_init(
    ffi.Pointer<Fixed32Array> secret_key,
  ) {
    return (_keystore_init ??=
        _dylib.lookupFunction<_c_keystore_init, _dart_keystore_init>(
            'keystore_init'))(
      secret_key,
    );
  }

  _dart_keystore_init? _keystore_init;

  /// Create a new [`KeyStore`].
  ///
  /// See [`KeyStore::new`] for full docs.
  ffi.Pointer<ffi.Void> keystore_new() {
    return (_keystore_new ??= _dylib
        .lookupFunction<_c_keystore_new, _dart_keystore_new>('keystore_new'))();
  }

  _dart_keystore_new? _keystore_new;

  /// Get the KeyStore Public Key as `Fixed32Array`.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  int keystore_public_key(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<Fixed32Array> out,
  ) {
    return (_keystore_public_key ??= _dylib.lookupFunction<
        _c_keystore_public_key,
        _dart_keystore_public_key>('keystore_public_key'))(
      ks,
      out,
    );
  }

  _dart_keystore_public_key? _keystore_public_key;

  /// Restore a `KeyStore` from a [`Mnemonic`] Paper Backup.
  ///
  /// see [`KeyStore::restore`] for full docs.
  /// ### Safety
  /// this function assumes that:
  /// - `paper_key` is not null and a valid c string.
  ffi.Pointer<ffi.Void> keystore_restore(
    ffi.Pointer<ffi.Int8> paper_key,
  ) {
    return (_keystore_restore ??=
        _dylib.lookupFunction<_c_keystore_restore, _dart_keystore_restore>(
            'keystore_restore'))(
      paper_key,
    );
  }

  _dart_keystore_restore? _keystore_restore;

  /// Get the KeyStore Secret Key as `Fixed32Array`.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  int keystore_secret_key(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<Fixed32Array> out,
  ) {
    return (_keystore_secret_key ??= _dylib.lookupFunction<
        _c_keystore_secret_key,
        _dart_keystore_secret_key>('keystore_secret_key'))(
      ks,
      out,
    );
  }

  _dart_keystore_secret_key? _keystore_secret_key;

  /// Get the KeyStore Seed as `Fixed32Array`.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `ks` is not null pointer to the `KeyStore`.
  int keystore_seed(
    ffi.Pointer<ffi.Void> ks,
    ffi.Pointer<Fixed32Array> out,
  ) {
    return (_keystore_seed ??=
        _dylib.lookupFunction<_c_keystore_seed, _dart_keystore_seed>(
            'keystore_seed'))(
      ks,
      out,
    );
  }

  _dart_keystore_seed? _keystore_seed;

  /// Calculate SHA256 Hash of the provided file path.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `file_path` is not null pointer.
  /// - `out` is not null pointer.
  int keystore_sha256_hash(
    ffi.Pointer<ffi.Int8> file_path,
    ffi.Pointer<Fixed32Array> out,
  ) {
    return (_keystore_sha256_hash ??= _dylib.lookupFunction<
        _c_keystore_sha256_hash,
        _dart_keystore_sha256_hash>('keystore_sha256_hash'))(
      file_path,
      out,
    );
  }

  _dart_keystore_sha256_hash? _keystore_sha256_hash;

  /// Free (Drop) a string value allocated by Rust.
  /// ### Safety
  /// this assumes that the given pointer is not null.
  void keystore_string_free(
    ffi.Pointer<ffi.Int8> ptr,
  ) {
    return (_keystore_string_free ??= _dylib.lookupFunction<
        _c_keystore_string_free,
        _dart_keystore_string_free>('keystore_string_free'))(
      ptr,
    );
  }

  _dart_keystore_string_free? _keystore_string_free;

  /// Verifies the signature of the message using the given `PublicKey`.
  ///
  /// ### Safety
  /// this function assumes that:
  /// - `thier_public` is not null pointer to the fixed size 32 bytes array.
  /// - `message` is not null pointer and valid bytes buffer.
  /// - `signature` is not null pointer to the fixed size 64 bytes array.
  int keystore_verify_signature(
    ffi.Pointer<Fixed32Array> thier_public,
    ffi.Pointer<SharedBuffer> message,
    ffi.Pointer<Fixed64Array> signature,
  ) {
    return (_keystore_verify_signature ??= _dylib.lookupFunction<
        _c_keystore_verify_signature,
        _dart_keystore_verify_signature>('keystore_verify_signature'))(
      thier_public,
      message,
      signature,
    );
  }

  _dart_keystore_verify_signature? _keystore_verify_signature;
}

abstract class OperationStatus {
  static const int Ok = 0;
  static const int Unknwon = 1;
  static const int KeyStoreNotInialized = 2;
  static const int BadFixed32ArrayProvided = 3;
  static const int BadFixed64ArrayProvided = 4;
  static const int BadSharedBufferProvided = 5;
  static const int KeyStoreHasNoSeed = 6;
  static const int AeadError = 7;
  static const int Bip39Error = 8;
  static const int Utf8Error = 9;
  static const int IoError = 10;
  static const int InvalidSignature = 11;
}

class Fixed32Array extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> buf;
}

class SharedBuffer extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> buf;

  @ffi.Uint64()
  external int len;

  @ffi.Uint64()
  external int cap;
}

class Fixed64Array extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> buf;
}

typedef _c_keystore_backup = ffi.Pointer<ffi.Int8> Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> seed,
);

typedef _dart_keystore_backup = ffi.Pointer<ffi.Int8> Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> seed,
);

typedef _c_keystore_calculate_signature = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<SharedBuffer> message,
  ffi.Pointer<Fixed64Array> out,
);

typedef _dart_keystore_calculate_signature = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<SharedBuffer> message,
  ffi.Pointer<Fixed64Array> out,
);

typedef _c_keystore_decrypt = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<SharedBuffer> data,
  ffi.Pointer<Fixed32Array> shared_secret,
);

typedef _dart_keystore_decrypt = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<SharedBuffer> data,
  ffi.Pointer<Fixed32Array> shared_secret,
);

typedef _c_keystore_dh = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> their_public,
  ffi.Pointer<Fixed32Array> out,
);

typedef _dart_keystore_dh = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> their_public,
  ffi.Pointer<Fixed32Array> out,
);

typedef _c_keystore_encrypt = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<SharedBuffer> data,
  ffi.Pointer<Fixed32Array> shared_secret,
);

typedef _dart_keystore_encrypt = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<SharedBuffer> data,
  ffi.Pointer<Fixed32Array> shared_secret,
);

typedef _c_keystore_free = ffi.Void Function(
  ffi.Pointer<ffi.Void> ks,
);

typedef _dart_keystore_free = void Function(
  ffi.Pointer<ffi.Void> ks,
);

typedef _c_keystore_init = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<Fixed32Array> secret_key,
);

typedef _dart_keystore_init = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<Fixed32Array> secret_key,
);

typedef _c_keystore_new = ffi.Pointer<ffi.Void> Function();

typedef _dart_keystore_new = ffi.Pointer<ffi.Void> Function();

typedef _c_keystore_public_key = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> out,
);

typedef _dart_keystore_public_key = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> out,
);

typedef _c_keystore_restore = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Int8> paper_key,
);

typedef _dart_keystore_restore = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Int8> paper_key,
);

typedef _c_keystore_secret_key = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> out,
);

typedef _dart_keystore_secret_key = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> out,
);

typedef _c_keystore_seed = ffi.Int32 Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> out,
);

typedef _dart_keystore_seed = int Function(
  ffi.Pointer<ffi.Void> ks,
  ffi.Pointer<Fixed32Array> out,
);

typedef _c_keystore_sha256_hash = ffi.Int32 Function(
  ffi.Pointer<ffi.Int8> file_path,
  ffi.Pointer<Fixed32Array> out,
);

typedef _dart_keystore_sha256_hash = int Function(
  ffi.Pointer<ffi.Int8> file_path,
  ffi.Pointer<Fixed32Array> out,
);

typedef _c_keystore_string_free = ffi.Void Function(
  ffi.Pointer<ffi.Int8> ptr,
);

typedef _dart_keystore_string_free = void Function(
  ffi.Pointer<ffi.Int8> ptr,
);

typedef _c_keystore_verify_signature = ffi.Int32 Function(
  ffi.Pointer<Fixed32Array> thier_public,
  ffi.Pointer<SharedBuffer> message,
  ffi.Pointer<Fixed64Array> signature,
);

typedef _dart_keystore_verify_signature = int Function(
  ffi.Pointer<Fixed32Array> thier_public,
  ffi.Pointer<SharedBuffer> message,
  ffi.Pointer<Fixed64Array> signature,
);
