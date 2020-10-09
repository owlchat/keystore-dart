import 'dart:typed_data';

import 'package:owlchat_keystore/owlchat_keystore.dart';
import 'package:test/test.dart';

void main() {
  group('Create KeyStore', () {
    final keyStore = OwlchatKeyStore();
    test('it should create new KeyStore', () {
      final keys = keyStore.create();
      expect(keys, isNotNull);
    });
    tearDownAll(keyStore.dispose);
  });

  group('Encrypt/Decrypt', () {
    final keyStore = OwlchatKeyStore();
    final input = Uint8List.fromList(
      List.of(
        'Owlchat'.codeUnits,
        growable: false,
      ),
    );
    Uint8List output;
    test('it should create new KeyStore', () {
      final keys = keyStore.create();
      expect(keys, isNotNull);
    });

    test('it should encrypt data', () {
      output = keyStore.encrypt(input);
      expect(output, isNotEmpty);
    });

    test('it should encrypt small data', () {
      final out = keyStore.encrypt(Uint8List.fromList([10, 11, 12]));
      expect(out, isNotEmpty);
    });

    test('it should decrypt data and should be same as input', () {
      output = keyStore.decrypt(output);
      expect(output, isNotEmpty);
      expect(output, input);
    });

    tearDownAll(keyStore.dispose);
  });

  group('Init KeyStore', () {
    final keyStore = OwlchatKeyStore();
    final input = Uint8List.fromList(
      List.of(
        'Owlchat'.codeUnits,
        growable: false,
      ),
    );
    SecretKey secretKey;
    Uint8List output;

    test('it should create new KeyStore', () {
      final keys = keyStore.create();
      secretKey = keys.secretKey;
      expect(keys, isNotNull);
    });

    test('it should encrypt data using current keystore', () {
      output = keyStore.encrypt(input);
      keyStore.clean(); // clear keystore.
      expect(output, isNotEmpty);
    });

    test('it should init keystore and decrypt data', () {
      final keys = keyStore.init(secretKey);
      expect(keys, isNotNull);
      expect(keys.secretKey, secretKey);

      output = keyStore.decrypt(output);
      expect(output, isNotEmpty);
      expect(output, input);
    });

    tearDownAll(keyStore.dispose);
  });

  group('Diffie–Hellman', () {
    final aliceKeystore = OwlchatKeyStore();
    final bobKeystore = OwlchatKeyStore();

    test('it should create same shared secret', () {
      final aliceKeys = aliceKeystore.create();
      final bobKeys = bobKeystore.create();

      final aliceSharedSecret = aliceKeystore.diffieHellman(bobKeys.publicKey);
      final bobSharedSecret = bobKeystore.diffieHellman(aliceKeys.publicKey);

      expect(aliceSharedSecret.asBase64(), bobSharedSecret.asBase64());
    });

    test('it should be able to exchange messages', () {
      final aliceKeys = aliceKeystore.create();
      final bobKeys = bobKeystore.create();

      final aliceSharedSecret = aliceKeystore.diffieHellman(bobKeys.publicKey);
      final bobSharedSecret = bobKeystore.diffieHellman(aliceKeys.publicKey);

      final aliceToBob = aliceKeystore.encrypt(
        Uint8List.fromList('Hello Bob!'.codeUnits),
        sharedSecret: aliceSharedSecret,
      );
      var msg = bobKeystore.decrypt(aliceToBob, sharedSecret: bobSharedSecret);
      expect(Uint8List.fromList('Hello Bob!'.codeUnits), msg);

      final bobToAlice = bobKeystore.encrypt(
        Uint8List.fromList('Hey Alice!'.codeUnits),
        sharedSecret: bobSharedSecret,
      );
      msg = aliceKeystore.decrypt(
        bobToAlice,
        sharedSecret: aliceSharedSecret,
      );
      expect(Uint8List.fromList('Hey Alice!'.codeUnits), msg);
    });
    tearDownAll(() {
      aliceKeystore.dispose();
      bobKeystore.dispose();
    });
  });

  group('Backup/Restore', () {
    final keyStore = OwlchatKeyStore();
    final input = Uint8List.fromList(
      List.of(
        'Owlchat'.codeUnits,
        growable: false,
      ),
    );
    String paperKey;
    Uint8List output;
    test('it should create new KeyStore', () {
      final keys = keyStore.create();
      paperKey = keyStore.backup();
      expect(keys, isNotNull);
      expect(paperKey, isNotEmpty);
    });

    test('it should encrypt data using current keystore', () {
      output = keyStore.encrypt(input);
      keyStore.clean(); // clean keystore.
      expect(output, isNotEmpty);
    });

    test('it should restore keystore using paperKey and decrypt data', () {
      final keys = keyStore.restore(paperKey);
      expect(keys, isNotNull);
      expect(keys.seed, isNotNull);

      output = keyStore.decrypt(output);
      expect(output, isNotEmpty);
      expect(output, input);
    });

    tearDownAll(keyStore.dispose);
  });
}
