import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MlKemClient,
  PqcSessionHandshake,
  bytesToHex,
  hexToBytes,
  bytesToBase64Url,
  base64UrlToBytes
} from '../dist/index.js';

test('ML-KEM SDK: Serialization Helpers Round-Trip', () => {
  const bytes = new Uint8Array([0, 1, 15, 16, 255, 128, 64]);
  const hex = bytesToHex(bytes);
  assert.equal(hex, '00010f10ff8040');
  const restoredFromHex = hexToBytes(hex);
  assert.deepEqual(restoredFromHex, bytes);

  const b64 = bytesToBase64Url(bytes);
  const restoredFromB64 = base64UrlToBytes(b64);
  assert.deepEqual(restoredFromB64, bytes);

  // Hex with 0x prefix
  const withPrefix = hexToBytes('0x00010f10ff8040');
  assert.deepEqual(withPrefix, bytes);

  // Odd length hex rejection
  assert.throws(() => hexToBytes('abc'), /INVALID_HEX_STRING/);
});

test('ML-KEM SDK: Client Pure ML-KEM Key Exchange', () => {
  const client = new MlKemClient();

  // Alice generates keypair
  const alice = client.createKeyPair('ML-KEM-768');
  assert.equal(typeof alice.encapsulationKeyHex, 'string');
  assert.equal(typeof alice.decapsulationKeyHex, 'string');

  // Bob encapsulates
  const bob = client.encapsulateSecret(alice.encapsulationKeyHex, 'ML-KEM-768');
  assert.equal(typeof bob.ciphertextHex, 'string');
  assert.equal(bob.sharedSecretHex.length, 64); // 32 bytes hex

  // Alice decapsulates
  const aliceDerivedSecret = client.decapsulateSecret(alice.decapsulationKeyHex, bob.ciphertextHex, 'ML-KEM-768');
  assert.equal(aliceDerivedSecret, bob.sharedSecretHex);
});

test('ML-KEM SDK: Client Hybrid Key Exchange (ML-KEM-768 + X25519)', () => {
  const client = new MlKemClient();

  // Alice generates hybrid keypair
  const alice = client.createHybridKeyPair('ML-KEM-768');
  assert.equal(typeof alice.pqcEncapsulationKeyHex, 'string');
  assert.equal(typeof alice.ecdhPublicKeyHex, 'string');

  // Bob encapsulates
  const bob = client.encapsulateHybridSecret({
    pqcEncapsulationKeyHex: alice.pqcEncapsulationKeyHex,
    ecdhPublicKeyHex: alice.ecdhPublicKeyHex
  }, 'ML-KEM-768');

  // Alice decapsulates
  const aliceDerivedCombinedSecret = client.decapsulateHybridSecret({
    pqcDecapsulationKeyHex: alice.pqcDecapsulationKeyHex,
    ecdhPrivateKeyHex: alice.ecdhPrivateKeyHex
  }, {
    pqcCiphertextHex: bob.pqcCiphertextHex,
    ecdhEphemeralPublicKeyHex: bob.ecdhEphemeralPublicKeyHex
  }, 'ML-KEM-768');

  assert.equal(aliceDerivedCombinedSecret, bob.combinedSharedSecretHex);
});

test('ML-KEM SDK: Full Post-Quantum Session Handshake Protocol', () => {
  const client = new MlKemClient();
  const sessionId = 'session-pqc-test-001';

  // Step 1: Alice creates ClientHello
  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');
  const clientHello = PqcSessionHandshake.createClientHello(sessionId, aliceKeyPair);
  assert.equal(clientHello.sessionId, sessionId);

  // Step 2: Bob processes ClientHello and creates ServerHello
  const { serverHello, serverSessionKeyHex } = PqcSessionHandshake.processClientHelloAndCreateServerHello(
    client,
    clientHello
  );
  assert.equal(serverHello.sessionId, sessionId);

  // Step 3: Alice processes ServerHello and confirms
  const { clientConfirmation, clientSessionKeyHex } = PqcSessionHandshake.processServerHelloAndConfirm(
    client,
    {
      pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex,
      ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex
    },
    serverHello,
    'ML-KEM-768'
  );

  // Assert keys match across parties
  assert.equal(clientSessionKeyHex, serverSessionKeyHex);

  // Step 4: Bob verifies client confirmation
  const isEstablished = PqcSessionHandshake.verifyClientConfirmation(
    serverSessionKeyHex,
    sessionId,
    clientConfirmation
  );
  assert.equal(isEstablished, true);
});

test('ML-KEM SDK: Adversarial Negative Control - Tampered Server Handshake Rejection', () => {
  const client = new MlKemClient();
  const sessionId = 'session-pqc-tamper-002';

  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');
  const clientHello = PqcSessionHandshake.createClientHello(sessionId, aliceKeyPair);

  const { serverHello } = PqcSessionHandshake.processClientHelloAndCreateServerHello(
    client,
    clientHello
  );

  // Attacker tampers with server auth tag
  const forgedServerHello = {
    ...serverHello,
    serverAuthTagHex: '0000000000000000000000000000000000000000000000000000000000000000'
  };

  assert.throws(
    () =>
      PqcSessionHandshake.processServerHelloAndConfirm(
        client,
        {
          pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex,
          ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex
        },
        forgedServerHello,
        'ML-KEM-768'
      ),
    /INVALID_SERVER_AUTH_TAG/
  );
});

test('ML-KEM SDK: Adversarial Negative Control - Session ID Replay Mismatch', () => {
  const client = new MlKemClient();
  const sessionId = 'session-legit-003';

  const aliceKeyPair = client.createHybridKeyPair('ML-KEM-768');
  const clientHello = PqcSessionHandshake.createClientHello(sessionId, aliceKeyPair);

  const { serverHello, serverSessionKeyHex } = PqcSessionHandshake.processClientHelloAndCreateServerHello(
    client,
    clientHello
  );

  const { clientConfirmation } = PqcSessionHandshake.processServerHelloAndConfirm(
    client,
    {
      pqcDecapsulationKeyHex: aliceKeyPair.pqcDecapsulationKeyHex,
      ecdhPrivateKeyHex: aliceKeyPair.ecdhPrivateKeyHex
    },
    serverHello,
    'ML-KEM-768'
  );

  // Attacker tries to use confirmation against another session ID
  const isEstablished = PqcSessionHandshake.verifyClientConfirmation(
    serverSessionKeyHex,
    'session-replayed-999',
    clientConfirmation
  );
  assert.equal(isEstablished, false);
});
