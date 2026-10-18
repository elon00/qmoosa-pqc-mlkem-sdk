import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  getMlKemParameters,
  constantTimeEqual,
  type MlKemParameterName,
  type MlKemParameters,
  type MlKemKeyPair,
  type MlKemEncapsulationResult,
  type HybridKemKeyPair,
  type HybridKemEncapsulationResult
} from '@qmoosa/pqc-mlkem-protocol';
import {
  MlKemEngine,
  deriveHybridSharedSecret
} from '@qmoosa/pqc-mlkem-engine';

export * from '@qmoosa/pqc-mlkem-protocol';
export * from '@qmoosa/pqc-mlkem-engine';

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('INVALID_HEX_STRING: Length must be even');
  }
  return new Uint8Array(Buffer.from(clean, 'hex'));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64UrlToBytes(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

export interface SerializedKeyPair {
  readonly encapsulationKeyHex: string;
  readonly decapsulationKeyHex: string;
  readonly parameterSet: MlKemParameterName;
}

export interface SerializedEncapsulationResult {
  readonly ciphertextHex: string;
  readonly sharedSecretHex: string;
  readonly parameterSet: MlKemParameterName;
}

export interface SerializedHybridKeyPair {
  readonly pqcEncapsulationKeyHex: string;
  readonly pqcDecapsulationKeyHex: string;
  readonly ecdhPublicKeyHex: string;
  readonly ecdhPrivateKeyHex: string;
  readonly parameterSet: MlKemParameterName;
}

export interface SerializedHybridEncapsulationResult {
  readonly pqcCiphertextHex: string;
  readonly ecdhEphemeralPublicKeyHex: string;
  readonly combinedSharedSecretHex: string;
  readonly parameterSet: MlKemParameterName;
}

export class MlKemClient {
  private readonly engine: MlKemEngine;

  constructor(engine?: MlKemEngine) {
    this.engine = engine ?? new MlKemEngine();
  }

  public createKeyPair(paramName: MlKemParameterName = ML_KEM_768.name): SerializedKeyPair {
    const kp = this.engine.generateKeyPair(paramName);
    return Object.freeze({
      encapsulationKeyHex: bytesToHex(kp.encapsulationKey),
      decapsulationKeyHex: bytesToHex(kp.decapsulationKey),
      parameterSet: paramName
    });
  }

  public encapsulateSecret(
    peerPublicKeyHex: string,
    paramName: MlKemParameterName = ML_KEM_768.name
  ): SerializedEncapsulationResult {
    const ek = hexToBytes(peerPublicKeyHex);
    const res = this.engine.encapsulate(ek, paramName);
    return Object.freeze({
      ciphertextHex: bytesToHex(res.ciphertext),
      sharedSecretHex: bytesToHex(res.sharedSecret),
      parameterSet: paramName
    });
  }

  public decapsulateSecret(
    privateKeyHex: string,
    ciphertextHex: string,
    paramName: MlKemParameterName = ML_KEM_768.name
  ): string {
    const dk = hexToBytes(privateKeyHex);
    const c = hexToBytes(ciphertextHex);
    const ss = this.engine.decapsulate(dk, c, paramName);
    return bytesToHex(ss);
  }

  public createHybridKeyPair(paramName: MlKemParameterName = ML_KEM_768.name): SerializedHybridKeyPair {
    const hkp = this.engine.generateHybridKeyPair(paramName);
    return Object.freeze({
      pqcEncapsulationKeyHex: bytesToHex(hkp.pqcKeyPair.encapsulationKey),
      pqcDecapsulationKeyHex: bytesToHex(hkp.pqcKeyPair.decapsulationKey),
      ecdhPublicKeyHex: bytesToHex(hkp.ecdhPublicKey),
      ecdhPrivateKeyHex: bytesToHex(hkp.ecdhPrivateKey),
      parameterSet: paramName
    });
  }

  public encapsulateHybridSecret(
    peerHybridPublicKey: { pqcEncapsulationKeyHex: string; ecdhPublicKeyHex: string },
    paramName: MlKemParameterName = ML_KEM_768.name
  ): SerializedHybridEncapsulationResult {
    const pqcEk = hexToBytes(peerHybridPublicKey.pqcEncapsulationKeyHex);
    const ecdhPublicKey = hexToBytes(peerHybridPublicKey.ecdhPublicKeyHex);

    const res = this.engine.encapsulateHybrid({ pqcEk, ecdhPublicKey }, paramName);
    return Object.freeze({
      pqcCiphertextHex: bytesToHex(res.pqcCiphertext),
      ecdhEphemeralPublicKeyHex: bytesToHex(res.ecdhEphemeralPublicKey),
      combinedSharedSecretHex: bytesToHex(res.combinedSharedSecret),
      parameterSet: paramName
    });
  }

  public decapsulateHybridSecret(
    localHybridPrivateKey: { pqcDecapsulationKeyHex: string; ecdhPrivateKeyHex: string; ecdhPublicKeyHex?: string },
    receivedHybridCiphertext: { pqcCiphertextHex: string; ecdhEphemeralPublicKeyHex: string },
    paramName: MlKemParameterName = ML_KEM_768.name
  ): string {
    const pqcDk = hexToBytes(localHybridPrivateKey.pqcDecapsulationKeyHex);
    const ecdhPrivateKey = hexToBytes(localHybridPrivateKey.ecdhPrivateKeyHex);
    const pqcCiphertext = hexToBytes(receivedHybridCiphertext.pqcCiphertextHex);
    const ecdhEphemeralPublicKey = hexToBytes(receivedHybridCiphertext.ecdhEphemeralPublicKeyHex);
    const ecdhPublicKey = localHybridPrivateKey.ecdhPublicKeyHex ? hexToBytes(localHybridPrivateKey.ecdhPublicKeyHex) : undefined;

    const ss = this.engine.decapsulateHybrid(
      { pqcDk, ecdhPrivateKey, ecdhPublicKey },
      { pqcCiphertext, ecdhEphemeralPublicKey },
      paramName
    );
    return bytesToHex(ss);
  }
}

/**
 * Post-Quantum Session Handshake
 */
export interface ClientHello {
  readonly sessionId: string;
  readonly parameterSet: MlKemParameterName;
  readonly pqcEncapsulationKeyHex: string;
  readonly ecdhPublicKeyHex: string;
  readonly timestamp: number;
}

export interface ServerHello {
  readonly sessionId: string;
  readonly pqcCiphertextHex: string;
  readonly ecdhEphemeralPublicKeyHex: string;
  readonly serverAuthTagHex: string;
  readonly timestamp: number;
}

export interface ClientConfirmation {
  readonly sessionId: string;
  readonly clientAuthTagHex: string;
  readonly timestamp: number;
}

export class PqcSessionHandshake {
  private static computeAuthTag(sessionKey: Uint8Array, label: string, sessionId: string): string {
    const hmac = createHmac('sha256', Buffer.from(sessionKey));
    hmac.update(`${label}:${sessionId}`);
    return hmac.digest('hex');
  }

  public static createClientHello(
    sessionId: string,
    clientKeyPair: SerializedHybridKeyPair,
    timestamp = Date.now()
  ): ClientHello {
    return Object.freeze({
      sessionId,
      parameterSet: clientKeyPair.parameterSet,
      pqcEncapsulationKeyHex: clientKeyPair.pqcEncapsulationKeyHex,
      ecdhPublicKeyHex: clientKeyPair.ecdhPublicKeyHex,
      timestamp
    });
  }

  public static processClientHelloAndCreateServerHello(
    client: MlKemClient,
    hello: ClientHello,
    timestamp = Date.now()
  ): { serverHello: ServerHello; serverSessionKeyHex: string } {
    const encResult = client.encapsulateHybridSecret({
      pqcEncapsulationKeyHex: hello.pqcEncapsulationKeyHex,
      ecdhPublicKeyHex: hello.ecdhPublicKeyHex
    }, hello.parameterSet);

    const sessionKey = hexToBytes(encResult.combinedSharedSecretHex);
    const serverAuthTag = this.computeAuthTag(sessionKey, 'SERVER-AUTH', hello.sessionId);

    const serverHello: ServerHello = Object.freeze({
      sessionId: hello.sessionId,
      pqcCiphertextHex: encResult.pqcCiphertextHex,
      ecdhEphemeralPublicKeyHex: encResult.ecdhEphemeralPublicKeyHex,
      serverAuthTagHex: serverAuthTag,
      timestamp
    });

    return { serverHello, serverSessionKeyHex: encResult.combinedSharedSecretHex };
  }

  public static processServerHelloAndConfirm(
    client: MlKemClient,
    clientPrivateKey: { pqcDecapsulationKeyHex: string; ecdhPrivateKeyHex: string },
    serverHello: ServerHello,
    paramName: MlKemParameterName = ML_KEM_768.name,
    timestamp = Date.now()
  ): { clientConfirmation: ClientConfirmation; clientSessionKeyHex: string } {
    const derivedKeyHex = client.decapsulateHybridSecret(
      clientPrivateKey,
      {
        pqcCiphertextHex: serverHello.pqcCiphertextHex,
        ecdhEphemeralPublicKeyHex: serverHello.ecdhEphemeralPublicKeyHex
      },
      paramName
    );

    const sessionKey = hexToBytes(derivedKeyHex);
    const expectedServerAuthTag = this.computeAuthTag(sessionKey, 'SERVER-AUTH', serverHello.sessionId);

    if (!constantTimeEqual(hexToBytes(serverHello.serverAuthTagHex), hexToBytes(expectedServerAuthTag))) {
      throw new Error('INVALID_SERVER_AUTH_TAG: Post-quantum session handshake failed authentication');
    }

    const clientAuthTag = this.computeAuthTag(sessionKey, 'CLIENT-AUTH', serverHello.sessionId);
    const clientConfirmation: ClientConfirmation = Object.freeze({
      sessionId: serverHello.sessionId,
      clientAuthTagHex: clientAuthTag,
      timestamp
    });

    return { clientConfirmation, clientSessionKeyHex: derivedKeyHex };
  }

  public static verifyClientConfirmation(
    serverSessionKeyHex: string,
    sessionId: string,
    clientConfirmation: ClientConfirmation
  ): boolean {
    if (clientConfirmation.sessionId !== sessionId) return false;
    const sessionKey = hexToBytes(serverSessionKeyHex);
    const expectedAuth = this.computeAuthTag(sessionKey, 'CLIENT-AUTH', sessionId);
    return constantTimeEqual(hexToBytes(clientConfirmation.clientAuthTagHex), hexToBytes(expectedAuth));
  }
}
