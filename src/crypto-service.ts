import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki' as const, format: 'der' as const },
  privateKeyEncoding: { type: 'pkcs8' as const, format: 'der' as const },
};

export function generateRSAKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

export function encryptWithRSA(publicKey: Uint8Array, plaintext: Uint8Array): { cipherText: Uint8Array, sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { cipherText, sharedSecret };
}

export function decryptWithRSA(secretKey: Uint8Array, cipherText: Uint8Array): Uint8Array {
  const sharedSecret = ml_kem768.decapsulate(cipherText, secretKey);
  return sharedSecret;
}

export function signData(secretKey: Uint8Array, data: string): Uint8Array {
  const msg = new TextEncoder().encode(data);
  const signature = ml_dsa65.sign(msg, secretKey);
  return signature;
}

export function verifySignature(publicKey: Uint8Array, data: string, signature: Uint8Array): boolean {
  const msg = new TextEncoder().encode(data);
  const isValid = ml_dsa65.verify(signature, msg, publicKey);
  return isValid;
}