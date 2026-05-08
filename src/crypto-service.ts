import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki' as const, format: 'der' as const },
  privateKeyEncoding: { type: 'pkcs8' as const, format: 'der' as const },
};

export function generateKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

export function encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array, sharedSecret: Uint8Array } {
  return ml_kem768.encapsulate(publicKey);
}

export function decapsulate(secretKey: Uint8Array, cipherText: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey);
}

export function encryptWithAES(sharedSecret: Uint8Array, plaintext: string): Uint8Array {
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  return aes.encrypt(plaintext);
}

export function decryptWithAES(sharedSecret: Uint8Array, encrypted: Uint8Array): string {
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  return aes.decrypt(encrypted);
}

export function generateDSASigningKeyPair() {
  return ml_dsa65.keygen();
}

export function sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(msg, secretKey);
}

export function verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean {
  return ml_dsa65.verify(sig, msg, publicKey);
}