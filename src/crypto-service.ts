import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki' as const, format: 'pem' as const },
  privateKeyEncoding: { type: 'pkcs8' as const, format: 'pem' as const },
};

export function generateKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, privateKey: secretKey };
}

export function encrypt(publicKey: Uint8Array, plaintext: Uint8Array): { cipherText: Uint8Array, sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { cipherText, sharedSecret };
}

export function decrypt(privateKey: Uint8Array, cipherText: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(cipherText, privateKey);
}

export function sign(msg: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(msg, privateKey);
}

export function verify(signature: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean {
  return ml_dsa65.verify(signature, msg, publicKey);
}

export function encryptWithAES_GCM(sharedSecret: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  return aes.encrypt(plaintext);
}

export function decryptWithAES_GCM(sharedSecret: Uint8Array, encrypted: Uint8Array): Uint8Array {
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  return aes.decrypt(encrypted);
}