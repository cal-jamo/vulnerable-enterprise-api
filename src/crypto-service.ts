import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki' as const, format: 'uint8array' as const },
  privateKeyEncoding: { type: 'pkcs8' as const, format: 'uint8array' as const },
};

export function generateKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, privateKey: secretKey };
}

export function encrypt(publicKey: Uint8Array, plaintext: string) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const key = sharedSecret.slice(0, 32);
  const aes = gcm(key, randomBytes(12));
  const encrypted = aes.encrypt(plaintext);
  return { cipherText, encrypted };
}

export function decrypt(privateKey: Uint8Array, cipherText: Uint8Array, sharedSecret: Uint8Array, encrypted: Uint8Array) {
  const sharedKey = ml_kem768.decapsulate(cipherText, privateKey);
  if (sharedKey.toString() !== sharedSecret.toString()) {
    throw new Error('Invalid shared secret');
  } else {
    const key = sharedKey.slice(0, 32);
    const aes = gcm(key, randomBytes(12));
    return aes.decrypt(encrypted);
  }
}

export function sign(privateKey: Uint8Array, data: string) {
  const msg = new TextEncoder().encode(data);
  return ml_dsa65.sign(msg, privateKey);
}

export function verify(publicKey: Uint8Array, data: string, signature: Uint8Array) {
  const msg = new TextEncoder().encode(data);
  return ml_dsa65.verify(signature, msg, publicKey);
}