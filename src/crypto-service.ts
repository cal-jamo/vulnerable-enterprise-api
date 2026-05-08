import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  seedLength: 64
};

export function generatePostQuantumKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

export function encryptWithPostQuantum(publicKey: Uint8Array, plaintext: Uint8Array) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const encrypted = aes.encrypt(plaintext);
  return { cipherText, encrypted };
}

export function decryptWithPostQuantum(secretKey: Uint8Array, cipherText: Uint8Array, encrypted: Uint8Array) {
  const sharedSecret = ml_kem768.decapsulate(cipherText, secretKey);
  const key = sharedSecret.slice(0, 32);
  const aes = gcm(key, encrypted.slice(-12));
  const decrypted = aes.decrypt(encrypted);
  return decrypted;
}

export function signData(secretKey: Uint8Array, data: string) {
  const msg = new TextEncoder().encode(data);
  const signature = ml_dsa65.sign(msg, secretKey);
  return signature;
}

export function verifySignature(publicKey: Uint8Array, data: string, signature: Uint8Array) {
  const msg = new TextEncoder().encode(data);
  const isValid = ml_dsa65.verify(signature, msg, publicKey);
  return isValid;
}