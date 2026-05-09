import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
};

export function generateKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

export function encapsulate(publicKey: Uint8Array, plaintext: Uint8Array) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const encrypted = aes.encrypt(plaintext);
  return { cipherText, encrypted };
}

export function decapsulate(cipherText: Uint8Array, secretKey: Uint8Array) {
  const sharedSecret = ml_kem768.decapsulate(cipherText, secretKey);
  return sharedSecret.slice(0, 32);
}

export function sign(data: string) {
  const msg = new TextEncoder().encode(data);
  const sigKeys = ml_dsa65.keygen();
  const sig = ml_dsa65.sign(msg, sigKeys.secretKey);
  return sig;
}

export function verify(signature: Uint8Array, data: string, publicKey: Uint8Array) {
  const msg = new TextEncoder().encode(data);
  const isValid = ml_dsa65.verify(signature, msg, publicKey);
  return isValid;
}