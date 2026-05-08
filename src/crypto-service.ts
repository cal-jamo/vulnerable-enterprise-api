import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/post-quantum/utils.js';

export function generateKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, privateKey: secretKey };
}

export function encrypt(publicKey: Uint8Array, plaintext: string): { cipherText: Uint8Array, sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { cipherText, sharedSecret };
}

export function decrypt(privateKey: Uint8Array, cipherText: Uint8Array): string {
  const sharedSecret = ml_kem768.decapsulate(cipherText, privateKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const decrypted = aes.decrypt(cipherText);
  return decrypted;
}

export function sign(privateKey: Uint8Array, data: string): Uint8Array {
  const msg = new TextEncoder().encode(data);
  const signature = ml_dsa65.sign(msg, privateKey);
  return signature;
}

export function verify(signature: Uint8Array, data: string, publicKey: Uint8Array): boolean {
  const msg = new TextEncoder().encode(data);
  const isValid = ml_dsa65.verify(signature, msg, publicKey);
  return isValid;
}