import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/post-quantum/utils.js';

const RSA_KEY_OPTIONS = {
  seedLength: 64,
};

export function generatePostQuantumKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

export function encapsulateWithMLKEM(publicKey: Uint8Array) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { cipherText, sharedSecret };
}

export function decapsulateWithMLKEM(cipherText: Uint8Array, secretKey: Uint8Array) {
  return ml_kem768.decapsulate(cipherText, secretKey);
}

export function encryptWithAESCipher(sharedSecret: Uint8Array, plaintext: Buffer) {
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const encrypted = aes.encrypt(plaintext);
  return encrypted;
}

export function decryptWithAESCipher(sharedSecret: Uint8Array, encrypted: Buffer) {
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const decrypted = aes.decrypt(encrypted);
  return decrypted.toString('utf-8');
}

export function generatePostQuantumSignatureKeys() {
  return ml_dsa65.keygen();
}

export function signDataWithMLDSA(privateKey: Uint8Array, data: string) {
  const msg = new TextEncoder().encode(data);
  return ml_dsa65.sign(msg, privateKey);
}

export function verifySignatureWithMLDSA(publicKey: Uint8Array, data: string, signature: Uint8Array) {
  const msg = new TextEncoder().encode(data);
  return ml_dsa65.verify(signature, msg, publicKey);
}