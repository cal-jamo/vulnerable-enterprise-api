import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
};

export function generateRSAKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, privateKey: secretKey };
}

export function encryptWithRSA(publicKey: Uint8Array, plaintext: string): Uint8Array {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const encrypted = aes.encrypt(Buffer.from(plaintext, 'utf-8'));
  return encrypted;
}

export function decryptWithRSA(privateKey: Uint8Array, ciphertext: Uint8Array): string {
  const sharedSecret = ml_kem768.decapsulate(ciphertext, privateKey);
  const key = sharedSecret.slice(0, 32);
  const encryptedData = sharedSecret.slice(32);
  const aes = gcm(key, encryptedData.slice(-12));
  const decrypted = aes.decrypt(encryptedData.slice(0, -12));
  return decrypted.toString('utf-8');
}

export function signData(privateKey: Uint8Array, data: string): Uint8Array {
  const msg = new TextEncoder().encode(data);
  const signature = ml_dsa65.sign(msg, privateKey);
  return signature;
}

export function verifySignature(publicKey: Uint8Array, data: string, signature: Uint8Array): boolean {
  const msg = new TextEncoder().encode(data);
  return ml_dsa65.verify(signature, msg, publicKey);
}