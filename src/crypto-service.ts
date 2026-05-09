import crypto from 'node:crypto';

const RSA_KEY_OPTIONS = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki' as const, format: 'pem' as const },
  privateKeyEncoding: { type: 'pkcs8' as const, format: 'pem' as const },
};

export function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', RSA_KEY_OPTIONS);
  return { publicKey, privateKey };
}

export function encryptWithRSA(publicKey: string, plaintext: string): Buffer {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(plaintext, 'utf-8'),
  );
}

export function decryptWithRSA(privateKey: string, ciphertext: Buffer): string {
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    ciphertext,
  );
  return decrypted.toString('utf-8');
}

export function signData(privateKey: string, data: string): Buffer {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  signer.end();
  return signer.sign(privateKey);
}

export function verifySignature(publicKey: string, data: string, signature: Buffer): boolean {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(data);
  verifier.end();
  return verifier.verify(publicKey, signature);
}
