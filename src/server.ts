```typescript
import express from 'express';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/post-quantum/utils.js';

const app = express();
app.use(express.json());

const seed = randomBytes(64);
const { publicKey, secretKey } = ml_kem768.keygen(seed);

app.post('/encrypt', (req, res) => {
  const { message } = req.body as { message: string };
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const encrypted = aes.encrypt(Buffer.from(message));
  res.json({ ciphertext: cipherText.toString('base64'), nonce: nonce.toString('base64'), tag: aes.getAuthTag().toString('base64'), iv: aes.getIV().toString('base64') });
});

app.post('/decrypt', (req, res) => {
  const { ciphertext, nonce, tag, iv } = req.body as { ciphertext: string, nonce: string, tag: string, iv: string };
  const sharedSecret = ml_kem768.decapsulate(Buffer.from(ciphertext, 'base64'), secretKey);
  const key = sharedSecret.slice(0, 32);
  const aes = gcm(key, Buffer.from(nonce, 'base64'), Buffer.from(iv, 'base64'), Buffer.from(tag, 'base64'));
  const decrypted = aes.decrypt(Buffer.from(ciphertext, 'base64'));
  res.json({ plaintext: decrypted.toString() });
});

app.post('/sign', (req, res) => {
  const { data } = req.body as { data: string };
  const msg = new TextEncoder().encode(data);
  const sigKeys = ml_dsa65.keygen();
  const signature = ml_dsa65.sign(msg, sigKeys.secretKey);
  const isValid = ml_dsa65.verify(signature, msg, sigKeys.publicKey);
  res.json({ signature: signature.toString('base64'), verified: isValid });
});

app.listen(3001, () => {
  console.log('Vulnerable Enterprise API running on :3001');
});
```