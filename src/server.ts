```typescript
import express from 'express';
import { ml_kem768, ml_dsa65 } from '@noble/post-quantum';
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
  const encrypted = aes.encrypt(message);
  res.json({ ciphertext: Buffer.concat([cipherText, encrypted]).toString('base64') });
});

app.post('/decrypt', (req, res) => {
  const { ciphertext } = req.body as { ciphertext: string };
  const ct = Buffer.from(ciphertext, 'base64');
  const { decrypted, sharedSecret } = ml_kem768.decapsulate(ct.slice(0, 768), secretKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = sharedSecret.slice(32, 44);
  const aes = gcm(key, nonce);
  const plaintext = aes.decrypt(ct.slice(768));
  res.json({ plaintext: plaintext });
});

app.post('/sign', (req, res) => {
  const { data } = req.body as { data: string };
  const sigKeys = ml_dsa65.keygen();
  const msg = new TextEncoder().encode(data);
  const signature = ml_dsa65.sign(msg, sigKeys.secretKey);
  const isValid = ml_dsa65.verify(signature, msg, sigKeys.publicKey);
  res.json({ signature: signature.toString('base64'), verified: isValid });
});

app.listen(3001, () => {
  console.log('Vulnerable Enterprise API running on :3001');
});
```