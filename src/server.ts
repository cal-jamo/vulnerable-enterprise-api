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
  res.json({ ciphertext: cipherText.toString('base64'), iv: nonce.toString('base64'), tag: aes.getAuthTag().toString('base64'), encryptedData: encrypted });
});

app.post('/decrypt', (req, res) => {
  const { ciphertext, iv, tag, encryptedData } = req.body as { ciphertext: string, iv: string, tag: string, encryptedData: string };
  const sharedSecret = ml_kem768.decapsulate(Buffer.from(ciphertext, 'base64'), secretKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = Buffer.from(iv, 'base64');
  const aes = gcm(key, nonce);
  const decrypted = aes.decrypt(Buffer.from(encryptedData, 'base64'), Buffer.from(tag, 'base64'));
  res.json({ plaintext: decrypted });
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
  console.log('Secure Post-Quantum API running on :3001');
});