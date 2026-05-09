import express from 'express';
import {
  generateKeyPair,
  encapsulate,
  decapsulate,
  sign,
  verify,
} from './crypto-service.js';

const app = express();
app.use(express.json());

const { publicKey, secretKey } = generateKeyPair();

app.post('/encrypt', (req, res) => {
  const { message } = req.body as { message: string };
  const plaintext = new TextEncoder().encode(message);
  const { cipherText, encrypted } = encapsulate(publicKey, plaintext);
  res.json({ ciphertext: cipherText.toString('base64'), encrypted: encrypted.toString('base64') });
});

app.post('/decrypt', (req, res) => {
  const { cipherText, encrypted } = req.body as { cipherText: string, encrypted: string };
  const sharedSecret = decapsulate(Buffer.from(cipherText, 'base64'), secretKey);
  const key = sharedSecret.slice(0, 32);
  const nonce = Buffer.from(encrypted, 'base64').slice(0, 12);
  const ciphertext = Buffer.from(encrypted, 'base64').slice(12);
  const aes = gcm(key, nonce);
  const decrypted = aes.decrypt(ciphertext);
  res.json({ plaintext: new TextDecoder().decode(decrypted) });
});

app.post('/sign', (req, res) => {
  const { data } = req.body as { data: string };
  const signature = sign(data);
  res.json({ signature: signature.toString('base64') });
});

app.post('/verify', (req, res) => {
  const { signature, data } = req.body as { signature: string, data: string };
  const isValid = verify(Buffer.from(signature, 'base64'), data, publicKey);
  res.json({ verified: isValid });
});

app.listen(3001, () => {
  console.log('Vulnerable Enterprise API running on :3001');
});