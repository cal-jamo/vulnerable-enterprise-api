import express from 'express';
import {
  generateKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
} from './crypto-service.ts';

const app = express();
app.use(express.json());

const { publicKey, privateKey } = generateKeyPair();

app.post('/encrypt', (req, res) => {
  const { message } = req.body as { message: string };
  const { cipherText, nonce, tag } = encrypt(publicKey, message);
  res.json({ cipherText: Array.from(cipherText), nonce: Array.from(nonce), tag: Array.from(tag) });
});

app.post('/decrypt', (req, res) => {
  const { cipherText, nonce, tag } = req.body as { cipherText: number[], nonce: number[], tag: number[] };
  const decrypted = decrypt(privateKey, { cipherText: new Uint8Array(cipherText), nonce: new Uint8Array(nonce), tag: new Uint8Array(tag) });
  res.json({ plaintext: decrypted });
});

app.post('/sign', (req, res) => {
  const { data } = req.body as { data: string };
  const signature = sign(privateKey, data);
  const isValid = verify(publicKey, data, signature);
  res.json({ signature: Array.from(signature), verified: isValid });
});

app.listen(3001, () => {
  console.log('Vulnerable Enterprise API running on :3001');
});