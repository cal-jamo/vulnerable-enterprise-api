import express from 'express';
import {
  generateKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
} from './crypto-service.js';

const app = express();
app.use(express.json());

const { publicKey, privateKey } = generateKeyPair();

app.post('/encrypt', (req, res) => {
  const { message } = req.body as { message: string };
  const { cipherText, encrypted } = encrypt(publicKey, message);
  res.json({ cipherText: Array.from(cipherText), encrypted: Array.from(encrypted) });
});

app.post('/decrypt', (req, res) => {
  const { cipherText, encrypted, sharedSecret } = req.body as { cipherText: number[], encrypted: number[], sharedSecret: number[] };
  const decrypted = decrypt(privateKey, new Uint8Array(cipherText), new Uint8Array(sharedSecret), new Uint8Array(encrypted));
  res.json({ plaintext: Array.from(decrypted) });
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