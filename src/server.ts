import express from 'express';
import {
  generateRSAKeyPair,
  encryptWithRSA,
  decryptWithRSA,
  signData,
  verifySignature,
} from './crypto-service.js';

const app = express();
app.use(express.json());

const { publicKey, privateKey } = generateRSAKeyPair();

app.post('/encrypt', (req, res) => {
  const { message } = req.body as { message: string };
  const { cipherText, sharedSecret } = encryptWithRSA(publicKey, message);
  res.json({ cipherText: Buffer.from(cipherText).toString('base64'), sharedSecret: Buffer.from(sharedSecret).toString('base64') });
});

app.post('/decrypt', (req, res) => {
  const { cipherText } = req.body as { cipherText: string };
  const decrypted = decryptWithRSA(privateKey, Buffer.from(cipherText, 'base64'));
  res.json({ plaintext: decrypted });
});

app.post('/sign', (req, res) => {
  const { data } = req.body as { data: string };
  const signature = signData(privateKey, data);
  const isValid = verifySignature(publicKey, data, signature);
  res.json({ signature: Buffer.from(signature).toString('base64'), verified: isValid });
});

app.listen(3001, () => {
  console.log('Vulnerable Enterprise API running on :3001');
});