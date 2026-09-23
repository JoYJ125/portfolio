import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server';

const app = express();
const port = Number(process.env.PORT || 3000);
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || `http://${rpID}:${port}`;
const rpName = '조유정 포트폴리오';
const credentialFile = path.join(process.cwd(), 'passkeys.json');

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static('.'));

let currentChallenge = null;
let credentials = loadCredentials();

function loadCredentials() {
  try {
    return JSON.parse(fs.readFileSync(credentialFile, 'utf8')).map((credential) => ({
      ...credential,
      publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64'))
    }));
  } catch {
    return [];
  }
}

function saveCredentials() {
  fs.writeFileSync(credentialFile, JSON.stringify(credentials.map((credential) => ({
    ...credential,
    publicKey: Buffer.from(credential.publicKey).toString('base64')
  })), null, 2));
}

app.get('/api/passkey/register-options', async (req, res) => {
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: 'portfolio-owner',
    userDisplayName: '포트폴리오 사용자',
    attestationType: 'none',
    excludeCredentials: credentials.map((credential) => ({
      id: credential.id,
      transports: credential.transports
    })),
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      userVerification: 'preferred'
    }
  });

  currentChallenge = options.challenge;
  res.json(options);
});

app.post('/api/passkey/register-verify', async (req, res) => {
  if (!currentChallenge) {
    return res.status(400).json({ success: false, message: '등록 요청이 만료되었습니다.' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });

    currentChallenge = null;

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ success: false, message: '패스키 등록 검증에 실패했습니다.' });
    }

    const { credential } = verification.registrationInfo;
    credentials.push({
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: req.body.response?.transports || []
    });
    saveCredentials();

    res.json({ success: true });
  } catch (error) {
    currentChallenge = null;
    console.error('Passkey registration verification failed:', error);
    res.status(400).json({ success: false, message: error.message });
  }
});

app.get('/api/passkey/login-options', async (req, res) => {
  if (credentials.length === 0) {
    return res.status(400).json({ success: false, message: '먼저 패스키를 등록해주세요.' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: credentials.map((credential) => ({
      id: credential.id,
      transports: credential.transports
    })),
    userVerification: 'preferred'
  });

  currentChallenge = options.challenge;
  res.json(options);
});

app.post('/api/passkey/login-verify', async (req, res) => {
  if (!currentChallenge) {
    return res.status(400).json({ success: false, message: '인증 요청이 만료되었습니다.' });
  }

  const storedCredential = credentials.find((credential) => credential.id === req.body.id);
  if (!storedCredential) {
    currentChallenge = null;
    return res.status(401).json({ success: false, message: '등록되지 않은 패스키입니다.' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: storedCredential
    });

    currentChallenge = null;

    if (!verification.verified) {
      return res.status(401).json({ success: false, message: '패스키 인증에 실패했습니다.' });
    }

    storedCredential.counter = verification.authenticationInfo.newCounter;
    saveCredentials();
    res.json({ success: true });
  } catch (error) {
    currentChallenge = null;
    console.error('Passkey authentication verification failed:', error);
    res.status(401).json({ success: false, message: error.message });
  }
});

app.delete('/api/passkey/delete', (req, res) => {
  if (credentials.length < 2) {
    return res.status(400).json({ message: '예비 패스키를 남겨두려면 패스키를 2개 이상 등록해야 합니다.' });
  }

  credentials.shift();
  saveCredentials();
  res.json({ message: '첫 번째 패스키를 삭제했습니다.' });
});

app.listen(port, () => {
  console.log(`Portfolio server: ${origin}`);
});
