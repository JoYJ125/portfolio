import express from 'express';
import crypto from 'node:crypto';
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static('.'));

let currentChallenge = null;
let credentials = loadCredentials();
const sessions = new Map();
const privateContent = [
  {
    title: '1. 준비 중인 프로젝트 메모',
    items: [
      '인프라 침입 탐지 & Log Parser 대시보드: Flask Webhook을 이용한 실시간 이벤트 수집기 설계',
      '보안 정책 설정 자동화 스크립트: Linux iptables 및 UFW 정책 자동 반영 Python CLI 툴 기획'
    ]
  },
  {
    title: '2. 지원 희망 기업 및 기관 목록',
    items: [
      '보안 전문 기업: SK쉴더스, 안랩, 이글루코퍼레이션 (인프라 보안 / SOC 운영 직무)',
      'IT/금융 인프라 부문: 주요 금융권 및 IT 대기업 보안 엔지니어링 직무',
      '특이사항: 스타트업 환경보다는 체계적인 가이드라인과 인프라 망이 구축된 환경 선호'
    ]
  },
  {
    title: '3. 학습 및 성장에 대한 셀프 회고 메모',
    items: [
      '네트워크/Linux: 이론으로만 접했던 패킷 흐름 및 Webhook 서버를 실제 구축하며 가시화해본 경험이 유효했음.',
      '향후 보완점: 단순 개발 역량에서 더 나아가 네트워크 패킷 분석 및 가상화 환경(Docker/K8s) 보안 설정 깊이 파고들기.'
    ]
  }
];

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
  console.log(`[Passkey] registration challenge issued: ${currentChallenge}`);
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
    console.log(`[Passkey] public key saved for credential: ${credential.id}`);

    res.json({ success: true });
  } catch (error) {
    currentChallenge = null;
    console.error('Passkey registration verification failed:', error);
    res.status(400).json({ success: false, message: error.message });
  }
});

app.post('/api/passkey/register-cancel', (req, res) => {
  currentChallenge = null;
  res.json({ success: true, message: '등록 대기 요청을 취소했습니다.' });
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
  console.log(`[Passkey] authentication challenge issued: ${currentChallenge}`);
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
    console.log(`[Passkey] authentication verified for credential: ${storedCredential.id}`);
    const sessionToken = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionToken, Date.now() + 30 * 60 * 1000);
    res.json({ success: true, sessionToken });
  } catch (error) {
    currentChallenge = null;
    console.error('Passkey authentication verification failed:', error);
    res.status(401).json({ success: false, message: error.message });
  }
});

app.post('/api/passkey/logout', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (token) sessions.delete(token);
  res.json({ success: true, message: '로그아웃했습니다.' });
});

app.get('/api/private-content', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const expiresAt = token ? sessions.get(token) : null;

  if (!expiresAt || expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ success: false, message: '패스키 인증이 필요합니다.' });
  }

  res.json({ success: true, content: privateContent });
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
