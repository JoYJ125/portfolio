# Portfolio submission information

## URLs

- 결과물 URL: https://joyj125.github.io/portfolio/
- 소스 URL: https://github.com/JoYJ125/portfolio

Both URLs use HTTPS and are public. The result page opens directly on the public introduction page without account creation, login, invitation, password, OAuth, or CAPTCHA. The public introduction content remains visible to everyone.

## Public and private content

The page is built by extending the existing introduction page. The public profile, skills, projects, and interests remain available without authentication. The private section is visually separated by a dashed boundary and contains generated placeholder content only; it does not contain real personal information.

Private content is not included in the unauthenticated HTML response. The local WebAuthn server returns it only after passkey verification and a short-lived session-token check. An unauthenticated request to `/api/private-content` receives HTTP 401.

## Account isolation status

The current implementation stores multiple passkeys for one portfolio owner. It does not yet implement two independent accounts with separate passkey namespaces and separate private-content records. Therefore T08-C36 through T08-C41 require a separately deployed account-aware backend before they can be honestly marked complete.

No cross-account success or rejection records are fabricated in this submission. The required next implementation is:

1. Give each account its own stable WebAuthn user ID and credential namespace.
2. Bind each session token to its account ID.
3. Return private content only for the account bound to the verified credential.
4. Record both cross-account access attempts as HTTP 401/403 while showing unchanged private-content counts.

## Hosting note

GitHub Pages provides the HTTPS public result URL but does not execute `server.js`. The WebAuthn API currently runs locally at `http://localhost:3000`; an HTTPS backend deployment is required for passkey interaction on the public result URL.
