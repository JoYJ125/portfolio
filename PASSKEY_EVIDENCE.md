# Passkey evidence for T08-C19 to T08-C26

## Registration flow

1. `GET /api/passkey/register-options` calls `generateRegistrationOptions()` on the server.
2. The server stores the generated `challenge` in `currentChallenge` until verification or cancellation.
3. The browser calls `navigator.credentials.create({ publicKey: options })`.
4. The browser sends `clientDataJSON` and `attestationObject` to `/api/passkey/register-verify`.
5. The server verifies the challenge and stores only the credential ID, public key, counter, and transports in `passkeys.json`.

The registration options include the human-readable identity `userDisplayName: "포트폴리오 사용자"` and `userName: "portfolio-owner"`.

## Requirement evidence

- **T08-C19**: `server.js` creates a new registration challenge and holds it in `currentChallenge` until verification or cancellation.
- **T08-C20**: Every registration-options request calls the random challenge generator again. The server logs each issued value as `[Passkey] registration challenge issued: ...`; two consecutive requests produced prefixes `YTt7Adr0` and `Sk-lEraO`, so the values differed.
- **T08-C21**: After successful verification, the server writes the credential to `passkeys.json` and logs `[Passkey] public key saved for credential: ...`.
- **T08-C22**: The stored `publicKey` field is a WebAuthn public key. It is not a password and is not a private key. The private key is never written to `passkeys.json`.
- **T08-C23**: The registration request body contains `clientDataJSON` and `attestationObject`. It contains no private-key field. The private key is created and retained by the authenticator.
- **T08-C24**: The registration identity is named `포트폴리오 사용자` in the WebAuthn options.
- **T08-C25**: If registration is cancelled or fails, the browser calls `/api/passkey/register-cancel`; the server clears `currentChallenge`. No credential is appended or saved. The page logs the cancellation or failure reason.
- **T08-C26**: This project requests `authenticatorAttachment: "platform"`, so the intended storage is the computer's built-in authenticator, such as Windows Hello. It does not request a USB security key or Google Password Manager. The operating system owns the private-key storage.

## Security boundary

The public profile remains in `index.html`. Private content is kept in `server.js` and is returned only from `/api/private-content` after a successful passkey verification and short-lived session-token check. An unauthenticated request receives HTTP `401`.

## Login evidence for T08-C27 to T08-C35

- **T08-C27**: `GET /api/passkey/login-options` generates and stores a fresh authentication challenge in `currentChallenge` for every login attempt.
- **T08-C28**: The server logs each authentication challenge. Two consecutive login requests produce different values; challenge values are not included in this document.
- **T08-C29**: `verifyAuthenticationResponse()` checks the signature against the matching credential's stored public key before issuing a session token.
- **T08-C30**:

	| Request | Result |
	| --- | --- |
	| Valid authenticator assertion | `200`, `success: true`, short-lived session token issued |
	| Unknown credential ID or invalid assertion | `401`, access denied |

- **T08-C31**: After a login verification attempt, `currentChallenge` is cleared. Replaying the same request receives `400`, `인증 요청이 만료되었습니다.`
- **T08-C32**: A successful login is represented by a short-lived random session token. The token is sent as `Authorization: Bearer <token>` when loading private content.
- **T08-C33**: `POST /api/passkey/logout` deletes the session token. Reusing the old token against `/api/private-content` then receives `401`, `패스키 인증이 필요합니다.`
- **T08-C34**: Session tokens are intentionally redacted in this document and in browser logs. Only the token prefix may be used in local debugging; the complete value is never submitted.
- **T08-C35**: The page contains no password input or password-based login flow. Authentication uses WebAuthn passkeys only.

## Multiple passkey evidence for T08-C42 to T08-C46

- **T08-C42**: The server stores multiple credential records for the same portfolio owner. The intended test state is two records in `passkeys.json`.
- **T08-C43**: `GET /api/passkey/list` returns each credential's human-readable `name` and `createdAt`. The page renders both fields for every registered passkey.
- **T08-C44**: Each listed passkey has its own delete button. Deleting one record leaves the other credential available for authentication.
- **T08-C45**: The deleted credential ID is removed from the server's `credentials` array and `passkeys.json`; a later assertion using that ID is rejected as an unregistered passkey.
- **T08-C46**: When the last passkey is deleted, the page displays `등록된 패스키가 없습니다. 패스키를 등록해주세요.` and the login-options API returns `400` with `먼저 패스키를 등록해주세요.` until a new passkey is registered.
