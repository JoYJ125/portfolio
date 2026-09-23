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
