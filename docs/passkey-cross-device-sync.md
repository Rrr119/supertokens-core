# Passkey cross-device sync

This feature adds an append-only device trust chain and one-time passkey sync envelopes beside the existing WebAuthn recipe. It does not replace WebAuthn verification or the Session recipe.

## Device trust chain

Each user has a SHA-256 hash chain stored in user metadata under `passkeySyncV1`.

- The first device writes a `GENESIS` link and signs it with an Ed25519 key.
- A trusted device writes a `DEVICE_ADDED` link and signs the new device's public key, device id, sequence and previous hash.
- A trusted device writes a `DEVICE_REVOKED` link to remove a device.
- Every link contains the previous link hash. `DeviceTrustChain.verify()` replays signatures, sequence numbers, previous hashes and revocations.

## Passkey sync envelopes

`POST /recipe/webauthn/passkey/sync` accepts:

- `action: "CREATE"` with `sourceDeviceId`, `targetDeviceId`, `credentialId`, `encryptedPayload` and optional `ttlMillis`.
- `action: "CLAIM"` with `syncId` and `targetDeviceId`.

Both devices must be trusted. The `credentialId` must already belong to the user's WebAuthn credentials. The server stores only the opaque encrypted payload and its SHA-256 integrity hash; production clients should end-to-end encrypt the passkey material with a key negotiated through the trusted-device channel. A claimed envelope becomes `CONSUMED` and cannot be replayed.

## Trust-chain API

`GET /recipe/webauthn/device/trust-chain?userId=...` returns the chain and its verification result.

`POST /recipe/webauthn/device/trust-chain` accepts `action: "GENESIS" | "ADD" | "REVOKE"` plus the fields required by that action.

## Session compatibility

Cross-device sign-in still completes through the unchanged `/recipe/webauthn/signin` API. After that returns `OK`, callers use the existing Session recipe. `PasskeySyncService.sessionClaims(...)` optionally adds the sync id, source/target device ids and trust-chain head hash to the normal JWT payload.

## Tests

`PasskeyCrossDeviceSyncTest` registers real WebAuthn credentials for `DESKTOP`, `MOBILE` and `TABLET` emulator devices, authorizes a new device through the trust chain, claims a sync envelope, imports the simulated platform-synced credential, performs a real passwordless assertion, and verifies the resulting Session.
