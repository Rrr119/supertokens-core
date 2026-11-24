package io.supertokens.passkeysync;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.ResourceDistributor;
import io.supertokens.auditlog.UnauditedTransaction;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.StorageUtils;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.exceptions.StorageTransactionLogicException;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.multitenancy.AppIdentifier;
import io.supertokens.pluginInterface.usermetadata.sqlStorage.UserMetadataSQLStorage;
import io.supertokens.pluginInterface.webauthn.WebAuthNStoredCredential;
import io.supertokens.storageLayer.StorageLayer;
import io.supertokens.usermetadata.UserMetadata;
import io.supertokens.webauthn.WebAuthN;
import org.jetbrains.annotations.TestOnly;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public final class PasskeySyncService {
    public static final String METADATA_KEY = "passkeySyncV1";
    public static final long DEFAULT_ENVELOPE_TTL_MILLIS = 5 * 60 * 1000L;

    private PasskeySyncService() {
    }

    @TestOnly
    public static DeviceTrustChain registerGenesisDevice(Main main, String userId, String deviceId,
                                                         DeviceKind deviceKind, String displayName,
                                                         String publicKey, String signature)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        Storage storage = StorageLayer.getStorage(main);
        AppIdentifier appIdentifier = ResourceDistributor.getAppForTesting().toAppIdentifier();
        return registerGenesisDevice(appIdentifier, storage, userId, deviceId, deviceKind, displayName,
                publicKey, signature);
    }

    public static DeviceTrustChain registerGenesisDevice(AppIdentifier appIdentifier, Storage storage,
                                                         String userId, String deviceId, DeviceKind deviceKind,
                                                         String displayName, String publicKey, String signature)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        validateDeviceInput(userId, deviceId, publicKey, signature);
        return mutateState(appIdentifier, storage, userId, state -> {
            if (!state.chain.links.isEmpty()) {
                throw new PasskeySyncException("DEVICE_TRUST_CHAIN_EXISTS",
                        "Genesis device can only be registered once");
            }
            long now = System.currentTimeMillis();
            TrustLink genesis = TrustLink.create(0, TrustLink.Type.GENESIS, userId, deviceId, null, null,
                    deviceKind, publicKey, displayName, now, DeviceTrustCrypto.GENESIS_PREVIOUS_HASH, signature);
            DeviceTrustChain candidate = new DeviceTrustChain(userId, List.of(genesis));
            assertValidCandidate(candidate);
            state.chain = candidate;
            return candidate;
        });
    }

    @TestOnly
    public static DeviceTrustChain addTrustedDevice(Main main, String userId, String deviceId,
                                                    DeviceKind deviceKind, String displayName, String publicKey,
                                                    String trustedByDeviceId, String endorsementSignature)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        Storage storage = StorageLayer.getStorage(main);
        AppIdentifier appIdentifier = ResourceDistributor.getAppForTesting().toAppIdentifier();
        return addTrustedDevice(appIdentifier, storage, userId, deviceId, deviceKind, displayName, publicKey,
                trustedByDeviceId, endorsementSignature);
    }

    public static DeviceTrustChain addTrustedDevice(AppIdentifier appIdentifier, Storage storage, String userId,
                                                    String deviceId, DeviceKind deviceKind, String displayName,
                                                    String publicKey, String trustedByDeviceId,
                                                    String endorsementSignature)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        validateDeviceInput(userId, deviceId, publicKey, endorsementSignature);
        if (isBlank(trustedByDeviceId)) {
            throw new PasskeySyncException("INVALID_DEVICE_TRUST", "trustedByDeviceId is required");
        }
        return mutateState(appIdentifier, storage, userId, state -> {
            assertExistingChainValid(state.chain);
            if (!state.chain.isTrusted(trustedByDeviceId)) {
                throw new PasskeySyncException("UNTRUSTED_ENDORSER",
                        "Endorsing device is not currently trusted", 403);
            }
            long now = System.currentTimeMillis();
            TrustLink link = TrustLink.create(state.chain.links.size(), TrustLink.Type.DEVICE_ADDED, userId,
                    deviceId, trustedByDeviceId, null, deviceKind, publicKey, displayName, now,
                    state.chain.headHash(), endorsementSignature);
            List<TrustLink> links = new ArrayList<>(state.chain.links);
            links.add(link);
            DeviceTrustChain candidate = new DeviceTrustChain(userId, links);
            assertValidCandidate(candidate);
            state.chain = candidate;
            return candidate;
        });
    }

    @TestOnly
    public static DeviceTrustChain revokeDevice(Main main, String userId, String targetDeviceId,
                                                String revokedByDeviceId, String revocationSignature)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        Storage storage = StorageLayer.getStorage(main);
        AppIdentifier appIdentifier = ResourceDistributor.getAppForTesting().toAppIdentifier();
        return revokeDevice(appIdentifier, storage, userId, targetDeviceId, revokedByDeviceId,
                revocationSignature);
    }

    public static DeviceTrustChain revokeDevice(AppIdentifier appIdentifier, Storage storage, String userId,
                                                String targetDeviceId, String revokedByDeviceId,
                                                String revocationSignature)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        if (isBlank(userId) || isBlank(targetDeviceId) || isBlank(revokedByDeviceId)
                || isBlank(revocationSignature)) {
            throw new PasskeySyncException("INVALID_DEVICE_REVOCATION",
                    "userId, targetDeviceId, revokedByDeviceId and signature are required");
        }
        return mutateState(appIdentifier, storage, userId, state -> {
            assertExistingChainValid(state.chain);
            if (!state.chain.isTrusted(revokedByDeviceId)) {
                throw new PasskeySyncException("UNTRUSTED_REVOKER",
                        "Revoking device is not currently trusted", 403);
            }
            long now = System.currentTimeMillis();
            TrustLink link = TrustLink.create(state.chain.links.size(), TrustLink.Type.DEVICE_REVOKED, userId,
                    revokedByDeviceId, revokedByDeviceId, targetDeviceId, null, null, null, now,
                    state.chain.headHash(), revocationSignature);
            List<TrustLink> links = new ArrayList<>(state.chain.links);
            links.add(link);
            DeviceTrustChain candidate = new DeviceTrustChain(userId, links);
            assertValidCandidate(candidate);
            state.chain = candidate;
            return candidate;
        });
    }

    @TestOnly
    public static DeviceTrustChain getTrustChain(Main main, String userId)
            throws PasskeySyncException, StorageQueryException {
        Storage storage = StorageLayer.getStorage(main);
        AppIdentifier appIdentifier = ResourceDistributor.getAppForTesting().toAppIdentifier();
        return getTrustChain(appIdentifier, storage, userId);
    }

    public static DeviceTrustChain getTrustChain(AppIdentifier appIdentifier, Storage storage, String userId)
            throws PasskeySyncException, StorageQueryException {
        if (isBlank(userId)) {
            throw new PasskeySyncException("INVALID_USER_ID", "userId is required");
        }
        JsonObject metadata = UserMetadata.getUserMetadata(appIdentifier, storage, userId);
        return State.fromMetadata(metadata, userId).chain;
    }

    @TestOnly
    public static PasskeySyncEnvelope createSyncEnvelope(Main main, String userId, String sourceDeviceId,
                                                         String targetDeviceId, String credentialId,
                                                         String encryptedPayload, Long ttlMillis)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        Storage storage = StorageLayer.getStorage(main);
        TenantIdentifier tenantIdentifier = ResourceDistributor.getAppForTesting();
        return createSyncEnvelope(main, tenantIdentifier, storage, userId, sourceDeviceId, targetDeviceId,
                credentialId, encryptedPayload, ttlMillis);
    }

    public static PasskeySyncEnvelope createSyncEnvelope(Main main, TenantIdentifier tenantIdentifier,
                                                         Storage storage,
                                                         String userId, String sourceDeviceId,
                                                         String targetDeviceId, String credentialId,
                                                         String encryptedPayload, Long ttlMillis)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        if (isBlank(userId) || isBlank(sourceDeviceId) || isBlank(targetDeviceId)
                || isBlank(credentialId) || isBlank(encryptedPayload)) {
            throw new PasskeySyncException("INVALID_SYNC_REQUEST", "userId, sourceDeviceId, targetDeviceId, "
                    + "credentialId and encryptedPayload are required");
        }
        List<WebAuthNStoredCredential> credentials = WebAuthN.listCredentialsForUser(main, storage,
                tenantIdentifier, userId);
        boolean credentialExists = credentials.stream().anyMatch(credential -> credentialId.equals(credential.id));
        if (!credentialExists) {
            throw new PasskeySyncException("PASSKEY_CREDENTIAL_NOT_FOUND",
                    "credentialId is not registered for this user", 404);
        }
        long ttl = ttlMillis == null || ttlMillis <= 0 ? DEFAULT_ENVELOPE_TTL_MILLIS : ttlMillis;
        AppIdentifier appIdentifier = tenantIdentifier.toAppIdentifier();
        return mutateState(appIdentifier, storage, userId, state -> {
            DeviceTrustChain.Verification verification = state.chain.verify();
            if (!verification.valid) {
                throw new PasskeySyncException("INVALID_TRUST_CHAIN",
                        String.join("; ", verification.problems), 409);
            }
            if (!verification.trustedDeviceIds.contains(sourceDeviceId)) {
                throw new PasskeySyncException("UNTRUSTED_SOURCE_DEVICE",
                        "Source device is not in the trusted chain", 403);
            }
            if (!verification.trustedDeviceIds.contains(targetDeviceId)) {
                throw new PasskeySyncException("UNTRUSTED_TARGET_DEVICE",
                        "Target device is not in the trusted chain", 403);
            }
            long now = System.currentTimeMillis();
            PasskeySyncEnvelope envelope = new PasskeySyncEnvelope(UUID.randomUUID().toString(), userId,
                    sourceDeviceId, targetDeviceId, credentialId, encryptedPayload,
                    DeviceTrustCrypto.sha256(encryptedPayload), PasskeySyncEnvelope.Status.PENDING, now,
                    now + ttl, null);
            state.envelopes.add(envelope);
            return envelope;
        });
    }

    @TestOnly
    public static PasskeySyncEnvelope claimSyncEnvelope(Main main, String userId, String syncId,
                                                        String targetDeviceId)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        Storage storage = StorageLayer.getStorage(main);
        AppIdentifier appIdentifier = ResourceDistributor.getAppForTesting().toAppIdentifier();
        return claimSyncEnvelope(appIdentifier, storage, userId, syncId, targetDeviceId);
    }

    public static PasskeySyncEnvelope claimSyncEnvelope(AppIdentifier appIdentifier, Storage storage,
                                                        String userId, String syncId, String targetDeviceId)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        if (isBlank(userId) || isBlank(syncId) || isBlank(targetDeviceId)) {
            throw new PasskeySyncException("INVALID_CLAIM_REQUEST",
                    "userId, syncId and targetDeviceId are required");
        }
        return mutateState(appIdentifier, storage, userId, state -> {
            PasskeySyncEnvelope envelope = state.envelopes.stream()
                    .filter(candidate -> candidate.syncId.equals(syncId))
                    .findFirst()
                    .orElseThrow(() -> new PasskeySyncException("SYNC_ENVELOPE_NOT_FOUND",
                            "Passkey sync envelope was not found", 404));
            if (!targetDeviceId.equals(envelope.targetDeviceId)) {
                throw new PasskeySyncException("SYNC_DEVICE_MISMATCH",
                        "This sync envelope is bound to another device", 403);
            }
            DeviceTrustChain.Verification verification = state.chain.verify();
            if (!verification.valid) {
                throw new PasskeySyncException("INVALID_TRUST_CHAIN",
                        String.join("; ", verification.problems), 409);
            }
            if (!verification.trustedDeviceIds.contains(targetDeviceId)) {
                throw new PasskeySyncException("UNTRUSTED_TARGET_DEVICE",
                        "Target device is not in the trusted chain", 403);
            }
            if (envelope.status == PasskeySyncEnvelope.Status.CONSUMED) {
                throw new PasskeySyncException("SYNC_ENVELOPE_CONSUMED",
                        "Passkey sync envelope has already been consumed", 409);
            }
            if (envelope.status == PasskeySyncEnvelope.Status.REVOKED) {
                throw new PasskeySyncException("SYNC_ENVELOPE_REVOKED",
                        "Passkey sync envelope has been revoked", 410);
            }
            if (System.currentTimeMillis() > envelope.expiresAt) {
                throw new PasskeySyncException("SYNC_ENVELOPE_EXPIRED",
                        "Passkey sync envelope has expired", 410);
            }
            if (!DeviceTrustCrypto.sha256(envelope.encryptedPayload).equals(envelope.payloadHash)) {
                throw new PasskeySyncException("SYNC_PAYLOAD_TAMPERED",
                        "Encrypted passkey payload failed integrity check", 409);
            }
            envelope.status = PasskeySyncEnvelope.Status.CONSUMED;
            envelope.consumedAt = System.currentTimeMillis();
            return envelope;
        });
    }

    public static JsonObject sessionClaims(PasskeySyncEnvelope envelope, DeviceTrustChain chain) {
        JsonObject claims = new JsonObject();
        claims.addProperty("authMethod", "passkey-cross-device-sync");
        claims.addProperty("syncId", envelope.syncId);
        claims.addProperty("sourceDeviceId", envelope.sourceDeviceId);
        claims.addProperty("deviceId", envelope.targetDeviceId);
        claims.addProperty("credentialId", envelope.credentialId);
        claims.addProperty("trustChainHead", chain.headHash());
        claims.addProperty("trustChainValid", chain.verify().valid);
        return claims;
    }

    private static void validateDeviceInput(String userId, String deviceId, String publicKey,
                                            String signature) throws PasskeySyncException {
        if (isBlank(userId) || isBlank(deviceId) || isBlank(publicKey) || isBlank(signature)) {
            throw new PasskeySyncException("INVALID_DEVICE_REQUEST",
                    "userId, deviceId, publicKey and signature are required");
        }
    }

    private static void assertExistingChainValid(DeviceTrustChain chain) throws PasskeySyncException {
        if (chain.links.isEmpty()) {
            throw new PasskeySyncException("DEVICE_TRUST_CHAIN_NOT_FOUND",
                    "Device trust chain has not been initialized", 404);
        }
        DeviceTrustChain.Verification verification = chain.verify();
        if (!verification.valid) {
            throw new PasskeySyncException("INVALID_TRUST_CHAIN",
                    String.join("; ", verification.problems), 409);
        }
    }

    private static void assertValidCandidate(DeviceTrustChain candidate) throws PasskeySyncException {
        DeviceTrustChain.Verification verification = candidate.verify();
        if (!verification.valid) {
            throw new PasskeySyncException("INVALID_DEVICE_SIGNATURE",
                    String.join("; ", verification.problems), 400);
        }
    }

    @UnauditedTransaction(justification = "Passkey trust-chain append is its own integrity record and does not mutate auth recipe rows")
    private static <T> T mutateState(AppIdentifier appIdentifier, Storage storage, String userId,
                                     StateMutation<T> mutation)
            throws PasskeySyncException, StorageQueryException, StorageTransactionLogicException {
        UserMetadataSQLStorage metadataStorage = StorageUtils.getUserMetadataStorage(storage);
        try {
            return metadataStorage.startTransaction(connection -> {
                JsonObject metadata = metadataStorage.getUserMetadata_Transaction(appIdentifier, connection,
                        userId);
                if (metadata == null) {
                    metadata = new JsonObject();
                }
                State state;
                try {
                    state = State.fromMetadata(metadata, userId);
                } catch (PasskeySyncException e) {
                    throw new StorageTransactionLogicException(e);
                }
                T result;
                try {
                    result = mutation.apply(state);
                } catch (PasskeySyncException e) {
                    throw new StorageTransactionLogicException(e);
                }
                metadata.add(METADATA_KEY, state.toJson());
                metadataStorage.setUserMetadata_Transaction(appIdentifier, connection, userId, metadata);
                metadataStorage.commitTransaction(connection);
                return result;
            });
        } catch (StorageTransactionLogicException e) {
            if (e.actualException instanceof PasskeySyncException passkeySyncException) {
                throw passkeySyncException;
            }
            throw e;
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private interface StateMutation<T> {
        T apply(State state) throws PasskeySyncException;
    }

    private static final class State {
        private DeviceTrustChain chain;
        private final List<PasskeySyncEnvelope> envelopes;

        private State(DeviceTrustChain chain, List<PasskeySyncEnvelope> envelopes) {
            this.chain = chain;
            this.envelopes = envelopes;
        }

        private static State fromMetadata(JsonObject metadata, String userId) throws PasskeySyncException {
            if (metadata == null || !metadata.has(METADATA_KEY) || metadata.get(METADATA_KEY).isJsonNull()) {
                return new State(new DeviceTrustChain(userId, List.of()), new ArrayList<>());
            }
            try {
                JsonObject stateJson = metadata.getAsJsonObject(METADATA_KEY);
                DeviceTrustChain chain = stateJson.has("chain") && stateJson.get("chain").isJsonObject()
                        ? DeviceTrustChain.fromJson(stateJson.getAsJsonObject("chain"))
                        : new DeviceTrustChain(userId, List.of());
                List<PasskeySyncEnvelope> envelopes = new ArrayList<>();
                if (stateJson.has("envelopes") && stateJson.get("envelopes").isJsonArray()) {
                    for (var element : stateJson.getAsJsonArray("envelopes")) {
                        envelopes.add(PasskeySyncEnvelope.fromJson(element.getAsJsonObject()));
                    }
                }
                return new State(chain, envelopes);
            } catch (IllegalStateException e) {
                throw new PasskeySyncException("INVALID_SYNC_STATE", "Passkey sync metadata is malformed");
            }
        }

        private JsonObject toJson() {
            JsonObject stateJson = new JsonObject();
            stateJson.addProperty("version", 1);
            stateJson.add("chain", chain.toJson());
            JsonArray envelopeArray = new JsonArray();
            for (PasskeySyncEnvelope envelope : envelopes) {
                envelopeArray.add(envelope.toJson());
            }
            stateJson.add("envelopes", envelopeArray);
            return stateJson;
        }
    }
}
