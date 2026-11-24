package io.supertokens.passkeysync;

import com.google.gson.JsonObject;

public final class PasskeySyncEnvelope {
    public enum Status {
        PENDING,
        CONSUMED,
        REVOKED
    }

    public final String syncId;
    public final String userId;
    public final String sourceDeviceId;
    public final String targetDeviceId;
    public final String credentialId;
    public final String encryptedPayload;
    public final String payloadHash;
    public Status status;
    public final long createdAt;
    public final long expiresAt;
    public Long consumedAt;

    public PasskeySyncEnvelope(String syncId, String userId, String sourceDeviceId, String targetDeviceId,
                               String credentialId, String encryptedPayload, String payloadHash, Status status,
                               long createdAt, long expiresAt, Long consumedAt) {
        this.syncId = syncId;
        this.userId = userId;
        this.sourceDeviceId = sourceDeviceId;
        this.targetDeviceId = targetDeviceId;
        this.credentialId = credentialId;
        this.encryptedPayload = encryptedPayload;
        this.payloadHash = payloadHash;
        this.status = status;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
    }

    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("syncId", syncId);
        json.addProperty("userId", userId);
        json.addProperty("sourceDeviceId", sourceDeviceId);
        json.addProperty("targetDeviceId", targetDeviceId);
        json.addProperty("credentialId", credentialId);
        json.addProperty("encryptedPayload", encryptedPayload);
        json.addProperty("payloadHash", payloadHash);
        json.addProperty("status", status.name());
        json.addProperty("createdAt", createdAt);
        json.addProperty("expiresAt", expiresAt);
        if (consumedAt != null) {
            json.addProperty("consumedAt", consumedAt);
        }
        return json;
    }

    public static PasskeySyncEnvelope fromJson(JsonObject json) throws PasskeySyncException {
        try {
            Long consumedAt = json.has("consumedAt") && !json.get("consumedAt").isJsonNull()
                    ? json.get("consumedAt").getAsLong()
                    : null;
            return new PasskeySyncEnvelope(
                    json.get("syncId").getAsString(),
                    json.get("userId").getAsString(),
                    json.get("sourceDeviceId").getAsString(),
                    json.get("targetDeviceId").getAsString(),
                    json.get("credentialId").getAsString(),
                    json.get("encryptedPayload").getAsString(),
                    json.get("payloadHash").getAsString(),
                    Status.valueOf(json.get("status").getAsString()),
                    json.get("createdAt").getAsLong(),
                    json.get("expiresAt").getAsLong(),
                    consumedAt);
        } catch (Exception e) {
            throw new PasskeySyncException("INVALID_SYNC_ENVELOPE", "Passkey sync envelope is malformed");
        }
    }
}
