package io.supertokens.passkeysync;

import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;

public final class TrustLink {
    public enum Type {
        GENESIS,
        DEVICE_ADDED,
        DEVICE_REVOKED
    }

    public final int sequence;
    public final Type type;
    public final String userId;
    public final String deviceId;
    public final String trustedByDeviceId;
    public final String targetDeviceId;
    public final DeviceKind deviceKind;
    public final String publicKey;
    public final String displayName;
    public final long createdAt;
    public final String previousHash;
    public final String hash;
    public final String signature;

    private TrustLink(int sequence, Type type, String userId, String deviceId, String trustedByDeviceId,
                      String targetDeviceId, DeviceKind deviceKind, String publicKey, String displayName,
                      long createdAt, String previousHash, String hash, String signature) {
        this.sequence = sequence;
        this.type = type;
        this.userId = userId;
        this.deviceId = deviceId;
        this.trustedByDeviceId = trustedByDeviceId;
        this.targetDeviceId = targetDeviceId;
        this.deviceKind = deviceKind;
        this.publicKey = publicKey;
        this.displayName = displayName;
        this.createdAt = createdAt;
        this.previousHash = previousHash;
        this.hash = hash;
        this.signature = signature;
    }

    public static TrustLink create(int sequence, Type type, String userId, String deviceId,
                                   String trustedByDeviceId, String targetDeviceId, DeviceKind deviceKind,
                                   String publicKey, String displayName, long createdAt,
                                   String previousHash, String signature) {
        TrustLink unsigned = new TrustLink(sequence, type, userId, deviceId, trustedByDeviceId, targetDeviceId,
                deviceKind, publicKey, displayName, createdAt, previousHash, null, signature);
        return new TrustLink(sequence, type, userId, deviceId, trustedByDeviceId, targetDeviceId, deviceKind,
                publicKey, displayName, createdAt, previousHash, unsigned.calculateHash(), signature);
    }

    public byte[] signingPayload() {
        return canonicalPayload(false).getBytes(StandardCharsets.UTF_8);
    }

    public String calculateHash() {
        return DeviceTrustCrypto.sha256(canonicalPayload(true));
    }

    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("sequence", sequence);
        json.addProperty("type", type.name());
        json.addProperty("userId", userId);
        json.addProperty("deviceId", deviceId);
        addNullable(json, "trustedByDeviceId", trustedByDeviceId);
        addNullable(json, "targetDeviceId", targetDeviceId);
        if (deviceKind != null) {
            json.addProperty("deviceKind", deviceKind.name());
        }
        addNullable(json, "publicKey", publicKey);
        addNullable(json, "displayName", displayName);
        json.addProperty("createdAt", createdAt);
        json.addProperty("previousHash", previousHash);
        json.addProperty("hash", hash);
        addNullable(json, "signature", signature);
        return json;
    }

    public static TrustLink fromJson(JsonObject json) throws PasskeySyncException {
        try {
            DeviceKind kind = json.has("deviceKind") && !json.get("deviceKind").isJsonNull()
                    ? DeviceKind.fromString(json.get("deviceKind").getAsString())
                    : null;
            return new TrustLink(
                    json.get("sequence").getAsInt(),
                    Type.valueOf(json.get("type").getAsString()),
                    json.get("userId").getAsString(),
                    json.get("deviceId").getAsString(),
                    stringOrNull(json, "trustedByDeviceId"),
                    stringOrNull(json, "targetDeviceId"),
                    kind,
                    stringOrNull(json, "publicKey"),
                    stringOrNull(json, "displayName"),
                    json.get("createdAt").getAsLong(),
                    json.get("previousHash").getAsString(),
                    json.get("hash").getAsString(),
                    stringOrNull(json, "signature"));
        } catch (PasskeySyncException e) {
            throw e;
        } catch (Exception e) {
            throw new PasskeySyncException("INVALID_TRUST_CHAIN", "Trust chain link is malformed");
        }
    }

    private String canonicalPayload(boolean includeCreatedAt) {
        StringBuilder payload = new StringBuilder(includeCreatedAt ? "trust-hash-v1\n" : "trust-signature-v1\n");
        append(payload, Integer.toString(sequence));
        append(payload, type.name());
        append(payload, userId);
        append(payload, deviceId);
        append(payload, trustedByDeviceId);
        append(payload, targetDeviceId);
        append(payload, deviceKind == null ? null : deviceKind.name());
        append(payload, publicKey);
        append(payload, displayName);
        if (includeCreatedAt) {
            append(payload, Long.toString(createdAt));
        }
        append(payload, previousHash);
        return payload.toString();
    }

    private static void append(StringBuilder builder, String value) {
        if (value == null) {
            builder.append("-1:\n");
        } else {
            builder.append(value.length()).append(':').append(value).append('\n');
        }
    }

    private static void addNullable(JsonObject json, String key, String value) {
        if (value != null) {
            json.addProperty(key, value);
        }
    }

    private static String stringOrNull(JsonObject json, String key) {
        return json.has(key) && !json.get(key).isJsonNull() ? json.get(key).getAsString() : null;
    }
}
