package io.supertokens.passkeysync;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class DeviceTrustChain {
    public static final class Verification {
        public final boolean valid;
        public final List<String> problems;
        public final Set<String> trustedDeviceIds;
        public final Set<String> revokedDeviceIds;
        public final Map<String, String> devicePublicKeys;

        Verification(List<String> problems, Set<String> trustedDeviceIds, Set<String> revokedDeviceIds,
                     Map<String, String> devicePublicKeys) {
            this.problems = Collections.unmodifiableList(new ArrayList<>(problems));
            this.valid = problems.isEmpty();
            this.trustedDeviceIds = Collections.unmodifiableSet(new HashSet<>(trustedDeviceIds));
            this.revokedDeviceIds = Collections.unmodifiableSet(new HashSet<>(revokedDeviceIds));
            this.devicePublicKeys = Collections.unmodifiableMap(new HashMap<>(devicePublicKeys));
        }
    }

    public final String userId;
    public final List<TrustLink> links;

    public DeviceTrustChain(String userId, List<TrustLink> links) {
        this.userId = userId;
        this.links = Collections.unmodifiableList(new ArrayList<>(links));
    }

    public String headHash() {
        return links.isEmpty() ? DeviceTrustCrypto.GENESIS_PREVIOUS_HASH : links.get(links.size() - 1).hash;
    }

    public boolean isTrusted(String deviceId) {
        Verification verification = verify();
        return verification.valid && verification.trustedDeviceIds.contains(deviceId);
    }

    public Verification verify() {
        List<String> problems = new ArrayList<>();
        Set<String> trusted = new HashSet<>();
        Set<String> revoked = new HashSet<>();
        Map<String, String> publicKeys = new HashMap<>();

        if (links.isEmpty()) {
            problems.add("Trust chain has no genesis link");
            return new Verification(problems, trusted, revoked, publicKeys);
        }

        String expectedPreviousHash = DeviceTrustCrypto.GENESIS_PREVIOUS_HASH;
        for (int index = 0; index < links.size(); index++) {
            TrustLink link = links.get(index);
            String linkPrefix = "link[" + index + "]";

            if (link.sequence != index) {
                problems.add(linkPrefix + " has sequence " + link.sequence + ", expected " + index);
            }
            if (!userId.equals(link.userId)) {
                problems.add(linkPrefix + " belongs to user " + link.userId + ", expected " + userId);
            }
            if (!expectedPreviousHash.equals(link.previousHash)) {
                problems.add(linkPrefix + " previousHash does not match the chain head");
            }
            if (link.hash == null || !link.calculateHash().equals(link.hash)) {
                problems.add(linkPrefix + " hash is invalid");
            }
            if (link.signature == null || link.signature.isBlank()) {
                problems.add(linkPrefix + " is missing its device signature");
            }

            expectedPreviousHash = link.hash;

            try {
                switch (link.type) {
                    case GENESIS -> verifyGenesis(link, index, publicKeys, trusted, problems);
                    case DEVICE_ADDED -> verifyAdded(link, index, publicKeys, trusted, revoked, problems);
                    case DEVICE_REVOKED -> verifyRevocation(link, index, publicKeys, trusted, revoked, problems);
                }
            } catch (Exception e) {
                problems.add(linkPrefix + " could not be verified: " + e.getMessage());
            }
        }

        return new Verification(problems, trusted, revoked, publicKeys);
    }

    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("userId", userId);
        json.addProperty("headHash", headHash());
        JsonArray linkArray = new JsonArray();
        for (TrustLink link : links) {
            linkArray.add(link.toJson());
        }
        json.add("links", linkArray);
        Verification verification = verify();
        json.addProperty("valid", verification.valid);
        if (!verification.valid) {
            JsonArray problemsArray = new JsonArray();
            verification.problems.forEach(problemsArray::add);
            json.add("problems", problemsArray);
        }
        return json;
    }

    public static DeviceTrustChain fromJson(JsonObject json) throws PasskeySyncException {
        String userId = json.get("userId").getAsString();
        List<TrustLink> links = new ArrayList<>();
        if (json.has("links") && json.get("links").isJsonArray()) {
            for (var element : json.getAsJsonArray("links")) {
                links.add(TrustLink.fromJson(element.getAsJsonObject()));
            }
        }
        return new DeviceTrustChain(userId, links);
    }

    private static void verifyGenesis(TrustLink link, int index, Map<String, String> publicKeys,
                                      Set<String> trusted, List<String> problems) {
        if (index != 0) {
            problems.add("link[" + index + "] genesis link must be the first link");
        }
        if (!DeviceTrustCrypto.GENESIS_PREVIOUS_HASH.equals(link.previousHash)) {
            problems.add("link[0] genesis previousHash is invalid");
        }
        if (link.publicKey == null || link.deviceKind == null) {
            problems.add("link[0] genesis device is missing publicKey or deviceKind");
            return;
        }
        if (!verifySignature(link.publicKey, link)) {
            problems.add("link[0] genesis self-signature is invalid");
            return;
        }
        publicKeys.put(link.deviceId, link.publicKey);
        trusted.add(link.deviceId);
    }

    private static void verifyAdded(TrustLink link, int index, Map<String, String> publicKeys,
                                    Set<String> trusted, Set<String> revoked, List<String> problems) {
        if (index == 0) {
            problems.add("link[0] cannot be DEVICE_ADDED");
        }
        if (link.publicKey == null || link.deviceKind == null) {
            problems.add("link[" + index + "] added device is missing publicKey or deviceKind");
        }
        String endorserKey = link.trustedByDeviceId == null ? null : publicKeys.get(link.trustedByDeviceId);
        if (endorserKey == null) {
            problems.add("link[" + index + "] endorser is not in the trust chain");
            return;
        }
        if (revoked.contains(link.trustedByDeviceId)) {
            problems.add("link[" + index + "] endorser has been revoked");
        }
        if (!verifySignature(endorserKey, link)) {
            problems.add("link[" + index + "] endorsement signature is invalid");
        }
        if (publicKeys.containsKey(link.deviceId)) {
            problems.add("link[" + index + "] device is already present in the trust chain");
            return;
        }
        if (link.publicKey != null) {
            publicKeys.put(link.deviceId, link.publicKey);
            trusted.add(link.deviceId);
        }
    }

    private static void verifyRevocation(TrustLink link, int index, Map<String, String> publicKeys,
                                         Set<String> trusted, Set<String> revoked, List<String> problems) {
        if (link.targetDeviceId == null || !publicKeys.containsKey(link.targetDeviceId)) {
            problems.add("link[" + index + "] revocation target is not in the trust chain");
        }
        String revokerKey = link.trustedByDeviceId == null ? null : publicKeys.get(link.trustedByDeviceId);
        if (revokerKey == null) {
            problems.add("link[" + index + "] revoker is not in the trust chain");
            return;
        }
        if (revoked.contains(link.trustedByDeviceId)) {
            problems.add("link[" + index + "] revoker has been revoked");
        }
        if (!verifySignature(revokerKey, link)) {
            problems.add("link[" + index + "] revocation signature is invalid");
        }
        if (link.targetDeviceId != null) {
            revoked.add(link.targetDeviceId);
            trusted.remove(link.targetDeviceId);
        }
    }

    private static boolean verifySignature(String publicKey, TrustLink link) {
        return link.signature != null &&
                DeviceTrustCrypto.verifyEd25519(publicKey, link.signingPayload(), link.signature);
    }
}
