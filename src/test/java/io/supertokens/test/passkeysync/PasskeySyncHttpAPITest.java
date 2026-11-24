package io.supertokens.test.passkeysync;

import com.google.gson.JsonObject;
import io.supertokens.ProcessState;
import io.supertokens.passkeysync.DeviceKind;
import io.supertokens.passkeysync.DeviceTrustCrypto;
import io.supertokens.passkeysync.TrustLink;
import io.supertokens.pluginInterface.STORAGE_TYPE;
import io.supertokens.storageLayer.StorageLayer;
import io.supertokens.test.TestingProcessManager;
import io.supertokens.test.Utils;
import io.supertokens.test.httpRequest.HttpRequestForTesting;
import io.supertokens.utils.SemVer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class PasskeySyncHttpAPITest {
    private static final String TRUST_CHAIN_URL = "http://localhost:3567/recipe/webauthn/device/trust-chain";
    private static final String SYNC_URL = "http://localhost:3567/recipe/webauthn/passkey/sync";

    @Rule
    public TestRule watchman = Utils.getOnFailure();

    @AfterClass
    public static void afterTesting() {
        Utils.afterTesting();
    }

    @Before
    public void beforeEach() {
        Utils.reset();
    }

    @Test
    public void trustChainAndSyncEndpointsWorkAndRejectReplay() throws Exception {
        String[] args = {"../"};
        TestingProcessManager.TestingProcess process = TestingProcessManager.start(args);
        assertNotNull(process.checkOrWaitForEvent(ProcessState.PROCESS_STATE.STARTED));

        if (StorageLayer.getStorage(process.getProcess()).getType() != STORAGE_TYPE.SQL) {
            return;
        }

        String email = "passkey-sync-api@example.com";
        JsonObject user = io.supertokens.test.webauthn.Utils.registerUserWithCredentials(
                process.getProcess(), email);
        String userId = user.get("recipeUserId").getAsString();
        String credentialId = user.get("webauthnCredentialId").getAsString();

        KeyPair desktopKey = generateKeyPair();
        KeyPair mobileKey = generateKeyPair();
        String desktopPublicKey = publicKey(desktopKey);
        String mobilePublicKey = publicKey(mobileKey);

        TrustLink genesisTemplate = template(0, TrustLink.Type.GENESIS, userId, "desktop", null, null,
                DeviceKind.DESKTOP, desktopPublicKey, DeviceTrustCrypto.GENESIS_PREVIOUS_HASH);
        JsonObject genesisRequest = new JsonObject();
        genesisRequest.addProperty("action", "GENESIS");
        genesisRequest.addProperty("userId", userId);
        genesisRequest.addProperty("deviceId", "desktop");
        genesisRequest.addProperty("deviceKind", "DESKTOP");
        genesisRequest.addProperty("displayName", "test-device");
        genesisRequest.addProperty("publicKey", desktopPublicKey);
        genesisRequest.addProperty("signature", sign(desktopKey, genesisTemplate));

        JsonObject genesisResponse = post(process, TRUST_CHAIN_URL, genesisRequest);
        assertEquals("OK", genesisResponse.get("status").getAsString());
        assertEquals(1, genesisResponse.getAsJsonObject("chain").getAsJsonArray("links").size());
        String headHash = genesisResponse.getAsJsonObject("chain").get("headHash").getAsString();

        JsonObject fetched = HttpRequestForTesting.sendGETRequest(process.getProcess(), "", TRUST_CHAIN_URL,
                Map.of("userId", userId), 10000, 1000, null, SemVer.v5_3.get(), null);
        assertEquals("OK", fetched.get("status").getAsString());
        assertTrue(fetched.getAsJsonObject("chain").get("valid").getAsBoolean());

        TrustLink addTemplate = template(1, TrustLink.Type.DEVICE_ADDED, userId, "mobile", "desktop", null,
                DeviceKind.MOBILE, mobilePublicKey, headHash);
        JsonObject addRequest = new JsonObject();
        addRequest.addProperty("action", "ADD");
        addRequest.addProperty("userId", userId);
        addRequest.addProperty("deviceId", "mobile");
        addRequest.addProperty("deviceKind", "MOBILE");
        addRequest.addProperty("displayName", "test-device");
        addRequest.addProperty("publicKey", mobilePublicKey);
        addRequest.addProperty("trustedByDeviceId", "desktop");
        addRequest.addProperty("signature", sign(desktopKey, addTemplate));

        JsonObject addResponse = post(process, TRUST_CHAIN_URL, addRequest);
        assertEquals("OK", addResponse.get("status").getAsString());
        assertEquals(2, addResponse.getAsJsonObject("chain").getAsJsonArray("links").size());

        JsonObject badSignatureRequest = addRequest.deepCopy();
        badSignatureRequest.addProperty("deviceId", "tablet");
        badSignatureRequest.addProperty("deviceKind", "TABLET");
        badSignatureRequest.addProperty("publicKey", publicKey(generateKeyPair()));
        badSignatureRequest.addProperty("signature", sign(mobileKey, addTemplate));
        JsonObject badSignatureResponse = post(process, TRUST_CHAIN_URL, badSignatureRequest);
        assertEquals("INVALID_DEVICE_SIGNATURE", badSignatureResponse.get("status").getAsString());

        JsonObject createRequest = new JsonObject();
        createRequest.addProperty("action", "CREATE");
        createRequest.addProperty("userId", userId);
        createRequest.addProperty("sourceDeviceId", "desktop");
        createRequest.addProperty("targetDeviceId", "mobile");
        createRequest.addProperty("credentialId", credentialId);
        createRequest.addProperty("encryptedPayload", "ciphertext");
        JsonObject createResponse = post(process, SYNC_URL, createRequest);
        assertEquals("OK", createResponse.get("status").getAsString());
        String syncId = createResponse.getAsJsonObject("envelope").get("syncId").getAsString();

        JsonObject claimRequest = new JsonObject();
        claimRequest.addProperty("action", "CLAIM");
        claimRequest.addProperty("userId", userId);
        claimRequest.addProperty("syncId", syncId);
        claimRequest.addProperty("targetDeviceId", "mobile");
        JsonObject claimResponse = post(process, SYNC_URL, claimRequest);
        assertEquals("OK", claimResponse.get("status").getAsString());
        assertEquals("CONSUMED", claimResponse.getAsJsonObject("envelope").get("status").getAsString());

        JsonObject replayResponse = post(process, SYNC_URL, claimRequest);
        assertEquals("SYNC_ENVELOPE_CONSUMED", replayResponse.get("status").getAsString());

        process.kill();
        assertNotNull(process.checkOrWaitForEvent(ProcessState.PROCESS_STATE.STOPPED));
    }

    private static JsonObject post(TestingProcessManager.TestingProcess process, String url, JsonObject body)
            throws Exception {
        return HttpRequestForTesting.sendJsonPOSTRequest(process.getProcess(), "", url, body, 10000, 10000,
                null, SemVer.v5_3.get(), null);
    }

    private static KeyPair generateKeyPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static String publicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    private static String sign(KeyPair keyPair, TrustLink template) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(template.signingPayload());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static TrustLink template(int sequence, TrustLink.Type type, String userId, String deviceId,
                                      String trustedByDeviceId, String targetDeviceId, DeviceKind kind,
                                      String publicKey, String previousHash) {
        return TrustLink.create(sequence, type, userId, deviceId, trustedByDeviceId, targetDeviceId, kind,
                publicKey, "test-device", 0L, previousHash, "placeholder-signature");
    }
}
