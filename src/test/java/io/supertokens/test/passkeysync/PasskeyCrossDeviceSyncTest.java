package io.supertokens.test.passkeysync;

import com.google.gson.JsonObject;
import com.google.gson.Gson;
import com.webauthn4j.data.AuthenticatorAssertionResponse;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.authenticator.webauthn.CredentialMapKey;
import com.webauthn4j.test.authenticator.webauthn.PackedAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.PublicKeyCredentialSource;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnModelAuthenticator;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;
import io.supertokens.Main;
import io.supertokens.ProcessState;
import io.supertokens.passkeysync.DeviceKind;
import io.supertokens.passkeysync.DeviceTrustChain;
import io.supertokens.passkeysync.PasskeySyncEnvelope;
import io.supertokens.passkeysync.PasskeySyncService;
import io.supertokens.passkeysync.TrustLink;
import io.supertokens.pluginInterface.STORAGE_TYPE;
import io.supertokens.session.Session;
import io.supertokens.session.info.SessionInformationHolder;
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

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class PasskeyCrossDeviceSyncTest {
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
    public void threeDeviceKindsCanSyncPasskeyToAnotherDeviceAndCreateSession() throws Exception {
        String[] args = {"../"};
        TestingProcessManager.TestingProcess process = TestingProcessManager.start(args);
        assertNotNull(process.checkOrWaitForEvent(ProcessState.PROCESS_STATE.STARTED));

        if (StorageLayer.getStorage(process.getProcess()).getType() != STORAGE_TYPE.SQL) {
            return;
        }

        Main main = process.getProcess();
        String email = "passkey-sync@example.com";
        JsonObject bootstrapUser = io.supertokens.test.webauthn.Utils.registerUserWithCredentials(main, email);
        String recipeUserId = bootstrapUser.get("recipeUserId").getAsString();

        String[] deviceIds = {"desktop-chrome", "mobile-safari", "tablet-android"};
        DeviceKind[] deviceKinds = {DeviceKind.DESKTOP, DeviceKind.MOBILE, DeviceKind.TABLET};
        KeyPair[] deviceKeys = generateDeviceKeys(3);
        DevicePasskey[] devicePasskeys = new DevicePasskey[3];

        DeviceTrustChain chain = null;
        for (int i = 0; i < 3; i++) {
            devicePasskeys[i] = registerWebAuthnCredential(main, email, recipeUserId);
            String publicKey = encodePublicKey(deviceKeys[i]);

            if (i == 0) {
                TrustLink genesisTemplate = signatureTemplate(0, TrustLink.Type.GENESIS, recipeUserId,
                        deviceIds[i], null, null, deviceKinds[i], publicKey, "Primary " + deviceKinds[i],
                        io.supertokens.passkeysync.DeviceTrustCrypto.GENESIS_PREVIOUS_HASH);
                String signature = sign(deviceKeys[i], genesisTemplate);
                chain = PasskeySyncService.registerGenesisDevice(main, recipeUserId, deviceIds[i],
                        deviceKinds[i], "Primary " + deviceKinds[i], publicKey, signature);
            } else {
                TrustLink addTemplate = signatureTemplate(chain.links.size(), TrustLink.Type.DEVICE_ADDED,
                        recipeUserId, deviceIds[i], deviceIds[0], null, deviceKinds[i], publicKey,
                        deviceKinds[i] + " device", chain.headHash());
                String endorsement = sign(deviceKeys[0], addTemplate);
                chain = PasskeySyncService.addTrustedDevice(main, recipeUserId, deviceIds[i], deviceKinds[i],
                        deviceKinds[i] + " device", publicKey, deviceIds[0], endorsement);
            }

            assertTrue(chain.verify().valid);
            assertTrue(chain.isTrusted(deviceIds[i]));
        }

        for (int sourceIndex = 0; sourceIndex < 3; sourceIndex++) {
            String targetDeviceId = "synced-browser-" + sourceIndex;
            KeyPair targetKey = generateDeviceKeys(1)[0];
            PackedAuthenticator targetAuthenticator = new PackedAuthenticator();
            ClientPlatform targetPlatform = EmulatorUtil.createClientPlatform(targetAuthenticator);

            chain = PasskeySyncService.getTrustChain(main, recipeUserId);
            TrustLink targetTemplate = signatureTemplate(chain.links.size(), TrustLink.Type.DEVICE_ADDED,
                    recipeUserId, targetDeviceId, deviceIds[sourceIndex], null, DeviceKind.OTHER,
                    encodePublicKey(targetKey), "Passkey-enabled browser", chain.headHash());
            String targetEndorsement = sign(deviceKeys[sourceIndex], targetTemplate);
            chain = PasskeySyncService.addTrustedDevice(main, recipeUserId, targetDeviceId, DeviceKind.OTHER,
                    "Passkey-enabled browser", encodePublicKey(targetKey), deviceIds[sourceIndex],
                    targetEndorsement);

            String encryptedPayload = "encrypted-passkey-blob:" + devicePasskeys[sourceIndex].credentialId;
            PasskeySyncEnvelope envelope = PasskeySyncService.createSyncEnvelope(main, recipeUserId,
                    deviceIds[sourceIndex], targetDeviceId, devicePasskeys[sourceIndex].credentialId,
                    encryptedPayload, 60 * 60 * 1000L);

            PasskeySyncEnvelope claimed = PasskeySyncService.claimSyncEnvelope(main, recipeUserId,
                    envelope.syncId, targetDeviceId);
            assertEquals(PasskeySyncEnvelope.Status.CONSUMED, claimed.status);
            assertEquals(encryptedPayload, claimed.encryptedPayload);

            copySyncedCredential(devicePasskeys[sourceIndex].authenticator,
                    devicePasskeys[sourceIndex].credentialId, targetAuthenticator);

            JsonObject signInOptions = io.supertokens.test.webauthn.Utils.signInOptions(main);
            Map<String, PublicKeyCredential<com.webauthn4j.data.AuthenticatorAssertionResponse,
                    com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput>> options =
                    io.supertokens.test.webauthn.Utils.createPublicKeyRequestOptions(signInOptions,
                            targetPlatform, devicePasskeys[sourceIndex].credentialId);
            JsonObject signInResponse = signIn(main, options.keySet().iterator().next(),
                    options.values().iterator().next());

            assertEquals("OK", signInResponse.get("status").getAsString());
            assertEquals(recipeUserId, signInResponse.get("recipeUserId").getAsString());

            DeviceTrustChain finalChain = PasskeySyncService.getTrustChain(main, recipeUserId);
            JsonObject sessionClaims = PasskeySyncService.sessionClaims(claimed, finalChain);
            SessionInformationHolder session = Session.createNewSession(main, recipeUserId, sessionClaims,
                    new JsonObject());
            assertNotNull(session.session.handle);
            assertNotNull(session.accessToken);
            assertEquals(recipeUserId, session.session.userId);
            assertEquals(targetDeviceId,
                    session.session.userDataInJWT.getAsJsonObject().get("deviceId").getAsString());

            SessionInformationHolder verified = Session.getSession(main, session.accessToken.token,
                    session.antiCsrfToken, false, true, false);
            assertEquals(session.session.handle, verified.session.handle);
            assertEquals("passkey-cross-device-sync",
                    verified.session.userDataInJWT.getAsJsonObject().get("authMethod").getAsString());
            assertTrue(verified.session.userDataInJWT.getAsJsonObject().get("trustChainValid").getAsBoolean());
        }

        process.kill();
        assertNotNull(process.checkOrWaitForEvent(ProcessState.PROCESS_STATE.STOPPED));
    }

    private static DevicePasskey registerWebAuthnCredential(Main main, String email, String recipeUserId)
            throws Exception {
        PackedAuthenticator authenticator = new PackedAuthenticator();
        ClientPlatform platform = EmulatorUtil.createClientPlatform(authenticator);

        JsonObject registerOptionsResponse = io.supertokens.test.webauthn.Utils.registerOptions(main, email);
        Map<String, PublicKeyCredentialCreationOptions> creationOptions =
                io.supertokens.test.webauthn.Utils.createPublicKeyCreationOptions(registerOptionsResponse);
        Map.Entry<String, PublicKeyCredentialCreationOptions> option =
                creationOptions.entrySet().iterator().next();

        PublicKeyCredential<com.webauthn4j.data.AuthenticatorAttestationResponse,
                RegistrationExtensionClientOutput> credential =
                io.supertokens.test.webauthn.Utils.createPasskey(platform, option.getValue());
        JsonObject response = io.supertokens.test.webauthn.Utils.registerCredentials(main, option.getKey(),
                credential, recipeUserId);
        assertEquals("OK", response.get("status").getAsString());
        return new DevicePasskey(authenticator, response.get("webauthnCredentialId").getAsString());
    }

    private static JsonObject signIn(
            Main main, String optionsId,
            PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential)
            throws Exception {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("webauthnGeneratedOptionsId", optionsId);
        requestBody.add("credential", new Gson().toJsonTree(credential));

        JsonObject response = requestBody.getAsJsonObject("credential").getAsJsonObject("response");
        response.addProperty("signature", Base64UrlUtil.encodeToString(credential.getResponse().getSignature()));
        response.addProperty("clientDataJSON",
                Base64UrlUtil.encodeToString(credential.getResponse().getClientDataJSON()));
        response.addProperty("authenticatorData",
                Base64UrlUtil.encodeToString(credential.getResponse().getAuthenticatorData()));
        if (credential.getResponse().getUserHandle() != null) {
            response.addProperty("userHandle",
                    Base64UrlUtil.encodeToString(credential.getResponse().getUserHandle()));
        }

        requestBody.getAsJsonObject("credential").addProperty("type", credential.getType());
        requestBody.getAsJsonObject("credential").getAsJsonObject("response").remove("transports");
        requestBody.getAsJsonObject("credential").remove("clientExtensionResults");
        requestBody.getAsJsonObject("credential").addProperty("rawId",
                Base64UrlUtil.encodeToString(credential.getRawId()));

        return HttpRequestForTesting.sendJsonPOSTRequest(main, "",
                "http://localhost:3567/recipe/webauthn/signin", requestBody, 10000, 1000, null,
                SemVer.v5_3.get(), null);
    }

    private static void copySyncedCredential(PackedAuthenticator source, String credentialId,
                                             PackedAuthenticator target) throws Exception {
        byte[] rawCredentialId = Base64UrlUtil.decode(credentialId.getBytes(StandardCharsets.UTF_8));
        PublicKeyCredentialSource credentialSource = source.lookup(rawCredentialId);
        assertNotNull(credentialSource);

        Field credentialMapField = WebAuthnModelAuthenticator.class.getDeclaredField("credentialMap");
        credentialMapField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<CredentialMapKey, PublicKeyCredentialSource> targetMap =
                (Map<CredentialMapKey, PublicKeyCredentialSource>) credentialMapField.get(target);
        CredentialMapKey key = new CredentialMapKey(credentialSource.getRpId(),
                credentialSource.getUserHandle());
        targetMap.put(key, credentialSource);

        Field counterField = WebAuthnModelAuthenticator.class.getDeclaredField("counter");
        counterField.setAccessible(true);
        counterField.setInt(target, counterField.getInt(source));

        assertArrayEquals(rawCredentialId, target.lookup(rawCredentialId).getId());
    }

    private static KeyPair[] generateDeviceKeys(int count) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair[] keyPairs = new KeyPair[count];
        for (int i = 0; i < count; i++) {
            keyPairs[i] = generator.generateKeyPair();
        }
        return keyPairs;
    }

    private static String encodePublicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    private static String sign(KeyPair keyPair, TrustLink template) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(template.signingPayload());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static TrustLink signatureTemplate(int sequence, TrustLink.Type type, String userId,
                                               String deviceId, String trustedByDeviceId,
                                               String targetDeviceId, DeviceKind deviceKind,
                                               String publicKey, String displayName, String previousHash) {
        return TrustLink.create(sequence, type, userId, deviceId, trustedByDeviceId, targetDeviceId,
                deviceKind, publicKey, displayName, 0L, previousHash, "signature-placeholder");
    }

    private record DevicePasskey(PackedAuthenticator authenticator, String credentialId) {
    }
}
