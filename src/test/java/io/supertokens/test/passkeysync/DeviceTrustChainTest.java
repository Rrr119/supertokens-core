package io.supertokens.test.passkeysync;

import com.google.gson.JsonObject;
import io.supertokens.passkeysync.DeviceKind;
import io.supertokens.passkeysync.DeviceTrustChain;
import io.supertokens.passkeysync.DeviceTrustCrypto;
import io.supertokens.passkeysync.TrustLink;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DeviceTrustChainTest {
    @Test
    public void verifiesSignaturesRevocationAndTampering() throws Exception {
        KeyPair desktopKey = generateKeyPair();
        KeyPair mobileKey = generateKeyPair();
        KeyPair tabletKey = generateKeyPair();

        TrustLink genesis = signedLink(0, TrustLink.Type.GENESIS, "user-1", "desktop", null, null,
                DeviceKind.DESKTOP, publicKey(desktopKey), desktopKey,
                DeviceTrustCrypto.GENESIS_PREVIOUS_HASH);
        TrustLink addMobile = signedLink(1, TrustLink.Type.DEVICE_ADDED, "user-1", "mobile", "desktop", null,
                DeviceKind.MOBILE, publicKey(mobileKey), desktopKey, genesis.hash);
        TrustLink addTablet = signedLink(2, TrustLink.Type.DEVICE_ADDED, "user-1", "tablet", "desktop", null,
                DeviceKind.TABLET, publicKey(tabletKey), desktopKey, addMobile.hash);
        TrustLink revokeMobile = signedLink(3, TrustLink.Type.DEVICE_REVOKED, "user-1", "desktop",
                "desktop", "mobile", null, null, desktopKey, addTablet.hash);

        DeviceTrustChain chain = new DeviceTrustChain("user-1",
                List.of(genesis, addMobile, addTablet, revokeMobile));
        DeviceTrustChain.Verification verification = chain.verify();

        assertTrue(verification.problems.toString(), verification.valid);
        assertTrue(chain.isTrusted("desktop"));
        assertTrue(chain.isTrusted("tablet"));
        assertFalse(chain.isTrusted("mobile"));

        JsonObject tamperedJson = chain.toJson();
        tamperedJson.getAsJsonArray("links").get(1).getAsJsonObject()
                .addProperty("displayName", "tampered-device");
        DeviceTrustChain tampered = DeviceTrustChain.fromJson(tamperedJson);
        assertFalse(tampered.verify().valid);
        assertFalse(tampered.isTrusted("mobile"));

        TrustLink badEndorsement = signedLink(4, TrustLink.Type.DEVICE_ADDED, "user-1", "watch", "mobile",
                null, DeviceKind.OTHER, publicKey(generateKeyPair()), mobileKey, revokeMobile.hash);
        DeviceTrustChain invalidChain = new DeviceTrustChain("user-1",
                List.of(genesis, addMobile, addTablet, revokeMobile, badEndorsement));
        DeviceTrustChain.Verification invalidVerification = invalidChain.verify();
        assertFalse(invalidVerification.valid);
        assertTrue(invalidVerification.problems.stream()
                .anyMatch(problem -> problem.contains("revoked") || problem.contains("signature")));
    }

    private static TrustLink signedLink(int sequence, TrustLink.Type type, String userId, String deviceId,
                                        String trustedByDeviceId, String targetDeviceId, DeviceKind kind,
                                        String publicKey, KeyPair signer, String previousHash) throws Exception {
        TrustLink template = TrustLink.create(sequence, type, userId, deviceId, trustedByDeviceId,
                targetDeviceId, kind, publicKey, "device-name", 123456789L, previousHash,
                "placeholder-signature");
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signer.getPrivate());
        signature.update(template.signingPayload());
        String encodedSignature = Base64.getEncoder().encodeToString(signature.sign());
        return TrustLink.create(sequence, type, userId, deviceId, trustedByDeviceId, targetDeviceId, kind,
                publicKey, "device-name", 123456789L, previousHash, encodedSignature);
    }

    private static KeyPair generateKeyPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static String publicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }
}
