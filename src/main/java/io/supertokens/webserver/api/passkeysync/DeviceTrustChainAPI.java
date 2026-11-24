package io.supertokens.webserver.api.passkeysync;

import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.passkeysync.DeviceKind;
import io.supertokens.passkeysync.DeviceTrustChain;
import io.supertokens.passkeysync.PasskeySyncException;
import io.supertokens.passkeysync.PasskeySyncService;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.exceptions.StorageTransactionLogicException;
import io.supertokens.pluginInterface.multitenancy.AppIdentifier;
import io.supertokens.pluginInterface.multitenancy.exceptions.TenantOrAppNotFoundException;
import io.supertokens.webserver.InputParser;
import io.supertokens.webserver.WebserverAPI;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class DeviceTrustChainAPI extends WebserverAPI {
    public DeviceTrustChainAPI(Main main) {
        super(main, "webauthn");
    }

    @Override
    public String getPath() {
        return "/recipe/webauthn/device/trust-chain";
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        try {
            String userId = InputParser.getQueryParamOrThrowError(req, "userId", false);
            AppIdentifier appIdentifier = getAppIdentifier(req);
            Storage storage = getTenantStorage(req);
            DeviceTrustChain chain = PasskeySyncService.getTrustChain(appIdentifier, storage, userId);

            JsonObject response = new JsonObject();
            response.addProperty("status", "OK");
            response.add("chain", chain.toJson());
            super.sendJsonResponse(200, response, resp);
        } catch (TenantOrAppNotFoundException | StorageQueryException e) {
            throw new ServletException(e);
        } catch (PasskeySyncException e) {
            sendDomainError(resp, e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        JsonObject input = InputParser.parseJsonObjectOrThrowError(req);
        String action = InputParser.parseStringOrThrowError(input, "action", false);
        String userId = InputParser.parseStringOrThrowError(input, "userId", false);

        try {
            AppIdentifier appIdentifier = getAppIdentifier(req);
            Storage storage = getTenantStorage(req);
            DeviceTrustChain chain;

            switch (action) {
                case "GENESIS" -> {
                    String deviceId = InputParser.parseStringOrThrowError(input, "deviceId", false);
                    DeviceKind kind = DeviceKind.fromString(
                            InputParser.parseStringOrThrowError(input, "deviceKind", false));
                    String displayName = InputParser.parseStringOrThrowError(input, "displayName", true);
                    String publicKey = InputParser.parseStringOrThrowError(input, "publicKey", false);
                    String signature = InputParser.parseStringOrThrowError(input, "signature", false);
                    chain = PasskeySyncService.registerGenesisDevice(appIdentifier, storage, userId, deviceId,
                            kind, displayName, publicKey, signature);
                }
                case "ADD" -> {
                    String deviceId = InputParser.parseStringOrThrowError(input, "deviceId", false);
                    DeviceKind kind = DeviceKind.fromString(
                            InputParser.parseStringOrThrowError(input, "deviceKind", false));
                    String displayName = InputParser.parseStringOrThrowError(input, "displayName", true);
                    String publicKey = InputParser.parseStringOrThrowError(input, "publicKey", false);
                    String trustedByDeviceId = InputParser.parseStringOrThrowError(input,
                            "trustedByDeviceId", false);
                    String signature = InputParser.parseStringOrThrowError(input, "signature", false);
                    chain = PasskeySyncService.addTrustedDevice(appIdentifier, storage, userId, deviceId, kind,
                            displayName, publicKey, trustedByDeviceId, signature);
                }
                case "REVOKE" -> {
                    String targetDeviceId = InputParser.parseStringOrThrowError(input,
                            "targetDeviceId", false);
                    String revokedByDeviceId = InputParser.parseStringOrThrowError(input,
                            "revokedByDeviceId", false);
                    String signature = InputParser.parseStringOrThrowError(input, "signature", false);
                    chain = PasskeySyncService.revokeDevice(appIdentifier, storage, userId, targetDeviceId,
                            revokedByDeviceId, signature);
                }
                default -> throw new PasskeySyncException("INVALID_ACTION",
                        "action must be GENESIS, ADD or REVOKE");
            }

            JsonObject response = new JsonObject();
            response.addProperty("status", "OK");
            response.add("chain", chain.toJson());
            super.sendJsonResponse(200, response, resp);
        } catch (PasskeySyncException e) {
            sendDomainError(resp, e);
        } catch (StorageQueryException | StorageTransactionLogicException | TenantOrAppNotFoundException e) {
            throw new ServletException(e);
        }
    }

    private void sendDomainError(HttpServletResponse resp, PasskeySyncException error) throws IOException {
        JsonObject response = new JsonObject();
        response.addProperty("status", error.getCode());
        response.addProperty("reason", error.getMessage());
        super.sendJsonResponse(200, response, resp);
    }
}
