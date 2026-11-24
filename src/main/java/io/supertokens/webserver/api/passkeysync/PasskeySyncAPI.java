package io.supertokens.webserver.api.passkeysync;

import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.passkeysync.PasskeySyncEnvelope;
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

public class PasskeySyncAPI extends WebserverAPI {
    public PasskeySyncAPI(Main main) {
        super(main, "webauthn");
    }

    @Override
    public String getPath() {
        return "/recipe/webauthn/passkey/sync";
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        JsonObject input = InputParser.parseJsonObjectOrThrowError(req);
        String action = InputParser.parseStringOrThrowError(input, "action", false);
        String userId = InputParser.parseStringOrThrowError(input, "userId", false);

        try {
            AppIdentifier appIdentifier = getAppIdentifier(req);
            Storage storage = getTenantStorage(req);
            PasskeySyncEnvelope envelope;

            switch (action) {
                case "CREATE" -> {
                    String sourceDeviceId = InputParser.parseStringOrThrowError(input,
                            "sourceDeviceId", false);
                    String targetDeviceId = InputParser.parseStringOrThrowError(input,
                            "targetDeviceId", false);
                    String credentialId = InputParser.parseStringOrThrowError(input, "credentialId", false);
                    String encryptedPayload = InputParser.parseStringOrThrowError(input,
                            "encryptedPayload", false);
                    Long ttlMillis = InputParser.parseLongOrThrowError(input, "ttlMillis", true);
                    envelope = PasskeySyncService.createSyncEnvelope(main, getTenantIdentifier(req), storage, userId,
                            sourceDeviceId, targetDeviceId, credentialId, encryptedPayload, ttlMillis);
                }
                case "CLAIM" -> {
                    String syncId = InputParser.parseStringOrThrowError(input, "syncId", false);
                    String targetDeviceId = InputParser.parseStringOrThrowError(input,
                            "targetDeviceId", false);
                    envelope = PasskeySyncService.claimSyncEnvelope(appIdentifier, storage, userId, syncId,
                            targetDeviceId);
                }
                default -> throw new PasskeySyncException("INVALID_ACTION",
                        "action must be CREATE or CLAIM");
            }

            JsonObject response = new JsonObject();
            response.addProperty("status", "OK");
            response.add("envelope", envelope.toJson());
            super.sendJsonResponse(200, response, resp);
        } catch (PasskeySyncException e) {
            JsonObject response = new JsonObject();
            response.addProperty("status", e.getCode());
            response.addProperty("reason", e.getMessage());
            super.sendJsonResponse(200, response, resp);
        } catch (StorageQueryException | StorageTransactionLogicException | TenantOrAppNotFoundException e) {
            throw new ServletException(e);
        }
    }
}
