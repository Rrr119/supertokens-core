/*
 *    Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
 *
 *    This software is licensed under the Apache License, Version 2.0 (the
 *    "License") as published by the Apache Software Foundation.
 *
 *    You may not use this file except in compliance with the License. You may
 *    obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */

package io.supertokens.test.multitenant;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.supertokens.ProcessState;
import io.supertokens.featureflag.EE_FEATURES;
import io.supertokens.featureflag.FeatureFlagTestContent;
import io.supertokens.multitenancy.Multitenancy;
import io.supertokens.pluginInterface.STORAGE_TYPE;
import io.supertokens.pluginInterface.multitenancy.*;
import io.supertokens.storageLayer.StorageLayer;
import io.supertokens.test.TestingProcessManager;
import io.supertokens.test.Utils;
import io.supertokens.test.httpRequest.HttpRequestForTesting;
import io.supertokens.test.httpRequest.HttpResponseException;
import io.supertokens.utils.SemVer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.Rule;

import java.io.IOException;
import java.util.HashMap;

import static org.junit.Assert.*;

/**
 * Tests for tenant_session_isolation_enabled (the tenant session isolation recipe). Covers the three
 * tenant-isolation behaviours: backwards compatibility when the flag is off (default), rejection of
 * cross-tenant handle-based session access when it is on, and tenant scoping of session listing and
 * revocation when it is on.
 */
public class TenantSessionIsolationTest {
    @Rule
    public TestRule watchman = Utils.getOnFailure();

    @Rule
    public TestRule retryFlaky = Utils.retryFlakyTest();

    TestingProcessManager.TestingProcess process;
    TenantIdentifier app;
    TenantIdentifier t1;
    TenantIdentifier t2;

    @AfterClass
    public static void afterTesting() {
        Utils.afterTesting();
    }

    @Before
    public void beforeEach() {
        Utils.reset();
    }

    @After
    public void afterEach() throws InterruptedException {
        if (process != null) {
            process.kill();
            assertNotNull(process.checkOrWaitForEvent(ProcessState.PROCESS_STATE.STOPPED));
        }
    }

    private static TenantConfig tenant(TenantIdentifier id, JsonObject coreConfig) {
        return new TenantConfig(id, new EmailPasswordConfig(true),
                new ThirdPartyConfig(true, new ThirdPartyConfig.Provider[0]),
                new PasswordlessConfig(true), null, null, coreConfig);
    }

    private void startProcessWithTenants(boolean isolationEnabled) throws Exception {
        String[] args = {"../"};

        process = TestingProcessManager.start(args);
        FeatureFlagTestContent.getInstance(process.getProcess())
                .setKeyValue(FeatureFlagTestContent.ENABLED_FEATURES, new EE_FEATURES[]{EE_FEATURES.MULTI_TENANCY});
        process.startProcess();
        assertNotNull(process.checkOrWaitForEvent(ProcessState.PROCESS_STATE.STARTED));

        if (StorageLayer.getStorage(process.getProcess()).getType() != STORAGE_TYPE.SQL) {
            return;
        }

        app = new TenantIdentifier(null, "a1", null);
        t1 = new TenantIdentifier(null, "a1", "t1");
        t2 = new TenantIdentifier(null, "a1", "t2");

        JsonObject appConfig = new JsonObject();
        if (isolationEnabled) {
            appConfig.addProperty("tenant_session_isolation_enabled", true);
        }
        Multitenancy.addNewOrUpdateAppOrTenant(process.getProcess(), new TenantIdentifier(null, null, null),
                tenant(app, appConfig));
        Multitenancy.addNewOrUpdateAppOrTenant(process.getProcess(), app, tenant(t1, new JsonObject()));
        Multitenancy.addNewOrUpdateAppOrTenant(process.getProcess(), app, tenant(t2, new JsonObject()));
    }

    private JsonObject createSession(TenantIdentifier tenantIdentifier, String userId)
            throws HttpResponseException, IOException {
        JsonObject request = new JsonObject();
        request.addProperty("userId", userId);
        request.add("userDataInJWT", new JsonObject());
        request.add("userDataInDatabase", new JsonObject());
        request.addProperty("enableAntiCsrf", false);

        JsonObject response = HttpRequestForTesting.sendJsonPOSTRequest(process.getProcess(), "",
                HttpRequestForTesting.getMultitenantUrl(tenantIdentifier, "/recipe/session"), request,
                1000, 1000, null, SemVer.v3_0.get(), "session");
        assertEquals("OK", response.get("status").getAsString());
        return response.get("session").getAsJsonObject();
    }

    private JsonObject getSessionByHandle(TenantIdentifier tenantIdentifier, String sessionHandle)
            throws HttpResponseException, IOException {
        HashMap<String, String> params = new HashMap<>();
        params.put("sessionHandle", sessionHandle);
        return HttpRequestForTesting.sendGETRequest(process.getProcess(), "",
                HttpRequestForTesting.getMultitenantUrl(tenantIdentifier, "/recipe/session"),
                params, 1000, 1000, null, SemVer.v3_0.get(), "session");
    }

    private JsonArray getSessionHandlesForUser(TenantIdentifier tenantIdentifier, String userId,
                                               boolean fetchAcrossAllTenants)
            throws HttpResponseException, IOException {
        HashMap<String, String> params = new HashMap<>();
        params.put("userId", userId);
        params.put("fetchAcrossAllTenants", String.valueOf(fetchAcrossAllTenants));
        JsonObject response = HttpRequestForTesting.sendGETRequest(process.getProcess(), "",
                HttpRequestForTesting.getMultitenantUrl(tenantIdentifier, "/recipe/session/user"),
                params, 1000, 1000, null, SemVer.v3_0.get(), "session");
        assertEquals("OK", response.get("status").getAsString());
        return response.get("sessionHandles").getAsJsonArray();
    }

    private JsonObject removeSessionsForUser(TenantIdentifier tenantIdentifier, String userId,
                                             boolean revokeAcrossAllTenants)
            throws HttpResponseException, IOException {
        JsonObject request = new JsonObject();
        request.addProperty("userId", userId);
        request.addProperty("revokeAcrossAllTenants", revokeAcrossAllTenants);
        JsonObject response = HttpRequestForTesting.sendJsonPOSTRequest(process.getProcess(), "",
                HttpRequestForTesting.getMultitenantUrl(tenantIdentifier, "/recipe/session/remove"), request,
                1000, 1000, null, SemVer.v3_0.get(), "session");
        assertEquals("OK", response.get("status").getAsString());
        return response;
    }

    private static boolean handlesContain(JsonArray handles, String handle) {
        for (int i = 0; i < handles.size(); i++) {
            if (handles.get(i).getAsString().equals(handle)) {
                return true;
            }
        }
        return false;
    }

    // Compatibility: with the flag unset (default false), the existing cross-tenant behaviour is
    // unchanged - a session can be fetched from another tenant's context, listing spans all tenants of
    // the app, and revoking by userId spans all tenants.
    @Test
    public void isolationDisabledByDefaultPreservesCrossTenantBehaviour() throws Exception {
        startProcessWithTenants(false);
        if (StorageLayer.getStorage(process.getProcess()).getType() != STORAGE_TYPE.SQL) {
            return;
        }

        String handle1 = createSession(t1, "userid").get("handle").getAsString();
        String handle2 = createSession(t2, "userid").get("handle").getAsString();

        // A session created in t1 can be fetched from t2's context.
        JsonObject fetched = getSessionByHandle(t2, handle1);
        assertEquals("OK", fetched.get("status").getAsString());
        assertEquals(handle1, fetched.get("sessionHandle").getAsString());

        // Listing spans all tenants of the app.
        JsonArray handles = getSessionHandlesForUser(t1, "userid", true);
        assertEquals(2, handles.size());
        assertTrue(handlesContain(handles, handle1));
        assertTrue(handlesContain(handles, handle2));

        // Revoking by userId spans all tenants.
        JsonObject removed = removeSessionsForUser(t1, "userid", true);
        assertEquals(2, removed.get("sessionHandlesRevoked").getAsJsonArray().size());
        assertEquals("UNAUTHORISED", getSessionByHandle(t1, handle1).get("status").getAsString());
        assertEquals("UNAUTHORISED", getSessionByHandle(t2, handle2).get("status").getAsString());
    }

    // Isolation on: handle-based session APIs reject handles belonging to a different tenant than the
    // one in the request path, while same-tenant access keeps working.
    @Test
    public void isolationEnabledRejectsCrossTenantHandleAccess() throws Exception {
        startProcessWithTenants(true);
        if (StorageLayer.getStorage(process.getProcess()).getType() != STORAGE_TYPE.SQL) {
            return;
        }

        String handle1 = createSession(t1, "userid").get("handle").getAsString();

        // Same-tenant access works.
        JsonObject fetched = getSessionByHandle(t1, handle1);
        assertEquals("OK", fetched.get("status").getAsString());
        assertEquals(handle1, fetched.get("sessionHandle").getAsString());

        // Cross-tenant fetch is rejected.
        assertEquals("UNAUTHORISED", getSessionByHandle(t2, handle1).get("status").getAsString());

        // Cross-tenant session data write is rejected; same-tenant write works.
        JsonObject updateRequest = new JsonObject();
        updateRequest.addProperty("sessionHandle", handle1);
        updateRequest.add("userDataInDatabase", new JsonObject());

        JsonObject crossTenantUpdate = HttpRequestForTesting.sendJsonPUTRequest(process.getProcess(), "",
                HttpRequestForTesting.getMultitenantUrl(t2, "/recipe/session/data"), updateRequest,
                1000, 1000, null, SemVer.v3_0.get(), "session");
        assertEquals("UNAUTHORISED", crossTenantUpdate.get("status").getAsString());

        JsonObject sameTenantUpdate = HttpRequestForTesting.sendJsonPUTRequest(process.getProcess(), "",
                HttpRequestForTesting.getMultitenantUrl(t1, "/recipe/session/data"), updateRequest,
                1000, 1000, null, SemVer.v3_0.get(), "session");
        assertEquals("OK", sameTenantUpdate.get("status").getAsString());
    }

    // Isolation on: listing sessions for a user is scoped to the request tenant even when
    // fetchAcrossAllTenants=true is passed, revoking by userId only revokes the request tenant's
    // sessions even when revokeAcrossAllTenants=true is passed, and revoking by explicit handles
    // rejects handles from other tenants.
    @Test
    public void isolationEnabledScopesListingAndRevocationToRequestTenant() throws Exception {
        startProcessWithTenants(true);
        if (StorageLayer.getStorage(process.getProcess()).getType() != STORAGE_TYPE.SQL) {
            return;
        }

        String handle1 = createSession(t1, "userid").get("handle").getAsString();
        String handle2 = createSession(t2, "userid").get("handle").getAsString();

        // fetchAcrossAllTenants=true is ignored: only the request tenant's sessions are listed.
        JsonArray handles = getSessionHandlesForUser(t1, "userid", true);
        assertEquals(1, handles.size());
        assertTrue(handlesContain(handles, handle1));

        // Revoking t2's handle from t1's context is rejected with a 400.
        JsonObject removeByHandleRequest = new JsonObject();
        JsonArray handlesToRemove = new JsonArray();
        handlesToRemove.add(handle2);
        removeByHandleRequest.add("sessionHandles", handlesToRemove);
        try {
            HttpRequestForTesting.sendJsonPOSTRequest(process.getProcess(), "",
                    HttpRequestForTesting.getMultitenantUrl(t1, "/recipe/session/remove"), removeByHandleRequest,
                    1000, 1000, null, SemVer.v3_0.get(), "session");
            fail();
        } catch (HttpResponseException e) {
            assertEquals(400, e.statusCode);
        }
        assertEquals("OK", getSessionByHandle(t2, handle2).get("status").getAsString());

        // revokeAcrossAllTenants=true is ignored: only t1's sessions are revoked.
        JsonObject removed = removeSessionsForUser(t1, "userid", true);
        JsonArray revokedHandles = removed.get("sessionHandlesRevoked").getAsJsonArray();
        assertEquals(1, revokedHandles.size());
        assertEquals(handle1, revokedHandles.get(0).getAsString());

        assertEquals("UNAUTHORISED", getSessionByHandle(t1, handle1).get("status").getAsString());
        assertEquals("OK", getSessionByHandle(t2, handle2).get("status").getAsString());
    }
}
