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

package io.supertokens.tenantsession;

import io.supertokens.Main;
import io.supertokens.config.Config;
import io.supertokens.exceptions.UnauthorisedException;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.multitenancy.exceptions.TenantOrAppNotFoundException;
import io.supertokens.session.Session;

// Tenant session isolation recipe. When tenant_session_isolation_enabled is true for an app, session
// management APIs called in a tenant's context can only see and affect that tenant's sessions:
//  - handle-based APIs (get session, session data, JWT data, revoke by handles) reject handles that
//    belong to a different tenant than the one in the request path;
//  - listing sessions for a user is always scoped to the request tenant (fetchAcrossAllTenants is
//    ignored);
//  - revoking sessions for a user is always scoped to the request tenant (revokeAcrossAllTenants is
//    ignored).
// Token-based APIs (verify, refresh, regenerate) are unchanged: the token itself carries the tenant
// and is the authority for those calls. The default (false) keeps the pre-existing cross-tenant
// behaviour, so existing API clients are unaffected.
public class TenantSession {

    public static boolean isIsolationEnabled(TenantIdentifier tenantIdentifier, Main main)
            throws TenantOrAppNotFoundException {
        return Config.getConfig(tenantIdentifier, main).getTenantSessionIsolationEnabled();
    }

    // Throws UnauthorisedException if isolation is enabled and the session handle belongs to a tenant
    // other than the request tenant. A no-op when isolation is disabled.
    public static void enforceSessionHandleInRequestTenant(TenantIdentifier requestTenantIdentifier, Main main,
                                                           String sessionHandle)
            throws TenantOrAppNotFoundException, UnauthorisedException {
        if (!isIsolationEnabled(requestTenantIdentifier, main)) {
            return;
        }
        String handleTenantId = Session.getTenantIdFromSessionHandle(sessionHandle);
        if (handleTenantId == null) {
            handleTenantId = TenantIdentifier.DEFAULT_TENANT_ID;
        }
        if (!handleTenantId.equals(requestTenantIdentifier.getTenantId())) {
            throw new UnauthorisedException("Session belongs to a different tenant");
        }
    }
}
