/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.tests.client.policies;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.keycloak.OAuthErrorException;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistration;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.condition.AnyClientConditionFactory;
import org.keycloak.services.clientpolicy.condition.ClientProtocolConditionFactory;
import org.keycloak.services.clientpolicy.executor.SecureRedirectUrisEnforcerExecutor;
import org.keycloak.services.clientpolicy.executor.SecureRedirectUrisEnforcerExecutorFactory;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicyFactory;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.events.Events;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.TestApp;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectTestApp;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.realm.UserConfig;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.page.ErrorPage;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.keycloak.tests.utils.ClientPoliciesUtil.createAnyClientConditionConfig;
import static org.keycloak.tests.utils.ClientPoliciesUtil.createClientProtocolConditionConfig;
import static org.keycloak.tests.utils.ClientPoliciesUtil.createSecureRedirectUrisEnforcerExecutorConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@KeycloakIntegrationTest
public class SecureRedirectUrisEnforcerExecutorTest extends AbstractClientPoliciesTest {

    private static final String CLIENT_NAME = "Zahlungs-App";
    private static final String ERR_MSG_CLIENT_REG_FAIL = "Failed to send request";

    @InjectRealm
    ManagedRealm realm;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectTestApp
    TestApp testApp;

    @InjectUser(config = TestUserConfig.class)
    ManagedUser user;

    @InjectPage
    ErrorPage errorPage;

    @InjectEvents
    Events events;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    private ClientRegistration reg;

    @BeforeEach
    public void setupDynamicClientRegistration() {
        // dynamic registration of the clients used here would otherwise be rejected by the anonymous trusted-host policy
        List<ComponentRepresentation> trustedHostPolicies = realm.admin().components()
                .query(null, ClientRegistrationPolicy.class.getCanonicalName())
                .stream()
                .filter(c -> TrustedHostClientRegistrationPolicyFactory.PROVIDER_ID.equals(c.getProviderId()))
                .toList();
        for (ComponentRepresentation policy : trustedHostPolicies) {
            realm.admin().components().removeComponent(policy.getId());
        }

        reg = ClientRegistration.create().url(keycloakUrls.getBase(), realm.getName()).build();
        ClientInitialAccessPresentation token = realm.admin().clientInitialAccess()
                .create(new ClientInitialAccessCreatePresentation(0, 100));
        reg.auth(Auth.token(token));
    }

    @AfterEach
    public void closeDynamicClientRegistration() throws ClientRegistrationException {
        reg.close();
    }

    @Test
    public void testNotRedirectBasedFlowClient_normalUri() throws Exception {
        setupPolicy(it -> {});

        // The executor's check logic is not executed to an auth code flow or implicit flow disabled client.

        // Registration
        // Success - even if not setting a valid redirect uri
        String clientId;
        String cId = null;
        try {
            clientId = generateSuffixedName(CLIENT_NAME);
            cId = createClientByAdmin(realm, clientId, OIDCLoginProtocol.LOGIN_PROTOCOL, (ClientRepresentation clientRep) -> {
                clientRep.setSecret("secret");
                clientRep.setRedirectUris(List.of("http://oauth.redirect/some")); // normally, a redirect url with http scheme is not allowed.
                clientRep.setStandardFlowEnabled(false);
                clientRep.setImplicitFlowEnabled(false);
                clientRep.setServiceAccountsEnabled(true);
            });
            ClientRepresentation cRep = getClientByAdmin(cId);
            assertEquals(new HashSet<>(List.of("http://oauth.redirect/some")), new HashSet<>(cRep.getRedirectUris()));
        } catch (ClientPolicyException cpe) {
            fail();
        }

        // Update
        // Success - even if not setting a valid redirect uri
        try {
            updateClientByAdmin(realm, cId, (ClientRepresentation clientRep) -> {
                clientRep.setAttributes(new HashMap<>());
                clientRep.setRedirectUris(List.of("")); // empty redirect uris are filtered out before persistence.
            });
            ClientRepresentation cRep = getClientByAdmin(cId);
            assertEquals(Collections.emptySet(), new HashSet<>(cRep.getRedirectUris()));
        } catch (ClientPolicyException cpe) {
            fail();
        }
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_normalUri() throws Exception {
        setupPolicy(it -> {});

        // register - fail
        // no redirect uri is not allowed
        testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(List.of(""));

        // register - fail
        // HTTP scheme not allowed
        testSecureRedirectUrisEnforcerExecutor_failRegisterDynamically(List.of("http://app.example.com:51004/oauth2redirect/example-provider"));

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                Arrays.asList("https://app.example.com:51004/oauth2redirect/example-provider", "https://dev.example.com/redirect"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // IPv4 loopback address not allowed
        testSecureRedirectUrisEnforcerExecutor_failUpdateByAdmin(alphaCid,
                Arrays.asList("https://127.0.0.1:8443", "https://app.example.com:51004/oauth2redirect/example-provider"));

        // update - fail
        // wildcard context path not allowed
        testSecureRedirectUrisEnforcerExecutor_failUpdateDynamically(alphaClientId,
                List.of("https://dev.example.com:8443/*"));

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                Arrays.asList("https://app.example.com:51004/oauth2redirect/example-provider/update", "https://dev.example.com/redirect/update"));

        // authorization request - fail
        // redirect_uri not matched with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "https://app.example.com:51004/oauth2redirect/example-provider");
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_IPv4LoopbackAddress() throws Exception {
        // the test application is served over http on a loopback address, so the http scheme has to be permitted as well
        setupPolicy(it -> {
            it.setAllowIPv4LoopbackAddress(true);
            it.setAllowHttpScheme(true);
        });

        // register - fail
        // IPv6 loopback address not allowed
        testSecureRedirectUrisEnforcerExecutor_failRegisterDynamically(Arrays.asList("https://127.0.0.1/oauth2redirect/example-provider",
                "http://[::1]/oauth2redirect/example-provider"));

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                Arrays.asList("https://app.example.com:51004/oauth2redirect/example-provider",
                        "https://127.0.0.1/oauth2redirect/example-provider"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // private use uri scheme not allowed
        testSecureRedirectUrisEnforcerExecutor_failUpdateByAdmin(alphaCid, List.of("com.example.app:/oauth2redirect/example-provider"));

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                List.of(testApp.getRedirectionUri(), "https://dev.example.com/redirect/update"));

        // authorization request - fail
        // invalid uri form
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "https://keycloak.org\n");

        // authorization request - success
        testSecureRedirectUrisEnforcerExecutor_successAuthorizationRequest(alphaClientId, testApp.getRedirectionUri());
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_IPv6LoopbackAddress() throws Exception {
        setupPolicy(it -> {
            it.setOAuth2_1Compliant(true);
            it.setAllowIPv6LoopbackAddress(true);
        });

        // register - fail
        // IPv4 loopback address not allowed
        testSecureRedirectUrisEnforcerExecutor_failRegisterDynamically(Arrays.asList("https://[::1]/", "https://127.0.0.1/auth/admin"));

        // register - fail
        // IPv4 loopback address not allowed (even when "localhost" is used)
        testSecureRedirectUrisEnforcerExecutor_failRegisterDynamically(Arrays.asList("https://[::1]/", "https://localhost/auth/admin"));

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                Arrays.asList("https://[::1]/oauth2redirect/example-provider", "https://[::1]/"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // representation of IPv6 loopback address [0:0:0:0:0:0:0:1] not allowed with OAuth 2.1 mode enabled
        testSecureRedirectUrisEnforcerExecutor_failUpdateByAdmin(alphaCid, List.of("https://[0:0:0:0:0:0:0:1]/oauth2redirect/example-provider"));

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                List.of("https://[::1]/oauth2redirect/example-provider/update", "https://dev.example.com/redirect/update"));

        // authorization request - fail
        // redirect_uri parameter not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "http://[::1]:65522/oauth2redirect/example-provider");
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_PrivateUseUriScheme() throws Exception {
        setupPolicy(it -> it.setAllowPrivateUseUriScheme(true));

        // register - fail
        // invalid uri form
        testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(List.of("com.example:"));

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                List.of("com.example.app:/oauth2redirect/example-provider",
                        "dev.com.example.app:/oauth2redirect/example-provider/dev"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // HTTP scheme not allowed
        testSecureRedirectUrisEnforcerExecutor_failUpdateDynamically(alphaClientId,
                Arrays.asList("com.example.app:/oauth2redirect/example-provider", "http://dev.example.com/redirect"));

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                Arrays.asList("com.example.app:/oauth2redirect/example-provider/update", "https://dev.example.com/redirect/update"));

        // authorization request - fail
        // redirect_uri not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "com.example.app:/oauth2redirect/example-provider");
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_AllowHttpScheme() throws Exception {
        setupPolicy(it -> {
            it.setAllowIPv4LoopbackAddress(true);
            it.setAllowIPv6LoopbackAddress(true);
            it.setAllowHttpScheme(true);
        });

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                Arrays.asList("http://localhost:8080/redirect", "http://dev.example.com/redirect/update"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                Arrays.asList("http://[::1]:8080/redirect", testApp.getRedirectionUri()));

        // authorization request - fail
        // redirect_uri not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "http://[::1]:8080/");

        // authorization request - success
        testSecureRedirectUrisEnforcerExecutor_successAuthorizationRequest(alphaClientId, testApp.getRedirectionUri());
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_AllowWildcardContextPath() throws Exception {
        setupPolicy(it -> {
            it.setAllowPrivateUseUriScheme(true);
            it.setAllowIPv4LoopbackAddress(true);
            it.setAllowIPv6LoopbackAddress(true);
            it.setAllowHttpScheme(true);
            it.setAllowWildcardContextPath(true);
        });

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                Arrays.asList("http://localhost:8080/*", "http://dev.example.com/redirect/update"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                Arrays.asList("http://[::1]:8080/*", testAppWildcardUri()));

        // authorization request - fail
        // redirect_uri not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "com.example.app:/oauth2redirect/example-provider");

        // authorization request - success
        testSecureRedirectUrisEnforcerExecutor_successAuthorizationRequest(alphaClientId, testApp.getRedirectionUri());
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_AllowPermittedDomains() throws Exception {
        setupPolicy(it -> {
            it.setAllowIPv4LoopbackAddress(true);
            it.setAllowPermittedDomains(Arrays.asList(
                    "oauth.redirect", "((dev|test)-)*example.org", "localhost"));
            it.setAllowHttpScheme(true);
            it.setAllowWildcardContextPath(true);
        });

        // register - fail
        // not match permitted domains
        testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(Arrays.asList("http://oauth.redirect/*", "http://dev.example.org/redirect"));

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                Arrays.asList("http://oauth.redirect/*", "http://dev-example.org/redirect"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // not match permitted domains
        testSecureRedirectUrisEnforcerExecutor_failUpdateDynamically(alphaClientId,
                Arrays.asList("http://dev.oauth.redirect/*", "http://test-example.com/redirect"));

        // update using rootUrl - fail
        try {
            updateClientByAdmin(realm, alphaCid, (ClientRepresentation clientRep) -> {
                clientRep.setAttributes(new HashMap<>());
                clientRep.setRootUrl("http://incorrect.org");
                clientRep.setRedirectUris(List.of("/redirect"));
            });
            fail("Expected to fail when updating clientId " + alphaCid + " with redirectUris: '/redirect'");
        } catch (ClientPolicyException cpe) {
            assertEquals(Errors.INVALID_REQUEST, cpe.getError());
        }

        // update using rootUrl - success
        updateClientByAdmin(realm, alphaCid, (ClientRepresentation clientRep) -> {
            clientRep.setAttributes(new HashMap<>());
            clientRep.setRootUrl("http://dev-example.org");
            clientRep.setRedirectUris(List.of("/redirect"));
        });
        ClientRepresentation cRep = getClientByAdmin(alphaCid);
        assertEquals(List.of("/redirect"), cRep.getRedirectUris());

        // update - success
        // the test application is served from a loopback address, which is validated as a loopback uri and not against the permitted domains
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                Arrays.asList("http://oauth.redirect/*", "http://dev-example.org/redirect", testAppWildcardUri()));

        // authorization request - fail
        // redirect_uri not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "http://dev-example.org/v2/redirect");

        // authorization request - success
        testSecureRedirectUrisEnforcerExecutor_successAuthorizationRequest(alphaClientId, testApp.getRedirectionUri());
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_OAuth2_1Compliant() throws Exception {
        setupPolicy(it -> {
            it.setAllowPrivateUseUriScheme(true);
            it.setAllowIPv4LoopbackAddress(true);
            it.setAllowIPv6LoopbackAddress(true);
            it.setAllowHttpScheme(true);
            it.setOAuth2_1Compliant(true);
        });

        // register - fail
        // IPv4 loopback address with port number not allowed
        testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(Arrays.asList("http://127.0.0.1/auth/admin", "http://127.0.0.1:8080/auth/admin"));

        // register - success
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(List.of("https://127.0.0.1/auth/admin"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // HTTP scheme not allowed
        testSecureRedirectUrisEnforcerExecutor_failUpdateDynamically(alphaClientId,
                List.of("https://127.0.0.1/auth/admin", "http://test-example.com/redirect"));

        // update - success
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                List.of("https://[::1]/auth/admin", "com.example.app:/oauth2redirect/example-provider"));

        // authorization request - fail
        // redirect_uri not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "com.example.app:/oauth3redirect/example-provider");
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_OAuth2_0Compliant() throws Exception {
        // OAuth 2.0 compliant rejects fragments and wildcards
        // but is less strict than OAuth 2.1 (allows localhost, HTTP, single-word schemes)
        setupPolicy(it -> {
            it.setAllowIPv4LoopbackAddress(true);
            it.setAllowIPv6LoopbackAddress(true);
            it.setAllowHttpScheme(true);
            it.setOAuth2_0Compliant(true);
        });

        // register - fail
        // fragment in redirect URI not allowed per RFC 6749
        testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(List.of("https://example.com/callback#fragment"));

        // register - fail
        // wildcard in redirect URI not allowed
        testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(List.of("https://example.com/*"));

        // register - success
        // localhost is still allowed (unlike OAuth 2.1)
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                List.of("http://localhost/auth/admin"));
        String alphaClientId = registerResultList.get(0);
        String alphaCid = registerResultList.get(1);

        // update - fail
        // fragment not allowed
        testSecureRedirectUrisEnforcerExecutor_failUpdateByAdmin(alphaCid,
                List.of("http://localhost/auth/admin#frag"));

        // update - success
        // HTTP scheme and localhost are allowed under OAuth 2.0 (unlike OAuth 2.1)
        testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(alphaCid,
                List.of("http://localhost/auth/redirect", "http://127.0.0.1:8080/callback"));

        // authorization request - fail
        // redirect_uri not match with registered redirect uris
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(alphaClientId, "http://localhost/auth/other");
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_AllowOpenRedirect() throws Exception {
        // Allow open redirect
        setupPolicy(it -> {
            it.setAllowOpenRedirect(true);
            it.setOAuth2_1Compliant(true);
        });

        // register - success
        // open redirect is allowed in any running mode
        testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(List.of(""));
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_postLogoutRedirectUris() throws Exception {
        setupPolicy(it -> it.setAllowPermittedDomains(List.of("oauth.redirect")));

        // Success - register without post-logout redirect uris
        String clientId = testSecureRedirectUrisEnforcerExecutor_successRegisterDynamicallyForUpdate(List.of("https://oauth.redirect/something"));

        // Success - update with post-logout redirect uris as "+"
        updateClientDynamically(reg, clientId, (OIDCClientRepresentation clientRep) -> {
            clientRep.setRedirectUris(List.of("https://oauth.redirect/some"));
            clientRep.setPostLogoutRedirectUris(List.of("+"));
        });
        OIDCClientRepresentation clientRepp = reg.oidc().get(clientId);
        Assertions.assertEquals(List.of("https://oauth.redirect/some"), clientRepp.getRedirectUris());
        Assertions.assertEquals(List.of("https://oauth.redirect/some"), clientRepp.getPostLogoutRedirectUris());

        // Fail - incorrect domain for post-logout redirect uri
        try {
            updateClientDynamically(reg, clientId, (OIDCClientRepresentation clientRep) -> {
                clientRep.setRedirectUris(List.of("https://oauth.redirect/some"));
                clientRep.setPostLogoutRedirectUris(List.of("https://incorrect.domain/some"));
            });
            fail();
        } catch (ClientRegistrationException e) {
            assertEquals(ERR_MSG_CLIENT_REG_FAIL, e.getMessage());
        }

        // Success - update with post-logout redirect uris as "+"
        updateClientDynamically(reg, clientId, (OIDCClientRepresentation clientRep) -> {
            clientRep.setRedirectUris(List.of("https://oauth.redirect/some"));
            clientRep.setPostLogoutRedirectUris(List.of("https://oauth.redirect/some-post-logout"));
        });
        clientRepp = reg.oidc().get(clientId);
        Assertions.assertEquals(List.of("https://oauth.redirect/some"), clientRepp.getRedirectUris());
        Assertions.assertEquals(List.of("https://oauth.redirect/some-post-logout"), clientRepp.getPostLogoutRedirectUris());
    }

    @Test
    public void testSecureRedirectUrisEnforcerExecutor_authorizationRequestWithClientProtocolConditionOidc() throws Exception {
        // Create a client before enabling the policy.
        // The redirect URI is registered, so the standard redirect_uri validation should pass.
        // The error is reported by redirecting back to the client, so the redirect URI has to be reachable.
        List<String> registerResultList = testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(
                List.of(testApp.getRedirectionUri()));
        String alphaClientId = registerResultList.get(0);

        setupPolicy(realm, SecureRedirectUrisEnforcerExecutorFactory.PROVIDER_ID,
                createSecureRedirectUrisEnforcerExecutorConfig(it -> {
                    it.setAllowIPv4LoopbackAddress(true);
                    it.setAllowHttpScheme(false);
                }),
                ClientProtocolConditionFactory.PROVIDER_ID,
                createClientProtocolConditionConfig(OIDCLoginProtocol.LOGIN_PROTOCOL));

        // authorization request - fail
        // The redirect_uri matches the registered redirect URI, but HTTP scheme should be rejected
        // by secure-redirect-uris-enforcer when AUTHORIZATION_REQUEST is enforced.
        testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequestWithRedirectUriToClient(alphaClientId, testApp.getRedirectionUri());
    }

    private void setupPolicy(Consumer<SecureRedirectUrisEnforcerExecutor.Configuration> executorConfig) throws Exception {
        setupPolicy(realm, SecureRedirectUrisEnforcerExecutorFactory.PROVIDER_ID,
                createSecureRedirectUrisEnforcerExecutorConfig(executorConfig),
                AnyClientConditionFactory.PROVIDER_ID, createAnyClientConditionConfig());
    }

    private ClientRepresentation getClientByAdmin(String cId) {
        return realm.admin().clients().get(cId).toRepresentation();
    }

    // The test application is served over http from a loopback address on a random port
    private String testAppWildcardUri() {
        URI redirectionUri = URI.create(testApp.getRedirectionUri());
        return redirectionUri.getScheme() + "://" + redirectionUri.getAuthority() + "/*";
    }

    private void testSecureRedirectUrisEnforcerExecutor_failRegisterByAdmin(List<String> redirectUrisList) {
        try {
            createClientByAdmin(realm, generateSuffixedName(CLIENT_NAME), OIDCLoginProtocol.LOGIN_PROTOCOL, (ClientRepresentation clientRep) -> {
                clientRep.setSecret("secret");
                clientRep.setRedirectUris(redirectUrisList);
            });
            fail();
        } catch (ClientPolicyException cpe) {
            assertEquals(OAuthErrorException.INVALID_REQUEST, cpe.getError());
        }
    }

    private void testSecureRedirectUrisEnforcerExecutor_failRegisterDynamically(List<String> redirectUrisList) {
        try {
            createClientDynamically(realm, reg, generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) ->
                clientRep.setRedirectUris(redirectUrisList));
            fail("Expected to fail with redirectUris: " + redirectUrisList);
        } catch (ClientRegistrationException cre) {
            assertEquals(ERR_MSG_CLIENT_REG_FAIL, cre.getMessage());
        }
    }

    // First item in the list is clientId. Second item is clientUUID (DB entity ID)
    private List<String> testSecureRedirectUrisEnforcerExecutor_successRegisterByAdmin(List<String> redirectUrisList) {
        String alphaClientId = null;
        String alphaCid = null;
        try {
            alphaClientId = generateSuffixedName(CLIENT_NAME);
            alphaCid = createClientByAdmin(realm, alphaClientId, OIDCLoginProtocol.LOGIN_PROTOCOL, (ClientRepresentation clientRep) -> {
                clientRep.setSecret("secret");
                clientRep.setRedirectUris(redirectUrisList);
            });
            ClientRepresentation cRep = getClientByAdmin(alphaCid);
            Set<String> expectedUris = redirectUrisList.stream()
                    .filter(s -> s != null && !s.isBlank())
                    .collect(Collectors.toSet());
            assertEquals(expectedUris, new HashSet<>(cRep.getRedirectUris()));
        } catch (ClientPolicyException cpe) {
            fail();
        }
        return Arrays.asList(alphaClientId, alphaCid);
    }

    // Return clientId (not DB UUID). Unlike createClientDynamically in the base class this keeps the registration
    // access token of the created client, so that the client can be updated dynamically afterwards.
    private String testSecureRedirectUrisEnforcerExecutor_successRegisterDynamicallyForUpdate(List<String> redirectUrisList) {
        try {
            OIDCClientRepresentation clientRep = new OIDCClientRepresentation();
            clientRep.setClientName(generateSuffixedName(CLIENT_NAME));
            clientRep.setRedirectUris(redirectUrisList);

            OIDCClientRepresentation response = reg.oidc().create(clientRep);
            reg.auth(Auth.token(response));

            String clientId = response.getClientId();
            realm.cleanup().add(r -> r.clients().findByClientId(clientId)
                    .forEach(c -> r.clients().get(c.getId()).remove()));
            return clientId;
        } catch (ClientRegistrationException cre) {
            fail("Did not expected to fail when dynamically registering client with redirectUris: " + redirectUrisList);
            // Should not be here
            return null;
        }
    }

    private void testSecureRedirectUrisEnforcerExecutor_failUpdateByAdmin(String cId, List<String> redirectUrisList) {
        try {
            updateClientByAdmin(realm, cId, (ClientRepresentation clientRep) -> {
                clientRep.setAttributes(new HashMap<>());
                clientRep.setRedirectUris(redirectUrisList);
            });
            fail("Expected to fail when updating clientId " + cId + " with redirectUris: " + redirectUrisList);
        } catch (ClientPolicyException cpe) {
            assertEquals(Errors.INVALID_REQUEST, cpe.getError());
        }
    }

    private void testSecureRedirectUrisEnforcerExecutor_failUpdateDynamically(String clientId, List<String> redirectUrisList) {
        try {
            updateClientDynamically(reg, clientId, (OIDCClientRepresentation clientRep) ->
                clientRep.setRedirectUris(redirectUrisList));
            fail();
        } catch (ClientRegistrationException e) {
            assertEquals(ERR_MSG_CLIENT_REG_FAIL, e.getMessage());
        }
    }

    private void testSecureRedirectUrisEnforcerExecutor_successUpdateByAdmin(String cId, List<String> redirectUrisList) {
        try {
            updateClientByAdmin(realm, cId, (ClientRepresentation clientRep) -> {
                clientRep.setAttributes(new HashMap<>());
                clientRep.setRedirectUris(redirectUrisList);
            });
            ClientRepresentation cRep = getClientByAdmin(cId);
            assertEquals(new HashSet<>(redirectUrisList), new HashSet<>(cRep.getRedirectUris()));
        } catch (ClientPolicyException cpe) {
            fail();
        }
    }

    private void testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequest(String clientId, String redirectUri) {
        oauth.client(clientId);
        oauth.redirectUri(redirectUri);
        oauth.openLoginForm();
        errorPage.assertCurrent();
    }

    private void testSecureRedirectUrisEnforcerExecutor_successAuthorizationRequest(String clientId, String redirectUri) {
        oauth.client(clientId, "secret");
        oauth.redirectUri(redirectUri);
        AuthorizationEndpointResponse response = oauth.doLogin(user.getUsername(), user.getPassword());
        Assertions.assertNotNull(response.getCode());
        AccessTokenResponse res = oauth.doAccessTokenRequest(response.getCode());
        assertEquals(200, res.getStatusCode());
        oauth.doLogout(res.getRefreshToken());
    }

    private void testSecureRedirectUrisEnforcerExecutor_failAuthorizationRequestWithRedirectUriToClient(String clientId, String redirectUri) {
        oauth.client(clientId);
        oauth.redirectUri(redirectUri);
        oauth.openLoginForm();
        EventAssertion.assertError(events.poll()).type(EventType.LOGIN_ERROR).error(Errors.INVALID_REQUEST)
                .details(Details.REASON, Details.CLIENT_POLICY_ERROR)
                .details(Details.RESPONSE_TYPE, "code")
                .details(Details.REDIRECT_URI, redirectUri)
                .details(Details.CLIENT_POLICY_ERROR, OAuthErrorException.INVALID_REQUEST);
    }

    private static final class TestUserConfig implements UserConfig {

        @Override
        public UserBuilder configure(UserBuilder user) {
            return user.username("test-user@localhost")
                    .email("test-user@localhost")
                    .password("password")
                    .name("test", "user");
        }
    }
}
