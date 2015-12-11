package test.oauth2

import static helper.ErrorDescriptions.*
import static helper.TokenEndpointAssert.*

class ClientCredentialsFunctionalSpec extends AbstractTokenEndpointFunctionalSpec {

    Map params = [grant_type: 'client_credentials', scope: 'test']

    void "client credentials with no client"() {
        expect:
        assertAccessTokenErrorRequest(params, 401, 'unauthorized', FULL_AUTHENTICATION_REQUIRED)
    }

    void "client credentials request for unauthorized client"() {
        given:
        params << [client_id: 'no-grant-client']

        expect:
        assertAccessTokenErrorRequest(params, 400, 'invalid_grant', GRANT_TYPE_REQUIRED)
    }

    void "client credentials with public client"() {
        given:
        params << [client_id: 'public-client']

        expect:
        assertAccessTokenAndNoRefreshTokenRequest(params)
    }

    void "client credentials with confidential client and no client secret"() {
        given:
        params << [client_id: 'confidential-client']

        expect:
        assertAccessTokenErrorRequest(params, 401, 'invalid_client', BAD_CLIENT_CREDENTIALS)
    }

    void "client credentials with confidential client and incorrect client secret"() {
        given:
        params << [client_id: 'confidential-client', client_secret: 'incorrect']

        expect:
        assertAccessTokenErrorRequest(params, 401, 'invalid_client', BAD_CLIENT_CREDENTIALS)
    }

    void "client credentials with confidential client"() {
        given:
        params << [client_id: 'confidential-client', client_secret: 'secret-pass-phrase']

        expect:
        assertAccessTokenAndNoRefreshTokenRequest(params)
    }

    void "restrict scope of token"() {
        given:
        params << [client_id: 'client-credentials-and-scopes', scope: 'write read']

        expect:
        assertAccessTokenAndScopesRequest(params, ['write', 'read'])
    }
}
