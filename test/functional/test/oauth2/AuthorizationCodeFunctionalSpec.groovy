package test.oauth2

import pages.ConfirmAccessPage
import pages.OAuth2ErrorPage
import pages.RegisteredRedirectPage
import spock.lang.Unroll

import static helper.TokenEndpointAssert.*

class AuthorizationCodeFunctionalSpec extends AuthorizationEndpointFunctionalSpec {

    void "client is not authorized to use authorization code flow"() {
        given:
        def params = createAuthorizationEndpointParams('password-only')

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_grant"')
    }

    void "client has no authorized grant types"() {
        given:
        def params = createAuthorizationEndpointParams('no-grant-client')

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text() == 'error="invalid_grant", error_description="A client must have at least one authorized grant type."'
    }

    void "invalid client requests authorization code"() {
        given:
        def params = createAuthorizationEndpointParams('invalid-client')

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_client"')
    }

    void "invalid client requests authorization code without scope"() {
        given:
        def params = createAuthorizationEndpointParams('invalid-client')
        params.remove('scope')

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_client"')
    }

    void "client is authorized for implicit but not authorization code"() {
        given:
        def params = createAuthorizationEndpointParams('implicit-only')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        def tokenEndpointParams = createTokenEndpointParams('implicit-only')
        assertAccessTokenErrorRequest(tokenEndpointParams, 400, 'invalid_grant')
    }

    void "successful authorization for client with refresh token"() {
        given:
        def params = createAuthorizationEndpointParams('public-client')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        def tokenEndpointParams = createTokenEndpointParams('public-client')
        assertAccessTokenAndRefreshTokenRequest(tokenEndpointParams)
    }

    void "successful authorization for client without refresh token"() {
        given:
        def params = createAuthorizationEndpointParams('authorization-code-only')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        def tokenEndpointParams = createTokenEndpointParams('authorization-code-only')
        assertAccessTokenAndNoRefreshTokenRequest(tokenEndpointParams)
    }

    void "state returned when user authorizes client"() {
        given:
        def params = createAuthorizationEndpointParams('public-client', 'TEST-AUTHORIZE')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        assertQueryContainsCodeAndState('TEST-AUTHORIZE')
    }

    void "state returned when user denies client"() {
        given:
        def params = createAuthorizationEndpointParams('public-client', 'TEST-DENY')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        denyButton.click()

        then:
        assertQueryContainsErrorCodeAndDescriptionAndState('access_denied', 'User denied access', 'TEST-DENY')
    }

    void "must include scope in authorization code request"() {
        given:
        def params = createAuthorizationEndpointParams('public-client')
        params.remove('scope')

        when:
        authorize(params)

        then:
        at RegisteredRedirectPage

        and:
        assertQueryContainsErrorCodeAndDescription('invalid_scope', 'Scope must be specified')
    }

    void "ignore scope if included in access token request for authorization code"() {
        given:
        def params = createAuthorizationEndpointParams('public-client')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        def tokenEndpointParams = createTokenEndpointParams('public-client')
        tokenEndpointParams << [scope: 'test']
        assertAccessTokenAndRefreshTokenRequest(tokenEndpointParams)
    }

    void "successful authorization for confidential client"() {
        given:
        def params = createAuthorizationEndpointParams('confidential-client')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        def tokenEndpointParams = createTokenEndpointParams('confidential-client', 'secret-pass-phrase')
        assertAccessTokenAndRefreshTokenRequest(tokenEndpointParams)
    }

    void "confidential client does not include secret in access token request"() {
        given:
        def params = createAuthorizationEndpointParams('confidential-client')

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        def tokenEndpointParams = createTokenEndpointParams('confidential-client')
        assertAccessTokenErrorRequest(tokenEndpointParams, 401, 'invalid_client')
    }

    @Unroll
    void "user denies client [#client] authorization"() {
        given:
        def params = createAuthorizationEndpointParams(client)

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        denyButton.click()

        then:
        assertQueryContainsErrorCodeAndDescription('access_denied', 'User denied access')

        where:
        _   |   client
        _   |   'public-client'
        _   |   'confidential-client'
    }

    private Map createAuthorizationEndpointParams(String clientId, String state = null) {
        def params = [response_type: 'code', client_id: clientId, scope: 'test']
        if(state) {
            params << [state: state]
        }
        return params
    }

    private Map createTokenEndpointParams(String clientId, String clientSecret = null) {
        def params = [grant_type: 'authorization_code', code: code, client_id: clientId]
        if(clientSecret) {
            params << [client_secret: clientSecret]
        }
        return params
    }
}
