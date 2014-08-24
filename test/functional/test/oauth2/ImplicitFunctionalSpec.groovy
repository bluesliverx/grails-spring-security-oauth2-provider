package test.oauth2

import pages.ConfirmAccessPage
import pages.OAuth2ErrorPage
import pages.RegisteredRedirectPage

import static helper.ErrorDescriptions.*

class ImplicitFunctionalSpec extends AuthorizationEndpointFunctionalSpec {

    Map params = [response_type: 'token', client_id: 'public-client', scope: 'test']

    void "client is not authorized to use implicit flow"() {
        given:
        params.client_id = 'password-only'

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_grant"')
    }

    void "client has no authorized grant types"() {
        given:
        params.client_id = 'no-grant-client'

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_grant"')
    }

    void "invalid client requests implicit without scope"() {
        given:
        params.client_id = 'invalid-client'
        params.remove('scope')

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_client"')
    }

    void "client is authorized for authorization code but not implicit"() {
        given:
        params.client_id = 'authorization-code-only'

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        assertFragmentContainsErrorCodeAndDescription('invalid_client', 'Unauthorized grant type: implicit')
    }

    void "redirect uri is missing and no uri is registered"() {
        given:
        params.client_id = 'no-redirect-uri'

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text() == 'error="invalid_request", error_description="A redirect_uri must be supplied."'
    }

    void "redirect uri does not match the one registered"() {
        given:
        params << [redirect_uri: 'http://somewhere']

        when:
        authorize(params)

        then:
        at OAuth2ErrorPage
        error.text().startsWith('error="invalid_grant", error_description="Invalid redirect: http://somewhere')
    }

    void "invalid scope requested"() {
        given:
        params.client_id = 'implicit-and-scopes'
        params << [scope: 'delete']

        when:
        authorize(params)

        then:
        assertFragmentContainsErrorCodeAndDescription('invalid_scope', 'Invalid scope: delete')
    }

    void "if redirect uri is omitted, use the one that is registered"() {
        when:
        authorize(params)

        then:
        at ConfirmAccessPage
    }

    void "redirect uri matches the registered redirect uri"() {
        given:
        params << [redirect_uri: REDIRECT_URI]

        when:
        authorize(params)

        then:
        at ConfirmAccessPage
    }

    void "successful authorization"() {
        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        at RegisteredRedirectPage

        and:
        assertFragmentContainsAccessTokenAndNoRefreshToken()
    }

    void "successful authorization returns optional scope when identical to requested scope"() {
        given:
        params.client_id = 'implicit-and-scopes'
        params << [scope: 'read']

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        at RegisteredRedirectPage

        and:
        assertFragmentContainsAccessTokenAndScopes([])
    }

    void "must include scope in implicit token request"() {
        given:
        params.remove('scope')

        when:
        authorize(params)

        then:
        at RegisteredRedirectPage

        and:
        assertFragmentContainsErrorCodeAndDescription('invalid_scope', SCOPE_REQUIRED)
    }

    void "state parameter is returned in response"() {
        given:
        params << [state: 'TEST']

        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        authorizeButton.click()

        then:
        at RegisteredRedirectPage

        and:
        assertFragmentContainsAccessTokenAndState('TEST')
    }

    void "user denies authorization"() {
        when:
        authorize(params)

        then:
        at ConfirmAccessPage

        when:
        denyButton.click()

        then:
        assertFragmentContainsErrorCodeAndDescription('access_denied', 'User denied access')
    }
}
