package test.oauth2

import helper.AccessTokenRequester

import static helper.ErrorDescriptions.*
import static helper.TokenEndpointAssert.assertAccessTokenAndRefreshTokenRequest
import static helper.TokenEndpointAssert.assertAccessTokenErrorRequest

class RefreshTokenFunctionalSpec extends AbstractTokenEndpointFunctionalSpec {

    Map params = [grant_type: 'refresh_token', client_id: 'public-client', scope: 'test']

    Map getRefreshTokenParams = [grant_type: 'password', username: 'user', password: 'test', client_id: 'public-client', scope: 'test']

    void setup() {
        params << [refresh_token: AccessTokenRequester.getRefreshToken(getRefreshTokenParams)]
    }

    void "refresh token with no client"() {
        given:
        params.remove('client_id')

        expect:
        assertAccessTokenErrorRequest(params, 401, 'unauthorized', FULL_AUTHENTICATION_REQUIRED)
    }

    void "invalid refresh token"() {
        given:
        def token = params.refresh_token + 'a'
        params.refresh_token = token

        expect:
        assertAccessTokenErrorRequest(params, 400, 'invalid_grant', invalidRefreshToken(token))
    }

    void "refresh token with client that requested the initial access token"() {
        expect:
        assertAccessTokenAndRefreshTokenRequest(params)
    }

    void "refresh token with different client than the one that requested the initial access token"() {
        given:
        params.client_id = 'no-grant-client'

        expect:
        assertAccessTokenErrorRequest(params, 400, 'invalid_grant', GRANT_TYPE_REQUIRED)
    }

    void "refresh token scopes are restricted to original access token's scope"() {
        given:
        getRefreshTokenParams << [scope: 'write read']
        params.refresh_token = AccessTokenRequester.getRefreshToken(getRefreshTokenParams)

        expect:
        assertAccessTokenErrorRequest(params, 400, 'invalid_scope', unableToNarrowScope('test'))
    }

    void "refresh token returns a new access token"() {
        given:
        def oldAccessToken = AccessTokenRequester.getAccessToken(getRefreshTokenParams)

        when:
        def newAccessToken = AccessTokenRequester.getAccessToken(params)

        then:
        oldAccessToken != newAccessToken
    }
}
