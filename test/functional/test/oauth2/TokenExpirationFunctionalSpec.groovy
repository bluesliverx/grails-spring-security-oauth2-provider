package test.oauth2

import helper.AccessTokenRequest
import helper.GrantTypes

class TokenExpirationFunctionalSpec extends AbstractAccessControlFunctionalSpec {

    static final int AGE_CLIENT_ACCESS_TOKEN_VALIDITY_LENGTH_SECONDS = 21
    static final int AGE_CLIENT_REFRESH_TOKEN_VALIDITY_LENGTH_SECONDS = 41

    void "client access token validity length takes priority over token services access token validity length"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ResourceOwnerCredentials, clientId: 'token-expiration')
        def token = getAccessToken(request)

        and:
        println "Aging access token ${token} for ${AGE_CLIENT_ACCESS_TOKEN_VALIDITY_LENGTH_SECONDS} seconds..."
        sleep(AGE_CLIENT_ACCESS_TOKEN_VALIDITY_LENGTH_SECONDS * 1000)

        when:
        def response = requestRawResponse('securedOAuth2Resources/user', token)

        then:
        response.status == 401
        response.data.error == 'invalid_token'
        response.data.error_description == "Access token expired: $token"
    }

    void "client refresh token validity length takes priority over token services refresh token validity length"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ResourceOwnerCredentials, clientId: 'token-expiration')
        def token = getRefreshToken(request)

        and:
        println "Aging refresh token ${token} for ${AGE_CLIENT_REFRESH_TOKEN_VALIDITY_LENGTH_SECONDS} seconds..."
        sleep(AGE_CLIENT_REFRESH_TOKEN_VALIDITY_LENGTH_SECONDS * 1000)

        and:
        request = new AccessTokenRequest(grantType: GrantTypes.RefreshToken, clientId: 'token-expiration', refreshToken: token)

        when:
        def response = requestRawTokenResponse(request)

        then:
        response.status == 401
        response.data.error == 'invalid_token'
        response.data.error_description == "Invalid refresh token (expired): $token"
    }
}
