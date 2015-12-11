package helper

import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import test.oauth2.AccessToken
import test.oauth2.RefreshToken

class TokenFactory {

    String clientId

    String tokenValue
    String refreshValue

    Map<String, Object> additionalInformation

    String authenticationKey
    byte[] serializedAuthentication

    AccessToken createGormAccessToken(Map overrides = [:]) {
        def token = new AccessToken(
                value: tokenValue,
                tokenType: 'bearer',
                clientId: clientId,
                scope: ['test'],
                expiration: new Date(),
                authenticationKey: authenticationKey,
                authentication: serializedAuthentication,
                additionalInformation: additionalInformation
        )
        addOverrides(token, overrides)
        token.save(failOnError: true)
    }

    RefreshToken createGormRefreshToken(Map overrides = [:]) {
        def token = new RefreshToken(
                value: refreshValue,
                expiration: new Date(),
                authentication: serializedAuthentication)
        addOverrides(token, overrides)
        token.save(failOnError: true)
    }

    private void addOverrides(Object token, Map overrides) {
        overrides.each { key, value ->
            token."$key" = value
        }
    }

    OAuth2AccessToken createOAuth2AccessToken(Map args = [:]) {
        def accessToken = new DefaultOAuth2AccessToken(args?.value as String)
        accessToken.scope = args?.scope
        accessToken.refreshToken = args?.refreshToken
        accessToken.tokenType = 'bearer'
        accessToken.expiration = args?.expiration ?: new Date()
        accessToken.additionalInformation = args?.additionalInformation ?: [:]
        return accessToken
    }

    OAuth2RefreshToken createOAuth2RefreshToken(Map args = [:]) {
        String value = args?.value
        Date expiration = args?.expiration
        return expiration ? new DefaultExpiringOAuth2RefreshToken(value, expiration) : new DefaultOAuth2RefreshToken(value)
    }
}
