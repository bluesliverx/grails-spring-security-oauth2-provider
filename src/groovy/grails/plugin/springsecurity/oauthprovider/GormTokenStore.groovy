package grails.plugin.springsecurity.oauthprovider

import groovy.util.logging.Slf4j
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.transaction.annotation.Transactional

@Slf4j
@Transactional
class GormTokenStore implements TokenStore {

    OAuth2AuthenticationSerializer oAuth2AuthenticationSerializer

    @Override
    OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.value)
    }

    @Override
    OAuth2Authentication readAuthentication(String token) {
        OAuth2Authentication authentication = null
        try {
            def gormAccessToken = GormOAuth2AccessToken.findByValue(token)
            def serializedAuthentication = gormAccessToken.authentication
            authentication = oAuth2AuthenticationSerializer.deserialize(serializedAuthentication)
        }
        catch (IllegalArgumentException e) {
            log.warn("Failed to deserialize authentication for access token [$token]")
            removeAccessToken(token)
        }
        return authentication
    }

    @Override
    void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        new GormOAuth2AccessToken(
                authentication: oAuth2AuthenticationSerializer.serialize(authentication),
                username: authentication.isClientOnly() ? null : authentication.name,
                clientId: authentication.authorizationRequest.clientId,
                value: token.value,
                tokenType: token.tokenType,
                expiration: token.expiration,
                scope: token.scope,
                refreshToken: token.refreshToken?.value
        ).save()
    }

    @Override
    OAuth2AccessToken readAccessToken(String tokenValue) {
        GormOAuth2AccessToken.findByValue(tokenValue)?.toAccessToken()
    }

    @Override
    void removeAccessToken(OAuth2AccessToken token) {
        removeAccessToken(token.value)
    }

    void removeAccessToken(String tokenValue) {
        def token = GormOAuth2AccessToken.findByValue(tokenValue)
        token.delete()
    }

    @Override
    void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        new GormOAuth2RefreshToken(
                authentication: oAuth2AuthenticationSerializer.serialize(authentication),
                value: refreshToken.value
        ).save()
    }

    @Override
    OAuth2RefreshToken readRefreshToken(String tokenValue) {
        GormOAuth2RefreshToken.findByValue(tokenValue)?.toRefreshToken()
    }

    @Override
    OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        OAuth2Authentication authentication = null
        String tokenValue = token.value
        try {
            def gormRefreshToken = GormOAuth2RefreshToken.findByValue(tokenValue)
            def serializedAuthentication = gormRefreshToken.authentication
            authentication = oAuth2AuthenticationSerializer.deserialize(serializedAuthentication)
        }
        catch (IllegalArgumentException e) {
            log.warn("Failed to deserialize authentication for refresh token [${tokenValue}]")
            removeRefreshToken(tokenValue)
        }
        return authentication
    }

    @Override
    void removeRefreshToken(OAuth2RefreshToken token) {
        removeRefreshToken(token.value)
    }

    void removeRefreshToken(String tokenValue) {
        def token = GormOAuth2RefreshToken.findByValue(tokenValue)
        token.delete()
    }

    @Override
    void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        def token = GormOAuth2AccessToken.findByRefreshToken(refreshToken.value)
        token.delete()
    }

    @Override
    OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        def serializedAuthentication = oAuth2AuthenticationSerializer.serialize(authentication)
        def token = GormOAuth2AccessToken.findByAuthentication(serializedAuthentication)
        if(!token)
            log.debug("Failed to find access token for authentication [$authentication]")
        return token?.toAccessToken()
    }

    @Override
    Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
        def gormAccessTokens = GormOAuth2AccessToken.findAllByUsername(userName)
        collectAccessTokensFromGormAccessTokens(gormAccessTokens, "username [$userName]")
    }

    @Override
    Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        def gormAccessTokens = GormOAuth2AccessToken.findAllByClientId(clientId)
        collectAccessTokensFromGormAccessTokens(gormAccessTokens, "clientId [$clientId]")
    }

    private static Collection<OAuth2AccessToken> collectAccessTokensFromGormAccessTokens(List<GormOAuth2AccessToken> gormAccessTokens, String searchArg) {
        if(!gormAccessTokens)
            log.debug("Failed to find access tokens for $searchArg")
        gormAccessTokens.collect { it.toAccessToken() } ?: Collections.emptyList()
    }
}
