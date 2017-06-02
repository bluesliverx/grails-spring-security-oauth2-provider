package grails.plugin.springsecurity.oauthprovider

import grails.gorm.transactions.Transactional
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2ValidationException
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AdditionalInformationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2ScopeSerializer
import grails.core.GrailsApplication
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator
import org.springframework.security.oauth2.provider.token.TokenStore

@Transactional
class GormTokenStoreService implements TokenStore {

    OAuth2AuthenticationSerializer oauth2AuthenticationSerializer
    AuthenticationKeyGenerator authenticationKeyGenerator

    OAuth2AdditionalInformationSerializer accessTokenAdditionalInformationSerializer
    OAuth2ScopeSerializer accessTokenScopeSerializer

    GrailsApplication grailsApplication

    private static
    final String INVALID_DOMAIN_CLASS_FORMAT = "The specified %s token domain class '%s' is not a domain class"

    @Override
    OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.value)
    }

    @Override
    OAuth2Authentication readAuthentication(String token) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()
        OAuth2Authentication authentication = null
        try {
            def valuePropertyName = accessTokenLookup.valuePropertyName
            def authenticationPropertyName = accessTokenLookup.authenticationPropertyName

            def gormAccessToken = GormAccessToken.findWhere((valuePropertyName): token)

            if(gormAccessToken) {
                def serializedAuthentication = gormAccessToken."$authenticationPropertyName"
                authentication = oauth2AuthenticationSerializer.deserialize(serializedAuthentication)
            }
        }
        catch (IllegalArgumentException e) {
            checkForDomainConfigurationRelatedException(e, 'access', accessTokenLookup.className)

            log.warn("Failed to deserialize authentication for access token")
            removeAccessToken(token)
        }
        return authentication
    }

    @Override
    void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def authenticationKeyPropertyName = accessTokenLookup.authenticationKeyPropertyName
        def authenticationPropertyName = accessTokenLookup.authenticationPropertyName
        def usernamePropertyName = accessTokenLookup.usernamePropertyName
        def clientIdPropertyName = accessTokenLookup.clientIdPropertyName
        def valuePropertyName = accessTokenLookup.valuePropertyName
        def tokenTypePropertyName = accessTokenLookup.tokenTypePropertyName
        def expirationPropertyName = accessTokenLookup.expirationPropertyName
        def refreshTokenPropertyName = accessTokenLookup.refreshTokenPropertyName
        def scopePropertyName = accessTokenLookup.scopePropertyName
        def additionalInformationPropertyName = accessTokenLookup.additionalInformationPropertyName

        def authenticationKey = authenticationKeyGenerator.extractKey(authentication)
        def gormAccessToken = GormAccessToken.findWhere((authenticationKeyPropertyName): authenticationKey) ?: GormAccessToken.newInstance()

        gormAccessToken."$authenticationKeyPropertyName" = authenticationKey
        gormAccessToken."$authenticationPropertyName" = oauth2AuthenticationSerializer.serialize(authentication)
        gormAccessToken."$usernamePropertyName" = authentication.isClientOnly() ? null : authentication.name
        gormAccessToken."$clientIdPropertyName" = authentication.getOAuth2Request().clientId
        gormAccessToken."$valuePropertyName" = token.value
        gormAccessToken."$tokenTypePropertyName" = token.tokenType
        gormAccessToken."$expirationPropertyName" = token.expiration
        gormAccessToken."$refreshTokenPropertyName" = token.refreshToken?.value
        gormAccessToken."$scopePropertyName" = accessTokenScopeSerializer.serialize(token.scope ?: [] as Set)
        gormAccessToken."$additionalInformationPropertyName" = accessTokenAdditionalInformationSerializer.serialize(token.additionalInformation ?: [:])

        if(!gormAccessToken.save()) {
            throw new OAuth2ValidationException("Failed to save access token", gormAccessToken.errors)
        }
    }

    @Override
    OAuth2AccessToken readAccessToken(String tokenValue) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def valuePropertyName = accessTokenLookup.valuePropertyName
        def gormAccessToken = GormAccessToken.findWhere((valuePropertyName): tokenValue)

        if (!gormAccessToken) {
            log.debug("Failed to find access token")
            return null
        }
        createOAuth2AccessToken(gormAccessToken)
    }

    @Override
    void removeAccessToken(OAuth2AccessToken token) {
        removeAccessToken(token.value)
    }

    void removeAccessToken(String tokenValue) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def valuePropertyName = accessTokenLookup.valuePropertyName
        def gormAccessToken = GormAccessToken.findWhere((valuePropertyName): tokenValue)

        gormAccessToken?.delete()
    }

    @Override
    void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        def (refreshTokenLookup, GormRefreshToken) = getRefreshTokenLookupAndClass()

        def authenticationPropertyName = refreshTokenLookup.authenticationPropertyName
        def valuePropertyName = refreshTokenLookup.valuePropertyName

        def ctorArgs = [
                (authenticationPropertyName): oauth2AuthenticationSerializer.serialize(authentication),
                (valuePropertyName): refreshToken.value,
        ]

        if(refreshToken instanceof ExpiringOAuth2RefreshToken) {
            def expirationPropertyName = refreshTokenLookup.expirationPropertyName
            ctorArgs << [(expirationPropertyName): refreshToken.expiration]
        }

        def gormRefreshToken = GormRefreshToken.newInstance(ctorArgs)
        if(!gormRefreshToken.save()) {
            throw new OAuth2ValidationException("Failed to save refresh token", gormRefreshToken.errors)
        }
    }

    @Override
    OAuth2RefreshToken readRefreshToken(String tokenValue) {
        def (refreshTokenLookup, GormRefreshToken) = getRefreshTokenLookupAndClass()

        def valuePropertyName = refreshTokenLookup.valuePropertyName
        def gormRefreshToken = GormRefreshToken.findWhere((valuePropertyName): tokenValue)

        createOAuth2RefreshToken(gormRefreshToken)
    }

    @Override
    OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        def (refreshTokenLookup, GormRefreshToken) = getRefreshTokenLookupAndClass()

        OAuth2Authentication authentication = null
        String tokenValue = token.value

        try {
            def valuePropertyName = refreshTokenLookup.valuePropertyName
            def authenticationPropertyName = refreshTokenLookup.authenticationPropertyName

            def gormRefreshToken = GormRefreshToken.findWhere((valuePropertyName): tokenValue)
            def serializedAuthentication = gormRefreshToken."$authenticationPropertyName"

            authentication = oauth2AuthenticationSerializer.deserialize(serializedAuthentication)
        }
        catch (IllegalArgumentException e) {
            checkForDomainConfigurationRelatedException(e, 'refresh', refreshTokenLookup.className)

            log.warn("Failed to deserialize authentication for refresh token")
            removeRefreshToken(tokenValue)
        }
        return authentication
    }

    @Override
    void removeRefreshToken(OAuth2RefreshToken token) {
        removeRefreshToken(token.value)
    }

    void removeRefreshToken(String tokenValue) {
        def (refreshTokenLookup, GormRefreshToken) = getRefreshTokenLookupAndClass()

        def valuePropertyName = refreshTokenLookup.valuePropertyName
        def gormRefreshToken = GormRefreshToken.findWhere((valuePropertyName): tokenValue)

        gormRefreshToken?.delete()
    }

    @Override
    void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def refreshTokenPropertyName = accessTokenLookup.refreshTokenPropertyName
        def gormAccessToken = GormAccessToken.findWhere((refreshTokenPropertyName): refreshToken.value)

        gormAccessToken?.delete()
    }

    @Override
    OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        def authenticationKey = authenticationKeyGenerator.extractKey(authentication)
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def authenticationKeyPropertyName = accessTokenLookup.authenticationKeyPropertyName
        def gormAccessToken = GormAccessToken.findWhere((authenticationKeyPropertyName): authenticationKey)

        if (!gormAccessToken) {
            log.debug("Failed to find access token for authentication [$authentication]")
            return null
        }

        def accessToken = createOAuth2AccessToken(gormAccessToken)
        def tokenValue = accessToken.value

        if(authenticationKey != getAuthenticationKeyFromAccessToken(tokenValue)) {
            log.warn("Authentication [$authentication] is not associated with retrieved access token")
            removeAccessToken(tokenValue)
            storeAccessToken(accessToken, authentication)
        }
        return accessToken
    }

    private String getAuthenticationKeyFromAccessToken(String token) {
        def authentication = readAuthentication(token)
        return authenticationKeyGenerator.extractKey(authentication)
    }

    @Override
    Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def clientIdPropertyName = accessTokenLookup.clientIdPropertyName
        def usernamePropertyName = accessTokenLookup.usernamePropertyName
        def gormAccessTokens = GormAccessToken.findAllWhere((clientIdPropertyName): clientId, (usernamePropertyName): userName)

        collectAccessTokensFromGormAccessTokens(gormAccessTokens, "clientId [$clientId], username [$userName]")
    }

    @Override
    Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        def (accessTokenLookup, GormAccessToken) = getAccessTokenLookupAndClass()

        def clientIdPropertyName = accessTokenLookup.clientIdPropertyName
        def gormAccessTokens = GormAccessToken.findAllWhere((clientIdPropertyName): clientId)

        collectAccessTokensFromGormAccessTokens(gormAccessTokens, "clientId [$clientId]")
    }

    private Collection<OAuth2AccessToken> collectAccessTokensFromGormAccessTokens(gormAccessTokens, String searchArg) {
        if (!gormAccessTokens) {
            log.debug("Failed to find access tokens for $searchArg")
        }
        gormAccessTokens.collect { createOAuth2AccessToken(it) } ?: Collections.emptyList()
    }

    OAuth2AccessToken createOAuth2AccessToken(gormAccessToken) {
        def accessTokenLookup = getAccessTokenLookupAndClass()[0] as Map

        def valuePropertyName = accessTokenLookup.valuePropertyName
        def tokenTypePropertyName = accessTokenLookup.tokenTypePropertyName
        def expirationPropertyName = accessTokenLookup.expirationPropertyName
        def refreshTokenPropertyName = accessTokenLookup.refreshTokenPropertyName
        def scopePropertyName = accessTokenLookup.scopePropertyName
        def additionalInformationPropertyName = accessTokenLookup.additionalInformationPropertyName

        def token = new DefaultOAuth2AccessToken(gormAccessToken."$valuePropertyName")
        token.refreshToken = createRefreshTokenForAccessToken(gormAccessToken, refreshTokenPropertyName)
        token.tokenType = gormAccessToken."$tokenTypePropertyName"
        token.expiration = gormAccessToken."$expirationPropertyName"

        def serializedScopes = gormAccessToken."$scopePropertyName"
        token.scope = serializedScopes ? accessTokenScopeSerializer.deserialize(serializedScopes) : [] as Set

        def serializedAdditionalInformation = gormAccessToken."$additionalInformationPropertyName"
        token.additionalInformation = serializedAdditionalInformation ? accessTokenAdditionalInformationSerializer.deserialize(serializedAdditionalInformation) : [:]

        return token
    }

    OAuth2RefreshToken createRefreshTokenForAccessToken(gormAccessToken, refreshTokenPropertyName) {

        if (gormAccessToken?."$refreshTokenPropertyName") {
            def (refreshTokenLookup, GormRefreshToken) = getRefreshTokenLookupAndClass()

            def refreshValue = gormAccessToken."$refreshTokenPropertyName"
            def refreshValuePropertyName = refreshTokenLookup.valuePropertyName

            def gormRefreshToken = GormRefreshToken.findWhere((refreshValuePropertyName): refreshValue)
            return createOAuth2RefreshToken(gormRefreshToken)
        } else {
            return null
        }
    }

    OAuth2RefreshToken createOAuth2RefreshToken(gormRefreshToken) {
        def refreshTokenLookup = SpringSecurityUtils.securityConfig.oauthProvider.refreshTokenLookup

        def valuePropertyName = refreshTokenLookup.valuePropertyName
        def expirationPropertyName = refreshTokenLookup.expirationPropertyName

        def value = gormRefreshToken?."$valuePropertyName"
        def expiration = gormRefreshToken?."$expirationPropertyName"

        def refreshToken = null

        if(value && expiration) {
            refreshToken = new DefaultExpiringOAuth2RefreshToken(value, expiration)
        }
        else if(value) {
            refreshToken = new DefaultOAuth2RefreshToken(value)
        }

        return refreshToken
    }

    private def getAccessTokenLookupAndClass() {
        def accessTokenLookup = SpringSecurityUtils.securityConfig.oauthProvider.accessTokenLookup
        def GormAccessToken = getAccessTokenClass(accessTokenLookup.className)
        [accessTokenLookup, GormAccessToken]
    }

    private def getRefreshTokenLookupAndClass() {
        def refreshTokenLookup = SpringSecurityUtils.securityConfig.oauthProvider.refreshTokenLookup
        Class GormRefreshToken = getRefreshTokenClass(refreshTokenLookup.className)
        [refreshTokenLookup, GormRefreshToken]
    }

    private Class getAccessTokenClass(String accessTokenClassName) {
        getTokenClass('access', accessTokenClassName)
    }

    private Class getRefreshTokenClass(String refreshTokenClassName) {
        getTokenClass('refresh', refreshTokenClassName)
    }

    private Class getTokenClass(String tokenType, String className) {
        def tokenClass = className ? grailsApplication.getDomainClass(className) : null
        if (!tokenClass) {
            def message = String.format(INVALID_DOMAIN_CLASS_FORMAT, tokenType, className)
            throw new IllegalArgumentException(message)
        }
        return tokenClass.clazz
    }

    private void checkForDomainConfigurationRelatedException(IllegalArgumentException e, String tokenType, String className) {
        def invalidDomainMessage = String.format(INVALID_DOMAIN_CLASS_FORMAT, tokenType, className)
        if (e.message == invalidDomainMessage) {
            throw e
        }
    }
}
