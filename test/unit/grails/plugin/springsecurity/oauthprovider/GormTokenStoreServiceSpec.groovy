package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.TestFor
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.AccessToken
import test.oauth2.RefreshToken

@TestFor(GormTokenStoreService)
class GormTokenStoreServiceSpec extends Specification {

    void setup() {
        service.oauth2AuthenticationSerializer = Stub(OAuth2AuthenticationSerializer)
        service.authenticationKeyGenerator = Stub(AuthenticationKeyGenerator)

        SpringSecurityUtils.securityConfig = [oauthProvider: [:]] as ConfigObject

        setAccessTokenClassName(AccessToken.class.name)
        setRefreshTokenClassName(RefreshToken.class.name)
    }

    void cleanup() {
        SpringSecurityUtils.securityConfig = null
    }

    private void setAccessTokenClassName(accessTokenClassName) {
        def accessTokenLookup = [
                className: accessTokenClassName,
                authenticationKeyPropertyName: 'authenticationKey',
                authenticationPropertyName: 'authentication',
                usernamePropertyName: 'username',
                clientIdPropertyName: 'clientId',
                valuePropertyName: 'value',
                tokenTypePropertyName: 'tokenType',
                expirationPropertyName: 'expiration',
                refreshTokenPropertyName: 'refreshToken',
                scopePropertyName: 'scope'
        ]
        SpringSecurityUtils.securityConfig.oauthProvider.accessTokenLookup = accessTokenLookup
    }

    private void setRefreshTokenClassName(refreshTokenClassName) {
        def refreshTokenLookup = [
                className: refreshTokenClassName,
                authenticationPropertyName: 'authentication',
                valuePropertyName: 'value',
        ]
        SpringSecurityUtils.securityConfig.oauthProvider.refreshTokenLookup = refreshTokenLookup
    }

    @Unroll
    void "invalid access token code domain class name for method [#methodName] with args #args"() {
        given:
        setAccessTokenClassName('invalidAccessTokenClass')

        when:
        service."$methodName"(*args)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified access token domain class 'invalidAccessTokenClass' is not a domain class"

        where:
        _   |   methodName                              |   args
        _   |   'readAuthentication'                    |   ['token']
        _   |   'storeAccessToken'                      |   [null, null]
        _   |   'readAccessToken'                       |   ['token']
        _   |   'removeAccessToken'                     |   [new DefaultOAuth2AccessToken('token')]
        _   |   'removeAccessToken'                     |   ['token']
        _   |   'getAccessToken'                        |   [null]
        _   |   'removeAccessTokenUsingRefreshToken'    |   [null]
        _   |   'findTokensByClientIdAndUserName'       |   ['client', 'user']
        _   |   'findTokensByClientId'                  |   ['client']
    }

    @Unroll
    void "invalid refresh token code domain class name for method [#methodName] with args #args"() {
        given:
        setRefreshTokenClassName('invalidRefreshTokenClass')

        when:
        service."$methodName"(*args)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified refresh token domain class 'invalidRefreshTokenClass' is not a domain class"

        where:
        _   |   methodName                          |   args
        _   |   'storeRefreshToken'                 |   [null, null]
        _   |   'readRefreshToken'                  |   ['token']
        _   |   'readAuthenticationForRefreshToken' |   [new DefaultOAuth2RefreshToken('token')]
        _   |   'removeRefreshToken'                |   [new DefaultOAuth2RefreshToken('token')]
        _   |   'removeRefreshToken'                |   ['token']
    }


}
