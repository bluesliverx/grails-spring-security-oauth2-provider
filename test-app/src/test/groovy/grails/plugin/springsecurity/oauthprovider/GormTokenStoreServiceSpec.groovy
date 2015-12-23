package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.serialization.DefaultOAuth2AdditionalInformationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.DefaultOAuth2ScopeSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AdditionalInformationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2ScopeSerializer
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import helper.OAuth2RequestFactory
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.AccessToken
import test.oauth2.RefreshToken

@TestFor(GormTokenStoreService)
@Mock([AccessToken, RefreshToken])
class GormTokenStoreServiceSpec extends Specification {

    final String clientId = 'client'

    final String username = 'user'
    final String password = 'password'

    final String tokenValue = 'TEST'
    final String refreshValue = 'REFRESH'

    Map<String, Object> additionalInformation = [additional: 'information']

    String authenticationKey = 'authKey'

    OAuth2Authentication oauth2Authentication = Mock(OAuth2Authentication)
    byte[] serializedAuthentication = [0xf0, 0x0d] as byte[]

    OAuth2Request oauth2Request = OAuth2RequestFactory.createOAuth2Request(clientId: clientId)

    void setup() {
        service.oauth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)
        service.authenticationKeyGenerator = Mock(AuthenticationKeyGenerator)

        service.accessTokenScopeSerializer = new DefaultOAuth2ScopeSerializer()
        service.accessTokenAdditionalInformationSerializer = new DefaultOAuth2AdditionalInformationSerializer()

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
                additionalInformationPropertyName: 'additionalInformation',
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
                expirationPropertyName: 'expiration',
        ]
        SpringSecurityUtils.securityConfig.oauthProvider.refreshTokenLookup = refreshTokenLookup
    }

    private AccessToken createGormAccessToken(Map overrides = [:]) {
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

    private RefreshToken createGormRefreshToken(Map overrides = [:]) {
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
        _   |   'storeRefreshToken'                 |   [new DefaultExpiringOAuth2RefreshToken('token', new Date()), null]
        _   |   'readRefreshToken'                  |   ['token']
        _   |   'readAuthenticationForRefreshToken' |   [new DefaultOAuth2RefreshToken('token')]
        _   |   'removeRefreshToken'                |   [new DefaultOAuth2RefreshToken('token')]
        _   |   'removeRefreshToken'                |   ['token']
    }

    void "read authentication removes access token if deserialization throws"() {
        given:
        def gormAccessToken = createGormAccessToken()
        def oauth2AccessToken = service.createOAuth2AccessToken(gormAccessToken)

        assert AccessToken.findByValue(tokenValue)

        when:
        service.readAuthentication(oauth2AccessToken)

        then:
        !AccessToken.findByValue(tokenValue)

        and:
        1 * service.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    void "read authentication removes refresh token if deserialization throws"() {
        given:
        def gormRefreshToken = createGormRefreshToken()
        def oauth2RefreshToken = service.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        when:
        service.readAuthenticationForRefreshToken(oauth2RefreshToken)

        then:
        !RefreshToken.findByValue(refreshValue)

        and:
        1 * service.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    void "authentication associated with stored access token is not the one provided"() {
        given:
        createGormAccessToken()

        and:
        def anotherAuthentication = Stub(OAuth2Authentication)
        assert anotherAuthentication != oauth2Authentication

        and:
        def differentAuthenticationKey = authenticationKey + 'a'

        when:
        def token = service.getAccessToken(oauth2Authentication)

        then:
        token.value == tokenValue

        and:
        service.authenticationKeyGenerator.extractKey(oauth2Authentication as OAuth2Authentication) >> authenticationKey
        service.authenticationKeyGenerator.extractKey(anotherAuthentication as OAuth2Authentication) >> differentAuthenticationKey

        service.oauth2AuthenticationSerializer.serialize(_) >> serializedAuthentication

        service.readAuthentication(tokenValue) >> anotherAuthentication
        service.removeAccessToken(tokenValue)

        service.storeAccessToken(_, _) >> { OAuth2AccessToken accessToken, OAuth2Authentication auth ->
            assert accessToken.value == tokenValue
            assert auth == oauth2Authentication
        }

        oauth2Authentication.getOAuth2Request() >> oauth2Request
    }
}
