package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2ValidationException
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AdditionalInformationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2ScopeSerializer
import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import helper.OAuth2AuthenticationFactory
import helper.OAuth2RequestFactory
import helper.TokenFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.AccessToken
import test.oauth2.RefreshToken

@Integration
@Rollback
class GormTokenStoreServiceIntegrationSpec extends Specification {

    @Autowired
    GormTokenStoreService gormTokenStoreService

    @Autowired
    OAuth2AuthenticationSerializer oauth2AuthenticationSerializer

    @Autowired
    OAuth2AdditionalInformationSerializer accessTokenAdditionalInformationSerializer

    @Autowired
    OAuth2ScopeSerializer accessTokenScopeSerializer

    @Autowired
    AuthenticationKeyGenerator authenticationKeyGenerator

    OAuth2AuthenticationFactory authenticationFactory
    TokenFactory tokenFactory

    final String clientId = 'client'

    final String username = 'user'
    final String password = 'password'

    final String tokenValue = 'TEST'
    final String refreshValue = 'REFRESH'

    Map<String, Object> additionalInformation = [additional: 'information']

    String authenticationKey

    OAuth2Request oauth2Request
    Authentication userAuthentication

    OAuth2Authentication oauth2Authentication
    byte[] serializedAuthentication

    OAuth2Authentication clientAuthentication
    byte[] serializedClientAuthentication

    void setup() {
        userAuthentication = new TestingAuthenticationToken(username, password)

        oauth2Request = OAuth2RequestFactory.createOAuth2Request(clientId: clientId)
        oauth2Authentication = new OAuth2Authentication(oauth2Request, userAuthentication)

        serializedAuthentication = oauth2AuthenticationSerializer.serialize(oauth2Authentication) as byte[]
        authenticationKey = authenticationKeyGenerator.extractKey(oauth2Authentication)

        clientAuthentication = new OAuth2Authentication(oauth2Request, null)
        serializedClientAuthentication = oauth2AuthenticationSerializer.serialize(clientAuthentication) as byte[]

        tokenFactory = new TokenFactory(
                clientId: clientId,
                tokenValue: tokenValue,
                refreshValue: refreshValue,
                additionalInformation: additionalInformation,
                authenticationKey: authenticationKey,
                serializedAuthentication: serializedAuthentication
        )

        authenticationFactory = new OAuth2AuthenticationFactory(
                oauth2AuthenticationSerializer: oauth2AuthenticationSerializer,
                userAuthentication: userAuthentication
        )
    }

    void "read authentication for access token"() {
        given:
        def gormAccessToken = tokenFactory.createGormAccessToken()
        def oauth2AccessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        expect:
        gormTokenStoreService.readAuthentication(oauth2AccessToken) == oauth2Authentication
    }

    void "store access token for user authentication using use refresh token"() {
        given:
        def oauth2RefreshToken = tokenFactory.createOAuth2RefreshToken(value: refreshValue)
        def oauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: tokenValue, refreshToken: oauth2RefreshToken)

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, oauth2Authentication)

        then:
        def gormToken = AccessToken.findByValue(tokenValue)
        gormToken != null

        and:
        gormToken.authentication == serializedAuthentication
        gormToken.username == username
        gormToken.value == tokenValue
        gormToken.refreshToken == refreshValue
    }

    void "store access token for user authentication without refresh token"() {
        given:
        def oauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: tokenValue)

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, oauth2Authentication)

        then:
        def gormToken = AccessToken.findByValue(tokenValue)
        gormToken != null

        and:
        gormToken.authentication == serializedAuthentication
        gormToken.username == username
        gormToken.value == tokenValue
        gormToken.refreshToken == null
    }

    void "store access token for client only using use refresh token"() {
        given:
        def oauth2RefreshToken = tokenFactory.createOAuth2RefreshToken(value: refreshValue)
        def oauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: tokenValue, refreshToken: oauth2RefreshToken)

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, clientAuthentication)

        then:
        def gormToken = AccessToken.findByValue(tokenValue)
        gormToken != null

        and:
        gormToken.authentication == serializedClientAuthentication
        gormToken.username == null
        gormToken.value == tokenValue
        gormToken.refreshToken == refreshValue
    }

    void "store access token for client only without refresh token"() {
        given:
        def oauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: tokenValue)

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, clientAuthentication)

        then:
        def gormToken = AccessToken.findByValue(tokenValue)
        gormToken != null

        and:
        gormToken.authentication == serializedClientAuthentication
        gormToken.username == null
        gormToken.value == tokenValue
        gormToken.refreshToken == null
    }

    void "store access token should update existing access token"() {
        given:
        def insertOauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: 'INSERT')
        def updateOauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: 'UPDATE')

        when:
        gormTokenStoreService.storeAccessToken(insertOauth2AccessToken, oauth2Authentication)

        then:
        AccessToken.findByValue('INSERT') != null

        when:
        gormTokenStoreService.storeAccessToken(updateOauth2AccessToken, oauth2Authentication)

        then:
        AccessToken.findByValue('UPDATE') != null
        AccessToken.findByValue('INSERT') == null
    }

    void "store access token with no scope"() {
        given:
        def oauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: tokenValue, scope: null)

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, oauth2Authentication)

        then:
        def gormToken = AccessToken.findByValue(tokenValue)
        gormToken != null

        and:
        gormToken.scope.isEmpty()
    }

    void "attempt to store invalid access token"() {
        given:
        OAuth2Authentication largeAuthentication = authenticationFactory.createLargeOAuth2Authentication()

        and:
        def oauth2AccessToken = tokenFactory.createOAuth2AccessToken(value: tokenValue)

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, largeAuthentication)

        then:
        def e = thrown(OAuth2ValidationException)

        e.message.startsWith('Failed to save access token')
        !e.errors.allErrors.empty
    }

    void "read access token that has additional information"() {
        given:
        tokenFactory.createGormAccessToken()

        when:
        def accessToken = gormTokenStoreService.readAccessToken(tokenValue)

        then:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'

        !accessToken.additionalInformation.isEmpty()
        accessToken.additionalInformation == additionalInformation
    }

    void "read access token that has no additional information"() {
        given:
        tokenFactory.createGormAccessToken(additionalInformation: null)

        when:
        def accessToken = gormTokenStoreService.readAccessToken(tokenValue)

        then:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'
        accessToken.additionalInformation.isEmpty()
    }

    void "remove access token"() {
        given:
        def gormAccessToken = tokenFactory.createGormAccessToken()
        def oauth2AccessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        assert AccessToken.findByValue(tokenValue)

        when:
        gormTokenStoreService.removeAccessToken(oauth2AccessToken)

        then:
        !AccessToken.findByValue(tokenValue)
    }

    void "store expiring refresh token"() {
        given:
        def expiration = new Date()
        def oauth2RefreshToken = tokenFactory.createOAuth2RefreshToken(value: refreshValue, expiration: expiration)

        when:
        gormTokenStoreService.storeRefreshToken(oauth2RefreshToken, oauth2Authentication)

        then:
        def gormToken = RefreshToken.findByValue(refreshValue)
        gormToken != null

        and:
        gormToken.value == refreshValue
        gormToken.authentication == serializedAuthentication
        gormToken.expiration == expiration
    }

    void "store unlimited refresh token"() {
        given:
        def oauth2RefreshToken = tokenFactory.createOAuth2RefreshToken(value: refreshValue)

        when:
        gormTokenStoreService.storeRefreshToken(oauth2RefreshToken, oauth2Authentication)

        then:
        def gormToken = RefreshToken.findByValue(refreshValue)
        gormToken != null

        and:
        gormToken.value == refreshValue
        gormToken.authentication == serializedAuthentication
        gormToken.expiration == null
    }

    void "attempt to store invalid refresh token"() {
        given:
        OAuth2Authentication largeAuthentication = authenticationFactory.createLargeOAuth2Authentication()

        and:
        def expiration = new Date()
        def oauth2RefreshToken = tokenFactory.createOAuth2RefreshToken(value: refreshValue, expiration: expiration)

        when:
        gormTokenStoreService.storeRefreshToken(oauth2RefreshToken, largeAuthentication)

        then:
        def e = thrown(OAuth2ValidationException)

        e.message.startsWith('Failed to save refresh token')
        !e.errors.allErrors.empty
    }

    void "read expiring refresh token by value"() {
        given:
        tokenFactory.createGormRefreshToken(expiration: new Date())
        assert RefreshToken.findByValue(refreshValue)

        when:
        def oauth2RefreshToken = gormTokenStoreService.readRefreshToken(refreshValue)

        then:
        oauth2RefreshToken.value == refreshValue
        oauth2RefreshToken instanceof ExpiringOAuth2RefreshToken
    }

    void "read unlimited refresh token by value"() {
        given:
        tokenFactory.createGormRefreshToken(expiration: null)
        assert RefreshToken.findByValue(refreshValue)

        when:
        def oauth2RefreshToken = gormTokenStoreService.readRefreshToken(refreshValue)

        then:
        oauth2RefreshToken.value == refreshValue
        !(oauth2RefreshToken instanceof ExpiringOAuth2RefreshToken)
    }

    void "read access token returns null when token not found"() {
        expect:
        gormTokenStoreService.readAccessToken(tokenValue) == null
    }

    void "return null if refresh token can't be read"() {
        expect:
        gormTokenStoreService.readRefreshToken(refreshValue) == null
    }

    void "return null if token cannot be found by authentication"() {
        expect:
        gormTokenStoreService.getAccessToken(oauth2Authentication) == null
    }

    void "read authentication for refresh token"() {
        given:
        def gormRefreshToken = tokenFactory.createGormRefreshToken()
        def oauth2RefreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        expect:
        gormTokenStoreService.readAuthenticationForRefreshToken(oauth2RefreshToken) == oauth2Authentication
    }

    void "remove refresh token"() {
        given:
        def gormRefreshToken = tokenFactory.createGormRefreshToken()
        def oauth2RefreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        when:
        gormTokenStoreService.removeRefreshToken(oauth2RefreshToken)

        then:
        !RefreshToken.findByValue(refreshValue)
    }

    void "remove access token by using refresh token"() {
        given:
        def oauth2RefreshToken = tokenFactory.createOAuth2RefreshToken(value: refreshValue)

        tokenFactory.createGormAccessToken(refreshToken: refreshValue)
        assert AccessToken.findByValueAndRefreshToken(tokenValue, refreshValue)

        when:
        gormTokenStoreService.removeAccessTokenUsingRefreshToken(oauth2RefreshToken)

        then:
        !AccessToken.findByValue(tokenValue)
    }

    void "get access token by authentication with additional information"() {
        given:
        tokenFactory.createGormAccessToken()

        when:
        def token = gormTokenStoreService.getAccessToken(oauth2Authentication)

        then:
        token.value == tokenValue
        token.additionalInformation == additionalInformation
    }

    void "get access token by authentication that does not have additional information"() {
        given:
        tokenFactory.createGormAccessToken(additionalInformation: null)

        when:
        def token = gormTokenStoreService.getAccessToken(oauth2Authentication)

        then:
        token.value == tokenValue
        token.additionalInformation.isEmpty()
    }

    void "find tokens by clientId or by username returns a collection of OAuth2AccessTokens"() {
        expect:
        gormTokenStoreService.findTokensByClientId('') instanceof Collection<OAuth2AccessToken>
        gormTokenStoreService.findTokensByClientIdAndUserName('', '') instanceof Collection<OAuth2AccessToken>
    }

    void "find tokens by client and username returns empty collection"() {
        expect:
        gormTokenStoreService.findTokensByClientIdAndUserName(clientId, '').empty
        gormTokenStoreService.findTokensByClientIdAndUserName(clientId, 'non-existent').empty
        gormTokenStoreService.findTokensByClientIdAndUserName(clientId, null).empty
    }

    void "find single token by client id and username"() {
        given:
        tokenFactory.createGormAccessToken(clientId: 'client', username: 'user', value: '1234')

        when:
        def tokens = gormTokenStoreService.findTokensByClientIdAndUserName('client', 'user')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by client id and username"() {
        given:
        tokenFactory.createGormAccessToken(clientId: 'client', username: 'user', value: '1234', authenticationKey: authenticationKey + '1')
        tokenFactory.createGormAccessToken(clientId: 'client', username: 'user', value: '5678', authenticationKey: authenticationKey + '2')

        when:
        def tokens = gormTokenStoreService.findTokensByClientIdAndUserName('client', 'user')

        then:
        tokens.size() == 2
        tokens.find { it.value == '1234' }
        tokens.find { it.value == '5678' }
    }

    void "find tokens by clientId returns empty collection"() {
        expect:
        gormTokenStoreService.findTokensByClientId('').empty
        gormTokenStoreService.findTokensByClientId('non-existent').empty
        gormTokenStoreService.findTokensByClientId(null).empty
    }

    void "find single token by clientId"() {
        given:
        tokenFactory.createGormAccessToken(clientId: 'test', value: '1234')

        when:
        def tokens = gormTokenStoreService.findTokensByClientId('test')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by clientId"() {
        given:
        tokenFactory.createGormAccessToken(clientId: 'test', value: '1234', authenticationKey: authenticationKey + '1')
        tokenFactory.createGormAccessToken(clientId: 'test', value: '5678', authenticationKey: authenticationKey + '2')

        when:
        def tokens = gormTokenStoreService.findTokensByClientId('test')

        then:
        tokens.size() == 2
        tokens.find { it.value == '1234' }
        tokens.find { it.value == '5678' }
    }

    void "null token domain class name"() {
        when:
        gormTokenStoreService.getTokenClass('test', null)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified test token domain class 'null' is not a domain class"
    }

    void "test createOAuth2AccessToken with refresh token"() {
        given:
        def gormRefreshToken = tokenFactory.createGormRefreshToken(value: refreshValue)
        def gormAccessToken = tokenFactory.createGormAccessToken(refreshToken: refreshValue)

        when:
        def accessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        then:
        accessToken != null

        and:
        accessToken instanceof OAuth2AccessToken

        and:
        accessToken.refreshToken instanceof ExpiringOAuth2RefreshToken
        accessToken.refreshToken.value == refreshValue
        accessToken.refreshToken.expiration == gormRefreshToken.expiration
    }

    void "test createOAuth2AccessToken without refresh token"() {
        given:
        def gormAccessToken = tokenFactory.createGormAccessToken()

        when:
        def accessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        then:
        accessToken != null

        and:
        accessToken instanceof OAuth2AccessToken

        and:
        accessToken.refreshToken == null
    }

    void "test createOAuth2RefreshToken"() {
        given:
        def gormRefreshToken = tokenFactory.createGormRefreshToken()

        when:
        def refreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        then:
        refreshToken instanceof ExpiringOAuth2RefreshToken

        and:
        refreshToken.value == gormRefreshToken.value
        refreshToken.expiration == gormRefreshToken.expiration
    }
}
