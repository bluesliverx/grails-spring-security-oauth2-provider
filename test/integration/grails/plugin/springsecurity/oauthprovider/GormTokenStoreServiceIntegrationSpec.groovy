package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2ValidationException
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AdditionalInformationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2ScopeSerializer
import grails.test.spock.IntegrationSpec
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator
import spock.lang.Unroll
import test.oauth2.AccessToken
import test.oauth2.Client
import test.oauth2.RefreshToken

class GormTokenStoreServiceIntegrationSpec extends IntegrationSpec {

    GormTokenStoreService tokenStore
    GrailsApplication grailsApplication

    OAuth2AdditionalInformationSerializer accessTokenAdditionalInformationSerializer
    OAuth2ScopeSerializer accessTokenScopeSerializer

    String tokenValue
    String refreshValue

    String authenticationKey
    Map<String, Object> additionalInformation

    OAuth2Authentication oAuth2Authentication
    byte[] serializedAuthentication

    Client client

    OAuth2AuthenticationSerializer originalSerializer
    AuthenticationKeyGenerator originalKeyGenerator

    OAuth2AdditionalInformationSerializer originalAccessTokenAdditionalInformationSerializer
    OAuth2ScopeSerializer originalAccessTokenScopeSerializer

    void setup() {
        originalSerializer = tokenStore.oauth2AuthenticationSerializer
        originalKeyGenerator = tokenStore.authenticationKeyGenerator

        originalAccessTokenAdditionalInformationSerializer = tokenStore.accessTokenAdditionalInformationSerializer
        originalAccessTokenScopeSerializer = tokenStore.accessTokenScopeSerializer

        mockServiceCollaborators(tokenStore)

        oAuth2Authentication = Stub(OAuth2Authentication)
        serializedAuthentication = [0x13, 0x37]
        authenticationKey = 'serializedAuthenticationKey'

        tokenValue = 'TEST'
        refreshValue = 'REFRESH'

        additionalInformation = [additional: 'information']

        client = new Client(clientId: 'test').save()
    }

    private void mockServiceCollaborators(GormTokenStoreService service) {
        service.oauth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)
        service.authenticationKeyGenerator = Mock(AuthenticationKeyGenerator)
    }

    void cleanup() {
        tokenStore.oauth2AuthenticationSerializer = originalSerializer
        tokenStore.authenticationKeyGenerator = originalKeyGenerator

        tokenStore.accessTokenAdditionalInformationSerializer = originalAccessTokenAdditionalInformationSerializer
        tokenStore.accessTokenScopeSerializer = originalAccessTokenScopeSerializer
    }

    private void expectAuthenticationKeyExtraction() {
        tokenStore.authenticationKeyGenerator.extractKey(oAuth2Authentication as OAuth2Authentication) >> authenticationKey
    }

    private void expectAuthenticationSerialization() {
        tokenStore.oauth2AuthenticationSerializer.serialize(oAuth2Authentication as OAuth2Authentication) >> serializedAuthentication
    }

    private void expectAuthenticationDeserialization() {
        tokenStore.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> oAuth2Authentication
    }

    private AccessToken createGormAccessToken(Map overrides = [:]) {
        def token = new AccessToken(
                value: tokenValue,
                tokenType: 'bearer',
                clientId: client.clientId,
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

    void "read authentication for access token"() {
        given:
        expectAuthenticationDeserialization()

        def gormAccessToken = createGormAccessToken()
        def oauth2AccessToken = tokenStore.createOAuth2AccessToken(gormAccessToken)

        expect:
        tokenStore.readAuthentication(oauth2AccessToken) == oAuth2Authentication
    }

    void "read authentication removes access token if deserialization throws"() {
        given:
        def gormAccessToken = createGormAccessToken()
        def oauth2AccessToken = tokenStore.createOAuth2AccessToken(gormAccessToken)

        assert AccessToken.findByValue(tokenValue)

        when:
        tokenStore.readAuthentication(oauth2AccessToken)

        then:
        !AccessToken.findByValue(tokenValue)

        and:
        1 * tokenStore.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    @Unroll
    void "store access token -- use refresh token? [#useRefreshToken] -- is client only? [#isClientOnly]"() {
        given:
        expectAuthenticationSerialization()
        expectAuthenticationKeyExtraction()

        and:
        def expiration = new Date()
        def scope = ['read'] as Set<String>

        def oauth2RefreshToken = Stub(OAuth2RefreshToken) {
            getValue() >> 'REFRESH'
        }

        def oauth2AccessToken = Stub(OAuth2AccessToken) {
            getScope() >> scope
            getRefreshToken() >> { useRefreshToken ? oauth2RefreshToken : null }
            getTokenType() >> 'bearer'
            getValue() >> 'TEST'
            getExpiration() >> expiration
            getAdditionalInformation() >> [foo: 'bar']
        }

        def oauth2Request = new OAuth2Request(null, 'testClient', null, false, null, null, null, null, null)

        oAuth2Authentication.getName() >> username
        oAuth2Authentication.getOAuth2Request() >> oauth2Request
        oAuth2Authentication.isClientOnly() >> isClientOnly

        expect:
        oauth2Request.clientId == 'testClient'

        when:
        tokenStore.storeAccessToken(oauth2AccessToken, oAuth2Authentication)

        then:
        def gormToken = AccessToken.findByValue('TEST')
        gormToken != null

        and:
        gormToken.authentication == serializedAuthentication
        gormToken.username == expectedUsername
        gormToken.clientId == 'testClient'
        gormToken.value == 'TEST'
        gormToken.tokenType == 'bearer'
        gormToken.expiration == expiration
        gormToken.scope.size() == 1
        gormToken.scope.contains('read')
        gormToken.refreshToken == expectedRefreshToken
        gormToken.additionalInformation.foo == 'bar'

        where:
        username    |   expectedUsername    |   isClientOnly    |   useRefreshToken |   refreshToken    |   expectedRefreshToken
        'testUser'  |   'testUser'          |   false           |   false           |   'IGNORE'        |   null
        'testUser'  |   null                |   true            |   false           |   'IGNORE'        |   null
        'testUser'  |   'testUser'          |   false           |   true            |   'REFRESH'       |   'REFRESH'
        'testUser'  |   null                |   true            |   true            |   'REFRESH'       |   'REFRESH'
    }

    void "store access token should update existing access token"() {
        given:
        expectAuthenticationSerialization()
        expectAuthenticationKeyExtraction()

        and:
        def expiration = new Date()
        def scope = ['read'] as Set<String>

        def oauth2RefreshToken = Stub(OAuth2RefreshToken) {
            getValue() >> 'REFRESH'
        }

        def insertOauth2AccessToken = Stub(OAuth2AccessToken) {
            getScope() >> scope
            getRefreshToken() >> oauth2RefreshToken
            getTokenType() >> 'bearer'
            getValue() >> 'INSERT'
            getExpiration() >> expiration
            getAdditionalInformation() >> [foo: 'bar']
        }

        def updateOauth2AccessToken = Stub(OAuth2AccessToken) {
            getScope() >> scope
            getRefreshToken() >> oauth2RefreshToken
            getTokenType() >> 'bearer'
            getValue() >> 'UPDATE'
            getExpiration() >> expiration
            getAdditionalInformation() >> [foo: 'bar']
        }

        def oauth2Request = new OAuth2Request(null, 'testClient', null, false, null, null, null, null, null)

        oAuth2Authentication.getName() >> 'testUser'
        oAuth2Authentication.getOAuth2Request() >> oauth2Request
        oAuth2Authentication.isClientOnly() >> false

        when:
        tokenStore.storeAccessToken(insertOauth2AccessToken, oAuth2Authentication)

        then:
        def insertedGormToken = AccessToken.findByValue('INSERT')
        insertedGormToken != null

        when:
        tokenStore.storeAccessToken(updateOauth2AccessToken, oAuth2Authentication)

        then:
        def gormToken = AccessToken.findByValue('UPDATE')
        gormToken != null
    }

    void "store access token with no additional information and no scope"() {
        given:
        expectAuthenticationSerialization()
        expectAuthenticationKeyExtraction()

        and:
        def oAuth2AccessToken = Stub(OAuth2AccessToken) {
            getScope() >> null
            getRefreshToken() >> null
            getTokenType() >> 'bearer'
            getValue() >> 'TEST'
            getExpiration() >> new Date()
            getAdditionalInformation() >> null
        }

        def oauth2Request = new OAuth2Request(null, 'testClient', null, false, null, null, null, null, null)

        oAuth2Authentication.getName() >> 'testUser'
        oAuth2Authentication.getOAuth2Request() >> oauth2Request
        oAuth2Authentication.isClientOnly() >> false

        when:
        tokenStore.storeAccessToken(oAuth2AccessToken, oAuth2Authentication)

        then:
        def gormToken = AccessToken.findByValue('TEST')
        gormToken != null

        and:
        gormToken.additionalInformation.isEmpty()
        gormToken.scope.isEmpty()
    }

    void "attempt to store invalid access token"() {
        given:
        final maxSize = 1024 * 4
        serializedAuthentication = new byte[maxSize + 1]

        expectAuthenticationSerialization()
        expectAuthenticationKeyExtraction()

        and:
        def expiration = new Date()
        def scope = ['read'] as Set<String>

        def oauth2AccessToken = Stub(OAuth2AccessToken) {
            getScope() >> scope
            getRefreshToken() >> null
            getTokenType() >> 'bearer'
            getValue() >> 'TEST'
            getExpiration() >> expiration
            getAdditionalInformation() >> [foo: 'bar']
        }

        def oauth2Request = new OAuth2Request(null, 'testClient', null, false, null, null, null, null, null)

        oAuth2Authentication.getName() >> 'testUser'
        oAuth2Authentication.getOAuth2Request() >> oauth2Request
        oAuth2Authentication.isClientOnly() >> false

        expect:
        oauth2Request.clientId == 'testClient'

        when:
        tokenStore.storeAccessToken(oauth2AccessToken, oAuth2Authentication)

        then:
        def e = thrown(OAuth2ValidationException)

        e.message.startsWith('Failed to save access token')
        !e.errors.allErrors.empty
    }

    void "read access token that has additional information"() {
        given:
        createGormAccessToken()

        when:
        def accessToken = tokenStore.readAccessToken(tokenValue)

        then:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'
        accessToken.additionalInformation.additional == 'information'
    }

    void "read access token that has no additional information"() {
        given:
        createGormAccessToken(additionalInformation: null)

        when:
        def accessToken = tokenStore.readAccessToken(tokenValue)

        then:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'
        accessToken.additionalInformation.isEmpty()
    }

    void "remove access token"() {
        given:
        def gormAccessToken = createGormAccessToken()
        def oauth2AccessToken = tokenStore.createOAuth2AccessToken(gormAccessToken)

        assert AccessToken.findByValue(tokenValue)

        when:
        tokenStore.removeAccessToken(oauth2AccessToken)

        then:
        !AccessToken.findByValue(tokenValue)
    }

    void "store expiring refresh token"() {
        given:
        expectAuthenticationSerialization()

        and:
        def expiration = new Date()

        def oAuth2RefreshToken = Stub(ExpiringOAuth2RefreshToken) {
            getValue() >> refreshValue
            getExpiration() >> expiration
        }

        when:
        tokenStore.storeRefreshToken(oAuth2RefreshToken, oAuth2Authentication)

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
        expectAuthenticationSerialization()

        and:
        def oAuth2RefreshToken = Stub(OAuth2RefreshToken) {
            getValue() >> refreshValue
        }

        when:
        tokenStore.storeRefreshToken(oAuth2RefreshToken, oAuth2Authentication)

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
        final maxSize = 1024 * 4
        serializedAuthentication = new byte[maxSize + 1]

        expectAuthenticationSerialization()

        and:
        def expiration = new Date()

        def oAuth2RefreshToken = Stub(ExpiringOAuth2RefreshToken) {
            getValue() >> refreshValue
            getExpiration() >> expiration
        }

        when:
        tokenStore.storeRefreshToken(oAuth2RefreshToken, oAuth2Authentication)

        then:
        def e = thrown(OAuth2ValidationException)

        e.message.startsWith('Failed to save refresh token')
        !e.errors.allErrors.empty
    }

    void "read expiring refresh token by value"() {
        given:
        createGormRefreshToken(expiration: new Date())
        assert RefreshToken.findByValue(refreshValue)

        when:
        def oAuthRefreshToken = tokenStore.readRefreshToken(refreshValue)

        then:
        oAuthRefreshToken.value == refreshValue
        oAuthRefreshToken instanceof ExpiringOAuth2RefreshToken
    }

    void "read unlimited refresh token by value"() {
        given:
        createGormRefreshToken(expiration: null)
        assert RefreshToken.findByValue(refreshValue)

        when:
        def oAuthRefreshToken = tokenStore.readRefreshToken(refreshValue)

        then:
        oAuthRefreshToken.value == refreshValue
        !(oAuthRefreshToken instanceof ExpiringOAuth2RefreshToken)
    }

    void "read access token returns null when token not found"() {
        expect:
        tokenStore.readAccessToken(tokenValue) == null
    }

    void "return null if refresh token can't be read"() {
        expect:
        tokenStore.readRefreshToken(refreshValue) == null
    }

    void "return null if token cannot be found by authentication"() {
        given:
        expectAuthenticationKeyExtraction()

        when:
        def token = tokenStore.getAccessToken(oAuth2Authentication)

        then:
        token == null
    }

    void "read authentication for refresh token"() {
        given:
        expectAuthenticationDeserialization()

        def gormRefreshToken = createGormRefreshToken()
        def oAuth2RefreshToken = tokenStore.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        expect:
        tokenStore.readAuthenticationForRefreshToken(oAuth2RefreshToken) == oAuth2Authentication
    }

    void "read authentication removes refresh token if deserialization throws"() {
        given:
        def gormRefreshToken = createGormRefreshToken()
        def oAuth2RefreshToken = tokenStore.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        when:
        tokenStore.readAuthenticationForRefreshToken(oAuth2RefreshToken)

        then:
        !RefreshToken.findByValue(refreshValue)

        and:
        1 * tokenStore.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    void "remove refresh token"() {
        given:
        def gormRefreshToken = createGormRefreshToken()
        def oAuth2RefreshToken = tokenStore.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        when:
        tokenStore.removeRefreshToken(oAuth2RefreshToken)

        then:
        !RefreshToken.findByValue(refreshValue)
    }

    void "remove access token by using refresh token"() {
        given:
        def oAuth2RefreshToken = Stub(OAuth2RefreshToken) { getValue() >> refreshValue }

        createGormAccessToken(refreshToken: refreshValue)
        assert AccessToken.findByValueAndRefreshToken(tokenValue, refreshValue)

        when:
        tokenStore.removeAccessTokenUsingRefreshToken(oAuth2RefreshToken)

        then:
        !AccessToken.findByValue(tokenValue)
    }

    void "get access token by authentication with additional information"() {
        given:
        createGormAccessToken()

        when:
        def token = tokenStore.getAccessToken(oAuth2Authentication)

        then:
        token.value == tokenValue
        token.additionalInformation.additional == 'information'

        and:
        2 * tokenStore.authenticationKeyGenerator.extractKey(_) >> authenticationKey
    }

    void "get access token by authentication that does not have additional information"() {
        given:
        createGormAccessToken(additionalInformation: null)

        when:
        def token = tokenStore.getAccessToken(oAuth2Authentication)

        then:
        token.value == tokenValue
        token.additionalInformation.isEmpty()

        and:
        tokenStore.authenticationKeyGenerator.extractKey(_) >> authenticationKey
    }

    void "authentication associated with stored access token is not the one provided"() {
        given:
        def spyService = Spy(GormTokenStoreService)
        mockServiceCollaborators(spyService)

        spyService.grailsApplication = grailsApplication

        spyService.accessTokenAdditionalInformationSerializer = accessTokenAdditionalInformationSerializer
        spyService.accessTokenScopeSerializer = accessTokenScopeSerializer

        createGormAccessToken()

        and:
        def anotherAuthentication = Stub(OAuth2Authentication)
        assert anotherAuthentication != oAuth2Authentication

        and:
        def differentAuthenticationKey = authenticationKey + 'a'

        when:
        def token = spyService.getAccessToken(oAuth2Authentication)

        then:
        token.value == tokenValue

        and:
        1 * spyService.authenticationKeyGenerator.extractKey(oAuth2Authentication as OAuth2Authentication) >> authenticationKey
        1 * spyService.authenticationKeyGenerator.extractKey(anotherAuthentication as OAuth2Authentication) >>  differentAuthenticationKey

        1 * spyService.readAuthentication(tokenValue) >> anotherAuthentication
        1 * spyService.removeAccessToken(tokenValue)

        1 * spyService.storeAccessToken(_, _) >> { OAuth2AccessToken accessToken, OAuth2Authentication auth ->
            assert accessToken.value == tokenValue
            assert auth == oAuth2Authentication
        }
    }

    void "find tokens by clientId or by username returns a collection of OAuth2AccessTokens"() {
        expect:
        tokenStore.findTokensByClientId('') instanceof Collection<OAuth2AccessToken>
        tokenStore.findTokensByClientIdAndUserName('', '') instanceof Collection<OAuth2AccessToken>
    }

    @Unroll
    void "find tokens by client ['testClient'] and username [#username] returns empty collection"() {
        expect:
        tokenStore.findTokensByClientIdAndUserName('testClient', username).empty

        where:
        username << ['', 'non-existent', null]
    }

    void "find single token by client id and username"() {
        given:
        createGormAccessToken(clientId: 'client', username: 'user', value: '1234')

        when:
        def tokens = tokenStore.findTokensByClientIdAndUserName('client', 'user')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by client id and username"() {
        given:
        createGormAccessToken(clientId: 'client', username: 'user', value: '1234', authenticationKey: authenticationKey + '1')
        createGormAccessToken(clientId: 'client', username: 'user', value: '5678', authenticationKey: authenticationKey + '2')

        when:
        def tokens = tokenStore.findTokensByClientIdAndUserName('client', 'user')

        then:
        tokens.size() == 2
        tokens[0].value == '1234'
        tokens[1].value == '5678'
    }

    @Unroll
    void "find tokens by clientId [#clientId] returns empty collection"() {
        expect:
        tokenStore.findTokensByClientId(clientId).empty

        where:
        clientId << ['', 'non-existent', null]
    }

    void "find single token by clientId"() {
        given:
        createGormAccessToken(clientId: 'test', value: '1234')

        when:
        def tokens = tokenStore.findTokensByClientId('test')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by clientId"() {
        given:
        createGormAccessToken(clientId: 'test', value: '1234', authenticationKey: authenticationKey + '1')
        createGormAccessToken(clientId: 'test', value: '5678', authenticationKey: authenticationKey + '2')

        when:
        def tokens = tokenStore.findTokensByClientId('test')

        then:
        tokens.size() == 2
        tokens[0].value == '1234'
        tokens[1].value == '5678'
    }

    void "null token domain class name"() {
        when:
        tokenStore.getTokenClass('test', null)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified test token domain class 'null' is not a domain class"
    }

    @Unroll
    void "test createOAuth2AccessToken with refresh token [#useRefreshToken]"() {
        given:
        def gormRefreshToken = useRefreshToken ? createGormRefreshToken(value: refreshTokenValue) : null

        def expiration = new Date()
        def gormAccessToken = createGormAccessToken(refreshToken: refreshTokenValue, expiration: expiration, scope: ['read'])

        when:
        def accessToken = tokenStore.createOAuth2AccessToken(gormAccessToken)

        then:
        accessToken instanceof OAuth2AccessToken

        and:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'
        accessToken.expiration == expiration
        accessToken.scope.size() == 1
        accessToken.scope.contains('read')

        and:
        if(useRefreshToken) {
            assert accessToken.refreshToken instanceof ExpiringOAuth2RefreshToken
            assert accessToken.refreshToken.value == refreshTokenValue
            assert accessToken.refreshToken.expiration == gormRefreshToken.expiration
        }
        else {
            assert accessToken.refreshToken == null
        }

        where:
        useRefreshToken     |   refreshTokenValue
        true                |   'gormRefreshToken'
        false               |   null
    }

    void "test createOAuth2RefreshToken"() {
        given:
        def gormRefreshToken = createGormRefreshToken()

        when:
        def refreshToken = tokenStore.createOAuth2RefreshToken(gormRefreshToken)

        then:
        refreshToken instanceof ExpiringOAuth2RefreshToken

        and:
        refreshToken.value == gormRefreshToken.value
        refreshToken.expiration == gormRefreshToken.expiration
    }
}
