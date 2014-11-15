package grails.plugin.springsecurity.oauthprovider

import grails.test.spock.IntegrationSpec
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

    def gormTokenStoreService
    def grailsApplication

    String tokenValue
    String refreshValue

    String authenticationKey

    OAuth2Authentication oAuth2Authentication
    byte[] serializedAuthentication

    Client client

    OAuth2AuthenticationSerializer originalSerializer
    AuthenticationKeyGenerator originalKeyGenerator

    void setup() {
        originalSerializer = gormTokenStoreService.oauth2AuthenticationSerializer
        originalKeyGenerator = gormTokenStoreService.authenticationKeyGenerator

        mockServiceCollaborators(gormTokenStoreService)

        oAuth2Authentication = Stub(OAuth2Authentication)
        serializedAuthentication = [0x13, 0x37]
        authenticationKey = 'serializedAuthenticationKey'

        tokenValue = 'TEST'
        refreshValue = 'REFRESH'

        client = new Client(clientId: 'test').save()
    }

    private void mockServiceCollaborators(GormTokenStoreService service) {
        service.oauth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)
        service.authenticationKeyGenerator = Mock(AuthenticationKeyGenerator)
    }

    void cleanup() {
        gormTokenStoreService.oauth2AuthenticationSerializer = originalSerializer
        gormTokenStoreService.authenticationKeyGenerator = originalKeyGenerator
    }

    private void expectAuthenticationKeyExtraction() {
        1 * gormTokenStoreService.authenticationKeyGenerator.extractKey(oAuth2Authentication as OAuth2Authentication) >> authenticationKey
    }

    private void expectAuthenticationSerialization() {
        1 * gormTokenStoreService.oauth2AuthenticationSerializer.serialize(oAuth2Authentication as OAuth2Authentication) >> serializedAuthentication
    }

    private void expectAuthenticationDeserialization() {
        1 * gormTokenStoreService.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> oAuth2Authentication
    }

    private AccessToken createGormAccessToken(Map overrides = [:]) {
        def token = new AccessToken(
                value: tokenValue,
                tokenType: 'bearer',
                clientId: client.clientId,
                scope: ['test'],
                authenticationKey: authenticationKey,
                authentication: serializedAuthentication
        )
        addOverrides(token, overrides)
        token.save(failOnError: true)
    }

    private RefreshToken createGormRefreshToken(Map overrides = [:]) {
        def token = new RefreshToken(value: refreshValue, authentication: serializedAuthentication)
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
        def oauth2AccessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        expect:
        gormTokenStoreService.readAuthentication(oauth2AccessToken) == oAuth2Authentication
    }

    void "read authentication removes access token if deserialization throws"() {
        given:
        def gormAccessToken = createGormAccessToken()
        def oauth2AccessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        assert AccessToken.findByValue(tokenValue)

        when:
        gormTokenStoreService.readAuthentication(oauth2AccessToken)

        then:
        !AccessToken.findByValue(tokenValue)

        and:
        1 * gormTokenStoreService.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
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
        }

        def oauth2Request = new OAuth2Request(null, 'testClient', null, false, null, null, null, null, null)

        oAuth2Authentication.getName() >> username
        oAuth2Authentication.getOAuth2Request() >> oauth2Request
        oAuth2Authentication.isClientOnly() >> isClientOnly

        expect:
        oauth2Request.clientId == 'testClient'

        when:
        gormTokenStoreService.storeAccessToken(oauth2AccessToken, oAuth2Authentication)

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

        where:
        username    |   expectedUsername    |   isClientOnly    |   useRefreshToken |   refreshToken    |   expectedRefreshToken
        'testUser'  |   'testUser'          |   false           |   false           |   'IGNORE'        |   null
        'testUser'  |   null                |   true            |   false           |   'IGNORE'        |   null
        'testUser'  |   'testUser'          |   false           |   true            |   'REFRESH'       |   'REFRESH'
        'testUser'  |   null                |   true            |   true            |   'REFRESH'       |   'REFRESH'
    }

    void "read access token"() {
        given:
        createGormAccessToken()

        when:
        def accessToken = gormTokenStoreService.readAccessToken(tokenValue)

        then:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'
    }

    void "remove access token"() {
        given:
        def gormAccessToken = createGormAccessToken()
        def oauth2AccessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        assert AccessToken.findByValue(tokenValue)

        when:
        gormTokenStoreService.removeAccessToken(oauth2AccessToken)

        then:
        !AccessToken.findByValue(tokenValue)
    }

    void "store refresh token"() {
        given:
        expectAuthenticationSerialization()

        and:
        def oAuth2RefreshToken = Stub(OAuth2RefreshToken) {
            getValue() >> refreshValue
        }

        when:
        gormTokenStoreService.storeRefreshToken(oAuth2RefreshToken, oAuth2Authentication)

        then:
        def gormToken = RefreshToken.findByValue(refreshValue)
        gormToken != null

        and:
        gormToken.value == refreshValue
        gormToken.authentication == serializedAuthentication
    }

    void "read refresh token by value"() {
        given:
        new RefreshToken(authentication: serializedAuthentication, value: refreshValue).save()
        assert RefreshToken.findByValue(refreshValue)

        when:
        def oAuthRefreshToken = gormTokenStoreService.readRefreshToken(refreshValue)

        then:
        oAuthRefreshToken.value == refreshValue
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
        given:
        expectAuthenticationKeyExtraction()

        when:
        def token = gormTokenStoreService.getAccessToken(oAuth2Authentication)

        then:
        token == null
    }

    void "read authentication for refresh token"() {
        given:
        expectAuthenticationDeserialization()

        def gormRefreshToken = new RefreshToken(value: refreshValue, authentication: serializedAuthentication).save()
        def oAuth2RefreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        expect:
        gormTokenStoreService.readAuthenticationForRefreshToken(oAuth2RefreshToken) == oAuth2Authentication
    }

    void "read authentication removes refresh token if deserialization throws"() {
        given:
        def gormRefreshToken = new RefreshToken(value: refreshValue, authentication: serializedAuthentication).save()
        def oAuth2RefreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        when:
        gormTokenStoreService.readAuthenticationForRefreshToken(oAuth2RefreshToken)

        then:
        !RefreshToken.findByValue(refreshValue)

        and:
        1 * gormTokenStoreService.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    void "remove refresh token"() {
        given:
        def gormRefreshToken = createGormRefreshToken()
        def oAuth2RefreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        assert RefreshToken.findByValue(refreshValue)

        when:
        gormTokenStoreService.removeRefreshToken(oAuth2RefreshToken)

        then:
        !RefreshToken.findByValue(refreshValue)
    }

    void "remove access token by using refresh token"() {
        given:
        def oAuth2RefreshToken = Stub(OAuth2RefreshToken) { getValue() >> refreshValue }

        createGormAccessToken(refreshToken: refreshValue)
        assert AccessToken.findByValueAndRefreshToken(tokenValue, refreshValue)

        when:
        gormTokenStoreService.removeAccessTokenUsingRefreshToken(oAuth2RefreshToken)

        then:
        !AccessToken.findByValue(tokenValue)
    }

    void "get access token by authentication"() {
        given:
        createGormAccessToken()

        when:
        def token = gormTokenStoreService.getAccessToken(oAuth2Authentication)

        then:
        token.value == tokenValue

        and:
        2 * gormTokenStoreService.authenticationKeyGenerator.extractKey(_) >> authenticationKey
    }

    void "authentication associated with stored access token is not the one provided"() {
        given:
        def spyService = Spy(GormTokenStoreService)
        mockServiceCollaborators(spyService)
        spyService.grailsApplication = grailsApplication

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
        gormTokenStoreService.findTokensByClientId('') instanceof Collection<OAuth2AccessToken>
        gormTokenStoreService.findTokensByClientIdAndUserName('', '') instanceof Collection<OAuth2AccessToken>
    }

    @Unroll
    void "find tokens by client ['testClient'] and username [#username] returns empty collection"() {
        expect:
        gormTokenStoreService.findTokensByClientIdAndUserName('testClient', username).empty

        where:
        username << ['', 'non-existent', null]
    }

    void "find single token by client id and username"() {
        given:
        createGormAccessToken(clientId: 'client', username: 'user', value: '1234')

        when:
        def tokens = gormTokenStoreService.findTokensByClientIdAndUserName('client', 'user')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by client id and username"() {
        given:
        createGormAccessToken(clientId: 'client', username: 'user', value: '1234', authenticationKey: authenticationKey + '1')
        createGormAccessToken(clientId: 'client', username: 'user', value: '5678', authenticationKey: authenticationKey + '2')

        when:
        def tokens = gormTokenStoreService.findTokensByClientIdAndUserName('client', 'user')

        then:
        tokens.size() == 2
        tokens[0].value == '1234'
        tokens[1].value == '5678'
    }

    @Unroll
    void "find tokens by clientId [#clientId] returns empty collection"() {
        expect:
        gormTokenStoreService.findTokensByClientId(clientId).empty

        where:
        clientId << ['', 'non-existent', null]
    }

    void "find single token by clientId"() {
        given:
        createGormAccessToken(clientId: 'test', value: '1234')

        when:
        def tokens = gormTokenStoreService.findTokensByClientId('test')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by clientId"() {
        given:
        createGormAccessToken(clientId: 'test', value: '1234', authenticationKey: authenticationKey + '1')
        createGormAccessToken(clientId: 'test', value: '5678', authenticationKey: authenticationKey + '2')

        when:
        def tokens = gormTokenStoreService.findTokensByClientId('test')

        then:
        tokens.size() == 2
        tokens[0].value == '1234'
        tokens[1].value == '5678'
    }

    void "null token domain class name"() {
        when:
        gormTokenStoreService.getTokenClass('test', null)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified test token domain class 'null' is not a domain class"
    }

    @Unroll
    void "test createOAuth2AccessToken with refresh token [#useRefreshToken]"() {
        given:
        if(useRefreshToken)
            createGormRefreshToken(value: refreshTokenValue)

        def expiration = new Date()
        def gormAccessToken = createGormAccessToken(refreshToken: refreshTokenValue, expiration: expiration, scope: ['read'])

        when:
        def accessToken = gormTokenStoreService.createOAuth2AccessToken(gormAccessToken)

        then:
        accessToken instanceof OAuth2AccessToken

        and:
        accessToken.value == tokenValue
        accessToken.tokenType == 'bearer'
        accessToken.expiration == expiration
        accessToken.scope.size() == 1
        accessToken.scope.contains('read')

        and:
        if(useRefreshToken)
            accessToken.refreshToken.value == refreshTokenValue
        else
            accessToken.refreshToken == null

        where:
        useRefreshToken     |   refreshTokenValue
        true                |   'gormRefreshToken'
        false               |   null
    }

    void "test createOAuth2RefreshToken"() {
        given:
        def gormRefreshToken = new RefreshToken(value: 'gormRefreshToken')

        when:
        def refreshToken = gormTokenStoreService.createOAuth2RefreshToken(gormRefreshToken)

        then:
        refreshToken instanceof OAuth2RefreshToken

        and:
        refreshToken.value == 'gormRefreshToken'
    }
}
