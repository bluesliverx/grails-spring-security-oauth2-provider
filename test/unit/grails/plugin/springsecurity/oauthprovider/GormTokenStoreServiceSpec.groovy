package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.OAuth2Authentication
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormTokenStoreService)
@Mock([GormOAuth2AccessToken, GormOAuth2RefreshToken])
class GormTokenStoreServiceSpec extends Specification {

    String tokenValue
    String refreshValue

    OAuth2Authentication oAuth2Authentication
    byte[] serializedAuthentication

    void setup() {
        service.oAuth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)

        oAuth2Authentication = Stub(OAuth2Authentication)
        serializedAuthentication = [0x13, 0x37]

        tokenValue = 'TEST'
        refreshValue = 'REFRESH'
    }

    private void expectAuthenticationSerialization() {
        1 * service.oAuth2AuthenticationSerializer.serialize(oAuth2Authentication as OAuth2Authentication) >> serializedAuthentication
    }

    private void expectAuthenticationDeserialization() {
        1 * service.oAuth2AuthenticationSerializer.deserialize(serializedAuthentication) >> oAuth2Authentication
    }

    void "read authentication for access token"() {
        given:
        expectAuthenticationDeserialization()

        def gormAccessToken = new GormOAuth2AccessToken(value: tokenValue, authentication: serializedAuthentication).save(validate: false)
        def oauth2AccessToken = gormAccessToken.toAccessToken()

        when:
        def authentication = service.readAuthentication(oauth2AccessToken)

        then:
        authentication == oAuth2Authentication
    }

    void "read authentication removes access token if deserialization throws"() {
        given:
        def gormAccessToken = new GormOAuth2AccessToken(value: tokenValue, authentication: serializedAuthentication).save(validate: false)
        def oauth2AccessToken = gormAccessToken.toAccessToken()

        assert GormOAuth2AccessToken.findByValue(tokenValue)

        when:
        service.readAuthentication(oauth2AccessToken)

        then:
        !GormOAuth2AccessToken.findByValue(tokenValue)

        and:
        1 * service.oAuth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    @Unroll
    void "store access token -- use refresh token? [#useRefreshToken] -- is client only? [#isClientOnly]"() {
        given:
        expectAuthenticationSerialization()

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

        def authorizationRequest = Stub(AuthorizationRequest) {
            getClientId() >> 'testClient'
        }

        oAuth2Authentication.getName() >> username
        oAuth2Authentication.getAuthorizationRequest() >> authorizationRequest
        oAuth2Authentication.isClientOnly() >> isClientOnly

        when:
        service.storeAccessToken(oauth2AccessToken, oAuth2Authentication)

        then:
        def gormToken = GormOAuth2AccessToken.findByValue('TEST')
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
        new GormOAuth2AccessToken(value: 'gormAccessToken', tokenType: 'bearer').save(validate: false)

        when:
        def accessToken = service.readAccessToken('gormAccessToken')

        then:
        accessToken.value == 'gormAccessToken'
        accessToken.tokenType == 'bearer'
    }

    void "remove access token"() {
        given:
        def gormAccessToken = new GormOAuth2AccessToken(value: tokenValue).save(validate: false)
        def oauth2AccessToken = gormAccessToken.toAccessToken()

        assert GormOAuth2AccessToken.findByValue(tokenValue)

        when:
        service.removeAccessToken(oauth2AccessToken)

        then:
        !GormOAuth2AccessToken.findByValue(tokenValue)
    }

    void "store refresh token"() {
        given:
        expectAuthenticationSerialization()

        and:
        def oAuth2RefreshToken = Stub(OAuth2RefreshToken) {
            getValue() >> refreshValue
        }

        when:
        service.storeRefreshToken(oAuth2RefreshToken, oAuth2Authentication)

        then:
        def gormToken = GormOAuth2RefreshToken.findByValue(refreshValue)
        gormToken != null

        and:
        gormToken.value == refreshValue
        gormToken.authentication == serializedAuthentication
    }

    void "read refresh token by value"() {
        given:
        new GormOAuth2RefreshToken(authentication: serializedAuthentication, value: refreshValue).save()
        assert GormOAuth2RefreshToken.findByValue(refreshValue)

        when:
        def oAuthRefreshToken = service.readRefreshToken(refreshValue)

        then:
        oAuthRefreshToken.value == refreshValue
    }

    void "return null if refresh token can't be read"() {
        expect:
        service.readRefreshToken(refreshValue) == null
    }

    void "return null if token cannot be found by authentication"() {
        given:
        expectAuthenticationSerialization()

        when:
        def token = service.getAccessToken(oAuth2Authentication)

        then:
        token == null
    }

    void "read authentication for refresh token"() {
        given:
        expectAuthenticationDeserialization()

        def gormRefreshToken = new GormOAuth2RefreshToken(value: refreshValue, authentication: serializedAuthentication).save()
        def oAuth2RefreshToken = gormRefreshToken.toRefreshToken()

        assert GormOAuth2RefreshToken.findByValue(refreshValue)

        expect:
        service.readAuthenticationForRefreshToken(oAuth2RefreshToken) == oAuth2Authentication
    }

    void "read authentication removes refresh token if deserialization throws"() {
        given:
        def gormRefreshToken = new GormOAuth2RefreshToken(value: refreshValue, authentication: serializedAuthentication).save()
        def oAuth2RefreshToken = gormRefreshToken.toRefreshToken()

        assert GormOAuth2RefreshToken.findByValue(refreshValue)

        when:
        service.readAuthenticationForRefreshToken(oAuth2RefreshToken)

        then:
        !GormOAuth2RefreshToken.findByValue(refreshValue)

        and:
        1 * service.oAuth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('BAD NEWS')
        }
    }

    void "remove refresh token"() {
        given:
        def gormRefreshToken = new GormOAuth2RefreshToken(value: refreshValue).save(validate: false)
        def oAuth2RefreshToken = gormRefreshToken.toRefreshToken()

        assert GormOAuth2RefreshToken.findByValue(refreshValue)

        when:
        service.removeRefreshToken(oAuth2RefreshToken)

        then:
        !GormOAuth2RefreshToken.findByValue(refreshValue)
    }

    void "remove access token by using refresh token"() {
        given:
        def oAuth2RefreshToken = Stub(OAuth2RefreshToken) { getValue() >> refreshValue }

        new GormOAuth2AccessToken(value: tokenValue, refreshToken: refreshValue).save(validate: false)
        assert GormOAuth2AccessToken.findByValue(tokenValue)

        when:
        service.removeAccessTokenUsingRefreshToken(oAuth2RefreshToken)

        then:
        !GormOAuth2AccessToken.findByValue(tokenValue)
    }

    void "get access token by authentication"() {
        given:
        expectAuthenticationSerialization()

        and:
        new GormOAuth2AccessToken(authentication: serializedAuthentication, value: tokenValue).save(validate: false)

        when:
        def token = service.getAccessToken(oAuth2Authentication)

        then:
        token.value == tokenValue
    }

    void "find tokens by clientId or by username returns a collection of OAuth2AccessTokens"() {
        expect:
        service.findTokensByClientId('') instanceof Collection<OAuth2AccessToken>
        service.findTokensByUserName('') instanceof Collection<OAuth2AccessToken>
    }

    @Unroll
    void "find tokens by username [#username] returns empty collection"() {
        expect:
        service.findTokensByUserName(username).empty

        where:
        username << ['', 'non-existent', null]
    }

    void "find single token by username"() {
        given:
        new GormOAuth2AccessToken(username: 'test', value: '1234').save(validate: false)

        when:
        def tokens = service.findTokensByUserName('test')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by username"() {
        given:
        new GormOAuth2AccessToken(username: 'test', value: '1234').save(validate: false)
        new GormOAuth2AccessToken(username: 'test', value: '5678').save(validate: false)

        when:
        def tokens = service.findTokensByUserName('test')

        then:
        tokens.size() == 2
        tokens[0].value == '1234'
        tokens[1].value == '5678'
    }

    @Unroll
    void "find tokens by clientId [#clientId] returns empty collection"() {
        expect:
        service.findTokensByClientId(clientId).empty

        where:
        clientId << ['', 'non-existent', null]
    }

    void "find single token by clientId"() {
        given:
        new GormOAuth2AccessToken(clientId: 'test', value: '1234').save(validate: false)

        when:
        def tokens = service.findTokensByClientId('test')

        then:
        tokens.size() == 1
        tokens[0].value == '1234'
    }

    void "find multiple tokens by clientId"() {
        given:
        new GormOAuth2AccessToken(clientId: 'test', value: '1234').save(validate: false)
        new GormOAuth2AccessToken(clientId: 'test', value: '5678').save(validate: false)

        when:
        def tokens = service.findTokensByClientId('test')

        then:
        tokens.size() == 2
        tokens[0].value == '1234'
        tokens[1].value == '5678'
    }
}
