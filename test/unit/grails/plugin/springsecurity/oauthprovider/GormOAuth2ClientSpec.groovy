package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.*
import org.springframework.security.oauth2.provider.ClientDetails
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormOAuth2Client)
class GormOAuth2ClientSpec extends Specification {

    void setup() {
        setUpSecurityConfig()
    }

    private void setUpSecurityConfig(Map overrides = [:]) {
        def clientConfig = [
                resourceIds: [],
                authorizedGrantTypes: [],
                scope: [],
                registeredRedirectUri: null,
                authorities: [],
                accessTokenValiditySeconds: null,
                refreshTokenValiditySeconds: null
        ] << overrides
        SpringSecurityUtils.securityConfig = [oauthProvider: [defaultClientConfig: clientConfig]] as ConfigObject
    }

    void "test toClientDetails"() {
        given:
        def client = new GormOAuth2Client(
                clientId: 'gormClient',
                clientSecret: 'grails',
                accessTokenValiditySeconds: 1234,
                refreshTokenValiditySeconds: 5678,
                authorities: ['ROLE_CLIENT'] as Set,
                authorizedGrantTypes: ['implicit'] as Set,
                resourceIds: ['someResource'] as Set,
                scopes: ['kaleidoscope'] as Set,
                redirectUris: ['http://anywhereButHere'] as Set
        )

        when:
        def details = client.toClientDetails()

        then:
        details instanceof ClientDetails

        and:
        details.clientId == 'gormClient'
        details.clientSecret == 'grails'

        and:
        details.accessTokenValiditySeconds == 1234
        details.refreshTokenValiditySeconds == 5678

        and:
        details.authorities.size() == 1
        details.authorities.find { it.authority == 'ROLE_CLIENT' }

        and:
        details.authorizedGrantTypes.size() == 1
        details.authorizedGrantTypes.contains('implicit')

        and:
        details.resourceIds.size() == 1
        details.resourceIds.contains('someResource')

        and:
        details.scope.size() == 1
        details.scope.contains('kaleidoscope')

        and:
        details.registeredRedirectUri.size() == 1
        details.registeredRedirectUri.contains('http://anywhereButHere')
    }

    @Unroll
    void "client id is required -- check invalid id [#clientId]"() {
        when:
        def client = new GormOAuth2Client(clientId: clientId)

        then:
        !client.validate(['clientId'])

        where:
        clientId << [null, '']
    }

    void "client id must be unique"() {
        given:
        def existingClient = new GormOAuth2Client(clientId: 'client')
        mockForConstraintsTests(GormOAuth2Client, [existingClient])

        when:
        def newClient = new GormOAuth2Client(clientId: 'client')

        then:
        !newClient.validate(['clientId'])
    }

    void "client secret can be optional"() {
        when:
        def client = new GormOAuth2Client()

        then:
        client.validate(['clientSecret'])

        when:
        def details = client.toClientDetails()

        then:
        !details.isSecretRequired()
    }

    @Unroll
    void "[#type] token validity can be null -- honor default if not specified"() {
        given:
        setUpSecurityConfig([(name): 13490])

        when:
        def client = new GormOAuth2Client()

        then:
        client.validate([name])

        when:
        def details = client.toClientDetails()

        then:
        details."$detailsMethodName"() == 13490

        where:
        type        |   name                            |   detailsMethodName
        'access'    |   'accessTokenValiditySeconds'    |   'getAccessTokenValiditySeconds'
        'refresh'   |   'refreshTokenValiditySeconds'   |   'getRefreshTokenValiditySeconds'
    }

    void "scopes can be optional -- honor default if not specified"() {
        given:
        setUpSecurityConfig([scope: ['read']])

        when:
        def client = new GormOAuth2Client(scopes: null)

        then:
        client.validate(['scopes'])

        when:
        def details = client.toClientDetails()

        then:
        details.scoped
        details.scope.size() == 1
        details.scope.contains('read')
    }

    void "multiple scopes"() {
        when:
        def client = new GormOAuth2Client(scopes: ['read', 'write', 'trust'] as Set)

        then:
        client.validate(['scopes'])

        when:
        def details = client.toClientDetails()

        then:
        details.scoped
        details.scope.size() == 3
        details.scope.contains('read')
        details.scope.contains('write')
        details.scope.contains('trust')
    }

    @Unroll
    void "authorities default to nothing"() {
        when:
        def client = new GormOAuth2Client()

        then:
        client.validate(['authorities'])

        when:
        def details = client.toClientDetails()

        then:
        details.authorities.empty
    }

    void "multiple authorities"() {
        when:
        def client = new GormOAuth2Client(authorities: ['ROLE_CLIENT', 'ROLE_TRUSTED_CLIENT'] as Set)

        then:
        client.validate(['authorities'])

        when:
        def details = client.toClientDetails()

        then:
        details.authorities.size() == 2
        details.authorities.find { it.authority == 'ROLE_CLIENT' }
        details.authorities.find { it.authority == 'ROLE_TRUSTED_CLIENT' }
    }

    void "grant types not required -- honor default if not specified"() {
        given:
        setUpSecurityConfig([authorizedGrantTypes: ['foo', 'bar']])

        when:
        def client = new GormOAuth2Client(authorizedGrantTypes: null)

        then:
        client.validate(['authorizedGrantTypes'])

        when:
        def details = client.toClientDetails()

        then:
        details.authorizedGrantTypes.size() == 2
        details.authorizedGrantTypes.contains('foo')
        details.authorizedGrantTypes.contains('bar')
    }

    void "multiple grant types"() {
        when:
        def client = new GormOAuth2Client(authorizedGrantTypes: ['password','authorization_code', 'refresh_token', 'implicit'] as Set)

        then:
        client.validate(['authorizedGrantTypes'])

        when:
        def details = client.toClientDetails()

        then:
        details.authorizedGrantTypes.size() == 4
        details.authorizedGrantTypes.contains('password')
        details.authorizedGrantTypes.contains('authorization_code')
        details.authorizedGrantTypes.contains('refresh_token')
        details.authorizedGrantTypes.contains('implicit')
    }

    void "redirect uris are not required -- honor default if not specified"() {
        given:
        setUpSecurityConfig([registeredRedirectUri: 'http://somewhere.com'])

        when:
        def client = new GormOAuth2Client(redirectUris: null)

        then:
        client.validate(['redirectUris'])

        when:
        def details = client.toClientDetails()

        then:
        details.registeredRedirectUri.size() == 1
        details.registeredRedirectUri.contains('http://somewhere.com')
    }

    void "multiple redirect uris"() {
        when:
        def client = new GormOAuth2Client(redirectUris: ['http://somewhere', 'http://nowhere'] as Set)

        then:
        client.validate(['redirectUris'])

        when:
        def details = client.toClientDetails()

        then:
        details.registeredRedirectUri.size() == 2
        details.registeredRedirectUri.contains('http://somewhere')
        details.registeredRedirectUri.contains('http://nowhere')
    }

    void "resource ids are optional -- honor default if not specified"() {
        given:
        setUpSecurityConfig([resourceIds: ['someResource']])

        when:
        def client = new GormOAuth2Client(resourceIds: null)

        then:
        client.validate(['resourceIds'])

        when:
        def details = client.toClientDetails()

        then:
        details.resourceIds.size() == 1
        details.resourceIds.contains('someResource')
    }
}
