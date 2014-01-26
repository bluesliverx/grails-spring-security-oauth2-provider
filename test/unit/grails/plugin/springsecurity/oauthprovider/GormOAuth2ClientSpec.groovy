package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.*
import org.springframework.security.oauth2.provider.ClientDetails
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormOAuth2Client)
class GormOAuth2ClientSpec extends Specification {

    void "test toClientDetails"() {
        given:
        def client = new GormOAuth2Client(
                clientId: 'gormClient',
                clientSecret: 'grails',
                accessTokenValiditySeconds: 1234,
                refreshTokenValiditySeconds: 5678,
                authorities: ['ROLE_CLIENT'] as Set,
                grantTypes: ['implicit'] as Set,
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
    void "[#type] token validity can be null"() {
        when:
        def client = new GormOAuth2Client()

        then:
        client.validate([name])

        where:
        type        |   name
        'access'    |   'accessTokenValiditySeconds'
        'refresh'   |   'refreshTokenValiditySeconds'
    }

    void "scopes can be optional"() {
        when:
        def client = new GormOAuth2Client(scopes: null)

        then:
        client.validate(['scopes'])

        when:
        def details = client.toClientDetails()

        then:
        !details.isScoped()
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

    void "grant types not required -- default to refresh_token and authorization_code"() {
        when:
        def client = new GormOAuth2Client(grantTypes: null)

        then:
        client.validate(['grantTypes'])

        when:
        def details = client.toClientDetails()

        then:
        details.authorizedGrantTypes.size() == 2
        details.authorizedGrantTypes.contains('refresh_token')
        details.authorizedGrantTypes.contains('authorization_code')
    }

    void "multiple grant types"() {
        when:
        def client = new GormOAuth2Client(grantTypes: ['password','authorization_code', 'refresh_token', 'implicit'] as Set)

        then:
        client.validate(['grantTypes'])

        when:
        def details = client.toClientDetails()

        then:
        details.authorizedGrantTypes.size() == 4
        details.authorizedGrantTypes.contains('password')
        details.authorizedGrantTypes.contains('authorization_code')
        details.authorizedGrantTypes.contains('refresh_token')
        details.authorizedGrantTypes.contains('implicit')
    }

    void "redirect uris are not required"() {
        when:
        def client = new GormOAuth2Client(redirectUris: null)

        then:
        client.validate(['redirectUris'])

        when:
        def details = client.toClientDetails()

        then:
        details.registeredRedirectUri == null
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

    void "resource ids are optional"() {
        when:
        def client = new GormOAuth2Client(resourceIds: null)

        then:
        client.validate(['resourceIds'])

        when:
        def details = client.toClientDetails()

        then:
        details.resourceIds.empty
    }
}
