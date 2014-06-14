package test.oauth2

import grails.test.mixin.*
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.Client

@TestFor(Client)
class ClientSpec extends Specification {

    @Unroll
    void "client id is required -- check invalid id [#clientId]"() {
        when:
        def client = new Client(clientId: clientId)

        then:
        !client.validate(['clientId'])

        where:
        clientId << [null, '']
    }

    void "client id must be unique"() {
        given:
        def existingClient = new Client(clientId: 'client')
        mockForConstraintsTests(Client, [existingClient])

        when:
        def newClient = new Client(clientId: 'client')

        then:
        !newClient.validate(['clientId'])
    }

    void "client secret can be optional"() {
        when:
        def client = new Client()

        then:
        client.validate(['clientSecret'])
    }

    @Unroll
    void "[#type] token validity can be null"() {
        when:
        def client = new Client()

        then:
        client.validate([name])

        where:
        type        |   name                            |   detailsMethodName
        'access'    |   'accessTokenValiditySeconds'    |   'getAccessTokenValiditySeconds'
        'refresh'   |   'refreshTokenValiditySeconds'   |   'getRefreshTokenValiditySeconds'
    }

    @Unroll
    void "valid scopes [#scopes]"() {
        when:
        def client = new Client(scopes: scopes)

        then:
        client.validate(['scopes'])

        where:
        _   |   scopes
        _   |   null
        _   |   [] as Set
        _   |   ['read', 'write', 'trust'] as Set
    }

    @Unroll
    void "valid authorities [#authorities]"() {
        when:
        def client = new Client(authorities: authorities)

        then:
        client.validate(['authorities'])

        where:
        _   |   authorities
        _   |   null
        _   |   [] as Set
        _   |   ['ROLE_CLIENT', 'ROLE_TRUSTED_CLIENT'] as Set
    }

    @Unroll
    void "valid grant types [#grantTypes]"() {
        when:
        def client = new Client(authorizedGrantTypes: grantTypes)

        then:
        client.validate(['authorizedGrantTypes'])

        where:
        _   |   grantTypes
        _   |   null
        _   |   [] as Set
        _   |   ['password','authorization_code', 'refresh_token', 'implicit'] as Set
    }

    @Unroll
    void "valid redirect uris [#redirectUris]"() {
        when:
        def client = new Client(redirectUris: redirectUris)

        then:
        client.validate(['redirectUris'])

        where:
        _   |   redirectUris
        _   |   null
        _   |   [] as Set
        _   |   ['http://anywhere'] as Set
        _   |   ['http://somewhere', 'http://nowhere'] as Set
    }

    @Unroll
    void "valid resource ids [#resourceIds]"() {
        when:
        def client = new Client(resourceIds: resourceIds)

        then:
        client.validate(['resourceIds'])

        where:
        _   |   resourceIds
        _   |   null
        _   |   [] as Set
        _   |   ['something'] as Set
        _   |   ['something', 'more'] as Set
    }

    @Unroll
    void "valid additional information [#info]"() {
        when:
        def client = new Client(additionalInformation: info)

        then:
        client.validate(['additionalInformation'])

        and:
        client.additionalInformation == info

        where:
        _   |   info
        _   |   null
        _   |   [:]
        _   |   [foo: 'bar']
        _   |   [foo: 'bar', buzz: 'bar', number: 1234]
    }
}
