package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.TestFor
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.Client

@TestFor(GormClientDetailsService)
class GormClientDetailsServiceSpec extends Specification {

    void setup() {
        service.grailsApplication = grailsApplication

        SpringSecurityUtils.securityConfig = [oauthProvider: [:]] as ConfigObject
        setUpDefaultClientConfig()

        setClientClassName(Client.class.name)
    }

    void cleanup() {
        SpringSecurityUtils.securityConfig = null
    }

    private void setClientClassName(clientClassName) {
        def clientLookup = [
                className: clientClassName,
                clientIdPropertyName: 'clientId',
                clientSecretPropertyName: 'clientSecret',
                accessTokenValiditySecondsPropertyName: 'accessTokenValiditySeconds',
                refreshTokenValiditySecondsPropertyName: 'refreshTokenValiditySeconds',
                authoritiesPropertyName: 'authorities',
                authorizedGrantTypesPropertyName: 'authorizedGrantTypes',
                resourceIdsPropertyName: 'resourceIds',
                scopesPropertyName: 'scopes',
                autoApproveScopesPropertyName: 'autoApproveScopes',
                redirectUrisPropertyName: 'redirectUris',
                additionalInformationPropertyName: 'additionalInformation'
        ]
        SpringSecurityUtils.securityConfig.oauthProvider.clientLookup = clientLookup
    }

    private void setUpDefaultClientConfig(Map overrides = [:]) {
        def clientConfig = [
                resourceIds: [],
                authorizedGrantTypes: [],
                scope: [],
                autoApproveScopes: [],
                registeredRedirectUri: null,
                authorities: [],
                accessTokenValiditySeconds: null,
                refreshTokenValiditySeconds: null,
                additionalInformation: [:]
        ] << overrides
        SpringSecurityUtils.securityConfig.oauthProvider.defaultClientConfig = clientConfig
    }

    private void overrideDefaultClientConfig(Map overrides = [:]) {
        overrides.each { key, value ->
            SpringSecurityUtils.securityConfig.oauthProvider.defaultClientConfig."$key" = value
        }
    }

    private def getClientLookup() {
        return SpringSecurityUtils.securityConfig.oauthProvider.clientLookup
    }

    private def getDefaultClientConfig() {
        return SpringSecurityUtils.securityConfig.oauthProvider.defaultClientConfig
    }

    @Unroll
    void "invalid client domain class name [#className]"() {
        given:
        setClientClassName(className)

        when:
        service.loadClientByClientId('gormClient')

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified client domain class '$className' is not a domain class"

        where:
        _   |   className
        _   |   'invalidClientClass'
        _   |   null
    }

    void "client secret can be optional"() {
        given:
        def client = new Client()

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        !details.isSecretRequired()
    }

    @Unroll
    void "[#type] token validity can be null -- honor default if not specified"() {
        given:
        overrideDefaultClientConfig([(name): 13490])

        and:
        def client = new Client()

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details."$detailsMethodName"() == 13490

        where:
        type        |   name                            |   detailsMethodName
        'access'    |   'accessTokenValiditySeconds'    |   'getAccessTokenValiditySeconds'
        'refresh'   |   'refreshTokenValiditySeconds'   |   'getRefreshTokenValiditySeconds'
    }

    @Unroll
    void "default config [#defaultKey] only honored if client [#clientKey] is null and not [#clientValue]"() {
        given:
        overrideDefaultClientConfig([(defaultKey): defaultValue])

        and:
        def client = new Client((clientKey): clientValue)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details."$detailsKey" == detailsValue

        where:
        defaultKey                      |   defaultValue    |   clientKey                       |   clientValue     |   detailsKey                      |   detailsValue
        'resourceIds'                   |   ['something']   |   'resourceIds'                   |   [] as Set       |   'resourceIds'                   |   [] as Set
        'authorizedGrantTypes'          |   ['password']    |   'authorizedGrantTypes'          |   [] as Set       |   'authorizedGrantTypes'          |   [] as Set
        'scope'                         |   ['read']        |   'scopes'                        |   [] as Set       |   'scope'                         |   [] as Set
        'autoApproveScopes'             |   ['auto']        |   'autoApproveScopes'             |   [] as Set       |   'autoApproveScopes'             |   [] as Set
        'registeredRedirectUri'         |   ['http://foo']  |   'redirectUris'                  |   [] as Set       |   'registeredRedirectUris'        |   null
        'authorities'                   |   ['ROLE_USER']   |   'authorities'                   |   [] as List      |   'authorities'                   |   [] as List
        'accessTokenValiditySeconds'    |   1234            |   'accessTokenValiditySeconds'    |   0               |   'accessTokenValiditySeconds'    |   0
        'refreshTokenValiditySeconds'   |   1234            |   'refreshTokenValiditySeconds'   |   0               |   'refreshTokenValiditySeconds'   |   0
        'additionalInformation'         |   [foo: 'bar']    |   'additionalInformation'         |   [:]             |   'additionalInformation'         |   [:]
    }

    void "scopes can be optional -- honor default if not specified"() {
        given:
        overrideDefaultClientConfig([scope: ['read']])

        and:
        def client = new Client(scopes: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.scoped
        details.scope.size() == 1
        details.scope.contains('read')
    }

    void "multiple scopes"() {
        given:
        def client = new Client(scopes: ['read', 'write', 'trust'] as Set)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.scoped
        details.scope.size() == 3
        details.scope.contains('read')
        details.scope.contains('write')
        details.scope.contains('trust')
    }

    void "auto approve scopes can be optional -- honor defaults if not specified"() {
        given:
        overrideDefaultClientConfig([autoApproveScopes: ['read', 'write']])

        and:
        def client = new Client(autoApproveScopes: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.isAutoApprove('read')
        details.isAutoApprove('write')
    }

    @Unroll
    void "authorities default to nothing"() {
        given:
        def client = new Client()

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.authorities.empty
    }

    void "multiple authorities"() {
        given:
        def client = new Client(authorities: ['ROLE_CLIENT', 'ROLE_TRUSTED_CLIENT'] as Set)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.authorities.size() == 2
        details.authorities.find { it.authority == 'ROLE_CLIENT' }
        details.authorities.find { it.authority == 'ROLE_TRUSTED_CLIENT' }
    }

    void "no grant types specified for client or in default config"() {
        given:
        overrideDefaultClientConfig([authorizedGrantTypes: []])

        and:
        def client = new Client(authorizedGrantTypes: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.authorizedGrantTypes.size() == 0
    }

    void "grant types not required -- honor default if not specified"() {
        given:
        overrideDefaultClientConfig([authorizedGrantTypes: ['foo', 'bar']])

        and:
        def client = new Client(authorizedGrantTypes: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.authorizedGrantTypes.size() == 2
        details.authorizedGrantTypes.contains('foo')
        details.authorizedGrantTypes.contains('bar')
    }

    void "multiple grant types"() {
        given:
        def client = new Client(authorizedGrantTypes: ['password','authorization_code', 'refresh_token', 'implicit'] as Set)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.authorizedGrantTypes.size() == 4
        details.authorizedGrantTypes.contains('password')
        details.authorizedGrantTypes.contains('authorization_code')
        details.authorizedGrantTypes.contains('refresh_token')
        details.authorizedGrantTypes.contains('implicit')
    }

    void "redirect uris are not required -- honor default if not specified"() {
        given:
        overrideDefaultClientConfig([registeredRedirectUri: ['http://somewhere.com']])

        and:
        def client = new Client(redirectUris: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.registeredRedirectUri.size() == 1
        details.registeredRedirectUri.contains('http://somewhere.com')
    }

    void "multiple redirect uris"() {
        given:
        def client = new Client(redirectUris: ['http://somewhere', 'http://nowhere'] as Set)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.registeredRedirectUri.size() == 2
        details.registeredRedirectUri.contains('http://somewhere')
        details.registeredRedirectUri.contains('http://nowhere')
    }

    void "resource ids are optional -- honor default if not specified"() {
        given:
        overrideDefaultClientConfig([resourceIds: ['someResource']])

        and:
        def client = new Client(resourceIds: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.resourceIds.size() == 1
        details.resourceIds.contains('someResource')
    }

    void "additional information is optional -- honor default if not specified"() {
        given:
        overrideDefaultClientConfig([additionalInformation: [foo: 'bar']])

        and:
        def client = new Client(additionalInformation: null)

        when:
        def details = service.createClientDetails(client, clientLookup, defaultClientConfig)

        then:
        details.additionalInformation.size() == 1
        details.additionalInformation.foo == 'bar'
    }
}
