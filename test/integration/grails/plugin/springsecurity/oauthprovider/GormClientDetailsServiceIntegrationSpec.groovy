package grails.plugin.springsecurity.oauthprovider

import grails.test.spock.IntegrationSpec
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.NoSuchClientException
import test.oauth2.Client

class GormClientDetailsServiceIntegrationSpec extends IntegrationSpec {

    def gormClientDetailsService

    void "request valid client using dynamic look up"() {
        given:
        new Client(
                clientId: 'gormClient',
                clientSecret: 'grails',
                accessTokenValiditySeconds: 1234,
                refreshTokenValiditySeconds: 5678,
                authorities: ['ROLE_CLIENT'] as Set,
                authorizedGrantTypes: ['implicit'] as Set,
                resourceIds: ['someResource'] as Set,
                scopes: ['kaleidoscope'] as Set,
                redirectUris: ['http://anywhereButHere'] as Set,
                additionalInformation: [text: 'words', number: 1234]
        ).save()

        when:
        def details = gormClientDetailsService.loadClientByClientId('gormClient')

        then:
        details instanceof ClientDetails

        and:
        details.clientId == 'gormClient'
        clientSecretIsEncoded(details.clientSecret, 'grails')

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

        and:
        details.additionalInformation.size() == 2
        details.additionalInformation.text == 'words'
        details.additionalInformation.number == 1234
    }

    private void clientSecretIsEncoded(String encodedSecret, String plainTextSecret) {
        assert encodedSecret != plainTextSecret
    }

    void "requested client not found"() {
        when:
        gormClientDetailsService.loadClientByClientId('gormClient')

        then:
        def e = thrown(NoSuchClientException)
        e.message == 'No client with requested id: gormClient'
    }
}
