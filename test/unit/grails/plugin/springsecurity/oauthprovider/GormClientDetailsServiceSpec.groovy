package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import org.springframework.security.oauth2.provider.NoSuchClientException
import spock.lang.Specification

@TestFor(GormClientDetailsService)
@Mock([GormOAuth2Client])
class GormClientDetailsServiceSpec extends Specification {

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

    void "requested client not found"() {
        when:
        service.loadClientByClientId('gormClient')

        then:
        def e = thrown(NoSuchClientException)
        e.message == 'No client with requested id: gormClient'
    }

    void "request valid client"() {
        given:
        def clientId = 'gormClient'
        new GormOAuth2Client(clientId: clientId).save(validate: false)

        when:
        def details = service.loadClientByClientId(clientId)

        then:
        details.clientId == clientId
    }
}
