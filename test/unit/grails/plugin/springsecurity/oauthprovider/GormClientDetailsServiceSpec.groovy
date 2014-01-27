package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.Mock
import org.springframework.security.oauth2.provider.NoSuchClientException
import spock.lang.Specification

@Mock([GormOAuth2Client])
class GormClientDetailsServiceSpec extends Specification {

    GormClientDetailsService service

    void setup() {
        service = new GormClientDetailsService()
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
