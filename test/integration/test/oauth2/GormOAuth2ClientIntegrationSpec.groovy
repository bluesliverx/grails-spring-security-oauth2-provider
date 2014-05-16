package test.oauth2

import grails.plugin.spock.IntegrationSpec
import grails.plugin.springsecurity.oauthprovider.GormOAuth2Client

class GormOAuth2ClientIntegrationSpec extends IntegrationSpec {

    void "client secret should be encoded differently for each public client"() {
        when:
        def client1 = new GormOAuth2Client(clientId: 'client-1').save(flush: true)
        def client2 = new GormOAuth2Client(clientId: 'client-2').save(flush: true)

        then:
        client1.clientSecret != null
        client2.clientSecret != null

        and:
        client1.clientSecret != client2.clientSecret
    }
}
