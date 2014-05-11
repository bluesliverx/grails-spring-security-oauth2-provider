package grails.plugin.springsecurity.oauthprovider.endpoint

import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException
import org.springframework.security.oauth2.provider.ClientDetails
import spock.lang.Specification

class RequiredRedirectResolverSpec extends Specification {

    RequiredRedirectResolver resolver
    ClientDetails client

    void setup() {
        resolver = new RequiredRedirectResolver()
        client = Stub(ClientDetails)
        client.getAuthorizedGrantTypes() >> (['implicit'] as Set<String>)
    }

    void "requested redirect uri matches registered redirect uri"() {
        given:
        client.getRegisteredRedirectUri() >> registered

        when:
        def actual = resolver.resolveRedirect(requested, client)

        then:
        actual == resolved

        where:
        requested           |   registered                              |   resolved
        'http://somewhere'  |   ['http://somewhere'] as Set<String>     |   'http://somewhere'
    }

    void "requested redirect uri must match registered redirect uri"() {
        given:
        client.getRegisteredRedirectUri() >> registered

        when:
        resolver.resolveRedirect(requested, client)

        then:
        def e = thrown(RedirectMismatchException)
        e.message == "Invalid redirect: $requested does not match one of the registered values: $registered"

        where:
        requested           |   registered
        'http://invalid'    |   ['http://somewhere'] as Set<String>
    }

    void "requested redirect uri must match registered redirect uri exactly"() {
        given:
        client.getRegisteredRedirectUri() >> registered

        when:
        resolver.resolveRedirect(requested, client)

        then:
        thrown(RedirectMismatchException)

        where:
        requested                       |   registered
        'http://somewhere1'             |   ['http://somewhere'] as Set<String>
        'http://somewhere?key=value'    |   ['http://somewhere'] as Set<String>
    }

    void "client must have a registered redirect uri"() {
        given:
        client.getRegisteredRedirectUri() >> registered

        when:
        resolver.resolveRedirect(requested, client)

        then:
        def e = thrown(RedirectMismatchException)
        e.message == "A redirect_uri must be registered."

        where:
        requested           |   registered
        'http://invalid'    |   [] as Set<String>
        'http://invalid'    |   null
    }
}
