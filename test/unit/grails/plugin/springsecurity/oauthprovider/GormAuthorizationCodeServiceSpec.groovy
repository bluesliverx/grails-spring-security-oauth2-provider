package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import grails.test.mixin.TestFor
import org.springframework.security.oauth2.provider.OAuth2Authentication
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.AuthorizationCode

@TestFor(GormAuthorizationCodeService)
class GormAuthorizationCodeServiceSpec extends Specification {

    String code = 'testAuthCode'
    OAuth2Authentication oauth2Authentication = Stub(OAuth2Authentication)

    void setup() {
        service.grailsApplication = grailsApplication
        service.oauth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)

        setAuthorizationCodeClassName(AuthorizationCode.class.name)
    }

    void cleanup() {
        SpringSecurityUtils.securityConfig = null
    }

    private void setAuthorizationCodeClassName(String authorizationCodeClassName) {
        def authorizationCodeLookup = [
                className: authorizationCodeClassName,
                authenticationPropertyName: 'authentication',
                codePropertyName: 'code'
        ]
        SpringSecurityUtils.securityConfig = [oauthProvider: [authorizationCodeLookup: authorizationCodeLookup]] as ConfigObject
    }

    @Unroll
    void "store invalid authorization code domain class name: [#className]"() {
        given:
        setAuthorizationCodeClassName(className)

        when:
        service.store(code, oauth2Authentication)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified authorization code domain class '$className' is not a domain class"

        where:
        _   |   className
        _   |   'invalidAuthCodeClass'
        _   |   null
    }

    @Unroll
    void "remove invalid authorization code domain class name: [#className]"() {
        given:
        setAuthorizationCodeClassName(className)

        when:
        service.remove(code)

        then:
        def e = thrown(IllegalArgumentException)
        e.message == "The specified authorization code domain class '$className' is not a domain class"

        where:
        _   |   className
        _   |   'invalidAuthCodeClass'
        _   |   null
    }
}
