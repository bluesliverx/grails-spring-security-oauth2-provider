package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices
import spock.lang.Specification
import test.oauth2.AuthorizationCode

@TestFor(GormAuthorizationCodeService)
@Mock([AuthorizationCode])
class GormAuthorizationCodeServiceSpec extends Specification {

    String code = 'testAuthCode'
    byte[] serializedAuthentication = [0x42]
    OAuth2Authentication oauth2Authentication = Mock(OAuth2Authentication)

    void setup() {
        service.grailsApplication = grailsApplication
        service.oauth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)

        setAuthorizationCodeClassName('test.oauth2.AuthorizationCode')
    }

    private void setAuthorizationCodeClassName(String authorizationCodeClassName) {
        def authorizationCodeLookup = [
                className: authorizationCodeClassName,
                authenticationPropertyName: 'authentication',
                codePropertyName: 'code'
        ]
        SpringSecurityUtils.securityConfig = [oauthProvider: [authorizationCodeLookup: authorizationCodeLookup]] as ConfigObject
    }

    void "must be an AuthorizationCodeServices"() {
        expect:
        service instanceof AuthorizationCodeServices
    }

    void "store authorization code and authentication"() {
        when:
        service.store(code, oauth2Authentication)

        then:
        def gormAuthorizationCode = AuthorizationCode.findByCode(code)
        gormAuthorizationCode != null

        and:
        gormAuthorizationCode.code == code
        gormAuthorizationCode.authentication == serializedAuthentication

        and:
        1 * service.oauth2AuthenticationSerializer.serialize(oauth2Authentication) >> serializedAuthentication
    }

    void "remove authorization code and return authorization request holder"() {
        given:
        new AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert AuthorizationCode.findByCode(code)

        when:
        def authentication = service.remove(code)

        then:
        authentication == oauth2Authentication
        !AuthorizationCode.findByCode(code)

        and:
        1 * service.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> oauth2Authentication
    }

    void "return null for invalid authorization code"() {
        expect:
        service.remove(code) == null
    }

    void "ensure authorization code is removed even if deserialization throws"() {
        given:
        new AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert AuthorizationCode.findByCode(code)

        when:
        def authentication = service.remove(code)

        then:
        authentication == null
        !AuthorizationCode.findByCode(code)

        and:
        1 * service.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('UH OH')
        }
    }

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
