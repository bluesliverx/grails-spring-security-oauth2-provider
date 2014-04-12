package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder
import spock.lang.Specification

@TestFor(GormAuthorizationCodeService)
@Mock([GormOAuth2AuthorizationCode])
class GormAuthorizationCodeServiceSpec extends Specification {

    String code = 'testAuthCode'
    byte[] serializedAuthentication = [0x42]
    AuthorizationRequestHolder authorizationRequestHolder = Mock(AuthorizationRequestHolder)

    void setup() {
        service.grailsApplication = grailsApplication
        service.authorizationRequestHolderSerializer = Mock(AuthorizationRequestHolderSerializer)

        setAuthorizationCodeClassName('grails.plugin.springsecurity.oauthprovider.GormOAuth2AuthorizationCode')
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
        service.store(code, authorizationRequestHolder)

        then:
        def gormAuthorizationCode = GormOAuth2AuthorizationCode.findByCode(code)
        gormAuthorizationCode != null

        and:
        gormAuthorizationCode.code == code
        gormAuthorizationCode.authentication == serializedAuthentication

        and:
        1 * service.authorizationRequestHolderSerializer.serialize(authorizationRequestHolder) >> serializedAuthentication
    }

    void "remove authorization code and return authorization request holder"() {
        given:
        new GormOAuth2AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert GormOAuth2AuthorizationCode.findByCode(code)

        when:
        def authentication = service.remove(code)

        then:
        authentication == authorizationRequestHolder
        !GormOAuth2AuthorizationCode.findByCode(code)

        and:
        1 * service.authorizationRequestHolderSerializer.deserialize(serializedAuthentication) >> authorizationRequestHolder
    }

    void "return null for invalid authorization code"() {
        expect:
        service.remove(code) == null
    }

    void "ensure authorization code is removed even if deserialization throws"() {
        given:
        new GormOAuth2AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert GormOAuth2AuthorizationCode.findByCode(code)

        when:
        def authentication = service.remove(code)

        then:
        authentication == null
        !GormOAuth2AuthorizationCode.findByCode(code)

        and:
        1 * service.authorizationRequestHolderSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('UH OH')
        }
    }

    void "store invalid authorization code domain class name: [#className]"() {
        given:
        setAuthorizationCodeClassName(className)

        when:
        service.store(code, authorizationRequestHolder)

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
