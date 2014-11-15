package grails.plugin.springsecurity.oauthprovider

import grails.test.spock.IntegrationSpec
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices
import test.oauth2.AuthorizationCode

class GormAuthorizationCodeServiceIntegrationSpec extends IntegrationSpec {

    String code = 'testAuthCode'
    byte[] serializedAuthentication = [0x42]
    OAuth2Authentication oauth2Authentication = Mock(OAuth2Authentication)

    def gormAuthorizationCodeService

    OAuth2AuthenticationSerializer originalSerializer

    void setup() {
        originalSerializer = gormAuthorizationCodeService.oauth2AuthenticationSerializer
        gormAuthorizationCodeService.oauth2AuthenticationSerializer = Mock(OAuth2AuthenticationSerializer)
    }

    void cleanup() {
        gormAuthorizationCodeService.oauth2AuthenticationSerializer = originalSerializer
    }

    void "must be an AuthorizationCodeServices"() {
        expect:
        gormAuthorizationCodeService instanceof AuthorizationCodeServices
    }

    void "store authorization code and authentication"() {
        when:
        gormAuthorizationCodeService.store(code, oauth2Authentication)

        then:
        def gormAuthorizationCode = AuthorizationCode.findByCode(code)
        gormAuthorizationCode != null

        and:
        gormAuthorizationCode.code == code
        gormAuthorizationCode.authentication == serializedAuthentication

        and:
        1 * gormAuthorizationCodeService.oauth2AuthenticationSerializer.serialize(oauth2Authentication) >> serializedAuthentication
    }

    void "remove authorization code and return authorization request holder"() {
        given:
        new AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert AuthorizationCode.findByCode(code)

        when:
        def authentication = gormAuthorizationCodeService.remove(code)

        then:
        authentication == oauth2Authentication
        !AuthorizationCode.findByCode(code)

        and:
        1 * gormAuthorizationCodeService.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> oauth2Authentication
    }

    void "return null for invalid authorization code"() {
        expect:
        gormAuthorizationCodeService.remove(code) == null
    }

    void "ensure authorization code is removed even if deserialization throws"() {
        given:
        new AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert AuthorizationCode.findByCode(code)

        when:
        def authentication = gormAuthorizationCodeService.remove(code)

        then:
        authentication == null
        !AuthorizationCode.findByCode(code)

        and:
        1 * gormAuthorizationCodeService.oauth2AuthenticationSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('UH OH')
        }
    }
}
