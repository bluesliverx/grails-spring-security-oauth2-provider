package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2ValidationException
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import helper.OAuth2AuthenticationFactory
import helper.OAuth2RequestFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices
import spock.lang.Specification
import test.oauth2.AuthorizationCode

@Integration
@Rollback
class GormAuthorizationCodeServiceIntegrationSpec extends Specification {

    @Autowired
    GormAuthorizationCodeService gormAuthorizationCodeService

    @Autowired
    OAuth2AuthenticationSerializer oauth2AuthenticationSerializer

    OAuth2AuthenticationFactory authenticationFactory

    String code = 'testAuthCode'
    Authentication userAuthentication

    OAuth2Authentication oauth2Authentication
    byte[] serializedAuthentication

    void setup() {
        userAuthentication = new TestingAuthenticationToken('user', 'password')

        authenticationFactory = new OAuth2AuthenticationFactory(
                oauth2AuthenticationSerializer: oauth2AuthenticationSerializer,
                userAuthentication: userAuthentication
        )

        oauth2Authentication = authenticationFactory.createOAuth2Authentication()
        serializedAuthentication = oauth2AuthenticationSerializer.serialize(oauth2Authentication) as byte[]
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
        gormAuthorizationCode.authentication == oauth2AuthenticationSerializer.serialize(oauth2Authentication)
    }

    void "attempt to store invalid authorization code (authentication exceeds max size allowed)"() {
        given:
        OAuth2Authentication largeAuthentication = authenticationFactory.createLargeOAuth2Authentication()

        when:
        gormAuthorizationCodeService.store(code, largeAuthentication)

        then:
        def e = thrown(OAuth2ValidationException)

        e.message.startsWith('Failed to save authorization code')
        !e.errors.allErrors.empty
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
    }

    void "return null for invalid authorization code"() {
        expect:
        gormAuthorizationCodeService.remove(code) == null
    }
}
