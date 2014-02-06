package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.Mock
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder
import spock.lang.Specification

@Mock([GormOAuth2AuthorizationCode])
class GormAuthorizationCodeServicesSpec extends Specification {

    GormAuthorizationCodeServices authorizationCodeServices
    String code = 'testAuthCode'

    byte[] serializedAuthentication = [0x42]
    AuthorizationRequestHolder authorizationRequestHolder = Mock(AuthorizationRequestHolder)

    void setup() {
        authorizationCodeServices = new GormAuthorizationCodeServices()
        authorizationCodeServices.authorizationRequestHolderSerializer = Mock(AuthorizationRequestHolderSerializer)
    }

    void "must be an AuthorizationCodeServices"() {
        expect:
        authorizationCodeServices instanceof AuthorizationCodeServices
    }

    void "store authorization code and authentication"() {
        when:
        authorizationCodeServices.store(code, authorizationRequestHolder)

        then:
        def gormAuthorizationCode = GormOAuth2AuthorizationCode.findByCode(code)
        gormAuthorizationCode != null

        and:
        gormAuthorizationCode.code == code
        gormAuthorizationCode.authentication == serializedAuthentication

        and:
        1 * authorizationCodeServices.authorizationRequestHolderSerializer.serialize(authorizationRequestHolder) >> serializedAuthentication
    }

    void "remove authorization code and return authorization request holder"() {
        given:
        new GormOAuth2AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert GormOAuth2AuthorizationCode.findByCode(code)

        when:
        def authentication = authorizationCodeServices.remove(code)

        then:
        authentication == authorizationRequestHolder
        !GormOAuth2AuthorizationCode.findByCode(code)

        and:
        1 * authorizationCodeServices.authorizationRequestHolderSerializer.deserialize(serializedAuthentication) >> authorizationRequestHolder
    }

    void "return null for invalid authorization code"() {
        expect:
        authorizationCodeServices.remove(code) == null
    }

    void "ensure authorization code is removed even if deserialization throws"() {
        given:
        new GormOAuth2AuthorizationCode(code: code, authentication: serializedAuthentication).save()
        assert GormOAuth2AuthorizationCode.findByCode(code)

        when:
        def authentication = authorizationCodeServices.remove(code)

        then:
        authentication == null
        !GormOAuth2AuthorizationCode.findByCode(code)

        and:
        1 * authorizationCodeServices.authorizationRequestHolderSerializer.deserialize(serializedAuthentication) >> {
            throw new IllegalArgumentException('UH OH')
        }
    }
}
