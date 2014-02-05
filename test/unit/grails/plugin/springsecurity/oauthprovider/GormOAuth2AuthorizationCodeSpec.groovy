package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.TestFor
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormOAuth2AuthorizationCode)
class GormOAuth2AuthorizationCodeSpec extends Specification {

    void "require code and authentication"() {
        given:
        def serializedAuthentication = [0x1] as byte[]

        when:
        def authorizationCode = new GormOAuth2AuthorizationCode(code: 'foo', authentication: serializedAuthentication)

        then:
        authorizationCode.validate()

        and:
        authorizationCode.code == 'foo'
        authorizationCode.authentication == serializedAuthentication
    }

    void "code must be unique"() {
        given:
        def existingCode = new GormOAuth2AuthorizationCode(code: 'foo')
        mockForConstraintsTests(GormOAuth2AuthorizationCode, [existingCode])

        when:
        def newCode = new GormOAuth2AuthorizationCode(code: 'foo')

        then:
        !newCode.validate(['code'])
    }

    @Unroll
    void "invalid code [#code]"() {
        when:
        def authorizationCode = new GormOAuth2AuthorizationCode(code: code)

        then:
        !authorizationCode.validate(['code'])

        where:
        code << ['', null]
    }

    @Unroll
    void "authentication must not be [#auth]"() {
        when:
        def authorizationCode = new GormOAuth2AuthorizationCode(authentication: auth as byte[])

        then:
        !authorizationCode.validate(['authentication'])

        where:
        auth << [ null, [] ]
    }
}