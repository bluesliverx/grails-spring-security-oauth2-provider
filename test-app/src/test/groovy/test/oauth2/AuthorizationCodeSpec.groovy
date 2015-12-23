package test.oauth2

import grails.test.mixin.TestFor
import spock.lang.Ignore
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.AuthorizationCode

@TestFor(AuthorizationCode)
class AuthorizationCodeSpec extends Specification {

    void "require code and authentication"() {
        given:
        def serializedAuthentication = [0x1] as byte[]

        when:
        def authorizationCode = new AuthorizationCode(code: 'foo', authentication: serializedAuthentication)

        then:
        authorizationCode.validate()

        and:
        authorizationCode.code == 'foo'
        authorizationCode.authentication == serializedAuthentication
    }

    @Ignore("TODO: Find Grails 3 equivalent of mockForConstraintsTests")
    void "code must be unique"() {
        given:
        def existingCode = new AuthorizationCode(code: 'foo')
        mockForConstraintsTests(AuthorizationCode, [existingCode])

        when:
        def newCode = new AuthorizationCode(code: 'foo')

        then:
        !newCode.validate(['code'])
    }

    @Unroll
    void "invalid code [#code]"() {
        when:
        def authorizationCode = new AuthorizationCode(code: code)

        then:
        !authorizationCode.validate(['code'])

        where:
        code << ['', null]
    }

    @Unroll
    void "authentication must not be [#auth]"() {
        when:
        def authorizationCode = new AuthorizationCode(authentication: auth as byte[])

        then:
        !authorizationCode.validate(['authentication'])

        where:
        auth << [ null, [] ]
    }
}