package test.oauth2

import grails.test.mixin.TestFor
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.RefreshToken

@TestFor(RefreshToken)
class RefreshTokenSpec extends Specification {

    void "value must be unique"() {
        given:
        def existingToken = new RefreshToken(value: 'gormRefreshToken')
        mockForConstraintsTests(RefreshToken, [existingToken])

        when:
        def newToken = new RefreshToken(value: 'gormRefreshToken')

        then:
        !newToken.validate(['value'])
    }

    @Unroll
    void "value is required -- test invalid [#value]"() {
        when:
        def token = new RefreshToken(value: value)

        then:
        !token.validate(['value'])

        where:
        value << [null, '']
    }

    @Unroll
    void "test authentication constraints [#auth] is valid [#valid]"() {
        when:
        def token = new RefreshToken(authentication: auth as byte[])

        then:
        token.validate(['authentication']) == valid

        where:
        auth        |   valid
        [0x1]       |   true
        []          |   false
        null        |   false
    }

    @Unroll
    void "expiration is optional -- [#value] is valid [#valid]"() {
        when:
        def token = new RefreshToken(expiration: value)

        then:
        token.validate(['expiration']) == valid

        where:
        value       |   valid
        new Date()  |   true
        null        |   true
    }
}