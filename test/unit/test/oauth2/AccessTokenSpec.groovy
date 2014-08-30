package test.oauth2

import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import spock.lang.Specification
import spock.lang.Unroll
import test.oauth2.AccessToken
import test.oauth2.RefreshToken

@TestFor(AccessToken)
@Mock([RefreshToken])
class AccessTokenSpec extends Specification {

    void "username is optional to support flows that don't require it"() {
        when:
        def token = new AccessToken(username: null)

        then:
        token.validate(['username'])
    }

    @Unroll
    void "clientId is required -- test invalid [#clientId]"() {
        when:
        def token = new AccessToken(clientId: clientId)

        then:
        !token.validate(['clientId'])

        where:
        clientId << [null, '']
    }

    @Unroll
    void "value is required -- test invalid [#value]"() {
        when:
        def token = new AccessToken(value: value)

        then:
        !token.validate(['value'])

        where:
        value << [null, '']
    }

    void "value must be unique"() {
        given:
        def existingToken = new AccessToken(value: 'gormAccessToken')
        mockForConstraintsTests(AccessToken, [existingToken])

        when:
        def newToken = new AccessToken(value: 'gormAccessToken')

        then:
        !newToken.validate(['value'])
    }

    @Unroll
    void "tokenType is required -- test invalid [#type]"() {
        when:
        def token = new AccessToken(tokenType: type)

        then:
        !token.validate(['tokenType'])

        where:
        type << [null, '']
    }

    void "allow expiration to be null"() {
        when:
        def token = new AccessToken(expiration: null)

        then:
        token.validate(['expiration'])
    }

    void "scope is required"() {
        when:
        def token = new AccessToken(scope: null)

        then:
        !token.validate(['scope'])
    }

    void "refresh token can be null"() {
        when:
        def token = new AccessToken(refreshToken: null)

        then:
        token.validate(['refreshToken'])
    }

    @Unroll
    void "authentication key [#key] is valid [#valid]"() {
        when:
        def token = new AccessToken(authenticationKey: key)

        then:
        token.validate(['authenticationKey']) == valid

        where:
        key         |   valid
        null        |   false
        ''          |   false
        '1'         |   true
        'asdf1234'  |   true
    }

    void "authentication key must be unique"() {
        given:
        def existingToken = new AccessToken(authenticationKey: 'key')
        mockForConstraintsTests(AccessToken, [existingToken])

        when:
        def newToken = new AccessToken(authenticationKey: 'key')

        then:
        !newToken.validate(['authenticationKey'])
    }

    @Unroll
    void "test authentication constraints [#auth] is valid [#valid]"() {
        when:
        def token = new AccessToken(authentication: auth as byte[])

        then:
        token.validate(['authentication']) == valid

        where:
        auth        |   valid
        [0x1]       |   true
        []          |   false
        null        |   false
    }
}