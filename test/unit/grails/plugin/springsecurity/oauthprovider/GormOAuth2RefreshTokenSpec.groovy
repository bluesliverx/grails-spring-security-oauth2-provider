package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.TestFor
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormOAuth2RefreshToken)
class GormOAuth2RefreshTokenSpec extends Specification {

    void "value must be unique"() {
        given:
        def existingToken = new GormOAuth2RefreshToken(value: 'gormRefreshToken')
        mockForConstraintsTests(GormOAuth2RefreshToken, [existingToken])

        when:
        def newToken = new GormOAuth2RefreshToken(value: 'gormRefreshToken')

        then:
        !newToken.validate(['value'])
    }

    @Unroll
    void "value is required -- test invalid [#value]"() {
        when:
        def token = new GormOAuth2RefreshToken(value: value)

        then:
        !token.validate(['value'])

        where:
        value << [null, '']
    }

    @Unroll
    void "test authentication constraints [#auth] is valid [#valid]"() {
        when:
        def token = new GormOAuth2RefreshToken(authentication: auth as byte[])

        then:
        token.validate(['authentication']) == valid

        where:
        auth        |   valid
        [0x1]       |   true
        []          |   false
        null        |   false
    }
}