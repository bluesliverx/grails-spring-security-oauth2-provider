package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.TestFor
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormOAuth2RefreshToken)
class GormOAuth2RefreshTokenSpec extends Specification {

    void "test toRefreshToken"() {
        given:
        def expiration = new Date()
        def token = new GormOAuth2RefreshToken(value: 'gormRefreshToken', expiration: expiration)

        when:
        def refreshToken = token.toRefreshToken()

        then:
        refreshToken instanceof OAuth2RefreshToken

        and:
        refreshToken.value == 'gormRefreshToken'
        refreshToken.expiration == expiration
    }

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

    void "expiration is required"() {
        when:
        def token = new GormOAuth2RefreshToken(expiration: null)

        then:
        !token.validate(['expiration'])
    }

    void "must belong to an access token"() {
        when:
        def token = new GormOAuth2RefreshToken(accessToken: null)

        then:
        !token.validate(['accessToken'])
    }
}