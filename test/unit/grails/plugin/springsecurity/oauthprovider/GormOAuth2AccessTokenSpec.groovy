package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.TestFor
import org.springframework.security.oauth2.common.OAuth2AccessToken
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(GormOAuth2AccessToken)
class GormOAuth2AccessTokenSpec extends Specification {

    void "test toAccessToken"() {
        given:
        def refreshToken = new GormOAuth2RefreshToken(value: 'gormRefreshToken')
        def expiration = new Date()

        def token = new GormOAuth2AccessToken(
                value: 'gormAccessToken',
                refreshToken: refreshToken,
                tokenType: 'bearer',
                expiration: expiration,
                scope: ['read'] as Set
        )

        when:
        def accessToken = token.toAccessToken()

        then:
        accessToken instanceof OAuth2AccessToken

        and:
        accessToken.value == 'gormAccessToken'
        accessToken.refreshToken.value == 'gormRefreshToken'
        accessToken.tokenType == 'bearer'
        accessToken.expiration == expiration
        accessToken.scope.size() == 1
        accessToken.scope.contains('read')
    }

    void "username is optional to support flows that don't require it"() {
        when:
        def token = new GormOAuth2AccessToken(username: null)

        then:
        token.validate(['username'])
    }

    @Unroll
    void "clientId is required -- test invalid [#clientId]"() {
        when:
        def token = new GormOAuth2AccessToken(clientId: clientId)

        then:
        !token.validate(['clientId'])

        where:
        clientId << [null, '']
    }

    @Unroll
    void "value is required -- test invalid [#value]"() {
        when:
        def token = new GormOAuth2AccessToken(value: value)

        then:
        !token.validate(['value'])

        where:
        value << [null, '']
    }

    void "value must be unique"() {
        given:
        def existingToken = new GormOAuth2AccessToken(value: 'gormAccessToken')
        mockForConstraintsTests(GormOAuth2AccessToken, [existingToken])

        when:
        def newToken = new GormOAuth2AccessToken(value: 'gormAccessToken')

        then:
        !newToken.validate(['value'])
    }

    @Unroll
    void "tokenType is required -- test invalid [#type]"() {
        when:
        def token = new GormOAuth2AccessToken(tokenType: type)

        then:
        !token.validate(['tokenType'])

        where:
        type << [null, '']
    }

    void "allow expiration to be null"() {
        when:
        def token = new GormOAuth2AccessToken(expiration: null)

        then:
        token.validate(['expiration'])
    }

    void "scope is required"() {
        when:
        def token = new GormOAuth2AccessToken(scope: null)

        then:
        !token.validate(['scope'])
    }
}