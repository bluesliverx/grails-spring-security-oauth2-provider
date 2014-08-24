package test.oauth2

import groovyx.net.http.HttpResponseException
import groovyx.net.http.RESTClient
import helper.AccessTokenRequester
import spock.lang.Specification
import spock.lang.Unroll

import static helper.AccessTokenRequester.*
import static helper.TokenEndpointAssert.*

class TokenEndpointFunctionalSpec extends Specification {

    void "clients must use POST for access token requests"() {
        given:
        def params = [grant_type: 'client_credentials', client_id: 'public-client', scope: 'test']

        when:
        new RESTClient().get(uri: TOKEN_ENDPOINT_URL, query: params)

        then:
        thrown HttpResponseException
    }

    @Unroll
    void "invalid client requested for grant_type [#grantType]"() {
        given:
        def params = [grant_type: grantType, client_id: 'invalid-client']

        expect:
        assertAccessTokenErrorRequest(params, 401, 'invalid_client')

        where:
        _   |   grantType
        _   |   'password'
        _   |   'client_credentials'
        _   |   'refresh_token'
    }

    @Unroll
    void "must include scope for grant_type [#grantType]"() {
        given:
        def params = [grant_type: grantType, client_id: 'public-client']

        expect:
        assertAccessTokenErrorRequest(params, 400, 'invalid_grant')

        where:
        _   |   grantType
        _   |   'password'
        _   |   'client_credentials'
        _   |   'refresh_token'
    }

    void "implicit grant type cannot be used with the token endpoint"() {
        given:
        def params = [grant_type: 'implicit', client_id: 'public-client', scope: 'test']

        expect:
        assertAccessTokenErrorRequest(params, 400, 'invalid_grant')
    }

    void "same access token is returned so long as it has not expired"() {
        given:
        def params = [grant_type: 'client_credentials', client_id: 'public-client', scope: 'test']

        when:
        def oldAccessToken = getAccessToken(params)

        and:
        def newAccessToken = getAccessToken(params)

        then:
        oldAccessToken == newAccessToken
    }

    void "invalid grant_type"() {
        given:
        def params = [grant_type: 'unknown', client_id: 'public-client', scope: 'test']

        expect:
        assertAccessTokenErrorRequest(params, 400, 'unsupported_grant_type')
    }
}
