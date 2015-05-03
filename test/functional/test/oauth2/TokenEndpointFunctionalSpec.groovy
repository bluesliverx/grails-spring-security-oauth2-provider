package test.oauth2

import groovyx.net.http.HttpResponseException
import groovyx.net.http.RESTClient
import spock.lang.Unroll

import static helper.AccessTokenRequester.getAccessToken
import static helper.AccessTokenRequester.TOKEN_ENDPOINT_URL
import static helper.AccessTokenRequester.requestAccessToken
import static helper.ErrorDescriptions.*
import static helper.TokenEndpointAssert.assertAccessTokenErrorRequest

class TokenEndpointFunctionalSpec extends AbstractTokenEndpointFunctionalSpec {

    void "clients must use POST for access token requests"() {
        given:
        def params = [grant_type: 'client_credentials', client_id: 'public-client', scope: 'test']

        when:
        new RESTClient().get(uri: TOKEN_ENDPOINT_URL, query: params)

        then:
        thrown HttpResponseException
    }

    void "missing all params for token request"() {
        expect:
        assertAccessTokenErrorRequest([:], 401, 'unauthorized', FULL_AUTHENTICATION_REQUIRED, true)
    }

    @Unroll
    void "invalid client requested for grant_type [#grantType]"() {
        given:
        def params = [grant_type: grantType, client_id: 'invalid-client']

        expect:
        assertAccessTokenErrorRequest(params, 401, 'invalid_client', BAD_CLIENT_CREDENTIALS, true)

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
        assertAccessTokenErrorRequest(params, 400, 'invalid_scope', SCOPE_REQUIRED)

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
        assertAccessTokenErrorRequest(params, 400, 'invalid_grant', IMPLICIT_GRANT_TYPE_UNSUPPORTED)
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

    void "additional information should be returned for each token request"() {
        given:
        def params = [grant_type: 'client_credentials', client_id: 'public-client', scope: 'test']

        when:
        def oldResponse = requestAccessToken(params).data as Map

        and:
        def newResponse = requestAccessToken(params).data as Map

        then:
        oldResponse.access_token == newResponse.access_token

        and:
        oldResponse.foo == 'bar'
        newResponse.foo == 'bar'
    }

    void "invalid grant_type"() {
        given:
        def params = [grant_type: 'unknown', client_id: 'public-client', scope: 'test']

        expect:
        assertAccessTokenErrorRequest(params, 400, 'unsupported_grant_type', unsupportedGrantType('unknown'))
    }
}
