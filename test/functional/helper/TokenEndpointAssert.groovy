package helper

import groovyx.net.http.HttpResponseDecorator
import groovyx.net.http.HttpResponseException

import static helper.AccessTokenAssert.*

class TokenEndpointAssert {

    static void assertAccessTokenAndNoRefreshTokenRequest(Map params) {
        def json = getSuccessfulResponseData(params)
        assertAccessTokenDataDoesNotContainRefreshToken(json)
    }

    static void assertAccessTokenAndRefreshTokenRequest(Map params) {
        def json = getSuccessfulResponseData(params)
        assertAccessTokenDataContainsRefreshToken(json)
    }

    static void assertAccessTokenAndScopesRequest(Map params, List scopes) {
        def json = getSuccessfulResponseData(params)
        assertAccessTokenDataContainsScopes(json, scopes)
    }

    static void assertAccessTokenErrorRequest(Map params, int statusCode, String errorCode) {
        def response = getErrorResponse(params)

        assertHeaders(response)
        assertStatusCode(response, statusCode)
        assertErrorCode(response, errorCode)
    }

    private static def getSuccessfulResponseData(Map params) {
        def response = AccessTokenRequester.requestAccessToken(params)

        assertStatusCode(response, 200)
        assertHeaders(response)

        def json = response.data
        assertRequiredAccessTokenData(json)

        return json
    }

    private static void assertHeaders(HttpResponseDecorator response) {
        assert response.contentType == 'application/json'
        assert response.headers['Cache-Control'].value == 'no-store'
        assert response.headers['Pragma'].value == 'no-cache'
    }

    private static void assertStatusCode(response, statusCode) {
        assert response.status == statusCode
    }

    private static HttpResponseDecorator getErrorResponse(Map params) {
        try {
            AccessTokenRequester.requestAccessToken(params)
            throw new IllegalStateException("Expected an error response from token endpoint but did not get one!")
        }
        catch (HttpResponseException e) {
            return e.response
        }
    }

    private static void assertErrorCode(HttpResponseDecorator response, String errorCode) {
        assert response.data.error == errorCode
    }

}
