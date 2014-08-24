package test.oauth2

import geb.spock.GebReportingSpec
import groovyx.net.http.HttpResponseDecorator
import groovyx.net.http.HttpResponseException
import groovyx.net.http.RESTClient
import helper.AccessTokenRequest
import helper.AccessTokenRequester
import helper.GrantTypes
import pages.AuthorizationPage
import pages.ConfirmAccessPage
import pages.DeniedPage
import pages.LoginPage
import pages.LogoutPage

abstract class AbstractAccessControlFunctionalSpec extends GebReportingSpec {

    boolean isLoggedIn = false
    RESTClient restClient = new RESTClient()

    def cleanup() {
        if(isLoggedIn) {
            logout()
        }
    }

    private void logout() {
        to LogoutPage
        logoutButton.click()
        browser.clearCookies()
    }

    protected void attemptRequestWithoutTokenRedirectsToDenied(String relativeUrl) {
        def requestUrl = browser.baseUrl + relativeUrl
        go requestUrl
        isAt DeniedPage
    }

    protected String requestPage(String relativeUrl, String token) {
        def requestUrl = browser.baseUrl + relativeUrl
        def headers = [Authorization: "Bearer $token"]
        def response = restClient.get(uri: requestUrl, headers: headers) as HttpResponseDecorator
        response.data
    }

    protected void forbiddenPage(String relativeUrl, String token) {
        try {
            def requestUrl = browser.baseUrl + relativeUrl
            def headers = [Authorization: "Bearer $token"]
            restClient.get(uri: requestUrl, headers: headers) as HttpResponseDecorator

            throw new IllegalStateException("Url [$requestUrl] should have been fordbidden")
        }
        catch(HttpResponseException e) {
            assert e.response.status == 403
        }
    }

    protected HttpResponseDecorator requestRawResponse(String relativeUrl, String token) {
        try {
            def requestUrl = browser.baseUrl + relativeUrl
            def headers = [Authorization: "Bearer $token"]
            restClient.get(uri: requestUrl, headers: headers) as HttpResponseDecorator
        }
        catch(HttpResponseException e) {
            return e.response
        }
    }

    protected String getAccessToken(AccessTokenRequest request) {

        Map params = createParamsFromRequest(request)

        switch(request.grantType) {

            case GrantTypes.AuthorizationCode:
                return authorizationCodeGrant(params)

            case GrantTypes.Implicit:
                return implicitGrant(params)

            case GrantTypes.ResourceOwnerCredentials:
                return resourceOwnerPasswordCredentialsGrant(params)

            case GrantTypes.ClientCredentials:
                return clientCredentialsGrant(params)

            default:
                throw new IllegalStateException('Unable to request access token')
        }
    }

    private Map createParamsFromRequest(AccessTokenRequest request) {
        Map params = [
                client_id: request.clientId,
                scope: request?.scope ?: 'test'
        ]

        if(request?.clientSecret) {
            params << [client_secret: request.clientSecret]
        }

        return params
    }

    private String authorizationCodeGrant(Map params) {
        params << [response_type: 'code']

        authorize(params)
        confirm()

        def tokenEndpointParams = createTokenEndpointParams(params.scope, params.client_id, params?.client_secret)
        AccessTokenRequester.getAccessToken(tokenEndpointParams)
    }

    private Map createTokenEndpointParams(String scope, String clientId, String clientSecret = null) {
        def code = getCodeFromQuery()
        def params = [grant_type: 'authorization_code', code: code, client_id: clientId, scope: scope]
        if(clientSecret) {
            params << [client_secret: clientSecret]
        }
        return params
    }

    private String getCodeFromQuery() {
        def query = new URI(driver.currentUrl).query
        def params = extractAccessTokenResponseFromParamString(query)
        assert params.code != null
        return params.code
    }

    private String implicitGrant(Map params) {
        params << [response_type: 'token']

        authorize(params)
        confirm()

        getAccessTokenFromFragment()
    }

    private String getAccessTokenFromFragment() {
        def fragment = new URI(driver.currentUrl).fragment
        def params = extractAccessTokenResponseFromParamString(fragment)
        assert params.access_token != null
        return params.access_token
    }

    private String resourceOwnerPasswordCredentialsGrant(Map params) {
        params << [grant_type: 'password', username: 'user', password: 'test']
        AccessTokenRequester.getAccessToken(params)
    }

    private String clientCredentialsGrant(Map params) {
        params << [grant_type: 'client_credentials']
        AccessTokenRequester.getAccessToken(params)
    }

    private void authorize(Map params) {
        to params, AuthorizationPage
        at LoginPage

        login()
    }

    protected void login() {
        username = 'user'
        password = 'test'
        loginButton.click()
        isLoggedIn = true
    }

    private void confirm() {
        at ConfirmAccessPage
        authorizeButton.click()
    }

    private Map extractAccessTokenResponseFromParamString(String paramString) {
        def data = [:]

        paramString?.split('&')?.each { param ->
            int idx = param.indexOf('=')

            if(paramContainsValue(idx, param)) {
                def key = URLDecoder.decode(param.substring(0, idx), 'UTF-8')
                def value = URLDecoder.decode(param.substring(idx + 1), 'UTF-8')
                data << [(key): value]
            }
        }
        return data
    }

    private boolean paramContainsValue(int idx, String param) {
        idx + 1 < param.length()
    }
}
