package test.oauth2

import geb.Page
import geb.spock.GebSpec
import grails.test.mixin.integration.Integration
import helper.TestEnvironmentCleaner
import pages.AuthorizationPage
import pages.LoginPage
import pages.LogoutPage

import static helper.AccessTokenAssert.*

@Integration
abstract class AbstractAuthorizationEndpointFunctionalSpec extends GebSpec {

    protected static final String REDIRECT_URI = 'http://localhost:8080/redirect'

    def cleanup() {
        logout()
        TestEnvironmentCleaner.cleanup()
    }

    private void logout() {
        to LogoutPage
        logoutButton.click()
        browser.clearCookies()
    }

    protected void authorize(Map params) {
        to params, AuthorizationPage
        at LoginPage

        login()
    }

    private void login() {
        username = 'user'
        password = 'test'
        loginButton.click()
    }

    protected String getCode() {
        def query = new URI(driver.currentUrl).query
        def params = extractAccessTokenResponseFromParamString(query)
        assert params.code != null
        return params.code
    }

    protected void assertQueryContainsCodeAndState(String state) {
        def query = new URI(driver.currentUrl).query
        def params = extractAccessTokenResponseFromParamString(query)
        assert params.code != null
        assertState(params, state)
    }

    protected void assertFragmentContainsAccessTokenAndNoRefreshToken() {
        def data = extractAccessTokenResponseFromFragment()

        assertRequiredAccessTokenData(data)
        assertAccessTokenDataDoesNotContainRefreshToken(data)
    }

    protected void assertFragmentContainsAccessTokenAndScopes(List scopes) {
        def data = extractAccessTokenResponseFromFragment()

        assertRequiredAccessTokenData(data)
        assertAccessTokenDataDoesNotContainRefreshToken(data)
        assertAccessTokenDataContainsScopes(data, scopes)
    }

    protected void assertFragmentContainsAccessTokenAndState(String state) {
        def data = extractAccessTokenResponseFromFragment()

        assertRequiredAccessTokenData(data)
        assertAccessTokenDataDoesNotContainRefreshToken(data)
        assertState(data, state)
    }

    private Map extractAccessTokenResponseFromFragment() {
        def fragment = new URI(driver.currentUrl).fragment
        return extractAccessTokenResponseFromParamString(fragment)
    }

    protected void assertFragmentContainsErrorCodeAndDescription(String errorCode, String description) {
        def fragment = new URI(driver.currentUrl).fragment
        assertErrorCodeAndDescription(fragment, errorCode, description)
    }

    protected void assertQueryContainsErrorCodeAndDescription(String errorCode, String description) {
        def query = new URI(driver.currentUrl).query
        assertErrorCodeAndDescription(query, errorCode, description)
    }

    protected void assertQueryContainsErrorCodeAndDescriptionAndState(String errorCode, String description, String state) {
        def query = new URI(driver.currentUrl).query
        assertErrorCodeAndDescription(query, errorCode, description)

        def data = extractAccessTokenResponseFromParamString(query)
        assertState(data, state)
    }

    private void assertState(Map data, String state) {
        assert data.state == state
    }

    private void assertErrorCodeAndDescription(String paramString, String errorCode, String description) {
        def data = extractAccessTokenResponseFromParamString(paramString)
        assert data.error == errorCode
        assert data.error_description == description
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
