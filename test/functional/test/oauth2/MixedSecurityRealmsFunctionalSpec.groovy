package test.oauth2

import helper.AccessTokenRequest
import helper.GrantTypes

class MixedSecurityRealmsFunctionalSpec extends AbstractAccessControlFunctionalSpec {

    void "accessing secured OAuth 2.0 resource does not affect the security context"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ClientCredentials, clientId: 'public-client')
        def token = getAccessToken(request)

        and:
        assert !currentSecurityContextHasGrantedAuthority('ROLE_CLIENT')

        when:
        requestPage('securedOAuth2Resources/clientRole', token) == 'client role'

        then:
        !currentSecurityContextHasGrantedAuthority('ROLE_CLIENT')
    }

    // TODO: This should retrieve the access token used via JavaScript
    void "accessing OAuth 2.0 resource does not affect form authenticated session"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ClientCredentials, clientId: 'public-client')
        def token = getAccessToken(request)

        and:
        formLogin()

        when:
        requestPage('securedOAuth2Resources/clientRole', token) == 'client role'

        then:
        attemptUnauthenticatedRequestRedirectsToDenied('securedWebResources/clientRole')

        and:
        assertPageContent('securedWebResources/userRole', 'form user role')
    }

    private void assertPageContent(String url, String content) {
        def requestUrl = browser.baseUrl + url
        go requestUrl
        assert page.contains(content)
    }
}
