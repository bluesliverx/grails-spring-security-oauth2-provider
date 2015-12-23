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
        requestResource('securedOAuth2Resources/clientRole', token) == 'client role'

        then:
        !currentSecurityContextHasGrantedAuthority('ROLE_CLIENT')
    }

    void "accessing OAuth 2.0 resource does not affect form authenticated session"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ClientCredentials, clientId: 'public-client')
        def token = getAccessToken(request)

        and:
        formLogin()

        when:
        def resource = accessOAuth2ResourceViaJavaScript('securedOAuth2Resources/clientRole', token)

        then:
        resource == 'client role'

        and:
        attemptUnauthenticatedRequestRedirectsToDenied('securedWebResources/clientRole')

        and:
        assertPageContent('securedWebResources/userRole', 'form user role')
    }

    private Object accessOAuth2ResourceViaJavaScript(String relativeUrl, String token) {
        js.exec(token, relativeUrl, '''
            var token = arguments[0];
            var relativeUrl = arguments[1];

            var xhr = new XMLHttpRequest();
            var text = null;

            xhr.open("GET", relativeUrl, false);
            xhr.setRequestHeader("Authorization", "Bearer " + token);
            xhr.send();

            return xhr.responseText;
        ''')
    }

    private void assertPageContent(String url, String content) {
        def requestUrl = browser.baseUrl + url
        go requestUrl
        assert page.contains(content)
    }
}
