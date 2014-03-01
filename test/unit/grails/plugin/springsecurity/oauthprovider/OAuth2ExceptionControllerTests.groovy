package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.TestFor
import org.codehaus.groovy.grails.web.errors.GrailsWrappedRuntimeException
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator

@TestFor(OAuth2ExceptionController)
class OAuth2ExceptionControllerTests {

    void setUp() {
        controller.webResponseExceptionTranslator = new DefaultWebResponseExceptionTranslator()
    }

    void testClientRegistrationExceptionHandler() {
        attachExceptionToRequest(new ClientRegistrationException('TEST'))

        controller.clientRegistrationExceptionHandler()
        def e = new BadClientCredentialsException()

        assert WWWAuthenticateHeaderIsPresent(e)
        assertResponseMatchesException(e)
    }

    void testOAuth2ExceptionHandler() {
        def e = new OAuth2Exception('TEST')
        attachExceptionToRequest(e)

        controller.oAuth2ExceptionHandler()
        assert !WWWAuthenticateHeaderIsPresent(e)

        assertResponseMatchesException(e)
    }

    void testUnauthorizedRequestReturnsWWWAuthenticateHeader() {
        def e = new UnauthorizedClientException('TEST')
        attachExceptionToRequest(e)

        controller.oAuth2ExceptionHandler()
        assert response.status == 401
        assert WWWAuthenticateHeaderIsPresent(e)
    }

    void testInsufficientScopeExceptionsReturnsWWWAuthenticateHeader() {
        def e = new InsufficientScopeException('TEST')
        attachExceptionToRequest(e)

        controller.oAuth2ExceptionHandler()
        assert response.status == 403
        assert WWWAuthenticateHeaderIsPresent(e)
    }

    private void attachExceptionToRequest(Exception e) {
        request.exception = new GrailsWrappedRuntimeException(controller.servletContext, e)
    }

    private boolean WWWAuthenticateHeaderIsPresent(OAuth2Exception e) {
        response.header('WWW-Authenticate') == "Bearer ${e.summary}"
    }

    private void assertResponseMatchesException(OAuth2Exception e) {
        assert response.header('Cache-Control') == 'no-store'
        assert response.header('Pragma') == 'no-cache'

        assert response.status == e.httpErrorCode
        assert response.json.error == e.OAuth2ErrorCode
        assert response.json.error_description == e.message
    }
}
