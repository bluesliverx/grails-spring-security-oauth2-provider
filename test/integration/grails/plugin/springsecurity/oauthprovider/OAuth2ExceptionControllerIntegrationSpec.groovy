package grails.plugin.springsecurity.oauthprovider

import grails.plugin.spock.IntegrationSpec
import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2TokenEndpointException
import org.codehaus.groovy.grails.web.errors.GrailsWrappedRuntimeException
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException
import org.springframework.security.oauth2.provider.ClientRegistrationException
import spock.lang.Unroll

class OAuth2ExceptionControllerIntegrationSpec extends IntegrationSpec {

    OAuth2ExceptionController controller

    void setup() {
        controller = new OAuth2ExceptionController()
    }

    @Unroll
    void "test token endpoint exception handler for [#exceptionClass]"() {
        given:
        def e = exceptionClass.newInstance('TEST')
        wrapAndAttachEndpointExceptionToRequest(e, OAuth2TokenEndpointException)

        when:
        controller.tokenEndpointExceptionHandler()

        then:
        controller.response.status == httpErrorCode

        controller.response.header('Cache-Control') == 'no-store'
        controller.response.header('Pragma') == 'no-cache'

        controller.response.json.error == oauth2ErrorCode
        controller.response.json.error_description != null

        checkWWWAuthenticateHeader(shouldHaveWWWAuthenticateHeader)

        where:
        exceptionClass              |   httpErrorCode   |   oauth2ErrorCode         |   shouldHaveWWWAuthenticateHeader
        InsufficientScopeException  |   403             |   'insufficient_scope'    |   true
        UnauthorizedClientException |   401             |   'unauthorized_client'   |   true
        OAuth2Exception             |   400             |   'invalid_request'       |   false
        ClientRegistrationException |   401             |   'invalid_client'        |   true
    }

    private void wrapAndAttachEndpointExceptionToRequest(Exception e, Class endpointExceptionClass) {
        def wrapped = endpointExceptionClass.newInstance(e) as Exception
        controller.request.exception = new GrailsWrappedRuntimeException(controller.servletContext, wrapped)
    }

    private void checkWWWAuthenticateHeader(boolean shouldHaveWWWAuthenticateHeader) {
        def header = controller.response.header('WWW-Authenticate')

        if(shouldHaveWWWAuthenticateHeader) {
            assert header != null
            assert header.startsWith('Bearer ')
        }
        else {
            assert header == null
        }
    }
}
