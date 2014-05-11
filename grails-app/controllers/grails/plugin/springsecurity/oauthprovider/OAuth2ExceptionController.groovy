package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.oauthprovider.endpoint.WrappedAuthorizationEndpoint
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.web.context.request.ServletWebRequest
import org.springframework.web.servlet.view.RedirectView

import static org.codehaus.groovy.grails.web.servlet.HttpHeaders.*

class OAuth2ExceptionController {

    WrappedAuthorizationEndpoint oauth2AuthorizationEndpoint

    def tokenEndpointExceptionHandler() {
        def e = unwrapException()
        log.info("Handling token endpoint exception [${e.class.simpleName}]: [${e.message}]")

        if(isClientRegistrationException(e)) {
            renderTokenEndpointException(new BadClientCredentialsException())
        }
        else {
            renderTokenEndpointException(e)
        }
    }

    private void renderTokenEndpointException(OAuth2Exception e) {
        addHeaders(e)
        render(status: e.httpErrorCode, contentType: 'application/json', encoding: 'utf-8') {
            [
                    error: e.OAuth2ErrorCode,
                    error_description: e.message
            ]
        }
    }

    private void addHeaders(OAuth2Exception e) {
        header(CACHE_CONTROL, 'no-store')
        header(PRAGMA, 'no-cache')

        boolean unauthorized = (e.httpErrorCode == HttpStatus.UNAUTHORIZED.value())
        boolean insufficientScope = (e instanceof InsufficientScopeException)

        if(unauthorized || insufficientScope) {
            def challenge = String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, e.summary)
            header(WWW_AUTHENTICATE, challenge)
        }
    }

    def authorizationEndpointExceptionHandler() {
        def e = unwrapException()
        log.info("Handling authorization endpoint exception [${e.class.simpleName}]: [${e.message}]")

        // Wrap the request and response for integrating with Spring exception handlers -- is this safe?
        def servletWebRequest = new ServletWebRequest(request, response)
        def modelAndView = null

        if(isClientRegistrationException(e)) {
            modelAndView = oauth2AuthorizationEndpoint.handleClientRegistrationException(e, servletWebRequest)
        }
        else if(isOAuth2Exception(e)) {
            modelAndView = oauth2AuthorizationEndpoint.handleOAuth2Exception(e, servletWebRequest)
        }
        else {
            throw new IllegalStateException("Invalid wrapped authorization endpoint exception")
        }

        if(modelAndView.view instanceof RedirectView) {
            def redirectView = modelAndView.view as RedirectView
            redirect(url: redirectView.url)
        }
        else {
            render(view: modelAndView.viewName, model: modelAndView.model)
        }
    }

    /*
        The original exception is first wrapped by one of the endpoint
        exceptions and then again wrapped by Grails as a GrailsWrappedRuntimeException.
        This unwraps all of that and hands back the original exception.
     */
    private def unwrapException() {
        def wrappedEndpointException = request.exception.cause
        def originalException = wrappedEndpointException.cause
        return originalException
    }

    private boolean isClientRegistrationException(e) {
        return e instanceof ClientRegistrationException
    }

    private boolean isOAuth2Exception(e) {
        return e instanceof OAuth2Exception
    }
}
