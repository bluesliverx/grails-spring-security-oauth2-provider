package grails.plugin.springsecurity.oauthprovider.servlet;

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2AuthorizationEndpointException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerExceptionResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuth2AuthorizationEndpointExceptionResolver extends AbstractHandlerExceptionResolver {

    private AuthorizationEndpoint authorizationEndpoint;

    public void setAuthorizationEndpoint(AuthorizationEndpoint authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    @Override
    protected ModelAndView doResolveException(HttpServletRequest request,
                  HttpServletResponse response, Object handler, Exception ex) {

        logger.debug("Entering authorization endpoint exception resolver");

        if(ex instanceof OAuth2AuthorizationEndpointException) {
            OAuth2AuthorizationEndpointException oae = (OAuth2AuthorizationEndpointException) ex;
            return handleException(request, response, oae);
        }

        return null;
    }

    private ModelAndView handleException(HttpServletRequest request, HttpServletResponse response,
                                         OAuth2AuthorizationEndpointException authorizationEndpointException) {
        try {
            Throwable cause = authorizationEndpointException.getCause();
            ServletWebRequest webRequest = new ServletWebRequest(request, response);

            logger.debug("Handling authorization endpoint exception: " + authorizationEndpointException.getCause());

            if(isClientRegistration(cause)) {
                ClientRegistrationException cre = (ClientRegistrationException) cause;
                return authorizationEndpoint.handleClientRegistrationException(cre, webRequest);
            }
            else if(isOAuth2Exception(cause)) {
                OAuth2Exception oae = (OAuth2Exception) cause;
                return authorizationEndpoint.handleOAuth2Exception(oae, webRequest);
            }
            else {
                throw new IllegalStateException("Invalid OAuthorizationEndpointException", cause);
            }

        }
        catch (Exception e) {
            throw new RuntimeException("An error occurred while resolving authorization endpoint exception", e);
        }
    }

    private boolean isClientRegistration(Throwable cause) {
        return cause instanceof ClientRegistrationException;
    }

    private boolean isOAuth2Exception(Throwable cause) {
        return cause instanceof OAuth2Exception;
    }
}
