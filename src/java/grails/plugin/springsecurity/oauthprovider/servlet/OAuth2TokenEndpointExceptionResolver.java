package grails.plugin.springsecurity.oauthprovider.servlet;

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2TokenEndpointException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.error.OAuth2ExceptionRenderer;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerExceptionResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuth2TokenEndpointExceptionResolver extends AbstractHandlerExceptionResolver {

    private TokenEndpoint tokenEndpoint;
    private OAuth2ExceptionRenderer exceptionRenderer;

    public void setTokenEndpoint(TokenEndpoint tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public void setExceptionRenderer(OAuth2ExceptionRenderer exceptionRenderer) {
        this.exceptionRenderer = exceptionRenderer;
    }

    @Override
    protected ModelAndView doResolveException(HttpServletRequest request,
            HttpServletResponse response, Object handler, Exception ex) {

        logger.debug("Entering token endpoint exception resolver");

        if(ex instanceof OAuth2TokenEndpointException) {
            OAuth2TokenEndpointException oae = (OAuth2TokenEndpointException) ex;
            return handleException(request, response, oae);
        }
        return null;
    }

    private ModelAndView handleException(HttpServletRequest request, HttpServletResponse response,
                                         OAuth2TokenEndpointException tokenEndpointException) {
        try {
            logger.debug("Handling token endpoint exception: " + tokenEndpointException.getCause());
            ResponseEntity<OAuth2Exception> entity = extractResponseEntity(tokenEndpointException);

            ServletWebRequest webRequest = new ServletWebRequest(request, response);
            exceptionRenderer.handleHttpEntityResponse(entity, webRequest);
            return new ModelAndView();
        }
        catch (Exception e) {
            throw new RuntimeException("An error occurred while resolving token endpoint exception", e);
        }
    }

    private ResponseEntity<OAuth2Exception> extractResponseEntity(OAuth2TokenEndpointException e) throws Exception {
        Throwable cause = e.getCause();

        if(cause instanceof ClientRegistrationException) {
            ClientRegistrationException cre = (ClientRegistrationException) cause;
            return tokenEndpoint.handleClientRegistrationException(cre);
        }
        else {
            OAuth2Exception oae = (OAuth2Exception) cause;
            return tokenEndpoint.handleException(oae);
        }
    }
}
