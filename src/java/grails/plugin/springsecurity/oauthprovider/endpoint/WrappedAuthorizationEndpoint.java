package grails.plugin.springsecurity.oauthprovider.endpoint;

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2AuthorizationEndpointException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.Map;

public class WrappedAuthorizationEndpoint extends AuthorizationEndpoint {

    @Override
    public ModelAndView authorize(Map<String, Object> model,
          @RequestParam(value = "response_type", required = false, defaultValue = "none") String responseType,
          @RequestParam Map<String, String> requestParameters, SessionStatus sessionStatus, Principal principal) {
        try {
            return super.authorize(model, responseType, requestParameters, sessionStatus, principal);
        }
        catch (ClientRegistrationException e) {
            throw new OAuth2AuthorizationEndpointException(e);
        }
        catch(OAuth2Exception e) {
            throw new OAuth2AuthorizationEndpointException(e);
        }
    }
}
