package grails.plugin.springsecurity.oauthprovider.exceptions;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class OAuth2AuthorizationEndpointException extends WrappedEndpointException {

    public OAuth2AuthorizationEndpointException(ClientRegistrationException e) {
        super(e.getMessage(), e);
    }

    public OAuth2AuthorizationEndpointException(OAuth2Exception e) {
        super(e.getMessage(), e);
    }
}
