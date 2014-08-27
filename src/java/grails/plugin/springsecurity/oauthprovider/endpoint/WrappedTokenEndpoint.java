package grails.plugin.springsecurity.oauthprovider.endpoint;

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2TokenEndpointException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Map;

public class WrappedTokenEndpoint extends TokenEndpoint {

    @Override
    public ResponseEntity<OAuth2AccessToken> getAccessToken(Principal principal,
            @RequestParam Map<String, String> parameters) {
        try {
            return super.getAccessToken(principal, parameters);
        }
        catch (ClientRegistrationException e) {
            throw new OAuth2TokenEndpointException(e);
        }
        catch (OAuth2Exception e) {
            throw new OAuth2TokenEndpointException(e);
        }
    }
}
