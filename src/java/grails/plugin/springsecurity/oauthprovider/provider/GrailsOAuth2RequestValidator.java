package grails.plugin.springsecurity.oauthprovider.provider;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;

public class GrailsOAuth2RequestValidator extends DefaultOAuth2RequestValidator {

    @Override
    public void validateScope(TokenRequest tokenRequest, ClientDetails client) throws InvalidScopeException {
        // Per RFC 6749 Section 4.1.3:
        // The scope parameter is not required the authorization_code flow and should be ignored if present
        if(!tokenRequest.getGrantType().equals("authorization_code")) {
            super.validateScope(tokenRequest, client);
        }
    }
}
