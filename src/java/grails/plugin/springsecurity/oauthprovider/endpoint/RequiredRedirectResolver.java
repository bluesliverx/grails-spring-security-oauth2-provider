package grails.plugin.springsecurity.oauthprovider.endpoint;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.ExactMatchRedirectResolver;

import java.util.Set;

public class RequiredRedirectResolver extends ExactMatchRedirectResolver {

    @Override
    public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {

        String redirectUri = super.resolveRedirect(requestedRedirect, client);
        Set<String> registeredUris = client.getRegisteredRedirectUri();

        if(registeredUris == null || !registeredUris.contains(redirectUri)) {
            throw new RedirectMismatchException("A redirect_uri must be registered.");
        }
        return redirectUri;
    }
}
