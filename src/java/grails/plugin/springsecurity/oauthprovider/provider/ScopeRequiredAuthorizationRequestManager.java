package grails.plugin.springsecurity.oauthprovider.provider;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class ScopeRequiredAuthorizationRequestManager extends DefaultAuthorizationRequestManager {

    private final ClientDetailsService clientDetailsService;

    public ScopeRequiredAuthorizationRequestManager(ClientDetailsService clientDetailsService) {
        super(clientDetailsService);
        this.clientDetailsService = clientDetailsService;
    }

    public AuthorizationRequest createAuthorizationRequest(Map<String, String> parameters) {

        String clientId = extractClientId(parameters);
        Set<String> scopes = extractScopes(parameters);

        DefaultAuthorizationRequest request = new DefaultAuthorizationRequest(parameters,
                Collections.<String, String> emptyMap(), clientId, scopes);

        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        request.addClientDetails(clientDetails);

        return request;
    }

    private String extractClientId(Map<String, String> parameters) {
        String clientId = parameters.get("client_id");
        if (clientId == null) {
            throw new InvalidClientException("A client id must be provided");
        }
        return clientId;
    }

    private Set<String> extractScopes(Map<String, String> parameters) {
        Set<String> scopes = OAuth2Utils.parseParameterList(parameters.get("scope"));
        boolean scopesNotPresent = scopesNotPresent(scopes);

        if(scopesNotPresent && scopesCanBeOmitted(parameters)) {
            scopes = Collections.emptySet();
        }
        else if(scopesNotPresent) {
            throw new InvalidScopeException("Scope must be specified");
        }
        return scopes;
    }

    private boolean scopesNotPresent(Set<String> scopes) {
        return (scopes == null) || (scopes.isEmpty());
    }

    // The access token request for the authorization code grant is the
    // only case where the scope param is not mentioned in the spec
    private boolean scopesCanBeOmitted(Map<String, String> parameters) {
        String grantType = parameters.get("grant_type");
        return (grantType != null) && (grantType.equals("authorization_code"));
    }
}
