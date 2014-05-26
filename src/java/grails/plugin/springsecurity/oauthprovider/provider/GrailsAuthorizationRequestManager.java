package grails.plugin.springsecurity.oauthprovider.provider;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class GrailsAuthorizationRequestManager extends DefaultAuthorizationRequestManager {

    private final ClientDetailsService clientDetailsService;
    private final boolean scopeRequired;

    public GrailsAuthorizationRequestManager(ClientDetailsService clientDetailsService, boolean scopeRequired) {
        super(clientDetailsService);
        this.clientDetailsService = clientDetailsService;
        this.scopeRequired = scopeRequired;
    }

    public AuthorizationRequest createAuthorizationRequest(Map<String, String> parameters) {

        String clientId = extractClientId(parameters);
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        validateGrantTypes(clientDetails);

        Set<String> scopes = extractScopes(parameters);

        DefaultAuthorizationRequest request = new DefaultAuthorizationRequest(parameters,
                Collections.<String, String> emptyMap(), clientId, scopes);

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

        if(scopesNotPresent && (scopesCanBeOmitted(parameters) || !scopeRequired)) {
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

    private void validateGrantTypes(ClientDetails clientDetails) {
        Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
        if(authorizedGrantTypes == null || authorizedGrantTypes.isEmpty()) {
            throw new InvalidGrantException("A client must have at least one authorized grant type.");
        }
    }
}
