package grails.plugin.springsecurity.oauthprovider.provider;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import java.util.*;

/**
 * Based heavily on {@link DefaultOAuth2RequestFactory} which initializes fields from the parameters map, validates
 * grant types and scopes, and fills in scopes with the default values from the client if they are missing.
 *
 * The API has undergone some dramatic changes compared to GrailsAuthorizationRequestManager. This stays close to
 * the original, keeping the option scopeRequired. Some code duplication was necessary due to private methods.
 *
 * @author Dave Syer
 * @author Amanda Anganes
 * @author Roy Willemse
 */

public class GrailsOAuth2RequestFactory extends DefaultOAuth2RequestFactory {

    private final ClientDetailsService clientDetailsService;

    private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

    private boolean checkUserScopes = false;

    private final boolean scopeRequired;

    public GrailsOAuth2RequestFactory(ClientDetailsService clientDetailsService, boolean scopeRequired) {
        super(clientDetailsService);
        this.clientDetailsService = clientDetailsService;
        this.scopeRequired = scopeRequired;
    }

    @Override
    public void setCheckUserScopes(boolean checkUserScopes) {
        this.checkUserScopes = checkUserScopes;
    }

    @Override
    public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        this.securityContextAccessor = securityContextAccessor;
    }

    @Override
    public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {

        String clientId = authorizationParameters.get(OAuth2Utils.CLIENT_ID);
        String state = authorizationParameters.get(OAuth2Utils.STATE);
        String redirectUri = authorizationParameters.get(OAuth2Utils.REDIRECT_URI);
        Set<String> responseTypes = OAuth2Utils.parseParameterList(authorizationParameters
                .get(OAuth2Utils.RESPONSE_TYPE));

        Set<String> scopes = extractScopes(authorizationParameters, clientId);

        AuthorizationRequest request = new AuthorizationRequest(authorizationParameters,
                Collections.<String, String>emptyMap(), clientId, scopes, null, null, false, state, redirectUri,
                responseTypes);

        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        validateGrantTypes(clientDetails);

        request.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);

        return request;

    }

    @Override
    public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient) {

        String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);
        if (clientId == null) {
            // if the clientId wasn't passed in in the map, we add pull it from the authenticated client object
            clientId = authenticatedClient.getClientId();
        }
        else {
            // otherwise, make sure that they match
            if (!clientId.equals(authenticatedClient.getClientId())) {
                throw new InvalidClientException("Given client ID does not match authenticated client");
            }
        }
        String grantType = requestParameters.get(OAuth2Utils.GRANT_TYPE);

        Set<String> scopes = extractScopes(requestParameters, clientId);
        TokenRequest tokenRequest = new TokenRequest(requestParameters, clientId, scopes, grantType);

        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        validateGrantTypes(clientDetails);

        return tokenRequest;
    }

    private Set<String> extractScopes(Map<String, String> requestParameters, String clientId) {
        Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        boolean scopesNotPresent = scopesNotPresent(scopes);

        // Use the client's registered defaults per spec if request isn't required to include scope
        if(scopesNotPresent && !scopeRequired) {
            scopes = clientDetails.getScope();
        }
        else if (scopesNotPresent && scopesCanBeOmitted(requestParameters)) {
            scopes = Collections.emptySet();
        }

        if (checkUserScopes) {
            scopes = checkUserScopes(scopes, clientDetails);
        }
        return scopes;
    }

    private Set<String> checkUserScopes(Set<String> scopes, ClientDetails clientDetails) {
        if (!securityContextAccessor.isUser()) {
            return scopes;
        }
        Set<String> result = new LinkedHashSet<String>();
        Set<String> authorities = AuthorityUtils.authorityListToSet(securityContextAccessor.getAuthorities());
        for (String scope : scopes) {
            if (authorities.contains(scope) || authorities.contains(scope.toUpperCase())
                    || authorities.contains("ROLE_" + scope.toUpperCase())) {
                result.add(scope);
            }
        }
        return result;
    }

    private boolean scopesNotPresent(Set<String> scopes) {
        return (scopes == null) || (scopes.isEmpty());
    }

    // The access token request for the authorization code grant is the
    // only case where the scope param is not mentioned in the spec
    private boolean scopesCanBeOmitted(Map<String, String> requestParameters) {
        String grantType = requestParameters.get("grant_type");
        return (grantType != null) && (grantType.equals("authorization_code"));
    }

    private void validateGrantTypes(ClientDetails clientDetails) {
        Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
        if (authorizedGrantTypes == null || authorizedGrantTypes.isEmpty()) {
            throw new InvalidGrantException("A client must have at least one authorized grant type.");
        }
    }

}
