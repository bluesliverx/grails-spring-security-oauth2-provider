package grails.plugin.springsecurity.oauthprovider.provider;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

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
        request.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);

        return request;

    }

    private Set<String> extractScopes(Map<String, String> requestParameters, String clientId) {
        Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        boolean scopesNotPresent = scopesNotPresent(scopes);

        if (scopesNotPresent && (scopesCanBeOmitted(requestParameters) || !scopeRequired)) {
            // If no scopes are specified in the incoming data, use the default values registered with the client
            // (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
            // least obnoxious choice as a default).
            scopes = clientDetails.getScope();

        } else if (scopesNotPresent) {
            throw new InvalidScopeException("Scope must be specified");
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

}
