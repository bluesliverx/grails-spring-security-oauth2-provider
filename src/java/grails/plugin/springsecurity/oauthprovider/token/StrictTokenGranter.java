package grails.plugin.springsecurity.oauthprovider.token;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import java.util.Collection;

/**
 * This wrapper tightens the restrictions on a client's allowed authorized grant types.
 * By default, AbstractTokenGranter, which all of the standard token granters are derived from,
 * will happily allow client's with empty authorized grant types to retrieve an access token.
 * This class will ensure this is not allowed.
 */
public class StrictTokenGranter implements TokenGranter {

    private final TokenGranter tokenGranter;
    private final ClientDetailsService clientDetailsService;

    public StrictTokenGranter(ClientDetailsService clientDetailsService, TokenGranter tokenGranter) {
        this.clientDetailsService = clientDetailsService;
        this.tokenGranter = tokenGranter;
    }

    @Override
    public OAuth2AccessToken grant(String grantType, AuthorizationRequest authorizationRequest) {

        String clientId = authorizationRequest.getClientId();
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
        if(authorizedGrantTypes == null || authorizedGrantTypes.isEmpty()) {
            throw new InvalidGrantException("A client must have at least one authorized grant type.");
        }
        return tokenGranter.grant(grantType, authorizationRequest);
    }
}
