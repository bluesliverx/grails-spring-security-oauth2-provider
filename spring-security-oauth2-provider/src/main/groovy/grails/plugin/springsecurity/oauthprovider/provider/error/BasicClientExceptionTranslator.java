package grails.plugin.springsecurity.oauthprovider.provider.error;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;

/**
 * The purpose of this exception translator is to ensure error messages are consistent regardless of the
 * chosen client authentication method (HTTP Basic or via request parameters)
 */
public class BasicClientExceptionTranslator extends DefaultWebResponseExceptionTranslator {

    @Override
    public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {

        // Wrap exception thrown when authenticating with a valid confidential client but missing or incorrect client secret
        if (e instanceof BadCredentialsException) {
            e = new BadCredentialsException(e.getMessage(), new BadClientCredentialsException());

        // Wrap exception thrown when authenticating with invalid client (client id does not exist)
        } else if (e.getCause() instanceof ClientRegistrationException) {
            e = new BadCredentialsException(e.getMessage(), new BadClientCredentialsException());
        }

        return super.translate(e);
    }
}
